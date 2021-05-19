use crate::state::{DownloadTask, State, UploadTask};
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use futures::{channel::mpsc, SinkExt};
use onedrive_api::{
    option::DriveItemPutOption, resource::DriveItem, ConflictBehavior, ItemLocation, UploadSession,
};
use reqwest::{header, Client, StatusCode};
use std::{
    io::{BufWriter, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};

// TODO: Concurrently.
pub async fn commit(mut state: State, download: bool, upload: bool) -> Result<()> {
    let download_tasks = state.get_pending_download()?;
    let upload_tasks = state.get_pending_upload()?;
    let client = Client::new();

    if download {
        println!("{} download task in total", download_tasks.len());
        for task in download_tasks {
            download_one(task, &mut state, &client).await?;
        }
    }

    if upload {
        let state = Arc::new(Mutex::new(state));
        println!("{} upload task in total", upload_tasks.len());
        // TODO: Create remote directories first.
        for task in upload_tasks {
            let upload = Upload {
                task,
                state: state.clone(),
                client: client.clone(),
            };
            tokio::spawn(upload.run()).await??;
        }
    }
    Ok(())
}

async fn download_one(mut task: DownloadTask, state: &mut State, client: &Client) -> Result<()> {
    const CHUNK_TIMEOUT: Duration = Duration::from_secs(10);
    const SAVE_STATE_PERIOD: Duration = Duration::from_secs(5);

    // TODO: Configurable.
    let temp_file_path =
        PathBuf::from(".onedrive-sync-temp").join(format!("download.{}.part", task.pending_id));

    log::debug!(
        "Start downloading {} bytes of {:?}, destination: {}, temp file: {}",
        task.size,
        task.item_id,
        task.dest_path.display(),
        temp_file_path.display(),
    );

    let (file, mut pos) = match task.current_size {
        Some(current_size) => {
            log::debug!(
                "Recover from partial download {}/{}",
                current_size,
                task.size
            );
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&temp_file_path)?;
            assert_eq!(file.metadata()?.len(), task.size);
            assert!(current_size <= task.size);
            file.seek(SeekFrom::Start(current_size))?;
            (file, current_size)
        }
        None => {
            log::debug!("Fresh download");
            if let Some(parent) = temp_file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_file_path)?;
            file.set_len(task.size)?;
            task.current_size = Some(0);
            state.save_download_state(&task)?;
            (file, 0)
        }
    };

    let mut file = BufWriter::new(file);
    let mut last_save_time = Instant::now();

    while pos < task.size {
        let url = match &task.url {
            // FIXME: URL may expire.
            Some(url) => url.clone(),
            None => {
                let onedrive = state.get_or_login().await?;
                let url = onedrive
                    .get_item_download_url(ItemLocation::from_id(&task.item_id))
                    .await?;
                task.url = Some(url.clone());
                state.save_download_state(&task)?;
                url
            }
        };

        // TODO: Retry.
        let mut resp = client
            .get(&url)
            .header(header::RANGE, format!("bytes={}-", pos))
            .send()
            .await?;
        ensure!(
            resp.status() == StatusCode::PARTIAL_CONTENT,
            "Not Partial Content response: {}",
            resp.status()
        );

        loop {
            let chunk = match tokio::time::timeout(CHUNK_TIMEOUT, resp.chunk()).await {
                Err(_) => {
                    log::error!("Download stream timeout");
                    break;
                }
                Ok(Err(err)) => {
                    log::error!("Download stream error: {}", err);
                    break;
                }
                Ok(Ok(None)) => {
                    ensure!(pos == task.size, "Download stream ends too early");
                    break;
                }
                Ok(Ok(Some(chunk))) => chunk,
            };

            file.write_all(&*chunk)?;
            assert!(pos + chunk.len() as u64 <= task.size);
            pos += chunk.len() as u64;

            if SAVE_STATE_PERIOD < last_save_time.elapsed() {
                log::trace!("Download checkpoint");
                task.current_size = Some(pos - file.buffer().len() as u64);
                state.save_download_state(&task)?;
                last_save_time = Instant::now();
            }
        }
    }

    file.flush()?;
    assert_eq!(pos, task.size);
    log::debug!(
        "Finished downloading {} bytes of {:?}, destination: {}",
        task.size,
        task.item_id,
        task.dest_path.display(),
    );

    // TODO: atime?
    filetime::set_file_mtime(&temp_file_path, task.remote_mtime.into())?;
    if let Some(parent) = task.dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // TODO: No replace.
    std::fs::rename(&temp_file_path, &task.dest_path)?;

    state.finish_download(task.pending_id)?;
    log::debug!(
        "Recovered mtime and placed {:?} to {}",
        task.item_id,
        task.dest_path.display(),
    );

    Ok(())
}

struct Upload {
    task: UploadTask,
    state: Arc<Mutex<State>>,
    client: Client,
}

impl Upload {
    const UPLOAD_PART_SIZE: usize = 8 << 20; // 8 MiB

    async fn run(mut self) -> Result<()> {
        let file = self.check_and_open_file().await?;
        let size = self.task.lock_size.unwrap();

        let item = if size == 0 {
            self.upload_empty().await?
        } else {
            let (sess, next_pos) = self.get_or_create_session().await?;
            self.upload_with_session(file, sess, next_pos).await?
        };

        log::debug!(
            "Finished uploading {} bytes of {:?}, remote: {}, id: {:?}",
            size,
            self.task.src_path.display(),
            self.task.remote_path,
            item.id,
        );
        self.state
            .lock()
            .await
            .finish_upload(self.task.pending_id, &item)?;
        return Ok(());
    }

    fn set_fs_time(&self, patch: &mut DriveItem) {
        patch.file_system_info = Some(Box::new(serde_json::json!({
            "lastModifiedDateTime": humantime::format_rfc3339_nanos(self.task.lock_mtime.unwrap()).to_string(),
        })));
    }

    async fn persist_state(&self) -> Result<()> {
        self.state.lock().await.save_upload_state(&self.task)
    }

    async fn check_and_open_file(&mut self) -> Result<File> {
        let file = File::open(&self.task.src_path).await?;
        let meta = file.metadata().await?;

        let size = meta.len();
        let mtime = meta.modified()?;
        match (self.task.lock_size, self.task.lock_mtime) {
            (Some(lock_size), Some(lock_mtime)) => {
                log::debug!(
                    "Previous locked size: {}, mtime: {:?}",
                    lock_size,
                    lock_mtime
                );
                ensure!(
                    size == lock_size && mtime == lock_mtime,
                    "File size or mtime changed since last partial upload. Previous size: {}, previous mtime: {}",
                    lock_size,
                    humantime::format_rfc3339_nanos(lock_mtime),
                );
            }
            (None, None) => {
                log::debug!("Lock at size: {}, mtime: {:?}", size, mtime);
                self.task.lock_size = Some(size);
                self.task.lock_mtime = Some(mtime);
                self.persist_state().await?;
            }
            _ => unreachable!(),
        }

        Ok(file)
    }

    // We cannot upload empty file through upload session.
    // Special care should be taken to set its mtime correctly.
    async fn upload_empty(&mut self) -> Result<DriveItem> {
        log::debug!("Upload empty file");
        let onedrive = self.state.lock().await.get_or_login().await?;

        let item = onedrive
            .upload_small(
                ItemLocation::from_path(self.task.remote_path.as_raw_str()).unwrap(),
                Vec::new(),
            )
            .await
            .context("Failed to upload empty file")?;

        log::debug!("Setting mtime of the empty file");
        let mut patch = DriveItem::default();
        self.set_fs_time(&mut patch);
        let updated = onedrive
            .update_item(ItemLocation::from_id(&item.id.unwrap()), &patch)
            .await
            .context("Failed to set times")?;

        Ok(updated)
    }

    async fn get_or_create_session(&mut self) -> Result<(UploadSession, u64)> {
        if let Some(url) = &self.task.session_url {
            log::debug!("Resuming upload from {}", url);
            let sess = UploadSession::from_upload_url(url.to_owned());
            match sess.get_meta(&self.client).await {
                Ok(meta) => {
                    let next_pos = match &meta.next_expected_ranges[..] {
                        // TODO: Better recovery?
                        [] => bail!("Inconsistent state of upload session"),
                        [r] => r.start,
                        ranges => bail!("Invalid next_expected_ranges: {:?}", ranges),
                    };
                    log::debug!("Resumed upload at {}, meta: {:?}", next_pos, meta);
                    return Ok((sess, next_pos));
                }
                Err(err) => {
                    log::warn!(
                        "Restart upload session for {}. Previous session seems expired: {}",
                        self.task.src_path.display(),
                        err,
                    );
                }
            }
        }

                log::debug!("Creating upload session");

                let mut initial = DriveItem::default();
                self.set_fs_time(&mut initial);

                let onedrive = self.state.lock().await.get_or_login().await?;
                // TODO: Save expiration time?
                let (sess, _meta) = onedrive
                    .new_upload_session_with_initial_option(
                        ItemLocation::from_path(self.task.remote_path.as_raw_str())
                            .context("Invalid remote path")?,
                        &initial,
                        // FIXME: Also use ctag?
                        DriveItemPutOption::new().conflict_behavior(ConflictBehavior::Replace),
                    )
                    .await?;
                self.task.session_url = Some(sess.upload_url().to_owned());
                self.persist_state().await?;
                Ok((sess, 0))
            }

    async fn upload_with_session(
        &mut self,
        mut file: File,
        sess: UploadSession,
        next_pos: u64,
    ) -> Result<DriveItem> {
        let size = self.task.lock_size.unwrap();
        assert!(next_pos < size);
        if next_pos != 0 {
            file.seek(SeekFrom::Start(next_pos)).await?;
        }

        let mut file_stream = FileReadStream::new(file);
        let mut item = None;

        for chunk_start in (next_pos..size).step_by(Self::UPLOAD_PART_SIZE) {
            let chunk_end = chunk_start
                .saturating_add(Self::UPLOAD_PART_SIZE as u64)
                .min(size);
            let chunk_len = (chunk_end - chunk_start) as usize;

            log::debug!("Uploading {}..{}/{} bytes", chunk_start, chunk_end, size);

            let (tx, rx) = mpsc::channel(1);
            let stream_fut = file_stream.stream_to(tx, chunk_len as u64);
            let upload_fut = self
                .client
                .put(sess.upload_url())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", chunk_start, chunk_end - 1, size),
                )
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, chunk_len)
                .body(reqwest::Body::wrap_stream(rx))
                .send();

            let ((), resp) = futures::join!(stream_fut, upload_fut);
            let resp: reqwest::Response = resp?;

            match resp.status() {
                StatusCode::ACCEPTED => {}
                StatusCode::CREATED => item = Some(resp.json::<DriveItem>().await?),
                st => {
                    bail!(
                        "Chunk upload failed with {}. Response: {:?}",
                        st,
                        resp.text().await,
                    );
                }
            }
        }

        Ok(item.unwrap())
    }
}

struct FileReadStream {
    file: File,
    buf: Option<Bytes>,
}

impl FileReadStream {
    const CHUNK_SIZE: usize = 64 << 10; // 64 KiB

    fn new(file: File) -> Self {
        Self { file, buf: None }
    }

    async fn stream_to(&mut self, mut tx: mpsc::Sender<Result<Bytes>>, len: u64) {
        let mut rest = len;
        while rest != 0 {
            let mut chunk = match self.buf.take() {
                Some(chunk) => chunk,
                None => {
                    let mut buf = bytes::BytesMut::with_capacity(Self::CHUNK_SIZE);
                    if let Err(err) = self
                        .file
                        .read_buf(&mut buf)
                        .await
                        .map_err(Into::into)
                        .and_then(|read| {
                            ensure!(read != 0, "End of file but still expecting {} bytes", rest);
                            Ok(())
                        })
                    {
                        if tx.send(Err(err)).await.is_err() {
                            return;
                        }
                    }
                    buf.freeze()
                }
            };
            if chunk.len() as u64 > rest {
                self.buf = Some(chunk.split_off(rest as usize));
            }
            rest -= chunk.len() as u64;
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
        }
    }
}
