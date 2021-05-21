use crate::state::{DownloadTask, State, Time, UploadTask};
use anyhow::{bail, ensure, Context, Error, Result};
use bytes::Bytes;
use colored::Colorize;
use futures::{channel::mpsc, SinkExt, StreamExt};
use onedrive_api::{
    option::DriveItemPutOption, resource::DriveItem, ConflictBehavior, ItemLocation, UploadSession,
};
use pbr::ProgressBar;
use reqwest::{header, Client, StatusCode};
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    fs::{create_dir_all, rename, File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter},
    sync::{Mutex, Semaphore},
};

const PROGRESS_REFRESH_DURATION: Duration = Duration::from_millis(100);

const DOWNLOAD_CONCURRENCY: usize = 4;

// TODO: Concurrently.
pub async fn commit(state: State, download: bool, upload: bool) -> Result<()> {
    let download_tasks = state.get_pending_download()?;
    let upload_tasks = state.get_pending_upload()?;

    if upload {
        for task in &upload_tasks {
            let meta = task.src_path.metadata()?;
            let (size, mtime) = (meta.len(), Time::from(meta.modified()?));
            ensure!(
                task.lock_size == size && task.lock_mtime == mtime,
                "File to be upload changed since last add: {}, lock size & mtime: {}, {}, current: {}, {}",
                task.src_path.display(),
                task.lock_size, task.lock_mtime,
                size, mtime,
            );
        }
    }

    let state = Arc::new(Mutex::new(state));

    let client = Client::new();

    if download && !download_tasks.is_empty() {
        let total_tasks = download_tasks.len();
        let total_bytes = download_tasks.iter().map(|task| task.size).sum();
        let progress = Arc::new(Progress {
            total_tasks,
            complete_tasks: 0.into(),
            failed_tasks: 0.into(),
            complete_bytes: 0.into(),
        });

        let (err_tx, mut err_rx) = mpsc::channel(1);

        let semaphore = Arc::new(Semaphore::new(DOWNLOAD_CONCURRENCY));
        for task in download_tasks {
            let download = Download {
                current_pos: 0,
                task,
                state: state.clone(),
                client: client.clone(),
                progress: progress.clone(),
                err_tx: err_tx.clone(),
            };
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                download.run().await
            });
        }

        // Don't deadlock.
        drop(err_tx);

        let mut pb = ProgressBar::new(total_bytes);
        pb.set_units(pbr::Units::Bytes);

        let mut success = true;
        loop {
            let running_tasks = DOWNLOAD_CONCURRENCY - semaphore.available_permits();
            progress.set_bar(&mut pb, running_tasks);

            pb.tick();
            match tokio::time::timeout(PROGRESS_REFRESH_DURATION, err_rx.next()).await {
                // Timeout
                Err(_) => {}
                // Finished.
                Ok(None) => break,
                // A task failed.
                Ok(Some(err)) => {
                    success = false;
                    eprintln!("Task failed: {}", err);
                }
            }
        }

        pb.finish();
        ensure!(success, "Some tasks failed");
    }

    if upload {
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

struct Progress {
    total_tasks: usize,
    complete_tasks: AtomicUsize,
    failed_tasks: AtomicU64,
    complete_bytes: AtomicU64,
}

impl Progress {
    fn set_bar<W: std::io::Write>(&self, bar: &mut ProgressBar<W>, running_tasks: usize) {
        let completed = self.complete_tasks.load(Ordering::Relaxed);
        let failed = self.failed_tasks.load(Ordering::Relaxed);
        let bytes = self.complete_bytes.load(Ordering::Relaxed);
        if failed == 0 {
            bar.message(&format!(
                "[{}/{}/{} files] ",
                running_tasks.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks
            ));
        } else {
            bar.message(&format!(
                "[{}/{}/{} files, {}] ",
                running_tasks.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks,
                format!("{} failed", failed).red(),
            ));
        }
        bar.set(bytes);
    }
}

struct Download {
    current_pos: u64,
    task: DownloadTask,
    state: Arc<Mutex<State>>,
    client: Client,
    progress: Arc<Progress>,
    err_tx: mpsc::Sender<Error>,
}

impl Download {
    const CHUNK_TIMEOUT: Duration = Duration::from_secs(10);
    const SAVE_STATE_PERIOD: Duration = Duration::from_secs(5);

    const MAX_RETRY: usize = 5;
    const RETRY_DELAY: Duration = Duration::from_secs(5);

    async fn run(mut self) {
        match self.run_helper().await {
            Ok(()) => {
                assert_eq!(self.current_pos, self.task.size);
                self.progress.complete_tasks.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                let _ = self.err_tx.send(err).await;
                self.progress.failed_tasks.fetch_add(1, Ordering::Relaxed);
                self.progress
                    .complete_bytes
                    .fetch_add(self.task.size - self.current_pos, Ordering::Relaxed);
            }
        }
    }

    async fn run_helper(&mut self) -> Result<()> {
        // TODO: Configurable.
        let temp_path = PathBuf::from(".onedrive-sync-temp")
            .join(format!("download.{}.part", self.task.pending_id));

        log::debug!(
            "Start downloading {} bytes of {:?}, destination: {}, temp file: {}",
            self.task.size,
            self.task.item_id,
            self.task.dest_path.display(),
            temp_path.display(),
        );

        let file = self.check_open_file(&temp_path).await?;
        let mut file = BufWriter::new(file);

        // TODO: Retry
        for i in 1..=Self::MAX_RETRY {
            if i != 1 || self.task.url.is_none() {
                match self.reload_download_url().await {
                    Ok(()) => {}
                    Err(err) => {
                        log::error!(
                            "Failed to get download url (try {}/{}): {}",
                            i,
                            Self::MAX_RETRY,
                            err,
                        );
                        continue;
                    }
                }
            }
            match self
                .download(&mut file, self.task.url.clone().unwrap())
                .await
            {
                Ok(()) => break,
                Err(err) if err.is::<std::io::Error>() => bail!("Unrecoverable IO error: {}", err),
                Err(err) => log::error!("Download error (try {}/{}): {}", i, Self::MAX_RETRY, err),
            }
            tokio::time::sleep(Self::RETRY_DELAY).await;
        }

        ensure!(self.current_pos == self.task.size, "Too many retries");

        file.flush().await?;
        drop(file);

        log::debug!(
            "Finished downloading {} bytes of {:?}, destination: {}",
            self.task.size,
            self.task.item_id,
            self.task.dest_path.display(),
        );

        // TODO: atime?
        filetime::set_file_mtime(&temp_path, self.task.remote_mtime.into())?;
        if let Some(parent) = self.task.dest_path.parent() {
            create_dir_all(parent).await?;
        }
        // TODO: No replace.
        rename(&temp_path, &self.task.dest_path).await?;

        self.state
            .lock()
            .await
            .finish_download(self.task.pending_id)?;
        log::debug!(
            "Recovered mtime and placed {:?} to {}",
            self.task.item_id,
            self.task.dest_path.display(),
        );

        Ok(())
    }

    fn advance_pos(&mut self, n: u64) {
        self.current_pos += n;
        self.progress.complete_bytes.fetch_add(n, Ordering::Relaxed);
    }

    async fn persist_state(&self) -> Result<()> {
        self.state.lock().await.save_download_state(&self.task)
    }

    async fn check_open_file(&mut self, temp_path: &Path) -> Result<File> {
        if let Some(prev_pos) = self.task.current_size {
            log::debug!(
                "Recover from partial download {}/{}",
                prev_pos,
                self.task.size
            );
            assert!(prev_pos <= self.task.size);
            let mut file = OpenOptions::new().write(true).open(&temp_path).await?;
            let got_size = file.metadata().await?.len();
            if got_size == self.task.size {
                file.seek(SeekFrom::Start(prev_pos)).await?;
                self.advance_pos(prev_pos);
                return Ok(file);
            } else {
                log::warn!(
                    "Temporary file length mismatch: got {}, expect {}. Discard it and re-download from start",
                    got_size,
                    self.task.size,
                );
            }
        }

        log::debug!("Fresh download");
        if let Some(parent) = temp_path.parent() {
            create_dir_all(parent).await?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;
        file.set_len(self.task.size).await?;
        self.task.current_size = Some(0);
        self.persist_state().await?;
        Ok(file)
    }

    async fn reload_download_url(&mut self) -> Result<()> {
        log::debug!("Fetching download url");
        let onedrive = self.state.lock().await.get_or_login().await?;
        let url = onedrive
            .get_item_download_url(ItemLocation::from_id(&self.task.item_id))
            .await?;
        log::debug!("Got download url: {}", url);
        self.task.url = Some(url);
        self.persist_state().await?;
        Ok(())
    }

    async fn download(&mut self, file: &mut BufWriter<File>, url: String) -> Result<()> {
        assert!(self.current_pos < self.task.size);

        let mut resp = self
            .client
            .get(url)
            .header(header::RANGE, format!("bytes={}-", self.current_pos))
            .send()
            .await?;
        ensure!(
            resp.status() == StatusCode::PARTIAL_CONTENT,
            "Not Partial Content response: {}",
            resp.status(),
        );

        let mut last_save_time = Instant::now();

        while self.current_pos < self.task.size {
            let chunk = match tokio::time::timeout(Self::CHUNK_TIMEOUT, resp.chunk()).await {
                Err(_) => bail!("Timeout"),
                Ok(Err(err)) => return Err(err.into()),
                Ok(Ok(None)) => {
                    bail!(
                        "Stream ended at {}, but expecting {}",
                        self.current_pos,
                        self.task.size,
                    )
                }
                Ok(Ok(Some(chunk))) => chunk,
            };

            let chunk_len = chunk.len() as u64;
            ensure!(
                self.current_pos + chunk_len <= self.task.size,
                "Stream length mismatch",
            );
            file.write_all(&*chunk).await?;
            self.advance_pos(chunk_len);

            if Self::SAVE_STATE_PERIOD < last_save_time.elapsed() {
                log::debug!("Download checkpoint");
                self.task.current_size = Some(self.current_pos - file.buffer().len() as u64);
                self.persist_state().await?;
                last_save_time = Instant::now();
            }
        }

        Ok(())
    }
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

        let item = if self.task.lock_size == 0 {
            self.upload_empty().await?
        } else {
            let (sess, next_pos) = self.get_or_create_session().await?;
            self.upload_with_session(file, sess, next_pos).await?
        };

        log::debug!(
            "Finished uploading {} bytes of {:?}, remote: {}, id: {:?}",
            self.task.lock_size,
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
            "lastModifiedDateTime": self.task.lock_mtime.to_string(),
        })));
    }

    async fn persist_state(&self) -> Result<()> {
        self.state.lock().await.save_upload_state(&self.task)
    }

    async fn check_and_open_file(&mut self) -> Result<File> {
        let file = File::open(&self.task.src_path).await?;
        let meta = file.metadata().await?;

        let size = meta.len();
        let mtime = Time::from(meta.modified()?);
        log::debug!(
            "Previous locked size: {}, mtime: {:?}",
            self.task.lock_size,
            self.task.lock_mtime,
        );
        ensure!(
            size == self.task.lock_size && mtime == self.task.lock_mtime,
            "File changed since last add. Previous size and mtime: {}, {}; current: {}, {}",
            self.task.lock_size,
            self.task.lock_mtime,
            size,
            mtime,
        );

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
        let size = self.task.lock_size;
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
