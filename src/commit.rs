use crate::state::{DownloadTask, State, Time, UploadTask};
use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use colored::Colorize;
use futures::{channel::mpsc, SinkExt, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use onedrive_api::{
    option::DriveItemPutOption, resource::DriveItem, ConflictBehavior, ItemLocation, UploadSession,
};
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
const UPLOAD_CONCURRENCY: usize = 4;

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{msg} {bytes}/{total_bytes} {binary_bytes_per_sec} [{bar}] {percent}% ETA {eta_precise}")
        .progress_chars("=>-")
}

pub async fn commit(state: State, download: bool, upload: bool) -> Result<()> {
    let download_tasks = state.get_pending_download()?;
    let upload_tasks = state.get_pending_upload()?;

    // Pre-check for changed files.
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

    let multi_bar = MultiProgress::new();
    let (mut download_progress, mut upload_progress) = (None, None);
    if download && !download_tasks.is_empty() {
        let progress = start_download_tasks(download_tasks, state.clone(), client.clone());
        multi_bar.add(progress.bar.clone());
        download_progress = Some(progress);
    }
    if upload && !upload_tasks.is_empty() {
        let progress = start_upload_tasks(upload_tasks, state.clone(), client.clone());
        multi_bar.add(progress.bar.clone());
        upload_progress = Some(progress);
    }

    multi_bar.join()?;

    let failed = download_progress
        .iter()
        .chain(&upload_progress)
        .map(|progress| progress.failed_tasks.load(Ordering::Relaxed))
        .sum::<usize>();
    ensure!(failed == 0, "{} tasks failed", failed);

    Ok(())
}

fn start_download_tasks(
    tasks: Vec<DownloadTask>,
    state: Arc<Mutex<State>>,
    client: Client,
) -> Arc<Progress> {
    let total_tasks = tasks.len();
    let total_bytes = tasks.iter().map(|task| task.size).sum();
    let progress = Arc::new(Progress::new(total_tasks, total_bytes));

    let semaphore = Arc::new(Semaphore::new(DOWNLOAD_CONCURRENCY));
    for task in tasks {
        let download = Download {
            current_pos: 0,
            task,
            state: state.clone(),
            client: client.clone(),
            progress: progress.clone(),
        };
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            download.run().await
        });
    }

    let progress2 = progress.clone();
    tokio::spawn(async move {
        loop {
            let running_tasks = DOWNLOAD_CONCURRENCY - semaphore.available_permits();
            if progress2.update_bar("Download", running_tasks) {
                break;
            }
            tokio::time::sleep(PROGRESS_REFRESH_DURATION).await;
        }
    });
    progress
}

fn start_upload_tasks(
    tasks: Vec<UploadTask>,
    state: Arc<Mutex<State>>,
    client: Client,
) -> Arc<Progress> {
    let total_tasks = tasks.len();
    let total_bytes = tasks.iter().map(|task| task.lock_size).sum();
    let progress = Arc::new(Progress::new(total_tasks, total_bytes));

    // TODO: Create remote directories first.
    let semaphore = Arc::new(Semaphore::new(UPLOAD_CONCURRENCY));
    for task in tasks {
        let upload = Upload {
            task,
            state: state.clone(),
            client: client.clone(),
            progress: progress.clone(),
            uploaded_bytes: Arc::new(0.into()),
        };
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            upload.run().await
        });
    }

    let progress2 = progress.clone();
    tokio::spawn(async move {
        loop {
            let running_tasks = UPLOAD_CONCURRENCY - semaphore.available_permits();
            if progress2.update_bar("Upload  ", running_tasks) {
                break;
            }
            tokio::time::sleep(PROGRESS_REFRESH_DURATION).await;
        }
    });
    progress
}

struct Progress {
    total_tasks: usize,
    complete_tasks: AtomicUsize,
    failed_tasks: AtomicUsize,
    total_bytes: AtomicU64,
    complete_bytes: AtomicU64,
    bar: ProgressBar,
}

impl Progress {
    fn new(total_tasks: usize, total_bytes: u64) -> Self {
        let bar = ProgressBar::new(total_bytes).with_style(progress_style());
        Self {
            total_tasks,
            complete_tasks: 0.into(),
            failed_tasks: 0.into(),
            total_bytes: total_bytes.into(),
            complete_bytes: 0.into(),
            bar,
        }
    }

    fn advance(&self, bytes: u64, jump: bool) {
        self.complete_bytes.fetch_add(bytes, Ordering::Relaxed);
        if jump {
            log::debug!("Reset ETA");
            self.bar.reset_eta();
            self.bar.reset_elapsed();
        }
    }

    fn task_complete(&self) {
        self.complete_tasks.fetch_add(1, Ordering::Relaxed);
    }

    fn task_fail(&self, msg: String, current: u64, total: u64) {
        self.failed_tasks.fetch_add(1, Ordering::Relaxed);
        self.complete_bytes.fetch_sub(current, Ordering::Relaxed);
        self.total_bytes.fetch_sub(total, Ordering::Relaxed);
        self.bar.println(msg);
        self.bar.reset_eta();
        self.bar.reset_elapsed();
    }

    // Upload progress bar and return if completed.
    fn update_bar(&self, msg: &str, running_tasks: usize) -> bool {
        let completed = self.complete_tasks.load(Ordering::Relaxed);
        let failed = self.failed_tasks.load(Ordering::Relaxed);
        let bytes = self.complete_bytes.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);
        if failed == 0 {
            self.bar.set_message(format!(
                "{} [{}/{}/{} files]",
                msg,
                running_tasks.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks
            ));
        } else {
            self.bar.set_message(format!(
                "{} [{}/{}/{} files, {}]",
                msg,
                running_tasks.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks,
                format!("{} failed", failed).red(),
            ));
        }
        self.bar.set_position(bytes);
        let finished = self.total_tasks == completed + failed && total_bytes == bytes;
        if finished {
            self.bar.finish();
        }
        finished
    }
}

struct Download {
    current_pos: u64,
    task: DownloadTask,
    state: Arc<Mutex<State>>,
    client: Client,
    progress: Arc<Progress>,
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
                self.progress.task_complete();
            }
            Err(err) => {
                self.progress.task_fail(
                    format!(
                        "Download failed for {}: {}",
                        self.task.dest_path.display(),
                        err,
                    ),
                    self.current_pos,
                    self.task.size,
                );
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

    fn advance_pos(&mut self, n: u64, jump: bool) {
        self.current_pos += n;
        self.progress.advance(n, jump);
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
                self.advance_pos(prev_pos, true);
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
            self.advance_pos(chunk_len, false);

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
    progress: Arc<Progress>,
    uploaded_bytes: Arc<AtomicU64>,
}

impl Upload {
    const UPLOAD_PART_SIZE: usize = 64 << 20; // 64 MiB

    async fn run(mut self) {
        match self.run_helper().await {
            Ok(()) => {
                self.progress.task_complete();
            }
            Err(err) => {
                let msg = format!(
                    "Upload failed for {}: {}",
                    self.task.src_path.display(),
                    err,
                );
                let current = Arc::try_unwrap(self.uploaded_bytes)
                    .expect("Upload request must be finished")
                    .into_inner();
                self.progress.task_fail(msg, current, self.task.lock_size);
            }
        }
    }

    async fn run_helper(&mut self) -> Result<()> {
        let file = self.check_and_open_file().await?;

        let item = if self.task.lock_size == 0 {
            self.upload_empty().await?
        } else {
            let (sess, next_pos) = self.get_or_create_session().await?;
            self.uploaded_bytes.fetch_add(next_pos, Ordering::Relaxed);
            self.progress.advance(next_pos, true);
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
            assert_ne!(chunk_len, 0);

            log::debug!("Uploading {}..{}/{} bytes", chunk_start, chunk_end, size);

            let (tx, rx) = mpsc::channel(1);
            let uploaded_bytes = self.uploaded_bytes.clone();
            let progress = self.progress.clone();
            let monitored_body = rx.inspect(move |chunk: &Result<Bytes>| {
                let len = chunk.as_ref().map_or(0, |bytes| bytes.len()) as u64;
                log::trace!("Upload {} bytes", len);
                uploaded_bytes.fetch_add(len, Ordering::Relaxed);
                progress.advance(len, false);
            });

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
                .body(reqwest::Body::wrap_stream(monitored_body))
                .send();

            let ((), resp) = futures::join!(stream_fut, upload_fut);
            let resp: reqwest::Response = resp?;

            match resp.status() {
                StatusCode::ACCEPTED => {}
                StatusCode::CREATED | StatusCode::OK => {
                    item = Some(resp.json::<DriveItem>().await?)
                }
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
