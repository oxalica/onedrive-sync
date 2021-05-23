use crate::state::{DownloadTask, OnedrivePath, State, Time, UploadTask};
use anyhow::{bail, ensure, Context, Error, Result};
use bytes::Bytes;
use colored::Colorize;
use futures::{channel::mpsc, SinkExt, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use onedrive_api::{
    option::DriveItemPutOption, resource::DriveItem, ConflictBehavior, ItemLocation, UploadSession,
};
use reqwest::{header, Client, StatusCode};
use std::{
    collections::HashSet,
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
    sync::{oneshot, Mutex, Semaphore},
};

// 15 Hz to match `indicatif`'s default.
const PROGRESS_REFRESH_DURATION: Duration = Duration::from_nanos(1_000_000_000 / 15);

const DOWNLOAD_CONCURRENCY: usize = 4;
const UPLOAD_CONCURRENCY: usize = 4;

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{msg} {bytes}/{total_bytes} {binary_bytes_per_sec} [{bar}] {percent}% ETA {eta_precise}")
        .progress_chars("=>-")
}

fn upload_dirs_progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{msg} [{pos}/{len} dirs] {per_sec} [{bar}] {percent}% ETA {eta_precise}")
        .progress_chars("=>-")
}

pub async fn commit(state: State, download: bool, upload: bool, show_progress: bool) -> Result<()> {
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

    let draw_target = if show_progress {
        ProgressDrawTarget::stderr()
    } else {
        ProgressDrawTarget::hidden()
    };
    let multi_bar = MultiProgress::with_draw_target(draw_target);

    let (mut dirs_bar, mut upload_progress, mut download_progress) = (None, None, None);
    if upload && !upload_tasks.is_empty() {
        let (dirs_bar_, progress) =
            start_upload_tasks(upload_tasks, state.clone(), client.clone(), show_progress).await?;
        if let Some(bar) = dirs_bar_ {
            dirs_bar = Some(bar.clone());
            multi_bar.add(bar);
        }
        multi_bar.add(progress.bar.clone());
        upload_progress = Some(progress);
    }
    if download && !download_tasks.is_empty() {
        let progress =
            start_download_tasks(download_tasks, state.clone(), client.clone(), show_progress);
        multi_bar.add(progress.bar.clone());
        download_progress = Some(progress);
    }

    let up_down_progress = download_progress.iter().chain(&upload_progress);

    {
        let _log_redirect_guard = match up_down_progress.clone().next() {
            None => return Ok(()),
            Some(prog) if show_progress => Some(
                crate::logger::LOGGER
                    .get()
                    .unwrap()
                    .attach_to(prog.bar.clone()),
            ),
            Some(_) => None,
        };
        multi_bar.join()?;
    }

    let mut failed = up_down_progress
        .map(|progress| progress.failed_tasks.load(Ordering::Relaxed))
        .sum::<usize>();
    if let Some(bar) = dirs_bar {
        if bar.position() != bar.length() {
            failed += (bar.length() - bar.position()) as usize;
            failed += upload_progress.as_ref().unwrap().total_tasks;
        }
    }
    ensure!(failed == 0, "{} tasks failed", failed);

    Ok(())
}

fn start_download_tasks(
    tasks: Vec<DownloadTask>,
    state: Arc<Mutex<State>>,
    client: Client,
    show_progress: bool,
) -> Arc<Progress> {
    let total_tasks = tasks.len();
    let total_bytes = tasks.iter().map(|task| task.size).sum();
    let progress = Arc::new(Progress::new(total_tasks, total_bytes, show_progress));

    let semaphore = Arc::new(Semaphore::new(DOWNLOAD_CONCURRENCY));
    for task in tasks {
        let download = Download::new(task, state.clone(), client.clone(), progress.clone());
        let semaphore = semaphore.clone();
        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            download.run().await
        });
    }

    let progress2 = progress.clone();
    tokio::spawn(async move {
        while progress2.update_bar("Downloading", "Download finished") {
            tokio::time::sleep(PROGRESS_REFRESH_DURATION).await;
        }
    });
    progress
}

async fn start_upload_tasks(
    tasks: Vec<UploadTask>,
    state: Arc<Mutex<State>>,
    client: Client,
    show_progress: bool,
) -> Result<(Option<ProgressBar>, Arc<Progress>)> {
    let missing_dirs = state
        .lock()
        .await
        .get_missing_ancestors_for_uploads(&tasks)?;
    let (dirs_bar, dirs_done_rx) = match missing_dirs.is_empty() {
        true => (None, None),
        false => {
            let (bar, rx) = start_upload_dirs(missing_dirs, state.clone());
            (Some(bar), Some(rx))
        }
    };

    let total_tasks = tasks.len();
    let total_bytes = tasks.iter().map(|task| task.lock_size).sum();
    let progress = Arc::new(Progress::new(total_tasks, total_bytes, show_progress));

    let progress2 = progress.clone();
    tokio::spawn(async move {
        if let Some(rx) = dirs_done_rx {
            progress2.bar.set_message("Waiting for dirs");
            if rx.await.is_err() {
                progress2.bar.finish_at_current_pos();
                return;
            }
        }

        let semaphore = Arc::new(Semaphore::new(UPLOAD_CONCURRENCY));
        for task in tasks {
            let upload = Upload::new(task, state.clone(), client.clone(), progress2.clone());
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                upload.run().await
            });
        }

        if show_progress {
            while progress2.update_bar("Uploading", "Upload finished") {
                tokio::time::sleep(PROGRESS_REFRESH_DURATION).await;
            }
        }
    });

    Ok((dirs_bar, progress))
}

fn start_upload_dirs(
    dirs: HashSet<OnedrivePath>,
    state: Arc<Mutex<State>>,
) -> (ProgressBar, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    let bar = ProgressBar::new(dirs.len() as u64).with_style(upload_dirs_progress_style());
    bar.set_message("Creating dirs");
    let bar2 = bar.clone();
    tokio::spawn(async move {
        match upload_dirs(dirs, state, &bar2).await {
            Ok(()) => {
                let _ = tx.send(());
            }
            Err(err) => {
                log::error!("Failed to create directories: {}", err);
                bar2.set_message("Create dirs failed");
                bar2.finish_at_current_pos();
            }
        }
    });
    (bar, rx)
}

// TODO: Batch request & concurrency.
async fn upload_dirs(
    dirs: HashSet<OnedrivePath>,
    state: Arc<Mutex<State>>,
    bar: &ProgressBar,
) -> Result<()> {
    let mut dirs = dirs.into_iter().collect::<Vec<_>>();
    dirs.sort_by(|a, b| Ord::cmp(&a.as_raw_str().len(), &b.as_raw_str().len()));

    let onedrive = state.lock().await.get_or_login().await?;
    for path in dirs {
        let (parent, name) = path.split_parent().expect("Root must exist");
        let item = onedrive
            .create_folder(ItemLocation::from_path(parent).unwrap(), name)
            .await?;
        state.lock().await.add_remote_dirs(&[item])?;
        bar.inc(1);
    }

    bar.finish_with_message("Dirs created");
    Ok(())
}

struct Progress {
    total_tasks: usize,
    running_tasks: AtomicUsize,
    complete_tasks: AtomicUsize,
    failed_tasks: AtomicUsize,
    total_bytes: AtomicU64,
    complete_bytes: AtomicU64,
    show_progress: bool,
    bar: ProgressBar,
}

impl Progress {
    fn new(total_tasks: usize, total_bytes: u64, show_progress: bool) -> Self {
        // The draw target here doesn't matter, since it will be attached to `MultiBar` later.
        let bar = ProgressBar::new(total_bytes).with_style(progress_style());
        Self {
            total_tasks,
            running_tasks: 0.into(),
            complete_tasks: 0.into(),
            failed_tasks: 0.into(),
            total_bytes: total_bytes.into(),
            complete_bytes: 0.into(),
            show_progress,
            bar,
        }
    }

    // Skip bytes already done. This decrease the total bytes.
    fn skip(&self, bytes: u64) {
        self.total_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.bar.reset_eta();
    }

    // Advance progress.
    fn advance(&self, bytes: u64) {
        self.complete_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn task_start(&self, msg: String) {
        if self.show_progress {
            log::debug!("{}", msg);
        } else {
            log::info!("{}", msg);
        }
        self.running_tasks.fetch_add(1, Ordering::Relaxed);
    }

    fn task_complete(&self, msg: String) {
        if self.show_progress {
            log::debug!("{}", msg);
        } else {
            log::info!("{}", msg);
        }
        // Print before finish.
        self.complete_tasks.fetch_add(1, Ordering::Release);

        self.running_tasks.fetch_sub(1, Ordering::Relaxed);
    }

    fn task_fail(&self, msg: String, skipped: u64, current: u64, total: u64) {
        log::error!("{}", msg);
        // Print before finish.
        self.failed_tasks.fetch_add(1, Ordering::Release);

        self.running_tasks.fetch_sub(1, Ordering::Relaxed);
        self.complete_bytes
            .fetch_sub(current - skipped, Ordering::Relaxed);
        self.total_bytes
            .fetch_sub(total - skipped, Ordering::Relaxed);
        self.bar.reset_eta();
    }

    // Upload progress bar and return `false` if finished.
    fn update_bar(&self, msg_running: &str, msg_done: &str) -> bool {
        // Make println to be emitted before `finish`.
        let completed = self.complete_tasks.load(Ordering::Acquire);
        let failed = self.failed_tasks.load(Ordering::Acquire);

        let running = self.running_tasks.load(Ordering::Relaxed);
        let bytes = self.complete_bytes.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);

        let finished = self.total_tasks == completed + failed && total_bytes == bytes;
        let msg = if finished { msg_done } else { msg_running };

        if failed == 0 {
            self.bar.set_message(format!(
                "{} [{}/{}/{} files]",
                msg,
                running.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks
            ));
        } else {
            self.bar.set_message(format!(
                "{} [{}/{}/{} files, {}]",
                msg,
                running.to_string().blue(),
                completed.to_string().green(),
                self.total_tasks,
                format!("{} failed", failed).red(),
            ));
        }
        self.bar.set_position(bytes);
        self.bar.set_length(total_bytes);
        if finished {
            self.bar.finish();
        }
        !finished
    }
}

struct Download {
    start_pos: u64,
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

    fn new(
        task: DownloadTask,
        state: Arc<Mutex<State>>,
        client: Client,
        progress: Arc<Progress>,
    ) -> Self {
        Self {
            start_pos: 0,
            current_pos: 0,
            task,
            state,
            client,
            progress,
        }
    }

    async fn run(mut self) {
        self.progress
            .task_start(format!("Downloading {}", self.task.dest_path.display()));
        match self.run_helper().await {
            Ok(()) => {
                assert_eq!(self.current_pos, self.task.size);
                self.progress
                    .task_complete(format!("Downloaded: {}", self.task.dest_path.display()));
            }
            Err(err) => {
                self.progress.task_fail(
                    format!(
                        "Download failed for {}: {}",
                        self.task.dest_path.display(),
                        err,
                    ),
                    self.start_pos,
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

        // File may already be downloaded, but failed to move to destination in the last time.
        if self.current_pos != self.task.size {
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

                let ret = self
                    .download(&mut file, self.task.url.clone().unwrap())
                    .await;

                // Always flush when download finished or failed.
                file.flush().await?;
                file.get_mut().sync_data().await?;
                self.task.current_size = Some(self.current_pos);
                self.persist_state().await?;

                match ret {
                    Ok(()) => break,
                    Err(err) if err.is::<std::io::Error>() => {
                        bail!("Unrecoverable IO error: {}", err)
                    }
                    Err(err) => {
                        log::error!("Download error (try {}/{}): {}", i, Self::MAX_RETRY, err)
                    }
                }
                tokio::time::sleep(Self::RETRY_DELAY).await;
            }
            ensure!(self.current_pos == self.task.size, "Too many retries");
        }

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
            match OpenOptions::new().write(true).open(&temp_path).await {
                Ok(mut file) => {
                    let got_size = file.metadata().await?.len();
                    if got_size == self.task.size {
                        file.seek(SeekFrom::Start(prev_pos)).await?;
                        self.start_pos = prev_pos;
                        self.current_pos = prev_pos;
                        self.progress.skip(prev_pos);
                        return Ok(file);
                    } else {
                        log::warn!(
                            "Temporary file length mismatch: got {}, expect {}. Discard it and re-download from start",
                            got_size,
                            self.task.size,
                        );
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    log::warn!("Temporary file missing. Re-download from start");
                }
                Err(err) => {
                    return Err(Error::from(err).context(format!(
                        "Failed open temporary file {}",
                        temp_path.display()
                    )))
                }
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
            self.current_pos += chunk_len;
            self.progress.advance(chunk_len);

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
    start_pos: u64,
}

impl Upload {
    const UPLOAD_PART_SIZE: usize = 64 << 20; // 64 MiB

    fn new(
        task: UploadTask,
        state: Arc<Mutex<State>>,
        client: Client,
        progress: Arc<Progress>,
    ) -> Self {
        Self {
            task,
            state,
            client,
            progress,
            uploaded_bytes: Arc::new(0.into()),
            start_pos: 0,
        }
    }

    async fn run(mut self) {
        self.progress
            .task_start(format!("Uploading: {}", self.task.src_path.display()));
        match self.run_helper().await {
            Ok(()) => {
                self.progress
                    .task_complete(format!("Uploaded: {}", self.task.src_path.display()));
            }
            Err(err) => {
                let msg = format!(
                    "Upload failed for {}: {}",
                    self.task.src_path.display(),
                    err,
                );
                let uploaded = Arc::try_unwrap(self.uploaded_bytes)
                    .expect("Upload request must be finished")
                    .into_inner();
                self.progress.task_fail(
                    msg,
                    self.start_pos,
                    self.start_pos + uploaded,
                    self.task.lock_size,
                );
            }
        }
    }

    async fn run_helper(&mut self) -> Result<()> {
        let file = self.check_and_open_file().await?;

        let item = if self.task.lock_size == 0 {
            self.upload_empty().await?
        } else {
            let (sess, next_pos) = self.get_or_create_session().await?;
            self.start_pos = next_pos;
            self.progress.skip(next_pos);
            self.upload_with_session(file, sess).await?
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
    ) -> Result<DriveItem> {
        let size = self.task.lock_size;
        assert!(self.start_pos < size);
        if self.start_pos != 0 {
            file.seek(SeekFrom::Start(self.start_pos)).await?;
        }

        let mut file_stream = FileReadStream::new(file);
        let mut item = None;

        for chunk_start in (self.start_pos..size).step_by(Self::UPLOAD_PART_SIZE) {
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
                progress.advance(len);
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
