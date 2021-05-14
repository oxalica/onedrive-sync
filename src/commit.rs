use crate::state::{DownloadTask, State, UploadTask};
use anyhow::{bail, ensure, Context, Result};
use onedrive_api::{
    option::DriveItemPutOption, resource::DriveItem, ConflictBehavior, ItemLocation, UploadSession,
};
use reqwest::{header, Client, StatusCode};
use std::{
    fs,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

// TODO: Download and upload concurrently.
pub async fn commit_download(state: &mut State) -> Result<()> {
    let tasks = state.get_pending_download()?;
    let client = Client::new();
    println!("{} download task in total", tasks.len());
    for task in tasks {
        download_one(task, state, &client).await?;
    }
    Ok(())
}

pub async fn commit_upload(state: &mut State) -> Result<()> {
    let tasks = state.get_pending_upload()?;
    let client = Client::new();
    println!("{} upload task in total", tasks.len());
    for task in tasks {
        upload_one(task, state, &client).await?;
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
        "Start downloading {} bytes of {:?}, target: {:?}, temp file: {}",
        task.size,
        task.item_id,
        task.target_path.display(),
        temp_file_path.display(),
    );

    let (file, mut pos) = match task.current_size {
        Some(current_size) => {
            log::debug!(
                "Recover from partial download {}/{}",
                current_size,
                task.size
            );
            let mut file = fs::OpenOptions::new().write(true).open(&temp_file_path)?;
            assert_eq!(file.metadata()?.len(), task.size);
            assert!(current_size <= task.size);
            file.seek(SeekFrom::Start(current_size))?;
            (file, current_size)
        }
        None => {
            log::debug!("Fresh download");
            if let Some(parent) = temp_file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let file = fs::OpenOptions::new()
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
        "Finished downloading {} bytes of {:?}, target: {:?}",
        task.size,
        task.item_id,
        task.target_path.display(),
    );

    // TODO: atime?
    filetime::set_file_mtime(&temp_file_path, task.remote_mtime.into())?;
    if let Some(parent) = task.target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // TODO: No replace.
    fs::rename(&temp_file_path, &task.target_path)?;

    state.finish_download(task.pending_id)?;
    log::debug!(
        "Recovered mtime and placed {:?} to {}",
        task.item_id,
        task.target_path.display(),
    );

    Ok(())
}

async fn upload_one(mut task: UploadTask, state: &mut State, client: &Client) -> Result<()> {
    const UPLOAD_PART_SIZE: usize = 4 << 20; // 4 MiB

    let mut file = fs::File::open(&task.local_path)?;
    let meta = file.metadata()?;

    let size = meta.len();
    let mtime = meta.modified()?;
    match (task.lock_size, task.lock_mtime) {
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
            task.lock_size = Some(size);
            task.lock_mtime = Some(mtime);
            state.save_upload_state(&task)?;
        }
        _ => unreachable!(),
    }

    log::debug!(
        "Start uploading {} bytes of {}, remote: {}",
        size,
        task.local_path.display(),
        task.remote_path,
    );

    let (sess, start_pos) = match &task.session_url {
        Some(url) => {
            let sess = UploadSession::from_upload_url(url.to_owned());
            // TODO: Check expiration?
            let meta = sess.get_meta(client).await?;
            let pos = match &meta.next_expected_ranges[..] {
                [r] => r.start,
                ranges => bail!("Invalid next_expected_ranges: {:?}", ranges),
            };
            log::debug!("Resumed upload at {}, meta: {:?}", pos, meta);
            (sess, pos)
        }
        None => {
            let onedrive = state.get_or_login().await?;
            let mut initial = DriveItem::default();
            initial.file_system_info = Some(Box::new(serde_json::json!({
                "lastModifiedDateTime": humantime::format_rfc3339_nanos(mtime).to_string(),
            })));
            // TODO: Save expiration time?
            let (sess, _meta) = onedrive
                .new_upload_session_with_initial_option(
                    ItemLocation::from_path(&task.remote_path).context("Invalid remote path")?,
                    &initial,
                    // FIXME: Also use ctag?
                    DriveItemPutOption::new().conflict_behavior(ConflictBehavior::Replace),
                )
                .await?;
            task.session_url = Some(sess.upload_url().to_owned());
            state.save_upload_state(&task)?;
            (sess, 0)
        }
    };

    assert!(start_pos <= size);
    file.seek(SeekFrom::Start(start_pos))?;
    let mut file = BufReader::new(file);

    let mut buf = vec![0u8; UPLOAD_PART_SIZE];
    let mut item = None;

    for chunk_start in (start_pos..size).step_by(UPLOAD_PART_SIZE) {
        let chunk_end = chunk_start
            .saturating_add(UPLOAD_PART_SIZE as u64)
            .min(size);
        let chunk_len = (chunk_end - chunk_start) as usize;

        log::debug!("Uploading {}..{}/{} bytes", chunk_start, chunk_end, size);

        file.read_exact(&mut buf[..chunk_len])?;
        let ret = sess
            .upload_part(
                bytes::Bytes::copy_from_slice(&buf[..chunk_len]),
                chunk_start..chunk_end,
                size,
                client,
            )
            .await?;
        assert_eq!(ret.is_some(), chunk_end == size);
        item = ret;
    }

    let item = item.unwrap();
    state.finish_upload(task.pending_id, &item)?;
    log::debug!(
        "Finished uploading {} bytes of {:?}, remote: {}, id: {:?}",
        size,
        task.local_path.display(),
        task.remote_path,
        item.id,
    );

    Ok(())
}
