use crate::state::{DownloadTask, State};
use anyhow::{ensure, Result};
use onedrive_api::{DriveLocation, ItemLocation, OneDrive};
use reqwest::{header, Client, StatusCode};
use std::{
    fs,
    io::{BufWriter, Seek, SeekFrom, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

// TODO: Download and upload concurrently.
pub async fn commit_download(mut state: State) -> Result<()> {
    let tasks = state.get_pending_download()?;
    let client = Client::new();
    println!("{} download task in total", tasks.len());
    for task in tasks {
        download_one(task, &mut state, &client).await?;
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
        "Start downloading {} bytes of {:?}, temp file: {}",
        task.size,
        task.item_id,
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
                let login = state.get_or_login().await?;
                let onedrive = OneDrive::new(login.token, DriveLocation::me());
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
        "Finished downloading {} bytes of {:?}",
        task.size,
        task.item_id,
    );

    filetime::set_file_mtime(&temp_file_path, task.remote_mtime.into())?;
    if let Some(parent) = task.target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(&temp_file_path, &task.target_path)?;

    state.finish_pending(task.pending_id)?;
    log::debug!(
        "Recovered mtime and placed {:?} to {}",
        task.item_id,
        task.target_path.display(),
    );

    Ok(())
}
