use crate::state::OnedrivePath;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub onedrive: OnedriveConfig,
}

#[derive(Default, Debug, Deserialize)]
pub struct OnedriveConfig {
    #[serde(default)]
    pub remote_path: OnedrivePath,
}

impl Config {
    const FILE_NAME: &'static str = "onedrive-sync.toml";

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn find_root_and_load(search_dir: impl AsRef<Path>) -> Result<(PathBuf, Self)> {
        for dir in fs::canonicalize(search_dir)?.ancestors() {
            let path = dir.join(Self::FILE_NAME);
            if path.exists() {
                let config = Self::load(&path)?;
                return Ok((dir.to_owned(), config));
            }
        }
        bail!(
            "Cannot find `{}` in any ancestor, please create one to mark the root directory for onedrive-sync",
            Self::FILE_NAME,
        );
    }
}
