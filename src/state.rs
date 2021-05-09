use anyhow::{Context, Result};
use onedrive_api::{
    option::CollectionOption,
    resource::{DriveItem, DriveItemField},
    ItemId, OneDrive,
};
use rusqlite::{named_params, params, types::Null, Connection};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::SystemTime};

#[derive(Debug)]
pub struct State {
    conn: rusqlite::Connection,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginInfo {
    pub client_id: String,
    pub redirect_uri: String,
    pub refresh_token: String,
    pub token: String,
    pub token_expire_time: SystemTime,
}

#[derive(Debug, Clone, Copy, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum Meta {
    LoginInfo,
    DeltaUrl,
    DeltaUrlTime,
}

#[derive(Debug, Clone)]
pub struct Item {
    pub id: ItemId,
    pub name: String,
    pub parent: Option<ItemId>,
    pub content: ItemContent,
}

#[derive(Debug, Clone)]
pub enum ItemContent {
    File {
        size: u64,
        mtime: SystemTime,
        sha1: String,
    },
    Directory,
}

impl Item {
    fn options() -> CollectionOption<DriveItemField> {
        CollectionOption::new().select(&[
            DriveItemField::id,
            DriveItemField::name,
            DriveItemField::size,
            DriveItemField::last_modified_date_time,
            DriveItemField::file,
            DriveItemField::parent_reference,
            DriveItemField::root,
        ])
    }

    fn parse_raw_item(item: &DriveItem) -> Result<Self> {
        let parent = match item.root.is_some() {
            true => None,
            false => Some(
                item.parent_reference
                    .as_ref()
                    .and_then(|v| v.get("id")?.as_str())
                    .map(|s| ItemId(s.to_owned()))
                    .context("Missing parent id")?,
            ),
        };

        let is_file = item.file.is_some();
        let content = match is_file {
            false => ItemContent::Directory,
            true => ItemContent::File {
                size: item.size.context("Missing size for file")? as u64,
                mtime: humantime::parse_rfc3339(
                    item.last_modified_date_time
                        .as_ref()
                        .context("Missing mtime for file")?,
                )?,
                sha1: item
                    .file
                    .as_ref()
                    .and_then(|v| v.get("hashes")?.get("sha1Hash")?.as_str())
                    .context("Missing sha1 for file")?
                    .to_owned(),
            },
        };

        Ok(Self {
            id: item.id.clone().context("Missing id")?,
            name: item.name.clone().context("Missing name")?,
            parent,
            content,
        })
    }
}

impl State {
    pub fn new(state_file: &Path) -> Result<Self> {
        // TODO: Exclusive?
        if let Some(parent) = state_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = rusqlite::Connection::open(&state_file)?;
        conn.execute_batch(include_str!("./schema.sql"))?;
        Ok(Self { conn })
    }

    fn get_meta(conn: &Connection, key: Meta) -> Result<Option<String>> {
        conn.query_row_and_then(
            r"SELECT `value` FROM `meta` WHERE `key` = ?",
            params![<&'static str>::from(key)],
            |row| row.get(0).map_err(Into::into),
        )
    }

    fn set_meta(conn: &Connection, key: Meta, value: &str) -> Result<()> {
        let affected = conn.execute(
            r"UPDATE `meta` SET `value` = ? WHERE `key` = ?",
            params![value, <&'static str>::from(key)],
        )?;
        assert_eq!(affected, 1);
        Ok(())
    }

    pub fn get_login_info(&self) -> Result<Option<LoginInfo>> {
        Self::get_meta(&self.conn, Meta::LoginInfo)?
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(Into::into)
    }

    pub fn set_login_info(&mut self, new_login: &LoginInfo) -> Result<()> {
        let json = serde_json::to_string(new_login)?;
        Self::set_meta(&self.conn, Meta::LoginInfo, &json)?;
        Ok(())
    }

    pub async fn sync_remote(&mut self, onedrive: &OneDrive) -> Result<()> {
        let txn = self.conn.transaction()?;
        {
            let mut tracker = match Self::get_meta(&txn, Meta::DeltaUrl)? {
                Some(delta_url) => {
                    onedrive
                        .track_root_changes_from_delta_url(&delta_url)
                        .await?
                }
                None => {
                    onedrive
                        .track_root_changes_from_initial_with_option(Item::options())
                        .await?
                }
            };
            let fetch_time = SystemTime::now();

            let mut stmt = txn.prepare(
                r"
                    INSERT OR REPLACE INTO `items`
                    (`id`, `name`, `parent`, `is_directory`, `size`, `mtime`, `sha1`)
                    VALUES
                    (:id, :name, :parent, :is_directory, :size, :mtime, :sha1)
                ",
            )?;

            let mut pages = 0usize;
            while let Some(page) = tracker.fetch_next_page(&onedrive).await? {
                log::info!("Fetched page {}", pages);
                pages += 1;

                for raw_item in page {
                    let item = Item::parse_raw_item(&raw_item)
                        .with_context(|| format!("Cannot parse item: {:?}", raw_item))?;
                    match item.content {
                        ItemContent::Directory => {
                            stmt.insert(named_params! {
                                ":id": item.id.0,
                                ":name": item.name,
                                ":parent": item.parent.as_ref().map(|id| &id.0),
                                ":is_directory": true,
                                ":size": Null,
                                ":mtime": Null,
                                ":sha1": Null,
                            })?;
                        }
                        ItemContent::File { size, mtime, sha1 } => {
                            stmt.insert(named_params! {
                                ":id": item.id.0,
                                ":name": item.name,
                                ":parent": item.parent.as_ref().map(|id| &id.0),
                                ":is_directory": false,
                                ":size": size,
                                ":mtime": humantime::format_rfc3339_seconds(mtime).to_string(),
                                ":sha1": sha1,
                            })?;
                        }
                    }
                }
            }

            let delta_url = tracker.delta_url().expect("Missing delta url").to_owned();
            Self::set_meta(&txn, Meta::DeltaUrl, &delta_url)?;
            Self::set_meta(
                &txn,
                Meta::DeltaUrlTime,
                &humantime::format_rfc3339_seconds(fetch_time).to_string(),
            )?;
        }
        txn.commit()?;
        Ok(())
    }
}
