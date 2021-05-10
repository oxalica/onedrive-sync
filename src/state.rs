use crate::tree::Tree;
use anyhow::{bail, Context, Result};
use onedrive_api::{
    option::CollectionOption,
    resource::{DriveItem, DriveItemField},
    Auth, ItemId, OneDrive, Permission,
};
use rusqlite::{named_params, params, types::Null, Connection};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime},
};

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
            DriveItemField::file,
            DriveItemField::file_system_info,
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
                    item.file_system_info
                        .as_ref()
                        .and_then(|v| v.get("lastModifiedDateTime")?.as_str())
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

    pub async fn get_or_login(&mut self) -> Result<LoginInfo> {
        let login: Option<LoginInfo> = Self::get_meta(&self.conn, Meta::LoginInfo)?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let login = match login {
            // FIXME: Refresh earlier?
            Some(login) if SystemTime::now() < login.token_expire_time => {
                log::debug!(
                    "Token still alive. Expiration time: {}",
                    humantime::format_rfc3339_nanos(login.token_expire_time)
                );
                login
            }
            Some(mut login) => {
                log::debug!(
                    "Token expired at {}, try refresh",
                    humantime::format_rfc3339_nanos(login.token_expire_time)
                );

                // FIXME: Dedup with login command?
                let auth = Auth::new(
                    login.client_id.clone(),
                    Permission::new_read().write(true).offline_access(true),
                    login.redirect_uri.clone(),
                );
                let token_resp = auth
                    .login_with_refresh_token(&login.refresh_token, None)
                    .await?;
                login.token = token_resp.access_token;
                login.refresh_token = token_resp.refresh_token.expect("Missing refresh token");
                login.token_expire_time =
                    SystemTime::now() + Duration::from_secs(token_resp.expires_in_secs);
                self.set_login_info(&login)?;
                log::debug!("New token saved");
                login
            }
            None => {
                bail!("No login info saved. Please run `onedrive-sync login` first");
            }
        };
        Ok(login)
    }

    pub fn set_login_info(&mut self, new_login: &LoginInfo) -> Result<()> {
        let json = serde_json::to_string(new_login)?;
        Self::set_meta(&self.conn, Meta::LoginInfo, &json)?;
        Ok(())
    }

    pub async fn sync_remote(&mut self, onedrive: &OneDrive, from_init: bool) -> Result<()> {
        let txn = self.conn.transaction()?;
        {
            let mut tracker = match Self::get_meta(&txn, Meta::DeltaUrl)? {
                Some(delta_url) if !from_init => {
                    // TODO: Large page.
                    onedrive
                        .track_root_changes_from_delta_url(&delta_url)
                        .await?
                }
                _ => {
                    onedrive
                        .track_root_changes_from_initial_with_option(Item::options())
                        .await?
                }
            };
            let fetch_time = SystemTime::now();

            if from_init {
                log::debug!("Clear all items in database (--from-init)");
                txn.execute(r"DELETE FROM `items`", [])?;
            }

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
                                ":mtime": humantime::format_rfc3339_nanos(mtime).to_string(),
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
                &humantime::format_rfc3339_nanos(fetch_time).to_string(),
            )?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_tree(&self) -> Result<Tree> {
        let mut stmt = self.conn.prepare(r"SELECT * FROM `items`")?;
        let items = stmt
            .query_and_then([], |row| {
                let content = match row.get("is_directory")? {
                    true => ItemContent::Directory,
                    false => ItemContent::File {
                        size: row.get("size")?,
                        mtime: humantime::parse_rfc3339(&row.get::<_, String>("mtime")?)?,
                        sha1: row.get("sha1")?,
                    },
                };
                Ok(Item {
                    id: ItemId(row.get("id")?),
                    name: row.get("name")?,
                    parent: row.get::<_, Option<String>>("parent")?.map(ItemId),
                    content,
                })
            })?
            .collect::<Result<Vec<_>>>()?;
        Ok(Tree::from_items(items).expect("Invalid remote state"))
    }
}
