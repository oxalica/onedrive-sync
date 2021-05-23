use crate::{
    config::Config,
    tree::Tree,
    util::{OnedrivePath, Time},
};
use anyhow::{bail, ensure, Context, Result};
use onedrive_api::{
    option::CollectionOption,
    resource::{DriveItem, DriveItemField},
    Auth, DriveLocation, ItemId, OneDrive, Permission, Tag,
};
use rusqlite::{
    named_params, params,
    types::Null,
    types::{FromSqlError, FromSqlResult, ValueRef},
    Connection,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use strum::{EnumString, IntoStaticStr};

#[derive(Debug)]
pub struct State {
    conn: rusqlite::Connection,
    root_dir: PathBuf,
    config: Config,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginInfo {
    pub client_id: String,
    pub redirect_uri: String,
    pub refresh_token: String,
    pub token: String,
    pub token_expire_time: SystemTime,
}

#[derive(Debug, Clone, Copy, IntoStaticStr)]
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
        ctag: Tag,
        mtime: Time,
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
            DriveItemField::c_tag,
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
                ctag: item.c_tag.clone().context("Missing c_tag")?,
                mtime: Time::from(humantime::parse_rfc3339(
                    item.file_system_info
                        .as_ref()
                        .and_then(|v| v.get("lastModifiedDateTime")?.as_str())
                        .context("Missing mtime for file")?,
                )?),
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

#[derive(Debug)]
pub enum Pending {
    Download {
        local_path: OnedrivePath,
        item_id: ItemId,
    },
    Upload {
        local_path: OnedrivePath,
        lock_size: u64,
        lock_mtime: Time,
    },
}

impl Pending {
    pub fn local_path(&self) -> &OnedrivePath {
        match self {
            Self::Download { local_path, .. } | Self::Upload { local_path, .. } => local_path,
        }
    }

    pub fn operation(&self) -> PendingOp {
        match self {
            Pending::Download { .. } => PendingOp::Download,
            Pending::Upload { .. } => PendingOp::Upload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum PendingOp {
    Download,
    Upload,
}

impl rusqlite::ToSql for PendingOp {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(<&'static str>::from(self).into())
    }
}

impl rusqlite::types::FromSql for PendingOp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        value
            .as_str()?
            .parse()
            .map_err(|err| FromSqlError::Other(Box::new(err)))
    }
}

#[derive(Debug)]
pub struct DownloadTask {
    pub pending_id: i64,
    pub item_id: ItemId,
    pub dest_path: PathBuf,
    pub remote_mtime: SystemTime,
    pub size: u64,
    pub ctag: Tag,
    pub url: Option<String>,
    pub current_size: Option<u64>,
}

#[derive(Debug)]
pub struct UploadTask {
    pub pending_id: i64,
    pub remote_path: OnedrivePath,
    pub src_path: PathBuf,
    pub lock_size: u64,
    pub lock_mtime: Time,
    pub session_url: Option<String>,
}

impl State {
    // TODO: Put database under sync root?
    // TODO: Should login be allowed outside sync dir?
    pub fn new(search_dir: impl AsRef<Path>, state_file: impl AsRef<Path>) -> Result<Self> {
        let (root_dir, config) = Config::find_root_and_load(search_dir)?;
        log::debug!(
            "Find root dir: {}, config: {:?}",
            root_dir.display(),
            config,
        );

        let state_file = state_file.as_ref();
        if let Some(parent) = state_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = rusqlite::Connection::open(&state_file)?;
        conn.execute_batch(include_str!("./schema.sql"))?;
        Ok(Self {
            conn,
            root_dir,
            config,
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn config(&self) -> &Config {
        &self.config
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

    // TODO: Return OneDrive?
    pub async fn get_or_login(&mut self) -> Result<OneDrive> {
        let login: Option<LoginInfo> = Self::get_meta(&self.conn, Meta::LoginInfo)?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let login = match login {
            // FIXME: Refresh earlier?
            Some(login) if SystemTime::now() < login.token_expire_time => {
                log::debug!(
                    "Token still alive. Expiration time: {}",
                    Time::from(login.token_expire_time),
                );
                login
            }
            Some(mut login) => {
                log::debug!(
                    "Token expired at {}, try refresh",
                    Time::from(login.token_expire_time)
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
        // TODO: Timeout?
        let onedrive = OneDrive::new(login.token, DriveLocation::me());
        Ok(onedrive)
    }

    pub fn set_login_info(&mut self, new_login: &LoginInfo) -> Result<()> {
        let json = serde_json::to_string(new_login)?;
        Self::set_meta(&self.conn, Meta::LoginInfo, &json)?;
        Ok(())
    }

    // TODO: Handle conflicts with pending operations.
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
                txn.execute(r"DELETE FROM `item`", [])?;
            }

            let mut stmt = txn.prepare(
                r"
                    INSERT OR REPLACE INTO `item`
                    (`item_id`, `item_name`, `parent_item_id`, `is_directory`, `size`, `ctag`, `mtime`, `sha1`)
                    VALUES
                    (:item_id, :item_name, :parent, :is_directory, :size, :ctag, :mtime, :sha1)
                ",
            )?;

            let mut pages = 0usize;
            while let Some(page) = tracker.fetch_next_page(&onedrive).await? {
                log::info!("Fetched page {}", pages);
                pages += 1;

                for raw_item in page {
                    // TODO: Deleted.
                    let item = Item::parse_raw_item(&raw_item)
                        .with_context(|| format!("Cannot parse item: {:?}", raw_item))?;
                    match item.content {
                        ItemContent::Directory => {
                            stmt.insert(named_params! {
                                ":item_id": item.id.0,
                                ":item_name": item.name,
                                ":parent": item.parent.as_ref().map(|id| &id.0),
                                ":is_directory": true,
                                ":size": Null,
                                ":ctag": Null,
                                ":mtime": Null,
                                ":sha1": Null,
                            })?;
                        }
                        ItemContent::File {
                            size,
                            ctag,
                            mtime,
                            sha1,
                        } => {
                            stmt.insert(named_params! {
                                ":item_id": item.id.0,
                                ":item_name": item.name,
                                ":parent": item.parent.as_ref().map(|id| &id.0),
                                ":is_directory": false,
                                ":size": size,
                                ":ctag": ctag.0,
                                ":mtime": mtime,
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
                &Time::from(fetch_time).to_string(),
            )?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_tree(&self) -> Result<Tree> {
        let mut stmt = self.conn.prepare(r"SELECT * FROM `item`")?;
        let items = stmt
            .query_and_then([], |row| {
                let content = match row.get("is_directory")? {
                    true => ItemContent::Directory,
                    false => ItemContent::File {
                        size: row.get("size")?,
                        ctag: Tag(row.get("ctag")?),
                        mtime: row.get("mtime")?,
                        sha1: row.get("sha1")?,
                    },
                };
                Ok(Item {
                    id: ItemId(row.get("item_id")?),
                    name: row.get("item_name")?,
                    parent: row.get::<_, Option<String>>("parent_item_id")?.map(ItemId),
                    content,
                })
            })?
            .collect::<Result<Vec<_>>>()?;
        Ok(Tree::from_items(items).expect("Invalid remote state"))
    }

    pub fn queue_pending(&mut self, pendings: impl IntoIterator<Item = Pending>) -> Result<()> {
        let txn = self.conn.transaction()?;
        {
            // We should delete child paths first, in case of conflict between directory and file.
            let mut stmt_del = txn.prepare(
                r"
                    DELETE FROM `pending`
                        WHERE SUBSTR(`local_path`, 1, LENGTH(:prefix) + 1) = :prefix || '/'
                ",
            )?;
            let mut stmt_ins = txn.prepare(
                r"
                    INSERT OR REPLACE INTO `pending`
                        (`operation`, `local_path`, `item_id`, `lock_size`, `lock_mtime`)
                        VALUES
                        (:operation, :local_path, :item_id, :lock_size, :lock_mtime)
                ",
            )?;
            for pending in pendings {
                stmt_del.execute(named_params! {
                    ":prefix": pending.local_path(),
                })?;
                match pending {
                    Pending::Download {
                        local_path,
                        item_id,
                    } => {
                        stmt_ins.insert(named_params! {
                            ":operation": PendingOp::Download,
                            ":local_path": local_path,
                            ":item_id": item_id.0,
                            ":lock_size": Null,
                            ":lock_mtime": Null,
                        })?;
                    }
                    Pending::Upload {
                        local_path,
                        lock_size,
                        lock_mtime,
                    } => {
                        stmt_ins.insert(named_params! {
                            ":operation": PendingOp::Upload,
                            ":local_path": local_path,
                            ":item_id": Null,
                            ":lock_size": lock_size,
                            ":lock_mtime": lock_mtime,
                        })?;
                    }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn unqueue_pending(&mut self, prefix: &OnedrivePath) -> Result<usize> {
        let affected = self.conn.execute(
            r"
                DELETE FROM `pending`
                    WHERE `local_path` = :prefix
                        OR SUBSTR(`local_path`, 1, LENGTH(:prefix) + 1) = :prefix || '/'
            ",
            named_params! {
                ":prefix": prefix.as_raw_str(),
            },
        )?;
        ensure!(affected != 0, "Not queued: {}", prefix);
        Ok(affected)
    }

    pub fn get_pending(&self) -> Result<Vec<Pending>> {
        self.conn
            .prepare(r"SELECT * FROM `pending`")?
            .query_and_then([], |row| match row.get::<_, PendingOp>("operation")? {
                PendingOp::Download => Ok(Pending::Download {
                    local_path: row.get("local_path")?,
                    item_id: ItemId(row.get("item_id")?),
                }),
                PendingOp::Upload => Ok(Pending::Upload {
                    local_path: row.get("local_path")?,
                    lock_size: row.get("lock_size")?,
                    lock_mtime: row.get("lock_mtime")?,
                }),
            })?
            .collect()
    }

    pub fn get_pending_download(&self) -> Result<Vec<DownloadTask>> {
        self.conn
            .prepare(
                r"
                SELECT `pending_id`, `item_id`, `local_path`, `mtime`, `size`, `ctag`, `url`, `current_size`
                    FROM `pending`
                    INNER JOIN `item` USING (`item_id`)
                    LEFT OUTER JOIN `download` USING (`pending_id`)
                    WHERE `operation` = ?
            ",
            )?
            .query_and_then(params![PendingOp::Download], |row| {
                Ok(DownloadTask {
                    pending_id: row.get("pending_id")?,
                    item_id: ItemId(row.get("item_id")?),
                    dest_path: row.get::<_, OnedrivePath>("local_path")?.root_at(&self.root_dir),
                    remote_mtime: humantime::parse_rfc3339(&row.get::<_, String>("mtime")?)?,
                    size: row.get("size")?,
                    ctag: Tag(row.get("ctag")?),
                    url: row.get("url")?,
                    current_size: row.get("current_size")?,
                })
            })?
            .collect::<Result<Vec<_>>>()
    }

    /// Save `url`, `current_size` for a running download.
    pub fn save_download_state(&mut self, task: &DownloadTask) -> Result<()> {
        self.conn.execute(
            r"
                INSERT OR REPLACE INTO `download`
                    (`pending_id`, `url`, `current_size`)
                    VALUES
                    (:pending_id, :url, :current_size)
            ",
            named_params! {
                ":pending_id": task.pending_id,
                ":url": task.url,
                ":current_size": task.current_size.expect("current_size should not be None"),
            },
        )?;
        Ok(())
    }

    pub fn finish_download(&mut self, pending_id: i64) -> Result<()> {
        let affected = self.conn.execute(
            r"
                DELETE FROM `pending`
                    WHERE `pending_id` = ? AND `operation` = ?
            ",
            params![pending_id, PendingOp::Download],
        )?;
        ensure!(affected == 1, "Pending download {} not found", pending_id);
        Ok(())
    }

    pub fn get_pending_upload(&self) -> Result<Vec<UploadTask>> {
        self.conn
            .prepare(
                r"
                SELECT `pending_id`, `local_path`, `lock_size`, `lock_mtime`, `session_url`
                    FROM `pending`
                    LEFT OUTER JOIN `upload` USING (`pending_id`)
                    WHERE `operation` = ?
            ",
            )?
            .query_and_then(params![PendingOp::Upload], |row| {
                let local_path: OnedrivePath = row.get("local_path")?;
                Ok(UploadTask {
                    pending_id: row.get("pending_id")?,
                    remote_path: self.config.onedrive.remote_path.join(&local_path),
                    src_path: local_path.root_at(&self.root_dir),
                    lock_size: row.get("lock_size")?,
                    lock_mtime: row.get("lock_mtime")?,
                    session_url: row.get("session_url")?,
                })
            })?
            .collect::<Result<Vec<_>>>()
    }

    /// Save `session_url` for a running download.
    pub fn save_upload_state(&mut self, task: &UploadTask) -> Result<()> {
        self.conn.execute(
            r"
                INSERT OR REPLACE INTO `upload`
                    (`pending_id`, `session_url`)
                    VALUES
                    (:pending_id, :session_url)
            ",
            named_params! {
                ":pending_id": task.pending_id,
                ":session_url": task.session_url,
            },
        )?;
        Ok(())
    }

    pub fn finish_upload(&mut self, pending_id: i64, item: &DriveItem) -> Result<()> {
        let item = Item::parse_raw_item(item)?;

        let txn = self.conn.transaction()?;

        let affected = txn.execute(
            r"
                DELETE FROM `pending`
                    WHERE `pending_id` = ? AND `operation` = ?
            ",
            params![pending_id, PendingOp::Upload],
        )?;
        ensure!(affected == 1, "Pending upload {} not found", pending_id);

        // TODO: Merge this with `sync_remote`.
        match item.content {
            ItemContent::Directory => unreachable!(),
            ItemContent::File {
                size,
                ctag,
                mtime,
                sha1,
            } => {
                txn.execute(
                    r"
                        INSERT INTO `item`
                        (`item_id`, `item_name`, `parent_item_id`, `is_directory`, `size`, `ctag`, `mtime`, `sha1`)
                        VALUES
                        (:item_id, :item_name, :parent_item_id, :is_directory, :size, :ctag, :mtime, :sha1)
                        ON CONFLICT (`item_id`) DO UPDATE SET
                            `item_name` = :item_name,
                            `size` = :size,
                            `ctag` = :ctag,
                            `mtime` = :mtime,
                            `sha1` = :sha1
                    ",
                    named_params! {
                        ":item_id": item.id.0,
                        ":item_name": item.name,
                        ":parent_item_id": item.parent.as_ref().map(|id| &id.0),
                        ":is_directory": false,
                        ":size": size,
                        ":ctag": ctag.0,
                        ":mtime": mtime,
                        ":sha1": sha1,
                    }
                )?;
            }
        }

        txn.commit()?;
        Ok(())
    }

    /// Returns all paths of directories which need to be created before upload (missing remote ancestors).
    ///
    /// Onedrive API *DOES* automatically create ancestors, but we need to follow foreign key restriction
    /// when inserting newly uploaded items into database.
    pub fn get_missing_ancestors_for_uploads(
        &self,
        tasks: &[UploadTask],
    ) -> Result<HashSet<OnedrivePath>> {
        let mut remote_dirs = HashSet::new();
        self.get_tree()?
            .walk(&OnedrivePath::default(), |node, path| {
                if node.is_directory() {
                    remote_dirs.insert(path.as_raw_str().to_owned());
                }
            });

        Ok(tasks
            .iter()
            .flat_map(|task| task.remote_path.raw_ancestors())
            .filter(|dir| !remote_dirs.contains(*dir))
            .map(|dir| OnedrivePath::from_raw(dir).unwrap())
            .collect())
    }

    pub fn add_remote_dirs(&mut self, items: &[DriveItem]) -> Result<()> {
        let mut stmt = self.conn.prepare(
            r"
                INSERT INTO `item`
                (`item_id`, `item_name`, `parent_item_id`, `is_directory`, `size`, `ctag`, `mtime`, `sha1`)
                VALUES
                (:item_id, :item_name, :parent_item_id, TRUE, NULL, NULL, NULL, NULL)
            ",
        )?;
        for item in items {
            let item = Item::parse_raw_item(item)?;
            assert!(matches!(item.content, ItemContent::Directory));
            stmt.execute(named_params! {
                ":item_id": item.id.0,
                ":item_name": item.name,
                ":parent_item_id": item.parent.as_ref().expect("Cannot create root").0,
            })?;
        }
        Ok(())
    }
}
