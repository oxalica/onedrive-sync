use crate::tree::Tree;
use anyhow::{bail, ensure, Context, Result};
use onedrive_api::{
    option::CollectionOption,
    resource::{DriveItem, DriveItemField},
    Auth, FileName, ItemId, OneDrive, Permission, Tag,
};
use rusqlite::{
    named_params, params,
    types::Null,
    types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    Connection, ToSql,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    ops::Deref,
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime},
};
use strum::{EnumString, IntoStaticStr};

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
                mtime: Time(humantime::parse_rfc3339(
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

/// A normalized and validated UTF8 path for OneDrive in format `^[.](/[^/])*$` without `.` or `..` in the middle.
#[derive(Debug, Clone)]
pub struct OnedrivePath(String);

impl OnedrivePath {
    pub fn new(path: &Path) -> Result<Self> {
        let mut buf = ".".to_owned();
        for comp in path.components() {
            match comp {
                Component::Prefix(_) | Component::RootDir => {
                    bail!("Absolute path is not allowed for remote path")
                }
                Component::ParentDir => bail!("`..` is not allowed for remote path"),
                Component::CurDir => {}
                Component::Normal(segment) => {
                    let segment = segment
                        .to_str()
                        .context("Non UTF8 path is not allowed for remote path")?;
                    FileName::new(segment).with_context(|| {
                        format!("Invalid file name for OneDrive: {:?}", segment)
                    })?;
                    // `Path::components` already filters empty components out.
                    assert!(!segment.is_empty() && segment != "." && segment != "..");
                    buf.push('/');
                    buf.push_str(segment);
                }
            }
        }
        Ok(Self(buf))
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.0.split('/').skip(1)
    }

    pub fn push(&mut self, segment: &str) {
        assert!(
            !segment.is_empty() && segment != "." && segment != ".." && !segment.contains("/"),
            "Invalid path segment: {:?}",
            segment,
        );
        self.0.push('/');
        self.0.push_str(segment);
    }

    pub fn pop(&mut self) {
        assert!(self.0 != ".");
        while self.0.pop() != Some('/') {}
    }
}

impl Deref for OnedrivePath {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for OnedrivePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl rusqlite::ToSql for OnedrivePath {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for OnedrivePath {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::new(Path::new(&String::column_result(value)?))
            .map_err(|err| FromSqlError::Other(err.into()))
    }
}

/// A wrapper for `SystemTime` to pretty print, serialize and deserialize in RFC3339 format.
#[derive(Debug, Clone, Copy)]
pub struct Time(SystemTime);

impl From<SystemTime> for Time {
    fn from(t: SystemTime) -> Self {
        Self(t)
    }
}

impl From<Time> for SystemTime {
    fn from(t: Time) -> Self {
        t.0
    }
}

impl FromStr for Time {
    type Err = humantime::TimestampError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        humantime::parse_rfc3339(s).map(Self)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        humantime::format_rfc3339_nanos(self.0).fmt(f)
    }
}

impl ToSql for Time {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(self.to_string().into()))
    }
}

impl FromSql for Time {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        String::column_result(value)?
            .parse::<Self>()
            .map_err(|err| FromSqlError::Other(err.into()))
    }
}

#[derive(Debug)]
pub struct Pending {
    pub op: PendingOp,
    pub item_id: Option<ItemId>,
    pub local_path: OnedrivePath,
}

#[derive(Debug, Clone, Copy, IntoStaticStr, EnumString)]
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

#[derive(Debug)]
pub struct DownloadTask {
    pub pending_id: i64,
    pub item_id: ItemId,
    pub target_path: PathBuf,
    pub remote_mtime: SystemTime,
    pub size: u64,
    pub ctag: Tag,
    pub url: Option<String>,
    pub current_size: Option<u64>,
}

#[derive(Debug)]
pub struct UploadTask {
    pub pending_id: i64,
    pub remote_path: String,
    pub local_path: PathBuf,
    pub lock_size: Option<u64>,
    pub lock_mtime: Option<SystemTime>,
    pub session_url: Option<String>,
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

    // TODO: Return OneDrive?
    pub async fn get_or_login(&mut self) -> Result<LoginInfo> {
        let login: Option<LoginInfo> = Self::get_meta(&self.conn, Meta::LoginInfo)?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let login = match login {
            // FIXME: Refresh earlier?
            Some(login) if SystemTime::now() < login.token_expire_time => {
                log::debug!(
                    "Token still alive. Expiration time: {}",
                    Time(login.token_expire_time),
                );
                login
            }
            Some(mut login) => {
                log::debug!(
                    "Token expired at {}, try refresh",
                    Time(login.token_expire_time)
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
            Self::set_meta(&txn, Meta::DeltaUrlTime, &Time(fetch_time).to_string())?;
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
            let mut stmt = txn.prepare(
                r"
                    INSERT INTO `pending`
                        (`item_id`, `local_path`, `operation`)
                        VALUES
                        (:item_id, :local_path, :operation)
                ",
            )?;
            for pending in pendings {
                stmt.insert(named_params! {
                    ":item_id": pending.item_id.as_ref().map(|id| &id.0),
                    ":local_path": pending.local_path,
                    ":operation": pending.op,
                })?;
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
                ":prefix": &**prefix,
            },
        )?;
        ensure!(affected != 0, "Not queued: {}", prefix);
        Ok(affected)
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
                    // TODO: Relative to sync root?
                    target_path: PathBuf::from(".").join(row.get::<_, String>("local_path")?),
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
                let path = row.get::<_, String>("local_path")?;
                assert!(path.starts_with("./"), "Must be a file starting with `./`");
                Ok(UploadTask {
                    pending_id: row.get("pending_id")?,
                    // TODO: Relative to sync root?
                    remote_path: path[1..].to_owned(),
                    local_path: PathBuf::from(".").join(&path),
                    lock_size: row.get("lock_size")?,
                    lock_mtime: row
                        .get::<_, Option<String>>("lock_mtime")?
                        .map(|tm| humantime::parse_rfc3339(&tm))
                        .transpose()?,
                    session_url: row.get("session_url")?,
                })
            })?
            .collect::<Result<Vec<_>>>()
    }

    /// Save `url`, `current_size` for a running download.
    pub fn save_upload_state(&mut self, task: &UploadTask) -> Result<()> {
        self.conn.execute(
            r"
                INSERT OR REPLACE INTO `upload`
                    (`pending_id`, `lock_size`, `lock_mtime`, `session_url`)
                    VALUES
                    (:pending_id, :lock_size, :lock_mtime, :session_url)
            ",
            named_params! {
                ":pending_id": task.pending_id,
                ":lock_size": task.lock_size,
                ":lock_mtime": task.lock_mtime.map(|tm| humantime::format_rfc3339_nanos(tm).to_string()),
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
                        INSERT OR REPLACE INTO `item`
                        (`item_id`, `item_name`, `parent_item_id`, `is_directory`, `size`, `ctag`, `mtime`, `sha1`)
                        VALUES
                        (:item_id, :item_name, :parent_item_id, :is_directory, :size, :ctag, :mtime, :sha1)
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
}
