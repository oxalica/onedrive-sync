use anyhow::{bail, ensure, Context, Result};
use onedrive_api::FileName;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use std::fmt;
use std::path::{Component, Path};
use std::str::FromStr;
use std::{borrow::Borrow, path::PathBuf};
use std::{ffi::OsStr, time::SystemTime};

/// A normalized and validated UTF8 absolute path for OneDrive in format `^(/[^/])*$` (empty for root)
/// without `.` or `..` in the middle.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct OnedrivePath(String);

impl OnedrivePath {
    pub fn validate_segment(segment: &OsStr) -> Result<&str> {
        ensure!(!segment.is_empty() && segment != "." && segment != "..");
        let segment = segment
            .to_str()
            .context("Non UTF8 path is not allowed for remote path")?;
        FileName::new(segment)
            .with_context(|| format!("Invalid file name for OneDrive: {:?}", segment))?;
        Ok(segment)
    }

    pub fn new(path: &Path) -> Result<Self> {
        let mut this = Self::default();
        for comp in path.components() {
            match comp {
                Component::Prefix(p) => bail!("Prefix is not allowed for remote path: {:?}", p),
                Component::ParentDir => bail!("`..` is not allowed for remote path"),
                Component::RootDir | Component::CurDir => {}
                Component::Normal(segment) => this.push(segment)?,
            }
        }
        Ok(this)
    }

    pub fn as_raw_str(&self) -> &str {
        &self.0
    }

    pub fn raw_ancestors(&self) -> impl Iterator<Item = &str> {
        std::iter::successors(Some(&*self.0), |s| {
            let idx = s.rfind('/')?;
            Some(&s[..idx])
        })
        .skip(1)
    }

    pub fn split_parent(&self) -> Option<(&str, &FileName)> {
        let idx = self.0.rfind('/')?;
        let parent = &self.0[..idx];
        let name = &self.0[idx + 1..];
        Some((parent, FileName::new(name).expect("Already checked")))
    }

    pub fn starts_with(&self, prefix: &Self) -> bool {
        let len = prefix.0.len();
        self.0.starts_with(&prefix.0) && self.0.as_bytes().get(len).map_or(true, |&b| b == b'/')
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.0.split('/').skip(1)
    }

    pub fn push(&mut self, segment: impl AsRef<OsStr>) -> Result<()> {
        self.0.push('/');
        self.0.push_str(Self::validate_segment(segment.as_ref())?);
        Ok(())
    }

    pub fn pop(&mut self) -> bool {
        if self.0.is_empty() {
            false
        } else {
            while self.0.pop() != Some('/') {}
            true
        }
    }

    /// Convert to a filesystem path under the given root.
    pub fn root_at(&self, root: impl Into<PathBuf>) -> PathBuf {
        if self.0.is_empty() {
            root.into()
        } else {
            root.into().join(&self.0[1..])
        }
    }

    pub fn relative_to(&self, cwd: &Self) -> String {
        if self.starts_with(cwd) {
            return format!(".{}", &self.0[cwd.0.len()..]);
        }
        let mut buf = String::new();
        for ancestor in cwd.raw_ancestors() {
            buf.push_str("../");
            if self.0.starts_with(ancestor)
                && self
                    .0
                    .as_bytes()
                    .get(ancestor.len())
                    .map_or(true, |&b| b == b'/')
            {
                if ancestor.len() < self.0.len() {
                    buf.push_str(&self.0[ancestor.len() + 1..]);
                } else {
                    buf.pop();
                }
                return buf;
            }
        }
        unreachable!()
    }

    pub fn join(&self, rhs: &Self) -> Self {
        // '/foo/bar' + '/baz/zab' -> '/foo/bar/baz/zab'
        Self(format!("{}{}", self.0, rhs.0))
    }

    pub fn join_str(&self, segment: &str) -> Result<Self> {
        let segment = Self::validate_segment(segment.as_ref())?;
        Ok(Self(format!("{}/{}", self.0, segment)))
    }

    pub fn join_os(&self, rhs: impl AsRef<Path>) -> Result<Self> {
        let mut this = self.clone();
        for comp in rhs.as_ref().components() {
            match comp {
                Component::Prefix(_) | Component::RootDir => {
                    bail!("Cannot reference file by absolute path")
                }
                Component::CurDir => {}
                Component::ParentDir => ensure!(this.pop(), "`..` gets out of sync root directory"),
                Component::Normal(segment) => this.push(segment)?,
            }
        }
        Ok(this)
    }
}

impl Borrow<str> for OnedrivePath {
    fn borrow(&self) -> &str {
        self.as_raw_str()
    }
}

impl fmt::Display for OnedrivePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("/")
        } else {
            self.0.fmt(f)
        }
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

impl<'de> serde::Deserialize<'de> for OnedrivePath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = <&str>::deserialize(deserializer)?;
        Self::new(Path::new(s)).map_err(D::Error::custom)
    }
}

/// A wrapper for `SystemTime` to pretty print, serialize and deserialize in RFC3339 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[cfg(test)]
mod test {
    use super::OnedrivePath;

    #[test]
    fn test_onedrive_path_relative_to() {
        #[track_caller]
        fn check(path: &str, cwd: &str, expect: &str) {
            let path = OnedrivePath::new(path.as_ref()).unwrap();
            let cwd = OnedrivePath::new(cwd.as_ref()).unwrap();
            assert_eq!(path.relative_to(&cwd), expect);
        }

        check("/foo/bar/baz", "/", "./foo/bar/baz");
        check("/foo/bar/baz", "/foo", "./bar/baz");
        check("/foo/bar/baz", "/foo/bar", "./baz");
        check("/foo/bar/baz", "/foo/bar/baz", ".");

        check("/foo/bar/baz", "/foo/bar/baz/aaa/bbb", "../..");
        check("/foo/bar/baz", "/foo/bar/baz/aaa", "..");
        check("/foo/bar/baz", "/foo/bar/aaa", "../baz");
        check("/foo/bar/baz", "/foo/bar/aaa/bbb", "../../baz");
        check("/foo/bar/baz", "/foo/aaa", "../bar/baz");
        check("/foo/bar/baz", "/foo/aaa/bbb", "../../bar/baz");
        check("/foo/bar/baz", "/aaa", "../foo/bar/baz");
        check("/foo/bar/baz", "/aaa/bbb", "../../foo/bar/baz");
    }
}
