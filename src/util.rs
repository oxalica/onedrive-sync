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

    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
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

    /// Construct from raw string returrned by `as_raw_str`.
    /// This method is stricter than `new` and will emit error for loose format.
    pub fn from_raw(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if !raw.is_empty() {
            ensure!(raw.starts_with('/'), "Invalid raw path: {:?}", raw);
            ensure!(
                raw.split('/')
                    .skip(1)
                    .all(|segment| Self::validate_segment(segment.as_ref()).is_ok()),
                "Invalid raw path: {:?}",
                raw
            );
        }
        Ok(Self(raw))
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
        let segment = Self::validate_segment(segment.as_ref())?;
        self.0.push('/');
        self.0.push_str(segment);
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
        self.as_raw_str().to_sql()
    }
}

impl FromSql for OnedrivePath {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Self::from_raw(value.as_str()?.to_owned()).map_err(|err| FromSqlError::Other(err.into()))
    }
}

impl<'de> serde::Deserialize<'de> for OnedrivePath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        Self::from_raw(s).map_err(D::Error::custom)
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
mod onedrive_path_test {
    use super::OnedrivePath;
    use std::path::Path;

    fn new(s: &str) -> OnedrivePath {
        OnedrivePath::new(s).unwrap()
    }

    #[test]
    fn test_default() {
        let a = OnedrivePath::default();
        let b = new("/");
        assert!(a.0.is_empty());
        assert!(b.0.is_empty());
    }

    #[test]
    fn test_validate_segment() {
        let validate = |s: &str| OnedrivePath::validate_segment(s.as_ref()).map(|s| s.to_owned());
        assert_eq!(validate("foo").unwrap(), "foo");
        assert_eq!(validate(".bar").unwrap(), ".bar");
        assert!(validate("").is_err());
        assert!(validate(".").is_err());
        assert!(validate("..").is_err());
        assert!(validate("a:b").is_err());
        assert!(validate("a/b").is_err());
    }

    #[test]
    fn test_new() {
        let new = |s: &str| OnedrivePath::new(s).map(|s| s.0);
        assert_eq!(new("foo").unwrap(), "/foo");
        assert_eq!(new("").unwrap(), "");
        assert_eq!(new("/").unwrap(), "");
        assert_eq!(new(".").unwrap(), "");
        assert_eq!(new("/foo").unwrap(), "/foo");
        assert_eq!(new("//foo//").unwrap(), "/foo");
        assert_eq!(new("./foo/.//bar/..hidden").unwrap(), "/foo/bar/..hidden");

        assert!(new("..").is_err());
        assert!(new("./foo/..").is_err());
        assert!(new("./foo/../bar").is_err());
    }

    #[test]
    fn test_from_raw() {
        assert_eq!(OnedrivePath::from_raw("").unwrap().0, "");
        assert_eq!(OnedrivePath::from_raw("/foo").unwrap().0, "/foo");
        assert!(OnedrivePath::from_raw("foo").is_err());
        assert!(OnedrivePath::from_raw("/").is_err());
        assert!(OnedrivePath::from_raw("/foo/").is_err());
        assert!(OnedrivePath::from_raw("/foo/./bar").is_err());
    }

    #[test]
    fn test_ancestors() {
        let ancestors = |s: &str| {
            new(s)
                .raw_ancestors()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>()
        };

        assert_eq!(ancestors("/"), &[] as &[&str]);
        assert_eq!(ancestors("/foo"), &[""]);
        assert_eq!(ancestors("/foo/bar"), &["/foo", ""]);
        assert_eq!(ancestors("/a/b/c/d"), &["/a/b/c", "/a/b", "/a", ""]);
    }

    #[test]
    fn test_split_parent() {
        assert!(new("/").split_parent().is_none());

        let p = new("/foo");
        let (parent, name) = p.split_parent().unwrap();
        assert_eq!(parent, "");
        assert_eq!(name.as_str(), "foo");

        let p = new("/foo/bar/baz");
        let (parent, name) = p.split_parent().unwrap();
        assert_eq!(parent, "/foo/bar");
        assert_eq!(name.as_str(), "baz");
    }

    #[test]
    fn test_starts_with() {
        let starts_with = |a: &str, b: &str| new(a).starts_with(&new(b));

        assert!(starts_with("/", "/"));
        assert!(!starts_with("/", "/foo"));
        assert!(starts_with("/foo/bar", "/foo/bar"));

        assert!(starts_with("/foo/bar", "/"));
        assert!(!starts_with("/foo/bar", "/fo"));
        assert!(starts_with("/foo/bar", "/foo"));
        assert!(!starts_with("/foo/bar", "/foo/ba"));
        assert!(starts_with("/foo/bar", "/foo/bar"));
        assert!(!starts_with("/foo/bar", "/foo/bar/baz"));
    }

    #[test]
    fn test_iter() {
        let iters = |s: &str| new(s).iter().map(|s| s.to_owned()).collect::<Vec<_>>();

        assert_eq!(iters("/"), &[] as &[&str]);
        assert_eq!(iters("/foo"), &["foo"]);
        assert_eq!(iters("/foo/bar"), &["foo", "bar"]);
    }

    #[test]
    fn test_push_pop() {
        let mut p = new("/");
        assert!(p.push("foo").is_ok());
        assert!(p.push(".").is_err());
        assert!(p.push("..").is_err());
        assert!(p.push("...").is_ok());
        assert!(p.push(".foo").is_ok());
        assert_eq!(p.0, "/foo/.../.foo");
        assert!(p.pop());
        assert_eq!(p.0, "/foo/...");
        assert!(p.pop());
        assert_eq!(p.0, "/foo");
        assert!(p.pop());
        assert_eq!(p.0, "");
        assert!(!p.pop());
        assert_eq!(p.0, "");
    }

    #[test]
    fn test_root_at() {
        assert_eq!(new("/").root_at("/foo"), Path::new("/foo"));
        assert_eq!(new("/foo/bar").root_at("/baz"), Path::new("/baz/foo/bar"));
    }

    #[test]
    fn test_relative_to() {
        #[track_caller]
        fn check(path: &str, cwd: &str, expect: &str) {
            assert_eq!(new(path).relative_to(&new(cwd)), expect);
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

    #[test]
    fn test_join_self() {
        let join = |a: &str, b: &str| new(a).join(&new(b)).0;
        assert_eq!(join("", ""), "");
        assert_eq!(join("/foo", ""), "/foo");
        assert_eq!(join("", "/foo"), "/foo");
        assert_eq!(join("/foo", "/bar"), "/foo/bar");
    }

    #[test]
    fn test_join_str() {
        let join = |a: &str, b: &str| new(a).join_str(b).map(|p| p.0);
        assert_eq!(join("/", "foo").unwrap(), "/foo");
        assert_eq!(join("/foo", "bar").unwrap(), "/foo/bar");
        assert!(join("/", "").is_err());
        assert!(join("/", "a:b").is_err());
        assert!(join("/foo", "bar/baz").is_err());
    }

    #[test]
    fn test_join_os() {
        let join = |a: &str, b: &str| new(a).join_os(b).map(|s| s.0);
        assert!(join("/", "/").is_err());
        assert!(join("/", "/foo/bar").is_err());
        assert!(join("/", "..").is_err());
        assert_eq!(join("/", ".").unwrap(), "");
        assert_eq!(join("/", "foo/bar").unwrap(), "/foo/bar");
        assert_eq!(join("/", "./foo/bar").unwrap(), "/foo/bar");
        assert_eq!(join("/foo/bar", "baz").unwrap(), "/foo/bar/baz");
        assert_eq!(join("/foo/bar", "..").unwrap(), "/foo");
        assert_eq!(
            join("/foo/bar", "./../hello/../wtf/./deep").unwrap(),
            "/foo/wtf/deep",
        );
        assert_eq!(join("/foo/bar", "../../root/..").unwrap(), "");
        assert!(join("/foo/bar", "../../root/../..").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(new("/").to_string(), "/");
        assert_eq!(new("/foo").to_string(), "/foo");
        assert_eq!(new("/foo/bar/").to_string(), "/foo/bar");
    }

    #[test]
    fn test_de() {
        #[derive(Debug, PartialEq, Eq, serde::Deserialize)]
        struct Foo {
            a: OnedrivePath,
        }

        assert_eq!(
            serde_json::from_str::<Foo>(r#"{"a":""}"#).unwrap(),
            Foo { a: new("") },
        );
        assert_eq!(
            serde_json::from_str::<Foo>(r#"{"a":"/foo/bar"}"#).unwrap(),
            Foo { a: new("/foo/bar") },
        );
        assert!(serde_json::from_str::<Foo>(r#"{"a":".."}"#).is_err());
        assert!(serde_json::from_str::<Foo>(r#"{"a":"foo/bar"}"#).is_err());
    }
}

#[cfg(test)]
mod time_test {
    use super::Time;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_to_from_str() {
        let s = "2020-05-23T18:30:15.123456789Z";
        let sys = SystemTime::UNIX_EPOCH + Duration::new(1590258615, 123456789);
        assert_eq!(Time::from(sys).to_string(), s);
        assert_eq!(SystemTime::from(s.parse::<Time>().unwrap()), sys);
    }
}
