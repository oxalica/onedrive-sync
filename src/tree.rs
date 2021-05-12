use crate::state;
use anyhow::{bail, ensure, Context, Result};
use onedrive_api::ItemId;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    ops::Deref,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime},
};

#[derive(Debug)]
pub struct Tree {
    root: TreeNode,
}

#[derive(Debug)]
pub enum TreeNode {
    File {
        id: ItemId,
        size: u64,
        mtime: SystemTime,
        sha1: String,
    },
    Directory {
        id: ItemId,
        children: BTreeMap<String, TreeNode>,
    },
}

impl TreeNode {
    pub fn id(&self) -> &ItemId {
        match self {
            Self::File { id, .. } | Self::Directory { id, .. } => id,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File { .. })
    }

    pub fn children(&self) -> Option<&BTreeMap<String, TreeNode>> {
        match self {
            Self::Directory { children, .. } => Some(children),
            Self::File { .. } => None,
        }
    }

    pub fn walk(&self, path: &mut RelativePath, cb: &mut impl FnMut(&TreeNode, &RelativePath)) {
        cb(self, path);
        if let Some(children) = self.children() {
            for (name, child) in children {
                path.push(name);
                child.walk(path, cb);
                path.pop();
            }
        }
    }
}

impl Tree {
    pub fn from_items(iter: impl IntoIterator<Item = state::Item>) -> Result<Self> {
        let items = iter
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect::<HashMap<_, _>>();

        let mut children_map: HashMap<ItemId, Vec<ItemId>> = HashMap::new();
        for item in items.values() {
            if let Some(parent) = &item.parent {
                children_map
                    .entry(parent.clone())
                    .or_default()
                    .push(item.id.clone());
            }
        }

        let root = items
            .values()
            .find(|item| item.parent.is_none())
            .context("Missing root")?;

        fn build(
            item: &state::Item,
            items: &HashMap<ItemId, state::Item>,
            children_map: &HashMap<ItemId, Vec<ItemId>>,
        ) -> Result<TreeNode> {
            Ok(match item.content {
                state::ItemContent::Directory => TreeNode::Directory {
                    id: item.id.clone(),
                    children: match children_map.get(&item.id) {
                        None => Default::default(),
                        Some(ids) => ids
                            .iter()
                            .map(|id| {
                                let item = items.get(id).context("Missing id")?;
                                Ok((item.name.clone(), build(item, items, children_map)?))
                            })
                            .collect::<Result<_>>()?,
                    },
                },
                state::ItemContent::File {
                    size,
                    mtime,
                    ref sha1,
                    ..
                } => TreeNode::File {
                    id: item.id.clone(),
                    size,
                    mtime,
                    sha1: sha1.clone(),
                },
            })
        }

        let root = build(root, &items, &children_map)?;
        Ok(Self { root })
    }

    pub fn resolve(&self, path: &RelativePath) -> Option<&TreeNode> {
        let mut cur = &self.root;
        for segment in path.iter() {
            cur = cur.children()?.get(segment)?;
        }
        Some(cur)
    }

    pub fn diff(&self, dir: impl AsRef<Path>) -> Result<Vec<Diff>> {
        let mut ret = Vec::new();
        diff_helper(&self.root, &mut dir.as_ref().to_owned(), &mut ret)?;
        Ok(ret)
    }
}

fn diff_helper(node: &TreeNode, path: &mut PathBuf, out: &mut Vec<Diff>) -> Result<()> {
    let meta = std::fs::symlink_metadata(&*path)?;
    ensure!(
        meta.is_dir() || meta.is_file(),
        "Unsupported file type: {:?}",
        meta.file_type(),
    );

    match (&node, meta.is_dir()) {
        (TreeNode::Directory { .. }, false) => {
            out.push(Diff::DirToFile(path.to_owned()));
        }
        (TreeNode::File { .. }, true) => {
            out.push(Diff::FileToDir(path.to_owned()));
        }
        // TODO: Check sha1.
        (TreeNode::File { size, mtime, .. }, false) => {
            let local_mtime = meta.modified()?;
            if *size != meta.len() || !eq_time(*mtime, local_mtime) {
                out.push(Diff::Modify(path.to_owned()));
            }
        }
        (TreeNode::Directory { children, .. }, true) => {
            let local_children = std::fs::read_dir(&*path)?
                .map(|entry| {
                    let name = entry?.file_name();
                    let name = name.to_str().with_context(|| {
                        format!("Non-UTF8 file {:?} found in {}", name, path.display())
                    })?;
                    Ok(name.to_owned())
                })
                .collect::<Result<BTreeSet<String>>>()?;

            for (name, child) in children {
                // Some special folders has empty name. Skip them.
                if name.is_empty() {
                    continue;
                }
                if local_children.contains(name) {
                    path.push(name);
                    diff_helper(child, path, out)?;
                    path.pop();
                } else {
                    out.push(Diff::Remove(path.join(name)));
                }
            }

            for name in &local_children {
                if !children.contains_key(name) {
                    out.push(Diff::Add(path.join(name)));
                }
            }
        }
    }
    Ok(())
}

// `fileSystemInfo` has time resolution of 0.001s, or 1ms. Sub-ms digits will be rounded.
fn eq_time(a: SystemTime, b: SystemTime) -> bool {
    let dt = a.duration_since(b).or(b.duration_since(a)).unwrap();
    dt <= Duration::from_millis(1)
}

#[derive(Debug)]
pub enum Diff {
    Add(PathBuf),
    Remove(PathBuf),
    Modify(PathBuf),
    DirToFile(PathBuf),
    FileToDir(PathBuf),
}

impl Diff {
    pub fn path(&self) -> &Path {
        match self {
            Self::Add(p)
            | Self::Remove(p)
            | Self::Modify(p)
            | Self::DirToFile(p)
            | Self::FileToDir(p) => p,
        }
    }
}

/// A normalized UTF8 relative path in format `^[.](/[^/])*$` and have no `.` or `..` in the middle.
#[derive(Debug, Clone)]
pub struct RelativePath(String);

impl RelativePath {
    pub fn new(path: &Path) -> Result<Self> {
        let mut buf = ".".to_owned();
        for comp in path.components() {
            match comp {
                Component::Prefix(_) | Component::RootDir => {
                    bail!("Absolute path is not allowed for remote path")
                }
                Component::ParentDir => bail!("`..` is not allowed for remote path"),
                Component::CurDir => {}
                Component::Normal(part) => {
                    let part = part
                        .to_str()
                        .context("Non UTF8 path is not allowed for remote path")?;
                    // `Path::components` already filters empty components out.
                    assert!(!part.is_empty() && part != "." && part != "..");
                    buf.push('/');
                    buf.push_str(part);
                }
            }
        }
        Ok(Self(buf))
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.0.split('/').skip(1)
    }

    pub fn push(&mut self, segment: &str) {
        assert!(!segment.is_empty() && segment != "." && segment != ".." && !segment.contains("/"));
        self.0.push('/');
        self.0.push_str(segment);
    }

    pub fn pop(&mut self) {
        assert!(self.0 != ".");
        while self.0.pop() != Some('/') {}
    }
}

impl Deref for RelativePath {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
