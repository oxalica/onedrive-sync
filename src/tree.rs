use crate::{
    state,
    util::{OnedrivePath, Time},
};
use anyhow::{ensure, Context, Result};
use onedrive_api::ItemId;
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

pub enum Tree {
    File {
        item_id: Option<ItemId>,
        size: u64,
        mtime: Time,
        sha1: Option<String>,
    },
    Directory {
        item_id: Option<ItemId>,
        children: BTreeMap<String, Tree>,
    },
}

// Do not recurse into children unless `{:#?}` is used.
impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File {
                item_id,
                size,
                mtime,
                sha1,
            } => f
                .debug_struct("File")
                .field("item_id", item_id)
                .field("size", size)
                .field("mtime", mtime)
                .field("sha1", sha1)
                .finish(),
            Self::Directory { item_id, children } => {
                let is_alternative = f.alternate();
                let mut d = f.debug_struct("Directory");
                d.field("item_id", &item_id);
                if is_alternative {
                    d.field("children", &children);
                } else {
                    d.field("children", &children.keys());
                }
                d.finish()
            }
        }
    }
}

impl Tree {
    pub fn item_id(&self) -> Option<&ItemId> {
        match self {
            Self::File { item_id, .. } | Self::Directory { item_id, .. } => item_id.as_ref(),
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File { .. })
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }

    pub fn children(&self) -> Option<&BTreeMap<String, Tree>> {
        match self {
            Self::Directory { children, .. } => Some(children),
            Self::File { .. } => None,
        }
    }

    fn total_size(&self) -> u64 {
        match self {
            Self::File { size, .. } => *size,
            Self::Directory { children, .. } => {
                children.values().map(|node| node.total_size()).sum()
            }
        }
    }

    pub fn calc_attr(&self) -> SimpleAttr {
        match self {
            Self::File { size, mtime, .. } => SimpleAttr {
                is_directory: false,
                size: *size,
                mtime: Some(*mtime),
            },
            Self::Directory { .. } => SimpleAttr {
                is_directory: true,
                size: self.total_size(),
                mtime: None,
            },
        }
    }

    pub fn resolve(&self, path: &OnedrivePath) -> Option<&Self> {
        let mut cur = self;
        for segment in path.iter() {
            cur = cur.children()?.get(segment)?;
        }
        Some(cur)
    }

    pub fn walk(&self, path: &OnedrivePath, mut cb: impl FnMut(&Tree, &OnedrivePath)) {
        self.walk_helper(&mut path.clone(), &mut cb);
    }

    fn walk_helper(&self, path: &mut OnedrivePath, cb: &mut impl FnMut(&Tree, &OnedrivePath)) {
        cb(self, path);
        if let Some(children) = self.children() {
            for (name, child) in children {
                path.push(name).expect("Remote name must be valid");
                child.walk_helper(path, cb);
                path.pop();
            }
        }
    }

    pub fn from_items(iter: impl IntoIterator<Item = state::Item>) -> Result<Self> {
        let items = iter
            .into_iter()
            // Special directories has empty name, which is invalid.
            .filter(|item| !item.name.is_empty())
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

        Self::from_items_helper(root, &items, &children_map)
    }

    fn from_items_helper(
        item: &state::Item,
        items: &HashMap<ItemId, state::Item>,
        children_map: &HashMap<ItemId, Vec<ItemId>>,
    ) -> Result<Tree> {
        match item.content {
            state::ItemContent::Directory => Ok(Tree::Directory {
                item_id: Some(item.id.clone()),
                children: match children_map.get(&item.id) {
                    None => Default::default(),
                    Some(ids) => ids
                        .iter()
                        .map(|id| {
                            let item = items.get(id).context("Missing id")?;
                            let tree = Self::from_items_helper(item, items, children_map)?;
                            Ok((item.name.clone(), tree))
                        })
                        .collect::<Result<_>>()?,
                },
            }),
            state::ItemContent::File {
                size,
                mtime,
                ref sha1,
                ..
            } => Ok(Tree::File {
                item_id: Some(item.id.clone()),
                size,
                mtime,
                sha1: Some(sha1.clone()),
            }),
        }
    }

    pub fn scan_recursive(path: impl AsRef<Path>) -> Result<Self> {
        Self::scan_recursive_helper(&mut path.as_ref().to_owned())
    }

    fn scan_recursive_helper(path: &mut PathBuf) -> Result<Self> {
        let meta = std::fs::metadata(&*path)?;
        ensure!(
            meta.is_file() || meta.is_dir(),
            "Unsupported file type: {:?}",
            meta.file_type(),
        );

        if meta.is_file() {
            Ok(Tree::File {
                item_id: None,
                mtime: meta.modified()?.into(),
                size: meta.len(),
                sha1: None,
            })
        } else {
            let mut children = BTreeMap::new();
            for entry in std::fs::read_dir(&*path)? {
                // Readdir failure is a hard error.
                let entry = entry?;
                let name = entry.file_name();
                match (|| -> Result<_> {
                    let name = OnedrivePath::validate_segment(&name)?;
                    path.push(name);
                    let ret = Self::scan_recursive_helper(path);
                    path.pop();
                    Ok((name, ret?))
                })() {
                    Ok((name, tree)) => {
                        children.insert(name.to_owned(), tree);
                    }
                    Err(err) => {
                        log::warn!("Skipped {:?} of {}: {}", name, path.display(), err);
                    }
                }
            }
            Ok(Tree::Directory {
                item_id: None,
                children,
            })
        }
    }

    pub fn diff<'a>(&'a self, rhs: &'a Self, prefix: &OnedrivePath) -> Vec<Diff<'a>> {
        let mut visitor = DiffVisitor {
            path: prefix.clone(),
            diffs: Vec::new(),
        };
        treediff::diff(self, rhs, &mut visitor);
        visitor.diffs
    }
}

impl treediff::Value for Tree {
    type Key = String;
    type Item = Tree;
    fn items<'a>(&'a self) -> Option<Box<dyn Iterator<Item = (Self::Key, &'a Self::Item)> + 'a>> {
        self.children()
            .map(|children| Box::new(children.iter().map(|(k, v)| (k.clone(), v))) as _)
    }
}

// For treediff.
// Return false on directories to always check recursively and never yield `unchanged` for them.
impl PartialEq<Tree> for Tree {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::File {
                    size: size1,
                    mtime: mtime1,
                    ..
                },
                Self::File {
                    size: size2,
                    mtime: mtime2,
                    ..
                },
            ) => size1 == size2 && eq_time((*mtime1).into(), (*mtime2).into()),
            _ => false,
        }
    }
}

struct DiffVisitor<'a> {
    path: OnedrivePath,
    diffs: Vec<Diff<'a>>,
}

impl<'a> treediff::Delegate<'a, String, Tree> for DiffVisitor<'a> {
    fn push<'b>(&mut self, k: &'b String) {
        self.path.push(k).expect("Names from tree must be valid");
    }

    fn pop(&mut self) {
        self.path.pop();
    }

    fn removed<'b>(&mut self, k: &'b String, lhs: &'a Tree) {
        self.diffs.push(Diff::Left {
            path: self.path.join_str(k).expect("Already checked"),
            lhs,
        });
    }

    fn added<'b>(&mut self, k: &'b String, rhs: &'a Tree) {
        self.diffs.push(Diff::Right {
            path: self.path.join_str(k).expect("Already checked"),
            rhs,
        });
    }

    fn modified(&mut self, lhs: &'a Tree, rhs: &'a Tree) {
        self.diffs.push(Diff::Conflict {
            path: self.path.clone(),
            lhs,
            rhs,
        });
    }
}

// `fileSystemInfo` has time resolution of 0.001s, or 1ms. Sub-ms digits will be rounded.
fn eq_time(a: SystemTime, b: SystemTime) -> bool {
    let dt = a.duration_since(b).or(b.duration_since(a)).unwrap();
    dt <= Duration::from_millis(1)
}

/// Diff of one path.
/// The `path` here relative to sync root dir.
#[derive(Debug)]
pub enum Diff<'a> {
    Left {
        path: OnedrivePath,
        lhs: &'a Tree,
    },
    Right {
        path: OnedrivePath,
        rhs: &'a Tree,
    },
    Conflict {
        path: OnedrivePath,
        lhs: &'a Tree,
        rhs: &'a Tree,
    },
}

impl<'a> Diff<'a> {
    pub fn path(&self) -> &OnedrivePath {
        match self {
            Self::Left { path, .. } | Self::Right { path, .. } | Self::Conflict { path, .. } => {
                path
            }
        }
    }

    pub fn lhs(&self) -> Option<&'a Tree> {
        match self {
            Self::Left { lhs, .. } | Self::Conflict { lhs, .. } => Some(lhs),
            Self::Right { .. } => None,
        }
    }

    pub fn rhs(&self) -> Option<&'a Tree> {
        match self {
            Self::Right { rhs, .. } | Self::Conflict { rhs, .. } => Some(rhs),
            Self::Left { .. } => None,
        }
    }

    pub fn into_left(self) -> Result<Self, Self> {
        match self {
            this @ Self::Left { .. } => Ok(this),
            this @ Self::Right { .. } => Err(this),
            Self::Conflict { path, lhs, .. } => Ok(Self::Left { path, lhs }),
        }
    }

    pub fn into_right(self) -> Result<Self, Self> {
        match self {
            this @ Self::Left { .. } => Err(this),
            this @ Self::Right { .. } => Ok(this),
            Self::Conflict { path, rhs, .. } => Ok(Self::Right { path, rhs }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SimpleAttr {
    pub is_directory: bool,
    pub size: u64,
    /// Directory mtime is not tracked.
    pub mtime: Option<Time>,
}

impl fmt::Display for SimpleAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use humansize::{file_size_opts, FileSize};
        write!(f, "[{}", if self.is_directory { "DIR, " } else { "" })?;
        let size = self.size.file_size(file_size_opts::BINARY).unwrap();
        write!(f, "{}]", size)?;
        Ok(())
    }
}
