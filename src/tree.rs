use crate::state;
use anyhow::{ensure, Context, Result};
use onedrive_api::ItemId;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

#[derive(Debug)]
pub struct Tree {
    root: Node,
}

#[derive(Debug)]
enum Node {
    File {
        id: ItemId,
        size: u64,
        mtime: SystemTime,
        sha1: String,
    },
    Directory {
        children: BTreeMap<String, Node>,
    },
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
        ) -> Result<Node> {
            Ok(match item.content {
                state::ItemContent::Directory => Node::Directory {
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
                } => Node::File {
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

    pub fn diff(&self, dir: impl AsRef<Path>) -> Result<Vec<Diff>> {
        let mut ret = Vec::new();
        diff_helper(&self.root, &mut dir.as_ref().to_owned(), &mut ret)?;
        Ok(ret)
    }
}

fn diff_helper(node: &Node, path: &mut PathBuf, out: &mut Vec<Diff>) -> Result<()> {
    let meta = std::fs::symlink_metadata(&*path)?;
    ensure!(
        meta.is_dir() || meta.is_file(),
        "Unsupported file type: {:?}",
        meta.file_type(),
    );

    match (&node, meta.is_dir()) {
        (Node::Directory { .. }, false) | (Node::File { .. }, true) => {
            out.push(Diff::Remove(path.to_owned()));
            out.push(Diff::Add(path.to_owned()));
        }
        // TODO: Check sha1.
        (Node::File { size, mtime, .. }, false) => {
            let local_mtime = meta.modified()?;
            if *size != meta.len() || !eq_time(*mtime, local_mtime) {
                out.push(Diff::Modify(path.to_owned()));
            }
        }
        (Node::Directory { children }, true) => {
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
}

impl Diff {
    pub fn path(&self) -> &Path {
        match self {
            Self::Add(p) | Self::Remove(p) | Self::Modify(p) => p,
        }
    }
}
