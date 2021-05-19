use anyhow::{bail, ensure, Context, Result};
use colored::Colorize;
use onedrive_api::{Auth, Permission};
use state::{LoginInfo, OnedrivePath, Pending, PendingOp, State};
use std::time::{Duration, SystemTime};
use std::{collections::HashMap, path::PathBuf};
use structopt::StructOpt;
use tree::Diff;

use crate::tree::Tree;

mod commit;
mod config;
mod state;
mod tree;

const REDIRECT_URI: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";

#[derive(Debug, StructOpt)]
enum Opt {
    /// Login to your OneDrive (Microsoft) account.
    Login(OptLogin),
    /// Fetch remote state and update local database without any uploading or downloading.
    Fetch(OptFetch),
    /// Recursive compare content of current directory with remote state.
    Status(OptStatus),
    /// Queue downloading or uploading of given paths.
    Add(OptAdd),
    /// Unqueue previously `add`ed paths.
    Reset(OptReset),
    /// Commit pending download and upload.
    Commit(OptCommit),
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let state = State::new(".", &default_state_file())?;

    let opt = Opt::from_args();
    match opt {
        Opt::Login(opt) => main_login(opt, state).await,
        Opt::Fetch(opt) => main_fetch(opt, state).await,
        Opt::Status(opt) => main_status(opt, state).await,
        Opt::Add(opt) => main_add(opt, state).await,
        Opt::Reset(opt) => main_reset(opt, state).await,
        Opt::Commit(opt) => main_commit(opt, state).await,
    }
}

#[derive(Debug, StructOpt)]
struct OptLogin {
    /// The client id used for OAuth2.
    #[structopt(long)]
    client_id: String,

    /// The login code for Code-Auth.
    /// If not provided, the program will interactively open your browser and
    /// ask for the redirected URL containing it.
    code: Option<String>,
}

async fn main_login(opt: OptLogin, mut state: State) -> Result<()> {
    let auth = Auth::new(
        opt.client_id.clone(),
        Permission::new_read().write(true).offline_access(true),
        REDIRECT_URI.to_owned(),
    );

    let code = match opt.code {
        Some(code) => code,
        None => ask_for_code(&auth.code_auth_url())?,
    };

    eprintln!("Logining...");
    let login_time = SystemTime::now();
    let token_resp = auth.login_with_code(&code, None).await?;
    let refresh_token = token_resp.refresh_token.expect("Missing refresh token");
    let token = token_resp.access_token;
    let token_expire_time = login_time + Duration::from_secs(token_resp.expires_in_secs);

    eprintln!("Login successfully, saving credential...");
    // TODO: Check drive id and maybe clean item cache.
    let login = LoginInfo {
        client_id: opt.client_id.clone(),
        redirect_uri: REDIRECT_URI.to_owned(),
        refresh_token,
        token,
        token_expire_time,
    };
    state.set_login_info(&login)?;

    Ok(())
}

fn ask_for_code(auth_url: &str) -> Result<String> {
    let _ = open::that(auth_url);
    eprintln!(
        "\
Your browser should be opened. If not, please manually open the link below:
{}

Login to your OneDrive (Microsoft) Account in the link, it will jump to a blank page
whose URL contains `nativeclient?code=`.
",
        auth_url
    );

    loop {
        eprintln!(
            "Please copy and paste the FULL URL of the blank page here and then press ENTER:"
        );
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let line = line.trim();

        const NEEDLE: &str = "nativeclient?code=";
        match line.find(NEEDLE) {
            Some(pos) => return Ok(line[pos + NEEDLE.len()..].to_owned()),
            _ => eprintln!("Invalid URL."),
        }
    }
}

#[derive(Debug, StructOpt)]
struct OptFetch {
    /// Force re-fetch all items instead of incremental (delta) fetch.
    #[structopt(long)]
    from_init: bool,
}

async fn main_fetch(opt: OptFetch, mut state: State) -> Result<()> {
    let onedrive = state.get_or_login().await?;
    state.sync_remote(&onedrive, opt.from_init).await?;
    Ok(())
}

#[derive(Debug, StructOpt)]
struct OptStatus {}

// TODO: Show pending operations.
async fn main_status(_: OptStatus, state: State) -> Result<()> {
    let remote_tree = state.get_tree()?;
    let remote_tree = remote_tree
        .resolve(&state.config().onedrive.remote_path)
        .context("Remote path of sync root is gone")?;
    log::trace!("Remote tree: {:#?}", remote_tree);

    let local_tree = Tree::scan_recursive(state.root_dir())?;
    log::trace!("Local tree: {:#?}", local_tree);

    let diffs = local_tree.diff(&remote_tree, &OnedrivePath::default());
    log::debug!("Got {} diff", diffs.len());
    log::trace!("Diff: {:#?}", diffs);

    let local_cwd = OnedrivePath::new(
        std::fs::canonicalize(".")?.strip_prefix(state.root_dir().canonicalize()?)?,
    )?;
    log::debug!("Local cwd from sync root: {}", local_cwd);

    let pendings = state.get_pending()?;
    let mut pending_prefix_map = HashMap::new();
    for pending in &pendings {
        let path = &pending.local_path;
        assert!(pending_prefix_map
            .insert(path.as_raw_str(), PendingPrefix::ExactPath { pending })
            .is_none());
        for prefix in path.raw_ancestors() {
            match pending_prefix_map
                .entry(prefix)
                .or_insert_with(|| PendingPrefix::PrefixPath {
                    op: Some(pending.op),
                    pending_count: 0,
                }) {
                // Diff::Conflict between directory and file. But there is a deeper file queued.
                // So we should keep it as directory.
                p @ PendingPrefix::ExactPath { .. } => {
                    *p = PendingPrefix::PrefixPath {
                        op: Some(pending.op),
                        pending_count: 1,
                    };
                }
                PendingPrefix::PrefixPath { op, pending_count } => {
                    *pending_count += 1;
                    if *op != Some(pending.op) {
                        *op = None;
                    }
                }
            }
        }
    }

    let mut status = StatusResult::default();
    for diff in diffs {
        split_diff(diff, &pending_prefix_map, &mut status);
    }

    if !status.queued_diffs.is_empty() {
        println!("Files to be commited:");
        for diff in &status.queued_diffs {
            println!("  {}", format_diff(diff, &local_cwd).green());
        }
        println!();
    }

    if !status.unqueued_diffs.is_empty() {
        let non_conflicts = status
            .unqueued_diffs
            .iter()
            .filter(|diff| !matches!(diff, Diff::Conflict { .. }));
        let conflicts = status
            .unqueued_diffs
            .iter()
            .filter(|diff| matches!(diff, Diff::Conflict { .. }));

        if non_conflicts.clone().next().is_some() {
            println!("Changes not queued for commit:");
            for diff in non_conflicts {
                println!("  {}", format_diff(diff, &local_cwd).red());
            }
            println!();
        }

        if conflicts.clone().next().is_some() {
            println!("Conflict files:");
            for diff in conflicts {
                println!("  {}", format_diff(diff, &local_cwd).red());
            }
            println!();
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct StatusResult<'a> {
    unqueued_diffs: Vec<Diff<'a>>,
    queued_diffs: Vec<Diff<'a>>,
}

#[derive(Debug)]
enum PendingPrefix<'a> {
    PrefixPath {
        /// `Some` if all queued operations are the same. `None` otherwise.
        op: Option<PendingOp>,
        /// The count of queued operations under this prefix.
        pending_count: usize,
    },
    ExactPath {
        pending: &'a Pending,
    },
}

/// Split `Diff` into queued part and not-queued part.
/// Maybe recurse into paths when a directory is not fully queued.
fn split_diff<'a>(
    diff: Diff<'a>,
    pending_prefix_map: &HashMap<&str, PendingPrefix<'a>>,
    out: &mut StatusResult<'a>,
) {
    fn resolve_conflict<'a>(diff: Diff<'a>, op: PendingOp) -> Diff<'a> {
        match op {
            PendingOp::Download => diff
                .into_right()
                .expect("Pending download must has remote file"),
            PendingOp::Upload => diff
                .into_left()
                .expect("Pending upload must has local file"),
        }
    }

    match pending_prefix_map.get(&diff.path().as_raw_str()) {
        // No queued files is under this diff node.
        None => {
            out.unqueued_diffs.push(diff);
        }
        // The diff node itself is a queued file.
        Some(PendingPrefix::ExactPath { pending }) => {
            let op = pending.op;
            out.queued_diffs.push(resolve_conflict(diff, op));
        }
        // The diff node is a directory containing queued files.
        Some(PendingPrefix::PrefixPath { op, pending_count }) => {
            // Avoid lifetime issue.
            let pending_count = *pending_count;

            // In case of directory, `Diff::Conflict` can appears only when
            // there's file on one side and directory on the other side.
            let op = op.expect("No mixed operations under a single diff node");
            let diff = resolve_conflict(diff, op);

            let (is_rhs, mut path, tree) = match diff {
                Diff::Conflict { .. } => unreachable!(),
                Diff::Left { path, lhs } => (false, path, lhs),
                Diff::Right { path, rhs } => (true, path, rhs),
            };
            let make_diff = |path, tree| match is_rhs {
                false => Diff::Left { path, lhs: tree },
                true => Diff::Right { path, rhs: tree },
            };

            let mut files = 0usize;
            tree.walk(&OnedrivePath::default(), |node, _| {
                if node.is_file() {
                    files += 1;
                }
            });

            // The whole sub-tree is queued.
            if files == pending_count {
                out.queued_diffs.push(make_diff(path, tree));
            // Some deeper path is not queued. Recurse into children.
            } else {
                for (name, child) in tree.children().expect("Prefix must be a directory") {
                    path.push(name).unwrap();
                    let sub_diff = make_diff(path.clone(), child);
                    split_diff(sub_diff, pending_prefix_map, out);
                    path.pop();
                }
            }
        }
    }
}

// FIXME: Print path relative to CWD.
fn format_diff(diff: &Diff<'_>, cwd: &OnedrivePath) -> String {
    match diff {
        Diff::Left { path, lhs } => {
            format!("local:    {} {}", path.relative_to(cwd), lhs.calc_attr())
        }
        Diff::Right { path, rhs } => {
            format!("remote:   {} {}", path.relative_to(cwd), rhs.calc_attr())
        }
        Diff::Conflict { path, lhs, rhs } => format!(
            "conflict: {} local:{} remote:{}",
            path.relative_to(cwd),
            lhs.calc_attr(),
            rhs.calc_attr(),
        ),
    }
}

#[derive(Debug, StructOpt)]
struct OptAdd {
    /// Paths to queue for download or upload.
    paths: Vec<PathBuf>,
    /// Add local path to queue uploading.
    #[structopt(long, conflicts_with = "remote")]
    local: bool,
    /// Add remote path to queue downloading.
    #[structopt(long)]
    remote: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Strategy {
    Auto,
    KeepLocal,
    KeepRemote,
}

fn add_pending_diff<'a>(
    pendings: &mut Vec<Pending>,
    strategy: Strategy,
    diffs: impl IntoIterator<Item = &'a Diff<'a>>,
    mut path_filter: impl FnMut(&OnedrivePath) -> bool,
) {
    log::debug!("Adding diff with strategy {:?}", strategy);
    match strategy {
        Strategy::Auto => unreachable!(),
        Strategy::KeepLocal => {
            for diff in diffs {
                diff.lhs().unwrap().walk(&diff.path(), |node, path| {
                    if node.is_file() && path_filter(path) {
                        pendings.push(Pending {
                            item_id: None,
                            local_path: path.clone(),
                            op: PendingOp::Upload,
                        });
                    }
                });
            }
        }
        Strategy::KeepRemote => {
            for diff in diffs {
                diff.rhs().unwrap().walk(&diff.path(), |node, path| {
                    if node.is_file() && path_filter(path) {
                        pendings.push(Pending {
                            item_id: Some(node.item_id().expect("Already from remote").clone()),
                            local_path: path.clone(),
                            op: PendingOp::Download,
                        });
                    }
                });
            }
        }
    }
}

async fn main_add(opt: OptAdd, mut state: State) -> Result<()> {
    // TODO: Dedup with `status`.
    let remote_tree = state.get_tree()?;
    let remote_tree = remote_tree
        .resolve(&state.config().onedrive.remote_path)
        .context("Remote path of sync root is gone")?;

    let local_tree = Tree::scan_recursive(state.root_dir())?;
    let diffs = local_tree.diff(&remote_tree, &OnedrivePath::default());
    log::debug!("Got {} diff", diffs.len());

    log::trace!("Diff: {:#?}", diffs);

    let local_cwd = OnedrivePath::new(
        std::fs::canonicalize(".")?.strip_prefix(state.root_dir().canonicalize()?)?,
    )?;
    log::debug!("Local cwd from sync root: {}", local_cwd);

    let strategy = match (opt.local, opt.remote) {
        (true, false) => Strategy::KeepLocal,
        (false, true) => Strategy::KeepRemote,
        (false, false) => Strategy::Auto,
        (true, true) => unreachable!("Checked by structopt"),
    };

    let mut pendings = Vec::new();

    for path in &opt.paths {
        let path_to_add = local_cwd.join_os(path)?;
        log::debug!("Try adding local path: {}", path_to_add);

        // The path to add is under (but is not) a diff node, so it's only available in one side.
        // /
        // `-a      <- Diff node. Only in local or remote.
        //   `-b    <- Path to add.
        //   ` `-c
        //   `-d
        let decision = if let Some(diff) = diffs.iter().find(|diff| {
            path_to_add.starts_with(diff.path())
                && path_to_add.as_raw_str().len() != diff.path().as_raw_str().len()
        }) {
            log::debug!("Path to add is under diff: {:?}", diff);

            let strategy = match diff {
                Diff::Left { path, lhs } => {
                    ensure!(lhs.is_directory(), "Is a file: {}", path);
                    ensure!(
                        strategy != Strategy::KeepRemote,
                        "Only in local: {}",
                        path_to_add.relative_to(&local_cwd),
                    );
                    Strategy::KeepLocal
                }
                Diff::Right { path, rhs } => {
                    ensure!(rhs.is_directory(), "Is a file: {}", path);
                    ensure!(
                        strategy != Strategy::KeepLocal,
                        "Only in remote: {}",
                        path_to_add.relative_to(&local_cwd),
                    );
                    Strategy::KeepRemote
                }
                Diff::Conflict { path, .. } => {
                    bail!("Is a file: {}", path.relative_to(&local_cwd))
                }
            };

            add_pending_diff(&mut pendings, strategy, std::iter::once(diff), |path| {
                path.starts_with(&path_to_add)
            });
            strategy

        // The path is a common prefix in both local and remote.
        // /
        // `-a      <- Common prefix in both local and remote. (No diff)
        //   `-b    <- Path to add.
        //   ` `-c  <- Maybe diff.
        //   `-d
        // `-e      <- Maybe diff.
        } else {
            log::debug!("Path to add is a common prefix");

            // All diff nodes selected by the path to add.
            let selected = diffs
                .iter()
                .filter(|diff| diff.path().starts_with(&path_to_add));

            // Validate strategy or auto guess.
            let (mut has_left, mut has_right) = (false, false);
            for diff in selected.clone() {
                match (strategy, diff) {
                    (Strategy::KeepRemote, Diff::Left { path, .. }) => {
                        bail!("Only in local: {}", path.relative_to(&local_cwd));
                    }
                    (Strategy::KeepLocal, Diff::Right { path, .. }) => {
                        bail!("Only in remote: {}", path.relative_to(&local_cwd));
                    }
                    (_, Diff::Left { .. }) => has_left = true,
                    (_, Diff::Right { .. }) => has_right = true,
                    (Strategy::Auto, Diff::Conflict { path, .. }) => {
                        bail!(
                            "Found conflict {}, please specify `--local` or `--remote`",
                            path.relative_to(&local_cwd),
                        );
                    }
                    _ => {}
                }
            }

            let strategy = match (strategy, has_left, has_right) {
                (Strategy::KeepLocal, _, _) | (Strategy::KeepRemote, _, _) => strategy,
                (Strategy::Auto, false, false) => bail!("No diff on {}", path_to_add.relative_to(&local_cwd)),
                (Strategy::Auto, false, true) => Strategy::KeepRemote,
                (Strategy::Auto, true, false) => Strategy::KeepLocal,
                (Strategy::Auto, true, true) => bail!(
                    "Found both local-only and remote-only paths under {}. Please specify `--local` or `--remote`",
                    path_to_add.relative_to(&local_cwd),
                ),
            };

            add_pending_diff(&mut pendings, strategy, selected, |_| true);
            strategy
        };

        match decision {
            Strategy::Auto => unreachable!(),
            Strategy::KeepLocal => println!("Added <local>{}", path_to_add),
            Strategy::KeepRemote => println!("Added <remote>{}", path_to_add),
        }
    }

    println!("Queue {} file(s)", pendings.len());
    state.queue_pending(pendings)?;

    Ok(())
}

#[derive(Debug, StructOpt)]
struct OptReset {
    /// Paths to unqueue.
    paths: Vec<PathBuf>,
}

async fn main_reset(opt: OptReset, mut state: State) -> Result<()> {
    let local_cwd = OnedrivePath::new(
        std::fs::canonicalize(".")?.strip_prefix(state.root_dir().canonicalize()?)?,
    )?;
    let mut affected = 0;
    for path in &opt.paths {
        let path = local_cwd.join_os(path)?;
        affected += state.unqueue_pending(&path)?;
    }
    println!("Unqueued {} file(s)", affected);
    Ok(())
}

#[derive(Debug, StructOpt)]
struct OptCommit {
    /// Only commit pending download.
    #[structopt(long)]
    download: bool,
    /// Only commit pending upload.
    #[structopt(long)]
    upload: bool,
}

// TODO: upload
async fn main_commit(opt: OptCommit, state: State) -> Result<()> {
    let (download, upload) = match (opt.download, opt.upload) {
        (false, false) => (true, true),
        o => o,
    };
    commit::commit(state, download, upload).await?;
    Ok(())
}

fn default_state_file() -> PathBuf {
    dirs::data_dir()
        .expect("Missing data dir")
        .join("onedrive-sync/db.sqlite")
}
