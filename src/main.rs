use anyhow::{bail, ensure, Context, Result};
use onedrive_api::{Auth, Permission};
use state::{LoginInfo, OnedrivePath, Pending, PendingOp, State};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
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

    for diff in &diffs {
        match diff {
            Diff::Left { path, lhs } => {
                // FIXME: Print path relative to CWD.
                println!("L  {} {}", path, lhs.calc_attr());
            }
            Diff::Right { path, rhs } => {
                println!(" R {} {}", path, rhs.calc_attr());
            }
            Diff::Conflict { path, lhs, rhs } => {
                println!("LR {} L:{} R:{}", path, lhs.calc_attr(), rhs.calc_attr());
            }
        }
    }
    Ok(())
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
                && path_to_add.as_str().len() != diff.path().as_str().len()
        }) {
            log::debug!("Path to add is under diff: {:?}", diff);

            let strategy = match diff {
                Diff::Left { path, lhs } => {
                    ensure!(lhs.is_directory(), "Is a file: {}", path);
                    ensure!(
                        strategy != Strategy::KeepRemote,
                        "Only in local: {}",
                        path_to_add,
                    );
                    Strategy::KeepLocal
                }
                Diff::Right { path, rhs } => {
                    ensure!(rhs.is_directory(), "Is a file: {}", path);
                    ensure!(
                        strategy != Strategy::KeepLocal,
                        "Only in remote: {}",
                        path_to_add,
                    );
                    Strategy::KeepRemote
                }
                Diff::Conflict { path, .. } => {
                    bail!("Is a file: {}", path)
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
                        bail!("Only in local: {}", path);
                    }
                    (Strategy::KeepLocal, Diff::Right { path, .. }) => {
                        bail!("Only in remote: {}", path);
                    }
                    (_, Diff::Left { .. }) => has_left = true,
                    (_, Diff::Right { .. }) => has_right = true,
                    (Strategy::Auto, Diff::Conflict { path, .. }) => {
                        bail!(
                            "Found conflict {:?}, please specify `--local` or `--remote`",
                            path
                        );
                    }
                    _ => {}
                }
            }

            let strategy = match (has_left, has_right, strategy) {
                (false, false, _) => bail!("No diff on {}", path_to_add),
                (false, true, Strategy::Auto) => Strategy::KeepRemote,
                (true, false, Strategy::Auto) => Strategy::KeepLocal,
                (true, true, Strategy::Auto) => bail!(
                    "Found both local-only and remote-only paths under {}. Please specify `--local` or `--remote`",
                    path_to_add,
                ),
                _ => strategy
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
async fn main_commit(opt: OptCommit, mut state: State) -> Result<()> {
    let (commit_download, commit_upload) = match (opt.download, opt.upload) {
        (false, false) => (true, true),
        o => o,
    };
    if commit_download {
        commit::commit_download(&mut state).await?;
    }
    if commit_upload {
        commit::commit_upload(&mut state).await?;
    }
    Ok(())
}

fn default_state_file() -> PathBuf {
    dirs::data_dir()
        .expect("Missing data dir")
        .join("onedrive-sync/db.sqlite")
}
