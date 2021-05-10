use anyhow::Result;
use onedrive_api::{Auth, DriveLocation, OneDrive, Permission};
use serde::Deserialize;
use state::{LoginInfo, State};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use structopt::StructOpt;

mod state;
mod tree;

const REDIRECT_URI: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";

#[derive(Debug, Deserialize)]
pub struct Config {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    write: bool,
    #[serde(default = "default_state_file")]
    state_file: PathBuf,
}

#[derive(Debug, StructOpt)]
enum Opt {
    /// Login to your OneDrive (Microsoft) account.
    Login(OptLogin),
    /// Fetch remote state and update local database without any uploading or downloading.
    Fetch(OptFetch),
    /// Recursive compare content of current directory with remote state.
    Status(OptStatus),
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let state = State::new(&default_state_file())?;

    let opt = Opt::from_args();
    match opt {
        Opt::Login(opt) => main_login(opt, state).await,
        Opt::Fetch(opt) => main_fetch(opt, state).await,
        Opt::Status(opt) => main_status(opt, state).await,
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
    let login = state.get_or_login().await?;
    let onedrive = OneDrive::new(login.token, DriveLocation::me());
    state.sync_remote(&onedrive, opt.from_init).await?;
    Ok(())
}

#[derive(Debug, StructOpt)]
struct OptStatus {}

async fn main_status(_: OptStatus, state: State) -> Result<()> {
    let tree = state.get_tree()?;
    let diffs = tree.diff(".")?;
    for diff in diffs {
        let prefix = match diff {
            tree::Diff::Add(_) => " A",
            tree::Diff::Remove(_) => " D",
            tree::Diff::Modify(_) => " M",
        };
        println!("{} {}", prefix, diff.path().display());
    }
    Ok(())
}

fn default_state_file() -> PathBuf {
    dirs::data_dir()
        .expect("Missing data dir")
        .join("onedrive-sync/db.sqlite")
}
