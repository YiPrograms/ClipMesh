use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clipmesh_protocol::{
    crypto::ChannelSecret,
    routing::{RouteSelection, routing_mode},
    wire::PasswordKdf,
};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const KEYRING_SERVICE: &str = "io.clipmesh.client";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateFile {
    pub server: Option<ServerRecord>,
    #[serde(default)]
    pub channels: Vec<StoredChannel>,
    #[serde(default)]
    pub routes: Vec<RouteSelection>,
    #[serde(default)]
    pub last_sequences: std::collections::HashMap<String, u64>,
    #[serde(default)]
    pub pause_sending: bool,
    #[serde(default)]
    pub pause_receiving: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerRecord {
    pub url: String,
    pub instance_id: Uuid,
    pub device_id: Uuid,
    pub device_name: String,
    pub server_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerSecrets {
    pub device_token: String,
    pub signing_private_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredChannel {
    pub id: Uuid,
    pub name: String,
    pub crypto_version: u16,
    pub kdf: PasswordKdf,
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub state_file: PathBuf,
    pub history_db: PathBuf,
    pub lock_file: PathBuf,
}

impl Paths {
    pub fn discover() -> anyhow::Result<Self> {
        let dirs = ProjectDirs::from("io", "ClipMesh", "ClipMesh")
            .context("could not find a user data directory")?;
        let config_dir = dirs.config_dir().to_path_buf();
        let data_dir = dirs.data_local_dir().to_path_buf();
        fs::create_dir_all(&config_dir)?;
        fs::create_dir_all(&data_dir)?;
        restrict_dir(&config_dir)?;
        restrict_dir(&data_dir)?;
        Ok(Self {
            state_file: config_dir.join("state.json"),
            history_db: data_dir.join("history.sqlite3"),
            lock_file: data_dir.join("engine.lock"),
            data_dir,
        })
    }
}

pub fn load(paths: &Paths) -> anyhow::Result<StateFile> {
    if !paths.state_file.exists() {
        return Ok(StateFile::default());
    }
    let state: StateFile = serde_json::from_slice(&fs::read(&paths.state_file)?)
        .context("invalid ClipMesh state file")?;
    if routing_mode(&state.routes).is_err() {
        bail!("saved routing state is invalid");
    }
    Ok(state)
}

pub fn save(paths: &Paths, state: &StateFile) -> anyhow::Result<()> {
    if routing_mode(&state.routes).is_err() {
        bail!("refusing to save invalid routing state");
    }
    let temporary = paths.state_file.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    restrict_file(&temporary)?;
    fs::rename(temporary, &paths.state_file)?;
    Ok(())
}

pub fn store_server_secrets(server_id: Uuid, value: &ServerSecrets) -> anyhow::Result<()> {
    set_secret(
        &format!("server:{server_id}"),
        &serde_json::to_string(value)?,
    )
}

pub fn server_secrets(server_id: Uuid) -> anyhow::Result<ServerSecrets> {
    serde_json::from_str(&get_secret(&format!("server:{server_id}"))?)
        .context("invalid server secret in credential store")
}

pub fn delete_server_secrets(server_id: Uuid) -> anyhow::Result<()> {
    delete_secret(&format!("server:{server_id}"))
}

pub fn store_channel_secret(server_id: Uuid, secret: &ChannelSecret) -> anyhow::Result<()> {
    set_secret(
        &format!("channel:{server_id}:{}", secret.channel_id),
        &serde_json::to_string(secret)?,
    )
}

pub fn channel_secret(server_id: Uuid, channel_id: Uuid) -> anyhow::Result<ChannelSecret> {
    serde_json::from_str(&get_secret(&format!("channel:{server_id}:{channel_id}"))?)
        .context("invalid channel secret in credential store")
}

pub fn delete_channel_secret(server_id: Uuid, channel_id: Uuid) -> anyhow::Result<()> {
    delete_secret(&format!("channel:{server_id}:{channel_id}"))
}

pub fn local_storage_key(server_id: Uuid) -> anyhow::Result<[u8; 32]> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let account = format!("local-storage:{server_id}");
    match get_secret(&account) {
        Ok(value) => STANDARD
            .decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid local storage key")),
        Err(_) => {
            use rand::RngCore;
            let mut value = [0_u8; 32];
            rand::rng().fill_bytes(&mut value);
            set_secret(&account, &STANDARD.encode(value))?;
            Ok(value)
        }
    }
}

fn entry(account: &str) -> anyhow::Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, account).context("credential store is unavailable")
}
fn set_secret(account: &str, value: &str) -> anyhow::Result<()> {
    entry(account)?
        .set_password(value)
        .context("could not save to the OS credential store")
}
fn get_secret(account: &str) -> anyhow::Result<String> {
    entry(account)?
        .get_password()
        .context("secret is missing from the OS credential store")
}
fn delete_secret(account: &str) -> anyhow::Result<()> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error).context("could not delete OS credential"),
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict_dir(_: &Path) -> anyhow::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn restrict_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict_file(_: &Path) -> anyhow::Result<()> {
    Ok(())
}
