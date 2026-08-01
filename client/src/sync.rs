use std::{fs::OpenOptions, time::Duration};

use anyhow::{Context, bail};
use chrono::Utc;
use clipmesh_protocol::crypto::{ClipboardItem, content_hash, decrypt_item, encrypt_item};
use fs2::FileExt;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::{
    api::Api,
    clipboard::{self, ClipboardCommand},
    history,
    state::{self, Paths},
};

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub configured: bool,
    pub connected: bool,
    pub server_name: String,
    pub server_url: String,
    pub device_name: String,
    pub channel_count: usize,
    pub send_count: usize,
    pub receive_count: usize,
    pub current_type: Option<String>,
    pub current_size: usize,
    pub current_preview: Option<String>,
    pub last_error: Option<String>,
    pub last_sync: Option<i64>,
    last_file_scan: Option<i64>,
}

pub enum EngineCommand {
    Publish(ClipboardItem),
    Copy(ClipboardItem),
    Reload,
    Stop,
}

pub struct Engine {
    pub commands: mpsc::Sender<EngineCommand>,
    pub snapshot: watch::Receiver<Snapshot>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Engine {
    pub async fn stop(self) -> anyhow::Result<()> {
        let _ = self.commands.send(EngineCommand::Stop).await;
        self.task.await??;
        Ok(())
    }
}

pub fn start(paths: Paths) -> anyhow::Result<Engine> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&paths.lock_file)?;
    lock.try_lock_exclusive()
        .context("ClipMesh is already running (stop the service before opening the TUI)")?;
    let (command_tx, command_rx) = mpsc::channel(16);
    let (snapshot_tx, snapshot_rx) = watch::channel(Snapshot::default());
    let task = tokio::spawn(async move {
        let _lock = lock;
        run(paths, command_rx, snapshot_tx).await
    });
    Ok(Engine {
        commands: command_tx,
        snapshot: snapshot_rx,
        task,
    })
}

async fn run(
    paths: Paths,
    mut commands: mpsc::Receiver<EngineCommand>,
    snapshot_tx: watch::Sender<Snapshot>,
) -> anyhow::Result<()> {
    let mut clipboard = clipboard::start();
    let mut snapshot = Snapshot::default();
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = poll.tick() => {
                if let Err(error) = receive_once(&paths, &clipboard.commands, &mut snapshot).await { snapshot.connected = false; snapshot.last_error = Some(error.to_string()); }
                let _ = flush_outbox(&paths, &mut snapshot).await;
                let _ = snapshot_tx.send(snapshot.clone());
            }
            Some(item) = clipboard.changes.recv() => {
                update_current(&mut snapshot, &item);
                if let Err(error) = publish(&paths, &item, None, &mut snapshot).await { snapshot.last_error = Some(error.to_string()); }
                let _ = snapshot_tx.send(snapshot.clone());
            }
            Some(command) = commands.recv() => match command {
                EngineCommand::Publish(item) => {
                    update_current(&mut snapshot, &item);
                    if !matches!(item, ClipboardItem::File(_)) {
                        let _ = clipboard.commands.send(ClipboardCommand::Write(item.clone()));
                    }
                    if let Err(error) = publish(&paths, &item, None, &mut snapshot).await { snapshot.last_error = Some(error.to_string()); }
                    let _ = snapshot_tx.send(snapshot.clone());
                }
                EngineCommand::Copy(item) => {
                    update_current(&mut snapshot, &item);
                    if !matches!(item, ClipboardItem::File(_)) {
                        let _ = clipboard.commands.send(ClipboardCommand::Write(item));
                    }
                    let _ = snapshot_tx.send(snapshot.clone());
                }
                EngineCommand::Reload => { let _ = snapshot_tx.send(snapshot.clone()); }
                EngineCommand::Stop => break,
            },
            else => break,
        }
    }
    let _ = clipboard.commands.send(ClipboardCommand::Stop);
    Ok(())
}

pub async fn publish_once(paths: &Paths, item: &ClipboardItem) -> anyhow::Result<()> {
    let mut snapshot = Snapshot::default();
    publish(paths, item, None, &mut snapshot).await
}

pub async fn publish_to(
    paths: &Paths,
    item: &ClipboardItem,
    targets: Vec<Uuid>,
) -> anyhow::Result<()> {
    let mut snapshot = Snapshot::default();
    publish(paths, item, Some(targets), &mut snapshot).await?;
    if let Some(error) = snapshot.last_error {
        bail!("{error}");
    }
    Ok(())
}

async fn receive_once(
    paths: &Paths,
    clipboard: &std::sync::mpsc::Sender<ClipboardCommand>,
    snapshot: &mut Snapshot,
) -> anyhow::Result<()> {
    let mut state = state::load(paths)?;
    let Some(server) = state.server.clone() else {
        snapshot.configured = false;
        snapshot.connected = false;
        return Ok(());
    };
    snapshot.configured = true;
    snapshot.server_url = server.url.clone();
    snapshot.device_name = server.device_name.clone();
    snapshot.channel_count = state.channels.len();
    snapshot.send_count = state
        .routes
        .iter()
        .filter(|route| route.send_enabled)
        .count();
    snapshot.receive_count = state
        .routes
        .iter()
        .filter(|route| route.receive_enabled)
        .count();
    let secrets = state::server_secrets(server.instance_id)?;
    let api = Api::authenticated(&server, &secrets)?;
    let info = api.info().await?;
    snapshot.server_name = info.name;
    if info.server_instance_id != server.instance_id || info.protocol_version != 1 {
        bail!("server identity or protocol changed");
    }
    snapshot.connected = true;
    snapshot.last_error = None;
    if state.pause_receiving {
        return Ok(());
    }
    let receive_ids: Vec<_> = state
        .routes
        .iter()
        .filter(|route| route.receive_enabled)
        .map(|route| route.channel_id)
        .collect();
    let scan_files = snapshot
        .last_file_scan
        .is_none_or(|last| Utc::now().timestamp() - last >= 60);
    for channel_id in receive_ids {
        if scan_files {
            let channel = state
                .channels
                .iter()
                .find(|channel| channel.id == channel_id)
                .context("received file for an unknown channel")?;
            let secret = state::channel_secret(server.instance_id, channel_id)?;
            for file_item in api.files(channel_id).await? {
                if file_item.origin_device_id == server.device_id
                    || history::contains_item(&paths.history_db, file_item.id)?
                {
                    continue;
                }
                let ciphertext = api.content(file_item.id).await?;
                match decrypt_item(&secret, server.instance_id, &file_item, ciphertext.clone()) {
                    Ok(ClipboardItem::File(_)) => history::add_received(
                        &paths.history_db,
                        &file_item,
                        &channel.name,
                        &ciphertext,
                        "received",
                    )?,
                    Ok(_) => {
                        snapshot.last_error =
                            Some("server file list contained a non-file item".into())
                    }
                    Err(error) => {
                        history::add_received(
                            &paths.history_db,
                            &file_item,
                            &channel.name,
                            &ciphertext,
                            "failed",
                        )?;
                        snapshot.last_error = Some(error.to_string());
                    }
                }
            }
        }
        let Some(item) = api.current(channel_id).await? else {
            continue;
        };
        if item.channel_sequence
            <= *state
                .last_sequences
                .get(&channel_id.to_string())
                .unwrap_or(&0)
        {
            continue;
        }
        if item.origin_device_id == server.device_id {
            api.ack(&item).await?;
            state
                .last_sequences
                .insert(channel_id.to_string(), item.channel_sequence);
            continue;
        }
        if item.content_type == clipmesh_protocol::FILE_MANIFEST_CONTENT_TYPE
            && history::contains_item(&paths.history_db, item.id)?
        {
            api.ack(&item).await?;
            state
                .last_sequences
                .insert(channel_id.to_string(), item.channel_sequence);
            continue;
        }
        let channel = state
            .channels
            .iter()
            .find(|channel| channel.id == channel_id)
            .context("received item for an unknown channel")?;
        let ciphertext = api.content(item.id).await?;
        let secret = state::channel_secret(server.instance_id, channel_id)?;
        match decrypt_item(&secret, server.instance_id, &item, ciphertext.clone()) {
            Ok(plaintext) => {
                update_current(snapshot, &plaintext);
                if !matches!(plaintext, ClipboardItem::File(_)) {
                    clipboard.send(ClipboardCommand::Write(plaintext)).ok();
                }
                history::add_received(
                    &paths.history_db,
                    &item,
                    &channel.name,
                    &ciphertext,
                    "received",
                )?;
            }
            Err(error) => {
                history::add_received(
                    &paths.history_db,
                    &item,
                    &channel.name,
                    &ciphertext,
                    "failed",
                )?;
                snapshot.last_error = Some(error.to_string());
            }
        }
        api.ack(&item).await?;
        state
            .last_sequences
            .insert(channel_id.to_string(), item.channel_sequence);
        snapshot.last_sync = Some(Utc::now().timestamp_millis());
    }
    if scan_files {
        snapshot.last_file_scan = Some(Utc::now().timestamp());
    }
    state::save(paths, &state)?;
    Ok(())
}

async fn publish(
    paths: &Paths,
    item: &ClipboardItem,
    target_override: Option<Vec<Uuid>>,
    snapshot: &mut Snapshot,
) -> anyhow::Result<()> {
    let state = state::load(paths)?;
    let Some(server) = state.server.clone() else {
        return Ok(());
    };
    let targets = target_override.unwrap_or_else(|| {
        state
            .routes
            .iter()
            .filter(|route| route.send_enabled)
            .map(|route| route.channel_id)
            .collect()
    });
    if targets.is_empty() {
        return Ok(());
    }
    let local_key = state::local_storage_key(server.instance_id)?;
    if state.pause_sending {
        history::set_outbox(&paths.history_db, &local_key, item, &targets)?;
        return Ok(());
    }
    let api = Api::authenticated(&server, &state::server_secrets(server.instance_id)?)?;
    let mut failed = Vec::new();
    for id in targets {
        let Some(channel) = state.channels.iter().find(|channel| channel.id == id) else {
            failed.push(id);
            continue;
        };
        let secret = state::channel_secret(server.instance_id, id)?;
        let envelope = encrypt_item(
            &secret,
            server.instance_id,
            server.device_id,
            item,
            Utc::now().to_rfc3339(),
        )?;
        match api.upload(&envelope).await {
            Ok(_) => history::add_sent(
                &paths.history_db,
                &envelope,
                &channel.name,
                &server.device_name,
                "accepted",
            )?,
            Err(error) => {
                history::add_sent(
                    &paths.history_db,
                    &envelope,
                    &channel.name,
                    &server.device_name,
                    "failed",
                )?;
                snapshot.last_error = Some(error.to_string());
                failed.push(id);
            }
        }
    }
    if failed.is_empty() {
        history::clear_outbox(&paths.history_db)?;
        snapshot.connected = true;
        snapshot.last_sync = Some(Utc::now().timestamp_millis());
    } else {
        history::set_outbox(&paths.history_db, &local_key, item, &failed)?;
    }
    Ok(())
}

async fn flush_outbox(paths: &Paths, snapshot: &mut Snapshot) -> anyhow::Result<()> {
    let state = state::load(paths)?;
    let Some(server) = state.server else {
        return Ok(());
    };
    if state.pause_sending {
        return Ok(());
    }
    let key = state::local_storage_key(server.instance_id)?;
    if let Some((item, targets)) = history::outbox(&paths.history_db, &key)? {
        publish(paths, &item, Some(targets), snapshot).await?;
    }
    Ok(())
}

fn update_current(snapshot: &mut Snapshot, item: &ClipboardItem) {
    snapshot.current_type = Some(item.content_type().into());
    snapshot.current_size = usize::try_from(item.display_size()).unwrap_or(usize::MAX);
    snapshot.current_preview = match item {
        ClipboardItem::Text(bytes) => std::str::from_utf8(bytes)
            .ok()
            .map(|value| value.chars().take(160).collect()),
        ClipboardItem::Png { width, height, .. } => Some(format!("{width} × {height} PNG")),
        ClipboardItem::File(manifest) => Some(format!(
            "{} · {} bytes · expires {}",
            manifest.filename, manifest.size, manifest.expires_at
        )),
    };
    let _ = content_hash(item);
}
