use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clipmesh_protocol::{PROTOCOL_VERSION, crypto, routing, wire::*};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use uuid::Uuid;

use crate::{
    api::Api,
    history,
    state::{self, Paths, ServerRecord, ServerSecrets, StoredChannel},
};

pub async fn pair(
    paths: &Paths,
    server_url: &str,
    name: &str,
    code: Option<String>,
) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        bail!("device name is required");
    }
    let api = Api::public(server_url)?;
    let info = api.info().await?;
    if info.protocol_version != PROTOCOL_VERSION {
        bail!("server protocol {} is not supported", info.protocol_version);
    }
    let code = match code {
        Some(value) => value,
        None => prompt("Pairing code: ", false)?,
    };
    let signing = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let public = signing.verifying_key().to_public_key_der()?;
    let private = signing.to_pkcs8_der()?;
    let registered = api
        .register(&RegisterDeviceRequest {
            pairing_code: code,
            name: name.trim().into(),
            signing_public_key: STANDARD.encode(public.as_bytes()),
            browser_family: "clipmesh-cli".into(),
            browser_version: Some(env!("CARGO_PKG_VERSION").into()),
            os_family: Some(std::env::consts::OS.into()),
        })
        .await?;
    if registered.server_instance_id != info.server_instance_id
        || registered.api_version != PROTOCOL_VERSION
    {
        bail!("server identity changed during pairing");
    }
    let mut state_file = state::load(paths)?;
    if let Some(previous) = &state_file.server
        && previous.instance_id != registered.server_instance_id
    {
        bail!("this installation is already paired; run `clipmesh forget` before changing servers");
    }
    state::store_server_secrets(
        registered.server_instance_id,
        &ServerSecrets {
            device_token: registered.device_token,
            signing_private_key: STANDARD.encode(private.as_bytes()),
        },
    )?;
    state_file.server = Some(ServerRecord {
        url: api_url(server_url)?,
        instance_id: registered.server_instance_id,
        device_id: registered.device_id,
        device_name: name.trim().into(),
        server_version: info.server_version,
    });
    state::save(paths, &state_file)?;
    println!("Paired {} with {}", name.trim(), info.name);
    Ok(())
}

pub async fn status(paths: &Paths) -> anyhow::Result<()> {
    let state_file = state::load(paths)?;
    let Some(server) = state_file.server else {
        println!("Not paired. Run `clipmesh pair --server URL --name NAME`.");
        return Ok(());
    };
    let api = Api::authenticated(&server, &state::server_secrets(server.instance_id)?)?;
    let online = api.info().await;
    println!("Device:  {} ({})", server.device_name, server.device_id);
    println!("Server:  {}", server.url);
    println!(
        "State:   {}",
        if online.is_ok() { "online" } else { "offline" }
    );
    println!(
        "Routes:  {} send / {} receive",
        state_file
            .routes
            .iter()
            .filter(|value| value.send_enabled)
            .count(),
        state_file
            .routes
            .iter()
            .filter(|value| value.receive_enabled)
            .count()
    );
    println!(
        "Mode:    {:?}",
        routing::routing_mode(&state_file.routes).map_err(anyhow::Error::msg)?
    );
    if let Err(error) = online {
        println!("Error:   {error}");
    }
    Ok(())
}

pub async fn send_file(
    paths: &Paths,
    path: Option<&Path>,
    filename: Option<&str>,
    media_type: &str,
) -> anyhow::Result<()> {
    if let Some(path) = path {
        let name = match filename {
            Some(value) => value.to_owned(),
            None => path
                .file_name()
                .and_then(|value| value.to_str())
                .context("file path has no valid UTF-8 basename; pass --filename")?
                .to_owned(),
        };
        return crate::file_transfer::send_path(paths, path, &name, media_type).await;
    }
    let name = filename.context("pass a file path, or pipe stdin with --filename NAME")?;
    if io::stdin().is_terminal() {
        bail!("no file path was provided and stdin is a terminal");
    }
    let mut temporary = tempfile::NamedTempFile::new().context("create stdin spool file")?;
    io::copy(&mut io::stdin().lock(), &mut temporary).context("read file content from stdin")?;
    crate::file_transfer::send_path(paths, temporary.path(), name, media_type).await
}

pub async fn list_channels(paths: &Paths) -> anyhow::Result<()> {
    let state_file = state::load(paths)?;
    let channels = available_channels(paths).await?;
    println!(
        "{:<38} {:<26} {:<7} {:<7} MEMBERS",
        "ID", "NAME", "SEND", "RECV"
    );
    for channel in channels {
        let route = state_file
            .routes
            .iter()
            .find(|value| value.channel_id == channel.id);
        println!(
            "{:<38} {:<26} {:<7} {:<7} {}",
            channel.id,
            truncate(&channel.name, 25),
            yes(route.is_some_and(|value| value.send_enabled)),
            yes(route.is_some_and(|value| value.receive_enabled)),
            channel.member_count
        );
    }
    Ok(())
}

pub async fn available_channels(paths: &Paths) -> anyhow::Result<Vec<ChannelSummary>> {
    let (_, api) = authenticated(paths)?;
    api.channels().await
}

pub async fn create_channel(paths: &Paths, name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        bail!("channel name is required");
    }
    let password = prompt_password_twice()?;
    let (mut state_file, api) = authenticated(paths)?;
    let server = state_file.server.clone().unwrap();
    let material = crypto::create_channel_material(&password, Uuid::new_v4())?;
    api.create_channel(&CreateChannelRequest {
        channel_id: material.channel_id,
        name: name.trim().into(),
        crypto_version: 1,
        password_kdf: material.password_kdf.clone(),
        wrapped_secret: material.wrapped_secret.clone(),
        membership_public_key: material.membership_public_key.clone(),
    })
    .await?;
    finish_join(&api, &server, &material.secret).await?;
    state::store_channel_secret(server.instance_id, &material.secret)?;
    state_file.channels.push(StoredChannel {
        id: material.channel_id,
        name: name.trim().into(),
        crypto_version: 1,
        kdf: material.password_kdf,
    });
    routing::add_channel(&mut state_file.routes, material.channel_id);
    state::save(paths, &state_file)?;
    println!(
        "Created and joined {} ({})",
        name.trim(),
        material.channel_id
    );
    Ok(())
}

pub async fn join_channel(paths: &Paths, id: Uuid) -> anyhow::Result<()> {
    let password = prompt("Channel password: ", true)?;
    let (mut state_file, api) = authenticated(paths)?;
    if state_file.channels.iter().any(|value| value.id == id) {
        println!("Already joined {id}");
        return Ok(());
    }
    let server = state_file.server.clone().unwrap();
    let parameters = api.join_parameters(id).await?;
    if parameters.channel_id != id || parameters.crypto_version != 1 {
        bail!("server returned mismatched channel parameters");
    }
    let secret = crypto::unwrap_channel_secret(
        &password,
        id,
        &parameters.password_kdf,
        &parameters.wrapped_secret,
        &parameters.membership_public_key.spki,
    )?;
    finish_join(&api, &server, &secret).await?;
    let name = api
        .channels()
        .await?
        .into_iter()
        .find(|value| value.id == id)
        .map(|value| value.name)
        .unwrap_or_else(|| id.to_string());
    state::store_channel_secret(server.instance_id, &secret)?;
    state_file.channels.push(StoredChannel {
        id,
        name: name.clone(),
        crypto_version: 1,
        kdf: parameters.password_kdf,
    });
    routing::add_channel(&mut state_file.routes, id);
    state::save(paths, &state_file)?;
    println!("Joined {name}");
    Ok(())
}

pub async fn leave_channel(paths: &Paths, id: Uuid, delete: bool) -> anyhow::Result<()> {
    let (mut state_file, api) = authenticated(paths)?;
    let server = state_file.server.clone().unwrap();
    if delete {
        api.delete_channel(id).await?;
    } else {
        api.leave(id).await?;
    }
    state_file.channels.retain(|value| value.id != id);
    state_file.routes.retain(|value| value.channel_id != id);
    state_file.last_sequences.remove(&id.to_string());
    state::save(paths, &state_file)?;
    state::delete_channel_secret(server.instance_id, id)?;
    println!("{} {id}", if delete { "Deleted" } else { "Left" });
    Ok(())
}

pub fn set_route(
    paths: &Paths,
    id: Uuid,
    send: Option<bool>,
    receive: Option<bool>,
) -> anyhow::Result<()> {
    if send.is_none() && receive.is_none() {
        bail!("set at least one of --send/--receive to true or false");
    }
    let mut state_file = state::load(paths)?;
    routing::set_route(&mut state_file.routes, id, send, receive).map_err(anyhow::Error::msg)?;
    state::save(paths, &state_file)?;
    println!(
        "Routing mode: {:?}",
        routing::routing_mode(&state_file.routes).map_err(anyhow::Error::msg)?
    );
    Ok(())
}

pub fn set_pause(
    paths: &Paths,
    sending: Option<bool>,
    receiving: Option<bool>,
) -> anyhow::Result<()> {
    let value = update_pause(paths, sending, receiving)?;
    println!(
        "Sending: {} · receiving: {}",
        if value.pause_sending {
            "paused"
        } else {
            "active"
        },
        if value.pause_receiving {
            "paused"
        } else {
            "active"
        }
    );
    Ok(())
}

pub(crate) fn update_pause(
    paths: &Paths,
    sending: Option<bool>,
    receiving: Option<bool>,
) -> anyhow::Result<state::StateFile> {
    let mut value = state::load(paths)?;
    if let Some(flag) = sending {
        value.pause_sending = flag;
    }
    if let Some(flag) = receiving {
        value.pause_receiving = flag;
    }
    state::save(paths, &value)?;
    Ok(value)
}

pub fn list_history(paths: &Paths) -> anyhow::Result<()> {
    println!(
        "{:<24} {:<8} {:<10} {:<18} {:<16} STATUS",
        "WHEN", "DIR", "TYPE", "CHANNEL", "ORIGIN"
    );
    for row in history::recent(&paths.history_db, 100)? {
        let when = chrono::DateTime::from_timestamp_millis(row.stored_at)
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "invalid".into());
        println!(
            "{:<24} {:<8} {:<10} {:<18} {:<16} {}",
            truncate(&when, 23),
            row.direction,
            short_type(&row.content_type),
            truncate(&row.channel_name, 17),
            truncate(&row.origin_device_name, 15),
            row.delivery_status
        );
        println!(
            "  local:{} item:{} channel:{}",
            row.local_id, row.item_id, row.channel_id
        );
    }
    Ok(())
}

pub fn history_item(paths: &Paths, local_id: Uuid) -> anyhow::Result<crypto::ClipboardItem> {
    let state_file = state::load(paths)?;
    let server = state_file.server.context("not paired; history is locked")?;
    let stored = history::entry(&paths.history_db, local_id)?;
    let secret = state::channel_secret(server.instance_id, stored.summary.channel_id)
        .context("history is locked; rejoin the channel to restore access")?;
    let metadata = if stored.summary.direction == "received" {
        serde_json::from_str::<ItemMetadata>(&stored.metadata_json)?
    } else {
        let envelope: crypto::EncryptedEnvelope = serde_json::from_str(&stored.metadata_json)?;
        ItemMetadata {
            id: envelope.id,
            channel_id: envelope.channel_id,
            origin_device_id: envelope.origin_device_id,
            origin_device_name: stored.summary.origin_device_name,
            channel_sequence: 0,
            crypto_version: envelope.crypto_version,
            content_type: envelope.content_type,
            ciphertext_size: envelope.ciphertext.len(),
            plaintext_size: Some(envelope.plaintext_size),
            image_width: envelope.image_width,
            image_height: envelope.image_height,
            nonce: envelope.nonce,
            created_at_client: Some(envelope.created_at_client),
            accepted_at: String::new(),
        }
    };
    Ok(crypto::decrypt_item(
        &secret,
        server.instance_id,
        &metadata,
        stored.ciphertext,
    )?)
}

pub fn show_history(paths: &Paths, local_id: Uuid, reveal: bool) -> anyhow::Result<()> {
    let stored = history::entry(&paths.history_db, local_id)?;
    println!(
        "Local ID:   {}\nItem ID:    {}\nChannel:    {} ({})\nOrigin:     {}\nDirection:  {}\nType:       {}\nStatus:     {}",
        stored.summary.local_id,
        stored.summary.item_id,
        stored.summary.channel_name,
        stored.summary.channel_id,
        stored.summary.origin_device_name,
        stored.summary.direction,
        stored.summary.content_type,
        stored.summary.delivery_status
    );
    if reveal {
        match history_item(paths, local_id)? {
            crypto::ClipboardItem::Text(bytes) => print!("\n{}", String::from_utf8(bytes)?),
            crypto::ClipboardItem::Png {
                width,
                height,
                bytes,
            } => println!(
                "\nPNG: {width} × {height}, {} bytes (use history export)",
                bytes.len()
            ),
            crypto::ClipboardItem::File(manifest) => println!(
                "\nFile: {}, {} bytes, available until {} (use history export)",
                manifest.filename, manifest.size, manifest.expires_at
            ),
        }
    } else {
        println!("\nPlaintext hidden. Pass --reveal to decrypt explicitly.");
    }
    Ok(())
}

pub fn copy_history(paths: &Paths, local_id: Uuid) -> anyhow::Result<()> {
    let item = history_item(paths, local_id)?;
    if matches!(item, crypto::ClipboardItem::File(_)) {
        bail!("files cannot be copied; use `clipmesh history export`");
    }
    crate::clipboard::write_once(&item)?;
    println!("Copied history entry {local_id}");
    Ok(())
}

pub async fn resend_history(paths: &Paths, local_id: Uuid) -> anyhow::Result<()> {
    let item = history_item(paths, local_id)?;
    if matches!(item, crypto::ClipboardItem::File(_)) {
        bail!("send the original file again instead of resending a retained file link");
    }
    crate::sync::publish_once(paths, &item).await?;
    println!("Resent history entry {local_id}");
    Ok(())
}

pub async fn export_history(paths: &Paths, local_id: Uuid, output: &Path) -> anyhow::Result<()> {
    let stored = history::entry(&paths.history_db, local_id)?;
    let item = history_item(paths, local_id)?;
    if let crypto::ClipboardItem::File(manifest) = item {
        let destination =
            crate::file_transfer::download(paths, &manifest, stored.summary.channel_id, output)
                .await?;
        println!("Downloaded file to {}", destination.display());
    } else {
        std::fs::write(output, item.bytes())?;
        println!("Exported plaintext to {}", output.display());
    }
    Ok(())
}

pub async fn forget(paths: &Paths) -> anyhow::Result<()> {
    let mut value = state::load(paths)?;
    let Some(server) = value.server.take() else {
        return Ok(());
    };
    for channel in &value.channels {
        state::delete_channel_secret(server.instance_id, channel.id)?;
    }
    state::delete_server_secrets(server.instance_id)?;
    value.channels.clear();
    value.routes.clear();
    value.last_sequences.clear();
    state::save(paths, &value)?;
    println!("Forgot {}. Local history remains encrypted.", server.url);
    Ok(())
}

pub fn prompt(label: &str, secret: bool) -> anyhow::Result<String> {
    if secret {
        return rpassword::prompt_password(label).context("could not read password");
    }
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}
async fn finish_join(
    api: &Api,
    server: &ServerRecord,
    secret: &crypto::ChannelSecret,
) -> anyhow::Result<()> {
    let challenge = api.join_challenge(secret.channel_id).await?;
    if challenge.server_instance_id != server.instance_id
        || challenge.channel_id != secret.channel_id
        || challenge.device_id != server.device_id
    {
        bail!("server returned a mismatched join challenge");
    }
    let signature = crypto::sign_join_challenge(
        secret,
        server.instance_id,
        server.device_id,
        challenge.challenge_id,
        &challenge.challenge_random,
        challenge.expires_at,
    )?;
    api.join(
        secret.channel_id,
        &JoinChannelRequest {
            challenge_id: challenge.challenge_id,
            signature_algorithm: "ecdsa-p256-sha256".into(),
            signature,
        },
    )
    .await
}
fn authenticated(paths: &Paths) -> anyhow::Result<(state::StateFile, Api)> {
    let state_file = state::load(paths)?;
    let server = state_file
        .server
        .as_ref()
        .context("not paired; run `clipmesh pair`")?;
    let api = Api::authenticated(server, &state::server_secrets(server.instance_id)?)?;
    Ok((state_file, api))
}
fn prompt_password_twice() -> anyhow::Result<String> {
    let first = prompt("Channel password: ", true)?;
    let second = prompt("Confirm password: ", true)?;
    if first != second {
        bail!("passwords do not match");
    }
    Ok(first)
}
fn api_url(value: &str) -> anyhow::Result<String> {
    Ok(crate::api::validated_server_url(value)?.to_string())
}
fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
fn truncate(value: &str, length: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(length).collect();
    if chars.next().is_some() {
        format!(
            "{}…",
            prefix
                .chars()
                .take(length.saturating_sub(1))
                .collect::<String>()
        )
    } else {
        prefix
    }
}
fn short_type(value: &str) -> &str {
    match value {
        "text/plain" => "text",
        "image/png" => "png",
        clipmesh_protocol::FILE_MANIFEST_CONTENT_TYPE => "file",
        _ => "unknown",
    }
}
