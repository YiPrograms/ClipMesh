use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clipmesh_protocol::{
    FILE_CHUNK_BYTES,
    crypto::{self, ClipboardItem, FileManifest},
    wire::CreateFileRequest,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use uuid::Uuid;

use crate::{
    api::Api,
    state::{self, Paths},
};

pub async fn send_path(
    paths: &Paths,
    source: &Path,
    filename: &str,
    media_type: &str,
) -> anyhow::Result<()> {
    let state_file = state::load(paths)?;
    let server = state_file
        .server
        .as_ref()
        .context("not paired; run `clipmesh pair`")?;
    let targets: Vec<_> = state_file
        .routes
        .iter()
        .filter(|route| route.send_enabled)
        .map(|route| route.channel_id)
        .collect();
    if targets.is_empty() {
        bail!("no send route is enabled");
    }
    if state_file.pause_sending {
        bail!("sending is paused");
    }
    let api = Api::authenticated(server, &state::server_secrets(server.instance_id)?)?;
    let info = api.info().await?;
    let support = info
        .file_transfer
        .context("this server does not support file transfer")?;
    let size = tokio::fs::metadata(source).await?.len();
    if size > support.max_file_bytes {
        bail!(
            "file is {} bytes; this server allows at most {} bytes",
            size,
            support.max_file_bytes
        );
    }
    if support.chunk_bytes != FILE_CHUNK_BYTES {
        bail!("server uses an unsupported file chunk size");
    }
    let hash = hash_file(source).await?;
    for channel_id in targets {
        let channel = state_file
            .channels
            .iter()
            .find(|channel| channel.id == channel_id)
            .context("send route references an unknown channel")?;
        let secret = state::channel_secret(server.instance_id, channel_id)?;
        let file_id = Uuid::now_v7();
        let chunk_count = crypto::file_chunk_count(size, FILE_CHUNK_BYTES)?;
        let mut nonce_prefix = [0_u8; 8];
        rand::rng().fill_bytes(&mut nonce_prefix);
        let mut manifest = FileManifest {
            file_id,
            filename: filename.into(),
            media_type: media_type.into(),
            size,
            chunk_size: FILE_CHUNK_BYTES,
            chunk_count,
            nonce_prefix: STANDARD.encode(nonce_prefix),
            sha256: STANDARD.encode(hash),
            expires_at: 1,
        };
        crypto::validate_file_manifest(&manifest)?;
        let created = api
            .create_file(
                channel_id,
                &CreateFileRequest {
                    file_id,
                    plaintext_size: size,
                    chunk_size: FILE_CHUNK_BYTES,
                    chunk_count,
                },
            )
            .await?;
        let mut file = File::open(source).await?;
        for index in created.next_chunk..chunk_count {
            let length = crypto::file_chunk_plaintext_size(&manifest, index)?;
            let mut plaintext = vec![0_u8; length];
            file.seek(std::io::SeekFrom::Start(
                u64::from(index) * u64::from(FILE_CHUNK_BYTES),
            ))
            .await?;
            file.read_exact(&mut plaintext).await?;
            let ciphertext = crypto::encrypt_file_chunk(
                &secret,
                server.instance_id,
                &manifest,
                index,
                &plaintext,
            )?;
            api.upload_file_chunk(file_id, index, ciphertext).await?;
        }
        let completed = api.complete_file(file_id).await?;
        manifest.expires_at = completed.expires_at;
        crate::sync::publish_to(paths, &ClipboardItem::File(manifest), vec![channel_id]).await?;
        println!(
            "Sent {} to {} (available until {})",
            filename,
            channel.name,
            chrono::DateTime::from_timestamp(completed.expires_at, 0)
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| completed.expires_at.to_string())
        );
    }
    Ok(())
}

pub async fn download(
    paths: &Paths,
    manifest: &FileManifest,
    channel_id: Uuid,
    output: &Path,
) -> anyhow::Result<PathBuf> {
    crypto::validate_file_manifest(manifest)?;
    let state_file = state::load(paths)?;
    let server = state_file.server.as_ref().context("not paired")?;
    let secret = state::channel_secret(server.instance_id, channel_id)
        .context("history is locked; rejoin the channel to download this file")?;
    let api = Api::authenticated(server, &state::server_secrets(server.instance_id)?)?;
    let remote = api.file_metadata(manifest.file_id).await?;
    if remote.channel_id != channel_id
        || remote.plaintext_size != manifest.size
        || remote.chunk_size != manifest.chunk_size
        || remote.chunk_count != manifest.chunk_count
        || remote.status != "ready"
    {
        bail!("server returned mismatched file metadata");
    }
    let destination = if output.is_dir() {
        output.join(&manifest.filename)
    } else {
        output.to_owned()
    };
    let temporary = destination.with_extension(format!(
        "{}.clipmesh-part",
        destination
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
    ));
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await
        .with_context(|| format!("could not create {}", temporary.display()))?;
    let result: anyhow::Result<()> = async {
        let mut hash = Sha256::new();
        for index in 0..manifest.chunk_count {
            let ciphertext = api.file_chunk(manifest.file_id, index).await?;
            let plaintext = crypto::decrypt_file_chunk(
                &secret,
                server.instance_id,
                manifest,
                index,
                &ciphertext,
            )?;
            hash.update(&plaintext);
            file.write_all(&plaintext).await?;
        }
        file.flush().await?;
        if STANDARD.encode(hash.finalize()) != manifest.sha256 {
            bail!("downloaded file hash does not match its encrypted manifest");
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        drop(file);
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    drop(file);
    if tokio::fs::try_exists(&destination).await? {
        let _ = tokio::fs::remove_file(&temporary).await;
        bail!("{} already exists", destination.display());
    }
    tokio::fs::rename(&temporary, &destination).await?;
    Ok(destination)
}

async fn hash_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut file = File::open(path).await?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; FILE_CHUNK_BYTES as usize];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}
