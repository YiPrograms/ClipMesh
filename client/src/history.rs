use std::path::Path;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::Context;
use clipmesh_protocol::{crypto::EncryptedEnvelope, wire::ItemMetadata};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct HistoryRow {
    pub local_id: Uuid,
    pub item_id: Uuid,
    pub channel_id: Uuid,
    pub channel_name: String,
    pub origin_device_name: String,
    pub direction: String,
    pub content_type: String,
    pub stored_at: i64,
    pub delivery_status: String,
}

#[derive(Clone, Debug)]
pub struct StoredHistory {
    pub summary: HistoryRow,
    pub metadata_json: String,
    pub ciphertext: Vec<u8>,
}

pub fn open(path: &Path) -> anyhow::Result<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS history(local_id TEXT PRIMARY KEY,item_id TEXT NOT NULL,channel_id TEXT NOT NULL,channel_name TEXT NOT NULL,origin_device_name TEXT NOT NULL,direction TEXT NOT NULL,content_type TEXT NOT NULL,metadata_json TEXT NOT NULL,ciphertext BLOB NOT NULL,stored_at INTEGER NOT NULL,delivery_status TEXT NOT NULL); CREATE INDEX IF NOT EXISTS history_recent ON history(stored_at DESC); CREATE TABLE IF NOT EXISTS outbox(singleton INTEGER PRIMARY KEY CHECK(singleton=1),nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,targets_json TEXT NOT NULL,captured_at INTEGER NOT NULL);")?;
    Ok(connection)
}

pub fn add_received(
    path: &Path,
    metadata: &ItemMetadata,
    channel_name: &str,
    ciphertext: &[u8],
    status: &str,
) -> anyhow::Result<()> {
    insert(
        path,
        metadata.id,
        metadata.channel_id,
        channel_name,
        &metadata.origin_device_name,
        "received",
        &metadata.content_type,
        metadata,
        ciphertext,
        status,
    )
}

pub fn add_sent(
    path: &Path,
    envelope: &EncryptedEnvelope,
    channel_name: &str,
    device_name: &str,
    status: &str,
) -> anyhow::Result<()> {
    insert(
        path,
        envelope.id,
        envelope.channel_id,
        channel_name,
        device_name,
        "sent",
        &envelope.content_type,
        envelope,
        &envelope.ciphertext,
        status,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert(
    path: &Path,
    item_id: Uuid,
    channel_id: Uuid,
    channel_name: &str,
    origin: &str,
    direction: &str,
    content_type: &str,
    metadata: &impl Serialize,
    ciphertext: &[u8],
    status: &str,
) -> anyhow::Result<()> {
    let connection = open(path)?;
    connection.execute("INSERT INTO history(local_id,item_id,channel_id,channel_name,origin_device_name,direction,content_type,metadata_json,ciphertext,stored_at,delivery_status) VALUES(?,?,?,?,?,?,?,?,?,?,?)", params![Uuid::new_v4().to_string(),item_id.to_string(),channel_id.to_string(),channel_name,origin,direction,content_type,serde_json::to_string(metadata)?,ciphertext,chrono::Utc::now().timestamp_millis(),status])?;
    connection.execute("DELETE FROM history WHERE local_id IN (SELECT local_id FROM history ORDER BY stored_at DESC LIMIT -1 OFFSET 500)", [])?;
    Ok(())
}

pub fn recent(path: &Path, limit: usize) -> anyhow::Result<Vec<HistoryRow>> {
    let connection = open(path)?;
    let mut statement = connection.prepare("SELECT local_id,item_id,channel_id,channel_name,origin_device_name,direction,content_type,stored_at,delivery_status FROM history ORDER BY stored_at DESC LIMIT ?")?;
    let rows = statement.query_map([limit as i64], |row| {
        Ok(HistoryRow {
            local_id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
            item_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap(),
            channel_id: Uuid::parse_str(&row.get::<_, String>(2)?).unwrap(),
            channel_name: row.get(3)?,
            origin_device_name: row.get(4)?,
            direction: row.get(5)?,
            content_type: row.get(6)?,
            stored_at: row.get(7)?,
            delivery_status: row.get(8)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("could not read history")
}

pub fn clear(path: &Path) -> anyhow::Result<()> {
    open(path)?.execute("DELETE FROM history", [])?;
    Ok(())
}

pub fn entry(path: &Path, local_id: Uuid) -> anyhow::Result<StoredHistory> {
    let connection = open(path)?;
    connection.query_row("SELECT local_id,item_id,channel_id,channel_name,origin_device_name,direction,content_type,stored_at,delivery_status,metadata_json,ciphertext FROM history WHERE local_id=?", [local_id.to_string()], |row| Ok(StoredHistory {
        summary: HistoryRow {
            local_id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
            item_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap(),
            channel_id: Uuid::parse_str(&row.get::<_, String>(2)?).unwrap(),
            channel_name: row.get(3)?,
            origin_device_name: row.get(4)?,
            direction: row.get(5)?,
            content_type: row.get(6)?,
            stored_at: row.get(7)?,
            delivery_status: row.get(8)?,
        },
        metadata_json: row.get(9)?,
        ciphertext: row.get(10)?,
    })).context("history entry was not found")
}

pub fn contains_item(path: &Path, item_id: Uuid) -> anyhow::Result<bool> {
    let value: i64 = open(path)?.query_row(
        "SELECT EXISTS(SELECT 1 FROM history WHERE item_id=?)",
        [item_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(value != 0)
}

pub fn delete(path: &Path, local_id: Uuid) -> anyhow::Result<()> {
    let changed = open(path)?.execute(
        "DELETE FROM history WHERE local_id=?",
        [local_id.to_string()],
    )?;
    if changed == 0 {
        anyhow::bail!("history entry was not found");
    }
    Ok(())
}

pub fn set_outbox(
    path: &Path,
    key: &[u8; 32],
    item: &clipmesh_protocol::crypto::ClipboardItem,
    targets: &[Uuid],
) -> anyhow::Result<()> {
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_value = Nonce::from(nonce);
    let ciphertext = Aes256Gcm::new_from_slice(key)?
        .encrypt(&nonce_value, serde_json::to_vec(item)?.as_ref())
        .map_err(|_| anyhow::anyhow!("could not encrypt the local outbox"))?;
    open(path)?.execute("INSERT INTO outbox(singleton,nonce,ciphertext,targets_json,captured_at) VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,targets_json=excluded.targets_json,captured_at=excluded.captured_at", params![nonce.to_vec(),ciphertext,serde_json::to_string(targets)?,chrono::Utc::now().timestamp_millis()])?;
    Ok(())
}

pub fn outbox(
    path: &Path,
    key: &[u8; 32],
) -> anyhow::Result<Option<(clipmesh_protocol::crypto::ClipboardItem, Vec<Uuid>)>> {
    let connection = open(path)?;
    let record: Option<(Vec<u8>, Vec<u8>, String)> = connection
        .query_row(
            "SELECT nonce,ciphertext,targets_json FROM outbox WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((nonce, ciphertext, targets)) = record else {
        return Ok(None);
    };
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid outbox nonce"))?;
    let nonce_value = Nonce::from(nonce);
    let plaintext = Aes256Gcm::new_from_slice(key)?
        .decrypt(&nonce_value, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("local outbox authentication failed"))?;
    Ok(Some((
        serde_json::from_slice(&plaintext)?,
        serde_json::from_str(&targets)?,
    )))
}

pub fn clear_outbox(path: &Path) -> anyhow::Result<()> {
    open(path)?.execute("DELETE FROM outbox", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clipmesh_protocol::crypto::ClipboardItem;

    #[test]
    fn outbox_is_authenticated_and_latest_only() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("history.sqlite3");
        let key = [7_u8; 32];
        let channel = Uuid::new_v4();
        set_outbox(
            &database,
            &key,
            &ClipboardItem::Text(b"first".to_vec()),
            &[channel],
        )
        .unwrap();
        set_outbox(
            &database,
            &key,
            &ClipboardItem::Text(b"latest".to_vec()),
            &[channel],
        )
        .unwrap();
        let (item, targets) = outbox(&database, &key).unwrap().unwrap();
        assert_eq!(item.bytes(), b"latest");
        assert_eq!(targets, vec![channel]);
        assert!(outbox(&database, &[8_u8; 32]).is_err());
        clear_outbox(&database).unwrap();
        assert!(outbox(&database, &key).unwrap().is_none());
    }
}
