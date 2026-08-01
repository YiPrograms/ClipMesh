use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::Instant,
};

use anyhow::Context;
use dashmap::DashMap;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

use crate::config::Config;

type ExpiredFileRow = (String, String, String, Option<String>, Option<String>);

#[derive(Clone, Debug, Serialize)]
pub struct RealtimeEvent {
    pub channel_id: Uuid,
    pub event: serde_json::Value,
}

pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub instance_id: Uuid,
    pub events: broadcast::Sender<RealtimeEvent>,
    pub disconnects: broadcast::Sender<Uuid>,
    pub ws_subscriptions: Arc<DashMap<(Uuid, Uuid), HashSet<Uuid>>>,
    pub ws_connections: Arc<DashMap<Uuid, usize>>,
    pub channel_writes: Arc<DashMap<Uuid, Arc<Mutex<()>>>>,
    pub file_writes: Arc<Mutex<()>>,
    pub rate_windows: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl AppState {
    pub async fn initialize(config: Config, db: SqlitePool) -> anyhow::Result<Self> {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT instance_id FROM server_info WHERE singleton = 1")
                .fetch_optional(&db)
                .await?;
        let instance_id = match existing {
            Some((value,)) => {
                Uuid::parse_str(&value).context("invalid stored server instance ID")?
            }
            None => {
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO server_info(singleton, instance_id, instance_name, created_at) VALUES (1, ?, ?, ?)")
                    .bind(id.to_string())
                    .bind(&config.instance_name)
                    .bind(chrono::Utc::now().to_rfc3339())
                    .execute(&db)
                    .await?;
                id
            }
        };
        let (events, _) = broadcast::channel(256);
        let (disconnects, _) = broadcast::channel(64);
        Ok(Self {
            config,
            db,
            instance_id,
            events,
            disconnects,
            ws_subscriptions: Arc::new(DashMap::new()),
            ws_connections: Arc::new(DashMap::new()),
            channel_writes: Arc::new(DashMap::new()),
            file_writes: Arc::new(Mutex::new(())),
            rate_windows: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn check_rate(
        &self,
        key: String,
        maximum: usize,
        window: std::time::Duration,
    ) -> bool {
        let mut windows = self.rate_windows.lock().await;
        let values = windows.entry(key).or_default();
        let now = Instant::now();
        while values
            .front()
            .is_some_and(|value| now.duration_since(*value) > window)
        {
            values.pop_front();
        }
        if values.len() >= maximum {
            return false;
        }
        values.push_back(now);
        true
    }

    pub fn spawn_cleanup(self: &Arc<Self>) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(error) = state.cleanup_once().await {
                    tracing::warn!(?error, "periodic cleanup failed");
                }
            }
        });
    }

    pub async fn reconcile_blobs(&self) -> anyhow::Result<()> {
        let referenced: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
            "SELECT channel_id,blob_key FROM current_channel_items UNION SELECT channel_id,blob_key FROM delivery_cache_items UNION SELECT channel_id,blob_key FROM file_objects WHERE status IN ('uploading','ready') UNION SELECT channel_id,blob_key FROM file_manifests",
        )
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .collect();
        let mut channels = tokio::fs::read_dir(&self.config.blob_dir).await?;
        while let Some(channel) = channels.next_entry().await? {
            if !channel.file_type().await?.is_dir() {
                continue;
            }
            let channel_name = channel.file_name().to_string_lossy().into_owned();
            let mut blobs = tokio::fs::read_dir(channel.path()).await?;
            while let Some(blob) = blobs.next_entry().await? {
                if !blob.file_type().await?.is_file() {
                    continue;
                }
                let blob_name = blob.file_name().to_string_lossy().into_owned();
                if !referenced.contains(&(channel_name.clone(), blob_name)) {
                    let _ = tokio::fs::remove_file(blob.path()).await;
                }
            }
        }
        Ok(())
    }

    async fn cleanup_once(&self) -> anyhow::Result<()> {
        let now = chrono::Utc::now();
        sqlx::query("DELETE FROM pairing_codes WHERE expires_at<? OR (consumed_at IS NOT NULL AND consumed_at<?)")
            .bind(now.to_rfc3339())
            .bind((now - chrono::Duration::minutes(5)).to_rfc3339())
            .execute(&self.db)
            .await?;
        sqlx::query("DELETE FROM channel_join_challenges WHERE expires_at<? OR (consumed_at IS NOT NULL AND consumed_at<?)")
            .bind(now.timestamp())
            .bind(now.timestamp() - 300)
            .execute(&self.db)
            .await?;
        sqlx::query("DELETE FROM ws_tickets WHERE expires_at<? OR (consumed_at IS NOT NULL AND consumed_at<?)")
            .bind(now.timestamp())
            .bind(now.timestamp() - 300)
            .execute(&self.db)
            .await?;
        let expired: Vec<(String, String)> = sqlx::query_as(
            "SELECT channel_id,blob_key FROM delivery_cache_items WHERE expires_at<?",
        )
        .bind(now.to_rfc3339())
        .fetch_all(&self.db)
        .await?;
        sqlx::query("DELETE FROM delivery_cache_items WHERE expires_at<?")
            .bind(now.to_rfc3339())
            .execute(&self.db)
            .await?;
        for (channel, blob) in expired {
            let retained: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM file_manifests WHERE channel_id=? AND blob_key=?)",
            )
            .bind(&channel)
            .bind(&blob)
            .fetch_one(&self.db)
            .await?;
            if !retained {
                let _ = tokio::fs::remove_file(self.config.blob_dir.join(channel).join(blob)).await;
            }
        }
        let expired_files: Vec<ExpiredFileRow> = sqlx::query_as(
            "SELECT f.file_id,f.channel_id,f.blob_key,m.item_id,m.blob_key FROM file_objects f LEFT JOIN file_manifests m ON m.file_id=f.file_id WHERE f.status IN ('uploading','ready') AND f.expires_at<?",
        )
        .bind(now.timestamp())
        .fetch_all(&self.db)
        .await?;
        for (file_id, channel, blob, manifest_item, manifest_blob) in &expired_files {
            if let Some(item_id) = manifest_item {
                sqlx::query("DELETE FROM current_channel_items WHERE item_id=?")
                    .bind(item_id)
                    .execute(&self.db)
                    .await?;
                sqlx::query("DELETE FROM delivery_cache_items WHERE item_id=?")
                    .bind(item_id)
                    .execute(&self.db)
                    .await?;
            }
            sqlx::query("DELETE FROM file_manifests WHERE file_id=?")
                .bind(file_id)
                .execute(&self.db)
                .await?;
            sqlx::query("UPDATE file_objects SET status='expired',deleted_at=? WHERE file_id=?")
                .bind(now.timestamp())
                .bind(file_id)
                .execute(&self.db)
                .await?;
            let _ = tokio::fs::remove_file(self.config.blob_dir.join(channel).join(blob)).await;
            if let Some(manifest_blob) = manifest_blob {
                let _ =
                    tokio::fs::remove_file(self.config.blob_dir.join(channel).join(manifest_blob))
                        .await;
            }
        }
        sqlx::query(
            "DELETE FROM file_objects WHERE status IN ('expired','deleted') AND deleted_at<?",
        )
        .bind((now - chrono::Duration::hours(24)).timestamp())
        .execute(&self.db)
        .await?;
        let orphaned: Vec<String> = sqlx::query_scalar("SELECT c.id FROM channels c WHERE c.created_at<? AND NOT EXISTS(SELECT 1 FROM channel_memberships m WHERE m.channel_id=c.id)")
            .bind((now - chrono::Duration::minutes(5)).to_rfc3339())
            .fetch_all(&self.db)
            .await?;
        for channel in orphaned {
            sqlx::query("DELETE FROM channels WHERE id=?")
                .bind(&channel)
                .execute(&self.db)
                .await?;
            let _ = tokio::fs::remove_dir_all(self.config.blob_dir.join(channel)).await;
        }
        Ok(())
    }
}
