use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::require_membership,
    error::{ApiError, ApiResult},
    model::{AuthDevice, ItemMetadata, UploadResponse},
    state::{AppState, RealtimeEvent},
};

type ItemRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Vec<u8>,
    Option<String>,
    String,
    String,
);

pub async fn upload(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<UploadResponse>)> {
    require_membership(&state, device.id, channel_id).await?;
    if !state
        .check_rate(
            format!("upload:{}", device.id),
            60,
            std::time::Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }
    let item_id = parse_uuid_header(&headers, "idempotency-key")?;
    if item_id.get_version() != Some(uuid::Version::SortRand) {
        return Err(ApiError::BadRequest("item ID must be UUIDv7".into()));
    }
    let crypto_version = parse_u64_header(&headers, "x-crypto-version")?;
    if crypto_version != 1 {
        return Err(ApiError::BadRequest("unsupported crypto version".into()));
    }
    let content_type = text_header(&headers, "x-content-type")?;
    let plaintext_maximum = match content_type.as_str() {
        "text/plain" => 1024 * 1024,
        "image/png" => 16 * 1024 * 1024,
        clipmesh_protocol::FILE_MANIFEST_CONTENT_TYPE => clipmesh_protocol::MAX_FILE_MANIFEST_BYTES,
        _ => return Err(ApiError::BadRequest("unsupported content type".into())),
    };
    let linked_file_id = optional_text_header(&headers, "x-file-id")?
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|_| ApiError::BadRequest("invalid x-file-id header".into()))
        })
        .transpose()?;
    if content_type == clipmesh_protocol::FILE_MANIFEST_CONTENT_TYPE {
        let file_id = linked_file_id
            .ok_or_else(|| ApiError::BadRequest("file manifest requires x-file-id".into()))?;
        let file: Option<(String, String, String, i64)> = sqlx::query_as(
            "SELECT channel_id,origin_device_id,status,expires_at FROM file_objects WHERE file_id=?",
        )
        .bind(file_id.to_string())
        .fetch_optional(&state.db)
        .await?;
        let Some((file_channel, origin, status, expires_at)) = file else {
            return Err(ApiError::BadRequest("linked file does not exist".into()));
        };
        if file_channel != channel_id.to_string() || origin != device.id.to_string() {
            return Err(ApiError::Forbidden);
        }
        if status != "ready" || expires_at < Utc::now().timestamp() {
            return Err(ApiError::Gone);
        }
    } else if linked_file_id.is_some() {
        return Err(ApiError::BadRequest(
            "only file manifests may include x-file-id".into(),
        ));
    }
    if body.len() < 16 || body.len() > plaintext_maximum + 16 {
        return Err(ApiError::PayloadTooLarge);
    }
    let nonce_text = text_header(&headers, "x-envelope-nonce")?;
    let nonce = STANDARD
        .decode(&nonce_text)
        .map_err(|_| ApiError::BadRequest("invalid envelope nonce".into()))?;
    if nonce.len() != 12 {
        return Err(ApiError::BadRequest(
            "envelope nonce must be 12 bytes".into(),
        ));
    }
    let created_at =
        optional_text_header(&headers, "x-client-created-at")?.filter(|value| !value.is_empty());
    if let Some(value) = &created_at {
        chrono::DateTime::parse_from_rfc3339(value)
            .map_err(|_| ApiError::BadRequest("invalid client timestamp".into()))?;
    }
    let plaintext_size = optional_u64_header(&headers, "x-plaintext-size")?;
    if plaintext_size.is_some_and(|value| value > plaintext_maximum as u64) {
        return Err(ApiError::PayloadTooLarge);
    }
    let width = optional_u64_header(&headers, "x-image-width")?;
    let height = optional_u64_header(&headers, "x-image-height")?;
    if content_type == "image/png" {
        let (width_value, height_value) = width
            .zip(height)
            .ok_or_else(|| ApiError::BadRequest("image dimensions are required".into()))?;
        if width_value == 0
            || height_value == 0
            || width_value > 16_384
            || height_value > 16_384
            || width_value.saturating_mul(height_value) > 64_000_000
        {
            return Err(ApiError::BadRequest(
                "image dimensions exceed limits".into(),
            ));
        }
    } else if width.is_some() || height.is_some() {
        return Err(ApiError::BadRequest(
            "non-image item cannot include image dimensions".into(),
        ));
    }

    if let Some(existing) = find_item(&state, item_id).await? {
        if existing.1 != channel_id.to_string() || existing.2 != device.id.to_string() {
            return Err(ApiError::Conflict(
                "idempotency key belongs to another envelope".into(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(UploadResponse {
                id: item_id,
                channel_sequence: existing.4 as u64,
                accepted_at: existing.13,
                deduplicated: true,
            }),
        ));
    }

    let channel_lock = state
        .channel_writes
        .entry(channel_id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _write_guard = channel_lock.lock().await;
    if let Some(existing) = find_item(&state, item_id).await? {
        if existing.1 != channel_id.to_string() || existing.2 != device.id.to_string() {
            return Err(ApiError::Conflict(
                "idempotency key belongs to another envelope".into(),
            ));
        }
        return Ok((
            StatusCode::OK,
            Json(UploadResponse {
                id: item_id,
                channel_sequence: existing.4 as u64,
                accepted_at: existing.13,
                deduplicated: true,
            }),
        ));
    }

    let channel_dir = state.config.blob_dir.join(channel_id.to_string());
    tokio::fs::create_dir_all(&channel_dir)
        .await
        .map_err(anyhow::Error::from)?;
    let blob_key = format!("{}.bin", item_id.simple());
    let blob_path = channel_dir.join(&blob_key);
    let temporary = channel_dir.join(format!(".{}.tmp", item_id.simple()));
    tokio::fs::write(&temporary, &body)
        .await
        .map_err(anyhow::Error::from)?;
    tokio::fs::rename(&temporary, &blob_path)
        .await
        .map_err(anyhow::Error::from)?;

    let accepted_at = Utc::now();
    let result: ApiResult<u64> = async {
        let mut transaction = state.db.begin().await?;
        let sequence: i64 = sqlx::query_scalar("UPDATE channels SET current_sequence=current_sequence+1 WHERE id=? AND deleted_at IS NULL RETURNING current_sequence")
            .bind(channel_id.to_string()).fetch_optional(&mut *transaction).await?.ok_or(ApiError::NotFound)?;
        sqlx::query("INSERT INTO delivery_cache_items(item_id,channel_id,origin_device_id,channel_sequence,crypto_version,content_type,ciphertext_size,plaintext_size,image_width,image_height,nonce,created_at_client,accepted_at_server,expires_at,blob_key) SELECT item_id,channel_id,origin_device_id,channel_sequence,crypto_version,content_type,ciphertext_size,plaintext_size,image_width,image_height,nonce,created_at_client,accepted_at_server,?,blob_key FROM current_channel_items WHERE channel_id=?")
            .bind((accepted_at + Duration::minutes(5)).to_rfc3339()).bind(channel_id.to_string()).execute(&mut *transaction).await?;
        sqlx::query("DELETE FROM current_channel_items WHERE channel_id=?").bind(channel_id.to_string()).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO current_channel_items(item_id,channel_id,origin_device_id,channel_sequence,crypto_version,content_type,ciphertext_size,plaintext_size,image_width,image_height,nonce,created_at_client,accepted_at_server,blob_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(item_id.to_string()).bind(channel_id.to_string()).bind(device.id.to_string()).bind(sequence).bind(crypto_version as i64).bind(&content_type).bind(body.len() as i64)
            .bind(plaintext_size.map(|v| v as i64)).bind(width.map(|v| v as i64)).bind(height.map(|v| v as i64)).bind(&nonce).bind(&created_at).bind(accepted_at.to_rfc3339()).bind(&blob_key)
            .execute(&mut *transaction).await?;
        if let Some(file_id) = linked_file_id {
            sqlx::query("INSERT INTO file_manifests(file_id,item_id,channel_id,origin_device_id,channel_sequence,crypto_version,content_type,ciphertext_size,plaintext_size,nonce,created_at_client,accepted_at_server,blob_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
                .bind(file_id.to_string()).bind(item_id.to_string()).bind(channel_id.to_string()).bind(device.id.to_string()).bind(sequence).bind(crypto_version as i64).bind(&content_type).bind(body.len() as i64).bind(plaintext_size.map(|v|v as i64)).bind(&nonce).bind(&created_at).bind(accepted_at.to_rfc3339()).bind(&blob_key)
                .execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(sequence as u64)
    }.await;
    let sequence = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = tokio::fs::remove_file(&blob_path).await;
            return Err(error);
        }
    };
    prune_cache(&state, channel_id).await?;
    let metadata = ItemMetadata {
        id: item_id.to_string(),
        channel_id: channel_id.to_string(),
        origin_device_id: device.id.to_string(),
        origin_device_name: device.name,
        channel_sequence: sequence as i64,
        crypto_version: crypto_version as i64,
        content_type: content_type.clone(),
        ciphertext_size: body.len() as i64,
        plaintext_size: plaintext_size.map(|v| v as i64),
        image_width: width.map(|v| v as i64),
        image_height: height.map(|v| v as i64),
        nonce: nonce_text,
        created_at_client: created_at,
        accepted_at: accepted_at.to_rfc3339(),
    };
    let _ = state.events.send(RealtimeEvent {
        channel_id,
        event: serde_json::json!({"type":"item_created","item":metadata}),
    });
    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            id: item_id,
            channel_sequence: sequence,
            accepted_at: accepted_at.to_rfc3339(),
            deduplicated: false,
        }),
    ))
}

pub async fn current(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<Json<ItemMetadata>> {
    require_membership(&state, device.id, channel_id).await?;
    let row = query_item(&state, "SELECT i.item_id,i.channel_id,i.origin_device_id,d.name,i.channel_sequence,i.crypto_version,i.content_type,i.ciphertext_size,i.plaintext_size,i.image_width,i.image_height,i.nonce,i.created_at_client,i.accepted_at_server,i.blob_key FROM current_channel_items i JOIN devices d ON d.id=i.origin_device_id WHERE i.channel_id=?", channel_id.to_string()).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(to_metadata(row)))
}

pub async fn content(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(item_id): Path<Uuid>,
) -> ApiResult<Response> {
    let row = find_item(&state, item_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let channel_id = Uuid::parse_str(&row.1).map_err(|error| ApiError::Internal(error.into()))?;
    require_membership(&state, device.id, channel_id).await?;
    let path = state.config.blob_dir.join(&row.1).join(&row.14);
    let bytes = tokio::fs::read(path).await.map_err(anyhow::Error::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct AckRequest {
    channel_id: Uuid,
    sequence: u64,
}

pub async fn ack(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(item_id): Path<Uuid>,
    Json(request): Json<AckRequest>,
) -> ApiResult<StatusCode> {
    require_membership(&state, device.id, request.channel_id).await?;
    let row = find_item(&state, item_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.1 != request.channel_id.to_string() || row.4 != request.sequence as i64 {
        return Err(ApiError::BadRequest("ack metadata mismatch".into()));
    }
    sqlx::query("UPDATE channel_memberships SET last_delivered_sequence=MAX(last_delivered_sequence,?) WHERE channel_id=? AND device_id=?")
        .bind(request.sequence as i64).bind(request.channel_id.to_string()).bind(device.id.to_string()).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn find_item(state: &AppState, item_id: Uuid) -> ApiResult<Option<ItemRow>> {
    let sql = "SELECT i.item_id,i.channel_id,i.origin_device_id,d.name,i.channel_sequence,i.crypto_version,i.content_type,i.ciphertext_size,i.plaintext_size,i.image_width,i.image_height,i.nonce,i.created_at_client,i.accepted_at_server,i.blob_key FROM current_channel_items i JOIN devices d ON d.id=i.origin_device_id WHERE i.item_id=? UNION ALL SELECT i.item_id,i.channel_id,i.origin_device_id,d.name,i.channel_sequence,i.crypto_version,i.content_type,i.ciphertext_size,i.plaintext_size,i.image_width,i.image_height,i.nonce,i.created_at_client,i.accepted_at_server,i.blob_key FROM delivery_cache_items i JOIN devices d ON d.id=i.origin_device_id WHERE i.item_id=? UNION ALL SELECT i.item_id,i.channel_id,i.origin_device_id,d.name,i.channel_sequence,i.crypto_version,i.content_type,i.ciphertext_size,i.plaintext_size,NULL,NULL,i.nonce,i.created_at_client,i.accepted_at_server,i.blob_key FROM file_manifests i JOIN devices d ON d.id=i.origin_device_id JOIN file_objects f ON f.file_id=i.file_id WHERE i.item_id=? AND f.status='ready' AND f.expires_at>=? LIMIT 1";
    Ok(sqlx::query_as(sql)
        .bind(item_id.to_string())
        .bind(item_id.to_string())
        .bind(Utc::now().timestamp())
        .bind(item_id.to_string())
        .fetch_optional(&state.db)
        .await?)
}

async fn query_item(state: &AppState, sql: &str, value: String) -> ApiResult<Option<ItemRow>> {
    Ok(sqlx::query_as(sql)
        .bind(value)
        .fetch_optional(&state.db)
        .await?)
}

fn to_metadata(row: ItemRow) -> ItemMetadata {
    ItemMetadata {
        id: row.0,
        channel_id: row.1,
        origin_device_id: row.2,
        origin_device_name: row.3,
        channel_sequence: row.4,
        crypto_version: row.5,
        content_type: row.6,
        ciphertext_size: row.7,
        plaintext_size: row.8,
        image_width: row.9,
        image_height: row.10,
        nonce: STANDARD.encode(row.11),
        created_at_client: row.12,
        accepted_at: row.13,
    }
}

async fn prune_cache(state: &AppState, channel_id: Uuid) -> ApiResult<()> {
    let rows: Vec<(String,String)> = sqlx::query_as("SELECT item_id,blob_key FROM delivery_cache_items WHERE channel_id=? AND (expires_at<? OR item_id NOT IN (SELECT item_id FROM delivery_cache_items WHERE channel_id=? ORDER BY channel_sequence DESC LIMIT 32)) ORDER BY channel_sequence")
        .bind(channel_id.to_string()).bind(Utc::now().to_rfc3339()).bind(channel_id.to_string()).fetch_all(&state.db).await?;
    for (item, blob) in rows {
        sqlx::query("DELETE FROM delivery_cache_items WHERE item_id=?")
            .bind(item)
            .execute(&state.db)
            .await?;
        remove_blob_if_unretained(state, channel_id, &blob).await?;
    }
    let mut total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(ciphertext_size),0) FROM delivery_cache_items WHERE channel_id=?",
    )
    .bind(channel_id.to_string())
    .fetch_one(&state.db)
    .await?;
    if total > 64 * 1024 * 1024 {
        let extra: Vec<(String,String,i64)> = sqlx::query_as("SELECT item_id,blob_key,ciphertext_size FROM delivery_cache_items WHERE channel_id=? ORDER BY channel_sequence").bind(channel_id.to_string()).fetch_all(&state.db).await?;
        for (item, blob, size) in extra {
            if total <= 64 * 1024 * 1024 {
                break;
            }
            sqlx::query("DELETE FROM delivery_cache_items WHERE item_id=?")
                .bind(item)
                .execute(&state.db)
                .await?;
            remove_blob_if_unretained(state, channel_id, &blob).await?;
            total -= size;
        }
    }
    Ok(())
}

async fn remove_blob_if_unretained(
    state: &AppState,
    channel_id: Uuid,
    blob: &str,
) -> ApiResult<()> {
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM file_manifests WHERE channel_id=? AND blob_key=?)",
    )
    .bind(channel_id.to_string())
    .bind(blob)
    .fetch_one(&state.db)
    .await?;
    if !retained {
        let _ = tokio::fs::remove_file(
            state
                .config
                .blob_dir
                .join(channel_id.to_string())
                .join(blob),
        )
        .await;
    }
    Ok(())
}

fn text_header(headers: &HeaderMap, name: &str) -> ApiResult<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::BadRequest(format!("missing or invalid {name} header")))
}
fn optional_text_header(headers: &HeaderMap, name: &str) -> ApiResult<Option<String>> {
    headers
        .get(name)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::BadRequest(format!("invalid {name} header")))
        })
        .transpose()
}
fn parse_u64_header(headers: &HeaderMap, name: &str) -> ApiResult<u64> {
    text_header(headers, name)?
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid {name} header")))
}
fn optional_u64_header(headers: &HeaderMap, name: &str) -> ApiResult<Option<u64>> {
    optional_text_header(headers, name)?
        .map(|v| {
            v.parse()
                .map_err(|_| ApiError::BadRequest(format!("invalid {name} header")))
        })
        .transpose()
}
fn parse_uuid_header(headers: &HeaderMap, name: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(&text_header(headers, name)?)
        .map_err(|_| ApiError::BadRequest(format!("invalid {name} header")))
}
