use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use clipmesh_protocol::{
    FILE_CHUNK_BYTES,
    crypto::file_chunk_count,
    wire::{CreateFileRequest, FileObjectResponse},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    auth::require_membership,
    error::{ApiError, ApiResult},
    model::{AuthDevice, ItemMetadata},
    state::AppState,
};

type ManifestRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    i64,
    Option<i64>,
    Vec<u8>,
    Option<String>,
    String,
);

type FileRow = (
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    String,
    String,
    Option<String>,
    i64,
    Option<i64>,
    String,
);

pub async fn create(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<CreateFileRequest>,
) -> ApiResult<(StatusCode, Json<FileObjectResponse>)> {
    require_membership(&state, device.id, channel_id).await?;
    if request.file_id.get_version() != Some(uuid::Version::SortRand) {
        return Err(ApiError::BadRequest("file ID must be UUIDv7".into()));
    }
    if request.plaintext_size > state.config.max_file_bytes {
        return Err(ApiError::PayloadTooLarge);
    }
    if request.chunk_size != FILE_CHUNK_BYTES
        || request.chunk_count
            != file_chunk_count(request.plaintext_size, request.chunk_size)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?
    {
        return Err(ApiError::BadRequest("invalid file chunk layout".into()));
    }
    if !state
        .check_rate(
            format!("file-create:{}", device.id),
            60,
            std::time::Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }

    let _guard = state.file_writes.lock().await;
    if let Some(row) = find(&state, request.file_id).await? {
        if row.1 != channel_id.to_string()
            || row.2 != device.id.to_string()
            || row.3 != request.plaintext_size as i64
            || row.5 != i64::from(request.chunk_size)
            || row.6 != i64::from(request.chunk_count)
        {
            return Err(ApiError::Conflict(
                "file ID belongs to another upload".into(),
            ));
        }
        return Ok((StatusCode::OK, Json(to_response(row, true)?)));
    }

    let global_usage: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(plaintext_size),0) FROM file_objects WHERE status IN ('uploading','ready')",
    )
    .fetch_one(&state.db)
    .await?;
    let channel_usage: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(plaintext_size),0) FROM file_objects WHERE channel_id=? AND status IN ('uploading','ready')",
    )
    .bind(channel_id.to_string())
    .fetch_one(&state.db)
    .await?;
    if (global_usage as u64).saturating_add(request.plaintext_size)
        > state.config.file_storage_quota
        || (channel_usage as u64).saturating_add(request.plaintext_size)
            > state.config.file_channel_quota
    {
        return Err(ApiError::StorageFull);
    }

    let created_at = Utc::now();
    let expires_at = created_at.timestamp()
        + i64::try_from(state.config.incomplete_upload_retention.as_secs())
            .map_err(|error| ApiError::Internal(error.into()))?;
    let blob_key = format!("file-{}.part", request.file_id.simple());
    let directory = state.config.blob_dir.join(channel_id.to_string());
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(anyhow::Error::from)?;
    let path = directory.join(&blob_key);
    tokio::fs::File::create(&path)
        .await
        .map_err(anyhow::Error::from)?;
    let result = sqlx::query("INSERT INTO file_objects(file_id,channel_id,origin_device_id,plaintext_size,ciphertext_size,chunk_size,chunk_count,next_chunk,status,created_at,expires_at,blob_key) VALUES(?,?,?,?,0,?,?,0,'uploading',?,?,?)")
        .bind(request.file_id.to_string())
        .bind(channel_id.to_string())
        .bind(device.id.to_string())
        .bind(request.plaintext_size as i64)
        .bind(i64::from(request.chunk_size))
        .bind(i64::from(request.chunk_count))
        .bind(created_at.to_rfc3339())
        .bind(expires_at)
        .bind(&blob_key)
        .execute(&state.db)
        .await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(path).await;
        return Err(error.into());
    }
    let row = find(&state, request.file_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("created file disappeared")))?;
    Ok((StatusCode::CREATED, Json(to_response(row, false)?)))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<Json<Vec<ItemMetadata>>> {
    require_membership(&state, device.id, channel_id).await?;
    let rows: Vec<ManifestRow> = sqlx::query_as("SELECT m.item_id,m.channel_id,m.origin_device_id,d.name,m.channel_sequence,m.crypto_version,m.content_type,m.ciphertext_size,m.plaintext_size,m.nonce,m.created_at_client,m.accepted_at_server FROM file_manifests m JOIN file_objects f ON f.file_id=m.file_id JOIN devices d ON d.id=m.origin_device_id WHERE m.channel_id=? AND f.status='ready' AND f.expires_at>=? ORDER BY m.channel_sequence DESC LIMIT 512")
        .bind(channel_id.to_string())
        .bind(Utc::now().timestamp())
        .fetch_all(&state.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| ItemMetadata {
                id: row.0,
                channel_id: row.1,
                origin_device_id: row.2,
                origin_device_name: row.3,
                channel_sequence: row.4,
                crypto_version: row.5,
                content_type: row.6,
                ciphertext_size: row.7,
                plaintext_size: row.8,
                image_width: None,
                image_height: None,
                nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, row.9),
                created_at_client: row.10,
                accepted_at: row.11,
            })
            .collect(),
    ))
}

pub async fn upload_chunk(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path((file_id, index)): Path<(Uuid, u32)>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if !state
        .check_rate(
            format!("file-chunk:{}", device.id),
            600,
            std::time::Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }
    let _guard = state.file_writes.lock().await;
    let row = find(&state, file_id).await?.ok_or(ApiError::NotFound)?;
    let channel_id = parse_uuid(&row.1)?;
    require_membership(&state, device.id, channel_id).await?;
    if row.2 != device.id.to_string() {
        return Err(ApiError::Forbidden);
    }
    if row.8 != "uploading" || row.11 < Utc::now().timestamp() {
        return Err(ApiError::Gone);
    }
    let next_chunk = u32::try_from(row.7).map_err(|error| ApiError::Internal(error.into()))?;
    if index > next_chunk {
        return Err(ApiError::Conflict(format!(
            "expected chunk {next_chunk}, received {index}"
        )));
    }
    let plaintext_size = row.3 as u64;
    let chunk_size = row.5 as u32;
    let chunk_count = row.6 as u32;
    if index >= chunk_count {
        return Err(ApiError::BadRequest(
            "file chunk index is out of range".into(),
        ));
    }
    let plaintext_length = if plaintext_size == 0 {
        0
    } else {
        let offset = u64::from(index) * u64::from(chunk_size);
        (plaintext_size - offset).min(u64::from(chunk_size))
    };
    let expected =
        usize::try_from(plaintext_length + 16).map_err(|error| ApiError::Internal(error.into()))?;
    if body.len() != expected {
        return Err(ApiError::BadRequest(
            "encrypted file chunk has the wrong length".into(),
        ));
    }

    let path = state.config.blob_dir.join(&row.1).join(&row.13);
    let offset = u64::from(index) * (u64::from(chunk_size) + 16);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await
        .map_err(anyhow::Error::from)?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(anyhow::Error::from)?;
    file.write_all(&body).await.map_err(anyhow::Error::from)?;
    file.set_len(offset + body.len() as u64)
        .await
        .map_err(anyhow::Error::from)?;
    file.flush().await.map_err(anyhow::Error::from)?;
    if index == next_chunk {
        sqlx::query("UPDATE file_objects SET next_chunk=?,ciphertext_size=? WHERE file_id=? AND status='uploading'")
            .bind(i64::from(index + 1))
            .bind((offset + body.len() as u64) as i64)
            .bind(file_id.to_string())
            .execute(&state.db)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn complete(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(file_id): Path<Uuid>,
) -> ApiResult<Json<FileObjectResponse>> {
    let _guard = state.file_writes.lock().await;
    let row = find(&state, file_id).await?.ok_or(ApiError::NotFound)?;
    let channel_id = parse_uuid(&row.1)?;
    require_membership(&state, device.id, channel_id).await?;
    if row.2 != device.id.to_string() {
        return Err(ApiError::Forbidden);
    }
    if row.8 == "ready" {
        return Ok(Json(to_response(row, true)?));
    }
    if row.8 != "uploading" || row.11 < Utc::now().timestamp() {
        return Err(ApiError::Gone);
    }
    if row.7 != row.6 {
        return Err(ApiError::Conflict(format!(
            "upload is incomplete: received {} of {} chunks",
            row.7, row.6
        )));
    }
    let expected_size = row.3 as u64 + 16 * row.6 as u64;
    let old_path = state.config.blob_dir.join(&row.1).join(&row.13);
    let new_key = format!("file-{}.bin", file_id.simple());
    let new_path = state.config.blob_dir.join(&row.1).join(&new_key);
    if tokio::fs::try_exists(&old_path)
        .await
        .map_err(anyhow::Error::from)?
    {
        if tokio::fs::metadata(&old_path)
            .await
            .map_err(anyhow::Error::from)?
            .len()
            != expected_size
        {
            return Err(ApiError::Conflict(
                "uploaded file length is incomplete".into(),
            ));
        }
        tokio::fs::rename(&old_path, &new_path)
            .await
            .map_err(anyhow::Error::from)?;
    } else if !tokio::fs::try_exists(&new_path)
        .await
        .map_err(anyhow::Error::from)?
    {
        return Err(ApiError::Conflict(
            "uploaded file content is missing".into(),
        ));
    }
    let now = Utc::now();
    let expires_at = now.timestamp()
        + i64::try_from(state.config.file_retention.as_secs())
            .map_err(|error| ApiError::Internal(error.into()))?;
    sqlx::query("UPDATE file_objects SET status='ready',ciphertext_size=?,completed_at=?,expires_at=?,blob_key=? WHERE file_id=?")
        .bind(expected_size as i64)
        .bind(now.to_rfc3339())
        .bind(expires_at)
        .bind(&new_key)
        .bind(file_id.to_string())
        .execute(&state.db)
        .await?;
    let row = find(&state, file_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("completed file disappeared")))?;
    Ok(Json(to_response(row, false)?))
}

pub async fn metadata(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(file_id): Path<Uuid>,
) -> ApiResult<Json<FileObjectResponse>> {
    let row = find(&state, file_id).await?.ok_or(ApiError::NotFound)?;
    require_membership(&state, device.id, parse_uuid(&row.1)?).await?;
    if row.8 == "expired" || row.8 == "deleted" || row.11 < Utc::now().timestamp() {
        return Err(ApiError::Gone);
    }
    Ok(Json(to_response(row, false)?))
}

pub async fn download_chunk(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path((file_id, index)): Path<(Uuid, u32)>,
) -> ApiResult<Response> {
    let row = find(&state, file_id).await?.ok_or(ApiError::NotFound)?;
    require_membership(&state, device.id, parse_uuid(&row.1)?).await?;
    if row.8 != "ready" || row.11 < Utc::now().timestamp() {
        return Err(ApiError::Gone);
    }
    if index >= row.6 as u32 {
        return Err(ApiError::NotFound);
    }
    let plaintext_size = row.3 as u64;
    let chunk_size = row.5 as u32;
    let plaintext_length = if plaintext_size == 0 {
        0
    } else {
        let offset = u64::from(index) * u64::from(chunk_size);
        (plaintext_size - offset).min(u64::from(chunk_size))
    };
    let length =
        usize::try_from(plaintext_length + 16).map_err(|error| ApiError::Internal(error.into()))?;
    let offset = u64::from(index) * (u64::from(chunk_size) + 16);
    let mut file = tokio::fs::File::open(state.config.blob_dir.join(&row.1).join(&row.13))
        .await
        .map_err(anyhow::Error::from)?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(anyhow::Error::from)?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .await
        .map_err(anyhow::Error::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}

pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(file_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let _guard = state.file_writes.lock().await;
    let row = find(&state, file_id).await?.ok_or(ApiError::NotFound)?;
    require_membership(&state, device.id, parse_uuid(&row.1)?).await?;
    if row.2 != device.id.to_string() {
        return Err(ApiError::Forbidden);
    }
    if row.8 != "deleted" && row.8 != "expired" {
        let manifest: Option<(String, String)> =
            sqlx::query_as("SELECT item_id,blob_key FROM file_manifests WHERE file_id=?")
                .bind(file_id.to_string())
                .fetch_optional(&state.db)
                .await?;
        if let Some((item_id, _)) = &manifest {
            sqlx::query("DELETE FROM current_channel_items WHERE item_id=?")
                .bind(item_id)
                .execute(&state.db)
                .await?;
            sqlx::query("DELETE FROM delivery_cache_items WHERE item_id=?")
                .bind(item_id)
                .execute(&state.db)
                .await?;
        }
        sqlx::query("DELETE FROM file_manifests WHERE file_id=?")
            .bind(file_id.to_string())
            .execute(&state.db)
            .await?;
        let _ = tokio::fs::remove_file(state.config.blob_dir.join(&row.1).join(&row.13)).await;
        if let Some((_, blob)) = manifest {
            let _ = tokio::fs::remove_file(state.config.blob_dir.join(&row.1).join(blob)).await;
        }
        sqlx::query("UPDATE file_objects SET status='deleted',deleted_at=? WHERE file_id=?")
            .bind(Utc::now().timestamp())
            .bind(file_id.to_string())
            .execute(&state.db)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn find(state: &AppState, file_id: Uuid) -> ApiResult<Option<FileRow>> {
    Ok(sqlx::query_as("SELECT file_id,channel_id,origin_device_id,plaintext_size,ciphertext_size,chunk_size,chunk_count,next_chunk,status,created_at,completed_at,expires_at,deleted_at,blob_key FROM file_objects WHERE file_id=?")
        .bind(file_id.to_string())
        .fetch_optional(&state.db)
        .await?)
}

fn to_response(row: FileRow, deduplicated: bool) -> ApiResult<FileObjectResponse> {
    Ok(FileObjectResponse {
        id: parse_uuid(&row.0)?,
        channel_id: parse_uuid(&row.1)?,
        origin_device_id: parse_uuid(&row.2)?,
        plaintext_size: row.3 as u64,
        ciphertext_size: row.4 as u64,
        chunk_size: row.5 as u32,
        chunk_count: row.6 as u32,
        next_chunk: row.7 as u32,
        status: row.8,
        expires_at: row.11,
        deduplicated,
    })
}

fn parse_uuid(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value).map_err(|error| ApiError::Internal(error.into()))
}
