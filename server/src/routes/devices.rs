use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto_protocol::sha256,
    error::{ApiError, ApiResult},
    model::{AuthDevice, PairingCodeResponse, RegisterDeviceRequest, RegisterDeviceResponse},
    state::{AppState, RealtimeEvent},
};

const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub async fn create_pairing(
    State(state): State<Arc<AppState>>,
) -> ApiResult<(StatusCode, Json<PairingCodeResponse>)> {
    if !state
        .check_rate(
            "pairing-create-global".into(),
            30,
            std::time::Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let raw: String = random
        .iter()
        .map(|byte| CODE_ALPHABET[*byte as usize % CODE_ALPHABET.len()] as char)
        .collect();
    let display = format!("{}-{}", &raw[..4], &raw[4..]);
    let expires = Utc::now() + Duration::minutes(5);
    sqlx::query("INSERT INTO pairing_codes(id, code_hash, expires_at) VALUES (?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(sha256(raw.as_bytes()))
        .bind(expires.to_rfc3339())
        .execute(&state.db)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PairingCodeResponse {
            code: display,
            expires_at: expires.to_rfc3339(),
        }),
    ))
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterDeviceRequest>,
) -> ApiResult<(StatusCode, Json<RegisterDeviceResponse>)> {
    if !state
        .check_rate(
            "pairing-register-global".into(),
            60,
            std::time::Duration::from_secs(60),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }
    validate_name(&request.name)?;
    if !matches!(request.browser_family.as_str(), "chrome" | "clipmesh-cli") {
        return Err(ApiError::BadRequest("unsupported client family".into()));
    }
    let signing_key = STANDARD
        .decode(&request.signing_public_key)
        .map_err(|_| ApiError::BadRequest("invalid signing public key".into()))?;
    if signing_key.len() < 64 || signing_key.len() > 512 {
        return Err(ApiError::BadRequest("invalid signing public key".into()));
    }
    let normalized_code: String = request
        .pairing_code
        .chars()
        .filter(|character| *character != '-')
        .flat_map(char::to_uppercase)
        .collect();
    let now = Utc::now();
    let mut transaction = state.db.begin().await?;
    let pairing_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM pairing_codes WHERE code_hash=? AND consumed_at IS NULL AND expires_at>?",
    )
    .bind(sha256(normalized_code.as_bytes()))
    .bind(now.to_rfc3339())
    .fetch_optional(&mut *transaction)
    .await?;
    let pairing_id =
        pairing_id.ok_or_else(|| ApiError::BadRequest("invalid or expired pairing code".into()))?;
    let changed =
        sqlx::query("UPDATE pairing_codes SET consumed_at=? WHERE id=? AND consumed_at IS NULL")
            .bind(now.to_rfc3339())
            .bind(pairing_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    if changed != 1 {
        return Err(ApiError::BadRequest("pairing code was already used".into()));
    }
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO devices(id,name,signing_public_key,browser_family,browser_version,os_family,created_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?)")
        .bind(device_id.to_string())
        .bind(request.name.trim())
        .bind(signing_key)
        .bind(request.browser_family)
        .bind(request.browser_version)
        .bind(request.os_family)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await?;
    let token = random_token();
    sqlx::query("INSERT INTO device_tokens(device_id,token_hash,created_at) VALUES (?,?,?)")
        .bind(device_id.to_string())
        .bind(sha256(&token))
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            device_id,
            device_token: URL_SAFE_NO_PAD.encode(token),
            server_instance_id: state.instance_id,
            api_version: 1,
        }),
    ))
}

#[derive(Serialize)]
pub struct DeviceResponse {
    id: Uuid,
    name: String,
    browser_family: String,
    browser_version: Option<String>,
    os_family: Option<String>,
    created_at: String,
    last_seen_at: String,
}

pub async fn get_device(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
) -> ApiResult<Json<DeviceResponse>> {
    let row: (String, String, Option<String>, Option<String>, String, String) = sqlx::query_as(
        "SELECT name,browser_family,browser_version,os_family,created_at,last_seen_at FROM devices WHERE id=?",
    )
    .bind(device.id.to_string())
    .fetch_one(&state.db)
    .await?;
    Ok(Json(DeviceResponse {
        id: device.id,
        name: row.0,
        browser_family: row.1,
        browser_version: row.2,
        os_family: row.3,
        created_at: row.4,
        last_seen_at: row.5,
    }))
}

#[derive(Deserialize)]
pub struct RenameRequest {
    name: String,
}

pub async fn rename_device(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Json(request): Json<RenameRequest>,
) -> ApiResult<Json<DeviceResponse>> {
    validate_name(&request.name)?;
    sqlx::query("UPDATE devices SET name=? WHERE id=?")
        .bind(request.name.trim())
        .bind(device.id.to_string())
        .execute(&state.db)
        .await?;
    get_device(
        State(state),
        AuthDevice {
            name: request.name,
            ..device
        },
    )
    .await
}

#[derive(Serialize)]
pub struct TokenResponse {
    device_token: String,
}

pub async fn rotate_token(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
) -> ApiResult<Json<TokenResponse>> {
    let token = random_token();
    sqlx::query("UPDATE device_tokens SET token_hash=?, created_at=? WHERE device_id=?")
        .bind(sha256(&token))
        .bind(Utc::now().to_rfc3339())
        .bind(device.id.to_string())
        .execute(&state.db)
        .await?;
    let _ = state.disconnects.send(device.id);
    Ok(Json(TokenResponse {
        device_token: URL_SAFE_NO_PAD.encode(token),
    }))
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
) -> ApiResult<StatusCode> {
    let now = Utc::now().to_rfc3339();
    let channels: Vec<String> =
        sqlx::query_scalar("SELECT channel_id FROM channel_memberships WHERE device_id=?")
            .bind(device.id.to_string())
            .fetch_all(&state.db)
            .await?;
    let mut transaction = state.db.begin().await?;
    let mut deleted_channels = Vec::new();
    let mut updated_channels = Vec::new();
    sqlx::query("UPDATE devices SET revoked_at=? WHERE id=?")
        .bind(&now)
        .bind(device.id.to_string())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM channel_memberships WHERE device_id=?")
        .bind(device.id.to_string())
        .execute(&mut *transaction)
        .await?;
    for channel in channels {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channel_memberships WHERE channel_id=?")
                .bind(&channel)
                .fetch_one(&mut *transaction)
                .await?;
        if count == 0 {
            sqlx::query("DELETE FROM channels WHERE id=?")
                .bind(&channel)
                .execute(&mut *transaction)
                .await?;
            deleted_channels.push(channel);
        } else {
            updated_channels.push(channel);
        }
    }
    transaction.commit().await?;
    state.ws_subscriptions.retain(|(id, _), _| *id != device.id);
    let _ = state.disconnects.send(device.id);
    for channel in updated_channels {
        if let Ok(channel_id) = Uuid::parse_str(&channel) {
            let _ = state.events.send(RealtimeEvent {
                channel_id,
                event: serde_json::json!({"type":"membership_changed","channel_id":channel_id,"data":{"device_id":device.id,"action":"revoked"}}),
            });
        }
    }
    for channel in deleted_channels {
        let _ = tokio::fs::remove_dir_all(state.config.blob_dir.join(channel)).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn random_token() -> [u8; 32] {
    let mut token = [0_u8; 32];
    rand::rng().fill_bytes(&mut token);
    token
}

fn validate_name(name: &str) -> ApiResult<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 80 || trimmed.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name must contain 1–80 non-control characters".into(),
        ));
    }
    Ok(())
}
