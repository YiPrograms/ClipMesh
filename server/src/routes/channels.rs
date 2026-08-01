use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use rand::RngCore;
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::{
    crypto_protocol::join_message,
    error::{ApiError, ApiResult},
    model::{
        AuthDevice, ChannelSummary, CreateChannelRequest, JoinChallengeResponse,
        JoinChannelRequest, JoinParametersResponse, MembershipPublicKey, PasswordKdf,
        WrappedSecret,
    },
    state::{AppState, RealtimeEvent},
};

type StoredChallenge = (String, String, Vec<u8>, i64, Vec<u8>);

pub async fn list(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
) -> ApiResult<Json<Vec<ChannelSummary>>> {
    let rows: Vec<(String, String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT c.id,c.name,c.crypto_version,COUNT(m.device_id),EXISTS(SELECT 1 FROM channel_memberships mine WHERE mine.channel_id=c.id AND mine.device_id=?),c.current_sequence FROM channels c LEFT JOIN channel_memberships m ON m.channel_id=c.id WHERE c.deleted_at IS NULL GROUP BY c.id ORDER BY c.name COLLATE NOCASE",
    )
    .bind(device.id.to_string())
    .fetch_all(&state.db)
    .await?;
    let channels = rows
        .into_iter()
        .map(|row| {
            Ok(ChannelSummary {
                id: parse_uuid(&row.0)?,
                name: row.1,
                crypto_version: row.2 as u16,
                member_count: row.3 as u32,
                joined: row.4 != 0,
                current_sequence: row.5 as u64,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(channels))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Json(request): Json<CreateChannelRequest>,
) -> ApiResult<(StatusCode, Json<ChannelSummary>)> {
    validate_channel(&request)?;
    let name = request.name.trim();
    let normalized_name: String = name.nfkc().flat_map(char::to_lowercase).collect();
    let kdf_json = serde_json::to_string(&request.password_kdf)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let wrapped_json = serde_json::to_string(&request.wrapped_secret)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let public_key = STANDARD
        .decode(&request.membership_public_key.spki)
        .map_err(|_| ApiError::BadRequest("invalid membership public key".into()))?;
    VerifyingKey::from_public_key_der(&public_key)
        .map_err(|_| ApiError::BadRequest("invalid P-256 public key".into()))?;
    let joined_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_memberships WHERE device_id=?")
            .bind(device.id.to_string())
            .fetch_one(&state.db)
            .await?;
    if joined_count >= 32 {
        return Err(ApiError::Conflict("joined-channel limit reached".into()));
    }
    let result = sqlx::query("INSERT INTO channels(id,normalized_name,name,crypto_version,password_kdf_json,wrapped_secret_json,membership_public_key_spki,created_by_device_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(request.channel_id.to_string()).bind(normalized_name).bind(name).bind(request.crypto_version as i64)
        .bind(kdf_json).bind(wrapped_json).bind(public_key).bind(device.id.to_string()).bind(Utc::now().to_rfc3339())
        .execute(&state.db).await;
    if let Err(sqlx::Error::Database(error)) = &result
        && error.is_unique_violation()
    {
        return Err(ApiError::Conflict(
            "channel ID or normalized name already exists".into(),
        ));
    }
    result?;
    Ok((
        StatusCode::CREATED,
        Json(ChannelSummary {
            id: request.channel_id,
            name: name.into(),
            crypto_version: request.crypto_version,
            member_count: 0,
            joined: false,
            current_sequence: 0,
        }),
    ))
}

pub async fn join_parameters(
    State(state): State<Arc<AppState>>,
    _device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<Json<JoinParametersResponse>> {
    let row: Option<(i64, String, String, Vec<u8>)> = sqlx::query_as("SELECT crypto_version,password_kdf_json,wrapped_secret_json,membership_public_key_spki FROM channels WHERE id=? AND deleted_at IS NULL")
        .bind(channel_id.to_string()).fetch_optional(&state.db).await?;
    let (version, kdf, wrapped, spki) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(JoinParametersResponse {
        channel_id,
        crypto_version: version as u16,
        password_kdf: serde_json::from_str::<PasswordKdf>(&kdf)
            .map_err(|error| ApiError::Internal(error.into()))?,
        wrapped_secret: serde_json::from_str::<WrappedSecret>(&wrapped)
            .map_err(|error| ApiError::Internal(error.into()))?,
        membership_public_key: MembershipPublicKey {
            algorithm: "ecdsa-p256-sha256".into(),
            spki: STANDARD.encode(spki),
        },
    }))
}

pub async fn join_challenge(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<JoinChallengeResponse>)> {
    if !state
        .check_rate(
            format!("join:{}", device.id),
            10,
            std::time::Duration::from_secs(300),
        )
        .await
    {
        return Err(ApiError::RateLimited);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channels WHERE id=? AND deleted_at IS NULL)",
    )
    .bind(channel_id.to_string())
    .fetch_one(&state.db)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let already_joined: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channel_memberships WHERE channel_id=? AND device_id=?)",
    )
    .bind(channel_id.to_string())
    .bind(device.id.to_string())
    .fetch_one(&state.db)
    .await?;
    if already_joined {
        return Err(ApiError::Conflict("device is already a member".into()));
    }
    let challenge_id = Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    let expires_at = Utc::now().timestamp() + 60;
    sqlx::query("INSERT INTO channel_join_challenges(id,channel_id,device_id,challenge_random,expires_at) VALUES (?,?,?,?,?)")
        .bind(challenge_id.to_string()).bind(channel_id.to_string()).bind(device.id.to_string()).bind(random.as_slice()).bind(expires_at)
        .execute(&state.db).await?;
    Ok((
        StatusCode::CREATED,
        Json(JoinChallengeResponse {
            challenge_id,
            challenge_random: STANDARD.encode(random),
            expires_at,
            server_instance_id: state.instance_id,
            channel_id,
            device_id: device.id,
        }),
    ))
}

pub async fn join(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<JoinChannelRequest>,
) -> ApiResult<StatusCode> {
    if request.signature_algorithm != "ecdsa-p256-sha256" {
        return Err(ApiError::BadRequest(
            "unsupported signature algorithm".into(),
        ));
    }
    let now = Utc::now().timestamp();
    let mut transaction = state.db.begin().await?;
    let challenge: Option<StoredChallenge> = sqlx::query_as(
        "SELECT j.channel_id,j.device_id,j.challenge_random,j.expires_at,c.membership_public_key_spki FROM channel_join_challenges j JOIN channels c ON c.id=j.channel_id WHERE j.id=? AND j.consumed_at IS NULL AND c.deleted_at IS NULL",
    ).bind(request.challenge_id.to_string()).fetch_optional(&mut *transaction).await?;
    let challenge =
        challenge.ok_or_else(|| ApiError::BadRequest("invalid or consumed challenge".into()))?;
    let changed = sqlx::query(
        "UPDATE channel_join_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(request.challenge_id.to_string())
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    if changed != 1
        || challenge.0 != channel_id.to_string()
        || challenge.1 != device.id.to_string()
        || challenge.3 < now
    {
        return Err(ApiError::BadRequest("invalid or expired challenge".into()));
    }
    let random: [u8; 32] =
        challenge.2.as_slice().try_into().map_err(|_| {
            ApiError::Internal(anyhow::anyhow!("stored challenge has invalid length"))
        })?;
    let signature_bytes = STANDARD
        .decode(request.signature)
        .map_err(|_| ApiError::BadRequest("invalid membership proof".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ApiError::BadRequest("invalid membership proof".into()))?;
    let key = VerifyingKey::from_public_key_der(&challenge.4)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("stored membership key is invalid")))?;
    key.verify(
        &join_message(
            state.instance_id,
            channel_id,
            device.id,
            request.challenge_id,
            &random,
            challenge.3,
        ),
        &signature,
    )
    .map_err(|_| ApiError::Forbidden)?;
    let joined_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_memberships WHERE device_id=?")
            .bind(device.id.to_string())
            .fetch_one(&state.db)
            .await?;
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_memberships WHERE channel_id=?")
            .bind(channel_id.to_string())
            .fetch_one(&state.db)
            .await?;
    if joined_count >= 32 || member_count >= 64 {
        return Err(ApiError::Conflict("membership limit reached".into()));
    }
    sqlx::query("INSERT INTO channel_memberships(channel_id,device_id,joined_at) VALUES (?,?,?)")
        .bind(channel_id.to_string())
        .bind(device.id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db)
        .await?;
    emit(
        &state,
        channel_id,
        "membership_changed",
        serde_json::json!({"device_id":device.id,"action":"joined"}),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn leave(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut transaction = state.db.begin().await?;
    let changed = sqlx::query("DELETE FROM channel_memberships WHERE channel_id=? AND device_id=?")
        .bind(channel_id.to_string())
        .bind(device.id.to_string())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_memberships WHERE channel_id=?")
            .bind(channel_id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
    if remaining == 0 {
        sqlx::query("DELETE FROM channels WHERE id=?")
            .bind(channel_id.to_string())
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    for mut subscription in state.ws_subscriptions.iter_mut() {
        if subscription.key().0 == device.id {
            subscription.value_mut().remove(&channel_id);
        }
    }
    emit(
        &state,
        channel_id,
        if remaining == 0 {
            "channel_deleted"
        } else {
            "membership_changed"
        },
        serde_json::json!({"device_id":device.id,"action":"left"}),
    );
    if remaining == 0 {
        cleanup_channel_blobs(&state, channel_id).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_channel(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let members: Vec<String> =
        sqlx::query_scalar("SELECT device_id FROM channel_memberships WHERE channel_id=?")
            .bind(channel_id.to_string())
            .fetch_all(&state.db)
            .await?;
    if members.len() != 1 || members[0] != device.id.to_string() {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("DELETE FROM channels WHERE id=?")
        .bind(channel_id.to_string())
        .execute(&state.db)
        .await?;
    emit(&state, channel_id, "channel_deleted", serde_json::json!({}));
    cleanup_channel_blobs(&state, channel_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Member {
    id: String,
    name: String,
    joined_at: String,
}

pub async fn members(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
    Path(channel_id): Path<Uuid>,
) -> ApiResult<Json<Vec<Member>>> {
    crate::auth::require_membership(&state, device.id, channel_id).await?;
    let values = sqlx::query_as("SELECT d.id,d.name,m.joined_at FROM channel_memberships m JOIN devices d ON d.id=m.device_id WHERE m.channel_id=? ORDER BY m.joined_at")
        .bind(channel_id.to_string()).fetch_all(&state.db).await?;
    Ok(Json(values))
}

fn validate_channel(request: &CreateChannelRequest) -> ApiResult<()> {
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "channel name must contain 1–80 non-control characters".into(),
        ));
    }
    if request.crypto_version != 1
        || request.password_kdf.name != "argon2id"
        || request.password_kdf.memory_kib < 65_536
        || request.password_kdf.memory_kib > 1_048_576
        || request.password_kdf.iterations < 3
        || request.password_kdf.iterations > 32
        || !(1..=16).contains(&request.password_kdf.parallelism)
        || request.password_kdf.output_bytes != 32
    {
        return Err(ApiError::BadRequest(
            "unsupported cryptographic profile".into(),
        ));
    }
    let salt = STANDARD
        .decode(&request.password_kdf.salt)
        .map_err(|_| ApiError::BadRequest("invalid KDF salt".into()))?;
    let nonce = STANDARD
        .decode(&request.wrapped_secret.nonce)
        .map_err(|_| ApiError::BadRequest("invalid wrap nonce".into()))?;
    let ciphertext = STANDARD
        .decode(&request.wrapped_secret.ciphertext)
        .map_err(|_| ApiError::BadRequest("invalid wrapped secret".into()))?;
    if salt.len() < 16
        || salt.len() > 64
        || request.wrapped_secret.algorithm != "aes-256-gcm"
        || nonce.len() != 12
        || ciphertext.len() < 32
        || ciphertext.len() > 4096
        || request.membership_public_key.algorithm != "ecdsa-p256-sha256"
    {
        return Err(ApiError::BadRequest(
            "invalid cryptographic envelope".into(),
        ));
    }
    Ok(())
}

fn parse_uuid(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value).map_err(|error| ApiError::Internal(error.into()))
}

fn emit(state: &AppState, channel_id: Uuid, event_type: &str, body: serde_json::Value) {
    let _ = state.events.send(RealtimeEvent {
        channel_id,
        event: serde_json::json!({"type":event_type,"channel_id":channel_id,"data":body}),
    });
}

async fn cleanup_channel_blobs(state: &AppState, channel_id: Uuid) {
    let directory = state.config.blob_dir.join(channel_id.to_string());
    if let Err(error) = tokio::fs::remove_dir_all(directory).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%channel_id, ?error, "failed to remove channel blobs");
    }
}
