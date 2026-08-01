use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use uuid::Uuid;

use crate::{crypto_protocol::sha256, error::ApiError, model::AuthDevice, state::AppState};

impl FromRequestParts<Arc<AppState>> for AuthDevice {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let token =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
                .map_err(|_| ApiError::Unauthorized)?;
        if token.len() != 32 {
            return Err(ApiError::Unauthorized);
        }
        let hash = sha256(&token);
        let record: Option<(String, String)> = sqlx::query_as(
            "SELECT d.id, d.name FROM devices d JOIN device_tokens t ON t.device_id=d.id WHERE t.token_hash=? AND d.revoked_at IS NULL",
        )
        .bind(hash)
        .fetch_optional(&state.db)
        .await?;
        let (id, name) = match record {
            Some(value) => value,
            None => {
                if !state
                    .check_rate(
                        "auth-fail-global".into(),
                        100,
                        std::time::Duration::from_secs(60),
                    )
                    .await
                {
                    return Err(ApiError::RateLimited);
                }
                return Err(ApiError::Unauthorized);
            }
        };
        sqlx::query("UPDATE devices SET last_seen_at=? WHERE id=?")
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(&id)
            .execute(&state.db)
            .await?;
        Ok(AuthDevice {
            id: Uuid::parse_str(&id).map_err(|error| ApiError::Internal(error.into()))?,
            name,
        })
    }
}

pub async fn require_membership(
    state: &AppState,
    device_id: Uuid,
    channel_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channel_memberships m JOIN channels c ON c.id=m.channel_id WHERE m.channel_id=? AND m.device_id=? AND c.deleted_at IS NULL)",
    )
    .bind(channel_id.to_string())
    .bind(device_id.to_string())
    .fetch_one(&state.db)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
