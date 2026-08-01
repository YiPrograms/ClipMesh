use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,
    #[error("access denied")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("resource has expired")]
    Gone,
    #[error("file storage quota exceeded")]
    StorageFull,
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Gone => StatusCode::GONE,
            Self::StorageFull => StatusCode::INSUFFICIENT_STORAGE,
            Self::Internal(error) => {
                tracing::error!(error = ?error, "request failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "internal server error".to_owned()
        } else {
            self.to_string()
        };
        (status, Json(ErrorBody { error: &message })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self::Internal(value.into())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
