pub mod auth;
pub mod config;
pub mod crypto_protocol;
pub mod error;
pub mod model;
pub mod routes;
pub mod state;

use std::sync::Arc;

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::{limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer};

use crate::{config::Config, state::AppState};

pub async fn build(config: Config) -> anyhow::Result<(Router, Arc<AppState>)> {
    tokio::fs::create_dir_all(&config.blob_dir)
        .await
        .context("create blob directory")?;

    let options = config
        .database_url
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .context("connect to SQLite")?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = Arc::new(AppState::initialize(config, pool).await?);
    state.reconcile_blobs().await?;
    let app = routes::router(state.clone())
        .layer(RequestBodyLimitLayer::new(17 * 1024 * 1024))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
        ))
        .layer(middleware::from_fn(safe_request_log));
    Ok((app, state))
}

async fn safe_request_log(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = std::time::Instant::now();
    let mut response = next.run(request).await;
    if path.starts_with("/api/") {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
    }
    tracing::info!(%method, %path, status = response.status().as_u16(), elapsed_ms = started.elapsed().as_millis(), "request");
    response
}
