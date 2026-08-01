mod channels;
mod devices;
mod files;
mod items;
mod web;
mod websocket;

use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(web::landing))
        .route("/docs", get(web::documentation))
        .route("/assets/app.css", get(web::css))
        .route("/assets/app.js", get(web::js))
        .route("/api/v1/info", get(web::info))
        .route("/api/v1/health", get(web::health))
        .route("/api/v1/pairing", post(devices::create_pairing))
        .route("/api/v1/devices/register", post(devices::register))
        .route(
            "/api/v1/device",
            get(devices::get_device)
                .patch(devices::rename_device)
                .delete(devices::revoke_device),
        )
        .route("/api/v1/device/token/rotate", post(devices::rotate_token))
        .route(
            "/api/v1/channels",
            get(channels::list).post(channels::create),
        )
        .route(
            "/api/v1/channels/{channel_id}/join-parameters",
            get(channels::join_parameters),
        )
        .route(
            "/api/v1/channels/{channel_id}/join-challenge",
            post(channels::join_challenge),
        )
        .route("/api/v1/channels/{channel_id}/join", post(channels::join))
        .route("/api/v1/channels/{channel_id}/leave", post(channels::leave))
        .route(
            "/api/v1/channels/{channel_id}",
            delete(channels::delete_channel),
        )
        .route(
            "/api/v1/channels/{channel_id}/members",
            get(channels::members),
        )
        .route("/api/v1/channels/{channel_id}/items", post(items::upload))
        .route("/api/v1/channels/{channel_id}/current", get(items::current))
        .route("/api/v1/items/{item_id}/content", get(items::content))
        .route("/api/v1/items/{item_id}/ack", post(items::ack))
        .route(
            "/api/v1/channels/{channel_id}/files",
            get(files::list).post(files::create),
        )
        .route(
            "/api/v1/files/{file_id}",
            get(files::metadata).delete(files::delete_file),
        )
        .route(
            "/api/v1/files/{file_id}/chunks/{index}",
            get(files::download_chunk).put(files::upload_chunk),
        )
        .route("/api/v1/files/{file_id}/complete", post(files::complete))
        .route("/api/v1/ws-ticket", post(websocket::create_ticket))
        .route("/api/v1/sync", get(websocket::upgrade))
        .with_state(state)
}
