use std::sync::Arc;

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse},
};
use serde::Serialize;

use crate::{config::NativeClientRelease, error::ApiResult, state::AppState};

pub async fn landing(State(state): State<Arc<AppState>>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ClipMesh</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><main><div class="brand">ClipMesh</div><h1>Encrypted clipboard sync<br>and file transfer.</h1><p class="lede">Pair browsers and native desktops with <strong>{}</strong>. Clipboard text, PNG images, and retained files are end-to-end encrypted; this server never receives channel passwords, clipboard plaintext, or filenames.</p><div class="actions"><a class="primary" href="{}" rel="noreferrer">Install Chrome extension</a><button id="pair">Create pairing code</button><a href="/docs">Documentation</a></div><section id="result" hidden aria-live="polite"></section><section class="native" id="native-downloads"><div class="section-heading"><div><div class="eyebrow">Native client</div><h2>Run ClipMesh in your terminal</h2></div>{}</div><div class="downloads">{}</div><p class="download-note">Portable archives. Running <code>clipmesh</code> opens the foreground TUI; use <code>clipmesh service install</code> for optional background sync. Send a path with <code>clipmesh send-file FILE</code>, or pipe content with <code>--filename</code>. Verify downloads against <a href="{}" rel="noreferrer">SHA256SUMS</a>.</p></section><ol><li>Install the Chrome extension or download the native client for this computer.</li><li>Return here and create a five-minute pairing code.</li><li>Run <code>clipmesh pair --server {} --name &quot;My computer&quot;</code>, or open ClipMesh in Chrome, and enter the code.</li></ol><aside><strong>Clipboard access is sensitive.</strong> ClipMesh can read supported clipboard content while its browser, TUI, or service is running. File content is uploaded only when you choose a file. Pause synchronization before copying secrets.</aside><p class="health"><span></span> Server online · Protocol v1</p></main><script src="/assets/app.js"></script></body></html>"#,
        escape_html(&state.config.instance_name),
        escape_attr(&state.config.chrome_store_url),
        release_badge(state.config.native_client.as_ref()),
        download_cards(state.config.native_client.as_ref()),
        checksum_url(state.config.native_client.as_ref()),
        escape_html(state.config.public_url.as_str())
    ))
}

pub async fn documentation() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ClipMesh documentation</title><link rel="stylesheet" href="/assets/app.css"></head><body><main><div class="brand">ClipMesh documentation</div><h1>Pair. Join. Route.</h1><h2>Pair a device</h2><p class="lede">Install the unlisted Chrome extension, create a five-minute code on the onboarding page, then open the extension while that server tab is active. Confirm the exact HTTPS origin and enter the code. Pairing does not grant access to any channel.</p><h2>Use channels</h2><p>Create a channel with a unique passphrase of at least twelve characters, preferably the built-in generated value. Share the password out of band. Other paired devices select the channel and enter the same password; the password is checked locally before the server receives a proof.</p><h2>Choose one routing mode</h2><ol><li><strong>Sync:</strong> one channel has Send and Receive.</li><li><strong>Send only:</strong> one or more channels have Send.</li><li><strong>Receive only:</strong> one or more channels have Receive.</li></ol><p>Disabled checkboxes prevent cross-channel loops. Pause controls leave these selections intact.</p><h2>Transfer files</h2><p>Choose a file in the extension or run <code>clipmesh send-file FILE</code>. ClipMesh uploads encrypted chunks before publishing a small encrypted manifest. Receiving devices download and decrypt chunks only after you select Download. The server controls size, retention, and storage quotas.</p><aside><strong>Security:</strong> the server stores ciphertext and visible routing metadata. Endpoint compromise, weak passwords, and people who retain a shared channel password remain outside end-to-end encryption's protection. Channel passwords cannot be recovered.</aside><p><a href="/">Return to onboarding</a></p></main></body></html>"#,
    )
}

pub async fn css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/app.css"),
    )
}

pub async fn js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        include_str!("../../static/app.js"),
    )
}

#[derive(Serialize)]
pub struct InfoResponse {
    name: String,
    server_instance_id: uuid::Uuid,
    server_version: &'static str,
    protocol_version: u16,
    chrome_store_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_client: Option<NativeClientInfo>,
    file_transfer: FileTransferInfo,
}

#[derive(Serialize)]
pub struct FileTransferInfo {
    max_file_bytes: u64,
    chunk_bytes: u32,
    retention_seconds: u64,
}

#[derive(Serialize)]
pub struct NativeClientInfo {
    version: String,
    downloads: Vec<NativeDownload>,
    checksums_url: String,
}

#[derive(Serialize)]
pub struct NativeDownload {
    os: &'static str,
    arch: &'static str,
    url: String,
}

pub async fn info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(InfoResponse {
        name: state.config.instance_name.clone(),
        server_instance_id: state.instance_id,
        server_version: env!("CARGO_PKG_VERSION"),
        protocol_version: 1,
        chrome_store_url: state.config.chrome_store_url.clone(),
        native_client: state.config.native_client.as_ref().map(native_info),
        file_transfer: FileTransferInfo {
            max_file_bytes: state.config.max_file_bytes,
            chunk_bytes: clipmesh_protocol::FILE_CHUNK_BYTES,
            retention_seconds: state.config.file_retention.as_secs(),
        },
    })
}

fn native_info(release: &NativeClientRelease) -> NativeClientInfo {
    NativeClientInfo {
        version: release.version.clone(),
        downloads: [
            ("windows", "x86_64", "zip"),
            ("linux", "x86_64", "tar.gz"),
            ("macos", "universal", "tar.gz"),
        ]
        .into_iter()
        .map(|(os, arch, extension)| NativeDownload {
            os,
            arch,
            url: asset_url(release, os, arch, extension),
        })
        .collect(),
        checksums_url: release
            .base_url
            .join("SHA256SUMS")
            .expect("relative release URL")
            .to_string(),
    }
}

fn asset_url(release: &NativeClientRelease, os: &str, arch: &str, extension: &str) -> String {
    release
        .base_url
        .join(&format!(
            "clipmesh-client-v{}-{os}-{arch}.{extension}",
            release.version
        ))
        .expect("relative release URL")
        .to_string()
}

fn download_cards(release: Option<&NativeClientRelease>) -> String {
    [("windows", "Windows", "x86-64", "zip"), ("macos", "macOS", "Universal", "tar.gz"), ("linux", "Linux", "x86-64", "tar.gz")].into_iter().map(|(os, label, arch, extension)| {
        match release {
            Some(value) => format!(r#"<a class="download-card" data-os="{os}" href="{}"><strong>{label}</strong><span>{arch} · {extension}</span><small>Download</small></a>"#, escape_attr(&asset_url(value, os, if os == "macos" { "universal" } else { "x86_64" }, extension))),
            None => format!(r#"<div class="download-card unavailable" data-os="{os}"><strong>{label}</strong><span>{arch} · {extension}</span><small>Not configured</small></div>"#),
        }
    }).collect()
}

fn release_badge(release: Option<&NativeClientRelease>) -> String {
    release
        .map(|value| {
            format!(
                "<span class=release>v{}</span>",
                escape_html(&value.version)
            )
        })
        .unwrap_or_else(|| "<span class=release>Unavailable</span>".into())
}
fn checksum_url(release: Option<&NativeClientRelease>) -> String {
    release
        .map(|value| {
            escape_attr(
                value
                    .base_url
                    .join("SHA256SUMS")
                    .expect("relative release URL")
                    .as_ref(),
            )
        })
        .unwrap_or_else(|| "#native-downloads".into())
}

#[derive(Serialize)]
pub struct HealthResponse<'a> {
    status: &'a str,
    database: &'a str,
    blob_storage: &'a str,
    server_version: &'a str,
    protocol_version: u16,
}

pub async fn health(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await?;
    let probe = state
        .config
        .blob_dir
        .join(format!(".health-probe-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&probe, b"")
        .await
        .map_err(anyhow::Error::from)?;
    tokio::fs::remove_file(probe)
        .await
        .map_err(anyhow::Error::from)?;
    Ok((
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: "ok",
            database: "ok",
            blob_storage: "ok",
            server_version: env!("CARGO_PKG_VERSION"),
            protocol_version: 1,
        }),
    ))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(value: &str) -> String {
    escape_html(value).replace('"', "&quot;")
}
