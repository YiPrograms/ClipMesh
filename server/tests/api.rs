use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clipmesh_server::{
    build,
    config::{Config, NativeClientRelease},
    crypto_protocol::join_message,
    model::{JoinChallengeResponse, RegisterDeviceResponse},
};
use futures_util::{SinkExt, StreamExt};
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::rand_core::OsRng,
    pkcs8::EncodePublicKey,
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

struct TestServer {
    app: Router,
    _temp: TempDir,
    instance_id: Uuid,
    config: Config,
    db: SqlitePool,
}

async fn server() -> TestServer {
    let temp = TempDir::new().unwrap();
    let database = format!("sqlite://{}", temp.path().join("clipmesh.db").display());
    let config = Config::test(database, temp.path().join("blobs"));
    let (app, state) = build(config.clone()).await.unwrap();
    TestServer {
        app,
        _temp: temp,
        instance_id: state.instance_id,
        config,
        db: state.db.clone(),
    }
}

async fn json_request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    value: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

async fn register(app: &Router, name: &str) -> RegisterDeviceResponse {
    let (_, pair) = json_request(app, "POST", "/api/v1/pairing", None, json!({})).await;
    let signing = SigningKey::random(&mut OsRng);
    let spki = signing.verifying_key().to_public_key_der().unwrap();
    let (status,value)=json_request(app,"POST","/api/v1/devices/register",None,json!({"pairing_code":pair["code"],"name":name,"signing_public_key":STANDARD.encode(spki.as_bytes()),"browser_family":"chrome","browser_version":"140","os_family":"linux"})).await;
    assert_eq!(status, StatusCode::CREATED);
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn native_client_registration_is_supported() {
    let server = server().await;
    let (_, pair) = json_request(&server.app, "POST", "/api/v1/pairing", None, json!({})).await;
    let signing = SigningKey::random(&mut OsRng);
    let spki = signing.verifying_key().to_public_key_der().unwrap();
    let (status, value) = json_request(&server.app, "POST", "/api/v1/devices/register", None, json!({"pairing_code":pair["code"],"name":"Native","signing_public_key":STANDARD.encode(spki.as_bytes()),"browser_family":"clipmesh-cli","browser_version":"0.3.0","os_family":"linux"})).await;
    assert_eq!(status, StatusCode::CREATED);
    let registered: RegisterDeviceResponse = serde_json::from_value(value).unwrap();
    let (status, device) = json_request(
        &server.app,
        "GET",
        "/api/v1/device",
        Some(&registered.device_token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(device["browser_family"], "clipmesh-cli");
}

async fn join_channel(
    app: &Router,
    server_id: Uuid,
    device: &RegisterDeviceResponse,
    channel_id: Uuid,
    membership: &SigningKey,
) {
    let (status, value) = json_request(
        app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join-challenge"),
        Some(&device.device_token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let challenge: JoinChallengeResponse = serde_json::from_value(value).unwrap();
    let random: [u8; 32] = STANDARD
        .decode(&challenge.challenge_random)
        .unwrap()
        .try_into()
        .unwrap();
    let proof: p256::ecdsa::Signature = membership.sign(&join_message(
        server_id,
        channel_id,
        device.device_id,
        challenge.challenge_id,
        &random,
        challenge.expires_at,
    ));
    let (status,_)=json_request(app,"POST",&format!("/api/v1/channels/{channel_id}/join"),Some(&device.device_token),json!({"challenge_id":challenge.challenge_id,"signature_algorithm":"ecdsa-p256-sha256","signature":STANDARD.encode(proof.to_bytes())})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

async fn create_channel(
    app: &Router,
    device: &RegisterDeviceResponse,
    membership: &SigningKey,
) -> Uuid {
    let channel_id = Uuid::new_v4();
    let spki = membership.verifying_key().to_public_key_der().unwrap();
    let (status,_)=json_request(app,"POST","/api/v1/channels",Some(&device.device_token),json!({"channel_id":channel_id,"name":format!("Channel {}",&channel_id.to_string()[..8]),"crypto_version":1,"password_kdf":{"name":"argon2id","salt":STANDARD.encode([7_u8;16]),"memory_kib":65536,"iterations":3,"parallelism":4,"output_bytes":32},"wrapped_secret":{"algorithm":"aes-256-gcm","nonce":STANDARD.encode([8_u8;12]),"ciphertext":STANDARD.encode([9_u8;64])},"membership_public_key":{"algorithm":"ecdsa-p256-sha256","spki":STANDARD.encode(spki.as_bytes())}})).await;
    assert_eq!(status, StatusCode::CREATED);
    channel_id
}

async fn upload(
    app: &Router,
    token: &str,
    channel_id: Uuid,
    item_id: Uuid,
    body: Vec<u8>,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/channels/{channel_id}/items"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/octet-stream")
                .header("idempotency-key", item_id.to_string())
                .header("x-crypto-version", "1")
                .header("x-content-type", "text/plain")
                .header("x-envelope-nonce", STANDARD.encode([3_u8; 12]))
                .header("x-client-created-at", "2026-08-01T00:00:00Z")
                .header(
                    "x-plaintext-size",
                    body.len().saturating_sub(16).to_string(),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn pairing_join_proof_items_and_authorization_work() {
    let server = server().await;
    let first = register(&server.app, "First").await;
    let second = register(&server.app, "Second").await;
    let membership = SigningKey::random(&mut OsRng);
    let spki = membership.verifying_key().to_public_key_der().unwrap();
    let channel_id = Uuid::new_v4();
    let (status,_)=json_request(&server.app,"POST","/api/v1/channels",Some(&first.device_token),json!({
        "channel_id":channel_id,"name":"Personal","crypto_version":1,
        "password_kdf":{"name":"argon2id","salt":STANDARD.encode([7_u8;16]),"memory_kib":65536,"iterations":3,"parallelism":4,"output_bytes":32},
        "wrapped_secret":{"algorithm":"aes-256-gcm","nonce":STANDARD.encode([8_u8;12]),"ciphertext":STANDARD.encode([9_u8;64])},
        "membership_public_key":{"algorithm":"ecdsa-p256-sha256","spki":STANDARD.encode(spki.as_bytes())}
    })).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, value) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join-challenge"),
        Some(&first.device_token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let challenge: JoinChallengeResponse = serde_json::from_value(value).unwrap();
    let random: [u8; 32] = STANDARD
        .decode(&challenge.challenge_random)
        .unwrap()
        .try_into()
        .unwrap();
    let proof: p256::ecdsa::Signature = membership.sign(&join_message(
        server.instance_id,
        channel_id,
        first.device_id,
        challenge.challenge_id,
        &random,
        challenge.expires_at,
    ));
    let proof_body = json!({"challenge_id":challenge.challenge_id,"signature_algorithm":"ecdsa-p256-sha256","signature":STANDARD.encode(proof.to_bytes())});
    let (status, _) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join"),
        Some(&first.device_token),
        proof_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join"),
        Some(&first.device_token),
        proof_body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, value) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join-challenge"),
        Some(&second.device_token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let expired: JoinChallengeResponse = serde_json::from_value(value).unwrap();
    sqlx::query("UPDATE channel_join_challenges SET expires_at=0 WHERE id=?")
        .bind(expired.challenge_id.to_string())
        .execute(&server.db)
        .await
        .unwrap();
    let (status, _) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/join"),
        Some(&second.device_token),
        json!({"challenge_id":expired.challenge_id,"signature_algorithm":"ecdsa-p256-sha256","signature":STANDARD.encode([0_u8;64])}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let item_id = Uuid::now_v7();
    let body = vec![4_u8; 32];
    let response = upload(
        &server.app,
        &first.device_token,
        channel_id,
        item_id,
        body.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = upload(
        &server.app,
        &first.device_token,
        channel_id,
        Uuid::now_v7(),
        vec![0_u8; 1024 * 1024 + 17],
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let response = upload(
        &server.app,
        &first.device_token,
        channel_id,
        item_id,
        body.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let next_item = Uuid::now_v7();
    let response = upload(
        &server.app,
        &first.device_token,
        channel_id,
        next_item,
        vec![5_u8; 24],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/items/{item_id}/content"))
                .header("authorization", format!("Bearer {}", first.device_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        body
    );

    let config = server.config.clone();
    drop(server.app);
    let (restarted, restarted_state) = build(config).await.unwrap();
    assert_eq!(restarted_state.instance_id, server.instance_id);
    let (status, current) = json_request(
        &restarted,
        "GET",
        &format!("/api/v1/channels/{channel_id}/current"),
        Some(&first.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["id"], next_item.to_string());
    let (status, _) = json_request(
        &restarted,
        "GET",
        &format!("/api/v1/channels/{channel_id}/current"),
        Some(&second.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = json_request(
        &restarted,
        "DELETE",
        &format!("/api/v1/channels/{channel_id}"),
        Some(&first.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn encrypted_files_are_finalized_before_members_can_download_them() {
    let server = server().await;
    let sender = register(&server.app, "Sender").await;
    let receiver = register(&server.app, "Receiver").await;
    let membership = SigningKey::random(&mut OsRng);
    let channel_id = create_channel(&server.app, &sender, &membership).await;
    join_channel(
        &server.app,
        server.instance_id,
        &sender,
        channel_id,
        &membership,
    )
    .await;
    join_channel(
        &server.app,
        server.instance_id,
        &receiver,
        channel_id,
        &membership,
    )
    .await;

    let file_id = Uuid::now_v7();
    let (status, created) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/files"),
        Some(&sender.device_token),
        json!({"file_id":file_id,"plaintext_size":3,"chunk_size":4*1024*1024,"chunk_count":1}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["status"], "uploading");
    assert_eq!(created["next_chunk"], 0);

    let (status, _) = json_request(
        &server.app,
        "GET",
        &format!("/api/v1/files/{file_id}"),
        Some(&receiver.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/files/{file_id}/chunks/0"))
                .header("authorization", format!("Bearer {}", receiver.device_token))
                .body(Body::from(vec![4_u8; 19]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let ciphertext = vec![7_u8; 19];
    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/files/{file_id}/chunks/0"))
                .header("authorization", format!("Bearer {}", sender.device_token))
                .body(Body::from(ciphertext.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (status, completed) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/files/{file_id}/complete"),
        Some(&sender.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(completed["status"], "ready");
    assert_eq!(completed["ciphertext_size"], 19);
    assert!(completed["expires_at"].as_i64().unwrap() > chrono::Utc::now().timestamp());

    let manifest_item_id = Uuid::now_v7();
    let manifest_ciphertext = vec![9_u8; 32];
    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/channels/{channel_id}/items"))
                .header("authorization", format!("Bearer {}", sender.device_token))
                .header("content-type", "application/octet-stream")
                .header("idempotency-key", manifest_item_id.to_string())
                .header("x-crypto-version", "1")
                .header("x-content-type", "application/vnd.clipmesh.file")
                .header("x-file-id", file_id.to_string())
                .header("x-envelope-nonce", STANDARD.encode([3_u8; 12]))
                .header("x-client-created-at", "2026-08-01T00:00:00Z")
                .header("x-plaintext-size", "16")
                .body(Body::from(manifest_ciphertext.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let (status, retained) = json_request(
        &server.app,
        "GET",
        &format!("/api/v1/channels/{channel_id}/files"),
        Some(&receiver.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retained.as_array().unwrap().len(), 1);
    assert_eq!(retained[0]["id"], manifest_item_id.to_string());

    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}/chunks/0"))
                .header("authorization", format!("Bearer {}", receiver.device_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        ciphertext
    );
    let (status, _) = json_request(
        &server.app,
        "DELETE",
        &format!("/api/v1/files/{file_id}"),
        Some(&receiver.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = json_request(
        &server.app,
        "DELETE",
        &format!("/api/v1/files/{file_id}"),
        Some(&sender.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = json_request(
        &server.app,
        "GET",
        &format!("/api/v1/files/{file_id}"),
        Some(&receiver.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn file_size_and_storage_quotas_are_enforced_at_creation() {
    let temp = TempDir::new().unwrap();
    let database = format!("sqlite://{}", temp.path().join("clipmesh.db").display());
    let mut config = Config::test(database, temp.path().join("blobs"));
    config.max_file_bytes = 32;
    config.file_storage_quota = 24;
    config.file_channel_quota = 24;
    let (app, state) = build(config).await.unwrap();
    let device = register(&app, "Quota").await;
    let membership = SigningKey::random(&mut OsRng);
    let channel_id = create_channel(&app, &device, &membership).await;
    join_channel(&app, state.instance_id, &device, channel_id, &membership).await;
    let (status, _) = json_request(
        &app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/files"),
        Some(&device.device_token),
        json!({"file_id":Uuid::now_v7(),"plaintext_size":33,"chunk_size":4*1024*1024,"chunk_count":1}),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = json_request(
        &app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/files"),
        Some(&device.device_token),
        json!({"file_id":Uuid::now_v7(),"plaintext_size":24,"chunk_size":4*1024*1024,"chunk_count":1}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = json_request(
        &app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/files"),
        Some(&device.device_token),
        json!({"file_id":Uuid::now_v7(),"plaintext_size":1,"chunk_size":4*1024*1024,"chunk_count":1}),
    )
    .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn revoked_device_credentials_stop_working() {
    let server = server().await;
    let device = register(&server.app, "Revoked").await;
    let (status, _) = json_request(
        &server.app,
        "DELETE",
        "/api/v1/device",
        Some(&device.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = json_request(
        &server.app,
        "GET",
        "/api/v1/device",
        Some(&device.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = json_request(
        &server.app,
        "POST",
        "/api/v1/ws-ticket",
        Some(&device.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_sole_members_leave_but_only_final_member_deletes() {
    let server = server().await;
    let first = register(&server.app, "First").await;
    let second = register(&server.app, "Second").await;
    let membership = SigningKey::random(&mut OsRng);
    let channel_id = create_channel(&server.app, &first, &membership).await;
    join_channel(
        &server.app,
        server.instance_id,
        &first,
        channel_id,
        &membership,
    )
    .await;
    join_channel(
        &server.app,
        server.instance_id,
        &second,
        channel_id,
        &membership,
    )
    .await;
    let (status, _) = json_request(
        &server.app,
        "DELETE",
        &format!("/api/v1/channels/{channel_id}"),
        Some(&first.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/leave"),
        Some(&first.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, members) = json_request(
        &server.app,
        "GET",
        &format!("/api/v1/channels/{channel_id}/members"),
        Some(&second.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(members.as_array().unwrap().len(), 1);
    let (status, _) = json_request(
        &server.app,
        "POST",
        &format!("/api/v1/channels/{channel_id}/leave"),
        Some(&second.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, channels) = json_request(
        &server.app,
        "GET",
        "/api/v1/channels",
        Some(&second.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(channels.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn websocket_tickets_are_single_use_and_support_heartbeat() {
    let server = server().await;
    let device = register(&server.app, "Socket").await;
    let (status, value) = json_request(
        &server.app,
        "POST",
        "/api/v1/ws-ticket",
        Some(&device.device_token),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ticket = value["ticket"].as_str().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = server.app.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("ws://{address}/api/v1/sync?ticket={ticket}");
    let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            r#"{"type":"ping","sent_at":"test"}"#.into(),
        ))
        .await
        .unwrap();
    let mut received_pong = false;
    for _ in 0..3 {
        if let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) = socket.next().await
            && text.contains("\"type\":\"pong\"")
        {
            received_pong = true;
            break;
        }
    }
    assert!(received_pong);
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());
    task.abort();
}

#[tokio::test]
async fn onboarding_and_api_security_headers_are_present() {
    let server = server().await;
    let response = server
        .app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    let page = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(page.contains("Install Chrome extension"));
    assert!(page.contains("Documentation"));
    assert!(page.contains("Native client"));
    assert!(page.contains("Windows"));
    assert!(page.contains("macOS"));
    assert!(page.contains("Linux"));
    assert!(page.contains("Not configured"));
    let response = server
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn configured_native_release_is_advertised_with_deterministic_assets() {
    let temp = TempDir::new().unwrap();
    let database = format!("sqlite://{}", temp.path().join("clipmesh.db").display());
    let mut config = Config::test(database, temp.path().join("blobs"));
    config.native_client = Some(NativeClientRelease {
        base_url: url::Url::parse("https://downloads.example/releases/v0.3.0/").unwrap(),
        version: "0.3.0".into(),
    });
    let (app, _) = build(config).await.unwrap();
    let (status, info) = json_request(&app, "GET", "/api/v1/info", None, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["native_client"]["version"], "0.3.0");
    assert_eq!(
        info["native_client"]["downloads"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        info["native_client"]["downloads"][0]["url"],
        "https://downloads.example/releases/v0.3.0/clipmesh-client-v0.3.0-windows-x86_64.zip"
    );
    assert_eq!(
        info["native_client"]["checksums_url"],
        "https://downloads.example/releases/v0.3.0/SHA256SUMS"
    );
}
