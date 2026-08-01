use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto_protocol::sha256,
    error::{ApiError, ApiResult},
    model::AuthDevice,
    state::AppState,
};

#[derive(Serialize)]
pub struct TicketResponse {
    ticket: String,
    expires_at: i64,
}

pub async fn create_ticket(
    State(state): State<Arc<AppState>>,
    device: AuthDevice,
) -> ApiResult<Json<TicketResponse>> {
    let mut ticket = [0_u8; 32];
    rand::rng().fill_bytes(&mut ticket);
    let expires_at = chrono::Utc::now().timestamp() + 30;
    sqlx::query("INSERT INTO ws_tickets(ticket_hash,device_id,expires_at) VALUES (?,?,?)")
        .bind(sha256(&ticket))
        .bind(device.id.to_string())
        .bind(expires_at)
        .execute(&state.db)
        .await?;
    Ok(Json(TicketResponse {
        ticket: URL_SAFE_NO_PAD.encode(ticket),
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct TicketQuery {
    ticket: String,
}

pub async fn upgrade(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TicketQuery>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let ticket = URL_SAFE_NO_PAD
        .decode(query.ticket)
        .map_err(|_| ApiError::Unauthorized)?;
    if ticket.len() != 32 {
        return Err(ApiError::Unauthorized);
    }
    let now = chrono::Utc::now().timestamp();
    let mut transaction = state.db.begin().await?;
    let device: Option<String> = sqlx::query_scalar("SELECT t.device_id FROM ws_tickets t JOIN devices d ON d.id=t.device_id WHERE t.ticket_hash=? AND t.consumed_at IS NULL AND t.expires_at>=? AND d.revoked_at IS NULL")
        .bind(sha256(&ticket)).bind(now).fetch_optional(&mut *transaction).await?;
    let device = device.ok_or(ApiError::Unauthorized)?;
    let changed = sqlx::query(
        "UPDATE ws_tickets SET consumed_at=? WHERE ticket_hash=? AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(sha256(&ticket))
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    if changed != 1 {
        return Err(ApiError::Unauthorized);
    }
    let device_id = Uuid::parse_str(&device).map_err(|error| ApiError::Internal(error.into()))?;
    let mut count = state.ws_connections.entry(device_id).or_insert(0);
    if *count >= 2 {
        return Err(ApiError::Conflict(
            "WebSocket connection limit reached".into(),
        ));
    }
    *count += 1;
    drop(count);
    Ok(ws.on_upgrade(move |socket| socket_loop(state, device_id, socket)))
}

async fn socket_loop(state: Arc<AppState>, device_id: Uuid, socket: WebSocket) {
    let connection_id = Uuid::new_v4();
    state
        .ws_subscriptions
        .entry((device_id, connection_id))
        .or_default();
    let (mut sender, mut receiver) = socket.split();
    let mut events = state.events.subscribe();
    let mut disconnects = state.disconnects.subscribe();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    let mut last_activity = tokio::time::Instant::now();
    loop {
        tokio::select! {
            incoming=receiver.next()=>match incoming {
                Some(Ok(Message::Text(text)))=>{
                    last_activity=tokio::time::Instant::now();
                    match handle_client_message(&state,device_id,connection_id,text.as_str()).await {
                        Ok(replies)=>for reply in replies { if send_json(&mut sender,&reply).await.is_err(){break;} },
                        Err(error)=>{ let value=serde_json::json!({"type":"error","message":error.to_string()}); if send_json(&mut sender,&value).await.is_err(){break;} }
                    }
                }
                Some(Ok(Message::Ping(data)))=>{ last_activity=tokio::time::Instant::now(); if sender.send(Message::Pong(data)).await.is_err(){break;} }
                Some(Ok(Message::Pong(_)))=>last_activity=tokio::time::Instant::now(),
                Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,
                _=>{}
            },
            event=events.recv()=>match event {
                Ok(event)=>{
                    let subscribed=state.ws_subscriptions.get(&(device_id,connection_id)).is_some_and(|set|set.contains(&event.channel_id));
                    if subscribed && send_json(&mut sender,&event.event).await.is_err(){break;}
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>if send_json(&mut sender,&serde_json::json!({"type":"resync_required"})).await.is_err(){break;},
                Err(tokio::sync::broadcast::error::RecvError::Closed)=>break,
            },
            revoked=disconnects.recv()=>if revoked.is_ok_and(|id|id==device_id){
                let _=sender.send(Message::Close(Some(axum::extract::ws::CloseFrame{code:1008,reason:"device credential changed".into()}))).await;
                break;
            },
            _=heartbeat.tick()=>{
                if last_activity.elapsed()>Duration::from_secs(75){break;}
                if sender.send(Message::Ping(Vec::new().into())).await.is_err(){break;}
            }
        }
    }
    state.ws_subscriptions.remove(&(device_id, connection_id));
    if let Some(mut count) = state.ws_connections.get_mut(&device_id) {
        if *count <= 1 {
            drop(count);
            state.ws_connections.remove(&device_id);
        } else {
            *count -= 1;
        }
    }
}

async fn send_json(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    value: &serde_json::Value,
) -> Result<(), axum::Error> {
    sender.send(Message::Text(value.to_string().into())).await
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Hello {
        #[serde(default)]
        last_sequences: HashMap<String, u64>,
        #[serde(default)]
        receive_channel_ids: Vec<Uuid>,
    },
    RoutingUpdate {
        receive_channel_ids: Vec<Uuid>,
        #[serde(default)]
        last_sequences: HashMap<String, u64>,
    },
    Ack {
        channel_id: Uuid,
        item_id: Uuid,
        sequence: u64,
    },
    Ping {
        sent_at: Option<String>,
    },
}

async fn handle_client_message(
    state: &AppState,
    device_id: Uuid,
    connection_id: Uuid,
    text: &str,
) -> ApiResult<Vec<serde_json::Value>> {
    let message: ClientMessage = serde_json::from_str(text)
        .map_err(|_| ApiError::BadRequest("invalid WebSocket message".into()))?;
    match message {
        ClientMessage::Hello {
            last_sequences,
            receive_channel_ids,
        }
        | ClientMessage::RoutingUpdate {
            last_sequences,
            receive_channel_ids,
        } => {
            update_subscriptions(state, device_id, connection_id, &receive_channel_ids).await?;
            replay_current(state, &receive_channel_ids, &last_sequences).await
        }
        ClientMessage::Ack {
            channel_id,
            item_id,
            sequence,
        } => {
            crate::auth::require_membership(state, device_id, channel_id).await?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM current_channel_items WHERE item_id=? AND channel_id=? AND channel_sequence=? UNION SELECT 1 FROM delivery_cache_items WHERE item_id=? AND channel_id=? AND channel_sequence=?)")
                .bind(item_id.to_string()).bind(channel_id.to_string()).bind(sequence as i64).bind(item_id.to_string()).bind(channel_id.to_string()).bind(sequence as i64).fetch_one(&state.db).await?;
            if !exists {
                return Err(ApiError::BadRequest("ack metadata mismatch".into()));
            }
            sqlx::query("UPDATE channel_memberships SET last_delivered_sequence=MAX(last_delivered_sequence,?) WHERE channel_id=? AND device_id=?").bind(sequence as i64).bind(channel_id.to_string()).bind(device_id.to_string()).execute(&state.db).await?;
            Ok(vec![])
        }
        ClientMessage::Ping { sent_at } => Ok(vec![
            serde_json::json!({"type":"pong","sent_at":sent_at,"server_at":chrono::Utc::now().to_rfc3339()}),
        ]),
    }
}

async fn update_subscriptions(
    state: &AppState,
    device_id: Uuid,
    connection_id: Uuid,
    requested: &[Uuid],
) -> ApiResult<()> {
    let unique: HashSet<Uuid> = requested.iter().copied().collect();
    if unique.len() != requested.len() || unique.len() > 32 {
        return Err(ApiError::BadRequest("invalid receive channel list".into()));
    }
    for channel in &unique {
        crate::auth::require_membership(state, device_id, *channel).await?;
    }
    state
        .ws_subscriptions
        .insert((device_id, connection_id), unique);
    Ok(())
}

async fn replay_current(
    state: &AppState,
    channels: &[Uuid],
    last: &HashMap<String, u64>,
) -> ApiResult<Vec<serde_json::Value>> {
    let mut replies = Vec::<(String, serde_json::Value)>::new();
    for channel in channels {
        type Row = (
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
        );
        let row:Option<Row>=sqlx::query_as("SELECT i.item_id,i.channel_id,i.origin_device_id,d.name,i.channel_sequence,i.crypto_version,i.content_type,i.ciphertext_size,i.plaintext_size,i.image_width,i.image_height,i.nonce,i.created_at_client,i.accepted_at_server FROM current_channel_items i JOIN devices d ON d.id=i.origin_device_id WHERE i.channel_id=?")
            .bind(channel.to_string()).fetch_optional(&state.db).await?;
        if let Some(row) = row
            && row.4 as u64 > *last.get(&channel.to_string()).unwrap_or(&0)
        {
            let item = serde_json::json!({"id":row.0,"channel_id":row.1,"origin_device_id":row.2,"origin_device_name":row.3,"channel_sequence":row.4,"crypto_version":row.5,"content_type":row.6,"ciphertext_size":row.7,"plaintext_size":row.8,"image_width":row.9,"image_height":row.10,"nonce":base64::engine::general_purpose::STANDARD.encode(row.11),"created_at_client":row.12,"accepted_at":row.13});
            replies.push((
                row.13,
                serde_json::json!({"type":"item_created","item":item}),
            ));
        }
    }
    replies.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(replies.into_iter().map(|(_, v)| v).collect())
}
