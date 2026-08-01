use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeClientInfo {
    pub version: String,
    pub downloads: Vec<NativeDownload>,
    pub checksums_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeDownload {
    pub os: String,
    pub arch: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub server_instance_id: Uuid,
    pub server_version: String,
    pub protocol_version: u16,
    pub chrome_store_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_client: Option<NativeClientInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_transfer: Option<FileTransferInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileTransferInfo {
    pub max_file_bytes: u64,
    pub chunk_bytes: u32,
    pub retention_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateFileRequest {
    pub file_id: Uuid,
    pub plaintext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileObjectResponse {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub origin_device_id: Uuid,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub next_chunk: u32,
    pub status: String,
    pub expires_at: i64,
    pub deduplicated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub pairing_code: String,
    pub name: String,
    pub signing_public_key: String,
    pub browser_family: String,
    pub browser_version: Option<String>,
    pub os_family: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: Uuid,
    pub device_token: String,
    pub server_instance_id: Uuid,
    pub api_version: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordKdf {
    pub name: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_bytes: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedSecret {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipPublicKey {
    pub algorithm: String,
    pub spki: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub channel_id: Uuid,
    pub name: String,
    pub crypto_version: u16,
    pub password_kdf: PasswordKdf,
    pub wrapped_secret: WrappedSecret,
    pub membership_public_key: MembershipPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSummary {
    pub id: Uuid,
    pub name: String,
    pub crypto_version: u16,
    pub member_count: u32,
    pub joined: bool,
    pub current_sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinParametersResponse {
    pub channel_id: Uuid,
    pub crypto_version: u16,
    pub password_kdf: PasswordKdf,
    pub wrapped_secret: WrappedSecret,
    pub membership_public_key: MembershipPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge_random: String,
    pub expires_at: i64,
    pub server_instance_id: Uuid,
    pub channel_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinChannelRequest {
    pub challenge_id: Uuid,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemMetadata {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub origin_device_id: Uuid,
    pub origin_device_name: String,
    pub channel_sequence: u64,
    pub crypto_version: u16,
    pub content_type: String,
    pub ciphertext_size: usize,
    pub plaintext_size: Option<usize>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub nonce: String,
    pub created_at_client: Option<String>,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadResponse {
    pub id: Uuid,
    pub channel_sequence: u64,
    pub accepted_at: String,
    pub deduplicated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsTicket {
    pub ticket: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol_version: u16,
        receive_channel_ids: Vec<Uuid>,
        last_sequences: std::collections::HashMap<String, u64>,
    },
    RoutingUpdate {
        receive_channel_ids: Vec<Uuid>,
        last_sequences: std::collections::HashMap<String, u64>,
    },
    Ack {
        channel_id: Uuid,
        item_id: Uuid,
        sequence: u64,
    },
    Ping {
        sent_at: String,
    },
}
