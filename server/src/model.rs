use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreatePairingRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingCodeResponse {
    pub code: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub pairing_code: String,
    pub name: String,
    pub signing_public_key: String,
    pub browser_family: String,
    pub browser_version: Option<String>,
    pub os_family: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: Uuid,
    pub device_token: String,
    pub server_instance_id: Uuid,
    pub api_version: u16,
}

#[derive(Clone, Debug)]
pub struct AuthDevice {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordKdf {
    pub name: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_bytes: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WrappedSecret {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MembershipPublicKey {
    pub algorithm: String,
    pub spki: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub channel_id: Uuid,
    pub name: String,
    pub crypto_version: u16,
    pub password_kdf: PasswordKdf,
    pub wrapped_secret: WrappedSecret,
    pub membership_public_key: MembershipPublicKey,
}

#[derive(Debug, Serialize)]
pub struct ChannelSummary {
    pub id: Uuid,
    pub name: String,
    pub crypto_version: u16,
    pub member_count: u32,
    pub joined: bool,
    pub current_sequence: u64,
}

#[derive(Debug, Serialize)]
pub struct JoinParametersResponse {
    pub channel_id: Uuid,
    pub crypto_version: u16,
    pub password_kdf: PasswordKdf,
    pub wrapped_secret: WrappedSecret,
    pub membership_public_key: MembershipPublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge_random: String,
    pub expires_at: i64,
    pub server_instance_id: Uuid,
    pub channel_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct JoinChannelRequest {
    pub challenge_id: Uuid,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ItemMetadata {
    pub id: String,
    pub channel_id: String,
    pub origin_device_id: String,
    pub origin_device_name: String,
    pub channel_sequence: i64,
    pub crypto_version: i64,
    pub content_type: String,
    pub ciphertext_size: i64,
    pub plaintext_size: Option<i64>,
    pub image_width: Option<i64>,
    pub image_height: Option<i64>,
    pub nonce: String,
    pub created_at_client: Option<String>,
    pub accepted_at: String,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub id: Uuid,
    pub channel_sequence: u64,
    pub accepted_at: String,
    pub deduplicated: bool,
}
