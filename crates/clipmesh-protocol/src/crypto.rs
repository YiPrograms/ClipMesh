use aes_gcm::{
    AeadInPlace, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    FILE_CHUNK_BYTES, FILE_MANIFEST_CONTENT_TYPE, MAX_FILENAME_BYTES, MAX_IMAGE_DIMENSION,
    MAX_IMAGE_PIXELS, MAX_MEDIA_TYPE_BYTES, MAX_PNG_BYTES, MAX_TEXT_BYTES, wire::*,
};

const WRAP_INFO: &[u8] = b"clipboard-sync/channel-wrap-key/v1";
const PASSWORD_CHECK_INFO: &[u8] = b"clipboard-sync/channel-password-check-key/v1";
const PASSWORD_CHECK_LABEL: &[u8] = b"clipboard-sync/password-check/v1\0";
const ITEM_ROOT_INFO: &[u8] = b"clipboard-sync/channel-item-root/v1";
const ITEM_KEY_INFO: &[u8] = b"clipboard-sync/item-key/v1\0";
const FILE_ROOT_INFO: &[u8] = b"clipboard-sync/channel-file-root/v1";
const FILE_KEY_INFO: &[u8] = b"clipboard-sync/file-key/v1\0";
const FILE_CHUNK_AAD_LABEL: &[u8] = b"clipboard-sync/file-chunk-aad/v1\0";
const WRAP_AAD_LABEL: &[u8] = b"clipboard-sync/channel-wrap-aad/v1\0";
const ITEM_AAD_LABEL: &[u8] = b"clipboard-sync/item-aad/v1\0";
pub const JOIN_LABEL: &[u8] = b"clipboard-sync/channel-join/v1\0";

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("incorrect password or corrupted channel data")]
    Password,
    #[error("cryptographic operation failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSecret {
    pub version: u16,
    pub channel_id: Uuid,
    pub root_key: String,
    pub membership_private_key: String,
    pub membership_public_key: String,
    pub crypto_version: u16,
}

#[derive(Clone, Debug)]
pub struct ChannelMaterial {
    pub channel_id: Uuid,
    pub password_kdf: PasswordKdf,
    pub wrapped_secret: WrappedSecret,
    pub membership_public_key: MembershipPublicKey,
    pub secret: ChannelSecret,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClipboardItem {
    Text(Vec<u8>),
    Png {
        bytes: Vec<u8>,
        width: u32,
        height: u32,
    },
    File(FileManifest),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    pub file_id: Uuid,
    pub filename: String,
    pub media_type: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub nonce_prefix: String,
    pub sha256: String,
    pub expires_at: i64,
}

impl ClipboardItem {
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Text(_) => "text/plain",
            Self::Png { .. } => "image/png",
            Self::File(_) => FILE_MANIFEST_CONTENT_TYPE,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(bytes) | Self::Png { bytes, .. } => bytes,
            Self::File(_) => &[],
        }
    }

    pub fn display_size(&self) -> u64 {
        match self {
            Self::Text(bytes) | Self::Png { bytes, .. } => bytes.len() as u64,
            Self::File(manifest) => manifest.size,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub origin_device_id: Uuid,
    pub crypto_version: u16,
    pub content_type: String,
    pub ciphertext: Vec<u8>,
    pub plaintext_size: usize,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub nonce: String,
    pub created_at_client: String,
    pub file_id: Option<Uuid>,
}

pub fn sha256(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

pub fn content_hash(item: &ClipboardItem) -> String {
    let mut digest = Sha256::new();
    match item {
        ClipboardItem::Text(bytes) => {
            digest.update([1]);
            digest.update(bytes);
        }
        ClipboardItem::Png { bytes, .. } => {
            digest.update([2]);
            digest.update(bytes);
        }
        ClipboardItem::File(manifest) => {
            digest.update([3]);
            digest.update(manifest.file_id.as_bytes());
            digest.update(manifest.filename.as_bytes());
            digest.update(manifest.sha256.as_bytes());
        }
    }
    STANDARD.encode(digest.finalize())
}

pub fn create_channel_material(password: &str, channel_id: Uuid) -> Result<ChannelMaterial> {
    validate_password(password)?;
    let mut salt = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let kdf = PasswordKdf {
        name: "argon2id".into(),
        salt: STANDARD.encode(salt),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
        output_bytes: 32,
    };
    let mut root_key = [0_u8; 32];
    rand::rng().fill_bytes(&mut root_key);
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let private_key = signing_key
        .to_pkcs8_der()
        .map_err(|_| ProtocolError::Crypto)?;
    let public_key = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| ProtocolError::Crypto)?;
    let secret = ChannelSecret {
        version: 1,
        channel_id,
        root_key: STANDARD.encode(root_key),
        membership_private_key: STANDARD.encode(private_key.as_bytes()),
        membership_public_key: STANDARD.encode(public_key.as_bytes()),
        crypto_version: 1,
    };
    let wrapped_secret = wrap_channel_secret(password, &kdf, &secret)?;
    Ok(ChannelMaterial {
        channel_id,
        password_kdf: kdf,
        wrapped_secret,
        membership_public_key: MembershipPublicKey {
            algorithm: "ecdsa-p256-sha256".into(),
            spki: secret.membership_public_key.clone(),
        },
        secret,
    })
}

pub fn wrap_channel_secret(
    password: &str,
    kdf: &PasswordKdf,
    secret: &ChannelSecret,
) -> Result<WrappedSecret> {
    validate_kdf(kdf)?;
    let (wrap_key, check_key) = derive_password_keys(password, kdf)?;
    let root = decode_fixed::<32>(&secret.root_key)?;
    let private_key = STANDARD
        .decode(&secret.membership_private_key)
        .map_err(|_| ProtocolError::Invalid("invalid membership private key"))?;
    let public_key = STANDARD
        .decode(&secret.membership_public_key)
        .map_err(|_| ProtocolError::Invalid("invalid membership public key"))?;
    let check = password_check(&check_key, secret.channel_id)?;
    let plaintext = encode_secret(&root, &private_key, &check)?;
    let aad = wrap_aad(secret.channel_id, kdf, &public_key)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| ProtocolError::Crypto)?;
    let nonce_value = Nonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::Crypto)?;
    Ok(WrappedSecret {
        algorithm: "aes-256-gcm".into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn unwrap_channel_secret(
    password: &str,
    channel_id: Uuid,
    kdf: &PasswordKdf,
    wrapped: &WrappedSecret,
    public_spki: &str,
) -> Result<ChannelSecret> {
    validate_kdf(kdf)?;
    if wrapped.algorithm != "aes-256-gcm" {
        return Err(ProtocolError::Invalid(
            "unsupported channel wrapping algorithm",
        ));
    }
    let (wrap_key, check_key) = derive_password_keys(password, kdf)?;
    let nonce = decode_fixed::<12>(&wrapped.nonce)?;
    let public = STANDARD
        .decode(public_spki)
        .map_err(|_| ProtocolError::Invalid("invalid public key"))?;
    let aad = wrap_aad(channel_id, kdf, &public)?;
    let mut ciphertext = STANDARD
        .decode(&wrapped.ciphertext)
        .map_err(|_| ProtocolError::Password)?;
    let nonce_value = Nonce::from(nonce);
    Aes256Gcm::new_from_slice(&wrap_key)
        .map_err(|_| ProtocolError::Crypto)?
        .decrypt_in_place(&nonce_value, &aad, &mut ciphertext)
        .map_err(|_| ProtocolError::Password)?;
    let (root, private, check) = decode_secret(&ciphertext)?;
    let expected = password_check(&check_key, channel_id)?;
    if !bool::from(check.ct_eq(&expected)) {
        return Err(ProtocolError::Password);
    }
    let signing = SigningKey::from_pkcs8_der(&private).map_err(|_| ProtocolError::Password)?;
    let verifying =
        VerifyingKey::from_public_key_der(&public).map_err(|_| ProtocolError::Password)?;
    let probe = b"ClipMesh membership key check";
    let signature: Signature = signing.sign(probe);
    verifying
        .verify(probe, &signature)
        .map_err(|_| ProtocolError::Password)?;
    Ok(ChannelSecret {
        version: 1,
        channel_id,
        root_key: STANDARD.encode(root),
        membership_private_key: STANDARD.encode(private),
        membership_public_key: public_spki.into(),
        crypto_version: 1,
    })
}

pub fn sign_join_challenge(
    secret: &ChannelSecret,
    server_id: Uuid,
    device_id: Uuid,
    challenge_id: Uuid,
    random_b64: &str,
    expires_at: i64,
) -> Result<String> {
    let random = decode_fixed::<32>(random_b64)?;
    let message = join_message(
        server_id,
        secret.channel_id,
        device_id,
        challenge_id,
        &random,
        expires_at,
    );
    let private = STANDARD
        .decode(&secret.membership_private_key)
        .map_err(|_| ProtocolError::Invalid("invalid private key"))?;
    let key = SigningKey::from_pkcs8_der(&private)
        .map_err(|_| ProtocolError::Invalid("invalid private key"))?;
    let signature: Signature = key.sign(&message);
    Ok(STANDARD.encode(signature.to_bytes()))
}

pub fn encrypt_item(
    secret: &ChannelSecret,
    server_id: Uuid,
    origin_device_id: Uuid,
    item: &ClipboardItem,
    created_at: String,
) -> Result<EncryptedEnvelope> {
    validate_item(item)?;
    let id = Uuid::now_v7();
    let key = item_key(&decode_fixed(&secret.root_key)?, secret.channel_id, id);
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let plaintext = encode_clipboard_payload(item)?;
    let aad = item_aad(
        server_id,
        secret.channel_id,
        id,
        origin_device_id,
        item.content_type(),
        &created_at,
    );
    let nonce_value = Nonce::from(nonce);
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto)?
        .encrypt(
            &nonce_value,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::Crypto)?;
    let (width, height) = match item {
        ClipboardItem::Png { width, height, .. } => (Some(*width), Some(*height)),
        _ => (None, None),
    };
    Ok(EncryptedEnvelope {
        id,
        channel_id: secret.channel_id,
        origin_device_id,
        crypto_version: 1,
        content_type: item.content_type().into(),
        ciphertext,
        plaintext_size: match item {
            ClipboardItem::File(_) => plaintext.len(),
            _ => item.bytes().len(),
        },
        image_width: width,
        image_height: height,
        nonce: STANDARD.encode(nonce),
        created_at_client: created_at,
        file_id: match item {
            ClipboardItem::File(manifest) => Some(manifest.file_id),
            _ => None,
        },
    })
}

pub fn decrypt_item(
    secret: &ChannelSecret,
    server_id: Uuid,
    metadata: &ItemMetadata,
    mut ciphertext: Vec<u8>,
) -> Result<ClipboardItem> {
    if metadata.crypto_version != 1
        || metadata.channel_id != secret.channel_id
        || metadata.ciphertext_size != ciphertext.len()
    {
        return Err(ProtocolError::Invalid(
            "unsupported or inconsistent envelope",
        ));
    }
    let root = decode_fixed(&secret.root_key)?;
    let key = item_key(&root, secret.channel_id, metadata.id);
    let nonce = decode_fixed::<12>(&metadata.nonce)?;
    let aad = item_aad(
        server_id,
        metadata.channel_id,
        metadata.id,
        metadata.origin_device_id,
        &metadata.content_type,
        metadata.created_at_client.as_deref().unwrap_or(""),
    );
    let nonce_value = Nonce::from(nonce);
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto)?
        .decrypt_in_place(&nonce_value, &aad, &mut ciphertext)
        .map_err(|_| ProtocolError::Invalid("clipboard envelope authentication failed"))?;
    let encoded_size = ciphertext.len();
    let item = decode_clipboard_payload(&ciphertext)?;
    validate_item(&item)?;
    let dimensions_match = match &item {
        ClipboardItem::Png { width, height, .. } => {
            metadata.image_width == Some(*width) && metadata.image_height == Some(*height)
        }
        _ => metadata.image_width.is_none() && metadata.image_height.is_none(),
    };
    let plaintext_size = match &item {
        ClipboardItem::File(_) => encoded_size,
        _ => item.bytes().len(),
    };
    if item.content_type() != metadata.content_type
        || plaintext_size != metadata.plaintext_size.unwrap_or(usize::MAX)
        || !dimensions_match
    {
        return Err(ProtocolError::Invalid(
            "authenticated item metadata mismatch",
        ));
    }
    Ok(item)
}

pub fn join_message(
    server_id: Uuid,
    channel_id: Uuid,
    device_id: Uuid,
    challenge_id: Uuid,
    random: &[u8; 32],
    expires_at: i64,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(JOIN_LABEL.len() + 104);
    value.extend_from_slice(JOIN_LABEL);
    for id in [server_id, channel_id, device_id, challenge_id] {
        value.extend_from_slice(id.as_bytes());
    }
    value.extend_from_slice(random);
    value.extend_from_slice(&expires_at.to_be_bytes());
    value
}

pub fn item_key(channel_root_key: &[u8; 32], channel_id: Uuid, item_id: Uuid) -> [u8; 32] {
    let root = Hkdf::<Sha256>::new(None, channel_root_key);
    let mut item_root = [0_u8; 32];
    root.expand(ITEM_ROOT_INFO, &mut item_root)
        .expect("fixed HKDF output");
    let item = Hkdf::<Sha256>::new(Some(channel_id.as_bytes()), &item_root);
    let mut info = Vec::from(ITEM_KEY_INFO);
    info.extend_from_slice(item_id.as_bytes());
    let mut key = [0_u8; 32];
    item.expand(&info, &mut key).expect("fixed HKDF output");
    key
}

pub fn file_key(channel_root_key: &[u8; 32], channel_id: Uuid, file_id: Uuid) -> [u8; 32] {
    let root = Hkdf::<Sha256>::new(None, channel_root_key);
    let mut file_root = [0_u8; 32];
    root.expand(FILE_ROOT_INFO, &mut file_root)
        .expect("fixed HKDF output");
    let file = Hkdf::<Sha256>::new(Some(channel_id.as_bytes()), &file_root);
    let mut info = Vec::from(FILE_KEY_INFO);
    info.extend_from_slice(file_id.as_bytes());
    let mut key = [0_u8; 32];
    file.expand(&info, &mut key).expect("fixed HKDF output");
    key
}

pub fn file_chunk_count(size: u64, chunk_size: u32) -> Result<u32> {
    if chunk_size == 0 {
        return Err(ProtocolError::Invalid("file chunk size must be positive"));
    }
    let count = size.div_ceil(u64::from(chunk_size)).max(1);
    u32::try_from(count).map_err(|_| ProtocolError::Invalid("file has too many chunks"))
}

pub fn file_chunk_plaintext_size(manifest: &FileManifest, index: u32) -> Result<usize> {
    if index >= manifest.chunk_count {
        return Err(ProtocolError::Invalid("file chunk index is out of range"));
    }
    if manifest.size == 0 {
        return Ok(0);
    }
    let offset = u64::from(index) * u64::from(manifest.chunk_size);
    usize::try_from((manifest.size - offset).min(u64::from(manifest.chunk_size)))
        .map_err(|_| ProtocolError::Invalid("file chunk is too large"))
}

pub fn encrypt_file_chunk(
    secret: &ChannelSecret,
    server_id: Uuid,
    manifest: &FileManifest,
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    validate_file_manifest(manifest)?;
    if plaintext.len() != file_chunk_plaintext_size(manifest, index)? {
        return Err(ProtocolError::Invalid(
            "file chunk length does not match manifest",
        ));
    }
    let root = decode_fixed(&secret.root_key)?;
    let key = file_key(&root, secret.channel_id, manifest.file_id);
    let nonce = file_chunk_nonce(manifest, index)?;
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto)?
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &file_chunk_aad(server_id, secret.channel_id, manifest, index),
            },
        )
        .map_err(|_| ProtocolError::Crypto)
}

pub fn decrypt_file_chunk(
    secret: &ChannelSecret,
    server_id: Uuid,
    manifest: &FileManifest,
    index: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    validate_file_manifest(manifest)?;
    let expected = file_chunk_plaintext_size(manifest, index)? + 16;
    if ciphertext.len() != expected {
        return Err(ProtocolError::Invalid(
            "encrypted file chunk length does not match manifest",
        ));
    }
    let root = decode_fixed(&secret.root_key)?;
    let key = file_key(&root, secret.channel_id, manifest.file_id);
    let nonce = file_chunk_nonce(manifest, index)?;
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ProtocolError::Crypto)?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &file_chunk_aad(server_id, secret.channel_id, manifest, index),
            },
        )
        .map_err(|_| ProtocolError::Invalid("file chunk authentication failed"))
}

pub fn validate_item(item: &ClipboardItem) -> Result<()> {
    match item {
        ClipboardItem::Text(bytes) => {
            if bytes.len() > MAX_TEXT_BYTES {
                return Err(ProtocolError::Invalid("text exceeds 1 MiB"));
            }
            let text = std::str::from_utf8(bytes)
                .map_err(|_| ProtocolError::Invalid("text is not UTF-8"))?;
            if text.contains('\0') {
                return Err(ProtocolError::Invalid("text contains a null byte"));
            }
        }
        ClipboardItem::Png {
            bytes,
            width,
            height,
        } => {
            if bytes.len() > MAX_PNG_BYTES
                || *width == 0
                || *height == 0
                || *width > MAX_IMAGE_DIMENSION
                || *height > MAX_IMAGE_DIMENSION
                || u64::from(*width) * u64::from(*height) > MAX_IMAGE_PIXELS
            {
                return Err(ProtocolError::Invalid("PNG exceeds image limits"));
            }
            if bytes.len() < 24
                || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
                || &bytes[12..16] != b"IHDR"
                || u32::from_be_bytes(bytes[16..20].try_into().unwrap()) != *width
                || u32::from_be_bytes(bytes[20..24].try_into().unwrap()) != *height
            {
                return Err(ProtocolError::Invalid("malformed PNG"));
            }
        }
        ClipboardItem::File(manifest) => validate_file_manifest(manifest)?,
    }
    Ok(())
}

pub fn validate_file_manifest(manifest: &FileManifest) -> Result<()> {
    let filename = manifest.filename.as_bytes();
    if filename.is_empty()
        || filename.len() > MAX_FILENAME_BYTES
        || manifest.filename == "."
        || manifest.filename == ".."
        || manifest
            .filename
            .chars()
            .any(|value| value.is_control() || matches!(value, '/' | '\\'))
    {
        return Err(ProtocolError::Invalid("invalid file name"));
    }
    if manifest.media_type.is_empty()
        || manifest.media_type.len() > MAX_MEDIA_TYPE_BYTES
        || !manifest
            .media_type
            .bytes()
            .all(|value| value.is_ascii_graphic())
    {
        return Err(ProtocolError::Invalid("invalid file media type"));
    }
    if manifest.chunk_size != FILE_CHUNK_BYTES
        || manifest.chunk_count != file_chunk_count(manifest.size, manifest.chunk_size)?
        || manifest.expires_at <= 0
        || decode_fixed::<8>(&manifest.nonce_prefix).is_err()
        || decode_fixed::<32>(&manifest.sha256).is_err()
    {
        return Err(ProtocolError::Invalid("invalid file manifest"));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < 12 {
        return Err(ProtocolError::Invalid(
            "channel password must contain at least 12 characters",
        ));
    }
    let normalized: String = password
        .to_ascii_lowercase()
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .collect();
    let weak = [
        "password1234",
        "123456789012",
        "qwertyuiop12",
        "letmeinplease",
        "correcthorsebatterystaple",
    ];
    let repeated = password
        .chars()
        .next()
        .is_some_and(|first| password.chars().all(|value| value == first));
    if weak.contains(&normalized.as_str()) || repeated {
        return Err(ProtocolError::Invalid(
            "choose a less common channel password",
        ));
    }
    Ok(())
}

fn validate_kdf(kdf: &PasswordKdf) -> Result<()> {
    if kdf.name != "argon2id"
        || !(65_536..=1_048_576).contains(&kdf.memory_kib)
        || !(3..=32).contains(&kdf.iterations)
        || !(1..=16).contains(&kdf.parallelism)
        || kdf.output_bytes != 32
        || STANDARD
            .decode(&kdf.salt)
            .map_err(|_| ProtocolError::Invalid("invalid KDF salt"))?
            .len()
            < 16
    {
        return Err(ProtocolError::Invalid("unsupported password KDF profile"));
    }
    Ok(())
}

fn derive_password_keys(password: &str, kdf: &PasswordKdf) -> Result<([u8; 32], [u8; 32])> {
    let salt = STANDARD
        .decode(&kdf.salt)
        .map_err(|_| ProtocolError::Invalid("invalid KDF salt"))?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| ProtocolError::Invalid("invalid KDF parameters"))?;
    let mut master = [0_u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut master)
        .map_err(|_| ProtocolError::Crypto)?;
    Ok((
        hkdf(&master, &[], WRAP_INFO),
        hkdf(&master, &[], PASSWORD_CHECK_INFO),
    ))
}

fn hkdf(input: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let value = Hkdf::<Sha256>::new(salt, input);
    let mut out = [0_u8; 32];
    value.expand(info, &mut out).expect("fixed HKDF output");
    out
}

fn password_check(key: &[u8; 32], channel_id: Uuid) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| ProtocolError::Crypto)?;
    mac.update(PASSWORD_CHECK_LABEL);
    mac.update(channel_id.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn wrap_aad(channel_id: Uuid, kdf: &PasswordKdf, public_key: &[u8]) -> Result<Vec<u8>> {
    let salt = STANDARD
        .decode(&kdf.salt)
        .map_err(|_| ProtocolError::Invalid("invalid KDF salt"))?;
    let mut out = Vec::new();
    out.extend_from_slice(WRAP_AAD_LABEL);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(channel_id.as_bytes());
    out.push(kdf.name.len() as u8);
    out.extend_from_slice(kdf.name.as_bytes());
    out.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    out.extend_from_slice(&kdf.iterations.to_be_bytes());
    out.extend_from_slice(&kdf.parallelism.to_be_bytes());
    out.extend_from_slice(&kdf.output_bytes.to_be_bytes());
    push_bytes(&mut out, &salt)?;
    push_bytes(&mut out, public_key)?;
    Ok(out)
}

fn item_aad(
    server_id: Uuid,
    channel_id: Uuid,
    item_id: Uuid,
    device_id: Uuid,
    content_type: &str,
    created_at: &str,
) -> Vec<u8> {
    let timestamp = created_at.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(ITEM_AAD_LABEL);
    out.extend_from_slice(&1_u16.to_be_bytes());
    for id in [server_id, channel_id, item_id, device_id] {
        out.extend_from_slice(id.as_bytes());
    }
    out.push(match content_type {
        "text/plain" => 1,
        "image/png" => 2,
        FILE_MANIFEST_CONTENT_TYPE => 3,
        _ => 0,
    });
    out.extend_from_slice(&(timestamp.len() as u16).to_be_bytes());
    out.extend_from_slice(timestamp);
    out
}

fn file_chunk_nonce(manifest: &FileManifest, index: u32) -> Result<[u8; 12]> {
    let prefix = decode_fixed::<8>(&manifest.nonce_prefix)?;
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    Ok(nonce)
}

fn file_chunk_aad(
    server_id: Uuid,
    channel_id: Uuid,
    manifest: &FileManifest,
    index: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILE_CHUNK_AAD_LABEL.len() + 66);
    out.extend_from_slice(FILE_CHUNK_AAD_LABEL);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(server_id.as_bytes());
    out.extend_from_slice(channel_id.as_bytes());
    out.extend_from_slice(manifest.file_id.as_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&manifest.size.to_be_bytes());
    out.extend_from_slice(&manifest.chunk_size.to_be_bytes());
    out
}

fn encode_secret(root: &[u8; 32], private: &[u8], check: &[u8; 32]) -> Result<Vec<u8>> {
    let mut out = vec![0xa4, 1, 1, 2];
    cbor_bytes(&mut out, root)?;
    out.push(3);
    cbor_bytes(&mut out, private)?;
    out.push(4);
    cbor_bytes(&mut out, check)?;
    Ok(out)
}

fn decode_secret(value: &[u8]) -> Result<([u8; 32], Vec<u8>, [u8; 32])> {
    let mut offset = 0;
    let mut byte = || {
        let result = value.get(offset).copied();
        offset += 1;
        result
    };
    if byte() != Some(0xa4) || byte() != Some(1) || byte() != Some(1) || byte() != Some(2) {
        return Err(ProtocolError::Password);
    }
    fn read(value: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
        let head = *value.get(*offset).ok_or(ProtocolError::Password)?;
        *offset += 1;
        let length = match head {
            0x40..=0x57 => usize::from(head - 0x40),
            0x58 => {
                let n = *value.get(*offset).ok_or(ProtocolError::Password)?;
                *offset += 1;
                usize::from(n)
            }
            0x59 => {
                let end = *offset + 2;
                let bytes: [u8; 2] = value
                    .get(*offset..end)
                    .ok_or(ProtocolError::Password)?
                    .try_into()
                    .unwrap();
                *offset = end;
                usize::from(u16::from_be_bytes(bytes))
            }
            _ => return Err(ProtocolError::Password),
        };
        let end = *offset + length;
        let bytes = value
            .get(*offset..end)
            .ok_or(ProtocolError::Password)?
            .to_vec();
        *offset = end;
        Ok(bytes)
    }
    let root: [u8; 32] = read(value, &mut offset)?
        .try_into()
        .map_err(|_| ProtocolError::Password)?;
    if value.get(offset) != Some(&3) {
        return Err(ProtocolError::Password);
    }
    offset += 1;
    let private = read(value, &mut offset)?;
    if value.get(offset) != Some(&4) {
        return Err(ProtocolError::Password);
    }
    offset += 1;
    let check: [u8; 32] = read(value, &mut offset)?
        .try_into()
        .map_err(|_| ProtocolError::Password)?;
    if offset != value.len() {
        return Err(ProtocolError::Password);
    }
    Ok((root, private, check))
}

fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    match value.len() {
        0..=23 => out.push(0x40 + value.len() as u8),
        24..=255 => {
            out.push(0x58);
            out.push(value.len() as u8);
        }
        256..=65_535 => {
            out.push(0x59);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(ProtocolError::Invalid("secret is too large")),
    };
    out.extend_from_slice(value);
    Ok(())
}
fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length =
        u16::try_from(value.len()).map_err(|_| ProtocolError::Invalid("value is too large"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn encode_clipboard_payload(item: &ClipboardItem) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_u16.to_be_bytes());
    match item {
        ClipboardItem::Text(bytes) => {
            out.push(1);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        ClipboardItem::Png {
            bytes,
            width,
            height,
        } => {
            out.push(2);
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        ClipboardItem::File(manifest) => {
            let filename = manifest.filename.as_bytes();
            let media_type = manifest.media_type.as_bytes();
            let nonce = decode_fixed::<8>(&manifest.nonce_prefix)?;
            let hash = decode_fixed::<32>(&manifest.sha256)?;
            out.push(3);
            out.extend_from_slice(manifest.file_id.as_bytes());
            out.extend_from_slice(&(filename.len() as u16).to_be_bytes());
            out.extend_from_slice(filename);
            out.extend_from_slice(&(media_type.len() as u16).to_be_bytes());
            out.extend_from_slice(media_type);
            out.extend_from_slice(&manifest.size.to_be_bytes());
            out.extend_from_slice(&manifest.chunk_size.to_be_bytes());
            out.extend_from_slice(&manifest.chunk_count.to_be_bytes());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&hash);
            out.extend_from_slice(&manifest.expires_at.to_be_bytes());
        }
    }
    Ok(out)
}
fn decode_clipboard_payload(value: &[u8]) -> Result<ClipboardItem> {
    if value.len() < 7 || value[..2] != 1_u16.to_be_bytes() {
        return Err(ProtocolError::Invalid("unsupported clipboard payload"));
    }
    let read_u32 = |offset: usize| {
        value
            .get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(ProtocolError::Invalid("invalid clipboard payload"))
    };
    match value[2] {
        1 => {
            let length = read_u32(3)? as usize;
            if value.len() != 7 + length {
                return Err(ProtocolError::Invalid("invalid text payload"));
            }
            Ok(ClipboardItem::Text(value[7..].to_vec()))
        }
        2 => {
            if value.len() < 15 {
                return Err(ProtocolError::Invalid("invalid image payload"));
            }
            let width = read_u32(3)?;
            let height = read_u32(7)?;
            let length = read_u32(11)? as usize;
            if value.len() != 15 + length {
                return Err(ProtocolError::Invalid("invalid image payload"));
            }
            Ok(ClipboardItem::Png {
                bytes: value[15..].to_vec(),
                width,
                height,
            })
        }
        3 => {
            let mut offset = 3;
            let file_id = Uuid::from_slice(
                value
                    .get(offset..offset + 16)
                    .ok_or(ProtocolError::Invalid("invalid file manifest"))?,
            )
            .map_err(|_| ProtocolError::Invalid("invalid file manifest"))?;
            offset += 16;
            let read_u16 = |value: &[u8], offset: &mut usize| -> Result<usize> {
                let end = *offset + 2;
                let bytes: [u8; 2] = value
                    .get(*offset..end)
                    .ok_or(ProtocolError::Invalid("invalid file manifest"))?
                    .try_into()
                    .unwrap();
                *offset = end;
                Ok(usize::from(u16::from_be_bytes(bytes)))
            };
            let filename_length = read_u16(value, &mut offset)?;
            let filename_end = offset + filename_length;
            let filename = std::str::from_utf8(
                value
                    .get(offset..filename_end)
                    .ok_or(ProtocolError::Invalid("invalid file manifest"))?,
            )
            .map_err(|_| ProtocolError::Invalid("invalid file name"))?
            .to_owned();
            offset = filename_end;
            let media_type_length = read_u16(value, &mut offset)?;
            let media_type_end = offset + media_type_length;
            let media_type = std::str::from_utf8(
                value
                    .get(offset..media_type_end)
                    .ok_or(ProtocolError::Invalid("invalid file manifest"))?,
            )
            .map_err(|_| ProtocolError::Invalid("invalid file media type"))?
            .to_owned();
            offset = media_type_end;
            let fixed = value
                .get(offset..offset + 64)
                .ok_or(ProtocolError::Invalid("invalid file manifest"))?;
            let size = u64::from_be_bytes(fixed[0..8].try_into().unwrap());
            let chunk_size = u32::from_be_bytes(fixed[8..12].try_into().unwrap());
            let chunk_count = u32::from_be_bytes(fixed[12..16].try_into().unwrap());
            let nonce_prefix = STANDARD.encode(&fixed[16..24]);
            let sha256 = STANDARD.encode(&fixed[24..56]);
            let expires_at = i64::from_be_bytes(fixed[56..64].try_into().unwrap());
            offset += 64;
            if offset != value.len() {
                return Err(ProtocolError::Invalid("invalid file manifest"));
            }
            Ok(ClipboardItem::File(FileManifest {
                file_id,
                filename,
                media_type,
                size,
                chunk_size,
                chunk_count,
                nonce_prefix,
                sha256,
                expires_at,
            }))
        }
        _ => Err(ProtocolError::Invalid("unsupported clipboard type")),
    }
}
fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(value)
        .map_err(|_| ProtocolError::Invalid("invalid base64"))?
        .try_into()
        .map_err(|_| ProtocolError::Invalid("invalid encoded length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Vectors {
        channel_root_key_hex: String,
        channel_id: Uuid,
        item_id: Uuid,
        server_instance_id: Uuid,
        device_id: Uuid,
        challenge_id: Uuid,
        challenge_random_base64: String,
        expires_at: i64,
        item_key_hex: String,
        join_message_hex: String,
    }
    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../../protocol/test-vectors.json")).unwrap()
    }
    #[test]
    fn matches_browser_vectors() {
        let vector = vectors();
        let root: [u8; 32] = hex::decode(vector.channel_root_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(item_key(&root, vector.channel_id, vector.item_id)),
            vector.item_key_hex
        );
        let random = decode_fixed(&vector.challenge_random_base64).unwrap();
        assert_eq!(
            hex::encode(join_message(
                vector.server_instance_id,
                vector.channel_id,
                vector.device_id,
                vector.challenge_id,
                &random,
                vector.expires_at
            )),
            vector.join_message_hex
        );
    }
    #[test]
    fn wraps_and_encrypts_round_trip() {
        let channel = Uuid::new_v4();
        let material = create_channel_material("a strong test passphrase", channel).unwrap();
        let secret = unwrap_channel_secret(
            "a strong test passphrase",
            channel,
            &material.password_kdf,
            &material.wrapped_secret,
            &material.membership_public_key.spki,
        )
        .unwrap();
        assert_eq!(secret.root_key, material.secret.root_key);
        let server = Uuid::new_v4();
        let device = Uuid::new_v4();
        let item = ClipboardItem::Text(b"hello".to_vec());
        let envelope = encrypt_item(
            &secret,
            server,
            device,
            &item,
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        let metadata = ItemMetadata {
            id: envelope.id,
            channel_id: channel,
            origin_device_id: device,
            origin_device_name: "test".into(),
            channel_sequence: 1,
            crypto_version: 1,
            content_type: envelope.content_type.clone(),
            ciphertext_size: envelope.ciphertext.len(),
            plaintext_size: Some(5),
            image_width: None,
            image_height: None,
            nonce: envelope.nonce.clone(),
            created_at_client: Some(envelope.created_at_client.clone()),
            accepted_at: "2026-01-01T00:00:01Z".into(),
        };
        assert_eq!(
            decrypt_item(&secret, server, &metadata, envelope.ciphertext)
                .unwrap()
                .bytes(),
            b"hello"
        );
    }

    #[test]
    fn file_manifest_and_chunks_round_trip() {
        let channel = Uuid::new_v4();
        let material = create_channel_material("a strong file passphrase", channel).unwrap();
        let server = Uuid::new_v4();
        let device = Uuid::new_v4();
        let plaintext = b"file contents";
        let manifest = FileManifest {
            file_id: Uuid::now_v7(),
            filename: "notes.txt".into(),
            media_type: "text/plain".into(),
            size: plaintext.len() as u64,
            chunk_size: FILE_CHUNK_BYTES,
            chunk_count: 1,
            nonce_prefix: STANDARD.encode([7_u8; 8]),
            sha256: STANDARD.encode(Sha256::digest(plaintext)),
            expires_at: 1_900_000_000,
        };
        let encrypted =
            encrypt_file_chunk(&material.secret, server, &manifest, 0, plaintext).unwrap();
        assert_eq!(
            decrypt_file_chunk(&material.secret, server, &manifest, 0, &encrypted).unwrap(),
            plaintext
        );
        let item = ClipboardItem::File(manifest.clone());
        let envelope = encrypt_item(
            &material.secret,
            server,
            device,
            &item,
            "2026-01-01T00:00:00Z".into(),
        )
        .unwrap();
        let metadata = ItemMetadata {
            id: envelope.id,
            channel_id: channel,
            origin_device_id: device,
            origin_device_name: "test".into(),
            channel_sequence: 1,
            crypto_version: 1,
            content_type: envelope.content_type.clone(),
            ciphertext_size: envelope.ciphertext.len(),
            plaintext_size: Some(envelope.plaintext_size),
            image_width: None,
            image_height: None,
            nonce: envelope.nonce.clone(),
            created_at_client: Some(envelope.created_at_client.clone()),
            accepted_at: "2026-01-01T00:00:01Z".into(),
        };
        match decrypt_item(&material.secret, server, &metadata, envelope.ciphertext).unwrap() {
            ClipboardItem::File(decoded) => assert_eq!(decoded, manifest),
            _ => panic!("expected a file manifest"),
        }
    }
}
