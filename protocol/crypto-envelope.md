# ClipMesh cryptographic envelope v1

All strings are UTF-8. Integers are unsigned big-endian unless stated otherwise. UUIDs are their 16 raw RFC 9562 bytes. Fixed labels include the shown trailing NUL byte. Non-empty password bytes are exact UTF-8 with no Unicode normalization. An empty password is encoded as the single reserved byte `0xff`, which cannot collide with valid UTF-8 password input.

## Password derivation and secret wrapping

Argon2id produces a 32-byte password master key using the parameters stored on the channel. HKDF-SHA-256 uses an empty salt and these exact info strings:

- `clipboard-sync/channel-wrap-key/v1`
- `clipboard-sync/channel-password-check-key/v1`

The channel-secret plaintext is canonical CBOR with integer keys:

```text
1 => secret bundle version (1)
2 => 32-byte channel root key
3 => membership P-256 private key in PKCS#8 DER
4 => 32-byte HMAC-SHA-256 password check over `"clipboard-sync/password-check/v1\0" || channel_id`, keyed by `channel-password-check-key`
```

It is encrypted with AES-256-GCM and a fresh 12-byte nonce. Its AAD is:

```text
"clipboard-sync/channel-wrap-aad/v1\0"
|| protocol_version:u16
|| channel_id:uuid
|| kdf_name_length:u8 || kdf_name
|| memory_kib:u32 || iterations:u32 || parallelism:u32 || output_bytes:u16
|| salt_length:u16 || salt
|| membership_spki_length:u16 || membership_spki
```

## Membership proof

ECDSA P-256/SHA-256 signs the following byte sequence. Signatures on the wire use the 64-byte IEEE-P1363 `r || s` encoding.

```text
"clipboard-sync/channel-join/v1\0"
|| server_instance_id:uuid
|| channel_id:uuid
|| device_id:uuid
|| challenge_id:uuid
|| challenge_random:bytes[32]
|| expires_at_unix_seconds:i64
```

Challenges expire after 60 seconds and are atomically consumed on the first proof attempt, whether verification succeeds or fails.

## Clipboard payloads

The channel item root is HKDF-SHA-256 over the channel root key, empty salt, and info `clipboard-sync/channel-item-root/v1`.

The independently domain-separated channel history root is HKDF-SHA-256 over the same channel root key, empty salt, and info `clipboard-sync/channel-history-root/v1`. Version 1 local history retains the original authenticated item envelope, so this root is reserved for future history-specific envelopes and is never substituted for an item key.

Each 32-byte item key is HKDF-SHA-256 with:

- input key material: channel item root
- salt: channel UUID bytes
- info: `clipboard-sync/item-key/v1\0` followed by item UUID bytes

Text plaintext:

```text
version:u16 (=1) || type:u8 (=1) || byte_length:u32 || exact UTF-8 bytes
```

PNG plaintext:

```text
version:u16 (=1) || type:u8 (=2) || width:u32 || height:u32 || byte_length:u32 || PNG bytes
```

File-manifest plaintext (`application/vnd.clipmesh.file`):

```text
version:u16 (=1) || type:u8 (=3)
|| file_id:uuid
|| filename_length:u16 || filename UTF-8
|| media_type_length:u16 || media_type ASCII
|| plaintext_file_size:u64
|| chunk_size:u32 (=4194304) || chunk_count:u32
|| nonce_prefix:bytes[8] || plaintext_sha256:bytes[32]
|| expires_at_unix_seconds:i64
```

The manifest contains no file body. The sender uploads every encrypted file chunk and finalizes the server object before publishing this manifest. WebSocket events continue to carry outer item metadata only; receivers fetch the small manifest envelope, and fetch file chunks only after an explicit download.

The AES-256-GCM AAD is:

```text
"clipboard-sync/item-aad/v1\0"
|| protocol_version:u16
|| server_instance_id:uuid
|| channel_id:uuid
|| item_id:uuid
|| origin_device_id:uuid
|| content_type:u8 (1=text/plain, 2=image/png, 3=application/vnd.clipmesh.file)
|| created_at_length:u16 || created_at_client UTF-8
```

The nonce is 12 fresh random bytes. A receiver authenticates the envelope before parsing, then compares the authenticated inner type, sizes, and image dimensions with the outer metadata.

## File chunks

The channel file root is HKDF-SHA-256 over the channel root key, empty salt, and info `clipboard-sync/channel-file-root/v1`. Each 32-byte file key is HKDF-SHA-256 with the channel UUID as salt and info `clipboard-sync/file-key/v1\0` followed by the file UUID.

Each file uses a fresh eight-byte random nonce prefix. Chunk `i` uses the 12-byte AES-256-GCM nonce `nonce_prefix || i:u32`. Because each file UUID derives a distinct key, the per-file counter cannot repeat a nonce under one key. The final chunk may be shorter than 4 MiB; an empty file has one zero-byte plaintext chunk and therefore a 16-byte ciphertext chunk.

Chunk AAD is:

```text
"clipboard-sync/file-chunk-aad/v1\0"
|| protocol_version:u16
|| server_instance_id:uuid
|| channel_id:uuid
|| file_id:uuid
|| chunk_index:u32
|| plaintext_file_size:u64
|| chunk_size:u32
```

Clients authenticate every chunk and verify the completed plaintext SHA-256 value from the encrypted manifest before accepting the download.
