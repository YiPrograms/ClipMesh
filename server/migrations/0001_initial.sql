PRAGMA foreign_keys = ON;

CREATE TABLE server_info (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  instance_id TEXT NOT NULL,
  instance_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  signing_public_key BLOB NOT NULL,
  browser_family TEXT NOT NULL,
  browser_version TEXT,
  os_family TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE device_tokens (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE pairing_codes (
  id TEXT PRIMARY KEY,
  code_hash BLOB NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE channels (
  id TEXT PRIMARY KEY,
  normalized_name TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  crypto_version INTEGER NOT NULL,
  password_kdf_json TEXT NOT NULL,
  wrapped_secret_json TEXT NOT NULL,
  membership_public_key_spki BLOB NOT NULL,
  created_by_device_id TEXT NOT NULL REFERENCES devices(id),
  created_at TEXT NOT NULL,
  current_sequence INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT
);

CREATE TABLE channel_memberships (
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  joined_at TEXT NOT NULL,
  last_delivered_sequence INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(channel_id, device_id)
);

CREATE TABLE channel_join_challenges (
  id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  challenge_random BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE current_channel_items (
  item_id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL UNIQUE REFERENCES channels(id) ON DELETE CASCADE,
  origin_device_id TEXT NOT NULL REFERENCES devices(id),
  channel_sequence INTEGER NOT NULL,
  crypto_version INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  ciphertext_size INTEGER NOT NULL,
  plaintext_size INTEGER,
  image_width INTEGER,
  image_height INTEGER,
  nonce BLOB NOT NULL,
  created_at_client TEXT,
  accepted_at_server TEXT NOT NULL,
  blob_key TEXT NOT NULL
);

CREATE TABLE delivery_cache_items (
  item_id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  origin_device_id TEXT NOT NULL REFERENCES devices(id),
  channel_sequence INTEGER NOT NULL,
  crypto_version INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  ciphertext_size INTEGER NOT NULL,
  plaintext_size INTEGER,
  image_width INTEGER,
  image_height INTEGER,
  nonce BLOB NOT NULL,
  created_at_client TEXT,
  accepted_at_server TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  blob_key TEXT NOT NULL
);

CREATE INDEX delivery_cache_channel_expiry ON delivery_cache_items(channel_id, expires_at);

CREATE TABLE ws_tickets (
  ticket_hash BLOB PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
