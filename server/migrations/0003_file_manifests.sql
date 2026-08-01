CREATE TABLE file_manifests (
  file_id TEXT PRIMARY KEY REFERENCES file_objects(file_id) ON DELETE CASCADE,
  item_id TEXT NOT NULL UNIQUE,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  origin_device_id TEXT NOT NULL REFERENCES devices(id),
  channel_sequence INTEGER NOT NULL,
  crypto_version INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  ciphertext_size INTEGER NOT NULL,
  plaintext_size INTEGER,
  nonce BLOB NOT NULL,
  created_at_client TEXT,
  accepted_at_server TEXT NOT NULL,
  blob_key TEXT NOT NULL
);

CREATE INDEX file_manifests_channel_sequence ON file_manifests(channel_id, channel_sequence);
