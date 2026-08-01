CREATE TABLE file_objects (
  file_id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  origin_device_id TEXT NOT NULL REFERENCES devices(id),
  plaintext_size INTEGER NOT NULL,
  ciphertext_size INTEGER NOT NULL DEFAULT 0,
  chunk_size INTEGER NOT NULL,
  chunk_count INTEGER NOT NULL,
  next_chunk INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('uploading', 'ready', 'expired', 'deleted')),
  created_at TEXT NOT NULL,
  completed_at TEXT,
  expires_at INTEGER NOT NULL,
  deleted_at INTEGER,
  blob_key TEXT NOT NULL
);

CREATE INDEX file_objects_channel_status ON file_objects(channel_id, status);
CREATE INDEX file_objects_expiry ON file_objects(status, expires_at);
