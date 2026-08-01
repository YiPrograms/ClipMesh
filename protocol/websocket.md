# ClipMesh WebSocket protocol v1

Obtain a single-use 30-second ticket with `POST /api/v1/ws-ticket`, then connect to `/api/v1/sync?ticket=...`. The socket accepts and emits JSON. Unknown message types or invalid fields produce an `error` response and never alter subscriptions.

Clients send `hello`, `routing_update`, `ack`, and `ping` messages as described by the product specification. A subscription is accepted only for joined channels. On `hello` or `routing_update`, the server returns each subscribed channel's current item when its sequence is newer than the supplied last sequence. Replayed current items are sorted by server acceptance time.

The server sends `item_created`, `channel_updated`, `channel_deleted`, `membership_changed`, `device_updated`, `resync_required`, `pong`, and `error` messages. Connected clients should send a ping at least once every 25 seconds and reconnect with exponential backoff and jitter.
