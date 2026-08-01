# Deploying ClipMesh

ClipMesh must be exposed over HTTPS/WSS except during loopback development. The server trusts no forwarding headers, so a reverse proxy cannot spoof client identity through headers. WebSocket upgrades must be forwarded without rewriting `/api/v1/sync`.

## Container deployment

Copy `deploy/clipmesh.env.example` to a private environment file, set a real HTTPS public URL and the exact unlisted Chrome Web Store URL, then run:

```sh
docker compose --env-file /path/to/clipmesh.env -f deploy/compose.yaml up -d --build
```

The Compose example includes Caddy for automatic certificates. Keep the `clipmesh-data` volume private and backed up. A backup may reveal device names, channel names, memberships, password KDF data, wrapped channel secrets, and ciphertext, but should never contain a channel password or clipboard plaintext.

## File retention and quotas

File content is stored as end-to-end encrypted ciphertext. Configure resource bounds with binary sizes (`B`, `KiB`, `MiB`, `GiB`, `TiB`) and durations (`s`, `m`, `h`, `d`):

```sh
CLIPMESH_MAX_FILE_BYTES=2GiB
CLIPMESH_FILE_RETENTION=7d
CLIPMESH_FILE_STORAGE_QUOTA=50GiB
CLIPMESH_FILE_CHANNEL_QUOTA=10GiB
CLIPMESH_INCOMPLETE_UPLOAD_RETENTION=1h
```

Completed retention begins when the final chunk is committed. Incomplete uploads expire separately. Expired ciphertext is deleted and leaves a lightweight 24-hour tombstone so clients receive `410 Gone`. Channel deletion removes its file objects immediately. When either quota is full, new uploads receive `507 Insufficient Storage`; the server does not silently evict an unexpired file.

## Native deployment

Build with `cargo build --release --locked`, install the binary and `deploy/systemd/clipmesh.service`, and place the environment file at `/etc/clipmesh/clipmesh.env`. Run the process as a dedicated user with write access only to its SQLite file and blob directory. Put Caddy, nginx, or another TLS reverse proxy in front of `127.0.0.1:8787`.

Back up the SQLite database and blob directory as one consistency unit. For SQLite's WAL mode, use SQLite's online backup mechanism or stop the service briefly before copying all database files. Restore the database and blobs to the same paths before restarting; the persistent server instance ID is required by envelope AAD and membership proofs.

## Upgrade checklist

1. Back up SQLite and blobs.
2. Build the new pinned source revision.
3. Stop the service, replace the binary, and start it.
4. Check `/api/v1/health` without authentication.
5. Confirm `server_version` and `protocol_version` from `/api/v1/info`.
6. Keep the prior binary and backup until a paired extension reconnects successfully.

Never enable a TLS-certificate bypass. Apply HSTS at the reverse proxy only after the domain and certificate lifecycle are stable.

## Native client downloads

The onboarding page shows Windows, macOS, and Linux cards. To turn those cards into links, set both variables below; omit both to leave native downloads unavailable without affecting existing deployments:

```sh
CLIPMESH_CLIENT_RELEASE_BASE_URL=https://github.com/owner/repository/releases/download/v0.3.0/
CLIPMESH_CLIENT_VERSION=0.3.0
```

The base URL is the directory containing the three portable archives and `SHA256SUMS`. It must use HTTPS outside loopback development. ClipMesh constructs deterministic asset names:

- `clipmesh-client-v0.3.0-windows-x86_64.zip`
- `clipmesh-client-v0.3.0-linux-x86_64.tar.gz`
- `clipmesh-client-v0.3.0-macos-universal.tar.gz`

The tag-triggered release workflow builds these archives, publishes checksums, and records GitHub artifact attestations. The initial native release is unsigned, so the download page directs users to verify `SHA256SUMS`; production distributors may add platform signing without changing filenames.
