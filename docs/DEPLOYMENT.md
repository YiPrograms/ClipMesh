# Deploying ClipMesh

ClipMesh must be exposed over HTTPS/WSS except during loopback development. The server trusts no forwarding headers, so a reverse proxy cannot spoof client identity through headers. WebSocket upgrades must be forwarded without rewriting `/api/v1/sync`.

## Container deployment

ClipMesh publishes a public multi-platform server image for Linux x86-64 and ARM64 at `ghcr.io/yiprograms/clipmesh`. No registry login is required. `latest` follows the latest successful build from `main`. Every build also publishes an immutable `sha-SHORT_COMMIT` tag, and tag-triggered builds publish semantic version tags.

For a local loopback-only evaluation without cloning the repository, download the minimal server Compose example:

```sh
curl -fsSLO https://raw.githubusercontent.com/YiPrograms/ClipMesh/main/deploy/compose.local.yaml
docker compose -f compose.local.yaml up -d
curl --fail http://127.0.0.1:8787/api/v1/health
```

The server is then available at <http://127.0.0.1:8787>. Its SQLite database and encrypted file blobs persist in the `clipmesh-data` volume. Stop and remove the container while retaining that volume with:

```sh
docker compose -f compose.local.yaml down
```

Do not expose the local example on a non-loopback interface; browser and native clients require HTTPS outside loopback development.

For a public deployment, download `deploy/compose.yaml` and `deploy/clipmesh.env.example`, then set `CLIPMESH_DOMAIN`, the matching HTTPS `CLIPMESH_PUBLIC_URL`, and at least one browser-extension distribution URL. `CLIPMESH_CHROME_STORE_URL` must be an exact Chrome Web Store listing; `CLIPMESH_EXTENSION_DOWNLOAD_URL` must be a direct HTTPS ZIP URL. Setting both offers both choices:

```sh
curl -fsSLO https://raw.githubusercontent.com/YiPrograms/ClipMesh/main/deploy/compose.yaml
curl -fsSL https://raw.githubusercontent.com/YiPrograms/ClipMesh/main/deploy/clipmesh.env.example -o .env
# Edit .env before continuing.
docker compose --env-file .env -f compose.yaml config
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml logs -f clipmesh
```

Check the running deployment and stop it without deleting its volumes with:

```sh
curl --fail https://clipmesh.example.com/api/v1/health
docker compose --env-file .env -f compose.yaml down
```

Set `CLIPMESH_IMAGE=ghcr.io/yiprograms/clipmesh:sha-07d4883` in `.env` to pin the currently published image; use a semantic version tag for future releases. Upgrades then require only a backup followed by `docker compose pull` and `docker compose up -d`. To build the current checkout instead, combine either base file with the source-build override:

```sh
docker compose -f deploy/compose.local.yaml -f deploy/compose.build.yaml up --build
```

The production Compose example includes Caddy for automatic certificates. If Traefik already terminates TLS, run only the ClipMesh service on a private Docker network and preserve the same container environment and `/var/lib/clipmesh` volume. Apply OIDC only to the onboarding and pairing-code creation routes; device registration and the device-token API must remain reachable by native and extension clients.

Keep the `clipmesh-data` volume private and backed up. A backup may reveal device names, channel names, memberships, password KDF data, wrapped channel secrets, and ciphertext, but should never contain a channel password or clipboard plaintext. Do not run `docker compose down --volumes` unless permanent deletion of the server database and encrypted files is intended.

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

## Browser extension downloads

Tagged releases publish `clipmesh-extension-vVERSION.zip` together with the native archives and a shared `SHA256SUMS`. To advertise manual installation on the onboarding page:

```sh
CLIPMESH_EXTENSION_DOWNLOAD_URL=https://github.com/YiPrograms/ClipMesh/releases/download/v0.3.1/clipmesh-extension-v0.3.1.zip
```

The server derives the adjacent `SHA256SUMS` link from this URL. The onboarding page explains that users must extract the ZIP into a permanent folder, enable Developer mode at `chrome://extensions`, select **Load unpacked**, and update the same folder in place. This distribution path is manual and does not provide Chrome Web Store signing or automatic updates.

For normal installation and automatic browser updates, additionally configure the approved listing:

```sh
CLIPMESH_CHROME_STORE_URL=https://chromewebstore.google.com/detail/clipmesh/EXTENSION_ID
```

## Native client downloads

The onboarding page shows Windows, macOS, and Linux cards. To turn those cards into links, set both variables below; omit both to leave native downloads unavailable without affecting existing deployments:

```sh
CLIPMESH_CLIENT_RELEASE_BASE_URL=https://github.com/YiPrograms/ClipMesh/releases/download/v0.3.1/
CLIPMESH_CLIENT_VERSION=0.3.1
```

The base URL is the directory containing the three portable archives and `SHA256SUMS`. It must use HTTPS outside loopback development. ClipMesh constructs deterministic asset names:

- `clipmesh-client-v0.3.1-windows-x86_64.zip`
- `clipmesh-client-v0.3.1-linux-x86_64.tar.gz`
- `clipmesh-client-v0.3.1-macos-universal.tar.gz`

The tag-triggered release workflow builds these archives, publishes checksums, and records GitHub artifact attestations. The initial native release is unsigned, so the download page directs users to verify `SHA256SUMS`; production distributors may add platform signing without changing filenames.
