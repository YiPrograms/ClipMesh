# ClipMesh

ClipMesh is a self-hosted, end-to-end encrypted clipboard and file-transfer mesh. It pairs a Chrome Manifest V3 extension or native Rust client with a Rust/SQLite server and synchronizes plain text, PNG images, and encrypted files through password-protected channels.

Canonical repository: <https://github.com/YiPrograms/ClipMesh>

## Development

Requirements: Rust 1.85 or newer, Node.js 20 or newer, and npm.

```sh
cargo test --workspace
cd extension
npm install
npm test
npm run build
```

Run the server with:

```sh
CLIPMESH_PUBLIC_URL=http://127.0.0.1:8787 cargo run -p clipmesh-server
```

The development server listens on `127.0.0.1:8787` and stores state under `server/data`. TLS is mandatory for non-loopback deployments; terminate TLS at a trusted reverse proxy or configure the server deployment accordingly.

Open <http://127.0.0.1:8787> for onboarding. To load the extension during development, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `extension/dist`. Create a pairing code on the onboarding page, open the extension popup while that tab is active, confirm the origin permission, and pair the device.

Tagged GitHub releases also contain `clipmesh-extension-vVERSION.zip` and `SHA256SUMS`. A server configured with `CLIPMESH_EXTENSION_DOWNLOAD_URL` presents that archive with accurate manual installation and update instructions. Chrome requires users to extract the ZIP and load the folder through Developer mode; a ZIP is not a one-click extension installer.

## Docker Compose

Run a loopback-only server for local evaluation:

```sh
docker compose -f deploy/compose.local.yaml up --build
```

Open <http://127.0.0.1:8787>, or check it from another terminal:

```sh
curl --fail http://127.0.0.1:8787/api/v1/health
```

State is retained in the `clipmesh-data` volume. Stop the containers with `Ctrl+C`; remove them without deleting data with:

```sh
docker compose -f deploy/compose.local.yaml down
```

For an HTTPS deployment with automatic certificates, copy and edit the environment example before starting the included Caddy stack:

```sh
cp deploy/clipmesh.env.example .env
# Set the domain, public URL, and at least one extension distribution URL.
docker compose --env-file .env -f deploy/compose.yaml up -d --build
docker compose --env-file .env -f deploy/compose.yaml logs -f clipmesh
```

The `.env` file is ignored by Git. See the [deployment guide](docs/DEPLOYMENT.md) for backups, upgrades, quotas, and using an existing reverse proxy.

## Native client

Build and launch the native client with:

```sh
cargo run -p clipmesh-client
```

Running `clipmesh` with no arguments starts the foreground TUI and owns clipboard synchronization for that session. Pair from the TUI with `p`, or use the scriptable command:

```sh
clipmesh pair --server https://clipmesh.example.com --name "Workstation"
clipmesh channel list
clipmesh channel create --name Personal
clipmesh route CHANNEL_ID --send=true --receive=true
clipmesh send-file ./report.pdf
tar cz ./project | clipmesh send-file --filename project.tar.gz --media-type application/gzip
```

Background sync is opt-in and uses the current user's native service manager:

```sh
clipmesh service install
clipmesh service start
clipmesh service status
clipmesh service stop
```

Stop the service before opening the foreground TUI. Device tokens, signing keys, channel secrets, and the local outbox key are stored in Windows Credential Manager, macOS Keychain, or Linux Secret Service. Linux clipboard support uses Wayland's data-control protocol when available and X11/XWayland otherwise.

Files are encrypted locally in independently authenticated 4 MiB chunks, uploaded to the server, and announced only after finalization. Receiving devices get a small encrypted manifest and download file content only when requested. Use the browser Download button or:

```sh
clipmesh history list
clipmesh history export LOCAL_ID --output ~/Downloads/
```

The server defaults to a 2 GiB maximum file, seven-day retention, 50 GiB instance quota, and 10 GiB per-channel quota. All are configurable; quota exhaustion rejects new files rather than deleting unexpired transfers.

## Repository map

- `server/`: Axum API, WebSocket relay, SQLite migrations, embedded onboarding assets, and encrypted clipboard/file retention.
- `client/`: Rust foreground TUI, headless sync engine, CLI administration, native clipboard adapters, local encrypted history, and user-service installers.
- `crates/clipmesh-protocol/`: Shared protocol v1 crypto, wire DTOs, clipboard encodings, and routing invariants.
- `extension/`: Chrome MV3 extension with browser adapters, offscreen clipboard access, Argon2id/AES-GCM protocol, routing, local outbox/history, popup, and full page.
- `protocol/`: Frozen binary encodings, WebSocket behavior, and OpenAPI 3.1 contract.
- `deploy/`: Container, Compose/Caddy, and systemd deployment examples.
- `docs/`: Operations, testing, privacy, and release guidance.

No channel password, channel root key, membership private key, device token, pairing code, WebSocket ticket, clipboard plaintext, filename, or file media type is intentionally logged. Local history stores authenticated ciphertext; previews and files are decrypted only when requested.

See [implementation status](docs/IMPLEMENTATION_STATUS.md), [deployment](docs/DEPLOYMENT.md), [testing](docs/TESTING.md), [security reporting](SECURITY.md), and [Chrome Web Store release](docs/CHROME_WEB_STORE.md) for verification and release workflows.

## License

ClipMesh is available under the [MIT License](LICENSE).
