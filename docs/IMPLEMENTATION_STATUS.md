# ClipMesh v0.3 implementation status

The repository includes these source deliverables:

- Rust/Axum server with SQLite WAL metadata, filesystem ciphertext blobs, pairing, opaque device credentials, channel membership proofs, authorization, bounded current/delivery retention, configurable chunked file retention and quotas, WebSocket replay, cleanup, and onboarding with Web Store or checksummed manual extension downloads.
- Chrome Manifest V3 extension with locally bundled Argon2id WebAssembly, versioned AES-GCM envelopes, P-256 membership proofs, exact routing-state enforcement, offscreen clipboard monitoring, text/PNG normalization, on-demand file upload/download, echo suppression, latest-only outbox, and encrypted client-local history.
- Native Rust client with a foreground-by-default TUI, the same protocol and routing rules, OS credential-store secrets, text/PNG clipboard monitoring, streaming path/stdin file transfer, encrypted SQLite history/outbox, administrative commands, and opt-in user-service management.
- Frozen cryptographic and WebSocket encodings plus an OpenAPI 3.1 contract and shared Rust/TypeScript vectors.
- Container, Compose/Caddy, systemd, privacy, testing, deployment, and unlisted Chrome Web Store release documentation.

Automated release gates cover protocol vectors, Argon2id, domain separation, wrong-password rejection, envelope and file-chunk authentication, routing transitions, history retention and usage accounting, latest-only outbox behavior, pairing, challenge replay/expiry, authorization, item/file limits and quotas, file finalization and deletion, channel lifecycle, credential revocation, WebSocket ticket/heartbeat behavior, persistence, onboarding headers, static analysis, production extension bundling, and the production container build.

The following are release-environment gates rather than missing source implementation:

1. Run the manual Chrome/OS matrix in `docs/TESTING.md` on current Windows, Linux, and macOS Chrome releases. Clipboard API behavior is platform-dependent and cannot be established by Node or server tests.
2. Publish the built extension through a developer-owned Chrome Web Store account with unlisted visibility.
3. Build and manually verify the portable native archives on every target OS, then publish them with `SHA256SUMS` and attestations.
4. Put the extension listing and native release URLs in server configuration, deploy behind a real HTTPS certificate, and verify install/download behavior from the onboarding page.

Do not call a deployment production-ready until those four gates pass.
