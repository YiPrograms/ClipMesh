# ClipMesh test matrix

Automated gates:

```sh
cargo fmt --all -- --check
cargo test --workspace
cd extension
npm ci
npm run check
npm test
npm run build
```

The automated suites cover routing-state invariants, an independently generated Argon2id v1.3 known-answer vector, channel wrap failure with a wrong password, HKDF domain separation, AES-GCM item/file authentication and metadata binding, history count/age/byte pruning and indexed usage accounting, latest-only outbox replacement, pairing, membership challenge replay and expiry, member/non-member authorization, item and file limits, file quota/finalization/download/deletion, idempotency, sole-member deletion, revoked credentials, WebSocket ticket/heartbeat behavior, extension distribution metadata, security headers, and persistence across a server rebuild/reopen.

Before publishing native archives, run the same bidirectional text/PNG, offline newest-only, pause, routing, history, sleep/resume, and credential-revocation scenarios with `clipmesh` on Windows x64, Linux x64, Intel macOS, and Apple Silicon macOS. Verify foreground TUI ownership first, then stop the TUI and repeat with the installed background service. Also verify an unavailable Linux Secret Service fails closed and that pure Wayland compositors without the data-control protocol show a clipboard error instead of silently weakening storage or transport security.

Before a release, load `extension/dist` into current stable Chrome on Windows, Linux, and macOS. Use at least two distinct Chrome profiles and execute this matrix:

1. Pair both profiles; set distinguishable device names.
2. Create and join a channel, first with a wrong password and then the correct one.
3. Send multiline text in both directions and verify exact bytes and no echo entry.
4. Send a PNG in both directions; verify dimensions and clipboard paste into a native image application.
5. Add two more channels and verify multi-channel Send-only and Receive-only routing.
6. Disconnect the server, copy three different items, reconnect, and verify only the newest is sent.
7. Disconnect a receiver while publishing three items, reconnect, and verify only each channel's latest item is applied in server acceptance order.
8. Exercise sleep/resume and extension service-worker termination from `chrome://serviceworker-internals`.
9. Exercise history copy, resend, delete, filters, retention limits, locked entries after leave, and rejoin unlock.
10. Verify pause timers retain selections and retrieve latest receive state on resume.
11. Attempt oversized text, oversized/malformed PNG, replayed challenge, non-member content fetch, non-sole deletion, and revoked-device reconnect.
12. Restart the server and confirm memberships and current ciphertext remain usable.
13. Upload and download empty, one-byte, multi-chunk, Unicode-named, and near-limit files; compare SHA-256 hashes on both ends.
14. Verify a receiving browser does not fetch file chunks until Download is selected, expired files show a clear error, and quota exhaustion does not evict an unexpired file.

Inspect server logs and SQLite/blob backups during the matrix. Search for known unique clipboard and password test markers; neither marker may occur outside encrypted client memory or decrypted clipboard operations.

Browser clipboard behavior differs by Chrome and OS release. This matrix is a release gate, not a substitute for automated tests.
