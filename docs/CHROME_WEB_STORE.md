# Chrome Web Store release

ClipMesh is designed for an **unlisted** Chrome Web Store item. Publishing the actual listing requires a Chrome Web Store developer account and is intentionally outside the source build.

Release procedure:

1. Run every automated and manual gate in `docs/TESTING.md`.
2. Set the extension version in `extension/package.json` and build with `npm ci && npm run build`.
3. Zip the contents of `extension/dist` (not the directory itself).
4. Upload the ZIP in the Chrome Web Store developer dashboard.
5. Select unlisted visibility. Do not claim silent installation or background operation while Chrome is closed.
6. Disclose clipboard read/write, local storage, offscreen processing, active-tab origin discovery, optional per-origin host access, and encrypted server transport.
7. Explain that channel keys live in extension-local storage and are not hardware-backed.
8. After review, copy the exact unlisted listing URL into `CLIPMESH_CHROME_STORE_URL` for each server deployment.
9. Verify the onboarding button opens that listing and installation preserves compatible local IndexedDB and `chrome.storage.local` data on update.

The extension bundles all executable JavaScript and its Argon2id WebAssembly module. The extension-page CSP permits local WebAssembly compilation but no remote scripts. It does not load remote code, request `<all_urls>`, inject scripts into webpages, or enable incognito operation.

## Manual ZIP releases

The tag-triggered GitHub workflow builds the same `extension/dist` content and publishes it as `clipmesh-extension-vVERSION.zip` with `SHA256SUMS` and a GitHub artifact attestation. The server automatically links to the official release matching its compiled version on the homepage.

Chrome does not install the ZIP directly. Users must extract it to a permanent folder, enable Developer mode at `chrome://extensions`, and use **Load unpacked**. Updates must replace the contents of that same folder before selecting **Reload**. Treat this as a technical/self-hosting distribution option; the Chrome Web Store remains the supported path for one-click installation and automatic updates.
