# ClipMesh privacy and security notes

The server sees device and channel names and IDs, membership relationships, online state, item type, image dimensions, ciphertext sizes, file sizes, retention timestamps, and timing. It stores password salts, Argon2id parameters, password-wrapped channel secret bundles, public membership keys, the latest ciphertext per channel, a bounded short-lived delivery cache, and retained encrypted file chunks. Filenames, file media types, and plaintext hashes are inside encrypted manifests and are not visible to the server.

The server does not receive channel passwords, password-derived keys, channel root keys, membership private keys, or clipboard plaintext. A stolen database permits offline password guessing against wrapped channel secrets, so generated unique passphrases remain essential.

Each browser client stores channel keys and its opaque server token in `chrome.storage.local`, never Chrome sync storage. Local history and the latest offline outbox live in IndexedDB. History records contain encrypted envelopes and metadata, not persistent plaintext previews or file bodies. File chunks are decrypted only during an explicit download and streamed to a user-selected destination when supported.

The native client stores device tokens, signing keys, channel secrets, and its local outbox key in the operating system credential store. Its SQLite history contains authenticated channel ciphertext and visible metadata. It does not fall back to plaintext secret storage when the credential store is unavailable.

End-to-end encryption does not protect a compromised endpoint, unlocked browser profile, weak/reused password, traffic metadata, denial of service, or a current/former member who retains the shared channel password and key.
