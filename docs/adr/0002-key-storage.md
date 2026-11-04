# ADR 0002: encrypted seed storage

**Status: accepted for M3. Experimental; not audited.**

## Decision

Store the 32-byte ML-DSA-65 seed rather than the 4032-byte expanded secret key. `qsg-core` reconstructs the signing key from the seed. Encrypt it with Argon2id v1.3 and XChaCha20-Poly1305. Pin `argon2 = 0.6.0` and `chacha20poly1305 = 0.11.0`; both are RustCrypto crates and neither exact selected version has been independently audited. An earlier RustCrypto ChaCha20/Poly1305 implementation received a NCC Group review, which is not an audit of these exact releases.

The normal parameters are memory 19456 KiB, iterations 2, lanes 1. These are the current OWASP Password Storage Cheat Sheet Argon2id minimum values, checked 2026-11-04: [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). Values are stored in the header. A loader bounds parameters before allocating KDF memory: 19456..=131072 KiB, 2..=6 iterations, and 1..=4 lanes. The format, including byte offsets and the explicit passphrase-less mode, is in [KEY-FORMAT.md](../KEY-FORMAT.md).

XChaCha20-Poly1305 is selected for its 192-bit nonce, which gives comfortable headroom for random nonces, and a single authenticated-encryption construction. The OS CSPRNG supplies 16-byte salts and 24-byte nonces. The complete fixed header is AEAD associated data. `none` KDF id uses a zero key, requires an explicit API flag, and returns an unencrypted-kind marker; it is not confidential or resistant to a malicious file writer.

## Filesystem and secret handling

Unix directories use mode 0700 and private files mode 0600; unsafe existing permissions are rejected with a corrective `chmod` command. A same-directory temporary file is created with exclusive creation and private mode, synced, then atomically published. Existing keys require explicit overwrite. Private-key symlinks are rejected. Windows uses `%APPDATA%\qsgit` (best-effort fallback under the user profile); Unix mode enforcement is unavailable there.

Passphrase, seed, derived key, and decrypted buffers are zeroized. The CLI will collect passphrases in M5; M3 accepts them only as library parameters. Passphrase-less creation is an explicit option.

## Consequences

- The file format is versioned and rejects unknown algorithms, KDFs, AEADs, malformed sizes, and excessive KDF work.
- Wrong passphrase and authentication failure share one error.
- Storage remains experimental, unaudited, and unsuitable for production until reviewed.
