# Key file format v1

**Status: experimental and not audited.** This is the M3 private-key file format. The file stores the 32-byte ML-DSA-65 seed, never the 4032-byte expanded key. It is reconstructed in memory by `qsg-core` when loaded.

## Private file

The complete file is exactly 107 bytes. All multi-byte integers are unsigned big-endian. The first 59 bytes are the header and are authenticated as AEAD associated data.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 6 | Magic | ASCII `QSGKEY` |
| 6 | 1 | Format version | `1` |
| 7 | 1 | Algorithm id | `1` = ML-DSA-65 |
| 8 | 1 | KDF id | `0` = none; `1` = Argon2id |
| 9 | 4 | Argon2 memory | KiB; zero for KDF none |
| 13 | 4 | Argon2 iterations | zero for KDF none |
| 17 | 1 | Argon2 lanes | zero for KDF none |
| 18 | 16 | Salt | Random OS CSPRNG bytes; retained for KDF none |
| 34 | 1 | AEAD id | `1` = XChaCha20-Poly1305 |
| 35 | 24 | Nonce | Random OS CSPRNG bytes |
| 59 | 32 | Ciphertext | Encrypted ML-DSA-65 seed |
| 91 | 16 | Authentication tag | XChaCha20-Poly1305 tag, appended to ciphertext by the AEAD |

Argon2id v1.3 defaults are memory `19456` KiB, iterations `2`, lanes `1`. The parameters are stored in the header. Loaders accept memory from 19456 through 131072 KiB, iterations from 2 through 6, and lanes from 1 through 4, also requiring memory >= 8 times the lane count. This bounds work before the KDF runs.

For KDF id `0`, all three KDF parameters must be zero and the encryption key is 32 zero bytes. This mode provides no confidentiality and is vulnerable to replacement by anyone who can modify the key file. It is available only through an explicit API acknowledgement; loading returns `KeyKind::Unencrypted` so callers can warn. The file is still mode 0600 on Unix.

Wrong passphrases and ciphertext/tag corruption return the same error. Unknown ids, unsupported versions, malformed lengths, and out-of-range KDF parameters have distinct errors. The header is authenticated in both modes; in the unencrypted mode the fixed key is public, so this does not provide protection against a file writer.

## Public file

The `.pub` file contains one LF-terminated OpenSSH-style line:

```text
ssh-mldsa65@qsgit <base64 public-key blob> [comment]
```

The blob uses the encoding from [docs/SPEC.md](SPEC.md): `string("ssh-mldsa65@qsgit") || string(1952-byte ML-DSA-65 public key)`. The comment is optional. Its fingerprint is produced by `qsg-sshsig` over that same blob.

## Filesystem handling

On Unix, the key directory must be exactly mode 0700 and private files exactly 0600. The library rejects looser permissions and reports the `chmod` command to correct them. Temporary files are created in the same directory with `create_new`, written and synced before atomic publication; an existing key is not replaced unless the caller explicitly requests overwrite. Unix reads use no-follow open semantics and reject private-key symlinks. On Windows, directory selection is best effort and these Unix permission guarantees are unavailable; the implementation checks for a symlink before opening but cannot provide Unix mode protections.

The default location is `$XDG_CONFIG_HOME/qsgit` when set on Unix, otherwise `~/.config/qsgit`. On Windows it is `%APPDATA%\qsgit`, with `%USERPROFILE%\AppData\Roaming\qsgit` as a fallback.

Windows: private-key file permissions are not enforced in v0.1.
