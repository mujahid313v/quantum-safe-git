# Threat model

**Status: design. Experimental. No audit.** M3 key storage is implemented but has not been audited.

| Threat | Notes | Planned response |
|--------|-------|------------------|
| Quantum attack on classical signatures | The reason for the project | ML-DSA-65 |
| Implementation bugs in crypto code | Neither the chosen pure-Rust `ml-dsa` crate nor liboqs is independently audited; liboqs is also not FIPS-validated | Reviewed library, known-answer tests, fuzzing |
| Side channels | Depends on the backend | Prefer constant-time implementations; check backend claims |
| Algorithm downgrade | Verifier accepting a weaker or unknown algorithm | Compile-time allowlist, hard failure on unknown types |
| Stolen private key | From a laptop or backup | M3 encrypts the stored seed with a passphrase and enforces Unix file permissions; not audited. Hardware keys are future work |
| Passphrase-less keys | Convenient but weak | M3 permits this only through an explicit API flag and returns an unencrypted-kind marker; the file remains mode 0600 on Unix. This is not audited and provides no confidentiality |
| Argon2id working-memory disclosure | Freed Argon2id internal working memory is not wiped | Argon2id internal working memory is not wiped when freed (argon2 0.6.0, verified by source inspection). Passphrase, seed, derived key and decrypted buffers are zeroized. Memory disclosure (core dumps, swap, cold boot) may expose key-derivation intermediates. Not audited. |
| Malware using an unlocked key | Can sign arbitrary commits | Out of scope; mention in docs |
| Malicious change to `allowed_signers` | e.g. inside a pull request | M4 strictly parses supported entries, but CI must still read the trust file from the base branch or trusted pipeline configuration; not audited |
| Backdated commits | Signer controls the commit time | Documented; trusted timestamping is future work |
| Revocation delay or coarse revocation | A revoked key has no effective date; an old valid signature also fails | M4 rejects every signature by a listed fingerprint; revocation takes effect only where the updated list is used; not audited |
| Unsigned commits | Nothing forces signing | `qsg verify-range` plus branch protection |
| Force-push or history rewrite | `verify-range` does not detect it | Branch protection and server-side rules |
| Parser bugs | SSHSIG and `allowed_signers` parsers read untrusted input | Strict parsing, property tests, and a cargo-fuzz target; not audited |
| Supply chain | liboqs or crates compromised; tampered release binaries | Pinned versions, cargo-audit and cargo-deny, signed checksums |
| Wrong identity | Principal not tied to commit author | Documented limitation |
| Passphrase capture | A hostile process can observe terminal input or compromise the process | M5a prompts through the terminal without echo and never reads the passphrase from Git's stdin; prompt and shim code are not audited |
| Git shim/parser failures | Git supplies paths, signatures, verify-time values, and signed data | M5a strictly accepts only Git's observed `-Y` calls, caps signatures at 128 KiB, allowed_signers/revocation input at 1 MiB, and signing/verification messages at 16 MiB; code is not audited |
| Misconfigured Git revocation file | Git may pass `-r <file>` to the custom verifier | M5a rejects `-r` with exit 255, so verification fails closed. Do not set `gpg.ssh.revocationFile` with QSGit; use `QSG_REVOKED_KEYS` or sibling `revoked_keys`. Deliberate v0.1 limitation; support for a QSGit list via `-r` may be added later. |
| Allowed-signers file editor | Malicious principal/key/date input or interrupted replacement | M5b validates through `qsg-trust`, bounds inputs, preserves unrelated lines, rejects duplicates, and writes a same-directory synced temporary file before rename; not audited. |
| Trust-file substitution in verify-range | A change supplies its own trusted key file | M5b compares the bytes actually used against tracked base/head blobs and fails closed on a difference unless explicitly overridden; external/untracked files remain caller-controlled; not audited. |
| Argument injection through revision values | A revision begins with an option-like value | `qsg` rejects option-prefixed revisions before invoking Git; `revision_option_injection_is_usage_error` covers this behavior. |
| Altered annotated tags | A tag object or signature is changed after signing | `tampered_annotated_tag_fails_qsg_verification` checks altered tag message and signature armor, each against a successful unaltered baseline. |
| Unreviewed ML-DSA backend | Backend defects may affect every signature | RustCrypto `ml-dsa` 0.1.2 is pre-1.0 and has not had an independent audit; see [ADR 0001](adr/0001-crypto-backend.md). |
| Incomplete history or empty range in CI | A shallow clone or incorrect base can omit commits | M5b fails unresolved/missing objects closed and offers `--fail-on-empty`; root commits are not included when used as the exclusive range base; not audited. |

## Mitigations currently implemented

- `qsg-sshsig` rejects unsupported SSHSIG versions, namespaces, reserved/hash fields, key types, malformed lengths, trailing bytes, and oversized input. Property tests exercise arbitrary decoder input; cargo-fuzz targets are available. On 2026-11-22, a manual 60-second smoke run completed `sshsig decode_blob` with 9,847,145 executions and `trust allowed_signers` with 1,226,798 executions. The supplied log shows both targets completed in 61 seconds and contains no crash, panic, sanitizer, timeout, or `ERROR: libFuzzer` report. This was a smoke run, not a fuzz campaign or security audit.
- `qsg-keystore` encrypts the ML-DSA seed, bounds Argon2 parameters, authenticates its header, and enforces private Unix modes; this implementation has not been audited.
- `qsg-trust` enforces exact principals, required Git namespace, bounded parsing, validity windows, and fingerprint revocation; this implementation has not been audited.
- M5a `qsg-ssh-keygen` prompts for encrypted-key passphrases from the terminal, bounds verification input, rejects unsupported Git call shapes, and connects signature verification with trust checks; it has not been audited.
- M5b `qsg verify`, `verify-range`, `trust`, and `doctor` reuse the shared verification and trust parsers; the file editor and range trust-source safeguard have not been audited.

## Known limitations

- Revocations have no effective date: a revoked key also invalidates its older signatures.
- Trusted principals are not bound to commit author identities.
- The shim rejects Git's `-r` revocation-file option and `check-novalidate` fallback; verification fails closed in those paths.
- Unix key-file permissions are enforced; Windows key permissions are not enforced.
- Argon2id working memory is not wiped when freed; see the disclosure row above.
