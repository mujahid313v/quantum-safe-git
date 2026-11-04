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
| Malicious change to `allowed_signers` | e.g. inside a pull request | CI reads it from the base branch or pipeline config |
| Backdated commits | Signer controls the commit time | Documented; trusted timestamping is future work |
| Revocation delay or coarse revocation | See trust model | Documented limitation |
| Unsigned commits | Nothing forces signing | `qsg verify-range` plus branch protection |
| Force-push or history rewrite | `verify-range` does not detect it | Branch protection and server-side rules |
| Parser bugs | SSHSIG container parser reads untrusted input; `allowed_signers` parsing is future work | Strict parsing, fuzzing |
| Supply chain | liboqs or crates compromised; tampered release binaries | Pinned versions, cargo-audit and cargo-deny, signed checksums |
| Wrong identity | Principal not tied to commit author | Documented limitation |

## Mitigations currently implemented

- `qsg-sshsig` rejects unsupported SSHSIG versions, namespaces, reserved/hash fields, key types, malformed lengths, trailing bytes, and oversized input. Property tests exercise arbitrary decoder input; a cargo-fuzz target is available, but no fuzz campaign has been run.
- `qsg-keystore` encrypts the ML-DSA seed, bounds Argon2 parameters, authenticates its header, and enforces private Unix modes; this implementation has not been audited.
