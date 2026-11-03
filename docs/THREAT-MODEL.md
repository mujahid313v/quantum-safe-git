# Threat model

**Status: design. Experimental. No audit.** No mitigation listed here is implemented yet.

| Threat | Notes | Planned response |
|--------|-------|------------------|
| Quantum attack on classical signatures | The reason for the project | ML-DSA-65 |
| Implementation bugs in crypto code | liboqs is not audited or FIPS-validated | Reviewed library, known-answer tests, fuzzing |
| Side channels | Depends on the backend | Prefer constant-time implementations; check backend claims |
| Algorithm downgrade | Verifier accepting a weaker or unknown algorithm | Compile-time allowlist, hard failure on unknown types |
| Stolen private key | From a laptop or backup | Encrypted key file; hardware keys are future work |
| Passphrase-less keys | Convenient but weak | Allowed only with `--no-passphrase` and a loud warning |
| Malware using an unlocked key | Can sign arbitrary commits | Out of scope; mention in docs |
| Malicious change to `allowed_signers` | e.g. inside a pull request | CI reads it from the base branch or pipeline config |
| Backdated commits | Signer controls the commit time | Documented; trusted timestamping is future work |
| Revocation delay or coarse revocation | See trust model | Documented limitation |
| Unsigned commits | Nothing forces signing | `qsg verify-range` plus branch protection |
| Force-push or history rewrite | `verify-range` does not detect it | Branch protection and server-side rules |
| Parser bugs | Container and `allowed_signers` parsers read untrusted input | Strict parsing, fuzzing |
| Supply chain | liboqs or crates compromised; tampered release binaries | Pinned versions, cargo-audit and cargo-deny, signed checksums |
| Wrong identity | Principal not tied to commit author | Documented limitation |

## Mitigations currently implemented

None.
