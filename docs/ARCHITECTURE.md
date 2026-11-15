# Architecture

**Status: M0-M5b are merged and implemented. M6 is implemented in PR #78 and pending merge; M7-M8 remain planned. Experimental, unaudited, and not for production use.**

## Idea

Git can delegate commit and tag signing to an external program (`gpg.format ssh` plus `gpg.ssh.program`). QSGit supplies such a program. It produces and checks ML-DSA-65 signatures wrapped in an SSH-signature-style container. Git does not inspect the signature blob; it trusts the program's output (see [GIT-INTERFACE.md](GIT-INTERFACE.md)).

## Components

| Component | Role |
|-----------|------|
| `qsg-core` | Implemented ML-DSA-65 key generation, sign, verify. No file or network I/O. |
| `qsg-sshsig` | Implemented strict signature-container encoding and decoding ([SPEC.md](SPEC.md)). |
| `qsg-keystore` | Implemented key generation and encrypted private-key storage. |
| `qsg-trust` | Implemented `allowed_signers`, validity-window, and revocation parsing/helpers. |
| `qsg-cli` (binary `qsg`) | Implements `keygen`, `pubkey`, `verify`, `verify-range`, `trust add/list/revoke`, and read-only `doctor`; object payload extraction follows Git's commit/tag parsing rules. |
| `qsg-verify` | Shared trust, validity, revocation, and cryptographic verification used by both the shim and standalone CLI. |
| `qsg-ssh-keygen` | Implements Git's `-Y sign`, `find-principals`, and `verify` calls; only the shim prints Git's successful `Good "git" signature ...` line. |

Crypto backend: RustCrypto `ml-dsa` 0.1.2, selected in [ADR 0001](adr/0001-crypto-backend.md); it has not been independently audited.

## Flows

Signing (calls verified by the M0 spike):

1. `git commit -S` writes the commit text (without signature) to a temp file.
2. Git runs `qsg-ssh-keygen -Y sign -n git -f <user.signingkey value> <temp file>`.
3. The program signs, writes `<temp file>.sig`, and exits 0.
4. Git stores the armored signature in the commit's `gpgsig` header.

Verification:

1. Git runs `-Y find-principals -f <allowed_signers> -s <sig file> -Overify-time=...`; the program prints the matching principal.
2. Git runs `-Y verify -n git -f <allowed_signers> -I <principal> -s <sig file> -Overify-time=...` with the signed text on stdin.
3. The program checks the signature and prints `Good "git" signature for <principal> with <KEYTYPE> key <fingerprint>`, exit 0. On failure it exits non-zero.

The same flows serve tags. Nothing needs a network or a service.

`qsg verify-range <base>..<head> --allowed-signers <file>` checks the Git revision range in reverse order, including merge commits. It uses the same shared verification checks as the shim. Its trust-file safeguard compares the actual file bytes to the base blob for repository-tracked paths; outside/untracked files still require a trusted pipeline source.

## Planned or out of scope for v0.1

M6 is implemented in PR #78 and pending merge. M7 is the documentation and security pass; M8 is the v0.1.0 release candidate. The following product capabilities remain out of scope for v0.1; other documents link here.

- gRPC or other signing service
- Desktop UI, IDE extensions
- Docker, Kubernetes, Helm
- Metrics and dashboards, centralised audit logging
- HSM, YubiKey, TPM, cloud KMS keys
- Hybrid signatures (Ed25519 + ML-DSA)
- Falcon / FN-DSA (TODO: verify NIST status)
- A reusable GitHub Action
- Transparency log or trusted timestamping
- ssh-agent support (`user.signingkey = key::...` makes Git pass `-U`)

Not goals at all: blockchain, machine-learning anomaly detection, mobile app, marketplace.

## Platforms

v0.1 targets Linux and macOS; Windows is supported for development and testing only, and private-key file permissions are not enforced there. Git 2.55.0 was tested on Windows and Git 2.56.0 on Ubuntu and macOS. Git 2.34.1 is known not to work because it does not pass `-Overify-time` to `find-principals`, so the shim fails closed. Source inspection shows Git 2.35.0 is the first checked release with `verify-time` in `gpg-interface.c`, but runtime compatibility of that release is not established. Versions 2.35.0 through 2.54.x are otherwise untested; see [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).

## SHA-256 repositories

QSGit signs the buffer Git hands over, so it does not depend on the object hash. The spike saw identical calls for sha1 and sha256 repositories. M6 adds end-to-end tests with SHA-256 repositories; those tests are implemented in PR #78, pending merge.
