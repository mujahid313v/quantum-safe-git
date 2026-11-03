# Architecture

**Status: design document. Experimental. No audit. Not for production use.** Almost nothing described here is implemented.

## Idea

Git can delegate commit and tag signing to an external program (`gpg.format ssh` plus `gpg.ssh.program`). QSGit supplies such a program. It produces and checks ML-DSA-65 signatures wrapped in an SSH-signature-style container. Git does not inspect the signature blob; it trusts the program's output (see [GIT-INTERFACE.md](GIT-INTERFACE.md)).

## Components

| Component | Role |
|-----------|------|
| `qsg-core` | ML-DSA-65 key generation, sign, verify. No file or network I/O. |
| `qsg-sshsig` | Encode and decode the signature container ([SPEC.md](SPEC.md)). |
| `qsg-keystore` | Key generation and encrypted private-key storage under `~/.config/qsgit/`. |
| `qsg-trust` | Parse `allowed_signers`, validity windows, revocation list. |
| `qsg-cli` (binary `qsg`) | User commands. |
| `qsg-ssh-keygen` | Implements only the `-Y` calls Git makes. Links `qsg-core` directly; it does not run `qsg`. |

Crypto backend: TBD (ADR 0001): either the `oqs` crate on liboqs, or a pure-Rust ML-DSA implementation.

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

`qsg verify-range <base>..<head> --allowed-signers <file>` (planned) checks many commits for CI use.

## Planned or out of scope for v0.1

This is the single list; other documents link here.

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

v0.1 targets Linux and macOS with Git 2.34 or newer. The spike ran on Windows only so far.

## SHA-256 repositories

QSGit signs the buffer Git hands over, so it does not depend on the object hash. The spike saw identical calls for sha1 and sha256 repositories. An end-to-end test with a sha256 repository is part of v0.1 (M6).
