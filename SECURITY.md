# Security Policy

**QSGit is experimental; neither QSGit nor its selected pure-Rust `ml-dsa` backend has been independently audited. Do not use it to protect anything that matters.**

## Supported versions

Only the latest commit on `main`. There are no releases yet.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability").

TODO: enable private vulnerability reporting in the repository settings.
TODO: add a security contact address.
TODO: set response-time targets once there is someone to meet them.

Please do not open public issues for vulnerabilities.

## What is implemented

Implemented security-relevant functionality includes ML-DSA-65 key generation/sign/verify, SSHSIG encoding, encrypted key storage, allowed-signers validity and revocation checks, the Git signing shim, standalone verification, range verification, trust-file editing, and read-only diagnostics. These implementations are experimental and have not been independently audited; see the threat and trust models for implemented controls and limitations.

## Further reading

- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md)
