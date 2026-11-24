# Changelog

## v0.1.0-rc.1

**Status: release candidate (pre-release); experimental; not independently audited; not for production use.** This is a source-only pre-release. Crate versions remain 0.1.0. Linux and macOS binaries are planned for a later release.

### Included milestones

- M0: Git SSH-signing interface investigation and recorded call behavior.
- M1-M2: ML-DSA-65 signing and verification, the SSHSIG-style container, and test vectors.
- M3-M4: encrypted key storage, allowed-signers parsing, validity windows, and fingerprint revocation.
- M5a-M5b: key and public-key commands, the Git shim, trust management, object and range verification, and `qsg doctor`.
- M6: end-to-end tests, SHA-256 repository coverage, supply-chain checks, and CI hardening.
- M6.1: the `time` advisory fix and Git-version doctor guidance.
- M7: release, security, trust, Git-interface, and third-party license documentation.

### Tested Git versions

Passing evidence is recorded for Git 2.39.5, 2.43.0, 2.55.0, 2.56.0, and 2.56.1. Git 2.34.1 fails because it does not pass `-Overify-time` to `find-principals`; the shim fails closed. Other versions without passing runtime evidence are untested. See [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md).

### Security and limitations

QSGit and its selected RustCrypto `ml-dsa` backend are not independently audited; `ml-dsa` is pre-1.0. Revocation has no effective date, principals are not bound to commit identities, the shim rejects `-r` and `check-novalidate`, Windows key permissions are not enforced, and Argon2 working memory is not wiped when freed. The custom key type is not recognized by stock OpenSSH or GitHub's "Verified" badge. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).

The `time` advisory RUSTSEC-2026-0009 is addressed by `time` 0.3.47. `Cargo.lock` still contains the reported `rsa` 0.9.10 advisory RUSTSEC-2023-0071 and `crypto-bigint` 0.5.5 advisory RUSTSEC-2026-0387; see [SECURITY.md](SECURITY.md).

A manual 60-second smoke run per target (not a fuzz campaign) completed `sshsig decode_blob` with 9,847,145 executions and `trust allowed_signers` with 1,226,798 executions on 2026-11-22. The supplied log shows both targets completing in 61 seconds without a reported crash or error. These bounded runs are not a security audit.
