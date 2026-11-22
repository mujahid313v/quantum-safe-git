# QSGit

**Status: Experimental. No releases or independent security audit of QSGit or its selected pure-Rust `ml-dsa` backend. Not for production use.**

QSGit is an early-stage project that aims to sign and verify Git commits and tags with a post-quantum signature algorithm, ML-DSA-65 (FIPS 204), using Git's built-in SSH-signature interface. Verification is offline: no server and no network.

An earlier prototype (Dilithium-3, pre-standard parameters) lives on the `legacy` branch and is superseded by this design.

## Where things stand

| Item | Status |
|------|--------|
| M0: Git SSH-signing interface spike | Merged and implemented; reproducible call/failure cells verified on Windows, Ubuntu, and macOS; Git 2.34.1 is known not to work |
| M1-M4 libraries | Merged and implemented; no independent security audit has been completed |
| M5a: key generation, public-key display, and Git shim | Merged and implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b: trust, standalone verification, and diagnostics | Merged and implemented; CI passes on Ubuntu and macOS |
| M6: end-to-end tests, supply-chain checks, and CI hardening | Done (merged in PR #78) |
| M6.1: advisory and doctor follow-up | Done (merged in PR #84) |
| M7: documentation and security pass | In review |
| M8: v0.1.0 release candidate | Planned |

M0 through M6.1 are merged and implemented. M5a adds key generation, public-key display, and a Git signing/verifying shim. M5b adds trust management, standalone object/range verification, and diagnostics. M6 adds end-to-end tests and CI hardening. M6.1 updates the time dependency and MSRV and corrects the Git-version guidance.

## Git compatibility

Runtime-tested versions with recorded evidence are Git 2.39.5 (Debian 12), 2.43.0 (Ubuntu 24.04), 2.55.0 (Windows 11), 2.56.0 (earlier Ubuntu/macOS CI), and 2.56.1 (latest Ubuntu/macOS CI). Ubuntu 22.04 with Git 2.34.1 failed because Git itself did not pass `-Overify-time` to `find-principals`, so the shim failed closed. Git 2.35.0 is the first checked release whose source contains `verify-time`; this source check does not establish runtime compatibility. Versions without recorded passing evidence are untested. See [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md) and [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).

## Quickstart

The README quickstart and the non-required CI smoke workflow run the same self-contained sequence. It creates a temporary home and Git configuration, makes a signed commit, verifies it with Git and QSGit, then confirms that a later unsigned commit is rejected by range verification.

```bash
bash tools/quickstart-smoke.sh
```

## Components

- `qsg`: implements `keygen`, `pubkey`, `verify`, `verify-range`, `trust`, and `doctor`.
- `qsg-ssh-keygen`: implements the Git `-Y sign`, `find-principals`, and `verify` calls.
- Workspace libraries: `qsg-core`, `qsg-sshsig`, `qsg-keystore`, `qsg-trust`, and shared `qsg-verify`.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The list of what is out of scope for v0.1 lives there, in one place.

## Known limitations by design

- QSGit signatures will not verify with stock `ssh-keygen`, and GitHub will not show a "Verified" badge for them.
- Trust comes only from a local `allowed_signers` file. See [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).

v0.1 targets Linux and macOS; Windows is supported for development and testing only, and private-key file permissions are not enforced there.

## Roadmap

| Milestone | Scope | Status |
|-----------|-------|--------|
| M0 | Repo cleanup and Git-interface spike | Merged and implemented; compatibility limits are documented above |
| M1 | ML-DSA-65 core (backend chosen by ADR) | Merged and implemented |
| M2 | SSHSIG-style format and spec, test vectors | Merged and implemented; OpenSSH interoperability verified on Windows, Ubuntu, and macOS CI |
| M3 | Encrypted key storage | Merged and implemented |
| M4 | allowed_signers parsing, validity, revocation | Merged and implemented |
| M5a | `qsg keygen`, `qsg pubkey`, and `qsg-ssh-keygen` Git shim | Merged and implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b | `trust`, `verify`, `verify-range`, and `doctor` CLI commands | Merged and implemented; CI passing on Ubuntu and macOS |
| M6 | End-to-end tests and CI | Done (merged in PR #78); SHA-256 e2e, tampered tag, ACVP pin, supply-chain audit, workflow hardening |
| M6.1 | Advisory and doctor follow-up | Done (merged in PR #84) |
| M7 | Documentation and security pass | In review |
| M8 | v0.1.0 release candidate | Planned |

## Documentation

- [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md): what Git actually calls (verified by spike)
- [docs/SPEC.md](docs/SPEC.md): signature format v1 (draft)
- [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md)
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- [docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)
- [SECURITY.md](SECURITY.md)
- [THIRD-PARTY.md](THIRD-PARTY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache-2.0
