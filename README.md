# QSGit

**Status: Experimental. No releases or independent security audit of QSGit or its selected pure-Rust `ml-dsa` backend. Not for production use.**

QSGit is an early-stage project that aims to sign and verify Git commits and tags with a post-quantum signature algorithm, ML-DSA-65 (FIPS 204), using Git's built-in SSH-signature interface. Verification is offline: no server and no network.

An earlier prototype (Dilithium-3, pre-standard parameters) lives on the `legacy` branch and is superseded by this design.

## Where things stand

| Item | Status |
|------|--------|
| M0: Git SSH-signing interface spike | All reproducible call/failure cells verified on Windows, Ubuntu, and macOS; Git 2.34 remains untested. See [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md) |
| M1–M4 libraries | Implemented; review and security audit pending |
| M5a: `qsg keygen`, `qsg pubkey`, Git SSH-signing shim | Implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b: `qsg trust`, `verify`, `verify-range`, and `doctor` | Implemented; CI passing on Ubuntu and macOS |
| M6: end-to-end tests, supply-chain checks and CI hardening | Implemented on `m6/tests-ci`; CI passing |
| M7�M8 | Planned |

M1–M4 library functionality is implemented. M5a adds key generation, public-key display, and a Git signing/verifying shim. M5b adds trust management, standalone object/range verification, and diagnostics; final validation and CI are pending.

## M5a workflow

Git compatibility tested with Git 2.55.0 on Windows and Git 2.56.0 on Ubuntu and macOS. Git 2.34 is the first release with SSH signing, but has not been tested; see [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).

```bash
qsg keygen                                   # create an ML-DSA-65 key pair
git config gpg.format ssh
git config gpg.ssh.program qsg-ssh-keygen
git config user.signingkey ~/.config/qsgit/<key>.pub   # exact form: see docs/GIT-INTERFACE.md
git config gpg.ssh.allowedSignersFile ~/.config/qsgit/allowed_signers
git commit -S -m "signed commit"
git verify-commit HEAD
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
| M0 | Repo cleanup and Git-interface spike | Partial: trusted call shapes verified on Windows/Linux/macOS; untrusted/expired cross-command matrix remains open |
| M1 | ML-DSA-65 core (backend chosen by ADR) | Implemented on `m1/core-mldsa`; review pending |
| M2 | SSHSIG-style format and spec, test vectors | Implemented on `m2/sshsig`; OpenSSH interoperability verified on Windows, Ubuntu, and macOS CI |
| M3 | Encrypted key storage | Implemented on `m3/keystore`; review pending |
| M4 | allowed_signers parsing, validity, revocation | Implemented on `m4/trust`; review pending |
| M5a | `qsg keygen`, `qsg pubkey`, and `qsg-ssh-keygen` Git shim | Implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b | `trust`, `verify`, `verify-range`, and `doctor` CLI commands | Implemented; CI passing on Ubuntu and macOS |
| M6 | End-to-end tests and CI | Implemented on `m6/tests-ci`; SHA-256 e2e, tampered tag, ACVP pin, supply-chain audit, workflow hardening |
| M7 | Documentation and security pass | Planned |
| M8 | v0.1.0 release candidate | Planned |

## Documentation

- [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md): what Git actually calls (verified by spike)
- [docs/SPEC.md](docs/SPEC.md): signature format v1 (draft)
- [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md)
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- [docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache-2.0
