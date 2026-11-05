# QSGit

**Status: Experimental. No releases or independent security audit of QSGit or its selected pure-Rust `ml-dsa` backend. Not for production use.**

QSGit is an early-stage project that aims to sign and verify Git commits and tags with a post-quantum signature algorithm, ML-DSA-65 (FIPS 204), using Git's built-in SSH-signature interface. Verification is offline: no server and no network.

An earlier prototype (Dilithium-3, pre-standard parameters) lives on the `legacy` branch and is superseded by this design.

## Where things stand

| Item | Status |
|------|--------|
| M0: Git SSH-signing interface spike | Verified on Windows (Git 2.55, OpenSSH 10.5); CI experiments on Linux/macOS documented. See [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md) |
| M1–M4 libraries | Implemented; review and security audit pending |
| M5a: `qsg keygen`, `qsg pubkey`, Git SSH-signing shim | Implemented; Windows end-to-end checked locally; Linux/macOS CI pending |
| M5b: trust/verify/verify-range/doctor commands | Planned |
| M6–M8 | Planned |

M1–M4 library functionality is implemented. M5a adds key generation, public-key display, and a Git signing/verifying shim; its end-to-end test passes locally on Windows. Linux/macOS CI confirmation is pending for this integration.

## M5a workflow

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

- `qsg`: M5a implements `keygen` and `pubkey`; more commands are planned for M5b.
- `qsg-ssh-keygen`: implements the Git `-Y sign`, `find-principals`, and `verify` calls.
- Workspace libraries: `qsg-core`, `qsg-sshsig`, `qsg-keystore`, and `qsg-trust`.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The list of what is out of scope for v0.1 lives there, in one place.

## Known limitations by design

- QSGit signatures will not verify with stock `ssh-keygen`, and GitHub will not show a "Verified" badge for them.
- Trust comes only from a local `allowed_signers` file. See [docs/TRUST-MODEL.md](docs/TRUST-MODEL.md).

## Roadmap

| Milestone | Scope | Status |
|-----------|-------|--------|
| M0 | Repo cleanup and Git-interface spike | Windows spike done; cleanup in progress; Linux/macOS re-run pending |
| M1 | ML-DSA-65 core (backend chosen by ADR) | Implemented on `m1/core-mldsa`; review pending |
| M2 | SSHSIG-style format and spec, test vectors | Implemented on `m2/sshsig`; OpenSSH interoperability verified on Windows, Ubuntu, and macOS CI |
| M3 | Encrypted key storage | Implemented on `m3/keystore`; review pending |
| M4 | allowed_signers parsing, validity, revocation | Implemented on `m4/trust`; review pending |
| M5a | `qsg keygen`, `qsg pubkey`, and `qsg-ssh-keygen` Git shim | Implemented; Windows end-to-end checked locally; Linux/macOS CI pending |
| M5b | `trust`, `verify`, `verify-range`, and `doctor` CLI commands | Planned |
| M6 | End-to-end tests and CI | Planned |
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
