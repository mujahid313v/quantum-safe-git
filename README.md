# QSGit

**Status: Experimental. No releases or independent security audit of QSGit or its selected pure-Rust `ml-dsa` backend. Not for production use.**

QSGit is an early-stage project that aims to sign and verify Git commits and tags with a post-quantum signature algorithm, ML-DSA-65 (FIPS 204), using Git's built-in SSH-signature interface. Verification is offline: no server and no network.

An earlier prototype (Dilithium-3, pre-standard parameters) lives on the `legacy` branch and is superseded by this design.

## Where things stand

| Item | Status |
|------|--------|
| M0: Git SSH-signing interface spike | Merged and implemented; reproducible call/failure cells verified on Windows, Ubuntu, and macOS; Git 2.34.1 is known not to work |
| M1-M4 libraries | Merged and implemented; security review/audit remains pending |
| M5a: key generation, public-key display, and Git shim | Merged and implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b: trust, standalone verification, and diagnostics | Merged and implemented; CI passes on Ubuntu and macOS |
| M6: end-to-end tests, supply-chain checks, and CI hardening | Implemented in PR #78, pending merge |
| M7-M8 | Planned |

M0 through M5b are merged and implemented. M5a adds key generation, public-key display, and a Git signing/verifying shim. M5b adds trust management, standalone object/range verification, and diagnostics. M6 is implemented in PR #78 and is pending merge.

## M5a workflow

Git 2.55.0 was tested on Windows and Git 2.56.0 on Ubuntu and macOS. Git 2.34.1 is known not to work: it does not pass `-Overify-time` to `find-principals`, so the shim fails closed. Source inspection shows that Git 2.35.0 is the first of the checked releases whose `gpg-interface.c` contains `verify-time` ([v2.34.0](https://github.com/git/git/blob/v2.34.0/gpg-interface.c), [v2.35.0](https://github.com/git/git/blob/v2.35.0/gpg-interface.c)); compatibility of 2.35.0 itself has not been demonstrated by the runtime matrix. Git versions 2.35.0 through 2.54.x are otherwise untested; see [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67). The `qsg doctor` minimum-version text still says 2.34 and is tracked there.

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
| M0 | Repo cleanup and Git-interface spike | Merged and implemented; compatibility limits are documented above |
| M1 | ML-DSA-65 core (backend chosen by ADR) | Merged and implemented; review pending |
| M2 | SSHSIG-style format and spec, test vectors | Merged and implemented; OpenSSH interoperability verified on Windows, Ubuntu, and macOS CI |
| M3 | Encrypted key storage | Merged and implemented; review pending |
| M4 | allowed_signers parsing, validity, revocation | Merged and implemented; review pending |
| M5a | `qsg keygen`, `qsg pubkey`, and `qsg-ssh-keygen` Git shim | Merged and implemented; end-to-end tests pass on Windows and Linux/macOS CI |
| M5b | `trust`, `verify`, `verify-range`, and `doctor` CLI commands | Merged and implemented; CI passing on Ubuntu and macOS |
| M6 | End-to-end tests and CI | Implemented in PR #78, pending merge; SHA-256 e2e, tampered tag, ACVP pin, supply-chain audit, workflow hardening |
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
