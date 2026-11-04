# QSGit

**Status: Experimental. No releases or independent security audit of QSGit or its selected pure-Rust `ml-dsa` backend. Not for production use.**

QSGit is an early-stage project that aims to sign and verify Git commits and tags with a post-quantum signature algorithm, ML-DSA-65 (FIPS 204), using Git's built-in SSH-signature interface. Verification is offline: no server and no network.

An earlier prototype (Dilithium-3, pre-standard parameters) lives on the `legacy` branch and is superseded by this design.

## Where things stand

| Item | Status |
|------|--------|
| M0: Git SSH-signing interface spike | Done on Windows (Git 2.55, OpenSSH 10.5). Linux/macOS not yet re-run. See [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md) |
| Empty Cargo workspace | Done (compiles, no functionality) |
| ML-DSA signing and verification | Planned (M1) |
| Everything else | Planned |

Nothing below works yet.

## Intended workflow (planned, not working yet)

```bash
qsg keygen                                   # create an ML-DSA-65 key pair
git config gpg.format ssh
git config gpg.ssh.program qsg-ssh-keygen
git config user.signingkey ~/.config/qsgit/<key>.pub   # exact form: see docs/GIT-INTERFACE.md
git config gpg.ssh.allowedSignersFile ~/.config/qsgit/allowed_signers
git commit -S -m "signed commit"
git verify-commit HEAD
```

## Components (planned)

- `qsg`: CLI (`keygen`, `pubkey`, `sign`, `verify`, `verify-range`, `trust add|list|revoke`, `doctor`).
- `qsg-ssh-keygen`: a small program implementing the `ssh-keygen -Y sign | find-principals | verify` calls that Git makes.
- Workspace crates: `qsg-core`, `qsg-sshsig`, `qsg-keystore`, `qsg-trust`, `qsg-cli` (builds the `qsg` binary), `qsg-ssh-keygen`.

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
| M5 | `qsg-ssh-keygen` and `qsg` CLI | Planned |
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
