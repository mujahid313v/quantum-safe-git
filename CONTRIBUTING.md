# Contributing

QSGit is a release candidate (pre-release); experimental; not independently audited; not for production use. It moves in small milestones (see the roadmap in the README). Please open an issue before starting anything large.

## Setup

- Rust stable, MSRV 1.88: `rustup component add clippy rustfmt`
- Git versions with passing runtime evidence: 2.39.5 (Debian 12), 2.43.0 (Ubuntu 24.04), 2.55.0 (Windows 11), 2.56.0 (earlier Ubuntu/macOS CI), and 2.56.1 (latest Ubuntu/macOS CI). Ubuntu 22.04 with Git 2.34.1 failed because Git does not pass `-Overify-time` to `find-principals`; the shim fails closed. Git 2.35.0 is the first checked release whose source contains `verify-time`, but runtime support is unverified. Versions without passing evidence are untested; see [docs/GIT-INTERFACE.md](docs/GIT-INTERFACE.md) and [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).
- Target platforms for v0.1: Linux and macOS. Development on Windows is possible but not a target; WSL is recommended.
- The backend is pure Rust; no CMake or native crypto library is required. Native Windows builds require the Visual Studio C++ Build Tools for the Rust linker.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
```

Supply-chain checks (`cargo audit`, `cargo deny`) run in `.github/workflows/audit.yml` and are not required PR checks. Run `cargo audit` and `cargo deny check licenses bans sources` locally when changing dependencies; review and report all findings.

## Rules for cryptographic code

- Never implement cryptographic primitives yourself. Use well-reviewed libraries (liboqs itself is not audited).
- Never log secrets, keys, or passphrases.
- Zeroize secret material.
- Changes to crypto code need known-answer tests.
- Parsers must be strict: reject unknown versions, algorithms, namespaces and trailing bytes.
- Add a dependency only with a short justification in the pull request.

## Commits

- Add a DCO sign-off to every commit: `git commit -s`.
- If you have a signing key configured, sign as well: `git commit -S -s -m "message"`.
- Conventional-style messages are welcome (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `security:`).

## Licensing

By contributing you agree that your contribution is licensed under Apache-2.0. The DCO sign-off certifies you have the right to submit it.
Third-party licenses and regeneration commands are listed in [THIRD-PARTY.md](THIRD-PARTY.md).
The M1 backend is RustCrypto `ml-dsa` (Apache-2.0 OR MIT); see [ADR 0001](docs/adr/0001-crypto-backend.md). The backend decision resolves the earlier liboqs/`oqs` licence TODO.

## Code of conduct

Please read the [Code of Conduct](CODE_OF_CONDUCT.md). For conduct reports, contact the maintainer through GitHub at `mujahid313v`.

## Release process

The source-only v0.1.0-rc.1 release procedure, including tag and archive verification, is documented in [docs/RELEASING.md](docs/RELEASING.md).
