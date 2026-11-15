# Contributing

QSGit is experimental and moves in small milestones (see the roadmap in the README). Please open an issue before starting anything large.

## Setup

- Rust stable, MSRV 1.87: `rustup component add clippy rustfmt`
- Git 2.55.0 was tested on Windows and Git 2.56.0 on Ubuntu and macOS. Git 2.34.1 is known not to work: it does not pass `-Overify-time` to `find-principals`, so the shim fails closed. Source inspection shows Git 2.35.0 is the first checked release whose `gpg-interface.c` contains `verify-time` ([v2.34.0](https://github.com/git/git/blob/v2.34.0/gpg-interface.c), [v2.35.0](https://github.com/git/git/blob/v2.35.0/gpg-interface.c)); runtime compatibility of 2.35.0 is not established. Git versions 2.35.0 through 2.54.x are otherwise untested; see [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).
- Target platforms for v0.1: Linux and macOS. Development on Windows is possible but not a target; WSL is recommended.
- Extra tools depend on the crypto backend chosen in ADR 0001 (for liboqs: CMake and a C compiler).

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
Supply-chain checks (`cargo audit`, `cargo deny`) run in `.github/workflows/audit.yml` on a schedule and on pull requests that change `Cargo.toml` or `Cargo.lock`; they are not required checks. Please look at their output when you add or update a dependency.
```

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
Third-party licences are tracked in THIRD-PARTY.md (to be generated with cargo-about or cargo-deny; TODO).
The M1 backend is RustCrypto `ml-dsa` (Apache-2.0 OR MIT); see [ADR 0001](docs/adr/0001-crypto-backend.md). The backend decision resolves the earlier liboqs/`oqs` licence TODO.

## Code of conduct

TODO: add CODE_OF_CONDUCT.md.
