# Contributing

QSGit is experimental and moves in small milestones (see the roadmap in the README). Please open an issue before starting anything large.

## Setup

- Rust stable: `rustup component add clippy rustfmt`
- Git 2.34 or newer (SSH-format signing)
- Target platforms for v0.1: Linux and macOS. Development on Windows is possible but not a target; WSL is recommended.
- Extra tools depend on the crypto backend chosen in ADR 0001 (for liboqs: CMake and a C compiler).

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
Licences of liboqs and the `oqs` crate: TODO: verify before adding them as dependencies.

## Code of conduct

TODO: add CODE_OF_CONDUCT.md.
