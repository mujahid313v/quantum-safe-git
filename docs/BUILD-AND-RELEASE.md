# Build and release

**Status: experimental. The workspace compiles but contains no functionality.**

## Build

```bash
git clone https://github.com/mujahid313v/quantum-safe-git.git
cd quantum-safe-git
cargo build --workspace
cargo test --workspace
```

Targets for v0.1 are Linux and macOS. On Windows, WSL (Ubuntu) is recommended. Native Windows needs the Visual Studio C++ Build Tools for the Rust linker.

The M1 backend is the pure-Rust RustCrypto `ml-dsa` crate, pinned in `crates/qsg-core/Cargo.toml`; it requires Rust 1.87 or newer and needs no CMake, C compiler, or manual native-library installation. See [ADR 0001](adr/0001-crypto-backend.md). The workspace's stable toolchain in CI is sufficient.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Fuzzing (planned): `cargo-fuzz`, which needs a nightly toolchain. Dependency checks (planned): `cargo audit`, `cargo deny`.

## Versioning

Pre-1.0 versions `0.x.y`. The first release candidate is `0.1.0`.

## Release steps (planned)

1. All checks and CI green.
2. Update versions and changelog.
3. Build release binaries for Linux and macOS: `qsg` and `qsg-ssh-keygen`.
4. Create `SHA256SUMS` covering both binaries.
5. Sign the tag and `SHA256SUMS` with QSGit itself once it works.
6. Publish a GitHub release with binaries, `SHA256SUMS` and its signature.

A checksum file downloaded from the same page as the binary does not prove authenticity. Users must verify the signature on `SHA256SUMS` (the verification procedure is written when the release process exists; TODO).
