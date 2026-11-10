# Build and release

**Status: experimental. The workspace implements ML-DSA-65 signing and verification, key storage, trust parsing, the Git shim, and the `qsg` commands. No independent security audit has been completed.**

## Build

```bash
git clone https://github.com/mujahid313v/quantum-safe-git.git
cd quantum-safe-git
cargo build --workspace
cargo test --workspace
```

v0.1 targets Linux and macOS; Windows is supported for development and testing only, and private-key file permissions are not enforced there. Native Windows development requires the Visual Studio C++ Build Tools for the Rust linker.

Tested with Git 2.55.0 on Windows and Git 2.56.0 on Ubuntu and macOS. Git 2.34.1 is known NOT to work: it does not pass `-Overify-time` to `find-principals` and the shim fails closed. Git 2.35.0 is the first version with the fix (source-verified from [git/git gpg-interface.c v2.34.0 vs v2.35.0](https://github.com/git/git/blob/v2.35.0/gpg-interface.c)). Versions between 2.35 and 2.55 are untested; see [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).

The M1 backend is the pure-Rust RustCrypto `ml-dsa` crate, pinned in `crates/qsg-core/Cargo.toml`; it requires Rust 1.87 or newer and needs no CMake, C compiler, or manual native-library installation. See [ADR 0001](adr/0001-crypto-backend.md). The workspace's stable toolchain in CI is sufficient.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
```

### CI workflows

| Workflow | File | Triggers | Required for PR? |
|---|---|---|---|
| CI | `.github/workflows/ci.yml` | push to main, PRs | **Yes** — jobs `check (ubuntu-latest)` and `check (macos-latest)` |
| Supply chain | `.github/workflows/audit.yml` | weekly schedule, workflow_dispatch, PRs touching Cargo.toml/Cargo.lock | No |
| Git minimum version | `.github/workflows/git-min-version.yml` | workflow_dispatch only | No |
| Fuzz smoke | `.github/workflows/fuzz.yml` | workflow_dispatch only | No |

The required CI workflow runs on every PR:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. Fetch pinned NIST ACVP vectors (`python3 crates/qsg-core/tests/fetch_acvp_vectors.py`)
4. OpenSSH version check (`ssh -V`)
5. Git verify-time spike (`python3 tools/spike/verify_time.py --check`)
6. Git SSH interface contract (`python3 tools/spike/git_interface_contract.py`)
7. Git trusted/untrusted call matrix (`python3 tools/spike/git_call_state_matrix.py`)
8. `cargo test --workspace --no-fail-fast` (with `QSG_REQUIRE_SSH_KEYGEN=1`)
9. Shim output (nocapture): `cargo test -p qsg-ssh-keygen --test git_end_to_end -- --nocapture`

The supply-chain workflow installs `cargo-audit 0.22.2` and `cargo-deny 0.20.2` with `--locked` (both MIT OR Apache-2.0). It reports all findings without hiding them. Scheduled workflows consume private-repo GitHub Actions minutes.

Fuzzing uses `cargo-fuzz` on nightly Rust. Each fuzz target runs for 60 seconds.

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
