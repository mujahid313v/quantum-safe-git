# Build and release

**Status: release candidate (pre-release); experimental; not independently audited; not for production use.**

## Build

```bash
git clone https://github.com/mujahid313v/quantum-safe-git.git
cd quantum-safe-git
cargo build --workspace
cargo test --workspace
```

v0.1 targets Linux and macOS; Windows is supported for development and testing only, and private-key file permissions are not enforced there. Native Windows development requires the Visual Studio C++ Build Tools for the Rust linker.

Runtime-tested Git versions with passing evidence are 2.39.5 (Debian 12), 2.43.0 (Ubuntu 24.04), 2.55.0 (Windows 11), 2.56.0 (earlier Ubuntu/macOS CI), and 2.56.1 (latest Ubuntu/macOS CI). The manual container results are: `ubuntu:22.04`, Git 2.34.1, **FAIL** because Git does not pass `-Overify-time` to `find-principals`; `debian:12`, Git 2.39.5, **PASS**; `ubuntu:24.04`, Git 2.43.0, **PASS**. Git 2.35.0 is the first checked release whose source contains `verify-time`; this does not prove runtime compatibility. Versions without passing evidence are untested. See [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).

The M1 backend is the pure-Rust RustCrypto `ml-dsa` crate, pinned in `crates/qsg-core/Cargo.toml`; it requires Rust 1.88 or newer and needs no CMake, C compiler, or manual native-library installation. See [ADR 0001](adr/0001-crypto-backend.md). The workspace's stable toolchain in CI is sufficient.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
```

### CI workflows

| Workflow | File | Triggers | Required for PR? |
|---|---|---|---|
| CI | `.github/workflows/ci.yml` | push to main, PRs | **Yes** - only jobs `check (ubuntu-latest)` and `check (macos-latest)` are required |
| Supply chain | `.github/workflows/audit.yml` | weekly schedule, workflow_dispatch, PRs touching Cargo.toml/Cargo.lock | No |
| Git minimum version | `.github/workflows/git-min-version.yml` | workflow_dispatch only | No |
| Fuzz smoke | `.github/workflows/fuzz.yml` | workflow_dispatch only | No |
| Quickstart smoke | `.github/workflows/quickstart.yml` | workflow_dispatch, selected README/guide/script/workflow pull requests | No |

Only the two `check` jobs in `ci.yml` are required PR checks. The required CI workflow runs on every PR:
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. Fetch pinned NIST ACVP vectors (`python3 crates/qsg-core/tests/fetch_acvp_vectors.py`)
4. OpenSSH version check (`ssh -V`)
5. Git verify-time spike (`python3 tools/spike/verify_time.py --check`)
6. Git SSH interface contract (`python3 tools/spike/git_interface_contract.py`)
7. Git trusted/untrusted call matrix (`python3 tools/spike/git_call_state_matrix.py`)
8. `cargo test --workspace --no-fail-fast` (with `QSG_REQUIRE_SSH_KEYGEN=1`)
9. Shim output (nocapture): `cargo test -p qsg-ssh-keygen --test git_end_to_end -- --nocapture`

The supply-chain workflow installs `cargo-audit 0.22.2` and `cargo-deny 0.20.2` with `--locked` (both MIT OR Apache-2.0). Run the checks locally with `cargo audit` and `cargo deny check` from the workspace root after installing those tools. The audit job reports all findings in its job summary. Scheduled workflows consume private-repo GitHub Actions minutes.

The workflow uses `cargo-fuzz` on nightly Rust with a 60-second limit per target. A manual smoke run, not a fuzz campaign, completed `sshsig decode_blob` with 9,847,145 executions and `trust allowed_signers` with 1,226,798 executions on 2026-11-22; both reported 61 seconds. The supplied log contains no crash or error report. These smoke runs are not a security audit.

### Third-party license inventory

Regenerate the shipped dependency output for the Linux and macOS release targets, then deduplicate by crate, version, and license:

```bash
cargo tree -p qsg -e normal,build --target x86_64-unknown-linux-gnu --prefix none --format "{p}|{l}" --offline --locked
cargo tree -p qsg-ssh-keygen -e normal,build --target x86_64-unknown-linux-gnu --prefix none --format "{p}|{l}" --offline --locked
cargo tree -p qsg -e normal,build --target aarch64-apple-darwin --prefix none --format "{p}|{l}" --offline --locked
cargo tree -p qsg-ssh-keygen -e normal,build --target aarch64-apple-darwin --prefix none --format "{p}|{l}" --offline --locked
```

To regenerate the complete workspace test dependency closure, include normal, build, and dev edges for all targets, deduplicate the output, and subtract the shipped table in [THIRD-PARTY.md](../THIRD-PARTY.md):

```bash
cargo tree --workspace -e all --target all --prefix none --format "{p}|{l}" --offline --locked
```

For a direct dev-edge listing, also run:

```bash
cargo tree --workspace -e dev --prefix none --format "{p}|{l}" --offline --locked
```

The shorter `-e dev` form prints dev-dependency edges but omits their normal/build transitive closure in this workspace, so it is not sufficient by itself for a complete dev-only inventory. All commands use Cargo's `{p}` package and `{l}` license format fields.

## Versioning

Pre-1.0 versions `0.x.y`. The first release candidate is `0.1.0`.

## Release procedure

The v0.1.0-rc.1 release is source-only: a source archive and `SHA256SUMS`; Linux and macOS binaries are planned for a later release. Follow [RELEASING.md](RELEASING.md) for maintainer and user verification steps. Authenticity is provided by the signed Git tag and an out-of-band verified release key. `SHA256SUMS` provides integrity only and is not signed.
