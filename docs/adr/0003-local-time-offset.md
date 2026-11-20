# ADR 0003: local-time offset in the Git shim

- Status: accepted for M5a
- Date: 2026-11-05

## Decision

Git's verified `-Overify-time=YYYYMMDDHHMMSS` argument is local civil time with no `Z` suffix. When a matching `allowed_signers` entry has a UTC (`Z`) validity boundary, `qsg-ssh-keygen` must convert that local time to UTC before asking `qsg-trust` to compare it. The single-threaded shim obtains candidate offsets from the operating system through `time::UtcOffset::local_offset_at`; it does not bundle a time-zone database. It computes candidate offsets around the given wall time and accepts a single matching UTC instant. Zero or multiple candidates fail closed. The lookup is attempted for find/verify calls; an unavailable offset is an error only when a matching key/principal entry actually compares local and UTC bases.

The original source review checked [`time` 0.3.44](https://docs.rs/crate/time/0.3.44/source/src/sys/local_offset_at/) before enabling local-offset lookup. That source's Windows implementation uses `SystemTimeToTzSpecificLocalTime`, which its comments identify as thread-safe; the Unix offset implementation uses `localtime_r`. QSGit does not call the separate `time::util::refresh_tz` API. The workspace now pins `time` 0.3.47 to include the advisory fix and requires Rust 1.88. The original source review was not repeated against 0.3.47; whether those platform implementation details are unchanged in 0.3.47 is unverified here. Unit tests use explicit offsets to avoid host timezone/DST dependence; the single-threaded shim process obtains system offsets. The unsafe platform code is inside the dependency; QSGit crates continue to forbid unsafe code.

A local civil time during a daylight-saving fall-back can identify two UTC instants; Git's verify-time string does not identify which occurrence was intended. The shim detects the ambiguity and fails closed for a mixed-basis validity check. A local time inside a forward clock jump maps to no instant and also fails closed. When all compared timestamps share a basis, no offset lookup is needed.

## Dependencies

| Crate | Exact version | License | Maintenance and audit status | Use |
|---|---:|---|---|---|
| [`time`](https://docs.rs/crate/time/0.3.47) | `0.3.47` | MIT OR Apache-2.0 | Fixes RUSTSEC-2026-0009; owner-verified upstream manifest declares Rust 1.88. No independent security audit of this exact release identified. Default features disabled; only `local-offset` enabled (which implies `std`). | Local UTC-offset lookup only in `qsg-ssh-keygen`. |
| [`rpassword`](https://docs.rs/crate/rpassword/7.5.4) | `7.5.4` | Apache-2.0 | Upstream-maintained; release history includes 7.5.4 dated 2026-05-31. No independent security audit identified. | No-echo passphrase input from the terminal in `qsg` and the Git shim. |

Additional packages introduced transitively by these dependencies in the M5a lockfile diff are listed here. Licenses are from `cargo metadata` package metadata; no independent audit evidence was identified for these exact versions.

| Package | Exact version | License | Audit status |
|---|---:|---|---|
| [`deranged`](https://crates.io/crates/deranged/0.5.9) | `0.5.9` | MIT OR Apache-2.0 | No independent audit evidence identified. |
| [`num-conv`](https://crates.io/crates/num-conv/0.2.2) | `0.2.2` | MIT OR Apache-2.0 | No independent audit evidence identified. |
| [`num_threads`](https://crates.io/crates/num_threads/0.1.8) | `0.1.8` | MIT OR Apache-2.0 | No independent audit evidence identified. |
| [`powerfmt`](https://crates.io/crates/powerfmt/0.2.1) | `0.2.1` | MIT OR Apache-2.0 | No independent audit evidence identified. |
| [`rtoolbox`](https://crates.io/crates/rtoolbox/0.0.6) | `0.0.6` | Apache-2.0 | No independent audit evidence identified. |
| [`time-core`](https://crates.io/crates/time-core/0.1.8) | `0.1.8` | MIT OR Apache-2.0 | No independent audit evidence identified. |

The `time` release is pinned exactly at 0.3.47 in the consuming manifests; its dependency closure is recorded in Cargo.lock. The original M5a lockfile statement above described the then-current lockfile and is historical. Both tools use hand-written argument parsing: the shim accepts only Git's three documented command shapes, and `qsg` currently has only two commands; adding a general parser dependency is not justified for these narrow interfaces.

## Alternatives

- Compare timestamps without conversion: rejected because Git supplies local civil time while OpenSSH validity boundaries may be UTC.
- Bundle a time-zone database: rejected for this milestone; use the host's configured timezone rules.
- Prompt from stdin: rejected because Git's verify path provides the signed payload on stdin. `rpassword::prompt_password` uses the terminal.

## Limitations

- Host timezone configuration must be available and correct. Offset lookup errors fail closed only when a matching entry requires a mixed-basis comparison. The code passes the resolved offset into a pure local-to-UTC conversion; unit tests use explicit offsets and do not call system timezone APIs. Changes to `TZ` made after process startup are not refreshed by QSGit.
- Repeated and nonexistent local civil times cannot be resolved from Git's timestamp alone; they fail closed for mixed-basis checks.
- `rpassword` and `time` are unaudited dependencies, and the QSGit integration is unaudited.
