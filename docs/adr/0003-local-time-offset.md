# ADR 0003: local-time offset in the Git shim

- Status: accepted for M5a
- Date: 2026-11-05

## Decision

Git's verified `-Overify-time=YYYYMMDDHHMMSS` argument is local civil time with no `Z` suffix. When a matching `allowed_signers` entry has a UTC (`Z`) validity boundary, `qsg-ssh-keygen` must convert that local time to UTC before asking `qsg-trust` to compare it. The shim obtains offsets from the operating system through `time::UtcOffset::local_offset_at`; it does not bundle a time-zone database. It computes candidate offsets around the given wall time and accepts a single matching UTC instant. Zero or multiple candidates fail closed. Offset lookup is skipped unless a matching key/principal entry actually compares local and UTC bases.

The shim remains single-threaded. The `time` crate's Unix local-offset support can be unavailable when the process is multi-threaded; the enabled `unsound_local_offset` cfg permits the API in the binary, and the implementation must not add threads around offset lookup. The crate contains its own platform-specific unsafe implementation; QSGit's crates continue to forbid unsafe code.

A local civil time during a daylight-saving fall-back can identify two UTC instants; Git's verify-time string does not identify which occurrence was intended. The shim detects the ambiguity and fails closed for a mixed-basis validity check. A local time inside a forward clock jump maps to no instant and also fails closed. When all compared timestamps share a basis, no offset lookup is needed.

## Dependencies

| Crate | Exact version | License | Maintenance and audit status | Use |
|---|---:|---|---|---|
| [`time`](https://docs.rs/crate/time/0.3.44) | `0.3.44` | MIT OR Apache-2.0 | Upstream-maintained; no independent security audit of this exact release identified. Declares Rust 1.81, compatible with workspace MSRV 1.87. | Local UTC-offset lookup only in `qsg-ssh-keygen`. |
| [`rpassword`](https://docs.rs/crate/rpassword/7.5.4) | `7.5.4` | Apache-2.0 | Upstream-maintained; release history includes 7.5.4 dated 2026-05-31. No independent security audit identified. | No-echo passphrase input from the terminal in `qsg` and the Git shim. |

Both exact versions are pinned in Cargo manifests. They were not already in the workspace lockfile. The `time` version is pinned below the newest release to preserve the declared Rust 1.87 minimum. Both tools use hand-written argument parsing: the shim accepts only Git's three documented command shapes, and `qsg` currently has only two commands; adding a general parser dependency is not justified for these narrow interfaces.

## Alternatives

- Compare timestamps without conversion: rejected because Git supplies local civil time while OpenSSH validity boundaries may be UTC.
- Bundle a time-zone database: rejected for this milestone; use the host's configured timezone rules.
- Prompt from stdin: rejected because Git's verify path provides the signed payload on stdin. `rpassword::prompt_password` uses the terminal.

## Limitations

- Host timezone configuration must be available and correct. Offset lookup errors fail closed only when a matching entry requires a mixed-basis comparison.
- Repeated and nonexistent local civil times cannot be resolved from Git's timestamp alone; they fail closed for mixed-basis checks.
- `rpassword` and `time` are unaudited dependencies, and the QSGit integration is unaudited.
