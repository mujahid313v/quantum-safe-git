# Security policy

## Project status and supported versions

QSGit is a release candidate (pre-release); experimental; not independently audited; not for production use. Supported versions are the latest commit on `main` and `v0.1.0-rc.1` once published.

## Reporting a vulnerability

For security reports, use GitHub private vulnerability reporting in this repository's Security tab. For conduct reports, contact the maintainer through GitHub at `mujahid313v`.

Please include the affected commit or tag, operating system and relevant Git/Rust versions, the impact you observed, and a minimal reproduction. Remove credentials, private keys, passphrases, and other private data from logs before sharing them.

The maintainer will make a best-effort effort to acknowledge, investigate, and coordinate a fix. There is no response or remediation SLA. Please coordinate public disclosure with the maintainer and allow reasonable time to investigate and prepare a fix.

## Scope

In scope: code and documentation in this repository. Out of scope: defects in stock Git or OpenSSH themselves. Reports about a QSGit interaction with those tools are in scope when the issue is in this repository's code.

See [THREAT-MODEL.md](docs/THREAT-MODEL.md) for known limitations and assumptions.

## Dependency advisories

The time advisory RUSTSEC-2026-0009 is addressed by the `time` 0.3.47 update. Cargo audit still reports RUSTSEC-2023-0071 for `rsa` 0.9.10 and RUSTSEC-2026-0387 for `crypto-bigint` 0.5.5 in `Cargo.lock`. Offline `cargo tree` inverse lookups print no workspace build path for either package; they remain visible in the lockfile and advisory report.
