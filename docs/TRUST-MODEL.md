# Trust model

**Status: M4 trust library and M5a shim integration implemented. Experimental. No audit.**

## Who is trusted

Only public keys listed in the verifier's `allowed_signers` file. A valid signature from an unlisted key means nothing.

Format (OpenSSH-compatible, custom key type):

```
<principals> <options> ssh-mldsa65@qsgit <base64 public key blob> [comment]
```

`valid-after` and `valid-before` accept `YYYYMMDD[Z]` or `YYYYMMDDHHMM[SS][Z]`, verified against ssh-keygen(1) and real OpenSSH. A missing `Z` means local civil time; `Z` means UTC. QSGit compares times naively when both use the same basis. For Git's local verify-time and a `Z` validity date, the single-threaded M5a shim obtains candidate offsets from the operating system and passes the resolved offset to a pure conversion function. It attempts lookup for find/verify calls but only requires a successful offset when a matching signer entry needs a mixed-basis comparison. If the offset cannot be determined then, verification fails closed. Unit tests use explicit offsets and do not call system timezone APIs. The method and dependency are documented in [ADR 0003](adr/0003-local-time-offset.md).

The shim does not bundle a time-zone database. During a daylight-saving fall-back, the same local clock time occurs twice and Git's `-Overify-time` string does not distinguish the two occurrences. QSGit detects multiple possible UTC instants and fails closed when a mixed-basis validity comparison needs the offset. Nonexistent local times fail closed as well.

Both boundaries are inclusive: a key is valid at exactly `valid-after` and exactly `valid-before`. This matches ssh-keygen(1) and real OpenSSH tests.

Unlike OpenSSH, QSGit requires an explicit `namespaces` option containing `git`; OpenSSH treats a missing namespace option as any namespace. Namespace values are matched exactly. Principals are exact-match only; wildcard and negation characters are rejected. Other key types are skipped and returned in the parser's `skipped` list; malformed QSGit key-type lines fail with a line-numbered error.

The parser accepts LF and CRLF, skips blank lines and lines beginning with `#`, and supports only `namespaces`, `valid-after`, and `valid-before`. `cert-authority` and unknown options are errors. Limits are 1 MiB per file, 16 KiB per line, and 10,000 non-comment entries.

## Where the file must come from

- CI must take `allowed_signers` from the base branch or from pipeline configuration, never from the pull request being checked. Otherwise an attacker adds their own key in the same pull request and signs with it.
- Locally, protect the file like any other trust anchor.

`qsg trust add <principal> <pubkey-file>` appends a QSGit ML-DSA public key with the `git` namespace; optional validity windows can be supplied with `--valid-after` and `--valid-before`. `qsg trust list` shows principals, fingerprints, windows, and skipped non-QSGit key types. `qsg trust revoke <fingerprint>` appends to the plain fingerprint revocation list. These commands preserve unrelated text and comments, reject duplicates, and atomically replace the edited file. Revoking a key rejects all of its signatures, including old ones.

For `qsg verify` and `qsg verify-range`, revocation source precedence is explicit `--revoked-keys`, then `QSG_REVOKED_KEYS`, then `revoked_keys` alongside `--allowed-signers`. A missing or malformed explicitly chosen file fails closed. CI must obtain the allowed-signers bytes from the base branch or trusted pipeline configuration; the verify-range safeguard compares the actual file with tracked base/head blobs but cannot establish provenance for external or untracked files.

The CI example in [USER_GUIDE.md](USER_GUIDE.md) uses `git show <base>:<path>` to materialize the base-branch trust file before invoking `qsg verify-range`.

## Validity windows and time

Git passes `-Overify-time=YYYYMMDDHHMMSS` derived from the commit's timestamp. The M4 logging-wrapper experiment verified that Git formats this value in the machine's local time, independently of the commit's recorded UTC offset, and does not append `Z`. This was tested locally on Windows with Git 2.55.0.windows.5 and in CI on Linux and macOS with Git 2.56.0; on both Unix systems it was tested under UTC, Asia/Kolkata, and America/Los_Angeles. Later runtime evidence includes passing Git 2.39.5 (Debian 12), 2.43.0 (Ubuntu 24.04), and 2.56.1 (latest Ubuntu/macOS CI); see [GIT-INTERFACE.md](GIT-INTERFACE.md) for the tested-version list. The timestamp is still chosen by the commit author: a stolen key can backdate signed commits into a validity window. Validity windows limit honest mistakes, not a determined attacker with the key.

## Rotation

1. Create a new key and add it to `allowed_signers`.
2. Keep the old public key (optionally with `valid-before`) so old commits still verify.
3. Never rewrite history or re-sign old commits.

## Revocation (v0.1 limits)

A revocation file contains one canonical `SHA256:<unpadded-base64>` fingerprint per line; blank lines and `#` comments are ignored. A malformed fingerprint fails parsing. A revoked key fails for all its signatures, including legitimate old ones, because the list has no effective date. "Revocation with effective date" is an open decision. Revocation also takes effect only where verifiers have the updated list.

The M5a Git shim reads the path in `QSG_REVOKED_KEYS` when that environment variable is set. Otherwise it looks for `revoked_keys` in the same directory as the `allowed_signers` file and uses an empty list if no sibling file exists. If the environment variable is set but the file is missing or malformed, verification fails closed. Git v2.55.0 source appends `-r <file>` to `-Y verify` only when `gpg.ssh.revocationFile` is configured, the file exists, and `find-principals` found a principal. Tests exercised this condition with a non-empty OpenSSH KRL containing the revoked Ed25519 public key and with a QSG fingerprint file. The shim rejects `-r` with exit 255 and `unsupported flag -r`; Git verification then fails closed. This is a deliberate v0.1 limitation: do not set `gpg.ssh.revocationFile` with QSGit. Use `QSG_REVOKED_KEYS` or sibling `revoked_keys` for QSG's supported plain fingerprint list. Support for a QSGit revocation list passed via `-r` may be added later. The shim inherits `QSG_REVOKED_KEYS` from its caller. See [the Git source check and CI probes](GIT-INTERFACE.md).

## Identity binding

v0.1 does not check that the principal matches the commit's author or committer email. Anyone with a trusted key can sign a commit that claims to be written by someone else. Documented limitation; open decision.

## Not provided in v0.1

Trusted timestamps, transparency logs, central revocation, key distribution. Planned items are listed in [ARCHITECTURE.md](ARCHITECTURE.md).
