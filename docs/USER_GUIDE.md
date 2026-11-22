# User guide

**M5b status: key generation, Git signing, trust management, verification, range verification, and diagnostics are implemented. Experimental, unaudited, and not for production use.**

## Requirements

- Runtime-tested Git versions with passing evidence are 2.39.5 (Debian 12), 2.43.0 (Ubuntu 24.04), 2.55.0 (Windows 11), 2.56.0 (earlier Ubuntu/macOS CI), and 2.56.1 (latest Ubuntu/macOS CI). Ubuntu 22.04 with Git 2.34.1 failed because Git does not pass `-Overify-time` to `find-principals`. Git 2.35.0 is the first checked release whose source contains `verify-time`, but runtime compatibility is unverified. Versions without passing evidence are untested; see [docs/GIT-INTERFACE.md](GIT-INTERFACE.md) and [issue #67](https://github.com/mujahid313v/quantum-safe-git/issues/67).
- v0.1 targets Linux and macOS; Windows is supported for development and testing only, and private-key file permissions are not enforced there.
- Rust 1.88 or newer to build from source.

## Build and install

```bash
cargo build --release --workspace
install -m 755 target/release/qsg ~/.local/bin/
install -m 755 target/release/qsg-ssh-keygen ~/.local/bin/
```

Both binaries must be on `PATH` for the example Git configuration below. Alternatively, set `gpg.ssh.program` to the full path of `qsg-ssh-keygen`.

## Create a key

```bash
qsg keygen
```

The default key directory is `$XDG_CONFIG_HOME/qsgit`, or `~/.config/qsgit` when `XDG_CONFIG_HOME` is unset. The command prompts twice on the terminal without echoing the passphrase. Passphrases must contain at least 12 characters; empty values are rejected. The key is not overwritten if it already exists.

For a key without passphrase encryption, use `qsg keygen --no-passphrase`. The command prints a warning because anyone who can read the private key can use it to sign. Other options are `--name NAME`, `--dir DIR`, and `--comment TEXT`.

The command prints the public key path, fingerprint, exact `allowed_signers` line to add (with a placeholder principal), and four Git configuration commands. Replace `you@example.org` with the principal you will use in the trust file. Add the line and run those commands yourself; QSGit does not edit Git configuration or the trust file.

To print the OpenSSH-style public key line again:

```bash
qsg pubkey ~/.config/qsgit/id_mldsa65.pub
```

## Configure trust and Git

Manage the allowed-signers file with `qsg trust`; it preserves unrelated lines and comments and uses atomic replacement:

```bash
qsg trust add you@example.org ~/.config/qsgit/id_mldsa65.pub
qsg trust list
qsg trust revoke SHA256:<fingerprint>
```

The default file is `~/.config/qsgit/allowed_signers` (or `$XDG_CONFIG_HOME/qsgit/allowed_signers`). `trust add` accepts `--allowed-signers`, `--valid-after`, and `--valid-before`; `trust list` accepts `--allowed-signers`; `trust revoke` accepts `--revoked-keys`. Revocation defaults to `revoked_keys` beside the default allowed-signers file. A revoked key fails for all its signatures, including old ones (v0.1 limitation).

Protect the allowed-signers file as a trust anchor. Then configure Git:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program qsg-ssh-keygen
git config --global user.signingkey ~/.config/qsgit/id_mldsa65.pub
git config --global gpg.ssh.allowedSignersFile ~/.config/qsgit/allowed_signers
```

The signing key can be the private key path or its `.pub` path. `key::...` and ssh-agent keys are unsupported. For CI, take `allowed_signers` from the base branch or trusted pipeline configuration, never from the pull request being verified.

## Sign and verify

```bash
git commit -S -m "signed commit"
git verify-commit HEAD
git tag -s v0.1.0 -m "signed release"
git verify-tag v0.1.0
git log --show-signature -1
```

The shim accepts Git's `sign`, `find-principals`, and `verify` calls. It reads at most 16 MiB from the signing buffer and from verification stdin. Signature files are limited to 128 KiB and `allowed_signers` to 1 MiB. Successful verification prints Git's required `Good "git" signature ...` line. Shim errors exit 255. The `qsg` CLI exits 0 on success, 1 on any runtime failure (including configuration and key-file failures), and 2 only for usage or argument errors.

The shim looks for revocations in `QSG_REVOKED_KEYS` when set. Otherwise, it reads `revoked_keys` next to `allowed_signers` if that file exists.

For standalone `qsg verify` and `qsg verify-range`, revocation source precedence is: explicit `--revoked-keys`, then `QSG_REVOKED_KEYS`, then `revoked_keys` beside `--allowed-signers`. An explicitly selected missing, unreadable, or malformed file is an error.

### Standalone verification

```bash
qsg verify --allowed-signers ~/.config/qsgit/allowed_signers --commit HEAD
qsg verify --allowed-signers ~/.config/qsgit/allowed_signers --tag v0.1.0
qsg verify --allowed-signers ~/.config/qsgit/allowed_signers --signature object.sig --message object.txt
qsg verify-range BASE..HEAD --allowed-signers ~/.config/qsgit/allowed_signers --fail-on-empty
qsg verify-range BASE..HEAD --allowed-signers ~/.config/qsgit/allowed_signers --format json
```

`verify` checks one signed commit, annotated tag, or signature/message pair. Commit time comes from the committer header and tag time from the tagger header, formatted in local time; `--verify-time YYYYMMDDHHMMSS` overrides it. Only namespace `git` is supported. `verify-range` checks every commit from `BASE` exclusive through `HEAD` inclusive, including merge commits. It fails if any commit is unsigned, invalid, untrusted, expired, or revoked. An empty range prints `0 commits in range` and succeeds; CI should pass `--fail-on-empty`.

Git range semantics exclude the base commit. A root commit used as the base is therefore not checked by that range; verify it separately with `qsg verify --commit <root>`. A missing base, unresolved range, shallow clone without needed commits, or missing object fails closed with an error.

In CI, provide trust bytes from the base branch or trusted pipeline configuration, never from the change under review. For example:

```bash
git fetch origin "$BASE_BRANCH"
BASE=$(git rev-parse "origin/$BASE_BRANCH")
HEAD=$(git rev-parse HEAD)
git show "$BASE:security/allowed_signers" > "$RUNNER_TEMP/allowed_signers"
qsg verify-range "$BASE..$HEAD" --allowed-signers "$RUNNER_TEMP/allowed_signers" --fail-on-empty
```

If the selected file path is tracked in the range and its actual bytes differ from the base blob (or it is added only in the head), verification warns loudly and exits 1. `--trust-file-from-head` explicitly overrides that check. Files outside the repository or untracked at both endpoints cannot be checked for provenance; supply those from trusted pipeline configuration.

JSON format is stable under `schema_version: 1`:

```json
{"schema_version":1,"range":"BASE..HEAD","commits":[{"commit":"<oid>","status":"verified|failed","fingerprint":"SHA256:... or null","reason":null}]}
```

Each commit object has `commit` (object ID), `status` (`verified` or `failed`), `fingerprint` (string on success, otherwise null), and `reason` (null on success, otherwise text). Range-level failures such as resolution or trust-source safeguard failures are reported on stderr and exit 1.

`qsg doctor` performs read-only checks of Git, configuration, the shim, trust files, signing key and environment. Git older than 2.35.0 produces an ERROR because it does not pass `-Overify-time`. Unlisted versions from 2.35.0 through the newest tested version produce a WARN that runtime support is untested; tested versions produce INFO. A version newer than the newest tested version produces INFO and says it is not yet tested. Unparseable version output produces a WARN. The command exits 0 when there are no ERROR items and 1 when any ERROR item is reported; WARN items do not affect the exit code. It never prints private key contents.

### Revocation troubleshooting

Do not set `gpg.ssh.revocationFile` when using QSGit. Git passes `-r <file>` to `-Y verify` only when the setting is present, the file exists, and a principal was found. QSGit's shim rejects `-r` with exit 255 and `unsupported flag -r`, so Git verification fails closed. Use `QSG_REVOKED_KEYS` or a `revoked_keys` file next to `allowed_signers`. This is a deliberate v0.1 limitation; support for passing a QSGit revocation list via `-r` may be added later.

## Limitations

There is no ready-made GitHub Action. The key type is custom, so stock OpenSSH and GitHub do not accept these ML-DSA signatures as ordinary SSH signatures. `gpg.ssh.revocationFile` must be unset: Git can pass `-r` to the shim, which rejects it and makes verification fail closed. Use `QSG_REVOKED_KEYS` or the sibling `revoked_keys` file instead.
