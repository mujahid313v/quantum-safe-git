# User guide

**M5a status: key generation and Git commit/tag signing work on the tested Windows setup. Linux/macOS CI verification is pending. Experimental, unaudited, and not for production use.**

## Requirements

- Git 2.34 or newer with SSH signing support.
- Linux or macOS are the v0.1 target platforms. Windows development works, but is not a release target yet.
- Rust 1.87 or newer to build from source.

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

Add the exact line printed by `qsg keygen` to `~/.config/qsgit/allowed_signers`, replacing the principal with your chosen identity. Protect this file as a trust anchor. Then configure Git:

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

The shim accepts Git's `sign`, `find-principals`, and `verify` calls. Verification reads at most 16 MiB from stdin. Signature files are limited to 128 KiB and `allowed_signers` to 1 MiB. Successful verification prints Git's required `Good "git" signature ...` line. Errors exit 255; the `qsg` CLI exits 0 on success, 1 on an operation failure, and 2 for usage/configuration errors.

The shim looks for revocations in `QSG_REVOKED_KEYS` when set. Otherwise, it reads `revoked_keys` next to `allowed_signers` if that file exists. Git does not provide a revocation-file argument to the custom shim.

## Still planned for M5b

`qsg trust`, `qsg verify`, `qsg verify-range`, and `qsg doctor` are not implemented in M5a. There is no ready-made GitHub Action. The key type is custom, so stock OpenSSH and GitHub's “Verified” badge do not accept these ML-DSA signatures.
