# User guide

**Status: planned workflow only. Nothing here works yet.** Experimental. No audit. Not for production use.

## Requirements (planned)

- Git 2.34 or newer
- Linux or macOS
- Rust stable, to build from source (see [BUILD-AND-RELEASE.md](BUILD-AND-RELEASE.md))

## Install (planned)

Build from source, then put both binaries on your PATH, for example:

```bash
cargo build --release
install -m 755 target/release/qsg ~/.local/bin/
install -m 755 target/release/qsg-ssh-keygen ~/.local/bin/
```

## Set up signing (planned)

```bash
qsg keygen
git config --global gpg.format ssh
git config --global gpg.ssh.program qsg-ssh-keygen
git config --global user.signingkey ~/.config/qsgit/<key>.pub   # exact form: see GIT-INTERFACE.md
git config --global gpg.ssh.allowedSignersFile ~/.config/qsgit/allowed_signers
```

`user.signingkey = key::...` is not supported in v0.1 (Git then passes `-U`, which means ssh-agent).

## Sign and verify (planned)

```bash
git commit -S -m "message"
git tag -s v0.1.0 -m "release"
git verify-commit HEAD
git verify-tag v0.1.0
git log --show-signature
```

## Trusted keys (planned)

```bash
qsg trust add alice@example.org ~/path/to/alice.pub
qsg trust list
qsg trust revoke <fingerprint>
```

The trusted-keys file format and its limits are described in [TRUST-MODEL.md](TRUST-MODEL.md).

## Verify a range, for CI (planned)

```bash
qsg verify-range <base>..<head> --allowed-signers <file>
```

Exit code 0 means every commit verified. Non-zero means at least one commit was unsigned, invalid, or signed by an untrusted key. Take the allowed-signers file from the base branch or pipeline configuration, not from the change under review. There is no ready-made GitHub Action yet.

## FAQ

**Will stock `ssh-keygen` or GitHub's "Verified" badge accept these signatures?** No. The key type is custom.

**Can I use my GPG keys?** No.

**What about hybrid signatures?** Planned, not in v0.1. Hybrid would mean two signatures, not GPG compatibility.

**Is it secure?** It has not been audited and does not exist yet. Do not rely on it.
