# Releasing QSGit

## v0.1.0-rc.1 scope and status

**Status: release candidate (pre-release); experimental; not independently audited; not for production use.** This is a source-only release: publish the Git source archive and `SHA256SUMS`. Do not upload Linux or macOS binaries for this candidate; binaries are planned for a later release. Crate versions remain 0.1.0.

The signed Git tag, made with QSGit itself, provides authenticity when verified against the release key whose fingerprint was confirmed out of band. `SHA256SUMS` provides archive integrity only. Do not claim that the checksum file is signed: the shim supports only the `git` namespace and cannot sign arbitrary files.

## Maintainer procedure

### Preconditions

1. Start from an up-to-date, clean `main` checkout. Confirm both required CI jobs, `check (ubuntu-latest)` and `check (macos-latest)`, are green.
2. Run and record `cargo deny check licenses bans sources` and `cargo audit` with the release tool versions. Review the latest supply-chain results separately; a passing job does not mean there are no advisories. The recorded status is that RUSTSEC-2026-0009 for `time` 0.3.47 is addressed, while RUSTSEC-2023-0071 for `rsa` 0.9.10 and RUSTSEC-2026-0387 for `crypto-bigint` 0.5.5 remain in Cargo.lock and the audit report. Record the maintainer's release decision about these findings; do not hide them.
3. Review the fuzz results and release notes. The recorded 60-second-per-target manual smoke run is not a fuzz campaign or audit.
4. Generate and verify the release key as described in [RELEASE-KEY.md](RELEASE-KEY.md), and fill both placeholders there. Confirm its fingerprint out of band before signing.

### Dry run before real tagging

After the release tooling and documentation are committed, start from a clean checkout. This creates a temporary lightweight tag, runs the source-release script, explicitly compares the two printed archive hashes, and deletes the tag. If the fixed example tag already exists locally, choose another unused `v0.1.0-rc.N` value.

```bash
set -euo pipefail
DRY_TAG=v0.1.0-rc.99
if git show-ref --verify --quiet "refs/tags/$DRY_TAG"; then
    echo "choose another unused dry-run tag" >&2
    exit 1
fi
DRY_DIR="$(mktemp -d)"
cleanup() {
    if git show-ref --verify --quiet "refs/tags/$DRY_TAG"; then
        git tag -d "$DRY_TAG"
    fi
    rm -rf "$DRY_DIR"
}
trap cleanup EXIT
git tag "$DRY_TAG"
DRY_OUTPUT="$(bash tools/make-source-release.sh "$DRY_TAG" "$DRY_DIR")"
printf '%s\n' "$DRY_OUTPUT"
FIRST_HASH="$(printf '%s\n' "$DRY_OUTPUT" | sed -n 's/^first archive hash: *//p')"
SECOND_HASH="$(printf '%s\n' "$DRY_OUTPUT" | sed -n 's/^second archive hash: *//p')"
test -n "$FIRST_HASH"
test "$FIRST_HASH" = "$SECOND_HASH"
git tag -d "$DRY_TAG"
trap - EXIT
rm -rf "$DRY_DIR"
```

### Build, configure, and sign

Build the release binaries locally so Git and QSGit can create and verify the tag. These binaries are not included in the release assets.

```bash
git checkout main
git pull --ff-only
git status --short
cargo build --release --locked --workspace
export PATH="$PWD/target/release:$PATH"
qsg --help
```

Set the release key paths, create a dedicated allowed-signers file, and configure Git only in this repository. Use the private key path for signing; protect it and its passphrase.

```bash
RELEASE_PRINCIPAL=qsg-release
RELEASE_KEY="$HOME/.config/qsgit/qsg-release"
RELEASE_ALLOWED_SIGNERS="$HOME/.config/qsgit/release-allowed_signers"
qsg trust add "$RELEASE_PRINCIPAL" "$RELEASE_KEY.pub" --allowed-signers "$RELEASE_ALLOWED_SIGNERS"

git config --local gpg.format ssh
git config --local gpg.ssh.program qsg-ssh-keygen
git config --local user.signingkey "$RELEASE_KEY"
git config --local gpg.ssh.allowedSignersFile "$RELEASE_ALLOWED_SIGNERS"
```

Create and verify the annotated, signed release tag with both Git and QSGit:

```bash
git tag -s v0.1.0-rc.1 -m "QSGit v0.1.0-rc.1"
git verify-tag v0.1.0-rc.1
qsg verify --tag v0.1.0-rc.1 --allowed-signers "$RELEASE_ALLOWED_SIGNERS"
```

Create the reproducible source archive and checksum in a temporary output directory outside the repository. The script requires the tag to resolve and the working tree to be clean.

```bash
OUTDIR="$(mktemp -d)"
bash tools/make-source-release.sh v0.1.0-rc.1 "$OUTDIR"
```

Publish the source archive and checksum file as a GitHub pre-release:

```bash
gh release create v0.1.0-rc.1 --prerelease --title "QSGit v0.1.0-rc.1" --notes-file docs/release-notes/v0.1.0-rc.1.md "$OUTDIR/qsgit-0.1.0-rc.1-source.tar.gz" "$OUTDIR/SHA256SUMS"
```

### Post-release fresh-clone verification

Use a new temporary directory and verify the tag before trusting the archive. Obtain the public key from [RELEASE-KEY.md](RELEASE-KEY.md), confirm its fingerprint through the independent channel, save its public key line as `release-key.pub`, and add it to the temporary allowed-signers file. The key in this repository is a convenience, not a trust anchor.

```bash
VERIFY_DIR="$(mktemp -d)"
git clone https://github.com/mujahid313v/quantum-safe-git.git "$VERIFY_DIR/repo"
cd "$VERIFY_DIR/repo"
git checkout v0.1.0-rc.1
cargo build --release --locked --workspace
export PATH="$PWD/target/release:$PATH"
qsg trust add qsg-release "$VERIFY_DIR/release-key.pub" --allowed-signers "$VERIFY_DIR/allowed_signers"
git config --local gpg.format ssh
git config --local gpg.ssh.program qsg-ssh-keygen
git config --local gpg.ssh.allowedSignersFile "$VERIFY_DIR/allowed_signers"
git verify-tag v0.1.0-rc.1
qsg verify --tag v0.1.0-rc.1 --allowed-signers "$VERIFY_DIR/allowed_signers"
gh release download v0.1.0-rc.1 --dir "$VERIFY_DIR/assets"
```

Check the downloaded archive against the checksum file. Use `sha256sum -c SHA256SUMS` where available, or `shasum -a 256 -c SHA256SUMS` on macOS. Then extract and rebuild the source:

```bash
tar -xzf "$VERIFY_DIR/assets/qsgit-0.1.0-rc.1-source.tar.gz" -C "$VERIFY_DIR"
cd "$VERIFY_DIR/qsgit-0.1.0-rc.1"
cargo build --release --locked
```

Successful tag verification authenticates the tagged source only to the extent that the independently confirmed release key is trusted. A matching SHA-256 digest detects archive corruption or mismatch; by itself it does not authenticate who published the archive.
