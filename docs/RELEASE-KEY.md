# Release verification key

This key is used to verify the QSGit-signed release tag. The fingerprint must also be confirmed through a channel independent of this repository. A key and fingerprint published only here are a convenience, not a trust anchor.

## Owner: fill before tagging

Public key line from `qsg pubkey`:

```text
<TO BE FILLED BY THE OWNER BEFORE TAGGING>
```

Fingerprint printed by `qsg keygen`:

```text
<TO BE FILLED BY THE OWNER BEFORE TAGGING>
```

The owner must confirm the fingerprint through a separate authenticated channel before publishing the release.

## Generate and record the key

Build the workspace tools, then create a passphrase-protected release key. `qsg keygen` prints the private and public paths and the key fingerprint; keep the private key offline and backed up securely.

```bash
cargo build --release --locked --workspace
qsg keygen --name qsg-release
qsg pubkey ~/.config/qsgit/qsg-release.pub
```

Use the paths printed by `qsg keygen` on systems where the default configuration directory differs. Copy the complete public-key line and fingerprint into the placeholders above. Publish the fingerprint through a separate channel and have a second person verify it before the tag is signed.

## Rotation and revocation

For a planned rotation, add the new public key to trusted release verification and keep the old key available so existing tags can still be checked. QSGit's revocation list has no effective date: revoking a fingerprint invalidates all signatures from that key, including earlier tags, and takes effect only for verifiers using the updated list. The verifier must obtain trust data independently and protect it as a trust anchor. See [TRUST-MODEL.md](TRUST-MODEL.md#rotation) and [its revocation limits](TRUST-MODEL.md#revocation-v01-limits).
