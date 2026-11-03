# Signature format v1 (draft)

**Status: M2 implemented. Experimental. No independent audit.** Ed25519 container interoperability passed in both directions with OpenSSH_for_Windows 9.5p2. Linux/macOS CI results are recorded after the M2 pull request checks complete.

## Container

Standard SSH-signature armor, because that is what Git expects to carry in `gpgsig`:

```
-----BEGIN SSH SIGNATURE-----
<base64, wrapped at 70 columns (as observed in OpenSSH output)>
-----END SSH SIGNATURE-----
```

QSGit emits LF-only armor, 70 base64 characters per line, and a final LF after the footer. Its decoder accepts exactly that canonical form with or without the final LF. It rejects CRLF, alternate wrapping, whitespace, malformed base64, and other headers/footers. OpenSSH's current `PROTOCOL.sshsig` says base64 lines SHOULD be wrapped every 76 characters; the Windows OpenSSH 9.5p2 `ssh-keygen -Y sign` output interoperated with this implementation's observed 70-column form. This 70-column rule is the tested QSGit canonical form.

The decoded binary blob is limited to 64 KiB. Encoded armor is limited to 128 KiB.

## Blob layout

All `string` fields are a 4-byte big-endian length followed by the bytes.

```
byte[6]  "SSHSIG"
uint32   version = 1
string   publickey        = string("ssh-mldsa65@qsgit") || string(public key bytes)
string   namespace        = "git"
string   reserved         = ""            (empty)
string   hash_algorithm   = "sha512"
string   signature        = string("ssh-mldsa65@qsgit") || string(ML-DSA-65 signature)
```

The signed message is not inside the blob. (Observed in the spike: an Ed25519 signature decodes to exactly this layout, with `sha512` and namespace `git`.)

The key type name is `ssh-mldsa65@qsgit`; retain it as a placeholder until M8. M2's decoder allowlist contains `ssh-ed25519` for interoperability tests and `ssh-mldsa65@qsgit` for QSGit signatures. Ed25519 key/signature byte lengths are 32/64; ML-DSA-65 lengths are 1952/3309. The inner public-key and signature blobs are each `string(key_type) || string(raw_key_or_signature)`.

## What is signed

```
H = SHA-512(message)                     message = bytes Git supplies
P = "SSHSIG" || string(namespace) || string(reserved) || string(hash_algorithm) || string(H)
signature = ML-DSA-65.Sign(secret key, P, context = "QSGit-v1")
```

This preimage was confirmed against OpenSSH [`PROTOCOL.sshsig`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig), sections 2 and 3: section 3 specifies the `SSHSIG` preamble followed by SSH strings for namespace, reserved, hash algorithm, and `H(message)`; section 2 says to hash the message first. The implementation passed `ssh-keygen -Y verify` in both directions with Ed25519 before adding ML-DSA.

Context: FIPS 204 allows a context string up to 255 bytes. If the chosen crate does not expose it, the prefix encoding must be defined here before release (TODO).

## Sizes (ML-DSA-65)

- public key: 1952 bytes
- signature: 3309 bytes
- secret key: 4032 bytes (in-memory format; the stored file format is defined in M3)
- armored signature: roughly 7 KB (estimate from the layout above)

## Verifier rules

Reject, with a clear error, if any of these hold:

- magic is not `SSHSIG` or version is not 1
- namespace is not `git`, reserved is not empty, hash algorithm is not `sha512`
- key type is not in the compile-time allowlist (no downgrade, no "skip unknown")
- trailing bytes after the last field, or any field length exceeds the remaining input
- the public key is not listed for the principal in `allowed_signers`, or is outside its validity window, or is revoked
- ML-DSA verification fails

## Key fingerprint

`SHA256:` followed by unpadded base64 of SHA-256 over the complete public-key blob, including its key type and length strings. This matches the output of `ssh-keygen -l -E sha256 -f` for the Ed25519 test key. ML-DSA uses the same calculation over its public-key blob.

## Test vectors

The fixed ML-DSA-65 SSHSIG vectors are in `crates/qsg-sshsig/tests/vectors/`:

- `ml-dsa65-valid-1.sshsig`, `ml-dsa65-valid-2.sshsig`: valid signatures over the message `QSGit M2 fixed ML-DSA-65 vector message\n` with context `QSGit-v1`.
- `ml-dsa65-mutated-1.sshsig`, `ml-dsa65-mutated-2.sshsig`: same records with one signature bit flipped; decoding succeeds and cryptographic verification fails.

The ignored test `regenerate_hedged_ml_dsa65_vectors` creates a fresh keypair with `qsg-core::keygen`, signs twice through `qsg-sshsig::sign_ml_dsa65` (hedged OS randomness), writes only public SSHSIG blobs, and derives each invalid vector by flipping one bit in its signature. Regeneration intentionally produces different valid bytes; the committed files are the fixed vectors used by tests.

Ed25519 interop was tested on Windows with OpenSSH_for_Windows 9.5p2. CI sets `QSG_REQUIRE_SSH_KEYGEN=1` and runs the same tests on Ubuntu and macOS; CI tool versions/results: TODO: verify after the PR checks run.
