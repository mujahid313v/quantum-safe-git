# Signature format v1 (draft)

**Status: draft. Experimental. No audit.** Layout of the container was checked against a real Ed25519 SSH signature produced during the M0 spike. ML-DSA parts are design only.

## Container

Standard SSH-signature armor, because that is what Git expects to carry in `gpgsig`:

```
-----BEGIN SSH SIGNATURE-----
<base64, wrapped at 70 columns (as observed in OpenSSH output)>
-----END SSH SIGNATURE-----
```

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

The key type name `ssh-mldsa65@qsgit` is a placeholder (TODO: final name).

## What is signed

```
H = SHA-512(message)                     message = bytes Git supplies
P = "SSHSIG" || string(namespace) || string(reserved) || string(hash_algorithm) || string(H)
signature = ML-DSA-65.Sign(secret key, P, context = "QSGit-v1")
```

This preimage follows OpenSSH's PROTOCOL.sshsig (TODO: confirm). M2 must first implement the same container for Ed25519 and check it against stock `ssh-keygen -Y verify`; only then swap in ML-DSA.

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

`SHA256:` followed by unpadded base64 of SHA-256 over the public-key blob (same style OpenSSH prints; TODO: confirm for the custom type).

## Test vectors

TODO (M2): our own vectors, plus NIST/ACVP known-answer tests for ML-DSA-65 (TODO: verify where to obtain them).
