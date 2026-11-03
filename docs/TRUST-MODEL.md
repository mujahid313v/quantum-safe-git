# Trust model

**Status: design. Experimental. No audit.**

## Who is trusted

Only public keys listed in the verifier's `allowed_signers` file. A valid signature from an unlisted key means nothing.

Format (OpenSSH-compatible, custom key type):

```
<principal> namespaces="git" [valid-after=<date>] [valid-before=<date>] ssh-mldsa65@qsgit <base64 public key blob>
```

Date syntax: follow ssh-keygen(1), section ALLOWED SIGNERS (TODO: verify exact format).

## Where the file must come from

- CI must take `allowed_signers` from the base branch or from pipeline configuration, never from the pull request being checked. Otherwise an attacker adds their own key in the same pull request and signs with it.
- Locally, protect the file like any other trust anchor.

## Validity windows and time

Git passes `-Overify-time=YYYYMMDDHHMMSS` derived from the commit's own timestamp (observed in the spike). That time is chosen by the signer. A stolen key can therefore sign commits with any date, including dates inside a validity window. Validity windows limit honest mistakes, not a determined attacker with the key.

UNVERIFIED: which time zone Git uses for that value (in the spike both the machine and the commit were +0530). Test across time zones in M5.

## Rotation

1. Create a new key and add it to `allowed_signers`.
2. Keep the old public key (optionally with `valid-before`) so old commits still verify.
3. Never rewrite history or re-sign old commits.

## Revocation (v0.1 limits)

A revocation list names key fingerprints. A revoked key fails for all its signatures, including legitimate old ones, because the list has no effective date. "Revocation with effective date" is an open decision. Revocation also takes effect only where verifiers have the updated list.

## Identity binding

v0.1 does not check that the principal matches the commit's author or committer email. Anyone with a trusted key can sign a commit that claims to be written by someone else. Documented limitation; open decision.

## Not provided in v0.1

Trusted timestamps, transparency logs, central revocation, key distribution. Planned items are listed in [ARCHITECTURE.md](ARCHITECTURE.md).
