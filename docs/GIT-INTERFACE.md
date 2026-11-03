# Git interface (verified by the M0 spike)

**Status:** Experimental. No audit. Not for production use.

## Test environment
- Windows, Git 2.55.0.windows.5, OpenSSH 10.5p1 (Git Bash).
- Linux and macOS: UNVERIFIED. Re-run the spike there before relying on this file.
- Method: (1) a logging wrapper around the real `ssh-keygen`, (2) a fake program returning a dummy armored blob, both set as `gpg.ssh.program`.
- Object formats tested with the real `ssh-keygen`: sha1 and sha256. The calls were identical.

## Configuration used

```
git config gpg.format ssh
git config gpg.ssh.program <program>
git config user.signingkey <path>
git config gpg.ssh.allowedSignersFile <file>
```

## Calls made by Git (VERIFIED)
| Operation | Command line | stdin | Expected result |
|-----------|--------------|-------|-----------------|
| Sign | `-Y sign -n git -f <signingkey value> <buffer file>` | empty | Signature written to `<buffer file>.sig`, exit 0 |
| Find principal | `-Y find-principals -f <allowed_signers> -s <sigfile> -Overify-time=YYYYMMDDHHMMSS` | empty | Principal name on stdout, exit 0 |
| Verify | `-Y verify -n git -f <allowed_signers> -I <principal> -s <sigfile> -Overify-time=YYYYMMDDHHMMSS` | the signed payload | One line on stdout, exit 0 |
- The buffer file holds the commit/tag text without the signature (`tree ...`, `author ...`, `committer ...`, message).
- `-f` receives exactly the value of `user.signingkey` when it is a path (both a private key path and a `.pub` path were observed, without `-U`).
- When `user.signingkey` is `key::<literal key>`, Git passes `-f <temp file> -U <buffer file>` (`-U` means ssh-agent).
- Verify output line accepted by Git: `Good "git" signature for <principal> with <KEYTYPE> key <fingerprint>`.
- On failure the program exited 255 and printed a message on stdout; `git verify-commit` then exited 1 and showed the message.
- `git verify-commit`, `git verify-tag`, `git log --show-signature` and `git merge --verify-signatures` each ran one find-principals call followed by one verify call.
- The signature is stored in the commit's `gpgsig` header between `-----BEGIN SSH SIGNATURE-----` and `-----END SSH SIGNATURE-----`.
- Git did not validate the blob: a dummy blob and a non-standard key type name in the "Good" line were accepted.

## Not verified
- Time zone of `verify-time` (UTC, local time, or the commit's offset). Both were +0530 in the test.
- Whether Git requires the `-----BEGIN SSH SIGNATURE-----` prefix.
- Whether stderr output from the program matters.
- Whether `check-novalidate` or `-r` (revocation file) is ever used.
- Behaviour on Linux, macOS, and other Git versions.

## Consequences for QSGit
- `qsg-ssh-keygen` implements only `sign`, `find-principals` and `verify`; any other `-Y` subcommand exits non-zero with a clear message.
- `user.signingkey` points to a QSGit key file path. The `key::` form (needs ssh-agent) is rejected with an explanatory error in v0.1.
- The shim must print exactly the `Good "git" signature for ...` line on success.
- `verify-time` parsing must be tested across time zones (M5).
