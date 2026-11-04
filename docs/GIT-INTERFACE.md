# Git interface (verified by the M0 spike)

**Status:** Experimental. No audit. Not for production use.

## Test environment
- Windows, Git 2.55.0.windows.5, OpenSSH 10.5p1 (Git Bash).

- The M0 call-shape spike above was run on Windows. Its Linux/macOS call-shape behavior remains UNVERIFIED.
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

## Git verification timestamp experiment (M4)

`tools/spike/verify_time.py` creates and verifies signed commits using a logging `gpg.ssh.program` wrapper. It varies the author and committer offsets independently among `+0000`, `+0530`, and `-0800`, and on Unix varies machine `TZ` among UTC, Asia/Kolkata, and America/Los_Angeles.

- Windows 11, Git 2.55.0.windows.5: VERIFIED locally. All three commit offsets produced `20250101053000` in both verification calls on the local +05:30 machine zone; Git appended no `Z`.
- Linux, Git 2.56.0, x86_64, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20: VERIFIED in M4 CI. For each of the three author/committer offset pairs, UTC produced `20250101000000`, Asia/Kolkata produced `20250101053000`, and America/Los_Angeles produced `20241231160000` in both verification calls.
- macOS 26, Git 2.56.0, arm64, OpenSSH_10.3p1: VERIFIED in M4 CI. The same three machine-zone values were observed for all author/committer offset pairs.

Observed behavior: Git formats the commit's epoch timestamp in the machine's local time, independently of the commit's recorded UTC offset, and does not append `Z`. On Linux and macOS, both `find-principals` and `verify` produced the same value. This is verified only for the Git versions and systems listed above.

## Not verified

- Whether Git requires the `-----BEGIN SSH SIGNATURE-----` prefix.
- Whether stderr output from the program matters.

- Whether `check-novalidate` or `-r` (revocation file) is ever used.
- M0 Git call shapes on Linux/macOS, and behavior on Git versions other than those listed above.

## Consequences for QSGit
- `qsg-ssh-keygen` implements only `sign`, `find-principals` and `verify`; any other `-Y` subcommand exits non-zero with a clear message.

- `user.signingkey` points to a QSGit key file path. The `key::` form (needs ssh-agent) is rejected with an explanatory error in v0.1.
- The shim must print exactly the `Good "git" signature for ...` line on success.

- M4 trust parsing treats Git's no-`Z` verify time as local civil time. When comparing it to a UTC validity date, callers must supply an explicit UTC offset.
