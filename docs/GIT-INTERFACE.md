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

- For a trusted key, `git verify-commit`, `git verify-tag`, `git log --show-signature` and `git merge --verify-signatures` run one find-principals call followed by one verify call. If no principal is found, Git may use the `check-novalidate` fallback described in M5a.
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

- Whether `-r` (revocation file) is ever used.
- M0 Git call shapes on Linux/macOS, and behavior on Git versions other than those listed above.

## Consequences for QSGit
- `qsg-ssh-keygen` implements only `sign`, `find-principals` and `verify`; any other `-Y` subcommand exits non-zero with a clear message.

- `user.signingkey` points to a QSGit key file path. The `key::` form (needs ssh-agent) is rejected with an explanatory error in v0.1.
- The shim must print exactly the `Good "git" signature for ...` line on success.

- M4 trust parsing treats Git's no-`Z` verify time as local civil time. When comparing it to a UTC validity date, callers must supply an explicit UTC offset.

## M5a QSGit shim behavior

The `qsg-ssh-keygen` executable now implements the three Git calls above. It accepts `-Y sign -n git -f <keyfile> <buffer>`, `-Y find-principals -f <allowed_signers> -s <sigfile> -Overify-time=<time>`, and `-Y verify -n git -f <allowed_signers> -I <principal> -s <sigfile> -Overify-time=<time>`. Both `-Overify-time=<time>` and `-O verify-time=<time>` are accepted. The find-principals call intentionally has no `-n`; the shim obtains and checks the namespace from the signature. Other subcommands, flags, positional arguments, non-Git namespaces, and ssh-agent `-U` calls fail with status 255. A `.pub` signing-key path resolves through `qsg-keystore` to the corresponding private key.

The shim prompts for encrypted-key passphrases through the terminal, never Git's stdin. On success, verify prints `Good "git" signature for <principal> with MLDSA65 key <SHA256:fingerprint>`. No matching principal exits 255 and prints `No principal matched.`. The shim limits signature files to 128 KiB, `allowed_signers` and revocation files to 1 MiB, and signed stdin to 16 MiB. See [USER_GUIDE.md](USER_GUIDE.md) for exit codes and revocation configuration.

M5a end-to-end coverage runs a real signed commit and tag through Git, checks `git verify-commit`, `git verify-tag`, and `git log --show-signature`, then exercises tampering, an untrusted key, a validity window, and revocation. On Windows 11, Git 2.55.0.windows.5 and OpenSSH_for_Windows 9.5p2 (LibreSSL 3.8.2), the local tests passed. Linux/macOS CI results are pending for this branch.

Rechecking the failure path found one additional Git call: if `find-principals` returns no principal, Git invokes `-Y check-novalidate -n git -s <sigfile>` before it reports verification failure. The M5a shim intentionally rejects this subcommand, as scoped, with status 255 and `unsupported -Y subcommand: check-novalidate`. Therefore an untrusted or expired key fails closed, but Git surfaces that unsupported-call diagnostic instead of OpenSSH's generic trust failure. Successful trusted verification still uses `find-principals` followed by `verify`.

The test uses a 2020 author date with a 2025 committer date and verifies against a window that includes only the latter; verification succeeds. It then signs a tag with a 2025 tagger date pointing at a commit dated 2020; tag verification also succeeds. Therefore Git's `-Overify-time` uses the **committer date for commits** and the **tagger date for tags** in the tested Git 2.55.0.windows.5 setup. Git formats both in the verifier machine's local zone without `Z`. The shim resolves local civil time to UTC only when a matching trust entry has a UTC validity boundary; details and DST behavior are in [ADR 0003](adr/0003-local-time-offset.md) and [TRUST-MODEL.md](TRUST-MODEL.md).

### OpenSSH failure comparison

The following baseline was observed with OpenSSH_for_Windows 9.5p2 using Ed25519 keys and `ssh-keygen -Y verify` directly (Windows reports process status 255 as signed `-1`):

| Case | Real `ssh-keygen` result | QSGit shim result |
|---|---|---|
| No principal for key | Direct `find-principals`: 255, `No principal matched.`; Git then makes a `check-novalidate` fallback call. | Direct `find-principals` matches OpenSSH. During Git verification, fallback is rejected with 255 and `unsupported -Y subcommand: check-novalidate`. |
| Bad signature | 255, `Could not verify signature.` and `Signature verification failed: incorrect signature` | 255; generic `Could not verify signature.` plus the same incorrect-signature explanation. ML-DSA bad-signature behavior is also covered by QSGit vectors. |
| Unknown principal | 255, `Could not verify signature.` | 255; `Could not verify signature.` plus QSGit's `no trusted key matches...` reason. |
| Wrong namespace | 255, `Could not verify signature.` and `Couldn't verify signature: namespace does not match` | Rejected during `find-principals` because the stored namespace must be `git`; 255 with a clear namespace error. |
| Expired key | Direct verify: 255, `Could not verify signature.` plus an `allowed_signers` line diagnostic naming the expiry and verify time. Git may use its no-principal fallback. | Git's expired-key flow returns no principal, then the shim rejects `check-novalidate` with 255. |

Ed25519 keys are used only to establish the stock OpenSSH message behavior; QSGit's shim intentionally supports its ML-DSA-65 key type. These are message-shape comparisons, not cryptographic interoperability between the algorithms.
