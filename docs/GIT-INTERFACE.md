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

- Untrusted and expired signature call flows for every verification command on Linux/macOS.
- Git's `gpg.ssh.revocationFile` argument behavior on Linux/macOS and Git versions other than those listed above.

## Consequences for QSGit
- `qsg-ssh-keygen` implements only `sign`, `find-principals` and `verify`; any other `-Y` subcommand exits non-zero with a clear message.

- `user.signingkey` points to a QSGit key file path. The `key::` form (needs ssh-agent) is rejected with an explanatory error in v0.1.
- The shim must print exactly the `Good "git" signature for ...` line on success.

- M4 trust parsing treats Git's no-`Z` verify time as local civil time. When comparing it to a UTC validity date, callers must supply an explicit UTC offset.

## M5a QSGit shim behavior

The `qsg-ssh-keygen` executable now implements the three Git calls above. It accepts `-Y sign -n git -f <keyfile> <buffer>`, `-Y find-principals -f <allowed_signers> -s <sigfile> -Overify-time=<time>`, and `-Y verify -n git -f <allowed_signers> -I <principal> -s <sigfile> -Overify-time=<time>`. Both `-Overify-time=<time>` and `-O verify-time=<time>` are accepted. The find-principals call intentionally has no `-n`; the shim obtains and checks the namespace from the signature. Other subcommands, flags, positional arguments, non-Git namespaces, and ssh-agent `-U` calls fail with status 255. A `.pub` signing-key path resolves through `qsg-keystore` to the corresponding private key.

The shim prompts for encrypted-key passphrases through the terminal, never Git's stdin. On success, verify prints `Good "git" signature for <principal> with MLDSA65 key <SHA256:fingerprint>`. No matching principal exits 255 and prints `No principal matched.`. The shim limits signature files to 128 KiB, `allowed_signers` and revocation files to 1 MiB, and both the signing buffer and verify stdin to 16 MiB. See [USER_GUIDE.md](USER_GUIDE.md) for CLI exit codes and revocation configuration.

M5a end-to-end coverage runs a real signed commit and tag through Git, checks `git verify-commit`, `git verify-tag`, and `git log --show-signature`, then exercises tampering, an untrusted key, a validity window, and revocation. On Windows 11, Git 2.55.0.windows.5 and OpenSSH_for_Windows 9.5p2 (LibreSSL 3.8.2), the local tests passed. The passing Linux/macOS M5a CI run is recorded below.

Rechecking the failure path found one additional Git call: if `find-principals` returns no principal, Git invokes `-Y check-novalidate -n git -s <sigfile>` before it reports verification failure. The M5a shim intentionally rejects this subcommand, as scoped, with status 255 and `unsupported -Y subcommand: check-novalidate`. A temporary untrusted-key Git run with this shim showed `git verify-commit` exits 1 and exposes that diagnostic on stderr; it does not display the `find-principals` message. Successful trusted verification still uses `find-principals` followed by `verify`. A direct real-OpenSSH probe with an Ed25519 signature and the signed message on stdin showed that `ssh-keygen -Y check-novalidate` prints `Good "git" signature with ED25519 key <fingerprint>` and exits 0 for a valid signature; for a tampered message it prints `Signature verification failed: incorrect signature` followed by `Could not verify signature.` and exits 255 (Windows reports `-1` through Python). With an untrusted Ed25519 key, real Git/OpenSSH printed a good cryptographic signature line followed by `No principal matched.` and exited 1. Implementing this command could change how Git flows handle untrusted signatures; TODO: verify in Git source before ever implementing it.

The test uses a 2020 author date with a 2025 committer date and verifies against a window that includes only the latter; verification succeeds. It then signs a tag with a 2025 tagger date pointing at a commit dated 2020; tag verification also succeeds. Therefore Git's `-Overify-time` uses the **committer date for commits** and the **tagger date for tags** in the tested Git 2.55.0.windows.5 setup. Git formats both in the verifier machine's local zone without `Z`. The shim resolves local civil time to UTC only when a matching trust entry has a UTC validity boundary; details and DST behavior are in [ADR 0003](adr/0003-local-time-offset.md) and [TRUST-MODEL.md](TRUST-MODEL.md).

### OpenSSH failure comparison

The following baseline was observed with Git 2.55.0.windows.5 and OpenSSH_for_Windows 9.5p2 (LibreSSL 3.8.2) using Ed25519 keys. QSGit behavior is from the M5a Git end-to-end test on Windows 11. Windows exposes native status 255 as signed `-1` in Python/subprocess output.

| Failure case | Our shim through Git | Real `ssh-keygen` through Git with Ed25519 |
|---|---|---|
| Tampered signature/message | Git verify exits 1; shim reports `Could not verify signature.` / `Signature verification failed: incorrect signature`. **VERIFIED: Git 2.55.0.windows.5, Windows 11.** | **Not compared through Git.** Direct OpenSSH `check-novalidate` probe as above. |
| Key not in allowed_signers | Git verify exits 1; stderr shows `unsupported -Y subcommand: check-novalidate` (no stdout). **VERIFIED: Git 2.55.0.windows.5, Windows 11.** | **Not compared through Git.** Real Git/OpenSSH untrusted-key behavior is described above, but no failure-matrix run was done. |
| Expired key | Git verify exits 1; the end-to-end test observes the shim's `unsupported -Y subcommand: check-novalidate` diagnostic. **VERIFIED: Git 2.55.0.windows.5, Windows 11.** | **Not compared through Git.** |
| Revoked key | Git verify exits 1; shim reports `revoked` in the verification failure. **VERIFIED: Git 2.55.0.windows.5, Windows 11.** | **Not compared through Git.** |
| Wrong namespace | Direct shim call rejects with status 255 and a namespace error. **Not compared through Git.** | **Not compared through Git.** Git uses namespace `git` for these operations, so this row needs an explicit probe to be verified. |

Ed25519 keys are used only to establish stock OpenSSH behavior; QSGit's shim intentionally supports its ML-DSA-65 key type. These are message-shape comparisons, not cryptographic interoperability between the algorithms.

### M0 Git interface contract CI probe

`tools/spike/git_interface_contract.py` runs as a normal Ubuntu/macOS CI step. The passing run was Git 2.56.0 on Ubuntu `Linux 7.0.0-1017-azure` (x86_64), OpenSSH_9.6p1 Ubuntu-3ubuntu13.20; and Git 2.56.0 on macOS `Darwin 25.6.0` (arm64), OpenSSH_10.5p1. Both contract steps and workspace tests passed.

The exact call shapes observed on both platforms were:

| Operation | Arguments passed to the program | Message source |
|---|---|---|
| Sign | `-Y sign -n git -f <keyfile> <bufferfile>` | No stdin (0 bytes); `<bufferfile>` exists and is a temporary Git signing buffer. Git writes the program's `<bufferfile>.sig` output into the commit/tag. |
| Find principals | `-Y find-principals -f <allowed_signers> -s <signature> -Overify-time=<YYYYMMDDHHMMSS>` | No stdin (0 bytes); Git passes no `-n`. |
| Verify | `-Y verify -n git -f <allowed_signers> -I <principal> -s <signature> -Overify-time=<YYYYMMDDHHMMSS>` | Signed message arrives on stdin (non-empty). |

Git uses the compact `-Overify-time=` spelling without a `Z`. The probe exercised commit signing/verification, log signature display, tag signing/verification, merge and pull with `--verify-signatures`, and `fsck`. On both platforms Git stored a non-armor signature written by the fake signer during `git commit -S`, but `git verify-commit` rejected it before calling the program with exit 128 and `fatal: bad/incompatible signature`. A syntactically armored test signature then verified successfully. The fake program wrote `M0 stderr probe` to stderr: Git suppressed it for signing, log display, merge, pull, and fsck; it surfaced it during `verify-commit` and `verify-tag`. Every successful operation retained exit 0, so this stderr did not change Git's success decision. `fsck` did not invoke the SSH signing program. That earlier trusted-flow probe did not configure `gpg.ssh.revocationFile`; the updated probe with an existing file confirms `-r` is appended only to `verify`.

### M0/D7 closeout probes (partial)

Git source check: [Git v2.55.0 `gpg-interface.c`](https://github.com/git/git/blob/v2.55.0/gpg-interface.c#L579-L592) appends `-r <ssh_revocation_file>` to the `-Y verify` invocation only after `find-principals` has returned a principal and only when `file_exists(ssh_revocation_file)` is true. If configured but absent, Git warns and omits `-r`. It does not append `-r` to `find-principals` or the `check-novalidate` fallback.

The CI contract probe creates a non-empty revocation file and logs arguments; it tests Git's argument condition, not the file format. It runs on Windows when available and is required on Ubuntu/macOS by `QSG_REQUIRE_SSH_KEYGEN=1`. The separate OpenSSH integration test generates an Ed25519 key and an OpenSSH KRL containing that public key, configures the existing KRL with `gpg.ssh.revocationFile`, and verifies the signed commit. The QSG integration test configures an existing file containing the revoked QSG fingerprint and records the shim's response.

| Git operation | Trusted key | Untrusted key | Expired key |
|---|---|---|---|
| `git verify-commit` | `find-principals`, `verify` | `find-principals`, `check-novalidate`; exit 1 | Same calls; exit 1 and `valid-before` diagnostic |
| `git verify-tag` | `find-principals`, `verify` | `find-principals`, `check-novalidate`; exit 1 | Same calls; exit 1 and `valid-before` diagnostic |
| `git log --show-signature -1` | `find-principals`, `verify` | `find-principals`, `check-novalidate`; exit 0 and displays `No principal matched.` | Same calls; exit 0 and displays expired diagnostic plus `No principal matched.` |
| `git merge --verify-signatures` | `find-principals`, `verify` | `find-principals`, `check-novalidate`; exit 128, untrusted signature fatal | Same calls and exit 128 |
| `git pull --verify-signatures` (local remote) | `find-principals`, `verify` | `find-principals`, `check-novalidate`; exit 128, untrusted signature fatal | Same calls and exit 128 |

The state matrix did not configure a revocation file, so no `-r` appears in those calls. Git appends `-r <file>` only to a principal-matched `verify` call when the configured file exists; it omits `-r` if the file is absent and on the no-principal `check-novalidate` path.

The state call matrix uses real Ed25519 signatures with real `ssh-keygen`, and the Python wrapper logs every argument before executing OpenSSH. All cells below were **VERIFIED** in CI on Git 2.56.0, Ubuntu `Linux 7.0.0-1017-azure` with OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 and macOS `Darwin 25.6.0` with OpenSSH_10.3p1. The Windows 11/Git 2.55.0.windows.5 trusted probe with an existing non-empty file also observed `-r <file>` on each `verify` call, and no `-r` on `find-principals`. The earlier local probe's file did not exist, so its “no `-r`” conclusion was incorrect.

| D7 Git verification failure | QSGit shim through Git | Stock OpenSSH Ed25519 through Git |
|---|---|---|
| Tampered commit | Git exit 1; stderr: `Could not verify signature.` then `Signature verification failed: incorrect signature` (**VERIFIED**, Windows 11, Git 2.55.0.windows.5) | Same exit and stderr (**VERIFIED**, Git 2.56.0 on Ubuntu 7.0.0-1017-azure/OpenSSH 9.6p1 and macOS 25.6.0/OpenSSH 10.3p1) |
| Key absent from `allowed_signers` | Git exit 1; stderr: `unsupported -Y subcommand: check-novalidate` (**VERIFIED**, Windows 11, Git 2.55.0.windows.5) | Verify-commit/tag exit 1 and output `Good "git" signature with ED25519 key ...` then `No principal matched.`; merge/pull exit 128 with an untrusted-signature fatal; log exits 0 and displays the signature and `No principal matched.` (**VERIFIED**, Ubuntu/macOS versions above) |
| Expired key (`valid-before` before `GIT_COMMITTER_DATE`) | Git exit 1; stderr: `unsupported -Y subcommand: check-novalidate` (**VERIFIED**, Windows 11, Git 2.55.0.windows.5) | Same exit codes as untrusted; find-principals diagnostic says `key has expired: verify time 2025-01-01T00:00:00 > valid-before 2020-01-01T00:00:00`, followed by `No principal matched.` (**VERIFIED**, Ubuntu/macOS versions above) |
| Revoked key | QSG `QSG_REVOKED_KEYS` and sibling list: Git exit 1 and `key is revoked`; with an existing `gpg.ssh.revocationFile`, Git passes `-r` and shim exits 255 with `unsupported flag -r` (Windows 11, Git 2.55.0.windows.5) | Real Ed25519 key is in a non-empty OpenSSH KRL; `git verify-commit` exits 1; stderr `Could not verify signature.`; `ssh-keygen -Q` independently confirms revocation (**VERIFIED**, Windows 11, Git 2.55.0.windows.5) |
| Wrong namespace | Not reproducible through Git, which requests namespace `git`. Direct crafted-signature shim test exits 255; stderr: `invalid signature: unsupported SSHSIG namespace` (**VERIFIED**, Windows 11, Git 2.55.0.windows.5; also run in Linux/macOS CI) | Not reproducible through Git |

For QSG signatures with an allowed principal and an existing `gpg.ssh.revocationFile`, Git passes `-r <file>` to the shim. The shim exits 255 and prints `unsupported flag -r` before checking the signature; Git verification exits 1. This fail-closed behavior means even a non-revoked QSG signature cannot verify in this configuration. The QSG revocation mechanisms remain `QSG_REVOKED_KEYS` and sibling `revoked_keys`. See [TRUST-MODEL.md](TRUST-MODEL.md). Git-level wrong-namespace cases are not reproducible because Git requests namespace `git`; the direct crafted-signature test confirms the shim rejects such a signature.
