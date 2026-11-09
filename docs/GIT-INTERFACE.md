# Git interface (verified by the M0 spike)

**Status:** Experimental. No audit. Not for production use.

## Test environment
- Windows 11, Git 2.55.0.windows.5, OpenSSH_for_Windows 9.5p2 (LibreSSL 3.8.2); the original M0 wrapper spike also used Git Bash OpenSSH 10.5p1.
- Ubuntu 24.04 CI, Git 2.56.0, Linux 7.0.0-1017-azure, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20.
- macOS CI, Git 2.56.0, Darwin 25.6.0, OpenSSH_10.3p1.
- Git 2.55.0 was tested locally on Windows; Git 2.56.0 was tested in CI on Ubuntu and macOS. Git 2.34 is the first release with SSH signing, but is untested; see issue [#67](https://github.com/mujahid313v/quantum-safe-git/issues/67).
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

- Git 2.34 and versions other than Git 2.55.0 and 2.56.0.
- Stock OpenSSH wrong-namespace verification through Git using a crafted external signature. The non-reproducibility claim is an inference from Git's normal `git` namespace flow, not a reproduced test; that D7 cell is marked **UNVERIFIED** below.
- Whether the real-OpenSSH KRL revocation case fails for the right reason on every OS: that test now has a baseline "verify succeeds before the KRL is configured" check (added in M6). See D7 table below for verified per-OS values.

## Consequences for QSGit
- `qsg-ssh-keygen` implements only `sign`, `find-principals` and `verify`; any other `-Y` subcommand exits non-zero with a clear message.

- `user.signingkey` points to a QSGit key file path. The `key::` form (needs ssh-agent) is rejected with an explanatory error in v0.1.
- The shim must print exactly the `Good "git" signature for ...` line on success.

- M4 trust parsing treats Git's no-`Z` verify time as local civil time. When comparing it to a UTC validity date, callers must supply an explicit UTC offset.

## M5a QSGit shim behavior

The `qsg-ssh-keygen` executable now implements the three Git calls above. It accepts `-Y sign -n git -f <keyfile> <buffer>`, `-Y find-principals -f <allowed_signers> -s <sigfile> -Overify-time=<time>`, and `-Y verify -n git -f <allowed_signers> -I <principal> -s <sigfile> -Overify-time=<time>`. Both `-Overify-time=<time>` and `-O verify-time=<time>` are accepted. The find-principals call intentionally has no `-n`; the shim obtains and checks the namespace from the signature. Other subcommands, flags, positional arguments, non-Git namespaces, and ssh-agent `-U` calls fail with status 255. A `.pub` signing-key path resolves through `qsg-keystore` to the corresponding private key.

The shim prompts for encrypted-key passphrases through the terminal, never Git's stdin. On success, verify prints `Good "git" signature for <principal> with MLDSA65 key <SHA256:fingerprint>`. No matching principal exits 255 and prints `No principal matched.`. The shim limits signature files to 128 KiB, `allowed_signers` and revocation files to 1 MiB, and both the signing buffer and verify stdin to 16 MiB. See [USER_GUIDE.md](USER_GUIDE.md) for CLI exit codes and revocation configuration.

M5a end-to-end coverage runs a real signed commit and tag through Git, checks `git verify-commit`, `git verify-tag`, and `git log --show-signature`, then exercises tampering, an untrusted key, a validity window, and revocation. On Windows 11, Git 2.55.0.windows.5 and OpenSSH_for_Windows 9.5p2 (LibreSSL 3.8.2), the local tests passed. The passing Linux/macOS M5a CI run is recorded below.

Rechecking the failure path found one additional Git call: if `find-principals` returns no principal, Git invokes `-Y check-novalidate -n git -s <sigfile>` before it reports verification failure. This branch is present in Git v2.55.0 and v2.56.0 `gpg-interface.c`; the M5a shim intentionally rejects it, as scoped, with status 255 and `unsupported -Y subcommand: check-novalidate`. A temporary untrusted-key Git run with this shim showed `git verify-commit` exits 1 and exposes that diagnostic on stderr; it does not display the `find-principals` message. Successful trusted verification uses `find-principals` followed by `verify`. A direct real-OpenSSH probe showed `check-novalidate` prints a good cryptographic signature line and exits 0 for a valid signature; a tampered message prints `Signature verification failed: incorrect signature` followed by `Could not verify signature.` and exits 255. On untrusted/expired keys, Git/OpenSSH prints the cryptographic signature information and `No principal matched.`. These fallback results were captured on the tested Git versions; `check-novalidate` remains deliberately unsupported in QSGit v0.1.

The test uses a 2020 author date with a 2025 committer date and verifies against a window that includes only the latter; verification succeeds. It then signs a tag with a 2025 tagger date pointing at a commit dated 2020; tag verification also succeeds. Therefore Git's `-Overify-time` uses the **committer date for commits** and the **tagger date for tags** in the tested Git 2.55.0.windows.5 setup. Git formats both in the verifier machine's local zone without `Z`. The shim resolves local civil time to UTC only when a matching trust entry has a UTC validity boundary; details and DST behavior are in [ADR 0003](adr/0003-local-time-offset.md) and [TRUST-MODEL.md](TRUST-MODEL.md).

### M0 Git interface contract CI probe

`tools/spike/git_interface_contract.py` runs as a normal Ubuntu/macOS CI step. The passing run was Git 2.56.0 on Ubuntu `Linux 7.0.0-1017-azure` (x86_64), OpenSSH_9.6p1 Ubuntu-3ubuntu13.20; and Git 2.56.0 on macOS `Darwin 25.6.0` (arm64), OpenSSH_10.3p1. Both contract steps and workspace tests passed.

The exact call shapes observed on both platforms were:

| Operation | Arguments passed to the program | Message source |
|---|---|---|
| Sign | `-Y sign -n git -f <keyfile> <bufferfile>` | No stdin (0 bytes); `<bufferfile>` exists and is a temporary Git signing buffer. Git writes the program's `<bufferfile>.sig` output into the commit/tag. |
| Find principals | `-Y find-principals -f <allowed_signers> -s <signature> -Overify-time=<YYYYMMDDHHMMSS>` | No stdin (0 bytes); Git passes no `-n`. |
| Verify | `-Y verify -n git -f <allowed_signers> -I <principal> -s <signature> -Overify-time=<YYYYMMDDHHMMSS>` | Signed message arrives on stdin (non-empty). |

Git uses the compact `-Overify-time=` spelling without a `Z`. The probe exercised commit signing/verification, log signature display, tag signing/verification, merge and pull with `--verify-signatures`, and `fsck`. On both platforms Git stored a non-armor signature written by the fake signer during `git commit -S`, but `git verify-commit` rejected it before calling the program with exit 128 and `fatal: bad/incompatible signature`. A syntactically armored test signature then verified successfully. The fake program wrote `M0 stderr probe` to stderr: Git suppressed it for signing, log display, merge, pull, and fsck; it surfaced it during `verify-commit` and `verify-tag`. Every successful operation retained exit 0, so this stderr did not change Git's success decision. `fsck` did not invoke the SSH signing program. That earlier trusted-flow probe did not configure `gpg.ssh.revocationFile`; the updated probe with an existing file confirms `-r` is appended only to `verify`.

### M0/D7 evidence

Git source check: [Git v2.55.0 `gpg-interface.c`](https://github.com/git/git/blob/v2.55.0/gpg-interface.c#L579-L592) appends `-r <ssh_revocation_file>` to the `-Y verify` invocation only after `find-principals` has returned a principal and only when `file_exists(ssh_revocation_file)` is true. If configured but absent, Git warns and omits `-r`. It does not append `-r` to `find-principals` or the `check-novalidate` fallback.

Evidence labels: **A** means the script/test asserts the claim and fails if it is wrong; **L** means the exact value was copied from captured local/CI output; **I** means inference. Inferred cells are marked **UNVERIFIED**. A cell can combine labels when its call/failure assertion is checked but its exact exit code or message is only logged.

The CI contract probe creates a non-empty revocation file and logs arguments; it tests Git's argument condition, not the file format. It runs on Windows when available and is required on Ubuntu/macOS by `QSG_REQUIRE_SSH_KEYGEN=1`. The separate OpenSSH integration test generates an Ed25519 key and an OpenSSH KRL containing that public key, configures the existing KRL with `gpg.ssh.revocationFile`, and verifies the signed commit. The QSG integration test configures an existing file containing the revoked QSG fingerprint and records the shim's response.

| Git operation | Trusted key | Untrusted key | Expired key |
|---|---|---|---|
| `git verify-commit` | `find-principals`, `verify` (**A:** calls and exit 0; **L:** Good line) | `find-principals`, `check-novalidate` (**A:** calls and nonzero; **L:** exit 1 and output) | Same calls (**A:** calls and nonzero; **L:** exit 1 and expiry diagnostic) |
| `git verify-tag` | `find-principals`, `verify` (**A:** calls and exit 0; **L:** Good line) | `find-principals`, `check-novalidate` (**A:** calls and nonzero; **L:** exit 1 and output) | Same calls (**A:** calls and nonzero; **L:** exit 1 and expiry diagnostic) |
| `git log --show-signature -1` | `find-principals`, `verify` (**A:** calls and exit 0; **L:** displayed Good line) | `find-principals`, `check-novalidate` (**A:** calls; **L:** exit 0 and `No principal matched.`) | Same calls (**A:** calls; **L:** exit 0 and expiry/No principal output) |
| `git merge --verify-signatures` | `find-principals`, `verify` (**A:** calls and exit 0; **L:** success output) | `find-principals`, `check-novalidate` (**A:** calls and nonzero; **L:** exit 128/fatal) | Same calls (**A:** calls and nonzero; **L:** exit 128/fatal) |
| `git pull --verify-signatures` (local remote) | `find-principals`, `verify` (**A:** calls and exit 0; **L:** success output) | `find-principals`, `check-novalidate` (**A:** calls and nonzero; **L:** exit 128/fatal) | Same calls (**A:** calls and nonzero; **L:** exit 128/fatal) |

The state matrix did not configure a revocation file and asserts that no logged invocation contains `-r` (**A**). Git appends `-r <file>` only to a principal-matched `verify` call when the configured file exists; it omits `-r` if the file is absent and on the no-principal `check-novalidate` path.

The state call matrix uses real Ed25519 signatures with real `ssh-keygen`, and the Python wrapper logs every argument before executing OpenSSH. All cells below were **VERIFIED** in CI on Git 2.56.0, Ubuntu `Linux 7.0.0-1017-azure` with OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 and macOS `Darwin 25.6.0` with OpenSSH_10.3p1. The Windows 11/Git 2.55.0.windows.5 trusted probe with an existing non-empty file also observed `-r <file>` on each `verify` call, and no `-r` on `find-principals`. The earlier local probe's file did not exist, so its “no `-r`” conclusion was incorrect.

| D7 Git verification failure | QSGit shim through Git | Stock OpenSSH Ed25519 through Git |
|---|---|---|
| Tampered commit | Exit 1 and stderr as shown (**A:** nonzero + signature error substring; **L:** exact exit/message), Windows 11 Git 2.55.0; VERIFIED Ubuntu Git 2.56.0 (`ubuntu-latest`, CI run bc727c5) and macOS Git 2.56.0 (`macos-latest`, CI run bc727c5): exit=1, stdout="", stderr=`Could not verify signature.\nSignature verification failed: incorrect signature` | Exit 1 and same stderr (**A:** calls + nonzero; **L:** exact output), Ubuntu `Linux 7.0.0-1017-azure` and macOS `Darwin 25.6.0`, Git 2.56.0 |
| Key absent from `allowed_signers` | Exit 1, stderr `unsupported -Y subcommand: check-novalidate` (**A:** nonzero + substring; **L:** exact exit/message), Windows 11 Git 2.55.0; VERIFIED Ubuntu Git 2.56.0 and macOS Git 2.56.0 (CI run bc727c5): exit=1, stdout="", stderr=`unsupported -Y subcommand: check-novalidate` | Verify-commit/tag exit 1; merge/pull exit 128; log exit 0 (**A:** calls + failure except log; **L:** exact exits/output), Ubuntu/macOS Git 2.56.0 |
| Expired key (`valid-before` before `GIT_COMMITTER_DATE`) | Exit 1, stderr `unsupported -Y subcommand: check-novalidate` (**A:** nonzero + substring; **L:** exact exit/message), Windows 11 Git 2.55.0; VERIFIED Ubuntu Git 2.56.0 and macOS Git 2.56.0 (CI run bc727c5): exit=1, stdout="", stderr=`unsupported -Y subcommand: check-novalidate` | Same per-command exits as untrusted; expiry message reports verify time 2025-01-01 greater than valid-before 2020-01-01 (**A:** calls + failure except log; **L:** exact exits/output), Ubuntu/macOS Git 2.56.0 |
| Revoked key | QSG list via env/sibling: exit 1 and `key is revoked` (**A:** failure + substring; **L:** exact exit/message). VERIFIED Ubuntu Git 2.56.0 and macOS Git 2.56.0 (CI run bc727c5): exit=1, stdout="", stderr=`Could not verify signature.\nkey is revoked: SHA256:...`. Existing fingerprint file via `gpg.ssh.revocationFile`: shim exit 1 `unsupported flag -r` (**A:** flag substring; **L:** exit 1); VERIFIED Ubuntu and macOS (CI run bc727c5): exit=1, stdout="", stderr=`unsupported flag -r` | Ed25519 public key in non-empty OpenSSH KRL: exit 1, stderr `Could not verify signature.`; VERIFIED Ubuntu Git 2.56.0 and macOS Git 2.56.0 (CI run bc727c5): exit=1, stdout="", stderr=`Could not verify signature.` (**A:** query output, Git failure, wrapper asserts `-r`; **L:** exact Git exit/text) |
| Wrong namespace | Direct crafted signature: exit 255, stderr `invalid signature: unsupported SSHSIG namespace` (**A:** exact status + substring; **L:** exact message), Windows 11 Git 2.55.0; VERIFIED Ubuntu Git 2.56.0 and macOS Git 2.56.0 (CI run bc727c5): exit=255, stdout="", stderr=`invalid signature: unsupported SSHSIG namespace` | **UNVERIFIED (I):** not reproduced through a Git command; conclusion that Git's normal path supplies `git` namespace does not test a crafted external signature |

The call-matrix assertions in `tools/spike/git_call_state_matrix.py` include:

```python
expected = ["find-principals", "verify"] if state == "trusted" else ["find-principals", "check-novalidate"]
if modes != expected:
    raise AssertionError(f"{state}/{operation}: expected {expected}, got {modes}; calls={calls}")
if any("-r" in call for call in calls):
    raise AssertionError(f"{state}/{operation}: unexpected -r without revocation config: {calls}")
if state == "trusted" and result.returncode != 0:
    raise AssertionError(f"trusted {operation} failed: {result.stderr}")
visible = result.stdout + result.stderr
if state == "trusted":
    expected_text = "good GPG signature" if operation.startswith(("merge", "pull")) else 'Good "git" signature'
    if expected_text not in visible:
        raise AssertionError(f"trusted {operation}: expected {expected_text!r}: {visible!r}")
if state != "trusted" and operation != "log --show-signature" and result.returncode == 0:
    raise AssertionError(f"untrusted/expired {operation} unexpectedly succeeded")
if state != "trusted":
    expected_code = 0 if operation == "log --show-signature" else (128 if operation.startswith(("merge", "pull")) else 1)
    if result.returncode != expected_code:
        raise AssertionError(f"{state}/{operation}: expected exit {expected_code}, got {result.returncode}")
    if operation.startswith(("merge", "pull")):
        expected_text = "untrusted GPG signature"
    else:
        expected_text = "No principal matched."
    if expected_text not in visible:
        raise AssertionError(f"{state}/{operation}: expected {expected_text!r}: {visible!r}")
    if state == "expired" and operation not in ("merge --verify-signatures", "pull --verify-signatures"):
        if "key has expired" not in visible:
            raise AssertionError(f"expired/{operation}: missing expiry diagnostic: {visible!r}")
```

The same script asserts tamper and KRL outcomes and prints the exact exit/output tuple for each case:

```python
if result.returncode != 1 or modes != ["find-principals", "verify"]:
    raise AssertionError(f"tampered Ed25519 commit result/calls invalid: {result}, {calls}")
if "Could not verify signature." not in result.stderr or "Signature verification failed: incorrect signature" not in result.stderr:
    raise AssertionError(f"tampered Ed25519 commit diagnostics changed: {result.stderr!r}")
if result.returncode != 1 or not has_revocation_arg:
    raise AssertionError(f"revocation-file verification failed to fail closed: {result}, {calls}")
if "Could not verify signature." not in result.stderr:
    raise AssertionError(f"revoked-key verification diagnostic changed: {result.stderr!r}")
```

The QSG shim tests in `crates/qsg-ssh-keygen/tests/git_end_to_end.rs` assert revocation and namespace rejection:

```rust
assert!(!rejected_r.status.success());
assert!(String::from_utf8_lossy(&rejected_r.stderr).contains("unsupported flag -r"));
assert!(!krl_query.status.success() && String::from_utf8_lossy(&krl_query.stdout).to_ascii_uppercase().contains("REVOKED"));
assert_eq!(output.status.code(), Some(255));
assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported SSHSIG namespace"));
```

For QSG signatures with an allowed principal and an existing `gpg.ssh.revocationFile`, Git passes `-r <file>` to the shim. The shim exits 255 and prints `unsupported flag -r` before checking the signature; Git verification exits 1. This fail-closed behavior means even a non-revoked QSG signature cannot verify in this configuration. The QSG revocation mechanisms remain `QSG_REVOKED_KEYS` and sibling `revoked_keys`. See [TRUST-MODEL.md](TRUST-MODEL.md). Git-level wrong-namespace cases are not reproducible because Git requests namespace `git`; the direct crafted-signature test confirms the shim rejects such a signature.
