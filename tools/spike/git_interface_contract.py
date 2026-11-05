#!/usr/bin/env python3
"""Exercise Git's SSH-signing subprocess contract on the current CI host."""

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

PRINCIPAL = "m0-contract@example.test"
NON_ARMOR = "QSGIT-M0-NON-ARMOR-SENTINEL"


def run(args, *, cwd=None, env=None, check=True):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {args!r}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="qsg-m0-git-contract-") as temp:
        root = Path(temp)
        log = root / "calls.jsonl"
        helper = root / "fake_ssh_keygen.py"
        helper.write_text(
            "import json, os, pathlib, sys\n"
            "args=sys.argv[1:]\n"
            "mode=args[args.index('-Y')+1]\n"
            "data=sys.stdin.buffer.read()\n"
            "with open(os.environ['QSG_M0_CALL_LOG'],'a',encoding='utf-8') as f:\n"
            " f.write(json.dumps({'operation':os.environ.get('QSG_M0_OPERATION'),'args':args,'stdin_bytes':len(data),'buffer_exists':pathlib.Path(args[-1]).is_file() if mode=='sign' else None})+'\\n')\n"
            "print('M0 stderr probe',file=sys.stderr)\n"
            f"if mode=='sign': pathlib.Path(args[-1]+'.sig').write_text({NON_ARMOR!r},encoding='ascii'); sys.exit(0)\n"
            f"if mode=='find-principals': print({PRINCIPAL!r}); sys.exit(0)\n"
            f"if mode=='verify': print('Good \\\"git\\\" signature for {PRINCIPAL} with ED25519 key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); sys.exit(0)\n"
            "sys.exit(2)\n",
            encoding="utf-8",
        )
        wrapper = root / "fake-ssh-keygen"
        wrapper.write_text(
            f"#!/bin/sh\nexec {sys.executable!r} {str(helper)!r} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        repo = root / "repo"
        repo.mkdir()
        run(["git", "init", "-q", str(repo)])
        for key, value in (
            ("user.name", "M0 contract"),
            ("user.email", PRINCIPAL),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", str(wrapper)),
            ("gpg.ssh.allowedSignersFile", str(root / "allowed_signers")),
            ("user.signingkey", str(root / "dummy-key")),
            ("commit.gpgsign", "true"),
        ):
            run(["git", "config", key, value], cwd=repo)
        (root / "allowed_signers").write_text(
            f'{PRINCIPAL} namespaces="git" ssh-ed25519 AAAA\n', encoding="ascii"
        )
        (root / "dummy-key").write_text("ignored by fake signer\n", encoding="ascii")
        (repo / "file.txt").write_text("signed content\n", encoding="ascii")
        run(["git", "add", "file.txt"], cwd=repo)
        base_branch = run(["git", "branch", "--show-current"], cwd=repo).stdout.strip()
        env = os.environ.copy()
        env["QSG_M0_CALL_LOG"] = str(log)
        env["GIT_CONFIG_GLOBAL"] = str(root / "global-config")
        env["GIT_CONFIG_NOSYSTEM"] = "1"

        def run_git(args, operation, cwd=repo):
            operation_env = env.copy()
            operation_env["QSG_M0_OPERATION"] = operation
            return run(["git", *args], cwd=cwd, env=operation_env)

        run_git(["commit", "-S", "-m", "signed commit"], "commit -S")
        run_git(["verify-commit", "HEAD"], "verify-commit")
        run_git(["log", "--show-signature", "-1"], "log --show-signature")

        # A tag and merge target exercise Git's other signature-checking paths.
        run_git(["tag", "-s", "v-contract", "-m", "signed tag"], "tag -s")
        run_git(["verify-tag", "v-contract"], "verify-tag")
        run(["git", "switch", "-q", "-c", "topic"], cwd=repo)
        (repo / "topic.txt").write_text("topic\n", encoding="ascii")
        run(["git", "add", "topic.txt"], cwd=repo)
        run_git(["commit", "-S", "-m", "topic"], "commit -S topic")
        run(["git", "switch", "-q", base_branch], cwd=repo)
        run_git(["merge", "--verify-signatures", "topic", "-m", "merge"], "merge --verify-signatures")

        # Pull a signed update from a local remote into a fresh clone.
        bare = root / "remote.git"
        run(["git", "init", "--bare", "-q", str(bare)])
        run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=bare)
        run(["git", "remote", "add", "origin", str(bare)], cwd=repo)
        run(["git", "push", "-q", "origin", "HEAD:main"], cwd=repo)
        clone = root / "clone"
        run(["git", "clone", "-q", str(bare), str(clone)])
        for key, value in (
            ("user.name", "M0 contract"),
            ("user.email", PRINCIPAL),
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", str(wrapper)),
            ("gpg.ssh.allowedSignersFile", str(root / "allowed_signers")),
            ("user.signingkey", str(root / "dummy-key")),
        ):
            run(["git", "config", key, value], cwd=clone)
        (clone / "pull.txt").write_text("pull\n", encoding="ascii")
        run(["git", "add", "pull.txt"], cwd=clone)
        run_git(["commit", "-S", "-m", "pull source"], "commit -S pull", cwd=clone)
        run(["git", "push", "-q", "origin", "HEAD:main"], cwd=clone, env=env)
        # Pull the signed descendant while the original repository is still at
        # the previous remote tip.
        run_git(["pull", "--verify-signatures", "origin", "main"], "pull --verify-signatures")
        calls_before_fsck = len(log.read_text(encoding="utf-8").splitlines())
        run_git(["fsck"], "fsck")
        calls_after_fsck = len(log.read_text(encoding="utf-8").splitlines())
        assert calls_after_fsck == calls_before_fsck, "fsck invoked the SSH signing program"

        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        modes = [call["args"][call["args"].index("-Y") + 1] for call in calls]
        assert {"sign", "find-principals", "verify"}.issubset(set(modes)), modes
        assert "check-novalidate" not in modes, modes
        assert all("-r" not in call["args"] for call in calls), calls
        signs = [call for call in calls if "sign" in call["args"]]
        finds = [call for call in calls if "find-principals" in call["args"]]
        verifies = [call for call in calls if "verify" in call["args"]]
        assert all(call["stdin_bytes"] == 0 for call in signs), signs
        assert all(call["buffer_exists"] for call in signs), signs
        assert all(call["stdin_bytes"] > 0 for call in verifies), verifies
        assert all(call["stdin_bytes"] == 0 for call in finds), finds
        assert all("-n" not in call["args"] for call in finds), finds
        assert all("-n" in call["args"] and call["args"][call["args"].index("-n") + 1] == "git" for call in signs + verifies)
        assert all(call["args"][:2] == ["-Y", "sign"] for call in signs), signs
        assert all(call["args"][:2] == ["-Y", "find-principals"] for call in finds), finds
        assert all(call["args"][:2] == ["-Y", "verify"] for call in verifies), verifies
        assert all(any(arg.startswith("-Overify-time=") for arg in call["args"]) for call in finds + verifies)
        signed = run(["git", "cat-file", "commit", "HEAD"], cwd=repo).stdout
        assert NON_ARMOR in signed, "Git did not retain the non-armor signature payload"
        print(
            f"Git={run(['git','--version']).stdout.strip()}; "
            f"OS={platform.system()} {platform.release()}; Python={platform.python_version()}"
        )
        print("Git accepted a signature payload without the SSH SIGNATURE armor header.")
        print("Successful Git operations tolerated program stderr (M0 stderr probe).")
        print("Observed calls:")
        for call in calls:
            print(json.dumps(call, sort_keys=True))
        print("No check-novalidate or -r observed in these trusted-signature flows.")


if __name__ == "__main__":
    main()
