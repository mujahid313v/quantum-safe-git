#!/usr/bin/env python3
"""Record Git's SSH verifier calls for trusted, untrusted, and expired Ed25519 keys."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

PRINCIPAL = "m0-state@example.test"
DATE = "2025-01-01T00:00:00+0000"


def run(args, *, cwd, env, check=True):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {args!r}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def main():
    if os.name != "posix":
        msg = "skipped Git state call matrix: executable wrapper requires POSIX"
        if os.environ.get("QSG_REQUIRE_SSH_KEYGEN") == "1":
            raise RuntimeError(f"{msg} while QSG_REQUIRE_SSH_KEYGEN=1")
        print(msg, flush=True)
        return
    missing = [tool for tool in ("git", "ssh-keygen") if shutil.which(tool) is None]
    if missing:
        msg = f"skipped Git state call matrix: missing {', '.join(missing)}"
        if os.environ.get("QSG_REQUIRE_SSH_KEYGEN") == "1":
            raise RuntimeError(f"{msg} while QSG_REQUIRE_SSH_KEYGEN=1")
        print(msg, flush=True)
        return

    git_version = subprocess.run(["git", "--version"], check=True, text=True, capture_output=True).stdout.strip()
    ssh_version = subprocess.run(["ssh", "-V"], check=False, text=True, capture_output=True)
    print(
        f"Git={git_version}; SSH={ssh_version.stderr.strip()}; "
        f"OS={platform.system()} {platform.release()}",
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="qsg-m0-state-matrix-") as tmp:
        root = Path(tmp)
        log = root / "ssh-keygen-calls.jsonl"
        real_ssh_keygen = shutil.which("ssh-keygen")
        wrapper = root / "ssh-keygen-wrapper"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "args=sys.argv[1:]\n"
            "with open(os.environ['QSG_M0_CALL_LOG'],'a',encoding='utf-8') as f: "
            "f.write(json.dumps(args)+'\\n')\n"
            f"os.execv({real_ssh_keygen!r}, [{real_ssh_keygen!r}, *args])\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        keys = root / "keys"
        keys.mkdir()
        key1 = keys / "signer"
        key2 = keys / "other"
        for key in (key1, key2):
            run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                cwd=root,
                env=os.environ.copy(),
            )
        pub1 = key1.with_suffix(".pub").read_text(encoding="ascii").strip()
        pub2 = key2.with_suffix(".pub").read_text(encoding="ascii").strip()

        def git_env(repo):
            env = os.environ.copy()
            env.update(
                {
                    "GIT_CONFIG_GLOBAL": str(root / "empty-global-config"),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "HOME": str(root),
                    "GIT_AUTHOR_NAME": "M0 State Matrix",
                    "GIT_AUTHOR_EMAIL": PRINCIPAL,
                    "GIT_COMMITTER_NAME": "M0 State Matrix",
                    "GIT_COMMITTER_EMAIL": PRINCIPAL,
                    "GIT_AUTHOR_DATE": DATE,
                    "GIT_COMMITTER_DATE": DATE,
                    "QSG_M0_CALL_LOG": str(log),
                }
            )
            return env

        def configure(repo, state):
            env = git_env(repo)
            run(["git", "init", "-q", str(repo)], cwd=root, env=env)
            values = (
                ("user.name", "M0 State Matrix"),
                ("user.email", PRINCIPAL),
                ("gpg.format", "ssh"),
                ("gpg.ssh.program", str(wrapper)),
                ("user.signingkey", str(key1)),
            )
            for k, v in values:
                run(["git", "config", k, v], cwd=repo, env=env)
            if state == "trusted":
                allowed_key = pub1
            elif state == "untrusted":
                allowed_key = pub2
            else:
                allowed_key = pub1
            validity = ',valid-before="20200101Z"' if state == "expired" else ""
            allowed = root / f"allowed-{state}"
            allowed.write_text(
                f'{PRINCIPAL} namespaces="git"{validity} {allowed_key}\n',
                encoding="ascii",
            )
            run(
                ["git", "config", "gpg.ssh.allowedSignersFile", str(allowed)],
                cwd=repo,
                env=env,
            )
            return env

        def signed_commit(repo, env, msg):
            (repo / f"file-{msg.replace(' ', '-')}.txt").write_text(msg + "\n", encoding="ascii")
            run(["git", "add", "."], cwd=repo, env=env)
            run(["git", "commit", "-q", "-S", "-m", msg], cwd=repo, env=env)

        def observe(state, operation):
            repo = root / f"repo-{state}-{operation.replace(' ', '-')}"
            repo.mkdir()
            env = configure(repo, state)
            signed_commit(repo, env, "base")
            run(["git", "tag", "-s", "v1", "-m", "tag"], cwd=repo, env=env)
            if operation == "verify-commit":
                args = ["git", "verify-commit", "HEAD"]
            elif operation == "verify-tag":
                args = ["git", "verify-tag", "v1"]
            elif operation == "log --show-signature":
                args = ["git", "log", "--show-signature", "-1"]
            elif operation == "merge --verify-signatures":
                base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, env=env, check=True, text=True, capture_output=True).stdout.strip()
                run(["git", "switch", "-q", "-c", "topic"], cwd=repo, env=env)
                signed_commit(repo, env, "topic")
                run(["git", "switch", "-q", "--detach", base], cwd=repo, env=env)
                run(["git", "switch", "-q", "-c", "main"], cwd=repo, env=env)
                args = ["git", "merge", "--verify-signatures", "topic", "-m", "merge"]
            else:
                bare = root / f"remote-{state}.git"
                run(["git", "init", "--bare", "-q", str(bare)], cwd=root, env=env)
                run(["git", "push", "-q", str(bare), "HEAD:main"], cwd=repo, env=env)
                run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=bare, env=env)
                clone = root / f"clone-{state}"
                run(["git", "clone", "-q", str(bare), str(clone)], cwd=root, env=env)
                clone_env = git_env(clone)
                run(["git", "config", "gpg.format", "ssh"], cwd=clone, env=clone_env)
                run(["git", "config", "gpg.ssh.program", str(wrapper)], cwd=clone, env=clone_env)
                allowed = root / f"allowed-{state}"
                run(["git", "config", "gpg.ssh.allowedSignersFile", str(allowed)], cwd=clone, env=clone_env)
                (repo / "next.txt").write_text("next\n", encoding="ascii")
                run(["git", "add", "next.txt"], cwd=repo, env=env)
                run(["git", "commit", "-q", "-S", "-m", "next"], cwd=repo, env=env)
                run(["git", "push", "-q", str(bare), "HEAD:main"], cwd=repo, env=env)
                args = ["git", "pull", "--verify-signatures", str(bare), "main"]
                repo = clone
                env = clone_env

            with log.open("w", encoding="utf-8") as f:
                f.write("")
            result = run(args, cwd=repo, env=env, check=False)
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            modes = [call[call.index("-Y") + 1] for call in calls if "-Y" in call]
            print(
                f"state={state}; operation={operation}; exit={result.returncode}; "
                f"calls={modes}; stdout={result.stdout.strip()!r}; stderr={result.stderr.strip()!r}",
                flush=True,
            )
            expected = ["find-principals", "verify"] if state == "trusted" else ["find-principals", "check-novalidate"]
            if modes != expected:
                raise AssertionError(f"{state}/{operation}: expected {expected}, got {modes}; calls={calls}")
            if state == "trusted" and result.returncode != 0:
                raise AssertionError(f"trusted {operation} failed: {result.stderr}")
            if state != "trusted" and operation != "log --show-signature" and result.returncode == 0:
                raise AssertionError(f"untrusted/expired {operation} unexpectedly succeeded")

        def observe_tampered_commit():
            repo = root / "repo-tampered"
            repo.mkdir()
            env = configure(repo, "trusted")
            signed_commit(repo, env, "signed before tampering")
            raw = subprocess.run(
                ["git", "cat-file", "commit", "HEAD"],
                cwd=repo,
                env=env,
                check=True,
                capture_output=True,
            ).stdout
            headers, message = raw.split(b"\n\n", 1)
            tampered = headers + b"\n\n" + message + b"tampered\n"
            object_hash = subprocess.run(
                ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
                cwd=repo,
                env=env,
                input=tampered,
                check=True,
                capture_output=True,
            ).stdout.decode("ascii").strip()
            run(["git", "update-ref", "HEAD", object_hash], cwd=repo, env=env)
            log.write_text("", encoding="utf-8")
            result = run(["git", "verify-commit", "HEAD"], cwd=repo, env=env, check=False)
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            modes = [call[call.index("-Y") + 1] for call in calls if "-Y" in call]
            print(
                f"D7 tampered Ed25519 commit; exit={result.returncode}; calls={modes}; "
                f"stdout={result.stdout.strip()!r}; stderr={result.stderr.strip()!r}",
                flush=True,
            )
            if result.returncode == 0 or modes != ["find-principals", "verify"]:
                raise AssertionError(f"tampered Ed25519 commit result/calls invalid: {result}, {calls}")

        for command in (
            "verify-commit",
            "verify-tag",
            "log --show-signature",
            "merge --verify-signatures",
            "pull --verify-signatures",
        ):
            for state in ("trusted", "untrusted", "expired"):
                observe(state, command)
        observe_tampered_commit()


if __name__ == "__main__":
    main()
