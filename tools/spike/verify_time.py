#!/usr/bin/env python3
"""Observe Git's -Overify-time argument using a fake gpg.ssh.program."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import platform

EPOCH = 1_735_689_600  # 2025-01-01 00:00:00 UTC
OFFSETS = ["+0000", "+0530", "-0800"]
ZONES = ["UTC", "Asia/Kolkata", "America/Los_Angeles"]
ARMOR = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"


def run(args, *, cwd=None, env=None, check=True):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args[0]}\n{result.stderr}")
    return result


def make_wrappers(directory):
    helper = directory / "wrapper.py"
    helper.write_text(
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['QSG_VERIFY_TIME_LOG'], 'a', encoding='utf-8') as f: f.write(json.dumps(args) + '\\n')\n"
        "mode = args[args.index('-Y') + 1] if '-Y' in args else ''\n"
        "if mode == 'sign': pathlib.Path(args[-1] + '.sig').write_text(" + repr(ARMOR) + ", encoding='ascii'); sys.exit(0)\n"
        "if mode == 'find-principals': print('m4-time-test@example.test'); sys.exit(0)\n"
        "if mode == 'verify': print('Good \\\"git\\\" signature for m4-time-test@example.test with ssh-mldsa65@qsgit key SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); sys.exit(0)\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        command = directory / "wrapper.cmd"
        command.write_text(f'@echo off\r\n"{sys.executable}" "{helper}" %*\r\n', encoding="ascii")
    else:
        command = directory / "wrapper.sh"
        command.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{helper}" "$@"\n', encoding="utf-8")
        command.chmod(0o755)
    return command


def expected_local(epoch, zone):
    if zone:
        from zoneinfo import ZoneInfo

        value = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).astimezone(ZoneInfo(zone))
    else:
        value = dt.datetime.fromtimestamp(epoch).astimezone()
    return value.strftime("%Y%m%d%H%M%S")


def scenarios():
    if sys.platform in ("linux", "darwin"):
        return [(offset, zone) for offset in OFFSETS for zone in ZONES]
    return [(offset, None) for offset in OFFSETS]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if observed output differs from local-time/no-Z behavior")
    args = parser.parse_args()
    git_version = run(["git", "--version"]).stdout.strip()
    print(f"Git verify-time experiment: {git_version}; OS={platform.system()} {platform.release()}; arch={platform.machine()}")
    with tempfile.TemporaryDirectory(prefix="qsg-verify-time-") as temp:
        root = Path(temp)
        wrapper = make_wrappers(root)
        for offset, zone in scenarios():
            safe_zone = (zone or "local").replace("/", "_")
            repo = root / f"repo-{offset.replace('+', 'p').replace('-', 'm')}-{safe_zone}"
            repo.mkdir()
            run(["git", "init", "-q", str(repo)])
            run(["git", "config", "user.name", "M4 time test"], cwd=repo)
            run(["git", "config", "user.email", "m4-time-test@example.test"], cwd=repo)
            run(["git", "config", "gpg.format", "ssh"], cwd=repo)
            run(["git", "config", "gpg.ssh.program", str(wrapper)], cwd=repo)
            run(["git", "config", "gpg.ssh.allowedSignersFile", str(repo / "allowed_signers")], cwd=repo)
            run(["git", "config", "user.signingkey", str(repo / "dummy-key")], cwd=repo)
            (repo / "allowed_signers").write_text("test namespaces=\"git\" ssh-ed25519 AAAA\n", encoding="ascii")
            (repo / "dummy-key").write_text("not a real key; wrapper ignores it\n", encoding="ascii")
            (repo / "content.txt").write_text("time experiment\n", encoding="ascii")
            run(["git", "add", "content.txt"], cwd=repo)
            log = repo / "wrapper-args.jsonl"
            env = os.environ.copy()
            env["QSG_VERIFY_TIME_LOG"] = str(log)
            if zone:
                env["TZ"] = zone
            else:
                env.pop("TZ", None)
            author_offset = OFFSETS[(OFFSETS.index(offset) + 1) % len(OFFSETS)]
            env["GIT_AUTHOR_DATE"] = f"@{EPOCH} {author_offset}"
            env["GIT_COMMITTER_DATE"] = f"@{EPOCH} {offset}"
            run(["git", "commit", "-q", "-S", "-m", f"offset {offset} zone {zone or 'local'}"], cwd=repo, env=env)
            run(["git", "verify-commit", "HEAD"], cwd=repo, env=env)
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            values = [arg.partition("=")[2] for call in calls for arg in call if arg.startswith("-Overify-time=")]
            expected = expected_local(EPOCH, zone)
            if not values:
                raise RuntimeError("Git did not pass an -Overify-time argument")
            print(f"author-offset={author_offset}; committer-offset={offset}; machine-TZ={zone or 'system-local'}; verify-time={values}; expected-local={expected}")
            if args.check and any(value != expected or value.endswith("Z") for value in values):
                raise RuntimeError(f"unexpected verify-time for offset={offset}, TZ={zone}: {values}, expected {expected} without Z")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"verify-time experiment failed: {error}", file=sys.stderr)
        sys.exit(1)
