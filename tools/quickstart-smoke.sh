#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

export HOME="$tmp_root/home"
export XDG_CONFIG_HOME="$HOME/.config"
export GIT_CONFIG_GLOBAL="$tmp_root/gitconfig"
export GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME"

cargo build --release --locked --workspace
qsg="$repo_root/target/release/qsg"
shim="$repo_root/target/release/qsg-ssh-keygen"
test -x "$qsg"
test -x "$shim"

work="$tmp_root/repository"
mkdir -p "$work"
cd "$work"
git init
git config user.name "QSGit Quickstart"
git config user.email "quickstart@example.invalid"
printf 'baseline\n' > README.txt
git add README.txt
git -c commit.gpgsign=false commit -m "unsigned range baseline"
base="$(git rev-parse HEAD)"

"$qsg" keygen --no-passphrase
key="$XDG_CONFIG_HOME/qsgit/id_mldsa65"
pubkey="$key.pub"
allowed="$XDG_CONFIG_HOME/qsgit/allowed_signers"
"$qsg" trust add quickstart@example.invalid "$pubkey"

git config gpg.format ssh
git config gpg.ssh.program "$shim"
git config user.signingkey "$pubkey"
git config gpg.ssh.allowedSignersFile "$allowed"
git config commit.gpgsign true

printf 'signed commit\n' >> README.txt
git add README.txt
git commit -S -m "signed quickstart commit"
signed="$(git rev-parse HEAD)"
git verify-commit HEAD
"$qsg" verify --commit HEAD --allowed-signers "$allowed"
"$qsg" verify-range "$base..$signed" --allowed-signers "$allowed" --fail-on-empty
"$qsg" doctor

printf 'unsigned commit\n' >> README.txt
git add README.txt
git -c commit.gpgsign=false commit -m "unsigned negative case"
if "$qsg" verify-range "$signed..HEAD" --allowed-signers "$allowed" --fail-on-empty; then
    echo "expected verify-range to reject the unsigned commit" >&2
    exit 1
fi
echo "quickstart smoke passed, including unsigned-commit rejection"

