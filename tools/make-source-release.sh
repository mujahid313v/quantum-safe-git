#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: tools/make-source-release.sh <tag> [outdir]" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
tag="$1"
outdir="${2:-.}"

if [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+)$ ]]; then
    version="${BASH_REMATCH[1]}"
else
    echo "error: expected a release-candidate tag such as v0.1.0-rc.1" >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if ! git show-ref --verify --quiet "refs/tags/$tag"; then
    echo "error: tag does not exist: $tag" >&2
    exit 1
fi
if ! git rev-parse --verify "${tag}^{commit}" >/dev/null 2>&1; then
    echo "error: tag does not resolve to a commit: $tag" >&2
    exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "error: working tree must be clean" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_tool="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    hash_tool="shasum"
else
    echo "error: need sha256sum or shasum -a 256" >&2
    exit 1
fi

hash_file() {
    if [[ "$hash_tool" == "sha256sum" ]]; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

archive_name="qsgit-$version-source.tar.gz"
prefix="qsgit-$version"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

git archive --format=tar --prefix="$prefix/" "$tag" | gzip -n > "$tmp_dir/archive-first.tar.gz"
git archive --format=tar --prefix="$prefix/" "$tag" | gzip -n > "$tmp_dir/archive-second.tar.gz"
first_hash="$(hash_file "$tmp_dir/archive-first.tar.gz")"
second_hash="$(hash_file "$tmp_dir/archive-second.tar.gz")"
if [[ "$first_hash" != "$second_hash" ]]; then
    echo "error: source archive is not reproducible" >&2
    exit 1
fi

mkdir -p "$outdir"
cp "$tmp_dir/archive-first.tar.gz" "$outdir/$archive_name"
printf '%s  %s\n' "$first_hash" "$archive_name" > "$outdir/SHA256SUMS"
printf 'first archive hash:  %s\n' "$first_hash"
printf 'second archive hash: %s\n' "$second_hash"
printf 'wrote %s and %s/SHA256SUMS\n' "$outdir/$archive_name" "$outdir"
