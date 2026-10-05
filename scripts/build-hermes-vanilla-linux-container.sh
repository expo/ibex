#!/usr/bin/env bash

# Run the canonical Linux release builder in the same pinned Debian/Rust
# container profile used by the ICU 74 filtering spike.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"

[[ $# -eq 2 ]] || {
  echo 'usage: scripts/build-hermes-vanilla-linux-container.sh <target> <archive.tar.gz>' >&2
  exit 2
}
target="$1"
output_archive="$2"
case "$target" in
  aarch64-unknown-linux-gnu) platform=linux/arm64 ;;
  x86_64-unknown-linux-gnu) platform=linux/amd64 ;;
  *) echo "unsupported Linux container target: $target" >&2; exit 2 ;;
esac
case "$output_archive" in
  /*) ;;
  *) echo "output archive must be absolute: $output_archive" >&2; exit 2 ;;
esac
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 1; }

output_dir="$(dirname "$output_archive")"
output_name="$(basename "$output_archive")"
cache_dir="${IBEX_HERMES_LINUX_CONTAINER_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ibex/hermes-vanilla-linux-container}"
staging_dir="$cache_dir/output"
staging_name=".$output_name.$$"
staging_archive="$staging_dir/$staging_name"
mkdir -p "$output_dir" "$staging_dir"
[[ ! -e "$staging_archive" ]] \
  || { echo "staged Linux bundle already exists: $staging_archive" >&2; exit 1; }

docker run --rm --platform "$platform" \
  -v "$repo_root:/repo:ro" \
  -v "$staging_dir:/out" \
  -v "$cache_dir:/cache" \
  -e IBEX_HERMES_RELEASE_CACHE_DIR=/cache/release \
  -e IBEX_HERMES_SOURCE_BUILD_LOCK_FILE=/cache/source-build.lock \
  rust:1.97-bookworm \
  bash /repo/scripts/build-hermes-vanilla-linux-in-container.sh \
    "$target" "/out/$staging_name"

[[ -s "$staging_archive" ]] \
  || { echo "Linux container did not produce $staging_archive" >&2; exit 1; }
mv "$staging_archive" "$output_archive"
printf 'copied Linux bundle to %s\n' "$output_archive"
