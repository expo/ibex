#!/usr/bin/env bash
# Symlink the heavy, git-ignored build artifacts from a warm primary checkout
# into this worktree so a fresh `git worktree add` can build and run generators
# without re-fetching or rebuilding them.
# @ref LLP 0017#3-standardize-timeout-and-directory-setup-on-build-machines —
# create required parent dirs (ios/, tools/) with mkdir -p before linking.
#
# Usage: scripts/link-worktree-artifacts.sh [SOURCE_CHECKOUT]
#   SOURCE_CHECKOUT defaults to the repository's main worktree.
#
# `target/` is intentionally NOT linked: sharing one Cargo target dir across
# worktrees lets concurrent builds contend or corrupt build products (LLP 0017
# item 4). Use an APFS clone of a warm target/ or sccache instead.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

# Artifacts to link, relative to a checkout root.
ARTIFACTS="ios/Frameworks tools/hermes node_modules"

resolve_dir() { ( cd "$1" 2>/dev/null && pwd -P ) || true; }

source_arg="${1:-}"
if [ -n "$source_arg" ]; then
  source_root="$(resolve_dir "$source_arg")"
  [ -n "$source_root" ] || { echo "error: source checkout '$source_arg' is not a directory" >&2; exit 1; }
else
  # Default to the main worktree (first entry of `git worktree list`).
  main_wt="$(git -C "$repo_root" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  source_root="$(resolve_dir "$main_wt")"
  [ -n "$source_root" ] || { echo "error: could not determine the main worktree; pass SOURCE_CHECKOUT explicitly" >&2; exit 1; }
fi

if [ "$source_root" = "$repo_root" ]; then
  echo "error: source checkout is this worktree ($repo_root); pass a different SOURCE_CHECKOUT" >&2
  exit 1
fi

linked=0
skipped=0
for rel in $ARTIFACTS; do
  src="$source_root/$rel"
  dest="$repo_root/$rel"

  if [ ! -e "$src" ]; then
    echo "skip $rel: not present in source ($src)" >&2
    skipped=$((skipped + 1))
    continue
  fi

  if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$src" ]; then
    skipped=$((skipped + 1))
    continue
  fi

  if [ -e "$dest" ] || [ -L "$dest" ]; then
    echo "skip $rel: already exists in this worktree (not overwriting)" >&2
    skipped=$((skipped + 1))
    continue
  fi

  mkdir -p "$(dirname "$dest")"
  ln -s "$src" "$dest"
  echo "linked $rel -> $src" >&2
  linked=$((linked + 1))
done

echo "Done: $linked linked, $skipped skipped (from $source_root)." >&2
