#!/usr/bin/env bash
# Symlink the heavy, git-ignored build artifacts from a warm primary checkout
# into THIS worktree so a fresh `git worktree add` can build and run generators
# without re-fetching or rebuilding them.
# @ref LLP 0018#1-make-link-worktree-artifactssh-target-the-invoking-worktree-and-fail-loud-on-a-no-op
# @ref LLP 0017#3-standardize-timeout-and-directory-setup-on-build-machines —
# create required parent dirs (ios/, tools/) with mkdir -p before linking.
#
# Usage: scripts/link-worktree-artifacts.sh [--dest DIR] [--require a,b,...] [SOURCE]
#   The DESTINATION is the worktree you are populating — by default the worktree
#   this shell is in (`git rev-parse --show-toplevel`), NOT where this script
#   file lives. Run the warm primary's copy from inside a fresh worktree and it
#   links into the fresh worktree. Override with --dest DIR.
#   SOURCE is the warm checkout to link FROM; it defaults to the primary
#   (first `git worktree list` entry) of the destination's repository.
#
#   --require a,b   Override the required-artifact set (default: ios/Frameworks,
#                   tools/hermes). A required artifact absent from SOURCE, or
#                   still absent from the DESTINATION after linking, is a hard
#                   error — the script asserts its postcondition and exits
#                   nonzero rather than reporting "0 linked" as success.
#
# `target/` is intentionally NOT linked: sharing one Cargo target dir across
# worktrees lets concurrent builds contend or corrupt build products (LLP 0017
# item 4). Use scripts/warm-worktree.sh --clone-target or sccache instead.
set -euo pipefail

# Required build postconditions vs optional convenience links. A missing
# required artifact makes cargo die later on a missing Hermes framework; a
# missing optional artifact (node_modules) is merely inconvenient.
REQUIRED_DEFAULT="ios/Frameworks tools/hermes"
OPTIONAL_ARTIFACTS="node_modules"

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

resolve_dir() { ( cd "$1" 2>/dev/null && pwd -P ) || true; }

dest_arg=""
source_arg=""
required_arg=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dest) dest_arg="${2:-}"; shift 2 ;;
    --dest=*) dest_arg="${1#--dest=}"; shift ;;
    --require) required_arg="${2:-}"; shift 2 ;;
    --require=*) required_arg="${1#--require=}"; shift ;;
    --) shift; break ;;
    -*) echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    *) source_arg="$1"; shift ;;
  esac
done
[ "$#" -gt 0 ] && [ -z "$source_arg" ] && { source_arg="$1"; shift; }

# --- Resolve the DESTINATION from the invocation, not from BASH_SOURCE. -------
if [ -n "$dest_arg" ]; then
  dest_root="$(resolve_dir "$dest_arg")"
  [ -n "$dest_root" ] || { echo "error: --dest '$dest_arg' is not a directory" >&2; exit 1; }
else
  dest_root="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null || true)"
  [ -n "$dest_root" ] || dest_root="$(pwd -P)"
fi

# --- Resolve the SOURCE (warm primary), anchored to the destination's repo. --
if [ -n "$source_arg" ]; then
  source_root="$(resolve_dir "$source_arg")"
  [ -n "$source_root" ] || { echo "error: source checkout '$source_arg' is not a directory" >&2; exit 1; }
else
  main_wt="$(git -C "$dest_root" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  source_root="$(resolve_dir "$main_wt")"
  [ -n "$source_root" ] || { echo "error: could not determine the warm primary worktree; pass SOURCE explicitly" >&2; exit 1; }
fi

if [ "$source_root" = "$dest_root" ]; then
  echo "error: source and destination are the same worktree ($dest_root)." >&2
  echo "       Run this from inside the worktree you want to populate, or pass --dest / a SOURCE." >&2
  exit 1
fi

# Split the artifact list into required (asserted) and optional (best-effort).
required_set="${required_arg:-$REQUIRED_DEFAULT}"
required_set="${required_set//,/ }"

link_one() {
  # link_one REL -> prints action to stderr; returns 0 if present at dest after.
  local rel="$1" src="$source_root/$1" dest="$dest_root/$1"

  if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$src" ]; then
    return 0  # already linked to this source — idempotent, in desired state.
  fi
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    echo "skip $rel: already exists in destination (not overwriting)" >&2
    [ -e "$dest" ]; return
  fi
  if [ ! -e "$src" ]; then
    echo "skip $rel: not present in source ($src)" >&2
    return 1
  fi
  mkdir -p "$(dirname "$dest")"
  ln -s "$src" "$dest"
  echo "linked $rel -> $src" >&2
  [ -e "$dest" ]
}

linked=0
missing_required=()

for rel in $required_set; do
  if link_one "$rel"; then
    linked=$((linked + 1))
  else
    missing_required+=("$rel")
  fi
done

for rel in $OPTIONAL_ARTIFACTS; do
  # Optional links: nice to have, never fatal.
  if link_one "$rel"; then
    linked=$((linked + 1))
  else
    echo "note: optional artifact '$rel' not linked (source or dest unavailable)" >&2
  fi
done

echo "Done: $linked linked into $dest_root (from $source_root)." >&2

# --- Assert the postcondition: every REQUIRED artifact exists at the dest. ---
if [ "${#missing_required[@]}" -gt 0 ]; then
  echo >&2
  echo "error: required build artifact(s) still absent at destination after linking:" >&2
  for rel in "${missing_required[@]}"; do
    if [ ! -e "$source_root/$rel" ]; then
      echo "  - $rel (missing from SOURCE $source_root/$rel — nothing to link; warm the primary first)" >&2
    else
      echo "  - $rel (present in source but not linked at $dest_root/$rel)" >&2
    fi
  done
  echo >&2
  echo "A fresh worktree without these will fail its native build later on a missing Hermes framework." >&2
  exit 1
fi
