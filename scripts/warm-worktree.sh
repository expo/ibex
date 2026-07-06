#!/usr/bin/env bash
# Warm a fresh worktree for native builds: link the git-ignored artifacts and,
# optionally, seed a PER-WORKTREE target/ by APFS-cloning a warm one.
# @ref LLP 0018#3-wire-up-a-native-build-cache-by-default-safely
#
# Usage: scripts/warm-worktree.sh [--dest DIR] [--source SRC] [--clone-target]
#   Links ios/Frameworks + tools/hermes (+ node_modules) via
#   link-worktree-artifacts.sh, then with --clone-target APFS `cp -c`-clones the
#   SOURCE's target/ into this worktree as its OWN target/ (a copy, never a
#   shared symlink — LLP 0017 item 4 forbids a shared mutable Cargo target dir).
#
#   sccache is the primary, always-safe cross-worktree cache (see
#   scripts/check-build-machine.sh); --clone-target is the fallback that gives a
#   cold worktree a warm starting point without re-doing ~40s of compilation.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

dest_arg=""
source_arg=""
clone_target=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --dest) dest_arg="${2:-}"; shift 2 ;;
    --dest=*) dest_arg="${1#--dest=}"; shift ;;
    --source) source_arg="${2:-}"; shift 2 ;;
    --source=*) source_arg="${1#--source=}"; shift ;;
    --clone-target) clone_target=1; shift ;;
    *) echo "error: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

# Resolve dest/source the same way the linker does.
if [ -n "$dest_arg" ]; then
  dest_root="$(cd "$dest_arg" && pwd -P)"
else
  dest_root="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null || pwd -P)"
fi
if [ -n "$source_arg" ]; then
  source_root="$(cd "$source_arg" && pwd -P)"
else
  main_wt="$(git -C "$dest_root" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  source_root="$(cd "$main_wt" && pwd -P)"
fi

# 1) Link the required artifacts (fails loud if a required one is unmet).
link_args=(--dest "$dest_root")
[ -n "$source_arg" ] && link_args+=("$source_root")
"$here/link-worktree-artifacts.sh" "${link_args[@]}"

# 2) Optionally seed a per-worktree target/ via an APFS clone.
if [ "$clone_target" -eq 1 ]; then
  src_target="$source_root/target"
  dst_target="$dest_root/target"
  if [ ! -d "$src_target" ]; then
    echo "error: --clone-target: no warm target/ at $src_target to clone" >&2
    exit 1
  fi
  if [ -e "$dst_target" ]; then
    echo "error: --clone-target: $dst_target already exists; refusing to overwrite." >&2
    echo "       Remove it first if you really want a fresh clone." >&2
    exit 1
  fi
  echo "cloning warm target/ (APFS cp -c) $src_target -> $dst_target ..." >&2
  # cp -c requests an APFS clonefile (copy-on-write): near-instant, no extra disk
  # until the new worktree's build diverges. It is a real per-worktree copy, so
  # concurrent Cargo writers never contend (unlike a shared CARGO_TARGET_DIR).
  if ! cp -c -R "$src_target" "$dst_target" 2>/dev/null; then
    echo "error: APFS clone failed (is this an APFS volume?). Falling back is unsafe;" >&2
    echo "       prefer sccache instead of a plain copy. See scripts/check-build-machine.sh." >&2
    exit 1
  fi
  echo "done: per-worktree target/ seeded at $dst_target" >&2
fi
