#!/usr/bin/env bash
# Smoke test for scripts/link-worktree-artifacts.sh.
# @ref LLP 0018#1-make-link-worktree-artifactssh-target-the-invoking-worktree-and-fail-loud-on-a-no-op
# Covers: fresh-worktree link-in via the primary's copy; the required-artifact-
# absent failure; the idempotent re-run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
script="$here/link-worktree-artifacts.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/link-wt-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

pass=0; fail=0
check() { if eval "$2"; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1"; fail=$((fail+1)); fi; }

# --- Case 1: fresh worktree links in via the PRIMARY's copy of the script. ----
# The destination must be the worktree the shell is in, not where the script
# file lives.
prim="$tmp/primary"
mkdir -p "$prim"
git -C "$prim" init -q
git -C "$prim" config user.email t@t; git -C "$prim" config user.name t
# ios/Frameworks and tools/hermes are git-IGNORED heavy artifacts — present only
# in the primary's working tree, absent from a fresh worktree checkout.
printf 'ios/\ntools/\n' > "$prim/.gitignore"
( cd "$prim" && git add -A && git commit -qm init )
mkdir -p "$prim/ios/Frameworks" "$prim/tools/hermes"
: > "$prim/ios/Frameworks/.keep"; : > "$prim/tools/hermes/.keep"
git -C "$prim" worktree add -q "$tmp/wt" -b feature 2>/dev/null

# Invoke the primary's script from inside the fresh worktree; it must resolve
# the destination from $PWD (the worktree), not from the script file location.
( cd "$tmp/wt" && bash "$script" ) >/dev/null 2>&1 || true
check "links into the fresh worktree, not the primary" \
  '[ -L "$tmp/wt/ios/Frameworks" ] && [ "$(cd "$tmp/wt/ios/Frameworks" && pwd -P)" = "$(cd "$prim/ios/Frameworks" && pwd -P)" ]'
check "primary is untouched (no self-link)" \
  '[ ! -L "$prim/ios/Frameworks" ]'

# --- Case 2: idempotent re-run stays exit 0. ---------------------------------
if ( cd "$tmp/wt" && bash "$script" ) >/dev/null 2>&1; then rc2=0; else rc2=$?; fi
check "idempotent re-run exits 0" '[ "$rc2" -eq 0 ]'

# --- Case 3: required artifact absent from source → nonzero + names it. -------
src2="$tmp/src2"; dst2="$tmp/dst2"
mkdir -p "$src2/ios/Frameworks" "$dst2"   # tools/hermes intentionally missing
if bash "$script" --dest "$dst2" "$src2" >"$tmp/out3" 2>&1; then rc3=0; else rc3=$?; fi
check "required-absent run exits nonzero" '[ "$rc3" -ne 0 ]'
check "failure message names the missing artifact" 'grep -q "tools/hermes" "$tmp/out3"'

echo "link-worktree-artifacts.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
