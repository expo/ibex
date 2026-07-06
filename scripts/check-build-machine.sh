#!/usr/bin/env bash
# Report every unmet agent-run precondition on THIS build machine, with its fix,
# and exit nonzero if any REQUIRED one is missing — so a fresh host is provably
# ready, not discovered-broken mid-ticket.
# @ref LLP 0018#4-establish-a-build-machine-bootstrap-checklist-and-close-the-timeout-gap
#
# Usage: scripts/check-build-machine.sh
#   Checks (required): a timeout binary (coreutils), the git hooks safe-default
#   state (LLP 0017), and cargo. Checks (recommended): sccache + its env, bun.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$here" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$repo_root" ] || repo_root="$(cd "$here/.." && pwd -P)"

fail=0
ok()   { printf '  ok    %s\n' "$1"; }
warn() { printf '  WARN  %s\n    → %s\n' "$1" "$2"; }
bad()  { printf '  FAIL  %s\n    → %s\n' "$1" "$2"; fail=1; }

echo "Build-machine precondition check ($repo_root)"
echo
echo "Required:"

# 1) A timeout binary, exercised THROUGH the wrapper agents actually call.
if "$here/with-timeout.sh" 1 true >/dev/null 2>&1; then
  ok "timeout wrapper works (timeout/gtimeout present)"
else
  bad "scripts/with-timeout.sh has no timeout binary" \
      "macOS: brew install coreutils (gtimeout); Linux: install coreutils"
fi

# 2) Git hooks in the LLP 0017 safe-by-default state (no networked side effects).
hookspath="$(git -C "$repo_root" config core.hooksPath || true)"
if [ "$hookspath" = ".githooks" ] && [ -x "$repo_root/.githooks/post-checkout" ]; then
  ok "git hooks point at .githooks (skill sync opt-in, LLP 0017)"
else
  bad "git core.hooksPath is not the safe .githooks set (got '${hookspath:-unset}')" \
      "run: git config core.hooksPath .githooks"
fi

# 3) cargo (the native toolchain).
if command -v cargo >/dev/null 2>&1; then
  ok "cargo present ($(cargo --version 2>/dev/null))"
else
  bad "cargo not found" "install Rust via https://rustup.rs"
fi

echo
echo "Recommended (speed / regeneration):"

# sccache is the write-safe cross-worktree compiler cache (LLP 0018 item 3).
if command -v sccache >/dev/null 2>&1; then
  ok "sccache present ($(sccache --version 2>/dev/null | head -1))"
  [ "${RUSTC_WRAPPER:-}" = "sccache" ] || warn "RUSTC_WRAPPER is not 'sccache'" \
      "export RUSTC_WRAPPER=sccache to dedupe compilation across worktrees"
  [ -n "${SCCACHE_DIR:-}" ] || warn "SCCACHE_DIR is unset" \
      "export a persistent SCCACHE_DIR so the cache survives across runs"
else
  warn "sccache not installed" \
      "brew install sccache (or cargo install sccache), then export RUSTC_WRAPPER=sccache + SCCACHE_DIR"
fi

# bun is needed only to REGENERATE vendored artifacts, not for a hermetic build.
if command -v bun >/dev/null 2>&1; then
  ok "bun present (needed for regenerate:vendored / check:drift)"
else
  warn "bun not installed" "needed only to regenerate vendored artifacts; a hermetic build does not require it"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "RESULT: NOT READY — fix the FAIL items above." >&2
  exit 1
fi
echo "RESULT: ready (required preconditions met)."
