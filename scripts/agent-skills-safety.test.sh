#!/usr/bin/env bash
# Smoke test for the agent-skill-sync safety guarantees.
# @ref LLP 0017#1-make-agent-skill-sync-safe-by-default — regression coverage for
# the acceptance criteria: a hook/sync run can never mutate the enclosing repo's
# remote, and the installer never enables hooks without an explicit opt-in.
#
# Runs fully offline (every case passes --no-fetch or exercises a path that
# refuses before any network op). Exits nonzero on the first failed assertion.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

work="$(mktemp -d "${TMPDIR:-/tmp}/ibex-skills-safety.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

pass=0
fail=0
ok()  { printf 'ok   - %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf 'FAIL - %s\n' "$*"; fail=$((fail + 1)); }

SENTINEL_ORIGIN="https://example.invalid/original-repo.git"

# Build an isolated stand-in for an Ibex checkout: a Git repo with a known
# origin, carrying copies of the shipped scripts and hooks so we test the real
# code with repo_root pointed at the sandbox (never the live repo).
make_outer() {
  local outer="$work/$1"
  mkdir -p "$outer/scripts" "$outer/.githooks"
  git -C "$outer" init -q
  git -C "$outer" remote add origin "$SENTINEL_ORIGIN"
  cp "$repo_root/scripts/sync-agent-skills.sh" "$outer/scripts/"
  cp "$repo_root/scripts/install-agent-skills.sh" "$outer/scripts/"
  cp "$repo_root/.githooks/post-checkout" "$outer/.githooks/"
  chmod +x "$outer/scripts/"*.sh "$outer/.githooks/post-checkout"
  printf '%s' "$outer"
}

origin_of() { git -C "$1" config --get remote.origin.url || true; }

# --- Case 1: hook is a no-op without opt-in --------------------------------
outer="$(make_outer case1)"
env -u IBEX_ENABLE_AGENT_SKILLS_SYNC -u IBEX_SKIP_AGENT_SKILLS_SYNC \
  "$outer/.githooks/post-checkout" >/dev/null 2>&1
if [ ! -e "$outer/.agent-skill-sources" ] && [ "$(origin_of "$outer")" = "$SENTINEL_ORIGIN" ]; then
  ok "post-checkout hook no-ops without IBEX_ENABLE_AGENT_SKILLS_SYNC"
else
  bad "post-checkout hook ran or mutated remote without opt-in"
fi

# --- Case 2: absent sources + no network mutates nothing -------------------
outer="$(make_outer case2)"
IBEX_AGENT_SKILL_SOURCES="$outer/.agent-skill-sources" \
  "$outer/scripts/sync-agent-skills.sh" --quiet --no-fetch >/dev/null 2>&1 || true
if [ "$(origin_of "$outer")" = "$SENTINEL_ORIGIN" ]; then
  ok "no-network sync with absent sources leaves origin untouched"
else
  bad "no-network sync changed origin (got $(origin_of "$outer"))"
fi

# --- Case 3: non-repo source dir (upward .git discovery) is refused --------
# A present-but-not-a-repo source dir makes `git -C "$dir"` walk up to the
# enclosing repo. The guard must die before any remote mutation.
outer="$(make_outer case3)"
mkdir -p "$outer/.agent-skill-sources/llp"
printf 'not a repo\n' > "$outer/.agent-skill-sources/llp/marker"
if IBEX_AGENT_SKILL_SOURCES="$outer/.agent-skill-sources" \
     "$outer/scripts/sync-agent-skills.sh" --quiet --no-fetch >/dev/null 2>&1; then
  bad "sync did not refuse a non-repo managed source dir"
elif [ "$(origin_of "$outer")" = "$SENTINEL_ORIGIN" ]; then
  ok "non-repo managed source dir is refused; enclosing origin preserved"
else
  bad "non-repo managed source dir corrupted enclosing origin (got $(origin_of "$outer"))"
fi

# --- Case 4: gitdir redirected at the enclosing repo is refused ------------
# A crafted `.git` file points the source dir's git-dir at the enclosing repo,
# so `--show-toplevel` looks local but mutations would hit the outer config.
outer="$(make_outer case4)"
mkdir -p "$outer/.agent-skill-sources/llp"
printf 'gitdir: %s\n' "$outer/.git" > "$outer/.agent-skill-sources/llp/.git"
if IBEX_AGENT_SKILL_SOURCES="$outer/.agent-skill-sources" \
     "$outer/scripts/sync-agent-skills.sh" --quiet --no-fetch >/dev/null 2>&1; then
  bad "sync did not refuse a gitdir-redirected managed source dir"
elif [ "$(origin_of "$outer")" = "$SENTINEL_ORIGIN" ]; then
  ok "gitdir-redirected managed source is refused; enclosing origin preserved"
else
  bad "gitdir-redirected managed source changed enclosing origin (got $(origin_of "$outer"))"
fi

# --- Case 5: installer does not enable hooks without opt-in ----------------
outer="$(make_outer case5)"
env -u IBEX_ENABLE_AGENT_SKILLS_SYNC \
  IBEX_AGENT_SKILL_SOURCES="$outer/.agent-skill-sources" \
  CLAUDE_SKILLS_DIR="$work/case5-claude" \
  CODEX_HOME="$work/case5-codex" \
  CURSOR_SKILLS_DIR="$work/case5-cursor" \
  CURSOR_AGENT_SKILLS_DIR="$work/case5-cursor2" \
  PI_AGENT_SKILLS_DIR="$work/case5-pi" \
  "$outer/scripts/install-agent-skills.sh" --quiet --no-fetch >/dev/null 2>&1 || true
if [ "$(git -C "$outer" config --get core.hooksPath || true)" != ".githooks" ]; then
  ok "installer leaves core.hooksPath unset without --enable-hooks/opt-in"
else
  bad "installer enabled core.hooksPath=.githooks without opt-in"
fi

# --- Case 6: installer WITH opt-in flag enables hooks ----------------------
outer="$(make_outer case6)"
env -u IBEX_ENABLE_AGENT_SKILLS_SYNC \
  IBEX_AGENT_SKILL_SOURCES="$outer/.agent-skill-sources" \
  CLAUDE_SKILLS_DIR="$work/case6-claude" \
  CODEX_HOME="$work/case6-codex" \
  CURSOR_SKILLS_DIR="$work/case6-cursor" \
  CURSOR_AGENT_SKILLS_DIR="$work/case6-cursor2" \
  PI_AGENT_SKILLS_DIR="$work/case6-pi" \
  "$outer/scripts/install-agent-skills.sh" --quiet --no-fetch --enable-hooks >/dev/null 2>&1 || true
if [ "$(git -C "$outer" config --get core.hooksPath || true)" = ".githooks" ]; then
  ok "installer enables core.hooksPath=.githooks with --enable-hooks"
else
  bad "installer did not enable hooks even with --enable-hooks"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
