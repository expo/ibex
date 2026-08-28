#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skills_root="$repo_root/skills"

# @ref LLP 0017#1-make-agent-skill-sync-safe-by-default — installing skills must
# not silently re-enable the hidden hook-sync regime. Configuring
# core.hooksPath=.githooks is opt-in only, via --enable-hooks or
# IBEX_ENABLE_AGENT_SKILLS_SYNC=1.
enable_hooks=0
if [ "${IBEX_ENABLE_AGENT_SKILLS_SYNC:-0}" = "1" ]; then
  enable_hooks=1
fi

sync_args=""
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      cat <<'USAGE'
Usage: scripts/install-agent-skills.sh [--quiet] [--no-fetch] [--enable-hooks]

Sync upstream skills and link them into the supported local agent skill
directories.

By default this does NOT configure Git hooks. Pass --enable-hooks (or set
IBEX_ENABLE_AGENT_SKILLS_SYNC=1) to point core.hooksPath at .githooks so
checkouts/merges/rebases refresh skills automatically. Automatic sync can
fetch from the network and update managed skill source repos, so it is opt-in.
USAGE
      exit 0
      ;;
    --enable-hooks)
      enable_hooks=1
      ;;
    *)
      sync_args="$sync_args $arg"
      ;;
  esac
done

# shellcheck disable=SC2086 -- intentional word-splitting of collected flags.
"$repo_root/scripts/sync-agent-skills.sh" $sync_args

timestamp="$(date +%Y%m%d%H%M%S)"

log() {
  printf '%s\n' "$*" >&2
}

backup_existing() {
  local path="$1"
  local root="$2"
  local name="$3"
  local backup="$root/.ibex-agent-skill-backups/$timestamp/$name"

  mkdir -p "$(dirname "$backup")"
  mv "$path" "$backup"
  log "Moved existing $path to $backup"
}

link_skill_into_root() {
  local root="$1"
  local name="$2"
  local target="$3"
  local dest="$root/$name"

  mkdir -p "$root"

  if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$target" ]; then
    return
  fi

  if [ -e "$dest" ] || [ -L "$dest" ]; then
    backup_existing "$dest" "$root" "$name"
  fi

  ln -s "$target" "$dest"
}

# Remove links this script previously installed whose skill no longer exists —
# e.g. after an upstream source is dropped from sync-agent-skills.sh. Without
# this, install_root only ever adds, so a removed skill stays behind in every
# agent directory as a dangling link and the removal never reaches the machine.
# Deliberately narrow: only symlinks pointing into $skills_root, and only ones
# that no longer resolve. Anything else in these shared directories belongs to
# another project and is not ours to delete.
prune_root() {
  local root="$1"
  local dest target

  [ -d "$root" ] || return 0

  for dest in "$root"/*; do
    [ -L "$dest" ] || continue
    target="$(readlink "$dest")"
    case "$target" in
      "$skills_root"/*)
        if [ ! -e "$dest" ]; then
          rm "$dest"
          log "Removed stale skill link $dest (target $target no longer exists)"
        fi
        ;;
    esac
  done
}

install_root() {
  local label="$1"
  local root="$2"
  local skill_md
  local skill_name

  prune_root "$root"

  for skill_md in "$skills_root"/*/SKILL.md; do
    [ -e "$skill_md" ] || continue
    skill_name="$(basename "$(dirname "$skill_md")")"
    link_skill_into_root "$root" "$skill_name" "$skills_root/$skill_name"
  done

  log "Installed agent skill links for $label: $root"
}

# Fail loud before fanning out: installing zero skills into every agent's
# skill directory is a no-op that used to exit 0 (scripts/README.md fail-loud
# rule, ENG-23131). sync-agent-skills.sh guards its own link step; this guards
# an out-of-band emptied/restructured skills/ tree.
skill_count=0
for skill_md in "$skills_root"/*/SKILL.md; do
  [ -e "$skill_md" ] || continue
  skill_count=$((skill_count + 1))
done
if [ "$skill_count" -eq 0 ]; then
  printf 'error: no skills with a SKILL.md found under %s; nothing to install\n' "$skills_root" >&2
  exit 1
fi

claude_skills_dir="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
codex_home="${CODEX_HOME:-$HOME/.codex}"
cursor_skills_dir="${CURSOR_SKILLS_DIR:-$HOME/.cursor/skills}"
cursor_agent_skills_dir="${CURSOR_AGENT_SKILLS_DIR:-$HOME/.cursor/skills-cursor}"
pi_skills_dir="${PI_AGENT_SKILLS_DIR:-$HOME/.pi/agent/skills}"

install_root "Claude" "$claude_skills_dir"
install_root "Codex" "$codex_home/skills"
install_root "Cursor Agent" "$cursor_skills_dir"
install_root "Cursor managed skills" "$cursor_agent_skills_dir"
install_root "Pi Agent" "$pi_skills_dir"

# OpenCode reads Claude-compatible skills; avoid installing a second native
# copy by default because duplicate skill names across OpenCode search paths
# can produce duplicate entries.
if [ "${IBEX_INSTALL_OPENCODE_NATIVE:-0}" = "1" ]; then
  opencode_skills_dir="${OPENCODE_SKILLS_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills}"
  install_root "OpenCode native" "$opencode_skills_dir"
else
  log "Installed for OpenCode via Claude-compatible skills path: $claude_skills_dir"
fi

if [ "$enable_hooks" = "1" ]; then
  if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$repo_root" config core.hooksPath .githooks
    log "Configured Git hooks path: .githooks (automatic skill sync enabled)"
  fi
else
  log "Left Git hooks unchanged. Re-run with --enable-hooks (or set"
  log "IBEX_ENABLE_AGENT_SKILLS_SYNC=1) to enable automatic skill sync on checkout."
fi

log "Done. Restart running agents to reload skills."
