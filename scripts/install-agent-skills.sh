#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skills_root="$repo_root/skills"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'USAGE'
Usage: scripts/install-agent-skills.sh [--quiet] [--no-fetch]

Sync upstream skills, link them into the supported local agent skill
directories, and configure this checkout's Git hooks to keep them refreshed.
USAGE
  exit 0
fi

"$repo_root/scripts/sync-agent-skills.sh" "$@"

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

install_root() {
  local label="$1"
  local root="$2"
  local skill_md
  local skill_name

  for skill_md in "$skills_root"/*/SKILL.md; do
    [ -e "$skill_md" ] || continue
    skill_name="$(basename "$(dirname "$skill_md")")"
    link_skill_into_root "$root" "$skill_name" "$skills_root/$skill_name"
  done

  log "Installed agent skill links for $label: $root"
}

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

if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$repo_root" config core.hooksPath .githooks
  log "Configured Git hooks path: .githooks"
fi

log "Done. Restart running agents to reload skills."
