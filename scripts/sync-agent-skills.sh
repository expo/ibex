#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sources_root="${IBEX_AGENT_SKILL_SOURCES:-$repo_root/.agent-skill-sources}"
skills_root="$repo_root/skills"
backup_root="$repo_root/.agent-skill-backups"

quiet=0
fetch=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet)
      quiet=1
      ;;
    --no-fetch)
      fetch=0
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/sync-agent-skills.sh [--quiet] [--no-fetch]

Clone or update the upstream skill repos and rebuild this repo's skills/
directory as symlinks to those managed clones.
USAGE
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ "${IBEX_AGENT_SKILLS_NO_NETWORK:-0}" = "1" ]; then
  fetch=0
fi

log() {
  if [ "$quiet" -eq 0 ]; then
    printf '%s\n' "$*" >&2
  fi
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

timestamp=""

backup_existing() {
  local path="$1"
  local label="$2"

  if [ -z "$timestamp" ]; then
    timestamp="$(date +%Y%m%d%H%M%S)"
  fi

  local backup="$backup_root/$timestamp/$label"
  mkdir -p "$(dirname "$backup")"
  mv "$path" "$backup"
  log "Moved existing $path to $backup"
}

ensure_repo() {
  local name="$1"
  local url="$2"
  local branch="$3"
  local dir="$sources_root/$name"

  mkdir -p "$sources_root"

  if [ ! -d "$dir/.git" ]; then
    if [ -e "$dir" ]; then
      die "$dir exists but is not a Git checkout"
    fi
    log "Cloning $url into $dir"
    git clone --depth 1 --branch "$branch" "$url" "$dir"
    return
  fi

  local current_url
  current_url="$(git -C "$dir" config --get remote.origin.url || true)"
  if [ "$current_url" != "$url" ]; then
    git -C "$dir" remote set-url origin "$url"
  fi

  if [ "$fetch" -eq 1 ]; then
    log "Updating $name from $url"
    git -C "$dir" fetch --prune origin "$branch"

    if git -C "$dir" show-ref --verify --quiet "refs/heads/$branch"; then
      git -C "$dir" switch "$branch" >/dev/null
    else
      git -C "$dir" switch -c "$branch" "origin/$branch" >/dev/null
    fi

    git -C "$dir" pull --ff-only origin "$branch"
  fi
}

replace_with_symlink() {
  local dest="$1"
  local target="$2"
  local label="$3"

  mkdir -p "$(dirname "$dest")"

  if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$target" ]; then
    return
  fi

  if [ -e "$dest" ] || [ -L "$dest" ]; then
    backup_existing "$dest" "$label"
  fi

  ln -s "$target" "$dest"
}

contains_name() {
  local needle="$1"
  shift
  local name
  for name in "$@"; do
    if [ "$name" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

ensure_repo "llp" "https://github.com/ccheever/llp.git" "main"
ensure_repo "skills" "https://github.com/ccheever/skills.git" "main"

mkdir -p "$skills_root"

managed_names=()

link_skill_dir() {
  local source_dir="$1"
  local name
  name="$(basename "$source_dir")"

  if [ ! -f "$source_dir/SKILL.md" ]; then
    return
  fi

  local source_rel="${source_dir#$repo_root/}"
  replace_with_symlink "$skills_root/$name" "../$source_rel" "skills/$name"
  managed_names+=("$name")
}

for source_dir in "$sources_root/llp/skills"/*; do
  [ -d "$source_dir" ] || continue
  link_skill_dir "$source_dir"
done

for source_dir in "$sources_root/skills"/*; do
  [ -d "$source_dir" ] || continue
  link_skill_dir "$source_dir"
done

for existing in "$skills_root"/*; do
  [ -L "$existing" ] || continue
  target="$(readlink "$existing")"
  case "$target" in
    ../.agent-skill-sources/*)
      name="$(basename "$existing")"
      if ! contains_name "$name" "${managed_names[@]}"; then
        rm "$existing"
        log "Removed stale managed skill link $existing"
      fi
      ;;
  esac
done

if [ "$quiet" -eq 0 ]; then
  printf 'Synced agent skills: %s\n' "${managed_names[*]}"
fi
