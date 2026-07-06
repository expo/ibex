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

# Physical (symlink-resolved) absolute path of an existing directory, or empty.
# @ref LLP 0017#1-make-agent-skill-sync-safe-by-default — never mutate a Git
# repo we cannot prove is a managed source checkout under $sources_root.
resolve_dir() {
  ( cd "$1" 2>/dev/null && pwd -P ) || true
}

repo_root_real="$(resolve_dir "$repo_root")"
sources_root_real=""

# Prove $dir is exactly the managed source checkout for a skill upstream before
# any mutating Git command runs against it. This defeats two escapes that let a
# `git -C "$dir" …` mutation land on the *Ibex* repository's shared config:
#   1. upward .git discovery — $dir is not itself a repo, so Git walks up to the
#      enclosing Ibex worktree;
#   2. gitdir redirection — a crafted `$dir/.git` file/worktree points its
#      git-dir at another repository (e.g. Ibex).
# Refuse unless the working-tree top-level AND the git-dir both resolve inside
# $dir, and $dir itself resolves strictly under $sources_root (never the Ibex
# worktree). See LLP 0017 acceptance criteria for the covered cases.
assert_managed_source_repo() {
  local dir="$1"
  local dir_real toplevel toplevel_real gitdir gitdir_real common common_real

  dir_real="$(resolve_dir "$dir")"
  [ -n "$dir_real" ] || die "managed source $dir is not a directory"

  if [ -z "$sources_root_real" ]; then
    sources_root_real="$(resolve_dir "$sources_root")"
    [ -n "$sources_root_real" ] || die "sources root $sources_root does not resolve to a directory"
  fi

  case "$dir_real/" in
    "$sources_root_real"/*) ;;
    *) die "refusing to touch $dir: resolves to $dir_real, outside managed sources root $sources_root_real" ;;
  esac

  if [ -n "$repo_root_real" ] && [ "$dir_real" = "$repo_root_real" ]; then
    die "refusing to touch $dir: resolves to the Ibex repo root $repo_root_real"
  fi

  toplevel="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" \
    || die "refusing to touch $dir: not a Git repository"
  toplevel_real="$(resolve_dir "$toplevel")"
  if [ "$toplevel_real" != "$dir_real" ]; then
    die "refusing to touch $dir: Git top-level is $toplevel_real, not the managed source dir $dir_real"
  fi

  gitdir="$(git -C "$dir" rev-parse --absolute-git-dir 2>/dev/null)" \
    || die "refusing to touch $dir: cannot resolve its Git directory"
  gitdir_real="$(resolve_dir "$gitdir")"
  common="$( ( cd "$dir" && git rev-parse --git-common-dir 2>/dev/null ) || true )"
  common_real="$( ( cd "$dir" && cd "$common" 2>/dev/null && pwd -P ) || true )"
  local g
  for g in "$gitdir_real" "$common_real"; do
    [ -n "$g" ] || die "refusing to touch $dir: cannot resolve its Git directory"
    case "$g/" in
      "$dir_real"/*) ;;
      *) die "refusing to touch $dir: Git dir $g is redirected outside the managed source dir $dir_real" ;;
    esac
  done
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

  # Clone path (directory absent): a fresh clone into $dir cannot mutate any
  # existing repository, so no identity proof is required — but it does touch
  # the network, so honor no-network mode.
  if [ ! -e "$dir" ]; then
    if [ "$fetch" -eq 0 ]; then
      log "Skipping clone of $name ($dir absent, network disabled)"
      return
    fi
    log "Cloning $url into $dir"
    git clone --depth 1 --branch "$branch" "$url" "$dir"
    return
  fi

  # Update path (directory present): every subsequent Git command runs against
  # $dir with `git -C`, so prove $dir is exactly the managed source checkout
  # before ANY mutation. Without this, a non-repo / redirected $dir lets the
  # mutations below land on the enclosing Ibex worktree's shared config.
  assert_managed_source_repo "$dir"

  # Non-network mode is read-only: skip both the remote repair and the fetch.
  if [ "$fetch" -eq 0 ]; then
    log "Leaving $name untouched ($dir present, network disabled)"
    return
  fi

  local current_url
  current_url="$(git -C "$dir" config --get remote.origin.url || true)"
  if [ "$current_url" != "$url" ]; then
    git -C "$dir" remote set-url origin "$url"
  fi

  log "Updating $name from $url"
  git -C "$dir" fetch --prune origin "$branch"

  if git -C "$dir" show-ref --verify --quiet "refs/heads/$branch"; then
    git -C "$dir" switch "$branch" >/dev/null
  else
    git -C "$dir" switch -c "$branch" "origin/$branch" >/dev/null
  fi

  git -C "$dir" pull --ff-only origin "$branch"
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

  # Build the link target from physically resolved paths: a literal
  # env/TMPDIR string (double slash, symlinked temp dir) used to defeat the
  # naive prefix strip and mint a broken "../<absolute-path>" link that still
  # counted as synced (ENG-23131). Sources under the repo root get a relative
  # link; an external IBEX_AGENT_SKILL_SOURCES tree gets an absolute one.
  local source_real target
  source_real="$(resolve_dir "$source_dir")"
  [ -n "$source_real" ] || die "skill source $source_dir does not resolve to a directory"
  case "$source_real/" in
    "$repo_root_real"/*) target="../${source_real#"$repo_root_real"/}" ;;
    *) target="$source_real" ;;
  esac
  replace_with_symlink "$skills_root/$name" "$target" "skills/$name"
  # Postcondition: the created link must resolve — a "successful" sync over
  # broken links is the silent no-op this script must never report.
  [ -e "$skills_root/$name" ] || die "skill link $skills_root/$name is broken (target $target)"
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

# Zero skills linked means the sync did not do its one job — absent sources
# (e.g. no-network mode before any clone) or an upstream restructure that left
# no SKILL.md matches. Exit nonzero instead of printing an empty "Synced
# agent skills:" success line (scripts/README.md fail-loud rule, ENG-23131).
# Checked before the stale-link cleanup so a broken sync also cannot delete
# every previously linked skill.
if [ "${#managed_names[@]}" -eq 0 ]; then
  die "no agent skills were linked from $sources_root (sources missing or no SKILL.md found); \
run without IBEX_AGENT_SKILLS_NO_NETWORK=1 to clone the upstream skill repos"
fi

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
