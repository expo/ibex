#!/usr/bin/env bash

# The sole Hermes source authority for Ibex 2. All supported builders use this
# exact upstream commit without applying a local patch stack.
IBEX_HERMES_VERSION="${IBEX_HERMES_VERSION:-260318099.0.0}"
IBEX_HERMES_SOURCE_REF="${IBEX_HERMES_SOURCE_REF:-${IBEX_HERMES_VERSION}-stable}"
IBEX_HERMES_VANILLA_SOURCE_COMMIT="${IBEX_HERMES_VANILLA_SOURCE_COMMIT:-6badada762121682b5481b6124e6c3a991ae6046}"
IBEX_HERMES_VANILLA_BUILD_REF="${IBEX_HERMES_VANILLA_BUILD_REF:-$IBEX_HERMES_VANILLA_SOURCE_COMMIT}"
IBEX_HERMES_BUILD_REF="$IBEX_HERMES_VANILLA_BUILD_REF"

ibex_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$@"
  else
    sha256sum "$@"
  fi | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /'
}

ibex_hermes_apple_build_authority_digest_hex() {
  local project_root
  project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  ibex_sha256 "$project_root/scripts/build-hermes.sh" | awk '{ print $1 }'
}

ibex_hermes_apple_vanilla_cache_key() {
  local version_key="$1"
  local debugger_suffix="${2:-}"
  printf '%s%s-vanilla-ba%s-oapple\n' \
    "$version_key" "$debugger_suffix" \
    "$(ibex_hermes_apple_build_authority_digest_hex | cut -c1-12)"
}

ibex_hermes_source_build_lock_path() {
  printf '%s\n' "${IBEX_HERMES_SOURCE_BUILD_LOCK_FILE:-${IBEX_HERMES_SOURCE_BUILD_LOCK_DIR:-$HOME/.cache/exact/hermes-source-build.lock}}"
}

ibex_acquire_hermes_source_build_lock() {
  local entrypoint="${1:-unknown-entrypoint}"
  local lock_file
  [[ "${IBEX_HERMES_SOURCE_BUILD_LOCK_HELD:-}" != 1 ]] || return 1
  command -v perl >/dev/null 2>&1 || return 1
  lock_file="$(ibex_hermes_source_build_lock_path)"
  mkdir -p "$(dirname "$lock_file")"
  exec 9>>"$lock_file"
  perl -MFcntl=:flock -e 'flock(STDIN, LOCK_EX) or die "flock: $!\n"' <&9
  : >"$lock_file"
  printf 'pid=%s\nentrypoint=%s\n' "$$" "$entrypoint" >&9
  IBEX_HERMES_SOURCE_BUILD_LOCK_HELD=1
  export IBEX_HERMES_SOURCE_BUILD_LOCK_HELD
}

ibex_release_hermes_source_build_lock() {
  [[ "${IBEX_HERMES_SOURCE_BUILD_LOCK_HELD:-}" == 1 ]] || return 0
  exec 9>&-
  unset IBEX_HERMES_SOURCE_BUILD_LOCK_HELD
}
