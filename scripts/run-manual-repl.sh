#!/usr/bin/env bash
# Run the ignored authenticated-observer REPL fixture from a foreground macOS
# terminal. This is an internal test fixture, not a production CLI bypass or
# target-conformance recipe.
# @ref LLP 0021#default-and-target-claim
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/run-manual-repl.sh [MACOS_HERMES_STAGE]

With no argument, the launcher uses Hermes installed in this Ibex checkout.
An explicit stage must contain ios/Frameworks/hermesvm.framework, the matching
hermes-profile-provenance.json receipt, headers, and Hermes tools.

Install the required local no-debugger profile with:
  HERMES_ENABLE_DEBUGGER=false ./scripts/download-hermes.sh
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -gt 1 ]; then
  usage
  exit 2
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
  echo "error: the manual REPL requires foreground terminal stdin and stdout" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  hermes_stage="$(cd -- "$1" && pwd)"
else
  hermes_stage="$repo_root"
fi
frameworks="$hermes_stage/ios/Frameworks"
headers="$frameworks/hermes-headers"
receipt="$frameworks/hermes-profile-provenance.json"
hermesc="$hermes_stage/tools/hermes/hermesc-macos-arm64"
hermes_cli="$hermes_stage/tools/hermes/hermes"

for required_file in \
  "$frameworks/hermesvm.framework/Versions/Current/hermesvm" \
  "$receipt" \
  "$hermesc" \
  "$hermes_cli"; do
  if [ ! -f "$required_file" ]; then
    echo "error: required Hermes artifact not found: $required_file" >&2
    if [ "$hermes_stage" = "$repo_root" ]; then
      echo "install it with: HERMES_ENABLE_DEBUGGER=false ./scripts/download-hermes.sh" >&2
    fi
    exit 2
  fi
done
if [ ! -d "$headers" ]; then
  echo "error: required Hermes headers not found: $headers" >&2
  if [ "$hermes_stage" = "$repo_root" ]; then
    echo "install them with: HERMES_ENABLE_DEBUGGER=false ./scripts/download-hermes.sh" >&2
  fi
  exit 2
fi

cd "$repo_root"

export HERMES_ENABLE_DEBUGGER=false
export IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE=1
export IBEX_FAIL_ON_STALE_VENDORED=1
export HERMES_LIB_DIR="$frameworks"
export HERMES_INCLUDE_DIR="$headers"
export JSI_INCLUDE_DIR="$headers"
export HERMESC="$hermesc"
export HERMES_CLI="$hermes_cli"
export HERMES_PROFILE_PROVENANCE_RECEIPT="$receipt"

exec cargo test --bin ibex \
  --features host-http-server,cli-notify,capsec-conformance-observer \
  terminal_session::tests::manual_authenticated_interactive_repl \
  -- --ignored --exact --nocapture --test-threads=1
