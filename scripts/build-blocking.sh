#!/usr/bin/env bash
# Run a long native build/test in the FOREGROUND under a wall-clock timeout, with
# a heartbeat, so an agent that launches it resumes when it finishes — instead of
# backgrounding it and parking on an event that never re-wakes the agent.
# @ref LLP 0018#6-long-agent-launched-builds-run-to-completion-on-a-resumable-path
#
# Usage: scripts/build-blocking.sh [--timeout DURATION] [-- <cargo args>]
#   Default command is `cargo build`; pass `-- test --lib` etc. to override.
#   DURATION defaults to 20m. The command runs in the foreground on the agent's
#   own control flow; cargo streams its own progress and a heartbeat marks
#   liveness so "background it to watch progress" is never the reason to detach.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

duration="20m"
args=(build)
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --timeout) duration="${2:-}"; shift 2 ;;
    --timeout=*) duration="${1#--timeout=}"; shift ;;
    --) shift; [ "$#" -gt 0 ] && args=("$@"); break ;;
    *) echo "error: unknown argument '$1' (did you mean '-- $*'?)" >&2; exit 2 ;;
  esac
done

echo "build-blocking: cargo ${args[*]} (foreground, timeout=$duration)" >&2

# Heartbeat so a quiet compile still shows liveness; killed when the build ends.
( while true; do sleep 30; echo "build-blocking: still running ($(date +%H:%M:%S))…" >&2; done ) &
hb=$!
trap 'kill "$hb" 2>/dev/null || true' EXIT

# Foreground, on the agent's own control flow. with-timeout.sh exits 124 on
# timeout — loud, not a silent hang.
"$here/with-timeout.sh" "$duration" cargo "${args[@]}"
