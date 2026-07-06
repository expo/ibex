#!/usr/bin/env bash
# Agent-facing test entry point that cannot silently run zero tests.
# @ref LLP 0018#2-give-agents-a-test-entry-point-that-cannot-silently-run-zero-tests
#
# Drives `cargo test` over the crate's FULL package test set by default — the
# ibex_runtime lib, the `ibex` binary target (src/bin/ibex/, which holds ~63
# tests), AND the integration tests under tests/. A bare `cargo test --lib` or
# `--bin ibex <filter>` can run zero matching tests and still exit 0; this
# wrapper sums the reported test counts and exits nonzero when zero tests ran.
#
# It also exports IBEX_FAIL_ON_STALE_VENDORED=1 so build.rs fails the run when an
# edited src/builtins/*.js (or other generated source) is newer than its embedded
# vendored-generated output — closing the "green build over stale bytes" gap
# (LLP 0018 item 5).
#
# Usage: scripts/run-tests.sh [--scope lib|bin|test|all] [--allow-zero]
#                             [FILTER] [-- <extra cargo/harness args>]
#   Default scope is `all` (the whole package). Narrowing is explicit and
#   opt-in. FILTER is a cargo test name substring, applied within the scope.
#
#   Examples:
#     scripts/run-tests.sh deep_freeze          # every matching test, all targets
#     scripts/run-tests.sh --scope lib          # lib unit tests only
#     scripts/run-tests.sh --scope bin cli      # binary tests matching `cli`
#     scripts/run-tests.sh -- --nocapture       # forward harness args
set -uo pipefail

scope="all"
allow_zero=0
filter=""
passthrough=()

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --scope) scope="${2:-}"; shift 2 ;;
    --scope=*) scope="${1#--scope=}"; shift ;;
    --allow-zero) allow_zero=1; shift ;;
    --) shift; passthrough=("$@"); break ;;
    -*) echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    *) if [ -z "$filter" ]; then filter="$1"; else passthrough+=("$1"); fi; shift ;;
  esac
done

case "$scope" in
  all)  targets=() ;;
  lib)  targets=(--lib) ;;
  bin)  targets=(--bins) ;;
  test) targets=(--tests) ;;
  *) echo "error: --scope must be one of lib|bin|test|all (got '$scope')" >&2; exit 2 ;;
esac

# Build the command without expanding a possibly-empty array (bash 3.2 + set -u
# treats "${empty[@]}" as an unbound-variable error).
cmd=(cargo test)
[ "${#targets[@]}" -gt 0 ] && cmd+=("${targets[@]}")
[ -n "$filter" ] && cmd+=("$filter")
[ "${#passthrough[@]}" -gt 0 ] && cmd+=(-- "${passthrough[@]}")

echo "run-tests: ${cmd[*]}  (scope=$scope)" >&2

tmp="$(mktemp "${TMPDIR:-/tmp}/ibex-run-tests.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# Fail the build if the embedded builtin is stale relative to its source.
export IBEX_FAIL_ON_STALE_VENDORED="${IBEX_FAIL_ON_STALE_VENDORED:-1}"

# Run cargo, streaming output live while capturing it for the count parse.
# PIPESTATUS[0] preserves cargo's real exit status (incl. a panic that aborts
# before every `test result:` line prints) — the parser never masks it.
"${cmd[@]}" 2>&1 | tee "$tmp"
cargo_status="${PIPESTATUS[0]}"

sum_field() { grep -Eo "[0-9]+ $1" "$tmp" | awk '{s+=$1} END{print s+0}'; }
passed="$(sum_field passed)"
failed="$(sum_field failed)"
ignored="$(sum_field ignored)"
run=$((passed + failed))

echo "run-tests: ran $run tests across scope=$scope ($passed passed, $failed failed, $ignored ignored)" >&2

# 1) A real cargo/test failure is the exit status, never masked by parsing.
if [ "$cargo_status" -ne 0 ]; then
  exit "$cargo_status"
fi

# 2) Zero tests run is a false-green trap — fail loud unless explicitly allowed.
if [ "$run" -eq 0 ] && [ "$allow_zero" -ne 1 ]; then
  echo "error: 0 tests ran (scope=$scope${filter:+, filter='$filter'})." >&2
  echo "       A green 'cargo test' that ran nothing is not verification." >&2
  echo "       Widen --scope, fix the filter, or pass --allow-zero if this is intentional." >&2
  exit 1
fi

exit 0
