#!/usr/bin/env bash
# Guard against secure-mode rot.
#
# `insecure` is in Cargo's default feature set (LLP 0039), so an ordinary
# `cargo build` and `cargo test` exercise a runtime with no sandbox. Nothing in
# the default path would notice if secure mode stopped compiling, stopped
# running, or silently stopped enforcing. This script is what notices.
#
# It checks three things, cheapest first:
#   1. secure mode still compiles;
#   2. the lib suite still passes under secure features;
#   3. enforcement is still *behaviourally* real — project reads work while
#      reads, writes, and spawns outside the project are refused.
#
# (3) is the one unit tests are least likely to catch and the one that matters
# most: a mode that compiles and passes its asserts but authorizes everything
# would look healthy right up until it shipped.
#
# @ref LLP 0039#secure-mode-must-stay-exercised
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SECURE_FEATURES="standard,unadvertised-dev-arming"

# Known pre-existing failure, tracked as ENG-25424: prepared-graph execution
# inputs are incomplete and leak host filesystem paths into source labels. It
# fails on clean main with every security feature inert, so it is not a signal
# about secure mode — but it is NOT security-irrelevant either (a leaked path in
# a source label reaches stack traces and source maps), which is why it has a
# ticket rather than a shrug. Skipped here so this guard stays green and keeps
# signalling *new* breakage; deliberately not `#[cfg]`-gated in the source, so a
# default `cargo test` still reports it.
KNOWN_UNRELATED_FAILURE="authenticated_source_graph_round_trips_through_prepared_cache"

echo "==> [1/3] secure mode compiles"
cargo check --bin ibex --no-default-features --features "$SECURE_FEATURES"

echo "==> [2/3] lib suite under secure features"
cargo test --lib --no-default-features --features "$SECURE_FEATURES" -- \
  --skip "$KNOWN_UNRELATED_FAILURE"

echo "==> [3/3] enforcement is behaviourally real"
cargo build --bin ibex --no-default-features --features "$SECURE_FEATURES"

export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-$REPO_ROOT/ios/Frameworks}"
IBEX_BIN="$REPO_ROOT/target/debug/ibex"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
# Project-root discovery authenticates a package.json, so the probe needs a
# minimal one to be a real project rather than a bare directory.
printf '{"name":"ibex-secure-mode-smoke","version":"0.0.0"}\n' >"$WORKDIR/package.json"
printf 'inside-the-project\n' >"$WORKDIR/data.txt"
OUTSIDE_FILE="$(mktemp)"
printf 'outside-the-project\n' >"$OUTSIDE_FILE"
OUTSIDE_WRITE="$WORKDIR/../ibex-secure-mode-should-not-write-$$"
trap 'rm -rf "$WORKDIR" "$OUTSIDE_FILE" "$OUTSIDE_WRITE"' EXIT

# Each probe prints one `<name>=<ok|BAD>` token. A refusal is the pass
# condition for the three negative probes, so a mode that stopped enforcing
# fails this step rather than quietly succeeding.
PROBE=$(cat <<PROBE_JS
const fs = require('fs');
const out = [];
function expectWorks(name, fn) {
  try { fn(); out.push(name + '=ok'); }
  catch (error) { out.push(name + '=BAD(' + String(error.message).slice(0, 60) + ')'); }
}
function expectRefused(name, fn) {
  try { fn(); out.push(name + '=BAD(permitted)'); }
  catch (_) { out.push(name + '=ok'); }
}
// Paths are mktemp-generated and quote-free, so plain interpolation is safe
// here; macOS ships bash 3.2, which has no \${var@Q}.
expectWorks('project_read', () => fs.readFileSync('data.txt', 'utf8'));
expectRefused('outside_read', () => fs.readFileSync('$OUTSIDE_FILE', 'utf8'));
expectRefused('outside_write', () => fs.writeFileSync('$OUTSIDE_WRITE', 'x'));
expectRefused('spawn', () => require('child_process').execSync('echo x'));
// The insecure ambient process.env projection must not exist here: a host
// sentinel inherited from the launcher environment stays unreadable and
// unenumerated (issues/20260724-insecure-process-env.md). NOTE: keep this
// block free of apostrophes — macOS bash 3.2 mis-parses an unpaired quote
// inside the heredoc command substitution and silently skips the probe.
if (process.env.IBEX_SECURE_SMOKE_SENTINEL === undefined
    && !Object.keys(process.env).includes('IBEX_SECURE_SMOKE_SENTINEL')) {
  out.push('env_sentinel_hidden=ok');
} else {
  out.push('env_sentinel_hidden=BAD(leaked)');
}
console.log('SECURE_SMOKE ' + out.join(' '));
PROBE_JS
)

RESULT="$(cd "$WORKDIR" && IBEX_SECURE_SMOKE_SENTINEL=must-not-leak "$IBEX_BIN" eval "$PROBE" 2>&1 | grep 'SECURE_SMOKE' || true)"

if [[ -z "$RESULT" ]]; then
  echo "FAIL: secure-mode smoke probe produced no result — the runtime did not run." >&2
  (cd "$WORKDIR" && "$IBEX_BIN" eval "$PROBE" 2>&1 | tail -20) >&2 || true
  exit 1
fi

echo "$RESULT"

if [[ -e "$OUTSIDE_WRITE" ]]; then
  echo "FAIL: secure mode wrote outside the project at $OUTSIDE_WRITE" >&2
  exit 1
fi

if [[ "$RESULT" == *"=BAD"* ]]; then
  echo "FAIL: secure mode is not enforcing as expected (see BAD markers above)." >&2
  exit 1
fi

echo "secure mode OK: compiles, tests pass, and enforcement is real."
