#!/usr/bin/env bash
# Run the rev2 CapSec demos. Ordinary execution is enforce + lockdown; the
# only audit posture is the separately named foreground diagnostic command.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

if [[ -n "${IBEX:-}" ]]; then
  :
elif command -v ibex >/dev/null 2>&1; then
  IBEX="$(command -v ibex)"
elif [[ -x "$REPO_ROOT/target/release/ibex" ]]; then
  IBEX="$REPO_ROOT/target/release/ibex"
elif [[ -x "$REPO_ROOT/target/debug/ibex" ]]; then
  IBEX="$REPO_ROOT/target/debug/ibex"
else
  echo "Could not find ibex. Build it with 'cargo build --bin ibex' or set IBEX." >&2
  exit 1
fi

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
dim() { printf "\033[2m%s\033[0m\n" "$*"; }
rule() { printf "\033[2m%s\033[0m\n" "────────────────────────────────────────────────────────────────────"; }

# Filter routine bootstrap chatter while returning the ibex process's status,
# not grep's. In particular, a failed demo can never be converted into green.
run() {
  local statuses
  set +e
  "$IBEX" "$@" 2>&1 \
    | grep -v -e '^note:' -e '^capsec readiness' -e '^Warning: bundler'
  statuses=("${PIPESTATUS[@]}")
  set -e
  return "${statuses[0]}"
}

ex1() {
  bold "Example 1 — enforce-by-default supply-chain containment"
  dim "Dependencies receive no ambient process authority; the root brokers values explicitly."
  rule
  (
    cd "$HERE/01-supply-chain"
    API_SECRET=sk_live_TOPSECRET run run app.js
  )
  echo
}

ex2() {
  bold "Example 2 — typed authority is not an ambient endowment"
  dim "The policy grants one env resource, but the package still has no process global."
  rule
  (
    cd "$HERE/02-least-privilege"
    APP_MODE=production DATABASE_URL='postgres://admin:hunter2@db' \
      STRIPE_KEY=sk_live_XYZ run run app.mjs
  )
  echo
}

ex3() {
  bold "Example 3 — the explicit foreground audit diagnostic"
  dim "Audit is a command, not a durable or permissive production mode."
  rule
  (
    cd "$HERE/03-audit-mode"
    API_SECRET=sk_live_TOPSECRET run capsec audit app.js
  )
  echo
}

ex4() {
  bold "Example 4 — policy drift and tampering fail closed"
  dim "A valid generated artifact checks; a one-byte digest mutation is refused."
  rule
  (
    cd "$HERE/04-defense-in-depth"
    run policy check --entry app.mjs
    run run app.mjs

    local tampered
    tampered="$(mktemp "${TMPDIR:-/tmp}/ibex-capsec-policy.XXXXXX")"
    sed 's/\("policyDigest": "sha256-\)./\1X/' ibex-policy.json >"$tampered"
    if run --policy "$tampered" run app.mjs; then
      rm -f "$tampered"
      echo "ERROR: tampered policy unexpectedly ran" >&2
      exit 1
    fi
    rm -f "$tampered"
    echo "  tampered policy: REFUSED (expected)"
  )
  echo
}

echo
bold "Ibex capability security rev2 — live demo"
dim "binary: $IBEX"
echo

case "${1:-all}" in
  1) ex1 ;;
  2) ex2 ;;
  3) ex3 ;;
  4) ex4 ;;
  all) ex1; ex2; ex3; ex4 ;;
  *) echo "usage: ./run.sh [1|2|3|4]" >&2; exit 1 ;;
esac
