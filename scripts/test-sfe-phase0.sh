#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
phase0_tmp="$(mktemp -d /tmp/ibex-sfe-phase0.XXXXXX)"
trap 'rm -rf -- "$phase0_tmp"' EXIT

cd "$repo_root"
cargo build --features sfe-dev-spike --bin ibex-sfe-dev-pack
cargo build --package ibex-compiled-stub
cargo build --bin ibex

mkdir -p "$phase0_tmp/checkout-a/src" "$phase0_tmp/checkout-b/src"
cp tests/fixtures/sfe-dev/entry.mjs "$phase0_tmp/checkout-a/src/entry.mjs"
cp tests/fixtures/sfe-dev/entry.mjs "$phase0_tmp/checkout-b/src/entry.mjs"
cp tests/fixtures/sfe-dev/value.mjs "$phase0_tmp/checkout-a/src/value.mjs"
cp tests/fixtures/sfe-dev/value.mjs "$phase0_tmp/checkout-b/src/value.mjs"
cp target/debug/ibex-compiled-stub "$phase0_tmp/stub-a"
cp target/debug/ibex-compiled-stub "$phase0_tmp/stub-b"

if [[ "$(uname -s)" == "Darwin" ]]; then
  # The catalog core is signature-stripped. The packager injects a named
  # __IBEX segment, after which the final image receives a fresh signature.
  codesign --remove-signature "$phase0_tmp/stub-a"
  codesign --remove-signature "$phase0_tmp/stub-b"
fi

target/debug/ibex-sfe-dev-pack \
  "$phase0_tmp/stub-a" \
  "$phase0_tmp/checkout-a/src/entry.mjs" \
  "$phase0_tmp/app-a"
target/debug/ibex-sfe-dev-pack \
  "$phase0_tmp/stub-b" \
  "$phase0_tmp/checkout-b/src/entry.mjs" \
  "$phase0_tmp/app-b"

cmp "$phase0_tmp/app-a" "$phase0_tmp/app-b"
rm -rf -- "$phase0_tmp/checkout-a" "$phase0_tmp/checkout-b"

if [[ "$(uname -s)" == "Darwin" ]]; then
  otool -l "$phase0_tmp/app-a" > "$phase0_tmp/app-a.load-commands"
  grep -q '__IBEX' "$phase0_tmp/app-a.load-commands"
  grep -q '__payload' "$phase0_tmp/app-a.load-commands"
  codesign --force --sign - --identifier dev.ibex.phase0 "$phase0_tmp/app-a"
  codesign --verify --strict "$phase0_tmp/app-a"
fi
result="$(SFE_BASE=from-launch "$phase0_tmp/app-a" --inspect compile --policy)"
information="$(SFE_BASE=from-launch "$phase0_tmp/app-a" --ibex-info)"
escaped_information="$(SFE_BASE=from-launch "$phase0_tmp/app-a" -- --ibex-info)"
later_information="$(SFE_BASE=from-launch "$phase0_tmp/app-a" value --ibex-info)"
target/debug/ibex inspect-executable "$phase0_tmp/app-a" > "$phase0_tmp/inspection.json"
grep -q '"envelopeConsistency":{"envelopeDigest":"sha256-' "$phase0_tmp/inspection.json"
grep -q '"state":"consistent"' "$phase0_tmp/inspection.json"
grep -q '"runtimeAdmission":{"carrierCount":3,"graphIdentity":"sha256-' "$phase0_tmp/inspection.json"
grep -q '"recordCount":3,"state":"inner-contracts-admitted"' "$phase0_tmp/inspection.json"
grep -q '"externalAttestation":{"reason":.*"state":"absent"' "$phase0_tmp/inspection.json"
if [[ "$(uname -s)" == "Darwin" ]]; then
  grep -q '"platformSignature":{"format":"mach-o","mechanism":"codesign-strict-plus-ibex-layout","state":"valid"}' "$phase0_tmp/inspection.json"
fi

if [[ "$result" != '{"answer":42,"applicationArgs":["--inspect","compile","--policy"],"capturedEnvironment":"from-launch"}' ]]; then
  echo "unexpected phase-0 result: $result" >&2
  exit 1
fi

python3 -c '
import json, sys
report = json.loads(sys.argv[1])
assert report["schema"] == "ibex/standalone-executable-info/1"
assert report["execution"] == {"applicationEvaluated": False}
assert report["integrity"]["status"] == "admitted"
assert report["boot"]["defaultMode"] == "ambient-compatibility"
assert report["boot"]["informationSelector"]["spelling"] == "--ibex-info"
assert report["provenanceKind"] == "development"
' "$information"
if [[ "$escaped_information" != '{"answer":42,"applicationArgs":["--ibex-info"],"capturedEnvironment":"from-launch"}' ]]; then
  echo "escaped information selector did not remain an application argument: $escaped_information" >&2
  exit 1
fi
if [[ "$later_information" != '{"answer":42,"applicationArgs":["value","--ibex-info"],"capturedEnvironment":"from-launch"}' ]]; then
  echo "later information selector did not remain an application argument: $later_information" >&2
  exit 1
fi

set +e
lifecycle_result="$(SFE_BASE=from-launch "$phase0_tmp/app-a" --async-exit-7)"
lifecycle_status=$?
set -e
if [[ "$lifecycle_status" -ne 7 ]]; then
  echo "unexpected compiled lifecycle status: $lifecycle_status" >&2
  exit 1
fi
# The development-only namespace diagnostic follows the application task
# drain. Release artifacts do not print that diagnostic.
expected_lifecycle_result=$'compiled-lifecycle-flush\n{"answer":42,"applicationArgs":["--async-exit-7"],"capturedEnvironment":"from-launch"}'
if [[ "$lifecycle_result" != "$expected_lifecycle_result" ]]; then
  echo "unexpected compiled lifecycle output: $lifecycle_result" >&2
  exit 1
fi
