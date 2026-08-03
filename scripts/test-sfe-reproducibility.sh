#!/usr/bin/env bash
# Synthetic pass/refusal vectors for the distinct clean matching-toolchain
# builder receipt required by the SFE release comparison.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/ibex-sfe-repro-test.XXXXXX")"
cleanup_repro_test() {
  [[ "$work" == *ibex-sfe-repro-test.* ]] || return
  rm -rf -- "$work"
}
trap cleanup_repro_test EXIT INT TERM

mkdir "$work/left" "$work/right"
python3 - "$work/left" left-builder <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
builder_id = sys.argv[2]
documents = {
    "build-statement.json": {
        "schema": "ibex/sfe-build-statement/1",
        "compilePlanDigest": "sha256-plan",
        "stubCoreDigest": "sha256-stub",
        "unsignedFileDigest": "sha256-unsigned",
        "publishedFileDigest": "sha256-published",
        "platformSignature": "not-applicable",
    },
    "inspection.json": {
        "target": {"triple": "x86_64-unknown-linux-gnu"},
        "envelopeConsistency": {"state": "consistent"},
        "runtimeAdmission": {"state": "inner-contracts-admitted"},
    },
    "catalog-report.json": {"catalogDigest": "sha256-catalog"},
    "contract-report.json": {"contractDigest": "sha256-contract"},
    "policy-toolchain-report.json": {"toolchainDigest": "sha256-policy"},
    "builder-receipt.json": {
        "schema": "ibex/sfe-builder-receipt/1",
        "builderId": builder_id,
        "target": "x86_64-unknown-linux-gnu",
        "source": {"gitCommit": "a" * 40, "gitTree": "b" * 40, "clean": True},
        "host": {"platform": "Linux", "architecture": "x86_64", "osRelease": "fixture"},
        "toolchain": {
            "rustc": "rustc fixture",
            "cargo": "cargo fixture",
            "cc": "cc fixture",
            "linker": "ld fixture",
            "xcode": None,
            "sdkVersion": None,
            "sdkBuildVersion": None,
        },
    },
}
for name, document in documents.items():
    (root / name).write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
PY
cp -R "$work/left/." "$work/right/"
python3 - "$work/right/builder-receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["builderId"] = "right-builder"
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY

"$repo_root/scripts/check-sfe-reproducibility.sh" \
  --target x86_64-unknown-linux-gnu \
  --left "$work/left" \
  --right "$work/right" \
  --output "$work/pass.json" >/dev/null
python3 - "$work/pass.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["schema"] == "ibex/sfe-reproducibility-report/2"
assert report["result"] == "pass"
assert report["left"]["builder"]["builderId"] == "left-builder"
assert report["right"]["builder"]["builderId"] == "right-builder"
PY

refusal() {
  local label="$1"
  local expected="$2"
  local report="$work/$label.json"
  set +e
  "$repo_root/scripts/check-sfe-reproducibility.sh" \
    --target x86_64-unknown-linux-gnu \
    --left "$work/left" \
    --right "$work/right" \
    --output "$report" >/dev/null 2>"$work/$label.stderr"
  local status=$?
  set -e
  [[ "$status" -eq 1 ]]
  python3 - "$report" "$expected" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["result"] == "fail"
assert sys.argv[2] in report["mismatchedFields"]
PY
}

python3 - "$work/right/builder-receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["builderId"] = "left-builder"
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
refusal same-builder builderId

python3 - "$work/right/builder-receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["builderId"] = "right-builder"
value["toolchain"]["cc"] = "different cc"
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
refusal toolchain-mismatch toolchain.cc

python3 - "$work/right/builder-receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["toolchain"]["cc"] = "cc fixture"
value["source"]["clean"] = False
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
refusal dirty-source right.source.clean

echo "SFE reproducibility receipt vectors passed"
