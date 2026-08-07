#!/usr/bin/env bash
# Compare the unsigned application identities produced by two independent SFE
# release builders. macOS ad-hoc signatures are intentionally outside this
# comparison; each build statement commits to the exact pre-signing bytes.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
set -euo pipefail

usage() {
  echo "usage: $0 --target TRIPLE --left EVIDENCE_DIRECTORY --right EVIDENCE_DIRECTORY --output REPORT.json" >&2
  exit 2
}

target=""
left=""
right=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || usage
      target="$2"
      shift 2
      ;;
    --left)
      [[ $# -ge 2 ]] || usage
      left="$2"
      shift 2
      ;;
    --right)
      [[ $# -ge 2 ]] || usage
      right="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$target" && -d "$left" && -d "$right" && -n "$output" ]] || usage
[[ "$left" != "$right" ]] || {
  echo "reproducibility evidence directories must be distinct" >&2
  exit 1
}
for evidence in "$left" "$right"; do
  for required in \
    build-statement.json \
    inspection.json \
    catalog-report.json \
    contract-report.json \
    policy-toolchain-report.json \
    builder-receipt.json; do
    [[ -f "$evidence/$required" ]] || {
      echo "reproducibility evidence is missing $evidence/$required" >&2
      exit 1
    }
  done
done
[[ ! -e "$output" ]] || {
  echo "reproducibility report already exists: $output" >&2
  exit 1
}
mkdir -p "$(dirname "$output")"

python3 - "$target" "$left" "$right" "$output" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import tempfile

target, left_arg, right_arg, output_arg = sys.argv[1:]
left = pathlib.Path(left_arg).resolve()
right = pathlib.Path(right_arg).resolve()
output = pathlib.Path(output_arg).resolve()

if target not in {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}:
    raise SystemExit(f"unsupported v1 SFE target: {target}")


def read_json(root: pathlib.Path, name: str):
    path = root / name
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def raw_digest(root: pathlib.Path, name: str) -> str:
    return "sha256-" + hashlib.sha256((root / name).read_bytes()).hexdigest()


def admit_builder(root: pathlib.Path):
    receipt = read_json(root, "builder-receipt.json")
    if set(receipt) != {"schema", "builderId", "target", "source", "host", "toolchain"}:
        raise SystemExit(f"invalid SFE builder receipt fields in {root}")
    if receipt["schema"] != "ibex/sfe-builder-receipt/1" or receipt["target"] != target:
        raise SystemExit(f"invalid SFE builder receipt identity in {root}")
    if not isinstance(receipt["builderId"], str) or not receipt["builderId"]:
        raise SystemExit(f"empty SFE builder identity in {root}")
    source = receipt["source"]
    if set(source) != {"gitCommit", "gitTree", "clean"}:
        raise SystemExit(f"invalid SFE builder source receipt in {root}")
    for field in ("gitCommit", "gitTree"):
        value = source[field]
        if not isinstance(value, str) or len(value) not in (40, 64) or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise SystemExit(f"invalid SFE builder source {field} in {root}")
    if not isinstance(source["clean"], bool):
        raise SystemExit(f"invalid SFE builder clean-source state in {root}")
    host = receipt["host"]
    if set(host) != {"platform", "architecture", "osRelease"} or not all(
        isinstance(host[field], str) and host[field]
        for field in ("platform", "architecture", "osRelease")
    ):
        raise SystemExit(f"invalid SFE builder host receipt in {root}")
    expected_host = {
        "aarch64-apple-darwin": ("Darwin", "arm64"),
        "x86_64-unknown-linux-gnu": ("Linux", "x86_64"),
    }[target]
    if (host["platform"], host["architecture"]) != expected_host:
        raise SystemExit(f"SFE builder host does not match {target} in {root}")
    toolchain = receipt["toolchain"]
    if set(toolchain) != {
        "rustc",
        "cargo",
        "cc",
        "linker",
        "xcode",
        "sdkVersion",
        "sdkBuildVersion",
    }:
        raise SystemExit(f"invalid SFE builder toolchain receipt in {root}")
    for field in ("rustc", "cargo", "cc", "linker"):
        if not isinstance(toolchain[field], str) or not toolchain[field]:
            raise SystemExit(f"empty SFE builder toolchain {field} in {root}")
    apple_fields = ("xcode", "sdkVersion", "sdkBuildVersion")
    if target == "aarch64-apple-darwin":
        if not all(isinstance(toolchain[field], str) and toolchain[field] for field in apple_fields):
            raise SystemExit(f"incomplete macOS builder toolchain in {root}")
    elif any(toolchain[field] is not None for field in apple_fields):
        raise SystemExit(f"Linux builder receipt contains an Apple toolchain in {root}")
    return receipt


def admit(root: pathlib.Path):
    statement = read_json(root, "build-statement.json")
    if set(statement) != {
        "schema",
        "compilePlanDigest",
        "stubCoreDigest",
        "unsignedFileDigest",
        "publishedFileDigest",
        "platformSignature",
    } or statement["schema"] != "ibex/sfe-build-statement/1":
        raise SystemExit(f"invalid SFE build statement in {root}")
    inspection = read_json(root, "inspection.json")
    if inspection.get("target", {}).get("triple") != target:
        raise SystemExit(f"inspection target mismatch in {root}")
    if inspection.get("envelopeConsistency", {}).get("state") != "consistent":
        raise SystemExit(f"inconsistent inspected envelope in {root}")
    if inspection.get("runtimeAdmission", {}).get("state") != "inner-contracts-admitted":
        raise SystemExit(f"unadmitted inspected envelope in {root}")
    catalog = read_json(root, "catalog-report.json")
    contract = read_json(root, "contract-report.json")
    toolchain = read_json(root, "policy-toolchain-report.json")
    return ({
        "catalogDigest": catalog["catalogDigest"],
        "contractDigest": contract["contractDigest"],
        "policyToolchainDigest": toolchain["toolchainDigest"],
        "compilePlanDigest": statement["compilePlanDigest"],
        "stubCoreDigest": statement["stubCoreDigest"],
        "unsignedFileDigest": statement["unsignedFileDigest"],
        "statementDigest": raw_digest(root, "build-statement.json"),
    }, admit_builder(root))


left_record, left_builder = admit(left)
right_record, right_builder = admit(right)
identity_fields = (
    "catalogDigest",
    "contractDigest",
    "policyToolchainDigest",
    "compilePlanDigest",
    "stubCoreDigest",
    "unsignedFileDigest",
)
mismatches = [
    field for field in identity_fields if left_record[field] != right_record[field]
]
if left_builder["builderId"] == right_builder["builderId"]:
    mismatches.append("builderId")
for side, builder in (("left", left_builder), ("right", right_builder)):
    if builder["builderId"] == "local-unidentified":
        mismatches.append(f"{side}.builderId")
    if builder["source"]["clean"] is not True:
        mismatches.append(f"{side}.source.clean")
for field in ("gitCommit", "gitTree"):
    if left_builder["source"][field] != right_builder["source"][field]:
        mismatches.append(f"source.{field}")
for field in left_builder["toolchain"]:
    if left_builder["toolchain"][field] != right_builder["toolchain"][field]:
        mismatches.append(f"toolchain.{field}")
report = {
    "schema": "ibex/sfe-reproducibility-report/2",
    "target": target,
    "comparison": "distinct-clean-matching-toolchain-builders-and-unsigned-application-bytes",
    "left": {**left_record, "builder": left_builder},
    "right": {**right_record, "builder": right_builder},
    "equalFields": list(identity_fields) if not mismatches else [
        field for field in identity_fields if field not in mismatches
    ],
    "mismatchedFields": mismatches,
    "result": "pass" if not mismatches else "fail",
}
encoded = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)

if mismatches:
    raise SystemExit(
        "SFE distinct clean matching-toolchain reproducibility mismatch: "
        + ", ".join(mismatches)
    )
print(
    f"SFE reproducibility passed: target={target} "
    f"unsigned={left_record['unsignedFileDigest']}"
)
PY
