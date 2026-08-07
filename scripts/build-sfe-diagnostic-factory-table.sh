#!/usr/bin/env bash
# Build a host-target, full-static-engine factory-table executable for the
# diagnostic comparison required by LLP 0029 phase 7. This deliberately uses
# the development contract/provenance lane; it is not a release producer and
# cannot be substituted for `ibex compile` output.
# @ref LLP 0029#1-command-surface-and-producer-pipeline
# @ref LLP 0029#7-phases-gates-and-the-author-decision-register
set -euo pipefail

readonly sfe_diagnostic_source_date_epoch=1
export SOURCE_DATE_EPOCH="$sfe_diagnostic_source_date_epoch"

usage() {
  echo "usage: $0 --target TRIPLE --hermes PATH --static-archive ROLE PATH [--static-archive ROLE PATH ...] --entry PATH --output PATH" >&2
  exit 2
}

invocation_dir="$PWD"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple=""
hermes_path=""
entry_path=""
output_path=""
static_archive_arguments=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || usage
      target_triple="$2"
      shift 2
      ;;
    --hermes)
      [[ $# -ge 2 ]] || usage
      hermes_path="$2"
      shift 2
      ;;
    --static-archive)
      [[ $# -ge 3 ]] || usage
      static_archive_arguments+=(--static-archive "$2" "$3")
      shift 3
      ;;
    --entry)
      [[ $# -ge 2 ]] || usage
      entry_path="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output_path="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$target_triple" ]] || usage
[[ -n "$hermes_path" ]] || usage
[[ -n "$entry_path" ]] || usage
[[ -n "$output_path" ]] || usage
[[ ${#static_archive_arguments[@]} -ge 3 ]] || usage

case "$target_triple" in
  aarch64-apple-darwin)
    [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] || {
      echo "diagnostic target $target_triple requires a Darwin-arm64 host" >&2
      exit 1
    }
    ;;
  x86_64-unknown-linux-gnu)
    [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] || {
      echo "diagnostic target $target_triple requires a Linux-x86_64 host" >&2
      exit 1
    }
    ;;
  *)
    echo "unsupported v1 SFE diagnostic target: $target_triple" >&2
    exit 1
    ;;
esac

absolute_file() {
  local path="$1"
  local directory
  directory="$(cd "$(dirname "$path")" && pwd -P)"
  printf '%s/%s\n' "$directory" "$(basename "$path")"
}

[[ -f "$hermes_path" ]] || {
  echo "Hermes runtime tool is absent: $hermes_path" >&2
  exit 1
}
[[ -f "$entry_path" ]] || {
  echo "diagnostic entry is absent: $entry_path" >&2
  exit 1
}
hermes_path="$(absolute_file "$hermes_path")"
entry_path="$(absolute_file "$entry_path")"
for ((index = 2; index < ${#static_archive_arguments[@]}; index += 3)); do
  archive_path="${static_archive_arguments[$index]}"
  [[ -f "$archive_path" ]] || {
    echo "static archive is absent: $archive_path" >&2
    exit 1
  }
  static_archive_arguments[$index]="$(absolute_file "$archive_path")"
done
if [[ "$output_path" != /* ]]; then
  output_path="$invocation_dir/$output_path"
fi
[[ ! -e "$output_path" ]] || {
  echo "diagnostic output already exists: $output_path" >&2
  exit 1
}

hermes_archive=""
jsi_archive=""
boost_context_archive=""
for ((index = 0; index < ${#static_archive_arguments[@]}; index += 3)); do
  archive_role="${static_archive_arguments[$((index + 1))]}"
  archive_path="${static_archive_arguments[$((index + 2))]}"
  case "$archive_role" in
    hermesvm) selected_name="hermes_archive" ;;
    jsi) selected_name="jsi_archive" ;;
    boost-context) selected_name="boost_context_archive" ;;
    *) continue ;;
  esac
  [[ -z "${!selected_name}" ]] || {
    echo "diagnostic builder received more than one $archive_role archive" >&2
    exit 1
  }
  printf -v "$selected_name" '%s' "$archive_path"
done
[[ -n "$hermes_archive" && -n "$jsi_archive" && -n "$boost_context_archive" ]] || {
  echo "diagnostic builder requires hermesvm, jsi, and boost-context static archives" >&2
  exit 1
}

hermes_lib_dir="$(dirname "$hermes_archive")"
hermes_static_lib_name="$(basename "$hermes_archive")"
hermes_static_lib_name="${hermes_static_lib_name#lib}"
hermes_static_lib_name="${hermes_static_lib_name%.a}"
[[ "$jsi_archive" == "$hermes_lib_dir/libjsi.a" && \
   "$boost_context_archive" == "$hermes_lib_dir/libboost_context.a" ]] || {
  echo "Hermes, JSI, and Boost.Context archives must use the standard co-located layout" >&2
  exit 1
}

case "$target_triple" in
  x86_64-unknown-linux-gnu)
    hermes_install_root="$(dirname "$hermes_lib_dir")"
    hermes_include_dir="$hermes_install_root/include"
    [[ -f "$hermes_include_dir/hermes/hermes.h" && "$hermes_static_lib_name" == "hermesvm_a" ]] || {
      echo "Linux hermesvm archive is outside the required include/lib install layout: $hermes_archive" >&2
      exit 1
    }
    ;;
  aarch64-apple-darwin)
    hermes_include_dir="$repo_root/ios/Frameworks/hermes-headers"
    [[ -f "$hermes_include_dir/hermes/hermes.h" && \
       "$hermes_static_lib_name" =~ ^hermesvm(lean)?_a$ ]] || {
      echo "macOS diagnostic build has no compatible static Hermes archive/header layout: $hermes_archive" >&2
      exit 1
    }
    ;;
esac

export HERMES_LINK_STATIC=1
export HERMES_STATIC_LIB_NAME="$hermes_static_lib_name"
export HERMES_INCLUDE_DIR="$hermes_include_dir"
export HERMES_LIB_DIR="$hermes_lib_dir"
export HERMES_BINARY="$hermes_path"
export HERMES_CLI="$hermes_path"
export CARGO_TARGET_DIR="$repo_root/target/sfe-diagnostic-factory-$target_triple"
unset IBEX_STUB_CONTRACT_PATH
unset IBEX_RELEASE_SFE_CATALOG_DIGEST
unset IBEX_RELEASE_POLICY_TOOLCHAIN_DIGEST

diagnostic_stage="$(mktemp -d "${TMPDIR:-/tmp}/ibex-sfe-diagnostic-factory.XXXXXX")"
cleanup_diagnostic_stage() {
  [[ "$diagnostic_stage" == *ibex-sfe-diagnostic-factory.* ]] || return
  rm -rf -- "$diagnostic_stage"
}
trap cleanup_diagnostic_stage EXIT INT TERM

cd "$repo_root"
cargo build --quiet --release --package ibex-compiled-stub
cargo build --quiet --release --features sfe-dev-spike --bin ibex-sfe-dev-pack --bin ibex

stub_path="$diagnostic_stage/ibex-compiled-stub"
candidate_path="$diagnostic_stage/factory-table-executable"
cp "$CARGO_TARGET_DIR/release/ibex-compiled-stub" "$stub_path"
if [[ "$target_triple" == "aarch64-apple-darwin" ]]; then
  codesign --remove-signature "$stub_path"
fi

"$CARGO_TARGET_DIR/release/ibex-sfe-dev-pack" \
  "$stub_path" \
  "$entry_path" \
  "$candidate_path"

if [[ "$target_triple" == "aarch64-apple-darwin" ]]; then
  codesign --force --sign - --options runtime --timestamp=none \
    --identifier dev.ibex.sfe.diagnostic.factory-table \
    "$candidate_path"
  codesign --verify --strict "$candidate_path"
fi

inspection_path="$diagnostic_stage/inspection.json"
"$CARGO_TARGET_DIR/release/ibex" inspect-executable "$candidate_path" > "$inspection_path"
python3 - "$inspection_path" "$target_triple" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
target = sys.argv[2]
if report.get("schema") != "ibex/executable-inspection/3":
    raise SystemExit("diagnostic factory-table inspection has the wrong schema")
if report.get("provenanceKind") != "development-or-unknown":
    raise SystemExit("diagnostic factory-table executable entered the release provenance lane")
if report.get("target") != {
    "triple": target,
    "minimumPlatform": "diagnostic-host-unpinned",
}:
    raise SystemExit("diagnostic factory-table executable has the wrong target contract")
if report.get("runtimeAdmission", {}).get("state") != "inner-contracts-admitted":
    raise SystemExit("diagnostic factory-table executable failed inner admission")
sections = report.get("sections", [])
manifest_count = sum(row.get("kind") == "carrier-manifest" for row in sections)
payload_count = sum(row.get("kind") == "carrier-payload" for row in sections)
if manifest_count == 0 or manifest_count != payload_count:
    raise SystemExit("diagnostic factory-table executable has an incomplete carrier partition")
PY

mkdir -p "$(dirname "$output_path")"
mv "$candidate_path" "$output_path"
echo "diagnosticFactoryTable=$output_path"
echo "target=$target_triple"
echo "engineVariant=$hermes_static_lib_name"
echo "releaseEligible=false"
