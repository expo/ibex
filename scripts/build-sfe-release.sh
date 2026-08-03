#!/usr/bin/env bash
# Build one host-target standalone-executable release kit: authenticated
# contract, release stub, addressed catalog asset, catalog-pinned producer, and
# the equally pinned catalog installer. The caller supplies the exact patched
# Hermes tools, archives, and policy runner so producer provenance is never
# inferred from PATH.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
set -euo pipefail

# Timestamp-bearing native producers must consume a declared constant rather
# than wall-clock time. Release provenance remains in the authenticated
# reports; this epoch exists only to normalize outputs such as OpenSSL's
# compiled `OPENSSL_BUILT_ON` string and the ELF build ID derived from it.
# Use 1 rather than 0 because some upstream Perl generators treat zero as
# false and fall back to the current time.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
readonly sfe_source_date_epoch=1
export SOURCE_DATE_EPOCH="$sfe_source_date_epoch"

usage() {
  echo "usage: $0 --target TRIPLE --minimum-platform BASELINE --engine-profile NAME --hermesc PATH --hermes PATH --policy-runner PATH --static-archive ROLE PATH [--static-archive ROLE PATH ...] --output DIR [--release NAME] [--sequence N]" >&2
  exit 2
}

invocation_dir="$PWD"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_triple=""
minimum_platform=""
engine_profile=""
hermesc_path=""
hermes_path=""
policy_runner_path=""
output_dir=""
release_name=""
catalog_sequence="1"
static_archive_arguments=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || usage
      target_triple="$2"
      shift 2
      ;;
    --minimum-platform)
      [[ $# -ge 2 ]] || usage
      minimum_platform="$2"
      shift 2
      ;;
    --engine-profile)
      [[ $# -ge 2 ]] || usage
      engine_profile="$2"
      shift 2
      ;;
    --hermesc)
      [[ $# -ge 2 ]] || usage
      hermesc_path="$2"
      shift 2
      ;;
    --hermes)
      [[ $# -ge 2 ]] || usage
      hermes_path="$2"
      shift 2
      ;;
    --policy-runner)
      [[ $# -ge 2 ]] || usage
      policy_runner_path="$2"
      shift 2
      ;;
    --static-archive)
      [[ $# -ge 3 ]] || usage
      static_archive_arguments+=(--static-archive "$2" "$3")
      shift 3
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output_dir="$2"
      shift 2
      ;;
    --release)
      [[ $# -ge 2 ]] || usage
      release_name="$2"
      shift 2
      ;;
    --sequence)
      [[ $# -ge 2 ]] || usage
      catalog_sequence="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$target_triple" ]] || usage
[[ -n "$minimum_platform" ]] || usage
[[ -n "$engine_profile" ]] || usage
[[ -n "$hermesc_path" ]] || usage
[[ -n "$hermes_path" ]] || usage
[[ -n "$policy_runner_path" ]] || usage
[[ -n "$output_dir" ]] || usage
[[ ${#static_archive_arguments[@]} -ge 3 ]] || usage
[[ "$catalog_sequence" =~ ^[1-9][0-9]*$ ]] || usage

case "$target_triple" in
  aarch64-apple-darwin)
    [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] || {
      echo "release kit target $target_triple requires a Darwin-arm64 host" >&2
      exit 1
    }
    ;;
  x86_64-unknown-linux-gnu)
    [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] || {
      echo "release kit target $target_triple requires a Linux-x86_64 host" >&2
      exit 1
    }
    ;;
  *)
    echo "unsupported v1 SFE target: $target_triple" >&2
    exit 1
    ;;
esac

for required_file in "$hermesc_path" "$hermes_path" "$policy_runner_path"; do
  [[ -f "$required_file" ]] || {
    echo "required Hermes tool is absent: $required_file" >&2
    exit 1
  }
done
for ((index = 2; index < ${#static_archive_arguments[@]}; index += 3)); do
  archive_path="${static_archive_arguments[$index]}"
  [[ -f "$archive_path" ]] || {
    echo "static archive is absent: $archive_path" >&2
    exit 1
  }
done

absolute_file() {
  local path="$1"
  local directory
  directory="$(cd "$(dirname "$path")" && pwd -P)"
  printf '%s/%s\n' "$directory" "$(basename "$path")"
}
hermesc_path="$(absolute_file "$hermesc_path")"
hermes_path="$(absolute_file "$hermes_path")"
policy_runner_path="$(absolute_file "$policy_runner_path")"
for ((index = 2; index < ${#static_archive_arguments[@]}; index += 3)); do
  static_archive_arguments[$index]="$(absolute_file "${static_archive_arguments[$index]}")"
done
if [[ "$output_dir" != /* ]]; then
  output_dir="$invocation_dir/$output_dir"
fi

# A release command names the exact static Hermes archive. Derive the compiler
# build environment from that authenticated input on both targets instead of
# relying on a caller's shell state. Otherwise a macOS invocation can silently
# link the checkout's dynamic framework and retain an absolute build-host
# rpath even though the catalog authenticates a static archive.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
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
    echo "release kit received more than one $archive_role archive" >&2
    exit 1
  }
  printf -v "$selected_name" '%s' "$archive_path"
done
[[ -n "$hermes_archive" && -n "$jsi_archive" && -n "$boost_context_archive" ]] || {
  echo "release kit requires hermesvm, jsi, and boost-context static archives" >&2
  exit 1
}
hermes_lib_dir="$(dirname "$hermes_archive")"
hermes_static_lib_name="$(basename "$hermes_archive")"
hermes_static_lib_name="${hermes_static_lib_name#lib}"
hermes_static_lib_name="${hermes_static_lib_name%.a}"
[[ "$jsi_archive" == "$hermes_lib_dir/libjsi.a" && \
   "$boost_context_archive" == "$hermes_lib_dir/libboost_context.a" ]] || {
  echo "Hermes, JSI, and Boost.Context archives must use the authenticated standard co-located layout" >&2
  exit 1
}

case "$target_triple" in
  x86_64-unknown-linux-gnu)
    # The standard Linux Hermes install keeps hermes-headers/ and lib/ as
    # siblings;
    # refusing any other shape prevents an unrelated header tree from being
    # selected silently.
    hermes_install_root="$(dirname "$hermes_lib_dir")"
    hermes_include_dir="$hermes_install_root/hermes-headers"
    [[ -f "$hermes_include_dir/hermes/hermes.h" && "$hermes_static_lib_name" == "hermesvm_a" ]] || {
      echo "Linux hermesvm archive is outside the required include/lib install layout: $hermes_archive" >&2
      exit 1
    }
    ;;
  aarch64-apple-darwin)
    hermes_include_dir="$repo_root/ios/Frameworks/hermes-headers"
    [[ -f "$hermes_include_dir/hermes/hermes.h" && \
       "$hermes_static_lib_name" =~ ^hermesvm(lean)?_a$ ]] || {
      echo "macOS release kit has no compatible static Hermes archive/header layout: $hermes_archive" >&2
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

cd "$repo_root"
package_version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(package["version"] for package in data["packages"] if package["name"] == "ibex-runtime"))')"
[[ -n "$package_version" ]] || {
  echo "cannot determine the Ibex package version" >&2
  exit 1
}
if [[ -z "$release_name" ]]; then
  release_name="ibex-$package_version"
fi
if [[ -e "$output_dir" ]]; then
  echo "release output already exists: $output_dir" >&2
  exit 1
fi

release_stage="$(mktemp -d "${TMPDIR:-/tmp}/ibex-sfe-release.XXXXXX")"
cleanup_release_stage() {
  [[ "$release_stage" == *ibex-sfe-release.* ]] || return
  rm -rf -- "$release_stage"
}
trap cleanup_release_stage EXIT INT TERM

contract_path="$release_stage/stub-contract.canonical.json"
contract_report="$release_stage/contract-report.json"
contract_features="sfe-catalog-build"
if [[ "$target_triple" == "x86_64-unknown-linux-gnu" ]]; then
  # The v1 Linux artifact owns its HTTP/WebSocket implementation. Build both
  # the contract-producing runtime and the shipped producer with the same
  # pinned static curl/TLS closure instead of inheriting the builder distro's
  # libcurl version (Ubuntu 22.04 carries an older ABI).
  # @ref LLP 0047#the-linux-ambient-network-gap-must-be-decided-not-inherited
  contract_features+=",sfe-static-network"
fi
cargo run --quiet --release --bin ibex-sfe-contract --features "$contract_features" -- \
  --target "$target_triple" \
  --minimum-platform "$minimum_platform" \
  --engine-profile "$engine_profile" \
  --hermesc "$hermesc_path" \
  --hermes "$hermes_path" \
  "${static_archive_arguments[@]}" \
  --output "$contract_path" > "$contract_report"

producer_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
contract_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["contractDigest"])' "$contract_report")"
contract_key="${contract_digest#sha256-}"
[[ "$contract_digest" == "sha256-$contract_key" && ${#contract_key} -eq 43 ]] || {
  echo "contract producer returned a malformed digest: $contract_digest" >&2
  exit 1
}
# Vendored OpenSSL records its build/install prefix in the static library. A
# checkout-local Cargo target therefore changes the linked stub even when all
# authenticated inputs match. Build only the release stub in a target- and
# contract-addressed absolute namespace shared by equivalent builders; Cargo's
# own fingerprints still rebuild it when source or compiler inputs change.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
stub_target_dir="/tmp/ibex-sfe-stub-target/$target_triple/$contract_key"
# Cargo fingerprints build-script environment values. Feeding the release stub
# through the random release-stage path would therefore perturb Rust/LLVM
# symbol identities even when the authenticated contract bytes were identical.
# Keep the compiler-facing path content-addressed beneath the declared target
# directory; the random stage remains appropriate for unpublished assembly.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
stub_contract_dir="$stub_target_dir/ibex-sfe-contract-inputs"
stub_contract_path="$stub_contract_dir/$contract_key.canonical.json"
mkdir -p "$stub_contract_dir"
if [[ -e "$stub_contract_path" ]]; then
  cmp -s "$contract_path" "$stub_contract_path" || {
    echo "content-addressed stub contract collision: $stub_contract_path" >&2
    exit 1
  }
else
  cp "$contract_path" "$stub_contract_path"
fi
if [[ "$target_triple" == "x86_64-unknown-linux-gnu" ]]; then
  CARGO_TARGET_DIR="$stub_target_dir" \
    IBEX_STUB_CONTRACT_PATH="$stub_contract_path" \
    IBEX_SFE_LINUX_RELEASE_STUB=1 \
    cargo build --quiet --release --package ibex-compiled-stub
else
  CARGO_TARGET_DIR="$stub_target_dir" \
    IBEX_STUB_CONTRACT_PATH="$stub_contract_path" \
    cargo build --quiet --release --package ibex-compiled-stub
fi
stub_core="$release_stage/ibex-compiled-stub-unsigned-core"
cp "$stub_target_dir/release/ibex-compiled-stub" "$stub_core"
if [[ "$target_triple" == "aarch64-apple-darwin" ]]; then
  codesign --remove-signature "$stub_core"

  [[ "$minimum_platform" =~ ^macos-([0-9]+\.[0-9]+)-arm64$ ]] || {
    echo "macOS minimum platform has an unsupported spelling: $minimum_platform" >&2
    exit 1
  }
  declared_macos_minimum="${BASH_REMATCH[1]}"
  actual_macos_minimum="$(otool -l "$stub_core" | awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
    in_build && $1 == "minos" { print $2; exit }
  ')"
  [[ -n "$actual_macos_minimum" ]] || {
    echo "release stub has no LC_BUILD_VERSION minimum macOS declaration" >&2
    exit 1
  }
  python3 -c '
import sys

def version(value):
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (3 - len(parts))

actual, declared = map(version, sys.argv[1:3])
if actual > declared:
    raise SystemExit(
        f"release stub requires macOS {sys.argv[1]}, newer than declared baseline {sys.argv[2]}"
    )
' "$actual_macos_minimum" "$declared_macos_minimum"
fi

catalog_store="$release_stage/catalogs"
catalog_report="$release_stage/catalog-report.json"
cargo run --quiet --release --package ibex-sfe-catalog --bin ibex-sfe-catalog -- assemble \
  --release "$release_name" \
  --sequence "$catalog_sequence" \
  --contract "$contract_path" \
  --stub "$stub_core" \
  --hermesc "$hermesc_path" \
  --catalogs-dir "$catalog_store" > "$catalog_report"
catalog_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["catalogDigest"])' "$catalog_report")"
catalog_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["catalogRoot"])' "$catalog_report")"
catalog_key="${catalog_digest#sha256-}"
[[ "$catalog_digest" == "sha256-$catalog_key" && ${#catalog_key} -eq 43 ]] || {
  echo "catalog assembler returned a malformed digest: $catalog_digest" >&2
  exit 1
}
[[ "$catalog_root" == "$catalog_store/$catalog_key" && -f "$catalog_root/manifest.json" ]] || {
  echo "catalog assembler returned an unexpected root: $catalog_root" >&2
  exit 1
}

# Ship the exact policy authoring code, CapSec contract inputs, native package
# closure, and Bun runner as a closed producer-only tree. The resulting app
# never reads this directory; it exists solely so a release `ibex policy`
# command does not need a source checkout or ambient JS installation.
# @ref LLP 0047#8-milestone-5--distribution-and-usability
policy_toolchain_root="$release_stage/policy-toolchain"
mkdir -p \
  "$policy_toolchain_root/bin" \
  "$policy_toolchain_root/packages/ibex-runtime-js/src/security"
cp -a "$repo_root/capsec" "$policy_toolchain_root/capsec"
cp -a "$repo_root/include" "$policy_toolchain_root/include"
cp -a "$repo_root/scripts" "$policy_toolchain_root/scripts"
cp -a "$repo_root/src" "$policy_toolchain_root/src"
mkdir -p "$policy_toolchain_root/packages"
cp -a "$repo_root/packages/ibex-devtools" \
  "$policy_toolchain_root/packages/ibex-devtools"
cp "$repo_root/packages/ibex-runtime-js/src/security/capsec-registry.generated.ts" \
  "$policy_toolchain_root/packages/ibex-runtime-js/src/security/capsec-registry.generated.ts"
cp "$repo_root/package.json" "$policy_toolchain_root/package.json"
cp "$repo_root/bun.lock" "$policy_toolchain_root/bun.lock"
cp -a "$repo_root/node_modules" "$policy_toolchain_root/node_modules"
cp "$policy_runner_path" "$policy_toolchain_root/bin/bun"
chmod +x "$policy_toolchain_root/bin/bun"

policy_toolchain_report="$release_stage/policy-toolchain-report.json"
cargo run --quiet --release --package ibex-sfe-catalog \
  --bin ibex-sfe-policy-toolchain -- \
  --root "$policy_toolchain_root" \
  --target "$target_triple" \
  --runner bin/bun \
  --script packages/ibex-devtools/src/scripts/generate-policy.mjs \
  > "$policy_toolchain_report"
policy_toolchain_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["toolchainDigest"])' "$policy_toolchain_report")"
policy_toolchain_key="${policy_toolchain_digest#sha256-}"
[[ "$policy_toolchain_digest" == "sha256-$policy_toolchain_key" && ${#policy_toolchain_key} -eq 43 ]] || {
  echo "policy-toolchain assembler returned a malformed digest: $policy_toolchain_digest" >&2
  exit 1
}
policy_toolchain_name="ibex-policy-toolchain-$policy_toolchain_key"

if [[ "$target_triple" == "x86_64-unknown-linux-gnu" ]]; then
  IBEX_RELEASE_SFE_CATALOG_DIGEST="$catalog_digest" \
  IBEX_RELEASE_POLICY_TOOLCHAIN_DIGEST="$policy_toolchain_digest" \
    cargo build --quiet --release --bin ibex --features sfe-static-network
else
  IBEX_RELEASE_SFE_CATALOG_DIGEST="$catalog_digest" \
  IBEX_RELEASE_POLICY_TOOLCHAIN_DIGEST="$policy_toolchain_digest" \
    cargo build --quiet --release --bin ibex
fi
IBEX_RELEASE_SFE_CATALOG_DIGEST="$catalog_digest" \
  cargo build --quiet --release --package ibex-sfe-catalog --bin ibex-sfe-catalog

deliverable="$release_stage/deliverable"
mkdir "$deliverable"
cp "$producer_target_dir/release/ibex" "$deliverable/ibex"
cp "$producer_target_dir/release/ibex-sfe-catalog" "$deliverable/ibex-sfe-catalog"
asset_base="ibex-sfe-catalog-$package_version-$target_triple-$catalog_key"
asset_name="$asset_base.tar.gz"
tar -C "$catalog_store" -czf "$deliverable/$asset_name" "$catalog_key"
cp "$contract_report" "$deliverable/contract-report.json"
cp "$catalog_report" "$deliverable/catalog-report.json"
cp "$policy_toolchain_report" "$deliverable/policy-toolchain-report.json"
mv "$policy_toolchain_root" "$deliverable/$policy_toolchain_name"
if [[ "$target_triple" == "x86_64-unknown-linux-gnu" ]]; then
  scripts/audit-sfe-linux-deps.sh \
    "$stub_core" \
    --contract "$contract_path" \
    --output "$deliverable/dependency-audit.json"
fi

mkdir -p "$(dirname "$output_dir")"
mv "$deliverable" "$output_dir"
echo "releaseKit=$output_dir"
echo "catalogDigest=$catalog_digest"
echo "policyToolchainDigest=$policy_toolchain_digest"
echo "catalogAsset=$output_dir/$asset_name"
echo "installCommand=tar -xzf $asset_name && $output_dir/ibex-sfe-catalog install --source $catalog_key"
