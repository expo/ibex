#!/usr/bin/env bash
# Exercise the catalog-installed producer and final-recipient path for one
# host-target SFE release kit. This is intentionally downstream of catalog
# construction: it uses only the release installation's catalog-pinned Ibex,
# pinned catalog installer, addressed catalog, and authenticated policy
# toolchain. It then relocates the output, removes source/catalog availability,
# and runs only the final image.
# @ref LLP 0047#8-milestone-5--distribution-and-usability
set -euo pipefail

usage() {
  echo "usage: $0 RELEASE_KIT_DIRECTORY [--evidence-output DIRECTORY]" >&2
  exit 2
}

[[ $# -eq 1 || ( $# -eq 3 && "$2" == "--evidence-output" ) ]] || usage
kit="$1"
evidence_output=""
if [[ $# -eq 3 ]]; then
  evidence_output="$3"
  if [[ "$evidence_output" != /* ]]; then
    evidence_output="$PWD/$evidence_output"
  fi
  [[ ! -e "$evidence_output" ]] || {
    echo "release-kit evidence output already exists: $evidence_output" >&2
    exit 1
  }
fi
[[ -d "$kit" ]] || usage
kit="$(cd "$kit" && pwd -P)"
ibex="$kit/ibex"
installer="$kit/ibex-sfe-catalog"
catalog_report="$kit/catalog-report.json"
policy_toolchain_report="$kit/policy-toolchain-report.json"
[[ -x "$ibex" ]] || { echo "release kit Ibex is absent or not executable: $ibex" >&2; exit 1; }
[[ -x "$installer" ]] || { echo "release kit catalog installer is absent or not executable: $installer" >&2; exit 1; }
[[ -f "$catalog_report" ]] || { echo "release kit catalog report is absent: $catalog_report" >&2; exit 1; }
[[ -f "$policy_toolchain_report" ]] || { echo "release kit policy-toolchain report is absent: $policy_toolchain_report" >&2; exit 1; }

catalog_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["catalogDigest"])' "$catalog_report")"
catalog_key="${catalog_digest#sha256-}"
[[ "$catalog_digest" == "sha256-$catalog_key" && ${#catalog_key} -eq 43 ]] || {
  echo "release kit catalog report has a malformed digest: $catalog_digest" >&2
  exit 1
}
catalog_assets=("$kit"/ibex-sfe-catalog-*"-$catalog_key.tar.gz")
[[ ${#catalog_assets[@]} -eq 1 && -f "${catalog_assets[0]}" ]] || {
  echo "release kit must contain exactly one catalog asset for $catalog_digest" >&2
  exit 1
}
catalog_asset="${catalog_assets[0]}"
catalog_asset_name="$(basename "$catalog_asset")"
policy_toolchain_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["toolchainDigest"])' "$policy_toolchain_report")"
policy_toolchain_key="${policy_toolchain_digest#sha256-}"
[[ "$policy_toolchain_digest" == "sha256-$policy_toolchain_key" && ${#policy_toolchain_key} -eq 43 ]] || {
  echo "release kit policy-toolchain report has a malformed digest: $policy_toolchain_digest" >&2
  exit 1
}
policy_toolchain_root="$kit/ibex-policy-toolchain-$policy_toolchain_key"
[[ -d "$policy_toolchain_root" && -f "$policy_toolchain_root/manifest.json" ]] || {
  echo "release kit policy toolchain is absent: $policy_toolchain_root" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/ibex-sfe-kit-check.XXXXXX")"
server_pid=""
lifecycle_pid=""
catalog_installed_root=""
catalog_was_present=false
original_catalog_withdrawn=false
catalog_moved=false
evidence_stage=""
signature_replacement_app=""
cleanup_kit_check() {
  # Bash inherits the EXIT trap in parenthesized commands. A crashing fixture
  # must return control to the top-level shell before cleanup withdraws the
  # work tree; otherwise the child can erase the saved preexisting catalog
  # before the parent has a chance to restore it.
  [[ "${BASH_SUBSHELL:-0}" -eq 0 ]] || return 0
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$lifecycle_pid" ]]; then
    kill -KILL "$lifecycle_pid" 2>/dev/null || true
    wait "$lifecycle_pid" 2>/dev/null || true
  fi
  if [[ -n "$catalog_installed_root" && -d "$catalog_installed_root" ]]; then
    mv "$catalog_installed_root" "$work/catalog.cleanup"
  fi
  if [[ "$original_catalog_withdrawn" == true ]]; then
    mkdir -p "$(dirname "$catalog_installed_root")"
    mv "$work/catalog.preexisting" "$catalog_installed_root"
    original_catalog_withdrawn=false
  fi
  if [[ -n "$evidence_stage" && -d "$evidence_stage" ]]; then
    [[ "$(basename "$evidence_stage")" == .ibex-sfe-evidence.* ]] || return
    rm -rf -- "$evidence_stage"
  fi
  [[ "$work" == *ibex-sfe-kit-check.* ]] || return
  rm -rf -- "$work"
}
trap cleanup_kit_check EXIT INT TERM

mkdir "$work/acquired" "$work/source" "$work/www" "$work/relocated" "$work/tampered"
mkdir "$work/home"
tar -C "$work/acquired" -xzf "$catalog_asset"
catalog_source="$work/acquired/$catalog_key"
[[ -f "$catalog_source/manifest.json" ]] || {
  echo "catalog asset does not contain addressed root $catalog_key" >&2
  exit 1
}
cp "$repo_root/tests/fixtures/sfe-release/network.mts" "$work/source/main.mts"
cp "$repo_root/tests/fixtures/sfe-release/network-value.mts" \
  "$work/source/network-value.mts"
cp "$repo_root/tests/fixtures/sfe-release/top-level-await.mts" "$work/source/tla.mts"
cp "$repo_root/tests/fixtures/sfe-release/lifecycle.mts" "$work/source/lifecycle.mts"
cp "$repo_root/tests/fixtures/sfe-release/http-server.mts" \
  "$work/source/http-server.mts"
cp "$repo_root/tests/fixtures/sfe-release/unavailable-backends.mts" \
  "$work/source/unavailable-backends.mts"
cp -R "$repo_root/tests/fixtures/sfe-release/module-matrix" "$work/source/module-matrix"
cp -R "$repo_root/tests/fixtures/sfe-release/unsupported-sites" \
  "$work/source/unsupported-sites"
cp "$repo_root/tests/fixtures/sfe-release/network-response.txt" "$work/www/response.txt"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    target_triple="aarch64-apple-darwin"
    expected_catalog_root="$HOME/Library/Caches/ibex/sfe-catalogs/$catalog_key"
    ;;
  Linux-x86_64)
    target_triple="x86_64-unknown-linux-gnu"
    expected_catalog_root="$work/cache/ibex/sfe-catalogs/$catalog_key"
    ;;
  *)
    echo "release-kit check has no v1 target for $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac
if [[ -d "$expected_catalog_root" ]]; then
  catalog_was_present=true
  catalog_installed_root="$expected_catalog_root"
  mv "$expected_catalog_root" "$work/catalog.preexisting"
  original_catalog_withdrawn=true
fi

policy_environment=(
  env -i
  "PATH=/usr/bin:/bin"
  "HOME=$work/home"
  "XDG_CACHE_HOME=$work/cache"
  "IBEX_REPO_ROOT=$work/checkout-must-not-be-used"
)
mkdir "$work/missing-policy-toolchain-install"
cp "$ibex" "$work/missing-policy-toolchain-install/ibex"
set +e
"${policy_environment[@]}" "$work/missing-policy-toolchain-install/ibex" policy generate \
  --entry "$work/source/main.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/missing-policy-toolchain.json" \
  > "$work/missing-policy-toolchain.stdout" \
  2> "$work/missing-policy-toolchain.stderr"
missing_policy_toolchain_exit=$?
set -e
[[ "$missing_policy_toolchain_exit" -eq 1 && ! -e "$work/missing-policy-toolchain.json" ]] || {
  echo "release Ibex did not refuse its missing packaged policy toolchain" >&2
  exit 1
}
rg -F 'SFP002 packaged policy author unavailable' \
  "$work/missing-policy-toolchain.stderr" >/dev/null

"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/main.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/ibex-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/tla.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/tla-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/module-matrix/entry.mjs" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/module-matrix-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/lifecycle.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/lifecycle-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/http-server.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/http-server-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/unavailable-backends.mts" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/unavailable-backends-policy.json"
"${policy_environment[@]}" "$ibex" policy generate \
  --entry "$work/source/unsupported-sites/entry.mjs" \
  --target-profile sfe-v1 \
  --target-triple "$target_triple" \
  --out "$work/unsupported-sites-policy.json"

set +e
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/main.mts" \
  --policy "$work/ibex-policy.json" \
  --output "$work/should-not-exist" \
  > "$work/missing-catalog.stdout" 2> "$work/missing-catalog.stderr"
missing_catalog_exit=$?
set -e
[[ "$missing_catalog_exit" -eq 1 && ! -e "$work/should-not-exist" ]] || {
  echo "compile did not refuse the absent release catalog" >&2
  exit 1
}
rg -F "$catalog_asset_name" "$work/missing-catalog.stderr" >/dev/null
rg -F 'ibex-sfe-catalog install --source' "$work/missing-catalog.stderr" >/dev/null

XDG_CACHE_HOME="$work/cache" "$installer" install --source "$catalog_source" \
  > "$work/catalog-install.json"
python3 -c '
import json, pathlib, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
expected_root = pathlib.Path(sys.argv[3]).resolve()
assert report["catalogDigest"] == expected
assert pathlib.Path(report["catalogRoot"]).resolve() == expected_root
' "$work/catalog-install.json" "$catalog_digest" "$expected_catalog_root"
catalog_installed_root="$expected_catalog_root"

XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/main.mts" \
  --policy "$work/ibex-policy.json" \
  --output "$work/standalone" \
  > "$work/compile.stdout" 2> "$work/compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/tla.mts" \
  --policy "$work/tla-policy.json" \
  --output "$work/tla-standalone" \
  > "$work/tla-compile.stdout" 2> "$work/tla-compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/module-matrix/entry.mjs" \
  --policy "$work/module-matrix-policy.json" \
  --output "$work/module-matrix-standalone" \
  > "$work/module-matrix-compile.stdout" 2> "$work/module-matrix-compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/lifecycle.mts" \
  --policy "$work/lifecycle-policy.json" \
  --output "$work/lifecycle-standalone" \
  > "$work/lifecycle-compile.stdout" 2> "$work/lifecycle-compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/http-server.mts" \
  --policy "$work/http-server-policy.json" \
  --output "$work/http-server-standalone" \
  > "$work/http-server-compile.stdout" 2> "$work/http-server-compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile "$work/source/unavailable-backends.mts" \
  --policy "$work/unavailable-backends-policy.json" \
  --output "$work/unavailable-backends-standalone" \
  > "$work/unavailable-backends-compile.stdout" \
  2> "$work/unavailable-backends-compile.stderr"
XDG_CACHE_HOME="$work/cache" "$ibex" compile \
  "$work/source/unsupported-sites/entry.mjs" \
  --policy "$work/unsupported-sites-policy.json" \
  --output "$work/unsupported-sites-standalone" \
  > "$work/unsupported-sites-compile.stdout" \
  2> "$work/unsupported-sites-compile.stderr"
for unsupported_shape in \
  computed-dynamic-import-without-candidate-table \
  computed-commonjs-require \
  unsupported-dynamic-import-options; do
  rg -F "$unsupported_shape" "$work/unsupported-sites-compile.stderr" >/dev/null
done
set +e
XDG_CACHE_HOME="$work/cache" "$ibex" compile \
  "$work/source/unsupported-sites/entry.mjs" \
  --policy "$work/unsupported-sites-policy.json" \
  --deny-unsupported \
  --output "$work/unsupported-sites-denied" \
  > "$work/unsupported-sites-denied.stdout" \
  2> "$work/unsupported-sites-denied.stderr"
unsupported_sites_denied_exit=$?
set -e
[[ "$unsupported_sites_denied_exit" -eq 1 && ! -e "$work/unsupported-sites-denied" ]] || {
  echo "--deny-unsupported did not refuse the guarded-site graph" >&2
  exit 1
}
rg -F 'SFE_UNSUPPORTED_SITES: --deny-unsupported refused 3' \
  "$work/unsupported-sites-denied.stderr" >/dev/null
if [[ "$target_triple" == "aarch64-apple-darwin" ]]; then
  # A copied SFE may use Apple system libraries, but it must not retain an
  # @rpath Hermes dependency or any build-host search path. This check runs on
  # the assembled app, not merely the pre-envelope stub.
  # @ref LLP 0047#8-milestone-5--distribution-and-usability
  otool -L "$work/standalone" > "$work/standalone.otool-libraries"
  if tail -n +2 "$work/standalone.otool-libraries" | \
      rg -v '^\s+(/System/Library/|/usr/lib/)' > "$work/non-system-dylibs"; then
    echo "macOS standalone retains a non-system dynamic dependency" >&2
    cat "$work/non-system-dylibs" >&2
    exit 1
  fi
  otool -l "$work/standalone" > "$work/standalone.otool-load-commands"
  if rg -A2 '^\s+cmd LC_RPATH$' "$work/standalone.otool-load-commands" \
      > "$work/standalone-rpaths"; then
    echo "macOS standalone retains a runtime search path" >&2
    cat "$work/standalone-rpaths" >&2
    exit 1
  fi
  declared_macos_baseline="$(python3 -c '
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
entries = [entry for entry in manifest["entries"] if entry["target"] == sys.argv[2]]
assert len(entries) == 1
print(entries[0]["minimumPlatform"])
' "$catalog_source/manifest.json" "$target_triple")"
  [[ "$declared_macos_baseline" =~ ^macos-([0-9]+\.[0-9]+)-arm64$ ]] || {
    echo "catalog has an unsupported macOS baseline: $declared_macos_baseline" >&2
    exit 1
  }
  declared_macos_minimum="${BASH_REMATCH[1]}"
  actual_macos_minimum="$(awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
    in_build && $1 == "minos" { print $2; exit }
  ' "$work/standalone.otool-load-commands")"
  [[ -n "$actual_macos_minimum" ]] || {
    echo "macOS standalone has no LC_BUILD_VERSION minimum declaration" >&2
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
        f"macOS standalone requires {sys.argv[1]}, newer than catalog baseline {sys.argv[2]}"
    )
' "$actual_macos_minimum" "$declared_macos_minimum"
fi
"$ibex" inspect-executable "$work/standalone" > "$work/inspection.json"
"$ibex" inspect-executable "$work/module-matrix-standalone" \
  > "$work/module-matrix-inspection.json"
python3 -c '
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
target = sys.argv[3]
assert report["schema"] == "ibex/executable-inspection/3"
assert report["envelopeConsistency"]["state"] == "consistent"
assert report["runtimeAdmission"]["state"] == "inner-contracts-admitted"
assert report["stubCoreConsistency"]["state"] == "consistent"
assert report["stubCoreConsistency"]["digest"] == report["provenance"]["stubCoreDigest"]
assert report["boot"]["defaultMode"] == "ambient-compatibility"
assert report["boot"]["capsecSelector"]["spelling"] == "--ibex-capsec"
assert report["boot"]["informationSelector"]["spelling"] == "--ibex-info"
assert report["boot"]["informationSelector"]["reportSchema"] == "ibex/standalone-executable-info/1"
assert report["boot"]["capsecAvailability"] == "unavailable-no-advertisement"
assert report["provenance"]["compilePlan"]["catalogDigest"] == expected
assert report["target"]["triple"] == target
backends = {row["surface"]: row for row in report["backendInventory"]["entries"]}
assert backends["fetch"]["status"] == "available"
assert backends["http-server"]["status"] == "available"
assert backends["websocket"]["status"] == "available"
assert backends["signals"]["status"] == "limited"
assert backends["workers"]["status"] == "unavailable"
if target == "aarch64-apple-darwin":
    assert backends["fetch"]["implementation"] == "nsurlsession"
else:
    assert backends["fetch"]["implementation"] == "static-libcurl-vendored-openssl"
' "$work/inspection.json" "$catalog_digest" "$target_triple"

# The inspector must project and rehash the actual outer stub bytes rather than
# echoing the digest claimed by embedded provenance. Mutate header slack on
# Mach-O and the final pre-envelope stub byte on ELF; both stay outside the
# authenticated inner envelope, so only the explicit stub-core check owns this
# refusal.
# @ref LLP 0029#2-executable-layout-stub-envelope-footer
stub_tampered="$work/tampered/stub-core"
cp "$work/standalone" "$stub_tampered"
python3 - "$stub_tampered" "$work/inspection.json" <<'PY'
import json, struct, sys

path = sys.argv[1]
inspection = json.load(open(sys.argv[2], encoding="utf-8"))
data = bytearray(open(path, "rb").read())
if data[:4] == struct.pack("<I", 0xfeedfacf):
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    offset = 32 + sizeofcmds + 32
else:
    offset = inspection["provenance"]["stubCoreReconstruction"]["size"] - 1
assert 0 <= offset < len(data)
data[offset] ^= 1
open(path, "wb").write(data)
PY
set +e
"$ibex" inspect-executable "$stub_tampered" \
  > "$work/stub-core-tamper.stdout" 2> "$work/stub-core-tamper.stderr"
stub_core_tamper_exit=$?
set -e
[[ "$stub_core_tamper_exit" -eq 1 ]] || {
  echo "inspection admitted a mutated outer stub core" >&2
  exit 1
}
rg -F 'executable stub core disagrees with release provenance' \
  "$work/stub-core-tamper.stderr" >/dev/null

if [[ "$target_triple" == "aarch64-apple-darwin" ]]; then
  # Exercise the real platform replacement operation, not only a synthetic
  # load-command vector. Apple's signature removal is not specified as a
  # byte-for-byte inverse of signing, so it must not be confused with the
  # producer-recorded pre-signing digest. The stripped image must preserve the
  # authenticated envelope/CompilePlan identity while reporting an invalid
  # platform-signature axis. Re-signing must restore strict platform/layout
  # validity and runnable behavior without changing that inner identity.
  # @ref LLP 0029#2-executable-layout-stub-envelope-footer
  signature_replacement_app="$work/signature-replacement-standalone"
  cp "$work/standalone" "$signature_replacement_app"
  /usr/bin/codesign --remove-signature "$signature_replacement_app"
  "$ibex" inspect-executable "$signature_replacement_app" \
    > "$work/signature-replacement-unsigned-inspection.json"
  python3 -c '
import json, sys
original = json.load(open(sys.argv[1], encoding="utf-8"))
stripped = json.load(open(sys.argv[2], encoding="utf-8"))
assert stripped["envelopeConsistency"]["state"] == "consistent"
assert stripped["runtimeAdmission"]["state"] == "inner-contracts-admitted"
assert stripped["stubCoreConsistency"] == original["stubCoreConsistency"]
assert stripped["platformSignature"]["state"] == "invalid"
assert stripped["authorityBundle"]["graphIdentity"] == original["authorityBundle"]["graphIdentity"]
assert stripped["provenance"]["compilePlan"] == original["provenance"]["compilePlan"]
' "$work/inspection.json" "$work/signature-replacement-unsigned-inspection.json"
  /usr/bin/codesign --force --sign - --options runtime --timestamp=none \
    "$signature_replacement_app"
  /usr/bin/codesign --verify --strict --verbose=2 "$signature_replacement_app"
  /usr/bin/codesign --display --verbose=4 "$signature_replacement_app" \
    > /dev/null 2> "$work/signature-replacement-codesign.txt"
  rg 'flags=.*runtime' "$work/signature-replacement-codesign.txt" >/dev/null
  "$ibex" inspect-executable "$signature_replacement_app" \
    > "$work/signature-replacement-signed-inspection.json"
  python3 -c '
import json, sys
original = json.load(open(sys.argv[1], encoding="utf-8"))
replacement = json.load(open(sys.argv[2], encoding="utf-8"))
assert replacement["envelopeConsistency"]["state"] == "consistent"
assert replacement["runtimeAdmission"]["state"] == "inner-contracts-admitted"
assert replacement["stubCoreConsistency"] == original["stubCoreConsistency"]
assert replacement["platformSignature"]["state"] == "valid"
assert replacement["authorityBundle"]["graphIdentity"] == original["authorityBundle"]["graphIdentity"]
assert replacement["provenance"]["compilePlan"] == original["provenance"]["compilePlan"]
' "$work/inspection.json" "$work/signature-replacement-signed-inspection.json"
fi

cp "$work/standalone" "$work/relocated/app"
cp "$work/tla-standalone" "$work/relocated/tla"
cp "$work/module-matrix-standalone" "$work/relocated/module-matrix"
cp "$work/lifecycle-standalone" "$work/relocated/lifecycle"
cp "$work/http-server-standalone" "$work/relocated/http-server"
cp "$work/unavailable-backends-standalone" "$work/relocated/unavailable-backends"
cp "$work/unsupported-sites-standalone" "$work/relocated/unsupported-sites"
if [[ -n "$signature_replacement_app" ]]; then
  cp "$signature_replacement_app" "$work/relocated/signature-replacement"
fi
mv "$work/source" "$work/source.unavailable"
mv "$catalog_installed_root" "$work/catalog.unavailable"
catalog_moved=true

# A copied executable must explain its authenticated posture without the Ibex
# CLI, its catalog, its source tree, or application evaluation. The network
# fixture would print a non-JSON marker if entry evaluation occurred.
# @ref LLP 0047#8-milestone-5--distribution-and-usability
(cd "$work/relocated" && ./app --ibex-info) \
  > "$work/standalone-info.json" 2> "$work/standalone-info.stderr"
[[ ! -s "$work/standalone-info.stderr" ]] || {
  echo "standalone information selector wrote unexpected stderr" >&2
  sed -n '1,20p' "$work/standalone-info.stderr" >&2
  exit 1
}
python3 -c '
import json, sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
inspection = json.load(open(sys.argv[2], encoding="utf-8"))
assert info["schema"] == "ibex/standalone-executable-info/1"
assert info["execution"] == {"applicationEvaluated": False}
assert info["integrity"]["status"] == "admitted"
assert info["integrity"]["stubContractDigest"] == inspection["envelopeConsistency"]["stubContractDigest"]
assert info["integrity"]["graphIdentity"] == inspection["runtimeAdmission"]["graphIdentity"]
assert info["boot"] == inspection["boot"]
assert info["target"] == inspection["target"]
assert info["backendInventory"] == inspection["backendInventory"]
assert info["provenanceKind"] == "release"
' "$work/standalone-info.json" "$work/inspection.json"

python3 "$repo_root/tests/fixtures/sfe-release/http_server.py" "$work/www" \
  > "$work/server.port" 2> "$work/server.stderr" &
server_pid=$!
for _attempt in 1 2 3 4 5; do
  if [[ -s "$work/server.port" ]]; then
    break
  fi
  sleep 1
done
server_port="$(sed -n '1p' "$work/server.port")"
[[ "$server_port" =~ ^[1-9][0-9]{1,4}$ ]] || {
  echo "fixture HTTP server did not publish a valid port" >&2
  sed -n '1,20p' "$work/server.stderr" >&2
  exit 1
}
fixture_url="http://127.0.0.1:$server_port/response.txt"
curl -fsS "$fixture_url" > /dev/null
set +e
(cd "$work/relocated" && ./app "$fixture_url") \
  > "$work/ambient.stdout" 2> "$work/ambient.stderr"
ambient_exit=$?
set -e
[[ "$ambient_exit" -eq 0 ]] || {
  echo "relocated ambient SFE exited $ambient_exit" >&2
  sed -n '1,40p' "$work/ambient.stderr" >&2
  exit 1
}
[[ "$(cat "$work/ambient.stdout")" == "fetch=200:sfe-network-ok" ]] || {
  echo "relocated ambient SFE produced unexpected output" >&2
  sed -n '1,40p' "$work/ambient.stdout" >&2
  exit 1
}
if [[ -n "$signature_replacement_app" ]]; then
  set +e
  (cd "$work/relocated" && ./signature-replacement "$fixture_url") \
    > "$work/signature-replacement.stdout" \
    2> "$work/signature-replacement.stderr"
  signature_replacement_exit=$?
  set -e
  [[ "$signature_replacement_exit" -eq 0 && \
     "$(cat "$work/signature-replacement.stdout")" == "fetch=200:sfe-network-ok" ]] || {
    echo "replacement-signed relocated SFE did not preserve execution" >&2
    sed -n '1,40p' "$work/signature-replacement.stderr" >&2
    exit 1
  }
fi

# Exercise the OS argument field rather than only the Rust decoder helper.
# Python's bytes argv preserves the invalid byte through execve on both v1
# POSIX tuples; the final image must refuse before evaluating the entry and
# name the zero-based application argument index.
# @ref LLP 0029#6-compiled-boot-and-process-semantics
set +e
python3 - "$work/relocated/app" \
  > "$work/non-unicode-argv.stdout" \
  2> "$work/non-unicode-argv.stderr" <<'PY'
import os
import sys

executable = os.fsencode(sys.argv[1])
os.execve(executable, [executable, b"\xff"], os.environb)
PY
non_unicode_argv_exit=$?
set -e
[[ "$non_unicode_argv_exit" -eq 1 && ! -s "$work/non-unicode-argv.stdout" ]] || {
  echo "non-Unicode argv fixture did not refuse before application output" >&2
  sed -n '1,20p' "$work/non-unicode-argv.stdout" >&2
  sed -n '1,20p' "$work/non-unicode-argv.stderr" >&2
  exit 1
}
rg -F 'compiled process argument 1 is not valid Unicode' \
  "$work/non-unicode-argv.stderr" >/dev/null || {
  echo "non-Unicode argv fixture omitted the offending argument index" >&2
  sed -n '1,20p' "$work/non-unicode-argv.stderr" >&2
  exit 1
}

set +e
(cd "$work/relocated" && ./tla) \
  > "$work/tla.stdout" 2> "$work/tla.stderr"
tla_exit=$?
set -e
[[ "$tla_exit" -eq 0 ]] || {
  echo "relocated top-level-await SFE exited $tla_exit" >&2
  sed -n '1,40p' "$work/tla.stderr" >&2
  exit 1
}
[[ "$(cat "$work/tla.stdout")" == "top-level-await-ok" ]] || {
  echo "relocated top-level-await SFE produced unexpected output" >&2
  sed -n '1,40p' "$work/tla.stdout" >&2
  exit 1
}

set +e
(cd "$work/relocated" && ./module-matrix right) \
  > "$work/module-matrix.stdout" 2> "$work/module-matrix.stderr"
module_matrix_exit=$?
set -e
[[ "$module_matrix_exit" -eq 0 ]] || {
  echo "relocated module-matrix SFE exited $module_matrix_exit" >&2
  sed -n '1,40p' "$work/module-matrix.stderr" >&2
  exit 1
}
[[ "$(cat "$work/module-matrix.stdout")" == "ibex:commonjs:static-esm:literal-dynamic:right" ]] || {
  echo "relocated module-matrix SFE produced unexpected output" >&2
  sed -n '1,40p' "$work/module-matrix.stdout" >&2
  exit 1
}
(cd "$work/relocated" && ./unsupported-sites) \
  > "$work/unsupported-sites.stdout" 2> "$work/unsupported-sites.stderr"
rg -Fx 'unsupported-sites-ok' "$work/unsupported-sites.stdout" >/dev/null

set +e
(cd "$work/relocated" && ./lifecycle exit-code) \
  > "$work/exit-code.stdout" 2> "$work/exit-code.stderr"
exit_code_exit=$?
(cd "$work/relocated" && ./lifecycle process-exit) \
  > "$work/process-exit.stdout" 2> "$work/process-exit.stderr"
process_exit_exit=$?
(cd "$work/relocated" && ./lifecycle foreground-throw) \
  > "$work/foreground-throw.stdout" 2> "$work/foreground-throw.stderr"
foreground_throw_exit=$?
(cd "$work/relocated" && ./lifecycle background-throw) \
  > "$work/background-throw.stdout" 2> "$work/background-throw.stderr"
background_throw_exit=$?
(cd "$work/relocated" && ./lifecycle rejection) \
  > "$work/rejection.stdout" 2> "$work/rejection.stderr"
rejection_exit=$?
(cd "$work/relocated" && ./lifecycle unavailable-worker) \
  > "$work/unavailable-worker.stdout" 2> "$work/unavailable-worker.stderr"
unavailable_worker_exit=$?
set -e
[[ "$exit_code_exit" -eq 24 && "$(cat "$work/exit-code.stdout")" == "exit-code-ready" ]] || {
  echo "numeric process.exitCode contract failed: status=$exit_code_exit" >&2
  sed -n '1,20p' "$work/exit-code.stdout" >&2
  sed -n '1,20p' "$work/exit-code.stderr" >&2
  exit 1
}
[[ "$process_exit_exit" -eq 23 && "$(cat "$work/process-exit.stdout")" == "process-exit-ready" ]] || {
  echo "process.exit contract failed" >&2
  exit 1
}
[[ "$foreground_throw_exit" -eq 1 ]] || {
  echo "foreground exception did not exit 1" >&2
  exit 1
}
[[ "$background_throw_exit" -eq 1 ]] || {
  echo "background exception did not exit 1" >&2
  exit 1
}
[[ "$rejection_exit" -eq 1 ]] || {
  echo "unhandled rejection did not exit 1" >&2
  exit 1
}
[[ "$unavailable_worker_exit" -eq 0 ]] || {
  echo "unavailable worker backend did not return its stable refusal: status=$unavailable_worker_exit" >&2
  sed -n '1,20p' "$work/unavailable-worker.stdout" >&2
  sed -n '1,20p' "$work/unavailable-worker.stderr" >&2
  exit 1
}
rg -Fx 'worker_threads.Worker is not supported in this runtime. Use child_process instead.' \
  "$work/unavailable-worker.stdout" >/dev/null
(cd "$work/relocated" && ./http-server) \
  > "$work/http-server.stdout" 2> "$work/http-server.stderr"
rg -Fx 'http-server=200:ibex-standalone-http-server' \
  "$work/http-server.stdout" >/dev/null
set +e
(cd "$work/relocated" && ./unavailable-backends) \
  > "$work/unavailable-backends.stdout" 2> "$work/unavailable-backends.stderr"
unavailable_backends_exit=$?
set -e
[[ "$unavailable_backends_exit" -eq 0 ]] || {
  echo "unavailable backend refusal matrix failed: status=$unavailable_backends_exit" >&2
  sed -n '1,20p' "$work/unavailable-backends.stdout" >&2
  sed -n '1,20p' "$work/unavailable-backends.stderr" >&2
  exit 1
}
expected_unavailable_backends=$'http2=http2.createServer is not supported in this runtime without native HTTP/2 support\ninspector=Inspector is not available in this runtime\nwasi=WASI is not supported in this runtime\nworkers=worker_threads.Worker is not supported in this runtime. Use child_process instead.'
[[ "$(cat "$work/unavailable-backends.stdout")" == "$expected_unavailable_backends" ]] || {
  echo "unavailable backend refusals did not match their stable errors" >&2
  sed -n '1,20p' "$work/unavailable-backends.stdout" >&2
  sed -n '1,20p' "$work/unavailable-backends.stderr" >&2
  exit 1
}
rg -F 'compiled JavaScript background failure was unhandled' \
  "$work/background-throw.stderr" >/dev/null
rg -F 'compiled JavaScript background failure was unhandled' \
  "$work/rejection.stderr" >/dev/null

run_signal_case() {
  local signal_name="$1"
  local expected_status="$2"
  local output="$work/signal-$signal_name.stdout"
  local error="$work/signal-$signal_name.stderr"
  local status
  (cd "$work/relocated" && exec ./lifecycle signal) > "$output" 2> "$error" &
  lifecycle_pid=$!
  for _attempt in $(seq 1 50); do
    if rg -Fx 'signal-ready' "$output" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$lifecycle_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  rg -Fx 'signal-ready' "$output" >/dev/null || {
    echo "$signal_name fixture did not become ready" >&2
    exit 1
  }
  kill -s "$signal_name" "$lifecycle_pid"
  set +e
  wait "$lifecycle_pid"
  status=$?
  set -e
  lifecycle_pid=""
  [[ "$status" -eq "$expected_status" ]] || {
    echo "$signal_name lifecycle status was $status, expected $expected_status" >&2
    exit 1
  }
}

run_signal_case INT 130
run_signal_case TERM 143
run_signal_case HUP 129

# Corrupt every load-bearing section independently in a copy of the final
# image. With the sentinel enabled, any module evaluation writes to stdout, so
# an empty stream proves bulk preflight refused before a carrier ran. The
# unselected candidate carrier is included to catch lazy, reached-only checks.
# @ref LLP 0047#6-milestone-3--real-hbc-envelope-execution
python3 - "$work/module-matrix-inspection.json" "$work/relocated/module-matrix" \
  > "$work/section-inventory.tsv" <<'PY'
import json
import pathlib
import struct
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
executable = pathlib.Path(sys.argv[2]).read_bytes()
footer_length = 88
assert len(executable) >= footer_length
magic = b"IBEX_SFE_V2\0\0\0\0\0"
footer_start = executable.rfind(magic)
assert footer_start >= 0 and footer_start + footer_length <= len(executable)
footer = executable[footer_start:footer_start + footer_length]
assert footer[:16] == magic
envelope_start = struct.unpack_from("<Q", footer, 24)[0]
sections = report["sections"]
kinds = {row["kind"] for row in sections}
required = {
    "stub-contract",
    "provenance-manifest",
    "embedded-module-graph",
    "resolved-policy",
    "entry-designation",
    "candidate-table",
    "carrier-manifest",
    "carrier-payload",
}
assert kinds == required, (kinds, required)
assert sum(row["kind"] == "candidate-table" for row in sections) >= 1
manifest_count = sum(row["kind"] == "carrier-manifest" for row in sections)
payload_count = sum(row["kind"] == "carrier-payload" for row in sections)
assert manifest_count == payload_count and manifest_count >= 6
for row in sections:
    offset = envelope_start + row["offset"]
    assert row["length"] > 0 and executable[offset] != 0
    print(f'{row["kind"]}\t{row["id"]}\t{offset}')
PY

tamper_count=0
while IFS=$'\t' read -r section_kind section_id byte_offset; do
  tamper_count=$((tamper_count + 1))
  tampered="$work/tampered/${section_kind}-${section_id}"
  cp "$work/relocated/module-matrix" "$tampered"
  printf '\0' | dd of="$tampered" bs=1 seek="$byte_offset" count=1 conv=notrunc status=none

  set +e
  IBEX_TAMPER_SENTINEL=1 "$tampered" right \
    > "$tampered.stdout" 2> "$tampered.stderr"
  tampered_exit=$?
  "$ibex" inspect-executable "$tampered" \
    > "$tampered.inspect.stdout" 2> "$tampered.inspect.stderr"
  tampered_inspect_exit=$?
  set -e

  [[ "$tampered_exit" -ne 0 && "$tampered_inspect_exit" -ne 0 && ! -s "$tampered.stdout" ]] || {
    echo "tampered $section_kind section $section_id did not refuse before carrier evaluation" >&2
    exit 1
  }
  rg -F 'SFE007 envelope digest mismatch' "$tampered.inspect.stderr" >/dev/null
done < "$work/section-inventory.tsv"
[[ "$tamper_count" -ge 18 ]] || {
  echo "final-envelope tamper matrix covered only $tamper_count sections" >&2
  exit 1
}

set +e
(cd "$work/relocated" && ./app --ibex-capsec "$fixture_url") \
  > "$work/capsec.stdout" 2> "$work/capsec.stderr"
capsec_exit=$?
set -e
[[ "$capsec_exit" -eq 1 && ! -s "$work/capsec.stdout" ]] || {
  echo "CapSec-selected SFE did not refuse before application output" >&2
  exit 1
}
rg -F 'has no accepted SFE CapSec advertisement' "$work/capsec.stderr" >/dev/null
[[ ! -e "$work/source" && ! -e "$catalog_installed_root" ]] || {
  echo "source or catalog became available during relocated execution" >&2
  exit 1
}

# Retain the authenticated, pre-signing identity needed to compare independent
# clean builders without treating ad-hoc macOS signature bytes as producer
# output. The statement is written by `ibex compile` from the exact unsigned
# bytes before signing; the inspection report independently binds the target,
# catalog, graph, carriers, and compiled stub.
# @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
if [[ -n "$evidence_output" ]]; then
  evidence_parent="$(dirname "$evidence_output")"
  mkdir -p "$evidence_parent"
  evidence_stage="$(mktemp -d "$evidence_parent/.ibex-sfe-evidence.XXXXXX")"
  cp "$work/standalone.build.json" "$evidence_stage/build-statement.json"
  cp "$work/inspection.json" "$evidence_stage/inspection.json"
  cp "$catalog_report" "$evidence_stage/catalog-report.json"
  cp "$kit/contract-report.json" "$evidence_stage/contract-report.json"
  cp "$policy_toolchain_report" "$evidence_stage/policy-toolchain-report.json"
  builder_id="${SFE_BUILDER_ID:-local-unidentified}"
  builder_git_commit="$(git -C "$repo_root" rev-parse HEAD)"
  builder_git_tree="$(git -C "$repo_root" rev-parse 'HEAD^{tree}')"
  if [[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
    builder_source_clean=true
  else
    builder_source_clean=false
  fi
  builder_rustc="$(rustc -vV)"
  builder_cargo="$(cargo -V)"
  builder_cc="$(cc --version 2>&1 | sed -n '1p')"
  builder_platform="$(uname -s)"
  builder_architecture="$(uname -m)"
  builder_os_release="$(uname -r)"
  if [[ "$builder_platform" == "Darwin" ]]; then
    builder_linker="$(ld -v 2>&1 | sed -n '1p')"
    builder_xcode="$(xcodebuild -version | tr '\n' ';' | sed 's/;$//')"
    builder_sdk_version="$(xcrun --show-sdk-version)"
    builder_sdk_build_version="$(xcrun --show-sdk-build-version)"
  else
    builder_linker="$(ld --version 2>&1 | sed -n '1p')"
    builder_xcode=""
    builder_sdk_version=""
    builder_sdk_build_version=""
  fi
  SFE_RECEIPT_BUILDER_ID="$builder_id" \
  SFE_RECEIPT_TARGET="$target_triple" \
  SFE_RECEIPT_GIT_COMMIT="$builder_git_commit" \
  SFE_RECEIPT_GIT_TREE="$builder_git_tree" \
  SFE_RECEIPT_SOURCE_CLEAN="$builder_source_clean" \
  SFE_RECEIPT_PLATFORM="$builder_platform" \
  SFE_RECEIPT_ARCHITECTURE="$builder_architecture" \
  SFE_RECEIPT_OS_RELEASE="$builder_os_release" \
  SFE_RECEIPT_RUSTC="$builder_rustc" \
  SFE_RECEIPT_CARGO="$builder_cargo" \
  SFE_RECEIPT_CC="$builder_cc" \
  SFE_RECEIPT_LINKER="$builder_linker" \
  SFE_RECEIPT_XCODE="$builder_xcode" \
  SFE_RECEIPT_SDK_VERSION="$builder_sdk_version" \
  SFE_RECEIPT_SDK_BUILD_VERSION="$builder_sdk_build_version" \
    python3 - "$evidence_stage/builder-receipt.json" <<'PY'
import json
import os
import sys


def nullable(name):
    value = os.environ[name]
    return value if value else None


receipt = {
    "schema": "ibex/sfe-builder-receipt/1",
    "builderId": os.environ["SFE_RECEIPT_BUILDER_ID"],
    "target": os.environ["SFE_RECEIPT_TARGET"],
    "source": {
        "gitCommit": os.environ["SFE_RECEIPT_GIT_COMMIT"],
        "gitTree": os.environ["SFE_RECEIPT_GIT_TREE"],
        "clean": os.environ["SFE_RECEIPT_SOURCE_CLEAN"] == "true",
    },
    "host": {
        "platform": os.environ["SFE_RECEIPT_PLATFORM"],
        "architecture": os.environ["SFE_RECEIPT_ARCHITECTURE"],
        "osRelease": os.environ["SFE_RECEIPT_OS_RELEASE"],
    },
    "toolchain": {
        "rustc": os.environ["SFE_RECEIPT_RUSTC"],
        "cargo": os.environ["SFE_RECEIPT_CARGO"],
        "cc": os.environ["SFE_RECEIPT_CC"],
        "linker": os.environ["SFE_RECEIPT_LINKER"],
        "xcode": nullable("SFE_RECEIPT_XCODE"),
        "sdkVersion": nullable("SFE_RECEIPT_SDK_VERSION"),
        "sdkBuildVersion": nullable("SFE_RECEIPT_SDK_BUILD_VERSION"),
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  if [[ -f "$kit/dependency-audit.json" ]]; then
    cp "$kit/dependency-audit.json" "$evidence_stage/dependency-audit.json"
  fi
  mv "$evidence_stage" "$evidence_output"
  evidence_stage=""
fi

echo "SFE release kit passed: target=$target_triple catalog=$catalog_digest producer=packaged-policy-toolchain unsupported=diagnostic-deny-invocation-guard network=static-envelope-fetch-http-server tla=relocated-source-free modules=esm-cjs-builtin-literal-computed backends=authenticated-stable-refusals lifecycle=argv-unicode-exit-exception-rejection-signals info=authenticated-first-position-no-evaluation signing=minimum-platform-hardened-replacement tamper=outer-stub-and-all-sections-preflight"
