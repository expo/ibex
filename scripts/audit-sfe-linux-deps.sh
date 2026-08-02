#!/usr/bin/env bash

# Audit the final x86_64 Linux compiled stub against the LLP 0029 release
# dependency contract. This inspects the ELF itself (DT_NEEDED, machine and
# optional GNU ISA floor, and GLIBC symbol versions) and also runs ldd so
# missing runtime resolutions fail in the build environment.
#
# @ref LLP 0029#2-executable-layout-stub-envelope-footer — no
# non-system dynamic libraries; the contract binds the measured GLIBC/ISA floor

set -euo pipefail

usage() {
  echo "usage: $0 <binary> (--contract <stub-contract.json> | --minimum-platform <baseline>) [--output <report.json>]" >&2
  exit 2
}

[[ $# -ge 3 ]] || usage
binary="$1"
shift
contract=""
minimum_platform=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --contract)
      [[ $# -ge 2 ]] || usage
      contract="$2"
      shift 2
      ;;
    --minimum-platform)
      [[ $# -ge 2 ]] || usage
      minimum_platform="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ -f "$binary" ]] || { echo "audit: binary is absent: $binary" >&2; exit 1; }
if [[ -n "$contract" && -n "$minimum_platform" ]] || [[ -z "$contract" && -z "$minimum_platform" ]]; then
  usage
fi
for tool in readelf ldd nm python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "audit: required tool is absent: $tool" >&2; exit 1; }
done

target="x86_64-unknown-linux-gnu"
if [[ -n "$contract" ]]; then
  [[ -f "$contract" ]] || { echo "audit: contract is absent: $contract" >&2; exit 1; }
  mapfile -t contract_target < <(python3 - "$contract" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as stream:
    value = json.load(stream)
print(value["target"]["triple"])
print(value["target"]["minimumPlatform"])
PY
  )
  [[ ${#contract_target[@]} -eq 2 ]] || { echo "audit: contract target is malformed" >&2; exit 1; }
  target="${contract_target[0]}"
  minimum_platform="${contract_target[1]}"
fi

[[ "$target" == "x86_64-unknown-linux-gnu" ]] || {
  echo "audit: unsupported target $target" >&2
  exit 1
}
if [[ "$minimum_platform" =~ ^linux-glibc-([0-9]+\.[0-9]+)-x86-64-v1$ ]]; then
  declared_glibc="${BASH_REMATCH[1]}"
else
  echo "audit: invalid Linux minimumPlatform: $minimum_platform" >&2
  exit 1
fi

elf_header="$(LC_ALL=C readelf -h "$binary")"
grep -q 'Class:[[:space:]]*ELF64' <<<"$elf_header" || { echo "audit: image is not ELF64" >&2; exit 1; }
grep -q 'Machine:[[:space:]]*Advanced Micro Devices X86-64' <<<"$elf_header" || {
  echo "audit: image is not x86_64" >&2
  exit 1
}

dynamic="$(LC_ALL=C readelf -d "$binary")"
if grep -Eq '\((RPATH|RUNPATH)\)' <<<"$dynamic"; then
  echo "audit: release stub carries RPATH/RUNPATH" >&2
  exit 1
fi
mapfile -t needed < <(sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' <<<"$dynamic" | LC_ALL=C sort -u)
allowed=(
  ld-linux-x86-64.so.2
  libc.so.6
  libdl.so.2
  libgcc_s.so.1
  libm.so.6
  libpthread.so.0
  libresolv.so.2
  librt.so.1
  libstdc++.so.6
  libz.so.1
)
for library in "${needed[@]}"; do
  allowed_match=false
  for system_library in "${allowed[@]}"; do
    if [[ "$library" == "$system_library" ]]; then
      allowed_match=true
      break
    fi
  done
  if [[ "$allowed_match" != true ]]; then
    echo "audit: non-system dynamic dependency is forbidden: $library" >&2
    exit 1
  fi
done
# A dynamic libcurl is already rejected by the closed allowlist above. The
# inverse check proves that the release image actually retained the selected
# static networking backend rather than silently compiling its bridge out.
# @ref LLP 0047#the-linux-ambient-network-gap-must-be-decided-not-inherited
if ! LC_ALL=C nm -g "$binary" 2>/dev/null | grep -E '[[:space:]]curl_easy_init$' >/dev/null; then
  echo "audit: compiled Linux release profile lacks the static libcurl Fetch/WebSocket backend" >&2
  exit 1
fi

ldd_output="$(LC_ALL=C ldd "$binary" 2>&1)" || {
  echo "audit: ldd could not resolve the release stub" >&2
  printf '%s\n' "$ldd_output" >&2
  exit 1
}
if grep -q 'not found' <<<"$ldd_output"; then
  echo "audit: ldd reports an unresolved dependency" >&2
  printf '%s\n' "$ldd_output" >&2
  exit 1
fi

actual_glibc="$(LC_ALL=C readelf --version-info "$binary" \
  | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' \
  | sed 's/^GLIBC_//' \
  | sort -Vu \
  | tail -n 1)"
[[ -n "$actual_glibc" ]] || { echo "audit: no GLIBC symbol floor found" >&2; exit 1; }
highest_glibc="$(printf '%s\n%s\n' "$actual_glibc" "$declared_glibc" | sort -V | tail -n 1)"
if [[ "$highest_glibc" != "$declared_glibc" ]]; then
  echo "audit: ELF requires GLIBC_$actual_glibc, above declared floor GLIBC_$declared_glibc" >&2
  exit 1
fi

# GNU_PROPERTY_X86_ISA_1_NEEDED is optional for the baseline x86-64 ABI. A
# missing note therefore means v1; an explicit v2/v3/v4 requirement would make
# this catalog cell incompatible and is rejected rather than relabeled.
isa_needed="$(LC_ALL=C readelf -n "$binary" | sed -n 's/.*x86 ISA needed: //p' | head -n 1)"
case "$isa_needed" in
  ""|x86-64-baseline) isa_floor="x86-64-baseline" ;;
  *)
    echo "audit: ELF requires unsupported GNU x86 ISA floor: $isa_needed" >&2
    exit 1
    ;;
esac

needed_lines="$(printf '%s\n' "${needed[@]}")"
allowed_lines="$(printf '%s\n' "${allowed[@]}")"
report="$(NEEDED_LINES="$needed_lines" ALLOWED_LINES="$allowed_lines" python3 - \
  "$target" "$minimum_platform" "$actual_glibc" "$isa_floor" <<'PY'
import json
import os
import sys

target, minimum_platform, actual_glibc, isa = sys.argv[1:]
value = {
    "schema": "ibex/sfe-linux-dependency-audit/1",
    "target": target,
    "minimumPlatform": minimum_platform,
    "measured": {
        "maximumGlibcSymbolVersion": actual_glibc,
        "cpuIsa": isa,
        "needed": [line for line in os.environ["NEEDED_LINES"].splitlines() if line],
    },
    "policy": {
        "allowedSystemDynamicLibraries": [
            line for line in os.environ["ALLOWED_LINES"].splitlines() if line
        ],
        "libcurlDisposition": "statically-linked",
        "rpathAllowed": False,
    },
    "result": "pass",
}
print(json.dumps(value, indent=2, sort_keys=True))
PY
)"

if [[ -n "$output" ]]; then
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$report" > "$output"
fi
printf '%s\n' "$report"
