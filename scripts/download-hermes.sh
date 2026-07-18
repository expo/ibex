#!/usr/bin/env bash
#
# Install Hermes runtime artifacts for Ibex.
#
# Usage:
#   ./scripts/download-hermes.sh
#   HERMES_VERSION=260318099.0.0-stable ./scripts/download-hermes.sh
#   IBEX_HERMES_FORCE_BUILD=1 ./scripts/download-hermes.sh   # skip the download path
#
# Install order (ENG-23147):
#   1. Prebuilt patched bundle from the GitHub Release for artifact identity
#      <hermes-commit-12>-<patch-digest-12> (scripts/hermes-version.sh). Within
#      that release, the platform asset name uses the stronger source-cache key
#      that also binds both builders plus the patch-application and shared
#      receipt/identity authorities.
#      The bundle is attestation- and checksum-verified. Bundles are published by
#      .github/workflows/hermes-artifacts.yml. On macOS the bundle is unpacked
#      into build-hermes.sh's local cache and installed through its cache-hit
#      path, so a downloaded install is byte-identical in shape to a built one.
#   2. From-source build (build-hermes.sh / build-hermes-linux.sh) on any miss,
#      checksum mismatch, or bundle-validation failure.
#
# If the download path misses AND the source build fails, this exits nonzero
# naming both causes — never a quiet partial install (LLP 0018).
# @ref LLP 0005#prebuilt-hermes-artifact-bundles — download-first bootstrap + one shared identity derivation
#
# The download path is taken for the pinned commit and a published exact
# profile: debugger-on defaults, plus the no-debugger macOS Release bundle used
# by exact-target conformance. Other configurations go to the source build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

# Default to the pinned Hermes commit — the stable branch name moves under
# cold clones (ENG-23092).
HERMES_VERSION="${HERMES_VERSION:-$IBEX_HERMES_BUILD_REF}"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64) HOST_ARCH="x64" ;;
    arm64|aarch64) HOST_ARCH="arm64" ;;
    *) HOST_ARCH="$ARCH_RAW" ;;
esac

# A mirror may supply the release bytes, but it is never an attestation trust
# anchor. The reviewed builder identity is deliberately not environment
# configurable: otherwise an attacker-controlled repository could attest an
# arbitrary binary plus a self-consistent public receipt and have build.rs
# mistake that installer assertion for the reviewed source build.
ARTIFACT_REPO="${IBEX_HERMES_ARTIFACT_REPO:-ccheever/ibex}"
readonly REVIEWED_ATTESTATION_REPO="ccheever/ibex"
readonly REVIEWED_ATTESTATION_WORKFLOW="ccheever/ibex/.github/workflows/hermes-artifacts.yml"
readonly REVIEWED_ATTESTATION_SOURCE_REF="refs/heads/main"
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"

# Prebuilt installation writes the same caches as the source builders. Join
# their lock protocol for the mutation, then release it before invoking a
# builder (which acquires the lock for its own complete run).
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

try_download_under_source_lock() {
    local status
    ibex_acquire_hermes_source_build_lock "$(basename "$0"):prebuilt-install" || return 1
    if "$@"; then
        status=0
    else
        status=$?
    fi
    if ! ibex_release_hermes_source_build_lock; then
        return 1
    fi
    return "$status"
}

is_truthy() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

echo "=== Hermes Install Script ==="
echo "Source ref: $HERMES_VERSION"
echo ""

# Reasons the prebuilt-bundle path does not apply. When this returns nonzero
# the script behaves exactly like the pre-ENG-23147 wrapper: straight to the
# platform source builder.
download_eligible() {
    if is_truthy "${IBEX_HERMES_FORCE_BUILD:-0}"; then
        echo "[download] IBEX_HERMES_FORCE_BUILD set; building from source."
        return 1
    fi
    if [[ ! "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
        echo "[download] requested ref '$HERMES_VERSION' is not the pinned commit form; building from source."
        return 1
    fi
    if ! is_truthy "$HERMES_DEBUGGER" && [[ "$PLATFORM" != "darwin" ]]; then
        echo "[download] no published no-debugger bundle for $PLATFORM; building from source."
        return 1
    fi
    if [[ "$PLATFORM" == "linux" ]] && is_truthy "${HERMES_ENABLE_INTL:-false}"; then
        echo "[download] non-default Intl configuration requested; building from source."
        return 1
    fi
    return 0
}

# Fetch $2 and $2.sha256 from release $1 into directory $3, then verify the
# bundle's GitHub build-provenance attestation. A checksum sidecar from the same
# release catches transport/copy errors but is not an independent authority;
# authenticated prebuilt installation therefore requires `gh attestation`.
fetch_release_asset() {
    local tag="$1" asset="$2" dest="$3"
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        gh release download "$tag" --repo "$ARTIFACT_REPO" --dir "$dest" \
            --pattern "$asset" --pattern "$asset.sha256" || return 1
    else
        echo "[download] authenticated gh is required to verify bundle build provenance; using a local source build." >&2
        return 1
    fi
    [[ -s "$dest/$asset" && -s "$dest/$asset.sha256" ]] || return 1
    if ! gh attestation verify "$dest/$asset" \
        --repo "$REVIEWED_ATTESTATION_REPO" \
        --signer-workflow "$REVIEWED_ATTESTATION_WORKFLOW" \
        --source-ref "$REVIEWED_ATTESTATION_SOURCE_REF" \
        --deny-self-hosted-runners >/dev/null; then
        echo "[download] GitHub build-provenance verification failed for $asset" >&2
        return 1
    fi
    echo "[download] verified GitHub build provenance for $asset"
}

verify_checksum() {
    local tarball="$1" sumfile="$2"
    local expected actual
    expected="$(awk 'NR == 1 { print $1 }' "$sumfile")"
    actual="$(ibex_sha256 "$tarball" | awk '{ print $1 }')"
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        echo "[download] CHECKSUM MISMATCH for $(basename "$tarball")" >&2
        echo "[download]   expected: ${expected:-<empty>}" >&2
        echo "[download]   actual:   $actual" >&2
        return 1
    fi
    echo "[download] checksum verified: $actual"
}

# The published bundles are the PATCHED engine (LLP 0013 stack applied before
# building). An unpatched bundle would make the 18 frame-attribution tests
# skip vacuously, so refuse to install one that lacks the capability export.
verify_frame_attribution_export() {
    local binary="$1" nm_flags="$2" symbols
    if ! command -v nm >/dev/null 2>&1; then
        echo "[download] nm unavailable; skipping frame-attribution export check" >&2
        return 0
    fi
    # Capture the complete symbol table before matching. A `nm | grep -q`
    # pipeline under pipefail can report a false negative when grep exits after
    # its first match and nm receives SIGPIPE.
    # shellcheck disable=SC2086 -- nm_flags is intentionally word-split.
    symbols="$(nm $nm_flags "$binary" 2>/dev/null)" || return 1
    if [[ "$symbols" != *ex_hermes_vm_current_package_id* ]]; then
        echo "[download] bundle binary $binary lacks ex_hermes_vm_current_package_id (unpatched engine?)" >&2
        return 1
    fi
    echo "[download] verified patched export in $(basename "$binary")"
}

# Download + validate the macOS bundle into build-hermes.sh's local cache dir,
# then let build-hermes.sh's cache-hit path do the actual install (single
# install codepath for downloaded and built artifacts).
#
# NOTE: these try_* functions use subshell bodies `( ... )` so the EXIT trap
# cleans the temp dir without leaking a RETURN trap into the caller, and every
# mutating step carries an explicit `|| return 1` — they are called from `if`
# conditions, where bash suspends `set -e` for the whole body.
try_download_darwin() (
    identity="$1"; cache_key="$2"; profile="$3"
    tag="hermes-$identity"
    if [[ "$profile" == "release" ]]; then
        asset="hermes-macos-$HOST_ARCH-release-$cache_key.tar.gz"
    else
        asset="hermes-macos-$HOST_ARCH-$cache_key.tar.gz"
    fi
    cache_dir="$HOME/.cache/exact/hermes/$cache_key"
    if [[ -d "$cache_dir/hermesvm.xcframework" ]] \
        && ibex_hermes_profile_receipt_has_cache_key \
            "$cache_dir/hermes-profile-provenance.json" "$cache_key"; then
        echo "[download] local build cache already has verified $cache_key; skipping download."
        return 0
    fi
    tmp="$(mktemp -d)" || return 1
    trap 'rm -rf "$tmp"' EXIT

    echo "[download] trying release $tag asset $asset from $ARTIFACT_REPO..."
    fetch_release_asset "$tag" "$asset" "$tmp" || return 1
    verify_checksum "$tmp/$asset" "$tmp/$asset.sha256" || return 1

    mkdir -p "$tmp/unpack" || return 1
    tar -xzf "$tmp/$asset" -C "$tmp/unpack" || return 1

    # Validate bundle shape + patched export + runnable host compiler before
    # letting it near the cache.
    [[ -d "$tmp/unpack/hermesvm.xcframework" ]] || { echo "[download] bundle missing hermesvm.xcframework" >&2; return 1; }
    [[ -d "$tmp/unpack/hermesvm.framework" ]] || { echo "[download] bundle missing hermesvm.framework" >&2; return 1; }
    [[ -f "$tmp/unpack/hermes-profile-provenance.json" ]] || { echo "[download] bundle missing Hermes source-profile receipt" >&2; return 1; }
    ibex_hermes_profile_receipt_has_cache_key \
        "$tmp/unpack/hermes-profile-provenance.json" "$cache_key" \
        || { echo "[download] bundle receipt does not bind source cache key $cache_key" >&2; return 1; }
    [[ -f "$tmp/unpack/include/jsi/jsi.h" ]] || { echo "[download] bundle missing include/jsi/jsi.h (empty headers?)" >&2; return 1; }
    [[ -x "$tmp/unpack/bin/hermesc" ]] || { echo "[download] bundle missing bin/hermesc" >&2; return 1; }
    verify_frame_attribution_export "$tmp/unpack/hermesvm.framework/Versions/1/hermesvm" "-gU" || return 1
    symbols="$(nm -gU "$tmp/unpack/hermesvm.framework/Versions/1/hermesvm" 2>/dev/null)" || return 1
    if [[ "$profile" == "release" && "$symbols" == *AsyncDebuggerAPI* ]]; then
        echo "[download] Release bundle unexpectedly exports debugger symbols" >&2
        return 1
    fi
    "$tmp/unpack/bin/hermesc" --help >/dev/null 2>&1 || { echo "[download] bundled hermesc does not run on this host" >&2; return 1; }

    mkdir -p "$(dirname "$cache_dir")" || return 1
    rm -rf "$cache_dir" || return 1
    mv "$tmp/unpack" "$cache_dir" || return 1
    echo "[download] installed prebuilt bundle into build cache: $cache_dir"
)

# Download + validate the Linux bundle, then install it into the repo layout
# build-hermes-linux.sh uses (linux/hermes-headers, linux/lib, tools/hermes).
try_download_linux() (
    identity="$1"; cache_key="$2"
    tag="hermes-$identity"
    asset="hermes-linux-$HOST_ARCH-$cache_key.tar.gz"
    tmp="$(mktemp -d)" || return 1
    trap 'rm -rf "$tmp"' EXIT

    echo "[download] trying release $tag asset $asset from $ARTIFACT_REPO..."
    fetch_release_asset "$tag" "$asset" "$tmp" || return 1
    verify_checksum "$tmp/$asset" "$tmp/$asset.sha256" || return 1

    mkdir -p "$tmp/unpack" || return 1
    tar -xzf "$tmp/$asset" -C "$tmp/unpack" || return 1

    [[ -f "$tmp/unpack/include/jsi/jsi.h" ]] || { echo "[download] bundle missing include/jsi/jsi.h (empty headers?)" >&2; return 1; }
    [[ -x "$tmp/unpack/bin/hermesc" ]] || { echo "[download] bundle missing bin/hermesc" >&2; return 1; }
    lib_file="$(find "$tmp/unpack/lib" -maxdepth 1 -name 'libhermesvm.*' -print -quit 2>/dev/null)"
    [[ -n "$lib_file" ]] || { echo "[download] bundle missing lib/libhermesvm.*" >&2; return 1; }
    if [[ "$lib_file" == *.so ]]; then
        verify_frame_attribution_export "$lib_file" "-D" || return 1
        [[ -f "$tmp/unpack/lib/hermes-profile-provenance.json" ]] \
            || { echo "[download] dynamic Linux bundle is missing its source-profile receipt" >&2; return 1; }
        ibex_hermes_profile_receipt_has_cache_key \
            "$tmp/unpack/lib/hermes-profile-provenance.json" "$cache_key" \
            || { echo "[download] Linux bundle receipt does not bind source cache key $cache_key" >&2; return 1; }
    else
        verify_frame_attribution_export "$lib_file" "" || return 1
        [[ ! -e "$tmp/unpack/lib/hermes-profile-provenance.json" ]] \
            || { echo "[download] static Linux bundle unexpectedly carries a mapped-object receipt" >&2; return 1; }
    fi
    "$tmp/unpack/bin/hermesc" --help >/dev/null 2>&1 || { echo "[download] bundled hermesc does not run on this host" >&2; return 1; }

    # Mirror build-hermes-linux.sh's install-into-repo step.
    headers_dir="$PROJECT_ROOT/linux/hermes-headers"
    lib_dir="$PROJECT_ROOT/linux/lib"
    tools_dir="$PROJECT_ROOT/tools/hermes"
    rm -rf "$headers_dir" || return 1
    mkdir -p "$headers_dir" "$lib_dir" "$tools_dir" || return 1
    cp -R "$tmp/unpack/include/"* "$headers_dir/" || return 1
    rm -f "$lib_dir/libhermesvm.so" "$lib_dir/libhermesvm.a" || return 1
    cp -f "$lib_file" "$lib_dir/" || return 1
    rm -f "$lib_dir/hermes-profile-provenance.json" || return 1
    if [[ -f "$tmp/unpack/lib/hermes-profile-provenance.json" ]]; then
        cp -f "$tmp/unpack/lib/hermes-profile-provenance.json" "$lib_dir/" || return 1
    fi
    cp -f "$tmp/unpack/bin/hermesc" "$tools_dir/hermesc-linux-$HOST_ARCH" || return 1
    chmod +x "$tools_dir/hermesc-linux-$HOST_ARCH" || return 1

    echo ""
    echo "Installed prebuilt Linux Hermes artifacts:"
    echo "  headers: $headers_dir"
    echo "  lib:     $lib_dir/$(basename "$lib_file")"
    echo "  hermesc: $tools_dir/hermesc-linux-$HOST_ARCH"
)

# LLP 0018: when the download path was attempted and the source build also
# fails, name both causes — the caller must not have to reconstruct which half
# fell over from a generic builder error.
run_source_build_or_die() {
    local builder="$1" download_attempted="$2"
    shift 2
    if "$builder" "$@"; then
        return 0
    fi
    echo "" >&2
    echo "[✗] Hermes install FAILED." >&2
    if [[ "$download_attempted" == "1" ]]; then
        echo "    - prebuilt-bundle download missed or failed validation (see [download] lines above)" >&2
    fi
    echo "    - from-source build ($(basename "$builder")) exited nonzero" >&2
    echo "    Nothing was installed. See LLP 0018 (fail loud) and scripts/hermes-version.sh for the pin." >&2
    exit 1
}

case "$PLATFORM" in
    linux)
        DOWNLOAD_ATTEMPTED=0
        if download_eligible; then
            DOWNLOAD_ATTEMPTED=1
            IDENTITY="${HERMES_VERSION:0:12}-$(ibex_hermes_patch_digest)"
            CACHE_KEY="$(ibex_hermes_linux_source_cache_key "${HERMES_VERSION:0:12}")"
            if try_download_under_source_lock try_download_linux "$IDENTITY" "$CACHE_KEY"; then
                exit 0
            fi
            echo "[download] prebuilt bundle unavailable; falling back to source build." >&2
        fi
        run_source_build_or_die "$SCRIPT_DIR/build-hermes-linux.sh" "$DOWNLOAD_ATTEMPTED" "$HERMES_VERSION"
        ;;
    darwin)
        DOWNLOAD_ATTEMPTED=0
        if download_eligible; then
            IDENTITY="${HERMES_VERSION:0:12}-$(ibex_hermes_patch_digest)"
            if is_truthy "$HERMES_DEBUGGER"; then
                PROFILE="debug"
                CACHE_KEY="$(ibex_hermes_apple_source_cache_key "${HERMES_VERSION:0:12}" "-debug")"
            else
                PROFILE="release"
                CACHE_KEY="$(ibex_hermes_apple_source_cache_key "${HERMES_VERSION:0:12}" "")"
            fi
            DOWNLOAD_ATTEMPTED=1
            if ! try_download_under_source_lock \
                try_download_darwin "$IDENTITY" "$CACHE_KEY" "$PROFILE"; then
                echo "[download] prebuilt bundle unavailable; falling back to source build." >&2
            fi
        fi
        # Installs from the cache populated above when the download succeeded
        # (or a prior build); otherwise builds from source.
        run_source_build_or_die "$SCRIPT_DIR/build-hermes.sh" "$DOWNLOAD_ATTEMPTED" "$HERMES_VERSION"
        ;;
    *)
        echo "Unsupported platform: $PLATFORM" >&2
        echo "Set HERMES_INCLUDE_DIR and HERMES_LIB_DIR manually for this target." >&2
        exit 1
        ;;
esac
