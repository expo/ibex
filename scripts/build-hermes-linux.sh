#!/usr/bin/env bash
#
# build-hermes-linux.sh
# Builds Hermes from source for Linux and installs artifacts for Ibex.
#
# Usage:
#   ./scripts/build-hermes-linux.sh
#   ./scripts/build-hermes-linux.sh --clean
#   ./scripts/build-hermes-linux.sh --release
#   ./scripts/build-hermes-linux.sh --debug
#   ./scripts/build-hermes-linux.sh --vanilla
#   ./scripts/build-hermes-linux.sh <git-tag-or-branch-or-commit>
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

# Default to the pinned Hermes commit — the stable branch name moves under
# cold clones (ENG-23092).
HERMES_VERSION_FROM_ENV="${HERMES_VERSION:-}"
HERMES_VERSION="${HERMES_VERSION:-$IBEX_HERMES_BUILD_REF}"
HERMES_CLI_REF=false
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"
HERMES_INTL_FROM_ENV="${HERMES_ENABLE_INTL:-}"
HERMES_INTL="${HERMES_ENABLE_INTL:-false}"
HERMES_INTL_CLI=false
HERMES_VANILLA="${IBEX_HERMES_VANILLA:-false}"
CLEAN_CACHE=false
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/exact/hermes-linux"
LINUX_DIR="$PROJECT_ROOT/linux"
LINUX_LIB_DIR="$LINUX_DIR/lib"
LINUX_HEADERS_DIR="$LINUX_DIR/hermes-headers"
TOOLS_DIR="$PROJECT_ROOT/tools/hermes"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            CLEAN_CACHE=true
            shift
            ;;
        --release|--no-debugger)
            HERMES_DEBUGGER=false
            shift
            ;;
        --debug)
            HERMES_DEBUGGER=true
            shift
            ;;
        --intl)
            HERMES_INTL=true
            HERMES_INTL_CLI=true
            shift
            ;;
        --no-intl)
            HERMES_INTL=false
            HERMES_INTL_CLI=true
            shift
            ;;
        --vanilla)
            HERMES_VANILLA=true
            shift
            ;;
        *)
            HERMES_VERSION="$1"
            HERMES_CLI_REF=true
            shift
            ;;
    esac
done

case "$HERMES_VANILLA" in
    1|true|TRUE|yes|YES|on|ON)
        HERMES_VANILLA=true
        if [[ "$HERMES_CLI_REF" != true && -z "$HERMES_VERSION_FROM_ENV" ]]; then
            HERMES_VERSION="$IBEX_HERMES_VANILLA_SOURCE_COMMIT"
        fi
        if [[ ! "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
            echo "A vanilla Hermes build requires an exact 40-hex source commit: $HERMES_VERSION" >&2
            exit 1
        fi
        if [[ -z "$HERMES_INTL_FROM_ENV" && "$HERMES_INTL_CLI" != true ]]; then
            HERMES_INTL=true
        fi
        HERMES_INTL_NORMALIZED="$(printf '%s' "$HERMES_INTL" | tr '[:upper:]' '[:lower:]')"
        case "$HERMES_INTL_NORMALIZED" in
            1|true|yes|on)
                HERMES_INTL=true
                ;;
            *)
                echo "A vanilla Hermes Linux build requires Intl" >&2
                exit 1
                ;;
        esac
        case "$HERMES_DEBUGGER" in
            0|false|FALSE|no|NO|off|OFF) DEBUG_SUFFIX="" ;;
            *) DEBUG_SUFFIX="-debug" ;;
        esac
        CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/exact/hermes2-linux-vanilla/${HERMES_VERSION}${DEBUG_SUFFIX}"
        LINUX_DIR="$PROJECT_ROOT/linux/Frameworks-vanilla"
        LINUX_LIB_DIR="$LINUX_DIR/linux-static"
        LINUX_HEADERS_DIR="$LINUX_DIR/hermes-headers"
        TOOLS_DIR="$PROJECT_ROOT/tools/hermes-vanilla"
        ;;
    *)
        HERMES_VANILLA=false
        ;;
esac

ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$CLEAN_CACHE" == "true" ]]; then
    rm -rf "$CACHE_DIR"
    echo "Cleaned Hermes Linux cache: $CACHE_DIR"
    exit 0
fi

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not found. Install cmake first."
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git not found."
    exit 1
fi

NUM_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)"
if (( NUM_CORES > 32 )); then
    NUM_CORES=32
fi
if [[ "$HERMES_VANILLA" == true ]]; then
    SRC_DIR="$CACHE_DIR/source"
else
    SRC_DIR="$CACHE_DIR/hermes-src"
fi
BUILD_DIR="$CACHE_DIR/build"
INSTALL_DIR="$CACHE_DIR/install"

mkdir -p "$CACHE_DIR"

if [[ "$HERMES_VANILLA" == true ]]; then
    # Never reset or clean the legacy source cache: it normally contains the
    # applied Ibex patch stack. Export the exact upstream object into this
    # vanilla lane's isolated build input instead.
    SOURCE_REPOSITORY="${IBEX_HERMES_SOURCE_REPOSITORY:-${XDG_CACHE_HOME:-$HOME/.cache}/exact/hermes-linux/hermes-src}"
    if [[ ! -d "$SOURCE_REPOSITORY/.git" ]]; then
        echo "No existing Hermes source repository at $SOURCE_REPOSITORY" >&2
        echo "Set IBEX_HERMES_SOURCE_REPOSITORY to an existing checkout containing $HERMES_VERSION" >&2
        exit 1
    fi
    EXPECTED_VANILLA_COMMIT="$HERMES_VERSION"
    CHECKED_OUT_COMMIT="$(git -C "$SOURCE_REPOSITORY" rev-parse --verify "${EXPECTED_VANILLA_COMMIT}^{commit}")" \
        || { echo "Existing Hermes source repository does not contain $HERMES_VERSION" >&2; exit 1; }
    if [[ "$CHECKED_OUT_COMMIT" != "$EXPECTED_VANILLA_COMMIT" ]]; then
        echo "Resolved Hermes commit $CHECKED_OUT_COMMIT differs from requested object $HERMES_VERSION" >&2
        exit 1
    fi
    # Re-materialize every invocation. A marker alone would let an edited or
    # partial prior export be relabeled as pinned vanilla. Git archive reads
    # the committed object, not the dirty legacy worktree, and preserves the
    # commit timestamps so an unchanged input remains an incremental build.
    SOURCE_STAGE="$(mktemp -d "$CACHE_DIR/source.XXXXXX")"
    git -C "$SOURCE_REPOSITORY" archive "$CHECKED_OUT_COMMIT" | tar -x -C "$SOURCE_STAGE"
    rm -rf "$SRC_DIR"
    mv "$SOURCE_STAGE" "$SRC_DIR"
    printf '%s\n' "$CHECKED_OUT_COMMIT" >"$CACHE_DIR/source-commit"
else
    if [[ ! -d "$SRC_DIR/.git" ]]; then
        rm -rf "$SRC_DIR"
        git clone https://github.com/facebook/hermes.git "$SRC_DIR"
    fi

    cd "$SRC_DIR"
    git reset --hard HEAD
    git clean -ffdx
    git fetch --all --tags
    if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
        # Treat a full object ID as an object identity before consulting branch
        # names; a 40-hex remote ref must never shadow the reviewed commit.
        if ! git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null; then
            git fetch origin "$HERMES_VERSION"
        fi
        git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null \
            || { echo "Requested Hermes commit is unavailable: $HERMES_VERSION" >&2; exit 1; }
        git checkout --detach "${HERMES_VERSION}^{commit}"
    elif [[ "$HERMES_VERSION" == "static_h" || "$HERMES_VERSION" == "main" ]]; then
        git checkout --detach origin/static_h
    elif git rev-parse --verify --quiet "origin/$HERMES_VERSION" >/dev/null; then
        git checkout --detach "origin/$HERMES_VERSION"
    else
        git checkout --detach "$HERMES_VERSION"
    fi

    CHECKED_OUT_COMMIT="$(git rev-parse HEAD^{commit})"
    if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ && "$CHECKED_OUT_COMMIT" != "$HERMES_VERSION" ]]; then
        echo "Checked-out Hermes commit $CHECKED_OUT_COMMIT differs from requested object $HERMES_VERSION" >&2
        exit 1
    fi
    git reset --hard "$CHECKED_OUT_COMMIT"
    git clean -ffdx
    if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
        echo "Hermes source checkout is not pristine after reset/clean" >&2
        exit 1
    fi

    # Build/install directories live beside the source checkout on Linux, so
    # erase them before patch verification under the same lock.
    rm -rf "$BUILD_DIR" "$INSTALL_DIR"

    # @ref LLP 0013#upstream-tracking — the real index and complete persistent
    # checkout are pristine before the carried Hermes patch stack is replayed.
    "$SCRIPT_DIR/apply-hermes-patches.sh" "$SRC_DIR"
fi

rm -rf "$INSTALL_DIR"

ACTUAL_COMMIT="$(printf '%s' "$CHECKED_OUT_COMMIT" | cut -c1-12)"
echo "Building Hermes for Linux from commit: $ACTUAL_COMMIT"
echo "Debugger enabled: $HERMES_DEBUGGER"
echo "Intl enabled: $HERMES_INTL"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

GENERATOR=(-G "Unix Makefiles")
if command -v ninja >/dev/null 2>&1; then
    GENERATOR=(-G Ninja)
fi

cmake -S "$SRC_DIR" -B "$BUILD_DIR" "${GENERATOR[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DHERMES_ENABLE_DEBUGGER="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL="$HERMES_INTL" \
    -DHERMES_BUILD_APPLE_FRAMEWORK=OFF \
    -DHERMES_BUILD_SHARED_JSI=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON

# The VM CLI is a compatibility probe, not an alternate runtime selector:
# build.rs compares its HBC version with hermesc before embedding bytecode.
# @ref LLP 0005#bytecode-precompilation-hermesc — Linux publishes both halves of the compiler/runtime version proof
cmake --build "$BUILD_DIR" --target hermesvm hermesvm_a hermesc hermes -j"$NUM_CORES"

mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/bin" "$INSTALL_DIR/include"

# The source runtime uses the shared object; LLP 0029 compiled stubs consume
# the full static archive. Publish them together so one authenticated Hermes
# bundle supports both profiles without relabeling either artifact.
if [[ -f "$BUILD_DIR/lib/libhermesvm.so" && -f "$BUILD_DIR/lib/libhermesvm_a.a" ]]; then
    cp "$BUILD_DIR/lib/libhermesvm.so" "$INSTALL_DIR/lib/"
    cp "$BUILD_DIR/lib/libhermesvm_a.a" "$INSTALL_DIR/lib/"
else
    echo "Could not find both libhermesvm.so and libhermesvm_a.a in $BUILD_DIR/lib"
    exit 1
fi
BOOST_CONTEXT_ARCHIVE="$(find "$BUILD_DIR/external/boost" -type f -name libboost_context.a -print -quit)"
if [[ -z "$BOOST_CONTEXT_ARCHIVE" ]]; then
    echo "Could not find Hermes Boost.Context archive under $BUILD_DIR/external/boost"
    exit 1
fi
cp "$BOOST_CONTEXT_ARCHIVE" "$INSTALL_DIR/lib/libboost_context.a"
if [[ ! -f "$BUILD_DIR/jsi/libjsi.a" ]]; then
    echo "Could not find Hermes JSI archive at $BUILD_DIR/jsi/libjsi.a"
    exit 1
fi
cp "$BUILD_DIR/jsi/libjsi.a" "$INSTALL_DIR/lib/libjsi.a"

if [[ "$HERMES_VANILLA" == true ]]; then
    # Ibex2 links the VM and its Linux Intl implementation statically. Carry
    # that complete third-party closure beside Hermes so the final executable
    # does not depend on the builder's libicu or terminfo shared objects.
    if ! command -v pkg-config >/dev/null 2>&1; then
        echo "pkg-config is required to locate the Linux static Hermes closure" >&2
        exit 1
    fi
    ICU_LIB_DIR="$(pkg-config --variable=libdir icu-i18n)"
    TINFO_LIB_DIR="$(pkg-config --variable=libdir tinfo)"
    for archive in libicui18n.a libicuuc.a libicudata.a; do
        if [[ ! -f "$ICU_LIB_DIR/$archive" ]]; then
            echo "Static ICU archive is missing: $ICU_LIB_DIR/$archive" >&2
            exit 1
        fi
        cp "$ICU_LIB_DIR/$archive" "$INSTALL_DIR/lib/"
    done
    if [[ ! -f "$TINFO_LIB_DIR/libtinfo.a" ]]; then
        echo "Static terminfo archive is missing: $TINFO_LIB_DIR/libtinfo.a" >&2
        exit 1
    fi
    cp "$TINFO_LIB_DIR/libtinfo.a" "$INSTALL_DIR/lib/"
fi

if [[ -f "$BUILD_DIR/bin/hermesc" ]]; then
    cp "$BUILD_DIR/bin/hermesc" "$INSTALL_DIR/bin/"
else
    echo "Could not find hermesc in $BUILD_DIR/bin"
    exit 1
fi
if [[ -f "$BUILD_DIR/bin/hermes" ]]; then
    cp "$BUILD_DIR/bin/hermes" "$INSTALL_DIR/bin/"
else
    echo "Could not find Hermes VM CLI in $BUILD_DIR/bin"
    exit 1
fi

# Public headers used by ibex-runtime build.rs.
# Preserve include shapes expected by Hermes headers:
#   <jsi/...> and <hermes/...>
mkdir -p "$INSTALL_DIR/include/jsi" "$INSTALL_DIR/include/hermes"
cp -R "$SRC_DIR/API/jsi/jsi/"* "$INSTALL_DIR/include/jsi/"
cp -R "$SRC_DIR/API/hermes/"* "$INSTALL_DIR/include/hermes/"
cp -R "$SRC_DIR/public/hermes/Public" "$INSTALL_DIR/include/hermes/"

# Install into repo conventions used by build.rs
mkdir -p "$LINUX_LIB_DIR" "$LINUX_HEADERS_DIR" "$TOOLS_DIR"
rm -rf "$LINUX_HEADERS_DIR"
mkdir -p "$LINUX_HEADERS_DIR"
cp -R "$INSTALL_DIR/include/"* "$LINUX_HEADERS_DIR/"
cp -f "$INSTALL_DIR/lib/libhermesvm_a.a" "$LINUX_LIB_DIR/"
cp -f "$INSTALL_DIR/lib/libjsi.a" "$LINUX_LIB_DIR/"
cp -f "$INSTALL_DIR/lib/libboost_context.a" "$LINUX_LIB_DIR/"
if [[ "$HERMES_VANILLA" == true ]]; then
    # This directory is the publication input for the self-contained static
    # engine. Do not retain a shared runtime from an earlier or adjacent build.
    rm -f "$LINUX_LIB_DIR/libhermesvm.so"
    cp -f "$INSTALL_DIR/lib/libicui18n.a" "$LINUX_LIB_DIR/"
    cp -f "$INSTALL_DIR/lib/libicuuc.a" "$LINUX_LIB_DIR/"
    cp -f "$INSTALL_DIR/lib/libicudata.a" "$LINUX_LIB_DIR/"
    cp -f "$INSTALL_DIR/lib/libtinfo.a" "$LINUX_LIB_DIR/"
else
    cp -f "$INSTALL_DIR/lib/libhermesvm.so" "$LINUX_LIB_DIR/"
fi
if [[ "$HERMES_VANILLA" == true ]]; then
    rm -f "$LINUX_LIB_DIR/hermes-profile-provenance.json"
else
    rm -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" \
        "$LINUX_LIB_DIR/hermes-profile-provenance.json"
    LINUX_CACHE_KEY="$(ibex_hermes_linux_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}")"
    echo "Source cache key: $LINUX_CACHE_KEY"
    ibex_write_source_patched_profile_receipt \
        "$INSTALL_DIR/lib/libhermesvm.so" \
        "$INSTALL_DIR/lib/hermes-profile-provenance.json" \
        "$HERMES_VERSION" \
        "$LINUX_CACHE_KEY"
    if [[ -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" ]]; then
        cp -f "$INSTALL_DIR/lib/hermes-profile-provenance.json" "$LINUX_LIB_DIR/"
    else
        echo "[provenance] custom Hermes source build has no reviewed profile receipt." >&2
    fi
fi
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) HERMESC_ARCH="x64" ;;
    arm64|aarch64) HERMESC_ARCH="arm64" ;;
    *) HERMESC_ARCH="$ARCH" ;;
esac
cp -f "$INSTALL_DIR/bin/hermesc" "$TOOLS_DIR/hermesc-linux-$HERMESC_ARCH"
cp -f "$INSTALL_DIR/bin/hermes" "$TOOLS_DIR/hermes-linux-$HERMESC_ARCH"

echo ""
echo "Installed Linux Hermes artifacts:"
echo "  headers: $LINUX_HEADERS_DIR"
echo "  libs:    $LINUX_LIB_DIR"
echo "  hermesc: $TOOLS_DIR/hermesc-linux-$HERMESC_ARCH"
echo "  hermes:  $TOOLS_DIR/hermes-linux-$HERMESC_ARCH"
if [[ "$HERMES_VANILLA" == true ]]; then
    echo ""
    echo "Write a HermesInputReceipt with:"
    echo "  node \"$SCRIPT_DIR/hermes-input-receipt.mjs\" \"$LINUX_DIR\""
fi
echo ""
echo "Suggested env (optional):"
echo "  export HERMES_INCLUDE_DIR=$LINUX_HEADERS_DIR"
echo "  export HERMES_LIB_DIR=$LINUX_LIB_DIR"
