#!/bin/bash

# Build the offline verifier from checksum-pinned Go source. This script never
# downloads or executes a prebuilt verifier binary. A cold Go module cache may
# fetch go.mod/go.sum-pinned source dependencies before the offline tests/build.
#
# @ref LLP 0035#transport-and-distribution-provenance — this helper is a
# diagnostic foundation; package acceptance remains disconnected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODULE_DIR="$PROJECT_ROOT/tools/portable-engine-attestation-verifier"
OUTPUT_PATH="${1:-$PROJECT_ROOT/target/tools/portable-engine-attestation-verifier}"
GO_BINARY="${IBEX_ATTESTATION_GO:-go}"
REQUIRED_GO_VERSION="go1.26.5"

if ! command -v "$GO_BINARY" >/dev/null 2>&1; then
    echo "portable verifier build: Go 1.26.5 was not found; set IBEX_ATTESTATION_GO" >&2
    exit 1
fi

GO_VERSION="$("$GO_BINARY" version)"
case "$GO_VERSION" in
    "go version $REQUIRED_GO_VERSION "*) ;;
    *)
        echo "portable verifier build: expected $REQUIRED_GO_VERSION, got: $GO_VERSION" >&2
        exit 1
        ;;
esac

mkdir -p "$(dirname "$OUTPUT_PATH")"
TEMP_OUTPUT="$OUTPUT_PATH.$$.tmp"
trap 'rm -f "$TEMP_OUTPUT"' EXIT

export CGO_ENABLED=0
export GOFLAGS=-mod=readonly
export GOWORK=off
export GOTOOLCHAIN=local
export LC_ALL=C
export TZ=UTC

(
    cd "$MODULE_DIR"
    "$GO_BINARY" test -count=1 ./...
    "$GO_BINARY" build \
        -trimpath \
        -buildvcs=false \
        -ldflags=-buildid= \
        -o "$TEMP_OUTPUT" \
        .
)

mv "$TEMP_OUTPUT" "$OUTPUT_PATH"
trap - EXIT
echo "portable verifier build: $OUTPUT_PATH"
