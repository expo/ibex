#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ibex-portable-verifier-build.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

FAKE_GO="$TEST_ROOT/go"
OUTPUT="$TEST_ROOT/portable-engine-attestation-verifier"

cat >"$FAKE_GO" <<'FAKE_GO_EOF'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" == "version" ]]; then
    echo "go version go1.26.5 linux/amd64"
    exit 0
fi

[[ "${GOWORK:-}" == "off" ]] || {
    echo "verifier build inherited an ambient Go workspace: ${GOWORK:-<unset>}" >&2
    exit 91
}
[[ "${GOFLAGS:-}" == "-mod=readonly" ]] || exit 92
[[ "${GOTOOLCHAIN:-}" == "local" ]] || exit 93

case "${1:-}" in
    test)
        exit 0
        ;;
    build)
        output=""
        while (( $# > 0 )); do
            if [[ "$1" == "-o" ]]; then
                output="$2"
                break
            fi
            shift
        done
        [[ -n "$output" ]] || exit 94
        printf 'fixture verifier\n' >"$output"
        ;;
    *)
        exit 95
        ;;
esac
FAKE_GO_EOF
chmod +x "$FAKE_GO"

GOWORK="$TEST_ROOT/hostile.go.work" \
    IBEX_ATTESTATION_GO="$FAKE_GO" \
    "$SCRIPT_DIR/build-portable-engine-attestation-verifier.sh" "$OUTPUT" >/dev/null

[[ -f "$OUTPUT" ]] || {
    echo "verifier build did not publish its completed output" >&2
    exit 1
}

echo "ok - portable verifier build ignores ambient Go workspaces"
