#!/usr/bin/env bash

# @ref LLP 0013#upstream-tracking-and-re-derivation — every source builder and
# prebuilt installer holds its platform kernel lock from pristine checkout or
# validated bundle selection through artifact publication.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/hermes-version.sh"

TMP="$(mktemp -d)"
ACTIVE_PIDS=()
DESCENDANT_RELEASE=""
cleanup() {
    local pid
    set +e
    if [[ -n "$DESCENDANT_RELEASE" ]]; then
        : >"$DESCENDANT_RELEASE"
    fi
    for pid in "${ACTIVE_PIDS[@]-}"; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${ACTIVE_PIDS[@]-}"; do
        [[ -n "$pid" ]] || continue
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT
export IBEX_HERMES_SOURCE_BUILD_LOCK_FILE="$TMP/hermes-source-build.lock"

fail() {
    echo "not ok - $*" >&2
    exit 1
}

# A release mirror is transport, not provenance authority. Exercise the real
# downloader with a hostile mirror override and a fake `gh`: release bytes may
# come from the override, while attestation lookup, signer identity, and source
# ref must remain pinned to the reviewed expo/ibex workflow on main.
DOWNLOAD_FIXTURE="$TMP/download-authority"
DOWNLOAD_SCRIPTS="$DOWNLOAD_FIXTURE/scripts"
DOWNLOAD_BIN="$DOWNLOAD_FIXTURE/bin"
GH_LOG="$DOWNLOAD_FIXTURE/gh.log"
mkdir -p "$DOWNLOAD_SCRIPTS" "$DOWNLOAD_BIN" "$DOWNLOAD_FIXTURE/home"
cp "$SCRIPT_DIR/download-hermes.sh" "$DOWNLOAD_SCRIPTS/download-hermes.sh"
cat >"$DOWNLOAD_SCRIPTS/hermes-version.sh" <<'EOF'
IBEX_HERMES_BUILD_REF="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ibex_acquire_hermes_source_build_lock() { return 0; }
ibex_release_hermes_source_build_lock() { return 0; }
ibex_hermes_patch_digest() { printf 'fixturepatch\n'; }
ibex_hermes_linux_source_cache_key() { printf '%s-fixture-linux\n' "$1"; }
ibex_hermes_apple_source_cache_key() { printf '%s%s-fixture-apple\n' "$1" "$2"; }
ibex_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
    else
        sha256sum "$@"
    fi
}
EOF
cat >"$DOWNLOAD_SCRIPTS/build-hermes-linux.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$DOWNLOAD_SCRIPTS/build-hermes.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$DOWNLOAD_BIN/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -s) printf 'Linux\n' ;;
    -m) printf 'x86_64\n' ;;
    *) printf 'Linux\n' ;;
esac
EOF
cat >"$DOWNLOAD_BIN/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$GH_LOG"
case "${1:-} ${2:-}" in
    "auth status")
        exit 0
        ;;
    "release download")
        shift 2
        destination=""
        patterns=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --dir)
                    destination="$2"
                    shift 2
                    ;;
                --pattern)
                    patterns+=("$2")
                    shift 2
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        [[ -n "$destination" ]]
        mkdir -p "$destination"
        bundle=""
        for pattern in "${patterns[@]}"; do
            case "$pattern" in
                *.sha256) ;;
                *)
                    bundle="$destination/$pattern"
                    printf 'fixture\n' >"$bundle"
                    ;;
            esac
        done
        [[ -n "$bundle" ]]
        if command -v shasum >/dev/null 2>&1; then
            digest="$(shasum -a 256 "$bundle" | awk '{ print $1 }')"
        else
            digest="$(sha256sum "$bundle" | awk '{ print $1 }')"
        fi
        printf '%s  %s\n' "$digest" "$(basename "$bundle")" >"$bundle.sha256"
        exit 0
        ;;
    "attestation verify")
        # Force the downloader onto its harmless fixture source-builder path
        # after recording the exact verification authority.
        exit 1
        ;;
esac
exit 1
EOF
chmod +x \
    "$DOWNLOAD_SCRIPTS/download-hermes.sh" \
    "$DOWNLOAD_SCRIPTS/build-hermes-linux.sh" \
    "$DOWNLOAD_SCRIPTS/build-hermes.sh" \
    "$DOWNLOAD_BIN/uname" \
    "$DOWNLOAD_BIN/gh"

GH_LOG="$GH_LOG" \
HOME="$DOWNLOAD_FIXTURE/home" \
PATH="$DOWNLOAD_BIN:$PATH" \
IBEX_HERMES_ARTIFACT_REPO="attacker-controlled/mirror" \
    "$DOWNLOAD_SCRIPTS/download-hermes.sh" >/dev/null 2>&1 \
    || fail "download authority fixture did not reach its source-build fallback"

RELEASE_LINE="$(grep '^release download ' "$GH_LOG" || true)"
ATTESTATION_LINE="$(grep '^attestation verify ' "$GH_LOG" || true)"
[[ "$RELEASE_LINE" == *"--repo attacker-controlled/mirror"* ]] \
    || fail "artifact mirror override did not remain limited to release transport"
[[ "$ATTESTATION_LINE" == *"--repo expo/ibex"* ]] \
    || fail "attestation repository was not pinned to expo/ibex"
[[ "$ATTESTATION_LINE" == *"--signer-workflow expo/ibex/.github/workflows/hermes-artifacts.yml"* ]] \
    || fail "attestation signer workflow was not pinned to the reviewed workflow"
[[ "$ATTESTATION_LINE" == *"--source-ref refs/heads/main"* ]] \
    || fail "attestation source ref was not pinned to reviewed main"
[[ "$ATTESTATION_LINE" != *"attacker-controlled/mirror"* ]] \
    || fail "artifact mirror override changed the attestation trust anchor"

wait_for_file() {
    local path="$1"
    local description="$2"
    local _
    for _ in $(seq 1 200); do
        [[ -e "$path" ]] && return 0
        sleep 0.02
    done
    fail "$description"
}

assert_lock_is_available() {
    perl -MFcntl=:flock -e '
        open(my $lock, ">>", $ARGV[0]) or die "open: $!\n";
        exit(flock($lock, LOCK_EX | LOCK_NB) ? 0 : 1);
    ' "$IBEX_HERMES_SOURCE_BUILD_LOCK_FILE" \
        || fail "kernel lock remained held after its owner exited"
}

APPLE_KEY="$(ibex_hermes_apple_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}" "-debug")"
LINUX_KEY="$(ibex_hermes_linux_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}")"
PATCH_PREFIX="$(ibex_hermes_patch_digest)"
APPLE_BUILD_HEX="$(ibex_hermes_apple_build_authority_digest_hex)"
LINUX_BUILD_HEX="$(ibex_hermes_linux_build_authority_digest_hex)"
PATCH_APPLICATION_PREFIX="$(ibex_hermes_patch_application_authority_digest)"
PATCH_IDENTITY_PREFIX="$(ibex_hermes_patch_identity_authority_digest)"
EXPECTED_AUTHORITY_KEY="p${PATCH_PREFIX}-ba${APPLE_BUILD_HEX:0:12}-bl${LINUX_BUILD_HEX:0:12}-a${PATCH_APPLICATION_PREFIX}-i${PATCH_IDENTITY_PREFIX}"
[[ "$(ibex_hermes_source_profile_authority_key)" == "$EXPECTED_AUTHORITY_KEY" ]] \
    || fail "shared source-profile key omits a reviewed receipt authority"
[[ "$APPLE_KEY" == "${IBEX_HERMES_SOURCE_COMMIT:0:12}-debug-${EXPECTED_AUTHORITY_KEY}-oapple" ]] \
    || fail "Apple source cache key has the wrong complete-authority shape"
[[ "$LINUX_KEY" == "${IBEX_HERMES_SOURCE_COMMIT:0:12}-${EXPECTED_AUTHORITY_KEY}-olinux" ]] \
    || fail "Linux source cache key has the wrong complete-authority shape"

assert_pristine_before_patch_replay() {
    local script="$1"
    local apply_line clean_line reset_line lock_line
    apply_line="$(grep -nF '"$SCRIPT_DIR/apply-hermes-patches.sh"' "$script" | cut -d: -f1)"
    clean_line="$(grep -nF 'git clean -ffdx' "$script" \
        | cut -d: -f1 | awk -v apply="$apply_line" '$1 < apply { line = $1 } END { print line }')"
    reset_line="$(grep -nF 'git reset --hard "$CHECKED_OUT_COMMIT"' "$script" | cut -d: -f1)"
    lock_line="$(grep -nF 'ibex_acquire_hermes_source_build_lock' "$script" | cut -d: -f1)"
    [[ -n "$apply_line" && -n "$clean_line" && -n "$reset_line" && -n "$lock_line" ]] \
        || fail "$(basename "$script") omits the locked pristine replay boundary"
    (( lock_line < reset_line && reset_line < clean_line && clean_line < apply_line )) \
        || fail "$(basename "$script") does not reset/clean before patch replay under the lock"
}

assert_pristine_before_patch_replay "$SCRIPT_DIR/build-hermes.sh"
assert_pristine_before_patch_replay "$SCRIPT_DIR/build-hermes-linux.sh"

assert_exact_object_precedes_remote_ref() {
    local script="$1"
    local exact_line remote_line compare_line apply_line
    exact_line="$(grep -nF 'if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then' "$script" | cut -d: -f1)"
    remote_line="$(grep -nF 'elif git rev-parse --verify --quiet "origin/$HERMES_VERSION"' "$script" | cut -d: -f1)"
    compare_line="$(grep -nF '"$CHECKED_OUT_COMMIT" != "$HERMES_VERSION"' "$script" | cut -d: -f1)"
    apply_line="$(grep -nF '"$SCRIPT_DIR/apply-hermes-patches.sh"' "$script" | cut -d: -f1)"
    [[ -n "$exact_line" && -n "$remote_line" && -n "$compare_line" && -n "$apply_line" ]] \
        || fail "$(basename "$script") omits exact Hermes object selection"
    (( exact_line < remote_line && remote_line < compare_line && compare_line < apply_line )) \
        || fail "$(basename "$script") permits a remote ref to shadow an exact Hermes object"
    grep -Fq 'git checkout --detach "${HERMES_VERSION}^{commit}"' "$script" \
        || fail "$(basename "$script") does not peel the exact requested commit"
}

assert_exact_object_precedes_remote_ref "$SCRIPT_DIR/build-hermes.sh"
assert_exact_object_precedes_remote_ref "$SCRIPT_DIR/build-hermes-linux.sh"
grep -Fq 'PROFILE_RECEIPT_DEST="$FRAMEWORKS_DIR/hermes-profile-provenance.json"' \
    "$SCRIPT_DIR/build-hermes.sh" \
    || fail "Apple builder does not own the installed profile receipt path"
grep -Fq 'cp "$PROFILE_RECEIPT_DEST" "$VERSION_CACHE/hermes-profile-provenance.json"' \
    "$SCRIPT_DIR/build-hermes.sh" \
    || fail "Apple builder does not publish the fresh reviewed receipt with its cache"
grep -Fq 'ibex_write_source_patched_profile_receipt \' \
    "$SCRIPT_DIR/build-hermes-linux.sh" \
    || fail "Linux builder does not publish a reviewed dynamic-runtime receipt"
grep -Fq '"$LINUX_LIB_DIR/hermes-profile-provenance.json"' \
    "$SCRIPT_DIR/build-hermes-linux.sh" \
    || fail "Linux builder does not install the reviewed receipt beside libhermesvm"
grep -Fq -- '--target hermesvm hermesvm_a hermesc hermes' \
    "$SCRIPT_DIR/build-hermes-linux.sh" \
    || fail "Linux builder does not build the runtime-side HBC version probe"
grep -Fq '"$TOOLS_DIR/hermes-linux-$HERMESC_ARCH"' \
    "$SCRIPT_DIR/build-hermes-linux.sh" \
    || fail "Linux builder does not publish the Hermes VM CLI beside hermesc"
grep -Fq 'bundle missing bin/hermes' "$SCRIPT_DIR/download-hermes.sh" \
    || fail "Linux prebuilt admission does not require the runtime-side HBC version probe"
grep -Fq 'Linux bundle compiler/runtime HBC versions are missing or differ' \
    "$SCRIPT_DIR/download-hermes.sh" \
    || fail "Linux prebuilt admission does not compare compiler/runtime HBC versions"
grep -Fq '"$profile_receipt" "$lib_dir/"' "$SCRIPT_DIR/download-hermes.sh" \
    || fail "Linux prebuilt installation does not retain the reviewed profile receipt"

assert_windows_locked_pristine_publication() {
    local builder="$SCRIPT_DIR/build-hermes-windows.ps1"
    local installer="$SCRIPT_DIR/install-windows-hermes.ps1"
    local lock_line reset_line clean_line apply_line build_line manifest_line
    local receipt_line publish_line release_line
    lock_line="$(grep -nF '$buildLock = Enter-HermesSourceBuildLock "build-hermes-windows-$Arch"' "$builder" | cut -d: -f1)"
    reset_line="$(grep -nF 'git -C $sourceDir reset --hard $checkedOutCommit' "$builder" | cut -d: -f1)"
    clean_line="$(grep -nF 'git -C $sourceDir clean -fdxq' "$builder" | cut -d: -f1)"
    apply_line="$(grep -nF '& bash $applyScriptUnix $sourceDirUnix' "$builder" | cut -d: -f1)"
    build_line="$(grep -nF 'cmake --build $buildDir' "$builder" | cut -d: -f1)"
    manifest_line="$(grep -nF -- '-Content ($manifest | ConvertTo-Json)' "$builder" | cut -d: -f1)"
    receipt_line="$(grep -nF -- '-Content ($receipt | ConvertTo-Json -Depth 8)' "$builder" | cut -d: -f1)"
    publish_line="$(grep -nF 'Remove-Item -LiteralPath $targetRoot' "$builder" | cut -d: -f1)"
    release_line="$(grep -nF 'Exit-HermesSourceBuildLock $buildLock' "$builder" | cut -d: -f1)"
    [[ -n "$lock_line" && -n "$reset_line" && -n "$clean_line" \
        && -n "$apply_line" && -n "$build_line" && -n "$manifest_line" \
        && -n "$receipt_line" && -n "$publish_line" && -n "$release_line" ]] \
        || fail "Windows builder omits the locked pristine/publication boundary"
    (( lock_line < reset_line && reset_line < clean_line && clean_line < apply_line \
        && apply_line < build_line && build_line < manifest_line \
        && manifest_line < receipt_line && receipt_line < publish_line \
        && publish_line < release_line )) \
        || fail "Windows builder releases its lock before complete artifact publication"
    [[ "$(sed -n "$((manifest_line - 2))p" "$builder")" == *'Write-Utf8NoBomFile `'* \
        && "$(sed -n "$((manifest_line - 1))p" "$builder")" == *'-Path (Join-Path $installDir "artifact.json") `'* ]] \
        || fail "Windows builder does not publish its manifest through the UTF-8 no-BOM writer"
    [[ "$(sed -n "$((receipt_line - 2))p" "$builder")" == *'Write-Utf8NoBomFile `'* \
        && "$(sed -n "$((receipt_line - 1))p" "$builder")" == *'-Path (Join-Path $binDir "hermes-profile-provenance.json") `'* ]] \
        || fail "Windows builder does not publish its receipt through the UTF-8 no-BOM writer"
    grep -Fq '[System.IO.FileShare]::None' "$builder" \
        || fail "Windows builder lock is not an exclusive OS file handle"
    grep -Fq 'finally {' "$builder" \
        || fail "Windows builder lock has no finally release path"

    local check_lock_line check_release_line source_branch_line
    local installer_publish_line installer_remove_line installer_release_line
    check_lock_line="$(grep -nF '$installCheckLock = Enter-HermesSourceBuildLock' "$installer" | cut -d: -f1)"
    check_release_line="$(grep -nF 'Exit-HermesSourceBuildLock $installCheckLock' "$installer" | cut -d: -f1)"
    source_branch_line="$(grep -nF 'if ($Source -or $env:IBEX_HERMES_FORCE_BUILD -eq "1")' "$installer" | cut -d: -f1)"
    installer_publish_line="$(grep -nF '$publishLock = Enter-HermesSourceBuildLock' "$installer" | cut -d: -f1)"
    installer_remove_line="$(grep -nF 'Remove-Item -LiteralPath $targetRoot' "$installer" | cut -d: -f1)"
    installer_release_line="$(grep -nF 'Exit-HermesSourceBuildLock $publishLock' "$installer" | cut -d: -f1)"
    [[ -n "$check_lock_line" && -n "$check_release_line" && -n "$source_branch_line" \
        && -n "$installer_publish_line" && -n "$installer_remove_line" \
        && -n "$installer_release_line" ]] \
        || fail "Windows installer omits its shared publication lock"
    (( check_lock_line < check_release_line && check_release_line < source_branch_line \
        && source_branch_line < installer_publish_line \
        && installer_publish_line < installer_remove_line \
        && installer_remove_line < installer_release_line )) \
        || fail "Windows installer holds the lock while delegating or publishes outside it"

    grep -Fq 'patchApplicationAuthorityDigest -eq "sha256-$patchApplicationAuthorityDigest"' "$installer" \
        || fail "Windows installer does not validate the full patch-application authority"
    grep -Fq 'patchIdentityAuthorityDigest -eq "sha256-$patchIdentityAuthorityDigest"' "$installer" \
        || fail "Windows installer does not validate the full patch-identity authority"
    grep -Fq 'windows_asset_key="${identity}-a${patch_application_hex:0:12}-i${patch_identity_hex:0:12}-bw' \
        "$SCRIPT_DIR/../.github/workflows/hermes-artifacts.yml" \
        || fail "Windows release asset key omits patch authority prefixes"
}

assert_windows_locked_pristine_publication

RECEIPT="$TMP/receipt.json"
printf '{\n  "origin": {\n    "cacheKey": "%s",\n    "kind": "source-patched-cache"\n  }\n}\n' \
    "$APPLE_KEY" >"$RECEIPT"
ibex_hermes_profile_receipt_has_cache_key "$RECEIPT" "$APPLE_KEY" \
    || fail "receipt cache-key validator rejected the exact key"
if ibex_hermes_profile_receipt_has_cache_key "$RECEIPT" "$LINUX_KEY"; then
    fail "receipt cache-key validator accepted a different platform key"
fi

# Three entrypoints must serialize without an empty-owner publication window or
# stale-lock quarantine race. Each holder also owns the same critical marker,
# so any overlap fails independently of the acquisition timing assertions.
HOLDER_READY="$TMP/holder-ready"
HOLDER_RELEASE="$TMP/holder-release"
CRITICAL="$TMP/critical-section"
CONTENDER_ONE_STARTED="$TMP/contender-one-started"
CONTENDER_TWO_STARTED="$TMP/contender-two-started"
CONTENDER_ONE_ACQUIRED="$TMP/contender-one-acquired"
CONTENDER_TWO_ACQUIRED="$TMP/contender-two-acquired"
SCRIPT_DIR="$SCRIPT_DIR" \
HOLDER_READY="$HOLDER_READY" \
HOLDER_RELEASE="$HOLDER_RELEASE" \
CRITICAL="$CRITICAL" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock darwin-builder-fixture
    trap "ibex_release_hermes_source_build_lock" EXIT
    mkdir "$CRITICAL"
    : >"$HOLDER_READY"
    while [[ ! -e "$HOLDER_RELEASE" ]]; do sleep 0.02; done
    rmdir "$CRITICAL"
' &
HOLDER_PID=$!
ACTIVE_PIDS+=("$HOLDER_PID")
wait_for_file "$HOLDER_READY" "first lock holder never became ready"

SCRIPT_DIR="$SCRIPT_DIR" \
STARTED="$CONTENDER_ONE_STARTED" \
ACQUIRED="$CONTENDER_ONE_ACQUIRED" \
CRITICAL="$CRITICAL" \
NAME="linux-builder-fixture" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    : >"$STARTED"
    ibex_acquire_hermes_source_build_lock "$NAME"
    trap "ibex_release_hermes_source_build_lock" EXIT
    mkdir "$CRITICAL"
    : >"$ACQUIRED"
    sleep 0.1
    rmdir "$CRITICAL"
' &
CONTENDER_ONE_PID=$!
ACTIVE_PIDS+=("$CONTENDER_ONE_PID")

SCRIPT_DIR="$SCRIPT_DIR" \
STARTED="$CONTENDER_TWO_STARTED" \
ACQUIRED="$CONTENDER_TWO_ACQUIRED" \
CRITICAL="$CRITICAL" \
NAME="prebuilt-installer-fixture" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    : >"$STARTED"
    ibex_acquire_hermes_source_build_lock "$NAME"
    trap "ibex_release_hermes_source_build_lock" EXIT
    mkdir "$CRITICAL"
    : >"$ACQUIRED"
    sleep 0.1
    rmdir "$CRITICAL"
' &
CONTENDER_TWO_PID=$!
ACTIVE_PIDS+=("$CONTENDER_TWO_PID")
wait_for_file "$CONTENDER_ONE_STARTED" "first contender never started"
wait_for_file "$CONTENDER_TWO_STARTED" "second contender never started"
sleep 0.15
[[ ! -e "$CONTENDER_ONE_ACQUIRED" && ! -e "$CONTENDER_TWO_ACQUIRED" ]] \
    || fail "a source-build entrypoint acquired concurrently with the holder"
: >"$HOLDER_RELEASE"
wait "$HOLDER_PID"
wait "$CONTENDER_ONE_PID"
wait "$CONTENDER_TWO_PID"
ACTIVE_PIDS=()
[[ -e "$CONTENDER_ONE_ACQUIRED" && -e "$CONTENDER_TWO_ACQUIRED" ]] \
    || fail "both waiting source-build entrypoints did not acquire serially"
[[ -f "$IBEX_HERMES_SOURCE_BUILD_LOCK_FILE" ]] \
    || fail "stable kernel lock file was unexpectedly unlinked"
assert_lock_is_available

# SIGKILL cannot run a shell trap. The kernel must release the advisory lock
# when the final holder closes, allowing a later run to recover without PID or
# process-start heuristics.
CRASH_READY="$TMP/crash-ready"
SCRIPT_DIR="$SCRIPT_DIR" \
CRASH_READY="$CRASH_READY" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock crash-fixture
    : >"$CRASH_READY"
    kill -STOP "$$"
' &
CRASH_PID=$!
ACTIVE_PIDS+=("$CRASH_PID")
wait_for_file "$CRASH_READY" "crash fixture never acquired"
kill -KILL "$CRASH_PID"
set +e
wait "$CRASH_PID"
CRASH_STATUS=$?
set -e
ACTIVE_PIDS=()
[[ "$CRASH_STATUS" == 137 ]] \
    || fail "SIGKILL fixture exited with $CRASH_STATUS instead of 137"
assert_lock_is_available

SCRIPT_DIR="$SCRIPT_DIR" bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock post-crash-fixture
    ibex_release_hermes_source_build_lock
'

# If the builder dies while a compiler/build descendant is still running, the
# inherited descriptor keeps the boundary closed until that descendant exits.
DESCENDANT_READY="$TMP/descendant-ready"
DESCENDANT_RELEASE="$TMP/descendant-release"
DESCENDANT_PID_FILE="$TMP/descendant-pid"
PARENT_READY="$TMP/descendant-parent-ready"
DESCENDANT_CONTENDER_STARTED="$TMP/descendant-contender-started"
DESCENDANT_CONTENDER_ACQUIRED="$TMP/descendant-contender-acquired"
SCRIPT_DIR="$SCRIPT_DIR" \
DESCENDANT_READY="$DESCENDANT_READY" \
DESCENDANT_RELEASE="$DESCENDANT_RELEASE" \
DESCENDANT_PID_FILE="$DESCENDANT_PID_FILE" \
PARENT_READY="$PARENT_READY" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock descendant-parent-fixture
    (
        : >"$DESCENDANT_READY"
        while [[ ! -e "$DESCENDANT_RELEASE" ]]; do sleep 0.02; done
    ) &
    printf "%s\n" "$!" >"$DESCENDANT_PID_FILE"
    : >"$PARENT_READY"
    kill -STOP "$$"
' &
DESCENDANT_PARENT_PID=$!
ACTIVE_PIDS+=("$DESCENDANT_PARENT_PID")
wait_for_file "$PARENT_READY" "descendant parent never acquired"
wait_for_file "$DESCENDANT_READY" "lock-inheriting descendant never started"
kill -KILL "$DESCENDANT_PARENT_PID"
set +e
wait "$DESCENDANT_PARENT_PID"
DESCENDANT_PARENT_STATUS=$?
set -e
ACTIVE_PIDS=()
[[ "$DESCENDANT_PARENT_STATUS" == 137 ]] \
    || fail "descendant parent exited with $DESCENDANT_PARENT_STATUS instead of 137"

SCRIPT_DIR="$SCRIPT_DIR" \
STARTED="$DESCENDANT_CONTENDER_STARTED" \
ACQUIRED="$DESCENDANT_CONTENDER_ACQUIRED" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    : >"$STARTED"
    ibex_acquire_hermes_source_build_lock descendant-contender-fixture
    trap "ibex_release_hermes_source_build_lock" EXIT
    : >"$ACQUIRED"
' &
DESCENDANT_CONTENDER_PID=$!
ACTIVE_PIDS+=("$DESCENDANT_CONTENDER_PID")
wait_for_file "$DESCENDANT_CONTENDER_STARTED" "descendant contender never started"
sleep 0.15
[[ ! -e "$DESCENDANT_CONTENDER_ACQUIRED" ]] \
    || fail "parent SIGKILL released a lock still inherited by a live descendant"
: >"$DESCENDANT_RELEASE"
wait_for_file "$DESCENDANT_CONTENDER_ACQUIRED" \
    "contender did not acquire after the final inherited descriptor closed"
wait "$DESCENDANT_CONTENDER_PID"
ACTIVE_PIDS=()
assert_lock_is_available

# EXIT-trap cleanup is the builder contract for normal failures and the
# explicit HUP/INT/TERM traps.
SCRIPT_DIR="$SCRIPT_DIR" bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock exit-trap-fixture
    trap "ibex_release_hermes_source_build_lock" EXIT
'
assert_lock_is_available

SIGNAL_READY="$TMP/signal-ready"
SCRIPT_DIR="$SCRIPT_DIR" \
SIGNAL_READY="$SIGNAL_READY" \
bash -c '
    set -euo pipefail
    source "$SCRIPT_DIR/hermes-version.sh"
    ibex_acquire_hermes_source_build_lock signal-trap-fixture
    trap "ibex_release_hermes_source_build_lock" EXIT
    trap "exit 143" TERM
    : >"$SIGNAL_READY"
    while true; do sleep 1; done
' &
SIGNAL_PID=$!
ACTIVE_PIDS+=("$SIGNAL_PID")
wait_for_file "$SIGNAL_READY" "signal-trap fixture never acquired"
kill -TERM "$SIGNAL_PID"
set +e
wait "$SIGNAL_PID"
SIGNAL_STATUS=$?
set -e
ACTIVE_PIDS=()
[[ "$SIGNAL_STATUS" == 143 ]] \
    || fail "TERM trap exited with $SIGNAL_STATUS instead of 143"
assert_lock_is_available

echo "ok - Hermes source-build lock, cache identity, and download attestation authority"
