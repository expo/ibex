#!/usr/bin/env bash

# Shared Hermes release pins for Ibex build/install scripts.
#
# The 260318099.0.0 release train is published as a moving stable source branch
# rather than with prebuilt Darwin tarballs. The selected source commit is
# post-260318099.0.1 and includes the WeakRef read-barrier fix. Maven publishes
# Android only through 260318099.0.1, so keep that reviewed platform profile on
# its older, unaffected artifact until a fixed AAR is available.

IBEX_HERMES_VERSION="${IBEX_HERMES_VERSION:-260318099.0.0}"
IBEX_HERMES_SOURCE_REF="${IBEX_HERMES_SOURCE_REF:-${IBEX_HERMES_VERSION}-stable}"

# The exact commit on $IBEX_HERMES_SOURCE_REF that the checked-in/cached
# artifacts and the carried patch stack (patches/hermes/) are validated
# against. The release branch above MOVES — a cold clone of the branch builds
# whatever its HEAD is that day, which is how ENG-22565's bootstrap breakage
# shipped — so the build scripts check out this commit, not the branch
# (ENG-23092). Update both together per the pin-bump runbook
# (patches/hermes/README.md; LLP 0013 upstream-tracking).
IBEX_HERMES_SOURCE_COMMIT="${IBEX_HERMES_SOURCE_COMMIT:-e639a7bad8bfca844d982afa54fac786c65a8856}"

# What the build scripts actually build by default: the pinned commit, with
# the branch name kept as a fallback if the commit pin is explicitly unset.
IBEX_HERMES_BUILD_REF="${IBEX_HERMES_BUILD_REF:-${IBEX_HERMES_SOURCE_COMMIT:-$IBEX_HERMES_SOURCE_REF}}"

IBEX_HERMES_ANDROID_VERSION="${IBEX_HERMES_ANDROID_VERSION:-250829098.0.14}"
IBEX_REACT_ANDROID_VERSION="${IBEX_REACT_ANDROID_VERSION:-0.86.0}"

# Reviewed Maven Central package pins. These values are deliberately literal
# source authorities rather than digests fetched beside the AARs: a checksum
# downloaded from the same mutable origin would not independently authenticate
# the package. Update the coordinate and its reviewed digest together.
IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256="2399d266ed06c2a907f1ceb2606c0958a293751781f23774a292c438779c3285"
IBEX_REACT_ANDROID_DEBUG_AAR_SHA256="46fc1bfcb0a0aa2c79a81d7804105c88de7d2936fce31ca14aa4ba0e847869ee"

# --- Shared build-identity helpers (ENG-23131 / ENG-23147) ---
#
# The Hermes release identity is <hermes-commit-12>-<patch-digest-12>: the
# pinned upstream commit plus a digest of the carried patch stack (content AND
# filenames, so an edit, add, remove, or rename all change the identity). Local
# source caches and per-platform release assets extend it with both builders,
# the patch-application verifier, and this script's receipt/identity authority.
# There must be exactly ONE derivation of each component — a second scheme that
# drifted would let a stale bundle install as current.
# @ref LLP 0013#upstream-tracking-and-re-derivation — the pin + patch stack is the fork

# shasum (perl, preinstalled on macOS + GitHub runners) and sha256sum
# (coreutils) emit identical "<hex>  <path>" lines, so either tool produces
# the same digest below.
ibex_sha256() {
    # Windows coreutils prints the binary-mode "*" marker; canonicalize to the
    # two-space text form so digest-over-digest payloads are platform-stable.
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
    else
        sha256sum "$@"
    fi | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /'
}

ibex_hermes_patch_digest() {
    ibex_hermes_patch_stack_digest_hex | awk '{ print substr($1, 1, 12) }'
}

ibex_hermes_patch_stack_digest_hex() {
    local project_root
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    (
        cd "$project_root"
        # shellcheck disable=SC2012 -- the sorted glob list feeds the digest;
        # relative path names are part of the hashed content on purpose.
        ls patches/hermes/*.patch 2>/dev/null | LC_ALL=C sort \
            | while IFS= read -r patch_file; do
                ibex_sha256 "$patch_file"
            done
    ) | ibex_sha256 | awk '{ print $1 }'
}

ibex_hermes_patch_application_authority_digest_hex() {
    local project_root
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    ibex_sha256 "$project_root/scripts/apply-hermes-patches.sh" | awk '{ print $1 }'
}

ibex_hermes_patch_application_authority_digest() {
    ibex_hermes_patch_application_authority_digest_hex \
        | awk '{ print substr($1, 1, 12) }'
}

ibex_hermes_apple_build_authority_digest_hex() {
    local project_root
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    ibex_sha256 "$project_root/scripts/build-hermes.sh" | awk '{ print $1 }'
}

ibex_hermes_linux_build_authority_digest_hex() {
    local project_root
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    ibex_sha256 "$project_root/scripts/build-hermes-linux.sh" | awk '{ print $1 }'
}

# This suffix is the shared authority for deriving and writing the reviewed
# source profile identity. Keep its byte range identical to the independent
# Rust reconstruction in build_support/hermes_profile_provenance.rs.
ibex_hermes_patch_identity_authority_digest_hex() {
    local project_root version_script
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    version_script="$project_root/scripts/hermes-version.sh"
    awk 'found || /^ibex_sha256\(\) \{/ { found = 1; print }' "$version_script" \
        | ibex_sha256 | awk '{ print $1 }'
}

ibex_hermes_patch_identity_authority_digest() {
    ibex_hermes_patch_identity_authority_digest_hex \
        | awk '{ print substr($1, 1, 12) }'
}

# Source-build cache keys bind every code authority in the source-patched
# reviewed profile: both platform builders, the patch-application verifier,
# and the shared identity/receipt authority above. A change to any receipt
# authority must miss both caches; otherwise a cache hit could select a receipt
# that strict build-time validation necessarily rejects. The release tag
# deliberately remains commit + patch stack; release assets use these stronger,
# per-platform keys so an authority edit cannot look already published.
# @ref LLP 0013#artifact-provenance-and-remaining-trust-boundaries — source
# cache identity is reconstructed from the complete reviewed fork authority.
ibex_hermes_source_profile_authority_key() {
    local apple_build_hex linux_build_hex application_hex identity_hex
    apple_build_hex="$(ibex_hermes_apple_build_authority_digest_hex)"
    linux_build_hex="$(ibex_hermes_linux_build_authority_digest_hex)"
    application_hex="$(ibex_hermes_patch_application_authority_digest_hex)"
    identity_hex="$(ibex_hermes_patch_identity_authority_digest_hex)"
    printf 'p%s-ba%s-bl%s-a%s-i%s\n' \
        "$(ibex_hermes_patch_digest)" \
        "${apple_build_hex:0:12}" \
        "${linux_build_hex:0:12}" \
        "${application_hex:0:12}" \
        "${identity_hex:0:12}"
}

# The vanilla (unpatched) profile deliberately derives its cache key from a
# DIFFERENT scheme than the reviewed source-patched one: it binds the pinned
# commit and the Apple build authority, and it never binds the patch stack —
# because there is no patch stack. The literal "vanilla" component guarantees
# the two key spaces cannot collide, so an unpatched build can never land in a
# reviewed cache slot or be installed as the reviewed profile. Vanilla builds
# emit no source-profile receipt at all.
# @ref LLP 0060#6-verification — the unpatched engine the vanilla gate builds against
ibex_hermes_apple_vanilla_cache_key() {
    local version_key="$1"
    local debugger_suffix="${2:-}"
    printf '%s%s-vanilla-ba%s-oapple\n' \
        "$version_key" \
        "$debugger_suffix" \
        "$(ibex_hermes_apple_build_authority_digest_hex | cut -c1-12)"
}

ibex_hermes_apple_source_cache_key() {
    local version_key="$1"
    local debugger_suffix="${2:-}"
    printf '%s%s-%s-oapple\n' \
        "$version_key" \
        "$debugger_suffix" \
        "$(ibex_hermes_source_profile_authority_key)"
}

ibex_hermes_linux_source_cache_key() {
    local version_key="$1"
    printf '%s-%s-olinux\n' \
        "$version_key" \
        "$(ibex_hermes_source_profile_authority_key)"
}

ibex_hermes_profile_receipt_has_cache_key() {
    local receipt="$1"
    local expected="$2"
    local observed
    [[ -f "$receipt" ]] || return 1
    observed="$(sed -n 's/^[[:space:]]*"cacheKey": "\([^"]*\)",[[:space:]]*$/\1/p' "$receipt")"
    [[ "$observed" == "$expected" ]]
}

# The Darwin and Linux builders own persistent Hermes checkouts and mutable
# build/install caches. Perl's core Fcntl module exposes the same kernel flock
# primitive on stock macOS and Linux, avoiding a directory lock's unavoidable
# empty-owner and stale-recovery rename races. Bash opens fd 9 and Perl acquires
# the lock on that inherited open-file description; the lock remains held by
# Bash (and any still-running build descendants) until every inherited fd is
# closed. Kernel close-on-exit is stale-lock recovery, including SIGKILL.
# Same-uid processes that ignore the protocol can still mutate the cache and
# are explicitly outside its trust boundary.
# @ref LLP 0013#upstream-tracking-and-re-derivation — one builder owns the
# source checkout from pristine reset through receipt/cache publication.
ibex_hermes_source_build_lock_path() {
    # HOME is deliberate: XDG_CACHE_HOME changes the Linux build cache but not
    # the repo outputs or Apple's cache, so it must not split the lock domain.
    printf '%s\n' "${IBEX_HERMES_SOURCE_BUILD_LOCK_FILE:-${IBEX_HERMES_SOURCE_BUILD_LOCK_DIR:-$HOME/.cache/exact/hermes-source-build.lock}}"
}

ibex_acquire_hermes_source_build_lock() {
    local entrypoint="${1:-unknown-entrypoint}"
    local lock_file owner_pid owner_entrypoint
    if [[ "${IBEX_HERMES_SOURCE_BUILD_LOCK_HELD:-}" == 1 ]]; then
        echo "[lock] Hermes source-build lock is already held by this process" >&2
        return 1
    fi
    if ! command -v perl >/dev/null 2>&1; then
        echo "[lock] Perl with core Fcntl is required for the portable Hermes source-build lock." >&2
        return 1
    fi
    lock_file="$(ibex_hermes_source_build_lock_path)"
    mkdir -p "$(dirname "$lock_file")" || return 1
    if ! exec 9>>"$lock_file"; then
        echo "[lock] Could not open Hermes source-build lock file: $lock_file" >&2
        return 1
    fi
    if ! perl -MFcntl=:flock \
        -e 'exit(flock(STDIN, LOCK_EX | LOCK_NB) ? 0 : 1)' <&9; then
        owner_pid="$(sed -n 's/^pid=//p' "$lock_file" 2>/dev/null | head -n 1 || true)"
        owner_entrypoint="$(sed -n 's/^entrypoint=//p' "$lock_file" 2>/dev/null | head -n 1 || true)"
        echo "[lock] Waiting for Hermes source build owned by pid ${owner_pid:-unknown} (${owner_entrypoint:-unknown})..." >&2
        if ! perl -MFcntl=:flock \
            -e 'flock(STDIN, LOCK_EX) or die "flock: $!\n"' <&9; then
            exec 9>&-
            return 1
        fi
        echo "[lock] Acquired Hermes lock after the prior owner released or exited." >&2
    fi

    # Metadata is diagnostic only; kernel flock is the authority. Truncating
    # this already-locked inode cannot create a second acquisition path.
    : >"$lock_file" || { exec 9>&-; return 1; }
    {
        printf 'pid=%s\n' "$$"
        printf 'entrypoint=%s\n' "$entrypoint"
    } >&9 || { exec 9>&-; return 1; }
    IBEX_HERMES_SOURCE_BUILD_LOCK_HELD=1
    IBEX_HERMES_SOURCE_BUILD_LOCK_PATH="$lock_file"
    export IBEX_HERMES_SOURCE_BUILD_LOCK_HELD \
        IBEX_HERMES_SOURCE_BUILD_LOCK_PATH
    echo "[lock] Acquired Hermes source-build lock for $entrypoint." >&2
}

ibex_release_hermes_source_build_lock() {
    [[ "${IBEX_HERMES_SOURCE_BUILD_LOCK_HELD:-}" == 1 ]] || return 0
    exec 9>&-
    echo "[lock] Released Hermes source-build lock." >&2
    unset IBEX_HERMES_SOURCE_BUILD_LOCK_HELD \
        IBEX_HERMES_SOURCE_BUILD_LOCK_PATH
}

# Materialize the source-build assertion that build.rs later verifies against
# the exact framework selected for linking. The receipt deliberately exists
# only for the reviewed pin. A custom/moving ref can still be built, but it
# cannot silently present itself as the reviewed `source-patched` profile.
# build.rs embeds this receipt only after independently re-hashing the selected
# framework, and the runtime compares it with the current bytes of the object
# containing the mapped factory. This is a mechanical candidate binding, not a
# loaded-page or independent build attestation.
# @ref LLP 0013#upstream-tracking-and-re-derivation — bind the loaded bytes to
# the complete reviewed fork identity, including both build authorities.
ibex_write_source_patched_profile_receipt() {
    local binary="$1"
    local output="$2"
    local requested_ref="$3"
    local cache_key="$4"
    local project_root patch_stack_hex patch_application_hex
    local patch_identity_hex apple_build_hex linux_build_hex binary_hex tmp
    local expected_cache_key alternate_cache_key target_arch

    if [[ "$requested_ref" != "$IBEX_HERMES_SOURCE_COMMIT" ]]; then
        rm -f "$output"
        echo "[provenance] custom Hermes ref '$requested_ref' is not the reviewed source-patched pin; no receipt emitted." >&2
        return 0
    fi
    if [[ ! -f "$binary" ]]; then
        echo "[provenance] linked Hermes framework binary is absent: $binary" >&2
        return 1
    fi
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    patch_stack_hex="$(ibex_hermes_patch_stack_digest_hex)"
    patch_application_hex="$(ibex_hermes_patch_application_authority_digest_hex)"
    patch_identity_hex="$(ibex_hermes_patch_identity_authority_digest_hex)"
    apple_build_hex="$(ibex_hermes_apple_build_authority_digest_hex)"
    linux_build_hex="$(ibex_hermes_linux_build_authority_digest_hex)"
    binary_hex="$(ibex_sha256 "$binary" | awk '{ print $1 }')"
    if [[ "$(basename "$binary")" == "libhermesvm.so" ]]; then
        expected_cache_key="$(ibex_hermes_linux_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}")"
        alternate_cache_key=""
        case "$(uname -m)" in
            x86_64|amd64) target_arch="x86_64" ;;
            arm64|aarch64) target_arch="aarch64" ;;
            *) target_arch="$(uname -m)" ;;
        esac
    else
        expected_cache_key="$(ibex_hermes_apple_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}" "-debug")"
        alternate_cache_key="$(ibex_hermes_apple_source_cache_key "${IBEX_HERMES_SOURCE_COMMIT:0:12}" "")"
        target_arch="universal"
    fi
    if [[ "$cache_key" != "$expected_cache_key" ]] \
        && [[ -z "$alternate_cache_key" || "$cache_key" != "$alternate_cache_key" ]]; then
        echo "[provenance] Hermes cache key does not bind the reviewed pin + patch stack + both build, patch-application, and identity authorities: $cache_key" >&2
        return 1
    fi

    for value in "$IBEX_HERMES_VERSION" "$IBEX_HERMES_SOURCE_REF" \
        "$IBEX_HERMES_SOURCE_COMMIT" "$cache_key" "$patch_stack_hex" \
        "$patch_application_hex" "$patch_identity_hex" "$apple_build_hex" \
        "$linux_build_hex" "$binary_hex" "$target_arch"; do
        if [[ ! "$value" =~ ^[A-Za-z0-9._/-]+$ ]]; then
            echo "[provenance] unsafe source-profile receipt value: $value" >&2
            return 1
        fi
    done

    mkdir -p "$(dirname "$output")"
    tmp="$(mktemp "${output}.tmp.XXXXXX")"
    cat >"$tmp" <<EOF
{
  "schema": "ibex/hermes-profile-provenance-receipt/2",
  "profileId": "source-patched",
  "targetVariant": "default",
  "artifact": {
    "binaryDigest": "sha256-$binary_hex",
    "fileName": "$(basename "$binary")",
    "targetArchitecture": "$target_arch"
  },
  "origin": {
    "kind": "source-patched-cache",
    "cacheKey": "$cache_key",
    "reviewedProfileIdentity": {
      "artifact": "facebook/hermes",
      "patchApplicationAuthorityDigest": "sha256-$patch_application_hex",
      "patchIdentityAuthorityDigest": "sha256-$patch_identity_hex",
      "patchStackDigest": "sha256-$patch_stack_hex",
      "sourceBuildAuthorityDigests": {
        "scripts/build-hermes-linux.sh": "sha256-$linux_build_hex",
        "scripts/build-hermes.sh": "sha256-$apple_build_hex"
      },
      "sourceCommit": "$IBEX_HERMES_SOURCE_COMMIT",
      "sourceRef": "$IBEX_HERMES_SOURCE_REF",
      "sourceVersion": "$IBEX_HERMES_VERSION"
    }
  }
}
EOF
    chmod 0644 "$tmp"
    mv -f "$tmp" "$output"
    echo "[provenance] wrote reviewed source-patched receipt: $output"
}
