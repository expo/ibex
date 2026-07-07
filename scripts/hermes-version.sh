#!/usr/bin/env bash

# Shared Hermes release pins for Ibex build/install scripts.
#
# The 260318099.0.0 release is published as a stable source branch rather than
# a GitHub release tag with prebuilt Darwin tarballs. Android's Maven artifact
# has not caught up yet, so keep that platform pin explicit and separate.

IBEX_HERMES_VERSION="${IBEX_HERMES_VERSION:-260318099.0.0}"
IBEX_HERMES_SOURCE_REF="${IBEX_HERMES_SOURCE_REF:-${IBEX_HERMES_VERSION}-stable}"

# The exact commit on $IBEX_HERMES_SOURCE_REF that the checked-in/cached
# artifacts and the carried patch stack (patches/hermes/) are validated
# against. The release branch above MOVES — a cold clone of the branch builds
# whatever its HEAD is that day, which is how ENG-22565's bootstrap breakage
# shipped — so the build scripts check out this commit, not the branch
# (ENG-23092). Update both together per the pin-bump runbook
# (patches/hermes/README.md; LLP 0013 upstream-tracking).
IBEX_HERMES_SOURCE_COMMIT="${IBEX_HERMES_SOURCE_COMMIT:-ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138}"

# What the build scripts actually build by default: the pinned commit, with
# the branch name kept as a fallback if the commit pin is explicitly unset.
IBEX_HERMES_BUILD_REF="${IBEX_HERMES_BUILD_REF:-${IBEX_HERMES_SOURCE_COMMIT:-$IBEX_HERMES_SOURCE_REF}}"

IBEX_HERMES_ANDROID_VERSION="${IBEX_HERMES_ANDROID_VERSION:-250829098.0.14}"
IBEX_REACT_ANDROID_VERSION="${IBEX_REACT_ANDROID_VERSION:-0.86.0}"

# --- Shared build-identity helpers (ENG-23131 / ENG-23147) ---
#
# The Hermes artifact identity is <hermes-commit-12>-<patch-digest-12>: the
# pinned upstream commit plus a digest of the carried patch stack (content AND
# filenames, so an edit, add, remove, or rename all change the identity).
# build-hermes.sh keys its local cache on it, the hermes-artifacts workflow
# names published release bundles with it, and download-hermes.sh looks those
# bundles up by it. There must be exactly ONE derivation of this digest — a
# second scheme that drifted would let a stale bundle install as current.
# @ref LLP 0013#upstream-tracking-and-re-derivation — the pin + patch stack is the fork

# shasum (perl, preinstalled on macOS + GitHub runners) and sha256sum
# (coreutils) emit identical "<hex>  <path>" lines, so either tool produces
# the same digest below.
ibex_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
    else
        sha256sum "$@"
    fi
}

ibex_hermes_patch_digest() {
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
    ) | ibex_sha256 | awk '{ print substr($1, 1, 12) }'
}
