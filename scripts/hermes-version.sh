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
