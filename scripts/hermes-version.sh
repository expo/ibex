#!/usr/bin/env bash

# Shared Hermes release pins for Ibex build/install scripts.
#
# The 260318099.0.0 release is published as a stable source branch rather than
# a GitHub release tag with prebuilt Darwin tarballs. Android's Maven artifact
# has not caught up yet, so keep that platform pin explicit and separate.

IBEX_HERMES_VERSION="${IBEX_HERMES_VERSION:-260318099.0.0}"
IBEX_HERMES_SOURCE_REF="${IBEX_HERMES_SOURCE_REF:-${IBEX_HERMES_VERSION}-stable}"
IBEX_HERMES_ANDROID_VERSION="${IBEX_HERMES_ANDROID_VERSION:-250829098.0.14}"
IBEX_REACT_ANDROID_VERSION="${IBEX_REACT_ANDROID_VERSION:-0.86.0}"
