#!/usr/bin/env bash

# Container body for build-hermes-vanilla-linux-container.sh. ICU uses two
# total make jobs; the release script caps Hermes at four Ninja jobs and puts
# every link in a two-slot pool.
set -euo pipefail

[[ $# -eq 2 ]] || exit 2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential ca-certificates cmake git libreadline-dev libtinfo-dev \
  locales ninja-build nodejs pkg-config python3 python3-jsonschema zlib1g-dev

export CARGO_BUILD_JOBS=4
exec /repo/scripts/build-hermes-vanilla-release.sh "$1" "$2"
