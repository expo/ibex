#!/usr/bin/env bash

# Container body for build-hermes-vanilla-linux-container.sh. ICU uses two
# total make jobs; the release script caps Hermes at four Ninja jobs and puts
# every link in a two-slot pool.
set -euo pipefail

[[ $# -eq 2 ]] || exit 2
export DEBIAN_FRONTEND=noninteractive
snapshot_timestamp=20261005T000000Z
printf '%s\n' \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot_timestamp} bookworm main" \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot_timestamp} bookworm-updates main" \
  "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${snapshot_timestamp} bookworm-security main" \
  > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/debian.sources
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential=12.9 \
  ca-certificates=20250419~deb12u1 \
  cmake=3.25.1-1 \
  git=1:2.39.5-0+deb12u3 \
  libreadline-dev=8.2-1.3 \
  libtinfo-dev=6.4-4 \
  locales=2.36-9+deb12u14 \
  ninja-build=1.11.1-2~deb12u1 \
  nodejs=18.20.4+dfsg-1~deb12u3 \
  pkg-config=1.8.1-1 \
  python3=3.11.2-1+b1 \
  python3-jsonschema=4.10.3-1 \
  zlib1g-dev=1:1.2.13.dfsg-1

export CARGO_BUILD_JOBS=4
exec /repo/scripts/build-hermes-vanilla-release.sh "$1" "$2"
