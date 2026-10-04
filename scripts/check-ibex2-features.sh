#!/usr/bin/env bash
set -euo pipefail

# Keep the engine-free library and each independently supported feature door
# buildable. This list is intentionally explicit so a new cfg gate cannot hide
# a broken default, empty, bindings-only, or crypto-only configuration.
cargo check -p ibex2
cargo check -p ibex2 --no-default-features
cargo check -p ibex2 --no-default-features --features bindings
cargo check -p ibex2 --no-default-features --features crypto
