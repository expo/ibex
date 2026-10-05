#!/usr/bin/env bash
set -euo pipefail

# Keep the engine-free library and each independently supported feature door
# buildable. This list is intentionally explicit so a new cfg gate cannot hide
# a broken default, empty, bindings-only, bindings-plus-Intl, crypto-only, or
# owning-runtime configuration. Intl is deliberately checked both off and on.
cargo check -p ibex2
cargo check -p ibex2 --no-default-features
cargo check -p ibex2 --no-default-features --features bindings
cargo check -p ibex2 --no-default-features --features bindings,intl
cargo check -p ibex2 --no-default-features --features crypto
cargo check -p ibex2-runtime --no-default-features
cargo check -p ibex2-runtime --no-default-features --features intl
