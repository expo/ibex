# `ibex2-runtime` tests fail without the `loader`/`websocket` features

**Status:** Open
**Systems:** Runtime, Tests
**Severity:** P3 (tests only)
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-06

`cargo test -p ibex2-runtime --no-default-features --features intl` fails 26 tests on main
(`d7b7d10`, Linux): 17 in the library's `engine::hermes::tests` (fetch, redirect, grants,
module authority, `javascript_websocket_reports_a_build_without_the_family`), 8 in
`tests/blob.rs`, and 1 in `tests/structured_clone.rs`. They load modules through the CLI
loader (`run_entry("./bridge.js")` → "not in the build manifest, and this build has no
loader") or assume WebSocket, but are compiled whenever their file is, not under
`cfg(feature = "loader")` / `cfg(feature = "websocket")`.

Found while qualifying lane S1, whose own changes pass in every default and
`--all-features` configuration.

## Fix

Gate each such test on the feature it needs (or give the file a `#![cfg]`), keep the
coverage under default features, and add `--no-default-features --features intl` (and plain
`--no-default-features`) to `scripts/check-ibex2-features.sh` so it can't regress.
