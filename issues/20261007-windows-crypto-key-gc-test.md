# Windows: `garbage_collection_releases_rust_key_handles` keeps one key handle

**Status:** Open
**Systems:** Runtime, Crypto, Engine
**Severity:** P3
**Author:** Claude (Opus 5.5), from the WebSocket cross-platform qualification
**Date:** 2026-10-07

`crates/ibex2-runtime/tests/subtle.rs`'s
`garbage_collection_releases_rust_key_handles` fails on Windows with
`--all-features` (the `crypto` feature on): after the global reference is
cleared and up to eight fresh-entrance full collections run,
`runtime.crypto_key_count()` is still 1 (`subtle.rs:593`, left 1, right 0).

It is not caused by the WebSocket work, which does not touch `ibex2-runtime`.
On the NUC (Windows, MSVC), `cargo test -q -p ibex2-runtime --all-features
--test subtle` failed 30 of 30 runs at expo/ibex main `c3fd74a` and failed the
same way on branch `ws-xp` (`4a407e9`). It passes on Linux and macOS. The
Windows qualification scripts used before 2026-10-07 ran `ibex2-runtime` only
with default features and `intl`, so it was not exercised there.

The test comment already notes that Hermes scans just-finished
Promise-reaction registers conservatively. A likely suspect is a stack or
register slot that the MSVC build keeps alive across the `eval("void 0")`
entrances, so the `CryptoKey`'s NativeState stays reachable. That is unproven.
The next step is to find out whether the key is ever released on Windows,
for example after more entrances or after the runtime drops, which would make
this a test-conservativeness problem. If it never is, it's a real handle leak.
