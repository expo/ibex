# Engine surgery: delete the SWC stack and the file-at-a-time path

**Status:** Open
**Severity:** P2
**Systems:** Module Loader, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4a/§4c
**Depends-on:** oxc-capsec-generator-update

Delete `enum TransformEngine`, the SWC arm, and the entire
file-at-a-time module — no consumer remains after the §4b migrations
(deletion over parity); `require()` of source files flows through the
producer's CommonJS artifact path (per-package attribution preserved).
Remove `IBEX_RUNTIME_TRANSFORM`/`EXACT_RUNTIME_TRANSFORM` outright at
0.2 (release notes + stable error-index entry; selector tests through
the removal commit, plus the fixture that removal changes nothing on
the shim path). Retire the path's cache-namespace and env-contract
estate per the retirement manifest. Remove all nine `swc_*` crates;
rewrite the `already_lowered` comments.

**Done when:** retirement manifest negative gate green; cargo-metadata
prefix gate shows zero resolved `swc_*` per retained profile;
`./ref-check` and full corpus green.
