# Native Tier 3 conformance runner with execution receipts

**Status:** Complete
**Severity:** P2
**Systems:** Module Loader, Build, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §5 (Phase 0), LLP 0019
**Depends-on:** oxc-tier3-forof-quarantine

Today no runner drives the LLP 0019 corpus through the native producer:
`tests/hermes_compat_conformance.rs` exercises the Tier 1 AST path and
(via `EXACT_COMPAT_TEST=1`) the compatibility loader. Build a
real-`ibex`-binary runner that drives every applicable for-of and
async-generator fixture through the **native** path on real Hermes, per
advertised tuple, source and prepared, with a test-only execution
receipt (`SourceId`, semantic digest, transform-fingerprint digest,
carrier kind, producer digest, loaded Hermes digest) proving the
intended native artifact executed. Add a checked-in mapping from every
LLP 0019 corpus case to native `Pass` or typed quarantine so no case
falls silently between tiers.

**Done when:** named required CI jobs on both advertised tuples run the
native runner unconditionally; receipts asserted; corpus-case mapping
checked in and complete.

## Completion evidence (2026-07-17)

- `config/llp0019-native-tier3-corpus.json` maps all 31 owning-corpus rows to
  native `pass` or an exact typed quarantine code/reason.
- `tests/native_tier3_conformance.rs` checks the map against the producer and
  invokes the real `ibex` binary for every admitted row in both source and
  prepared profiles.
- `run-native-tier3-conformance.mjs` compares output with the Node oracle and
  requires a receipt binding `SourceId`, semantic/fingerprint digests,
  carrier, producer binary, and loaded Hermes.
- `module-loader-baselines.yml` runs the named receipt corpus unconditionally
  in the macOS-arm64 and Linux-x64 native-runner cells. The CapSec
  conformance feature supplies a debug-only pre-advertisement host while the
  ordinary and release constructors retain report-derived promotion.
