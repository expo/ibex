# Exhaustive Hermes target matrix (syntax → pass | typed unsupported)

**Status:** Closed
**Resolution:** Closed from the evidence recorded in f5688afb: every target-matrix row has source/prepared fixtures and an explicit pass or typed-quarantine disposition.
**Severity:** P2
**Systems:** Module Loader, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §5 (Phase 0), LLP 0019
**Depends-on:** oxc-tier3-forof-quarantine

Define what the native producer promises: an exhaustive matrix mapping
each Hermes-relevant syntax family to a landed pass or a typed
unsupported disposition with a stable diagnostic — for-of and async
generators, `for await`, `using`/`await using`, BigInt lowering (Hermes
rejects literal syntax; the canonical pass exists), decorators (SWC
parses them today, the Oxc fingerprint pins `decorators=off`; the
matrix records the author's intentional-incompatibility decision), and
source-map expectations. Every row gets real-binary
source/prepared fixtures and a final window-close disposition.

**Done when:** matrix checked in; every row has fixtures and a
disposition; decorator row resolved per the recorded author decision.

## Worktree evidence (2026-07-17)

`config/llp0019-hermes-target-matrix.json` now covers for-of, async
generators, `for await`, `using`/`await using`, BigInt, decorators, and source
maps. Rust tests pin each row to the producer and assert the BigInt pass plus
the source-map v3/SourceId contract. The real-binary runner drives every
resolved row through source and prepared profiles; passing rows require
execution receipts and quarantined rows require the stable code/reason with
no receipt.

The 2026-07-18 author decision resolves decorators as an intentional 0.2
incompatibility. The row now requires the stable
`IBEX_LEGACY_HERMES_SYNTAX` / `decorator` quarantine in source and prepared
real-Hermes profiles, completing the matrix without adding a lowering pass.
