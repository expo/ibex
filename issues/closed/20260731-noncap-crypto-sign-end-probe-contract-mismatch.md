# noncap batch red on main: crypto Sign.end probe contract-mismatch

**Status:** Closed
**Severity:** P3
**Systems:** CapSec, Testing
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** LLP 0044 §9 (found by the day-one measurement's representative
batch run); issues/20260731-preexisting-capsec-evidence-js-reds.md (adjacent
but a different suite — that one is bun tests, this is the Rust batch);
llp/evidence/0044-batch-timing-*.json

`capsec_public_noncap_builtin_recipe_batch` fails on current main against a
freshly generated `aarch64-apple-darwin` recipe catalog
(`sha256-XcvN5FFF9meYMuBBgdMjEy8mmG8QiBrhNf9Z3w_ZISg`):

```
surface.builtin.export.exact.crypto.sign.end.016nd0t.main.non-capability:
public builtin probe failed:
{"kind":"contract-mismatch","moduleSpecifier":"node:crypto","exportName":"Sign.end"}
```

One throwing probe fails the whole batch by design. Either the authored
probe spec for `Sign.end` drifted from the loaded prototype's contract, or
the runtime export changed shape after the probe landed. Reproduce:

```
IBEX_CAPSEC_RECIPE_CATALOG=<generated catalog> \
IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT=<out> \
cargo test --bin ibex --features capsec-conformance-observer,openssl-crypto \
  capsec_public_noncap_builtin_recipe_batch -- --test-threads=1 --nocapture
```

**Done when:** the probe spec and the live `Sign.end` contract agree (fix
whichever drifted, empirically verified per the family's authoring rule) and
the batch passes against a regenerated catalog.

## Resolution (2026-08-03)

The `Sign.end` recipe and runtime contract already agreed. The independent
loaded-engine validator for zlib stream completion treated every export name
ending in `.end` as a zlib operation before checking its source family, so it
rejected `exact_crypto:Sign.end` as a contract mismatch. The validator now
applies that vocabulary only to `node_zlib`, while a negative regression keeps
the dedicated `zlib-end-owner` setup unavailable to other source families.

The exact generated Windows recipe no longer returns `contract-mismatch` in
the harness regression, and the physical CapSec matrix is the merge gate for
the complete bound-engine proof.
