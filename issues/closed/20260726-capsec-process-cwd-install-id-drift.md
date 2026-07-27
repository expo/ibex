# Reconcile the `process.cwd` CapSec install identity

Status: Resolved

The exact committed Apple snapshot cannot start the complete native public
primary shard because three checked artifacts disagree about the source-derived
`process.cwd` root-global install identity:

- `capsec/generated/root-global-disposition-manifest.json` carries
  `root-global.process.cwd.85eed694780dbac5`;
- `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs` and
  its test require `root-global.process.cwd.2583c1a2d2ca2d7b`;
- `src/bin/ibex/engine/capsec_conformance_batch.rs` requires the same
  `2583c1a2d2ca2d7b` value.

The failure occurs at fixture 3, before the filesystem rows changed by the
Windows append-open evidence repair. After integrating the moving `main` CLI
and evaluator inventory, regenerating the Apple recipe catalog produces digest
`sha256-hzFaFp6ca8rOPfB-aswmofNj87HnLQAhzJZgbDPfvg0`; the same install-ID
disagreement remains. This is checked artifact/validator drift rather than a
target-catalog change from the filesystem repair.

## Done when

- Determine which source-derived identity is authoritative and regenerate or
  correct every checked artifact together.
- Add a deterministic drift regression that cannot accept a manifest and
  evidence validator with different install IDs.
- Pass both complete Apple native public shards on the M4 verifier under
  `IBEX_FAIL_ON_STALE_VENDORED=1`.

## Resolution

The checked root-global disposition manifest is authoritative. The JavaScript
public-evidence validator and Rust native producer now look up both the
converted `process.cwd` facade and its private `__exactGetCwd` terminal by
install ID in that manifest, then validate the exact observed keys,
dispositions, activations, property paths, source references, consumer, and
live expectation. Neither validator carries a second hard-coded install ID.
Regressions reject the retired ID and manifest/evidence drift.

The physical M4 verifier passed all 281 primary and 313 secondary Apple
fixtures under strict stale-vendored enforcement. Cross-shard validation
merged all 594 executions with zero failures and aggregate digest
`sha256-pjKQVJY9H5oqPUfAd-3At7dYhftHksIn1291nfpP3ms`.
