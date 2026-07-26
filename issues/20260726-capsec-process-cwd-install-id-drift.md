# Reconcile the `process.cwd` CapSec install identity

Status: Open

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
