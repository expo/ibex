# capsec_public_startup_environment_batch: RAF root-global disposition red on main

**Status:** Open
**Opened:** 2026-08-24 (by the LLP 0055 S3 lane, during pre-land gating).
**Date:** 2026-08-24

`cargo test --bin ibex --features capsec-conformance-observer
loaded_hermes_isolates_principal_environment_overlays` fails on a clean
`origin/main` checkout (fe53e64fa, fresh worktree, fresh
`scripts/download-hermes.sh`):

```
Armed startup refused: root-global disposition
(sha256-_PMdttWNedOTqYXqj0F4IBAc7uidOWc_U0hyKusPJg8):
extra post-bootstrap roots: __exactRequestAnimationFrame
load armed principal-overlay runtime: Hermes refused to seal armed bootstrap (fault 4)
```

The armed live sweep (`hermes_runtime.cc` ~9540: `count > baselineCount`
and not in `reachableRoots`) finds `__exactRequestAnimationFrame` installed
above baseline without a reachable classification for the
principal-environment-overlay lane. Attribution runs (2026-08-24):

- clean origin/main: FAILS (above);
- LLP 0055 S3 branch (agent/0055-s3, four slices): fails identically —
  the S3 slices neither cause nor mask it;
- `capsec_public_startup_batch` proper and
  `capsec_public_callback_invariant_batch` are green in both trees.

Likely either a missing disposition row/classification for the RAF bridge
in the overlay lane or a stale manifest against the current installer set
(the root-global generator's full-inventory pass is separately blocked by
pre-existing unclassified plan-seam surfaces — see the note in the LLP
0055 S3(D2) commit's summary). Needs its owner to classify the surface or
regenerate with the plan-seam classifications resolved.
