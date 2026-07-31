# Four pre-existing capsec-evidence JS test failures on main (masked by the fmt gate)

**Status:** Open
**Severity:** P2
**Systems:** CapSec, Testing, CI
**Author:** Claude Fable 5 (Claude Code), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** issues/closed/20260728-capsec-public-surface-evidence-backlog (adjacent program),
`.github/workflows/ci.yml` Preflight

`bun test packages` fails 4 tests at origin/main (verified 2026-07-31 in a
clean worktree at the 661dd16e lineage, independent of the ticket-sweep
branch). Main's Preflight has NOT been running the bun suites — it dies
earlier at the `cargo fmt --check` gate (fixed by the sweep), so these reds
were invisible on the badge. Once Preflight reaches the bun step it will
report them.

1. `capsec-loader-output-templates.test.mjs` — "source-bound module-loader
   output recipes > partitions the exact catalogued module-loader family":
   `expect(rows).toHaveLength(169)` got 174 — five new catalogued
   module-loader family rows without template partitioning.
2. `capsec-fixture-evidence.test.mjs` — "Exact fixture-evidence pilot >
   credits nine actual fixtures…keeps promotion closed": aggregate drifted
   (±4 rows).
3. `authenticated-graph-snapshot.test.mjs` — "matches the cross-language
   golden identity": the JS golden no longer matches; the Rust-side
   projection presumably moved (LLP 0413 phase-4 / graph-snapshot work). Do
   NOT blind-restamp — the golden exists to catch exactly this; re-derive
   from the Rust side and review the delta.
4. `capsec-output-shape-sweep.test.mjs` — "output-shape-sweep-v3 evidence
   contract": `toHaveLength(6517)` got 6520 — three new Host ABI execution
   rows unaccounted in the sweep partition.

These smell like one family: recent upstream capsec/LLP 0413 landings grew
catalogued surfaces without updating the evidence-side pins, the same
pattern as the regen-chain drift the sweep repaired. Each pin is a reviewed
count/golden, so each fix is a reviewed restamp with the delta named, not a
number bump.

Done when `bun test packages` is green at main and each restamp records
which upstream commit grew the counts.
