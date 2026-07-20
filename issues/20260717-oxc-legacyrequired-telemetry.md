# Decision-grade LegacyRequired telemetry + static-scan denominator

**Status:** In Progress
**Severity:** P2
**Systems:** Module Loader, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §5

Upgrade the compat loader's `LegacyRequired` diagnostic to a typed
event: stable category enum covering all shapes, module,
original-source site, runtime version — structured, not stderr prose.
Aggregate across CI test/fixture runs; wire the Snapback generated-CLI
test population report (cross-repo). Add the static-scan denominator:
computed-`require`/computed-import occurrence counts across the
authenticated dependency trees CI already builds, with populations
named and digested. Archive the combined report (content-addressed)
before window close; telemetry is labeled advisory — the report feeds
register items 2 and 3, it does not decide them.

**Done when:** typed events emitted; CI aggregation job + static scan
land; archived report format defined; population boundary stated in
the report itself.

## Ibex implementation evidence (2026-07-17)

- `LegacyModuleRunnerRequirement` now emits
  `ibex/legacy-required-telemetry-event/1` with stable category/shape/code,
  canonical module `SourceId`, original-source byte/line/column, and runtime
  version. Native quarantine tests require exactly one event and no execution
  receipt.
- `legacy-required-telemetry.mjs` owns the deterministic
  `ibex/legacy-required-telemetry-report/1` envelope: named population
  boundary, controlled/advisory labels, authenticated tree digest, event
  digest and counts, and the explicitly upper-bound Oxc static denominator.
- The macOS/Linux native CI matrix uploads the report for its controlled
  Tier-3/target population. The local 22-execution run produced eight typed
  events and is archived content-addressed at
  `llp/evidence/0028-legacy-required-telemetry-c263362b29515b259e68b6f33df21374fb9141f8bab74bc415917775093d3a47.json`.

This remains **In Progress** only for the separately owned Snapback
generated-CLI test-population producer/aggregation wiring. The report format
and population-boundary contract it must emit are now available from Ibex;
no released-user field usage is inferred from either controlled population.
