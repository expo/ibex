# LLP 0036: Target Advertisement Completion Plan

**Type:** Plan
**Status:** Draft
**Systems:** Security, CI, Build, Runtime, Engine, Tooling
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-23
**Related:** LLP 0021 (capsec registry / WP10 target proof); LLP 0032 (conformance execution and evidence sharding); LLP 0035 (portable engine artifact provenance); ENG-24933; ENG-24578; ENG-24580; ENG-24579

## Summary

ENG-24933 landed the promotion *machinery* — portable promotion bundles,
promoted-report admission, the physical-promotion ceremony, and evidence routing
through public executors. It did **not** flip any target cell to advertised.
On current `origin/main`, `target-attestations.json` is empty and all 15,158
target cells (7,579 coverage edges × 2 platforms) are `disposition:
"unsupported"`.

This plan records what actually blocks advertisement, with each claim measured
against the live artifacts rather than inferred, and lays out the remaining work
so it can be scoped and staffed. Its central finding is that advertisement is
**not a task** — it is gated on one months-scale authoring program plus one
open design decision that must be answered *first*, because if the answer is
negative the authoring program is moot.

## Three independent gates block advertisement

A target cell advertises only when all three hold. They form a chain: break any
link and the published claim would be unfounded, so the system publishes nothing
rather than something partly true.

1. **Producer attestation (gate 3) — CLOSED.** Build artifacts must be signed by
   a trusted CI identity so a downloaded binary is provably the tested one.
   GitHub issues these attestations only for org-owned public repos; the
   `ccheever/ibex → expo/ibex` public flip closed this gate. Rotation validated
   across the installer, producer, physical-promotion, promotion-lineage,
   evidence-contract, and Go verifier-oracle suites. See LLP 0035.

2. **Sweep bidirectionality (gate 1) — CLOSED BY AUTHOR DECISION at 6 rows.**
   Every host-ABI output channel must have a known checkable shape and vice
   versa. The residual campaign ran 41 → 6 across physically-proven tranches
   (see LLP 0035 §"Host-ABI output-shape residuals"). The remaining 6 are 1
   permanent borrowed-pointer return (no bounded value by contract) and 5 GPU
   authority/bridge success rows the conformance profile deliberately excludes.
   Reopening this is a prerequisite for advertisement but is a separate,
   smaller effort than gate 2.

3. **Report completeness (gate 2) — OPEN, and the dominant cost.** The
   remainder of this plan is about gate 2.

## Gate 2, measured

`assertRecipeCatalogComplete` (`capsec-conformance-recipes.mjs:4367`) requires
`fullyExecutableFixtures === requiredFixtures && unresolvedFixtures === 0`, and
gates `capsec-portable-promotion-bundle.mjs:341` directly on the advertisement
path. There is **no partial credit** and **no residualization escape**:
`residualReasons` is exactly what marks a recipe `unresolved`, so marking rows
residual does not satisfy the gate — it is the state the gate rejects.

Current recipe catalog (measured 2026-07-23 from the ceremony's preserved
`executable-recipes.json`):

| status | rows |
| --- | --- |
| fully-executable | 2,592 |
| unresolved | 21,993 |
| **total** | **24,585** |

The ceremony **does run locally** (`bun run verify:capsec-conformance --
--target aarch64-apple-darwin`; evidence under `target/capsec-suite-evidence-*/`).
Execution is not the bottleneck — it faithfully runs the 2,592 authored recipes
and then the completeness assert rejects the report because 21,993 remain
unresolved.

## The unresolved 21,993 split into two provable categories

Grouping every unresolved row by its **scenario** (the last dotted segment of
the fixture id — what aspect it proves) and checking which scenarios are *ever*
fully-executable anywhere in the 24,585-row catalog yields a clean partition:

- **Reachable scenarios — 18,266 unresolved rows.** Scenario types with
  hundreds of working examples already (`non-capability` 1,480 executable,
  `closed` 610, `allow`/`deny`/`malformed` ~70 each, `branch-selection`,
  `no-effect`, …). These are ordinary probe-authoring: real, laborious,
  parallelizable, template-able, but **not in doubt** — the same scenario
  already works on other surfaces. At the historical ENG-24580 tranche rate of
  5–36 rows per commit this is hundreds of commits, a staffed program measured
  in months.

- **Never-executable scenarios — 3,727 unresolved rows under exactly 7
  scenario types**, each with **zero** fully-executable instances anywhere in
  the catalog:
  `attribution-missing-deny`, `generation-recheck`, `principal-restore`,
  `snapshot-mismatch-deny`, `cannot-widen-authority`, `post-lockdown-invariant`,
  `malformed-branch-facts`.
  All 7 are internal callback-security invariants — the runtime checking its own
  attribution / principal / snapshot state. None has ever been driven from
  public JS in 24,585 rows.

## The open design question (answer before budgeting the grind)

The 7 never-executable scenarios attach to surfaces the current public-surface
harness has no recorded way to invoke (e.g. `native-op:global:AbortController`,
whose *every* scenario including plain `non-capability` is unresolved). Whether
this is fixable harness plumbing or a hard limit of the public-surface model is
**not determined by this plan**. A suspected mechanism — that
`publicInvocation` metadata is produced only for a subset of surface kinds in
`capsec-surface-inventory.mjs` — was investigated but **not confirmed** (the
distinguishing metadata lives in the live public-surface-executions evidence,
not the static implementation-manifest, and that live artifact was not audited).

> **Decision owed, to the conformance-harness owner:** can the 7 internal-invariant
> scenarios be observed through a sanctioned public path, or does gate 2 require
> a harness extension to attest internal enforcement? If they cannot be reached
> and no extension is intended, advertisement is unreachable on the current
> design, and the 18,266 rows of reachable-scenario authoring are moot. This
> question must be resolved before the authoring program is funded.

## Plan

1. **Resolve the design question above.** Audit the live
   public-surface-executions evidence for one blocked surface (e.g.
   `AbortController`) versus one reachable one (e.g. `Atomics`), determine why
   one carries a usable public invocation and the other does not, and get an
   owner decision on whether the 7 scenarios get a sanctioned observation path.
   Everything else is contingent on this.

2. **If the 7 are reachable / a harness extension is approved:** land that
   extension, then treat gate 2 as a bulk authoring program.

3. **Reachable-scenario authoring program (18,266 rows).** Start with the
   `non-capability` class — it has the widest existing precedent (1,480
   executable) and is the most likely to admit a generator rather than
   hand-authoring. Prove a template on one dense family (e.g.
   `surface.native.op.global`, ~3,000 rows), measure the real per-row cost, then
   fan out. `log`/report any silent coverage caps.

4. **Reopen gate 1 (6 rows)** in parallel — smaller and independent. The 5 GPU
   authority/bridge rows need typed generations + a typed root principal
   (`capture_v2`) and features the conformance profile excludes (the 2 bridge
   routes); the pointer-return row is permanent. Coordinate with the
   GPU-authority / LLP 0033 owner.

5. **Run the ceremony to completion and admit the report**, flipping the Apple
   matrix cells to advertised. Only then is ENG-24578's target promotion (and
   ENG-24669, the product) unblocked.

## Non-goals

- This plan does **not** author recipes or touch conformance fixtures; the
  ENG-24933 machinery regenerates that surface and changes there must be
  coordinated.
- It does **not** reopen gate 1's closure decision — that remains the author's
  call.
- It does **not** assert the design question's answer; it scopes and escalates
  it.

## Provenance of the numbers

All catalog figures were measured on 2026-07-23 from the conformance ceremony's
own preserved `executable-recipes.json` under `target/capsec-suite-evidence-*/`,
re-derived immediately before this document was written. Earlier intra-session
estimates (a "96% clear" figure, a "~1,600" never-executable count) were
superseded by these full-catalog measurements; the 96% figure measured only the
560-row native executable batch, not the 24,585-row catalog, and the 1,600 was
the global-family subset of the 3,727 catalog-wide.
