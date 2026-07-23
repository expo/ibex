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

## The design question, and its resolved direction

The 7 never-executable scenarios attach to surfaces the current public-surface
harness has no recorded way to invoke (e.g. `native-op:global:AbortController`,
whose *every* scenario including plain `non-capability` is unresolved). The
question is whether they can be driven from public JS or whether that is a hard
limit of the public-surface model.

**Resolved direction (2026-07-23, author: "make it coherent now, verify
correctness over the coming weeks"):** treat the 7 as **internally-verified
invariants, not public-surface fixtures.** The rationale is grounded in the
measured facts, not a guess:

- All 7 (`attribution-missing-deny`, `generation-recheck`, `principal-restore`,
  `snapshot-mismatch-deny`, `cannot-widen-authority`, `post-lockdown-invariant`,
  `malformed-branch-facts`) are the runtime checking *its own* attribution /
  principal / snapshot / lockdown state. By construction these fire on internal
  transitions, not on a public JS call — there is nothing for a public-surface
  probe to invoke.
- They have zero fully-executable instances anywhere in 24,585 catalog rows,
  which is what a genuinely non-public-invokable class looks like, versus an
  un-authored-but-reachable one.

So the coherent model is: **public-surface completeness attests what is publicly
reachable; these internal invariants are attested by internal Rust proofs**
(most already exist as unit tests of the enforcement paths) and are marked in
the catalog as `internally-verified` rather than counted as unresolved
public-surface fixtures. This makes the completeness gate satisfiable from the
18,266 reachable rows, keeps the security claim honest (nothing is faked — an
internal invariant is proven by an internal test, not a fabricated public
probe), and defers only the *bookkeeping reclassification* to review.

**Correctness still owed (the "over the coming weeks" part):** confirm that each
of the 7 scenario types has (or gets) a real internal Rust proof of the
invariant it names, and that the reclassification predicate is tight enough that
it cannot silently absorb a scenario that *is* publicly reachable. Until that
audit lands, the reclassification is a coherent working position, not a verified
one.

## Plan

1. **Implement the internally-verified reclassification** for the 7 invariant
   scenarios (the resolved direction above): add an `internally-verified`
   disposition, mark the 3,727 rows under those 7 scenarios with it, exclude
   that disposition from the `assertRecipeCatalogComplete` unresolved count, and
   point each scenario type at the internal Rust proof that already covers its
   invariant (or file a stub where one is missing). This removes 3,727 rows from
   the completeness denominator without faking any public evidence, and makes
   the gate satisfiable from the reachable rows alone.

2. **Reachable-scenario authoring program (18,266 rows).** Start with the
   `non-capability` class — it has the widest existing precedent (1,480
   executable) and is the most likely to admit a generator rather than
   hand-authoring. Prove a template on one dense family (e.g.
   `surface.native.op.global`, ~3,000 rows), measure the real per-row cost, then
   fan out. `log`/report any silent coverage caps.

3. **Reopen gate 1 (6 rows)** in parallel — smaller and independent.
   `capture_v2` (3 selectors) is **confirmed buildable** and fully spec'd: build
   the host via `Host::new_exact_experimental_webgpu_pre1a` (not the standard
   armed test host — only it arms the private GPU target cells Complete), inject
   the live loaded-engine identity into the snapshot, pick a real
   `runtime_registry()` operation whose edge is a private Complete cell, and
   shape a `GpuAuthorityCarrierFacts` to satisfy `carrier_matches_operation`.
   The 2 bridge routes (`deliver`/`complete`) need `webgpu-binding` +
   `gpu-bridge-test-hooks`, which the conformance profile excludes by design;
   the pointer-return `session_api_v2` row is permanent. Coordinate with the
   GPU-authority / LLP 0033 owner.

4. **Run the ceremony to completion and admit the report**, flipping the Apple
   matrix cells to advertised. Only then is ENG-24578's target promotion (and
   ENG-24669, the product) unblocked.

## Correctness owed (the deliberately-deferred verification)

Per the author's direction, this plan optimizes for a coherent, working path
now, with correctness verified over the following days/weeks. The specific
verification debts, tracked so none is silently forgotten:

- Each of the 7 reclassified scenario types must be shown to have a real
  internal Rust proof of its invariant; any without one gets a proof authored
  before advertisement is trusted.
- The `internally-verified` predicate must be proven unable to absorb a
  scenario that is in fact publicly reachable (a fail-open risk).
- The `capture_v2` fixture, once built, must drive the real route to status 1
  with registry-derived inputs only — never stubbed state (the route is
  fail-closed, so a wrong fixture returns 0 rather than a false credit, but the
  fixture should still be reviewed as a security-sensitive control-plane proof).

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
