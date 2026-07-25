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

## The unresolved catalog split into two provable categories

Grouping every unresolved row by its **scenario** (the last dotted segment of
the fixture id — what aspect it proves) and checking which scenarios are *ever*
fully-executable anywhere in the 24,585-row catalog yields a clean partition:

- **Public residual scenarios — 18,945 current Apple rows.** The original
  2026-07-23 measurement was 18,266 reachable rows. The proof audit returned
  `malformed-branch-facts` to this side of the boundary, and later catalog
  growth changed the total. Scenario types with
  hundreds of working examples already (`non-capability` 1,480 executable,
  `closed` 610, `allow`/`deny`/`malformed` ~70 each, `branch-selection`,
  `no-effect`, …). These are ordinary probe-authoring: real, laborious,
  parallelizable, template-able, but **not in doubt** — the same scenario
  already works on other surfaces. At the historical ENG-24580 tranche rate of
  5–36 rows per commit this is hundreds of commits, a staffed program measured
  in months.

- **Runtime-owned invariant scenarios — six scenario types**, each with **zero**
  fully-executable instances anywhere in the catalog:
  `attribution-missing-deny`, `generation-recheck`, `principal-restore`,
  `snapshot-mismatch-deny`, `cannot-widen-authority`, and
  `post-lockdown-invariant`. These are internal callback-security invariants —
  the runtime checking its own attribution / principal / snapshot state.
  `malformed-branch-facts` was originally included as a seventh member, but the
  proof audit found no owning-language invariant mechanism for it. It remains a
  public residual: public JS cannot inject malformed internal branch facts, and
  absence of a public route is not execution evidence.

## The design question, and its resolved direction

The originally proposed 7 never-executable scenarios attach to surfaces the current public-surface
harness has no recorded way to invoke (e.g. `native-op:global:AbortController`,
whose *every* scenario including plain `non-capability` is unresolved). The
question is whether they can be driven from public JS or whether that is a hard
limit of the public-surface model.

**Resolved direction (2026-07-23, author: "make it coherent now, verify
correctness over the coming weeks"), corrected by the proof audit on
2026-07-24:** treat the six runtime-owned scenarios as **internally-verified
invariants, not public-surface fixtures.** The rationale is grounded in the
measured facts, not a guess:

- The six (`attribution-missing-deny`, `generation-recheck`, `principal-restore`,
  `snapshot-mismatch-deny`, `cannot-widen-authority`, `post-lockdown-invariant`,
  excluding `malformed-branch-facts`) are the runtime checking *its own*
  attribution / principal / snapshot / lockdown state. By construction these
  fire on internal transitions, not on a public JS call — there is nothing for
  a public-surface probe to invoke.
- They have zero fully-executable instances anywhere in 24,585 catalog rows,
  which is what a genuinely non-public-invokable class looks like, versus an
  un-authored-but-reachable one.

So the coherent model is: **public-surface completeness attests what is publicly
reachable; these internal invariants are attested by internal Rust proofs**
(most already exist as unit tests of the enforcement paths) and are marked in
the catalog as `internally-verified` rather than counted as unresolved
public-surface fixtures. This makes the completeness gate satisfiable from the
remaining public residual rows, keeps the security claim honest (nothing is faked — an
internal invariant is proven by an internal test, not a fabricated public
probe), and defers only the *bookkeeping reclassification* to review.

**Proof audit completed (2026-07-24):** each of the six retained scenario types
now names an exact Rust mechanism and source location, and one secure-mode
evidence command executes every mechanism. The report no longer credits a
catalog disposition by itself: every retained fixture must carry its exact
plan, execution binding, proof-plan digest, runtime observation, result marker,
and artifact digest. The closed scenario vocabulary prevents the predicate from
absorbing another scenario. `malformed-branch-facts` failed the audit and remains
unresolved.

## Plan

1. **Implement the internally-verified reclassification** for the six proven
   invariant scenarios (the corrected direction above): add an
   `internally-verified` disposition, exclude
   that disposition from the `assertRecipeCatalogComplete` unresolved count, and
   point each scenario type at the internal Rust proof that already covers its
   invariant (or file a stub where one is missing). This currently removes
   3,068 Apple rows and 3,056 Windows rows from
   the completeness denominator without faking any public evidence, and makes
   the gate satisfiable from the reachable rows alone.
   **DONE and audited (2026-07-24):** `INTERNALLY_VERIFIED_SCENARIOS` is a
   closed six-member vocabulary; recipes in those scenarios carry
   `status: "internally-verified"`; `summarize` emits `internallyVerifiedFixtures`
   and drops them from `unresolvedFixtures`; `assertRecipeCatalogComplete` counts
   `fullyExecutable + internallyVerified` toward recipe completeness and skips
   public-probe checks for them. The ceremony does not credit that status:
   `capsec_internal_invariant_evidence_batch` executes the six exact Rust
   mechanisms under the explicit secure profile, and the report validates
   per-fixture evidence expanded from those scenario-class observations.
   Portable promotion re-executes that same dedicated batch under a distinct
   internal plan schema, brackets it with a same-process mapped-engine
   observation, and emits exact detached portable evidence for all internal
   rows. Internal evidence is therefore neither catalog-only nor routed through
   a public callback command.
   `malformed-branch-facts` remains unresolved. Current measured catalogs:
   Apple 3,068 internally verified / 18,945 unresolved; Windows 3,056 internally
   verified / 19,208 unresolved. The two-row increase on each target is the
   honest non-capability coverage for the internal batch's binding and output
   environment controls.

2. **Public-residual authoring program (currently 18,945 Apple rows) — it is a
   generator-and-execution problem, not per-row authoring.** Historical
   measured structure (2026-07-23): the then-current 18,266 rows collapsed to
   5,325 surfaces across just 53
   (surface-kind × scenario) template-classes. The scenario columns
   (`allow`/`deny`/`malformed`/`missing-attribution`/`wrong-principal`, ~2,330
   each) are matrix expansions of one probe per surface — they are generated,
   never authored. By surface-kind: builtin 8,828, native-op 4,400, loader
   3,008, startup 908, host-abi 561, cli 516, callback 45.

   **The densest family — `builtin:export`, 8,709 rows (48% of the work) —
   measured end to end:** it reduces to 1,551 surfaces → 31 effect-signatures →
   ~7 capability families (782 `(none)`/non-capability, ~454 network, ~200 fs,
   ~54 stdio, plus sys/env/process). The authoring unit is the *capability
   family*, not the row: `moduleAliasEffectExpectation`
   (`capsec-public-probe-templates.mjs`) today templates exactly one effect
   class (`env:read`), which is why only ~1,341 rows resolve. Each family needs
   one expectation entry (`actionIds`, `requiredAuthority` with a concrete
   resource, `allowedStages`) plus a `setup` kind; the Rust batch executor
   (`capsec_public_builtin_batch.rs`) is **generic** — it imports the module,
   invokes the export, and observes the typed decisions against the recipe, so
   it already executes any family whose `setup` it supports (`none`,
   `filesystem-file`, `filesystem-directory` today; network would need a new
   setup kind). The recipe generator then fans one template out over every
   matching surface automatically.

   **Cost implication:** per-row token cost is ≈0 (surface data is extracted
   from the live inventory; the scenario matrix is generated). The real cost is
   ~6 remaining capability-family templates for `builtin:export` (env is proven)
   plus their bounded batch-execution support, and the wall-clock floor is the
   engine-locked physical-proof batch run, not authoring. Cheaper models buy
   little: the volume is a handful of high-stakes templates, and a wrong
   `requiredAuthority` mis-credits a security probe, so template design wants the
   strongest model, while fan-out and execution consume no model tokens. Order
   of attack: prove one clean capability family end to end (`fs:read`, 31
   surfaces), measure real fanout + execution wall-clock, then fs:write/list,
   network (new setup kind), and route the 782 `(none)` surfaces through the
   existing non-capability template. `log`/report any silent coverage caps.

   **`fs:read` prototype — measured end to end (2026-07-23), then reverted.** A
   `readFileSync` template was authored (mirroring the `fs:list` `statSync`
   pattern with the `fs:read` capability and `filesystem-file` setup) and driven
   through the real builtin batch on the bound engine. Findings, in order:
   - **Authoring fanout confirmed:** one export table entry produced all 5
     scenario rows (`allow`/`deny`/`malformed`/`missing-attribution`/
     `wrong-principal`) — exec count 2,592 → 2,597, unresolved 18,266 → 18,261.
     The scenario matrix is free, as predicted.
   - **Execution is per-family, not per-row, but not a pure mirror.** The batch
     executor's JS invocation is generic (`Reflect.apply`), but the
     `filesystem-file` setup handler carries a per-export allow-list and a
     hard-coded `fs:list` cap, so each new fs family needs a small executor
     edit.
   - **The typed sequence must be observed, never guessed.** `readFileSync`
     yields a **9-decision** open-then-read chain
     (`requested,requested,discovery,requested,repeat,commit,repeat,repeat,repeat`),
     not the 4–5 of a stat. Only a batch run reveals it.
   - **Traversal-allowance authoring gate (LLP 0037 D2, code-verified review
     2026-07-24).** When a family's observed set is a superset of its declared
     capability, the extra is tolerated only as a *traversal* effect. Before
     pinning the family, confirm from its observed sequence that every surplus
     `fs:list` occurs at an open/traversal stage — not as a real directory
     listing the operation performs. A family that genuinely lists must declare
     that `fs:list`, not inherit the traversal allowance. This is a required
     step of the per-family loop, not an assumption carried by the pattern.
   - **Two genuine security-model questions surfaced — the real per-family
     cost.** (1) *Stratum:* the open's path-traversal `fs:list` decisions
     resolve through the root principal's **ambient-mount** authority while the
     `fs:read` commit stays on the **static floor** — the batch's
     stat-era assertion assumed static-floor for all non-discovery decisions.
     (2) *Action attribution:* the runtime observes **both** `fs:list`
     (traversal) and `fs:read`, but the coverage edge declares only `fs:read`,
     so the batch's `observed_actions == expected_action_ids` invariant fails.
     Neither is a mechanical fix: (1) asks whether ambient traversal crediting
     is the intended model, (2) asks whether `readFileSync` should declare
     `fs:list`+`fs:read` in coverage or whether traversal is incidental. Both
     are coverage-model / security decisions for the model owner, so the
     prototype was reverted rather than land loosened security assertions.

   **Revised cost model:** authoring a family ≈ free (one entry, matrix
   generated); execution support ≈ a small executor edit per family; **but each
   capability family can surface one or two coverage-model/security questions
   that need review, not code.** That review — not tokens, not parallelism — is
   the true pacing cost, and it is why cheaper models and fan-out do not
   compress the schedule: the bottleneck is per-family security judgment.

   **The recurring questions are patterns, not per-family — resolve them once
   up front.** The two `fs:read` questions (ambient-mount traversal stratum;
   declared-vs-incidental action attribution) are not unique to fs:read: every
   open-then-act family (`fs:write`, `fs:list` streams, `network` connect/
   listen) hits the same two patterns. They are lifted into **LLP 0037**
   (public-surface authorization attribution patterns) as decisions D1/D2/D3 for
   a single ruling. Once ruled, the per-family loop is fully mechanical —
   author template → run batch → pin the observed sequence (D3) → regenerate →
   confirm green — with the batch executor gaining exactly two narrow,
   documented generalizations (D1 traversal stratum, D2 superset-with-traversal
   allowance). The remaining families and surface-kinds then become a fan-out
   parallelizable across agents and engine instances, bounded by engine-lock
   contention rather than review. Resolving LLP 0037 is the prerequisite for
   this step.

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

## Measured correction: there is no cheap bulk win left (2026-07-23)

An earlier read of this plan treated the `(none)` non-capability surfaces
(~3,700) as a cheap high-volume sweep on one template. **Measuring it corrected
that.** The `(none)` bucket has a cheap head — readable exports (constants, data
properties, module values, no arguments) — and that head is **already
harvested**: 2,163 `(none)` rows are already fully-executable. What remains
unresolved is the tail:

- **~1,718 authorable-but-not-cheap.** Of the 526 authorable builtin `(none)`
  surfaces, **313 are callable functions** needing a per-function invocation
  template (safe arguments + setup + observed no-decision completion), 118 are
  `unknown` shape, and only ~92 are simple readable accessor/data — and even
  those are unresolved for surface-specific reasons, not a missing bulk template.
  The callable tail (crypto functions, `Cipher` methods, etc.) is the same
  per-surface authoring shape as the fs export tail, not a fan-out.
- **~1,654 structurally hard** (`native-public-source-invocation-unavailable`):
  no public invocation path, same class as the module-runner CJS residuals.
- **~606 closed-surface denials** needing a denial probe each.

**Conclusion.** Every remaining gate-2 bucket has the same structure — a cheap
head that is largely already harvested, and a tail that is genuine per-surface /
per-function authoring. There is no template that unlocks thousands of rows at
once. The realistic cost of gate 2 is therefore proportional to the number of
distinct surface-invocation shapes (thousands), throttled by the engine-locked
batch and, for capability families, by the LLP 0037-class security review. This
does not change the plan's steps; it removes the hope of a shortcut and makes the
strategic question below load-bearing.

### Strategic question this forces

Because there is no bulk shortcut, the highest-leverage move may not be authoring
at all but **reducing the bar**: (a) extend the internally-verified
classification (LLP 0036 step 1) to any *reachable* scenario-class that is in
truth attested internally, shrinking the executable denominator; or (b) decide
with the owner whether advertisement can be scoped to a coherent *subset* of
target cells rather than the current all-or-nothing completeness gate, so real
advertised cells land before the full per-surface program completes. Both are
design decisions for the owner; either could collapse the program's cost by more
than any authoring throughput. This should be settled before committing to the
full per-surface grind.

## Correctness owed (the deliberately-deferred verification)

Per the author's direction, this plan optimizes for a coherent, working path
now, with correctness verified over the following days/weeks. The specific
verification debts, tracked so none is silently forgotten:

- **Closed 2026-07-24:** six reclassified scenario types have exact secure Rust
  proofs and executed, digest-bound evidence. The seventh proposed type,
  `malformed-branch-facts`, had no such proof and was removed from the
  classification.
- **Closed 2026-07-24:** the `internally-verified` predicate is a closed
  six-member scenario vocabulary, every recipe carries the independently
  derived proof plan, and report credit requires executed evidence rather than
  the status label.
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
