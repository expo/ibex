# LLP 0044: Scoped Advertisement and Conformance-Evidence Cost Collapse

**Type:** RFC
**Status:** Draft
**Systems:** Security, Conformance, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** LLP 0021 (conformance program and promotion gate); LLP 0032
(execution and evidence sharding); LLP 0036 (target advertisement completion
plan — this RFC is the proposed resolution of its "Strategic question");
LLP 0037 (D1/D2/D3 rulings, accepted 2026-07-23); LLP 0029 §7 register item 4
(v1.1 single-tuple milestone); LLP 0031 (platform matrix);
issues/20260728-capsec-public-surface-evidence-backlog.md;
issues/20260717-sfe-capsec-advertisement.md; ENG-24933; ENG-24578

## Summary

The first verified CapSec target advertisement (v1.1,
`aarch64-apple-darwin`) is currently priced as a months-scale program
because LLP 0021's completeness gate is all-or-nothing: no cell advertises
until **every** required public-surface row in the catalog is fully
executable or internally verified, and LLP 0036's measured correction
established that the residual tail is genuine per-surface authoring with no
bulk template shortcut. LLP 0036 ends by naming the only moves that can
collapse the cost — shrinking the obligation denominator, or scoping the
advertisement — and defers both to the owner.

This RFC proposes taking both moves, plus the already-unblocked mechanized
authoring lane, as one coherent v1.1 design:

1. **Scoped advertisement** — an advertisement claims a declared, generated
   subset of target cells; the completeness gate binds to the scope; every
   out-of-scope cell stays `unsupported` and keeps refusing at runtime.
2. **Obligation-vocabulary audits** — extend the proven
   `malformed-branch-facts` / internally-verified precedent: audit the
   residual families that are structurally not public-surface obligations
   and retire or reclassify them with executed internal evidence, never
   label-only credit.
3. **Mechanized family authoring** — run the LLP 0036 §Plan step-2 loop,
   which the accepted LLP 0037 D1/D2/D3 rulings made "fully mechanical,"
   over whatever the scoped required set still needs.

A fourth family of ideas — crediting adapter-probe evidence or dynamic
route witnesses toward promotion — is recorded and **rejected by default**
(§6) because it weakens the source-bound evidence bar that the first three
proposals preserve.

Target outcome: a v1.1 advertisement measured in **weeks and low tens of
thousands of dollars**, instead of months and an authoring program whose
cost is proportional to thousands of distinct surface-invocation shapes.

## 1. The measured baseline (2026-07-31)

Catalog `sha256-XcvN5FFF9meYMuBBgdMjEy8mmG8QiBrhNf9Z3w_ZISg`
(`aarch64-apple-darwin`): 23,597 required / 3,928 fully executable / 3,042
internally verified / 16,627 unresolved. Dominant residual reasons:

| residual reason | rows |
| --- | ---: |
| ambiguous-static-enforcement-route | 6,755 |
| no-static-enforcement-terminal | 5,508 |
| native-public-source-invocation-unavailable | 4,261 |
| conditional-branch-selection-probe-not-authored | 2,187 |
| callback-invariant `*-probe-not-authored` (6 scenarios) | 3,042 |
| argument-selected-terminal-alternatives-not-authored | 1,691 |
| non-capability-no-decision-probe-not-authored | 1,417 |

(Reasons overlap; `public-surface-invocation-not-authored` is a
19,669-row supercategory.) LLP 0036's measured findings stand and are
assumed here, not relitigated: the scenario matrix is generated (per-row
token cost ≈ 0); the per-family pacing cost was security review, which the
LLP 0037 rulings resolved as reusable patterns; and the remaining tail is
per-surface invocation authoring at a historical 5–36 rows/commit.

## 2. Proposal 1 — Scoped advertisement

**Change.** An advertisement is generated from a complete passing report
over a **declared scope**: a generated subset of the target's coverage
cells. `assertRecipeCatalogComplete` binds to the scoped required set
(`unresolved-in-scope === 0`), not the global catalog. Every out-of-scope
cell keeps `disposition: "unsupported"`, and the runtime behavior for
unsupported cells is exactly today's: refuse/deny, fail closed. The
published claim becomes "this target enforces the declared scope; every
surface outside it is refused," which is a *true* statement the current
all-or-nothing gate cannot make at any partial state.

**Honesty constraints** (all MUST):

- **Generated, not hand-picked.** The scope is defined intensionally —
  by capability family, surface kind, and scenario class (e.g. "all
  `fs:*`, `net:*`, `process:*`, `env:*` coverage edges and their full
  scenario matrices") — and expanded by the generator from the live
  inventory. No row-level cherry-picking; a family is in scope or it is
  not.
- **Closed under enforcement dependency.** If a scoped surface's observed
  typed sequence traverses another cell (the LLP 0037 D1/D2 open-then-act
  pattern), that cell is pulled into scope. The generator computes the
  closure and the report validates it; a scope that fails closure does not
  produce an advertisement.
- **Bound into identity.** The scope definition and its expansion digest
  are part of the advertisement, the report, and the attestation, exactly
  as catalogs are bound today. Two scopes are two advertisements.
- **Stated as release constraints.** The unsupported remainder is
  enumerated by family in the release notes, per the backlog ticket's
  existing "stated as release constraints, not hidden by aggregate
  coverage counts" rule.
- **Monotone.** v1.2+ scopes must be supersets of the v1.1 scope for the
  same tuple; scope can widen, never silently narrow.

**Why this is sound.** The enforcement engine is complete and armed
startup already refuses everything unproven. Advertisement is a *claim*,
not a change in runtime authority; scoping the claim to what is proven is
strictly more honest than publishing nothing (the current state makes no
claim at all, which also communicates nothing). The all-or-nothing gate
was the right default while the machinery was unproven; it is now the only
thing standing between a complete enforcement implementation and any
verified public claim.

**Amendments required.** LLP 0021: promotion/advertisement section gains
the scope object and the scoped completeness rule. LLP 0032: no phase
changes; the report schema carries the scope. Generator/report/admission
code: scope expansion, closure check, scoped completeness assert,
scope-bearing attestation.

## 3. Proposal 2 — Obligation-vocabulary audits

Precedents, both already accepted and executed: the six callback-invariant
scenarios became **internally-verified** with exact Rust mechanisms and an
executed evidence batch (3,042 rows out of the public denominator, no
label-only credit); `malformed-branch-facts` was **retired** as an
ill-typed obligation after the input-ownership audit (661 rows).

Run the same audit over the residual families whose rows are plausibly not
public-surface obligations at all:

- **`native-public-source-invocation-unavailable` (4,261).** Each row
  asserts a public invocation obligation for a surface with no recorded
  public invocation path. The audit asks, per family: is the surface
  genuinely publicly unreachable on this target build (→ the obligation is
  ill-typed for this target: retire to a target-absence or closed-surface
  obligation, which is provable), reachable only through internal
  transitions (→ internally-verified candidate, needs an exact mechanism
  and executed evidence), or reachable but unrecorded (→ stays, feeds
  Proposal 3)?
- **`ambiguous-static-enforcement-route` (6,755) and
  `no-static-enforcement-terminal` (5,508).** These mark rows where static
  analysis cannot name the enforcement route/terminal. For rows whose
  surfaces fall out of the v1.1 scope, nothing is owed now. For in-scope
  rows, the physical batch run itself pins the observed route (LLP 0037
  D3: sequences are pinned from a run, never authored) — so the audit
  question is narrow: does an executed, pinned sequence retire the
  static-ambiguity residual reason? If yes, these resolve as a byproduct
  of Proposal 3's batch runs rather than as separate work.
- **`builtin-export-resolves-to-bootstrap-internal` (36).** Same
  input-ownership shape as `malformed-branch-facts`; likely retirable.

Rules: every reclassification names its exact mechanism and lands with
executed, digest-bound evidence (the 2026-07-24 audit standard); the
internally-verified vocabulary stays closed and grows only by this audit;
retirement means the obligation was ill-typed, never that it was
inconvenient.

## 4. Proposal 3 — Mechanized family authoring for the scoped remainder

LLP 0036 §Plan step 2, unchanged in design, now unblocked: D1/D2/D3 are
accepted, so the per-family loop is author template → run batch → pin the
observed sequence → regenerate → confirm green. What this RFC adds is
sequencing and scale discipline:

- **Scope-first.** Author only what the v1.1 scope requires after
  Proposals 1–2 land. Do not resume the global grind.
- **Fan-out.** Template authoring and executor setup-kind edits
  parallelize across agents; batch execution parallelizes across engine
  instances and machines (the fleet in `MACHINE_FLEET.md`), bounded by
  engine-lock contention, not review.
- **Strong model for templates, zero model for rows.** A wrong
  `requiredAuthority` mis-credits a security probe; template design uses
  the strongest model and human/LLP-0037-pattern review. Fan-out and
  execution consume no model tokens.
- **No silent caps.** Every batch reports what it skipped; a family that
  surfaces a *new* attribution pattern (not covered by D1–D4) stops and
  files it against LLP 0037 rather than landing a loosened assertion.

## 5. Cost model

With today's catalog and the LLP 0036 measurements:

- Proposal 1 makes the denominator the scoped required set. A core-families
  scope (fs/net/process/env capability edges + their matrices + closure) is
  on the order of a few thousand rows, most already fully executable —
  the 3,928 executable rows cluster in exactly these families.
- Proposal 2 removes or converts the structurally-non-public families
  (up to ~4,3k rows globally; what matters is the in-scope share).
- Proposal 3 is then a bounded number of capability-family templates
  (LLP 0036 measured ~6 remaining for `builtin:export`'s dense head, plus
  setup kinds) with batch wall-clock, not authoring, as the floor.

Estimated: 1–2 weeks wall-clock, engineering-dominant, low tens of
thousands of dollars in tokens/compute — versus the measured
months-at-5–36-rows/commit baseline. The estimate is falsifiable at day
one: expanding the candidate scope and diffing it against the executable
set (Proposal 1 requires only generator work to measure) yields the exact
in-scope residual count before any rules change lands.

## 6. Rejected by default: evidence-bar reductions

Two mechanisms were considered and are recorded so they are not
re-proposed casually:

- **Adapter-evidence promotion.** 11,650 fixtures are adapter-executable,
  but LLP 0021 classifies adapter-probe evidence as a distinct diagnostic
  schema, "deliberately non-promotable," rejected at publication; LLP 0032
  runs the adapter phase but its output "never counts as fixture passes."
  Crediting it would replace the authored source-bound public invocation
  bar with a weaker execution route.
- **Dynamic route witnessing as a substitute for authored invocation.**
  Pinning observed sequences from runs is already the rule (D3) *within*
  authored probes; accepting a witnessed route *without* an authored,
  bounded public invocation would credit surfaces no one has actually
  driven from public JS.

Both are strictly weaker claims than Proposals 1–3 achieve, and both
become unnecessary if the scoped denominator is right-sized. Revisit only
if, after Proposals 1–3, a material in-scope remainder exists whose
authoring cost is demonstrably prohibitive — and then through a formal
LLP 0021 amendment with its own review, never as a generator flag.

## 7. Author-decision register

Decisions this RFC surfaces for the owner; each blocks the step noted:

1. **Accept scoped advertisement** (blocks everything; this is LLP 0036's
   strategic question (b)). If rejected, v1.1 reverts to the full
   per-surface program and this RFC reduces to Proposals 2–3 as
   accelerants.
2. **The v1.1 scope definition** (blocks Proposal 1 implementation): which
   capability families/surface kinds are in the first scope. Recommended
   starting point: the filesystem, network, process/spawn, and environment
   capability edges — the enforcement families users actually rely on —
   with the measured expansion + closure presented for sign-off before the
   gate change lands.
3. **The audit list** (blocks Proposal 2): approve auditing the three
   families in §3, and rule on each family's outcome when its audit
   reports.
4. **Budget and wall-clock target** (blocks Proposal 3 fan-out scale).
5. **Review intensity for this RFC**: given it amends the promotion gate —
   the security-critical claim boundary — the recommendation is
   `Status: Review` with the formal multi-model loop before any gate code
   changes.

## 8. Non-goals

- No change to runtime enforcement, arming, or fail-closed behavior;
  out-of-scope surfaces refuse exactly as they do today.
- No credit without executed, digest-bound evidence; no label-only
  reclassification.
- No change to gate 1 (host-ABI sweep closure) or gate 3 (producer
  attestation) — both closed per LLP 0036.
- Windows/second-tuple sequencing stays as LLP 0029 register item 4 set
  it: v1.1 is single-tuple; the second tuple follows in a later milestone.
