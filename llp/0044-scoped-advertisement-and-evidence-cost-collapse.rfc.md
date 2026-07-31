# LLP 0044: Scoped Advertisement and Conformance-Evidence Cost Collapse

**Type:** RFC
**Status:** Draft
**Systems:** Security, Conformance, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-31
**Revised:** 2026-07-31d (§5 day-one measurement addendum, §9 — this
revision is UNREVIEWED beyond the dual-READY revision `e41717a8b82b`; it
adds measured data and changes no design content. Headline: the cost
hypothesis is falsified as originally stated — only 378 of the seed
scope's 9,806 fixtures are already executable, and 39% of seed-pure cells
are poisoned by Lane B/C rows, 64% of network cells — but a surviving
fs+env+process scope is 89% certifiable at 3,256 authorable rows across
424 surfaces in 64 template classes; representative batch runs in 16.24 s
on the bound engine, so authoring iteration, not execution, is the cost
floor. Evidence: llp/evidence/0044-scope-measurement-09e6aece….json and
0044-batch-timing-501504f6….json)
**Revised:** 2026-07-31c (round-3 revision — Fable r3 READY with four
MINORs, Codex r3 NOT READY with two IN-DELTA MATERIALs, all addressed:
every broad "fail-closed" characterization of the remainder is deleted
(Summary and "Why this is sound"), replaced with the layer-precise rule
that "fail-closed" always names startup admission, typed-gate refusal, or
physical entrypoint refusal — and the zero-decision remainder has none;
the scope-digest lifecycle no longer asserts an armed-snapshot join —
the armed-snapshot producer, `ibex/capsec-armed/1` parser, and
`ExpectedArmingIdentity` are named in the consumer table as carrying no
scope identity today, the runtime join is explicitly undesigned, the join
matrix becomes part of this RFC's review package (an appendix to the
LLP 0021 amendment), and register item 5 is BLOCKED on it; the historical
one-row delta is recorded as identifiable only by regenerating the
acceptance-era catalog, otherwise permanently unknown; the v1/v2
advertisement-chain split is structural in the consumer table
(`generate-capsec-registry.mjs` is on the closed v1 chain); the
physically-refused option's compositional caveat is stated (it removes
remainder interference; in-scope compositions stay per-invocation);
§5 cross-references §1's retention requirement; the expansion-diff and
rename mappings get their own schemas and digest domains)
**Revised:** 2026-07-31b (round-2 revision — Fable r2 READY with five
MINORs, Codex r2 NOT READY with four IN-DELTA MATERIALs, all addressed:
the false "no path becomes more permissive" invariant is replaced with the
exact statement — typed-gate refusal semantics unchanged, runtime
availability deliberately expands to uncertified paths, and that expansion
is what register item 2 decides; the certified claim is pinned to
**per-invocation conformance under source-derived preconditions** with
compositional enforcement explicitly uncertified (threat model, §2); the
consumer table is corrected — the Go attestation verifier is
provenance-only and scope-transparent — and extended with the promotion
authority, evidence-contract validator, bundle and promotion-lineage
verifiers, `build.rs` report selector, target-cell bytes, fixture catalog,
and registry generator, with a scope-digest lifecycle statement and a
required join-matrix deliverable; monotone lineage gains a rollback-
resistant protocol (predecessor hash chain anchored in the checked-in
promotion lineage, genesis rule, closed selector grammar, authenticated
retirement/rename mappings); Lane A names all three authored suppressors;
register item 2 carries the measurement precondition; §1's one-row delta
is restated as un-diffed pending the measurement's retained artifacts;
"the enforcement engine is complete" is bounded; runtime introspection and
adversarial fixtures added to the amendment list)
**Revised:** 2026-07-31 (round-1 dual-review revision: the published claim for
out-of-scope surfaces is downgraded from "refused" to "uncertified" — the
refusal claim was an unverified universal negative, and `Incomplete` cells
only refuse at reached typed gates, so zero-decision surfaces can execute;
the scope unit is now the complete, indivisible target cell and scenario
class is never a selection axis; the consumer analysis (armed cell-map
construction, promotion-bundle cell invariant, portable admission, the
LLP 0035 verifier chain) is in the document and a distinct scoped arm state
is acknowledged as a required amendment; the dependency closure is
conservative and pre-execution, validated against every physical
observation; scope identity gets a canonical artifact, digest domain,
single-active-scope rule, and an authenticated-predecessor monotonicity
protocol; the §3 audits are split into four lanes and no-terminal rows
explicitly keep the current evidence bar; the §5 cost model is restated as
an unmeasured hypothesis whose day-one measurement is a precondition to the
register's scope decisions; the register grows from five to ten items;
review artifacts: llp/reviews/0044-*.{fable,codex}.md round 1)
**Related:** LLP 0021 (conformance program and promotion gate); LLP 0032
(execution and evidence sharding); LLP 0036 (target advertisement completion
plan — this RFC is the proposed resolution of its "Strategic question");
LLP 0037 (D1–D4 rulings); LLP 0029 §7 register item 4 (v1.1 single-tuple
milestone); LLP 0031 (platform matrix); LLP 0035 (portable provenance and
the verifier chain); LLP 0040 (precedent: surfaces can retire from the
inventory);
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

1. **Scoped certification** — an advertisement certifies a declared,
   generated, dependency-closed set of complete target cells; every
   surface outside the scope carries **no conformance claim** (uncertified,
   listed as a release constraint). Typed-gate refusal semantics are
   unchanged; runtime availability deliberately expands (§2).
2. **Obligation-vocabulary audits** — extend the proven
   `malformed-branch-facts` / internally-verified precedent through four
   explicitly separated audit lanes, each preserving the executed-evidence
   standard; no-terminal rows keep the current evidence bar.
3. **Mechanized family authoring** — run the LLP 0036 §Plan step-2 loop,
   which the accepted LLP 0037 rulings made "fully mechanical," over
   whatever the certified scope still requires.

A fourth family of ideas — crediting adapter-probe evidence or dynamic
route witnesses toward promotion — is recorded and **rejected by default**
(§6).

Target outcome: a v1.1 certification whose cost is set by a measured scope
rather than by the full catalog. The cost estimate itself is an unmeasured
hypothesis until the §5 day-one measurement runs; that measurement gates
the register's scope decisions.

## 1. The measured baseline and its provenance

Catalog `sha256-XcvN5FFF9meYMuBBgdMjEy8mmG8QiBrhNf9Z3w_ZISg`
(`aarch64-apple-darwin`), generated 2026-07-31 on `main` at `619ce9e8`'s
parent tree via
`bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs
--target aarch64-apple-darwin --output <path>`: 23,597 required / 3,928
fully executable / 3,042 internally verified / 16,627 unresolved / 11,650
adapter-executable (`adapterExecutableFixtures` in the generator summary —
diagnostic tier only, see §6). This is one required row below the backlog
ticket's rev-2 acceptance snapshot (`sha256-GHlq…`, 23,598). The specific
row has **not been diffed**, and retained *future* artifacts cannot name
it: the acceptance-era catalog is not in the repo, so the historical
delta is identifiable only by regenerating the `sha256-GHlq…` catalog
from its exact bound source state — otherwise it is recorded here as
**permanently unknown**, which does not affect any claim in this
document. Separately, the §5 day-one measurement MUST retain its
generated catalog summary (and this one's) in its evidence index so that
every figure in this section, and every future delta, is re-derivable
from retained artifacts rather than from prose.

Dominant unresolved residual reasons (reasons overlap;
`public-surface-invocation-not-authored` is a 19,669-row supercategory that
also spans reasons retained on resolved rows):

| residual reason | rows | status |
| --- | ---: | --- |
| ambiguous-static-enforcement-route | 6,755 | unresolved |
| no-static-enforcement-terminal | 5,508 | unresolved |
| native-public-source-invocation-unavailable | 4,261 | unresolved |
| conditional-branch-selection-probe-not-authored | 2,187 | unresolved |
| argument-selected-terminal-alternatives-not-authored | 1,691 | unresolved |
| non-capability-no-decision-probe-not-authored | 1,417 | unresolved |
| callback-invariant `*-probe-not-authored` (6 scenarios) | 3,042 | **already resolved** — internally-verified per LLP 0036 step 1; reasons are retained on resolved rows by the generator |

LLP 0036's measured findings stand and are assumed here, not relitigated:
the scenario matrix is generated (per-row token cost ≈ 0); the per-family
pacing cost was security review, which the LLP 0037 rulings resolved as
reusable patterns; the remaining tail is per-surface invocation authoring
at a historical 5–36 rows/commit; and the already-executable mass sits
largely in the `(none)`/non-capability and `closed` buckets, **not** in the
capability families a v1.1 scope would center on.

## 2. Proposal 1 — Scoped certification

**Change.** An advertisement is generated from a complete passing report
over a **declared scope**: a generated, dependency-closed set of the
target's coverage cells. `assertRecipeCatalogComplete` binds to the scoped
required set (`unresolved-in-scope === 0`), not the global catalog.

**The published claim** (exact wording is normative): *"this target's
enforcement is certified for the declared scope; every surface outside the
scope carries no conformance claim."* The claim MUST NOT assert that
out-of-scope surfaces are refused, absent, or safe.

**Threat model of the claim (normative).** The certification is
**per-invocation**: each in-scope cell's enforcement is certified under
the source-derived preconditions its recipes establish. It is **not
compositional**: because uncertified surfaces remain callable (below), a
composition in which an uncertified surface manipulates state, authority,
handles, configuration, or lifecycle that a later in-scope invocation
depends on is itself uncertified. The scoped ceremony includes
adversarial-composition fixtures as *diagnostic* evidence, but the claim
never extends to compositions. An owner who needs compositional assurance
in the presence of the remainder needs register item 2's
physically-refused posture instead — which removes the
remainder-interference channel; compositions of in-scope invocations
remain per-invocation-certified under either option. The typed-gate
refusal layer (unproven capability routes refuse at typed gates;
`Incomplete` cells refuse when a typed effect gate is reached) is a design
property, not a certified fact — and it is *known* not to cover
zero-decision surfaces: an `Incomplete` cell refuses only when a typed
gate is actually reached (`crates/capsec-semantics/src/decision.rs`
`Incomplete` handling), so a surface with no typed terminal can execute.
Certifying refusal of the remainder would be an unverified universal
negative; this RFC does not make that claim, and register item 2 puts the
stronger physically-refused posture to the owner as a separate, costed
option.

**Scope unit (MUST).** The unit of scope membership is the **complete
target cell**: a cell is in scope with its full generated scenario matrix
and every source-derived implementation branch, indivisibly. Scenario
class is a *descriptive* dimension only — it is never a selection axis,
and no scenario obligation of an in-scope cell can be subtracted. (A cell
whose only obligations are target-absence rows participates through those
rows exactly as today.) This closes partial-cell credit under any name.

**Honesty constraints** (all MUST):

- **Generated, not hand-picked.** The scope is defined intensionally — by
  capability family and surface kind — and expanded by the generator from
  the live inventory. No row-level or cell-level cherry-picking; a family
  is in scope or it is not.
- **Conservative pre-execution closure.** The dependency closure is
  computed from **source-derived routes and argument-selected branch
  alternatives** before any execution — not from observed sequences, which
  do not exist yet for unresolved recipes and cannot see unexercised
  branches. Every physical observation is then validated against the
  closure: an observed traversal into a cell the closure excluded fails
  the run (it proves the closure wrong). A dependency that cannot be
  conservatively resolved keeps its dependent cell out of scope or fails
  promotion — never a warning.
- **Canonical scope identity.** The scope is a canonical artifact
  (intensional definition + expanded cell set + closure edges) with its
  own digest domain. Exactly **one active scope per tuple**; admission
  rejects a second concurrent scope for the same target/features rather
  than selecting among scopes. The scope digest is bound through every
  promotion-facing artifact: recipe catalog, public execution evidence,
  report, attestation, portable promotion bundle, admission result, and
  the runtime's authenticated cell map. Report admission **re-derives**
  the expansion and closure from the intensional definition against the
  bound inventory; it never trusts the report's row list.
- **Monotone lineage (rollback-resistant).** The scope artifact embeds
  the digest of its predecessor scope, forming a hash chain, and admission
  does not take the artifact's word for which predecessor is current: it
  resolves the tuple's **currently admitted** scope from the checked-in
  promotion lineage (the same repo-anchored `target-attestations` /
  promotion-lineage chain LLP 0035 admission already validates) and
  requires the new artifact's predecessor digest to equal it. A genesis
  scope is explicitly marked as such and is admissible only when the
  lineage records no prior scope for the tuple. Pointing at an older,
  smaller predecessor therefore fails admission — the lineage names the
  latest, not the artifact. The intensional definition uses a **closed
  selector grammar** (enumerated capability-family and surface-kind
  identifiers, set semantics only — no free-form predicates), so the
  superset check is set inclusion, not interpretation. Surfaces retired
  from the inventory itself (the LLP 0040 precedent) are recorded in the
  generated expansion diff as retirements, each validated against the
  inventory: a "retired" cell that is still present in the live inventory
  is narrowing, and fails. Renames/splits/merges of stable cells ride an
  authenticated mapping generated from inventory history, validated the
  same way. The expansion-diff artifact and the rename/split/merge
  mapping each carry their own schema and digest domain, bound into the
  scope artifact. Any other narrowing fails promotion.
- **Stated as release constraints.** The uncertified remainder is
  enumerated by family in the release notes, **generated from the same
  validated expansion diff the gate checks**, per the backlog ticket's
  "stated as release constraints, not hidden by aggregate coverage
  counts" rule.
- **Negative controls (evidence, not proof).** The scoped ceremony
  executes at least one out-of-scope negative-control probe per major
  uncertified family on the exact advertised build, demonstrating the
  fail-closed behavior where it exists (typed-gate refusal) and recording
  absence where the surface is absent. These are diagnostic supporting
  evidence for the design property; they do not upgrade the claim.

**Consumer analysis.** The all-or-nothing assumption is baked into more
than the completeness assert; each consumer below must be amended or
explicitly shown scope-transparent before any gate code lands:

| consumer | current behavior | scoped-certification consequence |
| --- | --- | --- |
| `assertRecipeCatalogComplete` (`capsec-conformance-recipes.mjs`) | global `unresolved === 0` | binds to the scoped required set |
| portable promotion bundle (`capsec-portable-promotion-bundle.mjs`, cell check) | rejects promotion if **any** target cell is `unsupported`/malformed | must accept out-of-scope `unsupported` cells listed in the bound scope artifact, and only those |
| armed host construction (`Host::new_armed_with_target_cells`, `src/host/mod.rs`) | requires every generated edge `Complete`/`Closed`; rejects partial maps | needs a **distinct scoped arm state**: an exhaustive cell map in which out-of-scope cells carry an explicit uncertified disposition, constructed only from an admitted scoped report; arming with a cell absent from the map remains a refusal |
| typed decision path (`crates/capsec-semantics/src/decision.rs`) | `Incomplete` refuses at reached typed gates only | unchanged — this is exactly why the claim is "uncertified," not "refused" |
| portable report admission (`src/host/portable_target_admission.rs`) | requires the exact complete coverage inventory and full fixture union | must validate the scoped required set against the re-derived expansion instead |
| portable advertisement schema (`ibex/capsec-target-advertisements/2`) and its reader `capsec-portable-engine-evidence-contract.mjs` | "advertised" semantically means whole-tuple conformant | schema revision (v3) carrying the scope digest and the distinct product term "scoped certification"; readers validate or transparently carry the scope |
| checked-in **v1** advertisement chain (`generate-capsec-registry.mjs` reads/emits the closed v1 schema; the promotion-lineage verifier pins that chain to v1) | a second, separate advertisement generation | its own row group in the join matrix: amended or shown scope-transparent explicitly — the v1/v2 split is structural, not a footnote |
| armed-snapshot producer, `ibex/capsec-armed/1` parser, `ExpectedArmingIdentity` | carry no scope identity today; Host obtains authenticated target cells separately through advertisement/report admission | the runtime scope join is **undesigned** — register item 5 blocker; see the lifecycle paragraph below |
| promotion authority, bundle verifier, promotion-lineage verifier, `build.rs` report selector, target-cell bytes, fixture catalog | assume whole-tuple completeness wherever they join report ↔ cells ↔ advertisement | each appears in the required **scope-binding join matrix** (below) as scope-validating or scope-transparent |
| Go attestation verifier (LLP 0035) | authenticates portable-engine **provenance** only; LLP 0035 keeps build consumption, Host target cells, and advertisement loading as separate gates | **scope-transparent** — no change unless its signed subject contract changes; the earlier claim that it "must surface the scope" was wrong and is withdrawn |

**Scope-digest lifecycle (normative).** The scope digest is *created* by
the generator from the intensional definition; *independently re-derived*
at report admission (expansion + closure recomputed against the bound
inventory); *bound* into the recipe catalog, public execution evidence,
report, attestation, promotion bundle, and admission result; *compared*
against the lineage-resolved predecessor; and *delivered* into runtime
state via the admitted report's cell map. **The runtime join beyond the
cell map is deliberately not designed here**: the armed-snapshot producer,
the `ibex/capsec-armed/1` parser, and `ExpectedArmingIdentity` carry no
scope identity today, and whether the snapshot carries `scopeDigest`
itself or joins an independently authenticated scope identity beside it —
including how snapshot/report scope substitution is prevented, and which
authority supplies the digest to runtime introspection — is the central
question of register item 5's design review. A complete artifact/consumer
**join matrix** — every artifact that creates, re-derives, binds,
compares, or carries `scopeDigest`, with each remaining consumer marked
scope-validating or scope-transparent, including the armed-snapshot
structures above and both advertisement chains — is part of **this RFC's
review package**: it MUST be authored as an appendix to the LLP 0021
amendment and reviewed with it, before register item 5 is put to the
owner and before any gate code lands; the table above is the seed, not
the proof.

The scoped arm state is therefore an **arming amendment**, not a claim
change alone; the earlier draft's "no arming change" framing was wrong and
is withdrawn. The exact invariant is: **typed-gate refusal semantics are
unchanged, and runtime availability deliberately expands** — today no
production target arms at all, and under a scoped certification the
uncertified remainder (including zero-decision surfaces) becomes callable.
That availability expansion is the substance of register item 2, not a
side effect; register item 5 gates the arm state's design review. The arm
state SHOULD be a distinct `ScopedAdvertised` variant with out-of-scope
cells mapped to a disposition distinguishable from "incomplete by defect"
in refusal telemetry, and the active scope digest plus the uncertified
remainder MUST be exposed through machine-readable runtime introspection,
not only release notes.

**Why this is sound.** The enforcement implementation is complete for
every surface with a source-proven enforcement route (the CapSec rev2
tranche); 5,508 rows still lack a source-proven terminal, which is
exactly why the remainder is uncertified rather than claimed refused. The
current state publishes no claim at all. Certifying exactly the proven scope —
with the remainder explicitly uncertified and enumerated — is strictly
more honest than silence and makes no statement that lacks executed,
digest-bound evidence. No fail-closed characterization is made of the
remainder as a whole; where this document says "fail-closed" it names the
exact layer it means (startup admission, typed-gate refusal, or physical
entrypoint refusal), and the zero-decision remainder has none of the
three.

**Amendments required.** LLP 0021: promotion/advertisement section — scope
object, scoped completeness rule, scoped arm-state admission,
single-active-scope rule, monotone lineage, and the join matrix. LLP 0032:
report schema carries the scope; no phase changes. LLP 0036: step-2
program re-scoped; internally-verified vocabulary growth rule (§3). Code:
every consumer row in the table above, the scope artifact generator,
closure computation, expansion-diff artifact, runtime scope introspection,
and adversarial fixtures covering scoped-state substitution, omitted map
entries, typed out-of-scope refusal, executable zero-decision remainder,
duplicate scopes, stale/rolled-back predecessors, and renamed/retired
cells.

## 3. Proposal 2 — Obligation-vocabulary audits (four lanes)

Precedents, both already accepted and executed: the six callback-invariant
scenarios became **internally-verified** with exact Rust mechanisms and an
executed evidence batch; `malformed-branch-facts` was **retired** as an
ill-typed obligation after the input-ownership audit.

The audits are four separated lanes with different evidence rules; the
earlier draft's suggestion that batch runs "retire the static-ambiguity
residual as a byproduct" conflated two of them and is withdrawn:

- **Lane A — route ambiguity (`ambiguous-static-enforcement-route`,
  6,755).** Clearable only by an **authored, bounded, source-bound public
  invocation** whose source-derived closed terminal allow-list contains
  the observed selection, matching the generator's three authored
  suppressors for this reason (effect probe, source-bound closure probe,
  callback-invariant probe — all authored and source-bound). This
  is ordinary Proposal-3 authoring for in-scope rows; out-of-scope rows
  are simply not owed under scoped certification.
- **Lane B — missing terminals (`no-static-enforcement-terminal`,
  5,508).** These rows **stay unresolved** until source provenance
  supplies a terminal. A pinned observed sequence does not manufacture a
  terminal, and no dynamic-witnessing path exists (§6). If a future case
  is ever made, it is a separately reviewed LLP 0021 evidence-bar
  amendment, not an outcome of this audit.
- **Lane C — claimed unreachability
  (`native-public-source-invocation-unavailable`, 4,261).** "No recorded
  public invocation path" is not proof of unreachability — the missing
  inventory data could itself be the defect. Retirement (to a
  target-absence or closed-surface obligation, which are provable) requires
  a **closed-world source join** plus loaded-target absence /
  immutable-closure evidence mapped exactly to every credited row.
  Reachable-but-unrecorded rows stay, and feed Proposal 3.
- **Lane D — bootstrap-internal resolution
  (`builtin-export-resolves-to-bootstrap-internal`, 36).** Same shape as
  `malformed-branch-facts`, but retirement still requires the exact
  import-resolution/closure proof, not the analogy.

Cross-cutting rules: every reclassification names its exact mechanism and
lands with executed, digest-bound evidence (the 2026-07-24 standard); a
batch observing zero typed decisions where the coverage edge declares a
capability **fails loudly** rather than pinning an empty route; retirement
means the obligation was ill-typed, never that it was inconvenient. The
`INTERNALLY_VERIFIED_SCENARIOS` vocabulary is **closed** today precisely so
the predicate cannot absorb scenarios; any growth by these audits is
itself an LLP 0021/0036 amendment (added to §2's list), and Lane C
outcomes that want internal verification need new *surface-keyed*
machinery — the current mechanism is scenario-keyed — whose design goes
through the same review as the arm state.

## 4. Proposal 3 — Mechanized family authoring for the scoped remainder

LLP 0036 §Plan step 2, unchanged in design, now unblocked: D1–D4 are
accepted, so the per-family loop is author template → run batch → pin the
observed sequence → regenerate → confirm green. What this RFC adds is
sequencing and scale discipline:

- **Scope-first.** Author only what the certified scope requires after
  Proposals 1–2 land. Do not resume the global grind.
- **Fan-out.** Template authoring and executor setup-kind edits
  parallelize across agents; batch execution parallelizes across engine
  instances and machines (the fleet in `MACHINE_FLEET.md`), bounded by
  engine-lock contention, not review.
- **Strong model for templates, zero model for rows.** A wrong
  `requiredAuthority` mis-credits a security probe; template design uses
  the strongest model and review against the LLP 0037 patterns. Fan-out
  and execution consume no model tokens.
- **No silent caps; no new-pattern improvisation.** Every batch reports
  what it skipped. A family that surfaces an attribution pattern not
  covered by D1–D4 stops and files it against LLP 0037 rather than
  landing a loosened assertion.

## 5. Cost model — an explicit hypothesis, and the measurement that gates it

**Hypothesis (unmeasured):** a core-families scope
(fs/net/process/env capability edges + closure) yields an in-scope
residual small enough that Proposals 1–3 deliver v1.1 in weeks at low
tens of thousands of dollars. This is *not* supported by the current
executable distribution — LLP 0036 measured the already-executable mass in
the `(none)`/non-capability and `closed` buckets, the `fs:read` family
prototype was reverted pending the (now-accepted) LLP 0037 rulings, and
network execution still needs a new setup kind. The hypothesis may be
wrong.

**The measurement (MUST precede register items 2 and 4).** Generate the
candidate scope artifact and publish, in this document's next revision:
in-scope cells and fixtures; the executable/internally-verified/unresolved
split; unresolved-by-residual-reason; the count of **distinct invocation
shapes** (the true authoring unit); closure additions beyond the seed
families; worst-case Lane A–D audit outcomes for in-scope rows; and a
representative batch execution duration on the bound engine; and the
retained catalog summaries §1 requires (this measurement's and §1's own)
in the measurement's evidence index. The owner
decides the scope on those numbers, not on this section's estimate. The
measurement is generator + closure work only — no gate code, no rules
change — so running it commits to nothing.

If the measured in-scope residual is not materially cheaper than the
LLP 0036 baseline, the honest conclusion is that scoped certification
changes *what can be claimed early*, not *what the claim costs*, and the
register decisions should be taken with that framing.

## 6. Rejected by default: evidence-bar reductions

Two mechanisms were considered and are recorded so they are not
re-proposed casually:

- **Adapter-evidence promotion.** 11,650 fixtures are adapter-executable
  (`adapterExecutableFixtures`, §1 provenance), but LLP 0021 classifies
  adapter-probe evidence as a distinct diagnostic schema, "deliberately
  non-promotable," rejected at publication; LLP 0032 runs the adapter
  phase but its output "never counts as fixture passes." Crediting it
  would replace the authored source-bound public invocation bar with a
  weaker execution route.
- **Dynamic route witnessing as a substitute for authored invocation or
  missing terminals.** Pinning observed sequences from runs is already
  the rule (D3) *within* authored probes; accepting a witnessed route
  *without* an authored, bounded public invocation — or treating an
  observation as supplying a terminal that source provenance lacks
  (§3 Lane B) — would credit surfaces no one has actually driven from
  public JS under a source-derived contract.

Both are strictly weaker claims than Proposals 1–3 achieve. Revisit only
through a formal LLP 0021 amendment with its own review, never as a
generator flag.

## 7. Author-decision register

Decisions this RFC surfaces for the owner; each blocks the step noted:

1. **Accept scoped certification at all** (blocks everything; this is
   LLP 0036's strategic question (b)). If rejected, v1.1 reverts to the
   full per-surface program and this RFC reduces to Proposals 2–3 as
   accelerants.
2. **Out-of-scope semantics** (blocks the claim wording and the arm-state
   design; REQUIRES the §5 measurement first): **uncertified**
   (recommended; this RFC's design — accepting that runtime availability
   expands to the uncertified remainder, per-invocation threat model) vs
   **physically refused** (requires an exhaustive out-of-scope refusal
   mechanism covering zero-decision and no-terminal surfaces — a
   materially larger runtime program whose cost would need its own
   estimate).
3. **Scope unit** (blocks Proposal 1): confirm complete-cell
   indivisibility with scenario class as a descriptive dimension only.
4. **The v1.1 scope definition** (blocks Proposal 1 implementation;
   REQUIRES the §5 measurement first): which capability families/surface
   kinds are in the first scope, decided on the measured expansion.
5. **The scoped arm state** (blocks arming amendments; BLOCKED until the
   complete armed-snapshot/report/cell-map scope-binding join matrix —
   §2's lifecycle paragraph — is authored and reviewed): approve the
   distinct arm-state direction in §2's consumer table, with its design
   going through security review alongside this RFC's gate changes.
6. **Monotone lineage enforcement** (blocks the scope artifact schema):
   confirm intensional-superset + authenticated predecessor +
   expansion-diff artifact, with inventory retirements permitted and all
   other narrowing fatal.
7. **Cross-tuple congruence** (blocks the second tuple's scoping): must
   the Windows tuple's scope be the same logical (intensional) scope as
   Apple's, or may tuples diverge? (Recommended: same intensional
   definition, per-tuple expansions.)
8. **The audit list** (blocks Proposal 2): approve Lanes A–D as scoped in
   §3, and rule on each lane's outcome when its audit reports.
9. **Budget and wall-clock target** (blocks Proposal 3 fan-out scale).
10. **Review intensity for this RFC**: given it amends the promotion gate
    and arming — the security claim boundary — the recommendation is
    `Status: Review` with the formal multi-model loop before any gate code
    changes.

## 8. Non-goals

- No change to typed-gate refusal semantics: every typed decision path
  behaves exactly as today. (Runtime *availability* does expand — a
  scoped-certified target arms where today nothing arms, making the
  uncertified remainder callable; that expansion is deliberate, stated in
  §2, and decided by register item 2. It is not claimed here as
  non-permissive.)
- No certified claim without executed, digest-bound evidence; the
  uncertified remainder is never described as refused, absent, or safe.
- No credit without executed evidence; no label-only reclassification; no
  dynamic-witnessing or adapter-promotion back door (§6); Lane B rows keep
  the current evidence bar.
- No change to gate 1 (host-ABI sweep closure) or gate 3 (producer
  attestation) — both closed per LLP 0036.
- Windows/second-tuple sequencing stays as LLP 0029 register item 4 set
  it: v1.1 is single-tuple; the second tuple follows in a later milestone
  (its scope congruence is register item 7).

## 9. Day-one measurement results (2026-07-31 addendum — unreviewed)

The §5 measurement ran on 2026-07-31 against the §1 catalog
(`sha256-XcvN5FFF…`, retained with the analysis in
`llp/evidence/0044-scope-measurement-09e6aeceb938aa0a945f5f94c2901dfcc84c66ed509d986f32d05f284dfaea18.json`;
batch timing in `llp/evidence/0044-batch-timing-501504f66a809003ed6b187bfbeda4d22d405b5438941cf7d4ad902b73ac4abf.json`).
Cells are `edgeIds`; a cell is *poisoned* when any of its unresolved rows
carries a Lane B (`no-static-enforcement-terminal`), Lane C
(`native-public-source-invocation-unavailable`), or Lane D
(`builtin-export-resolves-to-bootstrap-internal`) residual reason —
rows authoring cannot clear without audit outcomes or new source
provenance. *Template classes* are (surface-kind × exact action set)
groups; they bound template count, not labor — each member surface still
needs arguments, setup, and a pinned observed sequence.

| scope variant | cells | certifiable | fixtures (already executable) | rows to author | surfaces | template classes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| seed-pure fs+network+process+env | 1,093 | 664 (61%) | 5,563 (378) | 5,185 | 625 | 83 |
| family-closure (adds path, stdio, sys) | 1,591 | 828 (52%) | — | 6,727 | 740 | — |
| **fs+env+process (no network)** | **513** | **457 (89%)** | **3,624 (368)** | **3,256** | **424** | **64** |

Per-family poison rates among seed-pure cells: network **64%**, fs 12%,
env 5%, process 0%. Representative batch execution
(`capsec_public_noncap_builtin_recipe_batch`, bound engine): **16.24 s**
— and it failed loudly on one live contract-mismatch
(`node:crypto` `Sign.end`; filed as
issues/20260731-noncap-crypto-sign-end-probe-contract-mismatch.md),
demonstrating the authoring loop the estimate must price.

**What the measurement establishes:**

- **The §5 hypothesis is falsified as stated.** The already-executable
  mass is not in the seed families (378 of 9,806 fixtures, 3.9%), so
  essentially all in-scope evidence must be newly authored; and clean
  whole-family certification of `network` is unreachable without Lane B
  terminal-provenance engineering — 64% of its cells are poisoned.
- **A surviving cheap scope exists: fs+env+process.** 89% of its cells
  are certifiable today; the poisoned 56 drop out only if the scope
  grammar can express a principled, generated exclusion (see below) or
  after audits. The authoring program is 64 template classes covering
  3,256 rows on 424 surfaces, with batch execution in seconds per
  family — the schedule is authoring iteration and review, heavily
  agent-parallelizable.
- **New register-relevant fact for items 4 and 2:** certifying any
  seed family *as a family* requires handling its poisoned cells. The
  measured options: (a) scope v1.1 to fs+env+process and defer network
  to a Lane B program; (b) extend the closed selector grammar with a
  generated criterion — "cells whose enforcement routes have
  source-proven terminals" — which is intensional and generated, but
  interacts with the anti-cherry-picking constraint the review settled
  and therefore needs its own review if chosen; (c) fund the Lane B
  terminal-provenance engineering first. This addendum recommends (a)
  and records (b) as needing review, deciding neither.

**Revised cost estimate on the measured numbers (fs+env+process, option
a):** 64 template-class campaigns at roughly half a day to a day and a
half each including batch iteration and LLP 0037-pattern review, heavily
parallelizable across agents and machines; roughly 2–4 weeks wall-clock
with 4–8 parallel streams and low-single-digit thousands of dollars in
tokens, plus the gate/amendment work §5's table already priced. The
6-week tail applies if option (b)/(c) is chosen or template classes
surface new attribution patterns that stop for LLP 0037 review.
