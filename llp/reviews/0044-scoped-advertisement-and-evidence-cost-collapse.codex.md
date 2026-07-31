# Reviews — LLP 0044 (Codex/OpenAI family)

## Round 1 — 2026-07-31

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.0,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`
- **Date:** 2026-07-31
- **Redacted:** no (public-repo content only)
- **Method:** full-repo read-only capsule (git ls-files snapshot), round-1
  brief on stdin; document revision under review `5c964e8e73eb`
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Review body (verbatim)

**Verdict:** `NOT READY`

## Strengths

- §2’s intensional, generator-expanded scope and prohibition on row-level cherry-picking are the right starting principles.
- §3 retains the closed-vocabulary, exact-mechanism, executed-evidence standard established on 2026-07-24.
- §6 correctly preserves LLP 0021/0032’s evidence-authority boundary: adapter evidence remains diagnostic, and D3 applies only inside an authored public invocation.
- §7 correctly leaves initial scope selection and audit outcomes to the owner, and §8 preserves LLP 0029’s single-tuple v1.1 sequencing.

## Concerns

1. **MATERIAL — The central “out-of-scope surfaces refuse” claim is false under the current runtime architecture.**

   §2 and §8 say scoped advertisement requires no arming or enforcement change. Today, however, unadvertised targets refuse globally before project code. Once admitted, `Host::new_armed_with_target_cells` requires every generated edge to be `Complete` or `Closed` and rejects a partial/incomplete map (`src/host/mod.rs:819-845`). Portable report admission likewise requires the exact complete coverage inventory and full fixture union (`src/host/portable_target_admission.rs:1443-1519`).

   More importantly, an `Incomplete` cell refuses only when a typed effect gate is actually reached (`crates/capsec-semantics/src/decision.rs:609-620`). Non-capability surfaces and precisely the rows with no known enforcement terminal may execute without such a gate. A scoped advertisement could therefore open startup globally while an out-of-scope, zero-decision or untracked-terminal surface remains callable. The published claim “every surface outside it is refused” would be false.

   **Resolution:** Either weaken the claim to “out-of-scope surfaces are not certified” or design a real scoped-arming mechanism. The latter must include an exhaustive scoped cell map, a distinct scoped-advertised arm state, and physical refusal/absence evidence at every out-of-scope public entrypoint—including non-capability and zero-decision surfaces. §8’s “no arming change” non-goal must then be removed.

2. **MATERIAL — Scope granularity and dependency closure can admit incomplete cells.**

   §2 calls scope a subset of coverage cells but permits selection by “scenario class.” LLP 0021 requires the complete obligation union for every selected cell’s exact source-derived branch set. If scenario classes can subtract deny, malformed, wrong-principal, or branch obligations from an otherwise in-scope cell, this is partial cell credit under another name.

   Closure is also defined from “observed typed sequences.” That is circular for unresolved recipes and insufficient for alternative argument-selected branches not exercised by one observation.

   **Resolution:** Make the unit of promotion strictly a complete target cell: all applicable implementation branches and the full generated scenario matrix are indivisible. Compute a conservative pre-execution dependency closure from source-derived routes and branch alternatives, then validate it against every physical observation. Unknown dependencies must keep the cell out of scope or fail promotion.

3. **MATERIAL — Identity binding and monotonicity lack an enforceable protocol.**

   §2 binds scope only into the advertisement, report, and attestation. It does not specify the joins through fixture/recipe catalogs, public execution evidence, target-cell bytes, portable promotion authority/admission, and the runtime’s authenticated cell map. “Exactly as catalogs are bound today” is not enough for a new security identity dimension.

   The monotonicity MUST is also unenforced. A later generator can redefine a selector, rename/remove edges, or publish a narrower expansion unless promotion validates against an authenticated predecessor. “Two scopes are two advertisements” additionally conflicts with current admission’s unique advertisement per target/features.

   **Resolution:** Define a canonical scope artifact and digest domain; bind it through every promotion-facing artifact and runtime admission result. Specify exactly one active scope per tuple or add scope identity to selection. Enforce superset evolution against an authenticated predecessor expansion, with explicit rules for renamed or retired cells.

4. **MATERIAL — §3 conflates valid D3 evidence with dynamic route witnessing that §6 rejects.**

   D3 permits pinning a typed sequence only after an authored, bounded, source-bound public invocation. It does not manufacture a terminal when static analysis has none. Current code reflects this distinction: an exact effect-builtin probe can clear `ambiguous-static-enforcement-route`, but `no-static-enforcement-terminal` remains unless a source-bound closure mechanism applies (`capsec-conformance-recipes.mjs:4467-4487`).

   Similarly, “no recorded public invocation path” is not proof of public unreachability. The 4,261 native rows are heterogeneous; lack of inventory data could be the defect being hidden.

   **Resolution:** Split the audits:

   - Clear ambiguity only with an authored invocation, a source-derived closed terminal allow-list, and exact observed selection.
   - Keep no-terminal rows unresolved until source provenance supplies a terminal or a separately reviewed evidence-bar amendment is accepted.
   - Retire unreachable rows only from a closed-world source join plus loaded-target absence/immutable-closure evidence, mapped exactly to every credited row.
   - Require equivalent exact import-resolution/closure proof for the 36 bootstrap-internal rows.

5. **MATERIAL — The 1–2 week cost claim is not supported by the measured corpus.**

   §5 relies on “a few thousand” scoped rows, says most are already executable, and returns to roughly six family templates. No candidate-scope expansion or closure artifact is presented, and the owner has not selected the scope. LLP 0036’s measured correction says the cheap head is already harvested and the remaining tail is per-surface/per-function authoring, with no template unlocking thousands of rows (§“Measured correction”).

   “Falsifiable on day one” describes a future measurement, not evidence supporting acceptance now. Observed-sequence closure also means the measurement is not necessarily “only generator work.”

   **Resolution:** Before acceptance, generate the recommended candidate scope and publish exact counts for cells, fixtures, unresolved reasons, distinct invocation shapes, closure additions, and worst-case audit outcomes. Measure representative batch duration and re-estimate from those results.

6. **MATERIAL — The decision register omits decisions that the body silently settles.**

   §7 does not surface:

   - whether out-of-scope means physically refused or merely uncertified;
   - whether scope is cell-level or scenario-level;
   - whether scoped arming is a new runtime posture;
   - how monotonic lineage is enforced;
   - whether later tuples must expose the same logical scope; or
   - whether no-terminal dynamic witnessing changes LLP 0021’s evidence bar.

   These are owner-level security and product decisions, not implementation details.

   **Resolution:** Add them to §7 with explicit blockers before the owner considers accepting scoped advertisement.

7. **MINOR — The baseline needs reproducible provenance.**

   §1’s 23,597-row catalog differs by one row from LLP 0021 and the backlog ticket’s 23,598-row accepted snapshot. The new digest may be legitimate, but the corresponding source revision, tree digest, engine/profile binding, retained artifact, and reproduction command are absent. The current repository does confirm 7,528 all-unsupported cells per tuple and zero advertisements/attestations.

   **Resolution:** Record the full catalog provenance and explain the one-row delta. Also distinguish residual reasons retained on internally verified rows from reasons contributing to the 16,627 unresolved count.

## Suggestions

- Give scoped conformance a distinct product term rather than overloading “target advertised,” which currently means exhaustive target completeness.
- Make the scope and unsupported remainder available through machine-readable runtime/CLI introspection, not only release notes.
- Add adversarial fixtures for unscoped non-capability execution, alternative-route dependencies, duplicate scopes, selector drift, predecessor narrowing, and scope/report substitution.
- Separate the scoped-arming design from the audit/cost execution plan if necessary; they currently obscure each other’s assumptions.

## Open questions

- Does the product truly require every out-of-scope API to be unavailable, or only to carry no conformance claim?
- What mechanism can refuse an out-of-scope surface that emits no typed decision?
- What is the exact expansion and residual count of the recommended v1.1 scope?
- Are scenario classes intended to select obligations, or only describe complete matrices attached to selected cells?
- What evidence proves negative public reachability for the native and bootstrap-internal families?
- Must the later Windows tuple expose the same logical scope as Apple?
- Can more than one scope for the same tuple coexist, and if so, how does startup select one unambiguously?

## Recommended next step

**revise and re-review**

## Round 2 (delta) — 2026-07-31

- **Method:** delta round against revision `2f6c27649e45` (revised from
  `5c964e8e73eb`); brief `llp0044-brief-r2.md` with the 9-item delta
  enumeration; round-1 artifacts included in the capsule; same
  family/runtime as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim (capsule-absolute link paths shortened to repo-relative).

### Round-2 review body (verbatim)

**Verdict:** `NOT READY`

## Delta assessment

1. **RESOLVED** — The normative claim is now explicitly “uncertified,” never refused or safe; negative controls remain diagnostic evidence only.
2. **PARTIALLY RESOLVED** — The four requested code characterizations are accurate, but the consumer inventory is incomplete and the Go-verifier claim is false.
3. **RESOLVED** — Complete target cells are indivisible; scenario class is descriptive only.
4. **RESOLVED** — Closure is pre-execution, source-derived, branch-conservative, observation-validated, and fails on unknown dependencies.
5. **PARTIALLY RESOLVED** — Canonical identity and re-derivation are present, but artifact binding and predecessor authentication remain incomplete.
6. **RESOLVED** — Lanes A–D preserve the no-terminal evidence bar and correctly require closed-world Lane C evidence and reviewed vocabulary machinery.
7. **RESOLVED** — Cost is explicitly hypothetical, the clustering claim is withdrawn, and the enumerated measurement gates register items 2 and 4.
8. **RESOLVED** — The register contains ten items and surfaces the claimed decisions.
9. **PARTIALLY RESOLVED** — Date, command, digest, adapter source, and resolved-row label are present; the one-row delta is asserted, not actually identified or reproducibly demonstrated.

## Concerns

1. **IN-DELTA — MATERIAL — “No path becomes more permissive” is false.**

   The RFC correctly admits that an out-of-scope zero-decision surface can execute after scoped arming ([LLP 0044 §2](`llp/0044-scoped-advertisement-and-evidence-cost-collapse.rfc.md:116`)), yet later says “no path becomes more permissive than today” and repeats that as a non-goal ([§2](`llp/0044-scoped-advertisement-and-evidence-cost-collapse.rfc.md:196`), [§8](`llp/0044-scoped-advertisement-and-evidence-cost-collapse.rfc.md:377`)).

   Today, anything except `CompleteAdvertised` refuses before a decision context exists ([decision.rs](`crates/capsec-semantics/src/decision.rs:229`)). A scoped state necessarily opens startup and allows zero-decision out-of-scope paths to run. That is intentionally more permissive, even if no typed-gate rule changes.

   Resolve by deleting the global non-permissiveness claim and stating the actual invariant: typed-gate refusal semantics are unchanged, while runtime availability expands to uncertified paths. If zero-decision execution is unacceptable, choose register item 2’s physically-refused design.

2. **IN-DELTA — MATERIAL — The consumer and binding analysis is not complete, and its Go-verifier statement is wrong.**

   The spot-checked claims about the promotion cell check, Host construction, `Incomplete`, and portable report admission are accurate:

   - Promotion rejects any `unsupported` cell ([promotion bundle](`packages/ibex-devtools/src/scripts/capsec-portable-promotion-bundle.mjs:163`)).
   - Host requires an exhaustive `Complete`/`Closed` map and `CompleteAdvertised` ([host/mod.rs](`src/host/mod.rs:819`)).
   - `Incomplete` refuses only at reached gates ([decision.rs](`crates/capsec-semantics/src/decision.rs:609`)).
   - Admission requires the exact coverage inventory and fixture union ([portable_target_admission.rs](`src/host/portable_target_admission.rs:1443`)).

   But the RFC’s generic “LLP 0035 installer / Go verifier-oracle chain” row misses concrete scope-sensitive consumers: the promotion authority, evidence-contract validator, bundle verifier, promotion-lineage verifier, `build.rs` report selector, target-cell bytes, and fixture catalog. The scope-binding list also omits several of those artifacts.

   Conversely, the Go verifier authenticates portable-engine provenance; LLP 0035 explicitly keeps build consumption, Host target cells, and advertisement loading as separate gates ([LLP 0035](`llp/0035-portable-engine-artifact-provenance.rfc.md:1379`)). It need not “surface the scope” unless its signed subject contract changes.

   Resolve with an exact artifact/consumer join matrix showing where `scopeDigest` is created, independently re-derived, bound, compared, and delivered to runtime state. Mark provenance-only consumers explicitly scope-transparent.

3. **IN-DELTA — MATERIAL — Monotone lineage still lacks an enforceable predecessor protocol.**

   “Authenticated predecessor” does not define how admission identifies the immediately previous accepted scope. A release could point to an older, smaller predecessor and pass the stated superset check while dropping cells from the actual latest scope. “Exactly one active scope per tuple” only prevents duplicates inside one publication; it does not prevent cross-release rollback.

   The RFC also lacks:

   - an initial-scope rule;
   - a stable selector grammar for deciding whether one intensional definition is a superset;
   - a channel or ledger anchoring the latest accepted predecessor;
   - rename/split/merge rules for stable cells;
   - proof that an inventory “retirement” is not relabelled narrowing.

   Resolve by specifying the predecessor trust anchor and immediate-successor rule, canonical selector semantics, rollback handling, and authenticated retirement/rename mappings.

4. **IN-DELTA — MATERIAL — Route closure is too narrow for callable uncertified surfaces.**

   The closure covers source-derived call routes and argument-selected alternatives. It does not say whether it covers state, authority, handle, configuration, or lifecycle dependencies created through another public surface. Because the revision expressly allows uncertified zero-decision surfaces to execute, such surfaces can potentially affect a later in-scope invocation without appearing in that invocation’s call route.

   The claim “enforcement is certified for the declared scope” is therefore ambiguous between:

   - isolated per-invocation conformance under fixed preconditions; and
   - compositional enforcement while arbitrary uncertified APIs remain callable.

   Resolve by defining the threat model. Either narrow the published claim to the first meaning, or extend closure and evidence to all security-relevant state/authority dependencies and test adversarial compositions.

5. **IN-DELTA — MINOR — The one-row provenance explanation is not reproducible as written.**

   “The live inventory advanced” does not identify the removed row. The supplied command regenerates only the current catalog; it cannot by itself re-derive the older `sha256-GHlq…` catalog or its delta. No retained old artifact, exact diff, source-tree digest, or bound engine identity is supplied.

   Resolve by retaining both catalog summaries or a generated one-row diff naming the exact cell/fixture, with exact source revisions/tree digests and reproduction commands for both snapshots.

## Suggestions

- Add adversarial tests for scoped-state substitution, omitted map entries, typed out-of-scope refusal, executable zero-decision remainder, duplicate scopes, stale predecessors, rollback, and renamed/retired cells.
- Use `ScopedAdvertised` as a distinct arm state and explicitly map out-of-scope cells to the existing `Incomplete` gate behavior.
- Expose the active scope digest and uncertified remainder through machine-readable runtime introspection.
- Replace “the enforcement engine is complete” with a precise, bounded statement; it is misleading beside 5,508 rows lacking source-proven terminals.

## Open questions

- Is scoped certification intended to be compositional in the presence of arbitrary callable uncertified APIs?
- What authority identifies the immediately previous accepted scope for a tuple?
- Which exact artifacts independently re-derive scope rather than merely carrying its digest?
- Is the Go attestation verifier intentionally being expanded beyond engine provenance, or should it remain scope-transparent?
- Which exact required row disappeared between `sha256-GHlq…` and `sha256-XcvN…`?

## Recommended next step

Revise and re-review. Remove the false non-permissiveness invariant, provide the exact scope-binding/consumer matrix, make lineage rollback-resistant, define the certification threat model, and publish the actual one-row baseline diff. Then run and include the mandatory day-one scope measurement before asking the owner to accept scoped certification.

## Round 3 (delta) — 2026-07-31

- **Method:** delta round against revision `3d2a1aebf78a` (revised from
  `2f6c27649e45`); brief `llp0044-brief-r3.md` with the 8-item delta
  enumeration; rounds 1–2 artifacts in the capsule; same family/runtime
  as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Round-3 review body (verbatim)

**Verdict:** `NOT READY`

## Delta assessment

1. **PARTIALLY RESOLVED** — The exact invariant is now normative, but contradictory fail-closed language remains in the summary and §2 rationale.
2. **RESOLVED** — The per-invocation threat model and explicit exclusion of compositional assurance are coherent.
3. **PARTIALLY RESOLVED** — The consumer inventory is substantially corrected, but the security-critical armed-snapshot join remains deferred to an unspecified future matrix.
4. **RESOLVED** — Predecessor equality, genesis, closed selectors, inventory-validated retirement, and authenticated mappings are specified.
5. **PARTIALLY RESOLVED** — The unsupported causal claim is withdrawn, but the proposed retained artifacts still cannot identify the missing historical row.
6. **RESOLVED** — Lane A now accurately names all three authored suppressors.
7. **RESOLVED** — Register item 2 now explicitly requires the §5 measurement.
8. **RESOLVED** — `ScopedAdvertised`, distinguishable telemetry, runtime introspection, adversarial fixtures, and bounded enforcement wording are present.

## Concerns

1. **IN-DELTA — MATERIAL — The withdrawn fail-closed claim still survives semantically.**

   The summary says “the runtime’s fail-closed posture is unchanged,” and §2’s “Why this is sound” describes the uncertified remainder as “fail-closed by design.” Both conflict with the normative threat model and exact invariant: zero-decision remainder surfaces can execute, and runtime availability deliberately expands when the scoped target arms. This is residue of the same overclaim rejected in round 2.

   Resolve by deleting both broad statements. Say only that typed-gate refusal semantics remain unchanged; make no fail-closed characterization of the remainder as a whole.

2. **IN-DELTA — MATERIAL — The runtime scope-digest join is asserted but not designed.**

   The normative lifecycle says `scopeDigest` is delivered through both the admitted cell map and armed snapshot. The consumer table does not identify the armed-snapshot producer, `ibex/capsec-armed/1` parser, or `ExpectedArmingIdentity` as consumers. Current code carries no scope identity in those structures; Host obtains authenticated target cells separately through advertisement/report admission. A promised future join matrix does not establish which authority binds the digest into runtime state or prevents snapshot/report scope substitution.

   Resolve with the actual artifact/consumer matrix before approving the arm-state design: name every field and schema revision, identify who independently authenticates each value, and specify whether the snapshot carries `scopeDigest` or joins an independently authenticated scope identity beside it.

3. **IN-DELTA — MINOR — The one-row provenance remediation cannot perform what §1 promises.**

   Retaining the current `sha256-XcvN…` summary and the future §5 summary cannot name the historical delta from `sha256-GHlq…`; the missing acceptance-era catalog remains absent.

   Resolve by retaining or regenerating the `sha256-GHlq…` catalog from its exact bound source state, or remove the promise that the future evidence index will name that historical row and record the delta as permanently unknown.

## Suggestions

- Make the scope-binding matrix part of this RFC’s review package, not merely a prerequisite immediately before gate code.
- Replace every broad “fail-closed” phrase with the precise layer it describes: startup admission, typed-gate refusal, or physical entrypoint refusal.
- Give the expansion-diff and rename/split/merge mapping explicit schemas and digest domains.

## Open questions

- Does register item 5 remain blocked until the complete armed-snapshot/report/cell-map join is reviewed?
- Which authority supplies `scopeDigest` to runtime introspection, and how is it joined to the armed snapshot?
- Can the acceptance-era `sha256-GHlq…` catalog actually be regenerated from a known revision and engine identity?

## Recommended next step

Revise the two material defects, correct the historical-delta promise, and run one narrow delta review. Keep the RFC in `Draft`; do not put register item 5 to the owner until the runtime scope-binding matrix exists.

## Round 4 (narrow delta) — 2026-07-31

- **Method:** narrow delta round against revision `e41717a8b82b` (revised from
  `3d2a1aebf78a`); brief `llp0044-brief-r4.md`; rounds 1–3 artifacts in
  the capsule; same family/runtime as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Round-4 review body (verbatim)

- **Verdict:** `READY`.
- **Delta assessment**
  1. Codex r3 C1 — RESOLVED.
  2. Codex r3 C2 — RESOLVED.
  3. Codex r3 C3 — RESOLVED.
  4. Fable r3 C1 — RESOLVED.
  5. Fable r3 C2 — RESOLVED.
  6. Fable r3 C3 — RESOLVED.
  7. Both r3 suggestions — RESOLVED.
- **Concerns** — None.
- **Recommended next step.** Accept the narrow delta. Keep register item 5 blocked until the complete scope-binding join matrix is authored and reviewed with the LLP 0021 amendment; land no gate code before that review.

## Close-out ledger — 2026-07-31

- **Terminal state: CONVERGED DUAL-READY** at document revision
  `e41717a8b82b` after 4 rounds (the second loop in this corpus to
  converge, after LLP 0041).
- Round history: r1 dual NOT READY (Fable 4 MATERIAL / Codex 6 MATERIAL)
  → r2 Fable READY / Codex NOT READY (4 IN-DELTA MATERIAL) → r3 Fable
  READY / Codex NOT READY (2 IN-DELTA MATERIAL) → r4 dual READY, zero
  surviving concerns. Revisions: `5c964e8e73eb` → `2f6c27649e45` →
  `3d2a1aebf78a` → `e41717a8b82b`.
- Design landed by the loop: uncertified-not-refused remainder claim with
  a normative per-invocation threat model; complete-cell scope unit;
  conservative pre-execution closure; rollback-resistant scope lineage
  anchored in the checked-in promotion lineage; corrected and extended
  consumer analysis (v1/v2 advertisement chains split; Go verifier
  scope-transparent; armed-snapshot join declared undesigned and BLOCKING
  register item 5); four-lane obligation audits with the no-terminal
  evidence bar preserved; cost model as measured-gated hypothesis.
- Not revised in (author's discretion at acceptance; folding them in
  makes that revision UNREVIEWED and it must be labeled so): the §5
  "and…; and…" grammar stack; retained-artifact corroboration of the §1
  catalog digest (closes with the §5 measurement by design).
- The author decides status. Both reviewers' terminal recommendation:
  set `Status: Review` per register item 10, run the §5 measurement,
  author the join-matrix appendix with the LLP 0021 amendment, then put
  register items 1, 2, 4, and (post-matrix) 5 to the owner. This ledger
  proposes that transition; it does not apply it.
