# Reviews — LLP 0044 (Claude/Fable family)

## Round 1 — 2026-07-31

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent
  tool (independent context; the authoring session did not write this review)
- **Date:** 2026-07-31
- **Redacted:** no (public-repo content only)
- **Method:** full-repo read-only capsule (git ls-files snapshot), round-1
  brief `llp0044-brief-r1.md`; document revision under review `5c964e8e73eb`
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Review body (verbatim)

**Verdict:** NOT READY

**Strengths**

- §6 is the strongest section: it accurately quotes the governing corpus (LLP 0021's "distinct diagnostic schema … rejected at publication," verified at `llp/0021-capsec-effect-model-migration.plan.md:2786`; LLP 0032's "never counts as fixture passes," verified at `llp/0032-capsec-conformance-execution-and-evidence-sharding.spec.md:408`), rejects both evidence-bar reductions by default, and requires a formal LLP 0021 amendment to ever revisit. This is exactly the right posture.
- §2's honesty-constraint skeleton (generated intensional scope, dependency closure, identity binding, release-constraint enumeration, monotonicity) is the right *shape* of answer to LLP 0036's strategic question (b), and correctly reuses the backlog ticket's "stated as release constraints, not hidden by aggregate coverage counts" rule verbatim.
- §1's numbers are internally consistent in a way that suggests real measurement: 16,627 unresolved + 3,042 internally verified = 19,669, exactly the stated `public-surface-invocation-not-authored` supercategory, which matches how `summarize()` counts residual reasons on internally-verified rows (`capsec-conformance-recipes.mjs:4492–4527`). The residual-reason vocabulary in the table matches the code (`:3721`, `:4437–4487`).
- §3's stated rules preserve the 2026-07-24 audit standard (exact mechanism, executed digest-bound evidence, retirement = ill-typed never inconvenient), and the three named families are the right candidates — they are the structurally-suspect reasons, and the `builtin-export-resolves-to-bootstrap-internal` analogy to `malformed-branch-facts` is apt.
- §7 correctly escalates the one decision that matters (item 1 is LLP 0036's question (b) by name) and recommends `Status: Review` with the formal loop for a promotion-gate change (item 5).
- The RFC accurately represents LLP 0036's measured correction, the 5–36 rows/commit rate, the ~6 remaining `builtin:export` family templates, and the D1–D4 status in LLP 0037 (D4 accepted 2026-07-25 per that doc's revision line).

**Concerns**

1. **MATERIAL — the published remainder claim is an unverified universal negative.** §2 defines the published claim as "this target enforces the declared scope; **every surface outside it is refused**," resting on "the enforcement engine is complete and armed startup already refuses everything unproven." But the backlog ticket the RFC re-scopes says the residual rows are "conformance and evidence *uncertainty*, not proof of a runtime bypass" — equally, not proof of refusal. Rows marked `ambiguous-static-enforcement-route` and `no-static-enforcement-terminal` (12,263 rows) are precisely rows where the analysis could not name the enforcement route or terminal. Under the all-or-nothing gate the refusal-of-remainder claim was vacuous; scoped advertisement makes it load-bearing with **zero executed evidence class named to back it**. The whole corpus's principle is that a published claim carries executed, digest-bound evidence — this half of the claim carries none. Resolve by either (a) downgrading the published wording to "surfaces outside the scope are unsupported and unverified; the runtime is designed to refuse them," or (b) naming and binding a concrete evidence mechanism for the remainder (e.g., the generated armed-startup descriptor/refusal sweep receipts that LLP 0021's revision history shows already exist, plus at least a sampled executed negative control demonstrating an out-of-scope surface refusing on the exact advertised build).

2. **MATERIAL — the amendment list understates what all-or-nothing is baked into, and the arming/consumer interaction is unanalyzed.** `capsec-portable-promotion-bundle.mjs:163–171` requires **every** target cell for the promoted tuple to be non-`unsupported` ("promotion target cells remain unsupported or malformed"), independently of `assertRecipeCatalogComplete`; §2's design ("every out-of-scope cell keeps `disposition: "unsupported"`") directly violates it. The advertisement object (`ibex/capsec-target-advertisements/2`) is per-target and today semantically means "whole tuple conformant"; every consumer — production arming (`TargetArmState` in `crates/capsec-semantics/src/arming.rs`), report admission, the installer/Go verifier-oracle chain from LLP 0035 — currently interprets "advertised" under that meaning. The RFC's "Amendments required" paragraph names generator/report/attestation changes but never analyzes the consumer side: whether arming on an advertised-but-scoped target actually consults per-cell dispositions to keep refusing the remainder, and whether advertisement schema consumers need a scope-aware v3. "Advertisement is a claim, not a change in runtime authority" is only true if that consumer analysis is done and comes back clean; it belongs in the RFC, not in the implementer's lap. Resolve: enumerate the consumers of the advertisement/cell-disposition artifacts, state for each whether scoped semantics are transparent or require change, and add the promotion-bundle cell invariant to the amendment list explicitly.

3. **MATERIAL — the scenario-class scoping axis is a cherry-picking vector the "no row-level" rule does not close.** §2 defines scope "by capability family, surface kind, **and scenario class**." Scoping by scenario class would permit an advertisement whose in-scope surfaces proved only `allow` rows while `deny`/`missing-attribution`/`wrong-principal` rows were scoped out — "enforces fs:\*" without ever demonstrating a refusal. That is not row-level cherry-picking, but it guts the security meaning of "enforces." The worked example says "full scenario matrices," but examples are not constraints. Resolve: add a MUST — an in-scope surface carries its complete generated scenario matrix; scenario-class exclusion is never a scoping axis (or is limited to explicitly justified classes like target-absence).

4. **MATERIAL — §5's central empirical claim is unmeasured and in tension with LLP 0036's own data.** "the 3,928 executable rows cluster in exactly these families [fs/net/process/env]" is stated as fact. LLP 0036 measured that the harvested cheap head is the `(none)`/non-capability readable-export bucket (2,163 executable `(none)` rows at the 2,592-executable baseline; scenario-type executables led by `non-capability` 1,480 and `closed` 610) — i.e., the executable mass demonstrably clustered *outside* the fs/net/process/env capability edges, the fs:read family prototype was **reverted**, and network still "would need a new setup kind." The weeks-and-low-tens-of-thousands estimate the owner is being asked to decide on (§7 items 1–2) rests on this clustering claim. The day-one falsifiability claim is real (generator-only measurement), which is exactly why the RFC should not assert the result before running it. Resolve: run the scope-expansion measurement and put the actual in-scope executable/residual split in §5, or rewrite the claim as an explicit unmeasured hypothesis with the measurement gating §7 item 2 — consistent with the corpus's measured-not-inferred standard.

5. **MINOR — admission-side re-derivation of the scope is implied but not stated.** Binding the "expansion digest" into the attestation proves *which* expansion was used, not that it is the *correct* expansion of the intensional definition against the bound inventory, nor that the closure was honored. LLP 0021's existing pattern ("the generator re-derives the exact required fixture set") suggests the intent; the RFC should say explicitly that report admission recomputes the expansion and closure from the intensional scope definition, never trusting the report's row list.

6. **MINOR — monotonicity is underspecified.** §2 says v1.2+ scopes must be supersets "for the same tuple" but not at what granularity (intensional definition vs. expanded row set), who enforces it, or how it interacts with catalog regeneration and surface retirement — the LLP 0040 WebGPU extraction already set precedent that surfaces can vanish from the inventory, which would break row-set supersets while an intensional-level check could mask a family silently losing rows. Define the granularity and the enforcement point (e.g., intensional superset + a required expansion-diff artifact against the prior advertisement).

7. **MINOR — Proposal 2 contradicts the closed-vocabulary rule without listing the amendment.** LLP 0036 (proof-audit section) states the closed six-member `INTERNALLY_VERIFIED_SCENARIOS` vocabulary exists precisely to "prevent the predicate from absorbing another scenario"; §3 proposes that the vocabulary "grows only by this audit." Growth-by-audit may be the right rule, but it is an amendment to LLP 0036/0021 that §2's amendment list omits — and the current mechanism is scenario-keyed, while `native-public-source-invocation-unavailable` rows are surface-keyed, so the "internally-verified candidate" outcome needs new machinery whose shape the RFC doesn't sketch.

8. **MINOR — the §1 residual table presents resolved rows as residuals.** The "callback-invariant `*-probe-not-authored` (6 scenarios) — 3,042" row consists entirely of internally-verified (resolved) rows, per §3 itself and per how the code retains residual reasons on internally-verified recipes (`capsec-conformance-recipes.mjs:5013–5020`). Under a header of "Dominant residual reasons" following "16,627 unresolved," this misleads (conservatively, but the corpus standard is precision). Label that row as already-resolved or drop it.

9. **MINOR — no provenance for the §1 numbers.** Catalog digest `sha256-XcvN5FFF…` appears nowhere else in the capsule; the closest corroborated accounting is the backlog ticket's `sha256-GHlq…` at 23,598/3,928/3,042/16,628 (one row and one digest apart). LLP 0036 carries a "Provenance of the numbers" section for exactly this reason; the RFC should state where and when its catalog and the residual-reason counts were measured so a reviewer can re-derive them.

**Suggestions**

- Add an executed out-of-scope negative control to the scoped ceremony (one refused invocation per major out-of-scope family on the advertised build) — cheap, and it converts part of Concern 1's universal negative into evidence.
- Have the release-notes remainder enumeration (§2, bullet 4) generated from the same expansion diff that the gate validates, so the constraint statement can't drift from the actual unsupported set.
- When escalating §7 items 1–2, present the day-one scope measurement alongside the register so the owner decides on numbers, not on the §5 estimate.
- In §3, state explicitly that a batch run observing zero typed decisions where the coverage edge declares a capability fails loudly rather than "pinning" an empty route — the `observed == expected` invariant implies it, but the audit text should say it.

**Open questions**

- Does armed startup on an advertised target actually consult per-cell dispositions for refusal of unsupported cells, or does any path treat "target advertised" as tuple-wide authority? This state (advertised target with unsupported cells) has never existed, so it has never been exercised.
- Can the dependency closure (§2, bullet 2) be computed for in-scope surfaces whose typed sequences are not yet pinned — i.e., is the day-one scope measurement's closure static-approximate, and if so, what happens when a later pinned run reveals a traversal into a cell the measured scope excluded?
- Will the second tuple (Windows, per LLP 0029 register item 4) reuse the same intensional scope definition, and does monotonicity bind per-tuple only or per-definition?
- What artifact backs the "11,650 adapter-executable" figure in §6 (presumably `adapterExecutableFixtures`, but it is uncorroborated in the capsule)?

**Recommended next step:** Revise and re-review. Concerns 1–4 are resolvable in one revision (wording + consumer enumeration + a MUST + running the already-planned measurement); none undermines the core direction, which correctly answers LLP 0036's strategic question. Do not put §7 item 1 to the owner until Concern 4's measurement is in the document.

## Round 2 (delta) — 2026-07-31

- **Method:** delta round against revision `2f6c27649e45` (revised from
  `5c964e8e73eb`); brief `llp0044-brief-r2.md` with the 9-item delta
  enumeration; round-1 artifacts included in the capsule; same
  family/runtime as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Round-2 review body (verbatim)

**Verdict:** READY

**Delta assessment**

1. **RESOLVED** — §2's normative claim is now "certified for the declared scope; every surface outside the scope carries no conformance claim," with an explicit MUST NOT (refused/absent/safe), the zero-decision execution fact stated with an accurate cite (verified: `crates/capsec-semantics/src/decision.rs:609-620` refuses `Incomplete` cells only at a reached typed gate), and negative controls demoted to "evidence, not proof."
2. **RESOLVED** — the six-row consumer table is present and every code characterization checks out: `Host::new_armed_with_target_cells` requires an exhaustive Complete/Closed map plus `TargetArmState::CompleteAdvertised` (`src/host/mod.rs:824-846`; the enum is `{CompleteAdvertised, Incomplete, Unadvertised}`, so a distinct scoped state genuinely requires amendment); the promotion bundle rejects any `unsupported` cell (`capsec-portable-promotion-bundle.mjs:163-171`); admission demands the exact complete inventory and fixture union (`src/host/portable_target_admission.rs:1045,1452,1518-1525`); `assertRecipeCatalogComplete` binds `unresolvedFixtures !== 0` globally (`capsec-conformance-recipes.mjs:4996-5010`); schema v2 const confirmed; "no arming change" explicitly withdrawn.
3. **RESOLVED** — "Scope unit (MUST)" makes the complete target cell indivisible and scenario class descriptive-only, never a selection axis.
4. **RESOLVED** — closure is conservative, pre-execution, from source-derived routes and argument-selected branch alternatives, validated against every physical observation, with unknown dependencies fatal or excluding.
5. **RESOLVED** — canonical scope artifact + digest domain, exactly one active scope per tuple, admission re-derives expansion and closure from the intensional definition, monotone lineage via authenticated predecessor + generated expansion-diff, with LLP 0040 retirements permitted (retirement precedent verified in `llp/0040-native-runtime-extension-sdk.rfc.md`).
6. **RESOLVED** — Lanes A–D are separated with distinct evidence rules; Lane B explicitly keeps the current bar with no dynamic witnessing; Lane C requires the closed-world source join; vocabulary growth is named an LLP 0021/0036 amendment and added to §2's amendment list; the surface-keyed-machinery note matches the code (`INTERNALLY_VERIFIED_SCENARIOS` is a frozen six-member scenario-keyed list, `capsec-internal-invariant-evidence.mjs:25-32`). One precision nit (Concern 1).
7. **RESOLVED** — §5 is labeled an unmeasured hypothesis, the false clustering claim is gone and replaced with an honest statement of the contrary LLP 0036 evidence, the measurement is a MUST-precondition for register items 2 and 4 with enumerated outputs, and the no-savings fallback framing is stated.
8. **RESOLVED** — the register is ten items and covers all six of Codex C6's omissions (out-of-scope semantics, scope unit, arm state, lineage, cross-tuple congruence; the dynamic-witnessing question is settled in the body by Lane B's fixed posture routing any change through a separate amendment, plus item 8).
9. **RESOLVED** — §1 carries command (options verified against `generate-capsec-conformance-recipes.mjs`: `--target`/`--output` exist), date, digest, and the one-row-delta explanation against the backlog ticket's `sha256-GHlq…` 23,598 snapshot (verified in `issues/20260728-capsec-public-surface-evidence-backlog.md:21`); the adapter figure is sourced to `adapterExecutableFixtures` (verified, `capsec-conformance-recipes.mjs:4509`); the callback-invariant row is labeled "already resolved." Counts remain internally consistent (3,928+3,042+16,627 = 23,597; supercategory 19,669 = 16,627+3,042).

**Concerns**

1. **IN-DELTA, MINOR** — §3 Lane A's parenthetical "(an authored effect probe can clear ambiguity; nothing else can)" overstates the code: `ambiguous-static-enforcement-route` is also suppressed by a `sourceBoundClosureProbe` (closed-surface invocation schema) and by a `callbackInvariantProbe` (`capsec-conformance-recipes.mjs:4481-4487`). All three are authored/source-bound, so the normative rule survives, but "exactly as the generator already distinguishes" is not exact. Resolve: correct the parenthetical to name all three suppressors or drop "nothing else can."
2. **IN-DELTA, MINOR** — "no path becomes more permissive than today" (§2 close, §8): relative to today's literally unarmable production state, scoped arming newly makes uncertified zero-decision surfaces *executable*, which the document itself acknowledges two paragraphs earlier. The sentence intends "the typed decision semantics are unchanged" and should say exactly that, so it cannot be read as a residue of the withdrawn refusal claim.
3. **IN-DELTA, MINOR** — §5 makes the measurement a MUST-precondition for register items 2 and 4, and item 4's text carries "REQUIRES the §5 measurement first," but item 2's text does not. Resolve: add the same cross-reference to item 2.
4. **IN-DELTA, MINOR** — the consumer table's enumeration misses two direct consumers of the advertisement schema: `capsec-portable-engine-evidence-contract.mjs` and `generate-capsec-registry.mjs` (both reference `ibex/capsec-target-advertisements/2`). They are plausibly intended under the "LLP 0035 installer / Go verifier-oracle chain" row, but the table's stated function is enumeration; name them or state they are covered by that row.
5. **PRE-EXISTING, MINOR** — the catalog digest `sha256-XcvN5FFF…` and commit `619ce9e8` remain uncorroborated by any retained artifact in the capsule; re-derivation requires checking out a tree the capsule cannot verify. Round 1's provenance ask (command + when + delta explanation) is substantially satisfied; retaining the generated catalog artifact (or its digest in a checked-in evidence index) would close this fully.

**Suggestions**

- When the scoped arm state is designed (register item 5), decide early whether out-of-scope cells reuse `TargetCellDisposition::Incomplete` or get a new variant — the current variant set is `{Complete, Closed, Incomplete}` and the choice affects whether the decision path can distinguish "uncertified by scope" from "incomplete by defect" in refusal telemetry.
- Bind the negative-control probe results into a named diagnostic artifact with its own schema (parallel to adapter evidence) so "evidence, not proof" is structurally enforced at publication, not just stated.
- Consider Codex's round-1 suggestion of a distinct product term for scoped conformance; the v3 schema revision is the natural place to introduce it.

**Open questions**

- Does the expansion-diff artifact get its own schema/digest domain, or ride inside the scope artifact? The lineage MUST implies a verifier consumes it; its identity binding is unstated.
- Under the scoped arm state, what happens at `ArmedSnapshot` authentication time (before host construction) — does the snapshot itself carry the scope digest, or only the cell map derived from the admitted report?
- For register item 7, if tuples share one intensional definition but expansions diverge, which artifact records the congruence check result?

**Recommended next step:** Accept the revision and move to the author-decision register: set `Status: Review` per register item 10, land the five MINOR fixes as editorial changes (no re-review needed), and run the §5 measurement before putting register items 2 and 4 to the owner. No further dual-review round is warranted on this text.

## Round 3 (delta) — 2026-07-31

- **Method:** delta round against revision `3d2a1aebf78a` (revised from
  `2f6c27649e45`); brief `llp0044-brief-r3.md` with the 8-item delta
  enumeration; rounds 1–2 artifacts in the capsule; same family/runtime
  as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Round-3 review body (verbatim)

**Verdict:** READY

**Delta assessment**

1. **RESOLVED** — "no path becomes more permissive" survives only in the revision-history line describing its own removal; §2's consumer-analysis close states the exact invariant (typed-gate refusal semantics unchanged, runtime availability deliberately expands to the uncertified remainder including zero-decision surfaces, expansion is the substance of register item 2), and §8's first non-goal restates it verbatim with "It is not claimed here as non-permissive."
2. **RESOLVED** — "Threat model of the claim (normative)" is in §2 with all four required elements: per-invocation certification under source-derived preconditions; compositions with callable uncertified surfaces (state/authority/handles/configuration/lifecycle interference) explicitly uncertified; adversarial-composition fixtures diagnostic only; compositional assurance against the remainder routed to register item 2's physically-refused option.
3. **RESOLVED** (one MINOR imprecision, Concern 1) — Go row is now provenance-only/scope-transparent with explicit withdrawal, and the characterization is correct: `llp/0035-portable-engine-artifact-provenance.rfc.md:1379-1383` states "Build consumption, runtime identity, Host target cells, and advertisement loading remain separate gates." New rows for the schema readers and promotion authority/bundle verifier/lineage verifier/`build.rs` selector/target-cell bytes/fixture catalog are present; the created/re-derived/bound/compared/delivered lifecycle is normative; the join matrix is a required amendment deliverable that MUST exist before gate code, with the table named "the seed, not the proof."
4. **RESOLVED** — predecessor hash chain; admission resolves the currently admitted scope from the checked-in promotion lineage and requires equality ("the lineage names the latest, not the artifact"); genesis rule; closed selector grammar with set-inclusion semantics; retired-but-still-present = narrowing = fail; authenticated rename/split/merge mappings. The claimed anchor is real: `scripts/portable-engine-promotion-lineage.mjs` reconstructs the Git lineage and pins `capsec/conformance/target-attestations.json` (TARGET_ATTESTATION_PATH, line 49) and the advertisement artifact.
5. **RESOLVED** — §1 no longer asserts a cause: the row is stated as "**not been diffed**," the non-re-derivability is explained (acceptance-era catalog not retained), and the §5 measurement MUST retain both catalog summaries in its evidence index. Backlog anchor verified (`issues/20260728-...backlog.md:21`: `sha256-GHlq…`, 23,598).
6. **RESOLVED** — Lane A names all three suppressors (effect probe, source-bound closure probe, callback-invariant probe), matching the generator exactly: `capsec-conformance-recipes.mjs:4481-4487` suppresses `ambiguous-static-enforcement-route` on `callbackInvariantProbe || effectBuiltinProbe || sourceBoundClosureProbe`.
7. **RESOLVED** — register item 2 now carries "REQUIRES the §5 measurement first," matching item 4.
8. **RESOLVED** — `ScopedAdvertised` SHOULD with an out-of-scope disposition distinguishable from "incomplete by defect" in refusal telemetry (genuinely new: `TargetArmState` is `{CompleteAdvertised, Incomplete, Unadvertised}`, `crates/capsec-semantics/src/decision.rs:52-56`); scope digest + uncertified remainder MUST be machine-readable runtime introspection; the amendment list carries all eight adversarial fixture classes from Codex r2's suggestion (rollback covered by "stale/rolled-back predecessors"); "Why this is sound" is bounded to "complete for every surface with a source-proven enforcement route" beside the 5,508 no-terminal rows.

End-to-end coherence: verified. The claim wording (§2 normative claim + MUST NOT), threat model (per-invocation), consumer table ("unchanged — this is exactly why the claim is 'uncertified,' not 'refused'"), arm-state paragraph, register items 2/5, and §8 non-goals all now say the same thing; no residue of the withdrawn refusal or non-permissiveness claims remains anywhere in the body. Revision identity confirmed: the capsule file's git blob hash is `3d2a1aebf78a…`.

**Concerns**

1. **IN-DELTA, MINOR** — The new consumer row lists `generate-capsec-registry.mjs` as a direct reader of `ibex/capsec-target-advertisements/2`, but it reads/emits the **v1** schema (`generate-capsec-registry.mjs:1058`), and the lineage verifier pins that chain there ("artifact-source target advertisements must remain on the closed v1 schema," `scripts/portable-engine-promotion-lineage.mjs:825`). There are two advertisement chains (checked-in v1 registry, portable v2), and the proposed "v3" revision sits over that two-generation reality. The row's substance (this reader must be amended or shown scope-transparent) is right, and the join-matrix deliverable would surface this — but the table as written mislabels the schema binding. Resolve: split or annotate the v1 chain in the row; no re-review needed.
2. **IN-DELTA, MINOR** — §5's enumerated measurement outputs do not repeat §1's retention requirement (both catalog summaries in the evidence index). The §1 MUST is normative and binding, but an implementer working from §5's list alone would miss it. A one-line cross-reference in §5 closes it.
3. **IN-DELTA, MINOR** — The threat-model sentence "An owner who needs compositional assurance in the presence of the remainder needs register item 2's physically-refused posture instead" can be read as promising that option 2 yields compositional certification. Physically refusing the remainder removes the remainder-interference channel; compositions of in-scope invocations remain per-invocation-certified either way. One qualifying clause ("assurance against remainder interference") makes it unmisreadable.
4. **PRE-EXISTING, MINOR** — Catalog digest `sha256-XcvN…` and commit `619ce9e8` remain uncorroborated by any retained artifact in the capsule (the digest appears nowhere else in the repo). The document now honestly states this and binds the fix to the §5 evidence index, which is the right disposition; this closes when that measurement lands, not by further wording.

**Suggestions**

- When the join matrix is authored, give the v1 registry-advertisement chain its own row group so the v1/v2 split (Concern 1) is structural rather than a footnote.
- Register item 2's "physically refused" branch should inherit the threat-model paragraph's compositional caveat explicitly, so the owner's two options are compared under the same claim semantics.
- Consider stating in §2 that the expansion-diff artifact carries its own digest domain (or rides inside the scope artifact) — Fable r2's open question on its identity binding is still unanswered and will surface during the LLP 0021 amendment.

**Open questions**

- At `ArmedSnapshot` authentication time, does the snapshot itself carry the scope digest, or only the cell map derived from the admitted report? (Carried over from r2; belongs to the register-item-5 design review, not this text.)
- For register item 7, which artifact records the cross-tuple congruence check result if tuples share one intensional definition with divergent expansions?

**Recommended next step**

Accept: no further dual-review round is warranted on this text. Land Concerns 1–3 as editorial fixes without re-review, set `Status: Review` per register item 10, run the §5 measurement (retaining both catalog summaries, which also discharges Concern 4), and only then put register items 1, 2, and 4 to the owner.

## Round 4 (narrow delta) — 2026-07-31

- **Method:** narrow delta round against revision `e41717a8b82b` (revised from
  `3d2a1aebf78a`); brief `llp0044-brief-r4.md`; rounds 1–3 artifacts in
  the capsule; same family/runtime as round 1.
- **Status:** RECEIVED 2026-07-31 — body below, recorded verbatim.

### Round-4 review body (verbatim)

**Verdict:** READY

**Delta assessment**

1. **RESOLVED** — Both offending statements are gone (no "posture is unchanged" or "fail-closed by design" anywhere in the body; verified by search). The remaining uses of "fail-closed" comply with the new rule: the negative-controls bullet names its layer parenthetically ("typed-gate refusal"), and "Why this is sound" states the layer-naming rule (startup admission, typed-gate refusal, physical entrypoint refusal) with the explicit statement that the zero-decision remainder has none of the three — which is accurate against `Incomplete` handling in `crates/capsec-semantics/src/decision.rs`. The only other occurrences are the revision-history line describing the deletion itself, the accepted r3 precedent.
2. **RESOLVED** — The lifecycle paragraph now delivers scope identity only "via the admitted report's cell map" and declares the runtime join beyond it deliberately undesigned; the armed-snapshot producer, `ibex/capsec-armed/1` parser, and `ExpectedArmingIdentity` are a consumer-table row marked "carry no scope identity today" (verified: `ExpectedArmingIdentity` in `crates/capsec-semantics/src/arming.rs:70` has no scope field); the join matrix is required as an appendix to the LLP 0021 amendment reviewed with this RFC's package, before item 5 goes to the owner and before gate code; register item 5 reads "BLOCKED until … authored and reviewed." This is exactly the disposition Codex's r3 recommended next step and first suggestion asked for, including naming the substitution-prevention and introspection-authority questions as the item-5 review's central content.
3. **RESOLVED** — §1 now states the row has not been diffed, that retained future artifacts cannot name it, that identification requires regenerating the `sha256-GHlq…` catalog from its exact bound source state and is otherwise **permanently unknown** (with the no-claim-affected note), and the retention MUST is scoped to future re-derivability (both catalog summaries in the §5 evidence index). This takes Codex's second offered resolution branch cleanly.
4. **RESOLVED** — The consumer table now has structurally separate rows: portable v2 schema + `capsec-portable-engine-evidence-contract.mjs` reader, and the checked-in v1 chain with `generate-capsec-registry.mjs` correctly placed on it (verified: it emits `ibex/capsec-target-advertisements/1` at line 1058) and the lineage-verifier pin noted, each with its own join-matrix row-group treatment ("structural, not a footnote").
5. **RESOLVED** — §5's measurement outputs now enumerate "the retained catalog summaries §1 requires (this measurement's and §1's own) in the measurement's evidence index."
6. **RESOLVED** — The threat-model sentence now reads "removes the remainder-interference channel; compositions of in-scope invocations remain per-invocation-certified under either option," which is exactly the qualifying clause requested and keeps the two register-item-2 options under the same claim semantics.
7. **RESOLVED** — "The expansion-diff artifact and the rename/split/merge mapping each carry their own schema and digest domain, bound into the scope artifact" is in the monotone-lineage bullet, and §2's code-amendment list already carries the expansion-diff artifact.

Revision identity confirmed: the capsule file's git blob hash is `e41717a8b82b…`. End-to-end coherence of the delta verified: the layer-naming rule, the undesigned-join declaration, the consumer-table rows, the lifecycle paragraph, register items 2/5, and §8's non-goals all say the same thing; no residue of the r3 defects survives.

**Concerns**

None that survive the narrow-scope rule. Two sub-editorial notes, recorded for the author without any review consequence: (a) §5's output list has a stacked "and … ; and …" from the retention insertion — pure grammar; (b) Fable r3 Concern 4 (the uncorroborated `sha256-XcvN…`/`619ce9e8` provenance) remains PRE-EXISTING/MINOR by design and closes when the §5 measurement lands, as already dispositioned in r3.

**Recommended next step**

Converged — accept. Both r3 MATERIALs are resolved in the way the objecting reviewer itself prescribed, and all four r3 MINORs are landed; no further dual-review round is warranted on this text. The author should set `Status: Review` per register item 10, run the §5 measurement (retaining both catalog summaries), author the join-matrix appendix with the LLP 0021 amendment, and only then put register items 1, 2, 4, and (after the matrix review) 5 to the owner.

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
