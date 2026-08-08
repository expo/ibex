# Reviews — LLP 0049 (Claude/Fable family)

## Round 1 — 2026-08-06

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent
  tool (independent context; the authoring session did not write this review)
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** full-repo read-only review at `main` = `aaa007ad`, document
  revision `e84e9e9dd319`, with a mandatory execution pass (retained-catalog
  digest + summary verification, line-pin checks, scope-identity greps,
  backlog-ticket cross-check) run before prose review; targeted questions
  Q1–Q4 per the round-1 brief
- **Verdict:** NOT READY

### Review body (verbatim)

**Reviewer:** independent adversarial reviewer (Claude/Fable family), did not author the document.
**Document revision verified:** `shasum -a 256` of `llp/0049-scoped-attestation-execution.plan.md` = `e84e9e9dd319…` — matches the brief. Repo at `main`, HEAD `aaa007ad`, clean except the (untracked) document itself.

#### 1. Execution-pass results

1. **§2 catalog table — PASS.** The retained 146 MB catalog's digest field (`recipeCatalogDigest`, not `digest`) = `sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY`, exactly as claimed; `summary` = 23,765 required / 3,931 fully executable / 3,124 internally verified / 16,710 unresolved / 11,680 adapter-executable — all five match the doc's table. `target.triple` = `aarch64-apple-darwin`, `profile` = `ibex/capsec/1`.
2. **§4.1 line pins — PASS.** `function builtinExportClassification` at `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:8842`; the `node_http2` `/^(?:http2serverrequest|http2serverresponse)(?:\.|$)/` → `effectSpec(["network:listen"])` at :9368–9371; the readline `/^interface(?:\.|$)/` catch-all at :9644. (Caveat: this is one of **three** effect-assertion sites in the `node_http2` block — see Concern 6.)
3. **§2 "no scope identity exists" — PASS.** Case-insensitive grep for `scopeDigest|scope-digest|scope_digest` under `src/`, `crates/`, `packages/ibex-devtools/src`: zero hits. `ExpectedArmingIdentity` (`crates/capsec-semantics/src/arming.rs:70–109`): profile, digests, target, entry, canonicalizers, protected artifacts — no scope field.
4. **§2 scope numbers — PASS.** `issues/20260728-capsec-public-surface-evidence-backlog.md:49–51` records 610 cells / 536 clean / 74 poisoned, 3,927 rows / 491 surfaces / 81 classes; lines 67–68 record post-tranche 3,922 / 490 / 80. All match, including the +671 rows / +17 classes drift arithmetic.
5. **§3 rule 3 tooling — PASS.** `scripts/llp0045-route-evidence-diff.mjs` exists (16,862 bytes); `package.json:60` carries `test:llp0045-route-evidence-gate`.
6. **Spot checks — PASS with one imprecision.** 168-row delta = 23,765 − 23,597 ✓; commits `53409737` ("seal network owner hook aliases"), `8cf677e7` ("callback-argument attribution"), `63bd1933` ("prove direct environment writes") all exist with matching subjects; §3 rule 9's feature vector matches `llp/0039…decision.md:259` verbatim; "timeout policy v5" is real (`llp/0032…spec.md:8`); all four `checkPromotion` names exist at `run-capsec-conformance.mjs:1878–1897` and `assertReportMayAdvertise`/`assertRecipeCatalogComplete` at `:12–17`; `verify:capsec-conformance` (`package.json:21`) and `check:secure-mode` (`package.json:50`) exist; all three §11 evidence files exist under `llp/evidence/`; both cited issue files exist; LLP 0039:76–77 ("disappears when the default build can arm from a real conformance report") matches §1's non-goal and §10 item d. The imprecision: §4.1's "all 18 producers throw" (Concern 6).

#### 2. Overall assessment

This is the best-grounded plan in this corpus: every empirical claim I executed reproduced exactly, the construction rules genuinely encode the LLP 0045/0046 failure modes, and the Phase 1 ordering correctly preserves LLP 0044's review-before-gate-code constraint, including neutralizing the round-1 Fable MATERIAL #1 (rule 8 + §7.4 hold the "no conformance claim, never refused" line with negative controls demoted to evidence-not-proof). But the plan's own headline discipline — "every phase below has an entry gate and an exit gate that are commands" — is not implemented for three of its four phases, its Phase 1 gate-code enumeration silently drops the two consumers LLP 0044's table most explicitly marks as requiring amendment (portable report admission and the promotion-bundle cell invariant), no phase's exit gate ever discharges the 74 poisoned cells, and the kill criteria miss the single most plausible way this program dies slowly (in-scope inventory growth outrunning authoring). These are all fixable in one revision, and none produces an unsound published claim (the Phase 3 gates fail closed on every gap found), but a plan whose stated value is its gates should not ship with holes in the gates.

#### 3. Strengths

- **§2 ground truth is real.** Every number checked against the retained catalog, the backlog ticket, and git reproduced exactly — the first plan in this corpus authored against verified rather than asserted denominators, and it says so honestly ("Do not reuse these numbers without regenerating").
- **§3 rules 2–7 are the distilled LLP 0046 §8 lesson**, each traceable to a specific documented failure (string buckets, stale denominators, one-directional gates, the `net.Socket.connect` misattribution), not generic hygiene.
- **§1's objective is stated in gate names that exist in code** (`run-capsec-conformance.mjs:1878–1897`), so the definition of done is executable, not prose.
- **§5 preserves LLP 0044's hard ordering** (join matrix → review → gate code; register item 5 decided post-matrix) and §5.3's adversarial fixture list matches LLP 0044 §2's seven classes exactly.
- **§3 rule 8 / §7.4 neutralize the LLP 0044 Fable r1 MATERIAL #1**: the claim wording, the layer-naming rule, and the evidence-not-proof labeling are all carried forward intact.
- **§9's "prior estimates are hypotheses to test" posture and §10's clean register** (with the item-1-rejection branch named as a valid exit) are exactly right.

#### 4. Concerns

1. **MATERIAL — §5.1/§5.3: the two consumers LLP 0044 says must change are never scheduled.** LLP 0044 §2's consumer table marks **portable report admission** (`src/host/portable_target_admission.rs` — "must validate the scoped required set against the re-derived expansion instead") and the **portable promotion bundle cell invariant** (`capsec-portable-promotion-bundle.mjs` — "must accept out-of-scope `unsupported` cells listed in the bound scope artifact, and only those") as requiring amendment. Neither appears anywhere in LLP 0049: §5.1's join-matrix "including" list names the promotion authority, bundle verifier, lineage verifier, `build.rs` selector, target-cell bytes, and fixture catalog but not report admission; §5.3's gate-code list (generator, scoped `assertRecipeCatalogComplete`, `ScopedAdvertised`, introspection, fixtures) reads as exhaustive and includes neither. §7.3 then presupposes admission-side re-derivation ("re-derived at admission from the bound inventory") that nobody was told to build. The adversarial fixtures would eventually catch it, but the plan should not rely on its fixtures to discover its own missing work items. **Resolve:** name both in §5.3's gate-code list, or state that the gate-code worklist is "every consumer the join matrix marks scope-validating," making the matrix the authoritative worklist.
2. **MATERIAL — Summary vs body: the entry-gate promise is unimplemented.** The Summary asserts "every phase below has an **entry gate and an exit gate that are commands**," and §3 rule 5 requires each phase's entry gate to include a fresh catalog + scope measurement. Only Phase 3 has a written entry gate (§7). Phases 0, 1, and 2 have exit gates only; Phase 1's dependence on Phase 0's item-1 decision is implicit; Phase 2's entry is a prose sentence ("starts the moment Phase 0's exit gate passes" — which of Phase 0's two exit gates?). **Resolve:** write the entry gate (command + measurement + dependency) for each phase, or soften the Summary claim.
3. **MATERIAL — no exit gate ever discharges the 74 poisoned cells.** §5.2 lives in Phase 1, but §5.3's exit gate (review artifacts, item 5 decided, gate code + fixtures, `check:secure-mode`) never mentions them; Phase 2's exit gate covers "the clean set" only; Phase 3's entry gate is just "Phases 1 and 2 exit gates both passed." The 74 are in scope (610-cell scope, complete-cell unit), so `unresolved-in-scope === 0` cannot hold until they are audited out, grammar-excluded, or the scope is re-cut — yet the phase structure lets the program arrive at Phase 3 with that obligation undischarged, discovering it only when the ceremony fails. **Resolve:** add "§5.2 disposition complete (each of the 74: audited, grammar-excluded, or scope re-cut decided)" to Phase 1's exit gate.
4. **MATERIAL — §6's parallelism premise is overstated against §9's re-cut branch.** "Every clean row in scope is owed under any scope design" is true for scope-identity design outcomes but false under the §5.2/§9 fallback: if the 74 survive both routes and the scope is re-cut to "a narrower family set," clean rows already authored in dropped families were not owed. The plan neither bounds nor acknowledges that waste, and its rows-per-class-descending ordering is poisoning-blind. **Resolve:** either acknowledge the bounded waste explicitly (74/610 cells poisoned puts a ceiling on it) or order early tranches toward families with zero poisoned cells until §5.2 reports.
5. **MATERIAL — §4.2/§9: item 2's "physically refused" outcome has no branch.** The exit gate says "items 1–4 decided" and names only item-1 rejection as a plan-terminating outcome. If the author chooses the physically-refused posture on item 2 (LLP 0044 calls it "a materially larger runtime program whose cost would need its own estimate"), the claim wording, the `ScopedAdvertised` arm state, and Phase 3's publication step are all invalidated — and the plan is silent. **Resolve:** add "item 2 decided as physically-refused → this plan returns to the author for re-scoping/re-estimation" alongside the item-1 branch.
6. **MINOR — §4.1's http2 item is imprecise twice.** (a) "All 18 producers throw" conflates LLP 0046 §2's finding: four *producers* throw (http2.js:250/254/258/262); the other cells are field-initializing constructors and header-map members. (b) The pinned withdrawal (:9368–9371) is one of **three** effect-assertion sites in the `node_http2` block — `connect` → `network:connect` at :9355–9358 and `performServerHandshake` → `network:listen` at :9363–9366 also assert effects on throwing producers. Presumably those two land under the `unsupported-throwing-stub` disposition, but the item should say how the withdrawal and the stub disposition partition the 18, or the fix as pinned leaves two false effect assertions standing.
7. **MINOR — §4.1's track label contradicts its last item.** `ex_host_env_ambient_set` "disposition must be settled here" — but choosing a disposition for an in-scope class whose asserted effect is inactive in the secure profile is a semantic ruling (the backlog ticket calls it "a seeding/disposition review prerequisite" and "an explicit release constraint"), sitting in the track headed "code, no author decision needed." Either specify the disposition in the plan or move the ruling into the §4.2 packet.
8. **MINOR — §3 rule 7's "terminal-diff instrument" does not exist as an artifact.** The `8cf677e7` comparison was ad hoc (nothing under `scripts/` or `packages/ibex-devtools/src` implements per-edgeId unioned terminal-set diffing as a named tool). Rule 3's gate enumerates route-evidence fields from the data so it may subsume much of it, but the plan invokes rules 3 and 7 as two distinct per-batch instruments. **Resolve:** land the instrument (script + `package.json` entry) as a Phase 0 deliverable, or state that rule 7 is satisfied by rule 3's tool over the terminal fields.
9. **MINOR — §3 rule 3 operational trap:** `llp0045-route-evidence-diff.mjs` defaults `--scope network` and supports only `network|all` (`:42`, `:63–64`). Every fs+env+process batch must pass `--scope all` or the gate trivially passes on the rows that matter. One sentence in §6's loop fixes it.
10. **MINOR — §2/§11 vs rule 1's letter:** the authoring-time catalog exists only in a session scratchpad; no summary is retained under `llp/evidence/` (contrast the 0044 measurement's retained JSON). Re-derivable by an 11-second regen at `aaa007ad`, so not unsound — but the plan's own rule says prose inherits numbers from retained artifacts. Retain a summary at commit time.

#### 5. Answers to Q1–Q4

**Q1 (Phase 1 completeness).** Nearly complete, with two omissions — the report-admission re-derivation and the promotion-bundle cell invariant (Concern 1), the only two consumer-table rows LLP 0044 marks "must be amended" that LLP 0049 never names. Everything else maps: the armed-snapshot trio with the three sub-questions ✓, both advertisement chains with the v1 row-group treatment ✓, the six join-matrix artifacts ✓, all four LLP 0021 amendment elements ✓ (single-active-scope implicitly via the duplicate-scopes fixture), LLP 0032/0036 amendments ✓, all seven adversarial fixture classes verbatim ✓, `Host::new_armed_with_target_cells` via the `ScopedAdvertised` arm state ✓, the typed decision path correctly left unamended ✓. Nothing in Phase 1 exceeds what LLP 0044 requires before gate code: §5.2's audits run in parallel without gating the matrix, and re-reviewing the claim wording inside the package is justified by Phase 3's wording-immunity requirement.

**Q2 (phase ordering).** The Phase 1 ∥ Phase 2 design is sound in the main line and register item c's "wait for the decision packet" recommendation is right — but the justifying premise ("owed under any scope design") fails under the §9 scope re-cut branch (Concern 4); a Phase 1/§5.2 outcome *can* invalidate Phase 2 output, in exactly one way: re-cut to a narrower family set. No Phase 1 design outcome invalidates Phase 2 evidence otherwise (schema changes don't touch authored templates or pinned sequences; the ceremony re-executes everything at Phase 3). Phase 0's two tracks do have a hidden serialization the "two tracks" framing obscures: the §4.2 packet requires §4.1's post-seeding re-measurement (item 4 must be decided on numbers that include the `ex_host_env_ambient_set` resolution, which changes the in-scope counts), so 4.2 strictly follows 4.1's exit gate — worth stating, since a one-sitting packet assembled early would repeat the plan-against-stale-numbers error. And the ambient-set item itself straddles the tracks (Concern 7).

**Q3 (kill-criteria gaps).** Three plausible failure modes escape §9 and §3: (a) **the treadmill** — the scope is intensional, so in-scope inventory growth (+671 rows / +17 classes in five days is the plan's own cited precedent) continuously refills the worklist; kill criterion 1 measures authoring slope once at calibration, rule 5 re-cuts tranches routinely and §9 explicitly labels that "routine, not fatal" — so authoring at a healthy slope that is nonetheless slower than net in-scope growth triggers nothing, forever. Add a net-closure criterion (e.g., two consecutive phase-boundary re-measurements where the worklist shrank by less than the authoring throughput → return to author). (b) **Phase 1 review-loop non-termination** — the serial critical path has no round/time bound, and the corpus documents a reviewer with a permanent NOT READY stance; the author decides under LLP 0005, but a plan with kill criteria should name the trigger. (c) **Item 2 decided as physically-refused** (Concern 5). A fourth, weaker: a Phase 2 batch exposing a genuine *enforcement* defect (not an attribution pattern — those stop and file against LLP 0037) has no named stop rule, though ordinary ticket discipline probably covers it.

**Q4 (unenforceable §3 rules).** Rule 7 is the clear case: it mandates an instrument that does not exist as an artifact (Concern 8) — a rule whose checker must be built is a rule that gets skipped in week three. Rule 2 has no checker, actor, or artifact: nothing prevents a tranche plan from sizing against a residual-reason bucket except a reader remembering LLP 0046; requiring each tranche-plan work item to cite the emitting code (`file:line`) would make it checkable. Rule 9's "port-binding suites never run in parallel" names no enforcement mechanism, and Phase 2 explicitly fans out across agents and the machine fleet — this needs a runner-level lock or an explicit serial rule in the batch harness, not agent good behavior. Rule 3 is enforceable but has the silent `--scope network` default (Concern 9). Rules 1, 5, 6, and 8 have adequate artifacts/actors (§11 index, phase-boundary regen, the review package).

#### 6. Suggestions (non-blocking)

- §6: state the batch-evidence retention path/naming convention now (rule 1 says `llp/evidence/`; ~80 template classes of receipts need a scheme before the fan-out starts, not after).
- §4.1: add the `--scope all` flag and the seeding-fix allow-list location to the exit gate command, making it copy-pasteable per the Summary's "gates are commands" standard.
- §9: record the current in-scope inventory growth rate (rows/day) alongside the calibration metrics so the treadmill criterion (Q3a) has a measured baseline.
- §10 item e: the recommendation is sound, but note that Concern 1's two consumers are gate-changing code — their *implementation* rides Phase 1's formal loop regardless of this document's own review intensity.

#### 7. Open questions for the author

- When the join matrix marks a consumer scope-validating, does its amendment automatically join §5.3's gate-code worklist, or is §5.3's list intended as exhaustive? (Determines whether Concern 1 is an enumeration bug or a design decision.)
- Which of the 18 `node_http2` cells does the §4.1 withdrawal cover vs the `unsupported-throwing-stub` disposition, given the three distinct effect-assertion sites (:9355, :9363, :9368)?
- Is Phase 2's engine rebuilt when Phase 1's gate code lands mid-campaign (rule 9 pins the feature vector, but the engine binary digest recipes bind will drift across the race the §7 entry gate acknowledges)?
- Who runs the §4.2 sitting — and if the author amends a recommendation (e.g., item 4 to a different family set), does Phase 2's already-started calibration tranche survive?

#### 8. Recommended next step and verdict

One focused revision: add the two missing consumers to §5.3 (Concern 1), write the missing entry gates (Concern 2), close the poisoned-cell gating hole (Concern 3), add the item-2 and treadmill branches (Concerns 4, 5, Q3a), and sweep the MINORs — every fix is wording or a small deliverable addition; none disturbs the phase architecture, which is sound. Then execute; no second full review round is warranted if the delta is confined to these items.

**Verdict: NOT READY** — the plan's skeleton, ground truth, and ordering are right and fully verified, but a plan whose contract is "gates that are commands" cannot be executed as written while three phases lack entry gates, two required gate-code items are unscheduled, and its largest standing obligation (the 74) is outside every exit gate.

## Round 2 (delta, final round) — 2026-08-06

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent
  tool (independent context; distinct from the round-1 reviewer and from the
  authoring session)
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** delta round at document revision `629599dea0b3`, HEAD
  `aaa007ad`; executed the revision's new factual claims (http2 sites,
  evidence-file digest self-verification, rule 3 mechanism produceability);
  full disposition table over both families' round-1 concerns with
  IN-DELTA / PRE-EXISTING labels per the round-2 brief
- **Verdict:** NOT READY — narrowly, on one IN-DELTA MATERIAL; reviewer
  states "With edit 1 in either form, this reviewer is READY."

### Review body (verbatim)

**Reviewer:** independent adversarial reviewer (Claude/Fable family); did not author the document or its revision.
**Precondition:** `shasum -a 256 llp/0049-scoped-attestation-execution.plan.md` = `629599dea0b3266298f79989d42fa27e65b04760e026819bac8423ca3bc207b5` — matches the brief. `git rev-parse --short HEAD` = `aaa007ad`, branch `main`; `git status` shows exactly the four untracked files the brief describes (the LLP, the evidence summary, the two review artifacts). Proceeding.

#### 1. Delta-verification results (executed, not trusted)

1. **http2 site 1 — PASS.** `capsec-coverage-model.mjs:9355–9358`: `/^connect$/` → `effectSpec(["network:connect"], "network", "WP6", …)` — exactly as the doc partitions it (verified via `grep -n` line-numbered read of :9345–9375).
2. **http2 site 2 — PASS.** `:9363–9366`: `/^performserverhandshake$/` → `effectSpec(["network:listen"], …)`.
3. **http2 site 3 — PASS.** `:9368–9371`: `/^(?:http2serverrequest|http2serverresponse)(?:\.|$)/` → `effectSpec(["network:listen"], …)`.
4. **Four producers throw unconditionally — PASS (with a one-line-pin note).** `src/builtins/http2.js`: `function createServer()` :250, `createSecureServer()` :254, `connect()` :258, `performServerHandshake()` :262, each body a single `throw _createUnsupportedError(…)` (:251/:255/:259/:263). The doc pins the function-declaration lines; the throw statements are one line below each. Consistent with LLP 0046 (`llp/0046-network-terminal-provenance-measurement.research.md:97–105`, which also confirms the 9-refusal and 42-alias counts at :34, :69, :406–407).
5. **Evidence summary exists and digest self-verifies — PASS.** `shasum -a 256` of `llp/evidence/0049-authoring-catalog-summary-4381ae02a8c7ee5d4438debc5ad0b664b6fe291ea80fae34a6a3ff77dbd4758a.json` = `4381ae02…d4758a`, equal to its filename digest.
6. **Evidence counts match §2 — PASS.** File `summary`: requiredFixtures 23,765 / fullyExecutable 3,931 / internallyVerified 3,124 / unresolved 16,710 / adapterExecutable 11,680; `recipeCatalogDigest` = `sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY`; target `aarch64-apple-darwin`, profile `ibex/capsec/1`; `generatedAtHead: aaa007ad` — all five counts and the digest match the §2 table (llp/0049:113–126) and the §11 row (:627).
7. **Rule 3 advance-declaration mechanism — FAIL (as enforcement; see New Finding 1).** The tool exists and does what rule 3's core gate needs (`scripts/llp0045-route-evidence-diff.mjs`: default `{ scope: "network" }` at :43, `network|all` only at :63–64, mandatory non-empty `sourceSpan`/`proof`, post-diff skeleton per header :30–36 — all matching the doc's characterization). But the ordering mechanism (:182–188, "the allow-list's content digest is recorded in the batch's evidence envelope before the candidate catalog is generated") assumes machinery nothing produces or checks: `grep -rn 'allowListDigest|evidenceEnvelope|evidence envelope'` across `scripts/` and `packages/ibex-devtools/src` = zero hits; the only envelope precedent (`llp/evidence/0044-batch-timing-501504f6….json`) is a hand-authored JSON with no allow-list field; and §6 retains the envelope **at commit time, after** the regen and diff (:461–463), so the claimed "before" ordering is self-attested, not verifiable. §4.1's Phase 0 deliverable bullet (:272–276) lands the rule 7 instrument and the rule 9 lock but not an envelope schema or an ordering checker.
8. **Other load-bearing delta claims — PASS.** All named artifacts exist: `src/host/portable_target_admission.rs`, `capsec-portable-promotion-bundle.mjs`, `capsec-portable-engine-evidence-contract.mjs`, `generate-capsec-registry.mjs`; `new_armed_with_target_cells` in `src/host/mod.rs`; `ibex/capsec-target-advertisements/2` in the evidence-contract module; the LLP 0044 must-amend rows with the exact quoted obligations at `llp/0044-…rfc.md:289` and `:292`; the ambient-set ruling text at `issues/20260728-…backlog.md:73–79` ("five rows… ABI returns `-1`… explicit release constraint") matching §4.2 (:289–294); `issues/20260801-readline-…`, `issues/20260805-windows-rust-default-full-suite-broadly-red.md`, and both port-binding suites (`tests/node_net_builtins.rs`; `host_http_server` hits in `src/`) exist. Both round-1 review artifacts read in full.

#### 2. Disposition table

| Concern | Disposition | Where |
| --- | --- | --- |
| **Codex 1 (BLOCKER)** — §7 "refuses everything else" | **RESOLVED** | Phase 3 exit gate :519–527: remainder gets "exactly the disposition the reviewed `ScopedAdvertised` state specifies — a disposition, not a refusal claim," CI refusal properties name their exact layer, physical-entrypoint only if item 2 selected it |
| **Fable 1 / Codex 2** — must-amend consumers unscheduled; checklist/fixtures incomplete | **RESOLVED** | :327–329 matrix = authoritative worklist; both consumers named with their exact LLP 0044 obligations :339–346; v2 reader :347–350; closed v1 chain row group :351–353; `Host::new_armed_with_target_cells` :354–357; typed decision path scope-transparent :358–360; Go verifier :361–362; full lifecycle binding set :366–371; §5.3 "every consumer the matrix marks scope-validating (explicitly including… two must-amend consumers)" :405–407; fixtures gain observed-closure-escape :411–413, split/merge :413–414, adversarial-composition (diagnostic) :414–416; split/merge mapping artifacts :368–370 |
| **Fable 2 / Codex 5 (gates-are-commands part)** — entry gates missing, Summary overstates | **RESOLVED** | Summary rescoped :74–79 ("where it is a decision or a review outcome, the gate says so and names the artifact"); written entry gates: Phase 0 :241–244, Phase 1 :318–319, Phase 2 :448–450, Phase 3 :490–492 |
| **Codex 5 (rule-3/rule-7 checker part) / Fable Q4** | **PARTIAL** | Rule 7 → named tool `scripts/capsec-terminal-evidence-diff.mjs` as a Phase 0 deliverable with interim gate :203–212, :272–276 — resolved. Rule 2 → tranche-review `file:line` checker :170–174 — resolved. Rule 9 → `flock` on `target/.capsec-port-suite.lock`, Phase 0 :227–231 — resolved. Rule 3 advance declaration → the new mechanism is asserted but unproducible/unverifiable as written (New Finding 1); `MASKED, NOT NEW` still has no named checker (tool contains zero occurrences of `MASKED`) |
| **Codex 3 / Fable Q2** — Phase 0 exit only 1–4; hidden track serialization | **RESOLVED** | "strictly serialized" with the stale-numbers rationale :236–240; packet = items 1,2,3,4,6,8,9,10 :286–287; exit gate "all eight items plus the ambient-set ruling decided" :300–301; item 5 BLOCKED :295–296, item 7 deferred :296–297; Phase 2 entry requires §4.2 exit incl. item 9 :448–449 |
| **Fable 3** — the 74 in no exit gate | **RESOLVED** | §5.3 exit gate :418–425: "§5.2 disposition complete — each of the 74… audit-cleared, grammar-excluded…, or covered by a decided scope re-cut," with the `unresolved-in-scope === 0` unreachability argument stated |
| **Fable 4 / Codex 4** — parallelism premise vs re-cut; diagnostic split | **RESOLVED** | §6 "Everything Phase 2 executes is diagnostic," authoritative only at Phase 3 (absorbing engine/schema drift) :433–439; waste ceiling bounded by 74/610 geometry, early tranches to zero-poisoned families :440–446 |
| **Fable 5 / part of Codex 6** — item-2 physically-refused branch | **RESOLVED** | §4.2 diversion :305–309; §9 kill criterion :572–575 |
| **Codex 6 / Fable Q3** — cumulative reforecast, item-5 rejection, treadmill, review bound | **RESOLVED** | Net-closure treadmill :557–562 (baseline rate measured at calibration :481–483); cumulative reforecast, third-stop trigger :563–567; item-5 rejection halt :572–575 (also §5.3 exit :419–420); Phase 1 three-round bound per LLP 0005 :579–583; cumulative 15% drift threshold :584–588 |
| **Fable 6** — http2 three-site imprecision | **RESOLVED** | :261–268 partitions all three sites (verified above); four producers vs remaining cells stated with the stub disposition :265–268 |
| **Fable 7** — ambient-set in the wrong track | **RESOLVED** | Ruling moved into the §4.2 packet as "a semantic ruling for the author, not a code fix" :288–294; in the exit gate :300–301 |
| **Fable 8** — rule 7 instrument nonexistent | **RESOLVED** | Named script + `package.json` entry + schema as Phase 0 deliverable, interim rule stated :203–212, :272–276 |
| **Fable 9** — `--scope all` trap | **RESOLVED** | Mandated with the rationale in rule 3 :176–178; in the §4.1 exit gate :278–280; in the §6 loop :459–460 (tool default verified `network`, tool :43) |
| **Fable 10 / Codex 7** — catalog summary not retained | **RESOLVED** | Retained, digest-named, counts verified (checks 5–6); §2 :115–117, §11 :627 |

#### 3. New findings

1. **IN-DELTA — MATERIAL — rule 3's advance-declaration "enforcement" is a convention wearing an enforcement label** (llp/0049:182–188). The revision answers round-1 "cannot prove declaration occurred in advance" (Codex 5/Q4) with: *"Advance declaration is enforced by ordering: the allow-list's content digest is recorded in the batch's evidence envelope before the candidate catalog is generated."* Three defects, verified: (a) no envelope schema, producer, or field exists anywhere in the tooling (zero grep hits for any envelope/allow-list-digest machinery; the 0044 precedent is hand-authored JSON); (b) nothing can verify the ordering — §6 retains the envelope at commit time (:461–463), after the regen and the diff, in the same commit, so "before" is self-attested by the same actor the rule distrusts; (c) unlike rule 7's honestly-declared missing instrument, this checker is not scheduled — §4.1's deliverables bullet (:272–276) covers the terminal-diff tool and port lock only. By the document's own §3 preamble ("a rule with neither [checker nor artifact] is a rule that gets skipped in week three"), this sub-rule currently has neither, and the sentence claims otherwise — the one place the revision repairs a gate hole with wording rather than a mechanism. **Exact resolution (either):** (i) make the ordering checkable — have the catalog generator accept and embed the allow-list digest into the candidate catalog (or require the envelope/allow-list committed before generation and have the gate check commit ancestry), define the envelope schema, and add both to the §4.1 deliverables bullet; or (ii) delete "is enforced by ordering" and state it as a declared procedure verified at tranche review, matching rule 2's checker style.
2. **PRE-EXISTING — MINOR — `MASKED, NOT NEW` vocabulary has no named checker** (llp/0049:180–182; residue of Codex 5/Q4). The tool contains no occurrence of `MASKED`; the requirement is checkable only by a human reading proof text, and rule 3 names no reviewer for it. One clause assigning it to tranche review (alongside rule 2's checker) closes it.
3. **PRE-EXISTING — MINOR — producer line pins are declaration lines, not throw lines** (llp/0049:265–266). `http2.js:250/254/258/262` are the `function` lines; the `throw` statements are :251/:255/:259/:263. Harmless as a producer pin, but a document this precise about pins should say which it means — or pin the throws.

No other in-delta defect found: the serialization rationale, the waste ceiling arithmetic (74/610), the net-closure test semantics, the ambient-set five-row characterization, the item-count arithmetic ("all eight" = 1,2,3,4,6,8,9,10), the diagnostic-schema step (:508–514), and every named file, symbol, suite, and issue ticket checked out against the repo.

#### 4. Verdict

**NOT READY** — narrowly, and on one item. Every round-1 concern from both families is genuinely resolved in substance except one sub-part of Codex 5, and the revision's repair for exactly that sub-part introduced the document's only false claim: an enforcement mechanism that nothing produces, nothing checks, and nothing is scheduled to build. In a plan whose stated thesis is "no gate is satisfied by intent," a self-attested ordering labeled "enforced" is material by the document's own standard, and the loop ending here makes precision on it the point.

**Minimal flip set (one edit, plus one optional):**
1. Rule 3 (:182–188): either add the envelope schema + ordering verification (generator-embedded allow-list digest, or committed-before check) to the §4.1 Phase 0 deliverables bullet, or reword the sentence to a declared procedure checked at tranche review — dropping the word "enforced."
2. (Optional, same edit) Name tranche review as the `MASKED, NOT NEW` checker.

Nothing else blocks: the phase architecture, gates, worklist authority, fixture set, and kill criteria are complete, internally consistent, and verified against the repository, and every gate that matters fails closed. With edit 1 in either form, this reviewer is READY.

## Close-out ledger — 2026-08-06 (written by the loop orchestrator, not a reviewer)

The loop closed at two rounds by pre-declared design. The round-2 flip sets
from both families were applied in full (rule 3 reworded to a declared
procedure with the envelope mechanics scheduled as §4.1 deliverables;
scope-measurement tool + schema named and exit gates made copy-pasteable;
net-closure inequality corrected; geometric waste ceiling withdrawn;
enforcement-defect stop rule added; MASKED-NOT-NEW checker assigned to
tranche review; http2 throw-line pins). Final revision `a622cba8c65b` is
UNREVIEWED beyond `629599dea0b3`. Terminal verdicts: Fable r2 NOT READY
(stating "With edit 1 in either form, this reviewer is READY"; that edit
was applied in its mechanism-scheduling form), Codex r2 NOT READY (all
three flip-set items applied). Status remains Draft; acceptance and the
§10 register are the author's.

## Round 3 (execution-round delta) — 2026-08-07

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent
  tool (independent context; authored neither the plan nor any revision)
- **Date:** 2026-08-07
- **Redacted:** no (public-repo content only)
- **Method:** delta round on the 2026-08-07 execution-round revision
  (`4e2990432` + `f77b30a5f`), document revision `b945bf4dbfa7`, HEAD
  `f77b30a5f`; verified claims against the emitting code rather than the
  calibration summary, including a direct survey of every
  `classification == "effects"` executor in `src/bin/ibex/engine/`
- **Verdict:** NOT READY (1 BLOCKER, 5 MATERIAL, 6 MINOR)

### Review body (verbatim)

# Review — LLP 0049, round 3 (execution-round delta)

**Document:** `/Users/ccheever/projects/ibex/llp/0049-scoped-attestation-execution.plan.md`
**Revision on disk:** `b945bf4dbfa7` (`shasum -a 256 llp/0049-scoped-attestation-execution.plan.md | cut -c1-12`) — matches the brief.
**Repo HEAD:** `f77b30a5f` (`git rev-parse --short=9 HEAD`) — matches the brief. Working tree clean.
**Delta scope confirmed:** `git show --stat f77b30a5f` (72+/2−, plan file only) plus `4e2990432` (both dated 2026-08-07) together contain exactly the six items the brief lists. Reviewed as one delta.

---

## 1. Checks

**Verified**

- Doc revision and HEAD match the brief; the delta is `4e2990432` + `f77b30a5f`, both 2026-08-07 (`git log -1 --format=%ci 4e2990432`).
- Rule 10's checker discipline **genuinely exists in this repo for other artifacts**: `schemas/vectors/portable-engine-provenance-v1.valid.json` is consumed from JS (`packages/ibex-devtools/src/scripts/capsec-live-portable-engine-evidence.test.mjs:26`, `packages/ibex-devtools/src/scripts/capsec-portable-promotion-bundle.test.mjs:53`, `scripts/portable-engine-promotion-lineage.test.mjs:57`) and from Rust (`src/engine/portable_identity.rs:1328`, `src/bin/ibex/engine/capsec_exact_fixture_evidence_batch.rs:331`, `src/host/portable_target_admission.rs:2149`).
- The rule-10 BLOCKER fix actually landed and is discharged in code: `e11071717 fix(capsec): unify the scope artifact's canonical form across languages (review BLOCKER-1)`; the shared vector `schemas/vectors/capsec-scope-v1.valid.json` is now consumed by JS (`packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-65`) **and** by Rust through the production parser (`src/host/portable_target_admission.rs:2159-2176`, `generated_scope_vector_deserializes_through_the_production_parser`).
- Rule 11 is **enforced, not merely mentioned**, in §5.3: the exit-gate sentence at line 534 was edited by the delta to add "an independent review of the merged implementation, with break-tests (§3 rule 11)" (`git show f77b30a5f`, hunk at §5.3).
- §6's "closed table of eleven reviewed `process.env` read sources" is accurate: `src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs:176` — `const EXPECTED_SOURCES: [ExpectedSource; 11]`.
- §6's "largest in-scope class is 454 rows across 77 surfaces" is accurate: `surface.loader.route × [fs:list, fs:read]` = 454 rows / 77 surfaces in `llp/evidence/0049-scope-measurement-phase2-calibration-close.json`.
- §6's host-abi conclusion (no effectful receipt) holds, though for a reason the text states incorrectly — see MINOR 12. Both host-abi executors hard-assert zero typed decisions: `src/bin/ibex/engine/capsec_conformance_batch.rs:3111` and `:3552`.
- The module-loader executor cannot produce an effectful receipt: `src/bin/ibex/engine/capsec_conformance_batch.rs:3867` (`classification == "non-capability"`), `:3868`, `:3884` (`expected_typed_decision_count == 0`).
- §6's exit-gate command is real: `scripts/capsec-scope-measurement.mjs:39,49,67,218` supports `--assert clean-unresolved=0`. `scripts/capsec-terminal-evidence-diff.mjs` exists.
- Poisoned-cell count is internally consistent at **73**; the only three "74" occurrences (lines 40, 175, 180) are explicitly labeled historical.
- §5.3's "LLP 0021 §A9 matrix unchanged at 33 rows" checks out (`grep -c '^| M[0-9]' llp/0021-…plan.md` = 33), and M11/M26 exist as scope-transparent rows (`llp/0021-…plan.md:4541,4556`).
- The `ex_host_env_ambient_set` ruling is recorded in the backlog ticket (`issues/20260728-capsec-public-surface-evidence-backlog.md:73-74,123-126`).

**Failed**

- **§6's headline calibration claim is false against the code** — an effectful, source-bound executor exists for a second surface kind. See BLOCKER 1.
- **The calibration's surface-kind survey omits the loader family**, 56.8% of the worklist. See MATERIAL 2.
- **§9's new kill criterion has no operand** — no spike estimate exists, is required, or is retained. See MATERIAL 3.
- **Rule 11's own checker is unsatisfied by the review that produced it** — no implementation-review artifact exists in the repo. See MATERIAL 5.
- **§2's "81 template classes" contradicts its own retained artifact** (80). See MINOR 7.

**Could not verify**

- "`surface.startup.env`'s `env:write` cells are Android/Rust startup sources with no JS-invocable surface at all" — targeted greps over `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs` did not confirm or refute the source attribution.
- "`cargo test --lib` 719/0", "Rust scoped fixtures 14/0", "`check:secure-mode` green", "the fix is break-tested" — not re-run (another session may be on this machine) and no retained artifact exists to check them against.
- "Five of ten names differed" in the rule-10 incident — the fix commits exist (`e11071717`, `caac9ecd5`); I did not reconstruct the pre-fix field lists.
- The round-4 dual-READY claim and LLP 0044 register item 5 acceptance beyond the 33-row matrix and M11/M26 existence.

---

## 2. Overall assessment

The two new rules are the strongest part of the delta. Rule 10 is correctly generalized, not a war story: it names a checker that this repo already practices for `portable-engine-provenance-v1` across three JS test files and three Rust sites, and the scope artifact's incident was genuinely the *absence* of that practice, now remedied. Rule 11 is likewise a real gate, wired into §5.3's exit-gate sentence rather than merely asserted.

The problem is the other half of the delta. §6's calibration result — the finding the delta exists to record, and the sole premise under §9's new kill criterion and §10 item (f) — does not survive contact with the code. `src/bin/ibex/engine/capsec_public_builtin_batch.rs` is a complete effectful executor for `surface.builtin.export` with 205 recipes already authored on the advertised tuple over exactly the in-scope fs and env families, and `surface.builtin.export` is 10 in-scope classes and 673 authorable rows. The claim also contradicts itself two sentences later, where it concedes that `surface.startup.env` "has an effectful probe path." Meanwhile the surface family that genuinely has no effectful executor — the loader kinds, 31 classes and 2,220 rows, 56.8% of the worklist, including the plan's own "largest in-scope class" — is not mentioned in the calibration at all, and is what §10(f)'s recommended spike would silently land on.

This is precisely the failure mode §3 rule 2 exists to prevent, one level up: a section-defining conclusion inherited from a session summary rather than derived from the emitting code. It is worth noting that the calibration artifact itself (`llp/evidence/0049-calibration-tranche-report.json`, `costModelFindings[3]`) is scrupulously scoped — it says only native-op *had* an executor among **the classes examined**, and names only host.abi and startup.env. The plan promoted that bounded observation into an unbounded one. The honesty defect is in the document, not the evidence.

Secondary: §9's new criterion measures against a number that nothing produces; the gate-code status block's figures have no retained artifact and no §11 row, which is the compliance condition §11 states about itself; and §6 now contains a calibration result ("security-sensitive Rust, not template text") that flatly contradicts the section's own opening premise ("Authoring needs no gate code") while §6's exit gate carries no rule-11 review.

---

## 3. Findings

### BLOCKER 1 — §6 (calibration result), §10 item (f) — IN-DELTA

**"Only `native-op` has an executor that can produce an effectful source-bound receipt today" is false.**

`src/bin/ibex/engine/capsec_public_builtin_batch.rs` is an effectful, source-bound executor for `surface.builtin.export`:

- admits `classification == "effects"` — `:432` (selector), `:1042` (assertion);
- runs the full effect scenario matrix `"allow" | "deny" | "malformed" | "missing-attribution" | "wrong-principal"` — `:1043-1046`;
- asserts **observed** typed decisions against the pinned count — `:1078` (`typed_decisions.len() == invocation.expected_typed_decision_count`), with `:1076` rejecting legacy checks as typed evidence and `:1227` pinning each decision's evidence identity;
- is **source-bound** — `:1071` (source-descriptor JCS digest) plus per-export `sourceKey` pinning to `node_fs` (`:641`, `:790`, `:856`, `:905`) and `node_os` (`:629`);
- drives **real** filesystem effects with fixture setup (`prepare_invocation`, `:604-970`) and verifies physical postconditions (`verify_postcondition`, `:517-530`, e.g. `mkdirSync` directory existence per scenario);
- has **205 recipes already authored** for `aarch64-apple-darwin` (`:448-461`), whose own comment enumerates them as `fs:list` accessSync/existsSync/realpathSync/statfsSync, `fs:read` readFileSync/readlinkSync, `fs:write` appendFileSync/mkdirSync/truncateSync/writeFileSync, openSync's three branches, and opendirSync — all inside the fs+env+process scope;
- the invocation machinery is explicitly generic, per its own comment at `:641-647`: "All are driven by the generic export invocation script."

`surface.builtin.export` is **10 in-scope template classes / 673 authorable rows** (17.2% of 3,911), computed from `llp/evidence/0049-scope-measurement-phase2-calibration-close.json`. Extending it to new exports needs a reviewed-table edit (`:685` panics on an unreviewed fs export) — which is exactly the "small executor edit per family" cost §6 already reports for native-op, not new executor construction.

The claim is also self-contradicting: the very next bullet concedes `surface.startup.env` "has an effectful probe path" (verified: `capsec_public_startup_environment_batch.test.rs:703`, `:881` assert `classification == "effects"` with nonzero decision counts).

Downstream, §10(f) states "the ~79 remaining template classes are gated on Rust executor work of unmeasured size." Of those 79, the 10 native-op classes (200 rows) are not gated at all and the 10 builtin-export classes (673 rows) are gated only on table extension. The item's scale is overstated by roughly 873 rows and 20 classes.

**Resolves it:** replace the headline with what the code supports — *three* surface kinds have effectful executors today (native-op, general; builtin-export, general invocation machinery with a reviewed per-export validation table and 205 recipes landed; startup-env read, closed 11-source table) — cite `capsec_public_builtin_batch.rs:432,1042,1078,1071` and `capsec_public_startup_environment_batch.test.rs:176,703`; then re-derive §10(f)'s scale from a per-surface-kind breakdown of the retained measurement rather than from the exclusivity claim.

### MATERIAL 2 — §6 (calibration result), §10 item (f) — IN-DELTA

**The calibration's surface-kind survey omits the loader family, which is the majority of the worklist and the actual gating risk.**

From `llp/evidence/0049-scope-measurement-phase2-calibration-close.json`: `surface.loader.*` is **31 of 79 classes and 2,220 of 3,911 rows (56.8%)**, and contains §6's own cited "largest in-scope class" (`surface.loader.route × [fs:list, fs:read]`, 454 rows / 77 surfaces). The only loader executor in the tree hard-asserts non-capability and zero typed decisions (`capsec_conformance_batch.rs:3867,3868,3884`), and a grep for `classification == "effects"` across `src/bin/ibex/engine/*.rs` returns only three files (`capsec_conformance_batch.rs`, `capsec_public_builtin_batch.rs`, `capsec_public_startup_environment_batch.test.rs`) — none of which serves loader surfaces. So the loader family has no effectful path at all: the strongest available form of the plan's thesis, and it goes unrecorded.

This matters operationally: §10(f)(i)'s "highest-row non-`native-op` surface kind, chosen from a fresh per-surface-kind row distribution" resolves to `surface.loader.route` (1,195 rows) — the kind the calibration never examined — yet neither §6 nor §10 says so, and the option text reads as though the kinds were surveyed.

**Resolves it:** add the per-surface-kind row/class distribution (it is already computable from the retained artifact) to §6, name the loader family as the kind with no effectful executor and cite `capsec_conformance_batch.rs:3884`, and say in §10(f) which kind the spike resolves to under the current measurement.

### MATERIAL 3 — §9 (executor-cost kill criterion) — IN-DELTA

**"Exceeds its spike estimate by 2x" has no operand.**

`grep -n "estimate\|spike" llp/0049-…plan.md` returns the criterion at line 777 and §10(f)(i) at line 854. §10(f)(i) defines the spike as running "purely to measure the multiplier before committing" — a measurement, not an estimate. Consequences: (a) for the spike kind itself there is no prior estimate to exceed by 2x, so the criterion cannot fire where it most matters; (b) for every other kind, nothing states that the spike's measurement becomes their estimate; (c) no unit is named — engineer-hours, wall-clock, rows/day, and correction-loop iterations would each give a different verdict; (d) §11 carries no row for such an estimate, so §3 rule 1 does not bind it and no artifact will exist to check against.

Round 2 corrected the net-closure criterion for firing on any positive growth. This is the same class of defect reached by a different route: there, a wrong inequality; here, a missing operand. Applying the same arithmetic scrutiny, the criterion as written is unevaluable.

**Resolves it:** name the unit and the artifact — e.g. "engineer-hours of Rust executor work per surface kind, recorded at spike close as an `llp/evidence/` row and indexed in §11; that measurement is the estimate for every subsequent kind; a kind exceeding it by 2x stops scaling." Or withdraw the criterion until §10(f) is discharged.

### MATERIAL 4 — §6 (opening premise and exit gate) — IN-DELTA

**§6 now contradicts itself on whether Phase 2 produces gate code, and its exit gate omits rule 11 for work the same section calls security-sensitive Rust.**

Line 577: "Authoring needs no gate code, so this phase starts once Phase 0 completes and runs concurrently with Phase 1." Lines 677-678, added by the delta: "LLP 0036's 'small executor edit per family' is confirmed as the real unit of work, and it is **security-sensitive Rust, not template text**." Both stand in the same section.

Rule 11's motivating case is exactly this: 719 self-verified green Rust tests that still shipped a BLOCKER. If Phase 2's dominant work product is security-sensitive Rust executors, rule 11 applies to Phase 2 at least as strongly as to Phase 1 — yet §6's exit gate (lines 692-699) contains only the scope-measurement assert, envelope retention, and delta cleanliness. Rule 11 is therefore not over-fitted to its incident; it is *under-applied* relative to what the delta itself now knows.

**Resolves it:** correct §6's opening premise, and add rule 11 to §6's exit gate for every batch that lands an executor change (the batch-only, template-only path can stay exempt).

### MATERIAL 5 — §3 rule 11 checker, §5.3 gate-code status block, §11 — IN-DELTA (honesty)

**The rule-11 checker is unsatisfied by the very review that produced rule 11.**

Rule 11's checker (lines 320-322) says "the review artifact and the break-test results are part of the exit gate." `ls llp/reviews/` (45 files) contains no implementation-review artifact — only `0021-scoped-advertisement-amendment.{fable,codex}.md` (the *design package* review) and `0049-scoped-attestation-execution.{fable,codex}.md` (reviews of this plan). Greps for "break-test" across `llp/` and `issues/` return only this plan itself.

Separately, the 2026-08-07 status block's figures — "`cargo test --lib` 719/0", "the Rust scoped fixtures 14/0", "`check:secure-mode` green with `SECURE_SMOKE` reporting real enforcement", "the fix is break-tested" — carry no retained artifact and no §11 row, while §11's own preamble states "the plan is out of compliance if a §3 rule 1 figure lacks a row." The 719 figure is load-bearing: it is rule 11's entire justification.

To be fair to the delta: the *substance* is verifiable in code. The BLOCKER fix landed (`e11071717`) and the cross-language vector is consumed from both sides (`capsec-scope-artifact.test.mjs:53-65`; `portable_target_admission.rs:2159-2176`). What is missing is the record, in a delta whose whole thesis is that self-verified green is not evidence.

**Resolves it:** retain the implementation review under `llp/reviews/0049-phase1-implementation.<family>.md` with its break-test results, and add §11 rows for it and for the 719/14/`check:secure-mode` run. Alternatively drop the unretained figures from the status block and cite the review artifact alone.

### MATERIAL 6 — §10 item (f) — IN-DELTA

**Item (f) is simultaneously "the one genuinely open" trade and a decision already taken, its option set is incomplete, and it is out of order in the register.**

Line 850 calls (f) "the one genuinely open scope/budget trade"; line 858 records "author indicated agreement 2026-08-07" with option (i). The ledger block at lines 818-827 is dated 2026-08-06 and does not mention (f), so the register's own status-of-record contradicts the item body. A reader cannot tell whether (f) needs a decision.

The option set is also incomplete, and incomplete *because of* BLOCKER 1. Given that builtin-export already has a general effectful executor and native-op is unblocked, there is a fourth option the plan never considers: **exhaust the classes reachable through the executors that already exist before funding any new executor construction** — ~873 rows (10 builtin-export classes + 10 native-op classes) with no new executor at all, which would also produce a far better-grounded cost model than a single spike.

Finally, item (f) is printed between (d) and (e) (lines 850 and 864) — the register reads d, f, e.

**Resolves it:** record the (f) decision in the ledger with its date and resulting status; add the fourth option; move (f) after (e).

### MINOR 7 — §2 — PRE-EXISTING

§2 states "3,927 clean authorable rows across 491 surfaces in **81** template classes" (lines 169-170) and repeats 81 at line 184. The retained artifact it cites reports `templateClasses: 80` (`llp/evidence/0049-scope-measurement-postseeding-df1da4b5….json`), and §11's own calibration-close row says "80 → 79" (line 887). A §3 rule 1 figure disagreeing with the artifact it inherits from. **Resolves it:** correct both to 80.

### MINOR 8 — §6 (worklist) — PRE-EXISTING, aggravated by the delta

Line 604-605 still reads "the ~3,922 clean authorable rows across ~80 template classes" — the 2026-08-05 figure §2's own denominator note (lines 181-185) declares superseded. Current retained figure: 3,911 rows / 488 surfaces / 79 classes. The delta added a calibration result to this same section without restating its worklist. **Resolves it:** restate as 3,911/79 with the calibration-close artifact cited, keeping the rule-5 re-derivation caveat.

### MINOR 9 — §5.3 gate-code status block — IN-DELTA

The block says "the report-schema version seam closed repo-wide" and then lists "two report schemas colliding on id `/3`" as still open. A reader cannot tell whether the seam is closed. `schemas/capsec-conformance-report-v2.schema.json:3` is the only conformance-report schema on disk carrying a `$id`, so the "/3" collision is not locatable from the repo. **Resolves it:** name the two colliding files and scope the "closed repo-wide" claim to what it actually covers.

### MINOR 10 — §6 (fan-out method) — IN-DELTA

Most of the fan-out method is legitimately advice, but two parts are mechanically checkable and would be worth more as rules with commands than as prose: "verify each branch's true diff from its **merge base**" (`git diff $(git merge-base origin/main HEAD)..HEAD`) and one-worktree-per-agent (`git worktree list`). As written, a Phase 2 lead cannot tell whether these bind. **Resolves it:** either promote those two into §3 with the command as checker, or state explicitly that §6's fan-out method is non-binding operational advice.

### MINOR 11 — §6, §11 (calibration record) — IN-DELTA

The enforcement-defect stop is now discharged: `issues/20260806-exactwhich-declares-typed-effects-it-never-emits.md` is in `issues/closed/`, fixed by `54f69d0df feat(capsec): typed enforcement for __exactWhich`. §6 and §11 still present that class as stopped. Accurate as history, stale as status. **Resolves it:** one line noting the defect is fixed and the class re-authorable.

### MINOR 12 — §6 (host-abi characterization) — IN-DELTA

"`surface.host.abi`'s probe path admits only non-capability module-runner ABIs with zero expected decisions" is wrong about the mechanism though right about the conclusion. There are two host-abi executors: `execute_module_runner_host_abi_public_recipe` asserts `classification == "non-capability"` (`capsec_conformance_batch.rs:3539`), but `execute_host_abi_public_recipe` admits `classification == "effects"` with scenario `"branch-selection" | "no-effect"` (`:3091,3093`). What actually blocks an effectful receipt in both is the zero-decision assertion (`:3111`, `:3552`), not non-capability admission. Under §3 rule 2, a mechanism claim should name the emitting code. **Resolves it:** restate as "both host-abi executors pin `expected_typed_decision_count == 0` (`capsec_conformance_batch.rs:3111`, `:3552`)."

---

## 4. Verdict

**NOT READY.**

Rules 10 and 11 are sound, correctly generalized, and backed by a checker discipline this repo demonstrably practices — that part of the delta should stand. But §6's calibration section, which the delta exists to record and on which §9's new criterion and §10's new register item both depend, asserts an exclusivity about the executor landscape that the code contradicts, while omitting the surface family that carries the majority of the worklist and no effectful executor at all. A plan whose §3 rule 2 forbids sizing work from anything but the emitting code cannot size its own dominant unknown from an inherited summary.

**Minimal flip set:**

1. **BLOCKER 1** — correct §6's executor claim to the three-kind reality with `file:line` citations, and re-derive §10(f)'s scale from the per-surface-kind distribution instead of the exclusivity premise.
2. **MATERIAL 2** — record the loader family's 31 classes / 2,220 rows and its zero-decision-only executor in §6, and name which kind §10(f)(i)'s spike resolves to.
3. **MATERIAL 3** — give §9's executor criterion a named unit, a retained artifact, and an explicit statement that the spike measurement is the estimate for subsequent kinds; or withdraw it until (f) is discharged.
4. **MATERIAL 4** — fix §6's "Authoring needs no gate code" premise and add rule 11 to §6's exit gate for executor-changing batches.
5. **MATERIAL 5** — retain the Phase 1 implementation review artifact under `llp/reviews/` with its break-test results and add §11 rows for it and the 719/14/`check:secure-mode` figures, or drop those figures.
6. **MATERIAL 6** — reconcile item (f)'s open-vs-decided status in the ledger and add the fourth option (exhaust the ~873 rows reachable through existing executors first).

The MINORs are worth folding into the same pass but do not gate the flip.
