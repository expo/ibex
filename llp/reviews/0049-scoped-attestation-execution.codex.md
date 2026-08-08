# Reviews — LLP 0049 (Codex/OpenAI family)

## Round 1 — 2026-08-06

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.1,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`, brief on stdin
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** read-only review at `main` = `aaa007ad`, document revision
  `e84e9e9dd319`, mandatory execution pass (catalog digest + counts via jq,
  line pins, scope-identity greps, backlog-ticket cross-check) before prose
  review; targeted questions Q1–Q4 per the round-1 brief
- **Verdict:** NOT READY (1 BLOCKER, 5 MATERIAL, 1 MINOR)

### Review body (verbatim from codex exec stdout)

## 1. Execution-pass results

- **Precondition — PASS:** `shasum -a 256 llp/0049-scoped-attestation-execution.plan.md` returned `e84e9e9dd319ac0a…`; `git rev-parse --short=8 HEAD` returned `aaa007ad`; branch is `main`.
- **§2 catalog — PASS:** `jq '{recipeCatalogDigest,summary}' …/catalog-aarch64-apple-darwin.json` returned digest `sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY` and 23,765 required / 3,931 fully executable / 3,124 internally verified / 16,710 unresolved / 11,680 adapter-executable.
- **§4.1 line pins — PASS:** `builtinExportClassification` is at `capsec-coverage-model.mjs:8842`; the `node_http2` match and unconditional `network:listen` effect are at `:9368–9371`; the readline catch-all is at `:9644–9645`.
- **Scope identity — PASS:** `rg -n -i 'scopeDigest|scope-digest|scope_digest' src crates packages/ibex-devtools/src` returned zero hits; `ExpectedArmingIdentity` has no scope field in `crates/capsec-semantics/src/arming.rs:70–109`.
- **Scope accounting — PASS:** 610 cells / 536 clean / 74 poisoned / 3,927 rows / 491 surfaces / 81 classes appear at `issues/20260728-capsec-public-surface-evidence-backlog.md:47–54`; post-tranche 3,922 / 490 / 80 appears at `:66–70`.
- **Rule 3 tooling — PASS:** `scripts/llp0045-route-evidence-diff.mjs` exists; its package test entry is at `package.json:60`. The test file contains 14 `test(...)` entries.
- **Additional spot-check — PASS:** `jq .durationSeconds llp/evidence/0044-batch-timing-501504f6….json` returned `16.24`; the artifact records the intentionally loud `Sign.end` contract-mismatch failure.

## 2. Overall assessment

The empirical baseline is accurate, and the plan has absorbed most of LLP 0046’s lessons. It is not yet safe to execute literally. The Phase 3 exit gate reintroduces the rejected universal-refusal claim; Phase 1’s checklist omits named consumers and fixtures required by LLP 0044; Phase 0 can exit with downstream-blocking decisions unresolved; and Phase 2 can spend work against a scope that Phase 1 may re-cut. Several advertised “command gates” are also prose-only. These are repairable, but they require revision before execution.

## 3. Strengths

- §2’s catalog and scope figures reproduce exactly, including the live-denominator drift and post-tranche accounting (`llp/0049-scoped-attestation-execution.plan.md:80–124`; execution results above).
- §5 correctly treats the runtime scope join as undesigned, puts the join matrix before gate code, and preserves register item 5 as blocked until review (`:227–245`, `:276–295`; LLP 0044 `:299–320`, `:508–512`).
- §3 correctly carries forward symmetric route-diffing, bidirectional terminal reasoning, denominator remeasurement, exact secure features, and the warning that Lane B counts miss confident misattributions (`:126–174`; LLP 0046 `:427–439`).
- Phase 3 correctly rejoins Phases 1 and 2 at one source revision and retains LLP 0032’s same-runner, same-suite-instance, pre/post-attestation authority model (`llp/0049…:336–354`; LLP 0032 `:572–617`).
- §3 rule 8 and Phase 3’s release-note/negative-control wording correctly say that out-of-scope controls are evidence, not proof (`llp/0049…:160–166`, `:355–359`). This substantially addresses the original Fable MATERIAL objection (`llp/reviews/0044-scoped-advertisement-and-evidence-cost-collapse.fable.md:29`).

## 4. Concerns

1. **BLOCKER — §7, lines 364–367: the exit gate restores the unsound refusal claim.**  
   “Arms in-scope cells and refuses everything else” contradicts §3 rule 8 and LLP 0044’s normative statement that out-of-scope surfaces are uncertified and may remain callable (`llp/0049…:160–166`, `:364–367`; LLP 0044 `:186–213`, `:322–347`). Literal execution either makes an unsupported universal claim or silently switches to register item 2’s much larger physically-refused program. Resolve by replacing “refuses everything else” with the reviewed uncertified disposition, and require CI only to prove the exact admission/typed-gate/physical-entrypoint properties actually selected.

2. **MATERIAL — §5.1/§5.3: the Phase 1 checklist is not complete enough to prevent consumer omission.**  
   LLP 0044 expressly requires each consumer to be amended or shown scope-transparent (`llp/0044…:282–320`). The plan does not explicitly name portable report admission, `Host::new_armed_with_target_cells`, the typed decision path, `capsec-portable-engine-evidence-contract.mjs`, or the scope-transparent Go verifier; nor does it enumerate the complete lifecycle binding across recipe catalog, public evidence, report, attestation, promotion bundle, and admission result (`llp/0049…:234–254`; LLP 0044 `:288–305`). Its fixture list also omits adversarial compositions and an observed-closure-escape fixture, while “rename-mapping” omits split/merge mappings (`llp/0049…:278–291`; LLP 0044 `:191–203`, `:229–269`, `:349–359`). Resolve with an exact, checkable Phase 1 table copied from the consumer and lifecycle requirements, plus composition, closure-escape, split, and merge fixtures.

3. **MATERIAL — §4.2/§6: Phase 0’s exit gate permits downstream work while blocking decisions remain open.**  
   Phase 0 presents items 1–4, 6, 8, 9, and 10, but its exit requires only 1–4 (`llp/0049…:212–225`). LLP 0044 says item 6 blocks the scope schema, item 8 blocks the audits, item 9 blocks Phase 2 fan-out, and item 10 governs the formal review (`llp/0044…:513–527`). Section 10(c)’s recommendation that authoring wait for the decision packet is therefore not enforced (`llp/0049…:420–424`). Require decisions 1–4, 6, 8, 9, and 10 at Phase 0 exit, with only item 5 deferred and item 7 explicitly out of scope.

4. **MATERIAL — §6: parallel authoring is broader than the stable scope.**  
   The assertion that every clean row is owed “under any scope design” is false because §5.2 may re-cut entire families if poisoned cells survive (`llp/0049…:256–274`, `:297–306`). It also departs from LLP 0044’s scope-first rule, which says to author only after Proposals 1–2 land (`llp/0044…:411–431`). Phase 1 can also add closure cells or change evidence schemas and scope bindings (`llp/0044…:229–247`). Resolve by limiting parallel work to reusable template development and explicitly diagnostic runs, or to a minimum scope guaranteed to survive every fallback; regenerate and authoritatively execute all promotion evidence after the reviewed scope identity lands.

5. **MATERIAL — §3 and phase exits: important rules are not enforceable as claimed.**  
   The plan says every phase’s entry and exit gates are commands (`llp/0049…:45–48`), but the Phase 0, Phase 1, and Phase 2 gates mostly state conditions without exact commands or result artifacts (`:208–225`, `:293–295`, `:332–334`). Rule 3’s tool checks non-empty `sourceSpan` and `proof`, but cannot prove declaration occurred in advance and does not enforce the required `MASKED, NOT NEW` vocabulary; it even emits a post-diff allow-list skeleton (`scripts/llp0045-route-evidence-diff.mjs:228–253`, `:414–440`). Rule 7 names the `8cf677e7` method but no command, CI target, or output schema (`llp/0049…:155–159`; `rg --files scripts packages/ibex-devtools/src | rg -i 'terminal.*diff|diff.*terminal'` returned zero). Resolve by defining executable commands, canonical artifacts, expected fields, and responsible actors for every gate.

6. **MATERIAL — §9: the kill criteria do not cover repeated new attribution patterns or rejection of item 5.**  
   Phase 2 stops a family whenever D1–D4 do not cover its pattern (`llp/0049…:316–322`), but the eight-week criterion applies only to the initial calibration projection (`:393–406`). Repeated mid-campaign stops can make the program unbounded without triggering a reforecast. Likewise, Phase 1 requires item 5 to be decided but gives no termination or fallback if the author rejects the reviewed arm state (`:293–295`). Add cumulative reforecast thresholds and explicit halt/re-scope branches for item 5 rejection and repeated LLP 0037 escalations.

7. **MINOR — §2/§11: the verified catalog summary is not retained under the plan’s own evidence rule.**  
   Rule 1 requires inherited figures to come from artifacts under `llp/evidence/` (`llp/0049…:132–135`), but the evidence index gives only the digest (`:439–445`). `rg --fixed-strings 'sha256-z5QP…' .` finds only lines 83 and 441 of the plan; the reviewed 146 MB artifact is in temporary storage. Retain a compact canonical summary containing the command, source revision, full-catalog digest, target/profile, and counts.

## 5. Answers to Q1–Q4

**Q1. Is Phase 1 complete?**  
No. All three named LLP amendments—0021, 0032, and 0036—are present (`llp/0049…:278–280`), but the consumer/artifact checklist omits the explicit items and fixtures identified in Concern 2. The Lane C/D audits themselves are not prerequisites to generic gate-code implementation under LLP 0044; only audit outcomes that alter the scope grammar, obligation vocabulary, or selected scope need to enter the pre-code review package (`llp/0044…:361–409`). They must finish before scope freeze and promotion, but need not delay unrelated gate plumbing.

**Q2. Is phase ordering wrong?**  
Yes. Phase 0’s “two tracks” have a real dependency: the decision packet must include the post-seeding remeasurement, so seeding and remeasurement precede the decisions (`llp/0049…:208–220`). Phase 0’s exit omits decisions that block Phases 1 and 2. Phase 2 may safely develop templates in parallel, but its selected worklist can be invalidated by Phase 1’s scope re-cut, closure expansion, or schema design; any pre-scope execution must be explicitly diagnostic and cannot substitute for Phase 3’s authoritative run (`llp/0049…:297–334`; LLP 0032 `:163–168`, `:561–590`).

**Q3. Do the kill criteria have gaps?**  
Yes. A plausible uncovered failure is repeated discovery of new attribution patterns after calibration: each family stops, yet no cumulative threshold forces a new schedule/budget decision. Item 5 rejection is another unhandled terminal branch. Add mid-campaign reforecast triggers, a maximum unresolved-pattern budget, and an explicit response to rejection of the scoped arm state (`llp/0049…:316–322`, `:393–406`).

**Q4. Is anything in §3 unenforceable?**  
Yes. Rule 3 cannot establish that an allow-list was authored in advance or enforce `MASKED, NOT NEW`; rule 5 supplies neither a canonical measurement command nor a comparison artifact; rule 7 has no named checker or artifact; and rule 8 has no claim lint or assigned reviewer and is contradicted by §7 itself (`llp/0049…:132–166`; `scripts/llp0045-route-evidence-diff.mjs:228–253`, `:414–440`). The phase gates also fail the document’s claim that they are commands.

## 6. Suggestions

- Make the join matrix itself machine-readable and require an exact row set corresponding to LLP 0044’s consumer table and lifecycle.
- Split Phase 2 into “template development/diagnostic replay” and “scope-bound authoritative execution.”
- Add a cumulative drift threshold; repeated sub-5% boundary drift can otherwise evade the current rule indefinitely (`llp/0049…:147–151`, `:404–406`).
- Give negative controls a distinct diagnostic schema so they cannot accidentally enter promotion evidence.

## 7. Open questions

- Does §7’s “refuses everything else” intentionally select physical refusal, or is it stale wording?
- Which fs/env/process families are guaranteed to remain if §5.2 re-cuts the scope?
- Are all Phase 2 runs before Phase 1 completion intended to be diagnostic only?
- What happens if the author rejects register item 5 after the join-matrix review?
- Which command and artifact are intended to implement rule 7’s per-edge terminal-set diff?

## 8. Recommended next step

Revise the Phase 3 exit claim first, expand Phase 1 into an exact consumer/artifact/fixture checklist, repair the Phase 0 exit gate, and distinguish diagnostic template work from authoritative evidence. Add executable gate commands and the missing kill branches, retain the compact catalog summary, then request a narrow delta review.

This review could not be written under `llp/reviews/` because the workspace was read-only.

**Final verdict: NOT READY.**

## Round 2 (delta, final round) — 2026-08-06

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.1,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`, brief on stdin
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** delta round at document revision `629599dea0b3`, HEAD
  `aaa007ad`; executed the revision's new claims (http2 partition incl.
  the 16+2 cell arithmetic, evidence digest, rule 3 mechanism vs the
  exact-field batch envelope schema, ambient-set ABI behavior, flock
  precedent, net-closure algebra); full disposition table with
  IN-DELTA / PRE-EXISTING labels per the round-2 brief
- **Verdict:** NOT READY (three-item flip set: rule 3 enforceability,
  named scope-measurement command/schema + copy-pasteable exit gates,
  net-closure inequality)

### Review body (verbatim from codex exec stdout)

## 1. Delta-verification results

- **PASS — revision and repository state.** `shasum -a 256 llp/0049-scoped-attestation-execution.plan.md` returned `629599dea0b3266298f79989d42fa27e65b04760e026819bac8423ca3bc207b5`; `git rev-parse --short=8 HEAD` returned `aaa007ad`; `git status --short --branch --untracked-files=all` showed `main` plus exactly the LLP, evidence file, and two review artifacts as untracked.
- **PASS — http2 effect-site partition.** The model has `connect → network:connect` at `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:9354-9358`, `performServerHandshake → network:listen` at `:9363-9366`, and the request/response class-prefix `network:listen` at `:9368-9371`. The prefix covers the sixteen request/response entries listed at `:1841-1856`; adding `connect` (`:1857`) and `performServerHandshake` (`:1865`) gives the stated 18 effect-classified cells.
- **PASS — four unconditional http2 throwers.** `createServer`, `createSecureServer`, `connect`, and `performServerHandshake` immediately throw at `src/builtins/http2.js:250-263`. The request/response constructors instead initialize caller-supplied stream and header state at `:347-365` and `:392-406`, consistent with the revised partition.
- **PASS — retained catalog summary.** `shasum -a 256 llp/evidence/0049-authoring-catalog-summary-*.json` returned `4381ae02a8c7ee5d4438debc5ad0b664b6fe291ea80fae34a6a3ff77dbd4758a`, exactly matching the filename. `jq .summary` returned 23,765 required, 3,931 fully executable, 3,124 internally verified, 16,710 unresolved, and 11,680 adapter-executable, matching `llp/0049-scoped-attestation-execution.plan.md:120-126`.
- **FAIL — Rule 3 advance declaration is not implemented by existing machinery.** The diff tool validates only the allow-list entries supplied at invocation and accepts any non-empty free-form `proof`; it neither reads an envelope nor checks an allow-list content digest or `MASKED, NOT NEW` vocabulary (`scripts/llp0045-route-evidence-diff.mjs:228-256`). Its report records only the allow-list path, not its content digest (`:337-353`). The existing public batch envelope is exact-field validated and permits only `publicBatchEvidenceSchema`, `recipeCatalogDigest`, `loadedEngineIdentity`, and `executions`, so nothing currently produces the assumed field (`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2164-2185`). The new ordering prose at `llp/0049-scoped-attestation-execution.plan.md:183-186` therefore quietly assumes unplanned schema/writer/checker work.
- **PASS — ambient-set factual ruling.** The ABI returns `-1` before mutation when the insecure ambient projection is inactive (`src/host/abi.rs:10314-10331`), and the secure-profile/no-typed-decision consequence is recorded in the live backlog at `issues/20260728-capsec-public-surface-evidence-backlog.md:72-79`. Moving it into the author packet at `llp/0049-scoped-attestation-execution.plan.md:284-301` is correct.
- **PASS — proposed port lock is implementable on the target platform.** The repo already demonstrates a stock-macOS/Linux kernel `flock` implementation through Perl `Fcntl`, including blocking acquisition and stale-lock recovery (`scripts/hermes-version.sh:166-174,190-215`), although the CapSec batch-harness lock remains a Phase 0 deliverable.
- **FAIL — new net-closure predicate.** With worklist movement `W1 = W0 − A + G`, the condition “worklist shrinking by less than rows authored” at `llp/0049-scoped-attestation-execution.plan.md:557-562` simplifies to `G > 0`; it fires on any positive inventory growth, not when growth outruns authoring as the text claims.

## 2. Disposition table

### Codex round 1

| Concern | Disposition | Revised-document evidence |
|---|---|---|
| Codex 1 — universal refusal claim | **RESOLVED** | The exit now assigns the reviewed uncertified disposition and requires every asserted refusal property to name its exact layer (`llp/0049-scoped-attestation-execution.plan.md:519-527`). |
| Codex 2 — incomplete consumer/worklist and fixtures | **RESOLVED** | The matrix is authoritative (`:323-327`); report admission and promotion-bundle invariants are explicit (`:336-343`); v2 reader, armed host, typed path, Go verifier, and lifecycle bindings are named (`:344-366`); split/merge and closure/composition fixtures appear at `:368-370,409-416`. |
| Codex 3 — Phase 0 exits with blocking decisions open | **RESOLVED** | Tracks are serialized (`:236-240`), and all eight register items plus ambient-set must be decided (`:284-301`). |
| Codex 4 — premature authoritative Phase 2 work | **RESOLVED** | Phase 2 is explicitly diagnostic (`:433-439`); authoritative execution occurs only in Phase 3 (`:491-507`); zero-poisoned families are prioritized (`:440-446`). |
| Codex 5 — prose-only gates and unenforceable rules | **PARTIAL** | Entry gates and several mechanisms were added (`:242-244,318-319,448-450,491-492`; rules 2/7/9 at `:171-175,203-212,223-232`). Rule 3 still lacks the envelope field/checker described above, and Phase 0/2 exit gates still say “regenerated,” “measurement,” and “unresolved-in-scope” without exact commands or schemas (`:278-282,485-487`). |
| Codex 6 — repeated attribution stops and item-5 rejection | **RESOLVED** | Every post-calibration stop triggers reforecast; the third reopens budget (`:563-567`), and item-5 rejection halts for re-scope/re-estimation (`:572-575`). |
| Codex 7 — catalog summary not retained | **RESOLVED** | The artifact is named in §2 (`:111-117`) and indexed with full digest/path (`:625-627`); its content digest and counts passed above. |

### Fable round 1

| Concern | Disposition | Revised-document evidence |
|---|---|---|
| Fable 1 — missing must-amend consumers | **RESOLVED** | Authoritative matrix worklist and both consumers at `:323-343`; downstream implementation is exhaustive over scope-validating rows at `:395-416`. |
| Fable 2 — missing entry gates / overstated Summary | **RESOLVED** | Summary now distinguishes commands from decisions/review artifacts (`:74-79`); entry gates exist at `:242-244,318-319,448-450,491-492`. |
| Fable 3 — 74 poisoned cells outside exit gates | **RESOLVED** | Phase 1 cannot exit until every poisoned cell is audit-cleared, grammar-excluded, or covered by a decided re-cut (`:418-425`). |
| Fable 4 — re-cut can waste Phase 2 work | **RESOLVED** | Runs are diagnostic and must be re-executed authoritatively (`:433-439`); early work is restricted to zero-poisoned families until §5.2 reports (`:440-446`). The separate geometric-bound wording has a new MINOR issue below. |
| Fable 5 — no physically-refused branch | **RESOLVED** | The outcome diverts at Phase 0 (`:300-309`) and is repeated as a kill branch (`:572-575`). |
| Fable 6 — imprecise http2 partition | **RESOLVED** | All three sites and the four throwing producers are distinguished at `:259-269`; source verification passed above. |
| Fable 7 — ambient-set ruling in wrong track | **RESOLVED** | It is now an explicit author ruling in the §4.2 packet (`:284-301`). |
| Fable 8 — terminal-diff instrument absent | **RESOLVED** | The instrument is explicitly a Phase 0 deliverable with path, behavior, package entry, and tests (`:203-212,272-276`). |
| Fable 9 — omitted `--scope all` | **RESOLVED** | It is mandatory in rule 3, Phase 0, and every Phase 2 batch (`:176-179,278-280,455-460`). |
| Fable 10 — catalog summary absent | **RESOLVED** | §2 and §11 name the digest-addressed artifact (`:111-117,625-627`); verification passed above. |

### Q3/Q4 sub-findings

| Sub-finding | Disposition | Revised-document evidence |
|---|---|---|
| Fable Q3a — inventory treadmill | **PARTIAL** | A criterion was added at `:557-562`, but its predicate is mathematically wrong and fires whenever growth is merely positive. |
| Fable Q3b — unbounded Phase 1 review loop | **RESOLVED** | Three-round bound and author handoff at `:579-583`. |
| Fable Q3c — physically-refused item 2 | **RESOLVED** | `:300-309,572-575`. |
| Fable Q3d — genuine enforcement defect during authoring | **UNRESOLVED** | Phase 2 stops and files only for attribution patterns outside D1–D4 (`:470-473`); the kill list at `:553-588` adds no enforcement-defect branch. |
| Codex Q3 — repeated attribution-pattern stops | **RESOLVED** | Per-stop reforecast and third-stop bound at `:563-567`. |
| Codex Q3 — item-5 rejection | **RESOLVED** | `:572-575`. |
| Codex suggestion — cumulative sub-5% drift | **RESOLVED** | Cumulative 15% full-replan threshold at `:584-588`. |
| Fable Q4 — Rule 2 lacks checker | **RESOLVED** | Every tranche item must cite emitting `file:line`, enforced at tranche review (`:171-175`). |
| Fable Q4 — Rule 3 defaults to network | **RESOLVED** | Mandatory `--scope all` at `:176-179,278-280,459-460`. |
| Fable Q4 — Rule 7 lacks instrument | **RESOLVED** | Phase 0 deliverable at `:203-212,272-276`. |
| Fable Q4 — Rule 9 lacks concurrency enforcement | **RESOLVED** | Batch-harness advisory lock is explicit and assigned to Phase 0 (`:223-232,272-276`). |
| Codex Q4 — Rule 3 cannot prove advance declaration or vocabulary | **UNRESOLVED** | Prose asserts digest ordering at `:183-186`, but existing code checks neither an envelope digest nor `MASKED, NOT NEW` (`scripts/llp0045-route-evidence-diff.mjs:228-256,337-353`; batch schema `capsec-public-surface-evidence.mjs:2164-2185`). |
| Codex Q4 — Rule 5 lacks canonical measurement command/artifact | **PARTIAL** | Retention and comparison policy are specified (`llp/0049…:192-199`), but “catalog regen plus scope measurement” does not identify the scope-measurement command or output schema; Phase 0 repeats the prose-only measurement (`:278-282`). |
| Codex Q4 — Rule 7 lacks checker/artifact | **RESOLVED** | `:203-212,272-276`. |
| Codex Q4 — Rule 8 lacks review enforcement and contradicts §7 | **RESOLVED** | Exact claim wording is a required review artifact (`:213-222,397-401`), and §7 no longer contradicts it (`:519-527`). |
| Codex Q4 — phase gates remain prose-only | **PARTIAL** | Entry gates were added, but Phase 0 and Phase 2 exit conditions still omit exact invocations/output schemas (`:278-282,485-487`). |

## 3. New findings

1. **IN-DELTA — MATERIAL — the net-closure test implements the wrong inequality.**  
   `llp/0049-scoped-attestation-execution.plan.md:557-562` says that if net shrink is less than authored rows, authoring is “losing to growth.” For authored rows `A` and new inventory `G`, net shrink is `A−G`; `A−G < A` means only `G>0`. The plan would return to the author after two boundaries with any positive inventory growth, even while authoring closes work much faster than growth adds it.  
   **Exact resolution:** trigger when net worklist movement is non-decreasing (`W1 >= W0`, equivalently `G >= A`), or define a measured closure-rate/deadline threshold if some positive but slower net closure is also unacceptable.

2. **IN-DELTA — MINOR — “74 of 610” is not a ceiling on wasted authored rows.**  
   The new sentence says re-cut exposure is bounded by poisoned-cell geometry (`llp/0049-scoped-attestation-execution.plan.md:440-445`). A single poisoned cell can cause its whole family—and all clean rows in that family—to be dropped, so the ratio `74/610` does not bound row or template-class waste. The following zero-poisoned-family ordering is the sound operational mitigation (`:444-446`).  
   **Exact resolution:** delete the geometric-ceiling claim, or replace it with a measured maximum count of clean rows/classes belonging to families eligible for re-cut.

## 4. Verdict

**NOT READY.**

The minimal flip set is:

1. Make Rule 3’s ordering enforceable: schedule a Phase 0 envelope/schema change that records a canonical allow-list content digest before candidate generation; make the diff gate recompute and compare that digest; add a machine-checked proof kind for `MASKED, NOT NEW`; and test that a post-diff allow-list cannot directly pass (`llp/0049…:176-186`; current gap at `scripts/llp0045-route-evidence-diff.mjs:228-256,337-353`).
2. Name the exact scope-measurement command and retained result schema, and give Phase 0/2 exit gates copy-pasteable commands plus expected artifacts (`llp/0049…:192-199,278-282,485-487`).
3. Correct the net-closure inequality at `llp/0049…:557-562`.

The enforcement-defect branch and geometric-bound wording should also be cleaned up, but neither alone would keep the document from READY once the three items above are fixed.

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

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.147.0,
  `-c model_reasoning_effort="xhigh"`,
  `--dangerously-bypass-approvals-and-sandbox` on a dedicated build host,
  brief on stdin
- **Date:** 2026-08-07
- **Redacted:** no (public-repo content only)
- **Method:** delta round on the 2026-08-07 execution-round revision,
  document `b945bf4dbfa7`, HEAD `f77b30a5f`; verified the executor claims
  against the emitting code and found an independent counterexample to the
  one Fable found
- **Verdict:** NOT READY (0 BLOCKER, 4 MATERIAL, all IN-DELTA).
  "No BLOCKER was found: the implementation remains explicitly gated
  rather than falsely declared complete."

### Review body (verbatim excerpt from codex exec stdout)

   101	}
   102	
   103	#[test]
   104	fn every_invalid_vector_is_refused() {
   105	    let valid = read("diagnostic-audit-v1.valid.json");
   106	    let mutations = read("diagnostic-audit-v1.invalid.json");
   107	    let cases = mutations["cases"].as_array().expect("cases array");
   108	    assert!(!cases.is_empty(), "the mutation corpus must not be empty");
   109	
   110	    for case in cases {
   111	        let id = case["id"].as_str().expect("case id");
   112	        let document_name = case["document"].as_str().expect("case document");
   113	        let mut document = valid["documents"][document_name].clone();
   114	        assert!(
   115	            !document.is_null(),
   116	            "{id}: names an unknown document {document_name}"
   117	        );
   118	        assert!(
   119	            accepts(document_name, &document),
   120	            "{id}: the unmutated document must be accepted, or the case proves nothing"
   121	        );
   122	
   123	        let path = case["mutationPath"].as_str().unwrap_or("");
   124	        apply_mutation(&mut document, path, &case["mutation"]);
   125	        assert_eq!(
   126	            case["expected"].as_str(),
   127	            Some("invalid"),
   128	            "{id}: this corpus holds only refusal cases"
   129	        );
   130	        assert!(
   131	            !accepts(document_name, &document),
   132	            "{id}: mutation was accepted but must be refused ({})",
   133	            case["why"].as_str().unwrap_or("no rationale recorded")
   134	        );
   135	    }
   136	}

codex
# Round 3 review — LLP 0049 execution-round delta

## 1. Verified / failed checks

- **VERIFIED — document identity:** on-disk SHA-256 is `b945bf4dbfa7212203dad05b67be7a9c7537e06b00e883b0821e5f82f8f3467d`, and HEAD is `f77b30a5f`; both match the brief. Command: `sha256sum llp/0049-scoped-attestation-execution.plan.md && git rev-parse --short=9 HEAD`.
- **VERIFIED — review target:** the execution-round delta is the two commits `4e2990432` and `f77b30a5f`; earlier review artifacts are present. Command: `git log --oneline -- llp/0049-scoped-attestation-execution.plan.md`; `llp/reviews/0049-scoped-attestation-execution.{fable,codex}.md`.
- **VERIFIED — indexed evidence exists:** every concrete artifact named in §11 exists and parses as JSON; `./ref-check` also reports zero errors. `llp/0049-scoped-attestation-execution.plan.md:871-889`; commands: `jq empty llp/evidence/*.json` for the indexed paths and `./ref-check`.
- **VERIFIED — the incident-specific scope vector is consumed on both sides:** JavaScript validates its canonical form/schema/digest, while Rust parses it through the production parser; both targeted tests pass. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`; `src/host/portable_target_admission.rs:2159-2177`; commands: `bun test packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs` and `cargo test --lib generated_scope_vector_deserializes_through_the_production_parser`.
- **VERIFIED — this discipline exists for another cross-language artifact:** diagnostic-audit vectors are consumed by independent JavaScript and Rust tests, including negative mutations. `packages/ibex-devtools/src/scripts/diagnostic-audit-schemas.test.mjs:18-29,56-80`; `crates/capsec-semantics/tests/diagnostic_audit_vectors.rs:71-135`; both targeted suites passed.
- **FAILED — rule 10 is not a repo-wide invariant:** its opening includes process boundaries, but its named checker covers only different-language producer/consumer pairs; existing Rust-produced/JavaScript-consumed public-batch evidence has no vector under `schemas/vectors/`. `llp/0049-scoped-attestation-execution.plan.md:299-312`; `src/bin/ibex/engine/capsec_conformance_batch.rs:4252-4267`; `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2144-2185`; command: `rg -n 'capsec-public-batch-evidence' schemas/vectors` returns no matches.
- **FAILED — “generated by the real producer” is not continuously checked:** the scope test reads committed bytes but neither regenerates them nor compares them with real-producer output. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`; command: `rg -n 'capsec-scope-v1.valid|generate.*scope.*vector' packages src schemas`.
- **FAILED — rule 11 is not enforced consistently:** §5.3 mentions review and break-tests, but Phase 0, Phase 2, and Phase 3 exit gates omit the supposedly every-phase requirement. `llp/0049-scoped-attestation-execution.plan.md:212-218,313-322,380-395,531-539,692-699,731-739`.
- **FAILED — the Phase 1 implementation-review discharge is not auditable:** the status records `719/0`, a BLOCKER, a neutered-assertion fixture, and fixes, but §11 contains no implementation-review artifact, reviewed revision, break-test commands/results, or finding disposition. `llp/0049-scoped-attestation-execution.plan.md:563-573,871-889`; command: `rg -n '719|wrong layer|assertion.*deleted|implementation review|break-tested' llp issues`.
- **FAILED — “only native-op has an effectful executor” is false as written:** the existing startup-environment executor runs loaded-engine sources, collects typed `env:read` decisions, validates them, and emits public-surface evidence. `packages/ibex-devtools/src/scripts/capsec-startup-environment-probe-templates.mjs:1-14,21-25`; `src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs:1072-1153,1285-1399,1737-1749`. The calibration artifact itself acknowledges that effectful path. `llp/evidence/0049-calibration-tranche-report.json:89-94`.
- **PARTIALLY VERIFIED — the two rejected candidate conclusions are narrower than the false universal claim:** `surface.host.abi × env:read` lacks an effectful executor, although host ABI has both non-capability module-runner and SQLite no-effect paths; the startup-env write candidates resolve to Android/Rust sources without the existing JavaScript read surface. `src/bin/ibex/engine/capsec_conformance_batch.rs:3078-3114,3503-3555`; `src/engine/native_android_networking.cc:344-350`; `issues/20260728-capsec-public-surface-evidence-backlog.md:123-132`.
- **VERIFIED — the completed calibration classes required executor work:** both retained batch artifacts record executor changes, and one records three generalization corrections. `llp/evidence/0049-batch-native-op-env-read-5EaSZqHyeHyZJ-kTorqcdNdYgBW-3wBtmZBbsIu4aV8.json:46-66`; `llp/evidence/0049-batch-native-op-fs-list-dzsLtlA9UI-XM0XnyrhbqwM-_XefBhoVPmkeqvcXVVg.json:46-66`.
- **FAILED — §9’s executor-cost kill criterion is not measurable:** no spike estimate, unit, per-kind baseline, or estimate artifact exists; “exceeds its spike estimate by 2x” also lacks the explicit arithmetic used by the corrected net-closure criterion. `llp/0049-scoped-attestation-execution.plan.md:769-781,850-862`; command: `rg -n 'spike estimate|executor-construction cost|per-surface-kind executor' llp issues`.
- **FAILED — §10(f) is not a coherent fork:** option (i) is an information-gathering precursor to choosing between scaling, narrowing, or a hybrid, yet it is presented as mutually exclusive with those choices and simultaneously described as author-agreed. `llp/0049-scoped-attestation-execution.plan.md:850-862`.
- **FAILED — the fan-out method is not “measured” in the retained-evidence sense:** §6 gives useful operational advice, but records no sample, branch measurements, comparison, or §11 artifact. `llp/0049-scoped-attestation-execution.plan.md:617-630,871-889`.
- **VERIFIED — poisoned-cell counts are internally reconciled:** the current plan and execution evidence use 73; the backlog’s earlier 74 is dated and explicitly superseded. `llp/0049-scoped-attestation-execution.plan.md:167-186`; `llp/evidence/0049-calibration-tranche-report.json:13-30`; `issues/20260728-capsec-public-surface-evidence-backlog.md:47-54,81-93`.
- **FAILED — one same-snapshot class count remains inconsistent:** §2 says 81 classes, while its post-seeding evidence records 80. `llp/0049-scoped-attestation-execution.plan.md:167-170`; `llp/evidence/0049-scope-measurement-postseeding-005189b86117530799564848414872280858a685a5f5dd0adddfe04cc529a238.json:39-44`.
- **VERIFIED — Phase 1 is not dishonestly marked complete:** the dated status block explicitly leaves report-schema collisions, weak fixtures, unpinned materials, and poisoned cells open. `llp/0049-scoped-attestation-execution.plan.md:563-573`.

## 2. Overall assessment

The delta captures two real failures and makes Phase 1 more candidly fail-closed. The shared-vector repair is also backed by executable tests.

It is not ready as a governing execution plan, however. Rule 10 overstates the scope of the implemented discipline; rule 11 is added only to the gate that suffered the incident and lacks an auditable discharge contract; §6 turns a candidate-specific calibration result into a false executor-wide claim; and the new cost kill criterion has neither a recorded estimate nor defined arithmetic. These are MATERIAL plan defects, not editorial polish.

No BLOCKER was found: the implementation remains explicitly gated rather than falsely declared complete.

## 3. Findings

### MATERIAL — §6 and §10(f): executor conclusion overclaims the evidence — IN-DELTA

“Only `native-op` has an executor capable of producing an effectful, source-bound receipt” is contradicted by the startup-environment batch executor, which executes loaded-engine sources and validates typed `env:read` decisions. `llp/0049-scoped-attestation-execution.plan.md:667-678,850-854`; `src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs:1072-1153,1285-1399`.

The evidence supports a narrower conclusion: neither of the two selected non-native candidate classes was reachable through an existing suitable executor without construction or extension. The host-ABI prose is also incomplete because a SQLite no-effect path exists alongside the non-capability module-runner path. `src/bin/ibex/engine/capsec_conformance_batch.rs:3078-3114,3526-3555`.

**Resolution:** replace the universal assertion with a retained per-surface-kind capability matrix distinguishing no executor, no-effect executor, effectful closed-table executor, and reusable effectful executor. Rewrite §6 and §10(f) from that matrix.

### MATERIAL — §3 rule 10: generalized beyond its checker and current conformance — IN-DELTA

The rule covers artifacts crossing a language **or process** boundary, but its only concrete checker is specified for different-language pairs. Existing public-batch evidence crosses both Rust→JavaScript and a process boundary without a `schemas/vectors/` vector. `llp/0049-scoped-attestation-execution.plan.md:299-312`; `src/bin/ibex/engine/capsec_conformance_batch.rs:4252-4267`; `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2144-2185`.

The repository demonstrates that shared vectors are an effective discipline, but it does not demonstrate that every cross-boundary artifact follows it. Nor does the scope-vector test prove ongoing real-producer generation. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`.

**Resolution:** either narrow rule 10 to independently implemented, security-relevant wire artifacts, or inventory all applicable boundaries and add vectors/tests for each. Define a checker for process-only boundaries and require regeneration/equality from the real producer, not merely validation of committed bytes.

### MATERIAL — §3 rule 11 and phase exits: process gate is incident-specific and unauditable — IN-DELTA

Rule 11 says every implementation phase receives independent adversarial review, but only Phase 1’s exit gate was amended. Phase 2 explicitly includes new Rust executor construction yet has no corresponding review item. `llp/0049-scoped-attestation-execution.plan.md:313-322,531-539,675-678,692-699`.

The Phase 1 status assertion is retained only as prose. It lacks the reviewed revision, reviewer identity/independence statement, adversarial mutations, commands and outputs, verdict, and disposition of unresolved findings. `llp/0049-scoped-attestation-execution.plan.md:563-573,871-889`.

**Resolution:** add the gate to every implementation-bearing phase—or explicitly scope and justify exemptions—and define discharge as a retained artifact tied to an exact revision, with break-test commands/results and no unresolved BLOCKER/MATERIAL findings unless explicitly dispositioned.

### MATERIAL — §9 and §10(f): kill arithmetic and decision state are undefined — IN-DELTA

The criterion cannot be evaluated because no spike estimate or measurement unit exists. A spike on one surface kind also cannot supply an estimate for “any surface kind” without an extrapolation rule. `llp/0049-scoped-attestation-execution.plan.md:777-781,850-862`.

Option (i) is a measurement step, not an alternative to the eventual campaign decision. “Author indicated agreement” leaves it unclear whether the spike is already authorized or still open.

**Resolution:** define and retain `E_k` and `C_k`, their units and scope, and an unambiguous predicate such as `C_k > 2 × E_k`. Split §10(f) into: (1) authorization and budget for the spike; and (2) a post-spike choice among staged expansion, broad construction, shared-executor investment, hybrid scope, or narrowing.

### MINOR — §6: fan-out method is guidance presented as measurement — IN-DELTA

No retained artifact shows the claimed measurement or compares this method against alternatives. `llp/0049-scoped-attestation-execution.plan.md:617-630,871-889`.

**Resolution:** call it retrospective guidance, or make it enforceable by recording branch, merge base, changed paths, integration owner, and reconciliation results for each tranche. If mandatory, promote those checkable requirements into §3.

### MINOR — §6/§11: calibration source revision is not reproducible — IN-DELTA

The calibration report and batch artifacts identify commit `6416114…` while explicitly saying the measured worktree was uncommitted. `llp/evidence/0049-calibration-tranche-report.json:5`; both `llp/evidence/0049-batch-native-op-*.json:5`.

**Resolution:** add the exact landed commit mapping, tree/patch digest, or rerun and restamp the artifacts against a committed tree.

### MINOR — §2: post-seeding class count is stale — PRE-EXISTING

The prose gives 81 classes for a snapshot whose retained artifact gives 80. `llp/0049-scoped-attestation-execution.plan.md:167-170`; `llp/evidence/0049-scope-measurement-postseeding-005189b86117530799564848414872280858a685a5f5dd0adddfe04cc529a238.json:39-44`.

**Resolution:** change 81 to 80 or identify the distinct snapshot underlying 81.

### MINOR — §5.3: successive “now” status blocks obscure current state — IN-DELTA

The 2026-08-06 block says gate code is still open; the immediately following 2026-08-07 block says it landed. Dates make the history recoverable, but “now” is stale in the earlier block. `llp/0049-scoped-attestation-execution.plan.md:541-573`.

**Resolution:** label the first block “superseded historical status” and keep one explicit current Phase 1 gate ledger.

## 4. Verdict

**NOT READY**

Minimal flip set:

1. Correct the executor claim using a retained per-surface-kind capability matrix.
2. Narrow or fully mechanize rule 10, including real-producer regeneration and process-only boundaries.
3. Turn rule 11 into an auditable gate for every implementation-bearing phase and retain the Phase 1 review/break-test artifact.
4. Record the spike estimate, units, and exact kill arithmetic; separate the agreed spike from the post-spike scope decision.
tokens used
330,540
# Round 3 review — LLP 0049 execution-round delta

## 1. Verified / failed checks

- **VERIFIED — document identity:** on-disk SHA-256 is `b945bf4dbfa7212203dad05b67be7a9c7537e06b00e883b0821e5f82f8f3467d`, and HEAD is `f77b30a5f`; both match the brief. Command: `sha256sum llp/0049-scoped-attestation-execution.plan.md && git rev-parse --short=9 HEAD`.
- **VERIFIED — review target:** the execution-round delta is the two commits `4e2990432` and `f77b30a5f`; earlier review artifacts are present. Command: `git log --oneline -- llp/0049-scoped-attestation-execution.plan.md`; `llp/reviews/0049-scoped-attestation-execution.{fable,codex}.md`.
- **VERIFIED — indexed evidence exists:** every concrete artifact named in §11 exists and parses as JSON; `./ref-check` also reports zero errors. `llp/0049-scoped-attestation-execution.plan.md:871-889`; commands: `jq empty llp/evidence/*.json` for the indexed paths and `./ref-check`.
- **VERIFIED — the incident-specific scope vector is consumed on both sides:** JavaScript validates its canonical form/schema/digest, while Rust parses it through the production parser; both targeted tests pass. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`; `src/host/portable_target_admission.rs:2159-2177`; commands: `bun test packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs` and `cargo test --lib generated_scope_vector_deserializes_through_the_production_parser`.
- **VERIFIED — this discipline exists for another cross-language artifact:** diagnostic-audit vectors are consumed by independent JavaScript and Rust tests, including negative mutations. `packages/ibex-devtools/src/scripts/diagnostic-audit-schemas.test.mjs:18-29,56-80`; `crates/capsec-semantics/tests/diagnostic_audit_vectors.rs:71-135`; both targeted suites passed.
- **FAILED — rule 10 is not a repo-wide invariant:** its opening includes process boundaries, but its named checker covers only different-language producer/consumer pairs; existing Rust-produced/JavaScript-consumed public-batch evidence has no vector under `schemas/vectors/`. `llp/0049-scoped-attestation-execution.plan.md:299-312`; `src/bin/ibex/engine/capsec_conformance_batch.rs:4252-4267`; `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2144-2185`; command: `rg -n 'capsec-public-batch-evidence' schemas/vectors` returns no matches.
- **FAILED — “generated by the real producer” is not continuously checked:** the scope test reads committed bytes but neither regenerates them nor compares them with real-producer output. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`; command: `rg -n 'capsec-scope-v1.valid|generate.*scope.*vector' packages src schemas`.
- **FAILED — rule 11 is not enforced consistently:** §5.3 mentions review and break-tests, but Phase 0, Phase 2, and Phase 3 exit gates omit the supposedly every-phase requirement. `llp/0049-scoped-attestation-execution.plan.md:212-218,313-322,380-395,531-539,692-699,731-739`.
- **FAILED — the Phase 1 implementation-review discharge is not auditable:** the status records `719/0`, a BLOCKER, a neutered-assertion fixture, and fixes, but §11 contains no implementation-review artifact, reviewed revision, break-test commands/results, or finding disposition. `llp/0049-scoped-attestation-execution.plan.md:563-573,871-889`; command: `rg -n '719|wrong layer|assertion.*deleted|implementation review|break-tested' llp issues`.
- **FAILED — “only native-op has an effectful executor” is false as written:** the existing startup-environment executor runs loaded-engine sources, collects typed `env:read` decisions, validates them, and emits public-surface evidence. `packages/ibex-devtools/src/scripts/capsec-startup-environment-probe-templates.mjs:1-14,21-25`; `src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs:1072-1153,1285-1399,1737-1749`. The calibration artifact itself acknowledges that effectful path. `llp/evidence/0049-calibration-tranche-report.json:89-94`.
- **PARTIALLY VERIFIED — the two rejected candidate conclusions are narrower than the false universal claim:** `surface.host.abi × env:read` lacks an effectful executor, although host ABI has both non-capability module-runner and SQLite no-effect paths; the startup-env write candidates resolve to Android/Rust sources without the existing JavaScript read surface. `src/bin/ibex/engine/capsec_conformance_batch.rs:3078-3114,3503-3555`; `src/engine/native_android_networking.cc:344-350`; `issues/20260728-capsec-public-surface-evidence-backlog.md:123-132`.
- **VERIFIED — the completed calibration classes required executor work:** both retained batch artifacts record executor changes, and one records three generalization corrections. `llp/evidence/0049-batch-native-op-env-read-5EaSZqHyeHyZJ-kTorqcdNdYgBW-3wBtmZBbsIu4aV8.json:46-66`; `llp/evidence/0049-batch-native-op-fs-list-dzsLtlA9UI-XM0XnyrhbqwM-_XefBhoVPmkeqvcXVVg.json:46-66`.
- **FAILED — §9’s executor-cost kill criterion is not measurable:** no spike estimate, unit, per-kind baseline, or estimate artifact exists; “exceeds its spike estimate by 2x” also lacks the explicit arithmetic used by the corrected net-closure criterion. `llp/0049-scoped-attestation-execution.plan.md:769-781,850-862`; command: `rg -n 'spike estimate|executor-construction cost|per-surface-kind executor' llp issues`.
- **FAILED — §10(f) is not a coherent fork:** option (i) is an information-gathering precursor to choosing between scaling, narrowing, or a hybrid, yet it is presented as mutually exclusive with those choices and simultaneously described as author-agreed. `llp/0049-scoped-attestation-execution.plan.md:850-862`.
- **FAILED — the fan-out method is not “measured” in the retained-evidence sense:** §6 gives useful operational advice, but records no sample, branch measurements, comparison, or §11 artifact. `llp/0049-scoped-attestation-execution.plan.md:617-630,871-889`.
- **VERIFIED — poisoned-cell counts are internally reconciled:** the current plan and execution evidence use 73; the backlog’s earlier 74 is dated and explicitly superseded. `llp/0049-scoped-attestation-execution.plan.md:167-186`; `llp/evidence/0049-calibration-tranche-report.json:13-30`; `issues/20260728-capsec-public-surface-evidence-backlog.md:47-54,81-93`.
- **FAILED — one same-snapshot class count remains inconsistent:** §2 says 81 classes, while its post-seeding evidence records 80. `llp/0049-scoped-attestation-execution.plan.md:167-170`; `llp/evidence/0049-scope-measurement-postseeding-005189b86117530799564848414872280858a685a5f5dd0adddfe04cc529a238.json:39-44`.
- **VERIFIED — Phase 1 is not dishonestly marked complete:** the dated status block explicitly leaves report-schema collisions, weak fixtures, unpinned materials, and poisoned cells open. `llp/0049-scoped-attestation-execution.plan.md:563-573`.

## 2. Overall assessment

The delta captures two real failures and makes Phase 1 more candidly fail-closed. The shared-vector repair is also backed by executable tests.

It is not ready as a governing execution plan, however. Rule 10 overstates the scope of the implemented discipline; rule 11 is added only to the gate that suffered the incident and lacks an auditable discharge contract; §6 turns a candidate-specific calibration result into a false executor-wide claim; and the new cost kill criterion has neither a recorded estimate nor defined arithmetic. These are MATERIAL plan defects, not editorial polish.

No BLOCKER was found: the implementation remains explicitly gated rather than falsely declared complete.

## 3. Findings

### MATERIAL — §6 and §10(f): executor conclusion overclaims the evidence — IN-DELTA

“Only `native-op` has an executor capable of producing an effectful, source-bound receipt” is contradicted by the startup-environment batch executor, which executes loaded-engine sources and validates typed `env:read` decisions. `llp/0049-scoped-attestation-execution.plan.md:667-678,850-854`; `src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs:1072-1153,1285-1399`.

The evidence supports a narrower conclusion: neither of the two selected non-native candidate classes was reachable through an existing suitable executor without construction or extension. The host-ABI prose is also incomplete because a SQLite no-effect path exists alongside the non-capability module-runner path. `src/bin/ibex/engine/capsec_conformance_batch.rs:3078-3114,3526-3555`.

**Resolution:** replace the universal assertion with a retained per-surface-kind capability matrix distinguishing no executor, no-effect executor, effectful closed-table executor, and reusable effectful executor. Rewrite §6 and §10(f) from that matrix.

### MATERIAL — §3 rule 10: generalized beyond its checker and current conformance — IN-DELTA

The rule covers artifacts crossing a language **or process** boundary, but its only concrete checker is specified for different-language pairs. Existing public-batch evidence crosses both Rust→JavaScript and a process boundary without a `schemas/vectors/` vector. `llp/0049-scoped-attestation-execution.plan.md:299-312`; `src/bin/ibex/engine/capsec_conformance_batch.rs:4252-4267`; `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2144-2185`.

The repository demonstrates that shared vectors are an effective discipline, but it does not demonstrate that every cross-boundary artifact follows it. Nor does the scope-vector test prove ongoing real-producer generation. `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`.

**Resolution:** either narrow rule 10 to independently implemented, security-relevant wire artifacts, or inventory all applicable boundaries and add vectors/tests for each. Define a checker for process-only boundaries and require regeneration/equality from the real producer, not merely validation of committed bytes.

### MATERIAL — §3 rule 11 and phase exits: process gate is incident-specific and unauditable — IN-DELTA

Rule 11 says every implementation phase receives independent adversarial review, but only Phase 1’s exit gate was amended. Phase 2 explicitly includes new Rust executor construction yet has no corresponding review item. `llp/0049-scoped-attestation-execution.plan.md:313-322,531-539,675-678,692-699`.

The Phase 1 status assertion is retained only as prose. It lacks the reviewed revision, reviewer identity/independence statement, adversarial mutations, commands and outputs, verdict, and disposition of unresolved findings. `llp/0049-scoped-attestation-execution.plan.md:563-573,871-889`.

**Resolution:** add the gate to every implementation-bearing phase—or explicitly scope and justify exemptions—and define discharge as a retained artifact tied to an exact revision, with break-test commands/results and no unresolved BLOCKER/MATERIAL findings unless explicitly dispositioned.

### MATERIAL — §9 and §10(f): kill arithmetic and decision state are undefined — IN-DELTA

The criterion cannot be evaluated because no spike estimate or measurement unit exists. A spike on one surface kind also cannot supply an estimate for “any surface kind” without an extrapolation rule. `llp/0049-scoped-attestation-execution.plan.md:777-781,850-862`.

Option (i) is a measurement step, not an alternative to the eventual campaign decision. “Author indicated agreement” leaves it unclear whether the spike is already authorized or still open.

**Resolution:** define and retain `E_k` and `C_k`, their units and scope, and an unambiguous predicate such as `C_k > 2 × E_k`. Split §10(f) into: (1) authorization and budget for the spike; and (2) a post-spike choice among staged expansion, broad construction, shared-executor investment, hybrid scope, or narrowing.

### MINOR — §6: fan-out method is guidance presented as measurement — IN-DELTA

No retained artifact shows the claimed measurement or compares this method against alternatives. `llp/0049-scoped-attestation-execution.plan.md:617-630,871-889`.

**Resolution:** call it retrospective guidance, or make it enforceable by recording branch, merge base, changed paths, integration owner, and reconciliation results for each tranche. If mandatory, promote those checkable requirements into §3.

### MINOR — §6/§11: calibration source revision is not reproducible — IN-DELTA

The calibration report and batch artifacts identify commit `6416114…` while explicitly saying the measured worktree was uncommitted. `llp/evidence/0049-calibration-tranche-report.json:5`; both `llp/evidence/0049-batch-native-op-*.json:5`.

**Resolution:** add the exact landed commit mapping, tree/patch digest, or rerun and restamp the artifacts against a committed tree.

### MINOR — §2: post-seeding class count is stale — PRE-EXISTING

The prose gives 81 classes for a snapshot whose retained artifact gives 80. `llp/0049-scoped-attestation-execution.plan.md:167-170`; `llp/evidence/0049-scope-measurement-postseeding-005189b86117530799564848414872280858a685a5f5dd0adddfe04cc529a238.json:39-44`.

**Resolution:** change 81 to 80 or identify the distinct snapshot underlying 81.

### MINOR — §5.3: successive “now” status blocks obscure current state — IN-DELTA

The 2026-08-06 block says gate code is still open; the immediately following 2026-08-07 block says it landed. Dates make the history recoverable, but “now” is stale in the earlier block. `llp/0049-scoped-attestation-execution.plan.md:541-573`.

**Resolution:** label the first block “superseded historical status” and keep one explicit current Phase 1 gate ledger.

## 4. Verdict

**NOT READY**

Minimal flip set:

1. Correct the executor claim using a retained per-surface-kind capability matrix.
2. Narrow or fully mechanize rule 10, including real-producer regeneration and process-only boundaries.
3. Turn rule 11 into an auditable gate for every implementation-bearing phase and retain the Phase 1 review/break-test artifact.
4. Record the spike estimate, units, and exact kill arithmetic; separate the agreed spike from the post-spike scope decision.
