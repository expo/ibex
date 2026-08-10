# LLP 0049: Scoped Attestation Execution Plan

**Type:** Plan
**Status:** Draft
**Systems:** Security, Conformance, CI, Runtime, Tooling
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-06
**Revised:** 2026-08-08 (Lane C A2 audit — all 14 poisoned cells were
cleared as ill-typed duplicate façade/private-bridge effect cells. The
closed-world join and armed loaded-target evidence map all 138 credited
rows to their exact inner typed gate or secure armed closure. The strict
152-entry route allow-list passed with zero unexplained or stale entries;
terminal evidence changed on zero cells. Regenerated A2 is 40 cells, zero
poisoned, and 137 authorable rows. Evidence is indexed in §11. This revision
is UNREVIEWED.)
**Revised:** 2026-08-07b (executor-reachability rebuild — a retained
per-surface-kind measurement falsified the §6 claim the previous revision
was built on, and both round-3 reviews (Fable NOT READY, one BLOCKER;
Codex NOT READY, four MATERIAL) had already falsified it independently,
with different counterexamples. §6 is rebuilt from
`llp/evidence/0049-executor-capability-matrix-ff9b3031….json`: **three**
effectful executors exist, not one, and the worklist is now stated by
executor tier — 200 rows T3, 1,171 T2, 757 T1, 1,783 T0 — of which
**2,540 (65%) are behind new executor construction**. New §6.1 carries
the matrix inline with `file:line` citations and its four qualifications;
new §6.2 records the strategic consequence — scope selection needs two
independent axes (Lane B/C/D poisoning **and** executor reachability) and
LLP 0044 selected fs+env+process on the first alone. §3 rule 10 is
narrowed to the boundary its checker actually covers, with the
process-boundary inventory gap recorded as a follow-up rather than
claimed as conformance, and its checker stated at true strength; rule 11
is extended to every implementation-bearing phase with an auditable
discharge contract; new §3.1 records the meta-lesson at its proper
altitude. §9's executor-cost kill criterion gains a named unit, a
retained artifact and an explicit extrapolation rule. §10 item (f) is
replaced by a four-option scope/budget fork — the recommendation is now
to re-cut the v1.1 scope on the reachability axis — and moved after (e);
the prior "author indicated agreement" is withdrawn as given under the
falsified premise. §5.3's unretained gate-code figures are dropped per
rule 1, and §2/§6/§11 counts are reconciled to their retained artifacts
(81 → 80; ~3,922/~80 → 3,911/488/79). This revision is UNREVIEWED.)
**Revised:** 2026-08-07 (execution round — what Phase 0/1 execution and
the independent implementation review taught, folded back in: §3 gains
rule 10 (an artifact crossing a language boundary is not agreed until one
shared vector is consumed from both sides — the scope artifact shipped two
incompatible canonical forms under one schema id and one digest domain,
and every test on both sides passed because each built its own fixture in
its own dialect) and rule 11 (implementation gets an independent
adversarial review with break-tests before its phase exit gate — 719 green
Rust tests written by the authoring agents still shipped that BLOCKER plus
a fixture that passed with the assertion it claimed to test deleted); §5.3
adds that review to the exit gate and records gate-code status; §6 carries
the 2026-08-06 calibration result — only `native-op` has an executor able
to produce an effectful receipt, so the unit of work is per-surface-kind
executor construction, not template authoring — plus the measured fan-out
method for Phase 2; §9 gains the executor-cost kill criterion; §10 gains
item (f), the executor budget, the one genuinely open scope/budget trade.
This revision is UNREVIEWED.)
**Revised:** 2026-08-06b (round-2 delta-review revision — Fable r2 NOT READY
on one IN-DELTA MATERIAL, Codex r2 NOT READY with a three-item flip set;
dispositions in `llp/reviews/0049-*`: rule 3's advance-declaration sentence
no longer claims enforcement that nothing produces — it is a declared
procedure checked at tranche review until the §4.1 envelope deliverable
(allow-list content digest in the batch envelope recorded before candidate
generation, recomputed and compared by the diff gate, a machine-checked
`MASKED, NOT NEW` proof kind, and a test that a post-diff-authored
allow-list cannot pass) lands; the scope-measurement command and result
schema are named (`scripts/capsec-scope-measurement.mjs`,
`ibex/llp-evidence/scope-measurement/1`, both §4.1 deliverables) and the
Phase 0/2 exit gates carry copy-pasteable commands; the net-closure kill
criterion's inequality is corrected — it now fires when the worklist fails
to shrink at all (growth ≥ rows authored) for two consecutive boundaries;
the prior wording fired on any positive growth (Codex r2 finding 1); the
"74 of 610" geometric waste ceiling is withdrawn — a single poisoned cell
can drop its whole family, so the ratio bounds nothing — replaced by the
zero-poisoned-family ordering plus a measured calibration exposure count;
Phase 2 gains an enforcement-defect stop rule distinct from the LLP 0037
attribution stop; the http2 producer pins name declaration vs throw lines.
This revision is UNREVIEWED beyond `629599dea0b3`; the loop closed at two
rounds by design and what remains is the §10 author register.)
**Revised:** 2026-08-06 (round-1 dual-review revision, Fable NOT READY /
Codex NOT READY, artifacts in `llp/reviews/0049-*`: the Phase 3 exit claim
no longer says the runtime "refuses everything else" — it names the reviewed
uncertified disposition instead (Codex BLOCKER 1); the join matrix is now the
authoritative gate-code worklist with the two LLP 0044 "must be amended"
consumers — portable report admission and the promotion-bundle cell
invariant — plus the v2 reader, `Host::new_armed_with_target_cells`, the
typed decision path, and the scope-transparent Go verifier named explicitly,
and the fixture list gains composition, closure-escape, and split/merge
coverage (Fable 1 / Codex 2); every phase now has a written entry gate and
the Summary's "gates are commands" claim is scoped to what is actually a
command (Fable 2 / Codex 5); Phase 0's exit requires the full decision
packet — items 1–4, 6, 8, 9, 10 — not just 1–4, and its two tracks are
explicitly serialized (Codex 3 / Fable Q2); the 73 poisoned cells join
Phase 1's exit gate (Fable 3); Phase 2 is split into diagnostic authoring
vs. Phase-3-only authoritative execution, with early tranches ordered
toward zero-poisoned families and the re-cut waste ceiling stated
(Fable 4 / Codex 4); kill criteria gain the net-closure treadmill test,
cumulative mid-campaign reforecast, the item-2 physically-refused and
item-5 rejection branches, a Phase 1 review-round bound, and a cumulative
drift threshold (Fable Q3 / Codex 6); §3 rules 2, 3, 7, and 9 each gained a
named checker, artifact, or lock (Fable Q4 / Codex Q4), including the
terminal-diff instrument as a Phase 0 deliverable and the mandatory
`--scope all` flag; the §4.1 http2 item now partitions the 18 cells across
its three effect-assertion sites correctly and the `ex_host_env_ambient_set`
ruling moved into the §4.2 decision packet (Fable 6, 7); the authoring-time
catalog summary is retained at
`llp/evidence/0049-authoring-catalog-summary-4381ae02….json` (Fable 10 /
Codex 7))
**Related:** LLP 0044 (the strategy this plan executes); LLP 0046 (the
measurement discipline and network preconditions); LLP 0045 (the plan whose
collapse dictates this plan's construction rules); LLP 0036 (the authoring
machinery and gate definitions); LLP 0032 (execution and evidence sharding);
LLP 0037 (D1–D4 attribution rulings); LLP 0021 (promotion authority — the
document Phase 1 amends); LLP 0029 §7 item 4 / LLP 0047 (why v1.1 is a
single-tuple milestone that does not gate shipping); LLP 0039 (what a
completed attestation eventually expires);
issues/20260728-capsec-public-surface-evidence-backlog.md (live scope
accounting); issues/20260801-network-terminal-provenance-program.md
(the deferred network program)

## Summary

This plan turns LLP 0044's scoped-advertisement strategy into an ordered,
gated execution program whose end state is a **verified scoped advertisement
for `aarch64-apple-darwin`** — the v1.1 milestone of LLP 0029 §7 item 4 —
covering the **fs+env+process** scope, with every out-of-scope surface
carrying **no conformance claim** (never a refusal claim; see §3 rule 8).

It exists because the previous three attempts at this problem each taught a
lesson this plan is built around:

- **LLP 0036** proved the machinery works and the grind does not scale: the
  ceremony runs, the gates are honest, and the historical tranche rate of
  5–36 rows per commit against ~17k unresolved rows is a program measured in
  months-to-years.
- **LLP 0044** measured the way out: a scope where authoring is tractable
  (fs+env+process), a 16-second batch loop, and a cost floor that is
  authoring iteration, not execution. But it is an RFC with a ten-item
  author-decision register, one item BLOCKED, and zero gate code permitted
  until a join matrix is reviewed.
- **LLP 0045/0046** demonstrated how plans in this corpus die: bucketing by
  emission labels instead of mechanisms, planning against unstable
  denominators, and declaring convergence without executing the claims.
  Seven of eight yield figures were wrong.

Accordingly: every phase below has an explicit **entry gate and exit gate**.
Where a gate condition is verifiable by command, the command is named;
where it is a decision or a review outcome, the gate says so and names the
artifact that records it — no gate is satisfied by intent. Every figure
carries its generation digest, and the plan re-derives its own denominators
at each phase boundary rather than trusting this document.

## 1. Objective and non-goals

**Objective.** All four `checkPromotion` names green over a declared scope
for `aarch64-apple-darwin` — `executable-recipe-catalog`,
`public-surface-execution`, `output-disposition-evidence`,
`conformance-report` — with `assertReportMayAdvertise` passing and a
non-empty attestation admitted through the promotion lineage, under a
scoped `assertRecipeCatalogComplete` (`unresolved-in-scope === 0`), with the
active scope digest and uncertified remainder exposed via machine-readable
runtime introspection.

**Non-goals (explicitly out of this plan's exit gate):**

- The **network** family. Deferred per LLP 0046 §6: its successor plan may
  not be authored until the seeding fixes land, the origin-policy decision
  is made (127 vs 239 cells — the single highest-leverage open call in the
  wider program), and the denominator is re-measured. Phase 0 lands the
  seeding fixes because they are shared prerequisites; the network plan
  itself is a separate future LLP.
- The **second tuple** (Windows) and cross-tuple scope congruence
  (LLP 0044 register item 7).
- Flipping the **default build** back to secure and retiring
  `unadvertised-dev-arming` (LLP 0039). A scoped advertisement arms only
  in-scope cells; whether that satisfies LLP 0039's "arm from a real
  conformance report" retirement condition is an author decision recorded
  in §10, not assumed here.
- Raising or bypassing any evidence bar: no adapter-evidence promotion, no
  dynamic route witnessing, no label-only reclassification, no partial-cell
  credit (LLP 0044 §6/§8, all preserved verbatim).

## 2. Ground truth at authoring time

All figures regenerated at `main` = `aaa007ad`, 2026-08-06, catalog digest
`sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY`
(`aarch64-apple-darwin`, profile `ibex/capsec/1`); compact summary retained
at `llp/evidence/0049-authoring-catalog-summary-4381ae02….json` per §3
rule 1. Do not reuse these numbers without regenerating; the catalog grew
168 rows in the six days after LLP 0044's day-one measurement.

| metric | count |
| --- | ---: |
| required rows | 23,765 |
| fully executable | 3,931 |
| internally verified | 3,124 |
| unresolved | 16,710 |
| adapter-executable (non-promotable) | 11,680 |

**The scope, currently measured:** fs+env+process is **610 cells — 537
clean, 73 poisoned** (Lane B/C/D rows authoring cannot clear), with
**3,927 clean authorable rows across 491 surfaces in 80 template
classes**. This is the Phase 0 post-seeding measurement recorded in
`llp/evidence/0049-scope-measurement-postseeding-df1da4b5….json` and
indexed in §11.

> **Denominator note (2026-08-06).** Earlier passages of this document
> said "536 clean / 74 poisoned," measured 2026-08-05 and recorded in
> `issues/20260728-capsec-public-surface-evidence-backlog.md` by the
> `capsec-fs-env-evidence` landing. That was the
> **pre-callback-attribution** state; the callback-argument attribution
> fix in the surface-inventory walker moved one cell from poisoned to
> clean, giving today's 537/73. Every "74" in this document has been
> re-pointed to 73. The same 2026-08-05 passage also recorded
> **3,922 rows / 490 surfaces / 80 classes** remaining after the first
> landed tranche; the post-seeding re-measurement supersedes it at
> 3,927/491/**80**, and §6's worklist figure is re-derived at entry per
> rule 5 regardless. (This paragraph and the table above said "81
> classes" through the 2026-08-07 revision; the artifact they cite
> records 80. Corrected 2026-08-07b — a §3 rule 1 figure may not
> disagree with the artifact it inherits from.) The **current** retained
> figure, after the Phase 2 calibration tranche closed one class, is
> **3,911 rows / 488 surfaces / 79 classes**
> (`llp/evidence/0049-scope-measurement-phase2-calibration-close.json`),
> and that is the denominator §6 and §6.1 use. Per §3 rule 5 all such
> figures are snapshots and must be re-derived at each gate, not quoted
> from here.

LLP 0044 §9's day-one figures (513 cells / 3,256 rows / 64 classes)
are superseded — the drift of +671 rows / +17 classes in five days is
itself the argument for §3 rule 5.

**Already landed (2026-08-05), which this plan builds on rather than
re-plans:**

- Hook-alias sealing (`53409737`): four `__exact*Owner` aliases normalized
  + all three C++ install sites sealed non-writable/non-configurable.
  Network Lane B 338 → 292.
- Callback-argument attribution (`8cf677e7`): 46 repository-wide terminal
  misattributions resolved (including the `net.Socket.connect` P1), 13
  Lane B cells gained real terminals, 0 terminals removed.
- The first fs+env+process template class (`63bd1933`):
  `surface.native.op × [env:write]`, 5 rows, all passing source-bound
  physical execution — the authoring loop of §6 is proven live, and this is
  calibration data point #1.

**Not yet in existence anywhere in code:** any scope identity. `scopeDigest`
has zero hits under `src/`, `crates/`, and `packages/ibex-devtools/src`;
`ExpectedArmingIdentity` (crates/capsec-semantics/src/arming.rs) carries no
scope field. Phase 1 starts from a blank page, which is exactly what
LLP 0044 register item 5 requires it to acknowledge.

## 3. Construction rules

These are the failure modes of LLP 0045 and the disciplines that caught
them, promoted to standing rules for every phase. Each rule names its
checker or artifact — a rule with neither is a rule that gets skipped in
week three. A phase that violates one is out of compliance regardless of
its output.

1. **Every load-bearing figure comes from a command executed at a named
   revision**, and is recorded with its catalog/evidence digest. Prose
   inherits numbers only from retained artifacts under `llp/evidence/`.
   *Checker:* the §11 evidence index; a figure without a row there is a
   violation.
2. **Name mechanisms from the code that emits them, never from a label's
   shape.** Residual-reason strings and ambiguity strings are emission
   artifacts. *Checker:* every tranche-plan work item cites the emitting
   code as `file:line`; a work item sized against a string bucket without
   an emitting-code citation is rejected at tranche review.
3. **Catalog deltas pass the symmetric paired allow-list gate**
   (`scripts/llp0045-route-evidence-diff.mjs`, always with `--scope all` —
   the tool's default is `--scope network` and would trivially pass on
   fs+env+process rows): every addition AND removal individually declared
   in advance with a source span and proof; unexplained removals fail
   exactly as unexplained additions do; the `MASKED, NOT NEW` proof
   vocabulary is required where resolving one thing unmasks another.
   *Advance declaration* is a declared procedure verified at tranche
   review until the §4.1 envelope deliverable lands, and mechanical after:
   the allow-list is committed before the candidate catalog is generated
   (post-deliverable: its content digest is recorded in the batch evidence
   envelope and the diff gate recomputes and compares it), and the tool's
   post-diff survey skeleton may only seed a re-run, never pass the gate
   directly. Tranche review is likewise the named checker for the
   `MASKED, NOT NEW` vocabulary until the deliverable adds it as a
   machine-checked proof kind.
4. **Clearance rules are checked in both directions.** Removing an
   ambiguity is not the same event as adding a terminal; a mechanism can
   clear its label while leaving the cell exactly as unprovable as before.
   *Checker:* rule 3's symmetric gate is the instrument; both directions of
   every delta must be covered by entries.
5. **Denominators are re-derived at every phase boundary.** The canonical
   commands are the catalog regen
   (`bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs --target aarch64-apple-darwin --output <fresh>`)
   plus the scope-measurement tool
   (`scripts/capsec-scope-measurement.mjs`, a §4.1 deliverable emitting
   the `ibex/llp-evidence/scope-measurement/1` schema — cells / clean /
   poisoned / authorable rows / surfaces / template classes per family
   set, with an `--assert` mode for use in exit gates), and each
   boundary's summaries are retained under `llp/evidence/` next to the
   ones they supersede. If the phase's planned
   worklist moved by more than 5% of rows, the tranche plan is re-cut
   before work continues; cumulative drift is tracked against the kill
   criterion in §9. Planning against a stale number is the error that
   produced LLP 0045.
6. **No convergence or completion claim without an execution pass.**
   Catalog regen is ~11 seconds; a representative batch is ~16 seconds.
   There is no excuse.
7. **Lane B count is not a sufficient soundness metric.** Confident
   misattributions live outside Lane B. Every batch runs the before/after
   terminal-diff instrument — per-edgeId unioned terminal sets, additions
   and removals both explained (the `8cf677e7` method). *Checker:* this
   instrument does not exist as a named tool yet; landing it
   (`scripts/capsec-terminal-evidence-diff.mjs` + a `package.json` test
   entry, output schema mirroring rule 3's entries) is a **Phase 0
   deliverable** (§4.1). Until it lands, rule 3's tool over the terminal
   route-evidence fields with `--scope all` is the interim gate, and no
   Phase 2 batch may run without one of the two.
8. **"Fail-closed" always names its layer** — startup admission, typed-gate
   refusal, or physical entrypoint refusal — and the zero-decision
   remainder has none of the three. The published claim never asserts that
   out-of-scope surfaces are refused, absent, or safe. This is the
   unresolved MATERIAL objection from LLP 0044's Fable review, and the
   claim wording in Phase 3 is written to be immune to it: negative
   controls are evidence, not proof, and never upgrade the claim.
   *Checker:* the Phase 1 review package includes the exact published
   claim wording; any sentence characterizing the remainder without naming
   its layer fails review.
9. **Every promotion-facing command byte-for-byte spells the secure feature
   vector** (`--no-default-features` +
   `standard,capsec-conformance-observer,openssl-crypto`); the command
   stored in a recipe or evidence plan is itself security-relevant
   evidence (LLP 0039). Port-binding suites (`node_net_builtins`,
   `host-http-server`) never run in parallel — enforced by a repo-local
   advisory lock taken by the batch harness (a `flock` on
   `target/.capsec-port-suite.lock`, added with the rule 7 instrument in
   Phase 0), not by agent discipline. Preflight includes `bun install` — a
   stale `node_modules` cost a real session a generator run on 2026-08-06.

10. **An artifact whose producer and consumer are implemented in
    different languages is not agreed until one shared vector is consumed
    from both sides.** Phase 1's only BLOCKER was found this way: the
    scope artifact had two incompatible canonical forms sharing one schema
    id and one digest domain — the JS producer emitting
    `scopeSchema`/`expandedCellIds`/seven-field closure edges, the Rust
    consumer declaring `schema`/`expandedCells`/two fields under
    `deny_unknown_fields`. Five of ten names differed. Every test on both
    sides passed, because **each side built its own fixture in its own
    dialect** and the artifact was the one CapSec artifact with no
    cross-language vector. *Checker:* every artifact with producers and
    consumers in different languages carries a vector under
    `schemas/vectors/`, consumed by a test on each side — for the scope
    artifact, `schemas/vectors/capsec-scope-v1.valid.json` read by
    `packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`
    and parsed through the production parser by
    `src/host/portable_target_admission.rs:2159-2177`. Agreement asserted
    in prose, or by two fixtures that never meet, is not agreement.

    Two honesty qualifications, both from the round-3 reviews, both
    recorded rather than papered over:

    - **The rule is stated at the boundary its checker covers.** Through
      the 2026-08-07 revision the rule read "a language **or process**
      boundary." That overreached: the checker is specified for
      different-language producer/consumer pairs only, and an in-tree
      artifact crossing both boundaries already does not conform —
      `ibex/capsec-public-batch-evidence/1` is written by Rust
      (`src/bin/ibex/engine/capsec_conformance_batch.rs:4252-4267`) and
      consumed by JS
      (`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:2144-2185`)
      with no vector under `schemas/vectors/`. Claiming repo-wide
      conformance would have been false. The remedy is an **inventory**,
      not a wider sentence: enumerating every cross-language and
      process-boundary artifact and closing the gaps is owed as a
      **filesystem ticket under `issues/`**, outside this plan's exit
      gate. Until that inventory exists, this rule binds **new**
      artifacts this plan creates and asserts nothing about existing
      ones.
    - **The checker's true strength.** Both tests read the *committed*
      vector bytes. They prove the two dialects agree on those bytes and
      that the production parser accepts them; they do **not** prove the
      real producer still emits them. Regenerate-and-compare against
      live producer output is a strictly stronger checker and is not
      implemented. Any artifact this plan adds under `schemas/vectors/`
      should carry the regeneration check; the existing vectors are
      credited only at the strength stated here.
11. **Every implementation-bearing phase gets an independent adversarial
    review before its exit gate, and the reviewer must try to break the
    fixtures.** Phase 1's gate code passed its full self-authored test
    suite — unit tests, the lineage suite, `check:secure-mode`, and every
    adversarial fixture, all written by the agents that wrote the code —
    and still shipped the rule-10 BLOCKER plus a fixture that refused at
    the wrong layer (it passed with the assertion it claimed to test
    deleted). Both were found by an outside reviewer instructed to revert
    defects and confirm the fixtures fail.

    **Which phases:** Phase 1 (gate code), **Phase 2 for every batch that
    lands an executor change** — §6.1 measures that as the dominant Phase 2
    work product, and it is security-sensitive Rust — and Phase 3 for the
    ceremony and publication wiring. A template-only, no-Rust-change batch
    is exempt; the exemption is claimed per batch in its evidence envelope,
    not assumed.

    **Discharge is a contract, not an assertion.** *Checker:* the phase
    does not exit on self-verified green; a retained artifact under
    `llp/reviews/` (indexed in §11) is part of the exit gate and carries
    all five of:

    1. the **exact reviewed revision** — commit and document/tree digest,
       not "current main";
    2. a **reviewer-independence statement** — family, runtime, and the
       fact that the reviewer authored neither the code nor its tests;
    3. the **break-tests actually run**: the defect reverted or the
       assertion deleted, the command, and the observed failure, for each
       fixture whose strength is being credited;
    4. **commands and outputs** for every green figure the phase claims,
       so that no count enters the plan without a retained source
       (rule 1);
    5. the **disposition of every finding** — fixed (with commit),
       accepted with rationale, or deferred to a named ticket. An open
       BLOCKER or MATERIAL with no disposition blocks the exit.

    Phase 1's own implementation review is not yet discharged under this
    contract — see the §5.3 status block, which is the worked example of
    the gap.
12. **Parallel agents get one worktree each, and every branch is diffed
    from its merge base.** Agents sharing a checkout collide on git state
    rather than on files, and a diff taken against a moving `origin/main`
    lies about what a branch changed. *Checker (commands, recorded in each
    batch's evidence envelope):* `git worktree list` shows one worktree per
    concurrent agent, and each branch's changed-path set comes from
    `git diff --stat $(git merge-base origin/main HEAD)..HEAD`. This rule
    is the checkable residue of §6's fan-out retrospective; the rest of
    that passage is explicitly non-binding advice.

### 3.1 What execution taught us

Rules 1–11 came from other plans' failures. Two lessons come from this
one, and they sit above any individual rule:

**A bounded observation must never be promoted into an unbounded claim.**
The 2026-08-06 calibration examined three surface kinds and found that,
among them, only `native-op` had an executor able to produce an effectful
source-bound receipt. The 2026-08-07 revision wrote that down as *only
`native-op` has* such an executor — dropping the quantifier's domain. The
per-surface-kind measurement of 2026-08-07
(`llp/evidence/0049-executor-capability-matrix-ff9b3031….json`) falsified
it: **three** effectful executors exist, and both round-3 reviewers had
already falsified it independently with different counterexamples (Fable
via `surface.builtin.export`, Codex via `surface.startup.env`). The
promoted claim then became the sole premise of a kill criterion (§9) and
a register item (§10 f), so one dropped quantifier propagated into the
plan's schedule and its budget fork.

That is exactly what §3 rule 2 forbids — size work from the emitting
code, never from a label or a summary — applied one level up: **the
summary being trusted was our own**. Rule 2's checker (a `file:line`
citation for every work item) would have caught it, because no
`file:line` citation for "no other executor exists" can be written
without reading every executor.

**A plan's construction rules apply to the plan itself.** §3 rule 1 says
every load-bearing figure comes from a command at a named revision, with
a §11 row. The falsified §6 claim had neither, and neither did the §5.3
gate-code figures written in the same revision — in a delta whose thesis
was that self-verified green is not evidence. The rules were being
enforced on the campaign's outputs and not on the document that defines
them. Concretely: a plan section that states a **universal negative**
("no executor can…", "nothing in the tree does…") is a rule-1 figure,
carries the same retention obligation as a count, and is the shape of
claim most likely to be false. Write it only from a measurement that
enumerated the whole domain, and retain that measurement.

## 4. Phase 0 — Decisions and denominator stabilization

Cheap, mostly mechanical, and everything downstream is mis-founded without
it. Two tracks — **strictly serialized**: the §4.2 decision packet is
assembled only after §4.1's exit gate, because items 2 and 4 must be
decided on the post-seeding re-measurement (deciding them on today's
numbers would repeat the plan-against-stale-numbers error).

**Entry gate:** `bun install` clean; catalog regenerated at the current
HEAD and its summary retained under `llp/evidence/` (the §2 artifact
satisfies this for the revision this document was authored at).

### 4.1 Seeding fixes and instruments (code, no author decision needed)

Per LLP 0046 §6 item 1 — "a prerequisite, not a parallel cleanup:
certifying a mis-seeded cell certifies a claim that is false about the
source." Current line numbers at `aaa007ad`; re-pin before editing.

- `builtinExportClassification`
  (packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:8842):
  member carve-outs ordered **before** receiver-class prefixes, using
  exact-string member sets, never widened regexes (the widened regex is how
  this arose). 11 of the 12 class-prefix sites are network; the 12th is
  readline (:9644, tracked as
  issues/20260801-readline-interface-prefix-seeds-stdio-effect.md).
- Withdraw the `node_http2` effect assertions at **all three** sites in
  its block — `connect` → `network:connect` (:9355–9358),
  `performServerHandshake` → `network:listen` (:9363–9366), and the
  class-prefix `network:listen` (:9368–9371). Per LLP 0046 §2 the four
  *producers* throw unconditionally (declarations
  http2.js:250/254/258/262, throw bodies :251/:255/:259/:263) and take
  the new `unsupported-throwing-stub` disposition; the remaining cells of
  the 18 (field-initializing constructors and header-map members) are
  re-seeded by member classification, not by any class prefix. The model
  currently asserts effects the implementation does not have.
- Add the `unsupported-throwing-stub` disposition for the 9 unconditional
  refusal cells.
- De-duplicate the 42 exact alias cells (`net.Stream.* ≡ net.Socket.*`,
  `ws.Server* ≡ ws.WebSocketServer*`).
- **Land the §3 instruments** — this bullet is the checker budget for the
  whole campaign; every Phase 2 batch is gated on the first two and the
  gates get progressively mechanical as the rest land:
  - rule 7's terminal-diff tool
    (`scripts/capsec-terminal-evidence-diff.mjs`: per-edgeId unioned
    terminal sets between two catalogs, symmetric, `package.json` entry,
    tests);
  - rule 9's port-suite lock (`flock` on `target/.capsec-port-suite.lock`
    in the batch harness);
  - rule 5's scope-measurement tool (`scripts/capsec-scope-measurement.mjs`
    emitting `ibex/llp-evidence/scope-measurement/1`, with `--assert`);
  - rule 3's advance-declaration mechanics: a batch evidence envelope
    schema carrying the allow-list content digest recorded before
    candidate generation, the diff gate recomputing and comparing that
    digest, a machine-checked proof kind for `MASKED, NOT NEW`, and a
    test pinning that a post-diff-authored allow-list cannot pass.

Exit gate (commands):

```
bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
  --target aarch64-apple-darwin --output <fresh>
node scripts/llp0045-route-evidence-diff.mjs --baseline <pre-fix> \
  --candidate <fresh> --scope all --allow-list <committed-list>
node scripts/capsec-terminal-evidence-diff.mjs --baseline <pre-fix> \
  --candidate <fresh>
node scripts/capsec-scope-measurement.mjs --families fs,env,process \
  --catalog <fresh>
```

all passing — the route-evidence diff with per-entry source spans against
the committed allow-list, the terminal diff clean or fully explained —
and the post-seeding scope measurement retained under `llp/evidence/`.

### 4.2 The decision packet (author, one sitting, after 4.1)

LLP 0044's register was written to be decided on measured data; §4.1's
exit gate produces that data. Present items **1, 2, 3, 4, 6, 8, 9, 10**
together with the post-seeding re-measurement attached (recommendations in
§10), plus one ruling this plan adds: the **`ex_host_env_ambient_set`
disposition** — the `surface.host.abi × [env:write]` class is sourced from
the compile-time `insecure` ambient projection, inactive in the secure
profile (ABI returns −1 with no typed decision), and it sits **inside the
fs+env+process scope**, so it is a semantic ruling for the author, not a
code fix; the backlog ticket carries it as an explicit release constraint.
Item 5 cannot be decided yet — it is BLOCKED on Phase 1's join matrix by
LLP 0044's own terms. Item 7 (cross-tuple congruence) is deferred with the
second tuple. The network origin-policy decision is **not** in this
packet; it belongs to the network program's own plan.

Exit gate (a decision event, recorded in LLP 0044's register and §10's
ledger): **all eight items plus the ambient-set ruling decided.** Two
outcomes divert the plan rather than pass the gate: item 1 rejected →
this plan terminates and v1.1 reverts to the full per-surface program — a
valid exit, recorded, not a process failure; item 2 decided as
**physically refused** → this plan returns to the author for re-scoping
and re-estimation, because the claim wording, the `ScopedAdvertised` arm
state, and Phase 3's publication step are all designed for the
uncertified-remainder posture and LLP 0044 prices the refused posture as
"a materially larger runtime program."

## 5. Phase 1 — Scope identity: the join matrix and gate code

The critical path, and the only phase whose product is design + review
rather than evidence. Nothing here is optional: LLP 0044 forbids any gate
code before the join matrix is authored and reviewed, and the consumer
table is "the seed, not the proof."

**Entry gate:** §4.2's exit gate passed (packet decided, neither diversion
taken).

### 5.1 Author the join matrix (LLP 0021 amendment appendix)

Every artifact that creates, re-derives, binds, compares, or carries
`scopeDigest`, with each consumer marked **scope-validating** or
**scope-transparent**. **The finished matrix is the authoritative
gate-code worklist**: every row marked scope-validating is a §5.3 work
item, and the lists below are the seed LLP 0044 provides, not a cap. The
seed, in full:

- the armed-snapshot producer, the `ibex/capsec-armed/1` parser, and
  `ExpectedArmingIdentity` — none carries scope identity today; the three
  open sub-questions are (i) snapshot-carries-`scopeDigest` vs. an
  independently authenticated scope identity joined beside it, (ii) how
  snapshot/report scope substitution is prevented, (iii) which authority
  supplies the digest to runtime introspection;
- the two consumers LLP 0044's table already marks **must be amended**:
  **portable report admission** (`src/host/portable_target_admission.rs` —
  validates the scoped required set against the **re-derived** expansion,
  never the report's own row list; §7.3 depends on this existing) and the
  **portable promotion bundle cell invariant**
  (`capsec-portable-promotion-bundle.mjs` — accepts out-of-scope
  `unsupported` cells listed in the bound scope artifact, **and only
  those**);
- **both advertisement chains** — the v2 portable chain
  (`ibex/capsec-target-advertisements/2` and its reader
  `capsec-portable-engine-evidence-contract.mjs` → v3 schema carrying the
  scope digest and the product term "scoped certification") and the
  **closed v1 chain** (`generate-capsec-registry.mjs`, pinned to v1 by the
  promotion-lineage verifier), which gets its own row group: amended or
  proven scope-transparent, explicitly;
- armed host construction (`Host::new_armed_with_target_cells`) — the
  `ScopedAdvertised` arm state with an exhaustive cell map and explicit
  uncertified disposition; arming with a cell absent from the map remains
  a refusal;
- the typed decision path (`crates/capsec-semantics/src/decision.rs`) —
  expected **unchanged** and shown scope-transparent (this is exactly why
  the claim is "uncertified," not "refused");
- the Go attestation verifier (LLP 0035) — expected scope-transparent
  (it authenticates provenance, not scope);
- the promotion authority, bundle verifier, lineage verifier, `build.rs`
  report selector, target-cell bytes, and fixture catalog, wherever they
  join report ↔ cells ↔ advertisement;
- the full lifecycle binding set: the scope digest is created by the
  generator, independently re-derived at admission, and **bound** into the
  recipe catalog, public execution evidence, report, attestation,
  promotion bundle, and admission result — each binding is a matrix row.

The scope artifact's companion artifacts — the expansion diff and the
rename **/split/merge** mappings — each carry their own schema and digest
domain, per LLP 0044 §2.

### 5.2 Poisoned-cell disposition (the 73)

The scope unit is the complete cell and families are in-or-out, so the 73
poisoned cells cannot be silently dropped. Two sanctioned routes, pursued
in parallel with the join matrix:

- **Audits** per LLP 0044 §3 lane rules: Lane C requires the closed-world
  source join plus loaded-target absence evidence mapped to every credited
  row; Lane D requires the exact import-resolution/closure proof; Lane B
  rows **stay unresolved** — a pinned observed sequence does not
  manufacture a terminal.
- **Grammar extension** (LLP 0044 option b): a generated intensional
  criterion ("cells whose enforcement routes have source-proven
  terminals"), which interacts with the anti-cherry-picking constraint and
  therefore needs its own review — bundle it into this phase's review loop
  if the audits leave a remainder.

Only audit outcomes that alter the scope grammar, the obligation
vocabulary, or the selected scope enter the pre-code review package; the
audits do not gate unrelated gate plumbing. They **do** gate scope freeze:
see this phase's exit gate. If neither route disposes of all 73, the scope
is re-cut on the Phase 0 measurement — see kill criteria, §9.

### 5.3 Review, then gate code

The review package (join matrix + LLP 0021/0032/0036 amendments + the
exact published claim wording per §3 rule 8 + grammar extension if taken)
goes through the formal multi-model loop per LLP 0044 register item 10 —
this is gate-changing, claim-boundary work, the one category where that
intensity is not optional. Only after review: **every consumer the matrix
marks scope-validating** (explicitly including §5.1's two must-amend
consumers), the scope artifact generator (intensional definition +
expanded cell set + closure edges, own digest domain, monotone lineage
with expansion-diff and rename/split/merge artifacts in their own digest
domains), the scoped `assertRecipeCatalogComplete` binding, the
`ScopedAdvertised` arm state with explicit uncertified disposition
distinguishable from "incomplete by defect" in refusal telemetry, runtime
scope introspection, and the adversarial fixture set: LLP 0044 §2's seven
classes (scoped-state substitution, omitted map entries, typed
out-of-scope refusal, executable zero-decision remainder, duplicate
scopes, stale/rolled-back predecessors, renamed/retired cells) plus an
**observed-closure-escape** fixture (a physical traversal into a cell the
closure excluded must fail the run — it proves the closure wrong), a
**split/merge mapping** fixture, and the adversarial-composition fixtures
LLP 0044 defines as **diagnostic, never claim-upgrading**.

Exit gate: review artifacts under `llp/reviews/`; register item 5 put to
the author and decided (rejection is a §9 diversion, not a gate pass);
gate code landed with its adversarial fixtures green; **an independent
review of the merged implementation, with break-tests, discharged under
§3 rule 11's five-item contract and retained under `llp/reviews/` with a
§11 row** (not discharged as of 2026-08-07b — see the status block);
`check:secure-mode` green; **§5.2 disposition complete** — each of the 73 poisoned cells is
audit-cleared, grammar-excluded under the reviewed extension, or covered
by a decided scope re-cut. `unresolved-in-scope === 0` is unreachable at
Phase 3 while any of the 73 lacks a disposition, so this phase does not
exit without one.

> **[Superseded historical status — see the 2026-08-07b block below for
> current Phase 1 state.] Review-package exit-gate condition: MET
> (2026-08-06).** The first two
> exit conditions are satisfied. Review artifacts exist under
> `llp/reviews/` —
> `0021-scoped-advertisement-amendment.fable.md` and
> `…codex.md`, four rounds each, closing **DUAL-READY at round 4** under
> the §9 author directive's Fable-gated decision rule. **LLP 0044
> register item 5 is decided: ACCEPTED** (Option B — scope identity
> returned by report admission and retained in
> `AdmittedScopedTargetCells`; the armed snapshot carries no scope
> identity), so this is a gate pass, not the §9 diversion. Every round-4
> finding from both families was applied to the package as a text
> revision; the LLP 0021 §A9 matrix is unchanged at **33 rows** and is
> now the accepted authoritative worklist for the gate code below.
>
> **Still open in Phase 1**, and the only things now standing between
> here and §5.3's exit: gate code landed with its adversarial fixtures
> green (the LLP 0044 §2 seven classes plus the observed-closure-escape,
> split/merge and adversarial-composition fixtures, and the LLP 0021 §A8
> subcases the review rounds added — F3a-1…5, F6a…F6h with the round-4
> additions F6f-4, F6f-5 and F6h-c); `check:secure-mode` green; and the
> **§5.2 disposition of the 73 poisoned cells**.

> **Gate-code status (2026-08-07b).** Implemented and merged: the
> six-slice program plus reconciliation landed on `main`. An independent
> review then found one BLOCKER (§3 rule 10) and one fixture refusing at
> the wrong layer; **the BLOCKER fix is verifiable in the tree** — the
> shared vector `schemas/vectors/capsec-scope-v1.valid.json` is now
> consumed from JS
> (`packages/ibex-devtools/src/scripts/capsec-scope-artifact.test.mjs:53-66`)
> and parsed through the production Rust parser
> (`src/host/portable_target_admission.rs:2159-2177`,
> `generated_scope_vector_deserializes_through_the_production_parser`),
> and both round-3 reviewers verified it independently.
>
> **Figures withdrawn (2026-08-07b).** The 2026-08-07 form of this block
> also carried `cargo test --lib` 719/0, the Rust scoped fixtures 14/0,
> `check:secure-mode` green, "the fix is break-tested," and "the
> report-schema version seam closed repo-wide." None had a retained
> artifact or a §11 row, so under §3 rule 1 they were not admissible
> figures and are **dropped** rather than restated. That is the honest
> disposition, not a claim that the runs did not happen: they are
> unretained, and an unretained green is exactly what rule 11 exists to
> refuse.
>
> **Rule 11 is therefore NOT discharged for Phase 1.** No artifact exists
> under `llp/reviews/` for the implementation review, so none of rule 11's
> five discharge items — reviewed revision, independence statement,
> break-test commands and results, commands and outputs for every claimed
> figure, disposition of every finding — is auditable. Retaining that
> artifact is now an explicit **exit-gate item** for this phase.
>
> **Still open before this phase exits:** the rule-11 discharge artifact
> above; the review's MATERIAL findings, which survive only as prose in
> this document and cannot be re-derived without it — a reported
> collision between two conformance-report schema ids (not locatable in
> the repo as written: `schemas/capsec-conformance-report-v2.schema.json`
> is the only conformance-report schema on disk carrying an `$id`, so the
> finding must be restated against real files or withdrawn), three
> further fixtures asserting less than their names claim, and matrix rows
> M11 and M26 unpinned; and the §5.2 disposition of the 73 poisoned
> cells. The "seam closed repo-wide" claim is likewise withdrawn until it
> names the files it covers.

## 6. Phase 2 — The authoring campaign (parallel with Phase 1)

This phase starts once Phase 0 completes and runs concurrently with
Phase 1 because it does not depend on Phase 1's **scope-identity** gate
code — not because it is code-free work. §6.1 measures the opposite:
**2,540 of the 3,911 in-scope rows sit behind new executor
construction**, and both classes the calibration tranche actually closed
needed Rust executor changes. Phase 2's dominant work product is
security-sensitive Rust in the batch executors, so §3 rule 11 applies to
it (see this phase's exit gate). What Phase 2 does *not* touch is the
scope-validating consumers, the scope-artifact generator, and the
`ScopedAdvertised` arm state — those are Phase 1's, and that is what
makes the phases concurrent. (The 2026-08-07 revision opened this section
with "Authoring needs no gate code," which its own calibration result
contradicted two pages later; corrected 2026-08-07b.) Two further
honesty constraints bound the parallelism:

- **Everything Phase 2 executes is diagnostic.** Authoritative promotion
  evidence is produced only by the Phase 3 ceremony (LLP 0032's authority
  classes: same runner, same suite-run-instance, engine attested before
  and after) at the frozen scope and revision. Phase 2 batch runs
  pre-verify templates and pin sequences; they are re-executed
  authoritatively at Phase 3, which also absorbs mid-campaign engine and
  schema drift from the Phase 1 race.
- **The re-cut branch is the one source of wasted work, and it is managed
  by ordering, not bounded by geometry.** "Owed under any scope design"
  holds for every Phase 1 design outcome except one: the §5.2/§9 scope
  re-cut, under which authored rows in dropped families were not owed —
  and because a single poisoned cell can drop its whole family, the
  73-of-610 cell ratio is **not** a ceiling on wasted rows. The
  mitigation is operational: **early tranches go to families with zero
  poisoned cells** until §5.2 reports (rows-per-class-descending ordering
  applies within that constraint), and calibration records the count of
  clean rows in families carrying ≥1 poisoned cell as the measured
  exposure.

**Entry gate:** §4.2's exit gate passed (the packet includes item 9, the
budget that sizes this fan-out — register item c); worklist re-derived
from the §4.1 post-seeding measurement.

**Worklist:** **3,911 clean authorable rows across 488 surfaces in 79
template classes** — the retained calibration-close measurement
(`llp/evidence/0049-scope-measurement-phase2-calibration-close.json`,
catalog `sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs`), re-derived
at entry per §3 rule 5. Through the 2026-08-07 revision this line still
read "~3,922 rows across ~80 template classes," a 2026-08-05 figure §2's
own denominator note had already declared superseded. §6.1 partitions
these same 3,911 rows by **executor tier**, which is the partition that
governs sequencing.

**The loop, per template class** (proven by the env:write landing):
author template → run batch on the bound engine → pin the observed typed
sequence (LLP 0037 D3 — observed, never guessed; `readFileSync` is 9
decisions, not 4) → regenerate catalog → confirm green → paired
allow-list diff (`--scope all`) + terminal-diff instrument (§3 rules 3
and 7) → commit, retaining the batch evidence envelope as
`llp/evidence/0049-batch-<template-class>-<digest>.json`. Per LLP 0037
D2, confirm per family that every surplus `fs:list` is traversal-stage
before pinning.

### Retained-handle setup authority (2026-08-10)

Retained filesystem and file-backed SQLite recipes use two distinct setup
constructors behind one authority-separation rule. Principal 0 receives only
the exact `requiredSetupFloor` and creates the real runtime-owned object before
observation: `__exactFsOpen` creates a Hermes `FdEntry`, while
`__exactSqliteOpen` (optionally followed by `__exactSqlitePrepare`) creates a
file-backed SQLite registry entry. Principal 1 receives the exact probe floor
and, for a deny row, its denial. Only the authenticated probe submission runs
under the canonical `[0, 1]` constrained-principal intersection. The handle
ownership check therefore still sees owner 0, while semantic authorization
must satisfy both principals and principal 1's denial remains decisive. Setup
and post-observation cleanup run root-only; the observer-only one-shot native
constraint is cleared after the probe submission. The retained-deny proof
installs `[0, 1]` through the observer-only
`ibex_private_test_eval_lowered_session_with_principals` hook as a stand-in for
frame attribution, so it certifies evaluator conjunction and repeat-stage
retained-handle authorization, not the production attribution path itself.

The first proof class is retained `__exactFsFstatSync`: its bound-engine deny
observation is one `repeat` `fs:list` decision with
`principal.000001.denial.000000` as the decisive row. A focused native test
proves file backing by first refusing a read-only open of an absent owned path
and then reading the seeded row through the statement handle returned by the
loaded globals. The first file-backed SQLite row, retained
`__exactSqliteGet` allow, also completes this section's ordinary authoring loop
through `execute_native_public_recipe` and
`validate_native_runtime_observation`. These are different
object-construction mechanisms even though they share the principal split.

The derivable executor-capability set is 61 rows, not the previously asserted
84: 13 retained-descriptor deny rows at the pre-constructor baseline (the
enumerated globals and fixture ids are retained in the two batch envelopes),
plus 48 non-fully-executable file-backed SQLite rows selected from
`__exactSqlite{All,Exec,Get,Prepare,Run,Values}`. Two rows are demonstrated and
closed: retained fstat deny and file-backed SQLite get allow. The remaining 12
FD-deny and 47 SQLite rows are a 59-row authoring backlog, not closure credit.
No authoritative promotion is claimed: Phase 2 evidence remains diagnostic,
and the fix revision still requires independent adversarial re-review.

**Fan-out method — retrospective, from Phase 1's parallel run
(2026-08-07).** Labeled "measured" through the 2026-08-07 revision; it is
not a measurement in the §3 rule 1 sense — no sample, no comparison
against an alternative method, no retained artifact — so it is relabeled
here. Its two mechanically checkable parts are promoted to §3 rule 12,
which binds; **everything else below is non-binding operational
advice.** Phase 2 is a much larger parallel campaign than Phase 1, so
record what actually worked:
give every agent its own **git worktree on its own branch** — exclusive
file ownership is not enough on its own, because agents sharing a checkout
collide on git state rather than on files; verify each branch's true diff
from its **merge base**, not from a moving `origin/main`, or the diff lies;
and expect the seams to appear at **unowned files** — Phase 1's version
seam was three constants nobody's slice owned, found by inspection rather
than by a failing test. Merge early and often: the one genuine integration
failure surfaced within minutes of the first three-way merge, and was
fixed by rebinding the caller's own fixtures rather than weakening the
assertion that caught it. Finally, when more than one session is live in
the same repository, re-check `git status` and `origin/main` before every
commit and never assert what is or is not on a shared branch from memory.

**Discipline (from LLP 0044 Proposal 3, unchanged):** strong model for
templates, zero model for rows — a wrong `requiredAuthority` mis-credits a
security probe; fan out template authoring and batch execution across
agents and the machine fleet (MACHINE_FLEET.md), bounded by engine-lock
contention and the rule 9 port-suite lock; every batch reports what it
skipped (no silent caps); a family that surfaces an attribution pattern
not covered by D1–D4 **stops and files against LLP 0037** rather than
landing a loosened assertion — and every such stop after calibration
triggers the §9 reforecast. Distinct from the attribution stop: a batch
that exposes a genuine **enforcement defect** — observed runtime behavior
contradicting the model's typed-decision claims, beyond attribution —
stops that family, files a P1, and holds all promotion-facing evidence
until the defect and its identity-restamp consequences (the LLP 0021/0032
chains) are through their own gates.

**Calibration before projection.** The first tranche is 5 template classes
spanning surface kinds (builtin export, native-op, host-abi, loader if in
scope). Measure: classes/day, rows/class, correction-loop iterations per
class (the LLP 0044 record predicts roughly one live contract-mismatch per
early batch — `Sign.end`, DEP0176, readline were found exactly this way),
**and the concurrent in-scope inventory growth rate (rows/day)** — the §9
net-closure criterion needs both slopes. Only the measured slope, not
LLP 0044's "2–4 weeks at 4–8 streams" estimate, is allowed to project the
campaign end date.

**Calibration result, 2026-08-06 — the tranche as designed above is not
achievable, and the unit of work is not what this section assumed.**
Evidence: `llp/evidence/0049-calibration-tranche-report.json`. Two classes
closed to the full gate standard (16 rows: `surface.native.op × [env:read]`
whole class, and two direct-list cells of `surface.native.op × [fs:list]`),
one class stopped on a genuine enforcement defect, and **the two remaining
candidate classes were rejected because they are executor-construction
work, not template authoring**. What survives from that tranche:

- **Both completed classes needed executor changes**, one requiring three
  separate generalizations for six rows. LLP 0036's "small executor edit
  per family" is confirmed as the real unit of work, and it is
  security-sensitive Rust, not template text.
- **Do not project the campaign from this sample.** Two `native-op` classes
  of 1–2 cells each, against a distribution whose largest in-scope class is
  454 rows across 77 surfaces.
- Inventory growth measured 0 during the session, but that is an artifact
  of a session that changed no surface-bearing source — §9's net-closure
  criterion still needs a cross-session boundary measurement.
- The `surface.native.op × [env:read, fs:list]` enforcement-defect stop
  **is discharged**: `issues/20260806-exactwhich-declares-typed-effects-it-never-emits.md`
  is in `issues/closed/`, fixed by `54f69d0df` (typed enforcement for
  `__exactWhich`), and the class is re-authorable. The stop is accurate as
  history and stale as status; recorded here so nobody re-opens it.

**Withdrawn (2026-08-07b): "only `native-op` has an executor that can
produce an effectful source-bound receipt today."** That sentence was the
premise of the previous revision's §9 kill criterion and §10 item (f). It
is **false**, and it is false in a specific way this plan's own §3 rule 2
forbids: the calibration examined three surface kinds and found that
*among them* only `native-op` had such an executor; this document dropped
the domain and wrote it as a universal. Both round-3 reviewers falsified
it independently and with different counterexamples — Fable via
`surface.builtin.export`, Codex via `surface.startup.env` — and the
per-surface-kind measurement in §6.1 falsifies it directly: **three**
effectful executors exist.

Where the fault lies, precisely, because it is tempting to put all of it
on this document. The calibration artifact's `honestAccounting` field
*is* correctly scoped — it says the **two rejected candidate classes**
had no executor able to produce a receipt for an effectful surface of
their kind, which remains true. But its `costModelFindings[3]` opens with
the same unbounded sentence in miniature ("Only native-op had an executor
able to produce an effectful source-bound receipt") and then concedes two
sentences later that `surface.startup.env` "has an effectful probe path."
So the artifact is internally inconsistent, and the plan promoted the
weaker half of it. The lesson in §3.1 applies to both: an evidence
artifact is not exempt from the quantifier discipline, and a plan reading
one must reconcile it against itself before inheriting a sentence.

§3.1 records the meta-lesson. §6.1 replaces the claim with the
measurement; §6.2 records what the measurement means for the scope
selection itself.

### 6.1 The measured executor capability matrix (2026-08-07)

Retained at
`llp/evidence/0049-executor-capability-matrix-ff9b3031….json` (schema
`ibex/llp-evidence/executor-capability-matrix/1`), generated at HEAD
`322b4260d` against catalog
`sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs` (22,505 required
fixtures) and joined to the same scope logic as
`scripts/capsec-scope-measurement.mjs`, so its 3,911 rows / 488 surfaces
/ 79 classes reconcile exactly with the §6 worklist. Every executor tier
below was derived by reading the emitting Rust; every claim in the
artifact carries `file:line`.

**Tiers.** An *effectful source-bound receipt* is a fully-executable
recipe whose public-surface invocation carries
`expectedTypedDecisionCount > 0` **and** non-empty capability action ids,
validated against decisions harvested from the loaded engine.

- **T0** — no executor serves this surface kind at all.
- **T1** — an executor exists but structurally cannot produce an
  effectful receipt (hard-asserts non-capability classification, and/or
  pins `expected_typed_decision_count == 0`, and/or pins empty action
  ids).
- **T2** — effectful, but only for an enumerated reviewed set of sources;
  a new source needs a reviewed-table edit.
- **T3** — reusable effectful: generic invocation machinery; a new
  surface needs arguments and setup but no structural change.

| surface kind | tier | rows | surfaces | classes | executor(s) | what a new row costs |
| --- | :-: | ---: | ---: | ---: | --- | --- |
| `surface.loader.route` | T0 | 1,195 | 131 | 9 | — | new executor construction |
| `surface.builtin.export` | T2 | 673 | 98 | 10 | `builtin-public` (effectful, `capsec_public_builtin_batch.rs:1683`) | reviewed-table edit for `node:os`-shaped exports only — see qualification 1 |
| `surface.startup.env` | T2 | 498 | 52 | 8 | `startup-environment-public` (effectful, `capsec_public_startup_environment_batch.test.rs:1627`) | reviewed-table edit — see qualification 1 |
| `surface.loader.function` | T1 | 487 | 47 | 5 | `module-loader-captured-route` (`capsec_public_noncap_builtin_batch.rs:3825`) | new effectful path |
| `surface.loader.operation` | T0 | 310 | 55 | 5 | — | new executor construction |
| `surface.host.abi` | T1 | 270 | 45 | 9 | `host-abi-public` (`capsec_conformance_batch.rs:3078`), `module-runner-host-abi` (`:3526`) | new effectful path — see qualification 3 |
| `surface.native.op` | T3 | 200 | 31 | 10 | `native-public` (effectful, `capsec_conformance_batch.rs:4091`) | arguments + setup, no structural change — see qualification 2 |
| `surface.loader.entry` | T0 | 132 | 11 | 3 | — | new executor construction |
| `surface.startup.supervisor` | T0 | 50 | 10 | 4 | — | new executor construction |
| eight leaf loader kinds (`require`, `json`, `commonjs`, `dynamic`, `native`, `esm`, `private`, `oxc`) | T0 | 12 each = 96 | 1 each = 8 | 2 each = 16 | — | new executor construction |
| **total** | | **3,911** | **488** | **79** | | |

**Rolled up by tier — this is the number that governs the campaign:**

| tier | rows | share | meaning |
| --- | ---: | ---: | --- |
| T3 | 200 | 5.1% | reachable with no structural executor change |
| T2 | 1,171 | 29.9% | nominally a reviewed-table edit |
| T1 | 757 | 19.4% | an executor exists and cannot be made to emit a receipt as written |
| T0 | 1,783 | 45.6% | no executor at all |
| **T1 + T0** | **2,540** | **64.9%** | **behind new executor construction** |

Three effectful executors serve the worklist today: `native-public`
(T3, generic — `setup_script` `capsec_conformance_batch.rs:1018`,
`materialize_native_arguments` `:1394`, `native_invocation_script`
`:1543`, with no `_ => panic!` catch-all on a global name),
`builtin-public` (T2 — classification pinned to `"effects"`
`capsec_public_builtin_batch.rs:1042`, observed typed decisions validated
against the pinned count `:1077-1084`, real on-disk postconditions
`:517-601`, 205 recipes already authored for this tuple `:449-463`), and
`startup-environment-public` (T2 — classification pinned to `"effects"`
`capsec_public_startup_environment_batch.test.rs:703`, `:881`, `env:read`
effects validated against decisions harvested from a real loaded-engine
evaluation `:1122-1152`).

**Four qualifications, without which the tiers mislead:**

1. **The T2 tiers are soft, and for this worklist mostly structural.**
   Authorable rows are by construction rows whose sources are *not* yet
   exercised, so a T2 tier always means at least one reviewed-table edit
   per source — and here usually more. Only **3 of the 673**
   `surface.builtin.export` rows and **0 of the 498**
   `surface.startup.env` rows sit on a cell that already carries an
   effectful fixture. The in-scope builtin-export sources are not
   `node:os`: they are `exact_sqlite` 246, `node_fs` 210,
   `node_fs_promises` 115, `node_child_process` 90, `node_dns` 12. The
   executor pins `module_specifier == "node:os"`
   (`capsec_public_builtin_batch.rs:628`) and `"node:fs"` (`:640`,
   `:788`) and panics on anything else (`:970`), so **463 of the 673
   rows are new-executor-scale work despite the T2 tier**, and the
   remaining 210 `node_fs` rows each need a new `expected_caps` arm
   behind a panic (`:656-686`, `:685`). On the startup side, **0 of the
   52 authorable environment names overlap the 11-entry
   `EXPECTED_SOURCES` table** (`:176-306`), and the worklist names are
   startup path-resolution reads (`HOME`, `TMPDIR`, `EXACT_*`,
   `IBEX_*`), not the tty/date/emitter mechanisms the executor's 5-arm
   dispatch implements (`:1199-1246`, `:449-491`), so most also need new
   mechanism JS on both sides. A further 102 of those 498 rows carry
   `fs:*` or `process:*` actions that executor has never validated.
2. **`process:*` is unproven everywhere, in every tier.** **Zero**
   recipes with status `fully-executable` in the entire 22,505-row
   catalog carry any `process:*` action id, while **197 authorable
   in-scope rows touch `process:*`** (`surface.builtin.export` 90,
   `surface.native.op` 59, `surface.startup.env` 48). The T3 tier on
   `surface.native.op` does **not** imply its 59 `process:spawn` rows
   are reachable: they have no `NativeProbeSetup` variant
   (`capsec_conformance_batch.rs:302-350`) and no effectful precedent
   anywhere, and the artifact records their structural cost as
   explicitly **undetermined** — settling it needs an authoring attempt,
   not more reading. The 200-row T3 figure is therefore an **upper
   bound** on what is reachable without construction; 14 of the 31
   authorable native globals are already proven effectful, the other 17
   (spawn/exec/sqlite/which/readlink) are not.
3. **`surface.host.abi` admits the `effects` classification and still
   cannot emit a receipt** — and the mechanism matters, because the
   2026-08-07 revision got it wrong while reaching the right
   conclusion. `execute_host_abi_public_recipe` *does* admit
   `classification == "effects"` (`capsec_conformance_batch.rs:3091`);
   what blocks the receipt is that **both** host-abi executors pin
   `expected_typed_decision_count == 0` (`:3111` and `:3552`), with
   empty action ids and empty typed stages (`:3096`, `:3113`). Zero of
   the 33 fully-executable host-abi-function probes in the catalog
   carry a typed decision. Admitting the effects *classification* is not
   producing an effectful *receipt*; only the second is a §3 rule 2
   mechanism claim.
4. **The loader block is the largest single obstruction and was never
   examined by the calibration.** **1,783 rows — 45.6% of the worklist**
   — are on surface kinds with **zero** public-surface probes of any
   invocation schema (`surface.loader.route` 1,195,
   `surface.loader.operation` 310, `surface.loader.entry` 132,
   `surface.startup.supervisor` 50, and the eight leaf loader kinds at 12
   each). Counting `surface.loader.function` (T1, 487 rows), the loader
   family alone is **2,220 rows / 38 template classes / 56.8% of the
   worklist**, and it contains this section's own cited largest in-scope
   class (`surface.loader.route × [fs:list, fs:read]`, 454 rows across 77
   surfaces). Its only two executors — `module-loader-authority`
   (`capsec_conformance_batch.rs:3845`, non-capability `:3867`, zero
   decisions `:3884`) and `module-loader-captured-route`
   (`capsec_public_noncap_builtin_batch.rs:3825`, `:3837`, `:3845`) — are
   both structurally non-effectful, so even reusing the nearest neighbour
   discharges nothing. Whether those executors could be extended rather
   than replaced is an authoring decision the artifact records as
   undetermined.

### 6.2 Executor reachability is a second scope-selection axis

This is the part of the measurement that reaches past Phase 2.

LLP 0044 selected **fs+env+process** as the v1.1 scope because it measured
the scope **89% clean — 457 of 513 cells certifiable**
(`llp/evidence/0044-scope-measurement-09e6aece….json`). That measurement
is sound and is not in question. But it measured exactly one thing:
**Lane B/C/D poisoning** — whether a cell's rows can be *proved* at all.

**Executor reachability is a second, independent axis, and nobody
measured it until 2026-08-07.** A cell can be perfectly clean on the
poisoning axis and still be unauthorable, because no executor can drive
its surface kind. The two axes are genuinely independent: authorable rows
are *by definition* rows on clean cells, and yet 2,540 of them — 65% —
are behind new executor construction. `surface.loader.route` is the
worked example: 1,195 authorable rows, every one on a clean cell, not one
of them reachable.

**The consequence, stated plainly: scope selection needs both axes, and
the current scope was chosen on one of them.** fs+env+process is clean;
fs+env+process is not reachable. With 65% of the selected scope behind new
executor construction of unmeasured size, **fs+env+process as selected is
a materially larger program than LLP 0044 priced** — LLP 0044 §9's
half-day-to-a-day-and-a-half per template class assumed template
authoring against existing executors, which describes 5.1% of the
worklist.

Two corollaries for the machinery, not just for this scope:

- **The scope-measurement tool measures one axis.**
  `scripts/capsec-scope-measurement.mjs` reports cells / clean / poisoned
  / authorable rows / surfaces / template classes. It cannot report
  reachability, so a scope selected from its output alone is selected on
  half the evidence. Joining an executor-tier column into that tool — the
  matrix artifact already replicates its scope logic exactly, so the join
  is mechanical — would make both axes visible at every §3 rule 5
  boundary. Recommended as a Phase 2 instrument; not yet a deliverable,
  because §10 item (f) may re-cut the scope first.
- **"Authorable" is the wrong word for what the tool counts.** It counts
  *unpoisoned*. A row is authorable only if it is both unpoisoned and
  reachable. This document keeps the tool's vocabulary to stay
  reconcilable with the retained artifacts, but the distinction is real
  and is the reason §6.1 exists.

**Consequence for sequencing.** The campaign cannot be scaled until the
per-surface-kind executor-construction cost is measured, and the scope
itself may need re-cutting on the reachability axis before that cost is
worth measuring. §10 item (f) carries the fork, and it is now a genuine
scope/budget decision rather than a scheduling question.

### 6.3 Phase 2 exit gate

Exit gate (command):
`node scripts/capsec-scope-measurement.mjs --families fs,env,process
--catalog <fresh> --assert clean-unresolved=0` passes on a fresh catalog —
the pre-gate-code equivalent of scoped `unresolved-in-scope === 0` for the
clean set (once Phase 1's scoped `assertRecipeCatalogComplete` exists, it
supersedes this assertion); every batch's evidence envelope digest-bound
and retained; zero unexplained route-evidence or terminal deltas over the
whole campaign; **and, per §3 rule 11, a retained independent
implementation review with break-tests for every batch that lands an
executor change** — the exemption for a template-only batch is claimed in
that batch's evidence envelope, not assumed. Since §6.1 measures executor
work as this phase's dominant work product, the rule-11 item is the
phase's principal exit condition, not a formality.

## 7. Phase 3 — Ceremony, admission, advertisement

Entry gate: Phases 1 and 2 exit gates both passed, at the same source
revision (a joint re-measurement — the two phases will have raced).

1. **Freeze the scope artifact** as the genesis lineage entry (explicitly
   marked; admissible only because lineage records no prior scope), at a
   named source revision and catalog digest.
2. **Run the ceremony to completion**:
   `bun run verify:capsec-conformance -- --target aarch64-apple-darwin`
   under timeout policy v5 and the sharding rules of LLP 0032 — a single
   suite-run-instance, authoritative shards same-runner by construction,
   engine attested before and after every engine-using phase.
3. **Admit and advertise**: all four `checkPromotion` names green;
   `assertReportMayAdvertise` passes; the scoped completeness re-derived
   at admission from the bound inventory (never trusting the report's row
   list — the §5.1 report-admission amendment); non-empty attestation
   lands in `capsec/conformance/target-attestations.json` through the
   promotion lineage.
4. **Publish honestly**: release notes enumerate the uncertified remainder
   by family, generated from the same validated expansion diff the gate
   checks; ≥1 negative-control probe per major uncertified family on the
   exact advertised build, carried in a **distinct diagnostic schema** so
   control evidence can never enter promotion evidence, labeled
   evidence-not-proof; runtime introspection exposes the active scope
   digest and remainder.
5. **Wire the standing guards**: the ceremony joins CI next to
   `check:secure-mode`; the scope artifact joins the drift checks so a
   silent inventory change cannot leave a stale advertisement standing.

Exit gate — the plan's definition of done: a verified scoped advertisement
for `aarch64-apple-darwin` admitted on `main`; explicit CapSec selection of
that tuple arms in-scope cells and gives the uncertified remainder
**exactly the disposition the reviewed `ScopedAdvertised` state
specifies — a disposition, not a refusal claim** (§3 rule 8: out-of-scope
surfaces carry no conformance claim, and any refusal property CI asserts
names its exact layer — startup admission, typed-gate refusal, or, only if
register item 2 selected it, physical entrypoint refusal); CI proves the
in-scope arming and the reviewed disposition on every commit.

## 8. What comes after (recorded so nobody hunts for it here)

- **Network**: the LLP 0046 §6 sequence — origin-policy decision,
  re-measure post-seeding-fix (Lane B is already 292, not 338, and the
  CAP/policy/pure/stub partition has not been re-cut since), then a plan
  organized by analyzer capability. Separate LLP.
- **Second tuple**: Windows, under register item 7's congruence decision.
  The Windows `rust-default-full` suite is broadly red
  (issues/20260805-windows-rust-default-full-suite-broadly-red.md) and
  must be green before its ceremony means anything.
- **Scope expansion**: strictly monotone via the lineage chain; each
  expansion is a new promotion, never an edit.
- **LLP 0039 revisit**: whether a scoped advertisement satisfies the
  `unadvertised-dev-arming` retirement condition (§10 item d).

## 9. Schedule shape and kill criteria

No dates until calibration reports. The prior estimates are recorded as
hypotheses to test, not commitments: LLP 0044 §9 priced the campaign at
roughly half a day to a day and a half per template class, 2–4 weeks
wall-clock at 4–8 parallel streams, low-single-digit thousands of dollars
in tokens; Phase 1's review loop is the serial critical path and recent
loops (LLP 0026–0045) ran 3–8 rounds over 3–10 days.

**Kill criteria — each returns to the author with data, none is silent:**

- Calibration slope projects the campaign beyond **8 weeks** at planned
  parallelism → stop; re-open register item 9 (budget) before continuing.
- **Net closure fails** (the treadmill): the scope is intensional, so
  in-scope inventory growth continuously refills the worklist (+671 rows
  in the five days before authoring; calibration records the live rate).
  If two consecutive phase-boundary re-measurements show the worklist
  failing to shrink at all (W_boundary ≥ W_previous — equivalently,
  inventory growth ≥ rows authored in the interval), authoring is losing
  to growth outright → return to the author. Slower-but-positive closure
  is governed by the 8-week projection line above, not by this criterion.
- **Executor-construction cost exceeds the baseline by 2x on any surface
  kind** → stop scaling that kind and return to the author with the
  measurement. The per-kind multiplier is the campaign's dominant unknown
  (§6.1, §10 item f), and a blown estimate there invalidates every
  projection built on it. The 2026-08-07 form of this criterion said
  "exceeds its spike estimate by 2x" and **had no operand** — no unit, no
  baseline, no artifact, and a spike defined as a measurement rather than
  an estimate. Round 2 killed a criterion for wrong arithmetic; this one
  had none. Fully specified, it is:
  - **Unit.** Executor-construction wall-clock minutes per authorable row
    of the surface kind — continuous with what the calibration tranche
    already records per class (`authoringWallClockMinutes`,
    `correctionLoopIterations`). Template authoring, batch runtime and
    catalog regen are counted separately and are **not** in this unit;
    the criterion prices Rust construction, which is what §6.1 says
    dominates.
  - **Baseline `E`.** The cost-per-row measured by the §10(f)(iii)
    spike, retained as
    `llp/evidence/0049-executor-spike-<surface-kind>-<digest>.json` and
    given a §11 row when it lands. That artifact must record: the surface
    kind, its pre-spike tier, rows closed, executor-construction minutes,
    correction-loop iterations, and the resulting cost-per-row.
  - **Extrapolation rule (explicit, because one spike cannot price every
    kind).** `E` from a spike at tier `t` is the baseline for every
    surface kind at tier `t` **or worse** (T0 is worse than T1; both mean
    new construction). A kind at a **strictly better** tier inherits
    nothing — a T2 kind is not priced by a T0 spike and gets its own
    first-class measurement before it is scaled. No baseline crosses
    from a better tier to a worse one in either direction by default.
  - **Predicate.** For surface kind `k`, let `C_k` be the measured
    cost-per-row once the greater of one full template class or 20% of
    `k`'s authorable rows has closed. `C_k > 2 × E` → stop scaling `k`.
  - **Armed state.** Until the spike artifact exists this criterion is
    **unevaluable and is not in force**, and this plan says so rather
    than implying a gate that cannot fire. If §10 item (f) resolves to an
    option with no spike, the first surface kind whose construction is
    funded produces `E` instead, under the same artifact contract.
- **Cumulative reforecast**: every post-calibration LLP 0037 stop (a new
  attribution pattern) re-projects the end date; a third stop, or any
  re-projection past the 8-week line, re-opens item 9 — repeated
  "healthy" pauses must not make the program unbounded without a
  decision.
- The 73 poisoned cells survive both audit lanes and the grammar-extension
  review → re-cut the scope on the Phase 0 measurement; if no family
  subset both survives poisoning and is worth advertising, item 1 returns
  to the author.
- **Register item 2 decided as physically refused** (§4.2), or **item 5
  rejected after the join-matrix review** (§5.3) → the plan halts and
  returns to the author for re-scoping and re-estimation; neither posture
  is executable under this document as written.
- The join-matrix review finds scope substitution unpreventable without
  restructuring the armed-snapshot format → the LLP 0021 amendment grows
  a format migration; re-estimate before proceeding.
- **Phase 1 review-loop bound**: after three rounds the loop stops and the
  package goes to the author with the disagreement ledger, per LLP 0005 —
  the corpus precedent is that these loops end on author decisions, not
  convergence, and the serial critical path must not wait on a permanent
  NOT READY stance. **Amended by author directive 2026-08-06** after the
  round-3 split verdict (Fable READY / Codex NOT READY): up to **three
  further rounds** (4–6) are authorized, under an explicit decision rule —
  **the package moves forward when the Claude/Fable family reports READY**,
  regardless of the Codex verdict. Codex findings continue to inform
  revisions; they no longer gate progress. If Fable has not reported READY
  by the end of round 6, the loop stops and the package returns to the
  author with the ledger.
- Any phase-boundary re-measurement moves the worklist by more than 5% →
  re-cut the tranche plan (§3 rule 5) — routine, not fatal; but
  **cumulative** drift exceeding 15% since the last full re-plan forces a
  full re-plan, so repeated sub-threshold drift cannot evade the rule
  indefinitely.

## 10. Decisions this plan surfaces (author register)

> **Ledger — 2026-08-06:** item (a) DECIDED — the full §4.2 packet
> resolved (see the dated resolution record in LLP 0044 §7): items 1, 2,
> 4 and the ambient-set ruling by explicit author choice (all four
> recommendations accepted: scoped certification adopted; uncertified
> remainder; fs+env+process; target-inapplicable-in-secure-profile with a
> generated release constraint); items 3, 6, 8, 9, 10 taken as
> recommendations under the author's standing default-recommendation
> disposition and recorded. Item (c) is thereby discharged (the packet is
> decided; Phase 2 may enter). Items (b), (d), (e) stand as written —
> (b) activates in Phase 1, (d) at Phase 3 close.
>
> **Ledger — 2026-08-07b:** item (f) is **OPEN**, and it is the register's
> only genuine fork. The "author indicated agreement 2026-08-07" recorded
> in the previous revision's (f) was given under the executor claim §6.1
> falsifies, so it does **not** carry and is withdrawn; item (f) below is
> rewritten with four options and a changed recommendation. Item (a)'s
> decision on LLP 0044 item 4 — **fs+env+process** as the v1.1 scope — is
> the specific decision option (f)(ii) would re-open: it was taken on the
> poisoning axis alone (§6.2), and re-opening it is a scope change, not a
> process failure. No other item's status changes.

a. **Adopt the Phase 0 decision packet** (LLP 0044 items 1, 2, 3, 4, 6, 8,
   9, 10 — all eight decided at §4.2 exit — plus the
   `ex_host_env_ambient_set` disposition). Recommendations: accept scoped
   certification (1); uncertified, not physically-refused, remainder (2 —
   the refused posture is a materially larger runtime program with no
   estimate, and a §9 diversion); complete-cell scope unit (3);
   **fs+env+process** as the v1.1 scope (4); monotone lineage as specified
   (6); Lanes A–D audit scopes as specified (8); budget per calibration
   (9); formal multi-model review for the Phase 1 package (10).
b. **Poisoned-cell route** (§5.2): audits first, grammar extension only if
   a remainder survives, scope re-cut as the fallback.
c. **Whether Phase 2 may start before the Phase 0 decision packet is
   decided.** Recommendation: no — §6's entry gate encodes this
   (authoring against an unaccepted scope risks exactly the wasted-yield
   failure LLP 0045 recorded, and item 9 sizes the fan-out). The only
   exception already exists (env:write, landed, and in every candidate
   scope).
d. **Whether a verified scoped advertisement satisfies LLP 0039's
   condition for retiring `unadvertised-dev-arming`.** Recommendation:
   partially — retire it for the advertised tuple only, keep it elsewhere;
   record the ruling in LLP 0039 either way.
e. **Review intensity for this plan itself.** Recommendation: stakes-scaled
   per LLP 0005 — this document sequences work but changes no claim
   boundary itself; the claim-boundary artifacts it produces (Phase 1
   package, including the two must-amend consumers' implementations) carry
   the formal loop instead. (This document received a bounded two-round
   dual-model review on 2026-08-06 and a third, execution-round delta
   review on 2026-08-07 — both families NOT READY; artifacts under
   `llp/reviews/0049-*`.)

f. **The v1.1 scope, re-opened on the executor-reachability axis.**
   *(Printed between (d) and (e) through the 2026-08-07 revision; moved to
   its correct position 2026-08-07b.)* **This is a genuine author fork —
   scope and budget — not a scheduling question,** and it is the only such
   item now open in this register.

   *Status of the prior agreement.* The 2026-08-07 revision recorded
   "author indicated agreement" with a bounded spike. That agreement was
   given under the premise that only `native-op` had an effectful
   executor and the remaining ~79 classes were uniformly gated on Rust
   work. §6.1 falsifies that premise: three effectful executors exist, the
   worklist splits 200 / 1,171 / 757 / 1,783 across tiers, and the kind a
   spike would land on was never examined. **The agreement therefore does
   not carry, and (f) is open.**

   *What is actually measured* (§6.1, from
   `llp/evidence/0049-executor-capability-matrix-ff9b3031….json`): of
   3,911 in-scope rows, **200 (5.1%) are reachable with no structural
   executor change** — and 59 of those are `process:spawn` rows with no
   precedent anywhere and an undetermined structural cost — while **2,540
   (64.9%) are behind new executor construction**, and **1,783 (45.6%)
   are on surface kinds with no executor of any kind**.

   Options:

   - **(i) Fund the executor construction for the full fs+env+process
     scope.** ~2,540 rows behind new executors, spanning the loader
     family (2,220 rows / 38 classes, no effectful path at all), the
     host-abi family (270 rows), plus structural work for 463 of the 673
     builtin-export rows. Honest about what LLP 0044 chose; expensive,
     and its size is unmeasured in every one of those kinds.
   - **(ii) Re-cut the v1.1 scope on the executor-reachability axis —
     advertise a genuinely reachable scope first. (Recommended.)** The
     scope was selected on the poisoning axis alone (§6.2); re-cutting it
     with reachability joined in produces a first advertisement that can
     actually be built, on evidence that already exists rather than on a
     spike yet to be run. **Why this is not a dead end:** LLP 0021 §A5
     makes lineage **monotone** — narrowing is expressible only as
     inventory retirement or authenticated rename/split/merge, and every
     expansion is a **new promotion, never an edit** (§8). Scope grows
     over time by construction, so a small honest first advertisement is
     the intended growth path, not a ceiling. **What it costs:** a
     smaller first claim. The advertised surface would be a fraction of
     fs+env+process, the release note's uncertified remainder would be
     correspondingly larger, and LLP 0044's "fs+env+process" headline
     would not be the v1.1 claim. §3 rule 8 already requires that
     remainder to carry no conformance claim, so the smaller scope costs
     credibility only if the plan oversells it — which is the failure
     this whole revision exists to correct.
   - **(iii) A bounded spike on `surface.loader.route`** — the highest-row
     unreachable kind at 1,195 rows / 131 surfaces / 9 classes, and the
     home of the largest in-scope class (454 rows). Closed to the full
     gate standard, purely to price executor construction before
     choosing, and producing the `E` baseline §9's criterion needs. Note
     what this option is: it defers the choice between (i) and (ii) by
     buying information, and it buys that information from the hardest
     kind in the worklist, which is the right place to buy it and also
     the most expensive.
   - **(iv) Exhaust the 200 reachable rows first.** Honestly: this is
     **5.1% of the worklist**, it does not constitute a campaign, and it
     cannot on its own reach `unresolved-in-scope === 0` for any scope
     worth advertising. It is a **sequencing detail** — sensible under
     (ii) and harmless under (i) or (iii) — not a strategy, and it should
     not be recorded as one. (Round-3 review proposed a larger version of
     this option, ~873 rows including all of builtin-export; §6.1
     qualification 1 falsifies it — 463 of those 673 rows are structural
     and the other 210 each need a Rust arm behind a panic.)

   Until (f) is discharged, no campaign end date may be projected: §9's
   8-week line has nothing to measure against, and §9's executor-cost
   criterion is explicitly unarmed.

> **Author ruling — 2026-08-08: the first advertised scope MUST contain
> zero poisoned cells.** Asked whether a first advertised scope may carry
> poisoned cells at all (the question the re-cut measurement could not
> answer, because it is not measurable), the author ruled **no**, and
> explicitly accepted more executor work as the price. This eliminates
> candidates A2, A, B and F — every scope carrying native-op's 14 Lane C
> cells — including the re-cut's own recommendation. The surviving
> zero-poison candidates are **C** `{env}×{startup}` (65 cells, 406
> authorable rows, floor 610, T0 10 · T2 396), **C2**
> `{env,fs,process}×{startup}` (73 / 548 / 650, T0 50 · T2 498), **D**
> `{env}×{host-abi,startup}` (72 / 441 / 645, T0 10 · T1 35 · T2 396) and
> **E** `{fs}×{host-abi}` (38 / 235 / 235, T1 235). Evidence:
> `llp/evidence/0049-scope-recut-candidates-ae3fcc4f….json`. The choice
> among them turns on executor-construction cost, which is being priced
> against the code rather than estimated; note E is the only candidate
> whose floor equals its authorable rows, i.e. carrying no out-of-family
> debt.

> **Attribution finding — 2026-08-08: `native-op` is the only surface that
> gets credited, and this supersedes the candidate analysis above.** Two
> observation spikes drove candidate E's four host-ABI resolvers and four
> structurally distinct candidate C startup-env cells under a fresh armed
> enforce Host and recorded every typed decision with the coverage edge it
> attributes to. **All eight fail D2**: no decision names the observed
> cell's own edge. E's decisions attribute to
> `native-op.exactreadfile` / `loader.require.resolve`; C's ten observed
> decisions all attribute to `native-op.exactgetenv`; the other three C
> shapes emitted no typed decision at all. Evidence:
> `llp/evidence/0049-observation-spike-e-hostabi-resolvers.json`,
> `llp/evidence/0049-observation-spike-c-startup-env-92ac3c91….json`.
>
> With `__exactWhich` and the 41 withdrawn host-ABI primitives this is the
> fourth confirmation of a single architectural fact. The enforcement is
> sound; the coverage model has been declaring authorization on surfaces
> that sit above the layer where the decision is actually made. **E, C, C2
> and D are all disqualified** — every zero-poison candidate was startup-
> or host-abi-based.
>
> **Author ruling — 2026-08-08:** pursue **A2** `{fs}×{native-op}` (54
> cells, 137 authorable rows) by **auditing its 14 Lane C poisoned cells
> to clear them**, which satisfies the standing zero-poison ruling rather
> than relaxing it. Lane C clearance requires the closed-world source join
> plus loaded-target absence evidence mapped to every credited row
> (LLP 0044 §3); "no recorded public invocation path" is not itself proof
> of unreachability. The broader model correction — withdrawing
> mis-attributed declarations across every non-`native-op` surface kind —
> is accepted as **follow-on work that must not block the first
> advertisement**.

> **Lane C A2 audit result — 2026-08-08: CLEARED 14 / AUTHORABLE 0 /
> UNDETERMINED 0.** The closed-world source join found physical public
> façades for ten cells, but no invocation path capable of emitting any of
> the fourteen credited seed edges. `Exact.which` / `Bun.which` and
> `Exact.write` / `Bun.write` close over exact inner native gates; the four
> module façades close over the captured resolver and authenticated loader
> gates; the two returned legacy-handle readers are hard-closed at the
> secure armed boundary; and the four raw resolver globals are captured and
> deleted before package execution. The armed loaded-target regression
> confirmed the exact inner edge IDs, alias identities, raw-global absence,
> and zero-decision handle refusals. Every one of the 138 credited rows is
> mapped in the retained artifact. This was a seeding/model defect, not a
> missing public-invocation inventory defect, so no inventory ticket was
> filed. The exact-string correction regenerates A2 from **54 cells / 14
> poisoned / 137 authorable rows** to **40 / 0 / 137**. Both required diff
> gates and `check:drift` exit zero.

## 11. Evidence index

Every phase adds its artifacts here as it closes; the plan is out of
compliance if a §3 rule 1 figure lacks a row.

| artifact | digest / path | phase |
| --- | --- | --- |
| authoring-time catalog summary (`aarch64-apple-darwin`, `aaa007ad`) | llp/evidence/0049-authoring-catalog-summary-4381ae02a8c7ee5d4438debc5ad0b664b6fe291ea80fae34a6a3ff77dbd4758a.json (full catalog digest `sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY`, re-derivable by regen at `aaa007ad`) | §2 |
| LLP 0044 day-one scope measurement (superseded by 2026-08-05 re-measure) | llp/evidence/0044-scope-measurement-09e6aece….json | §2 |
| representative batch timing (16.24 s) | llp/evidence/0044-batch-timing-501504f6….json | §6 |
| paired allow-list worked example | llp/evidence/0045-allow-list-duplicate-definition-hygiene.json | §3 |
| **Lane C A2 closed-world audit** — 14 cells and all 138 credited rows; CLEARED 14 / AUTHORABLE 0 / UNDETERMINED 0; A2 54 / 14 poisoned / 137 rows → 40 / 0 / 137 | `llp/evidence/0049-lanec-audit-a2-bdf8c0830f289761d3f99d9f57ad65c7c8849699ee4caa77abb4a7fdc44e1d34.json` (raw-file SHA-256 `bdf8c0830f289761d3f99d9f57ad65c7c8849699ee4caa77abb4a7fdc44e1d34`; baseline catalog `sha256-vCNYGlWKR7woDl-piD2Ae4BtZxMWmE46ovTG_VSWsYo`; candidate `sha256-jJZNbFdLXbS3C92g7RhbJmTIJXtgGFOoovo47a9XmRI`; allow-list `llp/evidence/0049-allow-list-lanec-audit-a2.json`) | §3 / §10(f) |
| Phase 0 post-seeding scope measurement (fs+env+process unchanged: 610 / 537 clean / 73 poisoned / 3,927 rows) | llp/evidence/0049-scope-measurement-postseeding-df1da4b5….json | §4 |
| Phase 0 seeding allow-list (rule 3, strict mode, 1,544 entries, 2,722/2,722 explained) | llp/evidence/0049-allow-list-phase0-seeding.json | §4 |
| Phase 0 terminal allow-list (rule 7, 463 entries) | llp/evidence/0049-terminal-allow-list-phase0-seeding.json | §4 |
| Phase 0 post-fix catalog digest (`22,505 / 3,926 / 3,124 / 15,455`; network Lane B 284 → 216) | `sha256-sMzObEF9jpCF5fpgJ4FIigkj05e2-FjFsrNqj9t3mhQ` (re-derivable by regen at the Phase 0 commit) | §4 |
| calibration tranche report (authoring slope + inventory growth rate) | llp/evidence/0049-calibration-tranche-report.json (2 of 5 planned classes completed to the full gate standard, 16 rows; 1 class stopped on an enforcement defect; the other 2 candidate classes were rejected as executor-construction work, not authoring) | §6 |
| Phase 2 calibration close scope measurement (3,927 → 3,911 rows / 491 → 488 surfaces / 80 → 79 classes) | llp/evidence/0049-scope-measurement-phase2-calibration-close.json (catalog `sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs`) | §6 |
| per-batch evidence envelopes | llp/evidence/0049-batch-`<template-class>`-`<digest>`.json — landed: `native-op-env-read-5EaSZ…` (6 rows), `native-op-fs-list-dzsLtl…` (10 rows), `native-op-fstat-retained-9YEp…` (1 newly authored row; reviewed NOT READY, flip set applied), `native-op-sqlite-get-retained-n3v05…` (1 newly authored row; independent re-review pending) | §6 |
| per-class paired allow-lists (rule 3, strict mode) | llp/evidence/0049-allow-list-class-native-op-env-read.json, llp/evidence/0049-allow-list-class-native-op-fs-list.json, llp/evidence/0049-allow-list-class-native-op-fstat-retained.json, llp/evidence/0049-allow-list-class-native-op-sqlite-get-retained.json | §6 |
| retained-handle independent review | llp/reviews/0049-a2-retained-handle-setup-executor.fable.md — `NOT READY`; FD authority separation accepted, four-item SQLite/count/disclosure flip set applied at the subsequent fix revision; re-review still owed | §3 rule 11 / §6 |
| **per-surface-kind executor capability matrix** — the source of every §6.1/§6.2/§10(f) figure (3,911 rows by tier: T3 200 / T2 1,171 / T1 757 / T0 1,783; 2,540 behind new executor construction; 197 process-touching rows; 0 fully-executable `process:*` recipes in 22,505) | llp/evidence/0049-executor-capability-matrix-ff9b303171350b36604359a8eb026d88a32d3248703d004c62b712a46623acd7.json (schema `ibex/llp-evidence/executor-capability-matrix/1`, generated at HEAD `322b4260d`, catalog `sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs`) | §6.1 |
| LLP 0044 day-one 89%-clean scope selection (457 of 513 cells certifiable) — the one-axis measurement §6.2 says is necessary and not sufficient | llp/evidence/0044-scope-measurement-09e6aece….json | §6.2 |
| Phase 1 implementation review + break-tests (§3 rule 11 discharge) | **OWED** — llp/reviews/0049-phase1-implementation.`<family>`.md; not yet retained, so rule 11 is undischarged for Phase 1 and the §5.3 gate-code figures are withdrawn rather than restated | §5.3 |
| executor-construction spike cost baseline (`E` for §9's criterion) | **OWED, conditional on §10(f)** — llp/evidence/0049-executor-spike-`<surface-kind>`-`<digest>`.json; until it exists §9's executor-cost criterion is unarmed | §9 |
