# LLP 0049: Scoped Attestation Execution Plan

**Type:** Plan
**Status:** Draft
**Systems:** Security, Conformance, CI, Runtime, Tooling
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-06
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
**3,927 clean authorable rows across 491 surfaces in 81 template
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
> 3,927/491/81, and §6's worklist figure is re-derived at entry per
> rule 5 regardless. Per §3 rule 5 all such figures are snapshots and
> must be re-derived at each gate, not quoted from here.

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
gate code landed with its adversarial fixtures green; `check:secure-mode`
green; **§5.2 disposition complete** — each of the 73 poisoned cells is
audit-cleared, grammar-excluded under the reviewed extension, or covered
by a decided scope re-cut. `unresolved-in-scope === 0` is unreachable at
Phase 3 while any of the 73 lacks a disposition, so this phase does not
exit without one.

> **Review-package exit-gate condition: MET (2026-08-06).** The first two
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

## 6. Phase 2 — The authoring campaign (parallel with Phase 1)

Authoring needs no gate code, so this phase starts once Phase 0 completes
and runs concurrently with Phase 1. Two honesty constraints bound the
parallelism:

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

**Worklist:** the ~3,922 clean authorable rows across ~80 template classes
(re-derived at entry per §3 rule 5).

**The loop, per template class** (proven by the env:write landing):
author template → run batch on the bound engine → pin the observed typed
sequence (LLP 0037 D3 — observed, never guessed; `readFileSync` is 9
decisions, not 4) → regenerate catalog → confirm green → paired
allow-list diff (`--scope all`) + terminal-diff instrument (§3 rules 3
and 7) → commit, retaining the batch evidence envelope as
`llp/evidence/0049-batch-<template-class>-<digest>.json`. Per LLP 0037
D2, confirm per family that every surplus `fs:list` is traversal-stage
before pinning.

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

Exit gate (command):
`node scripts/capsec-scope-measurement.mjs --families fs,env,process
--catalog <fresh> --assert clean-unresolved=0` passes on a fresh catalog —
the pre-gate-code equivalent of scoped `unresolved-in-scope === 0` for the
clean set (once Phase 1's scoped `assertRecipeCatalogComplete` exists, it
supersedes this assertion); every batch's evidence envelope digest-bound
and retained; zero unexplained route-evidence or terminal deltas over the
whole campaign.

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
   dual-model review on 2026-08-06; artifacts under `llp/reviews/0049-*`.)

## 11. Evidence index

Every phase adds its artifacts here as it closes; the plan is out of
compliance if a §3 rule 1 figure lacks a row.

| artifact | digest / path | phase |
| --- | --- | --- |
| authoring-time catalog summary (`aarch64-apple-darwin`, `aaa007ad`) | llp/evidence/0049-authoring-catalog-summary-4381ae02a8c7ee5d4438debc5ad0b664b6fe291ea80fae34a6a3ff77dbd4758a.json (full catalog digest `sha256-z5QPdB9MRkAq54UR9Z_1R7f5mzeklzv0HIp0Iqy4wfY`, re-derivable by regen at `aaa007ad`) | §2 |
| LLP 0044 day-one scope measurement (superseded by 2026-08-05 re-measure) | llp/evidence/0044-scope-measurement-09e6aece….json | §2 |
| representative batch timing (16.24 s) | llp/evidence/0044-batch-timing-501504f6….json | §6 |
| paired allow-list worked example | llp/evidence/0045-allow-list-duplicate-definition-hygiene.json | §3 |
| Phase 0 post-seeding scope measurement (fs+env+process unchanged: 610 / 537 clean / 73 poisoned / 3,927 rows) | llp/evidence/0049-scope-measurement-postseeding-df1da4b5….json | §4 |
| Phase 0 seeding allow-list (rule 3, strict mode, 1,544 entries, 2,722/2,722 explained) | llp/evidence/0049-allow-list-phase0-seeding.json | §4 |
| Phase 0 terminal allow-list (rule 7, 463 entries) | llp/evidence/0049-terminal-allow-list-phase0-seeding.json | §4 |
| Phase 0 post-fix catalog digest (`22,505 / 3,926 / 3,124 / 15,455`; network Lane B 284 → 216) | `sha256-sMzObEF9jpCF5fpgJ4FIigkj05e2-FjFsrNqj9t3mhQ` (re-derivable by regen at the Phase 0 commit) | §4 |
| calibration tranche report (authoring slope + inventory growth rate) | llp/evidence/0049-calibration-tranche-report.json (2 of 5 planned classes completed to the full gate standard, 16 rows; 1 class stopped on an enforcement defect; the other 2 candidate classes were rejected as executor-construction work, not authoring) | §6 |
| Phase 2 calibration close scope measurement (3,927 → 3,911 rows / 491 → 488 surfaces / 80 → 79 classes) | llp/evidence/0049-scope-measurement-phase2-calibration-close.json (catalog `sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs`) | §6 |
| per-batch evidence envelopes | llp/evidence/0049-batch-`<template-class>`-`<digest>`.json — landed: `native-op-env-read-5EaSZ…` (6 rows), `native-op-fs-list-dzsLtl…` (10 rows) | §6 |
| per-class paired allow-lists (rule 3, strict mode) | llp/evidence/0049-allow-list-class-native-op-env-read.json, llp/evidence/0049-allow-list-class-native-op-fs-list.json | §6 |
