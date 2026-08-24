# Review: LLP 0055 r1 — grok (round 1)

**Reviewer:** grok-4.6, effort xhigh, headless (`--output-format plain`), full slice-1 diff inlined (no repository access); commissioning context inlined from Exact LLP 0417 §6, 0553.001 O-3, and orchestrator-verified ground truths.
**Date:** 2026-08-24. **Requested by:** the Exact 0417 H1 orchestrator lane (cross-family round 1).
**Verdict:** NOT READY (blocking findings 1–10). Folded into r2 — G5 code-verified against link_import/link_export record-id capture before adoption; G1/G2 adopted as wording/split fixes with 0417's taxonomy and rule-3 ordering preserved; G10 adopted via the effect-class qualification (the outstanding-effects refusal is not implementable — no effect census exists).

---

I'll start by reading the full commissioning prompt and the complete inlined diff so the review is based on the whole artifact, not the truncated excerpt.The prompt path from the system note didn't resolve; I'll locate the full request and the inlined diff in this workspace.The workspace has the full prompt and the complete diff. Next I’ll read both, then review the spec on its own terms.## Overall Assessment

The draft is a coherent H1 contract: four counters are separated, the capture table stays boot-only, the keypair/verifier split from the producer-only HMAC is the right 0042 move, and the per-slot token plus v1 runtime-recreate posture match the commissioning notes. It is not implementable as written. The publication seam is not atomic, the race-loss class can tear down a successful commit, getter indirection is specified only for namespace `recordId` capture, the V2 ceiling does not pin deferred membership, and the signed “base-graph digest” is ambiguous after the first revision. Those are specification defects, not leftover engine work.

## MATERIAL Findings (numbered; severity, the defect, the smallest fix)

**1. Blocking — race-loss classified as `full-reload-current-authority` undoes the winner.**  
§1 says the CAS loser “refuses (full-reload class) and restages.” §10 maps that refusal to `full-reload-current-authority`. §3 says that class tears down and recreates the runtime. On one owner thread the winner’s `commit` lands `r+1`, then the loser’s `commit` returns full-reload, and the host recreates, wiping the winner. A lost race is a coherent live graph at `r+1`, not a broken one.  
**Fix:** Map successor-law CAS failure to `keep-last-good`. Winner stands; loser drops shadow records; producer restages from the new live base. Drop “and restages” from the full-reload path.

**2. Blocking — `dispose-then-evaluate` is applying-in-place and runs before CAS.**  
Obligation 2 and §8 forbid an applying-in-place pipeline and put activation inside commit. §5.2 item 4 still exposes dispose-then-evaluate *before* `commit`, and §5.3’s atomic step does not include dispose or activate. Dispose can run against live records, then ceiling/converse/CAS can still fail, leaving disposed incarnations reachable through unretargeted slots. That is the pipeline §8 claims to have rejected.  
**Fix:** Delete the pre-commit dispose-then-evaluate hook. Dispose of the prior incarnation and activate of the next occur only after a successful successor-law CAS, inside §5.3. Pre-commit evaluation is shadow-only and must not mutate live host targets or registries. Failed commit then still sees the old graph.

**3. Blocking — the §5.3 publication step is not a closed atomic transaction.**  
The live `GenerationRecordV2` map and live v2 digest are never swapped, so the engine slots, the authenticated graph, and the next envelope’s bound digest can diverge. Replacement evaluation is not in the step, so slot retarget can expose TDZ (or skip evaluation entirely). Step 3 is JS (`__privInvalidateHotRevisionRecords`) under a “no interleaved JS execution” rule; re-entry can run getters mid-publish. Retarget (§5.3.1) before install-revision advance (§5.3.2) is only safe if `publish()` looks up the same live record getters use; that lookup is unspecified. If `publish()` still uses `current_install_revision`’s old row, an old token can publish after getters already see the new record.  
**Fix:** Make §5.3 one owner-thread transaction, in this order, with no JS and no `publish()` in between: (0) CAS, (1) install-revision advance *and* swap accepted-closure rows in the live V2 graph, recompute the live v2 digest, (2) slot-table retarget, (3) native loader-cache + carrier-memo eviction with a non-reentrant, non-user-JS path, (4) counter + receipt. Pin `publish()` to the slot’s current record id (same table as getters). Replacement records must be instantiated and past export TDZ before retarget is visible.

**4. Blocking — no shadow-graph `publish` predicate.**  
Staged records are keyed at candidate install revision `base+1` (§5.2.2). Live `publish` succeeds iff `token.install_revision == current_install_revision[source_id]` (§2.2). That map advances only at commit (§5.3.2). Shadow-evaluate is before commit (§5.2.4). Using live `publish` either always refuses shadow TLA/CJS/dynamic completions or publishes them into the live graph. Transaction-local publication is unspecified.  
**Fix:** Shadow `publish` writes only the transaction’s shadow map and succeeds iff `token.install_revision == txn.base+1` and `source_id ∈ txn.invalidated`. Live `publish` stays as in §2.2 and cannot see shadow rows.

**5. Blocking — getter indirection does not cover the actual import path.**  
§2.3’s normative runner change is only that `hermes_module_runner.cc` namespace getters stop capturing `recordId`. `import { x }`, `export { x } from`, `export * from`, and CJS→ESM synthetic namespaces are link-time live bindings onto cells, not those getters. If they keep a captured record id, replacing `B` without re-instantiating `A` is a no-op for named imports; F5 would still pass. 0023/§2.3 say outside importers bind the slot; the concrete change does not.  
**Fix:** State that every use of another module’s exports — namespace getters, module-environment live bindings, re-export forwarding, star exports, dynamic-import namespaces, CJS→ESM synthetics — resolves through the slot table at use time. Extend F5 with a named-import, a re-export chain, a star export, and a CJS adapter, each observing old-then-new with no mixed graph. CJS `module.exports` object identity must *not* be stable (0023 forbids sharing CJS exports).

**6. Blocking — 0023 still forbids sharing namespaces while F5 requires a stable namespace object.**  
0023 keeps “must not share … namespaces” and tries to save it by saying a slot is not a namespace. §2.3/F5 say importers hold a stable namespace *object identity* whose getters retarget. Implementers will mint a fresh exotic object per incarnation (break F5) or reuse one (break 0023).  
**Fix:** In 0023 and §2.3: the ESM namespace exotic object is slot-owned, one per `(ExecutionGeneration, SourceId)`, stable for the generation. Incarnations must not share module environments, cells, promises, cached errors, or CJS export objects. Getters on the slot-owned namespace must not expose a prior incarnation’s cells.

**7. Blocking — V2 ceiling omits deferred membership; obligation 4 is not pinned for candidate/deferred tables.**  
Digest domain `/2` covers deferred facts; the V2 ceiling is only `BTreeSet<(SourceId, GraphEdgeKey, SourceId)>` plus candidate-site digests. Flipping deferred→eager on an already-authorized dynamic/CJS edge does not add an edge or change a candidate digest, so it is an eager-graph widening the ceiling does not see. F4 only pins two same-spelling `resolution_kind`s. The §12 ledger still claims obligation 4 discharged via §4/F4.  
**Fix:** Pin deferred-membership (and the bootstrap-internal CJS set) in the V2 ceiling, or classify any deferred-bit change as `full-reload-current-authority`. Add fixtures: candidate-site digest change refuses; deferred→eager refuses; keep F4 as specified.

**8. Blocking — “committed base-graph digest” is boot digest or live-at-`r`, and the payload digest does not enumerate V2 rows.**  
After revision `r+1` the live v2 digest moves. If the field is 0042’s boot/deployment digest, later envelopes do not bind the graph the successor law is applying to. If it is the live digest at `(g,r)` but still named as the boot digest, the second update fails live-state verification unless the consumer cheats. The payload digest covers “typed metadata” without listing `GraphEdgeKey` bindings, candidate-table digests, or deferred facts — the rows the ceiling must check.  
**Fix:** Name the field the live v2 digest at successor-law base `(g,r)`, recomputed in §5.3 after every commit; verify against that, not the boot commitment digest. Enumerate the canonical update body: invalidation set, per-record artifact/source integrity, declared effect class, and the full V2 rows (bindings, candidate digests, deferred facts). F9 must include digest-at-`r` mismatch after one successful revision, and `target ≠ base+1`.

**9. Blocking — loader-cache invalidation has no miss path that respects OQ2.**  
The capture table is a frozen exactly-once boot hook with quarantine-on-misuse. §5.3.3 invalidates the compat cache for replaced `SourceId`s and does not say where a later miss goes. A miss into `captureDevServedModuleTable` either quarantines the session or reinstalls boot bytes over the committed incarnation.  
**Fix:** After commit, replaced `SourceId`s resolve through the engine slot table / already-installed revision records. Cache invalidation must not induce a capture-table lookup. Pin that in §5.1 and F7.

**10. Blocking — incarnation isolation uses the same ambient-effect hole §3 used to forbid surviving-runtime generation transitions.**  
§3 recreates the runtime because unpin does not retire timers, next-ticks, globals, or host registrations. A hot revision also does not unpin (§5.4 / 0027) and v1 does not implement the candidate-effect lease (§7). Replaced incarnations keep running timers that can mutate globals and host registrations while slots already point at the successor. 0023 applies the cross-generation prohibition “with the same force” at the incarnation boundary and names only `hot.data` as an exception.  
**Fix:** Until the lease exists, a v1 invalidation closure that includes a record with outstanding ambient effects refuses `full-reload-current-authority` (runtime recreate). Alternatively, qualify 0023/§2.1: ambient effects of a replaced incarnation are not retired in v1, and that is a named exception beside `hot.data`. Silence is not a third option.

## Minor Findings

- `begin_revision` does not say whether `base` must equal live. If it does, F2 needs overlapping transactions; if it does not, pin that only `commit` CAS-checks. The `&mut` surface vs two in-flight `HotRevisionTransactionV1`s should match F2.
- “All six `GenerationPublicationKind`s” are never named; F1 should list them, including CJS adapter, error cache, and artifact cache, plus an unchanged importer of a replaced module.
- 0055 Related claims 0027 “revision-aware unpin”; the body says hot revisions do not unpin.
- Update-verifier public key is not listed as HMAC-covered in the 0042 boot commitment; production schema should structurally reject the keypair fields.
- Slot table key is `(graph_generation, slot id)` while slots are keyed by `SourceId`; say whether they are the same.
- F9 omits `runId` mismatch, authority-stamp mismatch, and HTTP/WS selection (obligation 3’s routing sentence is normative on Exact but not fixture-pinned).
- `ImmutableGenerationAdmissionV1` keeps a V1 name with a V2 edge type; easy to implement the old `(SourceId, String, SourceId)` set by accident.
- Overflow → full-reload is sound; say that a generation transition resets `HotRevision` to 0 on the *new* runtime, not on the dying one.

## Obligation Check (the 7 obligations + O-3 + 3 H0 MATERIALs — one row each: discharged/scheduled/missing)

| Item | Status |
| --- | --- |
| (1) per-slot incarnation predicate + TLA/stale fixture | **discharged** in §2.2/F1 for the stated predicate; importer-chain/CJS coverage is a fixture gap (Finding 5) |
| (2) two-phase Contract adapter or shadow-root-only; no in-place | **missing** — §8 decides (a) with fallback (b), but §5.2.4 still offers dispose-then-evaluate before commit (Finding 2) |
| (3) target/base-graph-bound signature; HTTP/WS check same fields | **missing** — four bold fields are listed, but the bound graph digest is ambiguous after revision 0 and V2 rows are not in the payload digest (Finding 8) |
| (4) `generation.rs` typed-graph + edge-ceiling fixture | **missing** — `GraphEdgeKey`/F4 are pinned; candidate/deferred ceiling+fixtures are not (Finding 7) |
| (5) candidate-effect lease as the only future effectful path | **scheduled** — exclusive future path is named in §7; v1 does not implement it; outstanding effects of *replaced* records are unfenced (Finding 10) |
| (6) getter indirection at call time, not captured `recordId` | **missing** — namespace getters only; live bindings/re-exports/CJS-ESM not pinned; F5 too narrow (Finding 5) |
| (7) OQ1 counter unification + OQ2 staging-seam shape | **missing** — OQ1 is discharged in §1; OQ2’s capture table is frozen, but the post-invalidation miss path is not (Finding 9) |
| Exact 0553.001 O-3 successor law | **discharged** in §1/`target = base+1` + consumer-live CAS; the CAS-*refusal class* is wrong (Finding 1) |
| H0 receipt authenticity | **discharged** in §9.1 (coordinate binding; order-based correlation rejected) |
| H0 bounded receipt retention | **discharged** in §9.2 (256 FIFO, closed field set) |
| H0 harness isolation | **scheduled** — Exact-side operating rule restated in §9.3 |

## Verdict

**NOT READY** (blocking: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10).
