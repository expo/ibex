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

---

# Round 2 (r2 delta+residue review)

**Reviewer:** grok-4.6, xhigh, headless, cumulative r2 diff + disposition ledger inlined. **Target:** r2 @4a1c5459b. **Verdict:** NOT READY (new blockers 1–3; G1–G10 resolved/partial per its table). Folded into r3.

I'll start by reading the full prompt and the LLP review skill so the round-2 audit follows the required process.The prompt is huge; I’ll pull the rest in chunks so the r2 diff and dispositions are complete.I'll locate the r2 LLP text and the rest of the cumulative diff so the audit is against the actual revision.The 0055 spec is the core of this review; I’ll read that section of the diff in full.I’ll verify G1/G2 against Exact 0417 and check the new r2 mechanisms against the primary sources.I have enough primary-source checks to write the round-2 audit: G1–G10 against the r2 text, then only new defects in the r2 mechanisms.## Overall Assessment

r2 is a real fold, not a paper one. G3–G10 land in the r2 text (slot-owned namespace, every use surface, shadow publish predicate, V2 ceiling + restart discipline, live v2 digest, capture-table miss rule, typed `ReadyToPublish` machine, no-fail bundle, provenance switch, 0553.001 duplicate-first, named ambient-effect exception). The two partials keep 0417’s wording where 0417 actually owns the row.

The new machinery is not closed. The state machine still runs dispose-registered evaluation — and allows overlapping transactions — before the 0553.001 duplicate/currency checks and before ceiling/converse. That makes the §10 “keep-last-good is compatible” note false and makes F2’s loser a full-reload of the winner on this surface. Receipts were declared advisory, then used as the producer’s restage coordinate source, and receipt emission still sits inside the no-fail bundle. Those are r2 defects, not restated r1 items.

## Resolution Table (G1–G10)

| ID | Status | Cite | Note |
| --- | --- | --- | --- |
| G1 | **PARTIAL** | §1, §10 race-class note, F2, §5.2.1 | **0417-ownership reason is sound.** Exact 0417 §4.8 lists “revision race lost” under `full-reload-current-authority` (line 546); this corpus should not silently reassign the taxonomy. The “and restages” wording is fixed (loser drops; **producer** restages). **The serial-apply / double-sending dismissal is not sound as a complete answer.** 0417 §4.7 does serialize Exact’s *host* apply task, but this spec’s own r2 surface does not: `begin_revision` “does **not** require `base` to equal the live coordinate — staging is optimistic and concurrent transactions may exist” and F2 stages two overlapping txns on one owner thread. After the winner’s `commit` lands `r+1`, the loser’s `commit` is the §10 race-lost row, i.e. runtime recreate, i.e. the winner is torn down *by F2*. Separately, the compatibility note claiming a 0417-owner keep-last-good refinement “is compatible with this spec” is **false** given §5.2.4 (see Finding 1). |
| G2 | **PARTIAL** | §5.2.4, §8, 0417 §4.8 rules 1/3/5 | **Declining “dispose after commit” is sound.** Rule 3 normatively keeps dispose-before-evaluate so old cleanup precedes new claiming, with the documented torn-down state on eval throw and “no committed incarnation is disposed twice **in one apply**.” The effects/publication split is now explicit; throwing dispose → full-reload is rule 5. **Rule 3 is not a reason to run dispose before uniqueness, currency, ceiling, or converse.** Rule 1 is “preflight before any effect”; 0553.001 checks currency *before apply* and revalidates at commit. r2 still puts those fallible checks in `commit()` after evaluation (Finding 1). |
| G3 | **RESOLVED** | §5.3, §2.2 | Fallible work first; live V2 row swap + digest recompute; records past export TDZ; `publish` and slot surfaces share one authority updated in the bundle; loader-private/non-reentrant cache surgery; invariant failure → quarantine/recreate; activation hook in-fence. |
| G4 | **RESOLVED** | §2.2 shadow predicate | Shadow publish is transaction-local: `install_revision == txn.base+1 ∧ source ∈ invalidated`; live `publish` cannot see shadow rows. |
| G5 | **RESOLVED** | §2.3, F5 | Every cross-closure surface (getters, import bindings, re-export/star aliases, dynamic-import namespaces) must observe successor-or-prior with no mixed graph; per-use slot lookup **or** atomic relink; importers not re-run; F5 covers those surfaces + TLA continuation. |
| G6 | **RESOLVED** | §2.3, 0023 amendment | Slot-owned namespace exotic object, one per `(ExecutionGeneration, SourceId)`; never-shared list is environments/cells/promises/errors/CJS export objects. (0024 still says “namespaces” never cross incarnations — Minor.) |
| G7 | **RESOLVED** | §4, F4, §3 | Ceiling pins deferred-dynamic/CJS membership, bootstrap-internal set, candidate attributes; every breach is restart, verbatim with `generation.rs` (“regenerate policy and restart the runtime”). Overriding the r1 full-reload preference is sound: the server pre-classifies shape edits into reload *before* staging, and v1 recreate derives a fresh ceiling from the new boot graph. |
| G8 | **RESOLVED** | §6, F9 | `committedBaseGraphDigest` is the live v2 digest at successor-law `(g, r)`, recomputed in §5.3.1; canonical body enumerates invalidation set + per-record typed V2 rows; F9 includes digest-at-r mismatch, `target ≠ base+1`, `runId`/authority-stamp mismatch. |
| G9 | **RESOLVED** | §5.1, F7 | Post-commit resolution of a replaced id is only through installed revision records; no capture-table reentry, quarantine, or boot-byte re-serve. |
| G10 | **RESOLVED** (via alternative) | §2.1, §7, 0023 | Refusing on an “outstanding ambient-effect census” is unimplementable. Named v1 exception + effect-class admission (pure / dispose-registered / else reload) is the honest detectable guard; the lease removes it later. |

## New MATERIAL Findings (numbered; severity, the defect, the smallest fix)

**1. Blocking — dispose-registered evaluation (and overlapping txns) run before duplicate-first, currency, ceiling, and converse; the §10 keep-last-good compatibility note is therefore false.**

§5.2.1 allows `base ≠ live` and concurrent `HotRevisionTransactionV1`s; only `commit` CASes. §5.2.4 runs dispose against the last *committed* incarnation before evaluate. §5.2.5 then does signature-adjacent revalidation, successor-law CAS, v2 ceiling, and converse — all after that dispose. §6 says the `(updateId)` table is checked “first” but does not make it a named guard before `begin_revision` / evaluation, and does not require recording **every attempt including drops** (Exact 0553.001 §2.2 lines 217–223: duplicate/identity lookup is the first stage-4 check, table records drops, otherwise a post-commit retransmit hits stale-base and commands a full reload). §5.2.4’s “at most once per apply” guard is per-transaction; two F2 txns are two applies.

Consequences on this surface, not on a hypothetical double-sending server:

- Retransmit of a just-committed `updateId`: dispose of the winner’s incarnation, then table-hit or CAS-fail.
- Stale-base sequential apply (the actual 0417 race): dispose the live `r+1` winner, then CAS-fail into full-reload.
- F2: both txns can dispose the same committed incarnation (contradicts 0417 rule 3’s twice-guard), winner commits, loser is §10 race-lost → recreate wipes the winner.
- §10’s claim that refining race-lost to `keep-last-good` “is compatible with this spec” is false: a CAS loser has already disposed live modules; keep-last-good would leave slots on a torn-down incarnation with no recreate.

**Fix:** (i) Duplicate/identity lookup is a named first consumer check, after signature verify and before `begin_revision` effects; the table records every attempt outcome including preflight/eval refusals and drops. (ii) `begin_revision` refuses `base ≠ live` with a non-reload class (keep-last-good / busy); commit CAS stays as a TOCTOU backstop that, under `&mut`, is quarantine if it ever fires. (iii) At most one in-flight txn, or at most one txn may enter dispose-registered evaluation; F2 becomes “second begin refuses, no dispose, no full-reload.” (iv) Ceiling, converse, export-shape, CJS eligibility complete in preflight (0417 rule 1) before any dispose. (v) Retract or rewrite the §10 compatibility note until (ii)–(iv) hold.

**2. Blocking — receipt de-fanging is not complete, and receipt emission is inside the no-fail bundle.**

§9.1 says receipts are advisory, no correctness-bearing decision rides them, the consumer executes class-correct recovery from its own verdict, and any server action derived from a receipt must be idempotent and advisory. Three r2 sentences violate that:

- §1: the producer “restages against the consumer’s committed coordinates **(reported in the refusal receipt)**.” Restaging the next payload from unauthenticated coordinates is a correctness decision. It is also the H0 MATERIAL 1 shape (forged/confused receipt → wrong producer action).
- Exact 0417 §4.3 still has a class-driven server response: `hmr-refused` carries `reasonClass` + committed coordinates “so the server never guesses,” and “only the full-reload class is answered with one `reload`.” This spec claims to discharge H0 MATERIAL 1 by de-fanging but does not mark that 0417 sentence as requiring an Exact-side amendment. Implementers will keep both: consumer self-recreates *and* the server reloads on a loopback-forgeable receipt.
- §5.3.7 emits the receipt inside the no-fail publication critical section. 0417 receipts are WS sends (fallible). A send/alloc failure would quarantine-recreate a revision whose records/slots/counter already published, and it makes advisory telemetry able to fail publication.

**Fix:** Producer restages from its own last-success record or from a **credential-gated pull** of live coordinates (the existing `hmr-payload` GET), never from an advisory receipt body. Explicitly ask Exact to amend 0417 §4.3: `reload` / re-arm are triggered by the consumer’s host-driven verdict, not by receipt class; receipts stay telemetry. End the §5.3 bundle at counter advance; synthesize and send the receipt after the fence, best-effort.

**3. Blocking — the in-fence activation hook cannot carry 0417’s remount-failure keep-last-good.**

§5.3.4 runs the consumer activation hook *after* live-graph adoption and slot retarget, under a no-fail / no-app-JS contract; hook failure is invariant-quarantine (runtime recreate), not a refusal. Exact 0417 §4.8 keep-last-good **includes** “a remount failure inside the joint publication transaction (the revision never commits)” — last-good records, slots, and pixels stand. §10 has no remount-failure row. §8 still names two-phase Contract adapter (a) as the v1 *target*. As written, (a)’s activate step cannot fail keep-last-good; any remount throw becomes recreate. That silently collapses v1 to (b) or to a harsher class than 0417 allows, without saying so.

**Fix:** Pin the split: Contract remount/prepare JS runs before `ReadyToPublish` on a shadow/prepared tree (throw → `keep-last-good`, live graph untouched). The §5.3.4 hook is only the no-JS, prevalidated root-pointer / host-token flip. If that split cannot be fixtured at H2 entry, v1 **is** (b) and (a) is withdrawn, not “the v1 target.”

## Minor Findings

- 0024 §7.9 cites 0055 §2.1 while still listing **namespaces** as never crossing incarnations; §2.1’s precise never-share list omits them (slot-owned facade). Drop “namespaces” from 0024 to match.
- 0026 §8 still writes the development record key as the three-tuple `(runtime/session identity, SourceId, execution generation)` and says “until they are [amended], the runner supports exactly one generation.” Terminology and the following paragraph already add install revision; this commit *is* the amendment. Update or delete the stale sentences.
- Replay table is keyed `(updateId)` rather than 0553.001’s `(session, producer, updateId)`. Fine as a v1 single-session projection if named as such.
- `prepared_carrier_tables` is itself a strong `shared_ptr` owner of the factory table (`hermes_runtime_internal.h:838-840`). Pin an occupancy count on that map key so “release when no live prepared record references it” is not blocked by the map’s own ref, and so erasing the key on the first replaced `SourceId` cannot drop factories still used by untouched records.
- `__privInvalidateHotRevisionRecords` is JS inside a “no app/user JavaScript interleaved” fence. Pin a no-checkpoint engine re-entry (no microtask drain, no host poll) or do the map surgery natively.
- §10 is not closed over §5.2.1: empty and graph-widening `begin_revision` have no class row (`generation.rs` widening is restart).
- Mixed effect classes inside one invalidation closure: the machine “exposes both orderings; the declared class selects one” per boundary, but does not define closure-wide order. Refuse mixed-class closures, or take the most conservative class.
- F4 should name the restart class on each ceiling-breach fixture, not only “refuses,” so the landed disposition cannot be implemented as full-reload by accident.

## Verdict

**NOT READY** (blocking: 1, 2, 3).

---

# Round 3 (r3 delta review)

**Reviewer:** grok-4.6, xhigh, headless, cumulative r3 diff inlined. **Target:** r3 @ef5e24dcb. **Verdict:** NOT READY (3 blockers). Folded into r4; finding 2's in-corpus class reassignment DECLINED (taxonomy ownership — same ground as the race row), its internal-contradiction half adopted via the restart-join rewrite; findings 1 and 3 adopted whole.

I'll start by reading the full prompt and the LLP review skill so the round-3 delta review follows the required format.The prompt is large; I’ll pull the rest of it and locate the r3 LLP 0055 text plus the prior review artifacts.I’ll keep reading LLP 0055 and the round-2 reviews so the resolution table is grounded in the r3 text.I’ll inspect the r3-only slice, headers, and Exact 0417/0553.001 cites so the delta hunt is against the actual changed text.I’ll pull Exact 0417 and 0553.001 on the cited recovery, remount, and replay rules so the owner-ask analysis is source-backed.Checking one 0553.001 ordering detail so the busy/replay finding is pinned to the source law.## Overall Assessment

r3 closed the three round-2 blockers as specified. Single-flight plus base-currency-at-begin stops dispose on a doomed transaction; receipts are post-fence telemetry; `ActivationPrepared` plus the sharpened §8 fallback carries 0417’s remount keep-last-good. Codex 11–13 are the same three holes; I agree they are resolved.

The r3 delta is not closed. “Record every attempt” plus unqualified within-generation idempotence poisons the busy retry §10 requires. Ceiling-breach recovery is not sound under both outcomes of Exact-owner ask 3: §10 tells the consumer to reload, the next paragraph and 0417 until-taken forbid answering restart with reload, and F4 still asserts restart strings. The restage coordinate pull, which ask 2’s taken outcome depends on, cites a GET that does not return live coordinates.

## Resolution Table (round-2 blockers)

| ID | Status | Cite | Note |
| --- | --- | --- | --- |
| **1** / codex 12 | **RESOLVED** | §1, §5.2, §10 race note, F2 | Second `begin` refuses busy; `base ≠ live` refuses at begin with committed `(g, r)` and a no-effect witness; duplicate/identity is named check 2; ceiling/converse/export-shape/CJS complete in preflight; commit CAS is a quarantining TOCTOU backstop. Ask 2’s until-taken full-reload is wasteful-but-sound (no effect has run). Residual is new finding 1 (busy recorded as a terminal replay outcome). |
| **2** / codex 13 + 8 | **RESOLVED** | §1, §5.3 after-fence, §9.1, §12 ask 1 | Producer must not restage from receipt bodies; receipts emit after counter advance, best-effort; candidate v2 digest is precomputed. Ask 1’s until-taken extra server reload is a coherent superset of consumer-executed recovery, not a sole path. Residual is new finding 3 (the named pull vehicle). |
| **3** / codex 11 | **RESOLVED** | §5.2.7–8, §5.3.4, §8, §10 remount row, F11 | Prepare/accept runs pre-commit on shadow targets; failure is keep-last-good with live records/slots/pixels standing (`contract-staged-pure` does not dispose first). `ready()` requires a transaction-bound token; §5.3.4 is only the no-JS flip. Unfixturable split withdraws (a) for v1, not “still targeted.” |
| Codex 3 (residue) | **PARTIAL** | §4, §10 ceiling row | Two recovery grades are the right doctrine and ask 3 is recorded. The until-taken/taken mapping is still contradictory — new finding 2. |
| Codex 7 (residue) | **RESOLVED** | §6 | Per-generation table, capacity 4096, rotate-before-evict, unqualified idempotence within a generation. |

## New MATERIAL Findings (numbered; severity, the defect, the smallest fix)

**1. Blocking — busy (and unauthenticated) attempts are sealed as idempotent replay outcomes, so the retry §10 requires cannot apply.**

§5.2 records each pre-begin check in the §6 table, including refusals. §6 then says an exact duplicate returns the prior outcome and applies nothing. §10’s busy row says keep-last-good and “retry after the in-flight apply settles.”

Sequence: U1 in flight; U2 signature-ok, table miss, `begin` busy, U2 → `busy`; U1 commits; producer retries U2 (same `updateId`, same digest); check 2 returns `busy` and proceeds no further. F2(a) and the §10 retry never run. 0553.001 records every *authenticated terminal* attempt so a post-keep-last-good retransmit is identity-conflict rather than stale-base reload — not so that a retryable occupancy nack becomes the payload’s sealed receipt. Recording a signature failure under an unauthenticated `updateId` is the same shape: a later legitimate signed body with that id is either a duplicate of `sig-fail` or `update-identity-conflict`.

**Fix:** The table records only authenticated terminal outcomes (commit, identity-conflict, admission/eval/prepare refusals, drop of a *begun* transaction). Do not insert signature failures. Do not insert surface-busy; an in-flight `updateId` may be reserved as pending so a duplicate during flight is busy without sealing busy as terminal; settlement overwrites pending with the terminal receipt. Then §10’s post-settle retry is a table miss and begins.

**2. Blocking — ceiling-breach recovery is not sound under both outcomes of ask 3.**

§4 keeps generation.rs restart-family strings on every ceiling breach and defers class reconciliation to Exact until ask 3 is taken. §10’s ceiling row then says recovery *is* the reload class’s same-authority re-derivation. The next paragraph says answering the restart class with a plain reload is non-conforming. Recovery is consumer-executed (§9.1), so the consumer is bound by §10.

- **Ask 3 not taken:** 0417 §4.8 still lists “principal or edge widening” under `regenerate-policy-and-restart-runtime` and forbids answering that class with reload. A consumer that follows the ceiling row reloads; a consumer that follows the next paragraph and 0417 re-arms. Both cannot be conforming.
- **Ask 3 taken:** 0417 agrees same-authority widening is reload, which matches the ceiling row — but F4 still asserts restart-family strings “so the landed disposition cannot silently become a plain reload,” i.e. the fixture forbids the recovery the row prescribes.

Everyday server pre-classification never hitting the ceiling does not save this: a defense-in-depth ceiling hit is a refusal this surface produces and §10 maps.

**Fix:** Assign the class in this corpus and make §4 / §10 / F4 / both ask-3 outcomes agree. Same-authority ceiling widening is `full-reload-current-authority` (reload diagnostic; F4 asserts that class). Restart strings and re-arm stay only for authority/integrity/principal. Until ask 3 is taken, Exact may *additionally* re-arm (strict superset, sound). After ask 3, both sides reload. Delete the instruction that a ceiling breach both emits restart strings and recovers as reload.

**3. Blocking — the restage coordinate pull cites a channel that does not return live coordinates.**

After de-fanging receipts, stale-base restage (and ask 2 taken: keep-last-good, pull, restage) is specified as a “credential-gated pull of the consumer’s live coordinates (the existing payload-channel GET under the §5 dev-session credential)” (§9.1, §1). Exact 0417 §4.3’s existing GET is `GET /__exact/hmr-payload?updateId=…`: the *consumer* fetching *payload bytes* from the producer. It does not return live `(g, r)` or the live v2 digest. “Own last-success record” is not a substitute for stale-base: last-success is the coordinate that just failed, and without a trusted receipt the producer cannot distinguish last-sent from last-committed. The pull is load-bearing; the cited vehicle cannot implement it.

**Fix:** Name a credential-gated consumer-status read that returns live `(ExecutionGeneration, HotRevision)` and the live v2 digest. v1 loopback may be an in-process read of the runner counter under the same session credential. Leave `hmr-payload` as the payload fetch. Receipts stay a hint to pull, never the coordinate source.

## Minor Findings

- `ready()` “consumes” the activation token, then §5.3.4 “applies” it. Pin linear ownership: `ready()` takes the token; the flip runs only at §5.3.4. Consuming-as-applying would root-swap before live-graph adoption.
- After `Preflighted`, “the only remaining fallible steps are evaluation and preparation,” but `commit` still has ordinary-refusal authority-stamp revalidation after dispose/prepare. The armed snapshot is immutable for the runtime’s life; a commit-time stamp mismatch cannot occur under the stated invariant and should quarantine like the base CAS if it ever fires.
- §1 cites the TOCTOU backstop as “§5.2.6”; it is §5.2 item 8 (`ready`/`commit`).
- §6 says check 1 verifies signature *and* every bound field; §5.2 check 1 is signature only. Bound-field currency belongs with check 3 or should be listed as part of check 1 without overlapping begin.

## Verdict

**NOT READY** (blocking: 1, 2, 3).

---

# Round 4 (r4 delta review)

**Reviewer:** grok-4.6, xhigh, headless, r4 delta + full r4 text inlined. **Target:** r4 @6306c3a0e. **Verdict:** NOT READY (1 blocker: capacity folded into full-reload cannot retire a runId-scoped table). Folded into r5; its round-3 blockers all RESOLVED.

I'll start by reading the LLP review skill and the full prompt so the round-4 review follows the required format.The prompt is long; I’ll continue from the spec body so the disposition ledger can be checked against the actual r4 text.I’ll load the round-3 reviews and the r4 delta so I can check each disposition against the rewritten sections.I’ll check Exact 0553.001 and 0417 on replay lifetime, capacity rotation, and ceiling recovery so the delta hunt is source-backed.The r3 blockers are closed in the body. One r4 composition is still unsound: session-lifetime replay versus the leftover full-reload capacity class.

## Overall Assessment

r4 applies the prescribed fixes for grok 1–3, and the body matches the disposition ledger on those three. Replay records only authenticated terminal outcomes, with pending in-flight reservations and no check-1 inserts; ceiling recovery is restart-join until ask 3 and reload-class after, with the contradictory reload-recovery sentence gone; restage is a credential-gated consumer-status read, not the payload GET. Codex’s session-lifetime move is in §6, but §10 still maps capacity to `full-reload-current-authority`. Under consumer-executed recovery that class does not retire a `runId`-scoped table, so the r4 capacity path does not unstick.

## Resolution Table (round-3 blockers)

| ID | Status | Cite | Note |
| --- | --- | --- | --- |
| **1** (busy/replay poisoning) | **RESOLVED** | §6, §5.2 checks 1–2, §5.3.7, F2(a), F9 | Check-1 failures never enter the table. Same-`updateId` in flight is pending busy, not a sealed busy receipt; settlement overwrites pending with the terminal outcome; a different-id surface-busy nack is not recorded. Fence finalizes the pre-reserved record; transport is post-fence. F2(a)/F9 pin retry-after-settle and unauthenticated-then-legitimate begin. Residual of the session-lifetime fold is new finding 1, not a miss of this fix. |
| **2** (ceiling-breach contradiction) | **RESOLVED** | §4, §10 ceiling row, F4, §12 ask 3 | The “recovery is the reload class’s re-derivation” instruction is gone. Until ask 3, every ceiling breach — same-authority widening included — is restart-family strings **and** the host restart join; v1 re-arm with unchanged authority is a no-op policy regeneration, not a plain ws reload. After the ask, same-authority widening moves to `full-reload-current-authority` and F4’s same-authority fixtures flip by recorded amendment. Declining in-corpus class reassignment on 0417 taxonomy ownership is sound; both ask-3 outcomes are now implementable without answering restart with reload. |
| **3** (restage pull vehicle) | **RESOLVED** | §9.1, §1 | The vehicle is a credential-gated consumer-status read of live `(ExecutionGeneration, HotRevision)` and the live v2 digest. v1 loopback may be in-process/status under the §5 session credential; Exact H2 names the wire route. Payload GET is no longer cited. Last-success is a warm-path shortcut only; it is not the stale-base answer. |

## New MATERIAL Findings (numbered; severity, the defect, the smallest fix)

**1. Blocking — session-lifetime capacity recovery is still specified as consumer full-reload, which cannot retire the table.**

r4 moved the replay table to **session (`runId`) lifetime** and made capacity “refusal-until-session-rotation, never eviction”: the consumer refuses **new** `updateId`s with a diagnostic naming session rotation, and the **producing session** rotates `runId` (new keypair, commitment, generation) to drop the table (§6). §10 still maps that refusal, together with `HotRevision` overflow, to `full-reload-current-authority`. §9.1 makes class-correct recovery **consumer-executed** from the consumer’s own verdict; receipts are not a correctness-bearing control path, and the status read returns only `(g, r)` plus the live v2 digest — not occupancy, and not a command to rotate `runId`.

Full-reload mints a new `ExecutionGeneration` under the **same** `runId` (§3). That is the right answer for overflow; it is not session rotation. After a capacity-driven recreate the table is still full, the next new `updateId` is refused again, and a producer that restages from the status read (the §9.1 rule) loops. Until ask 1 is taken, an Exact server that only sees the §10 class will also `reload` rather than rotate the session.

This is the r3 generation-scoped recovery left in place after the table’s lifetime changed. It is the same shape as r3 finding 2: two incompatible recovery instructions for one refusal.

**Fix:** Split the §10 row. `HotRevision` overflow stays `full-reload-current-authority`. Replay-table capacity is not a consumer reload: keep-last-good occupancy (last-good stands; further **new** ids refuse) until the producer rotates `runId`, which is what actually retires the table. Do not fold capacity into a generation transition, and do not require the producer to take that rotation from an advisory receipt — the apply NACK’s distinct diagnostic is the producer-visible signal.

## Minor Findings

- §5.2 still introduces the pre-begin list as “each recorded as an attempt outcome … including refusals and drops.” Check 1 and §6 say the opposite for unauthenticated failures and occupancy nacks. Retract the parenthetical to “authenticated terminal outcomes per §6.”
- §9.1’s heading still says receipt authenticity is “**discharged** by de-fanging”; the paragraph and §12 correctly say **MITIGATED**, residual named, discharge at H2. Align the heading with the body.
- §12’s 0553.001 O-3 line still reads “unqualified **within-generation** idempotence, rotate-before-evict.” The r4 law is session-lifetime, rotate-`runId`-before-evict.
- Converse no-op (§5.2.5, §10, F2(d)): pin the quantifier. Keep-last-good “nothing to apply” holds when **every** invalidated replacement is row-identical to live (candidate v2 digest equals live), not when **any** one member is. A mixed closure with unchanged siblings must still apply the members that changed; §2.3 already does not re-run importers.
- F2(a) “after the in-flight apply settles, the **same** update begins normally” is true only for a **different** `updateId` (the §10 busy nack). A same-id retry after settlement is F9’s terminal hit, not a new begin.
- F4’s title still says every fixture asserts the restart-family string; the ask-3 taken path is the recorded class flip in the §4 adversarial paragraph. Scope the title as until-taken.
- §13.2 still describes v1 ceiling recovery as “the §4 same-authority re-derivation.” Until ask 3 that recovery is the host restart join (§4/§10).
- Fail-stop quarantine/recreate does not say what happens to a **pending** slot. Under session-lifetime the table survives the generation transition; pin that pending is dropped or finalized before the dying runtime yields, so a same-id remint is not busy forever. (Remint will usually carry a new `updateId`; still define the slot.)
- Begun-transaction **refusals** skip the §5.3 bundle, so they never hit step 7. §6 already requires pending → terminal on authenticated refusal; say that overwrite happens before the refusal is yielded, same durability as the in-fence success write.

## Verdict

**NOT READY** (blocking: 1).

---

# Round 5 (r5 delta review)

**Reviewer:** grok-4.6, xhigh, headless, r5 delta + full r5 text inlined. **Target:** r5 @5eb732839. **Verdict:** READY (3 minors, folded into r6). NOTE: r6 supersedes the quarantine-terminal-receipt mechanism this round approved (codex r5 found it unrepresentable in 0553.001's receipt union); grok re-reviews that change in round 6.

## Overall Assessment

r5 applies the prescribed fix for grok r4-1, and the body matches the disposition ledger on that split. Capacity is no longer a consumer reload: §6 and §10 treat it as a `keep-last-good` occupancy refusal with a session-rotation diagnostic, last-good standing, no generation transition, and `runId` rotation as the only retirement. Codex r4-1 and r4-2 are handled correctly: the table is host-held, quarantine and pre-bundle refusals terminalize pending before any later begin can see it, and the converse no-op is the transaction-wide empty changed set.## Overall Assessment

r5 applies the prescribed fix for grok r4-1, and the body matches the disposition ledger on that split. Capacity is no longer a consumer reload: §6 and §10 treat it as a `keep-last-good` occupancy refusal with a session-rotation diagnostic, last-good standing, no generation transition, and `runId` rotation as the only retirement. Codex r4-1 and r4-2 are handled correctly: the table is host-held, quarantine and pre-bundle refusals terminalize pending before any later begin can see it, and the converse no-op is the transaction-wide empty changed set. F2(d)/F2(e) pin both. The r4→r5 delta does not introduce a new loop or stranded identity.

## Resolution Table

| ID | Status | Cite | Note |
| --- | --- | --- | --- |
| **Grok r4-1** (capacity folded into full-reload loops) | **RESOLVED** | §6 capacity, §10 split rows, F9 capacity clause | Overflow stays `full-reload-current-authority`. Capacity is a `keep-last-good` occupancy refusal for *new* `updateId`s; terminal duplicates still answer; no generation transition is implied or performed; §6 states the reload-would-loop reason verbatim. Only producer `runId` rotation retires the table. The apply NACK’s distinct diagnostic is the producer-visible signal; it does not ride an advisory receipt. Consumer-executed recovery of this class is “last-good stands,” which is the recovery that does not loop. |
| **Codex r4-1** (quarantine-stranded pending) | **AGREE RESOLVED** | §6 host-held + quarantine-settles, §5.3 pre-reserve, F2(e); also grok r4 minors 8–9 | Host-held table survives v1 recreate and dies with the session, so the pending slot is not implicitly dropped by generation transition. Invariant-quarantine terminalizes through the pre-reserved record *before update processing resumes*; a begun transaction’s ordinary refusal overwrites pending→terminal *before the refusal is yielded*. F2(e) forces both a backstop failure and a mid-bundle fail-stop to return the quarantined terminal after recreate, never busy. A same-`updateId` remint with a new digest is then identity-conflict, not occupancy. |
| **Codex r4-2** (converse no-op too broad) | **AGREE RESOLVED** | §5.2.5, §10 no-op row, F2(d) | Matches grok r4 minor 4. No-op only when the entire staged set is row-identical (transaction-wide changed set empty). An unchanged member inside a non-empty changed closure is legitimate; 0417 re-evaluates the accepted boundary and its invalidated importer chain, so those importers become new incarnations and F2(d) requires both install revisions to advance. The r4 per-member rule is superseded. |

## New MATERIAL Findings (numbered; severity, the defect, the smallest fix)

None.

## Minor Findings

- **§2.3 vs §5.2.5/F2(d).** §2.3 still says relink “is a binding rewrite, never a re-evaluation; importers are not re-run either way.” That is the cross-closure observation rule (F1/F5: an importer *not* in the invalidation set keeps its install revision and its TLA). The r5 converse text requires invalidated unchanged importers *inside* the set to re-evaluate and advance. Scope §2.3’s “importers are not re-run” to non-invalidated consumers / binding-update mechanism so it cannot be read as forbidding F2(d).
- **Item-8 vs pre-reserve sequencing.** Quarantine settlement is specified as an infallible field write on the pre-reserved outcome record. Mid-bundle fail-stop is past that reserve. Item 8 still sits in `commit()` *before* “Then the §5.3 bundle,” and pre-reserve is described as pre-fence work in §5.3’s preamble. Pin that the record is constructed before the commit-time backstops run (or that item-8 constructs-and-finalizes the same way pre-bundle refusals overwrite pending). F2(e) already requires the outcome; this is only the sequenced vehicle.
- **F9 capacity clause.** F9 still says only “refuses new `updateId`s until session rotation, never evicting.” It does not assert the r5 class split (keep-last-good, no generation transition). Add that witness so H2 cannot re-fold capacity into overflow’s reload.

## Verdict

READY
