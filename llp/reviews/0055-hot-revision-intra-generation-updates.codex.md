# Review: LLP 0055 r1 — codex (round 1)

**Reviewer:** codex `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, read-only sandbox over /Users/ccheever/projects (ibex worktree agent/0417-h1 @fe9238a8b + the Exact repo authorities).
**Date:** 2026-08-24. **Requested by:** the Exact 0417 H1 orchestrator lane (cross-family round 1 over the slice-1 doc set; the draft author is same-family Claude, so this is a cross-family round).
**Verdict:** NOT READY (blocking findings 1–10). Folded into r2 — adjudication in the r2 Revised entry; two proposed fixes declined with recorded reasons (dispose-after-commit; outstanding-ambient-effect refusal).

---

## Overall Assessment

**NOT READY.** The baseline code claims are accurate, and the core counter/signature tuple is sound. However, LLP 0055 does not yet normatively close several load-bearing paths: ordinary imports bypass the proposed slots, CJS adapter semantics conflict with stable namespaces, the immutable ceiling omits deferred facts, commit/effect state is incomplete, replay contradicts Exact 0553.001, and two H0 receipt MATERIALs remain open.

## Verified Claims

| claim | verdict | cite |
|---|---|---|
| `generation.rs` uses `BTreeMap<String, SourceId>`, domain `ibex/module-generation-graph/1`, and tests with empty binding maps | VERIFIED | [generation.rs:19](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/generation.rs:19), [generation.rs:82](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/generation.rs:82), [generation.rs:148](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/generation.rs:148), [generation.rs:627](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/generation.rs:627) |
| Live runner edges use `GraphEdgeKey { specifier, resolution_kind }` plus candidate/deferred/bootstrap tables | VERIFIED | [graph.rs:119](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/graph.rs:119), [graph.rs:137](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/graph.rs:137), [runner_pipeline.rs:266](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/runner_pipeline.rs:266) |
| `graph_generation` derives from `snapshot.generations().dynamic` | VERIFIED | [runner_pipeline.rs:2061](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/runner_pipeline.rs:2061). The executable path additionally hard-codes generation `1`: [hermes.rs:2571](/Users/ccheever/projects/ibex-wt/0417-h1/src/bin/ibex/engine/hermes.rs:2571) |
| Dev-served capture is frozen, exactly once, and quarantines repeat/malformed capture | VERIFIED | [module-loader.js:147](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/bootstrap/module-loader.js:147), [module-loader.js:164](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/bootstrap/module-loader.js:164), [module-loader.js:205](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/bootstrap/module-loader.js:205) |
| Namespace getters capture fixed generation and `recordId` at instantiation | VERIFIED | [hermes_module_runner.cc:3695](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:3695), [hermes_module_runner.cc:3701](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:3701) |
| Unpin removes requests and ESM/CJS records, releasing their contexts, but does not retire timers/next-ticks/globals/host registrations | VERIFIED | [hermes_module_runner.cc:2798](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:2798), [hermes_runtime_internal.h:822](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:822), [hermes_runtime_internal.h:841](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:841) |
| LLP 0042 already carries `{runId, generation, issuedAtMs}` and a producer-only HMAC | VERIFIED | [LLP 0042:230](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0042-prepared-graph-independent-commitment.rfc.md:230). The producer-only custody at lines 240–245 supports the asymmetric-key rationale |
| Prepared-carrier memo has no `SourceId` key or eviction path | VERIFIED | [hermes_runtime_internal.h:836](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:836), [hermes_module_runner.cc:2121](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:2121) |

## MATERIAL Findings

1. **MATERIAL — Getter-only slots do not update ordinary imports or re-export chains.** LLP 0055 mandates slot lookup only for namespace getters, while existing `NativeModuleImportBinding`, alias cells, dynamic bindings, and evaluation dependencies retain fixed record IDs. An unchanged importer—including a resumed TLA continuation—therefore continues reading the old incarnation. The claimed stable namespace also conflicts with the amendment saying live namespaces never cross incarnations. Cites: [LLP 0055:128](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:128), [0023:769](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0023-virtual-filesystem-namespace.spec.md:769), [hermes_runtime_internal.h:251](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:251), [hermes_module_runner.cc:883](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:883), [hermes_module_runner.cc:3237](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:3237), [hermes_module_runner.cc:3788](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:3788).  
   **Smallest fix:** define a generation-owned namespace facade distinct from incarnation namespaces; make every cross-closure named/default/namespace import, re-export/star alias, dynamic binding, and dependency link store or resolve a slot ID. Add direct-import, re-export, star, dynamic-import, and TLA-continuation cases to F5.

2. **MATERIAL — CJS adapters cannot honor stable namespace identity and the required v1 refusal is absent.** CJS adapter namespaces are non-extensible data-property snapshots, not slot-backed getters, and their errors are sticky. Exact 0417 therefore requires cross-boundary CJS named-import edges to full-reload; LLP 0055 omits that refusal while amended 0027 suggests adapter completion is supported. Cites: [Exact 0417:438](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:438), [hermes_module_runner.cc:327](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:327), [hermes_module_runner.cc:358](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:358), [0027:286](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0027-module-artifact-and-interop.spec.md:286), [LLP 0055:365](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:365).  
   **Smallest fix:** make any CJS adapter exposed outside the invalidation closure ineligible for v1 hot commit and map it to full reload. Add success, throw/error-cache, `default`, `module.exports`, and detected-named-export fixtures.

3. **MATERIAL — The v2 ceiling does not cover the full typed graph and weakens the landed widening disposition.** Records digest deferred facts, but the ceiling pins only typed edges and candidate-site digests. It omits eager/deferred membership, computed deferred attributes, and bootstrap-internal CJS membership. LLP 0055 also maps some new edges/candidate changes to plain full reload, whereas landed `generation.rs` and Exact 0417 assign edge widening beyond the immutable ceiling to restart/re-arm. Cites: [LLP 0055:185](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:185), [LLP 0055:198](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:198), [LLP 0055:373](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:373), [runner_pipeline.rs:279](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/runner_pipeline.rs:279), [generation.rs:220](/Users/ccheever/projects/ibex-wt/0417-h1/src/module_loader/generation.rs:220), [Exact 0417:566](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:566), [Exact 0417:712](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:712).  
   **Smallest fix:** pin exact eager/deferred/bootstrap membership and computed attributes in the ceiling, require exact-edge policy reauthorization, map every ceiling breach to restart/re-arm, and add deferred-bit/bootstrap-set adversarial fixtures.

4. **MATERIAL — Commit eligibility and effect/refusal semantics are not a closed state machine.** Preflight explicitly runs no app code, yet §10 calls evaluation failure a preflight failure. Nothing makes `commit` require successful shadow/dispose evaluation, settled TLA, finalized CJS adapters, or a class-valid ready receipt. `effectful-unknown`, observed-class mismatch, throwing dispose, and post-preflight evaluation errors are missing from the refusal table. This leaves TDZ, stale-error, and effect-leak behavior consumer-defined. Cites: [LLP 0055:227](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:227), [LLP 0055:316](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:316), [LLP 0055:365](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:365), [Exact 0417:461](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:461).  
   **Smallest fix:** define typed transaction states and permit commit only from a runtime-issued `ReadyToPublish` state after class-specific evaluation/settlement. Enforce `effectful-unknown` structurally, import Exact’s complete refusal map, and fixture dispose throw, class mismatch, TLA rejection, and cached-error replacement.

5. **MATERIAL — The publication step omits required ownership/root publication and lacks a no-fail contract.** The exhaustive list retargets slots and invalidates caches but never publishes/adopts staged record and binding ownership or activates the prepared Contract/root swap. It also introduces a private JS cache bridge without stating that every publication operation is prevalidated and infallible or defining fail-stop behavior after partial mutation. This does not discharge Contract obligation 2 or F7. Cites: [LLP 0055:246](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:246), [LLP 0055:331](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:331), [Exact 0417:451](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:451), [Exact 0417:515](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:515).  
   **Smallest fix:** define one native no-fail commit bundle containing record/binding adoption, slot changes, cache ownership, prepared Contract activation, install revisions, and counter advance. All fallible work occurs before it; an impossible invariant failure quarantines/recreates rather than returning an ordinary refusal.

6. **MATERIAL — “Carrier memo eviction for replaced `SourceId`s” has no valid keying model.** The current memo is one table per `(principal, compartment, carrier digest)` and can contain factories for several sources. Per-`SourceId` eviction is therefore undefined and contradicts the claim that untouched records retain their memo entries. Cites: [LLP 0055:252](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:252), [LLP 0055:263](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:263), [hermes_runtime_internal.h:836](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:836), [hermes_module_runner.cc:2121](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_module_runner.cc:2121).  
   **Smallest fix:** add a generation/source entry overlay or tombstone plus source-to-carrier reverse ownership. Retire the replaced entry atomically; evict the shared carrier table only when no live prepared entry references it.

7. **MATERIAL — Replay semantics contradict Exact 0553.001.** The successor law itself is correct, but LLP 0055 says an exact duplicate refuses on stale base and makes its 1024-entry `updateId` table diagnostic-only. Exact 0553.001 requires duplicate/content lookup before currency: exact duplicates return the prior receipt without applying, while same-ID/different-bytes conflicts. Cites: [LLP 0055:298](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:298), [Exact 0553.001:205](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:205).  
   **Smallest fix:** either delegate replay explicitly to the 0553 envelope layer and remove the contrary rule, or implement its first-check `(session, producer, updateId) → envelopeDigest + receipt` semantics.

8. **MATERIAL — H0 receipt authenticity is not discharged.** Public revision coordinates plus a loopback peer gate authenticate neither a browser nor another local process—the exact attack recorded by the H0 review. Yet receipts remain correctness-bearing. Cites: `b8b853902:docs/reports/0417-h0-spike-security-review.md:20-34`, [LLP 0055:344](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:344), [Exact 0417:614](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:614).  
   **Smallest fix:** authenticate receipt bodies with consumer-specific key material delivered through a non-public host handoff, or make receipts advisory and require the consumer itself to execute the class-correct recovery.

9. **MATERIAL — H0 receipt amplification remains unbounded by bytes/shape.** A 256-entry FIFO and closed field names do not bound WS frame size, JSON depth, strings, stage arrays, active sessions, or total retained bytes; the H0 attack occurs before or during retention. Cites: `b8b853902:docs/reports/0417-h0-spike-security-review.md:35-40`, [LLP 0055:357](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:357).  
   **Smallest fix:** add a pre-parse frame limit, exact scalar/array/depth limits, per-session and global byte budgets, and refuse oversize before allocation/re-serialization.

10. **MATERIAL — The amendment set retains contradictory authority text and settles non-ceded OQ4.** LLP 0026 still defines incarnation without install revision, states all development invalidation creates a new generation, and conditions multi-generation support on amendments that this commit now lands. Separately, LLP 0055 mandates per-module slots and plain-only `hot.data`, although Exact 0417 leaves OQ4 open and ceded only OQ1/OQ2. Cites: [0026:209](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0026-esm-module-runner.rfc.md:209), [0026:1070](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0026-esm-module-runner.rfc.md:1070), [LLP 0055:100](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:100), [LLP 0055:150](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:150), [Exact 0417:781](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:781), [Exact 0417:791](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:791).  
    **Smallest fix:** amend 0026’s terminology and §8 baseline in the same set; obtain an Exact-owner amendment settling OQ4, or leave slot granularity/`hot.data` value algebra explicitly open and stop attributing “plain values” to Exact.

## Minor Findings

- §11 says F1–F9 “all live” in the test tree, but this commit contains no HotRevision, slot, or signature fixtures; change this to “required/planned H1 fixtures.” [LLP 0055:384](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:384)
- F9 should explicitly include wrong profile, boot identity, base-graph digest, and separate HTTP-selection/WS-routing mismatch fixtures assigned to Exact H2. [LLP 0055:408](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:408)
- The proposed V2 record still calls its ceiling `ImmutableGenerationAdmissionV1`; give the new wire/type a V2 name to prevent accidental V1 comparability. [LLP 0055:185](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:185)
- LLP 0027’s earlier unconditional “rejects mixed inline/prepared graphs” should be scoped explicitly to boot/rejoin admission now that the later amendment creates a post-boot exception. [0027:180](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0027-module-artifact-and-interop.spec.md:180)
- H0 harness isolation is correctly Exact-owned, but §12 should label it “scheduled/operating rule,” not imply Ibex discharge. Compare `b8b853902:docs/reports/0417-h0-spike-security-review.md:41-45` with [LLP 0055:360](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:360).

## Obligation Ledger Check

| row | result | check |
|---|---|---|
| 1 — per-slot incarnation predicate + fixture | PARTIAL | Equation is stated, but destination-fencing for TLA importer propagation and CJS adapter/error publication is not pinned; findings 1, 2, 4 |
| 2 — Contract adapter or shadow-root-only | FAIL | Conditional target exists, but no typed root activation enters the publication transaction; finding 5 |
| 3 — target/base-graph-bound signature | PASS | Required tuple and pre-staging verification are normative; transport negatives need clearer H2 fixture assignment |
| 4 — typed graph/digest/ceiling/tests | FAIL | Digest mentions deferred facts, ceiling does not pin them; finding 3 |
| 5 — candidate-effect lease only future path | FAIL | Policy sentence exists, but the API/refusal state machine does not structurally refuse `effectful-unknown`; finding 4 |
| 6 — getter indirection | FAIL | Namespace-getter-only indirection misses direct imports, aliases, re-exports, dynamic bindings, and CJS adapters; findings 1–2 |
| 7 — OQ1 counter + OQ2 staging seam | PASS | Counter separation and new Rust revision seam are settled coherently, subject to the 0026 cleanup in finding 10 |
| O-3 — successor counter | PASS | Revision 0, exactly-live-plus-one, checked against the consumer’s live counter at owner publication, non-wrapping. Replay remains separately wrong under finding 7 |
| H0 MATERIAL 1 — receipt authenticity | FAIL | Coordinates plus loopback do not authenticate the local sender; finding 8 |
| H0 MATERIAL 2 — bounded retention | FAIL | Count bound does not close byte/depth/CPU amplification; finding 9 |
| H0 MATERIAL 3 — harness isolation | SCHEDULED | Correctly left as an Exact-side operating rule, but not discharged by Ibex |

## Verdict

**NOT READY (blocking findings 1–10).**
---

# Round 2 (r2 delta+residue review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r2 @4a1c5459b. **Verdict:** NOT READY (residues 3/7/8 + new 11–13). Folded into r3.

## Overall Assessment

**NOT READY.** Seven round-1 findings are resolved; findings 3, 7, and 8 remain partial. Both declined fixes are defensible against Exact 0417: §4.8 rule 3 requires dispose-before-evaluate with documented degraded semantics, while rule 4 intentionally uses declared/observed effect classes because no ambient-effect census exists.

The r2 state machine and publication bundle introduce three additional MATERIAL gaps. I could not append this review to the `.codex.md` artifact because the supplied workspace is read-only.

## Resolution Table (10 rows: finding | RESOLVED/PARTIAL/UNRESOLVED | cite | note)

| finding | status | cite | note |
|---|---|---|---|
| 1 | RESOLVED | [0055 §2.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:188), [F5](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:580) | All cross-module use surfaces are covered by slot lookup or atomic relink; importers do not re-run, and the namespace facade is generation-owned. |
| 2 | RESOLVED | [0055 §2.3 CJS rule](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:218), [F10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:601) | Cross-closure CJS adapters/exports now refuse; whole-closure replacement has the required coverage. |
| 3 | PARTIAL | [0055 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:284), [Exact 0417 §4.8](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:566) | Ceiling breadth and the local breach mapping are fixed. However, server pre-classification still routes the same edge/deferred widening to ordinary reload, where a fresh ceiling is derived under unchanged policy. Exact classifies edge widening as restart/re-arm regardless of where detected. Remove that shortcut or obtain an Exact-owner amendment. |
| 4 | RESOLVED | [0055 §5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:318), [Exact rules 3–5](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:472) | Typed states, shadow publication, settled TLA/CJS, structural `effectful-unknown` refusal, mismatch, evaluation, and dispose-throw rows are present. The two declined fixes are sound against Exact’s governing text. |
| 5 | RESOLVED | [0055 §5.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:365), [§8](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:487) | Record/binding adoption, graph/digest publication, root activation, cache ownership, counter advance, and fail-stop quarantine are now included. New defects in how readiness and receipt emission compose with this bundle are findings 11 and 13. |
| 6 | RESOLVED | [0055 §5.3.6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:397), [actual table key](/Users/ccheever/projects/ibex-wt/0417-h1/src/engine/hermes_runtime_internal.h:836) | The design now matches the real `(principal_id, compartment_identity, carrier_digest)` multi-source table: records switch provenance and release references; the table is not erased per `SourceId`. |
| 7 | PARTIAL | [0055 §6 replay law](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:449), [0553.001 §2.2](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:205) | Duplicate-first lookup and same-ID/different-bytes conflict are fixed, but FIFO eviction explicitly makes later duplicates non-idempotent. Exact requires exact duplicates to return the prior receipt without qualification. Retain replay identity for the whole session/producer scope, or rotate the session before eviction. |
| 8 | PARTIAL | [0055 §9.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:506), [Exact 0417 §4.3](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:303), [§4.8](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:536) | 0055 locally de-fangs receipts, but accepted Exact 0417 still says `hmr-refused` drives a class-based server response and that the server answers full-reload receipts with `reload`. An Exact-owner amendment must move recovery wholly to the consumer and make the server response advisory. |
| 9 | RESOLVED | [0055 §9.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:519) | Frame, depth, shape, row, count, per-session-byte, and global-byte limits now bound ingestion and retention. |
| 10 | RESOLVED | [0055 OQ4 disposition](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:233), [0026 Terminology](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0026-esm-module-runner.rfc.md:209), [0026 §8](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0026-esm-module-runner.rfc.md:1089) | The install-revision terminology and §8 baseline are corrected; slot granularity and `hot.data` algebra are proposals explicitly left to Exact OQ4. |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

11. **MATERIAL — `ReadyToPublish` does not prove consumer activation is prepared.** The state machine verifies engine evaluation, CJS, TLA, and dispose state, then §5.3 invokes a merely “registered callback slot.” There is no transaction-bound activation token or state covering `hot.accept`/Contract preparation, so the asserted no-fail hook is not mechanically established and remount/accept failure has no precommit transition. Exact requires remount failure to refuse before publication. Cites: [0055 §5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:340), [§5.3.4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:387), [Exact 0417 §4.4](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:326), [§4.8 remount rule](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:515).  
   **Smallest fix:** add `ActivationPrepared` to the typed machine. `ready()` must consume a transaction-bound no-fail activation token produced after accept/remount preparation; preparation or accept-callback failure refuses before commit.

12. **MATERIAL — optimistic stale transactions can dispose the wrong committed incarnation before CAS.** Transactions may coexist and need not have a live base until commit, but `dispose-registered` runs dispose during evaluation while the successor check occurs only afterward. Two base-`r` transactions can both dispose incarnation `r`; worse, after one commits `r+1`, the other may dispose the new winner before its CAS loses. Immediate reload eventually recovers, but the state machine allows a transaction already doomed by currency to execute destructive application effects. Cites: [0055 §5.2 items 1 and 4–5](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:325), [Exact rule 3](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:472).  
   **Smallest fix:** immediately before the first app-visible dispose/evaluation effect, revalidate and reserve the live base through publication. Serialize `dispose-registered` transactions; race losers must drop before dispose. Preserve dispose-before-evaluate within the winning reservation.

13. **MATERIAL — advisory receipt emission remains inside the “no-fail” correctness bundle.** Step 7 combines counter advance with receipt emission. Transport emission is ordinarily fallible; under §5.3, failure would therefore quarantine/recreate after publication, making an advisory receipt correctness-bearing despite §9.1. Live-digest recomputation inside the bundle similarly performs avoidable work after mutation begins. Cites: [0055 §5.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:365), [step 7](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:403), [§9.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:506).  
   **Smallest fix:** precompute and validate the candidate graph digest before the bundle; atomically install that digest and advance the counter. Construct/enqueue/send the advisory receipt after commit, with send failure limited to telemetry loss or retry—never quarantine or recovery.

## Minor Findings

- [0027’s Revised entry](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0027-module-artifact-and-interop.spec.md:8) still says “per-`SourceId` carrier-memo eviction,” contradicting its corrected provenance/reference-retirement body.
- [0024’s Revised entry](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0024-structured-evaluation-and-session.spec.md:8) says “live state never crosses incarnations” without acknowledging 0055’s named ambient-effect exception. Its §7.9 body is narrower; qualify the header.
- [0023 §2.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0023-virtual-filesystem-namespace.spec.md:769) first says incarnations do not share “namespaces,” then introduces the stable slot-owned namespace. The subsequent distinction makes the intent recoverable, but “incarnation-private namespaces” would remove the apparent contradiction.
- §9.2 says scalar lengths are bounded without stating the individual limits. The 64 KiB frame ceiling prevents unbounded amplification, so this is testability/documentation rather than a MATERIAL gap.

## Verdict

**NOT READY (blocking findings 3, 7, 8, 11, 12, 13).**
---

# Round 3 (r3 delta review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r3 @ef5e24dcb. **Verdict:** NOT READY (4 MATERIALs). Folded into r4; the ceiling-class conflict with grok's round-3 finding 2 adjudicated in codex's favor on taxonomy-ownership grounds.

## Overall Assessment

r3 at `ef5e24dcb42cde6f38436c8ce599e0c800d4e079` is improved but **NOT READY**. No later revision was present.

Single-flight is coherent with Exact’s serial executor: busy is a defensive refusal normally unreachable through the conforming apply queue. `ActivationPrepared` now mechanically establishes a transaction-bound, no-JS flip with an objective shadow-root fallback. Moving transport send post-fence is also sound.

Four MATERIAL defects remain: an ordinary-fallible authority check still follows app-visible effects; replay lifetime and receipt durability still violate 0553.001; and owner asks 1 and 3 are not sound under their “not taken” outcomes. Owner ask 2 is sound either way.

## Resolution Table (round-2 blockers)

| Blocker | Status | r3 judgment |
|---|---|---|
| codex 3 | **PARTIAL** | The two recovery grades are coherent, but same-authority edge widening is routed to reload while accepted Exact still requires re-arm. [0055 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:307), [§10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:627), [Exact 0417 §4.8](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:566) |
| codex 7 | **PARTIAL** | Live-generation eviction is removed, but generation rotation is not session rotation; Exact’s replay key is session-scoped and checked before generation currency. Receipt synthesis can also fail after commit. [0055 §6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:510), [0553.001 §2.2](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:212) |
| codex 8 | **PARTIAL** | Consumer recovery and producer coordinate-pull are fixed, but the unchanged Exact server still takes a correctness-bearing action from unauthenticated receipts. [0055 §9.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:573), [Exact 0417 §4.3](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:303) |
| codex 11 | **RESOLVED** | `ActivationPrepared`, token-consuming `ready()`, the no-JS flip, and the objective shadow-root fallback close the blocker. [0055 §5.2.7](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:400), [§8](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:552) |
| codex 12 | **RESOLVED** | The stale-transaction/dispose-the-winner defect is closed by single-flight, base currency at begin, and preflight completion before evaluation. [0055 §5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:345) |
| codex 13 | **RESOLVED** | Candidate digest installation is precomputed, the bundle ends at counter advance, and transport send is post-fence. [0055 §5.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:418) |
| grok 1 | **RESOLVED** | Duplicate/currency/ceiling/converse checks now precede dispose; race keep-last-good is genuinely compatible because stale-base refusal is effect-free. [0055 §5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:357), [§10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:635) |
| grok 2 | **PARTIAL** | Coordinate pull and post-fence send are fixed; the untaken Exact receipt amendment remains blocking. [0055 §9.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:582) |
| grok 3 | **RESOLVED** | Preparation failure is precommit `keep-last-good`; commit performs only a prevalidated token flip. [0055 §5.2.7](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:400), [§5.3.4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:439) |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — an ordinary-fallible admission check still follows app-visible effects.** Evaluation, dispose, and consumer preparation precede `commit`, but `commit` then performs fallible authority and authority-stamp validation with ordinary refusals. This directly contradicts §5.2’s governing invariant. [0055 §5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:353), [evaluation/preparation](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:384), [late check](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:408)  
   **Smallest fix:** perform ordinary authority/stamp admission before evaluation and hold a transaction-bound immutable authority reservation through publication. Retain commit-time comparison only as an invariant backstop, like the base compare.

2. **MATERIAL — replay scope and outcome durability remain incompatible with 0553.001.** Exact binds `(session, producer, updateId)` and checks it before currency; r3 instead retires entries on generation rotation, although generation is a separate coordinate. Additionally, exact duplicates require the prior receipt, while r3 permits post-commit receipt allocation failure. Best-effort transport is sound; best-effort receipt synthesis/storage is not. [0055 §6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:510), [post-fence allocation](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:461), [0553.001 replay law](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:212), [mandatory receipt](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:547)  
   **Smallest fix:** retain replay identities for the full session/producer lifetime, bind them to the complete signed-envelope digest, and rotate `runId`/session—not merely generation—before capacity. Pre-reserve outcome/receipt storage; finalize it infallibly before yielding, while keeping transport send post-fence and best-effort.

3. **MATERIAL — owner ask 1’s until-taken behavior is not actually redundant.** A forgeable `hmr-refused` can arrive before any consumer verdict and make the unchanged Exact server issue a reload. That reload is therefore not necessarily “beside” consumer recovery; accepted Exact explicitly calls these receipts correctness-bearing. [0055 §9.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:585), [Exact response](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:311), [Exact security posture](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:614)  
   **Smallest fix:** make the advisory behavior conditional on the Exact amendment. Until it is taken, either authenticate receipts with consumer-private material or leave H0 authenticity explicitly undis­charged and retain Exact’s current server-authoritative semantics.

4. **MATERIAL — owner ask 3 is unsound when not taken.** r3 says same-authority edge growth recovers through reload/re-derivation, but accepted Exact presently places all edge widening in `regenerate-policy-and-restart-runtime` and forbids answering it with reload. Keeping only the restart diagnostic string does not preserve the required recovery action. [0055 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:307), [0055 refusal row](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:627), [Exact 0417 §4.8](/Users/ccheever/projects/exact/llp/0417-native-source-hmr.rfc.md:566)  
   **Smallest fix:** state the two outcomes conditionally: until ask 3 is taken, every edge widening re-arms; after amendment, same-authority widening may use generation re-derivation.

## Minor Findings

- The r3 `Revised` entry says “two Exact-owner asks” while listing three. [0055 header](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:26)
- §1 points the commit-time backstop to §5.2.6, but it now lives in step 8. [0055 §1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:107)

## Verdict

**NOT READY (blocking findings 1–4).**
---

# Round 4 (r4 delta review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r4 @6306c3a0e. **Verdict:** NOT READY (2 MATERIALs: quarantine-stranded pending entry; converse no-op quantifier too broad). Folded into r5.

## Overall Assessment

r4 at `6306c3a0eba4febb3e3deb39af7bf0cbf5175e0e` is improved but not ready. Findings 1, 3, and 4 are substantively resolved. Replay handling is mostly corrected, but invariant-quarantine can strand a session-lifetime pending entry. The new converse wording also rejects legitimate mixed invalidation closures.

## Resolution Table (round-3 findings)

| Finding | Status | Cite | Assessment |
| --- | --- | --- | --- |
| 1 — authority check after effects | RESOLVED | §5.2 checks 1, 3, item 8; §10 backstop row | Ordinary authority admission precedes effects; all commit comparisons are invariant backstops that quarantine rather than ordinarily refuse. |
| 2 — replay scope/durability | PARTIAL | §5.3 steps 7/post-fence; §6 replay law | Session lifetime, envelope-digest binding, pending/terminal states, capacity behavior, and normal commit durability are corrected. Invariant-quarantine does not settle or retire pending entries; finding 1 below. |
| 3 — ask-1 until-taken behavior | RESOLVED | §9.1; §12 H0 ledger | The residual forged-receipt reload is now explicitly acknowledged and authenticity is classified as mitigated pending H2. The stale §9.1 heading is minor. |
| 4 — ask-3 not-taken behavior | RESOLVED | §4 two recovery grades; §10 ceiling row; F4 | Until ask 3, every breach reaches restart/re-arm; after it, same-authority widening moves to reload. The normative conditional is sound. |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — invariant-quarantine can strand a replay identity as pending for the remainder of the session.** §6 changes replay retention from generation lifetime to `runId` lifetime and converts pending to terminal only on commit or authenticated refusal. But §5.2 item 8 classifies a backstop mismatch as neither, and §5.3 permits mid-bundle invariant detection to quarantine/recreate before step 7 finalizes the outcome. A v1 recreate rotates `ExecutionGeneration`, not necessarily `runId`, so the pending entry survives and exact duplicates answer busy indefinitely, contradicting §6’s session-lifetime terminal-idempotence guarantee. Cites: §3; §5.2 item 8; §5.3 opening and step 7; §6 pending/terminal law.  
   **Smallest fix:** require every invariant-quarantine to either infallibly terminalize its pending entry before update processing resumes or rotate/revoke `runId` and retire the replay table. Fixture both a forced item-8 failure and a mid-bundle fail-stop.

2. **MATERIAL — the converse split treats any unchanged member as making the whole invalidation closure a no-op.** §5.2.5 refuses when “an invalidated module” is row-identical to live. Legitimate accepted closures can contain a changed leaf plus unchanged accepting/importer modules that must re-evaluate; the new rule would discard the real edit. This is broader than the intended touched-but-unchanged transaction case. Cites: §5.2.5; §10 no-op row; F2(d); Exact 0417 §§4.1 and 4.8.  
   **Smallest fix:** refuse as no-op only when the transaction-wide changed set is empty—all staged replacement rows are identical—not when any individual closure member is unchanged. Add a changed-leaf plus unchanged-accepting-importer fixture.

## Minor Findings

- §5.2’s pre-begin introduction still says every check outcome is recorded, contradicting the explicit check-1 and surface-busy exclusions. Scope it to authenticated, accepted-for-processing attempts.
- §9.1’s heading still says authenticity is “discharged,” while its corrected body and §12 say “mitigated.”
- §12 still summarizes replay as “within-generation idempotence, rotate-before-evict”; it should say session-lifetime idempotence and refusal-until-session-rotation.
- §13.2 still states unconditional same-authority re-derivation, and F4’s heading is unconditionally restart-stringed. Both should mirror the ask-3 conditional in §4.
- F2(a)’s “same update begins normally” is only true if the first transaction settles without committing. If it commits, the producer must pull the new coordinates and re-mint.

## Verdict

NOT READY (blocking findings 1–2).
---

# Round 5 (r5 delta review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r5 @5eb732839. **Verdict:** NOT READY (2 MATERIALs: check-order makes post-commit duplicates unreachable; quarantined not representable in the closed receipt union). Folded into r6 — both adopted, the second via session-poison (superseding r5's quarantine-terminal receipt).

## Overall Assessment

r5 correctly resolves the converse quantifier and capacity-class defects. The quarantine disposition remains incomplete: the new terminal outcome is neither reachable under the current validation order nor representable in the governing receipt algebra.

This verdict binds to r5 commit `5eb732839`; no later revision was present.

## Resolution Table

| Round-4 item | Status | Assessment |
| --- | --- | --- |
| 1 — quarantine strands pending | PARTIAL | Host ownership and pending→terminal ordering are now explicit in [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:596), but findings 1–2 prevent the promised terminal replay from working end to end. |
| 2 — converse quantifier too broad | RESOLVED | [§5.2.5](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:448), §10, and F2(d) consistently use the transaction-wide empty changed set. The changed-leaf/unchanged-invalidated-importer case matches Exact 0417 §4.8. |
| Capacity split | RESOLVED | [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:624) and [§10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:748) correctly separate overflow from host-table occupancy and require producer `runId` rotation rather than reload. |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — the new post-settlement/post-recreate terminal-hit assertions are unreachable under the unchanged validation order.** §5.2 check 1 compares the envelope’s committed base-graph digest against live session state before check 2 consults the host-held replay table. After a successful changed commit, §5.3.1 installs a new graph digest; recreation may likewise boot a different graph. The original exact duplicate therefore fails check 1 rather than returning its terminal entry, contradicting the new F2(a)/F2(e) assertions. Cites: [§5.2 checks 1–2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:423), [§5.3.1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:514), [F2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:778).  
   **Smallest fix:** after cryptographic signature and stable session/addressing authentication, perform the host-table `(updateId, envelopeDigest)` lookup before live generation/revision/base-graph currency comparisons. Make F9 distinguish a fresh stale-base attempt from a known exact duplicate.

2. **MATERIAL — `quarantined` is not a representable terminal receipt outcome.** r5 requires an infallible field write recording `quarantined` and F2(e) requires returning that terminal receipt, while §10 says invariant quarantine is not a refusal class. The governing `ExactApplyReceiptV1` union permits only `committed`, `committed-degraded`, or `refused { class, code }`; its apply-time registry contains no quarantine outcome. Cites: [LLP 0055 §6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:611), [LLP 0055 §10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:754), [Exact 0553.001 §5.1](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:547).  
   **Smallest fix:** either add an authority-approved typed quarantine outcome with coordinate and replay semantics, or take round 4’s alternative: rotate/revoke `runId` and retire the table on quarantine instead of promising a prior receipt.

## Minor Findings

- §6 calls an undefined “apply NACK” the producer-visible capacity signal, while §9 defines only advisory consumer-to-producer receipts. Name the host-local/status carrier or assign that plumbing explicitly to Exact H2.
- §2.3’s “importers are not re-run either way” should say “outside-closure importers”; r5 correctly says invalidated importers inside the closure re-evaluate.

## Verdict

NOT READY (blocking findings 1–2).
---

# Round 6 (r6 delta review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r6 @ace96ed86. **Verdict:** NOT READY (1 MATERIAL: check-3 refusals lacked replay reservation semantics). Folded into r7.

## Overall Assessment

r6 resolves both round-5 blockers at the intended outcome level. The split verification order is spoof-safe: the complete envelope is signature-authenticated and session-addressed before replay lookup, while generation, revision, and graph-digest currency remain before staging. Session poisoning also avoids inventing a fourth receipt outcome and gives the producer a bounded recovery path.

However, r6 introduces one MATERIAL inconsistency: authenticated attempts that fail the new check 3 are still asserted not to create replay entries. That breaks session-scoped `updateId` content binding and Exact 0553.001’s outcome replay law.

## Resolution Table

| Round-5 finding | Status | Cite | Assessment |
| --- | --- | --- | --- |
| 1 — post-commit duplicates unreachable | RESOLVED | [§5.2 checks 1–3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:440), [§6 verification order](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:618), [F2(b)](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:817) | An authenticated exact duplicate now reaches its terminal entry before moving currency is compared. Deferring currency creates no spoof window because signature and stable session/addressing bindings precede lookup. |
| 2 — `quarantined` unrepresentable | RESOLVED | [§5.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:522), [§6 quarantine law](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:644), [F2(e)](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:824) | Quarantine no longer creates an outcome outside the closed receipt union. Runtime recreation, session poisoning, and eventual whole-table retirement on `runId` rotation form a coherent fail-stop recovery. |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — check-3 refusals have no coherent replay reservation semantics.** r6 moves stale generation, revision, and base-graph digest from check 1 to authenticated live-currency check 3. Yet F9 still says those failures create no replay entry and that a later differently signed body may reuse the same `updateId`. This contradicts §6’s session-lifetime content-binding law and Exact 0553.001, which records authenticated stage-4 outcomes so exact retries replay the refusal and different bytes conflict. The phrase “reserves … at `begin`” is ambiguous because check 3 itself invokes `begin_revision`. Cites: [§5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:440), [§6 replay law](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:625), [F9](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:851), [Exact 0553.001 §2.2](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:212), [Exact verification order](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:519).  
   **Smallest fix:** after a check-2 miss—and after different-ID busy and capacity gates—reserve `pending` before check-3 currency validation. Terminalize every check-3 refusal before yielding. Split F9 so only check-1 authentication/addressing failures create no entry; stale generation/revision/digest and successor failures become terminal replay entries.

## Minor Findings

- Explicitly place the host-held `rotation-required` gate after check 1 and before check 2. Otherwise §5.2 says a stranded pending duplicate answers busy while §6/F2(e) says poison overrides it with the rotation diagnostic. Also state that the marker is set before recreation or update processing resumes.
- Qualify §5.3’s statement that a later exact duplicate “always” returns a receipt: invariant quarantine is the specified fail-stop exception and returns the direct rotation-required diagnostic instead.
- A validly signed but wrongly addressed envelope is authenticated-but-misaddressed, not “unauthenticated” as §5.2 check 1 currently says. The no-table disposition remains sound.

## Verdict

NOT READY (blocking finding 1).
---

# Round 7 (r7 delta review)

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r7 @589b872ff. **Verdict:** NOT READY (1 MATERIAL: pending reservation preceded the different-ID busy refusal). Folded into r8.

## Overall Assessment

r7 resolves the rotation-gate blocker and correctly adopts replay semantics for authenticated currency refusals. I agree with the adjudication against Grok’s no-record minor: Exact 0553.001 makes `updateId` content-bound and records stage-4 outcomes, so an exact retry must replay the refusal while different bytes conflict.

One ordering gap remains: the different-`updateId` single-flight busy gate is not placed before the new pending reservation. Under the literal pipeline, `begin_revision` can refuse busy after the entry has already been reserved, contradicting the no-entry busy rule and F2(a).

## Resolution Table

| Round-6 item | Status | Assessment |
| --- | --- | --- |
| Codex finding 1 — check-3 replay reservation | PARTIAL | Currency refusals now reserve and terminalize correctly in [§5.2 check 3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:488), [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:670), and [F9](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:893). The required pre-reservation different-ID busy gate remains missing; finding 1 below. |
| Codex minor 1 — rotation gate placement/lifetime | RESOLVED | The gate is explicitly after check 1 and before all table operations; its setting, recreation survival, and `runId`-only clearing are pinned in [§5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:473). This also resolves Grok’s round-6 blocker. |
| Codex minor 2 — “always returns” quarantine exception | RESOLVED | [§5.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:563) names the fail-stop exception. |
| Codex minor 3 — misaddressed wording | RESOLVED | [§5.2 check 1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:469) now says “unauthenticated or misaddressed.” |
| Grok minors — §6 terminology, quarantine class, item-8 pointer | RESOLVED | [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:670), [§10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:824), and [item 8](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:547) contain the requested corrections. |
| Grok no-record currency-refusal minor | ADJUDICATED AGAINST — AGREE | Exact 0553.001 requires content binding and prior-outcome replay after duplicate-first lookup. [Exact 0553.001 §2.2](/Users/ccheever/projects/exact/llp/0553.001-patch-envelope.spec.md:212) |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — the pending reservation still precedes the different-ID single-flight busy refusal.** The surface says a second `begin_revision` refuses busy and creates no replay entry, but check 3 now reserves `pending` before invoking `begin_revision` and terminalizes every check-3 refusal. Thus a different-ID concurrent attempt either seals busy as a terminal outcome or requires an unstated exception, contradicting §6 and F2(a). Cites: [single-flight and ordered checks](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:452), [reservation before `begin_revision`](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:488), [§6 no-entry rule](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:676), [F2(a)](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:854).  
   **Smallest fix:** after a check-2 miss, add a named different-ID single-flight gate before capacity and pending reservation. A busy attempt stops with the direct busy response and no entry; only a non-busy, under-capacity attempt reserves before currency validation.

## Minor Findings

- [§5.2 check 1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:469) calls itself the “ONLY failure disposition with no entry,” although different-ID busy, capacity, and fresh rotation-required responses also create no entry. Scope this to validation failures or check-1 failures.
- [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:676) still says reservation occurs “at `begin`” and describes settlement only for a “begun transaction.” Align it with the new pre-`begin_revision` reservation and include all reserved authenticated attempts.

## Verdict

NOT READY (blocking finding 1).
---

# Round 8 (r8 delta review) — TERMINAL: READY

**Reviewer:** codex `gpt-5.6-sol`, xhigh, read-only, same access. **Target:** r8 @c1205c3cb. **Verdict:** READY — no MATERIALs, no minors; all round-7 items resolved. Loop terminal: both families READY on r8.

## Overall Assessment

r8 fully resolves the round-7 blocker and associated minors. The delta introduces no new MATERIAL issue.

## Resolution Table

| Round-7 item | Resolution | Assessment |
| --- | --- | --- |
| Finding 1 — reservation preceded different-ID busy refusal | RESOLVED | The named busy gate now follows duplicate lookup and precedes capacity and reservation. Different-ID busy attempts receive a direct response and create no entry; only non-busy, under-capacity attempts reserve. [§5.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:502) |
| Minor — “only failure disposition” overclaim | RESOLVED | The statement is scoped to validation failures and distinguishes occupancy nacks. [§5.2 check 1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:481) |
| Minor — pending reservation/settlement wording | RESOLVED | Reservation is anchored before currency validation, past all three gates; settlement covers every reserved attempt, including check-3 refusals. [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:697) |
| Minor — verification-order summary omitted gates | RESOLVED | The summary names rotation, busy, and capacity in their correct positions. [§6](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:676) |

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

None.

## Minor Findings

None.

## Verdict

READY
---

# Code rounds (slice-2 implementation)

**Round 1 (747abb599):** NOT READY, 7 findings (4 HIGH — unauthenticated typed metadata, cloneable manager, unbound shadow tokens, shape/CJS gaps; 3 MEDIUM). **Round 2 (post-fix @dfc5c8d78):** NOT READY, 3 residues (agreement omissions; authentication sources; cross-manager nonces). **Final (@6a6926d22):** NOT READY, 1 blocker (foreign-transaction portability). **Confirmation (@bbabca0f0+):** READY. Full artifacts:

## codex-code-review

## Overall Assessment

NOT READY. Independent GPT-5.5, GPT-5.6, and security-family reviews converged on significant admission and publication-algebra defects. The focused executable reports 16/16 tests passing, and formatting/diff checks pass, but several fixtures rely on metadata the real authenticated graph must reject.

## Spec-Conformance Table (per §/F row: conforms | gap | cite)

| Row | Status | Cite |
| --- | --- | --- |
| §1 successor/base law | gap | Generation is hard-coded to 1, the owner is cloneable, and generation-mismatch errors omit live `(g,r)`: [generation.rs:891](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:891), [generation.rs:898](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:898), [generation.rs:1003](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1003); [r8 §1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:212). Commit backstops are correctly invariant-worded at [generation.rs:1041](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1041). |
| §2.1 incarnation key | gap | The install revision is present, including revision 0 on V1, but cloneable ownership can create two indistinguishable live authorities: [generation.rs:69](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:69), [generation.rs:891](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:891). |
| §2.2 live/shadow predicates | gap | The individual comparisons conform, but live and shadow use the same cloneable token type, so a dropped shadow token can become live-valid after another matching commit: [generation.rs:98](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:98), [generation.rs:964](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:964), [generation.rs:1225](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1225); [r8 §2.2](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:304). |
| §2.3 export/CJS eligibility | gap | Only ESM export descriptors and replacement-side `CommonJs` status are checked; source goal and CJS detected exports are omitted: [generation.rs:1101](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1101); [r8 §2.3](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:341). |
| §4 V2 digest | conforms | Deterministic BTree iteration plus JCS covers semantic digest, typed binding targets and `resolutionKind`, candidate digest/attributes, both deferred sets, and bootstrap membership: [generation.rs:364](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:364), [generation.rs:383](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:383). |
| §4 authenticated rows/ceiling | gap | Typed facts are not checked against artifact declarations, edge removal passes the ceiling, and legitimate builtin bootstrap rows cannot initialize admission: [generation.rs:219](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:219), [generation.rs:317](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:317), [generation.rs:442](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:442), [generation.rs:515](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:515). |
| §10 strings/classes | gap | Restart-family implementation strings remain strict, but stale-generation does not use the mandated live-coordinate stale-base diagnostic: [generation.rs:1003](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1003); [r8 §10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:827). |
| F1 | gap | All six live kinds are exercised, but shadow/live separation and dropped-token non-reuse are not: [tests.rs:457](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:457), [tests.rs:472](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:472). |
| F2 | gap | Converse/no-op/unchanged-importer cases are covered, but the stale-generation test pins the wrong message and cloneable owners defeat the global one-winner law: [tests.rs:602](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:602). Slice-3 single-flight absence is not charged. |
| F3 | gap | Package mutation refuses restart, but the assertion is only `.contains("restart")`, not the required family string: [tests.rs:730](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:730). |
| F4 | gap | Fixtures use undeclared typed rows, do not test missing-edge refusal, omit deferred-CJS coverage, and assert digest differences only for bindings: [tests.rs:757](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:757). |
| F6 | gap | Add/remove/rename descriptor cases exist, but interop/source-goal and CJS detected-name changes do not: [tests.rs:909](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:909). |
| F7 | gap | The sole assignment is correctly last: [generation.rs:1143](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1143). Tests compare digest/revision/install maps, not full live-record byte identity: [tests.rs:259](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:259). |
| F10 | gap | The test checks only two outside edge kinds and a metadata-level whole-closure commit; it does not pin `default`, `'module.exports'`, detected names, sticky-error/eviction, or non-crossing export objects: [tests.rs:1072](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1072); [r8 F10](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:934). |

## MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **HIGH — V2 accepts unauthenticated typed graph metadata.** `GenerationRecordV2::from_verified` checks only deferred membership, while `from_records` checks only duplicate IDs and target presence. It drops V1’s artifact/resolver agreement validation through `SynchronousGraphPlan`: [generation.rs:139](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:139), [generation.rs:219](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:219), [generation.rs:317](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:317). The fixtures demonstrate the hole: artifacts declare no edges, while every V2 row invents one; candidate site 7 and bootstrap membership are similarly undeclared: [tests.rs:119](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:119), [tests.rs:191](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:191), [tests.rs:812](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:812). Smallest fix: construct V2 records from a validated typed-plan capability, checking exact artifact edges, computed-site ordinals, candidate attributes, deferred declarations, bootstrap declarations, and targets; make raw-map construction private and revalidate clone-and-swap candidates equivalently.

2. **HIGH — The live revision authority is cloneable.** `ModuleExecutionGenerationsV2` derives `Clone`, allowing two copies to commit different `r+1` successors from the same base despite the unique-owner successor law: [generation.rs:891](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:891); [r8 §1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:212). This directly obstructs slice-3 single-flight. Smallest fix: remove `Clone` from the live manager and any wrapper that could duplicate slot authority.

3. **HIGH — Shadow publication capability is not transaction-bound.** Live and shadow APIs accept the same `GenerationPublicationToken`. A token retained from a dropped transaction can pass live publication after another transaction installs the same source, revision, and digest: [generation.rs:964](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:964), [generation.rs:1245](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1245). F1 retains such a token but never tries reuse: [tests.rs:496](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:496). Smallest fix: introduce a distinct shadow-token type bound to an unforgeable transaction identity; live publication must reject shadow provenance, with commit explicitly adopting shadow results.

4. **HIGH — Export and CJS interop shape can change during a hot commit.** Eligibility compares only `export_descriptors`; it ignores `source_goal` and `commonjs_exports`, and boundary detection considers only the replacement being CommonJS: [generation.rs:1106](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1106), [artifact.rs:217](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/artifact.rs:217). ESM↔CJS or CJS detected-name/reexport changes can therefore commit. Smallest fix: compare a canonical full export-shape fingerprint covering source goal, normalized export descriptors, and CJS detected interop exports; inspect both current and replacement boundary forms.

5. **MEDIUM — The edge ceiling does not detect missing boot edges.** Validation rejects extras/retargets but treats the candidate as an allowed subset of `authorized_edges`: [generation.rs:515](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:515). R8 requires all shape facts pinned and routes shape changes through generation re-derivation: [r8 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:409). Smallest fix: collect the candidate edge set and require exact equality, with restart-family diagnostics for both extras and missing rows.

6. **MEDIUM — Real bootstrap-internal rows are unrepresentable.** Bootstrap facts are derived for builtin artifacts, but admission requires every source to have a defining principal; builtins return `None`: [graph.rs:235](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/graph.rs:235), [generation.rs:442](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:442), [identity.rs:117](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/identity.rs:117). F4 masks this by placing bootstrap facts on a root-owned ordinary Module. Smallest fix: separate exact source membership from optional file-principal pins, and define fail-closed builtin/synthetic admission while deriving bootstrap facts only from eligible builtin declarations.

7. **MEDIUM — The execution-generation half of the base coordinate is incomplete.** `new` always installs `ExecutionGeneration::INITIAL`; callers cannot initialize the session-minted generation required after reload, and the generation-mismatch branch omits live coordinates: [generation.rs:898](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:898), [generation.rs:914](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:914), [generation.rs:1003](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1003); [r8 §1](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:239). Smallest fix: accept a validated nonzero `ExecutionGeneration` at construction and collapse both base mismatches into the live-coordinate diagnostic.

## Security Delta Verdict

Unsafe. V1 control flow and refusal messages remain unchanged apart from adding revision-0 incarnation data, restart-family refusals were not softened, all recoverable commit checks precede the sole live assignment, and no production `unwrap`, `expect`, or `panic!` was added. Nevertheless, V2 is below the landed admission ceiling because verified artifacts can acquire unverified graph facts, the live authority can be cloned, shadow capability can escape a refused transaction, and interop shape can change without the required refusal.

## Minor Findings

- `typed_rows_equal` covers every stored V2 fact, and the JCS/BTreeMap digest construction is deterministic. `edge_digest_row` correctly includes `target` only for binding rows.
- `export_descriptor_set` deliberately ignores order and collapses byte-identical duplicates. That is consistent with set semantics, but no fixture pins the intended duplicate behavior.
- Preflight currently checks ceiling before converse, export shape, and CJS eligibility. Combined-invalid candidates may therefore observe a restart result before a more specific reload/keep-last-good result; the intended precedence should be documented and fixture-pinned.
- All 16 focused tests pass. Their principal gaps are: fabricated rather than artifact-declared non-empty typed maps; no isolated digest-difference assertions for candidate/deferred/bootstrap facts; no deferred-CJS case; substring-only restart checks; incomplete F6/F7/F10 coverage; and no shadow-to-live misuse negative.
- Repository search found no external `ModuleIncarnationKey` literals, so adding `install_revision` causes no in-tree construction fallout. V1 paths continue to return revision 0 and retain their existing messages.
- `git diff --check` and `cargo fmt --all -- --check` pass.

## Verdict

NOT READY (with blocking finding numbers: 1–7).
## codex-code-rereview

## Overall Assessment

NOT READY. The fix resolves most round-1 findings and substantially closes the fixture gaps, but three MATERIAL security residues remain:

1. Typed candidate/edge metadata still lacks a complete authenticated construction path.
2. The agreement validator accepts omitted artifact-declared bindings.
3. Transaction nonces collide across independent managers, so shadow tokens are not truly transaction-bound.

The existing post-fix generation test binary passes all 18 targeted tests. `git diff --check` passes and the worktree is clean. A fresh build was blocked by the read-only filesystem; the broader prebuilt suite’s filesystem-dependent tests consequently failed with `PermissionDenied`.

## Resolution Table

| Item | Resolution | Evidence |
|---|---|---|
| Codex 1 — unauthenticated typed metadata | **PARTIAL — blocking findings 1–2** | Construction now requires a verified artifact and revalidates at construction, stage, and clone-and-swap, but raw targets/pins remain publicly supplied and agreement is incomplete. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:238) |
| Codex 2 — live manager derived `Clone` | **RESOLVED** | `ModuleExecutionGenerationsV2` no longer derives `Clone`. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:979) |
| Codex 3 — shadow tokens not transaction-bound | **PARTIAL — blocking finding 3** | Distinct token type and same-manager nonce reuse checks are present, but nonce identity is only manager-local. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:118) |
| Codex 4 — export/CJS shape could change | **RESOLVED** | Shape covers `source_goal`, descriptor set, and `commonjs_exports`; export-shape precedes CJS. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1202) |
| Codex 5 — edge removal passed ceiling | **RESOLVED** | Candidate edges must exactly equal the ceiling; subsets now refuse. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:623) |
| Codex 6 — builtin/bootstrap rows unrepresentable | **RESOLVED** | Membership is independent of principal pins; principal-less rows are integrity-pinned and cannot be invalidated. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:523) |
| Codex 7 — hard-coded generation and incomplete mismatch diagnostic | **RESOLVED** | Generation is injected through a nonzero constructor; stale-base errors report live generation and revision. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:29), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1096) |
| Grok 1 — CJS live-or-replacement disjunction | **RESOLVED** | Boundary eligibility is `CommonJsRequire ∨ current_is_commonjs ∨ replacement_is_commonjs`. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1214) |
| Grok 2 — full shape tuple | **RESOLVED** | `export_shape` includes `SourceGoalV1`, descriptors, and canonical `commonjs_exports`. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1307) |
| Exact restart strings | **RESOLVED** | F3/F4 assert exact restart-family diagnostics. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:891) |
| Commit-path F4 | **RESOLVED** | Edge retarget/removal, site changes, deferred changes, and bootstrap changes reach `commit_revision`. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1061) |
| Deferred-CJS | **RESOLVED** | Deferred CJS→eager change refuses with the exact membership diagnostic. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1282) |
| F6 interop cases | **RESOLVED** | Add/remove/rename/descriptor, goal flips, and CJS detector-output changes are covered; same-shape replacement commits. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1395) |
| F10 disjunction | **RESOLVED** | Outside CJS require, CJS boundary under multiple edge kinds, whole-closure success, and precedence are covered. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1684) |
| Identity snapshots | **RESOLVED** | Refusals compare graph digest, revision, and per-source install revisions before/after. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:348) |
| Refused slot commit | **RESOLVED** | A refused revision leaves the native owner value and revision unchanged. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1915) |
| Shadow all-six-kinds | **RESOLVED** | All six kinds publish to shadow state and are carried on commit. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:589) |
| Shadow reuse negative | **PARTIAL — blocking finding 3** | Sequential reuse within one manager refuses, but cross-manager reuse is untested and succeeds when local nonce/row coordinates coincide. [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:604) |

## r9 Addendum Verification

The r8→r9 diff contains exactly the declared additions: the Revised entry, three §4 paragraphs, and §5.2.5 precedence. No unrelated text changed.

- **Exact edge-set equality:** sound and implemented exactly.
- **Membership versus principal pins:** sound and implemented exactly.
- **Typed-metadata agreement:** not sound or complete as written or implemented; findings 1–2 block it.
- **Specific-first precedence:** sound and implemented in the required order: converse/no-op, export shape, CJS eligibility, then ceiling. [r9 §5.2.5](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:561)

Interpretation point (a) is correct: a CJS→ESM flip with an outside edge must report export-shape because r9 explicitly puts it first. Same-goal cases validate the ordinary CJS behavior, while code inspection establishes the full live-or-replacement disjunction.

Interpretation point (b) is also acceptable. The public path intentionally refuses builtin/synthetic targets at `begin_revision`, making the bootstrap ceiling backstop unreachable during conforming operation. A test-private transaction mutation is an appropriate white-box method for exercising that defense-in-depth branch.

Overall, however, the addendum is not yet sound and completely implemented because its typed-authentication paragraph claims guarantees the current artifact schema and APIs cannot establish.

## New MATERIAL Findings (numbered; severity, cite, smallest fix)

1. **MATERIAL — r9 does not identify an authentication source for resolved targets or candidate-sidecar pins, and the code accepts them as caller-created values.** `ModuleArtifactV1` declares edge spellings/kinds and only a computed-site ordinal; it does not declare the resolved `SourceId`, candidate-table digest, or `attributes_digest`. Nevertheless, public V2 constructors accept raw bindings and `CandidateSitePinV1`, while graph construction merely checks that targets exist. [artifact.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/artifact.rs:97), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:218), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:358), [r9 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:439)

   Smallest fix: make records derive their rows from a validated authenticated graph-plan/envelope object. Candidate pins should derive from validated `ComputedCandidateTableV1` tokens, including `validate_requester`, rather than caller-provided digests. Amend r9 to name the authentication source for targets, sidecar attributes, and deferred classification instead of attributing all of them to artifact declarations.

2. **MATERIAL — typed agreement is one-sided and accepts omitted artifact-declared bindings.** The validator rejects a supplied key absent from declarations, but never requires every declared static, literal-dynamic, or CJS-require key to be represented. Thus an artifact declaring `./dep` with empty `bindings` passes construction; on an initial graph that omission is then blessed into the ceiling. It also does not prohibit a bootstrap-internal declaration from simultaneously appearing as an ordinary binding. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:267)

   Smallest fix: derive the exact expected binding-key set from the artifact, subtract only authenticated bootstrap-private declarations, and require equality. Add negatives for missing ESM, literal dynamic, and CJS bindings, plus double-represented bootstrap-internal edges.

3. **MATERIAL — manager-local nonces permit cross-manager shadow-token reuse.** Every new manager initializes its counter to `1`; the token carries no manager or generation identity, and `shadow_publish` compares only that local counter before checking source, candidate revision, and digest. Two first transactions over the same replacement therefore accept each other’s token—even across different execution generations—and the receiving transaction relabels the receipt with its own generation. [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:985), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1367), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1380)

   Smallest fix: bind tokens with an opaque per-transaction capability, such as a private shared identity checked by pointer identity, or a globally unique manager identity plus counter and generation. Add same-generation and cross-generation two-manager reuse negatives.

## Security Delta Verdict

**UNSAFE — unchanged.**

Of the four round-1 security blockers:

- Manager cloning is closed.
- Export/CJS shape enforcement is closed.
- Typed-metadata authentication remains incomplete through findings 1–2.
- Shadow transaction binding remains incomplete through finding 3.

## Minor Findings

- r9’s normative removal rule is clear, but §10 and §11 F4 were not updated to name edge removal explicitly. “ANY v2 ceiling breach” technically covers it, and the code has the test, but the required-fixture ledger should record it.
- The F10 tests do not independently isolate the live and replacement CJS disjuncts because same-goal CJS cases make both true. The implementation is correct; extracting the eligibility predicate would permit direct truth-table testing.
- The LLP review artifact could not be written because the supplied workspace is read-only.

## Verdict

NOT READY (with blocking finding numbers 1–3).
## codex-final-review

## Resolution Table

| Item | Result | Evidence |
|---|---|---|
| Residue 1 — authentication sources | RESOLVED | r10 correctly assigns declaration identity, resolved targets/deferred classification, and candidate pins to their respective authorities ([LLP 0055 §4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:452)). This matches link-plan validation ([graph.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/graph.rs:335)) and requester-bound sidecar validation ([computed_candidates.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/computed_candidates.rs:110)). |
| Residue 2 — two-sided agreement | RESOLVED | Undeclared rows refuse; every declared ESM-static key must be bound, while unresolved call-time keys may remain unbound ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:282), [LLP 0027](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0027-module-artifact-and-interop.spec.md:14)). Construction, clone-and-swap, Module-goal, CommonJS-goal, and snapshot-identity cases are covered ([tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1979)). |
| Residue 3 — shadow-token manager identity | RESOLVED for token-to-transaction reuse | Manager identity is process-allocated, copied into transactions/tokens, and compared before the transaction nonce ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:120), [generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1421)). Same-generation and cross-generation manager negatives exist ([tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:2093)). |
| Principal-less commit backstop | RESOLVED | Commit mirrors the begin refusal before graph publication, with direct snapshot-identity coverage ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1197), [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:2150)). |
| F4 edge removal/bootstrap coverage | RESOLVED | r10 names edge removal, equality rejects removal, and the bootstrap ceiling is now tested directly after the principal-less backstop ([LLP 0055 F4](/Users/ccheever/projects/ibex-wt/0417-h1/llp/0055-hot-revision-intra-generation-updates.spec.md:948), [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1122), [tests.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation/tests.rs:1385)). |

## Layering Judgment (residue 1)

Acceptable for the slice-2 algebra. There are currently no non-test V2 construction callers, and `from_verified` explicitly states its upstream plan/sidecar precondition ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:245)).

The analogy to `VerifiedModuleArtifactV1` is not mechanically exact—the plan-derived rows remain raw collections rather than an unforgeable witness—but deferring their production to slice 3 is sound provided `HotRevisionSurfaceV1` becomes the sole production constructor as r10 requires.

## New MATERIAL Findings

1. **MATERIAL — whole transactions can still cross managers.** `manager_identity` is stored in `HotRevisionTransactionV1`, but `ModuleExecutionGenerationsV2::commit_revision` never compares it with `self.manager_identity` ([transaction field](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1363), [commit checks](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1171)). Consequently, a transaction minted and shadow-published by manager A can be passed to manager B when generation, base, policy, and graph coincide; B accepts A’s replacements and accumulated shadow receipts at publication ([commit adoption](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1296)). The new tests exercise a foreign token against B’s transaction, not A’s entire transaction against B’s commit.

   Smallest fix: reject `transaction.manager_identity != self.manager_identity` before the existing commit backstops, with same-generation and cross-generation foreign-transaction tests including a staged shadow receipt and unchanged-state assertion.

## Minor Findings

- The type comment still says construction authenticates every typed row “against the verified artifact,” while r10 correctly assigns targets, deferred classification, and candidate pins elsewhere ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:230)). Also, “raw typed maps are not a public path” is literally stronger than the current public module/public constructors. Prefer “not a production path” or narrow visibility before slice 3.
- `NEXT_MANAGER_IDENTITY.fetch_add` wraps rather than refusing exhaustion, so “process-unique” is not mathematically permanent ([generation.rs](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:128), [allocation](/Users/ccheever/projects/ibex-wt/0417-h1-s2/src/module_loader/generation.rs:1041)).

## Verdict

NOT READY (blocking finding 1).
## codex-confirm

## Resolution

The blocker is resolved: `commit_revision` checks `manager_identity` before every backstop, and both foreign-manager tests include staged shadow receipts plus unchanged-state assertions. All 23 focused generation tests pass.

Minor 1 is resolved: the `from_verified` comment accurately distinguishes artifact-enforced agreement from upstream-authenticated targets, classifications, and candidate pins.

Minor 2 is not fully resolved: `fetch_add` wraps the atomic before returning `u64::MAX`; after rejecting `MAX` and `0`, a later mint reuses identity `1`. Use a checked `fetch_update`/CAS that leaves the counter permanently exhausted. This remains non-MATERIAL due to the unreachable-in-practice \(2^{64}\) construction requirement.

## New MATERIAL Findings

None.

## Verdict

READY
