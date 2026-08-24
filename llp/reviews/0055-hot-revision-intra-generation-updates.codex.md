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