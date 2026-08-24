# Review: LLP 0056 — Package-Aware Composition Admission (codex family)

**Reviewer family:** codex
**Model:** gpt-5.6-sol (provider openai), reasoning effort xhigh
**Session id:** 01a0346c-4df6-7512-9791-018a49751509
**Mode:** `codex exec -s read-only` in the 0056 worktree at ibex `94c85abab`; repo access + a capsule copy of Exact LLP 0413.001 r6; blind to the sibling grok review
**Rounds:**
- Round 1 (2026-08-24): reviewed r1 (`fa7b5ed0d`). Verdict: NOT READY.
- Round 2 (2026-08-24): reviewed r3 (`54d142d78`), fresh session (id 01a0349c-e902-7632-842c-c53a0eb68400), mutually blind to the sibling grok round; capsule: 0413.001 r7 @246f959cc + the exact-b7 dark-lane TS files at Exact origin/main (pre-@a049ed9aa). Verdict: NOT READY (4 MATERIAL areas; every decisive claim verified by the orchestrator against the trees before the r4 fold — all confirmed).
- Round 3 / delta (2026-08-24): reviewed r4 (`c1a05966f`), fresh session (id 01a034d2-fbad-7080-b28d-0ea2dfb2ca0d), mutually blind to the sibling grok round; capsule refreshed to Exact @a049ed9aa. Verdict: NOT READY (2 MATERIAL — expectations-schema maxima gap in the claimed O-1 authority; #14/#22 producer-routing contradiction; both verified and folded into r5).

## Round 1 (r1, verbatim)

## Overall Assessment

The architecture is promising: per-package content roots, an authenticated composition envelope, typed one-way references, atomic multi-root linking, and evaluate-then-invoke are the right general shape.

The Draft is not implementation-ready. The principal blockers are an incomplete/non-deterministic refusal registry, unreachable imported refusal rows, missing verifier inputs, an undefined generation-splice proof, omission of the authorized/deferred linker path, and an incomplete multi-root evaluation state machine.

The checked source files are unchanged from `94c85abab`; the current `HEAD` only adds LLP 0056.

## Verified Claims (spot-checks performed, with file:line)

- The §6.1 table contains every literal `IBEX_PREPARED_*` and `IBEX_DEV_COMMITTED_*` identifier emitted by the two production/dev wrappers and the core. The production wrapper tokens appear at [runner_pipeline.rs:3443](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3443), the core tokens span [runner_pipeline.rs:3547](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3547) through [runner_pipeline.rs:3825](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3825), and the dev-channel tokens appear at [runner_pipeline.rs:5996](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:5996) and [runner_pipeline.rs:6305](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6305). No literal token name is missing.

- The landed C ABI only attempts to serialize/write `out_report_json` in the success branch; failures write only `out_error` ([runner_pipeline.rs:6396](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6396), [runner_pipeline.rs:6412](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6412)).

- The landed return semantics are exactly `0` success, `1` before evaluation, and `2` during evaluation ([runner_pipeline.rs:6410](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6410)). The phase boundary is immediately before `linked.evaluate()` ([runner_pipeline.rs:6197](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6197)); the public header states the same fallback/no-restart rule ([exact_runtime.h:535](/Users/ccheever/projects/ibex-wt/pkg-admission/include/exact_runtime.h:535)).

- `SynchronousGraphPlan` is single-root today: `evaluation_order`, `linkage_order`, and `synchronous_evaluation_order` each accept one `entry` ([graph.rs:536](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/graph.rs:536), [graph.rs:548](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/graph.rs:548), [graph.rs:587](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/graph.rs:587)).

- `NativeSynchronousGraph` stores one `entry` and one flat evaluation order ([module_runner.rs:2890](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:2890)). Its graph-level namespace accessor is `namespace_json` ([module_runner.rs:4065](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:4065)).

- The generation-uniformity citation is exact: every reachable configuration is compared with the selected generation at [module_runner.rs:3606](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:3606).

- The sticky evaluation outcome and record-attributed error behavior are correctly described ([module_runner.rs:4012](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:4012)).

- `invoke_named_export` is implementable at the engine seam, but it requires a new native ABI call. The present native accessor merely `JSON.stringify`s the namespace and therefore cannot preserve or invoke function values ([hermes_module_runner.cc:4205](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/hermes_module_runner.cc:4205)). The existing length-aware export-property helper is suitable for the implementation ([hermes_module_runner.cc:197](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/hermes_module_runner.cc:197)).

- The composition-role/principal vocabulary is disciplined in the Draft, and the landed grouping really is by per-record defining principal ([LLP 0056:96](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:96), [runner_pipeline.rs:3631](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3631)).

## Factual Errors Found (file:line, MATERIAL/MINOR)

- **MINOR — the “exactly three places” digest enumeration is wrong.** The three served-package-byte locations are the top-level index field ([runner_pipeline.rs:224](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:224)), each carrier manifest ([carrier.rs:94](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/carrier.rs:94)), and each inline record artifact ([artifact.rs:265](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/artifact.rs:265)). `PreparedGraphCommitmentV1` is a fourth binding surface but is host-held, not inside package bytes ([arming.rs:48](/Users/ccheever/projects/ibex-wt/pkg-admission/crates/capsec-semantics/src/arming.rs:48)). LLP 0056 names the commitment while omitting the index ([LLP 0056:230](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:230)). The proposed package index happens to replace the omitted field, so the resulting schema direction is still sound.

- **MINOR — one §6.1 site is off by one.** `IBEX_PREPARED_COMMITMENT_SCHEMA` is emitted at [runner_pipeline.rs:3561](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3561), not line 3560 as listed at [LLP 0056:523](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:523).

- **MATERIAL — the “untokenized refusal classes” list is not complete.** Unclassified failures also arise from open/metadata/read operations ([runner_pipeline.rs:3255](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3255)), commitment-facet construction and missing root principals ([runner_pipeline.rs:3309](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3309)), directory enumeration ([runner_pipeline.rs:3589](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3589)), candidate-table decoding ([runner_pipeline.rs:3619](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3619)), missing carrier entries and SourceId display conversion ([runner_pipeline.rs:3777](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3777)), and the dev wrapper’s plan/config/runtime construction ([runner_pipeline.rs:6091](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6091)). These are absent from the purported complete list at [LLP 0056:535](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:535).

- **MATERIAL — `ibex:compiler-fingerprint-mismatch` is unreachable in the only v1 posture.** The dev path derives `transform_fingerprint_digest` from the artifact’s own fingerprint ([runner_pipeline.rs:3765](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3765)); admission recomputes that same fingerprint and compares it to the derived value ([artifact.rs:570](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/artifact.rs:570)). The independent current-toolchain comparison is explicitly skipped in dev posture ([runner_pipeline.rs:3734](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3734)). Therefore the promised F-i reachability fixture cannot exist without a new independent expected fingerprint.

- **MATERIAL — `ibex:encoding-incompatible` also lacks the claimed composition-path branch if v3 applies the v2 checks “verbatim.”** The caller chooses the engine expectation from the manifest’s own declared kind ([runner_pipeline.rs:3676](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3676)), making the source-carrier/engine disagreement at [carrier.rs:323](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/carrier.rs:323) unreachable through this caller. A manifest declaring source while carrying HBC bytes is not sniffed by `validate`; it reaches native loading later. LLP 0056 needs a new explicit declared-encoding/bytes predicate or must remove this imported v1 row ([LLP 0056:573](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:573)).

- **MINOR — `carrier.rs:170` is producer-side, not on the admission path.** It belongs to `from_inline_artifacts` ([carrier.rs:137](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/carrier.rs:137)); the reachable admission checks are at [carrier.rs:281](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/carrier.rs:281) and [carrier.rs:307](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/carrier.rs:307). Including line 170 in the O-2 covering map mixes producer and admission outcomes ([LLP 0056:569](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:569)).

## Design Concerns (MATERIAL)

- **The imported registry is not yet a determinate registry.** Exact r6 authorizes O-2 to replace its six placeholders and requires parity/reachability ([0413.001-r6.md:332](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:332), [0413.001-r6.md:523](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:523)). Expanding to eleven rows is a reasonable O-2 proposal, but it is not governing until Exact receives an explicit amendment. LLP 0056 supplies no replacement ordinals or consolidated table ([LLP 0056:555](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:555)). It also leaves precedence ambiguous between “lowest ordinal” and “app before agent” ([LLP 0056:606](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:606)), and says both that a step-3 remainder becomes `ibex:prepared-commitment-corrupt` and that step 3 defaults to `package-root-mismatch` ([LLP 0056:450](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:450)). Publish one numbered replacement table and one precedence tuple, such as `(step, predicateOrdinal, roleOrder)`.

- **`generation-splice` is not decidable from the specified schemas.** Step 3 requires one generation across the envelope and every package ([LLP 0056:450](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:450)), but neither the package index ([LLP 0056:270](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:270)) nor `PreparedPackage` producer identity ([LLP 0056:341](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:341)) contains one. Candidate tables happen to carry a generation, but packages need not contain candidate tables ([computed_candidates.rs:43](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/computed_candidates.rs:43)). Prefer a detached per-package attestation in the envelope—`(role, packageRoot, producer, generation)`—so generation splicing is detectable without making content-addressed package bytes session-dependent.

- **Required verifier inputs have no input channel.** The new ABI drops the landed `expected_target` argument ([LLP 0056:204](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:204)), while the expectations schema contains no target, engine/encoding profile, or O-3 frozen resolver/transform inventory ([LLP 0056:185](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:185)). The landed ABI receives and compares `expected_target` explicitly ([runner_pipeline.rs:6322](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6322), [exact_runtime.h:541](/Users/ccheever/projects/ibex-wt/pkg-admission/include/exact_runtime.h:541)); Exact O-3 requires the boundary inventory as explicit verifier input ([0413.001-r6.md:530](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:530)). Add these fields or name authoritative runtime queries for each.

- **The dev-unarmed design contradicts r6’s authorized-linker requirement.** Exact r6 explicitly requires the authorized linker path even in dev-unarmed posture ([0413.001-r6.md:201](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:201)). The landed dev entry calls unauthenticated `link_prepared` ([runner_pipeline.rs:6187](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6187)), which supplies empty authorization receipts ([module_runner.rs:3514](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:3514)). LLP 0056 instead reduces `cross-principal-denied` to a role-direction test on external references ([LLP 0056:780](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:780)), ignoring cross-defining-principal edges within each package. Define the dev-unarmed `GraphImportPolicy`, authorize internal and external edges, and generalize `link_authorized_prepared`, not the bypass.

- **Host-bridged dynamic imports are not connected to the proposed runtime.** Admitted records currently default deferred-dynamic state to empty ([runner_pipeline.rs:3813](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3813)); the current plan eagerly incorporates candidate tables ([runner_pipeline.rs:6091](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:6091)). The engine already has a distinct deferred-link path and installs literal/computed declarations only when `deferred_dynamic` is supplied ([module_runner.rs:3810](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:3810)). The proposed `link_prepared_composition` has no deferred declarations, activation owner, alias-aware runtime lookup, or retained session handle ([LLP 0056:638](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:638)). This blocks the required computed bootstrap seam.

- **Multi-root linking needs an explicit main root and descriptor state machine.** `link_inner` currently uses the single entry both to select generation ([module_runner.rs:3589](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:3589)) and to set `import.meta.main` ([module_runner.rs:3984](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:3984)). Because descriptor order is agent then app, replacing `entry` with an ordered roots vector risks marking the agent as main. Separately, the current single sticky outcome cannot represent “agent segment succeeded, invoke pending, app segment pending” ([module_runner.rs:4012](/Users/ccheever/projects/ibex-wt/pkg-admission/src/engine/module_runner.rs:4012)). Specify `main_root = app` independently and a monotonic descriptor executor with sticky terminal failure.

- **The invoke-before-app-entry guarantee is not enforced.** Agent→app references are legal ([LLP 0056:327](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:327)), and the current DFS evaluates every statically reachable dependency before its importer ([graph.rs:1422](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/graph.rs:1422)). If the agent root can reach the app root—directly or through an app cycle—the app entry evaluates before invocation, contradicting step 9 ([LLP 0056:493](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:493)). Step 7 must prove that the app root is absent from the agent evaluation closure.

- **The “total report” has no total tagged shape.** Step 0 is outside the registry ([LLP 0056:396](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:396)), yet the ABI says a report is always written ([LLP 0056:211](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:211)). The report sketch appears to require `failureStage` and `reasonCode` even on success, while step-9 errors return an admitted report without a registry reason ([LLP 0056:695](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:695), [LLP 0056:727](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:727)). Define tagged `admitted`, `refused`, `channel-error`, and possibly `admitted-startup-error` shapes, including serialization/allocation failure behavior.

## Design Concerns (MINOR)

- **Extraction is feasible, but not as a nearly mechanical core split.** The current helpers require a root principal for builtin attribution ([runner_pipeline.rs:3312](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3312)), and inventory enumeration specially permits an uncommitted `activation/` directory ([runner_pipeline.rs:3595](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:3595)). LLP 0056 should either make the root-principal invariant normative per package or remove the fallback, and explicitly forbid or define the activation carve-out.

- **The package core should return a typed capability rather than exposing `SourceGraphRecordV1`.** That record contains candidate tables, deferred dynamic state, prepared carrier state, and private path/display facts ([runner_pipeline.rs:266](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/runner_pipeline.rs:266)). An `AdmittedPackageV1` with controlled union/link accessors would make the extraction boundary clearer.

- **Named-export presence should mean resolved namespace presence.** Checking only whether the entry artifact “has” a descriptor mishandles indirect/star exports; the graph already resolves star-export chains and ambiguity ([graph.rs:1390](/Users/ccheever/projects/ibex-wt/pkg-admission/src/module_loader/graph.rs:1390)). Step 7 should use the resolved namespace plan.

- **Numeric wire bounds need spelling out.** The expectations use unconstrained `u64` fields ([LLP 0056:185](/Users/ccheever/projects/ibex-wt/pkg-admission/llp/0056-package-aware-composition-admission.spec.md:185)), while r6 requires RFC 8785/I-JSON number discipline and safe-integer report counters ([0413.001-r6.md:143](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:143), [0413.001-r6.md:376](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:376)). Pin `0..=2^53-1` or use canonical decimal strings.

- **The r6 fixture text itself needs an amendment.** Its normative step 7 maps missing named export to `entry-descriptor-invalid` ([0413.001-r6.md:249](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:249)), but fixture 35 still expects `entry-plan-mismatch` ([0413.001-r6.md:467](/private/tmp/claude-501/-Users-ccheever-projects-exact/3a3a2aea-2be8-4a33-9229-9ec619632b72/scratchpad/pkg-admission/0413.001-r6.md:467)).

## Answers to the Standard Review Questions

- **Is it a good idea?** Yes. Package-local bytes plus an authenticated composition envelope is substantially better than extending the whole-publication digest. It directly supports app-byte stability and makes role boundaries inspectable.

- **Do we have a good plan?** The four implementation legs are sensible, but schema/registry work cannot be considered landable until the refusal table, verifier inputs, generation evidence, and runtime state machine are fixed.

- **What should change?**
  - Generate the Rust refusal enum from the vendored registry rather than hand-maintaining both.
  - Introduce `AdmittedPackageV1`, `AdmittedCompositionV1`, and a typed `AdmissionError { step, predicate, role, code }`.
  - Use a tagged binding target—`Local` versus `External { role }`—instead of an optional `externalRole`.
  - Generalize the authorized deferred-prepared linker, not only `link_inner`.
  - Add a dedicated native invoke ABI with evaluated-state checking, length-bearing export names, structured-error retention, and host-task checkpointing.
  - Make the descriptor executor own partial-progress and sticky-failure state.

- **Anything wrongheaded?** The package/composition split is not wrongheaded. Treating composition-role direction as a substitute for per-defining-principal authorization is. So is claiming registry coverage while retaining unreachable rows and prose/default ambiguity.

- **Novel improvements:** detached generation attestations preserve content-addressed package reuse; a monotonic descriptor executor makes evaluation/invocation order mechanically enforceable; and a retained composition session object can unify alias resolution, deferred activation, graph lifetime, and reporting.

- **Key open questions:** What independently authenticates package generation? What policy authorizes intra-package cross-principal edges in dev-unarmed mode? Who owns deferred activation after the startup C call returns? What is the exact precedence tuple? Which root receives `import.meta.main`? Can the agent evaluation closure ever contain the app root?

## Recommended Next Step

Revise LLP 0056 before implementation:

1. Publish a consolidated numbered refusal registry, reachability proof for every row, and unambiguous precedence/default rules.
2. Add the missing verifier inputs and generation-attestation model.
3. Specify the authorized deferred multi-root session and descriptor state machine, including `main_root` and the agent-closure exclusion.
4. Replace the report sketch with explicit tagged schemas for every ABI outcome.
5. Amend Exact 0413.001’s literal registry and stale fixture 35, then rerun the independent review loop.

Verdict: NOT READY — the architectural direction is good, but registry reachability, verifier authority, generation proof, dynamic-link ownership, and multi-root execution semantics remain materially incomplete.

## Round 2 (r3, verbatim)

## Overall Assessment

The architecture is sound, and the 38-row registry passes the required byte-level lockstep check. However, r3 is **not ready for acceptance**. Material normative gaps remain in generation-carrier completeness, bounds placement, authorization staging, producer-identity attestation, and acceptance/lockstep prose.

## Verified Claims (spot-checks performed, with file:line)

- `HEAD` is `54d142d78`; `src/`, `crates/`, and `include/` are byte-identical to `94c85abab`.
- The three served-byte whole-publication bindings are correctly identified: index at `runner_pipeline.rs:224-231`, carrier manifest at `carrier.rs:94-102`, and artifact producer identity at `artifact.rs:265-275`. The host-held fourth surface is `arming.rs:48-59`.
- The 18 literal `_CORRUPT` sites and other landed tokens in §6.1 match the tree, including `runner_pipeline.rs:3261-3288`, `3547-3564`, `3598`, `3612`, `3621`, `3634`, `3649`, `3728`, `3749`, and `3825`.
- Dropping `ibex:compiler-fingerprint-mismatch` is correct for dev-unarmed: the posture skips the independent check at `runner_pipeline.rs:3734-3738`, while the expected fingerprint is derived from the artifact itself at `runner_pipeline.rs:3765-3766`; the otherwise failing comparison is `artifact.rs:570-571`.
- The encoding branch at `carrier.rs:323-327` is unreachable through the landed caller because the caller selects expectations from the manifest’s declared encoding at `runner_pipeline.rs:3676-3685`. The new byte-shape sniff is therefore necessary.
- Runtime engine identity is correctly sourced from the loaded engine at `runner_pipeline.rs:6011-6033`.
- The defining-principal authorizer compares importer and target principals and consults policy at `security.rs:409-442`.
- The authorized prepared linker is `module_runner.rs:2937-2966`; the landed dev lane uses the receipt-free bypass at `runner_pipeline.rs:6187-6194`.
- HBC preflight currently occurs outside the shared admission core at `runner_pipeline.rs:6065-6088`, calling `module_runner.rs:459-469`; composition-only parameterization preserves the existing lane.
- The graph is presently single-root (`graph.rs:536-603`), selects generation from the entry at `module_runner.rs:3589-3593`, and marks that entry as `import.meta.main` at `module_runner.rs:3984-3988`. The named `mainRoot = app` pin is necessary.
- Sticky evaluation is as described at `module_runner.rs:4012-4059`; namespace access serializes through `JSON.stringify` at `hermes_module_runner.cc:4205-4212`.
- The landed C ABI emits reports only on success and returns 0/1/2 as described at `runner_pipeline.rs:6396-6418`.
- The dark Exact files are demonstrably r6-shaped: `PreparedPackageDeliveryV1` carries `produceGeneration` beside bytes at `prepared-composition-schema.ts:146-155`; the producer emits it at `prepared-composition-producer.ts:694-698`; admission consumes it at `prepared-composition-admission.ts:60-66` and `489-497`.

## Factual Errors Found (file:line, MATERIAL/MINOR)

- **MATERIAL — the “one canonical serialized generation carrier” is incomplete.** LLP 0056 says package bytes carry no generation and the envelope triple is the only serialized carrier (`llp/0056-package-aware-composition-admission.spec.md:420-422`, `556-587`), yet its package index retains candidate-table files (`402-414`). The inherited `ComputedCandidateTableV1` serializes `generation` at `computed_candidates.rs:43-50`, validates it at `84-85`, and compares it with execution generation at `runner_pipeline.rs:1143-1148`. The spec must define a generation-free candidate-table successor or explicitly reconcile this field.
- **MATERIAL — producer-identity attestation does not match r7 precisely.** R7 requires every package index’s producer identity to equal the envelope’s (`0413.001-r7-at-246f959cc.md:162-167`). The 0056 index sketch carries only `producerBinaryDigest` (`llp/0056...spec.md:402-414`), and §4.8 compares that digest to an identity (`563-567`). Either add the producer ID to the package-level identity or normatively require all index-committed carrier/artifact identities to equal the envelope’s full identity.
- **MATERIAL — acceptance coupling contradicts itself.** The normative sentence still says 0056 cannot become Accepted until generated parity passes (`llp/0056...spec.md:1266-1269`), immediately followed by r3 saying generated parity is now only an implementation-leg gate (`1270-1274`).
- **MATERIAL — the claimed cross-repository reference-scope declaration is absent from the capsule.** 0056 says `§4.4`, `§4.8`, and `§10` are declared 0056-relative “in both repositories” (`884-888`). Exact’s lockstep prose at `0413.001-r7-at-246f959cc.md:325-353` contains no such declaration; in that document, the bare references naturally point to unrelated or nonexistent Exact sections.
- **MINOR — stale O-1 wording.** Section 9.1 says the seed has landed at `llp/0056...spec.md:1156-1161`, then says “Until the O-1 package lands” at `1174-1176`. This should say until r7 alignment/parity passes.
- **MINOR — “ALWAYS written” is too strong.** The ABI comment promises an output report on every outcome (`326`), while §8 permits report serialization failure without changing the outcome (`1142-1143`). Specify a fallback report or permit a null report explicitly.

## Fold Verification (r1 -> r2/r3: held / not held, per finding)

- **38-row ordinalized registry, precedence tuple, one default per step — HELD.** Exactly 38 rows; one `(step, ordinal, roleOrder)` rule; one default for each step/substep.
- **Dropped compiler-fingerprint row — HELD.** The cited dev posture makes it unreachable.
- **Encoding-sniff predicate — HELD.** It closes the caller-selected-expectation hole.
- **Total/injective landed covering map — HELD at the specification level.** Spot-checked literal tokens, file-I/O classes, candidate decode, carrier/artifact checks, HBC checks, and wrapper construction. The proposed implementation fixture remains an implementation gate.
- **Defining-principal authorization and authorized linker — PARTIALLY HELD.** The principal semantics and chosen linker are correct, but the step-6-to-step-8 authorization capability is unspecified.
- **Decidable generation attestation — NOT FULLY HELD.** The envelope triple solves the sidecar problem, but candidate-table generation and full producer identity remain unresolved.
- **Complete verifier inputs — HELD.** Commitment slimming, mandatory expectations, target, O-3 inventory digest, clock, and runtime-owned engine identity match r7.
- **Bounds split by enforcement surface — NOT HELD.** The external-reference cap remains envelope-only.
- **Tagged report shapes — HELD**, subject to the minor serialization/“always” contradiction.
- **Fixture 35a/35b — HELD** in both documents.
- **Alias disjointness and composition-wide verification — HELD.**
- **HBC preflight composition-only — HELD.**
- **Purity theorem, tagged binding targets, named main root, order-guarantee proof, descriptor executor, and retained session — HELD.**

## Lockstep Verification (6.2 vs 4.1; envelope shapes)

- Extracted rows matching `^| <number> | \``: 38 in 0056 and 38 in r7. Every row is byte-equal.
- Extracted four-line Defaults paragraphs: byte-equal.
- Precedence tuple, ordinal evaluation order, D1–D9 amendment direction, fixture-35 correction, and environment/channel codes are semantically consistent.
- No registry-row byte drift exists.
- The bare section-reference scope is not lockstep-safe because only 0056 declares it 0056-relative.
- Commitment shape matches: schema/workflow metadata plus only `compositionRootDigest`.
- Expectations match exactly: `expectedTarget`, `expectedRoles`, `sessionNonce`, `authorityGeneration`, `resolverGeneration`, `policyDigest`, `resolverInventoryDigest`, and `nowUnixMs`; all mandatory and I-JSON-safe.
- The `(role, packageRoot, producerGeneration)` triple matches r7.
- The accompanying full-producer-identity predicate does not yet match precisely, as noted above.

## Dark-Impl Pin Assessment (d1, d2)

**d1 — correct and sufficiently precise.** The dark producer’s branch at `prepared-composition-producer.ts:756-817` maps both unresolved and resolvable-but-unpublished dynamic targets to `"target is not a bundle module"`. Under package-local admission, the decidable fact is whether the owning package publishes a target record, not why the project-wide resolver omitted it. Keeping the closed two-member enum is the right call. Add a fixture for each of the two underlying producer situations, both expecting row #30 only on committed-row divergence.

**d2 — correct principle, incomplete pin.** Rejecting `PreparedPackageDeliveryV1` is correct: the dark wrapper is outside both the package-root and composition-root commitments. The envelope triple should be the sole authenticated produce-generation carrier. Completeness requires explicitly evolving/removing `ComputedCandidateTableV1.generation` and stating how the envelope-attested generation enters in-memory execution configuration.

## Design Concerns (MATERIAL)

- **External-reference bound is enforced at the wrong surface.** External bindings live in package rows (§4.5), but `external references ≤ 4,096` is listed only under envelope decode (`llp/0056...spec.md:245-251`). A malicious committed package can contain more than 4,096 external rows before step 6 compares the union table. Enforce the cap during step-3 package decode as well.
- **Authorization staging lacks a typed handoff.** Step 6 assigns denial to #34 (`694-706`), while step 8 and §7.2 say the authorized constructor authorizes and links (`725-730`, `1021-1025`). The current authorized constructor likewise authorizes internally at `module_runner.rs:2951-2966`. Define an `AuthorizedCompositionPlanV1` produced at step 6 with retained receipts and consumed at step 8, or the denial can surface incorrectly as #38.
- **Generation-free package evolution is underspecified.** Candidate-table schema evolution and its execution-generation replacement belong in §4/§11 and the O-1 corpus, not as an inference left to implementers.
- **Acceptance criteria must have one normative meaning.** Relaxing generated parity to an implementation gate is sound because the document tables are already byte-identical and nothing admits before implementation leg 3. The old acceptance-blocking sentence must nevertheless be removed or rewritten.

## Design Concerns (MINOR)

- Change “tampered carrier hits #15 first” at `llp/0056...spec.md:660-663`; manifest-only principal tamper can reach the principal checks at `carrier.rs:281` or `307`.
- Make report serialization/allocation behavior part of each tagged ABI outcome.
- Add the 0056-relative reference-scope sentence to Exact r7 outside the shared table, so the row bytes remain identical.
- OQ-D’s thenable semantics are acceptable for v1, but a diagnostic flag for “bootstrap returned thenable” would make later regressions visible.

## Answers to the Standard Review Questions

The proposal is a good idea. Per-package roots plus an authenticated composition envelope are the right architecture for stable app bytes, one-way package composition, and fail-closed admission.

The implementation plan is well sequenced: schema/corpus, admission, link/evaluate, then Exact integration. It needs a small but load-bearing schema revision and a typed authorization-plan handoff before implementation begins.

I would:

1. Define a generation-free candidate-table successor.
2. Pin full package producer identity against the envelope.
3. Enforce the external-reference cap at package decode.
4. Introduce `AuthorizedCompositionPlanV1` between steps 6 and 8.
5. Repair the acceptance paragraph and add the Exact-side reference-scope note.

Nothing about the core package/composition split is wrongheaded. The unauthenticated sidecar is wrongheaded and r3 correctly rejects it; leaving other serialized generation fields implicit would recreate the same ambiguity.

A useful non-standard improvement would be an executable “schema invariant audit” generated from O-1 that asserts: no generation-bearing field exists below a package root, every registry row has a reachability recipe, and every step-6 authorization receipt is consumed exactly once at step 8.

The key remaining questions are where full producer identity lives, what replaces candidate-table generation, and what typed capability bridges authorization and linking.

## Recommended Next Step

Keep the document in Draft and produce r4 with the five targeted changes above. No architectural rewrite is needed. Re-run the row/default byte comparison after adding only surrounding Exact prose, then require the r7-shaped O-1 corpus and generated parity check before implementation leg 1 proceeds.

Verdict: NOT READY — the one-carrier generation invariant, producer-identity attestation, bounds placement, and step-6 authorization handoff remain materially incomplete.


## Round 3 / delta (r4, verbatim)

## Overall Assessment

The architecture is strong and r4 folds nearly all round-2 findings correctly. The 38-row lockstep is exact. However, r4 is not ready: one claimed O-1 authority omits required numeric bounds, and producer-identity failures have conflicting refusal assignments.

## Verified Claims (spot-checks performed, with file:line)

- `HEAD` is `c1a05966f`; `src/`, `crates/`, and `include/` are byte-identical to `94c85abab`.
- Candidate-table v1 serializes `generation` (`computed_candidates.rs:43-50`), validates it (`:80-85`), and checks it against execution generation (`runner_pipeline.rs:1138-1148`).
- Landed artifact and carrier identities contain both producer ID and binary digest (`artifact.rs:265-275`; `carrier.rs:94-102`) and admission compares both (`artifact.rs:533-542`; `carrier.rs:309-313`).
- The existing authorized prepared linker performs authorization internally (`module_runner.rs:2937-2966`), confirming why r4’s step-6 capability handoff is necessary.
- Link-time configuration generation is selected and checked uniformly (`module_runner.rs:3589-3608`); `import.meta.main` is currently positional to the single entry (`:3984-3988`), validating the explicit app `mainRoot`.
- Exact’s delivery wrapper now carries no generation (`prepared-composition-schema.ts:162-172`); the envelope has attestation triples (`:228-243`), producer emits them (`prepared-composition-producer.ts:636-645`), and the admission mirror consumes them (`prepared-composition-admission.ts:495-510`).
- `collectAliasImportSites` uses declared edges plus host-bridged rows exactly as r4 states (`prepared-composition-schema.ts:485-515`).
- The parity check’s lockstep leg explicitly reports unarmed before the vendor pointer contains LLP 0056 and arms afterward (`check-prepared-composition-schema-parity.mjs:152-186`).

## Fold Verification (round-2 findings -> r4: held / not held, per finding)

- Generation-free candidate-table v2: **HELD**. §4.3 defines v2 as v1 minus `generation`, rejects v1 as #12, preserves the old lane, and supplies the envelope generation in memory.
- Full producer identity in the package index versus envelope: **HELD at the invariant level**, but r4 introduces a MATERIAL refusal-routing inconsistency described below.
- External-reference cap at package decode: **HELD** (§3.1, lines 274-285).
- `AuthorizedCompositionPlanV1` step 6 → step 8 handoff: **HELD** (§5, lines 797-817; §7.2, lines 1131-1160).
- Single-meaning acceptance coupling: **HELD** (§6, lines 863-878; §11, lines 1416-1426).
- §6.2 reference-scope overclaim: **HELD**. r4 accurately says only 0056 currently declares the scope and records the Exact-side note as a handoff (`:994-1002`).
- Ordinal-outer step-3 sweep: **HELD** (`:739-748`).
- `*_for_roots` entry-plan argument order: **HELD** (`:1121-1124`).
- §9.1 staleness: **NOT HELD**, MINOR. It still says A1/r7 alignment is “in flight” (`:1296-1301`).
- Report null on serialization failure: **HELD** (`:1279-1283`).
- Thenable diagnostic: **HELD semantically** (`:1190-1199`, `:1276-1278`).
- Expiry/policy note: **HELD** (`:344-350`).
- d1 literal-dynamic-only and identity rationale: **HELD** (`:496-519`).
- #16 tamper wording: **HELD** (`:761-766`).

## Delta Scan (new-in-r4 text)

- Candidate-table v2 is consistent with the landed generation check and one-carrier invariant, provided admission authenticates the v2 wire digest before constructing the generation-stamped in-memory execution form.
- Adding `producerId` is consistent with landed carrier/artifact identity shapes.
- The typed authorization capability is the correct evolution of `link_authorized_prepared`; it prevents policy denial from migrating to #38.
- Alignment-wave results:
  - Commitment authority: true (`prepared-composition-commitment-v1.schema.json:7-24`).
  - Expectations property set and requiredness: true, but its claimed numeric constraints are false.
  - Alias evidence basis: true.
  - Generation-carrier resolution: true.
  - Lockstep arming note: true.
  - Leg-1 hold release: overstated because §9.1 remains stale and the parity check omits the two channel schemas.
- The supplied capsule omits the vector corpus and builder, so the claimed count of 21 cannot be independently confirmed. The check only reports `corpus.vectors.length` dynamically (`check-prepared-composition-schema-parity.mjs:309-329`).

## Lockstep Verification

- Extracted rows matching `^| <number> | \``: 38 from r4 and 38 from Exact r7.
- Rows are byte-identical; both SHA-256:
  `879deaec27b2ef9b916f09a5842a421fdc4016c2cf0cbb130176d3e231c47fb0`.
- Defaults paragraphs are byte-identical; both SHA-256:
  `5117549d6f5a426beff35a329b63e54f030f5f5a8d215983d5fafa83c6376995`.
- r3→r4 comparison also confirms the shared rows and Defaults paragraph were unchanged. All r4 edits remained outside those shared bytes.

## Factual Errors Found (file:line, MATERIAL/MINOR)

- **MATERIAL — the landed expectations schema does not enforce the claimed I-JSON bound.** LLP 0056 says integers are `0..=2^53-1` and claims the authority file has I-JSON constraints (`llp/0056-package-aware-composition-admission.spec.md:319-344`). The schema gives `authorityGeneration`, `resolverGeneration`, and `nowUnixMs` only `minimum: 0`, with no safe-integer maximum (`composition-verifier-expectations-v1.schema.json:47-65`). The parity check does not inspect this schema or the commitment schema (`check-prepared-composition-schema-parity.mjs:266-306`), so it can report PASS without detecting the mismatch.
- **MATERIAL — producer-identity refusal routing is contradictory.** §4.8 assigns an index-versus-record producer mismatch to #14 (`llp/0056...spec.md:643-646`), while §6.4 maps carrier/artifact producer staleness to #22 (`:1083`). The landed check jointly compares producer ID and digest (`artifact.rs:533-542`). This leaves one failure class with two registry dispositions and different A/P classifications.
- **MINOR — §9.1 still reports obsolete alignment state.** It says r7 alignment is in flight (`llp/0056...spec.md:1296-1301`) while the Summary and §11 say it completed and released the hold (`:159-169`, `:1384-1402`).

## Design Concerns (MATERIAL)

- The O-1 authority must not permit integers outside the cross-language canonical range while the spec and Rust implementation reject them. Add `maximum: 9007199254740991` to all three expectation integers and extend the parity check to validate both channel schemas.
- Choose one deterministic disposition for producer mismatches. The clean split is:
  - index full identity versus envelope → #22;
  - carrier/artifact identity versus authenticated index → #14.
  
  Then update §6.4 and its covering-map fixture accordingly without changing shared row bytes.

## Design Concerns (MINOR)

- State explicitly that the v2 candidate-table digest authenticates the generation-free wire form and is checked before creating any stamped execution representation.
- Change `invoke_named_export -> Result<()>` or document retained executor state so the required `agentInvokeReturnedThenable` diagnostic has an explicit transport.
- Rewrite §9.1 to name exactly which Exact-side rows are aligned and which ibex-half O-1 rows remain provisional.

## Answers to the Standard Review Questions

The proposal is a good idea. Per-package roots plus an authenticated composition envelope are the right way to obtain stable app bytes, one-way package composition, and fail-closed admission.

The implementation plan is well sequenced. Candidate-table v2, explicit authorization capability, ordinal-outer evaluation, and named multi-root execution materially improve implementability.

I would keep the architecture and make a narrow r5: repair the expectations authority/check, resolve #14 versus #22, and remove stale coordination prose. I would not add another generation carrier, producer channel, role, or lifetime authority.

A useful non-standard improvement is an executable invariant audit asserting that no serialized field below the envelope carries generation, every producer-identity comparison has one refusal code, and every numeric schema field used across TS/Rust is I-JSON bounded.

The key open questions are only the exact #14/#22 split, the stamped candidate-table runtime representation, and how the thenable diagnostic crosses the native seam.

## Recommended Next Step

Produce r5 with the two MATERIAL repairs, update §9.1, rerun the unchanged row/default comparison, and perform another focused delta review. No architectural rewrite is needed.

Verdict: NOT READY — the claimed O-1 expectations authority omits its safe-integer maxima, and producer-identity mismatch routing is split between #14 and #22.
