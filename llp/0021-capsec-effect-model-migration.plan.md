# LLP 0021: Capability Security Effect-Model Migration

**Type:** Plan
**Status:** Accepted
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-10
**Revised:** 2026-08-06 (adds the DRAFT "Amendment: scoped advertisement"
section and its scope-digest join-matrix appendix, authored as the LLP 0049
Phase 1 review package per LLP 0044 §2/§7; round-1 revision applied the same
day — both round-1 flip sets landed, matrix grown M1–M31, round 2 pending;
the amendment is UNDER LLP 0049
PHASE 1 REVIEW and no gate code may land until that review completes —
LLP 0044 register item 5 stays BLOCKED and every pre-amendment section of
this document continues to describe the enforced all-or-nothing gate)
**Revised:** 2026-08-03 (restores `node:diagnostics_channel` and `node:domain`
to the independent public-evidence validator's terminal-builtin vocabulary
after the exact Apple matrix proved that production, authoring, and the Rust
loaded-engine executor recognized all seven reviewed families while the final
JavaScript evidence check repeated only five; a regression now exercises the
root-module closure contract for all seven families)
**Revised:** 2026-08-03 (synchronizes the independent loaded-engine target-
absence budget with the already-reviewed source-derived Apple catalog: 114
executable absence fixtures partition exactly into 92 target-absence
invocations and 22 native-global absence reads; the executor retains both the
total and split assertions so future catalog growth remains fail-closed)
**Revised:** 2026-08-03 (scopes the reviewed pure-compatibility call validator
to callable `node_readline` recipes after a physical Windows-catalog replay
proved that its default branch also rejected the inert
`node:readline.promises` data read; non-callable export reads now bypass that
call-only vocabulary, while the exact CSI and Interface call contracts,
unreviewed readline calls, and callable-as-read near misses remain fail-closed)
**Revised:** 2026-08-03 (retires executable credit for the deprecated root
`node:fs` `F_OK`, `R_OK`, `W_OK`, and `X_OK` accessors after physical Apple
and Windows batches proved that each getter intentionally enters the DEP0176
warning path; armed runtimes keep `process.emitWarning` disabled, so authoring
now records the four exact rows as `builtin-export-requires-deprecation-warning`
residuals and the loaded-engine validator rejects stale recipes before
evaluating a getter, while the inert `fs.constants` object remains separately
covered; Apple accounting becomes 3,926 fully executable / 3,050 internally
verified / 16,671 unresolved and Windows becomes 3,560 / 3,036 / 16,710)
**Revised:** 2026-07-28 (accepts the security-critical CapSec rev2 implementation under an explicit convergence boundary: the final armed `exact_crypto` mixed-module controls are sealed only for the JCS-canonical authenticated builtin SourceId, shared by the `crypto`, `exact:crypto`, and `node:crypto` cache aliases, and pin `fips`, `secureHeapUsed`, `setEngine`, and `setFips` to immutable `ERR_ACCESS_DENIED` / `CryptoControl` refusal while leaving unarmed diagnostic behavior unchanged; the planned pre-fix negative control proved mutable descriptors and successful access, while the fixed EPYC authenticated batch passes 845/845 receipts against loaded engine `sha256-MdTBzG7byvsZPmeYDdFD1zx9oP33e7f9Iza6sWNR7LU`, independently reconstructs all four new records, and has raw evidence SHA-256 `08a1585232e19e13d7b9b64f4f6a7b758214a685f564e6a96835be56c4f4577c`; final Apple catalog `sha256-GHlqGTU7b020Cp107EbGh4TShEtB_kOoRz5R1pDtYEo` reports 23,598 required / 3,928 executable / 3,042 internally verified / 16,628 unresolved and Windows `sha256-FAud-eHXcShfXTx3wsnucQFaQ96H2khcNzhxUqxbwzU` reports 23,257 / 3,564 / 3,028 / 16,665; advertisements remain empty, so no exact target is falsely claimed, and target promotion plus catalog/evidence completeness move to prioritized filesystem tickets rather than extending this security-implementation tranche)
**Revised:** 2026-07-28 (retires the stale armed-runtime crash exclusion for the four source-inventoried global WebCrypto CSPRNG routes: `Crypto.getRandomValues`, `crypto.getRandomValues`, `Crypto.randomUUID`, and `crypto.randomUUID`; both `getRandomValues` spellings receive a harness-owned four-byte `Uint8Array`, both UUID spellings require a normal string return, and every route binds its exact global/prototype source descriptor, reaches quiescence, performs owned cleanup, and emits zero legacy or typed decisions; an EPYC authenticated armed batch passes all 579 Apple global-callable rows against loaded engine `sha256-MdTBzG7byvsZPmeYDdFD1zx9oP33e7f9Iza6sWNR7LU`, including independent JavaScript reconstruction of the four new records; Apple catalog `sha256-h-aEuY5hwrzFjpPHiwFduM-g8AZggxy2rg7QLAiwrtM` reports 23,595 required / 3,924 executable / 3,040 internally verified / 16,631 unresolved and Windows `sha256-FQOQTr_HtWdl9UXnHquLaEp--6knN2qhgflw1PnH6GY` reports 23,254 / 3,560 / 3,026 / 16,668; advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (seals the armed `__exactAndroidDispatchPlatformEvent` rendezvous after trusted bootstrap while preserving native Android framework-event delivery through an owner-thread JSI function retained by the runtime; the initial trusted shared-runtime drain and unarmed compatibility runtimes may resolve the public global before finalization, but armed delivery after project admission never falls back to a mutable project-visible spelling; the first EPYC batch proved the gap when root disposition refused the still-reachable dispatcher, while the hardened batch emits 841 passing records and the new absence receipt independently reconstructs exactly; an Android-defined C++ syntax build and a source contract verify the retained-handler dispatch path; the descriptor sweep advances to 369 sealed/private and 2,441 permitted reachable rows across 2,810 install branches; Apple catalog `sha256-O-gOrYFifBB1UOiBdeaaRgvh9lcT4TII-bOGrHKK3bE` reports 23,595 required / 3,920 executable / 3,040 internally verified / 16,635 unresolved and Windows `sha256-OC3SQg1at67QVQt-uxJKuGIuvB-fTgQ8GfxLRZa5maM` reports 23,254 / 3,556 / 3,026 / 16,672; advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (seals only the dangerous members of the armed `Bun.unsafe` / `Exact.unsafe` compatibility namespace: `gcAggressionLevel` and `segfault` are deleted and verified absent before project code, while the namespace and pure `arrayBufferToString` helper remain available and unarmed diagnostic behavior is unchanged; exact `shared-runtime-global-absence` authoring promotes all four target-applicable rows on Apple and Windows; the first physical batch proved the prior enforcement gap when the generated startup sweep refused `Exact.unsafe.gcAggressionLevel` as still reachable, and the hardened rerun emits 840 passing records including the four new receipts; the reviewed lockdown digest advances to `sha256-17da17dbe9239bda0640545bfc0fd669f4127b920148c66076bec63d1c8d0ec1` and evaluator identity to `hermes-evaluators.9eb62c380d7cf28c16a42808ca30fc984b0368f88f9a453f441bb38c352e3f99`; Apple catalog `sha256-JF9k4eov8f5c6zDrYFMD9h-Yet2wKlgjNUHyOx7Vx68` reports 23,595 required / 3,919 executable / 3,040 internally verified / 16,636 unresolved and Windows `sha256-9bOXZs5uruLhxISbPsJhv1PFvF1OfK7t_5qNlywlYr8` reports 23,254 / 3,555 / 3,026 / 16,673; independent JavaScript reconstructs the four physical records exactly, advertisements remain empty, and criterion 7 remains open)
**Revised:** 2026-07-28 (seals the armed `Bun.inspect` and `Exact.inspect` aliases plus the POSIX-only `process._uncaughtExceptionHandler` and `process._unhandledRejectionHandler` compatibility cells after trusted bootstrap capture; diagnostic runtimes retain them, while armed lockdown deletes and verifies all four paths before project code; recipe authoring and JavaScript/Rust evidence validation admit the two handler receipts only for the exact Apple `global_stream_enhance` / `legacy-bootstrap` / `posix` branch and source reference, so Windows receives only the two target-applicable inspector receipts; the first physical batch correctly rejected the new POSIX recipes until the Rust executor repeated that same narrow reviewed path; the reviewed lockdown digest advances to `sha256-2d4051daed930d036f233781d19e9a23bcf40e46a94a0eae3b175983ae6641c4` and evaluator identity to `hermes-evaluators.879af494f194ff54a22db7cffc2cf359d37e935e1a262e6b6322ee0331ea729f`; Apple catalog `sha256-hLTMCr30pcFO9cJUq5nrhV6KRrTrD2hf3rptNKL16JM` reports 23,595 required / 3,915 executable / 3,040 internally verified / 16,640 unresolved and Windows `sha256-1s5hJyUumk_KtK51EdbRK75KqUR3XoGJNpZCWb0HuPc` reports 23,254 / 3,551 / 3,026 / 16,677; the isolated EPYC authenticated closed batch emits 836 passing records including all four Apple receipts, independent JavaScript reconstructs them exactly, advertisements remain empty, and criterion 7 remains open)
**Revised:** 2026-07-28 (seals the deliberate `__exactMemoryDebug` facade from armed runtimes and promotes its root plus eight members through exact `shared-runtime-global-absence` receipts on both candidate targets; the first physical batch correctly failed because the diagnostic root remained reachable, and the first hardening rerun then exposed a disposition-generation gap where dual-role global/native reconciliation retained the native spelling and incorrectly expected the deleted root to remain reachable; final lockdown now deletes and verifies the root before project code, the shared-runtime closure vocabulary recognizes that exact dual-role spelling, and the generated descriptor sweep requires all nine paths absent; unarmed diagnostic runtimes retain the compatibility facade; the reviewed lockdown digest advances to `sha256-154d9ce9cd21785f2ec4c20f3f439d6070ce583db5a7bb7b0ac08f1e3acfcf1d` and evaluator identity to `hermes-evaluators.b4106e7d147ac12fb8357cfff2aa90e1f7d2768f9a98971b27ed104af36bb50d`; Apple catalog `sha256-hQCUY7PAXXC9ZH9kIxR66SR_n2iXA_dRZii3oj35kYo` reports 23,595 required / 3,911 executable / 3,040 internally verified / 16,644 unresolved and Windows `sha256-QhN-pTt-_OuYCsF1HqTjBudSOe39yBqfAfE9wIbeSxg` reports 23,254 / 3,549 / 3,026 / 16,679; the isolated EPYC authenticated closed batch emits 832 passing records including all nine new receipts, independent JavaScript reconstructs them exactly, advertisements remain empty, and criterion 7 remains open)
**Revised:** 2026-07-28 (promotes the source-inventoried `process.__exactStreamStabilityPatched` cell through an exact `shared-runtime-global-absence` receipt on both candidate targets; authoring binds the one default branch to both of its real installation routes—the legacy compatibility bootstrap and the native evaluated `streamStabilityPatchJS` program—rather than crediting either source in isolation; the loaded engine proves descriptor-only absence before project code without evaluating an accessor and emits zero legacy or typed decisions, so no runtime hardening change is required; independent JavaScript reconstructs the physical record exactly and the authoring, evidence, and Rust validators all reject an incomplete or invented composed source route; Apple catalog `sha256-1EmfZurA_iPo27IUi0BVNFKhEDeNKzhFlV6A4HdZ-cU` reports 23,595 required / 3,902 executable / 3,040 internally verified / 16,653 unresolved and Windows `sha256-bDeRV4H8i9o0mpMzHEoq7yb0_quO5qZsq1rtqAOW7qQ` reports 23,254 / 3,540 / 3,026 / 16,688; the EPYC authenticated closed batch emits 823 passing records including the new receipt, while advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (promotes six source-inventoried private process compatibility cells through exact `shared-runtime-global-absence` receipts on both candidate targets: `process.domain`, `process.__exactAsyncIpcListenerPatch`, `process.__exactLateIpcListenerPatch`, `process.__exactProcessIpcBootstrapInstalled`, `process.__exactStreamPinned`, and `process._umask`; each recipe binds its exact source descriptor and target branch to descriptor-only traversal of the armed shared runtime, which proves the cell is absent without evaluating accessors or entering project code and emits zero legacy or typed decisions; independent authoring, JavaScript validation, and Rust vocabularies repeat the exact six-name set and reject invented source descriptors; Apple catalog `sha256-_MSXwq8gQdFTpbfx9PgdE-YJM6QOZAda5GXC8AR2-1w` reports 23,595 required / 3,901 executable / 3,040 internally verified / 16,654 unresolved and Windows `sha256-PYjbeP4gVXEBqxsRi88aonzXKxFl0Df02dWHPSyBMbc` reports 23,254 / 3,539 / 3,026 / 16,689; the EPYC authenticated closed batch emits 822 passing records including all six new Apple receipts, while advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (promotes the nine target-applicable nested `process.report` rows through exact `process-report-member-closure` receipts: Apple covers `compact`, `directory`, `filename`, `getReport`, `reportOnFatalError`, `reportOnSignal`, `reportOnUncaughtException`, `signal`, and `writeReport`, while Windows correctly excludes the POSIX-only `compact` source branch; every recipe binds its exact source-derived nested row and selected target branch to the final immutable parent `process.report` armed gate, then proves ordinary public read plus callable invocation or data assignment and a post-replacement retry all fail with `ERR_ACCESS_DENIED` / `ProcessReport` before nested state is reachable; the physical result also proves the parent accessor is pinned, has no defining-prototype member, hides process backing state, executes project code, and emits zero legacy or typed decisions; independent authoring, validation, and Rust vocabularies reject invented nested gates or mutable-parent evidence; Apple catalog `sha256-8oHM6nTtzAtjZqWHsmwa_iy1bVASKD-pBty1BMzcQ-c` reports 23,595 required / 3,895 executable / 3,040 internally verified / 16,660 unresolved and Windows `sha256-ZHS7enZp8pQtgJdSWorrUgMKbI1ilPghq0-K4Hl2kYs` reports 23,254 / 3,533 / 3,026 / 16,695; the EPYC authenticated closed batch emits 816 passing records including all nine Apple receipts, while advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (promotes the ten armed process compatibility methods plus `title` and `report` through twelve source-bound `process-shared-state-closure` receipts on both exact candidate targets; each method proves identical direct, defining-prototype, and post-replacement `ERR_ACCESS_DENIED` refusal with its reviewed permission family, while each property proves read/write/replacement refusal and `title` additionally proves direct invocation of its defining prototype getter and setter is closed; authoring exposed and fixed that previously untested `Process.prototype.title` accessor bypass by pinning the own and prototype accessors to the same immutable refusal; every receipt proves hidden credential/title backing state, project-code execution, and zero legacy or typed decisions; the reviewed lockdown digest advances to `sha256-2d639dfcb7460411a28ab4a1f84e1a9712765a1853562950584415a13fc2fa5f` and evaluator identity to `hermes-evaluators.9bf29919e44ebbb3ce3ab599f2eabbe58f1171b5b46aa5d0139ca0475f40d0f6` without changing the four reachable evaluator names or taming kinds; Apple catalog `sha256-CqIzkbSPRjF3YGImjTgYrsCbiN50tnfVCVDQqRnTq6c` reports 23,595 required / 3,886 executable / 3,040 internally verified / 16,669 unresolved and Windows `sha256-ownbT67hUSjxbA6E_oFeFGulBGp5Hs-n_3kyvO5ybm4` reports 23,254 / 3,525 / 3,026 / 16,703; the EPYC authenticated closed batch emits 807 passing records including all twelve new physical receipts, while advertisements remain empty and criterion 7 remains open)
**Revised:** 2026-07-28 (promotes exactly eighteen closed armed-process event methods through a dedicated physical public-surface batch: eleven registration/removal/introspection aliases and seven wholly closed emitter/introspection methods now bind their exact source-derived target branch to the final `hermes_runtime.cc` armed gate, use a method-specific bounded argument shape, and prove identical direct and defining-prototype `ERR_ACCESS_DENIED` / `ProcessEvents` refusals, immutable instance and prototype descriptors, hidden module-private state, project-code execution, and zero legacy or typed decisions; independent JavaScript validation and tamper tests repeat the exact eighteen-name vocabulary and reject invented source gates or mutable prototype receipts; adding the final process gate to the content-addressed lockdown script intentionally advances the reviewed taming digest to `sha256-9f79a77fc45cb8d2d163928f0f834d35ec121a7cdb4dc553463a77961ed0124f` and evaluator review identity to `hermes-evaluators.276ad10bd883c9796f65ea3e2fb18fe373ce9cc32545c5437bf87b73ebacfd60`, with source-derived registry outputs regenerated after review; Apple accounting is 23,592 required / 3,829 fully executable / 3,040 internally verified / 16,723 unresolved and Windows is 23,251 / 3,468 / 3,026 / 16,757; lifecycle `exit` / `beforeExit` branch-selection and no-effect receipts remain residual, and advertisements remain empty)
**Revised:** 2026-07-28 (closes the residual armed shared-process compatibility mutators at the final lockdown boundary: `_getActiveHandles`, `_getActiveRequests`, `_kill`, `abort`, `binding`, `kill`, `setegid`, `seteuid`, `setgid`, and `setuid` are pinned deny-only on both the process instance and defining prototype with their exact process permission family; `title` and `report` are accessor-closed; title and credential backing values move into the existing module-private process `WeakMap`; a real armed-Hermes regression proves direct/prototype/replacement denial, immutable descriptors, usable numeric credential reads, absent public backing cells, and zero typed decisions; the reviewed lockdown digest advances to `sha256-7c1fd40d57c3f85e29440af225521d3f517b4ef3fa81eccbffe78f10ebec7e0c` and evaluator identity to `hermes-evaluators.7caaeab4c8213d44ea2db42d6039b2a20ac470b1857f46c1b76adc201fdd7afb` without changing the four reachable evaluator names or their taming kinds; this enforcement checkpoint does not yet claim exact-target public execution receipts and advertisements remain empty)
**Revised:** 2026-07-28 (integrates the loader-lane observability counters from upstream while making their armed proof unforgeable: mutable source-transform and dynamic-compile counts remain loader-private, the root publishes only a frozen two-getter view under a non-writable/non-configurable descriptor, diagnostic runtimes retain their accumulating compatibility object, and source plus real armed-Hermes regressions prove live numeric counts and failed root/member replacement with zero typed decisions; the source-derived registry classifies the exact root and two members as authority-free WP7 bootstrap state, growing to 7,528 edges / 7,829 branches / 15,056 target cells / 13,383 references and 6,520 reviewed output rows; both target advertisements remain empty)
**Revised:** 2026-07-28 (closes the armed shared-process event registry at its final lockdown boundary: the eleven listener registration/removal/introspection aliases retain only the LLP 0025 `exit` / `beforeExit` diagnosed no-effect branches, while other event names and the seven wholly closed emitter/introspection methods throw stable `ERR_ACCESS_DENIED` before touching shared state or typed authority; the public instance and defining prototype are both pinned against replacement and prototype-call bypass, and the runtime bundle moves its listener map, capture callback, hook flags, lifecycle diagnosis latch, and listener limit into a module-private `WeakMap` rather than TypeScript-private public cells; a real armed-Hermes regression proves both lifecycle branches, ordinary and prototype denials, immutable descriptors, hidden backing state, and zero typed decisions; exact-target recipe authoring remains a separate follow-on before these catalog rows receive executable credit)
**Revised:** 2026-07-28 (integrates the linear dynamic-import scanner from the moving main branch and classifies its two source-inventoried index recognizers, `indexAfterDynamicImport` and `indexAfterLoweredDynamicImport`, as exact WP1 pure-in-memory computation; near-miss names remain fail-closed, the scanner's performance rationale now points to local LLP 0026, and the source-derived registry grows to 7,525 edges / 7,826 branches / 15,050 target cells / 13,380 references; each target gains two unresolved non-capability obligations without executable credit, yielding Apple catalog `sha256-nEKb_9CF470hyx564E5B_kzYSvy6XC-0IAMoDZfD_Uw` at 23,592 required / 3,811 fully executable / 3,040 internally verified / 16,741 unresolved and Windows catalog `sha256-5YC94zWdHp5ceY9cEA1sZrC1PICvc2FaDun_hNPXM4w` at 23,251 / 3,450 / 3,026 / 16,775; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct `_flush(callback)` on exactly eleven Apple zlib owners and nine Windows owners: the harness first feeds the owner-specific fixed encoder input or complete compressed decoder member through the same receiver and awaits that prefill callback, then invokes only the selected `_flush`; every call returns undefined, sets `_flushed`, leaves the writable side non-terminal, and delivers exactly one callback before owner destruction, native-handle closure, quiescence, and zero decisions; the nine established owners require a successful callback, while `ZstdCompress` and `ZstdDecompress` require the exact source-defined `ENOSYS` callback refusal because no native zstd backend is installed, so those rows prove finalization control flow rather than codec support; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/prefill/callback-outcome/final-state/cleanup contract; final Apple accounting is 23,590 required / 3,811 fully executable / 3,040 internally verified / 16,739 unresolved and Windows is 23,249 / 3,450 / 3,026 / 16,773; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct `_transform(Buffer, "buffer", callback)` on exactly eleven Apple zlib owners and nine Windows owners: each fixed encoder or complete decoder input returns undefined, invokes the callback exactly once without error, records the exact accepted byte length, leaves the receiver non-terminal, destroys it, closes any native handle, quiesces, and observes zero decisions; zstd wrappers are confined to the current no-bridge retained-input branch and make no codec claim; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/encoding/callback/accepted-state/cleanup contract; final Apple accounting is 23,590 required / 3,800 fully executable / 3,040 internally verified / 16,750 unresolved and Windows is 23,249 / 3,441 / 3,026 / 16,782; advertisements remain empty)
**Revised:** 2026-07-28 (promotes public `params(1, 0, callback)` on exactly eleven Apple zlib owners and nine Windows owners: every selected call fixes compression level 1 and default strategy 0, returns its fresh receiver, invokes the callback exactly once without error, proves the selected `_level` and `_strategy` while the receiver remains non-terminal, destroys it, closes any native handle, quiesces, and observes zero decisions; Brotli, decoder, and zstd wrappers are included only for their source-defined retained-state control path, while native deflate-family compressors additionally enter the installed parameter bridge; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/arguments/callback/selected-state/cleanup contract; final Apple accounting is 23,590 required / 3,789 fully executable / 3,040 internally verified / 16,761 unresolved and Windows is 23,249 / 3,432 / 3,026 / 16,791; advertisements remain empty)
**Revised:** 2026-07-28 (promotes public `flush(callback)` on exactly eleven Apple zlib owners and nine Windows owners: every selected call uses the first-argument callback form and therefore the source-defined default full-flush branch, returns its fresh receiver, invokes the callback exactly once without error, proves the receiver is still non-terminal before cleanup, destroys it, closes any native handle, quiesces, and observes zero decisions; the owner vocabulary includes the two zstd wrappers because this exact control write is a safe source-defined no-op when the zstd bridge is absent, without claiming zstd codec execution; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/callback/return/non-terminal/cleanup contract; final Apple accounting is 23,590 required / 3,778 fully executable / 3,040 internally verified / 16,772 unresolved and Windows is 23,249 / 3,423 / 3,026 / 16,800; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct incremental `write(Buffer, callback)` on exactly nine Apple zlib owners and seven Windows owners: every selected call must return a boolean, invoke its dedicated callback exactly once without error, retain the fixed input until a separate harness-owned empty terminal `end`, emit a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, emit exactly one `finish`, reach flushed and ended writable state, destroy the receiver, close the native handle, quiesce, and observe zero decisions; this terminal-write contract accommodates the Apple Brotli wrappers, which buffer writes until finalization, without conflating the selected `write` return/callback with the auxiliary `end`; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/callback/terminal/output/cleanup contract; the merged diagnostic loader's two late-resolver selector functions are also classified as exact WP3 control-plane surfaces, adding six fixture obligations (four internally verified, two unresolved) without executable credit; final Apple accounting is 23,590 required / 3,767 fully executable / 3,040 internally verified / 16,783 unresolved and Windows is 23,249 / 3,414 / 3,026 / 16,809; both zstd owners remain residual and advertisements remain empty)
**Revised:** 2026-07-28 (strengthens 19 already executable `node:timers` calls from generic captured-output receipts to direct, source-bound lifecycle contracts: `active`, `clearInterval`, `clearTimeout`, `enroll`, `Immediate.close`, `Immediate.hasRef`, `Immediate.ref`, `Immediate.unref`, `setImmediate`, `setInterval`, `setTimeout`, `Timeout.close`, `Timeout.hasRef`, `Timeout.ref`, `Timeout.refresh`, `Timeout._scheduleNative`, `Timeout.unref`, `unenroll`, and `_unrefActive`; each contract fixes the exact root or inherited-prototype descriptor, owned setup, arguments, result, inert callback behavior, complete cancellation/cleanup, quiescence, and zero decisions, with a fixed 60-second delay ensuring cancellation rather than timer delivery; `clearImmediate` remains on its existing closed/generic route and the two constructors remain generic captured-output rows; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact contract; the generic captured-output set falls from 141 to 122 and the descriptor residual manifest from 485 to 466, while Apple accounting remains 3,758 fully executable / 3,036 internally verified / 16,790 unresolved and Windows remains 3,407 / 3,022 / 16,814; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct synchronous `_processChunk(Buffer, Z_FINISH)` on exactly nine Apple zlib owners and seven Windows owners: every call must return a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, close the constructor-created idle native selector, quiesce, and observe zero decisions; Apple additionally covers `BrotliCompress` and `BrotliDecompress`, while Windows leaves them target-unavailable and both targets leave zstd residual because no native zstd bridge exists; the receipt is explicitly one-shot and does not cover incremental write, transform, parameter, flush, or finalization state; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/flush-flag/output/cleanup contract; Apple accounting is 3,758 fully executable / 3,036 internally verified / 16,790 unresolved and Windows is 3,407 / 3,022 / 16,814; advertisements remain empty)
**Revised:** 2026-07-28 (promotes terminal `end(Buffer)` on exactly nine Apple zlib owners and seven Windows owners: every call must return the receiver, deliver a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, emit exactly one `finish`, reach terminal writable state, leave no native codec ownership live, quiesce, and observe zero decisions; Apple additionally covers `BrotliCompress` and `BrotliDecompress`, while Windows leaves them target-unavailable and both targets leave zstd residual because no native zstd bridge exists; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/output/lifecycle contract; Apple accounting is 3,749 fully executable / 3,036 internally verified / 16,799 unresolved and Windows is 3,400 / 3,022 / 16,821; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly four Apple-only one-shot Brotli routes: `brotliCompressSync`, `brotliDecompressSync`, `brotliCompress`, and `brotliDecompress`; the synchronous calls require a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, while the callbacks return `undefined`, deliver exactly once without error, satisfy the same output proof, and reach quiescence; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact four-name vocabulary, source descriptor, fixed input/compressed bytes, dispatch, and output contract; Apple accounting is 3,740 fully executable / 3,036 internally verified / 16,808 unresolved while Windows remains 3,393 / 3,022 / 16,828 because it does not install the native Brotli bridge; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly seven one-shot `node:zlib` callback wrappers: `deflate`, `deflateRaw`, `gzip`, `gunzip`, `inflate`, `inflateRaw`, and `unzip`; the loaded harness passes a dedicated callback credential, awaits exactly one deferred delivery, rejects errors, and verifies a nonempty encoded byte view or the exact decoded bytes `[105, 98, 101, 120]` before quiescence; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact seven-name vocabulary, source descriptor, compressed/input bytes, callback contract, undefined source return, and delivery proof; Apple accounting is 3,736 fully executable / 3,036 internally verified / 16,812 unresolved and Windows is 3,393 / 3,022 / 16,828; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly four isolated `node:zlib` synchronous decoders: `gunzipSync`, `inflateRawSync`, `inflateSync`, and `unzipSync`; each public root call receives one fixed deflate, raw-deflate, or gzip Buffer and must return the exact decoded bytes `[105, 98, 101, 120]`, with no retained stream and zero decisions; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact four-name vocabulary, source descriptor, compressed input, dispatch, and decoded-byte proof; Apple accounting is 3,729 fully executable / 3,036 internally verified / 16,819 unresolved and Windows is 3,386 / 3,022 / 16,835; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly three isolated `node:zlib` synchronous encoders: `deflateRawSync`, `deflateSync`, and `gzipSync`; each public root call receives the fixed Buffer bytes `[105, 98, 101, 120]`, returns a nonempty byte view, retains no codec stream, reaches quiescence, and observes zero decisions; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact three-name vocabulary, source descriptor, input, dispatch, result, and byte-view proof; Apple accounting is 3,725 fully executable / 3,036 internally verified / 16,823 unresolved and Windows is 3,382 / 3,022 / 16,839, while the descriptor residual manifest falls from 521 to 518; decoders, callback codecs, and stream-processing calls remain residual)
**Revised:** 2026-07-28 (promotes exactly two additional fresh `node:dgram` operations: the owner-checked `Socket._closed` boolean read and `Socket.dropMembership("224.0.0.1")` on an unbound udp4 receiver; construction creates only source-owned state and a principal stamp, `_closed` reads the own non-configurable accessor, and `dropMembership` returns before the native hook because the handle remains `-1`; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact constructed-instance/call descriptors, udp4 setup, literal group address, result types, quiescence, and zero-decision contract; Apple accounting is 3,722 fully executable / 3,036 internally verified / 16,826 unresolved and Windows is 3,379 / 3,022 / 16,842, while the descriptor residual manifest falls from 522 to 521)
**Revised:** 2026-07-28 (promotes exactly five terminal calls on fresh `node:net` receivers: `Server.close`, `Socket.close`, `Socket.resetAndDestroy`, `Stream.close`, and `Stream.resetAndDestroy`; the dedicated setup constructs each receiver without a transport, attaches one harness close observer before dispatch, and requires exact close delivery plus terminal in-memory state before completion; authoring, independent evidence validation, Rust validation, and the loaded-engine harness repeat the closed five-name vocabulary, exact source descriptor, owner setup, dispatch, cleanup fields, quiescence, and zero-decision contract; Apple accounting is 3,720 fully executable / 3,036 internally verified / 16,828 unresolved and Windows is 3,377 / 3,022 / 16,844, while the descriptor residual manifest falls from 527 to 522)
**Revised:** 2026-07-28 (promotes exactly three fresh `node:https` server constructors: `Server`, `Server.constructor`, and `createServer`; each source call layers one private-state HTTP wrapper over one idle TLS server without binding a transport or creating an HTTP selector, while the inner TLS server still mints one runtime/principal owner token; the dedicated loaded-engine setup closes the outer server, awaits outer close delivery and delayed inner token retirement, and requires a later outer `address()` call to reach the guarded inner server and fail with `ERR_TLS_SERVER_CLOSED`; authoring, independent evidence validation, Rust validation, and physical Hermes execution repeat the exact `node:https` descriptor, `member-assignment` provenance, dispatch, cleanup, and quiescence contract; Apple accounting is 3,715 fully executable / 3,036 internally verified / 16,833 unresolved and Windows is 3,372 / 3,022 / 16,849, while the descriptor residual manifest falls from 530 to 527)
**Revised:** 2026-07-28 (promotes exactly three fresh `node:tls` server constructors: `Server`, `Server.constructor`, and `createServer`; each source call creates no transport or native listener but does mint one private runtime/principal owner token and install the two registry lifecycle listeners, so the dedicated loaded-engine setup attaches one harness close observer, invokes exact `close`, awaits the internal close hook and delayed retirement timer, and requires a subsequent guarded lifecycle call to fail with `ERR_TLS_SERVER_CLOSED`; authoring, independent evidence validation, Rust validation, and physical Hermes execution repeat the exact descriptor/dispatch/cleanup contract; Apple accounting is 3,712 fully executable / 3,036 internally verified / 16,836 unresolved and Windows is 3,369 / 3,022 / 16,852, while the descriptor residual manifest falls from 533 to 530)
**Revised:** 2026-07-28 (promotes exactly the `node:tls` `SecureContext.context` read on a fresh harness-owned `SecureContext`: source construction installs one own enumerable, non-writable, non-configurable, frozen opaque object without allocating a TLS engine or consulting native trust state; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the exact constructed-instance descriptor, empty constructor, object result, quiescence, and zero-decision contract; Apple accounting is 3,709 fully executable / 3,036 internally verified / 16,839 unresolved and Windows is 3,366 / 3,022 / 16,855)
**Revised:** 2026-07-28 (promotes exactly five transport-free `node:tls` socket calls: `TLSSocket`, `TLSSocket.close`, `TLSSocket.destroy`, `TLSSocket.ref`, and `TLSSocket.unref`; the harness constructs every receiver without an underlying transport, so no native TLS owner token, engine, selector, listener, or timer exists before the selected call, while close/destroy must drain their terminal timer before quiescence; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the exact closed vocabulary and zero-decision contract; Apple accounting is 3,708 fully executable / 3,036 internally verified / 16,840 unresolved and Windows is 3,365 / 3,022 / 16,856)
**Revised:** 2026-07-28 (strengthens the four already executable `node:http` header validators from generic captured-output evidence to dedicated `ibex/capsec-builtin-call-invocation/1` contracts: `_checkInvalidHeaderChar("ibex")`, `_checkIsHttpToken("x-ibex")`, `validateHeaderName("x-ibex")`, and `validateHeaderValue("x-ibex", "ibex")`; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the literal arguments, direct root-call dispatch, result type, quiescence, and zero-decision proof; because all four rows were already executable, Apple accounting remains 3,703 fully executable / 3,036 internally verified / 16,845 unresolved and Windows remains 3,360 / 3,022 / 16,861, while the generic captured-output set falls from 145 to 141 and the descriptor residual manifest from 542 to 538)
**Revised:** 2026-07-28 (promotes exactly `node_readline.Interface.pause` through a separate harness-owned non-terminal `Interface` lifecycle receipt: the selected call must return the receiver object while leaving it open but paused, preserve the constructor's exact data/error/end/close listener set, record one resume and one pause, and emit no close event; the harness then invokes exact `Interface.close` as auxiliary cleanup and proves all listeners detached, two total pauses, one close event, quiescence, and zero decisions; the three constructor-instance `_on*` closures remain residual; Apple accounting is 3,703 fully executable / 3,036 internally verified / 16,845 unresolved and Windows accounting is 3,360 / 3,022 / 16,861)
**Revised:** 2026-07-28 (promotes exactly `node_readline.Interface.close` on a fresh harness-owned non-terminal `Interface` whose inert input shim proves the constructor installed the exact data/error/end/close listener set and resumed once, then proves the selected close call detached every listener, paused once, marked the receiver closed, emitted one close event, returned `undefined`, reached quiescence, and emitted zero decisions; `Interface.pause` remains residual because it returns while retaining those constructor listeners; Apple accounting is 3,702 fully executable / 3,036 internally verified / 16,846 unresolved and Windows accounting is 3,359 / 3,022 / 16,862)
**Revised:** 2026-07-27 (promotes exactly `exact_crypto.KeyObject.equals` for two separately constructed harness-owned secret `KeyObject` instances containing the same fixed four-byte `ibex` value; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness repeat a dedicated pair-owner setup, exact prototype descriptor, peer binding, boolean result, quiescence, and zero-decision contract without adding a generic nested-constructor facility; Apple accounting is 3,701 fully executable / 3,036 internally verified / 16,847 unresolved and Windows accounting is 3,358 / 3,022 / 16,863)
**Revised:** 2026-07-27 (promotes exactly three source-only compatibility calls: `exact_crypto.createPrivateKey("ibex-key")`, `exact_crypto.createPublicKey("ibex-key")`, and `node_readline.CSI(["31m"])`; the first two construct only in-memory compatibility wrappers without parsing, importing, or consulting a native key store, while CSI concatenates a harness-owned string array without opening a terminal or retaining a stream; authoring, independent evidence validation, Rust validation, and the loaded-engine JavaScript harness repeat the complete source descriptor, literal argument, root-call setup, result type, quiescence, and zero-decision contract; the cross-source `dns/promises.getDefaultResultOrder` projection remains residual; Apple accounting is 3,700 fully executable / 3,036 internally verified / 16,848 unresolved and Windows accounting is 3,357 / 3,022 / 16,864)
**Revised:** 2026-07-27 (promotes exactly two bounded X509 instance operations: an own `raw` accessor read and `toString()` on a fresh harness-owned `X509Certificate("ibex-x509-fixture")`; the locked primordial `Object.prototype.toString` previously swallowed ordinary prototype assignment, so `crypto.js` now installs the intended own override with an explicit descriptor while preserving lockdown; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness separately repeat the exact constructor, access/call, result type, quiescence, and zero-decision contract; Apple accounting is 3,697 fully executable / 3,036 internally verified / 16,851 unresolved and Windows accounting is 3,354 / 3,022 / 16,867)
**Revised:** 2026-07-27 (promotes exactly six fresh `node:dgram` udp4 construction/lifecycle calls: `Socket`, `Socket.close`, `Socket.constructor`, `Socket.ref`, `Socket.unref`, and `createSocket`; construction creates the principal stamp but no native handle, binding, poll timer, or peer route, while close must drain its terminal event before quiescence; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness each repeat the real `src/builtins/dgram.js` descriptor, canonical `node:dgram` invocation, exact udp4 setup, result, and normal-return proof; bind, connect, send, address, membership, and buffer operations remain residual; Apple accounting is 3,695 fully executable / 3,036 internally verified / 16,853 unresolved and Windows accounting is 3,352 / 3,022 / 16,869)
**Revised:** 2026-07-27 (promotes exactly nine fresh `node:http` construction/lifecycle calls: `Agent.destroy`, `Server`, `Server.close`, `Server.closeAllConnections`, `Server.closeIdleConnections`, `Server.constructor`, `Server.ref`, `Server.unref`, and `createServer`; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness each repeat the complete source descriptor, empty arguments, exact fresh receiver setup, result type, and normal-return proof; no receiver has a listener, socket, or native selector, and `Server.close` must drain its terminal event before quiescence; listening, client-request, and transport-retaining routes remain residual; Apple accounting is 3,689 fully executable / 3,036 internally verified / 16,859 unresolved and Windows accounting is 3,346 / 3,022 / 16,875)
**Revised:** 2026-07-27 (promotes exactly seven inert `closed` boolean reads on fresh harness-owned `default`, `Duplex`, `PassThrough`, `Readable`, `Stream`, `Transform`, and `Writable` instances; the inventory's inherited/prototype rows do not describe a value on those prototypes, so authoring, independent validation, and Rust execution require the separate `constructed-instance-property` access kind, exact owner setup, own getter, boolean result, quiescence, and zero decisions; mutable `readableState` and `writableState` graphs remain residual; Apple accounting is 3,680 fully executable / 3,036 internally verified / 16,868 unresolved and Windows accounting is 3,337 / 3,022 / 16,884)
**Revised:** 2026-07-27 (promotes idle `destroy` on exactly 11 Apple zlib owners and the nine installed Windows owners: construction establishes the principal-bound native selector, the public source path authenticates before delegating, `_destroy` closes the selector, and the harness performs idempotent cleanup before proving quiescence; authoring, independent validation, and Rust execution repeat the exact owner/method/result contract; Windows Brotli owners remain residual because their native codec prerequisite is not installed; Apple accounting is 3,673 fully executable / 3,036 internally verified / 16,875 unresolved and Windows accounting is 3,330 / 3,022 / 16,891)
**Revised:** 2026-07-27 (promotes exactly six lifecycle calls on the base `node:stream` module-value constructor: `_close`, `_emitClose`, `_undestroy`, `constructor`, `destroy`, and `unpipe`; authoring, validation, and physical execution independently require `["prototype", method]` rather than the nonexistent `["default", "prototype", method]`, and only this closed name set receives the module-value correction; `default.pipe` remains residual because it retains listener and pipeline ownership; Apple accounting is 3,662 fully executable / 3,036 internally verified / 16,886 unresolved and Windows accounting is 3,321 / 3,022 / 16,900)
**Revised:** 2026-07-27 (promotes exactly eight explicit-parameter `exact_crypto` Diffie-Hellman calls: `DiffieHellman`, `createDiffieHellman`, and `getGenerator`, `getPrime`, `getPrivateKey`, `getPublicKey`, `setPrivateKey`, and `setPublicKey` on a harness-owned instance constructed from fixed prime 23 and generator 5; the author, independent validator, and Rust executor separately repeat the exact setup, arguments, result types, and ordinary-return proof, while `generateKeys` and `computeSecret` remain residual because they enter random or modular work; Apple accounting is 3,656 fully executable / 3,036 internally verified / 16,892 unresolved and Windows accounting is 3,315 / 3,022 / 16,906)
**Revised:** 2026-07-27 (promotes exactly 24 Promise-returning readable-stream consumers: `every`, `find`, `forEach`, `reduce`, `some`, and `toArray` on `Duplex`, `PassThrough`, `Readable`, and `Transform`; every recipe constructs an already-ended empty stream, awaits the exact returned Promise inside the observation, then requires event-loop quiescence and zero decisions, while the independent validator and Rust executor repeat the closed owner/method/argument/result contract; `wrap`, `compose`, and `pipeline` remain residual because their delegated ownership is not closed by this receipt; Apple accounting is 3,648 fully executable / 3,036 internally verified / 16,900 unresolved and Windows accounting is 3,307 / 3,022 / 16,914)
**Revised:** 2026-07-27 (promotes exactly 15 post-initialization scalar reads from `cluster`, `http`, and `os`: each capability-bearing module is loaded and quiesced before the export observer opens, so initialization receives no credit, while an independently duplicated descriptor/type allowlist requires the later authenticated cached read to return its exact boolean, number, object, string, or symbol type with zero decisions; generic exports from these three modules remain excluded; Apple accounting is 3,570 fully executable / 3,036 internally verified / 16,977 unresolved and Windows accounting is 3,229 / 3,022 / 16,991)
**Revised:** 2026-07-27 (promotes exactly 24 locally authored `dns/promises` error-code data reads through an independently duplicated name and descriptor allowlist: inventory may retain the conservative `unknown` static shape only when the source is the exact `node_dns_promises` member assignment and the recipe requires a runtime string; both physical engines returned strings with zero decisions for all 24 while generic unknown-shape reads, 42 DNS promises callables, and three Resolver `_handle` callables remain residual; Apple accounting is 3,555 fully executable / 3,036 internally verified / 16,992 unresolved and Windows accounting is 3,214 / 3,022 / 17,006)
**Revised:** 2026-07-27 (thirteen exact public loader routes now require a fresh armed runtime, real public `require` traversal, one matching receipt from a loader-private source point, quiescence, engine re-attestation, and zero legacy or typed decisions; a 100-route Apple audit rejected 87 static candidates that bypassed, cached, or entered typed authority, while all retained routes pass physically on Apple and Windows at source `362e21c7` / tree `sha256-7Rdvzwm5tGaDVNqW1U9sUiyp1VabIIhRuCT_iN-uOPI`; Apple catalog `sha256-YwyEGiU906sxfdDbSQreOmeQUuFcp_FzeFgFj-x5qbQ` reports 23,844 required / 3,531 fully executable / 3,134 internally verified / 17,179 unresolved and Windows catalog `sha256-Emt8544W78pVLMizBGhKaQt2tIJuqWE6Se383StPlu8` reports 23,503 / 3,190 / 3,120 / 17,193; the source inventory also excludes preprocessor predicates and Mach-O section metadata from pseudo-function/native-operation discovery; both advertisement sets remain empty)
**Revised:** 2026-07-26 (the artifact-independent armed import boundary now closes the process-wide `node:diagnostics_channel` and legacy `node:domain` registries alongside the previously terminal runtime-inspection and execution builtins, even under an authenticated overbroad snapshot; 31 additional source and alias facets per exact target execute as direct closed-import evidence, bringing the terminal-builtin tranche to 137 without converting imports that still contain supported export operations into module-wide denials)
**Revised:** 2026-07-26 (the residual installed Windows filesystem plane now refuses armed execution before path conversion, descriptor lookup, caller-buffer acquisition, worker dispatch, or legacy capability probing: whole-file write, mkdir, realpath, readlink, access, truncate, statfs, path/descriptor async whole-file write, every generic async path/stat operation, and the JavaScript synchronous writev fallback all return structured EPERM; the already typed retained-object routes remain unchanged)
**Revised:** 2026-07-26 (armed POSIX and Windows `__exactFsWriteAsync` / `__exactFsWritevAsync` now retain bounded caller input and submit one exact-object `fs:write` Repeat on the filesystem worker immediately before their sole scalar or aggregate mutation; Windows restricts the typed worker route to an existing append-only retained file, and both Windows descriptor durability surfaces plus their POSIX counterparts use distinct public-edge Repeats immediately before flushing, promoting eight async-write recipes on both targets and eight additional durability recipes on Windows)
**Revised:** 2026-07-26 (armed Windows TCP now authorizes requested host/port before DNS, every member of the complete canonical candidate set before connect, and the verified `getpeername` peer at Commit; retained socket identity and connection id bind generation-aware Repeat to each read/write while the registry lock prevents close/reuse races, and five connect plus three lifecycle recipes become executable)
**Revised:** 2026-07-26 (armed POSIX and Windows `__exactFsReadAsync` / `__exactFsReadvAsync` now carry the runtime/owner/principal/retained-object operation lease to the filesystem worker and submit one exact-object `fs:read` Repeat immediately before their sole scalar or aggregate acquisition; vector destinations are bounded without caller-sized preauthorization allocation and receive bytes only from the successful owned result, positioned reads preserve the cursor, and eight recipes become executable on each exact target while worker-backed writes and durability remain residual)
**Revised:** 2026-07-26 (armed Windows `__exactFsReadFileAsync` now captures one schedule-time runtime/principal operation lease and performs both path and retained-descriptor reads on the filesystem worker through typed VFS ABIs: path reads authorize requested/discovery `fs:list` plus commit/per-chunk `fs:read`, descriptor reads serialize the retained cursor and reauthorize every 64 KiB chunk plus EOF, denial precedes lookup or disclosure, eleven Windows recipes are newly executable, and worker-backed scalar/vector reads plus other installed Windows effects remain residual)
**Revised:** 2026-07-25 (armed Windows exact-string `"a"` open now admits only an existing regular file through an append-only retained handle: `fs:write` Requested precedes lookup, `fs:list` Requested/Discovery authenticates the existing object, `fs:write` Commit binds its identity/generation, and scalar `__exactFsWrite` performs one exact-object Repeat immediately before a short-write append; absence never creates, denial never mutates, package-source hard-link aliases refuse at Commit, ten Windows recipes are newly executable, and all other writable/async/durability modes remain residual)
**Revised:** 2026-07-25 (armed Windows synchronous `__exactFsReadv` now validates the runtime/owner-bound retained descriptor before inspecting a bounded vector, authorizes one exact-object `fs:read` Repeat, acquires bytes through the same retained file with positional-cursor restoration, and scatters only after success; four public scenarios are executable on each exact target while worker-backed vector reads remain residual)
**Revised:** 2026-07-25 (armed Windows read-only `__exactFsOpen` now returns the exact retained VFS file behind a runtime/owner-bound opaque registry entry, preserves the optional bearer for later operations, and `__exactFsFstatSync` authorizes Repeat against that same object and handle identity before metadata disclosure; write-capable opens fail closed before resolution, ten exact-target recipes are executable, and descriptor reads/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactReaddir` retains the exact directory object, enumerates it through that handle, authorizes requested/discovery `fs:list` plus repeat before each disclosed member, and never falls back to pathname enumeration; physical replacement-race and public denial tests pass, five exact-target recipes are executable, and descriptors/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactLstat` retains the final reparse object without following it, authorizes requested/discovery/repeat `fs:list` with `no-follow-final`, and never falls back to pathname lstat; physical replacement-race and public denial tests pass, five exact-target recipes are executable, and enumeration/descriptors/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactStat` is the second installed filesystem effect moved to the retained-object VFS: file and authenticated mount-root metadata authorize requested/discovery/repeat `fs:list`, serialize only after repeat, and never fall back to pathname stat; five exact-target recipes are now executable while enumeration, descriptors, mutations, and async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactReadFile` is the first installed filesystem effect moved from the legacy pathname oracle to the runtime VFS retained-object state machine: frame-derived constrained principals authorize requested/discovery `fs:list` and commit/repeat `fs:read`, denial never falls back, and five exact-target recipes are now executable; async reads and all other installed Windows filesystem effects remain residual)
**Revised:** 2026-07-25 (Windows retained relative opens stage long and short directory-entry names plus 128-bit file identity, refuse selection through any 8.3 name, withhold delete sharing, and repeat/object-match the entry; physical custom-short-name and entry-replacement fixtures close the arbitrary 8.3 alias gap, leaving the typed installed filesystem backend and incomplete exact-target evidence as the Windows promotion blockers)
**Revised:** 2026-07-25 (Windows binds ASCII case-folding into selector and occurrence identity, uses the same key for resolver manifests/absences/denied subtrees, refuses non-ASCII and tilde components, and refuses case-sensitive traversal directories while preserving lexical SourceId and distinct hard links; arbitrary administrator-assigned 8.3 aliases, the installed native filesystem effect backend, and incomplete exact-target evidence keep Windows unadvertised)
**Revised:** 2026-07-25 (Windows VFS and armed Oxc resolution now decode contained Microsoft symlink/junction reparses from retained no-follow handles, object-match and double-read mutable payloads, authorize complete target-plus-tail paths before lookup, and restart from the retained root; unsupported providers, the Windows alias-canonicalization gap, the installed native filesystem effect backend, and incomplete exact-target evidence keep the target unadvertised)
**Revised:** 2026-07-25 (mixed filesystem dispatchers now carry exact branch-local closure: unbound path/descriptor mutations and recursive mkdir select deny-only `fs:unbound-mutation` branches before lookup, while retained-object branches remain effectful; target predicates preserve Apple worker-backed `chmod`/`utime`, close them on Windows, and source inventory binds the POSIX filesystem translation unit only to targets that compile it; Apple accounting is 2,760 fully executable / 3,114 internally verified / 17,849 unresolved and Windows accounting is 2,341 / 3,102 / 18,099)
**Revised:** 2026-07-25 (`node:fs.opendirSync` adds five empty-directory Apple public recipes with exact `__exactReaddir` evidence, path-bound `Dir` results, and mandatory close proof; Apple accounting is now 2,666 fully executable / 3,114 internally verified / 18,260 unresolved)
**Revised:** 2026-07-25 (`node:fs.openSync` adds fifteen flag-selected Apple public recipes across exact read, write, and read-write authority branches; every successful descriptor is closed and the three synthetic branch-selection rows remain residual; Apple accounting is now 2,661 fully executable / 3,114 internally verified / 18,265 unresolved)
**Revised:** 2026-07-25 (`node:fs.readlinkSync` corrects stored-link-byte authorization from ambient `fs:list` to `fs:read` commit/repeat, adds exact translated-string and denial evidence, and promotes five Apple rows; Apple accounting is now 2,646 fully executable / 3,114 internally verified / 18,280 unresolved)
**Revised:** 2026-07-25 (`node:fs.mkdirSync` adds five Apple public recipes that physically select absolute, non-recursive creation, bind the exact absent-create decision chain, and prove creation/no-creation postconditions; Apple accounting is now 2,641 fully executable / 3,114 internally verified / 18,285 unresolved)
**Revised:** 2026-07-25 (`node:fs.appendFileSync` adds five Apple public recipes with exact open/write decisions, prefix-plus-suffix mutation proof, and deny-no-mutation proof; Apple accounting is now 2,636 fully executable / 3,114 internally verified / 18,290 unresolved)
**Revised:** 2026-07-25 (`node:fs.truncateSync` adds five Apple public recipes with retained-object `fs:write` commit/repeat evidence and exact mutation/non-mutation postconditions; Apple accounting is now 2,631 fully executable / 3,114 internally verified / 18,295 unresolved)
**Revised:** 2026-07-25 (`node:fs.existsSync` adds five value-bound Apple public recipes, proving that permission denial is retained as a typed denied decision even though the API returns `false`; Apple accounting is now 2,626 fully executable / 3,114 internally verified / 18,300 unresolved)
**Revised:** 2026-07-25 (`node:fs.statfsSync` adds five bound-engine Apple public recipes through its exact six-decision `fs:list` sequence; Apple accounting is now 2,621 fully executable / 3,114 internally verified / 18,305 unresolved)
**Revised:** 2026-07-25 (retires the generated `malformed-branch-facts` execution scenario because logical-branch predicates are authenticated registry metadata rather than runtime input, preserving registry-shape validation plus real branch-selection/no-effect evidence; confirms the empty production bootstrap floor as the exact least-authority declaration while retaining the generic one-shot seal and nonempty-floor mechanism)
**Revised:** 2026-07-25 (reconciles module-runner conformance with invocation-time activation: the 19 production-reachable ABI lifecycle surfaces execute while authenticated `require` resolution and source reads remain attributed to two reviewed auxiliary effect edges; six eager dynamic/require-link ABIs and teardown-only generation unpin remain residual; separates the public callback Cargo filter from its containing module so it cannot also select the bound internal-evidence producer; refreshes the source-derived Apple and Windows fixture totals)
**Revised:** 2026-07-25 (deletes the legacy `PolicyFile` parser, public module, `HostConfig` policy/path/allow/deny seams, policy-string mode parser, and runtime readiness dependency; foreground audit remains an explicitly policyless diagnostic host and historical compatibility-manager algebra is covered only through private test setup)
**Revised:** 2026-07-25 (removes `insecure` from Cargo defaults: plain builds enforce the supported profile and refuse before project code while no exact target is advertised; unadvertised secure development and no-sandbox execution require explicit compile-time features; invocation-time ESM import and CommonJS require now cover source and prepared targets)
**Revised:** 2026-07-24 (production native-graph dependency source reads authorize the exact typed edge and retain a digest-bound receipt; dependency carriers derive a carrier receipt from that continuation, while entry-only carriers require an opaque graph/request join minted before any cache discovery; armed transpilation has no persistent cache-read path; every promotion-facing conformance Cargo executor now disables defaults and selects the production observer feature set explicitly)
**Revised:** 2026-07-25 (adds the product-neutral native runtime-extension
authority capsule projection, fixed exact extension resource semantics,
launcher-observed linked-artifact identity binding, construction-time
authority-digest and exact native-registry projection claims, and context-local
operation leases)
**Revised:** 2026-07-20 (extends authenticated fresh-engine, zero-decision source receipts to 30 additional reviewed public builtin spellings, binds their exact root value types, and leaves both `stream/consumers` spellings residual because compatibility loading shadows their manifest source)
**Revised:** 2026-07-19 (binds the exact `dns/promises` carrier/provider callable shape to independent inventory and classifier review pins while leaving all 45 derived routes residual; strengthens four DNS no-effect alias receipts with exact cache-miss, VFS source, body-completion, alias, and runtime-nonce evidence)
**Revised:** 2026-07-18 (ENG-25076 adds the target-local Exact GPU binding/profile producer and independently executed preparation evidence while preserving empty advertisements)
**Revised:** 2026-07-17 (ENG-24578 moves the lockdown startup postcondition to authenticated direct-file native-graph execution while retaining a separate zero-decision startup window, because persistent-session lowering intentionally closes evaluator syntax)
**Revised:** 2026-07-17 (ENG-24578 moves the four lockdown-tamed evaluator probes from the deliberately syntax-closed persistent-session route to authenticated direct-file native-graph admission, preserving exact loaded-engine evidence without reopening REPL dynamic code)
**Revised:** 2026-07-18 (CLI protected-artifact publication now uses the
target durability boundary, and external JavaScript tools receive ordinary
Windows path spellings only after authenticated canonical selection)
**Revised:** 2026-07-18 (Windows module resolution restores canonical object
identity after the Oxc compatibility projection, and byte-authenticated Rust
fixtures use checkout-stable LF authorities)
**Revised:** 2026-07-18 (the Windows full-matrix Rust product gate preserves
the fail-on-zero wrapper while binding Cargo to the configured MSVC linker and
vendored OpenSSL to native Perl before Git Bash can shadow those tools)
**Revised:** 2026-07-18 (Windows replacement translation units preserve
cross-target integration-test C ABI shape so the full Rust gate can link before
the test reports target/profile inapplicability)
**Revised:** 2026-07-18 (target-local protected-artifact publication fsyncs
the parent directory on Unix and flushes the pinned linked file on Windows,
where opening a directory through `std::fs::File` is refused)
**Revised:** 2026-07-18 (Windows builtin recipes keep callable Brotli exports
residual because the target installs deflate/inflate but not the native Brotli
codec globals those exports require)
**Revised:** 2026-07-18 (Windows source-bound builtin recipes keep the default
`src/builtins/crypto.js` implementation residual because the target installs a
reduced bootstrap-local `node:crypto` replacement)
**Revised:** 2026-07-18 (Windows package-source authentication inventories
the integrity tree twice and opens every object relative to the pinned package
root handle while refusing reparse traversal)
**Revised:** 2026-07-18 (Windows recipe generation keeps all 134 filesystem
public probes residual while the backend still lacks the non-Unix typed
retained-object adapter)
**Revised:** 2026-07-18 (Windows evaluator review canonicalizes CRLF to LF
for checked-in PowerShell authorities while release manifests continue to
attest the platform-native builder bytes exactly)
**Revised:** 2026-07-18 (the origin/main integration restamps the reviewed
Hermes evaluator identity after adding static-library packaging to the source
build authority; evaluator reachability and lockdown taming are unchanged)
**Revised:** 2026-07-18 (ENG-24933 binds direct path truncation to retained-object typed authorization and physically proves five Apple scenarios)
**Revised:** 2026-07-18 (ENG-24933 removes the stale descriptor durability-read branch under LLP 0023's write-authorized durability contract, physically executes the asynchronous durability-write branch on Apple, and keeps the aggregate metadata-write branch residual pending an exact open/closed split)
**Revised:** 2026-07-18 (ENG-24933 physically executes open-family retained descriptor truncation on an exact Apple-owned file while keeping closed metadata mutation, absent Windows surfaces, and prerequisite-conflicting denial residual)
**Revised:** 2026-07-18 (ENG-24933 physically executes retained descriptor durability on Apple through typed fsync/fdatasync repeat gates and owned-file cleanup, while prerequisite-conflicting denial remains residual)
**Revised:** 2026-07-18 (ENG-24933 physically executes retained descriptor metadata on Apple, closes the setup descriptor outside observation, and leaves prerequisite-conflicting denial and the legacy Windows path residual)
**Revised:** 2026-07-18 (ENG-24933 keeps POSIX evidence directories mode-private while treating Windows' synthetic POSIX mode bits as non-authoritative)
**Revised:** 2026-07-18 (ENG-24933 executes all three asynchronous descriptor-open branches through event-loop quiescence on Apple, closes returned descriptors, and keeps the uninstalled Windows surface residual)
**Revised:** 2026-07-18 (ENG-24933 executes all three direct descriptor-open access branches against exact pre-seeded files, closes returned descriptors, proves non-mutation, and removes the fixtures)
**Revised:** 2026-07-18 (ENG-24933 binds direct append to an exact pre-seeded file, proves preserved prefix bytes and denial non-mutation, and removes the owned fixture)
**Revised:** 2026-07-18 (ENG-24933 executes direct directory enumeration against one harness-owned entry with retained repeat evidence and unconditional cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct whole-file creation to source-derived bytes, an exact harness-owned floor, and verified content cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct non-recursive directory creation to an exact harness-owned floor and proves post-operation cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct terminal-builtin import-gate closure when the static route has no downstream alternative, after the complete Apple run exposed the validator mismatch)
**Revised:** 2026-07-17 (ENG-24933 closes the armed Exact/Bun accessibility application-state namespace after trusted bootstrap and binds its source-derived cells to physical absence)
**Revised:** 2026-07-17 (ENG-24933 restamps the reviewed Hermes evaluator identity after the Release artifact builder changed, preserving fail-closed source-authority drift detection)
**Revised:** 2026-07-17 (ENG-24578 binds native-public async completion to event-loop quiescence, reconciles retained-path live traces with the source-bound internal observer-stage contract, and keeps armed `mkdtemp` residual because its public entry point remains closed)
**Revised:** 2026-07-17 (ENG-25062 was reopened after merge-prep review confirmed that graph-link receipts are produced and retained, but production source/cache/prepared-carrier reads do not yet enter the receipt-revalidated access closures; the existing Host edge authentication and exact prepared-byte comparison remain in force without claiming the stronger closure-gated boundary)
**Revised:** 2026-07-16 (the module-runner safety review classifies exact generated manifest-builtin fan-out as closed private runtime linkage that may be eagerly materialized without a package/filesystem probe, but activation is confined to the exact builtin record's synchronous evaluation and cannot escape or re-enter through a retained `require` closure)
**Revised:** 2026-07-17 (ENG-24933 versions the conformance cache by the no-debugger build profile and reattests every restored framework before execution)
**Revised:** 2026-07-17 (ENG-24933 explicitly binds CI artifact selection and wrapper compilation to the Release profile and makes symbol attestation SIGPIPE-safe)
**Revised:** 2026-07-17 (ENG-24933 binds 33 legacy-bootstrap global paths to physical absence from the armed shared runtime without dereferencing missing roots)
**Revised:** 2026-07-17 (ENG-24933 binds all nine debugger ABI functions and their nine native-operation facets to physical null/zero/no-event results on the exact no-debugger Apple artifact)
**Revised:** 2026-07-17 (ENG-24933 binds all 106 source and alias facets of the terminal `async_hooks`, inspector, VM, WASI, and worker-thread builtins to loaded-engine denial of every public alias under an authenticated overbroad snapshot)
**Revised:** 2026-07-17 (ENG-24933 completes a source-, tree-, engine-, target-, and catalog-bound physical Apple Release report with 24/24 prerequisite commands passing; the report remains fail-closed with 1 conformant cell, 7,107 incomplete cells, and no advertisement)
**Revised:** 2026-07-17 (ENG-24933 implements Windows mapped-DLL object identity and a pinned patched no-debugger Release artifact pipeline while retaining the target's unsupported status pending runtime evidence)
**Revised:** 2026-07-18 (LLP 0030 separates policyless foreground source audit
from historical armed `diagnostic-audit` artifacts: foreground audit uses a
non-authorizing graph/decision context, the production verified-target gate,
and its own evidence digests; no new durable audit snapshot may arm)
**Revised:** 2026-07-17 (arming ABI v2 adds the evaluator-owned one-shot bootstrap authority floor/seal, an immutable root-only authority ceiling, and authenticated embedded protected ranges while retaining host-path protected objects)
**Revised:** 2026-07-17 (LLP 0014 canonical policy v2 rotates the policy digest domain while retaining the same checked semantic-set projection)
**Revised:** 2026-07-17 (ENG-24933 binds every exact-target evidence producer to the Apple OpenSSL crypto profile after a physical no-debugger Release run exposed the missing feature contract)
**Revised:** 2026-07-17 (ENG-24933 credits 14 source-bound asymmetric/EVP crypto executions on the Apple OpenSSL target profile)
**Revised:** 2026-07-17 (ENG-24933 credits nine bounded authority-control refusals and the post-capture absence of the loader-private manifest resolver)
**Revised:** 2026-07-17 (ENG-24933 credits six owner-authenticated refusals for unknown retained HTTP server and spawned-process identifiers)
**Revised:** 2026-07-17 (ENG-24933 credits synchronous and asynchronous filesystem close through harness-owned, source-bound descriptors)
**Revised:** 2026-07-17 (ENG-24933 credits two incomplete authority-call refusals and the exact invalid spawned-process handle refusal)
**Revised:** 2026-07-17 (ENG-24933 proves immutable module-level intrinsic receivers in builtin routes, removing 404 false ambiguous-route residuals without promoting unexecuted fixtures)
**Revised:** 2026-07-17 (ENG-24933 authenticates timer cancellation and ref-state mutation to the retained timer owner, replacing four closed native/global rows with eight executable non-capability and invariant recipes)
**Revised:** 2026-07-17 (ENG-24578 reconciles module-runner evidence with the production security boundary and credits 24 exact executions: four loader/source-acquisition surfaces, 19 native ABI lifecycle surfaces, and one armed namespace-inspection closure; six eager dynamic/require-link ABIs and the teardown-only generation-unpin ABI remain residual)
**Revised:** 2026-07-16 (ENG-24933 removes thirteen closed memory-debug implementation surfaces by capturing diagnostic state behind its deliberate API)
**Revised:** 2026-07-16 (ENG-24933 removes ten closed internal locale/accessibility state surfaces by retaining mutable state in module singletons)
**Revised:** 2026-07-16 (ENG-24933 completes malformed, missing-attribution, and wrong-principal scenarios for bounded loopback TCP connect)
**Revised:** 2026-07-16 (ENG-24933 completes thirty-six malformed, missing-attribution, and wrong-principal scenarios for system information, environment, and stdout)
**Revised:** 2026-07-16 (ENG-24933 closes twelve malformed, missing-attribution, and wrong-principal scenarios for retained metadata and whole-file reads)
**Revised:** 2026-07-16 (ENG-24933 binds direct `statfs` metadata to retained typed `fs:list` authorization and closes five exact public scenarios)
**Revised:** 2026-07-16 (ENG-24933 binds asynchronous `chmod` and `utime` to retained files, repeats authorization on the worker, and closes twelve exact public scenarios with owned cleanup)
**Revised:** 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the Exact-bound artifact preparer while preserving empty advertisements)
**Revised:** 2026-07-15 (ENG-25062 registered the module-runner factory, record, CJS-to-ESM edge, generation-lease, and compatibility-marker surfaces as closed non-capability control-plane operations)
**Revised:** 2026-07-15 (ENG-25066 made the authenticated graph decision set and process-stable principal projection the ordinary-ESM execution path)
**Revised:** 2026-07-15 (LLP 0026 adoption defines the module-initialization task boundary and trusted-loader source-acquisition classification)
**Revised:** 2026-07-16 (ENG-24578 residualizes 3,018 rationale-only
callback/control-plane rows because a generic invariant run cannot prove an
arbitrary carrier's selected branch; it retains eight exact embedder-mechanism
executions and requires every authenticated work-unit publication to be
consumed before teardown.)
**Revised:** 2026-07-15 (ENG-24578 residualizes raw resolver-output rows:
the resolver bridges are bootstrap-private and sealed before authenticated
project-source ingress, so unarmed or pre-bootstrap bare evaluation cannot
serve as execution evidence.)
**Revised:** 2026-07-15 (ENG-24578 binds cwd disclosure to the public
`process.cwd` facade over the sealed private bridge, and records the legacy
`.node`/`.wasm` resolver facets as residual until an authenticated source-bound
executor can distinguish their private rejection branches.)
**Revised:** 2026-07-15 (ENG-24578 aligns non-recursive armed `mkdir`
with LLP 0023's one-`mkdirat` contract: authorization retains the parent and
preauthorizes the absent child, but a failed post-create commit never performs
name-bound rollback that could unlink a racing replacement.)
**Revised:** 2026-07-14 (ENG-24578 binds the armed environment to an explicitly
empty base plus per-principal overlays, and replaces ambient compatibility
switches with fixed, digest-bound bootstrap modes; the Bun facade remains absent
unless the authenticated snapshot opts in.)
**Revised:** 2026-07-14 (ENG-24578 constrains diagnostic child IPC to a private one-shot POSIX socket handoff while armed IPC remains closed and unadvertised); 2026-07-14 (ENG-24933 introduces the dedicated binary Exact app/agent ingress while preserving the unadvertised Apple target and records the remaining artifact/conformance gate); 2026-07-12 (ENG-24263: the complete exact-engine prerequisite matrix and artifact evidence now run in CI, which requires the incomplete candidate to remain unadvertised rather than treating expected refusal as conformance); 2026-07-12 (ENG-24278 bounds POSIX TCP/UDP repeat work with socket-identity, exact-peer/destination, principal-set, and mutable-generation leases); 2026-07-12 (post-cutover security review hardened WP3–WP5: exact package content/graph roots and import edges, checked digest/set invariants, actual-engine and runtime-scoped arming, complete closed-startup controls, race-safe retained filesystem objects, analysis-byte/package-tree joining, and content-addressed report-derived target advertisements; the current registry still advertises no executable target — ENG-24232 through ENG-24281); 2026-07-12 (ENG-24233/24239/24247/24249–24253 remediate conformance evidence, policy identity, selector constraints, generation publication, atomic evidence, drift classification, package-root ceilings, and descriptor authorization leases); 2026-07-12 (ENG-24267/24268/24273/24276/24278/24280 align canonical ordering and mapped-IP semantics, harden generators, correct RFC 8785 numbers and staged decisions, and bound repeat-stage work); 2026-07-12 (ENG-24462/ENG-24465 bind filesystem occurrences separately to every constrained principal and protect every authenticated package subtree lexically against writes; ENG-24464 makes production run nonces construction-fresh; ENG-24466 explicitly closes diagnostic file execution in the advertised registry pending authenticated ingress); 2026-07-11 (WP0 semantic contract frozen by ENG-24144: profile, 38-action vocabulary, 57-bit reconciliation, typed occurrence/containment semantics, digest projections, and enforce-default target rule); 2026-07-11 (WP1 generated source-surface inventory, production registry, unsupported target matrix, and cross-language bindings implemented by ENG-24145); 2026-07-11 (WP2 typed Rust policy and decision core implemented by ENG-24146 with strict contract ingestion, canonicalization/digests, typed containment, decision precedence, staged conjunction/intersection, generations, and exact cache identities); 2026-07-11 (WP3 typed ESM/CJS import authoring and integrity-bound canonical generation implemented by ENG-24147); 2026-07-11 (WP4 strict immutable snapshot ingestion, production CLI arming, and explicit host/Hermes digest handshake implemented by ENG-24148); 2026-07-11 (WP5 initial retained checked-object record plus exact logical-branch schema and filesystem branch migration in progress under ENG-24149); 2026-07-11 (WP6 retained verified-peer record, metadata-peer denial, and exact logical network branch migration landed under ENG-24150, with runtime typed gates and red-team coverage still pending); 2026-07-11 (WP7 deny-only escape/process catalog invariant plus exact loader, process, stdio, environment, and host-default branch migration landed under ENG-24151, with runtime gates and red-team coverage still pending); 2026-07-11 (WP8 structured decision evidence, exact Android media-operation branches, and immutable snapshot-to-verified-decision-context arming landed under ENG-24152, with live handles/grants/deputy gate migration still pending); 2026-07-11 (WP10 exact-target report schema and fail-closed execution-evidence binding introduced by ENG-24154; the macOS candidate remains unadvertised pending complete executed fixtures)
**Revised:** 2026-07-17 (ENG-24933 records the retained TCP metadata residual gate after physical loopback execution exposed repeat decisions on actionless logical fixtures)
**Revised:** 2026-07-17 (ENG-24933 proves armed whole-environment enumeration selects its empty zero-decision branch without crediting the unreachable legacy wildcard path)
**Revised:** 2026-07-17 (ENG-24933 closes both public cr-sqlite enablement exports through exact in-memory refusal evidence)
**Revised:** 2026-07-18 (Windows public recipes remain residual where platform globals, including setup prerequisites, use legacy capability oracles, install explicit unsupported placeholders, or exclude their default-source registration from the target build)
**Revised:** 2026-07-17 (ENG-24933 closes both public SQLite extension-loading exports through exact in-memory refusal evidence); 2026-07-17 (ENG-24933 closes public messaging roots and executes debugger/shared-runtime/native absence evidence on both exact candidates); 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the Exact-bound artifact preparer while preserving empty advertisements); 2026-07-14 (ENG-24933 introduces the dedicated binary Exact app/agent ingress while preserving the unadvertised Apple target and records the remaining artifact/conformance gate); 2026-07-12 (ENG-24263: the complete exact-engine prerequisite matrix and artifact evidence now run in CI, which requires the incomplete candidate to remain unadvertised rather than treating expected refusal as conformance); 2026-07-12 (ENG-24278 bounds POSIX TCP/UDP repeat work with socket-identity, exact-peer/destination, principal-set, and mutable-generation leases); 2026-07-12 (post-cutover security review hardened WP3–WP5: exact package content/graph roots and import edges, checked digest/set invariants, actual-engine and runtime-scoped arming, complete closed-startup controls, race-safe retained filesystem objects, analysis-byte/package-tree joining, and content-addressed report-derived target advertisements; the current registry still advertises no executable target — ENG-24232 through ENG-24281); 2026-07-12 (ENG-24233/24239/24247/24249–24253 remediate conformance evidence, policy identity, selector constraints, generation publication, atomic evidence, drift classification, package-root ceilings, and descriptor authorization leases); 2026-07-12 (ENG-24267/24268/24273/24276/24278/24280 align canonical ordering and mapped-IP semantics, harden generators, correct RFC 8785 numbers and staged decisions, and bound repeat-stage work); 2026-07-12 (ENG-24462/ENG-24465 bind filesystem occurrences separately to every constrained principal and protect every authenticated package subtree lexically against writes; ENG-24464 makes production run nonces construction-fresh; ENG-24466 explicitly closes diagnostic file execution in the advertised registry pending authenticated ingress); 2026-07-11 (WP0 semantic contract frozen by ENG-24144: profile, 38-action vocabulary, 57-bit reconciliation, typed occurrence/containment semantics, digest projections, and enforce-default target rule); 2026-07-11 (WP1 generated source-surface inventory, production registry, unsupported target matrix, and cross-language bindings implemented by ENG-24145); 2026-07-11 (WP2 typed Rust policy and decision core implemented by ENG-24146 with strict contract ingestion, canonicalization/digests, typed containment, decision precedence, staged conjunction/intersection, generations, and exact cache identities); 2026-07-11 (WP3 typed ESM/CJS import authoring and integrity-bound canonical generation implemented by ENG-24147); 2026-07-11 (WP4 strict immutable snapshot ingestion, production CLI arming, and explicit host/Hermes digest handshake implemented by ENG-24148); 2026-07-11 (WP5 initial retained checked-object record plus exact logical-branch schema and filesystem branch migration in progress under ENG-24149); 2026-07-11 (WP6 retained verified-peer record, metadata-peer denial, and exact logical network branch migration landed under ENG-24150, with runtime gates and red-team coverage still pending); 2026-07-11 (WP7 deny-only escape/process catalog invariant plus exact loader, process, stdio, environment, and host-default branch migration landed under ENG-24151, with runtime gates and red-team coverage still pending); 2026-07-11 (WP8 structured decision evidence, exact Android media-operation branches, and immutable snapshot-to-verified-decision-context arming landed under ENG-24152, with live handles/grants/deputy gate migration still pending); 2026-07-11 (WP10 exact-target report schema and fail-closed execution-evidence binding introduced by ENG-24154; the macOS candidate remains unadvertised pending complete executed fixtures)
**Revised:** 2026-07-19 (ENG-24933 executes each reviewed `util`/`sys`
public spelling in a fresh engine and binds its first-load `NODE_DEBUG` read to
the independently observed native environment gate; platform and lazy DNS
aliases remain residual.)
**Revised:** 2026-08-03 (aggregate public-evidence validation now applies the
pairwise-distinct runtime-nonce rule only to authenticated builtin first-load
receipts; loader source-point receipts are emitted by a separate harness
process whose monotonic runtime counter occupies an independent namespace.)
**Revised:** 2026-07-19 (ENG-24933 reconciles the current lazy DNS sources with
the coverage model: the four exact `dns`/`node:dns` and promises import
spellings, plus both default namespace rows, are module-reachability-only;
each import spelling now requires fresh-engine observation from before its
first `require` through event-loop quiescence, while `getServers`, `Resolver`,
and other exported operations remain separate and uncredited; the promises
spellings now execute their declared `node_dns_promises` manifest source rather
than a bootstrap-internal shadow; `getServers` and `Resolver` now carry the
conditional native-resolution/filesystem-fallback effects that the lazy source
actually triggers.)
**Related:** LLP 0002 (host ABI); LLP 0004 (module loading); LLP 0005 (generated build artifacts); LLP 0013 (per-package enforcement mechanics); LLP 0014 (import-site grants and generated policy); LLP 0016 (architecture assessment); LLP 0020 (Oden portability research); LLP 0026 (module-runner authority amendments); LLP 0027 (module artifacts and interop); Oden LLP 0019 (Capability Security, Revision 2); Oden LLP 0020 (Capability Security by Default); ENG-24143

## Summary

Ibex will replace its current string-based capability policy plane with the
effect-oriented model developed in Oden. The existing enforcement substrate
remains: runtime-instance isolation, per-package principals, native compartment
globals, lockdown, frame-derived attribution, import gating, and
authority-bearing attenuated handles. The replacement is above that substrate:
typed effects, generated coverage and conformance data, typed policy artifacts,
explicit resource semantics, and a fail-closed armed runtime snapshot.

This is a direct cutover, not a compatibility migration. Ibex has no external
users whose committed policies or CLI workflows need preservation. The project
will therefore not build a frozen legacy oracle, dual-profile runtime, policy
translator, or deprecation period. Current policy files, permissive defaults,
and weakening flags are development-state implementation details that may be
deleted as soon as their replacements work.

The destination has these properties:

1. The unit of mediation is a normalized **effect**, not a capability string
   attached one-to-one to an API. One operation may require several effects,
   and all must authorize before the corresponding effect occurs.
2. Capability definitions, surface-to-effect coverage edges, target
   conformance cells, and policy/classifier rules are generated datasets with
   deterministic drift checks.
3. Policy moves one way through **authored source → canonical review policy →
   armed snapshot**. Only the armed snapshot is consumed by the engine.
4. Canonical positive authority uses explicit actions and typed resources.
   Paths, endpoints, routes, ports, peer classes, executable identities, and
   other resource kinds are not overloaded colon-delimited strings.
5. Policy and runtime semantics are bound by profile, vocabulary, registry,
   policy, and armed-snapshot digests.
6. Every authority-bearing runtime surface is classified and tested. A surface
   is enforced, deliberately closed, absent, unsupported, or explicitly a
   non-capability; there is no unclassified production surface.
7. Normal `ibex` execution enforces the complete supported profile by default.
   Missing policy means empty dependency authority, not permissive execution.
   A target that cannot support the profile refuses before project code.

This plan is complete only when the old matcher and policy format are gone, the
default command cannot silently weaken the posture, and every advertised target
has a generated conformance report proving the profile it claims.

## Motivation

LLP 0013's mechanism work substantially exists and remains the right substrate,
but the policy plane has accumulated ambiguity that the Oden work made
concrete:

- `PolicyFile` accepts unversioned arrays of capability strings. Matching,
  resource grammar, action implication, and future vocabulary growth are
  implicit in handwritten code.
- The current shape encourages one operation to check one capability even when
  the operation discloses, reads, writes, connects, redirects, spawns, or
  delegates through several independently meaningful effects.
- Generated import-site policy is reviewable, but the artifact does not
  cryptographically bind the exact vocabulary, normalization semantics,
  surface classification, target support, or runtime bindings it relies on.
- Filesystem and network authorization can be separated from the OS object or
  final peer used after the check. String-level authorization alone cannot
  express retained-object, redirect, DNS rebinding, proxy-route, or staged
  authorization semantics cleanly.
- Enforcement completeness depends heavily on remembering to classify each new
  native, loader, builtin, callback, inspector, process-global, or resource-use
  surface. Oden demonstrated that this should be a generated inventory and CI
  invariant.
- The current CLI makes permissive execution the implicit no-policy default and
  exposes public weakening paths. That is the wrong long-term identity for a
  runtime whose defining distinction is package-level capability security.

Because Ibex has no external consumers yet, the usual reason to preserve these
semantics—migration cost—does not apply. The lowest-risk long-term choice is to
change direction now, before examples, embedders, and policies harden around the
intermediate model.

## Decision boundary

### Retained from LLP 0013 and LLP 0014

- Runtime instances remain the outer trust-domain boundary.
- Integrity-bound package principals remain the package-layer subjects.
- Hermes frame attribution and schedule-time principal capture remain the
  unforgeable source of acting-principal identity.
- Native per-package compartment globals and lockdown remain the reachability
  and shared-intrinsic integrity layer.
- Import gating and compartment endowments remain defense in depth; making an
  API unreachable never substitutes for checking its effect when reachable.
- Passed, attenuated handles remain the primary voluntary delegation channel.
- Import-site grants in root-principal code remain the concise grant-authoring
  surface, with package-authored declarations treated as requests rather than
  grants.
- Root and runtime-internal principals remain explicit identities rather than
  attribution fallbacks. Missing attribution continues to deny.

### Replaced

- `PolicyFile` as an unversioned bag of string lists.
- A single handwritten capability manifest serving simultaneously as public
  vocabulary, matcher input, implementation inventory, and conformance claim.
- Colon-delimited capability strings as the canonical review or engine format.
- Implicit action derivations and positive wildcards whose meaning can grow as
  the vocabulary grows.
- One-operation/one-check reasoning.
- Check-then-reopen filesystem and check-requested-host-only network semantics.
- A committed durable `audit` or `permissive` policy mode.
- Default permissive execution, `--allow-all`, public permissive execution,
  advisory-attribution execution, environment-selected weakening, and
  enforce-without-required-lockdown behavior on the normal production command.

### Deferred above the core

The following Oden work is not required to complete this migration: AI-assisted
grant proposal conversations, protected authorization receipt workflows,
isolated candidate publication, daemon migration, and report-artifact privacy.
The core must expose authenticated typed evidence those systems could consume,
but Ibex does not need to copy Oden's complete product workflow.

## Target model

### Effects and decision sets

A **surface** is a JavaScript API, loader path, builtin, native op, startup
route, callback, or other entry point. A generated **coverage edge** maps a
surface to one or more normalized effects and identifies the enforcement gate,
principal source, normalization rule, authorization stage, and fixture set.

An **effect occurrence** contains the runtime facts needed to decide one
authority-bearing action. A policy row contains an **authority selector** over
such occurrences. Runtime observations such as a selected DNS candidate or file
identity never become reusable authored authority.

All effects in one decision set are conjunctive. An operation may proceed to a
stage only after every effect knowable at that stage is allowed for every
non-transparent constrained principal. Later discoveries—symlink targets, DNS
candidates, redirects, proxy routes, accepted peers—pause the operation and
authorize the next stage before committing it. Missing required facts,
unclassified surfaces, missing attribution, unknown definitions, and unsupported
target cells deny or refuse arming.

### Generated semantic datasets

The implementation has four generated inputs:

1. **Capability definitions** — action identity, selector and occurrence
   schemas, normalization, authoring disposition, delegation/dynamic behavior,
   and risk metadata.
2. **Coverage edges** — surface inventory, effects, principal/effect-owner
   source, gate, stages, lifetime/recheck obligations, and stable identifiers.
3. **Backend/target conformance cells** — implemented disposition and required
   fixtures for each coverage edge on each supported target/profile.
4. **Policy and classifier rules** — derivations, non-capability rationales,
   decision precedence, protected resources, risk promotion, route/address
   classes, and other decision-affecting data.

Generated Rust, C++, JavaScript/TypeScript, JSON schemas, documentation tables,
and fixtures consume these sources. Handwritten duplicate matcher tables are
not authoritative. Drift is a build/CI failure.

Coverage edges contain semantic data only. A separately generated
`implementation-manifest.json` joins each edge to source-derived definitions,
stubs, or security-relevant references, the later work package that owns its
gate, fixture obligations, and content digests for generated outputs. Those
references are inventory evidence, not conformance evidence; only executed
fixtures can promote a target cell.

An effect edge is normally `conjunctive`. WP1 may record a known
parameter/provenance-dependent surface as `conditional-unrefined` only while
every corresponding target cell remains `unsupported`; the edge names its
refinement owner and why its possible effect set is not yet executable. Such an
edge cannot be promoted or armed. The owning filesystem, network, process, or
device work package must replace it with exact conjunctive logical branches
before conformance.

An exact conditional edge carries a canonical `logicalBranches` set. Each
branch names the normalized operation facts that select it and either its
complete conjunctive effect set, principal/effect-owner sources, lifetime, and
barriers, or a deny-only closed disposition with its closed action and
rationale. This permits a dispatcher to retain narrow object-bound operations
without misclassifying adjacent unbound mutations as effects. Immutable target
facts may participate in selection only when they come from the exact
digest-bound target profile; they are never caller-supplied runtime input.
Selection facts are produced only after argument/resource normalization and
must select exactly one branch; missing, unknown, or overlapping facts deny.
Fixture obligations are derived independently for every logical branch,
including branch selection, explicit no-effect branches, and a physical
pre-effect refusal for every closed branch, so a union of possible effects
cannot masquerade as executed conditional semantics.

### Policy forms and digests

Policy has three forms:

1. **Authored source** may use import-site syntax, aliases, macros, logical
   paths, and package selectors.
2. **Canonical review policy** contains explicit actions, typed resources,
   integrity-bound principals, explicit derivations, and reproducible logical
   bindings. It is the artifact a human reviews and may commit.
3. **Armed snapshot** binds the canonical policy to one execution: engine
   target, generated registry, effective mode, canonical host objects and paths,
   final route constraints, process-wide ceiling, protected guards, package
   graph, root identity, and immutable runtime generations. It is the only form
   the decision engine consumes.

The profile is `ibex/capsec/1`; this is Ibex's first public contract. Oden's
`/2` suffix belongs to Oden's own profile lineage, while the shared ancestry is
expressed by the effect/registry semantics and `capsec/semantics/1` core
contract. Digest encoding and domains are frozen below. A stale or mismatched
digest refuses arming. Duplicate keys, unknown positive actions, unresolved
selectors, aliases, macros, and machine-specific unbound paths may not reach
the armed snapshot.

`runtimeExtensions`, when present, is a closed
`ibex/runtime-extension-authority-capsule/1` projection. Its
`extensionSetDigest` uses domain `ibex:runtime-extension-set:1` over the sorted
selection tuple `(id, version, sdkVersion, manifestDigest)`. Its complete
`authorityCapsuleDigest` uses domain
`ibex:runtime-extension-authority-capsule:1` and omits only the digest field
itself. Both use the existing canonical `sha256-` plus unpadded-base64url
encoding. The capsule binds required SDK feature bits; full operation entry
paths and flags; callback producer affinity, owner-thread delivery, and queue
bounds; selected provider ABI version, size, and identity; and optional
source/Hermes-bytecode bootstrap content digests, lengths, source URLs, and
the closed `script-global` evaluation mode. Absence is the canonical empty
extension projection.

### Default execution contract

Normal project-code execution uses enforce mode. Absence of authored grants
produces empty package floors and closed dynamic ceilings; it does not select a
weaker mode. Lockdown, per-package attribution, compartment globals, and full
deputy intersection are required structural posture rather than independently
disableable policy preferences.

Audit is the separately named, ephemeral `ibex capsec audit` foreground
workflow governed by LLP 0030. It uses
`ForegroundAuditGraphSnapshotV1`/`ForegroundAuditDecisionContextV1`, not an
`ArmedSnapshot`; the historical armed-schema `diagnostic-audit` value is
decode-only until the next schema major removes it and no new instance may
arm. Permissive behavior exists only inside isolated tests. The
`contract-fixture` armed workflow is schema-only, must use the synthetic
`capsec-contract-fixture` target, and is never executable. None of these is a
mode of ordinary `ibex run`. Embedders must select an explicit supported profile
and successfully arm it; the legacy host constructor must not silently create a
production runtime that claims package security while running permissively.

### Module initialization and trusted source acquisition

LLP 0026 adds one explicit boundary to full deputy intersection. A module
factory's once-per-execution-generation initialization is an autonomous,
record-owned task: it executes in the defining principal's authenticated
compartment, and the constrained-principal set begins at that initialization
task boundary. Importer frames physically above a synchronous `require()` do
not join initialization-time decisions. This preserves deterministic module
state across cold/warm, synchronous/asynchronous, and competing-importer
orders. It does not widen the module's own grants. Calls through exports after
initialization continue to intersect the complete live caller and scheduler
chain exactly as before.

Module source acquisition is classified as a narrow trusted-loader operation,
not as `fs:list`/`fs:read` authority borrowed from the importer. It may occur
only after the exact authenticated import edge authorizes and is bound to that
edge's `SourceId`, source binding, locator, integrity, requesting record, and
graph generation. It is non-delegable and conveys no general filesystem
authority. The generated coverage registry rows for module-source acquisition
must use this classification before the ModuleRunner security integration can
claim conformance; denial, no-probe, cache-hit, prepared-carrier, and
wrong-principal fixtures are mandatory.

First-party and package source reads pin the authenticated root directory
object and open every descendant component relative to the retained parent
without following links. Unix uses descriptor-relative `openat`; Windows uses
`NtCreateFile` with the retained directory handle as `RootDirectory` and
`FILE_OPEN_REPARSE_POINT` at every step. Package reads additionally compare two
complete integrity inventories and retain source bytes from the same opened
handle that supplied their digest record. Both paths validate the armed root
object before accepting source bytes, so a path rename or reparse substitution
cannot redirect trusted-loader acquisition.

ENG-25062 implements that boundary as a typed `GraphDecisionSet` over the
exact requesting and target `SourceId`, resolution kind, conditions,
attributes, actor, effect owner, schedule-time identity, canonical constrained
set, stage, atomicity group, graph generation, and coverage edge. Successful
authorization returns an opaque receipt bound to the armed snapshot digest and
all four authority generations. The graph linker produces and retains those
receipts. The production native-graph builder now separates metadata resolution
from executable-source acquisition for every authored dependency. It
authorizes the exact typed edge before the Host may enter the retained-object
source read, keeps that read inside an opaque acquisition closure, computes the
authenticated byte digest, finalizes the source-access receipt, and retains the
receipt for the graph lifetime before releasing bytes to the producer. The
entry read remains joined to its separate authenticated launch request. Armed
transpilation is fresh and in-memory, so it has no persistent `CacheRead` path
to authorize. When a prepared carrier contains an authored dependency, its read
derives an exact `PreparedCarrierRead` receipt from that dependency's retained
source-acquisition continuation, binds the expected source integrity and
deterministic carrier digest, reads the manifest/payload only inside the
receipt-revalidated closure, and retains the resulting receipt for the prepared
graph lifetime. Prepared-cache loading additionally requires an opaque,
non-serializable entry-join token minted only after the structured file
request's VFS identity, principal, snapshot digest, source integrity, goal,
dialect, role, and main-entry status match the graph. The token is rejoined to
the current graph before `index.json` is read. A carrier with no dependency
receipt is admissible only when it contains that joined launch entry, rather
than inventing an import edge for the entry.
Module factories remain reachability-only at the graph boundary; host effects
they perform still enter ordinary typed semantic-core `DecisionSet`s at their
native effect gates. Generated target cells remain unsupported until executed
conformance evidence promotes them.

## WP0 semantic contract

ENG-24144 freezes the following contract for WP1–WP11. The machine-readable
authority is under `capsec/`; this section records the design decisions that
those artifacts implement.

### Ownership and profile identity

Ibex owns the initial canonical contract under `capsec/`. WP2 places the
runtime-neutral Rust implementation behind the neutral crate boundary
`crates/capsec-semantics` in this repository. A second runtime consumes that
exact source or makes an explicit ownership move; it must not copy the schemas,
canonicalizer, precedence implementation, or matcher into a second authority.
Product capability definitions, coverage edges, principal attribution adapters,
and target cells remain Ibex-local.

The product profile is `ibex/capsec/1`; the neutral semantic-core contract is
`capsec/semantics/1`. Profile suffixes are product-local compatibility versions,
not cross-runtime marketing generations.

An authenticated native runtime-extension capsule may add only namespaced data:
extension/operation IDs, authority classes, trusted-bootstrap surface names,
callback identities and bounded delivery facts, provider ABI identities, and
protected bootstrap/native linked-artifact identities. The neutral crate owns the single
`runtime-extension:invoke` definition and
`runtime-extension.identity.v1` exact normalization behavior. Extension
fragments are closed data objects and cannot provide matchers, normalizers,
precedence, action definitions, target predicates, or executable semantic
logic. Their authority exists only while the complete capsule is digest-bound
into the armed snapshot.

### Typed resources and initial vocabulary

Canonical positive rows contain one explicit two-part action and one typed
resource object. No `*`, bare family, family prefix, alias, comma list, or
colon-delimited resource can survive source ingestion. Authoring macros may
expand only against the pinned vocabulary and their expansions appear as
explicit canonical rows.

Initial authorable resource kinds are:

- logical-root `path-exact` and `path-tree`. Exact matches the entire decoded
  component sequence; tree is a component-boundary prefix including its base.
  Package roots additionally require the same package-root binding owner.
  Valid UTF-8 uses UTF-8 form and other byte components use canonical unpadded
  base64url. Target-neutral identity rejects only empty, dot, dot-dot, NUL, and
  slash components; a backslash or Windows-reserved name remains representable
  for Unix. At arming, Unix/Android accepts all remaining byte names, Windows
  additionally requires valid UTF-8 ASCII, rejects controls, forbidden characters,
  trailing dot/space, DOS device names, tilde spellings, and adapter-reported
  aliases, and binds ASCII case-folding as its current candidate identity. A
  case-sensitive Windows directory refuses rather than collapsing distinct names.
  Retained relative opens additionally stage the exact long/short directory-entry
  names and file ID, refuse selection through any 8.3 name, and repeat the entry
  after opening without delete sharing. The Apple bound-volume adapter supplies
  its actual case/normalization alias key.
  Alias collisions are compared only within the same bound-root/volume
  namespace; two packages' separate package-root bindings do not alias.
  Absolute paths are explicitly host-bound, and execution still requires a
  retained or verified platform object identity;
- separate fetch, raw/bidirectional connect, Unix connect, internet/Unix
  listen, and standalone DNS-query resources. Fetch never implies connect.
  Network selectors bind the exact scheme or transport, canonical DNS/IP/CIDR,
  remote or listen port, direct route, and peer classes. Runtime occurrences
  additionally materialize the concrete port, selected candidate, verified
  peer, and connection/listener identity applicable at each stage; those facts
  never become reusable authored selectors. Non-direct routes are discovered
  and refused before DNS, connect, or request bytes in this profile; typed
  proxies require a future profile;
- exact environment names: `env:read` accepts broker-base and
  principal-overlay, while `env:write` accepts principal-overlay and one
  child-launch. Read and write never imply one another;
- executable identity binding logical name, path, content, platform object,
  and, when present, interpreter path/content/platform object. Spawn composes
  `process:spawn`, child working-directory, child environment, and inherited
  stdio effects into one conjunctive decision set; closed stdio and unexported
  anonymous-pipe creation carry no external authority, while every exported
  endpoint has an exact owner-bound identity;
- independent stdio resources with stream and exact source identity:
  `stdio:query` accepts stdin/stdout/stderr, `stdio:read` only stdin,
  `stdio:write` only stdout/stderr, and `stdio:raw` only terminal-backed stdin;
  plus explicit system-information kinds, typed location/camera/microphone
  acquisition, and native system clipboard formats.

The optional native runtime-extension profile adds one product-neutral,
equality-only resource:
`{"kind":"runtime-extension","extensionId":...,"authorityClass":...}`.
It has no wildcard, family, prefix, or manifest-defined containment. The
authenticated capsule separately proves that an exact operation ID belongs to
that extension and authority class; opaque operation resource data contributes
only a canonical digest to the occurrence/lease identity. Every constrained
principal must already hold the exact selector in its immutable static floor,
so ambient-root fallback cannot manufacture extension authority.

`fs:list`, `fs:read`, `fs:write`, and `fs:watch` are independent. A matcher
never derives one action from another. SQLite file operations decompose into
the corresponding filesystem effects for the main database, parent, and
journal/WAL/SHM objects; `sqlite:*` is not canonical authority. Unix sockets
decompose `network:local` into connect or listen plus the applicable filesystem
effects. Ordinary randomness, pure in-memory cryptography, ordinary/high-
resolution clocks, and status-only attenuations are reasoned non-capabilities.
Exact SQLite `:memory:` databases are likewise computation because the host
authorizer denies attach/detach and extension loading. URI-looking or empty
filenames are not covered by that exemption and remain file-backed effects.

Location, camera, microphone, and clipboard are authorable target-specific
definitions. Their cells remain unsupported until native gates and broker/
lifetime fixtures prove them (`device:microphone` is known ungated today).
Storage remains deny-only until principal/shared namespace and native isolation
are proven. Shared process mutation, ambient IPC, inspector/runtime inspection,
VM, workers, WASI, and FFI remain deny-only or absent. The generated
reconciliation table joins every one of the 57 current bit names to its exact
destination disposition across 38 typed action definitions; the Rust bit source
remains the sole bit-number authority.

A package principal is the exact package locator plus integrity digest (with
its review name), not a package name alone. Root-only sources author positive
grants. Canonical provenance may merge several non-authorizing source records,
while definition lifecycle and channel restrictions still determine whether a
row may become static, dynamic, handle-mediated, or terminal authority.

### Decision, staging, and principal semantics

For one normalized effect and one constrained principal, precedence is:

1. arm validity and authenticated profile/digest agreement;
2. attribution (`NoUser`, missing, or ambiguous denies);
3. definition lifecycle and exact target-cell closure;
4. built-in protected-resource guards;
5. process-wide ceiling;
6. root-only authority ceiling for an authenticated root principal;
7. principal-specific denial;
8. revocation and negative generation;
9. quarantine denial;
10. definition/edge positive predicates;
11. static floor;
12. an explicit unforgeable bearer handle;
13. a typed dynamic session grant within the static ceiling;
14. generated implicit package-self access;
15. ambient root for the root dimension only; and
16. the effective mode's missing-authority result.

Every deny stratum precedes every positive authority source. The direct cutover
has no runtime legacy-oracle or compatibility-mask stratum; the 57-bit table is
build-time reconciliation evidence only. An unbounded process ceiling
continues; a bounded ceiling requires containment, and an empty bounded ceiling
denies everything.
The root ceiling is independently bounded or unbounded, applies only to an
authenticated root principal, and constrains `AmbientRoot` without narrowing a
package floor. It is immutable publication identity and therefore cannot be
widened through a live-generation update.
Every filesystem occurrence is projected separately through each constrained
principal's authenticated root binding before any principal-indexed authority
stratum runs. That rule applies to protected resources, process ceilings,
principal denials, revocations, static floors, handles, dynamic grants, and
implicit package-self authority; an actor-projected package path is never reused
as another package's resource. An unprojected multi-principal path occurrence
fails closed. A deeper foreign package binding shadows an owned package
ancestor, so an outer package sees a nested dependency through the best
ownerless root rather than as part of its own package tree; equal package host
bindings and package principals without bindings refuse arming. Other
path-bearing resource kinds (executables and Unix sockets) refuse a
multi-principal package-root decision until their adapters supply complete
projections. The host, ABI, and semantic core all use the same JCS principal
ordering. No later source, including ambient root, can override an earlier
ceiling or denial.

The exact reserved `runtime/ibex-runtime-internal` frame stamp is transparent;
other runtime identities are not, and the reserved identity is never an
attribution fallback. `NoUser`, missing, or ambiguous attribution denies. Live
user frames plus authenticated schedule-time and owner/deputy identities form
a deduplicated constrained set. Each non-transparent dimension must allow;
dimensions intersect and never union. All effects known at a stage are
conjunctive and authorize before that stage's first visible or irreversible
action. Later object, DNS candidate, redirect, route, accepted-peer, or resource
discovery re-enters the same precedence before the next effect. Missing facts
deny, speculative effects are forbidden, and a late denial releases provisional
resources without pretending earlier discovery was reversible.

An armed snapshot has exactly one authority row matching `rootIdentity`. Every
package-graph node has a unique locator-and-integrity principal, an exact
authority row, and its own package-root binding; package authority rows may not
exist outside the graph. Import allowlists exactly equal authenticated graph
edges, and every logical path resolves through a root binding. Exact protected
objects cover armed policy, engine binary, package graph, and registry. In
addition, arming derives `fs:write` path-tree guards for every authenticated
package binding in every principal's projected view. Authenticated package
source cannot be written through any registered package spelling, even when two
such spellings share an inode; writable package scratch space requires a
separate future binding. A pre-existing filesystem alias outside every
authenticated package binding is not covered by this lexical guarantee and
requires a future commit-time identity/integrity guard. Network posture binds
direct-only routing and always denies metadata and unspecified peers.

Compiled arming may satisfy a protected role with an authenticated embedded
range instead of a host pathname. An embedded protected artifact binds one
mapped executable object, a nonempty safe-integer byte range, the exact section
role, and the admitted content digest. Host and embedded artifacts together
must fill every protected role exactly once; embedded ranges on one executable
cannot overlap. Several ranges in one mapped executable collapse to one
filesystem write guard for that executable object, while their role/range/
digest identities remain distinct immutable arming facts.

### Handles, dynamic authority, and generations

Ibex deliberately retains LLP 0013's possession-based delegation within one
authenticated runtime. A handle is an unforgeable bearer object whose exact
action/resource grant, source owner, ancestry, and snapshot identity are fixed
at mint. Passing the object is voluntary delegation; frame/schedule attribution
still records the holder and actor chain. Handle use re-enters every negative
stratum at every effect stage, can attenuate only to the same action and a
strict resource subset, and is invalidated by ancestor revocation. A temporary
operation lease is native, operation-bound, non-transferable, and cannot turn
mode fallback into reusable authority. This is an explicit Ibex adaptation of
the Oden model, not an accidental omission of delegatee identity.

Authority containment is meaningful only within the same armed snapshot. Any
authority containing a package logical root also requires the same package-root
binding owner. Different actions are always incomparable even when their
resource shapes coincide.

Dynamic grants use typed resources and cannot cross the canonical static
escalation ceiling. Deny-only, planned, terminal, and static-only definitions
cannot enter the dynamic overlay. Mode fallback can never mint a grant or
handle. Revocation advances a negative generation before any later positive
decision.

Arm-time ceilings, protected-object/resource guards, and principal policies
retain an identity-preserving copy-on-write backing after validation. A live
publication must present those exact four immutable identities and then fully
validates only the changed generations, revocations, handles, and dynamic
grants. Cloning and publishing live authority is therefore constant-time in
the size of the static policy; attempting to mutate any immutable component
creates a new backing identity and refuses publication `[observed]`
(ENG-24280).

Decision caches key at least action, canonical resource bytes, constrained
principal set, effect owner, stage, vocabulary/registry/policy/armed-snapshot
digests, and negative/dynamic/handle generations. Repeated and live operations
must still obey their coverage edge's lifetime recheck contract.
Authority-reducing release, reset, shutdown, and cancellation have no positive
effect stage: they validate the retained object's runtime and principal owner
but remain possible after its positive grant is revoked. Requiring a live
positive lease to relinquish an owned resource can leak authority and violates
the registry's `authority-release` non-capability classification.

### Canonicalization and digest domains

All digest inputs are valid UTF-8 containing only Unicode scalar values and are
strict I-JSON serialized with RFC 8785 JCS. Duplicate keys are rejected before
canonicalization, and integers outside the I-JSON safe range use a tagged
canonical string. Arrays named by `digestContract.setKeys` are semantic sets
sorted and deduplicated by canonical JCS bytes. Composite-row sets use the exact
`(schema, path, orderBy)` declarations in `digestContract.keyedSets`; other
arrays retain sequence meaning. The hash frame is:

```text
SHA-256(UTF8(domain) || 0x00 || canonical-payload)
```

Digest text is lowercase `sha256-` followed by unpadded base64url. Domains are:

- `ibex:capsec:vocab:1` — definitions, selector/occurrence schemas,
  decision-affecting coverage/classifier rules, and non-capability rationales;
- `ibex:capsec:registry:1` — the source-derived generated registry,
  implementation references, and fixtures. Report-promoted target-cell bytes
  are bound separately so publishing a report cannot change the registry or
  implementation digest that the same report attests;
- `ibex:capsec:policy:2` — canonical review policy with its own digest omitted;
- `ibex:capsec:armed:1` — policy/registry identities plus resolved host objects,
  engine target, routes, graph, ceilings, generations, run nonce, and channel
  epoch; and
- `ibex:capsec:conformance:1` — one observed result for every target cell and
  the exact engine/fixture/report provenance.

Vocabulary and registry aggregates use `ibex/capsec-digest-bundle/1`, with
members ordered lexically by logical name and exact member lists frozen in
`digestContract.projections`. Policy, armed-snapshot, and conformance
projections omit only their own digest fields. The checked vocabulary bundle is
assembled from the exact WP0 definition/rule/schema files plus normative
coverage and containment vectors. The registry fixture content-addresses every
semantic and invalid fixture body as well as its closed file inventory; digest
payloads and the fixed digest-vector oracle are explicitly excluded where
including their raw bytes would create a cycle, and are checked independently.
The generated production registry is available after WP1. Its target cells are
all unsupported and its source references are explicitly non-conformance
inventory evidence. A tiny authored attestation catalog may name only a
content-addressed report; generation revalidates that report against the exact
source-derived implementation manifest and derives both target cells and the
advertisement list. Target cells, their matrix, and advertisements are excluded
from `implementationManifestDigest`, breaking the otherwise circular
report-promotes-cells-that-change-the-report-input dependency. The armed
snapshot remains a `contract-fixture`, and conformance remains unavailable
until WP10. Canonical policy and armed examples carry
recomputed self-digests and exact cross-digests. One checked golden vector
freezes each of the five domains, and the domain-to-payload mapping is fixed.

Production handle, dynamic-permission, and denial evidence carry all four
loaded vocabulary, registry, policy, and armed-snapshot digests from the
immutable engine decision context rather than expected wrapper values.
Foreground-audit evidence instead carries vocabulary, registry, the compiled
diagnostic-baseline digest, and the foreground graph digest; it never fills a
policy or armed-snapshot slot with a lookalike value.

### Default and target claim

Durable canonical policy accepts only enforce. Audit is a separately named,
ephemeral foreground workflow; production permissive/off are not profile
members. Missing policy canonicalizes to enforce with empty dependency floors
and empty escalation ceilings. Full deputy intersection, lockdown, frame
attribution, native compartments, and immutable arming are structural.

WP1 advertises no targets and records one candidate exact target,
`aarch64-apple-darwin` with structural `hermes-frame-attribution`,
`native-compartments`, and `native-lockdown` features. These are security
properties, not Cargo feature names. An executable production snapshot may arm
only when its exact target triple and canonical feature set
are advertised and every coverage edge has a matching `enforced`, `closed`, or
`absent` cell; a missing or `unsupported` cell refuses before project code.
Foreground source audit does not arm, but uses this same verified target and
feature-set authority before capture; the OS/architecture allowlist alone is
not an advertisement.
Public-address classification remains closed until pinned IANA IPv4 and IPv6
special-purpose snapshots enter the registry. IPv4-mapped IPv6 is classified
through its embedded IPv4 address, unmatched addresses fall back to `reserved`,
and classifier activation gates the first target advertisement.

WP9 flips the ordinary command once at least one exact advertised target has a
complete generated conformance report. The repository does not wait for every
conceivable build triple, but a build on any incomplete target refuses before
project code rather than degrading or selecting the legacy plane. Public claims
remain exact-target claims. Internal unit/integration fixtures are sufficient
for permissive compatibility investigation; the production CLI gains no raw
developer harness.

Exact embedding does not create a second or weaker target-claim plane. The
dedicated `exact.invokeHostAsync` ABI removes the generic string bridge from
app and agent traffic, with separate canonical numeric endowment sets and no
UI-worklet installation, but the same target-advertisement rule still governs
production construction. Before Exact may consume an armed artifact through
the public embedding ABI, the normal Ibex package flow must supply the generic
snapshot/expected-identity inputs plus Exact's single-source operation manifest;
the target-local producer then publishes a final pair bound to the loaded
engine, this registry, the exact package graph, and the protected manifest.
Its target row
must be promoted only from the checked conformance report. Missing artifacts,
wrong targets, identity or registry mismatches, fixed/stale nonces, replayed
input, and unadvertised rows all remain startup refusals.

Implementation status (2026-07-17): the dedicated binary app/agent ingress and
single-use completion path exist and are usable by an armed runtime without
making `__hostCall` reachable. Its setter publishes an immutable method on the
stable pre-captured `exact` object and atomically completes the one-shot package
baseline finalization, so package compartments cannot intercept or replace the
capability. Armed snapshots now conditionally authenticate the Exact manifest
as a fifth protected artifact and carry exact app, agent-isolate, and empty
UI-worklet ID sets. The setter validates that three-way binding before any JSI
or callback-state mutation. The public artifact-preparation ABI authenticates
an already-built pair against the checked registry, loaded engine, package
graph/root objects, and protected artifacts, then replaces its construction
nonce and digest; it cannot advertise a target. A second target-local preparer
now strictly validates Exact's raw operation manifest, derives the complete
three-context projection without a caller allowlist, materializes those bytes
as the fifth protected artifact, and re-authenticates the fresh pair. Exact's
Apple and Windows consumers use this seam. The normal target-local producer now
builds the complete pair directly from the installed app root, loaded engine,
checked registry, canonical empty package policy/graph, and strict Exact
manifest; it therefore does not package stale filesystem identities. Exact's
protected-artifact publisher uses the target's real durability boundary after
the content-addressed hard link is installed: Unix syncs the parent directory,
while Windows re-flushes the still-pinned file object because Rust's ordinary
file API cannot open a directory for `sync_all`. Both paths validate the
read-only file and its exact bytes before publication; this portability split
does not relax artifact identity or immutability. Exact's bundled-root producer
is complete. The former additive `exactGpuProvider` builder/profile path was a
WebGPU-specific one-off and was removed by LLP 0040. Selected runtime
extensions now enter through the generic, product-neutral authority
template/capsule projection: the launcher binds the complete descriptor,
linked-artifact, provider-ABI, global/module, operation, callback, and
loaded-executable facts before arming. An unselected build has no
runtime-extension capsule or extension library. Package-bearing policy input
remains a separate future contract. Apple/Windows conformance reports and target
advertisements remain incomplete. The merge reconciles both per-target
catalogs from the source registry before retaining evidence; point counts from
either pre-merge catalog are not publication authority. Windows differences
remain explicit target-applicability or unauthored-path facts, and none is
credited as a pass. The latest source-bound tranches add 322 armed shared-runtime global
absence recipes, nine armed direct-native global absence recipes, 18 physical
no-debugger ABI closure recipes, 106
terminal-builtin closure recipes, four public SQLite extension-load and
cr-sqlite enablement closure recipes, four
loader/source-acquisition recipes, 19 native module-runner ABI
lifecycle recipes, one armed namespace-inspection closure, two armed
whole-environment zero-decision branch recipes, 14 asymmetric/EVP
crypto recipes, eight
owner-authenticated timer-control recipes, nine bounded authority-control
refusals, six retained HTTP/process owner refusals, two owned filesystem-close
executions, three incomplete/invalid authority-control refusals, one loader-private
post-capture absence, five cached
system-information authorization scenarios and twelve asynchronous path-operation scenarios for
the `readdir` and `realpath` branches, twelve retained-file `chmod`/`utime`
scenarios, five retained-target direct `statfs` scenarios, twelve complete
malformed/attribution/principal scenarios for retained metadata and whole-file
reads, thirty-six complete malformed/attribution/principal scenarios for system
information, environment, and stdout, three complete adversarial loopback TCP
connect scenarios, plus five zlib stream lifecycle recipes, eleven TLS lifecycle
recipes, and a principal-owned network stamp recipe. Ten internal locale and
accessibility state-object surfaces no longer exist: normalized mutable state is
held in module singletons while host snapshot inputs and update hooks remain
explicit globals. Thirteen memory-debug implementation surfaces likewise no
longer exist: the timer, samples, counters, and options are captured behind the
deliberate `__exactMemoryDebug` diagnostic API in unarmed tooling, while armed
lockdown removes that facade before project code. Six `__OriginalPromise`
surfaces likewise no longer exist: rejection tracking
retains the unwrapped constructor in its install closure instead of publishing
a project-visible bypass around the wrapped global constructor. Eleven
write-only process-compatibility diagnostics likewise no longer publish
bootstrap progress, fallback objects, or exception strings to project code;
the sole control predicate is local to the compatibility IIFE. The
decompression unhandled-rejection filter sentinel is module-local as well,
rather than a project-writable global. Bundled-entry remap consumption is now
tracked by exact host entry-path value in the trusted module-loader closure
while the host entry-path input remains explicit. The libuv EOF value is now an
immutable constant at both internal consumers rather than a project-writable
transport sentinel. Readable-stream compatibility retry scheduling is likewise
captured inside bootstrap rather than exposed as a mutable global. The resource
recipes create, exercise, and release their runtime/principal-owned
native state in one bounded invocation. Fourteen Linux/Android-only
`node:constants` exports now carry source-bound Apple absence evidence from the
real public module path rather than remaining generic availability residuals.
Async evidence remains open through a bounded event-loop quiescence drain and
binds both the dispatch edge and the worker edge actually observed at runtime.
The armed `mkdtemp` family remains unresolved: its returned generated path is
not yet retained and authenticated strongly enough for the executor to remove
the created directory, so it cannot claim safe public execution or cleanup.
Both candidate matrices therefore remain unsupported;
this partial implementation is not grounds to promote a target or retain
production benchmark evidence.

The source-bound native-read harness admits inherited members only for 57
static data constants whose descriptors prove the exact property path. Runtime
evidence records the owner depth for every path segment and requires a positive
final depth; own-property substitution, inherited callables/accessors, instance
members, and dynamic tables remain rejected.

The builtin route analyzer now admits module bindings only when their source
initializer is recursively proven intrinsic and the binding is never
reassigned. This reduces `ambiguous-static-enforcement-route` from 7,496 to
7,092: an opaque reassignment still fails closed, and removing false route
ambiguity is not itself public execution evidence. The later terminal-builtin
denial tranche resolves 106 exact source and alias facets before module evaluation,
including 49 otherwise ambiguous call graphs, so the current residual counts
are 7,043 ambiguous routes. The current Apple catalog has 23,815 required,
2,469 executable, and 21,346 unresolved fixtures; Windows has 23,700 required,
2,327 executable, and 21,373 unresolved fixtures. Nine direct native
compatibility, diagnostic, IPC, signal, process, and working-directory globals
are now deleted after lazy installation on the armed lockdown path, and their
exact source-derived JSI cells prove physical absence. The armed runtime also
deletes the configurable `Exact.accessibility` and `Bun.accessibility`
application-state namespaces after trusted shared-runtime installation and
before the compartment baseline is finalized. Accessibility snapshots,
notification hooks, and module-local state remain available to trusted web and
React Native compatibility modules, while all 28 source-derived public
namespace/member cells prove physical absence. Change-listener registration is
closed with the rest of the namespace because future callback payloads cross
the same ambient embedder channel; it is not merely attribution plumbing. The
armed runtime further deletes `BroadcastChannel`, `MessageChannel`, and
`MessagePort` after trusted bootstrap captures any internal constructors. All
29 inventoried constructor/member cells prove physical absence without
breaking the unarmed diagnostic compatibility runtime. The physical
no-debugger tranche also executes all nine debugger ABI functions on both exact
candidates and binds their nine corresponding native-operation facets to the
same zero, null-pointer, or no-event results; the Windows `get_scripts` stub
returns no debugger data. Together with the other closed families, the
preceding messaging checkpoint carried 386 closed fixtures per exact target,
and the loaded Apple engine passed all 386 with zero typed or legacy decisions.
Cache Storage, Web Storage, and IndexedDB now follow the same physical-absence
rule. The armed runtime deletes all 13 ambient storage roots while diagnostic
runtimes retain them. Sixty-three helper, callback, and release members that
were previously labeled non-capability are now closed with the object graph
that would mint them; this removes 180 inapplicable callback-invariant
obligations instead of pretending those unreachable members are independent
APIs. The 232 source-derived storage cells raise each exact target to 618
closed fixtures; the loaded Apple engine passes the complete batch with zero
typed or legacy decisions. Its 2,800-fixture callback-invariant batch binds the
current source-derived shape: 507 fixtures for each of four target-wide
scenarios, 382 for each of two authority scenarios, and eight non-capability
controls. The application runtime
does not install the worklet-only `worklet`, `measure`, or
`scheduleOnAppRuntime` namespaces. Eleven exact source facets now prove that
runtime-variant boundary through physical absence, including `worklet.clamp`
and `worklet.lerp`, which are closed with their absent namespace rather than
misreported as independently reachable pure helpers. This raises the exact
closed batch to 629 fixtures without treating worklet-runtime reachability as
application-runtime authority. The exact SQLite refusal tranche then executes
both `loadExtension` and `enableCrSqlite` through the `Database` and default
exports, using in-memory databases through both public module aliases. Each
exact target now carries 633 closed fixtures without constructing filesystem
authority or loading native code.

Six retained TCP metadata/control operations (`__exactTcpLocalAddr`,
`__exactTcpRead`, `__exactTcpRemoteAddr`, `__exactTcpSetKeepAlive`,
`__exactTcpSetNoDelay`, and `__exactTcpWrite`) have two actionless logical
`metadata` fixtures apiece. A physical loaded-engine audit drove each family
through a harness-owned loopback client and found that the native operation
emits the retained socket's `repeat` decision. The evidence validator therefore
correctly rejects a zero-decision recipe: those twelve cells remain residual
until the semantic registry binds the retained lease action/resource/owner to
the logical fixtures (or explicitly reclassifies the branches). UDP address and
WebSocket release require their own retained-owner setup and were not inferred
from the TCP result.

### WP0 artifacts and gate

The schemas, registry inputs, examples, invalid goldens, and generated legacy
table live under `capsec/`. `contract-files.json` is a closed inventory of every
schema, registry, example, invalid fixture, and generated artifact; an unlisted
or missing file fails validation, and every registered invalid fixture must be
executed and rejected.

`capsec-contract.mjs` rejects duplicate keys, validates Draft 2020-12 schemas,
checks cross-file action/resource references, requires selector and occurrence
examples for every authorable resource kind, requires containment vectors for
every handle/dynamic resource kind, and joins definitions to normalizers and
coverage edges exactly. It also checks all five digest vectors, keyed canonical
sets, target cells, armed graph/root/binding/protected-object invariants, and an
exact one-to-one reconciliation with live rows inside
`CAPABILITY_BIT_DEFINITIONS`; commented or outside-constant Rust lookalikes are
not authority. `--check` is non-writing and participates in the repository's
single generated-drift gate.

## Implementation plan

The work is organized around stable work packages so Linear tickets can remain
connected to this document even if ticket titles or implementation details
change. Each package lands tests and generated outputs with its code; a later
phase does not postpone testing an earlier one.

### WP0 — Freeze the target semantics and registry contract

Define the Ibex destination vocabulary and the schemas for capability
definitions, effects, authority selectors, effect occurrences, coverage edges,
target cells, policy rules, canonical policy, and armed snapshots. Adapt Oden's
semantics deliberately rather than copying Oden/Deno-only surface rows.

Decide the initial disposition of every existing Ibex capability: authorable,
deny-only/closed, absent, unsupported, or non-capability. Settle exact versus
tree path semantics; fetch/connect/listen/resolve endpoint resources; process,
stdio, inspector, storage, device, crypto, and runtime-internal categories; and
which rows are terminal, static-only, handle-delegable, or dynamically
acquirable.

Acceptance:

- Schemas and canonical examples cover every initial authorable resource kind.
- Every current capability bit has an explicit destination disposition.
- Positive action wildcards and untyped canonical strings are impossible.
- Decision precedence, principal intersection, staged effects, handles,
  revocation, caching generations, and digest domains are specified.

Implementation: frozen by ENG-24144 in `capsec/`; validation is
`bun run check:capsec-contract` plus
`bun test packages/ibex-devtools/src/scripts/capsec-contract.test.mjs`.

### WP1 — Generate the registry and completeness inventory

Implement the four generated datasets, code generation, drift checking, and the
surface inventory. Seed the inventory from native host calls, loader branches,
builtin exports, startup/inspector paths, callback queues, and resource families.

Acceptance:

- Every inventoried surface has exactly one coverage edge or explicit
  non-capability/closed classification.
- Adding an unclassified surface or unknown capability fails generation/CI.
- Generated bindings and documentation are byte-reproducible.
- Target cells begin honestly as unsupported/closed until fixtures prove more.

Implementation: ENG-24145 generates the production coverage registry, exact
candidate-target product, source-surface/fixture-obligation manifest, stable-ID
schema, review tables, and Rust/C++/JavaScript/TypeScript bindings. Discovery is
source-derived across native globals, public host/embedder/worklet ABI,
builtin exports, installed globals, loader branches, callback producers,
startup installers/scripts, inspector operations, and CLI commands. Unknown
surfaces/actions/normalizers fail generation; source filenames never choose a
semantic classification. `bun run check:capsec-registry`,
`bun run check:capsec-contract`, their focused tests, and the repository drift
gate are non-writing checks.

Implementation alternatives retain their source-derived target variant,
normalized applicability, backend/stub disposition, and a globally unique
branch ID. Every target cell lists the exact applicable branch IDs even while
unsupported; fixture obligations are scoped to those branch IDs. Promotion
must execute the complete obligation union for exactly that source-derived
branch set. Unknown, wrong-target, omitted, or invented branch evidence fails
validation, while a branchless target can advance only to target-proved
`absent`. A known `unsupported-stub` branch cannot promote. Weak-fallback and
source-uncertain provenance are resolved only by the WP10 report's executed
obligations bound to the exact target binary; they are not conformance evidence
by themselves.

The ENG-24145 baseline contains 6,804 logical surfaces and coverage edges,
6,984 implementation-branch rows, and 11,048 source references. It includes
2,823 builtin surfaces: 2,696 export/prototype/inherited-shape APIs plus 127
specifier aliases. Inherited CommonJS and authored shared-runtime class shapes
are traversed exactly when their base is source-resolvable; otherwise a
review-bound dynamic-table sentinel closes the entire inherited property domain.
Builtin enforcement-route discovery likewise follows only immutable source
provenance: direct calls, constructor bodies, locally authored callable
alternatives, and literal CommonJS dependencies joined to the exact manifest
source key and export. Reassigned or computed dependency receivers, opaque
callable alternatives, intrinsic mutation, and unresolved cross-source exports
routinely remain explicit ambiguities. The bounded `dns/promises` exception
projects exactly 42 callable carrier rows from the structurally reviewed
`node_dns` provider plus three provider Resolver `_handle` instance rows. Both
complete source ASTs, their exact source keys and paths, and the projection
schema are bound to a pinned inventory digest; the semantic classifier carries
an independent hardcoded digest and exact 45-name review set. Any one-sided
source, scanner, metadata, or classifier drift therefore fails closed. The
projection does not invent a call route: every row retains one explicit
carrier/provider or constructor-instance ambiguity and no terminal. Multiple
source-proven terminals are retained
rather than guessed away; WP10 still requires bounded public arguments to show
which route the bound engine actually executes.
It also includes 178 host-ABI surfaces: the complete 84/36/10
`ex_host_*`/`ex_hermes_*`/`ex_worklet_*` families, one `ex_android_*` entry,
and 39 Java plus 8 JNI Android bridge routes. All 6,804 candidate-target cells
are unsupported; 760 known
parameter/provenance-dependent effect edges are explicitly
`conditional-unrefined` and therefore unpromotable.

Generator hardening now makes the reviewed/discovered join bidirectional,
rejects overlapping logical-branch predicates (including subset and
cross-fact overlaps), fails on unrouted fixed rows and Android provider
overloads, understands adjacent C++ literals and digit separators, and derives
implementation branch identity from the target variant rather than mutable
source-reference paths. Provenance remains digest-bound without becoming the
semantic identifier.

### WP2 — Implement the typed policy and decision core

Replace string parsing and matching with the typed Rust semantic core. Implement
canonicalization, deterministic serialization, digest computation, decision
precedence, conjunctive decision sets, staged decisions, principal
intersection, negative generations, and cache keys.

Acceptance:

- Property and differential tests cover canonicalization and matcher behavior.
- Unknown/malformed definitions fail in every mode.
- Adding a future vocabulary action cannot widen an existing positive policy.
- The decision core consumes normalized typed effects, never authored strings.

Implementation: ENG-24146 adds the product-neutral `crates/capsec-semantics`
workspace member. It strictly ingests the frozen WP0 definitions/rules, uses
RFC 8785 canonical bytes and domain-bound digests, validates typed selector and
occurrence semantics, evaluates every deny stratum before positive authority,
intersects constrained principals, conjoins effects, rejects speculative stage
facts, binds revocation/dynamic/handle generations, and keys decisions by the
complete frozen semantic identity. Rust golden and property tests consume the
same WP0 fixtures as the JavaScript/schema validator; CI runs the focused Rust
test and clippy gates without requiring a Hermes build.

The action-definition `selectorConstraints` fields are executable semantics in
the Rust core, not schema commentary: the same validator now governs armed
floors, denials, process/escalation ceilings, handles, dynamic grants, and
normalized occurrence requests. A corpus test routes every declared invalid
fixture through the corresponding strict JSON, selector, or occurrence ingress.
Principal and every other semantic set now use one JCS-byte order at engine,
host, and core boundaries. IPv4-mapped IPv6 values canonicalize to their
embedded IPv4 identity, RFC 8785 number bytes use ECMAScript tie-breaking, late
listen/device facts are required only when their stage produces them, and the
decision cache is bounded and generation-evictable.

### WP3 — Rebuild policy generation and import-site authoring

Adapt LLP 0014's import-site generator to emit authored-source inputs and the
typed canonical review policy. Preserve provenance, root-only grant authority,
request/delegation intersection, union across authorized root import sites, and
explicit import/endowment surfaces.

Acceptance:

- Generated policy contains every package in the integrity-bound graph.
- Every grant has source/delegation provenance.
- Package code cannot self-grant through import attributes or manifests.
- Drift reporting distinguishes authority expansion, narrowing, and semantic
  vocabulary changes.

Implementation update (2026-07-12): policy authoring reuses the contract's
action-specific selector validator. Drift review performs containment-aware
diffs for floors, denials, ceilings, package/builtin imports, endowments, and
principal identities, classifying expansion, narrowing, mixed, identity, and
vocabulary changes. Every semantic set uses canonical UTF-8/JCS byte order.

### WP4 — Arm immutable snapshots through the CLI, host, and engine

Build the trusted arming pipeline that binds canonical policy to an execution
and hands the authenticated immutable snapshot to the host/engine. Report the
actually loaded profile and digests from the decision context.

Production runtime construction owns `runNonce`. After authenticating any
supplied snapshot template, it discards the artifact/caller nonce, generates a
fresh 128-bit value with the operating-system CSPRNG, and finalizes the armed
digest before handing the snapshot to the host and engine. Fixed nonces remain
valid only in contract fixtures; RNG failure refuses construction.

The same construction boundary owns every compatibility input that may affect
trusted bootstrap shape. It reads an admitted launcher control at most once
before arming, normalizes it into the closed, sorted
`bootstrapCompatibilityModes` set, and includes that set in the final snapshot
digest. After arming, native bootstrap receives only the authenticated fixed
projection: it does not reread the launcher environment, and its temporary
carrier is sealed before project code. These modes grant no authority and are
not environment entries.

The snapshot separately requires `environmentBase: []`. An armed runtime never
copies the host process environment into JavaScript or falls through to it.
Values created during execution live only in a runtime-scoped map keyed by the
authenticated principal; exact-name read, write, and non-empty enumeration are
independently authorized at their requested and commit stages.

Acceptance:

- The runtime refuses before project code on stale/mismatched policy, registry,
  engine target, package graph, or required target cell.
- Mutable authored files and environment variables are not consulted after
  arming.
- The environment base is explicitly empty, and compatibility shape is a
  digest-bound fixed-mode projection rather than an environment backchannel.
- Audit, denial, handle, and dynamic-permission records carry the loaded
  semantic identity and snapshot generation.

Implementation status (2026-07-12): Rust ingestion checks the WP0 root,
authority/graph-edge, root-binding, and four protected-object invariants and
uses the checked digest contract's semantic-set canonicalization. Production
derives exact target cells from authenticated registry data; because every
current cell is unsupported and no target is advertised, ordinary execution
refuses before project code. Arming measures the artifact containing the loaded
Hermes factory, requires structural lockdown/compartments/frame attribution,
uses per-run nonces, rejects every generated closed startup control, and binds
an immutable Host context to each runtime. The old unarmed constructor is
non-executable. Package principals are stamped only after exact locator,
resolved root, and whole-tree integrity verification; package-to-root imports
require an exact authenticated graph edge. Default project-root discovery
selects only a canonical ancestor containing `package.json`; a manifestless
entry must receive an explicit trusted `--project-root` and otherwise refuses
before policy construction or project evaluation.

Implementation update (2026-07-12): canonical policy now carries the exact
registry digest as well as vocabulary identity. Production strictly
deserializes the complete typed artifact, recomputes its self-digest, validates
every authority against current definitions, and refuses independently
recomputed stale vocabulary or registry policies before projection. Bounded
process ceilings containing package logical roots expand into one bound row per
authenticated package principal rather than losing their owner identity.

Implementation update (2026-07-17): the semantic decision set now carries a
distinct root-authority-ceiling stratum before principal denials. Canonical
policy v2 root-ceiling rows populate it only for the authenticated root;
fixtures prove an empty bounded root ceiling denies `AmbientRoot`, a matching
row permits it, and package floors are unaffected. `ArmedSnapshot` also admits
strict embedded protected-artifact facts, enforces the host/embedded role union
and per-object range non-overlap, and cross-binds role, object, range, and
digest in `ExpectedArmingIdentity`. The arming ABI is
`ibex-capsec-arming-2-root-ceiling-embedded-ranges-bootstrap-seal`.
`ArmedSnapshot` also binds a strict immutable root-only bootstrap authority
floor. Its positive stratum requires an evaluator-owned one-way token and
bootstrap matches cannot fall through to `AmbientRoot`; retained context clones
therefore deny the same effect after sealing. Hermes requires the active Host
to consume the token exactly once after armed-posture verification and before
application attribution. Production boot construction intentionally publishes
an empty bootstrap floor: the current bootstrap performs no root-attributed
capability effect, and its authenticated runtime inputs execute under the
transparent runtime principal. Inventing a positive selector would widen
authority rather than complete the mechanism. The one-shot token,
seal-before-application transition, nonempty-floor semantics, and
retained-context denial remain covered by mechanism tests; any future
root-attributed bootstrap effect must add its exact selector and a real
application-level retained-callback fixture in the same change.

Implementation update (2026-07-25): `ArmedSnapshot` strictly ingests the
optional runtime-extension authority capsule and requires a
`runtime-extension-authority-capsule` protected role. `ExpectedArmingIdentity`
independently binds the capsule digest and the launcher's actual sorted linked
object/range/content identities; descriptor or linked-artifact substitution
therefore refuses even when an attacker recomputes the outer armed digest. The
protected artifact's `contentDigest` is the ordinary SHA-256 of the exact
materialized capsule bytes; it is intentionally distinct from the
domain-separated semantic `authorityCapsuleDigest`, which is independently
recomputed after strict parsing.
Legacy armed construction may claim only the empty projection. Extension-aware
construction supplies the exact snapshot and authority digests, and the Host
rechecks the latter against the claimed context before any operation. Before
Hermes allocation, the structurally validated C registry must also serialize
its closed identity/surface projection; the Host strictly parses and
exact-compares it with the capsule, so attaching the correct authority digest
to a changed operation, callback, provider, module, global, feature, or
bootstrap table still refuses construction. A
successful generic typed decision mints a random nonzero context-local opaque
lease bound to capsule, namespace, operation, class, canonical resource
digest, and constrained principals; check/revoke and context release cannot
transfer it across constructions. Diagnostic/unarmed Host construction does
not authenticate extensions. Each copied nonempty bootstrap payload is
SHA-256 checked against its capsule-bound canonical digest through a bounded
generic Host ABI before Hermes allocation; invalid, oversized, or mismatched
inputs refuse. Conformance fixtures use an armed test profile through this
same path rather than a permissive bypass.

### WP5 — Convert filesystem effects and checked-object execution

Map all filesystem surfaces to explicit list/read/write/watch effects and typed
exact/tree resources. Replace check-then-reopen paths with retained handles or
verified post-open identities, including symlink, hard-link, rename, metadata,
special-file, and platform alias behavior.

Acceptance:

- Multi-effect operations authorize every disclosure/read/write stage.
- Symlink/hard-link/TOCTOU fixtures operate on the object actually used.
- File descriptors and handles retain owner, authority source, revocation
  generation, and resource identity for repeated operations.

Implementation status (2026-07-11): synchronous and worker-backed async native
`fs.open` now have an
armed-only staged adapter for read, write, create, and truncate. It authorizes
the requested logical path, retains and verifies the resolved parent directory
inside the authenticated logical root, distinguishes existing from
absent-create discovery, and authorizes the operation effects before `openat`.
Final symlinks are closed with `O_NOFOLLOW`; parent symlinks that resolve outside
the authenticated binding are refused. Truncation is deferred until commit has
authorized the actual `fstat` identity and retained descriptor ID, so a denial
cannot mutate an existing or absent target. An explicitly presented typed
bearer ID participates in every stage. Legacy hosts retain their existing gate;
armed refusal never falls back to it. The fd registry retains the parent
descriptor and presented bearer ID, and every armed read or write re-authorizes
at `repeat` against fresh identities and current authority generations. Async
commit runs on the worker before the descriptor is delivered to JavaScript;
registry publication remains on the attributed runtime thread. The remaining
descriptor metadata/disclosure operations (`fstat`, truncate, sync, ownership,
mode, and times, including their worker-backed forms) reuse the retained
descriptor and typed repeat checks. Synchronous and worker-backed whole-file
reads use their own conjunctive registry edges: `fs:list` authorizes requested
path lookup and retained-object discovery, then `fs:read` authorizes commit
immediately before the first byte can be observed and every repeat lease. The
private descriptor open between discovery and commit discloses no file bytes
and does not add a redundant read-discovery decision. Public `Cargo.toml`
allow/deny recipes prove the six-decision component-walk, commit, and repeat
sequence and fail closed at the
first list decision when lookup authority is absent. Whole-file reads accept
only retained regular files. They perform one full repeat decision per
descriptor lease and cheaply compare
negative, dynamic, and handle generations before each chunk; any change
re-enters the full evaluator before more bytes are observed. Leases are local
to the exact operation and retained descriptors, so operation/gate/principal/
object facts cannot collide and descriptor reuse starts a new lease. `stat` and directory
enumeration likewise use retained no-follow targets and their own `fs:list`
edges; enumeration rechecks before every disclosed entry. Worker-backed path
and descriptor stat use the async stat edge and recheck on the worker before
serialization. Sync and async lstat retain the link object itself with
`no-follow-final` semantics. Realpath returns the canonical path of the retained
no-follow descriptor under its own list edge. Whole-file replace,
append, and worker-backed write use their own edges, authorize absent-create or
existing state before `openat`, commit the actual regular file before delayed
truncation, and recheck before each write/flush. The registry's ordinary
`fs:list` lifecycle remains requested/discovery; retained-object Repeat checks
are separately bound to exact native filesystem terminals by the source-authored
internal-observer stage contract. Non-recursive synchronous and worker-backed
directory creation use the `mkdir` edge: they authorize the requested path,
retain and verify the parent, preauthorize absent creation, and create exactly
once with `mkdirat`. A failed post-create check leaves the new, still-empty
directory in place: reopening the name to verify and then calling `unlinkat`
would permit a replacement race, so armed code deliberately performs no
name-bound rollback. Worker-backed single-path `chmod` and `utime` are the
narrow metadata-mutation exception: both retain the target, authorize commit,
and repeat authorization on the worker immediately before `fchmod`/`futimes`.
Their synchronous, link, ownership, and descriptor variants remain closed.
`mkdtemp` also remains closed at the armed public entry point. Recursive
creation remains closed until every created component can run the full
object-bound sequence independently. Path removal
also remains closed in armed execution: retaining a target descriptor and then
calling name-based `unlinkat` would still permit a swap between identity check
and deletion, so sync and async denial fixtures require the original file or
directory to survive until a genuinely race-safe removal strategy is adopted.
The same armed denial fixture covers unported sync and async rename, copy,
symlink, and hard-link paths, proving they cannot mutate either source or
destination through the legacy oracle while their typed staged adapters remain
pending.

Post-review hardening (2026-07-12) preserves ENOENT/ENOTDIR and Node-shaped
denials, avoids read-opening metadata targets and blocking FIFO lstat, shares a
bounded runtime-scoped parent-directory descriptor cache, and rechecks regular
whole-file reads per chunk. Open/create rollback ownership is established only
by successful `O_CREAT|O_EXCL`; state races rediscover and reauthorize before
retry, so a competitor's file is never treated as ours to unlink or truncate.
FD, IPC, and transferable registries bind runtime nonce plus device/inode and
evict stale rows on descriptor-number reuse. Async worker exceptions and result
delivery failures reject instead of aborting or hanging, completed closures
release descriptor captures eagerly, and callback attribution intersects live,
captured, owner, and scheduler principals. Async directory traversal, realpath,
watch polling, recursive-readdir spelling, and non-recursive `rm` parity now use
worker-backed paths; that worker plumbing does not reopen the armed `mkdtemp`,
watch, recursive, or removal entry points described above. Windows preserves
distinct errno values and implements recursive-mkdir results, exclusive copy,
truncate, utimes, and statfs through the portable host ABI.

The first Windows mutation slice is deliberately smaller than the flag's
legacy meaning. Armed `__exactFsOpen(path, "a")` accepts only an **existing**
regular file. It submits `fs:write` Requested before lookup, uses
requested/discovery `fs:list` to authenticate the existing leaf, opens that
leaf with native append-only access and no delete sharing, object-matches it,
then submits `fs:write` Commit with the retained identity and authenticated
package-source generation. An absent leaf returns `ENOENT`; `O_CREAT` is never
exercised. The descriptor registry retains the opaque append-only file,
runtime, owner, principals, bearer, namespace, object identities, and handle
ID. Armed scalar `__exactFsWrite` validates that registry entry before
inspecting caller bytes, submits one `fs:write` Repeat, performs one
short-write-preserving append through the same file, and rechecks identity
after I/O. The JavaScript position argument cannot weaken append semantics.
Requested denial happens before lookup and leaves bytes unchanged; Repeat
denial happens before mutation; a hard-link alias to authenticated package
source refuses at Commit when its retained object/generation joins the
package-source guard. Numeric flags, `"as"`, `"ax"`, read/write modes,
truncate/create modes, positional non-append writes, synchronous vector writes,
and the remaining write-capable descriptor families
remain closed or residual. Worker-backed append writes and synchronous
durability are the bounded exceptions described below.

Armed Windows `__exactReadFile`, `__exactStat`, `__exactLstat`,
`__exactReaddir`, retained `__exactFsOpen`, `__exactFsRead`,
`__exactFsReadv`, `__exactFsWrite`, `__exactFsFstatSync`, and
`__exactFsReadFileAsync`, `__exactFsReadAsync`, `__exactFsReadvAsync`,
`__exactFsWriteAsync`, `__exactFsWritevAsync`, `__exactFsFsyncSync`, and
`__exactFsFdatasyncSync` are the first
installed Windows filesystem effects to leave the legacy path oracle.
Their private
native bridges derive the runtime generation, actor, and canonical
constrained-principal stack from engine provenance, resolve only virtual
syntax, and delegate to the cross-platform `RuntimeVfsSession` retained-object
operations. Whole-file read emits requested/discovery `fs:list` followed by
commit/repeat `fs:read` for the selected object and deliberately inherits the
VFS bounded whole-file input limit. Stat opens the selected object for metadata
only and emits requested/discovery/repeat `fs:list`; the list lifecycle has no
Commit observation, and Repeat runs immediately before Node-shaped metadata
serialization. Stat also handles the authenticated mount root without
inventing a namespace parent. Lstat uses the same three-stage list lifecycle
with `no-follow-final`, stops traversal at a final reparse object, reopens that
object relative to its retained parent for metadata only, and object-matches it
before Repeat and disclosure. Unlike the POSIX adapter's additional root-walk
observations, the retained authenticated mount handle is structural session
state on these routes, so no synthetic observations are claimed.
`VirtualFileSystem::readdir_authenticated` emits requested/discovery `fs:list`,
reopens a nested final directory relative to its retained parent with
`FILE_LIST_DIRECTORY` access and without delete sharing, and object-matches
that handle before enumeration. It queries `FileIdExtdBothDirectoryInformation`
on the retained handle, uses the long name as the sole output coordinate,
validates but never emits the associated 8.3 short name, preserves malformed
UTF-16 as an explicit byte marker, sorts deterministically, and authorizes
Repeat once for each member immediately before adding that name to the returned
listing. The authenticated mount root is already retained and therefore has no
fabricated parent; the synthetic namespace root `/` exposes only mount names
and requires no filesystem authorization. Refused or malformed typed calls
return the VFS error and never fall through to
`exactResolveVfsPath`, `requireReadCapability`, `ex_host_fs_read_file`,
`ex_host_fs_stat`, `ex_host_fs_lstat`, or `ex_host_fs_readdir`.

Read-only `__exactFsOpen` uses the same contained discovery protocol, then
opens and object-matches a regular file for read at Commit. The private Host
ABI returns the exact `File` plus its namespace, retained parent/final object
identities, retained handle ID, canonical virtual path, and presented bearer.
The Windows engine keeps that opaque file behind its existing monotonically
allocated numeric descriptor table together with the engine-derived runtime
and principal owner; JavaScript cannot forge a handle or move it between
owners by guessing an integer. `__exactFsFstatSync` first enforces that registry
ownership, then authorizes one `fs:list` Repeat against the stored parent,
final object, handle ID, and bearer and obtains metadata from the same retained
file. It performs no pathname lookup and cannot fall back to `ex_host_fs_fstat`.
`__exactFsRead` and synchronous `__exactFsReadv` apply the same owner/runtime
and readable-open checks, then authorize one `fs:read` Repeat against those
stored occurrence facts before reading the retained file itself. The vector
route validates at most 1,024 destinations and a `uint32` aggregate length,
acquires one owned aggregate result, and scatters into JavaScript buffers only
after the Repeat and retained-identity postcheck succeed. Sequential reads
advance that file's cursor; positional scalar and vector reads restore it
before returning. The VFS checks the retained object identity before
authorization and after I/O, and the armed engine cannot fall back to the
pathname-based legacy read oracle.
Armed write/create/truncate/append open flags and unsupported numeric flag bits
return `EPERM` before virtual resolution, legacy authorization, or host file
creation. Unarmed compatibility continues to use the existing host path.

Armed `__exactFsReadFileAsync` captures the runtime nonce, canonical
constrained-principal stack, actor, virtual input, and optional bearer on the
runtime thread, and uses that same immutable stack for its native-worker
operation lease and private typed ABI call. The path branch does not resolve or
authorize before dispatch: on the worker, `VirtualFileSystem::read_authenticated`
performs Requested/Discovery `fs:list`, Commit `fs:read`, and a generation-aware
Repeat before each bounded read chunk. Requested denial therefore happens on
the worker before lookup. The descriptor branch retains the owner/runtime-bound
opaque file entry for the operation, holds its per-file I/O mutex from the
current cursor through EOF, and calls
`read_descriptor_authenticated` once per 64 KiB chunk plus EOF. Each call
submits a fresh exact-object `fs:read` Repeat and advances the cursor only after
that decision succeeds. Neither branch can reopen the legacy pathname oracle,
and Promise settlement still occurs on the attributed runtime thread.

Armed scalar `__exactFsReadAsync` and aggregate `__exactFsReadvAsync` use a
separate single-acquisition protocol on both installed filesystem backends.
The runtime thread first validates the owner/runtime-bound readable descriptor,
safe position, and bounded byte count; vector validation inspects at most 1,024
actual ArrayBuffer views and records only their lengths before authorization.
The worker operation lease installs the exact captured principal stack. On
POSIX, one `fs:read` Repeat against the retained parent, duplicated file object,
stored path, owner, and bearer executes immediately before the single
`read`/`pread` or `readv`/`preadv`; vector destination storage is allocated only
after that decision. On Windows, the worker holds the retained file's I/O mutex
and invokes an async-surface-specific typed VFS bridge, which performs the same
exact-object Repeat immediately before acquisition. Both backends return owned
bytes and publish them to JavaScript only after success; the vector facade
validates all destinations before scattering that aggregate. Empty requests
perform no acquisition and emit no decision. Positioned requests preserve the
retained cursor, while a sequential request advances it.

Armed scalar `__exactFsWriteAsync` and aggregate `__exactFsWritevAsync` use the
corresponding worker-side retained-object protocol. The runtime thread first
validates the owner/runtime-bound writable descriptor and snapshots no more
than 1,024 actual ArrayBuffer views with an aggregate host-I/O bound. On POSIX,
the worker submits one surface-specific exact-object `fs:write` Repeat against
the duplicated retained descriptor immediately before `write`/`pwrite` or
`writev`/`pwritev`. On Windows, the route accepts only an existing retained
append-only descriptor, holds its I/O mutex, and passes either the scalar bytes
or one flattened vector aggregate to a surface-specific typed VFS bridge. That
bridge object-matches before the Repeat, appends once, and object-matches again
before returning. Flattening preserves one logical `writev` mutation and
prevents partial authorization across component buffers. Empty scalar and
all-empty vector requests return zero without a typed decision.

Synchronous descriptor durability now has the same exact-object boundary on
both installed backends. `__exactFsFsyncSync` and
`__exactFsFdatasyncSync` validate a retained writable descriptor and submit one
`fs:write` Repeat attributed to their own distinct public surface edge
immediately before `fsync`/`fdatasync` or `sync_all`/`sync_data`. Windows holds
the retained file's I/O mutex while the private VFS bridge object-matches,
authorizes, flushes, and rechecks. POSIX uses the retained parent plus the live
descriptor identity immediately before its syscall. Durability does not borrow
the prerequisite open edge, and cleanup remains outside the decision window.

This is a bounded slice, not Windows filesystem promotion. Unsupported
write-capable open modes, synchronous vector/positional mutation, and the other
installed Windows filesystem routes remain residual until their own
retained-object contracts are implemented.
Those residual routes are nevertheless closed in armed execution. The
installed `__exactWriteFile`, `__exactMkdir`, `__exactRealpath`,
`__exactReadlink`, `__exactAccess`, `__exactTruncate`, `__exactStatfs`,
path and descriptor forms of `__exactFsWriteFileAsync`, every operation
selected through `__exactFsPathAsync`, and every target kind selected through
`__exactFsStatAsync` return structured `EPERM` before path conversion,
descriptor lookup, caller-buffer acquisition, worker dispatch, or legacy
capability probing. On a target without a typed synchronous
`__exactFsWritev`, the JavaScript `writevSync` fallback invokes the
bootstrap-captured armed mutation guard before decomposing the vector into
scalar writes. Unarmed compatibility and the typed retained-object Windows
routes listed above are unchanged.
Exact-target recipe generation now
schedules the five `__exactReadFile`, five `__exactStat`, and five
`__exactLstat`, five `__exactReaddir`, six read-only `__exactFsOpen`, and four
`__exactFsRead`, four `__exactFsReadv`, plus four `__exactFsFstatSync`
scenarios on Windows. It also schedules eleven executable
`__exactFsReadFileAsync` rows: all six path scenarios and five descriptor
scenarios; descriptor denial remains residual because the same denied floor
cannot create its required retained setup handle. It additionally schedules
four executable retained-descriptor rows apiece for `__exactFsReadAsync` and
`__exactFsReadvAsync` on both targets; each deny row remains residual for the
same source-setup reason. It also schedules four executable rows apiece for
`__exactFsWriteAsync` and `__exactFsWritevAsync` on both targets, plus four
apiece for `__exactFsFsyncSync` and `__exactFsFdatasyncSync` on both targets.
Each deny row remains residual because the denied `fs:write` floor cannot
construct its prerequisite writable descriptor. The generator continues to
classify the remaining 142 callable Windows filesystem
recipes under
`public-surface-filesystem-not-typed-on-target`; five `__exactAppendFile`
recipes remain under the more exact
`native-public-operation-not-installed-on-target` build-source boundary. The
corrected Windows catalog is 23,505 required / 2,453 fully executable / 3,122
internally verified / 17,930 unresolved with digest
`sha256-Pc_rPPo2gn0lrqXTz6uXaz_x-lpoHBLXPUpeIKmUU4M`. It no longer promotes
19 private native module-runner lifecycle ABI rows while LLP 0026 keeps
Windows compatibility-only. Apple is independently shaped at 23,846 / 2,799 /
3,136 / 17,911 with digest
`sha256-hzFaFp6ca8rOPfB-aswmofNj87HnLQAhzJZgbDPfvg0`. The six new required
rows on each target are the landed `compat --probe` CLI surfaces; they remain
honestly unresolved until an exact public invocation is authored.

Integrating the lockdown error-prototype override repair changed the
source-derived taming digest to
`sha256-db554fcb6c9c245527ee92fc34988671b3797dfa15676ad75e72a3734ffd6c5c`
and the reviewed evaluator identity to
`hermes-evaluators.3e6954de6300cf7cbd32f27af9077c4a0a55dc951e106a44a991791846e9971f`.
The reachable evaluator family and all three reviewed engine profiles remain
unchanged. The identity composition changes catalog digests but not semantic
counts; the six landed CLI surfaces account for the count increase above.

The Windows TCP connect path now uses the typed network adapter. `Requested`
authorizes the caller's host/port before DNS, `Candidate` authorizes every
member of the complete canonical resolver set before its connect attempt, and
`Commit` binds the selected candidate to the actual peer returned by
`getpeername`. The retained socket records a monotonically allocated socket
identity, runtime/owner identity, selected candidate, verified peer, and exact
connection id. Every armed read or write obtains a stable generation bracket,
rechecks the current peer, submits a full `Repeat`, revalidates the same
registry entry and connection id, and holds the registry lock through the
WinSock operation so close and numeric-socket reuse cannot race the effect.
Release remains authority reducing and checks ownership without requiring live
policy authority. The five staged `__exactTcpConnect` scenarios and the three
zero-decision close/reset/shutdown lifecycle scenarios are now executable on
Windows. Target-aware recipe binding selects the installed Windows JSI source
descriptor rather than borrowing the default POSIX translation unit.

The non-capability `__exactTcpClose`, `__exactTcpReset`, and
`__exactTcpShutdown` probes execute against an exact loopback socket produced
by that typed Windows connect path. They remain zero-decision observations:
setup supplies the required authority, while lifecycle release cannot mint or
widen it. The sole remaining
`native-public-prerequisite-not-typed-on-target` row is the unrelated Windows
filesystem close setup.

The Windows network translation unit registers `__exactUdpSocket` and
`__exactUdpClose` as explicit throwing placeholders; their real operations
exist only in the default Unix network source. Both non-capability recipes
therefore remain residual under
`native-public-operation-not-installed-on-target`. A callable placeholder is
not execution evidence for a returning operation, and close must not borrow a
socket from a producer that the target explicitly refuses.

Windows also substitutes eight platform-specific translation units for the
default filesystem, crypto, DNS, process, network, OS-info, debugger, and
process-setup backends. Source inventory retains both sides of that build graph,
so a source-discovered default registration alone cannot authorize a Windows
public invocation. Recipe generation intersects native installation branches
with the sources `build.rs` actually compiles and keeps 37 recipes across 33
default-only globals residual under
`native-public-operation-not-installed-on-target`. This includes
`__exactGetProcessRSS`, the first physical mismatch, plus the default-only
asymmetric crypto, performance, signal, Brotli, and async-close surfaces later
in the same batch. Duplicated globals with a real Windows installation branch
remain scheduled. These residuals are neither target-absence passes nor
evidence for an uncompiled enforcement branch.

Exact-target conformance snapshots, including startup-environment and callback
package-root overrides, now derive test root-binding components and object
identity through the production host helpers on every platform. The
previous test helper retained only `Normal` path components and refreshed
object identity only on Unix; on Windows that dropped the drive prefix from a
canonical temporary project root, so authenticated module-graph capture could
not match the bound logical root. Reusing the production encoding preserves the
Windows prefix and pinned file identity without introducing a test-only path
model. Conversely, reconstruction of a Windows host-bound logical path seeds
the native path from that volume or namespace prefix plus its root separator;
pushing the prefix into an already separator-rooted `PathBuf` collapses the
drive and leaves module resolution rooted at `\\`. Module-specifier query and
fragment stripping likewise begins after the Windows verbatim namespace prefix
(`\\?\`), so the prefix's question mark cannot truncate an authenticated entry
path before resolution. At Oxc and external JavaScript-tool compatibility
boundaries only, canonical verbatim drive and UNC spellings are projected to
their ordinary Windows equivalents. Oxc results are canonicalized immediately
after resolution, and tool scripts are selected and authenticated before
projection, so authenticated paths and identities remain canonical and
unchanged outside those compatibility boundaries. Checked-in module-runner and computed-candidate
fixtures whose bytes or canonical JSON text are authenticated are explicitly
LF-normalized by Git, keeping those authority and golden comparisons identical
on Windows and Unix checkouts.

The Windows Oxc boundary is now backed by retained-handle traversal rather than
ambient pathname queries. It retains the authenticated project/package root,
opens every ordinary component relative to that handle without following
reparse points, and object-matches each directory witness/reopen pair. For a
Microsoft symlink or mount-point reparse, it reads the payload through the
witnessed no-follow handle, reopens and object-matches the same component,
requires an identical second payload, normalizes the complete target plus
pending tail beneath the retained root, checks denied principal subtrees before
lookup, and restarts traversal from the root handle. Oxc `read_link` receives
only an ordinary drive/UNC or relative spelling whose destination has already
passed those boundary checks. Unsupported provider tags, malformed or changing
payloads, outside targets, and excessive depth remain refusals.

Package manifest semantics still come only from strict VFS-captured bytes or
explicit absence, and `NODE_PATH` remains disabled. This makes authenticated
entry, relative, `#imports`, package-export, and contained symlink/junction
resolution executable on Windows and lets the closed module-runner fixture use
the same graph builder and authorized linker as Unix. It does not promote the
target. Windows now binds the digest-identified `windows-ascii-casefold-v1`
function into authored selectors and occurrences; the resolver compares captured
manifests, absences, and denied subtrees in the same coordinate while retaining
lexical display and SourceId. Non-ASCII and tilde components refuse before lookup,
and every retained traversal directory must successfully prove that its
per-directory case-sensitive flag is clear. This closes ordinary ASCII case
aliases without collapsing hard-link entries. Administrator-assigned 8.3 aliases
that omit `~` are closed by the retained relative-open protocol: stage the
parent entry's long name, short name, and 128-bit file ID; refuse a short-name
selection; open no-follow without delete sharing; then repeat and object-match
the entry. Query failure and replacement refuse. Installed Windows
`node:fs`/native filesystem effects still lack the typed retained-object adapter,
and the exact target public-evidence catalog remains incomplete.

Filesystem path occurrences now retain a non-wire projection for every
constrained principal, keyed exactly to the constrained set and effect index.
Every authority stratum uses that principal's projection, so two packages with
the same package-relative tail cannot borrow one another's self grants. Arming
also derives hard-deny `fs:write` path-tree guards for every package binding in
every authenticated principal's view, including nested package layouts. These
lexical guards make installed package source immutable without attempting to
enumerate inodes or assuming that hard-linked files have distinct identities;
first-party project paths outside package bindings remain writable. A foreign
nested package is a shadow boundary rather than part of its ancestor's package
tree, and colliding physical package bindings refuse. Aliases outside all
registered package spellings remain a distinct integrity problem rather than a
claim made by the lexical guard.

### WP6 — Convert network effects and protected peers

Map fetch, raw/bidirectional connect, listen, and standalone resolve to separate
typed resources. Authorize requested endpoint, selected candidates, redirects,
reconnects, routes/proxies, listeners, and final verified peers at their stages.
Add an engine-level protected metadata-peer guard with only an exact loud
exception if Ibex needs one.

Implementation status (2026-07-11): the armed host now constructs typed
`network:fetch` decision sets for requested and candidate stages using the
authenticated principal stack, concrete scheme/host/port, resolved candidate
set, selected candidate, and optional verified peer/connection facts. Candidate
authorization applies selector peer classes, while an independent host guard
unconditionally rejects metadata-service and unspecified selected or verified
peers. Live fetch remains closed until the transport adapter can report and
recheck the actual connected peer; requested-host authorization alone is not
treated as sufficient enforcement. The host also evaluates staged typed TCP
connect occurrences under the distinct `network:connect` action and retained
verified-peer/connection facts. A package fixture proves a fetch-only floor
cannot yield raw TCP authority, while a matching connect floor commits the
verified public peer.
The C ABI accepts the complete staged network fact set for fetch and connect,
maps authenticated numeric frame stacks to typed principals, and rejects
noncanonical host/IP text, duplicate-key or ill-typed candidate JSON, invalid
ports/stages/transports, and unsafe redirect counters before host evaluation.
The synchronous POSIX TCP adapter now uses that ABI end to end: it authorizes
the request before resolution, submits the canonically sorted complete
`getaddrinfo` candidate set, authorizes each attempted address, verifies
`getpeername` at commit, retains the candidate/peer/connection facts with the
socket handle. The first later I/O, and each generation-lease renewal, verifies
the immutable connected peer with `getpeername`; stable later I/O pins the exact
socket registry identity through the syscall without copying the retained
candidate/peer strings. Retained socket use reuses a full repeat decision only
for the exact peer and principal set while all mutable authority generations
remain unchanged; a generation or deputy-set change forces a stable
before/after redecision and another peer verification. The nonblocking POSIX path applies the same request and
candidate gates, registers only a pending handle, and withholds read/write
authority until poll observes successful `SO_ERROR`, verifies `getpeername`,
and commits the peer. Pending handles may only be polled or closed. Armed
local-bind options remain closed pending their own typed effects. Windows, TLS,
WebSocket, and the remaining UDP adapters are not yet migrated. POSIX unconnected UDP sends
are gated under their own registry edge: only canonical literal IPv4/IPv6
destinations are accepted, and the first datagram authorizes requested,
candidate, and committed destination facts immediately before `sendto` through
one parsed and attributed ABI call. Repeated datagrams reuse that complete
decision only for the same socket identity, literal host/port, canonical
principal set, and unchanged negative/dynamic/handle generations. Endpoint,
principal, revocation, or handle-generation changes force a stable
before/after three-stage redecision; the registry lock pins the fd through
`sendto`, so close/reuse cannot consume the lease. A bounded live fixture proves
sixteen identical datagrams require only one three-stage decision, revocation
forces exactly one renewal, and a metadata destination is rejected before
transmission. UDP bind/receive/listen authority remains
unmigrated and closed in armed execution.
One live armed closure fixture exercises the remaining transport families at
their native boundaries: fetch, standalone DNS, WebSocket, TCP listen, HTTP
serve, Unix connect/listen, and UDP bind all refuse before an external effect;
the Unix socket path remains absent. Together with the positive TCP-connect
and per-datagram UDP fixtures, the initial advertised network profile is thus
either typed end to end or explicitly closed rather than falling back to the
legacy capability oracle.

Acceptance:

- DNS rebinding, mixed answers, numeric aliases, redirects, WebSocket/raw
  transport, proxy, reconnect, and private/metadata peer fixtures pass.
- A fetch grant never yields raw transport authority.
- A hostname grant cannot silently reach a denied address class or port.

### WP7 — Close loader, process, inspector, stdio, and escape surfaces

Classify and gate typed local imports, dynamic imports, builtin loading,
subprocesses, executable identity, child environment/stdio, inspector routes,
process-global mutation, workers, VM/eval, WASI, FFI/native addons, storage, and
runtime inspection. Unsupported authority is closed rather than represented by
a token the runtime cannot enforce.

Acceptance:

- Static, literal-dynamic, computed, text/JSON/bytes, and CJS loader paths have
  explicit coverage.
- Inspector and runtime-memory surfaces cannot bypass package isolation.
- Terminal capabilities cannot be dynamically granted or delegated through an
  ordinary handle.
- Closed rows have denial/absence fixtures on every advertised target.

Implementation status (2026-07-11): the armed host decodes explicit builtin
and package import axes from the authenticated snapshot. Numeric engine module
IDs bind only to a matching package name plus locator from that snapshot;
unknown or mismatched registrations fail closed. Root and package import checks
therefore no longer consult `PolicyFile` once armed.
Armed runtime construction also rejects every inspector activation and
configuration flag (`inspect`, wait/open/pause, host, and port), including the
duplicate `run`-subcommand spellings, before reading arming artifacts or
allocating the engine. Ambient compatibility switches do not survive that
boundary as mutable controls. The trusted launcher may instead capture the
closed fixed compatibility set into the snapshot before its digest is
finalized; native bootstrap consumes only that authenticated projection and
seals its temporary carrier. The Bun facade is absent by default. When, and
only when, the snapshot includes `bun`, bootstrap installs `Bun` as the same
object as `Exact`; that identity adds no effect authority and cannot be toggled
by a later `process.env` write. Hidden compatibility-fidelity controls that
expose internals or alter process-wide stack/HTTP-parser configuration remain
rejected before armed artifact I/O.
Ad-hoc eval/print, explicit or implicit REPL entry, and debug-registry commands
are likewise rejected at the production dispatcher/runtime boundary before
arming artifact I/O, engine allocation, or evaluation of supplied code.
The trusted compatibility loader exposes parse-free source-lane observability
through `__ibexCompatLoaderStats`, but the armed form is evidence rather than a
mutable project control. Source-transform and dynamic-function-compile counts
live in loader-private state. The visible root is non-writable and
non-configurable, its value is frozen, and its two enumerable members are
getter-only views of those private counters. Package code can therefore read
the lane proof but cannot replace the root, redefine a member, or forge either
count. Unarmed diagnostic loaders retain the accumulating compatibility object
needed by their multi-loader posture. Source and physical armed-Hermes
regressions prove live numeric counts, exact descriptors, failed mutation, and
zero typed decisions.
At runtime armed `process.env` has no broker-base branch. It begins at the
snapshot's explicit empty base and projects only the current authenticated
principal's runtime-scoped overlay. Scalar read, mutation, and each non-empty
enumeration member take exact-name typed decisions at requested and commit;
`env:read` and `env:write` remain independent. A write changes neither the host
process environment nor another principal's overlay, and a fresh runtime starts
empty. Process cwd disclosure uses its distinct `path:cwd-observe` action over
the exact `session-state` / `cwd` selector: requested and commit authorize the
read before `getcwd`, while denial occurs before disclosure. The armed root
realm exposes only `process.cwd`; that public function has captured the sealed
private `__exactGetCwd` bridge, whose own root property remains absent. The
source-derived facade path and both root-global disposition identities are
digest-bound in the loaded-engine fixture. Cwd mutation remains denied without
changing the host process directory. Live armed fixtures cover these
boundaries.
Armed lockdown also seals the shared process-event registry after trusted
bootstrap has installed its internal lifecycle and IPC machinery. The eleven
listener aliases admit only `exit` and `beforeExit`, whose LLP 0025 behavior is
a diagnosed no-op that stores and exposes no listener; any other event throws
`ERR_ACCESS_DENIED` before registry access. Manual emit/warning publication,
event-name and listener-limit inspection, and uncaught-capture mutation are
wholly closed. Both the instance methods and their defining prototype methods
are non-writable and non-configurable, preventing a prototype-call bypass. The
shared-runtime implementation keeps the actual event map and related hook
state in a module-private `WeakMap`, so TypeScript's erased `private` modifier
does not leave a public backing cell. A physical armed-Hermes regression
exercises ordinary calls, prototype calls, attempted replacement, both
lifecycle branches, hidden backing state, and the zero-decision invariant.
WP10 additionally binds each lifecycle case to public execution evidence:
eleven exact methods times `exit` / `beforeExit` times the independently
required branch-selection / no-effect obligations produce forty-four receipts.
Each receipt authenticates the target-local installation branch, the registry
logical-branch predicate, and the final armed gate, then invokes both the
instance and defining prototype. The physical result must preserve the exact
source-defined return (`process`, zero, or an empty array), store no listener,
expose empty listener views, keep both descriptors pinned and backing state
hidden, and emit no legacy or typed decision. The once-per-session diagnostic
remains covered by the shared-runtime lifecycle regression; it is not
fabricated as a per-recipe observation.
The adjacent `process.umask` closure has its own public receipt. It calls both
the read form and a zero-mask write through the captured public binding,
requires the exact `ERR_ACCESS_DENIED` / `ProcessUmask` refusal, proves the
instance descriptor is pinned and `_umask` is absent, rejects replacement, and
observes no legacy or typed decision.
The remaining shared-process compatibility mutators are closed at the same
armed lockdown boundary. `_getActiveHandles` and `_getActiveRequests` use
`ProcessInspection`; `_kill` and `kill` use `ProcessSignals`; `abort` uses
`ProcessLifecycle`; `binding` uses `ProcessBinding`; and `setegid`, `seteuid`,
`setgid`, and `setuid` use `ProcessCredentials`. Each callable is pinned on
both the process instance and defining prototype so neither replacement nor a
prototype call can bypass the refusal. `process.title` and `process.report`
are accessor-closed with `ProcessTitle` and `ProcessReport` respectively.
Title plus the captured uid/gid/euid/egid values live only in the same
module-private process `WeakMap`; their numeric read accessors remain usable,
but armed project code cannot mutate erased TypeScript backing cells. A live
armed-Hermes regression covers the exact permission families, direct and
prototype calls, replacement attempts, accessor descriptors, hidden state,
and the zero-decision invariant. Exact-target receipts for these rows remain a
separate WP10 promotion.
The deliberate memory-diagnostics facade remains available to unarmed tooling,
but armed lockdown deletes `__exactMemoryDebug` and verifies the root is absent
before project code can run. The generated root-global disposition sweep
repeats that absence for the facade and its eight members. This seal is keyed
by the exact shared-runtime closure vocabulary, including the canonical native
spelling produced when the root's global installation and private-native
semantic roles reconcile. A physical pre-hardening failure proved the
reachable facade; a second fail-closed startup exposed and corrected the
dual-role disposition gap. The final loaded-engine receipts traverse
descriptors only, prove all nine paths absent, execute no project code, and
emit no legacy or typed decisions.
The armed diagnostic seal also removes `Bun.inspect` and `Exact.inspect`, whose
pretty-printer can traverse arbitrary object graphs, plus the legacy
`process._uncaughtExceptionHandler` and
`process._unhandledRejectionHandler` cells, which can re-enter the shared
process event registry. Trusted bootstrap code has already captured the
underlying rejection handlers before this seal runs; unarmed diagnostic
runtimes retain all four compatibility surfaces. Root-disposition generation
requires all four paths absent. Exact-target receipts bind both inspector
aliases on Apple and Windows, while the two process aliases are admitted only
for their source-inventoried Apple POSIX branch: exact
`global_stream_enhance` ownership, `legacy-bootstrap` route, and
`stream-enhance.js` source reference. Authoring, JavaScript validation, and the
Rust executor repeat that finite exception rather than widening generic POSIX
global authoring.
The adjacent `Bun.unsafe` / `Exact.unsafe` compatibility namespace remains
present because `arrayBufferToString` is a reviewed pure byte transform.
Armed lockdown removes only `gcAggressionLevel` and `segfault`, preventing
runtime-control or crash affordances without deleting the safe helper.
The generated descriptor sweep verifies those four qualified member paths
absent. A pre-hardening physical run failed closed at startup when
`Exact.unsafe.gcAggressionLevel` remained reachable; the hardened loaded engine
proves both names absent through both namespace aliases with no project code
and no legacy or typed decision.
Android platform-state delivery previously left
`__exactAndroidDispatchPlatformEvent` reachable because framework events can
arrive after bootstrap and native code resolved their JavaScript consumer by
global name. That let armed project code forge app/configuration/deep-link
events. The armed finalizer now captures the completed shared-runtime consumer
as an owner-thread native JSI root, deletes the rendezvous, and requires it
absent in the descriptor sweep. After project admission, native Android
delivery invokes only the retained function and fails closed if it is
unavailable; it never falls back to project-visible state. The initial trusted
bundle drain and unarmed runtimes retain the historical global lookup.
A pre-hardening physical batch refused the reachable root, the hardened batch
proves exact absence, and an Android-defined translation-unit build plus source
contract cover the platform-only retained dispatch path.
The same live fixture invokes shell exec, synchronous spawn, and asynchronous
spawn with a real marker-file command. All three are denied at the armed native
boundary and the marker remains absent, so executable selection, child
environment, stdio, and IPC option parsing cannot reach process creation via
the legacy `process:spawn` oracle.
Diagnostic audit keeps the child-process compatibility suite executable without
widening that production boundary. Its low-descriptor regression uses a plain
POSIX child to exercise IPC and extra-stdio `dup2` mapping directly; it does not
grant a nested Ibex runtime ambient ownership of inherited numeric descriptors.
A diagnostic nested Ibex child may adopt exactly one inherited POSIX IPC socket,
but only through a process-wide, construction-captured, one-shot lease released
to the first claimed unarmed Host context. The socket is validated and bound to
the runtime plus device/inode identity, its close-on-exec flag is restored before
project code, both startup markers stay absent from the principal environment,
and the temporary bootstrap carrier is removed after trusted runtime capture.
The captured carrier exposes only a frozen zero-argument close hook bound to
that runtime and socket identity. Trusted `process.disconnect()` consumes the
hook once; runtime teardown is the exact-once fallback. Each close revalidates
the native socket identity, so a stale or reused descriptor number revokes the
old lease without ever closing the replacement object.
Armed contexts, later runtimes, invalid descriptors, Windows, and unrelated
grandchildren cannot consume or inherit that lease. This is diagnostic
compatibility plumbing, not `ipc:channel` authority or target-conformance
evidence; every armed IPC cell remains closed and unsupported until a typed,
attributed channel design and its exact-target fixtures exist.
Parent-side extra stdio is a bounded, backpressure-aware full-duplex stream:
`end` half-closes writes, readable EOF gates the child `close` event, and
`destroy` releases both directions. Production child environment and inherited
stdio effects remain closed pending their typed conjunctive spawn implementation.
The armed import gate also carries an artifact-independent terminal-builtin
deny set for `async_hooks`, `diagnostics_channel`, `domain`, `inspector`, `vm`,
`wasi`, and `worker_threads` (including `node:` aliases and subpaths). A
deliberately overbroad but otherwise authenticated snapshot cannot re-enable
those runtime-inspection, process-wide publication/context, VM, WASI, or worker
escape surfaces; ordinary typed builtins such as `node:fs` remain governed by
the snapshot import policy. This module-wide closure is limited to source
families whose root and every export are closed. A mixed module with supported
operations is not terminal-denied merely because some of its import-time or
export routes remain closed.
The armed `exact_crypto` builtin is the corresponding mixed-module control
case. After the authenticated body has executed but before its cache record is
published, the loader recognizes only the JCS-canonical builtin SourceId and
pins the `fips` accessor plus `secureHeapUsed`, `setEngine`, and `setFips`
callables to immutable `ERR_ACCESS_DENIED` / `CryptoControl` refusal. Because
`crypto`, `exact:crypto`, and `node:crypto` resolve through that one authenticated
cache record, they share both identity and the sealed descriptors; a forged
label or noncanonical SourceId cannot select the tamer. Diagnostic unarmed
runtimes retain the compatibility behavior. Exact source-bound recipes prove
the descriptors, alias identity, stable FIPS state, and zero decisions rather
than converting generic import failure into control-closure evidence.
For a terminal builtin with no downstream static call-graph terminal, the
authenticated import gate is itself the runtime terminal. Its closure recipe
therefore may have one exact surface key and zero route alternatives. Evidence
accepts that direct route only for the terminal-builtin import operation, only
when the recipe is the closed scenario, and only when the runtime-derived key
equals that sole bound surface. The original complete Apple run at `510ba04e`
executed all 106 facets in the first five source families before exposing the
former validator contradiction. Current exact-target batches execute 137
facets across all seven families. A missing surface binding still fails
closed rather than turning an empty alternative set into wildcard authority.
On-disk `.node` native-addon and `.wasm` module candidates now refuse in the
native resolver before their bytes are read into the JavaScript compilation
path. The authenticated VFS import path used by loaded-engine conformance does
not execute the legacy `resolve_with_oxc` facet named by those inventory rows,
and its normalized public error cannot identify which private rejection branch
fired. The public loader-kind and compatibility-module facets therefore remain
residual even though the underlying resolver refusal is implemented. Promotion
requires a future authenticated, source-bound executor that reaches and
distinguishes each legacy branch without treating a generic failed import as
branch evidence.
The eight native OS-information functions used by public `node:os` now enter
the same exact typed plane on every implementation target. Hostname, CPU,
memory, uptime, user, load-average, and network-interface reads authorize both
their generated requested and commit stages before invoking POSIX, Apple, or
Windows APIs. Loaded-Hermes fixtures exercise all 18 public exports in every
effect scenario. Allow, malformed, missing-attribution, and wrong-principal
fixtures independently observe the public requested/commit route under its
exact floor while their typed adapter cases exercise the scenario-specific
semantic branch; principal-deny fixtures observe the public requested-stage
denial. Neither path consults the legacy string oracle (ENG-24450).
The same exact-engine batch now exercises `node:fs` `statSync`, `lstatSync`, and
`readdirSync` against harness-owned file and directory fixtures beneath an
authenticated, canonical logical-root binding. Metadata calls must return after
emitting requested, discovery, and repeat decisions. Directory enumeration must
also emit the repeat decision that establishes its generation lease before any
entry is returned. Denial fixtures stop at requested. For these exact
source/setup/argument recipes, a noisy static dynamic-call list is diagnostic
rather than residual: promotion still requires the runtime-observed gate to
belong to the source-derived terminal allow-list.
Direct global `print()` writes now authorize the exact stdout console-broker
identity (`broker` / `ibex:console:stdout`) at requested, commit, and repeat
before enqueuing a line. Denial therefore cannot leak output through the
best-effort mirror, and this public path no longer bypasses typed
`stdio:write` authority.
The initial profile therefore has no debugger protocol or compatibility-facade
route that bypasses package attribution or typed authority. Snapshot-enabled
`Bun` is only an identity alias of the already-governed `Exact` object.

### WP8 — Port handles, dynamic authority, and audit evidence

Rebase attenuated handles, revocation cascades, dynamic permission ceilings,
change signals, deputy intersection, and audit output onto typed effects and the
armed snapshot. Distinguish effect actor, effect owner, authority source, and
constrained principal set.

Acceptance:

- Possession-based delegation remains usable without becoming ambient authority.
- Revocation invalidates caches, derived handles, and live/repeated operations.
- Dynamic grants cannot exceed the canonical static ceiling or apply to
  static-only/closed definitions.
- Evidence groups denials without losing loaded-policy or effect provenance.

Implementation status (2026-07-11): armed hosts now decode the immutable
snapshot into a validated `VerifiedDecisionContext`, accept strict typed
decision-set/effect-gate input, classify final peers, and retain bounded
structured evidence. Every legacy string check, import check, handle mint, and
dynamic grant fails closed once that typed context is installed; production
call sites must migrate to the typed ingress before a target can advertise.
Typed dynamic grant publication now validates the canonical ceiling before
advancing its generation; revocation advances negative and dynamic generations
before publishing the replacement context, invalidating prior decisions. Typed
bearer handles use OS-random identifiers, can be minted only from an owner's
static floor or re-attenuated from a handle currently held by the actor, and
revoke descendants as one negative/handle-generation publication.

The live Hermes surface also exposes typed dynamic grant and revocation as
`Ibex.permissions.requestTyped(request)` and `revokeTyped(grantId)`. Requests
cross the native boundary as strict typed JSON and therefore use the same
ceiling, lifecycle, digest, and generation validation as embedder calls;
legacy colon strings are rejected by the typed method rather than reinterpreted.
Both the private bridge and public methods are exact registry surfaces.
Typed bearer mint and cascade revocation are likewise reachable as
`Ibex.authority.mintHandle(request)` and `revokeHandle(handleId)`. Handle IDs
remain opaque strings; the live bridge exposes no numeric conversion or legacy
capability-string minting path.
The live native ABI authenticates both authority surfaces from the executing
Hermes principal rather than trusting the principal or actor supplied in JSON.
Dynamic grants must name that authenticated principal and may be revoked only
by it; handle mint actors must match it, and handle revocation is limited to the
authenticated owner or current holder. Forged package identities and unknown
grant or handle IDs therefore refuse at the bridge instead of becoming ambient
authority or cross-principal revocation.
For a new handle, the bridge also carries the canonical full Hermes principal
stack into the host. The requested selector must be covered by every
constrained principal's static floor, so an authorized inner actor cannot use
an ungranted caller as a deputy to mint authority. Re-attenuation remains bound
to an explicitly presented parent held by the authenticated actor.
Successful typed grant, revocation, mint, and cascade-revocation publications
wake the runtime. Each event-loop poll compares the authenticated negative,
dynamic, and handle generations; changes emit a frozen generation tuple through
`Ibex.authority.onChange`, including mutations initiated by an embedder rather
than JavaScript itself.
Every typed decision context carries a canonical sorted `presentedHandleIds`
set. The bearer stratum considers only those IDs, and rejects duplicate,
unsorted, unknown, or wrong-holder presentation as invalid attribution. Merely
minting a handle for a principal therefore never turns possession into ambient
principal authority.
Armed root bindings are decoded into typed values and host paths normalize
through the longest authenticated binding. Package roots match only their exact
package owner, project roots do not borrow package identity, absolute bindings
remain exact, and paths outside every armed binding refuse before a decision.
For filesystem effects the host computes that normalization once per
constrained principal, preserves the complete principal set for attribution and
evidence, and refuses a missing, extra, or noncanonical projection before any
authority match.
Live typed filesystem decisions now carry the canonical full Hermes principal
stack, including the captured schedule-time owner. Worker dispatch snapshots
that stack on the runtime thread and installs a scoped immutable copy on the
worker, so commit/repeat checks cannot lose an outer caller or detached
scheduler. The evaluator intersects every constrained principal; an ungranted
outer principal therefore denies even when the innermost actor has authority.
Timers and next-tick queues likewise retain the complete schedule-time stack
and restore it only for their callback invocation, so a later
authority-bearing operation cannot shed an outer constrained deputy;
generation checks still occur at the operation and observe intervening
revocation rather than caching the schedule-time allow.
A retained-operation fixture publishes ceiling-bounded dynamic filesystem
authority, commits a descriptor use, revokes the grant, observes both negative
and dynamic generation advances, and proves the immediately following repeat
check denies.
Distinct live dynamic grants are now restamped atomically to one published
generation on every add/revoke/regrant transition, with failed publication
leaving both rows and clocks unchanged. The typed decision ABI returns the
decision and its exact structured evidence from one evaluation; bounded
history receives a clone of that same record and is no longer queried to build
the response.

Implementation update (2026-07-16): a diagnostic harness executes six
callback/control-plane invariants against the loaded armed Hermes engine through
production `process.env` and public authority-control operations:
missing attribution denies, scheduled decisions recheck authority after
generation changes, callback principals restore after delivery, bearer handles
cannot cross snapshot identities, public grant requests cannot widen the static
ceiling, and lockdown remains structurally immutable. A feature-gated one-shot
observer records only the actual principal and runtime nonce; it cannot evaluate
or authorize an operation, and the harness deletes its global before the public
invariant operation runs. These six generic invariant runs are suite-prerequisite
diagnostics only. Async attribution remains channel-by-channel rather than
structurally forced through one chokepoint (LLP 0016 §W2), so a rationale ID and
static source reference do not prove that an arbitrary carrier entered its body
or used the checked mechanism. The 2,976 carrier-specific invariant recipes
therefore remain residual pending exact carrier execution or an independently
proved carrier-to-mechanism relation with its own non-terminal evidence contract.
Only nine Exact embedder rows currently have source-bound exact-mechanism public
executions; those carry runtime-derived lifecycle results and zero legacy
observations. No diagnostic run may manufacture a `terminalObservedKey` or close
an enforcement-branch fixture for a carrier it did not execute.

### WP9 — Make complete enforcement the default and remove weakening paths

Flip ordinary CLI execution and embedding defaults only after WP4–WP8 cover the
required initial profile. Remove or quarantine legacy policy parsing, public
permissive execution, `--allow-all`, advisory attribution, environment-selected
weakening, durable audit mode, optional lockdown under enforce, and permissive
legacy host construction.

Implementation status (2026-07-11): `Auto` and explicit `enforce` now resolve
to the same enforce posture even when no policy is present. Durable audit or
permissive policy modes, `--allow-all`, explicit permissive mode, legacy
allow/deny overrides, environment-endowment widening, and advisory-attribution
flags/environment inputs refuse instead of weakening production. Lockdown is
installed structurally for both the ordinary CLI and direct `Runtime`
construction, and missing lockdown, frame attribution, or package isolation is
a hard enforce failure with no advisory override. Inspector and runtime-fidelity
controls refuse at ordinary host construction. Compatibility inputs cannot
remain ambient controls: the only admitted armed forms are launcher-captured,
fixed modes bound into the finalized snapshot, and they grant no authority. The
ordinary no-policy path now constructs an execution-bound immutable typed
snapshot instead of the legacy host: it binds the actual project directory
object, patched-Hermes binary digest, exact advertised target/features, empty
package graph, empty dependency floors and dynamic ceilings, and the current
semantic/registry identity. Auto and explicit enforce produce identical policy
and authority state. Each runtime construction injects a fresh run nonce before
finalizing the armed digest, so complete snapshot bytes and handshake digests
intentionally differ. The trusted module loader may read
only source that canonicalizes under the authenticated project binding after
the typed import gate succeeds. A project-local `ibex-policy.json` (or explicit
`--policy`) is now accepted only as strict, digest-valid canonical typed policy;
its package principals, typed floor/denial/ceiling rows, import axes,
endowments, graph nodes, root and package import edges, and authenticated package-root
bindings are projected one way into that same snapshot. Environment-selected
policy paths and stale/tampered policy digests refuse. Production builds always
enable enforce isolation and cannot persist audit or permissive posture.
Diagnostic audit is a separately named foreground command,
`ibex capsec audit <file>`; it accepts no durable policy or ambient endowment
input and never becomes an armed production profile. In the candidate registry,
that canonical file-execution dispatch route is conservatively closed under
`vm:evaluate` until authenticated code ingress and its fixtures exist; parser
and positional metadata remain structural rows and claim no ingress authority.

Acceptance:

- Plain `ibex run` and an explicit enforce affirmation arm identical policy and
  make identical authority decisions.
- Missing policy yields empty dependency authority under enforce.
- Missing/incomplete prerequisites refuse before project code.
- Audit is a visibly separate diagnostic workflow and cannot become durable
  production posture.

### WP10 — Prove targets and publish the conformance report

Build the generated cross-target conformance report and run the red-team suite
for each advertised target. Exercise the real Exact/Snapback graphs and the npm
compatibility corpus as product-quality evidence, not as a reason to preserve
the old policy format.

Implementation status (2026-07-12): no target is advertised complete. The
former runner incorrectly converted a handful of broad suite successes into
21,597 synthetic per-obligation passes. The runner now executes the full
default Rust/integration/red-team matrix, all-feature executable
library/binary/test/example coverage plus compile-only all-target coverage,
complete devtools and runtime-JS tests, Hermes transform/loader corpora,
all generated drift gates, contract/registry checks, and `ref-check` from a
clean revision. It launches an executable Hermes probe, but records that probe
identity separately from the actual runtime engine artifact whose digest enters
the binding; the probe can never promote a different embedded library. Those
broad results remain prerequisite suite evidence only, and command logs are
streamed to files with full digests plus bounded tails rather than retained
unbounded in the report.
Command-evidence directories must be real on every host and owned whenever the
runtime exposes a numeric user identity. POSIX additionally requires no group
or other permission bits; Windows does not expose authoritative POSIX mode
bits, so its synthetic mode is not used as a security decision.
The same runner is now the arm64 macOS and x64 Windows CI gate. CI invokes
`verify:capsec-conformance --target <triple> --expect-incomplete`, which still
runs the entire matrix and emits exact command, adapter, public-surface,
execution, and report artifacts. That mode succeeds only after the report is generated, remains
`incomplete`, independently fails the recipe/public/report promotion checks,
and has no matching committed target attestation. It fails automatically once
the target becomes conformant, forcing CI to remove the expectation and adopt
the ordinary promotion gate rather than silently retaining a stale
"incomplete" posture. On Windows, the full Rust product gate still passes
through the fail-on-zero wrapper; that wrapper binds Cargo to the configured
absolute MSVC linker before Git Bash can prepend its unrelated Coreutils
`link.exe`, and binds vendored OpenSSL to a validated native Perl from the
original Windows developer path rather than Git's incomplete Perl.
Target-selected replacement translation units still provide any cross-target
integration-test C ABI whose runtime contract reports that the physical target
or profile is unsupported; target absence is a test result, not a link error.
An obligation can pass only with fixture-specific command evidence carrying
its exact fixture ID, result marker, exit status, recomputed evidence digest,
and exact execution binding. Missing, generic, duplicated, stale, or synthetic
records keep the report incomplete. Promotion remains closed until real
executable evidence exists for every required fixture and the full matrix is
green.

Implementation status (2026-07-24): after `insecure` entered Cargo's default
feature set, the recipe and runner commands still used default features and
therefore exercised the deliberate no-sandbox bypass while naming their output
as CapSec evidence. All promotion-facing Rust executors now share an explicit
`--no-default-features` command with
`standard,capsec-conformance-observer,openssl-crypto`, and catalog tests reject
any generated Cargo executor that regresses. Re-executing the callback
mechanism smoke under that profile exposed and repaired an Exact endowment
ordering defect in the harness: the one-shot authenticated endowment is
published before the first session submission can add the runtime-owned `$_`
root and close the bootstrap disposition. The smoke passes in secure mode.
The broader callback batch remains incomplete for a separate reason: only
eight exact public mechanisms are executable while the report currently
auto-credits 2,800 rationale-wide internal rows. That accounting must be
replaced by executed internal proof rather than weakening the command profile.

Implementation status (2026-07-25): Cargo defaults no longer include
`insecure`. Plain `ibex` uses the secure production posture and, while the
advertisement set is empty, refuses before project code. Secure development
without an advertisement requires the compile-time
`unadvertised-dev-arming` feature; the ambient no-sandbox posture requires the
separately named `insecure` feature. Neither weakening is a runtime flag or a
silent default.

Implementation status (2026-07-25): the internal accounting is now
evidence-backed. The proof audit retained exactly six closed-vocabulary
runtime-owned scenarios. A later input-ownership audit removed
`malformed-branch-facts` from fixture obligations entirely: branch predicates
are authenticated registry metadata rather than caller-supplied runtime facts,
so per-surface execution could never prove a malformed input path. This is no
credit or reclassification; registry contract validation owns malformed
predicate refusal. Every retained internal recipe carries
a source-bound proof plan naming its mechanism, source location, secure Cargo
command, and proof-plan digest. The secure internal batch executes each of the
six mechanisms once and expands that scenario-class observation into exact
fixture records carrying the fixture plan, common execution binding, engine
digest, result marker, and artifact digest. Report generation validates those
records independently; catalog status alone leaves the fixtures missing.
Apple now has 2,666 fully executable rows, 3,114 internally verified rows, and
18,260 unresolved rows;
Windows has 2,240 fully executable rows, 3,102 internally verified rows, and
18,583 unresolved rows. The
public callback batch is correspondingly pinned to its eight exact authored
mechanisms. Portable recipe projection preserves internal rows under their
dedicated executor and excludes them from public-surface execution; portable
mapped-process production for the internal executor remains a separate
promotion integration step.

Implementation status (2026-07-25): invocation-time activation changed the
module-runner graph's public evidence window. A CommonJS lifecycle fixture can
execute zero decisions for its selected non-capability ABI while the surrounding
graph legitimately authorizes exact `require` resolution and authenticated
source reads. The native harness now permits only those two reviewed auxiliary
coverage edges, requires allowed outcomes and the exact observer session, and
still reports zero decisions for the selected ABI surface. The authenticated
graph exercises all 19 production-reachable lifecycle ABIs. Six eager
dynamic/require-link functions are not invoked by the deferred call-time
production route and therefore remain residual instead of borrowing the
generic graph command. The refreshed Apple catalog has 24,654 required, 2,596
fully executable, 3,092 internally verified, and 18,966 unresolved fixtures;
Windows has 24,539 required, 2,230 fully executable, 3,080 internally verified,
and 19,229 unresolved fixtures.

Implementation status (2026-07-16): the report-crediting fixture pilot reruns
exactly nine source-bound Exact embedder mechanisms independently of the public
catalog/adapter batches. The set covers the single-use host-call route,
endowment and exact-set authorization, unendowed-operation closure, and all three
artifact-bound preparation/materialization ABIs; generic callback/control-plane
rows are not credited by analogy. Every
`ibex/capsec-fixture-evidence/2` record carries the committed revision/tree,
exact target and mapped engine identity, full fixture plan, recipe/public
digests, producer command and exit status, and the fresh runtime observation.
The runner validates the artifact through its `--fixture-evidence` path and
credits exactly nine passes; all other obligations remain missing or residual, so
the report remains `incomplete` and the target remains unadvertised. Missing,
duplicate, stale, mismatched-plan/engine, or mechanism-invalid pilot evidence
fails closed rather than reverting to zero credited rows.

Builtin public-surface evidence follows the same rule at value granularity.
The source scanner records whether an export is data, a readable accessor, a
callable, or unresolved, plus source-derived platform availability where the
builtin authors conditional tables. It also distinguishes manifest-importable
aliases from bootstrap-internal names that preempt a same-named manifest
source. Registry-only names remain executable when an authenticated import
policy grants their exact spelling, even when they are neither advertised nor
bundler-external. Bootstrap-shadowed and unaliased manifest exports remain in
the completeness inventory, but receive an explicit reachability residual
rather than a public invocation recipe. A generic read recipe is valid only for
a publicly reachable root data property or readable root accessor on the
selected target; the loaded runtime must match the authored property
descriptor, and accessor evidence actually invokes the getter. Retrieving a
function, constructor, or prototype method is presence evidence rather than
execution evidence, so those surfaces remain residual until a bounded
call/setup recipe is authored.
Import-only aliases are not generically executable. An effect-bearing alias is
eligible only when an authored source-bound template identifies its exact
first-load effect and each public spelling executes in a fresh armed engine
whose observer opens before the first `require`. The reviewed `NODE_DEBUG`
initialization family uses that path. Platform-classified filesystem,
constants, and OS aliases remain residual because a bare import emits no typed
decision. The current DNS sources are different from their former eager
implementation: resolver configuration is loaded lazily only when an exported
operation asks for it. Therefore exactly `dns`, `node:dns`, `dns/promises`, and
`node:dns/promises` are classified as `module-reachability-only` and each is
executed in its own fresh armed engine with the observer open before the first
`require` and through event-loop quiescence. Evidence must contain zero legacy
or typed decisions and must bind the exact alias source metadata and carrier
edge. Each accepted receipt must prove exactly one authenticated module-cache
miss, the exact VFS builtin `SourceId`, completed builtin-body evaluation, and
the exact requested alias. The four receipts must also carry pairwise-distinct
tagged runtime nonces, so neither a cache hit nor shared-engine alias reuse can
stand in for an independent first load. In particular, the two promises
spellings fall through `loadInternal` to
their declared `node_dns_promises` manifest source; a synthesized
`dns.promises` cache would not be source-bound evidence for that manifest
alias. The two scanner-produced DNS `default` namespace rows share the corrected
non-capability classification, but remain output-shape residuals while their
value shape is unresolved. This import evidence does not execute or credit
`getServers`, `Resolver`, or any other export; those calls remain separate
obligations. The reviewed two-source shape makes 42 `node_dns_promises`
callables and three `node_dns` Resolver `_handle` callables inventory-visible,
but all 45 remain route residuals and are explicitly excluded from generic
effect, closed, and non-capability probe authors. `getServers` and `Resolver`
are effect-bearing conditional rows. The same `node_dns_promises` source also
authors 24 error-code exports by loop-copying string values onto the public
module. Those rows are data reads, not callable projections, but the scanner
conservatively records their `valueShape` as `unknown`. They are executable
only through an exact, independently duplicated allowlist of the 24 export
names whose descriptors also bind `node_dns_promises`, the two public
`dns/promises` spellings, the member-assignment idiom, a single-segment access
path, and `expectedValueType: "string"`. The physical executor and independent
evidence validator both require the loaded value to be a string. This
exception does not make generic unknown-shape reads executable and does not
credit any of the 42 callable projections or three Resolver `_handle`
callables.

The `node_cluster`, `node_http`, and `node_os` modules remain excluded from
generic export-read authoring because their initialization can perform
capability-bearing work. Exactly 15 later scalar reads are separately
executable: the module is first loaded and driven to quiescence before the
export observer opens, then the invocation performs an authenticated public
`require` against that cache and resolves the exact source-derived export.
This proves only the read; it neither observes nor credits module
initialization. Independent authoring, physical execution, and evidence
validation bind each exact source key, export name, source ref, public alias
set, export idiom, access path, static shape, and expected runtime type. All
other exports from those modules remain behind the generic exclusion.

`getServers` and `Resolver` remain effect-bearing conditional rows:
uncached system-server discovery uses the native `network:resolve` gate and may
fall back to `fs:list` plus `fs:read`; cached or explicitly configured server
state is the no-effect branch. A reviewed decision-free root cohort uses the
same exact fresh-engine receipt for
30 additional spellings: the bare/`node:` pairs for `buffer`, `console`,
`module`, `path`, `path/posix`, `path/win32`, `punycode`, `querystring`,
`string_decoder`, `timers`, `timers/promises`, `trace_events`, and `v8`, plus
`exact:clipboard`, `exact:http`, and the shared `exact:sqlite`/`bun:sqlite`
source. The SQLite and string-decoder roots must return a function; every other
root in this set must return an object. The root type is descriptor-bound
presence evidence only and does not credit any export or lazy installer edge.
Both `stream/consumers` spellings remain residual because `loadInternal()`
returns the compatibility `stream.consumers` value before the declared
`node_stream_consumers` manifest body can execute; `internal/fs/utils` remains
bootstrap-shadowed for the same evidence reason. All other non-capability
aliases remain residual: a shared-engine zero-decision result cannot establish
that each spelling has an effect-free first load because later aliases reuse
the module cache. Cache order is not independent execution evidence. Export
reads and calls remain separate
obligations: their exact public module is loaded and driven to
event-loop quiescence before the per-export observer opens, then the invocation
still performs the authenticated public `require` and resolves the
source-derived export from that cache. This isolates both synchronous and
deferred module initialization from the export body without claiming that
initialization was zero-effect. The closed generated builtin manifest may
authenticate, source-materialize, compile, and link exact private builtin
dependencies as runtime build metadata before a builtin body executes. That
operation has no package/path resolver route and no ambient filesystem probe,
so it does not create a package import edge. Activation of one of those links
is nevertheless confined to the exact builtin record at the top of synchronous
initialization: the exemption does not suppress capability terminal checks,
survive after initialization, or re-enter through an exported `require`
closure while another record is active.

Generic root-accessor reads are eligible only when the accessor itself is
zero-effect. The deprecated `node:fs` `F_OK`, `R_OK`, `W_OK`, and `X_OK`
getters intentionally emit DEP0176 and therefore remain explicit residuals in
an armed runtime; their inert numeric values are available through the
separately inventoried `fs.constants` object. A warning-producing getter must
not gain zero-decision credit by disabling, pre-emitting, or swallowing the
warning in the harness.

Bounded non-capability callable recipes are grouped by exact source template,
not inferred from `typeof value === "function"`. The first authored families
cover `assert`, `buffer`, `events`, `path`, `perf_hooks`, `punycode`,
`querystring`, `zlib`, `stream`, `string_decoder`, `url`, and `util`: each
recipe fixes its setup, receiver, arguments, dispatch mode, and expected return
type. Direct member-to-member aliases inherit a callable shape only from the
already observed source member, and reuse that member family's bounded
arguments rather than weakening the template allowlist.
Loaded-engine validators for these call families apply only to callables; an
inert data read from the same source family does not inherit or fail a
call-only name vocabulary. Conversely, changing a reviewed callable recipe
into an export read is a contract mismatch rather than a way around its setup
and argument checks.
Prototype recipes construct the declared owner (with dedicated bounded Buffer,
CallTracker, zlib-transform, string-decoder, and configured
readable/writable/duplex stream fixtures), then dispatch the exact
source-inventoried prototype function. Zlib decoder probes derive a valid
compressed input with the matching one-shot encoder, and every zlib receiver
closes native stream state in a `finally` path. Stream recipes use inert
read/write/transform callbacks; standalone `destroy` receives an explicit
non-error value so it cannot leave an asynchronous `AbortError`, and `compose`
remains residual because its normal return still owns a live pipeline.
Performance observer `observe` likewise remains residual because it retains a
callback; constructor, query, mutation, and explicitly disconnected observer
recipes have bounded lifetimes. Evidence requires a normal return from the
selected dispatch; an argument/receiver binding error or any other throw fails
the recipe and cannot stand in for body entry. Normal return is not completion
evidence on its own: the observer remains open while the harness drives the
loaded engine to event-loop quiescence under the recipe's fixed one-second
bound. A timeout or event-loop error stops the batch before another fixture can
inherit its work, and the runtime completion marker is independently checked
against the authored mode and bound. A later tranche adds exact bounded
templates for in-memory crypto hash/HMAC/sign/verify, KDF, random-buffer,
prime, key, DH, and ECDH operations; pure module/path, IP/block-list, URL, and
version helpers; and unbound server metadata operations. Promise-returning
stream consumers, pipelines, `wrap`, and Hash/HMAC readable-side finalization
remain residual;
their one-shot recipes do not own enough state to prove completion even with a
quiescence drain. All accepted calls and data/accessor reads execute against
the same mapped Hermes
identity; there are no promoted cache-dependent module imports.
Loaded execution also exposed lazy builtin assignments that were swallowed by
locked inherited primordial properties; those Buffer, AssertionError, and
StringDecoder prototype members
are now installed as explicit writable/configurable own properties without
weakening primordial lockdown. Source inventory also preserves own prototype
overrides when an inherited member of the same name was propagated into a
concrete constructor.

Windows installs a reduced `node:crypto` implementation directly from the
bootstrap module loader instead of loading `src/builtins/crypto.js`. Exact
target generation therefore keeps every public recipe whose source descriptor
names that default file residual under
`builtin-export-source-replaced-on-target`, including overlapping export names:
executing a same-named replacement function is not evidence that the
source-bound default implementation ran. Those recipes become executable on
Windows only after inventory and recipe generation bind the replacement's own
source surface (or the target stops replacing the module).

The Windows zlib bridge installs `__exactDeflateSync` and
`__exactInflateSync`, but not the `__exactBrotli*` codec globals. Source-bound
`Brotli*`, `brotli*`, and `createBrotli*` call recipes therefore remain
residual on that target under
`builtin-export-native-prerequisite-not-installed-on-target`; a callable
JavaScript wrapper that can only throw for its absent native prerequisite is
not normal-return execution evidence. Source-defined scalar `BROTLI_*`
constants remain executable because reading them does not claim codec
execution.

Closed and conditional evidence remains branch-executed rather than
classification-derived. A closed CLI facet is executable only when the harness
first reconciles its source-discovered spelling, action, arity, defaults, and
parser against the live Clap command and then observes the production entry
reject that selected control before artifact or project execution. The four
Hermes evaluator identities additionally bind the reviewed engine identity and
lockdown-taming digest, resolve their exact intrinsic access path, and must
actually throw the exact native lockdown error when invoked on the loaded
engine. Their public fixture is an authenticated direct-file program admitted
through the native module graph: persistent-session lowering intentionally
closes evaluator syntax before runtime and is never bypassed for this evidence.

Production startup evidence now covers ten curated structural stages against a
fresh armed runtime from the exact mapped Hermes artifact: runtime creation,
global/module-loader/shared-runtime installation, capability-hatch sealing,
eager lazy-installer sealing, lockdown, freeze-hatch sealing, compartment
registry installation, and explicitly enabled Web Streams installation. Each
stage has one fixed source descriptor and an independently validated
postcondition; the probe then executes a project marker and requires zero
legacy or typed decisions. The lockdown-stage self-check uses authenticated
direct-file native-graph admission so it can inspect the tamed evaluator
without bypassing the persistent-session syntax closure; its startup,
admission, and execution observation windows are independently empty.
Scanner-only script URLs, evaluation/call-site
facets, installer definitions, skipped legacy bootstraps, and platform-only
routes remain residual rather than inheriting these stage results.
Direct `__exactReadFile` now has five Windows exact-target recipes as well as
the existing Apple evidence. The Windows invocation passes a null typed handle
to the public global and requires the target-specific four-stage sequence:
requested/discovery `fs:list`, then commit/repeat `fs:read`. Success and
negative-attribution scenarios bind returned bytes or typed refusal to that
sequence; denial stops at requested. Physical engine tests prove successful
bytes, pre-lookup denial, and zero legacy decisions. The lower retained VFS
fixture separately replaces the selected leaf between discovery and commit and
requires a stale-object refusal. The asynchronous Windows read remains
residual because it still lacks per-chunk typed generation rechecks.
Direct non-recursive `__exactMkdir` now uses a separate harness-owned path under
`target/`, an exact `fs:list` and `fs:write` floor, and source-authored boolean
arguments. Successful public execution must emit the complete seven-decision
component walk: requested full spelling, authenticated-root discovery,
requested/repeat authorization for the retained `target` directory, requested
leaf lookup, requested dangling spelling, and absent-create discovery. The
authorized `mkdirat` is deliberately the terminal mutation and emits no
name-bound post-create commit; the harness must remove the created directory before
the fixture can pass. Denial occurs at requested before creation. This closes
the direct Apple and Windows surface cells independently from the asynchronous
dispatcher route; recursive creation remains closed under armed startup.
Direct `__exactWriteFile` similarly receives bytes from the source-bound
`__exactStringToUtf8Bytes` native producer and a null typed-handle argument. It
can create only one exact harness-owned target file under the joint `fs:list`
and `fs:write` floor. Passing evidence requires requested, retained-parent and
created-target discovery through the complete nine-decision component walk,
commit, and repeat sequence, exact written bytes, and removal of the file after the
call; denial stops at requested before creation.
Direct `__exactAppendFile` uses the same typed retained-object route against a
pre-seeded exact harness-owned file. Passing evidence must preserve the known
prefix, append all source-derived suffix bytes, observe the eight-decision
existing-path sequence (full-spelling request, authenticated-root discovery,
requested/repeat checks for both components, commit, and write repeat), and
then remove the file. Denial stops
at requested, leaves the prefix byte-identical, and still removes the harness
fixture outside the observation.
Direct `__exactFsOpen` covers its read, write, and read-write logical branches
with non-mutating `r`, `a`, and `r+` flags against three exact pre-seeded files.
Successful and branch-selection evidence must emit an access-class request,
the six-decision existing-path component walk, and commit (eight decisions),
then close the returned descriptor through
`__exactFsClose`, prove the fixture bytes unchanged, and remove the file.
Denial stops at requested and still proves unchanged bytes before harness
cleanup. Standalone `__exactFsClose` evidence also requires a descriptor staged
before observation. It remains residual on Windows because the installed
`__exactFsOpen` prerequisite still uses the legacy capability oracle there;
executing close after a denied setup would fabricate evidence for an
unavailable retained object.
The POSIX `__exactFsOpenAsync` surface mirrors those three exact owned fixtures
through event-loop quiescence. Successful and branch-selection evidence binds
the seven-decision component-walk-and-commit sequence to the asynchronous
surface plus its synchronous descriptor-cleanup terminal,
closes the returned descriptor, proves unchanged bytes, and removes the file;
denial stops at requested and removes its unchanged fixture. The Windows
backend does not install `__exactFsOpenAsync`, so Windows recipes remain
explicitly residual instead of borrowing the POSIX invocation.
Retained `__exactFsFstatSync` metadata now has four physical Apple recipes. The
harness opens source-bound `Cargo.toml` before observation under exact
`fs:list` and `fs:read` floors, passes only the retained descriptor to the
metadata surface, requires one typed `fs:list` repeat decision, and closes the
descriptor after collecting observations. Cleanup therefore cannot contribute
an unrelated decision to the recipe it proves. The deny recipe remains
residual: denying the same principal's `fs:list` authority would prevent the
prerequisite descriptor from being opened, so the harness cannot honestly
stage that retained-object scenario. Windows now executes the same four
retained-object scenarios through its typed descriptor-metadata gate.
Retained `__exactFsFsyncSync` and `__exactFsFdatasyncSync` durability each add
four physical recipes on both exact targets. Before observation, the harness
creates a distinct exact file under `target/` and opens an append descriptor
through the source-bound native surface under joint `fs:list` and `fs:write`
floors. Each durability invocation must emit one typed `fs:write` repeat
decision on its own public edge, preserve the fixture bytes, and then close the
descriptor and remove the owned file outside the decision window. Windows
performs the flush through the same retained typed VFS file while holding its
I/O mutex; POSIX authorizes the live retained descriptor immediately before the
syscall. Denial remains residual because denying the descriptor's required
`fs:write` authority would prevent the prerequisite writable descriptor from
being opened.
The same owned-descriptor harness now physically executes
`__exactFsFtruncateSync` on Apple. Four recipes require one typed `fs:write`
repeat decision, then independently verify the exact two-byte length before
closing the descriptor and removing the file. The global is not installed by
the Windows filesystem backend, so its exact Windows cell is an executable
target-absence obligation; the
Apple deny recipe also remains residual because its required writable-descriptor
setup cannot survive the same principal's `fs:write` denial. Descriptor mode
and timestamp mutation remain unresolved: LLP 0023 keeps `fchmod` and `futimes`
closed pending object-bound mutation work, so physical execution alone would
overclaim the governing contract.
Direct `__exactTruncate` now uses the same object-bound shape on armed Apple
runtimes: the six-decision existing-path component walk precedes a
non-truncating `openat`, commit binds the actual regular-file descriptor, and a
repeat decision immediately precedes `ftruncate`. Five public recipes operate
only on an exact harness-owned file, verify its two-byte result or unchanged
denial bytes, and remove it. The legacy Windows backend remains residual until
it can provide the same retained-object execution contract.
The conditional `__exactFsFdAsync` registry now matches that retained-object
contract instead of claiming an unreachable `durability-read` branch. LLP 0023
places `fsync`, `fdatasync`, and their `FileHandle` aliases in the open-write
family because they act on a descriptor already authorized to write; the
runtime likewise requires a writable owned descriptor and emits `fs:write`.
Apple public evidence selects `durability-write` with `fsync`, awaits event-loop
quiescence, requires exactly one typed repeat decision, then closes the
descriptor and verifies the unchanged owned file before removal. Its deny case
remains residual because the setup itself requires the authority being denied,
and the Windows backend does not install this dispatcher; source inventory now
labels `hermes_runtime_fs.cc` as POSIX, so Windows receives one exact absence
fixture rather than inheriting a fictitious fallback implementation.
The former aggregate `metadata-write` branch is split exactly. `ftruncate`
selects its own open-family `fs:write` branch, while `fchmod`, `fchown`, and
`futimes` each select a deny-only `fs:unbound-mutation` branch. The same
branch-local closure models every unbound operation spelling in
`__exactFsPathAsync` and the recursive branch of `__exactMkdir`; the public
closed harness invokes each spelling, requires exact `EPERM`, zero legacy and
typed decisions, and recursively compares the entire filesystem fixture before
and after. Apple has 17 such dispatcher closures and Windows has 16; the
Windows-only path `chmod`/`utime` closures replace the three descriptor
closures whose dispatcher is absent there.
Direct `__exactReaddir` now enumerates a separate exact directory containing one
harness-owned file. Passing evidence must select the six-decision existing-path
component walk and three later repeat decisions: retained-target open,
pre-enumeration reauthorization, and the generation-bound lease for the one
disclosed entry. The harness removes the entry and directory after both
success and denial, and successful evidence records that cleanup explicitly.
The runtime-create descriptor binds `ex_hermes_create_armed`, not the historical
`ex_hermes_create` symbol that production deliberately leaves non-executable.

A zero-effect conditional branch may pass without a typed decision only when a
source-bound public invocation itself selects the registry's exact branch facts,
returns normally, emits zero legacy and typed observations, and releases every
harness-owned resource. The first such family covers the seven native JSI and
seven Rust host-ABI SQLite operations on exact in-memory handles; each proves
both branch selection and the no-effect result while the file-backed branches
remain independent obligations. A valid public API cannot inject malformed
internal branch facts, so malformed-branch-fact fixtures remain residual rather
than reusing a generic malformed adapter result or a hand-labelled terminal.

The macOS/aarch64
candidate has exact loaded-Hermes adapter-probe evidence, but probe coverage is
deliberately non-promotable and is not represented as fixture pass claims.
The physical Release candidate is a universal MinSizeRel Hermes build with the
debugger disabled, the pinned Exact patch set applied, and the expected patched
package-attribution export. Its loaded arm64 identity is recorded independently
from the executable probe. The first whole-report run against that artifact
failed closed when the native public batch reached an Apple OpenSSL-backed ECDH
fixture without the `openssl-crypto` build profile. All executable-recipe,
fixture-evidence, public-surface, callback, closed, startup, startup-environment,
and target-absence commands now bind that profile explicitly alongside the
observer. A focused rerun against the same loaded Release artifact passes all
470 native, host-ABI, and module-loader public fixtures, including the ECDH
fixture that exposed the omission. The regenerated catalog retains 23,126
required, 4,845 executable, and 18,281 unresolved fixtures. This corrects the
evidence producer contract but does not promote the candidate or turn the
remaining residuals into passes.
The complete physical Apple Release run now succeeds at source revision
`9329a9123a10e379d6253afb6a90a33de5de928e` with all 24 exact prerequisite
commands passing. The execution artifact is bound to source-tree digest
`sha256-37oyAHa_E6_FdVqKjL51CEVsmjQrmfp4QZSLePRTP6s`, the loaded arm64 engine
digest `sha256-TI61ftuk_AoTSSNEjQOOuOEopGFCsAH38C7Qu9yxYuw`, and recipe-catalog
digest `sha256-ocEiwJu5McEiGcypMkUBhB0q47sT8-47nTm4PYxJO_8`. The resulting
report is intentionally `incomplete`: one of 7,108 target cells is conformant,
7,107 remain incomplete, nine of 23,126 required fixtures pass, 23,117 are
missing, and none fail. Its conformance digest is
`sha256-pX31WIshSle8F2DnydGKCn_AeMw8npRyIhDtX2SG1LM`. This supplies the missing
physical Release report without weakening the promotion rule: the target stays
unadvertised until every required fixture and target cell conforms.
The artifact workflow now reproduces that no-debugger Darwin Release profile
as a separately named, checksummed bundle and rejects either a missing patch
export or any exported debugger API. `download-hermes.sh` installs that exact
profile into the same content-addressed build cache used by local source builds.
The conformance workflow uses a separately versioned no-debugger cache key and
rechecks the attribution export and debugger-symbol absence after every cache
restore, so an older debugger-enabled framework cannot enter the matrix merely
because it shares the source pin and patch digest. The job explicitly exports
`HERMES_ENABLE_DEBUGGER=false`, binding both prebuilt artifact selection and the
compiled Exact wrapper to that profile. Symbol checks capture the complete
`nm` output before matching, so `grep -q` cannot terminate the producer with
SIGPIPE and turn a present debugger symbol into a false absence result.
Windows no longer has to rely on the historical unpatched NuGet artifact. Its
installer now fetches the exact commit-plus-patch-digest Release bundle and
falls back to the same source build; the artifact manifest binds commit, patch
digest, architecture, configuration, debugger state, and DLL digest. At
runtime, the C++ bridge snapshots the loader module set, requires exactly one
loaded module with the authored `hermesvm.dll` basename, pins that module by
its mapped base address, and obtains its loader-reported pathname. This avoids
both an executable-side MSVC import thunk and ambiguous basename lookup. Rust
reopens that pathname and compares its Windows volume serial/file index with
the pinned file used for hashing.
That detects ordinary named-file substitution, but it does not authenticate
the already mapped image section: a post-load replacement can make both file
handles identify different bytes from the code supplying the running process.
The release workflow has now built and inspected the DLL on a Windows runner
and published the exact checksummed Release bundle; its DLL digest is
`6f5190b9f8bf943b073e62dc5dbc2e297b77b7becbac3ca0c209b12d92828b6a`.
The artifact manifest and installer continue to hash the PowerShell builder's
raw platform-native checkout bytes. Evaluator discovery has a distinct source
review domain: it canonicalizes CRLF to LF for the Windows builder and installer
before hashing, so semantically identical Git checkouts retain one reviewed
Function-family reachability claim without weakening the release bundle's
byte-exact provenance check. Any non-line-ending source mutation still changes
the evaluator review identity and fails closed pending review.
Windows x64 is now a declared but unadvertised candidate alongside Apple arm64.
The complete-matrix workflow installs the checked Release DLL, revalidates its
manifest, digest, patched export, and debugger-free profile, then explicitly
selects `x86_64-pc-windows-msvc` for recipe generation and report execution.
Deterministic registry, contract, generated-policy, aggregate-generated, and
LLP-reference drift checks run as an evidence-retained preflight before engine
attestation or physical fixture execution, so stale source artifacts cannot
consume an authoritative matrix run before refusing the report.
Its current catalog has 2,327 executable and 21,373 unresolved fixtures. The
first authoritative Windows attempt physically rejected the published DLL:
although its manifest claimed the no-debugger Release profile, its PE export
table still contained the full `AsyncDebuggerAPI`/CDP implementation. The
Windows builder now passes a quoted, typed `HERMES_ENABLE_DEBUGGER:BOOL=OFF`
argument (the prior unquoted PowerShell token preserved `$debugger` literally),
checks the configured CMake cache, and rejects the implementation-only
`CDPAgent`/`CDPDebugAPI` exports before writing a manifest. Install and
publication paths independently enforce the same implementation-symbol check.
A rebuilt physical artifact must still close both the independent source-build
authority and mapped-image provenance blockers, and a complete report must
finish and be inspected, before any Windows target cell or advertisement can
change. Incomplete evidence is retained as a refusal artifact, not promotion
authority.
`bun run verify:capsec-conformance` must publish a conformant revision-, tree-,
full loaded-engine identity-, vocabulary-, registry-, source-implementation-,
target-, and fixture-catalog-bound report. Promotion then requires a checked
content-addressed attestation; the generator reopens and validates the report,
the complete executable-recipe catalog, and a separate public-surface execution
artifact, plus the loaded-engine output-disposition evidence. All four are
immutable regular files addressed by their raw content, and the report and
attestation bind the catalog and public-execution semantic digests together
with the exact output-disposition evidence bytes. Adapter-probe evidence is a
distinct diagnostic schema and is rejected at publication.
`IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT` only selects the
harness-owned diagnostic artifact destination; it never supplies authority,
policy, a principal, a target claim, or production runtime input. The generator
re-derives the exact required fixture set and
requires one passing authored public-surface invocation (or target-absence
probe) with the selected terminal observation for every recipe, with zero
residual, missing, duplicate, or failed rows. It then derives every cell and
advertisement and permits no source changes after the reported revision except
those four evidence files, the attestation, and generated publication
artifacts. Until every required fixture genuinely passes, production startup
refuses before project code on every target.

Source-derived global reads are executable evidence only when the authored
runtime graph proves a concrete access path, every path segment has an actual
registration rather than a synthesized namespace prefix, and the final value
is unambiguously data or an accessor. The loaded-engine probe resolves the
source-proven property path, checks the final descriptor shape, performs the
read, and requires zero legacy or typed authorization observations. Merely
retrieving a function is never call evidence. Conditional namespace aliases,
multi-installer globals, receiver-dependent prototype members, and lazy getters
that may already have materialized a callable remain residual until they have a
bounded call/setup recipe. This keeps inventory facts from becoming synthetic
execution claims while permitting exact non-capability data reads to close.

Bounded native-call recipes likewise use only harness-owned literals,
callbacks, listeners, handles, or results of source-bound native producers.
When two arguments need the same generated key pair, the loaded-engine harness
caches the exact producer invocation and projects only an own `privateKey` or
`publicKey` property; independently generated keys are not interchangeable
evidence. Timer callbacks are inert and their returned timers are cancelled
before the fixture completes. Resource-consuming calls receive a handle minted
inside that invocation. Compile-guarded globals absent from the attested engine
remain residual even when source discovery finds their registration text.
Every non-capability recipe requires zero legacy and zero typed authorization
observations; in particular, ordinary random bytes cannot retain the retired
always-allowed `crypto:random` legacy check.

Promise-returning public builtin calls require a stronger receipt than a
synchronous function return. The readable-stream consumer family is executable
only for an already-ended, empty stream created by the harness, with the exact
returned Promise awaited inside the same observation and event-loop quiescence
proved afterward. The recipe author, evidence validator, and Rust executor each
repeat the closed owner, method, arguments, and settled result type. A Promise
object returned to a synchronous harness is not completion evidence. Stream
composition, wrapping, and pipeline operations retain delegated sources or
pipelines and remain residual until a recipe owns and drains those resources.

The base `node:stream` constructor is the module value itself. It has no nested
`default` property, so its reviewed lifecycle calls resolve through
`["prototype", method]`. That correction is executable only for the separately
enumerated `_close`, `_emitClose`, `_undestroy`, `constructor`, `destroy`, and
`unpipe` set on a harness-created plain Stream; generic default-owner prototype
authoring remains unavailable. In particular, `pipe` retains listener and
pipeline ownership after returning and remains residual.

Explicit-parameter Diffie-Hellman construction and state-only accessors are
executable only with the independently repeated evidence vector: prime 23 as
one harness-owned byte, generator 5, and private/public setter input 3.
Supplying the prime avoids lazy prime generation, and the reviewed getters and
setters only project or replace bounded in-memory byte arrays. The recipe
author, evidence validator, and Rust executor separately enumerate the exact
constructor, factory, four getters, two setters, setup kinds, arguments, and
result types. `generateKeys` and `computeSecret` remain residual because this
receipt does not own random-key generation or broaden bounded state evidence
into modular key-agreement evidence.

Idle zlib destruction is executable only for a closed owner allowlist. Each
constructor establishes its principal-bound native selector before the
invocation, the public `destroy` source path authenticates that selector before
delegating to the stream lifecycle, and `_destroy` closes it. The harness then
performs idempotent cleanup and requires event-loop quiescence; no input is
submitted to a codec. The recipe author, independent evidence validator, and
Rust executor separately enumerate the exact owners, empty argument list,
object result, cleanup, and zero-decision contract. Apple installs and executes
`BrotliCompress`, `BrotliDecompress`, `Deflate`, `DeflateRaw`, `Gunzip`, `Gzip`,
`Inflate`, `InflateRaw`, `Unzip`, `ZstdCompress`, and `ZstdDecompress`.
Windows executes the same set except the two Brotli owners, whose absent native
codec prerequisite remains explicit residual evidence rather than a throwing
wrapper being credited as normal execution.

Three one-shot zlib encoders have a separate isolated receipt:
`deflateRawSync`, `deflateSync`, and `gzipSync`. Each exact public root call
receives one harness-owned Buffer containing bytes `[105, 98, 101, 120]`; the
loaded engine requires a nonempty byte-view result before recording normal
return and event-loop quiescence. No incremental codec selector, callback,
listener, or deferred stream survives the call. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript boundary each
repeat the same three-name allowlist, source descriptor, argument, dispatch,
result type, and byte-view proof. This receipt does not cover callback codecs,
`_processChunk`, `flush`, `params`, `write`, or any other stream-processing
method; direct `write` and `_processChunk` use the separately bounded receipts
below rather than borrowing this synchronous one-shot proof.

Four one-shot zlib decoders have their own isolated receipt: `gunzipSync`,
`inflateRawSync`, `inflateSync`, and `unzipSync`. Their harness-owned inputs are
fixed complete deflate, raw-deflate, or gzip encodings of `[105, 98, 101, 120]`.
The loaded engine credits normal return only when the result is a byte view
whose length and every byte exactly reproduce that payload, then requires
event-loop quiescence and zero decisions. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript boundary each
repeat the exact four-name allowlist, source descriptor, compressed bytes,
root-call dispatch, object result, and decoded-byte proof. Brotli, zstd,
callback codecs, retained codec objects, multi-member variants beyond the
single fixed gzip member, and every incremental stream method remain residual
except for the separately bounded Apple-only Brotli routes below.

Seven one-shot callback wrappers have a distinct deferred-delivery receipt:
`deflate`, `deflateRaw`, `gzip`, `gunzip`, `inflate`, `inflateRaw`, and
`unzip`. The harness passes the fixed encoder or decoder Buffer followed by a
dedicated callback credential, requires the public source call itself to return
`undefined`, awaits exactly one later callback, rejects any error, and accepts
only a nonempty encoder byte view or the exact decoded bytes
`[105, 98, 101, 120]`. Completion then requires event-loop quiescence and zero
decisions. The author, independent evidence validator, Rust validator, and
loaded-engine boundary each repeat the exact seven-name allowlist, source
descriptor, input, callback-result contract, dispatch, return type, and
delivery proof. This does not admit Brotli or zstd wrappers, `info` engines,
arbitrary callbacks, multiple delivery, or any retained codec stream through
this seven-name receipt; the separately bounded Apple-only Brotli callbacks
follow below.

Four Apple-only one-shot Brotli routes have a platform-bounded receipt:
`brotliCompressSync`, `brotliDecompressSync`, `brotliCompress`, and
`brotliDecompress`. Compression receives the fixed Buffer bytes
`[105, 98, 101, 120]` and must produce a nonempty byte view. Decompression
receives the fixed complete Brotli member `[139, 1, 128, 105, 98, 101, 120, 3]`
and must reproduce exactly `[105, 98, 101, 120]`. The callback variants must
return `undefined`, deliver exactly once without error, satisfy the matching
output proof, and then reach event-loop quiescence. The recipe author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
boundary each repeat the exact four-name vocabulary, source descriptor, fixed
bytes, root dispatch, return contract, and output proof. Windows continues to
leave all four rows residual because that target does not install the native
Brotli bridge; zstd one-shot wrappers, `info` engines, arbitrary callbacks,
multiple delivery, retained codec objects, and incremental stream methods other
than the separately bounded terminal `end` lifecycles below remain residual.

Terminal zlib `end(Buffer)` has a separate stream-lifecycle receipt for exactly
nine Apple owners: `BrotliCompress`, `BrotliDecompress`, `Deflate`,
`DeflateRaw`, `Gunzip`, `Gzip`, `Inflate`, `InflateRaw`, and `Unzip`. Windows
executes the same set without the two target-unavailable Brotli owners.
Compression receives `[105, 98, 101, 120]` and must emit a nonempty byte view;
each decoder receives its fixed complete Brotli, deflate, raw-deflate, or gzip
member and must emit exactly `[105, 98, 101, 120]`. The selected source call
must return the receiver object, emit exactly one `finish`, set terminal
writable state, leave no native selector live, and reach event-loop quiescence
with zero decisions; owners without a native stream still pass the same
idempotent cleanup proof. The author, independent evidence validator, Rust
validator, and loaded-engine JavaScript boundary separately repeat the exact
owner set, inherited prototype descriptor, input, output contract, dispatch,
finish, cleanup, and quiescence proof. `ZstdCompress.end` and
`ZstdDecompress.end` remain residual because the runtime deliberately exposes
no native zstd bridge. Parameter changes, flushes, transforms, and direct
writes or synchronous `_processChunk` calls are not credited by this receipt;
the latter two have separate contracts below.

Direct incremental zlib `write(Buffer, callback)` has a terminal-write receipt
for the same nine Apple owners and seven non-Brotli Windows owners as
`end(Buffer)`. Compression receives `[105, 98, 101, 120]`; each decoder
receives its fixed complete Brotli, deflate, raw-deflate, or gzip member. The
selected source call must return a boolean and invoke the dedicated callback
exactly once without error. Only after that callback does the harness supply a
separate empty `end()` to release retained input, wait for exactly one
`finish`, and require a nonempty encoded byte view or exact decoded bytes
`[105, 98, 101, 120]`. It then destroys the receiver and proves flushed and
ended writable state, `destroyed === true`, a null native handle, event-loop
quiescence, and zero decisions. The separate terminal step is required for the
Apple Brotli wrappers because their stream fallback buffers incremental writes
until finalization; it does not turn `end`'s return into evidence for the
selected `write` return or callback. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript boundary each repeat
the exact owner, inherited-prototype descriptor, fixed input, dedicated
callback, terminal method, output, and cleanup contract. Both zstd owners
remain residual because the runtime deliberately exposes no native zstd
bridge, and `_writeNative`, `_transform`, `_flush`, `flush`, and `params`
remain outside this receipt.

Public zlib `flush(callback)` has a separate non-terminal lifecycle receipt for
all nine non-zstd Apple owners, the seven non-Brotli Windows owners, and both
zstd wrappers on either target. The harness passes its dedicated callback as
the first argument, fixing the source branch to the default `Z_FULL_FLUSH`,
and requires the source call to return the fresh receiver. The callback must
run exactly once without error while the receiver still has
`_flushed === false` and `writableEnded === false`; the harness then destroys
the receiver, closes any native handle, drains byte-view output, quiesces, and
observes zero decisions. The two zstd entries prove only the source-defined
control write: with no native zstd bridge, their flush marker is a safe no-op
and does not constitute zstd compression or decompression evidence. The
author, independent evidence validator, Rust validator, and loaded-engine
JavaScript boundary each repeat the exact owner vocabulary, inherited
prototype descriptor, first-argument callback form, default flush selection,
receiver return, non-terminal state, and cleanup contract. `_flush`,
`_writeNative`, `_transform`, and `params` remain outside this receipt.

Public zlib `params(1, 0, callback)` has its own selected-state receipt over the
same eleven Apple and nine Windows owners as public `flush`. The fixed numeric
arguments choose compression level 1 and default strategy 0; the source call
must return the fresh receiver and deliver its dedicated callback exactly once
without error. Before cleanup, the harness proves `_level === 1`,
`_strategy === 0`, `_flushed === false`, and `writableEnded === false`; it then
destroys the receiver, closes any native handle, drains byte-view output,
quiesces, and observes zero decisions. Native deflate-family compressors enter
the installed parameter bridge, while decoder, Brotli, and no-bridge zstd
wrappers prove only their source-defined retained-state control path. This
does not claim Brotli or zstd codec execution. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript boundary each repeat
the exact owner vocabulary, inherited descriptor, arguments, callback,
selected state, receiver return, and cleanup contract. `_flush`,
`_writeNative`, and `_transform` remain outside this receipt.

Direct zlib `_transform(Buffer, "buffer", callback)` has a bounded
accepted-input receipt over the same eleven Apple and nine Windows owners. Each
encoder receives `[105, 98, 101, 120]`; the nine established decoders receive
their fixed complete Brotli, deflate, raw-deflate, or gzip member. The direct
source call must return undefined, deliver its callback exactly once without
error, and set both byte counters to the exact input length while leaving
`_flushed` and `writableEnded` false. The harness drains byte-view output,
destroys the receiver, closes any native handle, quiesces, and observes zero
decisions. The two zstd wrappers receive fixed bytes only on the current
no-bridge retained-input branch, so this receipt makes no zstd codec claim.
The author, independent evidence validator, Rust validator, and loaded-engine
boundary repeat the exact owner, input, encoding, callback, accepted-state,
undefined-return, and cleanup contract. `_flush` and `_writeNative` remain
outside this receipt.

Direct zlib `_flush(callback)` has a separate deferred-dispatch finalization
receipt over the same eleven Apple and nine Windows owners. Before selecting
`_flush`, the harness feeds the exact encoder bytes or complete compressed
decoder member through the same receiver's `_transform` and waits for exactly
one error-free prefill callback; this ordering covers both synchronous native
streams and deferred Brotli/zstd fallback buffering without letting setup
stand in for the selected call. The selected source call must return undefined,
set `_flushed === true`, leave `writableEnded === false`, and deliver its
callback exactly once. The nine established owners require no callback error.
The two no-backend zstd owners instead require the exact `ENOSYS` callback
refusal after retained-input finalization; this is evidence for the real
source-defined refusal, not zstd compression or decompression support. The
harness drains only byte-view output, destroys the receiver, requires a null
native handle, quiesces, and observes zero decisions. The author, independent
evidence validator, Rust validator, and loaded-engine boundary repeat the exact
owner vocabulary, inherited `_flush` descriptor, prefill bytes, callback error
code, undefined return, final state, and cleanup contract. `_writeNative`
remains outside this receipt.

Direct synchronous zlib `_processChunk(Buffer, Z_FINISH)` has a distinct
one-shot receipt for the same nine Apple owners and seven non-Brotli Windows
owners as terminal `end`. Compression receives `[105, 98, 101, 120]` and must
return a nonempty byte view; each decoder receives its fixed complete Brotli,
deflate, raw-deflate, or gzip member and must return exactly
`[105, 98, 101, 120]`. The flush flag is fixed to `Z_FINISH` (`4`), even though
the compatibility method currently delegates directly to its stored one-shot
function. Construction may establish an idle native selector, so the harness
must close it in every return or throw path before quiescence. The author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
boundary separately repeat the exact owner set, inherited prototype
descriptor, input, numeric flag, result contract, cleanup, and zero-decision
proof. This receipt does not credit `_writeNative`, `_transform`, `flush`,
`_flush`, `_final`, or `params`; `write` uses the distinct terminal-write
receipt above. It leaves both zstd owners
residual because their one-shot function deliberately reports `ENOSYS`.

The seven reviewed `node:stream` `closed` projections require a constructed
receiver even though the source inventory exposes them as inherited or direct
prototype rows. `Stream()` installs an own accessor backed by `_closed`; the
value does not live on the exported prototype. Authoring therefore cannot reuse
generic prototype reads. It constructs exactly one fresh idle `default`,
`Duplex`, `PassThrough`, `Readable`, `Stream`, `Transform`, or `Writable`,
requires the final property to be an own getter, reads its inert boolean, and
then proves event-loop quiescence with zero decisions. The author, independent
validator, and Rust executor separately repeat that owner/access/result
contract. `readableState` and `writableState` remain residual because their
mutable object graphs are not justified by this scalar receipt.

Fresh HTTP lifecycle evidence is limited to nine independently repeated
contracts: `Agent.destroy`; construction through `Server`,
`Server.constructor`, or `createServer`; and `Server.close`,
`Server.closeAllConnections`, `Server.closeIdleConnections`, `Server.ref`, and
`Server.unref`. Every receiver is constructed by the harness with empty
arguments and owns no listener, socket, or native selector. The recipe author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
harness each repeat the complete `node_http` source descriptor, canonical
`node:http` invocation, exact receiver setup, empty argument list, result type,
and normal-return proof. `Server.close` may schedule its terminal close event;
the receipt is valid only after that event drains and event-loop quiescence is
observed with zero typed decisions. This exception does not admit arbitrary
HTTP calls: client-request operations, `Agent.addRequest`, `Server.listen`,
`Server.getConnections`, and every route requiring or retaining live transport
state remain residual.

Four source-only HTTP validators use separate exact root-call contracts rather
than inheriting the generic captured-output route:
`_checkInvalidHeaderChar("ibex")`, `_checkIsHttpToken("x-ibex")`,
`validateHeaderName("x-ibex")`, and
`validateHeaderValue("x-ibex", "ibex")`. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript harness each
repeat the literal arguments, direct call dispatch, boolean or undefined
result, event-loop quiescence, and zero-decision contract. These four rows were
already executable through the generic captured-output mechanism, so the
stronger proof changes neither target's executable total nor its unresolved
total; it removes them from the generic captured set and from the
descriptor-only residual manifest. This closed proof does not admit malformed
input, thrown validation results, arbitrary header data, or other HTTP
exports.

Fresh net terminal evidence is limited to five independently repeated
contracts: `Server.close`, `Socket.close`, `Socket.resetAndDestroy`,
`Stream.close`, and `Stream.resetAndDestroy`. The dedicated setup constructs
each receiver with empty arguments and attaches one close observer before
dispatch. A fresh `Server` owns no listener, native handle, accept timer,
connection, or Unix path; a fresh `Socket` or legacy `Stream` owns no native
handle, pending connect, write queue, poll timer, or peer route. The loaded
harness still requires exactly one close event and verifies the final
in-memory state: a server is non-listening with a null handle, while sockets
are destroyed, closed, and have a null handle. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript harness
separately repeat the exact five-name vocabulary, canonical `node:net`
invocation, source descriptor, owner setup, empty arguments, object result,
cleanup fields, quiescence, and zero-decision contract. This receipt does not
admit `listen`, `connect`, accepted sockets, writes, reset of a live transport,
or any other operation requiring a native handle or peer lifecycle.

Transport-free TLS socket evidence is limited to five independently repeated
contracts: construction through `TLSSocket`, plus `close`, `destroy`, `ref`,
and `unref` on a fresh harness-created `TLSSocket`. The constructor receives no
underlying transport, so it does not capture a native TLS owner token, create a
TLS engine, bind a selector, install transport listeners, or schedule a timer.
`ref` and `unref` consequently return the wrapper without delegating, while
`close` and `destroy` update only wrapper state and queue the terminal close
event; the receipt is valid only after that timer drains and event-loop
quiescence is observed. The recipe author, independent evidence validator,
Rust validator, and loaded-engine JavaScript harness separately repeat the
complete `node_tls` descriptor, canonical `node:tls` invocation, empty
transport/argument setup, object result, and zero-decision contract. This
closed proof does not admit `connect`, `write`, `end`, server construction, or
any call that binds or operates on a transport.

The TLS `SecureContext.context` read uses a separate constructed-instance
contract. A fresh `SecureContext()` normalizes only the harness-owned empty
options object and installs `context` as an own enumerable, non-writable,
non-configurable data property whose value is a frozen opaque object. No TLS
engine is allocated and no native trust or certificate state is consulted.
The recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat the exact `node_tls`
descriptor, empty constructor, `["context"]` instance access, object result,
quiescence, and zero-decision proof. This scalar-shaped receipt does not expose
the constructor's private WeakMap state or admit certificate, key, cipher, or
server operations.

Fresh TLS Server construction is executable only through a separate retirement
contract for `Server`, `Server.constructor`, and `createServer`. Each source
call creates an idle `net.Server` with no bound transport, native listener,
accept timer, or connection, but `_decorateServer` still mints one private
runtime/principal TLS owner token and installs its `listening` and `close`
registry hooks. The loaded harness therefore attaches exactly one close
observer, invokes the guarded `close`, awaits the internal close hook and the
subsequent retirement timer, and requires one close event plus a later guarded
`address()` call failing with `ERR_TLS_SERVER_CLOSED`. Reaching that terminal
state proves native token release completed before the private state was
scrubbed; a close failure instead escapes the timer and fails the fixture. The
recipe author, independent evidence validator, Rust validator, and loaded
engine separately repeat the exact constructor surface, dispatch kind, empty
arguments, object source result, cleanup fields, quiescence, and zero-decision
contract. This receipt does not admit `listen`, accepted connections,
handshakes, credentials, ticket keys, or any other transport-bearing server
operation.

Fresh HTTPS Server construction uses the same retirement mechanism but retains
its distinct source contract. `Server`, `Server.constructor`, and
`createServer` construct an HTTP wrapper with one private principal stamp and
no HTTP native selector, then install one fresh idle TLS server as its net
server. Neither layer binds a transport; the inner TLS layer owns the single
retirable token. The loaded harness closes the outer HTTP wrapper, observes its
close event only after the inner TLS close event propagates, waits one later
timer turn, and calls the outer `address()`. That call delegates to the guarded
inner server and must fail with `ERR_TLS_SERVER_CLOSED`, proving its token was
released and private TLS state scrubbed before the fixture completed. The
recipe author, independent evidence validator, Rust validator, and loaded
engine separately repeat the exact `node:https` module identity,
`member-assignment` export provenance, empty construction arguments, dispatch,
cleanup fields, quiescence, and zero-decision contract. This does not admit
`listen`, requests, accepted connections, handshakes, credentials, agents, or
client transports.

Fresh UDP lifecycle evidence is similarly limited to `Socket`,
`Socket.constructor`, `createSocket`, `Socket.close`, `Socket.ref`,
`Socket.unref`, and `Socket.dropMembership("224.0.0.1")`, all with the exact
`udp4` constructor argument. Construction creates the authenticated principal
stamp but no native handle, binding, poll timer, or peer route. `ref` and
`unref` therefore update only wrapper state, while `close` marks the wrapper
closed and schedules its terminal event; the receipt requires that event to
drain before quiescence. On that same fresh receiver `dropMembership` returns
`undefined` before consulting the native membership hook because the private
handle remains `-1`; the literal group address does not widen the contract to
other membership calls or receiver states.

The separate `Socket._closed` read constructs the same fresh udp4 receiver and
accesses only its own non-enumerable, non-configurable getter/setter pair. The
getter authenticates the retained owner state and returns its boolean close
bit; it does not expose `_handle`, the private WeakMap state, a binding, or a
route. The author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness each repeat the real
`src/builtins/dgram.js` descriptor, two public module aliases, canonical
`node:dgram` invocation, exact constructed receiver, access/call shape, literal
argument, result type, and zero-decision proof. The closed set still excludes
bind, connect, disconnect, send, address, add-membership,
source-specific-membership, buffer-size, socket-option, and every operation
that requires a bound handle, peer route, throwing result, or separately owned
network lifecycle.

X509 instance evidence is limited to two bounded operations on a fresh
harness-owned `X509Certificate("ibex-x509-fixture")`. The `raw` row requires
the own constructed-instance accessor and returns only its bounded byte object.
The `toString` row calls the source-defined certificate formatter and requires
a string result. Lockdown makes the inherited primordial
`Object.prototype.toString` non-writable, so ordinary assignment previously
failed silently instead of installing the intended X509 override. The builtin
now defines that own method explicitly with the reviewed descriptor, analogous
to other compatibility methods that must survive primordial locking. The
recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat the exact constructor,
access or call kind, result type, quiescence, and zero-decision contract. This
receipt does not admit certificate verification, hostname/email/IP checks,
public-key export, or other X509 operations whose inputs or outputs require a
separate bounded proof.

Three source-only compatibility helpers have a similarly closed receipt.
`exact_crypto.createPrivateKey("ibex-key")` and
`exact_crypto.createPublicKey("ibex-key")` construct only the source-defined
in-memory key wrappers; these compatibility functions do not parse or import
the bytes and do not consult a native key store. `node_readline.CSI(["31m"])`
only concatenates the harness-owned string array into an escape sequence; it
does not open a terminal or retain a stream. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript harness separately
repeat the exact source descriptor, root-call setup, literal argument, result
type, quiescence, and zero-decision contract. This closed list does not admit
other crypto or readline calls. In particular,
`dns/promises.getDefaultResultOrder` remains residual because its public export
is an explicitly marked cross-source projection rather than a locally authored
callable.

`exact_crypto.KeyObject.equals` has a separate pair-owner receipt. The harness
constructs two distinct secret `KeyObject` instances from the same fixed four
bytes (`ibex`) and passes the second only through a named setup binding to the
first instance's exact prototype method. The returned boolean proves the
source-defined in-memory byte comparison. The four validators repeat the
complete descriptor, bytes, key type, receiver, peer binding, result,
quiescence, and zero-decision contract. The setup kind is specific to this
route; it does not expose a generic nested-constructor argument that another
crypto callable could inherit.

`node_readline.Interface.close` and `node_readline.Interface.pause` have
separate lifecycle-owner receipts. Each harness constructs a fresh
non-terminal `Interface` over an inert input shim that accepts only the exact
data, error, end, and close listeners and records exactly one constructor
resume. The close receipt proves the selected call detaches every listener,
pauses exactly once, closes the receiver, emits one close event, returns
`undefined`, and reaches event-loop quiescence with zero legacy or typed
decisions. The pause receipt first proves the selected call returns the
receiver object while leaving it open but paused, preserves all four
constructor listeners, records exactly one pause, and emits no close event.
The harness then invokes exact `Interface.close` as auxiliary cleanup and
proves every listener detached, two total pauses, one close event, quiescence,
and zero decisions. Cleanup runs even when the pre-cleanup pause-state check
fails. The recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat each complete descriptor,
owner, terminal mode, listener lifecycle, result, cleanup, and zero-decision
contract. This closed list does not admit the constructor-instance
`_onAbortSignal`, `_onClose`, or `_onError` closures.

Acceptance:

- Every authorable edge has positive, negative, wrong-principal, malformed,
  missing-attribution, and target-specific fixtures.
- Multi-effect, lifetime, revocation, loader, filesystem, network, process, and
  escape-surface suites pass on every advertised target.
- The report binds source revision, engine identity, target, profile, semantic
  and registry digests, fixture catalog, and observed results.
- Unsupported targets do not advertise or silently degrade the complete profile.

### WP11 — Reconcile the corpus and remove the legacy plane

Update LLP 0013 and LLP 0014 to describe the final mechanism and artifact,
revise LLP 0016's assessment, update LLP 0002/0004/0005 where their contracts
change, refresh demos and documentation, and delete dead code/generators/tests
for the legacy plane.

Implementation status (2026-07-25): the `PolicyFile` parser and public module,
the `HostConfig` policy/path/allow/deny seams, and the policy-string mode parser
have been deleted. Foreground audit deliberately constructs a policyless
diagnostic Host under LLP 0030; no durable string-policy value is representable
at that boundary. Historical compatibility-manager import/deputy/dynamic
algebra remains covered only through private test setup, not a parser or
embedder configuration surface. LLP 0013, LLP 0014, and LLP 0016 identify their
old mode, flag, and string-policy passages as superseded. The canonical typed
artifact, armed snapshot, and target-bound conformance report are the current
contracts. ENG-24263 retired LLP 0013's executable string-policy corpus and its
127 legacy fixtures. A checked 69-case retirement join names the current typed,
armed-engine, production-closure, or migrated diagnostic coverage for every
former test; the live callback harness also proves package-global withholding
and native-freeze hatch removal, while process signaling is covered inside the
authenticated armed process-closure test.

Acceptance:

- `./ref-check` passes and all capsec `@ref`s point to current semantics.
- No documentation teaches permissive-by-default or the legacy string format.
- No production path parses or executes the legacy `PolicyFile` model.
- The root LLP and implementation-status sections identify the supported
  profile and current target conformance honestly.

## Dependency order

The executable dependency graph is:

```text
WP0 ─┬─> WP1 ────────────────┐
     └─> WP2 ─> WP3 ─> WP4 ─┼─> WP5 ─┐
                            ├─> WP6 ─┤
                            ├─> WP7 ─┼─> WP9 ─┐
                            └─> WP8 ─┘        ├─> WP11
WP1 ────────────────────────────────> WP10 ───┘
WP5, WP6, WP7, WP8 ─────────────────> WP10
```

WP5–WP8 are intentionally parallel once the typed core and armed-snapshot seam
exist. WP10 begins with registry/fixture infrastructure during WP1 and closes
only after every enforcement workstream lands. WP9 is the product cutover, not
the point at which enforcement work starts. WP11 removes the old plane only
after both cutover and conformance are green.

## Linear execution contract

Each WP maps to one child issue beneath an umbrella issue. Issues use Linear's
blocking relations to encode the graph above and belong to the Exact project.
Every issue description must include:

- this LLP and its WP anchor;
- the exact in-scope surfaces and explicit exclusions;
- acceptance criteria copied or strengthened from the WP;
- required tests and generated artifacts;
- the LLPs and existing `@ref`s that govern its files;
- a rule that semantic/code changes update the governing LLP in the same commit.

The umbrella issue tracks the overall completion gate but is not a substitute
for dependency relations. The created issue set is:

| Work package | Linear issue | Blocked by                                            |
| ------------ | ------------ | ----------------------------------------------------- |
| Program      | ENG-24143    | completion is defined by the child graph              |
| WP0          | ENG-24144    | —                                                     |
| WP1          | ENG-24145    | ENG-24144                                             |
| WP2          | ENG-24146    | ENG-24144                                             |
| WP3          | ENG-24147    | ENG-24146                                             |
| WP4          | ENG-24148    | ENG-24145, ENG-24147                                  |
| WP5          | ENG-24149    | ENG-24148                                             |
| WP6          | ENG-24150    | ENG-24148                                             |
| WP7          | ENG-24151    | ENG-24148                                             |
| WP8          | ENG-24152    | ENG-24148                                             |
| WP9          | ENG-24153    | ENG-24149, ENG-24150, ENG-24151, ENG-24152            |
| WP10         | ENG-24154    | ENG-24145, ENG-24149, ENG-24150, ENG-24151, ENG-24152 |
| WP11         | ENG-24155    | ENG-24153, ENG-24154                                  |

## Risks and controls

### Scope expansion

The Oden corpus contains product workflows far beyond Ibex's core needs.
Deferring grant-assistant, publication, daemon, and privacy systems keeps this
plan focused. New product surfaces must justify themselves independently.

### A typed model that remains incomplete

Schemas alone do not create security. Generated surface inventory and target
cells land before broad conversion work, and target claims stay closed until
fixtures prove each edge.

### Big-bang cutover instability

The external cutover is direct, but implementation is staged behind internal
seams. The typed decision core, generator, and armed snapshot land before
surface conversions; filesystem/network/escape/handle work then proceeds in
parallel. The legacy plane is deleted only at the end.

### Cross-project drift with Oden

Ibex should reuse runtime-neutral schemas, canonicalizers, property fixtures,
and Rust decision logic where practical, but not force Deno-specific vocabulary
or product workflow into Hermes. Shared components need one source of truth and
cross-repo fixture parity; target-specific coverage edges remain local.

### Default enforcement before evidence

Having no external users removes migration constraints, not the need for
correctness. WP9 remains gated on complete initial enforcement and WP10 remains
the release/claim gate. Development can exercise the new default earlier, but
unsupported targets may not silently claim completion.

## Completion criteria

This plan is complete when:

1. The typed effect model is the only production policy and decision plane.
2. Every production surface has a generated classification and target cell.
3. Canonical policy and armed snapshots are deterministic, typed, digest-bound,
   and fail closed on mismatch.
4. Filesystem and network checks bind the object/peer actually used, with
   staged multi-effect authorization.
5. Handles, dynamic authority, deputy intersection, import gating, and audit
   evidence operate on the same immutable effect semantics.
6. Plain `ibex` execution enforces the supported profile and offers no silent
   weakening path.
7. Every advertised target has a passing generated conformance report.
8. Legacy policy code, docs, demos, and stale LLP claims are removed or revised.

Acceptance on 2026-07-28 closes the security-critical implementation program
without weakening criterion 7 as a release-claim gate. The advertisement set
is empty, so no target is claimed without a passing complete report; finishing
the remaining exact-target public-surface catalog and promoting a target are
separate, prioritized follow-ups. Unresolved catalog rows are not evidence of
ambient authority, but they remain explicit residual uncertainty and must not
be represented as verified conformance.

## Resolved WP0 questions

1. Ibex owns the canonical contract and neutral crate boundary initially;
   another consumer reuses it or explicitly moves ownership, never copies it.
2. The profile is `ibex/capsec/1`; the neutral core is
   `capsec/semantics/1`.
3. Location, camera, microphone, and clipboard are target-specific authorable
   definitions; storage and unproved device families stay closed, absent, or
   unsupported exactly as the generated reconciliation records.
4. Production gets no raw/permissive developer harness; isolated fixtures and
   the explicit ephemeral audit workflow cover compatibility work.
5. WP9 may flip after one exact target is complete, but every incomplete build
   target refuses before project code. No target silently inherits another
   target's conformance or falls back to the legacy plane.

## Amendment: scoped advertisement (2026-08-06)

> **Status: DRAFT, UNDER LLP 0049 PHASE 1 REVIEW; no gate code may land
> until this amendment's review completes (LLP 0044 §7 item 5).
> Round-1 revision applied 2026-08-06 (both round-1 flip sets,
> `llp/reviews/0021-scoped-advertisement-amendment.codex.md` and
> `…fable.md`, applied in full); round-2 revision applied 2026-08-06
> (both round-2 flip sets — Codex's three items and Fable's four —
> applied in full); round 3 (the final round the LLP 0049 §9 loop bound
> permits) pending.**
>
> This amendment is the LLP 0049 Phase 1 review package required by
> LLP 0044 §2's scope-digest lifecycle paragraph. It changes the
> promotion/advertisement claim boundary: an advertisement stops meaning
> "whole-tuple conformant" and starts meaning "certified for a declared,
> generated, dependency-closed scope, with everything else explicitly
> uncertified." The decided posture it implements is the LLP 0044 §7
> resolution record of 2026-08-06: item 1 scoped certification ACCEPTED,
> item 2 UNCERTIFIED remainder, item 4 fs+env+process. Register item 5
> (the runtime scope join, §A6 below) remains an open author decision that
> this amendment designs but does not decide. Until the review completes
> and the author decides item 5, every pre-amendment section of this
> document — in particular WP10's completeness rule and the
> "Default and target claim" — remains the enforced state of the system.
>
> All file:line citations in this amendment are pinned at `main` =
> `6416114d` (2026-08-06). `scopeDigest` has zero occurrences in code at
> this revision (verified by repository-wide search over `src/`,
> `crates/`, `packages/ibex-devtools/src`, `scripts/`, `build_support/`,
> and `tools/`): this amendment designs the scope identity from a blank
> page, and the join matrix in §A9 says so row by row. Re-pin lines
> before implementing.
>
> **Disclosed pin drift (recorded 2026-08-06, round-2 revision).** The
> pin is already stale in one place both round-2 reviewers checked:
> `assertRecipeCatalogComplete` is at
> `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs:5048`
> at `6416114d` and at **`:5248`** at `f154a5c5` (verified at both), so
> §A2's and M2's `:5048` / `:5050-5055` / `:5062-5081` citations name the
> right code at the wrong lines today. This is the disclosed drift the
> paragraph above anticipates, not an error; it is recorded explicitly so
> a round-3 reader does not re-derive it. Rows whose citations were
> re-verified at `f154a5c5` during the round-2 revision say so in the row
> (M11, M18, M27, and A3's projection/ingress facts).

### A1. The scope object

The scope is a canonical, generated artifact with its own digest domain —
never a hand-authored list and never a property scattered across other
artifacts.

- **Schema (proposed):** `ibex/capsec-scope/1`; digest domain
  `ibex:capsec:scope:1` under the canonical-form rule of LLP 0032
  (JCS serialization, domain-separated tag, self-digest field excluded
  from the digest input).
- **Contents (closed field set):** profile (`ibex/capsec/1`); the target
  tuple (triple + canonical sorted feature list, exactly the fields
  `select_v2_advertisement` matches on,
  `src/host/portable_target_admission.rs:571-580`); the **intensional
  definition** in a closed selector grammar — enumerated
  capability-family identifiers and surface-kind identifiers with set
  semantics only, no free-form predicates, so the lineage superset check
  is set inclusion, not interpretation; the **expanded cell set** — the
  exact `edgeId` list the generator expands from the live inventory, each
  cell complete and indivisible (scenario class is descriptive, never a
  selection axis; no scenario obligation of an in-scope cell can be
  subtracted); the **closure edges** — the conservative pre-execution
  dependency closure computed from source-derived routes and
  argument-selected branch alternatives, never from observed sequences;
  the predecessor scope digest or an explicit genesis marker (§A5); and
  `scopeDigest` itself.
- **Companion artifacts, each in its own digest domain** (LLP 0044 §2):
  the expansion diff (`ibex/capsec-scope-expansion-diff/1`, domain
  `ibex:capsec:scope-expansion-diff:1`) recording per-cell
  additions/retirements against the predecessor expansion, with each
  retirement validated against the live inventory (a "retired" cell still
  present in the inventory is narrowing and fails); and the
  rename/split/merge mapping (`ibex/capsec-scope-cell-mapping/1`, domain
  `ibex:capsec:scope-cell-mapping:1`) generated from inventory history
  and validated the same way. Both are bound into the scope artifact by
  digest. Split and merge entries must be total on both sides: every
  predecessor cell named by a mapping entry must be consumed exactly
  once, and every successor cell produced exactly once (§A8 F9).
- **Generator:** a new devtools script beside
  `generate-capsec-conformance-recipes.mjs`, consuming the same reviewed
  coverage/implementation inputs the fixture catalog consumes
  (`fixtureCatalogForTarget`,
  `packages/ibex-devtools/src/scripts/capsec-conformance.mjs:304`). The
  generator is the sole **creator** of `scopeDigest`; every other
  consumer either independently re-derives it (admission, §A3), binds it,
  compares it, or carries it (§A9).
- A dependency that cannot be conservatively resolved keeps its dependent
  cell out of scope or fails promotion — never a warning. Every physical
  observation during the ceremony is validated against the closure: an
  observed traversal into a cell the closure excluded **fails the run**
  (it proves the closure wrong; §A8 F8).

### A2. Scoped completeness rule

`assertRecipeCatalogComplete`
(`packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs:5048`)
currently requires, over the whole catalog:
`fullyExecutableFixtures + internallyVerifiedFixtures === requiredFixtures`
and `unresolvedFixtures === 0` (:5050-5055), then per-recipe status
validation. The amendment binds it to the scoped required set:

- The catalog summary partitions by scope membership of each row's cell
  (`edgeId` ∈ expanded cell set). New summary fields carry
  `scopeDigest`, `requiredFixturesInScope`, `unresolvedFixturesInScope`,
  and the out-of-scope remainder counts.
- The completeness assertion becomes exactly
  **`unresolved-in-scope === 0`** with
  `fullyExecutableInScope + internallyVerifiedInScope ===
  requiredFixturesInScope`, and per-recipe validation runs for every
  in-scope row exactly as today (internally-verified proof-plan equality
  included, :5062-5081).
- Out-of-scope rows are never deleted, never reclassified, and never
  counted toward completeness: they remain in the catalog as the
  enumerable uncertified remainder. A row whose cell is out of scope but
  whose status is anything other than its honest current status fails
  validation — scoping must not perturb the remainder's accounting.
- The four `checkPromotion` names
  (`packages/ibex-devtools/src/scripts/run-capsec-conformance.mjs:1868-1899`)
  keep their names and order; `executable-recipe-catalog` and
  `public-surface-execution` bind to the scoped expansion (§A9 M2, M3),
  and `assertReportMayAdvertise`
  (`packages/ibex-devtools/src/scripts/capsec-conformance.mjs:612`)
  requires the report's scope bindings (§A9 M4).

Partial-cell credit stays closed under any name: membership is per
complete cell, so every generated scenario row of an in-scope cell counts
toward `unresolved-in-scope`.

### A3. Scoped arm-state admission (`ScopedAdvertised`)

Today `Host::new_armed_with_target_cells` (`src/host/mod.rs:781`) refuses
any cell map that is not exhaustive over
`CAPSEC_COVERAGE_EDGE_IDS` with every cell `Complete` or `Closed`, and
any arm state other than `TargetArmState::CompleteAdvertised`
(:824-845, refusal "armed target cells are incomplete" :844). The
amendment adds a **distinct scoped arm state**, constructed only from an
admitted scoped report:

- `TargetArmState` (`crates/capsec-semantics/src/decision.rs:52-56`)
  gains `ScopedAdvertised` carrying the admitted scope identity (the
  digest, plus the admitted remainder accounting for introspection).
- **The opaque admitted aggregate — `AdmittedScopedTargetCells`.** The
  admission result is one opaque object, named exactly
  `AdmittedScopedTargetCells`, constructible **only** by portable report
  admission (§A9 M7 — private constructor in
  `src/host/portable_target_admission.rs`, no public field access, no
  `Default`, and **no constructor outside `portable_target_admission`**.
  Precision, round-2 revision: `portable_target_admission` is a private
  child module (`src/host/mod.rs:23`), so the opaque type is genuinely
  unconstructible from `src/host/mod.rs` and the M15 constructors
  provably cannot mint it — that half is a type-system boundary. But
  the in-file `#[cfg(test)]` module at
  `src/host/portable_target_admission.rs:1560` is a *descendant* module
  with full private access, so "no test constructor" there is
  constrained **by review, not by the type system**. F11's negative half
  is stated against the M15 constructors, where the boundary is real,
  and must not be read as covering the in-file test module.)
  It contains, inseparably: (a) the
  **re-derived scope identity** (the recomputed `scopeDigest` plus the
  lineage-resolved predecessor it was compared against and the
  remainder accounting); (b) the **expanded in-scope set** (the exact
  `edgeId` list); and (c) the **exhaustive host-level cell
  dispositions** for every generated edge. `Host` consumes the
  aggregate **atomically**: the constructors (§A9 M12/M13) take the
  aggregate, not a bare map, re-check the in-scope/out-of-scope
  partition against the carried expansion at construction, and retain
  the aggregate itself. Both runtime introspection (§A9 M16) and the
  per-gate `TargetCellDisposition` projection derive from the **same
  retained aggregate** — there is no second copy of the scope, the
  expansion, or the map anywhere in the armed Host, so
  introspected-scope/enforced-map divergence is unrepresentable
  (§A8 F11's positive invariant). An independently mutable parallel
  Host record is explicitly rejected as not security-equivalent.
- The cell map remains **exhaustive**: every generated edge must appear.
  The map's value type is a **new host-side disposition type**,
  `HostCellDisposition` (it may live beside the aggregate in
  `portable_target_admission.rs`): `Certified(TargetCellDisposition)`
  for in-scope cells — carrying `Complete`/`Closed` exactly as derived
  today (`src/host/portable_target_admission.rs:1489-1505`) — and
  `Uncertified` for out-of-scope cells. The typed vocabulary
  (`TargetCellDisposition`, `crates/capsec-semantics/src/decision.rs:395-400`)
  is untouched: `Uncertified` projects to
  `TargetCellDisposition::Incomplete` in **`fn target_cell`**
  (`src/host/mod.rs:956-961`), keeping decision.rs untouched. Arming
  with a cell absent from the map remains a refusal — the exhaustiveness
  check is not relaxed (§A8 F2). (Type placement settled by this design
  revision; recorded in §A10.)
  **Projection site corrected (round-2 revision; re-verified at
  `f154a5c5`).** The round-1 text pinned the projection to
  `src/host/mod.rs:2844-2846`. That is one of **eleven** `EffectGate`
  construction sites (`grep -c "target_cell: self.target_cell"
  src/host/mod.rs` = 11: :2346, :2846, :2929, :3002, :3107, :3188,
  :3346, :3495, :3588, :3684, :3768), so "exactly at" was wrong. The
  genuine single funnel every one of them passes through is the private
  `fn target_cell` (:956-961), which today does
  `self.target_cells.get(edge).copied().unwrap_or(Incomplete)`.
  Projecting there requires `HostCellDisposition` to derive `Copy` so
  the `.copied()` shape and `TargetCellDisposition`'s own `Copy`
  (`decision.rs:393`) are both preserved; a non-`Copy`
  `HostCellDisposition` would force a signature change at all eleven
  sites and is therefore rejected. Making the funnel authoritative is
  necessary but **not sufficient** — see the ingress rule below.
- **The aggregate must be authoritative at every evaluator ingress —
  the ingress rule (normative; new in the round-2 revision).** The
  round-1 text asserted that under `ScopedAdvertised` every per-gate
  disposition derives from the retained aggregate and that
  introspected/enforced divergence is therefore "unrepresentable." That
  claim was **false at the ABI boundary**, and the correction is the
  most load-bearing change in this revision. Verified at `f154a5c5`:
  - `EffectGate.target_cell` is a **public** field of a
    `Deserialize` struct (`crates/capsec-semantics/src/decision.rs:401-407`),
    so a gate is fully caller-constructible from JSON.
  - `ex_host_evaluate_typed_decision` (`src/host/abi.rs:5823-5839`) is an
    **unconditionally exported** `#[no_mangle] pub unsafe extern "C"`
    symbol taking a caller-supplied `gates` buffer. It calls
    `Host::evaluate_typed_decision_json_with_evidence`
    (`src/host/mod.rs:3963-3990`), which strict-parses the buffer,
    `serde_json::from_value`s it into `Vec<EffectGate>`, and evaluates it
    **unchanged**. Four `pub` Rust-level ingresses take caller-supplied
    gates the same way — `evaluate_typed_decision` (:3776),
    `evaluate_typed_decision_with_evidence` (:3844),
    `evaluate_typed_decision_json` (:3942),
    `evaluate_typed_decision_json_with_evidence` (:3963). (The only
    in-repo caller of the C symbol is test-gated —
    `src/bin/ibex/engine/hermes.rs:1144` under
    `#[cfg(all(test, feature = "capsec-conformance-observer"))]` — but
    the *symbol* is exported unconditionally and is reachable by any
    embedder or native runtime extension linking the host ABI, which is
    exactly the population this certification speaks to.)
  - `Host::authorize_runtime_extension_operation`
    (`src/host/mod.rs:1107-1310`, `pub(crate)`, **not** test-gated,
    reached from the exported
    `ex_host_authorize_runtime_extension_operation_v1`,
    `src/host/abi.rs:5447`/`:5587`, and from
    `src/host/embedder_artifacts.rs:2193`) constructs its gate directly
    at :1304-1310 with `target_cell: TargetCellDisposition::Complete`
    hardcoded and `coverage_edge_id` taken verbatim from the
    caller-supplied `effect_semantics` argument (:1113, :1266).
  So today an out-of-scope edge presented as `complete` — or a
  runtime-extension effect-semantics string naming an uncertified cell —
  reaches the evaluator with a disposition the admitted map never
  produced. The A3 claim is repaired by rule, not by assertion:

  > **Ingress rule.** Under `TargetArmState::ScopedAdvertised`, no
  > `EffectGate` may be evaluated whose `target_cell` was not produced
  > by `fn target_cell` from the retained `AdmittedScopedTargetCells`.
  > Every evaluator ingress — the four `pub` Rust methods, the C ABI
  > entry point behind them, and the runtime-extension path — **must
  > discard the incoming `target_cell` and recompute it** from the
  > aggregate, keyed by the gate's `coverage_edge_id`, before the gate
  > reaches `evaluate_decision_set*`.

  **Discard-and-recompute is preferred over equality-checking** the
  caller's value, for three reasons. (1) It is *total*: an
  equality-check has to decide what to do about an edge id absent from
  the aggregate, and the honest answer there is already
  `target_cell`'s `unwrap_or(Incomplete)` default — recomputation gets
  that for free, an equality-check has to re-derive it and can get it
  wrong. (2) It removes a value from the trust boundary rather than
  validating one across it: after recomputation the caller's byte has
  no authority at all, so no future refactor can reintroduce a path
  where it wins. (3) It cannot fail-open on a mismatch: an
  equality-check is one inverted comparison away from admitting the
  caller's `complete`, whereas recomputation has no comparison to
  invert. The cost is that a caller passing a *correct* disposition can
  no longer detect that it did so — which is not a capability anything
  needs. The recomputed value is what the decision uses; the discarded
  incoming value MAY be recorded in the telemetry envelope below as a
  `presentedTargetCell` field for diagnosis, and a presented value that
  differs from the recomputed one is a reportable event, never a
  refusal input.
  **The runtime-extension direct-`Complete` path is scoped, not
  eliminated.** Eliminating it would mean routing runtime-extension
  authorization through the coverage inventory, which it deliberately
  is not in: its `coverage_edge_id` is an extension-declared
  effect-semantics string, not necessarily a generated `edgeId`. What
  authorizes it today is the static-floor coverage check immediately
  above it (`src/host/mod.rs:1245-1264` — every constrained principal's
  static authority must cover the requested selector) plus the
  admission of the extension itself; the `Complete` literal is
  asserting "this gate's cell obligation is not the mechanism guarding
  this call," not "this cell is certified. " Under `ScopedAdvertised`
  that is no longer safe to leave implicit, so the normative rule is:
  the path resolves its `coverage_edge_id` against the aggregate
  first — if the id **is** a generated inventory edge, the aggregate's
  disposition wins (an `Uncertified` cell refuses, exactly as any other
  out-of-scope reached gate does); if it is **not** a generated edge,
  the path keeps its literal `Complete` and the refusal envelope records
  `hostDisposition: "extension-declared"`, which is the honest
  statement that this decision was never scope-governed. A
  runtime-extension effect-semantics string that collides with a
  generated `edgeId` therefore cannot launder an uncertified cell into
  `Complete`. §A9 M32 is the worklist row; §A8 F1c and F3 gain the ABI
  subcases that prove it.
- **Uncertified is distinguishable from incomplete-by-defect — the host
  telemetry envelope.** The distinction lives at the host cell-map layer
  and in refusal telemetry, not in the typed decision algorithm: the
  reached-gate refusal semantics are `Incomplete`'s
  (`crates/capsec-semantics/src/decision.rs:609-621` refuses before any
  lifecycle result, and the hard decision already carries
  `Some(gate.coverage_edge_id)` at :618). The host emits a **named
  machine-readable envelope**, schema `ibex/capsec-scoped-refusal/1`,
  keyed by `coverage_edge_id`, with the closed field set:
  `coverageEdgeId`; `scopeDigest` (from the retained aggregate);
  `hostDisposition` (`uncertified` | `incomplete-defect` |
  `absent-edge` | `extension-declared`, resolved by aggregate lookup —
  under `ScopedAdvertised`, admission has already refused any in-scope
  defect, so a runtime `TargetCellIncomplete` can only be an
  out-of-scope cell or an absent-edge default,
  `src/host/mod.rs:956-961`); the optional `presentedTargetCell`
  (the discarded ingress value, per the ingress rule above); and the
  echoed `DecisionReason`. This keeps the typed decision path
  scope-transparent (§A9 M14).
  **There is no central emission point today, and creating one is
  scope-validating work (correction, round-2 revision).** The round-1
  text said the envelope is emitted "at the central host refusal path —
  the single code path that receives a hard `TargetCellIncomplete`
  decision." No such path exists. Verified at `f154a5c5`: there are
  **three independent decision-evaluation bodies** with **four**
  `capsec_semantics::decision::evaluate_decision_set*` call sites —
  `evaluate_typed_decision_inner_and_then` (`src/host/mod.rs:3794`,
  calling :3811 and :3820),
  `evaluate_typed_decision_with_evidence` (:3844, calling :3857), and
  `evaluate_typed_path_decision_with_evidence` (:3874, calling :3888).
  The latter two do **not** delegate to `_inner_and_then`; each acquires
  its own `decision_context` read guard and calls the evaluator
  directly. So the envelope requires either (a) funnelling all three
  bodies through one refusal-observing helper that sees every returned
  `Decision` before it leaves the Host, or (b) emitting at all three
  sites. (a) is preferred — three emission sites is three places to
  forget one, and the ingress rule above needs the same funnel anyway —
  but either discharges the obligation. Building that funnel is
  **scope-validating work carried by §A9 M13/M14**, not an existing
  property being relied upon. Whether host-emitted telemetry alone
  satisfies LLP 0044's "distinguishable in refusal telemetry" — or the
  annotation must ride the typed decision as a new `DecisionReason`,
  a decision.rs change that flips M14 to scope-validating for a second,
  independent reason — remains the named review question (§A10 #1); the
  envelope above plus the funnel is the fully specified host-layer
  design that question chooses between.
- A `ScopedAdvertised` state is constructible **only** through the
  admission path (§A9 M7/M12) — concretely, only from an
  `AdmittedScopedTargetCells` aggregate. The dev/insecure/observer/test
  constructors (§A9 M15) keep synthesizing
  `CompleteAdvertised`-with-synthetic-cells and must remain incapable of
  minting a `ScopedAdvertised` state, an `AdmittedScopedTargetCells`
  value, or a scope digest (§A8 F11).

### A4. Single active scope

Exactly one active scope per tuple. Admission **rejects** a second
concurrent scope for the same target/features rather than selecting among
scopes. The existing uniqueness refusal in `select_v2_advertisement`
("no unique verified advertisement",
`src/host/portable_target_admission.rs:568-580`) already refuses two
advertisements for one tuple; the amendment extends the invariant to the
scope: one advertisement carries exactly one `scopeDigest`, and a catalog
carrying two rows for the tuple — even with distinct scope digests —
remains refused (§A8 F5).

### A5. Monotone lineage

Rollback-resistant, per LLP 0044 §2, anchored in the checked-in promotion
lineage that `scripts/portable-engine-promotion-lineage.mjs` already
validates:

- The scope artifact embeds its predecessor's `scopeDigest`, forming a
  hash chain. Admission does not take the artifact's word for which
  predecessor is current: it resolves the tuple's currently admitted
  scope from the checked-in promotion lineage and requires the new
  artifact's predecessor digest to equal it. Pointing at an older,
  smaller predecessor fails admission (§A8 F6).
- A **genesis** scope is explicitly marked and admissible only when the
  lineage records no prior scope for the tuple (LLP 0049 Phase 3 step 1).
- Narrowing is expressible only as inventory retirements (validated
  against the live inventory via the expansion diff) or authenticated
  rename/split/merge mappings; any other narrowing fails promotion. The
  intensional superset check is set inclusion over the closed selector
  grammar.
- **Semantic preservation across the mapping (normative).** Totality of
  the mapping (§A1) accounts for identifiers; these rules preserve the
  obligations behind them. Mapping validation fails promotion unless
  every rule holds:
  - a **rename** of an in-scope predecessor cell places its successor
    in scope;
  - a **split** of an in-scope predecessor cell places **every**
    successor in scope — no successor of an in-scope cell may land in
    the uncertified remainder;
  - a **merge** with **any** in-scope predecessor places the successor
    in scope;
  - a predecessor cell named by any mapping entry **cannot
    simultaneously count as retired** — the retirement set and the
    mapped-predecessor set must be disjoint;
  - the **predecessor and current inventory digests** are bound into
    the mapping artifact and **independently regenerated** by the
    validator from the two inventory revisions — live-inventory absence
    alone never proves a retirement, so inventory drift cannot be
    laundered as retirement;
  - **genesis admission searches authenticated history** for the
    canonical tuple: a genesis-marked scope is admissible only when no
    revision in the walk records a scope for that exact tuple (§A9
    M27's discovery walk, run down to the pinned lineage floor).
- **Genesis history-completeness precondition (normative; added by the
  round-2 revision — this closes the one live bypass either round-2
  review found).** The round-1 text said genesis is admissible when the
  walk "exhausts **retained** history," and nothing constrained what
  "retained" meant. Verified at `f154a5c5`:
  `grep -n "shallow\|grafts\|rev-list\|--depth"
  scripts/portable-engine-promotion-lineage.mjs` finds only
  `--no-replace-objects` (`:144`) — no shallow-repository assertion, no
  graft or replace-ref check, no root pin. A checkout whose **tree is
  current** but whose history is truncated (shallow clone, re-created
  repository, filtered history) would therefore exhaust the walk
  immediately and mint a genesis scope — arbitrarily narrow, with no
  predecessor comparison and no F6 trip. This is **not** the
  whole-checkout-rollback boundary documented below, which concerns a
  binary rebuilt from *old* sources; here the sources are current and
  only the lineage evidence is absent. Before any genesis conclusion the
  verifier therefore asserts a non-shallow object store, the absence of
  grafts and replace refs, and first-parent termination at the **pinned
  lineage floor** — the full precondition set and its object-level
  rationale are in §A9 M27 (v) and (vi), and F6a/F6e fixture it. Absence
  of a predecessor must be a positive, checkable fact about
  content-hashed objects, never the failure of a search.
- **Tuple migration is a named open decision (§A10 #7).** Any
  feature-list change creates a fresh tuple and therefore a legitimate
  fresh genesis with no predecessor — the one narrowing-shaped move the
  per-tuple chain permits. Whether genesis admission must additionally
  refuse while a *prefix tuple* (same triple, different feature list)
  has a live scope is the author's decision, referencing deferred
  register item 7.
- **Genuine inventory retirement bottoms out in reviewed inventory code
  changes.** A cell that truly leaves the generated inventory narrows
  the certified surface, and the chain permits it by design; the guard
  on that one lane is code review of the inventory change (the LLP 0044
  §2 / LLP 0040 accepted posture), not this chain. Stated here so no
  reader mistakes the expansion-diff validation for a guard it is not.
- Scope expansion is strictly monotone via the chain; each expansion is a
  new promotion, never an edit.

### A6. Register item 5 design: the runtime scope join (decision required)

LLP 0044 §2 deliberately left the runtime join undesigned: the
armed-snapshot producer, the `ibex/capsec-armed/1` parser, and
`ExpectedArmingIdentity` carry no scope identity today, and the Host
obtains authenticated target cells separately through
advertisement/report admission. The three sub-questions, designed against
the real code:

**(i) Does the armed snapshot carry `scopeDigest`, or does an
independently authenticated scope identity join beside it?**

*The real producer/parser.* The production snapshot is composed by the
launcher itself: `build_default_armed_host`
(`src/bin/ibex/runtime.rs:5242`) instantiates the checked-in identity
template `capsec/examples/armed-snapshot.canonical.json` (:5290-5293),
fills in launcher-observed facts (engine identity, entry, project-root
discovery, path canonicalizers, protected artifacts), stamps `runNonce`
and `armedSnapshotDigest` in `finalize_production_snapshot` (:4804-4816,
called at :5814), builds `ExpectedArmingIdentity` from the same document
(:5827-5881), and authenticates via `ArmedSnapshot::load`
(`crates/capsec-semantics/src/arming.rs:345`, schema pin
`ibex/capsec-armed/1` :351, frozen digest projection
`crates/capsec-semantics/src/digest.rs:159-163`). The launcher **never
reads the promoted report**: target cells reach the Host on a separate
path — `Host::new_armed` (`src/host/mod.rs:723`) calls
`authenticated_target_cells` (:6726), which admits the compile-time
embedded advertisement, admission marker, and promoted report
(:6738-6752) and joins them to the snapshot only through the tuple
(`snapshot.engine_target()` + `engine_features()`) and the loaded engine
identity (`authenticate_local_engine`,
`src/host/portable_target_admission.rs:1534`).

*Option A — snapshot carries `scopeDigest`.* The launcher has no
independent source for the value: it would copy it from the same embedded
advertisement chain the Host already admits, so the snapshot copy is
derivative — it adds a second copy that must be kept consistent and
authenticates nothing the admission path has not already authenticated
(a compromised embedded chain compromises both copies identically).
Mechanically it requires: a new field in the snapshot document and in
`ExpectedArmingIdentity` (`crates/capsec-semantics/src/arming.rs:70-109`);
either a schema revision to `ibex/capsec-armed/2` or a change to the
frozen v1 digest projection (`digest.rs:159-163`) — both restamp the
reviewed digest-contract surface (`capsec/contract-files.json`,
`capsec-contract.mjs:496`, the digest vectors, and the checked-in
template); and it ripples into every schema-pinned consumer outside this
plan's blast radius, including the single-file-executable chain
(`crates/sfe-format/src/lib.rs:787`,
`crates/sfe-format/src/app_bound.rs:387`,
`crates/sfe-catalog/src/lib.rs:708`), the host ABI ingestion route
(`src/host/abi.rs:1381-1392`), and the embedder template path
(`src/host/embedder_artifacts.rs:702`). §A9 M11 enumerates these.

*Option B — an independently authenticated scope identity joins beside
the snapshot.* The scope digest is delivered exclusively by the admission
result: `authenticated_target_cells`/`authenticated_report_target_cells`
(§A9 M7) returns the opaque `AdmittedScopedTargetCells` aggregate (§A3)
— the exhaustive scoped cell map **and** the admitted scope identity,
inseparably — both re-derived/validated against the checked
source-derived authority (`checked_report_authority`,
`src/host/portable_target_admission.rs:1151`), with the lineage
predecessor compared against the build-embedded checked promotion
admission (§A9 M27); `Host::new_armed_with_target_cells` consumes the
aggregate atomically into the `ScopedAdvertised` arm state. `ibex/capsec-armed/1` and
`ExpectedArmingIdentity` are byte-for-byte unchanged; the snapshot's role
stays exactly what it is today — authenticating launcher-observed
execution identity, tuple, and engine — and the tuple+engine join is the
only bridge between snapshot and scope, exactly as it is today between
snapshot and report.

**Recommendation: Option B.** The security argument: the only component
that can *independently* re-derive the scope (expansion + closure
recomputed against the bound inventory) is report admission; every copy
of `scopeDigest` placed anywhere else is either derivative (adds
consistency obligations without adding authentication) or a new
substitution surface (a launcher-asserted value a lookalike snapshot
could vary). Option B keeps the trusted base minimal, adds zero schema
revisions and zero digest-contract restamps outside the promotion chain
itself, and leaves the snapshot's reviewed threat model untouched.

**(ii) How is snapshot/report scope substitution prevented?**

Under Option B there is no snapshot-side scope to substitute; the
substitution channels and their closures are:

1. *A report/advertisement pair from scope S1 presented as S2.* The scope
   digest never travels alone: admission re-derives the expansion and
   closure from the intensional definition against the bound inventory
   and compares the result with the digest bound into the advertisement,
   report bindings, and bundle (§A9 M7); a mismatch refuses (§A8 F1).
2. *A snapshot steering cell-map selection.* The snapshot selects nothing
   but the tuple, and the tuple's advertisement is unique (§A4); the
   tuple and engine identity are launcher-authenticated against the
   loaded engine (`authenticate_local_engine`), so there is no
   snapshot-controllable degree of freedom left that chooses among
   scopes.
3. *Two builds embedding different scoped reports for one tuple.* The
   predecessor-chain check against the checked-in promotion lineage
   (§A5) names the currently admitted scope, carried into the binary by
   the checked promotion admission (§A9 M27); an embedded report whose
   scope is not the lineage-resolved current one refuses at admission
   (§A8 F6). The build-time selector (§A9 M20) independently verifies
   the report↔advertisement join before embedding. Whole-checkout
   rollback — a binary honestly rebuilt from old sources — is outside
   this chain: build provenance's layer (§A9 M26/M27).

Under Option A the answer would additionally require proving the
snapshot's copy equal to the admission result at arm time — a comparison
whose failure mode (which side wins?) is exactly the ambiguity Option B
avoids.

**(iii) Which authority supplies the digest to runtime introspection?**

The retained `AdmittedScopedTargetCells` aggregate held by the armed
Host — the same object that supplies every per-gate disposition (the
`ScopedAdvertised` state, §A3) — is the sole introspection authority.
Never the snapshot, never release notes, never a re-read of repository
files at runtime. The introspection surface (§A9 M16, schema id
reserved `ibex/capsec-scope-introspection/1`) exposes the active scope
digest and the uncertified remainder machine-readably, and it is new
code: no such surface exists today; §A8 F11's positive half asserts its
coherence with the enforced map.

> **AUTHOR DECISION REQUIRED (LLP 0044 register item 5).** This section
> recommends Option B with the `ScopedAdvertised` arm state of §A3 and
> the introspection authority of (iii). The author decides after this
> amendment's review completes; rejection is an LLP 0049 §9 diversion
> (the plan halts and returns for re-scoping), not a gate pass.

### A7. The published claim (normative wording)

Per LLP 0049 §3 rule 8, the exact sentences published with a scoped
advertisement, under the decided uncertified posture (LLP 0044 §7
item 2). This wording is normative; any published paraphrase that
characterizes the remainder without naming its layer fails review.

> This target's enforcement is certified for the declared scope
> (scope digest `<sha256-…>`, scope `<families/surface kinds>`). The
> certification is per-invocation: each in-scope cell's enforcement is
> certified under the source-derived preconditions its recipes
> establish. Every surface outside the scope carries no conformance
> claim: it is uncertified, the certification does not constrain its
> availability and no universal physical-refusal claim is made, and it
> is enumerated by family as a release constraint generated from the
> same validated expansion diff the promotion gate checks. No statement
> is made that out-of-scope surfaces are refused, absent, or safe.
>
> Where a fail-closed property is asserted for the uncertified
> remainder, it names its exact layer: (1) **startup admission** — a
> scope/map-integrity property (metadata admission): an armed runtime
> refuses to start with a cell map that omits any generated inventory
> cell, which protects the integrity of the admitted scope and map and
> is never an execution-refusal property of any surface;
> (2) **typed-gate refusal** — a typed effect gate that is actually
> reached on an uncertified cell refuses. Zero-decision surfaces —
> uncertified surfaces that reach no typed gate — have no typed-gate
> refusal and no physical-entrypoint refusal, and their execution is
> not constrained by this certification. Negative-control probes
> executed against uncertified families on the exact advertised build
> are diagnostic evidence, not proof, and never upgrade this claim.
>
> The certification is not compositional: a composition in which an
> uncertified surface manipulates state, authority, handles,
> configuration, or lifecycle that a later in-scope invocation depends
> on is itself uncertified. Adversarial-composition fixtures in the
> ceremony are diagnostic only.

(The physical-entrypoint-refusal layer is deliberately absent from the
claim: register item 2 selected the uncertified posture, so no physical
refusal of the remainder exists to name.)

### A8. Adversarial fixture set

Each fixture class pins the join-matrix rows named; all are refusal/
diagnostic fixtures and none upgrades any claim. Classes F1–F7 are
LLP 0044 §2's seven; F8–F10 are the LLP 0049 round-1 additions; F11–F12
arise from this amendment's code survey. The round-1 review revision
(2026-08-06) added the F1a–F1c subcases, F4's zero-contribution
assertion, F6's documented rollback boundary, and F11's positive
coherence half. The **round-2 revision** added F1c's ABI subcase, the
new class **F3a** (ABI-level ingress authority), and F6's five lineage
subcases (F6a–F6e), all in response to the two round-2 BLOCKERs.

- **F1 — scoped-state substitution.** A digest-valid report/advertisement
  pair generated under scope S1 presented under scope S2's identity (and
  the converse: S2's scope artifact beside S1's report) must refuse at
  admission with the re-derivation mismatch. Explicit subcases, each its
  own fixture:
  - **F1a — stale advertisement + fresh report.** An older
    advertisement generation crossed with a newer report (and the
    converse) refuses at the existing byte-binding equality
    (`src/host/portable_target_admission.rs:1341-1387`) extended with
    the scope binding.
  - **F1b — cross-tuple crossing.** Artifacts from tuple T1 presented
    under tuple T2 — including a snapshot from a different tuple's run —
    refuse at `bindings.target` equality, tuple-unique selection
    (:568-580), and `authenticate_local_engine`; the scope's embedded
    canonical tuple (§A1) makes the crossing a scope mismatch as well.
  - **F1c — direct scope-identity/map crossing at the Host
    constructor.** An attempt to hand `Host` a scope identity from one
    admission and a cell map from another is unrepresentable by
    construction (`AdmittedScopedTargetCells`, §A3): the fixture proves
    no constructor path accepts the pieces separately.
    **ABI subcase (added by the round-2 revision):** the same crossing
    attempted at the ABI boundary rather than the constructor — a
    caller invoking `ex_host_evaluate_typed_decision`
    (`src/host/abi.rs:5823-5839`) with a serialized gate whose
    `coverage_edge_id` belongs to scope S1's expansion while the armed
    Host holds S2's aggregate. The fixture asserts the disposition the
    evaluator sees is S2's, from the retained aggregate, regardless of
    what the caller serialized — i.e. that the ingress rule leaves the
    caller no channel to name a scope at all.
  Pins M1, M6, M7, M12, M32.
- **F2 — omitted map entries.** A scoped cell map missing any generated
  edge — in-scope or out-of-scope — must refuse arming (the
  exhaustiveness check, `src/host/mod.rs:824-845`). Pins M13.
- **F3 — typed out-of-scope refusal.** A reached typed gate on an
  uncertified cell refuses exactly as `Incomplete` does today
  (`decision.rs:609-621`), and the emitted refusal telemetry
  distinguishes `uncertified` from incomplete-by-defect. **Extended by
  the round-2 revision:** the fixture drives the refusal through **each
  of the three evaluation bodies** (`src/host/mod.rs:3794`, `:3844`,
  `:3874`) and asserts the envelope is emitted exactly once per
  refusal in all three — which is the executable form of "the funnel
  M13 builds actually covers every path." Pins M13, M14.
- **F3a — ABI ingress authority (new class; round-2 revision).** The
  fixture the second round-2 BLOCKER demands: a caller-supplied
  `complete` must not override an uncertified cell. Under
  `ScopedAdvertised` with a known out-of-scope `coverage_edge_id`:
  - **F3a-1** — a gate serialized with `"targetCell":"complete"` is
    submitted through `ex_host_evaluate_typed_decision`
    (`src/host/abi.rs:5823-5839`) and **refuses** with
    `DecisionReason::TargetCellIncomplete`, exactly as if the caller
    had said `incomplete`; the emitted envelope carries
    `hostDisposition: "uncertified"` and records the discarded
    `presentedTargetCell: "complete"`.
  - **F3a-2** — the same through each of the four `pub` Rust ingresses
    (`src/host/mod.rs:3776`, `:3844`, `:3942`, `:3963`), since the C
    symbol is only one of five doors.
  - **F3a-3** — the converse honesty check: a gate serialized
    `"incomplete"` on an **in-scope** `Complete` cell evaluates as
    `Complete`, proving the ingress rule *recomputes* rather than
    taking the minimum of the two values (which would be a different,
    weaker rule that happens to pass F3a-1).
  - **F3a-4** — a runtime-extension authorization
    (`ex_host_authorize_runtime_extension_operation_v1`,
    `src/host/abi.rs:5447`) whose `effect_semantics` string collides
    with a generated inventory `edgeId` that is out of scope refuses;
    the same call with a non-inventory effect-semantics string
    proceeds and its envelope records
    `hostDisposition: "extension-declared"`.
  - **F3a-5** — the whole class is asserted to be a **no-op under
    `CompleteAdvertised`**: every F3a case behaves exactly as it does
    today when the arm state is not `ScopedAdvertised`, so the ingress
    rule cannot regress existing releases.
  Pins M13, M14, M32.
- **F4 — executable zero-decision remainder.** A zero-decision
  uncertified surface executes under `ScopedAdvertised`; the fixture
  records the execution in the distinct diagnostic schema and proves the
  promotion evidence set is unchanged by it — asserting the
  **zero-authoritative-contribution rule** (§A9 M7) directly:
  out-of-scope executions present in the diagnostic artifact imply a
  byte-identical authoritative evidence set, with zero out-of-scope
  fixtures in the required, passed, or execution unions.
  Evidence-not-proof; diagnostic only. Pins M3, M7, M14, and the §A7
  wording.
- **F5 — duplicate scopes.** Two advertisements for one tuple (same or
  different scope digests) refuse selection; a bundle carrying two scope
  artifacts refuses validation. Pins M6, M7 (via §A4), M17.
- **F6 — stale/rolled-back predecessor.** A scope artifact whose
  predecessor digest names an older, lineage-superseded scope refuses
  admission; a genesis-marked scope refuses when the lineage already
  records a scope for the tuple. **Lineage-root rollback boundary
  (documented, not fixtured):** rollback of the entire authenticated
  checkout — rebuilding a binary from old sources whose embedded chain
  is internally consistent — is **out of this chain's scope by
  design**; runtime freshness against a rebuilt-from-old-sources binary
  is build provenance's layer (§A9 M26/M27), and F6 asserts staleness
  only relative to an intact authenticated lineage.
  **Lineage-algorithm subcases (added by the round-2 revision; these
  are the executable form of M27's rewritten algorithm — without them
  the algorithm is prose):**
  - **F6a — genesis.** A history terminating at the pinned lineage
    floor (`afad4af9`, M27 (v)) whose floor catalog is present,
    `enabled: false`, and empty, and whose floor parent lacks the
    catalog path entirely, admits a genesis-marked scope.
  - **F6b — promotion → ordinary commits → reset → second promotion.**
    The full M27 (iv) lifecycle. The walk must skip every ordinary
    first-parent descendant (which inherits the published catalog bytes
    but fails the (i) promotion-revision predicate), select promotion 1
    by that predicate, read its **tracked** `admittedScopeDigest` (M27
    (ii)), and admit promotion 2 only when its predecessor digest
    equals it. This is the fixture that would have caught the round-1
    algorithm; it must fail against the round-1 text and pass against
    the round-2 text.
  - **F6c — stale predecessor.** Promotion 2 naming promotion 0's
    scope digest refuses, with promotion 1 present in the walk.
  - **F6d — false genesis.** A genesis-marked scope presented on a
    history that contains promotion 1 refuses.
  - **F6e — truncated history.** A checkout whose **tree is current**
    but whose history is shallow, grafted, or replace-ref-bearing
    fails M27 (vi)'s preconditions *before* the walk runs, and
    therefore never reaches the genesis conclusion. Round-2 Fable
    identified this as the one live bypass of a guarantee this
    amendment newly claims; it is closed by precondition and pinned
    here rather than disclosed as a non-guarantee.
  Pins M7, M19, M27.
- **F7 — renamed/retired cells.** A "retired" cell still present in the
  live inventory fails the expansion-diff validation; a rename not
  covered by the authenticated mapping fails as narrowing. Pins M1, M22.
- **F8 — observed-closure-escape.** A ceremony run whose physical
  traversal enters a cell the closure excluded fails the run — the
  observation proves the closure wrong, and no warning path exists.
  Pins M1, M3, M25.
- **F9 — split/merge mapping.** A split whose successor cells do not
  exactly partition the predecessor (a cell consumed twice, or dropped)
  fails mapping validation; same for merges. Pins M1, M22.
- **F10 — adversarial compositions.** Uncertified-surface-then-in-scope-
  invocation compositions (state, authority, handle, configuration,
  lifecycle interference) executed as **diagnostic, never
  claim-upgrading** evidence in a distinct diagnostic schema. Pins M3
  and the §A7 wording.
- **F11 — scoped-state coherence (negative and positive).** Negative
  half: the M15 constructors — dev-arming, insecure, simulator-observer,
  test, and native module-runner, all of which live in `src/host/mod.rs`
  — cannot construct a `ScopedAdvertised` state, an
  `AdmittedScopedTargetCells` value, or emit a scope digest through
  introspection; each continues to arm only its existing
  synthetic-complete posture. This half rests on a **module boundary**:
  `mod portable_target_admission` is a private child (`mod.rs:23`), so
  the opaque type is unconstructible from `mod.rs`. It does **not**
  extend to the in-file `#[cfg(test)]` module at
  `portable_target_admission.rs:1560`, a descendant with private access
  where the constraint is review, not the type system (§A3); the
  fixture must not be written as if it did. **Positive half (the
  coherence invariant):** under `ScopedAdvertised`, the introspected
  scope digest, the introspected remainder, and **every** per-gate
  disposition the Host projects derive from the same retained
  `AdmittedScopedTargetCells` aggregate — the fixture arms, introspects,
  and sweeps every generated edge's projected disposition, asserting
  equality with the aggregate's partition. With the ingress rule (§A3,
  M32) in force the sweep must also cover dispositions **as the
  evaluator sees them**, not only as `fn target_cell` returns them —
  otherwise the positive half proves coherence of a value the ABI can
  still bypass, which is exactly the gap round 2 found.
  Pins M12, M13, M15, M16, M32.
- **F12 — v1 chain non-carriage.** The checked-in v1 advertisement file
  remains empty-v1 on the artifact-source side
  (`scripts/portable-engine-promotion-lineage.mjs:825-826`), and the
  runtime continues to refuse v1 advertisements
  (`src/host/portable_target_admission.rs:540-544`); a scoped
  advertisement forced into the v1 schema must refuse everywhere it is
  presented. Pins M18.

### A9. Appendix — the scope-digest join matrix

The authoritative gate-code worklist (LLP 0049 §5.1): every row marked
**scope-validating** is a §5.3 work item; every row marked
**scope-transparent** carries the argument for why it needs no change and
the fixture that would catch it becoming load-bearing. Lifecycle verbs
per LLP 0044 §2: the digest is *created* by the generator (M1),
*independently re-derived* at admission (M7), *bound* into the six
lifecycle artifacts (M2–M6, plus the admission result in M7, plus the
execution-binding surface M28), *compared* against the lineage-resolved
predecessor (M19, via M7, anchored at runtime by the build-embedded
checked promotion admission — M27), and *delivered* into runtime state
via the admitted aggregate (M12/M13), and — new in the round-2
revision — made *authoritative at every evaluator ingress* (M32).
All line numbers at `6416114d`; rows M27–M31, added by the round-1
revision, were re-verified at `90aafc67` (docs-only over the pin);
M32 and the round-2 corrections to M11, M13, M14, M18 and M27 were
verified at `f154a5c5` and say so in the row.

Summary table (rows detailed below):

| row | consumer / artifact | class | pinned by |
| --- | --- | --- | --- |
| M1 | scope artifact generator + companions (new) | scope-validating (creates) | F1, F7, F8, F9 |
| M2 | recipe catalog + `assertRecipeCatalogComplete` | scope-validating (binds) | F1 |
| M3 | public execution evidence + completeness | scope-validating (binds) | F4, F8, F10 |
| M4 | conformance report (rich v1 + portable v2) | scope-validating (binds) | F1 |
| M5 | target attestation | scope-validating (binds) | F1 |
| M6 | portable promotion bundle + cell invariant | scope-validating (binds; **must-amend**) | F1, F5 |
| M7 | portable report admission | scope-validating (re-derives + compares; **must-amend**) | F1, F5, F6 |
| M8 | armed-snapshot producer | scope-transparent under Option B | F1 |
| M9 | `ibex/capsec-armed/1` parser + digest contract | scope-transparent under Option B | F1 |
| M10 | `ExpectedArmingIdentity` | scope-transparent under Option B | F1 |
| M11 | other armed-snapshot schema pins (SFE, ABI, embedder, vectors) | scope-transparent under Option B | F1 |
| M12 | `Host::new_armed` (delivery join) | scope-validating (delivers) | F1, F2 |
| M13 | `Host::new_armed_with_target_cells` + `ScopedAdvertised` | scope-validating (delivers) | F2, F3 |
| M14 | typed decision path | scope-transparent (algorithm) | F3, F4 |
| M15 | dev/insecure/observer/test constructors | scope-transparent (must stay incapable) | F11 |
| M16 | runtime scope introspection (new) | scope-validating (carries) | F11 |
| M17 | v2 advertisement schema + reader (→ v3) | scope-validating (carries) | F1, F5 |
| M18 | closed v1 advertisement chain (row group) | scope-transparent, proven; ownership settled (§A10 #2) | F12 |
| M19 | promotion-lineage verifier | scope-validating (lineage anchor) | F6 |
| M20 | `build.rs` report selector | scope-validating (carries) | F1, F6 |
| M21 | target-cell bytes | scope-validating (binds) | F1, F2 |
| M22 | fixture catalog / checked report authority | scope-validating (re-derivation input) | F7, F9 |
| M23 | promotion authority artifact | scope-validating (binds) | F1 |
| M24 | bundle graph verifier | scope-validating (member set) | F5 |
| M25 | ceremony gate (`checkPromotion` ×4) + candidate pointer | scope-validating (binds) | F8 |
| M26 | Go attestation verifier | scope-transparent | — |
| M27 | checked promotion-admission chain (schema/producer/carrier/parser) | scope-validating (lineage anchor carrier; **must-amend**) | F1, F6 |
| M28 | portable execution-binding digest + strict plan parsers | scope-validating (binds; carriage rule §A10 #5) | F1 |
| M29 | physical-promotion workflow | scope-transparent (orchestration) | F8 |
| M30 | report-schema evolution surface (JSON Schemas + v1 digest-contract chain) | scope-validating (restamp surface; rev-vs-evolve §A10 #6) | F1 |
| M31 | installer lineage consumption | scope-transparent | F6 |
| M32 | evaluator ingresses — host C ABI + runtime-extension gate | scope-validating (makes the aggregate authoritative; **must-amend**) | F1c, F3a |

**M1 — scope artifact generator (new; creates `scopeDigest`).**
No file exists; `scopeDigest` has zero code occurrences at `6416114d`.
Required: the §A1 generator and both companion artifacts, consuming the
same reviewed coverage/implementation inputs as `fixtureCatalogForTarget`
(`packages/ibex-devtools/src/scripts/capsec-conformance.mjs:304`).
Fixtures F1, F7, F8, F9.

**M2 — recipe catalog binding + scoped completeness
(scope-validating).**
Current: `assertRecipeCatalogComplete`
(`packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs:5048`)
is global — `fullyExecutable + internallyVerified === required` and
`unresolvedFixtures === 0` (:5050-5055); it also gates the portable
recipe-catalog derivation (`capsec-portable-promotion-bundle.mjs:342`)
and the ceremony (`run-capsec-conformance.mjs:1878-1880`). Amendment:
§A2 — the summary carries `scopeDigest`, the assertion binds to
`unresolved-in-scope === 0`, out-of-scope rows are retained and
enumerated. Fixture F1.

**M3 — public execution evidence (scope-validating).**
Current: `assertPublicSurfaceExecutionComplete`
(`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:9701`)
is checked with `expectedFixtureIds` flat-mapped from the **full** fixture
catalog (`run-capsec-conformance.mjs:1881-1889`). Amendment: the expected
set becomes the scoped expansion's required fixtures; the artifact binds
`scopeDigest`; out-of-scope negative-control and composition runs land in
a distinct diagnostic schema that can never enter this artifact. The
downstream binding digest and the strict Rust plan parsers that consume
this artifact's digests are M28 — a change here that adds a binding
field is not complete until M28's closed field lists admit it.
Fixtures F4, F8, F10.

**M4 — conformance report (scope-validating).**
Current: the rich report is built with schema `ibex/capsec-conformance/1`
(`packages/ibex-devtools/src/scripts/capsec-conformance.mjs:393`, schema
at :571) and `assertReportMayAdvertise` (:612-643) requires
`status === "conformant"`, `incompleteCells === 0`,
`missingFixtures === 0`, `failedFixtures === 0`, and
`passedFixtures === requiredFixtures` — all-or-nothing over the whole
inventory. The portable v2 report is derived in the bundle
(`capsec-portable-promotion-bundle.mjs:870`, `reportCells`). Amendment:
both report schemas carry `scopeDigest` in `bindings` (LLP 0032
amendment delta); `assertReportMayAdvertise` requires the scope binding
and interprets the summary counts against the scoped required set, with
the uncertified remainder carried as explicit accounting, not as
`incompleteCells`. The JSON Schema files and the v1 digest-contract
chain this binding change restamps are enumerated in M30 — this row is
not implementable without M30's worklist. Fixture F1.

**M5 — target attestation (scope-validating).**
Current: `capsec/conformance/target-attestations.json` is the closed v1
schema with an empty list; the v2 attestation is validated against the
report and independent authority field-by-field in
`validatePublicationJoins`
(`packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs:1037-1108`).
Amendment: the attestation (v2 → v3 alongside M17) carries `scopeDigest`
and the join check compares it with the report binding and the authority
entry. Fixture F1.

**M6 — portable promotion bundle + cell invariant (scope-validating;
LLP 0044 must-amend #2).**
Current: `exactTargetCells`
(`packages/ibex-devtools/src/scripts/capsec-portable-promotion-bundle.mjs:149-179`)
rejects promotion if **any** exact-target cell has
`disposition === "unsupported"` or is malformed (:164-171), and
`validateSourceClosure` (:262-325) requires the target rows to cover the
exact reviewed edge inventory with dispositions equal to the
independently derived closure. The bundle emits the v2 advertisement
catalog itself (:1113-1148 inside `buildPortablePromotionBundleV2`,
:1037). Amendment: the bundle carries the scope artifact (and its
companions) as members; the cell invariant accepts out-of-scope
**uncertified** cells **only** when listed in the bound scope artifact,
and only those — an uncertified cell not named by the scope artifact, or
an in-scope cell carrying the uncertified disposition, refuses; the
emitted advertisement carries `scopeDigest`. Fixtures F1, F5.

**M7 — portable report admission (scope-validating; re-derives +
compares; LLP 0044 must-amend #1).**
Current: `src/host/portable_target_admission.rs` —
`select_v2_advertisement` (:529; v1 refusal :540-544; tuple uniqueness
:568-580), `require_checked_promotion` (:639),
`checked_report_authority` (:1151) re-deriving per-edge branch/fixture
authority from the embedded implementation manifest (:37-40), and
`authenticated_report_target_cells` (:1310/:1318) requiring: exact
ordered coverage inventory membership (:1443-1452), per-cell equality
with the checked source-derived authority (:1481-1487), disposition
derivation Complete/Closed only (:1489-1505), and the full fixture union
`required == passed == executions` with `incomplete_cells == 0`
(:1508-1527). Amendment: admission re-derives the scoped expansion and
closure from the intensional definition against the bound inventory —
**never trusting the report's row list** — validates the scoped required
set (in-scope cells against unchanged per-cell authority; out-of-scope
cells against the uncertified disposition and the scope artifact's
enumeration), recomputes `scopeDigest` and compares it with the
advertisement/report/bundle bindings, resolves the predecessor from the
checked-in lineage (§A5), and returns the `AdmittedScopedTargetCells`
aggregate (§A3): the exhaustive scoped cell map plus the admitted scope
identity (Option B, §A6).
**The scoped forms of the :1508-1527 equalities (normative).** Writing
S for the expanded in-scope cell set, the admission invariant becomes:
`required_fixtures(S)` non-empty;
`required_fixtures(S) == passed_fixtures(S) == execution_fixtures` (the
report's authoritative execution set, as sets of fixture IDs);
`summary.cells == |full inventory|` (the report stays exhaustive);
`summary.conformant_cells == |S|`;
`summary.incomplete_cells == 0`; the uncertified remainder carried as
its own explicit summary count equal to `|inventory| − |S|`;
`summary.required_fixtures == |required_fixtures(S)|`;
`summary.passed_fixtures == |passed_fixtures(S)|`;
`summary.missing_fixtures == 0`; `summary.failed_fixtures == 0`. And
the **zero-authoritative-contribution rule**: out-of-scope cells
contribute **zero** required fixtures, **zero** passed fixtures, and
**zero** executions to the authoritative evidence set — an
authoritative execution or fixture row attributed to an out-of-scope
cell refuses admission outright (diagnostic artifacts are the only
place such runs may exist, M3). F4 asserts this rule directly.
**Scope of that rule, disambiguated (round-2 revision).** It governs
the **authoritative unions and the execution set — not row content**.
Out-of-scope report cells keep their honest source-derived
`required_fixtures` exactly as today; what the rule forbids is those
fixtures entering `required_fixtures(S)`, `passed_fixtures(S)`, or the
authoritative execution set, and it forbids an authoritative execution
row being attributed to an out-of-scope cell. The alternative reading —
that out-of-scope rows must literally carry empty `required_fixtures` —
is **wrong** and would contradict three things this amendment relies
on: §A2's "out-of-scope rows are never reclassified… honest current
status," M22's "the full-inventory derivation is **unchanged**," and
today's per-cell authority equality at
`src/host/portable_target_admission.rs:1481-1487`, which applies to
**every** cell and derives non-empty required fixtures for out-of-scope
cells. An implementation that emptied those rows would fail :1481-1487
against the checked source-derived authority.
**The runtime lineage anchor.** This code runs inside the armed binary
with no repository access: the predecessor comparison at runtime is
against the **build-embedded checked promotion admission**
(`require_checked_promotion` :639 over
`EMBEDDED_PORTABLE_ENGINE_PROMOTION_ADMISSION`,
`src/host/mod.rs:6743-6746`), which — per M27 — carries the admitted
scope digest and predecessor scope digest stamped by the script-time
lineage verifier (M19), the authority that resolved them from
authenticated Git history. Admission trusts the anchor's bytes only
after the existing domain-digest verification and requires the scope
artifact delivered by M20 to match it. LLP 0049 §7.3 depends on this
row existing. Fixtures F1, F5, F6.

**M8 — armed-snapshot producer (scope-transparent under Option B).**
Current: `build_default_armed_host` (`src/bin/ibex/runtime.rs:5242`),
template `capsec/examples/armed-snapshot.canonical.json` (:5290-5293),
`finalize_production_snapshot` (:4804-4816, called :5814),
`ArmedSnapshot::load` call (:5882-5885); the session-worker re-load path
(:3869-3892) re-authenticates the same document. No scope identity in
the document. Transparency argument: the producer authenticates
launcher-observed execution identity only and never reads the promoted
report; under Option B the scope reaches the Host exclusively through
M7/M12, so the snapshot neither carries nor selects scope. Under
Option A this row flips to scope-validating with the §A6 cascade.
Fixture F1 (substitution attempts must be closed without any snapshot
participation).

**M9 — `ibex/capsec-armed/1` parser and digest contract
(scope-transparent under Option B).**
Current: `ArmedSnapshot::load`
(`crates/capsec-semantics/src/arming.rs:345`; schema pin :351;
`ARMED_SNAPSHOT_SCHEMA` :37); frozen digest projection
(`crates/capsec-semantics/src/digest.rs:159-163`, omitting only
`armedSnapshotDigest`). Transparency argument: same as M8 — the parser
authenticates the launcher's facts; adding scope would change the frozen
projection and restamp the reviewed contract surface for no added
authentication. Under Option A: schema rev to `ibex/capsec-armed/2` or
projection change, plus M11's cascade. Fixture F1.

**M10 — `ExpectedArmingIdentity` (scope-transparent under Option B).**
Current: `crates/capsec-semantics/src/arming.rs:70-109` — profile,
digests, target, engine, features, entry, discovery, canonicalizers,
protected artifacts; **no scope field**. Transparency argument /
Option A delta: as §A6(i). Fixture F1.

**M11 — other `ibex/capsec-armed/1` schema pins (scope-transparent under
Option B; consumers LLP 0044's table missed).**
Sweep-verified enumeration. **Count adjudicated by the round-2 revision;
the round-1 command was undercounting and is replaced.**

The round-1 row recorded, at `90aafc67`:

```
grep -rn '"ibex/capsec-armed/1"' --include='*' . | grep -v node_modules | grep -v llp/ | grep -v target/
```

→ **20 lines / 16 files**. Codex's round-2 delta ran, against the
committed tree at `38c382d2`:

```
git grep -n -F '"ibex/capsec-armed/1"' 38c382d2 -- . ':!llp/**' ':!target/**' ':!node_modules/**'
```

→ **21 lines / 17 files**, with `git grep -o … | wc -l` → **23 literal
occurrences**. Both were re-run during this revision (at `f154a5c5`,
docs-only over `38c382d2`) and **both reproduce exactly**. Codex is
right and the round-1 count was wrong.

**Why the round-1 command undercounted — worse than "it did not exclude
the mirror."** The seventeenth file is
`vendored-generated/capsec-runtime-projection.canonical.json:1`, and the
round-1 pipeline's `grep -v target/` is a **content** filter, not a path
filter: that file is a single-line canonical JSON document whose body
contains the substring `/target/` (in
`"orderBy":["/edgeId","/target/triple","/target/features"]`), so the
matching line filtered *itself* out. A real pin was dropped by an
accident of the mirror's contents, which is exactly the failure mode a
"measured blast radius" claim must not have. Round-1 Fable's independent
"21 hits" observation was therefore right about the count and round-2
Fable's verbatim re-run of the recorded command reproduced the recorded
20 — both correct, because the recorded command is the defective object.

**The command this row now records** (path-anchored exclusions, binary
safety, fixed-string match; re-run 2026-08-06 at `f154a5c5`):

```
grep -rn --binary-files=text -F '"ibex/capsec-armed/1"' . \
  --exclude-dir=node_modules --exclude-dir=llp \
  --exclude-dir=target --exclude-dir=.git
```

→ **21 lines / 17 files**, and with `-o` in place of `-n`, **23 literal
occurrences** — reconciling with the `git grep` form exactly.

**Lines vs. occurrences.** The two counts differ by two because two
matching lines carry the string twice:
`crates/capsec-semantics/src/arming.rs:3679` (a duplicate-key test
fixture: `{"snapshotSchema":"ibex/capsec-armed/1","snapshotSchema":"ibex/capsec-armed/1"}`)
and the single-line vendored mirror. Pin *sites* are best counted by
line (21); a mechanical restamp under Option A must edit *occurrences*
(23). Neither number alone is the blast radius.

The **21 lines in 17 files**, classified:
- **Direct schema pins (validate or freeze the schema string):**
  `crates/capsec-semantics/src/arming.rs:37` (`ARMED_SNAPSHOT_SCHEMA`,
  enforced by `ArmedSnapshot::load`);
  `crates/sfe-format/src/lib.rs:787` and
  `crates/sfe-format/src/app_bound.rs:387` (SFE validators);
  `crates/capsec-semantics/src/canonical.rs:267` (contract-fixture
  projection table); `crates/capsec-semantics/src/digest.rs:161`
  (frozen digest projection); `capsec/schema/armed-snapshot.schema.json:37`
  (JSON Schema const); `schemas/stub-contract-v1.schema.json:122`,
  `schemas/stub-contract-v3.schema.json:124`,
  `schemas/app-bound-common-v1.schema.json:232`,
  `schemas/capsec-runtime-projection-v1.schema.json:27` (JSON Schema
  consts); `capsec/registry/policy-rules.json:248` (`inputSchema`);
  `packages/ibex-devtools/src/scripts/capsec-contract.mjs:496` (digest
  contract).
- **Generated mirrors / emission sites / vectors:**
  `crates/sfe-catalog/src/lib.rs:708` and
  `crates/sfe-format/src/lib.rs:1596,:1745` (emission constructors);
  `packages/ibex-devtools/src/scripts/generate-capsec-runtime-projection.mjs:134`
  (generator of the runtime-projection artifact);
  `capsec/examples/armed-snapshot.canonical.json:2` (checked-in
  template, listed in `capsec/contract-files.json:44`);
  `capsec/examples/digest-bundle.canonical.json:269005,:269812` (digest
  vectors); `crates/capsec-semantics/src/arming.rs:3679` (test
  fixture, **two occurrences on the line**);
  **`vendored-generated/capsec-runtime-projection.canonical.json:1`**
  (added by the round-2 revision — the checked-in canonical mirror of
  the runtime projection, **two occurrences on the line**, emitted by
  `generate-capsec-runtime-projection.mjs:31` and embedded into Rust by
  the generator's `include_bytes!` emission at `:154-158`, consumed at
  `src/capsec_runtime_projection_generated.rs:14`. It is a generated
  artifact, so under Option A it does not need hand-editing — but it
  **does** need a regeneration pass plus the digest re-pin its
  `generated_capsec_runtime_projection_digest_matches_bytes` test
  enforces, and it must appear in the Option-A worklist for that
  reason).
- **Transitive callers (no literal pin; ingest via
  `ArmedSnapshot::load`):** the host ABI ingestion route
  (`src/host/abi.rs:1381-1392`), the embedder template loader
  (`src/host/embedder_artifacts.rs:702`), and the environment-template
  schema-file invariants
  (`packages/ibex-devtools/src/scripts/capsec-environment-output-templates.mjs:305-313`).
Under Option B: all untouched. Under Option A: every direct pin revs or
restamps and every generated mirror regenerates — this row is the
measured blast radius that §A6's recommendation prices. Each round has
found it larger: the original enumeration listed six pins and misfiled
two transitive routes as pins; round 1 corrected that to 20 lines / 16
files; round 2 corrects it to **21 lines / 17 files / 23 occurrences**,
adding a generated mirror with its own digest-pinned regeneration.
Every correction has moved in the same direction, which strengthens
§A6's recommendation of Option B rather than weakening it. Fixture F1.

**M12 — `Host::new_armed` (scope-validating; the delivery join).**
Current: `src/host/mod.rs:723-739` — validates loaded engine and
protected artifacts, calls `authenticated_target_cells` (:729, fn at
:6726-6762), then constructs with
`TargetArmState::CompleteAdvertised`. Amendment: receives the
`AdmittedScopedTargetCells` aggregate from M7 **atomically** — never a
bare map beside a bare digest — and constructs the `ScopedAdvertised`
state from it; a scoped admission result can never construct
`CompleteAdvertised`, and vice versa. Fixtures F1 (incl. F1c), F2.

**M13 — `Host::new_armed_with_target_cells` + `ScopedAdvertised`
(scope-validating).**
Current: `src/host/mod.rs:781`; exhaustiveness gate :824-845 (every
generated edge present and `Complete|Closed`, arm state must be
`CompleteAdvertised`, refusal "armed target cells are incomplete" :844);
absent-from-map lookups default to `Incomplete` (`target_cell`,
:956-961). Amendment: §A3 — the constructor's scoped form consumes the
`AdmittedScopedTargetCells` aggregate, whose map values are the new
host-side `HostCellDisposition` type; it re-checks at construction that
`Uncertified` appears for exactly the out-of-scope cells of the carried
expansion (an in-scope `Uncertified` or out-of-scope `Certified` entry
refuses), keeps the exhaustiveness refusal, retains the aggregate as
the single source for introspection (M16) and per-gate projection, and
keeps absent-from-map as refusal-by-construction.
**Additional scope-validating work carried by this row (round-2
revision).** Two pieces of code that A3 round-1 assumed existed do not,
and building them belongs here:
1. **The projection funnel.** `fn target_cell`
   (`src/host/mod.rs:956-961`) becomes the `HostCellDisposition →
   TargetCellDisposition` projection point, serving all **eleven**
   `EffectGate` construction sites (:2346, :2846, :2929, :3002, :3107,
   :3188, :3346, :3495, :3588, :3684, :3768). `HostCellDisposition`
   must derive `Copy` so the existing `.copied()` shape and the
   signature at all eleven sites are unchanged.
2. **A single refusal-observing funnel.** No central host refusal path
   exists: there are three independent decision-evaluation bodies with
   four `evaluate_decision_set*` call sites (`src/host/mod.rs:3794`
   → :3811/:3820; :3844 → :3857; :3874 → :3888), and the latter two do
   not delegate to the first. Creating one helper that every body
   routes its returned `Decision` through — so every reached-gate
   refusal is observed exactly once — is **scope-validating work**, not
   an existing property. Emitting at all three sites instead is an
   acceptable but inferior discharge (three places to forget one), and
   the ingress rule below needs the same funnel regardless.
3. **The ingress rule (§A3).** Under `ScopedAdvertised` every evaluator
   ingress discards and recomputes `EffectGate.target_cell` from the
   retained aggregate. The four `pub` methods at :3776/:3844/:3942/:3963
   and the C ABI entry behind them are the ingresses; M32 carries the
   ABI row and the runtime-extension path. Fixtures F2, F3, F3a, F11.

**M14 — typed decision path (scope-transparent in algorithm).**
Current: `crates/capsec-semantics/src/decision.rs` —
`TargetCellDisposition` (:395-400), `Incomplete` refuses at a reached
gate before any lifecycle result (:609-621,
`DecisionReason::TargetCellIncomplete`), `Closed` denies (:672-683),
`Complete` passes. Transparency argument: this is exactly why the claim
is "uncertified," not "refused" — the reached-gate refusal is unchanged
and uncertified cells project to `Incomplete` in `fn target_cell`
(`src/host/mod.rs:956-961`) via the host-side `HostCellDisposition`
type (§A3 — type placement settled by this design revision: the new
type lives on the host side and decision.rs is untouched).
**Scope of the transparency claim, narrowed by the round-2 revision.**
"Transparent" means the *algorithm* in `decision.rs` is unchanged. It
does **not** mean the host side is already correct: the projection site
was mis-pinned in round 1 (:2844-2846 is 1 of 11 gate constructions,
not "exactly at"), there is no central refusal path to emit the
envelope from (three evaluation bodies, :3794/:3844/:3874), and
`EffectGate.target_cell` is a **public deserialized field**
(`decision.rs:401-407`) that caller-supplied gates set directly through
the C ABI. The first two are M13's new work items; the third is M32.
This row stays scope-transparent only because none of the three
requires a `decision.rs` change. Named tension for review
(§A10 #1): LLP 0044 requires uncertified distinguishable from
incomplete-by-defect in refusal telemetry; §A3 places the distinction
in the host-emitted `ibex/capsec-scoped-refusal/1` envelope keyed by
`coverage_edge_id`, emitted from the funnel M13 builds. If review
instead requires a distinct `DecisionReason`, this row flips to
scope-validating. Fixtures F3, F3a, F4.

**M15 — non-advertisement constructors (scope-transparent; must remain
incapable).**
Current: `new_armed_unadvertised_dev` (`src/host/mod.rs:655`),
`new_armed_insecure` (:695), simulator performance observer (:745),
`new_armed_for_test` (:885), native module-runner conformance (:931) —
each synthesizes a complete cell map and `CompleteAdvertised`.
Transparency argument: none reads an advertisement, so none can mint a
scope; the amendment adds the F11 fixtures proving they cannot construct
`ScopedAdvertised` or surface a scope digest. Fixture F11.

**M16 — runtime scope introspection (scope-validating; new).**
No surface exists today. Amendment: machine-readable exposure of the
active scope digest and uncertified remainder, schema id reserved as
`ibex/capsec-scope-introspection/1`, read exclusively from the armed
Host's retained `AdmittedScopedTargetCells` aggregate (§A3, §A6 iii) —
the same object every per-gate disposition derives from; absent under
every M15 constructor and in unarmed/diagnostic modes. Fixture F11
(both halves).

**M17 — v2 advertisement schema and reader (scope-validating; v2 → v3).**
Current: `ibex/capsec-target-advertisements/2`
(`packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs:51`),
its JSON Schema (`schemas/capsec-target-advertisements-v2.schema.json`),
the field-by-field publication join (:1037-1108), and the sole
authority-bearing validator `validatePortablePromotionV2` (:1116).
"Advertised" semantically means whole-tuple conformant. Amendment:
schema revision v3 carrying `scopeDigest` and the distinct product term
"scoped certification"; the reader validates the scope join (or, for
provenance-only consumers, transparently carries it); `matchingCatalogEntry`
(:1027) keys stay tuple-based with §A4's uniqueness. Fixtures F1, F5.

**M18 — closed v1 advertisement chain (row group; scope-transparent,
proven — ownership settled, §A10 #2).**
Current facts: `generate-capsec-registry.mjs` emits
`ibex/capsec-target-advertisements/1` from checked attestations
(`buildTargetAdvertisements`,
`packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs:1056-1090`,
schema at :1058; promotions loaded and re-validated at :799-1024;
publication paths allow-listed at :764-770; doc summary at :529). The
checked-in file is empty-v1 today. The promotion-lineage verifier pins
the **artifact-source** copy to exactly empty-v1
(`scripts/portable-engine-promotion-lineage.mjs:819-826`) and requires
exactly one target-advertisement blob in an admission (:738) at the
exact checked path (:789-790). The runtime **refuses** v1 outright
(`src/host/portable_target_admission.rs:540-544`). Transparency proof
obligation: the v1 chain carries no scope because it may never carry a
scoped advertisement at all — F12 pins that a scoped advertisement
forced into v1 refuses at the registry generator (schema validation),
the lineage verifier, and the runtime.
**The pin inventory for `capsec/generated/target-advertisements.json` —
sweep-recorded, not asserted complete (requalified by the round-2
revision).** This row has now missed pins twice: the original list had
three, round 1 raised it to eight and called that "the complete pin
inventory," and round-2 Fable found at least three more, one of which
**falsifies a stated disposition**. The claim is therefore replaced with
a recorded command and its result — the same requalification M11
received and passed. Sweep re-run 2026-08-06 at `f154a5c5`:

```
grep -rn --binary-files=text -F 'target-advertisements.json' . \
  --exclude-dir=node_modules --exclude-dir=llp \
  --exclude-dir=target --exclude-dir=.git \
  --exclude-dir=vendored-generated
```

→ **19 lines in 15 files**. The v1 JSON Schema file itself
(`capsec/schema/target-advertisements.schema.json`) has a different
basename and is pin 8 below; the sweep does not and cannot find pins
expressed only as schema-id strings, so it bounds the *path* surface,
not the whole v1 chain. Implementers must re-run it, not trust this
list. Each hit's disposition under the settled owner (§A10 #2 — the
v2/v3 publication owns the path's bytes at promotion time):
1. Registry generator v1 emission
   (`generate-capsec-registry.mjs:1056-1090`, path allow-listed :766) —
   **retired from this path**: the v1 emission moves to a diagnostic
   artifact path or is taught to emit the v2/v3 publication bytes
   verbatim; it never writes v1 bytes to the owned path again.
2. Lineage-verifier artifact-source pin
   (`portable-engine-promotion-lineage.mjs:48` `TARGET_ADVERTISEMENT_PATH`;
   the empty-v1 assertions at `:825-826` inside
   `assertSourceAuthorityClosed` `:804-826`) — **unchanged, and now
   with the lifecycle that makes "unchanged" true past promotion 1.**
   Round-1 said this pin stays untouched because it constrains the
   *source revision's* copy. Round-2 Codex and Fable both showed that
   argument holds only for the **first** promotion: once v2/v3 owns the
   path, the next promotion's artifact-source revision is a descendant
   of the previous promotion merge and carries v2/v3 bytes there, so
   `:825-826` fails. The reconciliation is **M27 (iv)**, the catalog
   enable/disable/**reset** lifecycle: a reviewed reset commit returns
   the tree to the closed foundation (disabled empty catalog, empty v1
   attestations, empty v1 advertisements) and *is* the artifact-source
   revision for the next promotion. With that lifecycle normative, this
   pin is genuinely unchanged for every promotion, and the alternative
   — revving `assertSourceAuthorityClosed` so the source foundation may
   carry the previous publication — is explicitly rejected in M27 (iv).
   Pin 2's disposition is now **load-bearing on M27 (iv)**: neither is
   coherent without the other.
3. Build-time selector
   (`build_support/portable_engine_promotion_report.rs:23`, schema pin
   :29) — **unchanged in role**: already requires tracked v2 bytes;
   revs alongside M17's v2→v3.
4. Admission unit test
   `tracked_source_a_legacy_advertisement_stays_closed`
   (`src/host/portable_target_admission.rs:1866-1879`, the
   `include_str!` at `:1869-1872`), which embeds the tracked file and
   asserts it refuses as legacy v1 — **retires or is replaced; the
   source-revision form is NOT available here** (correction, round-2
   revision). Round 1 offered "source-revision check *or* retirement"
   for pins 4–6 alike. That is a real choice for pins 5 and 6 (Node
   tests that read `repoRoot` at run time and could read a historical
   blob instead), but a false one for pin 4: it uses
   `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), …))`, a
   **compile-time** embed of the working-tree file, and a Rust unit
   test in that module has no Git object access at check time. Only
   retirement, or replacement by the F12 fixtures, is genuinely open.
   The author picks between those two, not among three.
5. Workflow-security test assertion
   (`scripts/hermes-artifacts-workflow-security.test.mjs:375-384`,
   `assert.deepEqual(advertisements.advertisements, [])` against the
   tracked HEAD copy) — **same disposition as pin 4**: source-revision
   check or retirement; it currently encodes "no target is ever
   advertised" as a permanent HEAD invariant, which the settled owner
   invalidates.
6. Packaging test assertion
   (`scripts/package-portable-hermes-macos.test.mjs:778-782`) — same
   disposition as pin 5.
7. Generated Rust carrier
   (`src/capsec_registry_generated.rs:12`,
   `CAPSEC_TARGET_ADVERTISEMENTS_JSON = include_str!(...)`, consumed by
   `authenticated_target_cells`, `src/host/mod.rs:6738-6742`) —
   **scope-transparent carrier, stays**: it delivers whatever bytes own
   the path without interpretation; the registry generator emits this
   .rs file, so retiring its v1 .json emission (pin 1) must keep the
   `include_str!` emission intact.
8. v1 JSON Schema const
   (`capsec/schema/target-advertisements.schema.json:13`) —
   **disposition CORRECTED by the round-2 revision; the round-1
   "unchanged" was falsified.** Round 1 said it "continues to describe
   the closed v1 schema for the artifact-source foundation copy and any
   diagnostic v1 output." It does not only that: pin 9 below applies
   this exact schema to the **HEAD** copy, so under the settled owner
   the schema file is not a bystander — it is one half of a check that
   fails the moment v2/v3 bytes land. The corrected disposition: the
   schema **file** is unchanged in content (it still describes v1
   correctly), but the *binding of this schema to the HEAD copy*
   must move with pin 9. Whichever way pin 9 resolves, this schema
   stops being applied to the published path.
9. **CapSec digest-contract runner, HEAD copy** (added by the round-2
   revision — the load-bearing miss).
   `packages/ibex-devtools/src/scripts/capsec-contract.mjs:3514-3517`
   reads the current-revision copy via `readConfinedGeneratedJson`, and
   `:3680-3685` validates it against
   `SCHEMA_IDS.targetAdvertisements`
   (`https://ibex.dev/capsec/schema/target-advertisements.schema.json`,
   `:130-131`) — i.e. **pin 8's v1 schema, applied to HEAD** — then
   consumes v1-shaped fields at `:4205`
   (`targetAdvertisements.targetCellsRawContentDigest`), `:4218` and
   `:4231` (`targetAdvertisements.advertisements`), and includes the
   document in bound sets at `:4426` and `:4495`. It is reachable
   because `capsec/contract-files.json:97` lists
   `generated/target-advertisements.json` in the contract file set.
   Under the settled owner, v2/v3 bytes at the path fail the CapSec
   contract runner outright — this is a **release-breaking**
   interaction, not a test nit. **Disposition (must be decided, not
   deferred): either the runner reads the artifact-source revision's
   copy instead of HEAD, or `SCHEMA_IDS.targetAdvertisements` becomes
   a version-dispatching binding that admits v2/v3 at this path.** The
   first keeps the digest contract's v1 surface frozen and is
   preferred; the second reopens the contract's schema surface and
   would restamp the registry digest vector (pin 11). This pin, not
   pins 4–6, is the one that gates whether the settled owner can ship.
10. **Registry generator declared outputs** (added by the round-2
    revision): `generate-capsec-registry.mjs:61-68`
    (`generatedRegistryPaths.targetAdvertisements`, the path the
    generator writes) and `:154-158` (the generated-artifact manifest
    entry `{path: "capsec/generated/target-advertisements.json",
    kind: "target-advertisements", digestBound: false}`), plus the
    allow-list at `:766` already named in pin 1 and the `include_str!`
    **emission template** at `:280` that produces pin 7's carrier —
    four distinct mechanisms, not one. **Disposition:** pin 1's
    "retired from this path" is incomplete unless it dispositions all
    of them together. Specifically, `generatedRegistryPaths` and the
    manifest entry must stop naming this path as a generator output
    (or must name it as an output the generator no longer writes), or
    an ordinary regenerate/drift pass will rewrite v1 bytes over the
    published v2/v3 bytes — silently, since the manifest marks it
    `digestBound: false`. The `:280` emission template must be kept,
    because pin 7's carrier must survive pin 1's retirement.
    `generate-capsec-registry.test.mjs:57` asserts this path is a
    per-target publication artifact held outside the source-derived
    output identity; it is consistent with the settled owner and
    stays.
11. **Checked digest vectors and contract file list** (added by the
    round-2 revision): `capsec/contract-files.json:97` and
    `capsec/examples/registry-digest-bundle.canonical.json:266855`.
    **Disposition:** mechanical restamp *if and only if* pin 9
    resolves toward keeping the HEAD binding; unchanged if pin 9 moves
    the runner to the artifact-source copy. Listed so the restamp is
    priced rather than discovered.
12. **Fourth HEAD-copy assertion** (added by the round-2 revision):
    `packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.test.mjs:1312-1324`
    asserts the HEAD copy's `targetAdvertisementSchema` is
    `ibex/capsec-target-advertisements/1` and its `advertisements`
    array is empty — the same class as pins 5 and 6 and unlisted in
    round 1. **Same disposition as pins 5/6**: source-revision check
    or retirement (both genuinely available; it is a Node test with
    `repoRoot` access).
13. **Lineage and admission vectors** (added by the round-2 revision):
    `scripts/portable-engine-promotion-lineage.test.mjs:42` and
    `schemas/vectors/portable-engine-promotion-admission-v1.valid.json:125`
    name the path as the admission's advertisement artifact.
    **Disposition: scope-transparent, stays** — they exercise the
    admission's blob-role structure, which the settled owner does not
    change; they rev only if M27's schema rev changes the vector shape.
    (`packages/ibex-devtools/src/scripts/run-capsec-conformance.mjs:1576`
    also appears in the sweep; it is the `trackedAdvertisementCandidate`
    pointer already dispositioned in M25 as a mechanical path.)
Fixture F12.

**M19 — promotion-lineage verifier (scope-validating; the lineage
anchor).**
Current: `scripts/portable-engine-promotion-lineage.mjs` validates the
admission catalog, blob roles/counts (:738), artifact-source state
(:819-826), and that published attestations/advertisements equal the
verified portable bundle graph (:915-926). The current topology is
one-shot: exactly one active admission (:686), an empty disabled source
foundation (:804-826), and one exact two-parent promotion merge
(:1064-1087). Amendment: the scope artifact and companions join the
closed member/role set; the verifier resolves the tuple's currently
admitted scope by the **evolvable discovery walk specified in M27** and
stamps the result into the checked promotion admission (M27's revised
schema) so M7's predecessor check has a build-embedded anchor; a bundle
whose scope predecessor does not equal the lineage-resolved current
scope fails verification. Fixture F6.

**M20 — `build.rs` report selector (scope-validating; carries).**
Current: `build.rs:864-877` embeds the selected promoted report;
`build_support/portable_engine_promotion_report.rs` —
`select_embedded_report` (:453), `select_report_artifact` (:286),
`matching_advertisement` (:314-360, keyed on
sourceRevision/triple/artifactId), `verify_report_advertisement_join`
(:362). Amendment: the selector carries the scope artifact bytes into
the build alongside the report (so admission can re-derive without
repository access), and the advertisement join includes `scopeDigest`
equality; the selector performs no scope re-derivation itself (that
authority stays in M7). **Anchor naming (round-1 revision):** the
runtime lineage anchor is the build-embedded checked promotion
admission (M27), stamped by the script-time lineage verifier (M19) —
this row's scope-artifact carriage and M27's anchor are the two
build-embedded scope inputs M7 joins, and neither is authoritative
without M7's re-derivation. Fixtures F1, F6.

**M21 — target-cell bytes (scope-validating; binds).**
Current: `capsec/registry/target-cells.json` (generator
`generate-capsec-portable-promotion-target-cells.mjs:126`;
all-unsupported today per LLP 0036) is bound by raw content digest into
the ceremony bindings (`run-capsec-conformance.mjs:1581-1597`), the
bundle (`capsec-portable-promotion-bundle.mjs:540-568`,
`validateTargetCells` in the evidence contract :795), and admission
binding equality (M7). The candidate derivation refuses
`conditional-unrefined` edges and non-promotable classifications
(`derivePortablePromotionTargetCells`,
`capsec-portable-promotion-bundle.mjs:188-261`). Amendment: the scoped
candidate cell bytes carry the uncertified disposition for exactly the
scope artifact's out-of-scope cells; the raw-content digest binding
chain is unchanged in mechanism and now transitively binds the scope.
Fixtures F1, F2.

**M22 — fixture catalog / checked report authority (scope-validating as
re-derivation input).**
Current: `fixtureCatalogForTarget`
(`packages/ibex-devtools/src/scripts/capsec-conformance.mjs:304`) is the
shared source-derived expansion; `checked_report_authority`
(`src/host/portable_target_admission.rs:1151`) re-derives per-edge
authority from the embedded implementation manifest. Amendment: the
full-inventory derivation is **unchanged** (the complete-cell rule needs
the full per-cell authority intact); scoping is a partition applied
after derivation, in M2/M7 — this row exists to pin that no scoped
variant of the catalog derivation itself is ever authored (a scoped
derivation would silently change per-cell authority and reopen
partial-cell credit). Fixtures F7, F9.

**M23 — promotion authority artifact (scope-validating; binds).**
Current: `ibex/capsec-portable-promotion-authority/1`
(`capsec-portable-engine-evidence-contract.mjs:400`
`validateAuthority`; joined to the report by `authorityForReport`
:437). Amendment: the authority entry carries `scopeDigest` so the
independent authority join (M5/M17 comparisons at :1037-1108) covers the
scope. Fixture F1.

**M24 — bundle graph verifier (scope-validating; member set).**
Current: `verify-capsec-portable-promotion-bundle.mjs` —
`validatePortablePromotionBundleGraph` (:269),
`verifyPortablePromotionBundleDirectory` (:372) — validates the closed
bundle member set and manifest joins. Amendment: the scope artifact and
companion files join the closed member set (an extra or missing scope
member fails the graph); the verifier does not interpret the scope
beyond membership and digest joins. Fixture F5.

**M25 — ceremony gate and candidate pointer (scope-validating).**
Current: the four `checkPromotion` names
(`run-capsec-conformance.mjs:1878-1899`) and the
`trackedAdvertisementCandidate` pointer (:1572-1578) into the bundle
directory's `target-advertisements.json`. Amendment: the four names bind
to the scoped rules of M2–M4; the ceremony additionally runs the F8
closure validation over every physical observation. The pointer itself
is a path and stays mechanical. Fixture F8.

**M26 — Go attestation verifier (scope-transparent).**
Current: `tools/portable-engine-attestation-verifier/verifier.go`
(constants :30-56) verifies Sigstore/SLSA provenance of the portable
engine artifact against pinned trust roots; it consumes no CapSec
advertisement, report, or cell schema (LLP 0035 keeps build consumption,
Host target cells, and advertisement loading as separate gates).
Transparency argument: its signed subject is the engine artifact, not
the conformance claim; no change unless its signed subject contract
changes. The earlier claim that it "must surface the scope" was wrong
and stays withdrawn (LLP 0044 §2).

**M27 — checked promotion-admission chain (scope-validating; the
lineage-anchor carrier; must-amend). Added by the round-1 revision.**
This is the artifact that actually crosses the build/runtime boundary
for lineage facts, and it was missing from the matrix. Current: the
schema is a closed field set with no scope fields
(`schemas/portable-engine-checked-promotion-admission-v1.schema.json:7-18`:
`schema`, `authorized`, `currentRevision`, `sourceRevision`,
`promotionTopicRevision`, `sourceTreeObjectId`, `targetTriple`,
`portableArtifactId`, `admissionDigest`, `verificationDigest`, under
`additionalProperties: false`); the producer is the lineage verifier's
checked-admission constructor
(`scripts/portable-engine-promotion-lineage.mjs:1185-1199`, freezing
exactly those fields plus a domain-separated `verificationDigest`); the
build carrier writes the bytes into `OUT_DIR` as
`portable_engine_promotion_admission.json`
(`build_support/portable_engine_build_consumption.rs:130-139`); the
Rust parser enforces the same closed key list
(`src/host/portable_target_admission.rs:613-628`,
`exact_object_keys`) and `require_checked_promotion` (:639) verifies
the domain digest before trusting any field.
**Revised schema (v1 → `ibex/portable-engine-checked-promotion-admission/2`,
new domain tag for `verificationDigest`; the closed sets in schema,
producer, and parser all rev together):** two fields join the closed
set — `admittedScopeDigest` (the tuple's currently admitted
`scopeDigest`; null exactly when `authorized` is false) and
`predecessorScopeDigest` (the admitted scope's own predecessor digest,
the explicit genesis marker for a genesis scope, or null exactly when
`authorized` is false).
**The evolvable lineage algorithm (normative; rewritten by the round-2
revision — the round-1 sketch was not implementable and both families
blocked on it). All pins in this subsection re-verified at `f154a5c5`.**
Today's topology is one-shot: a single active admission, an empty
disabled source foundation, one exact two-parent promotion merge (M19).
The round-1 sketch said the verifier walks first-parent history for "the
most recent revision whose tracked catalog carries an admission" and
re-runs "the same object-hash checks used today" at each hop. Three
things were wrong with that, and each is corrected below: catalog bytes
**persist into descendants**, so carrying an admission proves nothing
about which revision was the promotion; the prior scope digest the walk
wants to read **does not exist in any tracked artifact**; and today's
per-hop checks **cannot** be re-run at a historical revision. The
algorithm is therefore restated in six parts.

**(i) The historical promotion-revision predicate (exact).** A revision
R is a *promotion revision for admission A* — the only kind of revision
the walk may select — exactly when all of the following hold, judged
purely from content-hashed Git objects read at R:
- R's tracked catalog at `CATALOG_PATH`
  (`schemas/portable-engine-promotion-admission-catalog-v1.json`,
  `scripts/portable-engine-promotion-lineage.mjs:42`) parses under
  `parseCatalog` (`:673-689`) — byte-exact canonical JSON plus one LF,
  exact key set, `enabled === true` — and carries A;
- R's commit object has exactly **two** parents (`:1065`);
- `R.parents[0] === A.sourceRevision` (`:1066`);
- the second parent T (the promotion topic) has exactly one parent and
  that parent is `A.sourceRevision` (`:1069`);
- `R.tree === T.tree` (`:1070`);
- `sourceCommit.tree === A.sourceTreeObjectId`, independently hashed
  (`:1071`);
- `sourceCommit.tree !== R.tree` (`:1072`).
This is exactly the shape the verifier requires today at HEAD
(`:1064-1074`), lifted from "the checkout I am standing in" to "any
revision R." A descendant of R that merely inherits the catalog bytes
fails the parent/tree clauses and is therefore **not** selectable — the
defect the round-1 walk had. The walk selects the most recent
first-parent-reachable R strictly before the current promotion that
satisfies the predicate for some admission whose `targetTriple` matches
the canonical tuple; it does **not** select on catalog contents alone.

**(ii) The tracked source of the prior scope digest.** The round-1 text
said the predecessor is "R_prev's `admittedScopeDigest`." That value
does not exist at R_prev: `admittedScopeDigest` is a field of the
**checked promotion admission**, which is a *build output* written to
`OUT_DIR` (`build_support/portable_engine_build_consumption.rs:135-139`)
and never tracked. The tracked admission's closed field set is
`schema`, `sourceRevision`, `sourceTreeObjectId`, `topology`,
`targetTriple`, `portableArtifactId`, `artifacts`, `admissionDigest`
(`validateAdmissionShape`,
`scripts/portable-engine-promotion-lineage.mjs:691-704`) — no scope
field. **Resolution: the tracked admission gains the scope digest.**
`admittedScopeDigest` joins the tracked admission's closed key set at
`:691-704` (and the catalog JSON Schema at `CATALOG_SCHEMA_PATH`), so
the value the walk reads at R_prev is a **tracked, canonical-JSON,
merge-shape-authenticated** field of the checked-in catalog — the same
bytes the promotion merge that created R_prev was reviewed with, and
already covered by `admissionDigest`. The build-output checked
admission's `admittedScopeDigest`/`predecessorScopeDigest` (the v2
fields above) remain what they were: the *anchor* carried into the
binary, copied from the tracked value by the verifier at stamping time.
Tracked field = the walk's source; build-output field = runtime's
anchor. This is a second must-amend surface on the same chain and is
why M27 stays `must-amend`.

**(iii) The reduced per-hop validation set (drops "unchanged in
kind").** Today's per-hop machinery cannot be re-run wholesale at a
historical revision. `verifyPortableEnginePromotionAdmission` (`:1034`)
resolves HEAD (`:1041`), asserts a clean worktree (`:1043`), and calls
`pinRunningAuthority` (`:1047`, fn `:1010-1025`), which asserts that the
**current tree's** copies of the verifier module, the CapSec contract,
the bundle verifier, the portable-evidence contract, the evidence
schemas, the catalog schema, the checked-admission schema and the
catalog itself equal the *running* files — including
`fs.realpathSync(moduleFilePath) === fs.realpathSync(expectedModule)`
(`:1012`). A literal re-run at R_prev therefore fails after **any**
maintenance commit touching those paths, which makes "unchanged in kind"
false. The walk uses this **reduced** set at each hop, and only this
set:
- content-hashed commit and tree objects read via `readGitObject`
  (`:571`) — which re-hashes independently — and `parseCommit` (`:580`),
  `collectTreeLeaves` (`:641`), `readTrackedBlob` (`:667`);
- canonical-JSON catalog parse and closed-key validation via
  `parseCatalog` (`:673-689`) and `validateAdmissionShape` (`:691-704`);
- the promotion-revision predicate of (i).
Everything else — `pinRunningAuthority`, `assertCleanWorktree`,
`assertSourceAuthorityClosed`, the changed-artifact verification, the
bundle-graph joins — runs **only at the current revision**, once. The
security posture this establishes, stated plainly so the round-3
reviewer can attack the right claim: **history is judged by the HEAD
verifier's code, not by the code that shipped at each historical
revision.** That is deliberate and, we argue, preferable — the current
reviewed verifier is the one whose behavior has been reviewed, and
letting a historical revision's own verifier logic judge itself would
make a compromised past verifier self-certifying. The cost is that the
walk authenticates *structure and content* at R_prev, not the full
promotion ceremony R_prev passed; the full ceremony's result is
attested by R_prev's own `admissionDigest` and by the fact that R_prev
is in the first-parent chain of a reviewed history.

**(iv) The catalog enable/disable/reset lifecycle between promotions
(this is what makes promotion 2 possible at all).** `parseCatalog`
requires `admissions.length === 0` when `enabled === false` (`:683`)
and `=== 1` when `enabled === true` (`:686`), and
`assertSourceAuthorityClosed` (`:804-826`, catalog clause `:807`)
requires the promotion's
**artifact-source revision** to carry a disabled, empty catalog
*and* an empty-v1 `capsec/generated/target-advertisements.json`
(`:822-826`) and empty v1 attestations (`:819-820`). Under M18's
settled owner the previous promotion leaves v2/v3 bytes at the
advertisement path, so a naive second promotion — whose source
revision is a descendant of promotion 1 — fails `:823-826`
immediately. The normative lifecycle that reconciles them:
1. A promotion merge R_n leaves the tree in the **published** state:
   catalog `enabled: true` with exactly one admission (carrying
   `admittedScopeDigest` per (ii)), and the advertisement path
   carrying the v2/v3 publication bytes.
2. Ordinary development continues on first-parent descendants of R_n.
   Those revisions inherit the published state; the predicate of (i)
   correctly declines to treat any of them as a promotion revision.
3. **The reset commit.** Before promotion n+1, one reviewed commit —
   the artifact-source revision for the next promotion — returns the
   tree to the closed foundation: catalog `enabled: false` with an
   empty `admissions` array, attestations back to empty v1, and the
   advertisement path back to empty v1. This is a *depublication*, not
   a rollback: it withdraws the previous advertisement from the working
   tree while R_n's tracked admission (and its `admittedScopeDigest`)
   remains reachable in history, which is where the walk reads it from.
   `assertSourceAuthorityClosed` then passes unchanged.
4. Promotion n+1 merges its topic onto that reset revision, satisfying
   (i) with `sourceRevision` = the reset commit.
This is what makes **M18 pin 2 genuinely "unchanged"** across repeated
promotions rather than only for the first one, and M18 pin 2's
disposition is amended to say so and to point here. The cost is
explicit and belongs in the review: **between the reset commit and the
next promotion merge, the tree advertises nothing.** That is the
correct state — the tree is not, at that moment, a published promotion
— but it means the reset commit must not be treated as a release-able
revision, and the ceremony must produce reset and promotion as a single
reviewed sequence. Fable's round-2 finding 3b is resolved by adopting
this lifecycle, not by revving `assertSourceAuthorityClosed`; revving
it (letting the source foundation carry the previous v2/v3 bytes) was
considered and rejected, because it would delete the one invariant
that makes each promotion's starting state unambiguous.

**(v) Pre-foundation semantics (how absence before the catalog is
authenticated).** The walk must terminate somewhere, and below the
catalog's introduction there is nothing to parse. Verified at
`f154a5c5`: the catalog was introduced **disabled and empty** at
`afad4af9` ("Merge checked portable promotion admission"), and
`afad4af9^` does not contain the path at all
(`git cat-file -e afad4af9^:schemas/portable-engine-promotion-admission-catalog-v1.json`
→ absent); `git log --all -S'"enabled": true' -- <catalog>` returns no
commit, so no active admission has ever existed in this repository's
history. The normative rule: the verifier pins **`afad4af9` as the
lineage floor** by commit object id. Walking below the floor is not
"exhaustion" — it is termination at a named, content-hashed object. At
the floor the catalog must be present, `enabled: false`, and empty; at
the floor's parent the path must be **absent**, and that absence is
authenticated the same way everything else here is, by reading the
tree object and finding no such leaf. A walk that reaches a revision
below the floor by any route, or that finds the floor's catalog in any
other state, **fails** rather than concluding genesis. This turns
"absence of evidence" into a positive, checkable object-level fact.

**(vi) Genesis history-completeness precondition (the one live
bypass).** Genesis admissibility rests on the walk finding no prior
admission, and nothing today constrains what history the walk gets to
see: `grep -n "shallow\|grafts\|rev-list\|--depth"
scripts/portable-engine-promotion-lineage.mjs` finds only
`--no-replace-objects` (`:144`). A checkout whose **tree is current**
but whose history is truncated — shallow clone, re-created repository,
filtered history — would exhaust the walk immediately and mint a
genesis scope, arbitrarily narrow, with no predecessor comparison. This
is **not** covered by the whole-checkout-rollback boundary below, which
concerns a binary rebuilt from *old* sources; here the sources are
current and only the lineage evidence is missing. It is closed, not
disclosed, because a bypass of a guarantee this amendment newly claims
is not something to carry into a disagreement ledger. Before the walk
runs, the verifier asserts:
- the object store is **not shallow** (`git rev-parse
  --is-shallow-repository` is `false`, and `.git/shallow` does not
  exist);
- there are **no grafts and no replace refs** (`.git/info/grafts`
  absent; `git for-each-ref refs/replace` empty — complementing the
  existing `--no-replace-objects`, which suppresses replacement at read
  time but does not prove none was configured);
- the first-parent walk **terminates at the pinned lineage floor**
  `afad4af9` of (v), by commit object id, and not by running out of
  parents.
Any assertion failing is a verification failure, not a genesis. F6
gains the truncated-history subcase.

**Fixtures for this algorithm (new; F6 subcases).** (1) *Genesis* — a
history terminating at the pinned floor with the floor's catalog
disabled/empty admits a genesis-marked scope. (2)
*Promotion → ordinary commits → reset → second promotion* — the full
(iv) lifecycle; the walk skips the ordinary descendants, selects
promotion 1 by the (i) predicate, reads its tracked
`admittedScopeDigest`, and admits promotion 2 only when its
predecessor digest equals it. (3) *Stale predecessor* — promotion 2
naming promotion 0's digest refuses. (4) *False genesis* — a
genesis-marked scope presented on a history that contains promotion 1
refuses. (5) *Truncated history* — a shallow or graft-bearing checkout
whose tree is current fails the (vi) preconditions and never reaches
the genesis conclusion.

**Today's admission cardinality is GLOBAL, not per-tuple (correction).**
The round-1 text said step 1 re-checks that "the single-active-admission
rule holds per tuple." It does not: `parseCatalog` asserts
`catalog.admissions.length === 1` for an enabled catalog (`:686`) —
**one admission in the whole catalog**, for any tuple. §A4's "exactly
one active scope per tuple" is a different, weaker invariant. The
evolvable topology specified here **keeps today's global rule**: one
active admission at a time, repeated promotions serialized through the
(iv) reset lifecycle. Multi-tuple concurrent promotion would require
relaxing `:686` to a per-tuple uniqueness rule, which is out of this
amendment's scope and is not assumed anywhere in it; the walk's "carries
an admission for the canonical tuple" filter is written to be correct
under either rule, and is trivially correct under today's.

**Whole-checkout-rollback boundary (explicit):** this chain
authenticates lineage *within* the retained history of the checkout
that built the binary, with (vi) now constraining what "retained" is
allowed to mean. Runtime freshness against a binary rebuilt from
old sources — where the entire checkout, catalog, and embedded chain
are internally consistent but stale — is **out of this chain's scope**:
that is build provenance's layer (M26, Sigstore/SLSA subject
verification), and no field added here claims otherwise. F6 documents
the same boundary from the fixture side. Fixtures F1, F6.

**M28 — portable execution-binding digest + strict evidence-plan
parsers (scope-validating; binds). Added by the round-1 revision.**
Current: `portableExecutionBindingDigest`
(`packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs:216-235`)
computes the domain digest over a **closed, hand-enumerated** binding
field list (sourceRevision … outputDispositionEvidenceRawContentDigest)
— an added `scopeDigest` binding is silently **ignored** unless this
list is amended; and two strict Rust plan parsers enforce closed
binding key sets that would **reject** a plan carrying an unexpected
scope binding: the portable public-batch parser
(`src/bin/ibex/engine/capsec_portable_public_batch.rs:183-204`,
`assert_exact_keys`) and the exact-fixture portable plan parser
(`src/bin/ibex/engine/capsec_exact_fixture_evidence_batch.rs:489-508`).
The two failure modes are opposite (silent non-binding vs. hard
rejection) and both are wrong. Amendment: the three closed lists rev in
lockstep with whichever carriage rule §A10 #5 selects — either
`scopeDigest` joins all three lists as a direct binding, or the rule is
formally transitive (the scope reaches the binding digest through
`recipeCatalogDigest`, whose catalog binds `scopeDigest` per M2) and
all three lists stay untouched **with that transitivity stated and
machine-checked** (a conformance check asserting the scope artifact is
digest-reachable from the binding). The rule must be uniform across
all execution-plan bindings. Fixture F1.

**M29 — physical-promotion workflow (scope-transparent; orchestration).
Added by the round-1 revision.**
Current: `.github/workflows/portable-engine-physical-promotion.yml`
derives promotion target cells, produces output-disposition evidence,
runs the complete v2 conformance + bundle generation, re-verifies and
freezes the bundle bytes, and uploads the immutable candidate
(:372-443). Transparency argument: the workflow is pure orchestration —
every scope-bearing judgment it triggers is made by the tools it
invokes (M1 generator, M2/M3 gates via `verify:capsec-conformance`,
M24's `verify-capsec-portable-promotion-bundle.mjs`), and it neither
reads nor writes scope fields itself; its inputs/outputs are paths and
digests. It becomes load-bearing only if a scope input were passed as a
workflow parameter — the F8 ceremony-closure validation and M24's
member-set check would catch a bundle whose scope artifact did not come
from the generator. Fixture F8.

**M30 — report-schema evolution surface (scope-validating; the restamp
worklist M4 prices). Added by the round-1 revision.**
Current: both report JSON Schemas close their `bindings` objects with
`additionalProperties: false`
(`capsec/schema/conformance-report.schema.json`,
`schemas/capsec-conformance-report-v2.schema.json`), so M4's
`scopeDigest` binding cannot land without schema-file changes; and the
rich v1 report schema id is pinned across the digest-contract chain:
`packages/ibex-devtools/src/scripts/capsec-contract.mjs:503`
(`inputSchema`), `capsec/registry/policy-rules.json:255`,
`crates/capsec-semantics/src/canonical.rs:278` (contract-fixture
projection table), `crates/capsec-semantics/src/digest.rs:166` (frozen
projection schema list), plus the checked contract example fixtures.
Amendment: this is the enumerated restamp surface for M4's binding
change. The framed decision (§A10 #6): does the rich report **rev its
schema id** (`ibex/capsec-conformance/1` → a new id, restamping the
four contract pins once, cleanly) or **evolve in place** (same id, new
optional-then-required binding, restamping the same pins plus every
checked example)? Either way the v2 portable report schema revs with
the bundle (M4/M6), and no report bytes may carry a scope binding the
schema files do not admit. Fixture F1.

**M31 — installer lineage consumption (scope-transparent). Added by the
round-1 revision.**
Current: `scripts/portable-engine-installer-core.mjs` imports the
lineage verifier (:34) and consumes its checked result reading only
`authorized`, revisions, `targetTriple` (:470-476) — no advertisement,
report, cell, or scope field. Transparency argument: the installer
gates artifact installation on lineage authorization, not on
conformance claims; the scope fields M27 adds to the checked admission
pass through it untouched (it never enumerates admission fields). The
fixture that would catch it becoming load-bearing: F6's
lineage-verification failures must fail installation identically before
and after the scope fields exist. Fixture F6.

**M32 — evaluator ingresses: the host ABI and the runtime-extension
path (scope-validating; must-amend). Added by the round-2 revision —
this is the row whose absence made A3's "divergence is unrepresentable"
claim false.**
The matrix through round 1 accounted for how a disposition is *derived*
(M7 admission → M12/M13 delivery → per-gate projection) but never
asked how a disposition *enters* the evaluator. There are two entrances
that bypass the derivation entirely. All citations verified at
`f154a5c5`.
**Current — ingress 1, the caller-supplied gate.**
`crates/capsec-semantics/src/decision.rs:401-407` defines `EffectGate`
with a **public** `target_cell: TargetCellDisposition` field on a
`#[derive(Deserialize)]` struct, so a gate is fully constructible from
untrusted JSON. `ex_host_evaluate_typed_decision`
(`src/host/abi.rs:5823-5839`) is an unconditionally exported
`#[no_mangle] pub unsafe extern "C"` symbol whose `gates` argument is a
caller-owned byte buffer; it calls
`Host::evaluate_typed_decision_json_with_evidence`
(`src/host/mod.rs:3963-3990`), which strict-parses the buffer,
deserializes `Vec<EffectGate>`, and passes it to the evaluator
**unchanged**. Four `pub` Rust-level ingresses accept caller-supplied
gates identically: `evaluate_typed_decision` (:3776),
`evaluate_typed_decision_with_evidence` (:3844),
`evaluate_typed_decision_json` (:3942),
`evaluate_typed_decision_json_with_evidence` (:3963). The only in-repo
caller of the exported C symbol is test-gated
(`src/bin/ibex/engine/hermes.rs:1144`, under
`#[cfg(all(test, feature = "capsec-conformance-observer"))]`) — but the
symbol itself carries no `cfg`, and embedders and native runtime
extensions linking the host ABI are precisely the population a scoped
certification addresses. Consequence today: an out-of-scope
`coverage_edge_id` presented with `target_cell: "complete"` is evaluated
as complete, and the retained aggregate never sees it.
**Current — ingress 2, the runtime-extension direct `Complete`.**
`Host::authorize_runtime_extension_operation`
(`src/host/mod.rs:1107-1310`) is `pub(crate)`, **not** test-gated, and
is reached from the exported
`ex_host_authorize_runtime_extension_operation_v1`
(`src/host/abi.rs:5447`, host call at `:5587`) and from
`src/host/embedder_artifacts.rs:2193`. It sets
`coverage_edge_id` from the caller's `effect_semantics` argument
(`:1113`, `:1266`) and constructs its gate at `:1304-1310` with
`target_cell: TargetCellDisposition::Complete` as a literal. What
authorizes the literal today is the static-floor coverage check
immediately above (`:1245-1264`) plus admission of the extension
itself; the literal asserts "the cell obligation is not the mechanism
guarding this call," which is defensible under `CompleteAdvertised` and
not self-evidently safe under `ScopedAdvertised`.
**Amendment.** §A3's **ingress rule** applies to both: under
`ScopedAdvertised`, every ingress **discards** the incoming
`target_cell` and **recomputes** it from the retained
`AdmittedScopedTargetCells` by `coverage_edge_id` (§A3 states why
discard-and-recompute is preferred over equality-checking). For
ingress 2 the rule is conditional and stated in §A3: if the
`coverage_edge_id` is a generated inventory edge the aggregate's
disposition wins; if it is not, the literal `Complete` stays and the
refusal envelope records `hostDisposition: "extension-declared"` — so
an extension cannot launder an uncertified generated cell by colliding
its effect-semantics string with an `edgeId`. The recomputation must
happen before the gate reaches any `evaluate_decision_set*` site, which
is the same funnel M13 builds. Under `CompleteAdvertised` nothing
changes, so this row is invisible to today's releases and load-bearing
for every scoped one. Fixtures F1c (ABI subcase), F3a.

### A10. Open questions for the review round

**Settled by the round-1 design revision** (recorded here so round 3
reviews the settlement, not the open question):
- **Uncertified-disposition type placement** (round-1 Fable MATERIAL 6):
  settled in §A3 — a new host-side `HostCellDisposition` type inside
  the `AdmittedScopedTargetCells` aggregate, with `Uncertified`
  projecting to `TargetCellDisposition::Incomplete` in `fn target_cell`
  (`src/host/mod.rs:956-961` — site corrected by the round-2 revision
  from :2844-2846, which is 1 of 11 gate constructions);
  `HostCellDisposition` must derive `Copy`; decision.rs untouched.
- **Zero-authoritative-contribution rule** (round-1 Fable open
  question 1): settled in M7 (normative scoped equalities) and asserted
  directly by F4; its scope disambiguated by the round-2 revision (it
  governs the authoritative unions and execution set, **not** row
  content — out-of-scope rows keep their honest source-derived
  `required_fixtures`).
- **The host telemetry envelope's existence and shape**
  (`ibex/capsec-scoped-refusal/1`, §A3): specified; only its
  sufficiency question remains open as item 1.

**Settled by the round-2 design revision** (both round-2 BLOCKERs and
both flip sets; recorded so round 3 reviews the settlement):
- **Evaluator-ingress authority** (round-2 Codex BLOCKER 2): settled by
  §A3's **ingress rule** and the new §A9 M32 row —
  discard-and-recompute at every ingress (with the reasoning for
  preferring it over an equality check stated in §A3), the
  runtime-extension direct-`Complete` path scoped rather than
  eliminated, and F1c's ABI subcase plus the new F3a class proving a
  caller-supplied `complete` cannot override an uncertified cell. The
  round-1 claim that divergence was "unrepresentable" is **withdrawn**
  as an existing property and restated as a property the ingress rule
  establishes.
- **Telemetry emission point** (round-2 Fable MATERIAL 1, and the
  sub-clause round-1 Codex BLOCKER 2's resolution text named): settled
  as *work*, not as a fact — there is no central refusal path today
  (three evaluation bodies at `src/host/mod.rs:3794`/`:3844`/`:3874`),
  and building one refusal-observing funnel is now an explicit
  scope-validating item under M13/M14, fixtured by F3's three-body
  extension.
- **The evolvable lineage algorithm** (round-2 Codex BLOCKER 1 and
  Fable MATERIAL 3): settled in M27, rewritten as six normative parts —
  the exact historical promotion-revision predicate, the **tracked**
  source of the prior scope digest (`admittedScopeDigest` joins the
  tracked admission's closed key set), the reduced per-hop validation
  set with "unchanged in kind" dropped, the enable/disable/**reset**
  catalog lifecycle that reconciles M18 pin 2, pre-foundation semantics
  with `afad4af9` as the pinned lineage floor, and the genesis
  history-completeness precondition. Fixtured by F6a–F6e.
- **Genesis via truncated history** (round-2 Fable MATERIAL 4 — the one
  finding flagged as a live security bypass): **closed by
  precondition**, not disclosed as a non-guarantee. §A5 and M27 (vi)
  require a non-shallow object store, no grafts or replace refs, and
  first-parent termination at the pinned floor; F6e fixtures it. The
  alternative the reviewer offered — naming truncated history as a
  stated non-guarantee — was considered and **rejected**: a newly
  claimed monotonicity guarantee should not ship with a named bypass.
- **Today's admission cardinality** (round-2 Fable MINOR): today's rule
  is `catalog.admissions.length === 1` **globally**
  (`scripts/portable-engine-promotion-lineage.mjs:686`), not per tuple;
  §A4's per-tuple rule is a different invariant. M27 records both and
  states that the evolvable topology **keeps the global rule**,
  serializing promotions through the reset lifecycle.
- **M18 pin 4's disposition form** (round-2 Fable MINOR): the
  source-revision alternative is unavailable at that site
  (`include_str!` is a compile-time embed); only retirement or
  replacement is open. M18 pin 4 says so.
- **A3's "no test constructor"** (round-2 Fable MINOR): narrowed to
  "no constructor outside `portable_target_admission`"; the in-file
  `#[cfg(test)]` module at
  `src/host/portable_target_admission.rs:1560` is a descendant with
  private access, constrained by review rather than by the type system.
  F11's negative half is stated against the M15 constructors, where the
  module boundary is real.

1. **Telemetry placement (M14):** host-layer uncertified annotation via
   the fully specified `ibex/capsec-scoped-refusal/1` envelope keyed by
   `coverage_edge_id` (§A3; recommended, keeps decision.rs
   scope-transparent) vs. a new `DecisionReason` variant (flips M14 to
   scope-validating and touches the wire decision schema). The residual
   question is exactly whether LLP 0044's "distinguishable in refusal
   telemetry" is satisfied by host-emitted telemetry when raw
   typed-decision-stream consumers see identical refusals.
2. **v1-path ownership (M18) — SETTLED normatively (both round-1
   reviews concurred it was not a genuine equal alternative):** the
   **v2/v3 publication owns
   `capsec/generated/target-advertisements.json`** at promotion time.
   The sweep-recorded thirteen-pin inventory with per-pin dispositions
   is in M18 (round-2 revision: the round-1 list of eight was neither
   complete nor internally correct, so the row now records a command
   and its result instead of claiming completeness). The remaining
   discretion, narrowed by round 2: (a) where the registry generator's
   retired diagnostic-v1 emission lands, together with its declared-
   output registry and generated-artifact manifest entries (M18 pin
   10 — otherwise a regenerate pass silently rewrites v1 over the
   published bytes); (b) the form — source-revision check vs.
   retirement — of the HEAD-copy test assertions, which is a genuine
   choice for pins 5, 6 and 12 (Node tests) and a **false** one for pin
   4 (a compile-time `include_str!`, where only retirement or
   replacement is available). The outcome (they stop asserting
   HEAD-copy emptiness) is not discretionary.
   **New sub-decision, and the one that gates shipping (round-2
   revision, M18 pin 9):** `capsec-contract.mjs:3514-3517`/`:3680-3685`
   validates the **HEAD** copy against the **v1** schema and reads
   v1-shaped fields from it, so under the settled owner the CapSec
   digest contract fails on v2/v3 bytes. Either the runner reads the
   artifact-source revision's copy (**recommended** — keeps the digest
   contract's v1 surface frozen) or `SCHEMA_IDS.targetAdvertisements`
   becomes version-dispatching at this path (reopens the contract's
   schema surface and restamps pin 11's vectors). This also **falsifies
   the round-1 disposition of pin 8**, which is corrected in M18.
3. **Scope artifact placement in the bundle vs. repository:** M20
   assumes the scope artifact rides the bundle and is embedded at build
   time; the alternative (checked-in beside `target-attestations.json`)
   changes M19's mechanics. The anchor question this item previously
   left implicit is now settled by M27 (the checked promotion admission
   carries the lineage-resolved digests; the script-time verifier
   stamps them), so this item narrows to confirming the recommended
   placement: bundle-carried, with the lineage recording its digest.
4. **`TargetArmState` payload:** `ScopedAdvertised` carrying the scope
   identity makes the enum non-`Copy`
   (`crates/capsec-semantics/src/decision.rs:52-56` derives `Copy`
   today); the alternative is the Host retaining the
   `AdmittedScopedTargetCells` aggregate with the enum carrying only
   the marker. Either representation is reviewable, but **only an
   opaque admission aggregate with atomic construction is acceptable**
   — an independently mutable parallel Host record is not
   security-equivalent (§A3); state and identity must be inseparable at
   construction.
5. **Execution-binding carriage rule (M28; new, from round 1):** does
   `scopeDigest` join `portableExecutionBindingDigest` and both strict
   Rust plan parsers' closed key lists as a **direct** binding, or is
   carriage **formally transitive** through `recipeCatalogDigest`
   (whose catalog binds the scope per M2), stated and machine-checked?
   Whichever rule is chosen must be uniform across every
   execution-plan binding.
6. **Report-schema evolution (M30; new, from round 1):** does the rich
   v1 report **rev its schema id**, restamping the four
   digest-contract pins once, or **evolve in place** under
   `ibex/capsec-conformance/1` with the same pins plus the checked
   examples restamped? M4 is not implementable until this is decided.
7. **Tuple migration (new, from round 1; references deferred register
   item 7):** any feature-list change creates a fresh tuple and hence a
   legitimate fresh genesis — the one narrowing-shaped move the
   per-tuple chain permits (§A5). Does genesis admission additionally
   refuse while a *prefix tuple* (same triple, different feature list)
   has a live scope, or is the fresh-genesis lane accepted as-is with
   the claim's honesty resting on the tuple being part of the
   authenticated identity?
8. **Total-scope end state (new, from round 1):** when a scope
   eventually expands to the full inventory, does the tuple stay
   `ScopedAdvertised` with a total scope, or re-enter
   `CompleteAdvertised`? M12 makes the two mutually non-constructible
   per admission result; stating the end-state intent now prevents a
   future "graduation" shortcut from being improvised at
   implementation time.
