# Oxc-only transform program (LLP 0028) — umbrella and execution map

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 1
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Oxc-only transform program (LLP 0028) — umbrella and execution map” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while delivery is a dependency-heavy, multi-stage program, with specific cited code, progress, or acceptance criteria.
**Severity:** P2
**Systems:** Issue tracking, Module Loader, Runtime, Build, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 (Draft, revision `ecd2821e`); LLP 0009, 0019, 0024, 0026, 0027

Execution map for LLP 0028: make Oxc the only production in-process
runtime transform engine and delete the SWC stack. The RFC is the
design authority; these issues are the work breakdown. Filed as
filesystem tickets at Charlie's direction; issues graduate to Linear
(Exact project) with pointers recorded here if PM state becomes
necessary. LLP 0028 is still `Draft` with an author-decision register
(§7) — tickets marked **blocked-on-decision** must not start until the
named decision is recorded.

**Execution order** (within a stage, parallelizable unless Depends-on
says otherwise):

1. Immediate, independent of the RFC lifecycle:
   `oxc-tier3-forof-quarantine`
2. Step 0 — Phase 0 freeze (all before the pin rotates):
   `oxc-native-tier3-runner`, `oxc-hermes-target-matrix`,
   `oxc-behavioral-transform-corpus`, `oxc-retirement-manifest`,
   `oxc-legacyrequired-telemetry`
3. Step 1 — toolchain + identity:
   `oxc-transform-config-manifest`, `oxc-toolchain-pin-rotation`,
   `oxc-dual-produce-report`, `oxc-audit-admission-spec`
4. Step 2 — computed-edge program (scope gated by register item 2):
   `llp0014-canonical-policy-v2` (shared with LLP 0029),
   `oxc-candidate-table-contract`, `oxc-candidate-runtime`,
   `oxc-invocation-error-taxonomy`
5. Step 3 — LLP 0024 migration:
   `oxc-llp0024-revision-and-differential`,
   `oxc-minimal-script-frontend`
6. Step 4 — window close (blocked on: platform Decision, accepted
   audit-admission Spec, archived telemetry report, quarantine rows
   resolved, minimal script frontend landed):
   `oxc-platform-decision`, `oxc-audit-admission-impl`,
   `oxc-entry-shim-migration`, `oxc-compat-selector-split`,
   `oxc-window-close`
7. Step 5 — surgery:
   `oxc-capsec-generator-update`, `oxc-engine-surgery`,
   `oxc-doc-reconciliation`

**Author-decision register** (LLP 0028 §7; blocking as noted):
1. **Resolved 2026-07-18:** LLP 0031 selects macOS arm64 and Linux x64 as
   evidence-gated 0.2 native targets; other tuples refuse source/module
   execution until independently promoted.
2. **Resolved 2026-07-18:** Snapback requires computed dynamic imports
   for 0.2; implement candidate tables now. Step 2 is unblocked and the
   telemetry gate is advisory only.
3. **Resolved 2026-07-18:** computed `require` stays fail-closed at reached
   invocation; its JSON-channel candidate design is deferred.
4. **Resolved 2026-07-18:** decorators are intentionally unsupported with a
   stable typed diagnostic.
5. **Resolved 2026-07-18:** LLP 0030 remains the standalone audit-admission
   Spec and enters formal review; candidate tables remain in LLP 0014/0026/0027.
6. **Resolved 2026-07-18:** do not extend the compatibility fence; hold 0.2
   until the step-4 gates pass.

Close this umbrella when LLP 0028's acceptance criteria are all green
and the doc moves to `Active`.
