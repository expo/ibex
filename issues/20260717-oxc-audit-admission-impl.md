# Implement audit-admission (audit source execution via the producer)

**Status:** Open
**Impact:** 4
**Urgency:** 3
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Implement audit-admission (audit source execution via the producer)” shows the issue materially affects a supported product or engineering path; it belongs in the current program but is not an immediate blocker, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Severity:** P2
**Systems:** Security, Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b
**Depends-on:** oxc-audit-admission-spec

Implement the accepted audit-admission Spec so snapshotless
audit/diagnostic runtimes execute source through the graph producer
under the contract's fences (or, if the fallback was chosen, refuse
source entries and accept only prepared carriers). Includes the
denied/missing/cross-principal fixtures and a fixture proving
`ibex capsec audit` executes source entries via the Oxc path
post-migration.

**Done when:** compat evaluator no longer reachable from audit
runtimes; contract fixtures green; the repointed loader conformance
runner passes under audit.

## Implementation plan — 2026-07-27

Code-verified phased plan (paths/type names checked against the tree at
eaf7ff67). Each phase lands green independently.

**Current reality.** `ibex capsec audit <file>` → `run_capsec_audit`
(`src/bin/ibex/main.rs:1368`) → `Runtime::from_audit_cli`
(`src/bin/ibex/runtime.rs:3402`, `SecurityMode::Audit`, already refuses
`--policy`) → `run_file_with_args` (`runtime.rs:3714`) — the compat evaluator
with no window check. The producer pipeline
(`build_authenticated_source_graph_v1_with_host`,
`src/module_loader/runner_pipeline.rs:1057`) requires
`Arc<ArmedSnapshot>` via `SourceGraphHost::snapshot()`, and
`SourceModuleGraphV1` embeds it. `Workflow::{ProductionEnforce,
DiagnosticAudit}` and the `MissingAuthorityMode`/`would_deny` stratum already
exist in `crates/capsec-semantics/src/decision.rs`; what's missing is the
diagnostic context, admission variant, receipts, and an unarmed native
evaluation path. The loader conformance runner
(`run-hermes-compat-loader.mjs:169`) already spawns `ibex capsec audit`.

1. **Closed schemas + sealed types** (small/medium):
   `schemas/diagnostic-graph-snapshot-v1.schema.json` +
   `diagnostic-audit-execution-receipt-v1` with valid/invalid vectors;
   Rust `ForegroundAuditGraphSnapshotV1` / `ForegroundAuditDecisionContextV1`
   / receipt types with no conversions to `ArmedSnapshot` (module privacy);
   register in `src/compiled_contract.rs`; capsec regen.
2. **Split graph-capture identity from armed authority** (medium, the
   load-bearing refactor): `SourceGraphHost::snapshot()` becomes a sealed
   authority enum {Armed, ForegroundAudit}; `DiagnosticSourceModuleGraphV1`
   without the ArmedSnapshot field; §2 capture fences (retained roots, byte
   capture, SourceId derivation, hard refusals) + fence unit tests. Watch
   `unarmed_closed` (`src/host/mod.rs:279`) and the "unarmed host cannot
   resolve executable modules" bail.
3. **Diagnostic admission + sealed linker arm + receipts** (large, riskiest):
   diagnostic `ArtifactAdmissionV1` variant (inline-only; HBC refuses);
   `evaluate_native_module_graph` (capsec-PINNED range — review+repin) gains a
   DiagnosticAudit arm installing `Workflow::DiagnosticAudit`, run-local
   generation/nonces, protected-object baseline, bounded (1,024) would-deny
   evidence stream, receipt at completion. UNKNOWN to prototype first: the
   native runner today evaluates only under armed structured sessions; the
   spec is silent on diagnostic session mechanics.
4. **Wire the CLI route** (medium): capture → diagnostic admission → native
   evaluation when the target is advertised by the arming-grade verified
   advertisement authority (NOT the CLI allowlist —
   `current_native_module_runner_target_is_advertised` is the weaker gate);
   stable `target-unavailable` refusal otherwise; v1 refuses `-e`/stdin/REPL
   audit forms. `main.rs` edits border the pinned
   `authenticated-product-routing` range.
5. **Conformance matrix + repointed corpus** (large, parallelizable): the 13
   spec items incl. denied/missing/cross-principal release-gate fixtures
   (denial = compiled registry state, not a supplied policy), receipts
   proving the native path in `run-hermes-compat-loader.mjs`, needle checks.
   New capsec batch files must join `REVIEWED_BINARY_RUST_PATHS` and carry
   `#[cfg(not(feature = "insecure"))]`.
6. **Delete audit reachability of the compat evaluator** — rides LLP 0028's
   window close (`20260717-oxc-window-close.md`); phases 4–5 already make it
   unreachable for advertised targets.

Cross-cutting: every phase runs the capsec regen chain; LLP 0021 needs the
foreground-vs-armed revision (LLP 0030 §1 says so); LLP 0028's register row
updates with progress.

## Phase 1 landed — 2026-08-05

The closed `ibex/diagnostic-graph-snapshot/1` and
`ibex/diagnostic-audit-execution-receipt/1` schemas now have executable valid
and invalid mutation vectors. The CapSec semantics crate exposes the wire
projection and receipt plus opaque, non-serializable
`ForegroundAuditGraphSnapshotV1` and `ForegroundAuditDecisionContextV1` live
types. Their fields and construction seal are module-private, no conversion to
`ArmedSnapshot` exists, and compile-fail tests pin external fabrication,
deserialization, and diagnostic-to-armed conversion as type errors. Phase 1
does not expose a live-handle constructor; Phase 2 must add the sole
capture-backed construction path together with the retained-object and byte
capture fences.

`src/compiled_contract.rs` carries a closed diagnostic-only registry for both
schema documents. It intentionally does not add either diagnostic evidence
type to the production stub's `acceptedSchemas`. The complete CapSec/vendored
regeneration chain and the independent generated-drift check completed without
tracked artifact changes.

Phases 2–6 remain open. In particular this phase does not change
`SourceGraphHost`, graph capture, artifact admission, the native linker,
receipts at runtime, CLI routing, conformance routing, or compatibility
evaluator reachability.
