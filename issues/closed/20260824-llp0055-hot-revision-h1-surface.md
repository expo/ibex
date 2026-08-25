# Exact LLP 0417 H1: hot-revision surface implementation program (LLP 0055)

**Opened:** 2026-08-24. **Governing spec:** llp/0055-hot-revision-intra-generation-updates.spec.md
(opened against Draft r1; **ACCEPTED r10, 2026-08-25** — Charlie Cheever, via orchestration
session exact-9e; commissioned by Exact LLP 0417 §6 Phase H1 after the H0 spike's stop rule did
not fire — Exact `docs/reports/0417-h0-spike.md`). Exact-side program tracking stays in the Exact repo; this
ticket tracks the ibex-side implementation slices.

## Slices

- [x] **S2 — typed graph + HotRevision algebra** (LLP 0055 §§1–2, 4): `GenerationRecordV2` /
  `AuthenticatedGenerationGraphV2` (digest domain `ibex/module-generation-graph/2`),
  `ImmutableGenerationAdmissionV2` over `GraphEdgeKey` + candidate-site pins, `HotRevision` +
  per-slot install-revision predicate, `begin_revision`/`commit_revision` with the
  exactly-live-plus-one CAS; fixtures F1–F4, F6, F7. Pure Rust, generation.rs only.
- [x] **S3 — staging seam + engine relink** (LLP 0055 §5, §2.3): `HotRevisionSurfaceV1` on the
  runner pipeline; ExecutionGeneration decoupling from the CapSec dynamic counter
  (runner_pipeline's `graph_generation` derivation); engine slot table + getter indirection;
  loader-cache invalidation bridge; prepared-carrier memo eviction; fixtures F5, F7-live, F8.
- [ ] **S4 — update-payload signature** (LLP 0055 §6; LLP 0042 amendment): ephemeral Ed25519
  session keypair, `ibex/hot-update-signature/1` domain, full tuple verification before staging;
  fixture F9 adversarial set.

## Notes

- The Exact consumer (transport, hot context, loopback peer gate, receipts) is 0417 Phase H2 in
  the Exact repo; nothing here ships a JS-visible surface, and `runtime-surface.json` is expected
  to be untouched until H2 needs one (any new `exact.*` surface joins it under ENG-22429).
- Seam coordination: LLP 0053 (carrier-bearing ingress, mid-review) touches the host-call ABI and
  capsec surfaces, not module_loader; if S3's engine work lands near its installer files, keep
  diffs additive and merge frequently.

## Status

- S2 LANDED on main @ed3da5182 (spec r10 + generation.rs algebra, 23 fixtures; dual-family loop: doc rounds 1-8 to dual-READY + code rounds to codex-confirm READY / grok-final READY; artifacts under llp/reviews/).
- Seam note: LLP 0056 leg 1 landed concurrently with a generation-free candidate-table v2 direction; LLP 0055 §4/r10 cites ibex/computed-candidates/1 — reconcile the sidecar-version citation when either spec activates its seam (doc-coherence, not a code conflict; 0056's leg touched graph.rs/runner_pipeline.rs with no overlap, full suite green post-rebase).
- S3 LANDED on main (four slices, this lane, 2026-08-24): S3(A) ExecutionGeneration decoupling
  (explicit session-minted coordinate; engine pin consumes the retained graph coordinate;
  authority counter no longer consulted); S3(B/C) plan-derived V2 graph
  (`SourceModuleGraphV1::generation_graph_v2()`, the sole production V2 row constructor) +
  `HotRevisionSurfaceV1` (§5.2 single-flight type-state chain, linear activation token, S4 seam
  marked, preflight extracted from `commit_revision` with byte-identical order/strings; F8);
  S3(D1) engine slot table `(generation, SourceId) → live record id` + retired→live forwarding
  with read-only indirection at the four cross-module use surfaces, slot-owned namespace
  transfer, `ex_hermes_module_commit_hot_revision` (all-or-nothing preflight, infallible
  mutation loop; F5, F7-live engine half, stale-write fencing); S3(D2)
  `__privInvalidateHotRevisionRecords` sealed capture bridge + prepared-carrier occupancy
  retirement (F7 carrier + loader halves). Lib suite 781/0 (767-at-branch baseline + 14 new);
  loader suite 15/0; capsec startup + callback hatch batches green. Deliberately inert: host
  API + fixtures only, no transport, no JS-visible surface, production begin refuses
  structurally; `runtime-surface.json` untouched. Engine wiring of the surface's §5.3 mount
  comments to the D1 ABI is H2-adjacent and stays open with S4.
- Pre-existing red attributed during S3 gating (NOT S3's):
  `capsec_public_startup_environment_batch::loaded_hermes_isolates_principal_environment_overlays`
  fails on clean origin/main ("extra post-bootstrap roots: __exactRequestAnimationFrame") —
  filed as `issues/20260824-startup-environment-batch-raf-disposition-red-on-main.md`.
