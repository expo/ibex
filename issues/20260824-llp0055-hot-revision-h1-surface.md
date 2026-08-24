# Exact LLP 0417 H1: hot-revision surface implementation program (LLP 0055)

**Opened:** 2026-08-24. **Governing spec:** llp/0055-hot-revision-intra-generation-updates.spec.md
(Draft r1; commissioned by Exact LLP 0417 §6 Phase H1 after the H0 spike's stop rule did not fire —
Exact `docs/reports/0417-h0-spike.md`). Exact-side program tracking stays in the Exact repo; this
ticket tracks the ibex-side implementation slices.

## Slices

- [x] **S2 — typed graph + HotRevision algebra** (LLP 0055 §§1–2, 4): `GenerationRecordV2` /
  `AuthenticatedGenerationGraphV2` (digest domain `ibex/module-generation-graph/2`),
  `ImmutableGenerationAdmissionV2` over `GraphEdgeKey` + candidate-site pins, `HotRevision` +
  per-slot install-revision predicate, `begin_revision`/`commit_revision` with the
  exactly-live-plus-one CAS; fixtures F1–F4, F6, F7. Pure Rust, generation.rs only.
- [ ] **S3 — staging seam + engine relink** (LLP 0055 §5, §2.3): `HotRevisionSurfaceV1` on the
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
