# Real-input dispatch ingress entered JS without the drive-guard entry boundary — input-seeded chains inherited residual carrier state and failed closed

- **Filed:** 2026-08-06, migrated from Exact
  `issues/20260805-input-dispatch-no-user-carrier-denies-async-capabilities.md`
  (live A/B evidence lives there: real click → direct capability fetch DENIED
  with a no-user constrained carrier; same fetch from setTimeout(0) GRANTED;
  agent-path activations always pass).
- **Owner:** capsec / engine embedding ingress.
- **Design:** LLP 0051 (runtime entry hygiene at the input dispatch ingress).

`ex_hermes_dispatch_event` entered JS through bare
`exactRuntimeEnterUserExecution` with no `ExactRuntimeDriveGuard`: no
generation validation, no Host-session entry, and no principal-boundary
reset — so an activation executed under whatever residual principal/carrier
TLS and Hermes embedder-slot state the runtime thread last held, and
downstream captures could collapse to the fail-closed no-user principal
(patch 0007 semantics) for the whole async chain. Harness witness: without
the guard, a first-party fs op in the dispatch-seeded promise chain failed
`ERR_IBEX_STALE_SESSION` (no session was ever entered).

Resolution: LLP 0051 Design A — the ingress takes the standard drive guard
(REENTRANT is a refusal; the API is contractually fresh-host-event-only).
Regressions: `input_dispatch_entry_grants_first_party_capabilities_across_hops`,
`input_dispatch_probe_is_gated_when_read_authority_is_withheld`,
`input_dispatch_refuses_a_stale_runtime_generation`
(`src/bin/ibex/engine/hermes.rs`); the no-shed direction is pinned by
`package_bearing_deputy_laundering_is_refused_on_every_continuation_path`
(`src/engine/runtime_extension_conformance_tests.rs`). Downstream Exact
verification tracked in the Exact ticket.
