# Key HandleRegistry grants by runtime and sweep them at destroy

**Status:** Open
**Severity:** P2
**Systems:** Host, Runtime, Capability Security
**Author:** Codex
**Date:** 2026-08-06
**Related:** LLP 0050 §5 / OQ3; Exact ENG-25093; Exact RFC 0115 OQ10

The host-global `HandleRegistry` stores grants without a runtime or realm key.
When a wrapper is collected but its JavaScript `FinalizationRegistry` callback
has not reached a checkpoint, destroying the minting runtime drops that cleanup
callback without revoking the grant. An escaped 53-bit bearer therefore remains
valid after its originating runtime dies, and repeated runtime churn has no
fixed registry-growth bound.

`src/engine/mod.rs::pending_js_cleanup_is_dropped_at_destroy_without_fault`
pins this residual deliberately: after collection with no poll/checkpoint and
runtime destroy, every minted FsHandle grant is still live. Its assertion is
annotated `@ref LLP 0050#5-decision-d4--honest-teardown-contract` so the test is
not mistaken for a desired reclamation guarantee.

## Proposal sketch

- Give each grant an authenticated runtime-generation key (pointer identity is
  insufficient; use the same nonce-bearing identity discipline as runtime
  callbacks).
- Thread that key through creation/delegation so descendants remain sweepable
  with their minting authority while preserving existing cascade revocation.
- Add an owner-side `HandleRegistry` sweep during runtime destruction, ordered
  before the host can forget the generation and without executing user JS.
- Prove explicit revoke, JS incremental cleanup, and destroy-time sweep are
  idempotent and cannot revoke grants belonging to a reused runtime address.

**Done when:** grants cannot outlive their minting runtime unless an explicit
cross-runtime transfer contract says otherwise; destroy sweeps the exact
generation; and the LLP 0050 T3 residual assertion is replaced with a positive,
generation-isolated reclamation assertion.
