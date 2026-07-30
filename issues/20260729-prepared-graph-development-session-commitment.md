# Development-session prepared-graph commitment transport

**Status:** Open
**Systems:** Module Loader, Dev Server, Session Workers, Host Embedding
**Author:** Codex
**Date:** 2026-07-29
**Related:** LLP 0042 §Development commitment; Exact LLP 0413 §16 Q14;
issues/closed/20260728-prepared-graph-independent-commitment.md

The production-shaped commitment and admission path is complete. Implement
the deliberately separate `ibex/prepared-graph-commitment-dev/1` credential
only after Exact chooses the cross-process transport:

- mint a run-scoped secret and `{runId, generation, issuedAtMs}` identity;
- MAC the canonical commitment body in the dev producer;
- carry it over authenticated dev/session state, never through the writable
  publication directory;
- revoke on session restart, generation advance, or explicit invalidation;
- emit visibly non-production admission diagnostics; and
- prove production `preparedGraphs` and production admission structurally
  refuse the dev credential.

Do not add a disk credential or reuse the production schema while the
transport decision remains open.
