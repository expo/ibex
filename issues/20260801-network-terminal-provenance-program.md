# Network terminal-provenance program (LLP 0045) — umbrella

**Status:** Open
**Severity:** P2
**Systems:** Security, Conformance, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0045 (the plan; read it first); LLP 0044 §9 (origin
measurement); issues/20260728-capsec-public-surface-evidence-backlog.md

Umbrella for making the network builtins' enforcement routes statically
provable, so the 373 network cells poisoned by
`no-static-enforcement-terminal` (64% of the family) convert from
unfixable-by-authoring into ordinary Lane A authoring work. LLP 0045 is
the design authority; this ticket tracks execution.

Work breakdown (details and gates in the LLP):

- [ ] Step 0: SSA-alias analyzer extension spike + soundness review
      (register item 2); measure per-module poison delta — expected to
      clear dns/tls outright.
- [ ] Step 1: http.js enforcement-trunk extraction (117 internal call
      sites / 62 prototype methods; register item 1 decision needed
      first).
- [ ] Step 2: net, http2, https, dgram, ws on the proven pattern.
- [ ] Step 3: full catalog regen (target: 373 → ~0 poisoned network
      cells, residue explicitly dispositioned) + security review of
      changed enforcement paths.

Blocked-on-decision: LLP 0045 register items 1 (de-patching enforcement
internals) and 3 (sequencing vs the fs+env+process v1.1 push). Do not
start step 1 before item 1 is decided; step 0 is decision-free and can
start any time.

**Done when:** LLP 0045 step-3 gate passes and network's cells are
Lane A-authorable, with the hand-off recorded in the backlog ticket.
