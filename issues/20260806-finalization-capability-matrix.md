# Complete the finalization capability and compartment matrix

**Status:** Open
**Severity:** P2
**Systems:** Build, Engine, Runtime, Capability Security
**Author:** Codex
**Date:** 2026-08-06
**Related:** LLP 0050 §2, §4, §6 / OQ2 / OQ5; Exact ENG-25093; Exact RFC 0115 OQ10

LLP 0050 classifies only fully validated desktop source-patched Hermes receipts
as `ibex_hermes_finalization_capable`. The remaining artifact and authority
rows need explicit evidence rather than OS-based inference.

## Matrix work

- Qualify or reject Android Maven artifacts, iOS device and simulator slices,
  and portable exact-target artifacts for native `FinalizationRegistry`,
  `WeakRef`, cleanup-at-checkpoint behavior, and `cleanupSome` absence.
- Decide whether these facts should become fields in an advertised capability
  receipt rather than a build-local cfg, and specify migration/versioning for
  consumers of that receipt.
- Preserve the rule that custom `HERMES_LIB_DIR` selections without a fully
  validated receipt make no capability claim.

## Armed-compartment attribution

Determine which package principal owns a cleanup callback when collection and
the later checkpoint occur under different package frames. Add an armed,
cross-package test that proves cleanup cannot inherit or borrow the authority
of the package, host task, or root frame that happens to drive the checkpoint.

## Native finalizer race coverage

LLP 0050 T4 now covers live acceptance, stale and invalid refusal, throwing
followed by good delivery, producer-side RAII destruction on refusal, and
owner-thread invocation. The enqueue-between-zero-native-worker-pin observation
and registry-erasure window is not covered: the repository has no deterministic
hook at that point, and a sleep-based race would be misleading. Add a typed
barrier hook at the zero-pin/erasure boundary and prove an enqueue admitted
before erasure is drained exactly once before teardown completes.

**Done when:** every artifact row has authenticated evidence and an explicit
classification, cleanup-callback principal attribution is specified and tested
in armed compartments, and the remaining T4 teardown race has deterministic
coverage.
