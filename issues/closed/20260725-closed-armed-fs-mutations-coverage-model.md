# Reconcile hard-closed armed filesystem mutations with effect obligations

**Status:** Closed
**Resolution:** Resolved
**Severity:** P1
**Systems:** Security, Runtime, CapSec Registry, Conformance
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-25
**Related:** LLP 0021, LLP 0023 §4.1, LLP 0036, LLP 0037

The public-residual authoring audit found a target-model contradiction for
legacy filesystem mutations such as `node:fs.unlinkSync`, `renameSync`,
`chmodSync`, `copyFileSync`, `symlinkSync`, and `linkSync`.

On the Apple armed runtime, their native terminals call
`refuseClosedArmedFsMutation` before path conversion, lookup, capability
probing, or mutation. This is the intended LLP 0023 security boundary and must
not be weakened. The source-derived recipe catalog nevertheless generates
ordinary effect scenarios for the corresponding public exports (including an
`allow` obligation) from their native coverage edges. Those rows cannot be
honestly satisfied by executing the mutation, and leaving them as generic
public-invocation residuals hides that the blocking fact is deliberate target
closure.

## Done when

- Inventory every public and native filesystem route guarded by
  `refuseClosedArmedFsMutation`, including the generic path-async dispatchers,
  and distinguish unconditional closure from argument-selected open branches
  such as non-recursive `mkdir`.
- Represent the armed-target closure in the governing coverage/implementation
  model without changing the runtime to permit the mutation.
- Replace impossible effect-allow obligations with target-appropriate closure
  evidence, or document and implement another model change that preserves the
  same fail-before-lookup behavior.
- Execute each public spelling on the bound Apple engine and prove the exact
  public refusal, zero typed decisions, and unchanged filesystem
  postcondition.
- Cover the corresponding Windows route explicitly rather than borrowing the
  Apple result, regenerate all derived artifacts, and update LLP 0021/0023/0036
  accounting.

## Progress

- The unconditional inventory is modeled as deny-only
  `fs:unbound-mutation`: 56 public exports and 20 direct native terminals.
- All 76 Apple spellings execute on the bound engine with exact `EPERM`, zero
  decisions, and unchanged recursive filesystem state. The independent
  promotion validator accepts the complete 684-fixture closed batch.
- Conditional coverage edges now represent branch-local closure for
  `__exactFsPathAsync`, `__exactFsFdAsync`, and recursive `mkdir` without
  widening or closing their reviewed effect-bearing siblings.
- Apple has 17 and Windows has 16 target-local mixed-dispatcher closures. The
  bound Apple engine passes the expanded 701-fixture batch, including all 93
  armed filesystem mutations, and the independent validator accepts the whole
  artifact.
- POSIX filesystem globals are source-bound to the POSIX implementation rather
  than treated as a cross-target default. The Windows plan therefore uses
  target-absence evidence for globals not compiled into that target and never
  borrows Apple execution.
- A physical Windows engine now passes the exact 680-fixture closed batch,
  including all 79 Windows filesystem-unbound mutation rows, with zero typed
  decisions and unchanged before/after filesystem digests. The independent
  validator re-derived the batch membership from the target recipe catalog and
  accepted all 680 records.

## Resolution

Closed by the branch-local conditional-disposition model, exact compiled-source
target applicability, regenerated target plans, and separate bound Apple and
physical Windows unchanged-state execution. The wider Windows target remains
incomplete and unadvertised; that broader promotion gap is not a contradiction
in this closure model.
