# Handoff prompt — two open CapSec P1s (2026-08-07)

Paste the block below into a fresh session working in `~/projects/ibex`.
It is self-contained; that session will not have seen the LLP 0049 Phase 1
orchestration conversation.

---

You are picking up two open P1 tickets in `/Users/ccheever/projects/ibex`.
They are independent of each other. Work them in the order given — the
first is blocking other people, the second is not.

## Coordination — read before touching anything

A concurrent session is completing the **LLP 0049 Phase 1 gate code** on
branch `phase1/integration`. Do not touch that branch, and do not merge it.
Its work is confined to: `packages/ibex-devtools/src/scripts/capsec-*`,
`scripts/portable-engine-promotion-lineage*`, `scripts/assert-releasable-*`,
`src/host/portable_target_admission.rs`, `src/host/mod.rs`,
`crates/capsec-semantics/`, `schemas/capsec-*`, `schemas/vectors/capsec-*`,
and `build_support/portable_engine_promotion_report.rs`.

Neither ticket below should require editing any of those. If you find that
one does, stop and say so rather than editing across the seam.

Note `origin/main` currently carries only part of Phase 1 (slice S1, the
scope identity contract at `7e1e1cd85`); the rest is deliberately staged off
main. Branch from `origin/main`.

## P1 #1 — `native-op:global:AsyncFunction` is unclassified (BLOCKING OTHERS)

Ticket: `issues/20260806-llp0050-asyncfunction-root-global-unclassified.md`

**Symptom.** `bun run check:drift` is red on main, and 7 tests in
`bun test packages/ibex-devtools/src/scripts/` fail, all from one root
error:

```
generate-root-global-dispositions.mjs --check
Error: unclassified observed surface native-op:global:AsyncFunction
  at classifyObservedSurface (capsec-coverage-model.mjs:15653)
```

**Provenance — already adjudicated, do not re-litigate.** This is
pre-existing to all current Phase 1 work: the identical 7 tests fail at
`5e41aca0`, and the failure reproduces at `8256639b` ("feat(engine): real
FinalizationRegistry semantics — LLP 0050") alone in a throwaway worktree.
The LLP 0050 landing exposed a new observed root global without running the
root-global disposition chain — note that `generate:root-global-dispositions`
is a DIFFERENT generator from `generate:capsec-registry`, which is how it was
missed.

**Why this matters more than one red check.** The 7 failures include the
registry generator's `renders byte-identically` and `keeps every committed
output current`. Those are the drift guards. While this is open, nobody in
any workstream can prove generated-artifact currency on main.

**Why it needs care.** `AsyncFunction` is an **eval-family constructor** —
it compiles code from strings, reachable as `(async()=>{}).constructor`. The
coverage model already knows it: `REVIEWED_HERMES_EVALUATORS` in
`packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:3064` lists it
with `reachability: "intrinsic-constructor"`, source
`hermes_intrinsic_evaluators`, beside `Function`, `GeneratorFunction` and
`eval`. Getting the disposition wrong fails in both directions:

- too permissive → the eval surface widens silently on an armed runtime;
- wrongly private → **armed startup refuses to seal bootstrap** and arming
  breaks. The standing rule is that a capture-then-delete global MUST be in
  `PRIVATE_CONSUMERS` (`capsec-root-global-dispositions.mjs:30`) or startup
  refuses.

**What to do.** Decide the disposition deliberately, comparing against how
the sibling evaluators (`Function`, `GeneratorFunction`, `eval`) are already
dispositioned — they are the precedent. Then regenerate the chain with its
generator (never hand-edit generated files) and confirm:

```
bun run check:drift
bun test packages/ibex-devtools/src/scripts/generate-capsec-registry.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-coverage-model.test.mjs
```

If the honest answer is that this needs a security ruling from the LLP 0050
author rather than a mechanical classification, say so and stop — that is a
legitimate outcome, and better than a guess that breaks arming.

## P1 #2 — `__exactWhich` declares typed effects the runtime never emits

Ticket: `issues/20260806-exactwhich-declares-typed-effects-it-never-emits.md`
(read it in full; it is precise and its citations are verified)

**Symptom.** The coverage edge `surface.native.op.exactwhich.0it66ce` in
`capsec/registry/coverage-edges.json` declares, conjunctively, typed
`env:read` at stages requested+commit, `fs:list` at requested+discovery, and
`barriers.authorizeBefore: [path-discovery, object-open, first-use]`.

The implementation at `src/engine/hermes_runtime_process.cc:3326-3382` emits
**no typed decision of any kind**:

- the only authorization is the **legacy** `checkCapability("process:spawn")`
  (:3337) — a capability the edge does not declare, via the pre-typed path,
  with no `ex_host_authorize_typed_*` call;
- `PATH` comes from `getenv("PATH")` (:3352) — the host process environment,
  bypassing the armed principal overlay that `__exactGetEnv` /
  `__exactGetAllEnv` authorize name-by-name;
- every PATH entry is probed with `access(fullPath, X_OK)` (:3367) and
  resolved with `realpath` (:3370) — filesystem discovery with no `fs:list`
  decision and no `openArmedListTarget`, unlike every other armed fs surface
  in `hermes_runtime_fs.cc`.

This is an LLP 0049 §6 **enforcement defect** (runtime behavior contradicting
the model's typed-decision claims), not an LLP 0037 attribution question —
there is nothing to credit, the observed typed sequence is empty.

**The open question that decides severity — measure it, do not assume.**
Does armed `checkCapability("process:spawn")` deny, or pass for the root
principal? `checkCapabilityWithFsMode`
(`src/engine/hermes_runtime_internal.h:1801-1910`) returns true
unconditionally under `isAllowAll()` and otherwise routes to
`ex_host_check_capability*`.

- **If it denies:** `__exactWhich` fails closed on the armed profile, the
  disclosure is unreachable, and only the *model* is wrong. Fix is a coverage-
  model correction (withdraw or correct the effect assertion) — the same class
  as the LLP 0046 §2 seeding fixes.
- **If it passes:** the disclosure of host-process PATH contents and resolved
  absolute paths is live under an armed runtime, and the fix is in the C++.

**First step, per the ticket:** run the batch physically rather than reasoning
from source. That yields the loud named failure (`runtime typed decision count
disagrees with the public recipe`, expected ≥2, observed 0) and the physical
answer to the open question. Batch commands must spell the secure feature
vector byte-for-byte: `--no-default-features --features
standard,capsec-conformance-observer,openssl-crypto` (LLP 0039).

The ticket also names a second instance of the same family,
`__exactHandleReadFileSync` (`ex_host_handle_check` + a direct `ifstream`) —
check whether the same finding applies once you know the answer.

## Reporting expectations

Honest reporting is absolute here: a red adjudicated to pre-existing beats a
green that papered. If either ticket turns out to need an author decision
rather than an implementation, record the decision cleanly and stop on that
item.
