# `__exactWhich` declares typed env:read + fs:list effects the armed runtime never emits

**Opened:** 2026-08-06 · **Priority:** P1 (draft — see Evidence status) · **Owner:**
the CapSec coverage-model / runtime-enforcement workstream (filed by the
LLP 0049 Phase 2 calibration tranche, which stopped the
`surface.native.op × [env:read, fs:list]` template class on this finding)

## Symptom

The coverage edge `surface.native.op.exactwhich.0it66ce`
(`capsec/registry/coverage-edges.json`) classifies `native-op:__exactWhich`
as **effects** and declares, conjunctively:

- `env:read` at stages `requested`, `commit`
- `fs:list` at stages `requested`, `discovery`
- `barriers.authorizeBefore: [path-discovery, object-open, first-use]`

The implementation (`src/engine/hermes_runtime_process.cc:3326-3382`) emits
**no typed decision of any kind**. In full:

- The only authorization is the **legacy** `checkCapability("process:spawn")`
  (:3337) — a capability the edge does not declare, through the pre-typed
  path, with no `ex_host_authorize_typed_*` call.
- The `PATH` value comes from `getenv("PATH")` (:3352) — the **host process
  environment**, not the armed principal overlay. Armed `__exactGetEnv` /
  `__exactGetAllEnv` read the overlay and authorize each exact name
  (`hermes_runtime.cc:4990-5137`, `typedEnvironmentOverlayAccessAllowed` in
  `hermes_runtime_internal.h:2000`); this path bypasses both.
- Every PATH entry is probed with `access(fullPath, X_OK)` (:3367) and the hit
  is resolved with `realpath` (:3370) — filesystem discovery with no
  `fs:list` decision and no `openArmedListTarget` call, unlike every other
  armed fs surface in `hermes_runtime_fs.cc`.

So the model asserts an authorization shape (typed `env:read` +
`fs:list`, staged, with pre-discovery barriers) that the runtime does not
have, and the surface discloses host-process PATH contents and resolved
absolute filesystem paths under a `process:spawn` legacy check.

## Why this is an enforcement defect, not an attribution question

LLP 0037 D1–D4 govern *how observed decisions are credited* (traversal
stratum, declared-vs-incidental capabilities, pinning observed sequences,
deny shape). Here there is nothing to credit: the observed typed sequence
is empty. This is the LLP 0049 §6 "enforcement defect" stop — runtime
behavior contradicting the model's typed-decision claims beyond
attribution — not an LLP 0037 filing.

## Evidence status (honest scope)

**Source-level, not yet physically executed.** The calibration tranche
stopped this class before spending a batch cycle, precisely because the
correct fix is not an authoring decision. What a batch run would add is the
loud named failure (`runtime typed decision count disagrees with the public
recipe`, expected ≥2, observed 0) plus the physical answer to the open
question below. Do that run as the first step of the fix.

## Open question the fix must answer

Does armed `checkCapability("process:spawn")` deny (making `__exactWhich`
fail closed on the armed profile, so the disclosure is unreachable and only
the *model* is wrong), or does it pass for the root principal (so the
disclosure is live)? `checkCapabilityWithFsMode`
(`hermes_runtime_internal.h:1801-1910`) returns true unconditionally under
`isAllowAll()` and otherwise routes to `ex_host_check_capability*`; the
armed answer must be measured, not assumed. The two branches have very
different severities:

- **Denies:** the cell is a mis-seeded model claim. Fix is in the coverage
  model (withdraw or correct the effect assertion), the same class of Phase 0
  seeding fix LLP 0046 §2 describes.
- **Passes:** the runtime discloses host PATH and resolved filesystem paths
  with no typed env or fs decision. That is a live capability-model hole and
  the P1 stands as written.

## Done when

The armed behavior is measured; either the effect assertion is corrected to
what the implementation does (through the coverage-model regen chain, with a
route-evidence allow-list entry) or the implementation is brought onto the
typed path (`authorizeTypedEnvironmentRead` for the PATH read,
`openArmedListTarget` for each probed path) and the observed sequence is
pinned; and the cell's five rows are then authorable in the fs+env+process
scope.

## Blast radius while open

`surface.native.op.exactwhich.0it66ce` is one **clean** (non-poisoned) cell
inside the LLP 0049 fs+env+process scope carrying 5 authorable rows. It is
the entire `surface.native.op × [env:read, fs:list]` template class, so that
class cannot reach `unresolved-in-scope === 0` until this is resolved.
`Exact.which` and `Bun.which` alias the same global
(`src/bin/ibex/runtime.rs:4238-4240`).
