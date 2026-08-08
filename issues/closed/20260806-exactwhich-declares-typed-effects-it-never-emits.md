# `__exactWhich` declares typed env:read + fs:list effects the armed runtime never emits

**Status:** Closed

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

## Resolution (2026-08-07)

Resolved on `main` by `54f69d0df` (`feat(capsec): typed enforcement for
__exactWhich; close legacy numeric bearers at the typed-arm boundary`). The
physical answer to the ticket's severity question is **deny**: an armed Host
hard-denies the legacy capability shim for the root principal, so the old
`checkCapability("process:spawn")` path made the host-PATH disclosure
unreachable. The original defect was therefore a certification-integrity
mis-declaration, not a live secure-runtime disclosure.

The implementation was nevertheless brought onto the typed path so the model
and runtime now agree deliberately rather than by legacy-shim coincidence:

- a bare command authorizes exact `env:read(PATH)` at requested+commit against
  the current principal overlay before any lookup, then probes candidates
  through staged `fs:list` in the armed VFS;
- a slash-containing command skips PATH and performs only the staged `fs:list`
  branch;
- successful lookup returns the virtual `/project/...` spelling, never a host
  `realpath`; ambient `getenv`/`access`/`realpath` lookup exists only in the
  explicit insecure build;
- `__exactHandleReadFileSync` now carries the deny-only `fs:unbound-read`
  classification, and both possession and re-attenuation of a legacy numeric
  bearer fail closed after the typed-arm boundary.

Physical verification used the exact LLP 0039 secure vector
`--no-default-features --features
standard,capsec-conformance-observer,openssl-crypto`:

- `armed_which_` runtime tests — 2 pass / 0 fail. Allowed bare lookup observed
  typed env requested+commit before filesystem decisions; the direct branch
  observed only typed `fs:list`; both denied branches crossed zero path lookup
  syscalls; neither consulted the legacy oracle.
- `armed_host_evaluates_typed_authority_and_records_structured_evidence` —
  PASS, physically confirming the armed root legacy shim denies.
- `armed_host_refuses_seeded_legacy_bearer_at_use_time` — PASS, including
  possession and re-attenuation refusal for a valid bearer minted before host
  installation.

A fresh `aarch64-apple-darwin` recipe catalog now derives two exact logical
branches for `surface.native.op.exactwhich.0it66ce`. Their Phase 2 public
invocation templates remain unauthored; that is ordinary authoring backlog,
not the enforcement defect that stopped the family.
