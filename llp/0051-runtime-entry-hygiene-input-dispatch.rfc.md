# LLP 0051: Runtime Entry Hygiene at the Input Dispatch Ingress and Carrier Hop Consistency

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Host ABI, Runtime, CapSec
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-08-06
**Revised:** 2026-08-06 (cross-family codex review r1 —
`llp/reviews/0051-runtime-entry-hygiene-input-dispatch.codex.md`:
renamed from "host activation principals"; the drive guard is runtime entry
hygiene, not an activation declaration; the sibling-ingress sweep is
withdrawn pending per-ingress classification (laundering risk on
deferred-execution channels); the root-cause section now separates confirmed
facts from the unproven causal link to the live symptom; REENTRANT remains a
refusal; the evidence matrix is expanded)
**Related:** LLP 0013 (compartments; Open Q3, patches 0007/0008), LLP 0040
(runtime-extension SDK; job-constrained principal carriers, Hermes patch
0013), LLP 0016 (architecture assessment; W2 per-channel async attribution),
LLP 0021 (typed effect model), LLP 0002 (host embedding ABI)

## Problem

Exact's blog-navigation diagnosis (Exact repo,
`issues/20260805-input-dispatch-no-user-carrier-denies-async-capabilities.md`)
proved, with a live A/B on one real macOS click, that a real OS input
activation enters JS through a boundary that seeds the promise-job
constrained-principal carrier with the fail-closed no-user principal:

- a capability-checked fetch issued directly in the input-seeded chain →
  `capability_denied` (`network:fetch:127.0.0.1`, audit principal "0");
- the identical fetch from a fresh `setTimeout(0)` task → granted;
- the identical flow driven by the agent path (in-runtime JS scheduling) →
  always granted.

That is a double inversion of the intended behavior: a real user's click is
less trusted than an agent's synthetic activation, and a bare async hop
*changes* effective authority. Exact worked around the module-loading
instance with a detached macrotask (`scheduleRuntimeInfrastructureTask`), a
per-call-site opt-out; the class (real input → async hop → any
capability-gated call) remained open for all app-authored code.

## Three rails, kept distinct

The codex review of r0 identified a conflation this revision unwinds. Three
different concepts are in play and must not be merged:

1. **Runtime admission (drive/session):** which live runtime generation and
   Host session is being driven — `ExactRuntimeDriveGuard`.
2. **Principal propagation (carriers):** whose authority constrains the
   work — frame attribution, typed-principal stacks, the Hermes
   job/embedder constrained-principal slots.
3. **User activation (provenance):** why the host delivered the event. Ibex
   has no representation of this today, and this RFC does **not** add one.
   If Ibex later gates capabilities on human activation
   (clipboard/fullscreen-class), that must be a separate, unforgeable,
   runtime-generation-bound token with source class, event identity, expiry
   and consumption state — the shape of the web's user-activation model
   (HTML user activation tracking; `navigator.userActivation`;
   `Event.isTrusted` as UA-only provenance) — intersected with package
   authority, never replacing it.

This RFC fixes a rail-1 defect and pins rail-2 invariants. It deliberately
declares nothing on rail 3.

## Root cause analysis

**Confirmed:** `ex_hermes_dispatch_event`
(`src/engine/hermes_runtime_ios.cc`) entered JS with no
`ExactRuntimeDriveGuard` and no `ScopedRuntimeSecurityContext` — no
generation/nonce validation, no Host-session entry, and no
principal-boundary reset (typed-principal TLS, native-callback principal
override, attribution-runtime selection, Hermes embedder-slot sync). The
only late check it received was `ScopedRuntimeExtensionHostTask`'s
owner-thread validation. Every guarded ingress performs the full
entry-boundary reset on entry. Witness: in an armed enforce harness,
dispatching on a thread without an entered session made a first-party fs op
in the activation's promise chain fail `ERR_IBEX_STALE_SESSION` — the entry
bypassed session establishment entirely.

**Confirmed hazard (teardown order):** `~ScopedRuntimeSecurityContext` and
the drive-guard destructor restore `g_vm_runtime` *before* the typed-stack
restore performs its Hermes sync; the sync no-ops when the restored
attribution runtime is null, so the outgoing VM's embedder-host carrier slot
can retain the extent's last non-empty value. Guarded entries clear it on
their next entry sync; a guard-less ingress inherited whatever was left.

**Suspected, not proven:** that this residual-slot mechanism is the specific
source of the no-user member observed in the live Exact denial. The
mechanism is consistent with the symptom's shape — agent entries
(guard-wrapped) always clean, input entries (guard-less) intermittently
tainted by whatever the thread's previous extents left, warmth removing the
sensitive fetch — but no call trace yet connects a specific stale slot to
that click. The downstream verification plan (Acceptance evidence) treats
the live A/B flip as the deciding observation, and the residual-slot
hardening (Design C) plus an instrumented trace remain required before this
class is claimed closed.

## Semantics verdict

**Direction 1 (real input fails closed): a missing drive/session boundary at
one ingress — a gap, not a designed posture.** LLP 0013 Open Q3 / patch 0007
made no-frame/no-context capture collapse to no-user to stop a *dependency*
laundering a detached deputy into trusted root; nothing in LLP 0013/0040
says a host-delivered input event should execute under another extent's
residue. The fix is hygiene — start the ingress from the same clean,
validated boundary every other ingress gets — after which authority comes,
as designed, from the executing first-party frames and explicit carriers.
It is *not* a minted "user is privileged" declaration, and the fail-closed
no-user default for genuinely unattributable contexts is unchanged.

**Direction 2 (a hop escalates): a state-hygiene consequence, not a designed
queue semantic.** At head, the embedder queues already capture and restore
the typed-principal stack (`TimerEntry.principalStack`, nextTick's
`entry.principalStack`), Hermes patch 0013 carries the promise-job sets with
no-user members preserved as fail-closed witnesses, and the conformance
suite pins that a compromised carrier stays denied across a `setTimeout`
hop (`__deputyTimerResult`,
`src/engine/runtime_extension_conformance_tests.rs`). A hop is designed to
preserve constraints. The observed escalation is the flip side of the
residual-state defect: the deny side carried inherited residue the
legitimate capture/restore machinery never owned. Under a hygienic entry the
direct chain and the hop agree, so a hop neither grants nor sheds authority.

## Design

### A. Runtime entry hygiene at `ex_hermes_dispatch_event` (landed shape)

`ex_hermes_dispatch_event` takes `ExactRuntimeDriveGuard` (with the
`restricted` refusal) before `exactRuntimeEnterUserExecution`, exactly like
its sibling public ingresses. The guard validates generation/owner and
exclusivity, enters the Host session, and performs the embedder-owned
entry-boundary reset so the activation starts from a clean, declared
context in which frame attribution sees the live first-party frames.
(Qualification from review: this resets the embedder-owned slots — typed
stack, native principal, embedder-host carrier; the Hermes current-job and
embedder-job carriers are intentionally separate and remain owned by the
Promise/job machinery.)

Contract: this API may only deliver a **fresh host event** into first-party
dispatch code. Package-derived continuations, operation completions, and
subscription deliveries must use carrier-bearing APIs (the generic runtime
callback queue, LLP 0040) that restore their acquisition context.

**REENTRANT is a refusal.** `drive_active` proves the runtime is executing,
not that an arriving event is an authorized continuation of the current
work. A dispatch attempted inside an active drive returns failure and the
host requeues it as a new outer drive (the Exact embedding already delivers
input as its own executor turn). r0's inherit-on-nesting lean is withdrawn.

Clearing residual state at this boundary is sound precisely because the API
is constrained to fresh host events: residue is never legitimate authority
for a fresh event. The same reset applied to a continuation-delivering
channel would be laundering — which is why the sweep below is withdrawn.

### B. Sibling-ingress classification (follow-up program, sweep withdrawn)

r0 proposed sweeping `emit_module_event_impl` and the three worklet dispatch
entries (`ex_hermes_dispatch_worklet_calls`,
`ex_hermes_dispatch_worklet_json_batch`,
`ex_hermes_dispatch_motion_rated_publish`) onto the guard. The review
identified this as a potential **widening**: `scheduleOnAppRuntime` is an
explicitly deferred-execution channel whose `ExWorkletScheduledCall` record
carries identity/order/generation but **no principal carrier**
(`include/exact_runtime.h`), and LLP 0016 W2 already names this per-channel
attribution shape as the standing weakness. Resetting such a channel to
clean root would erase a constraint that should have been carried.

Instead, every bare-`exactRuntimeEnterUserExecution` ingress gets classified
before it is changed, into one of:

- `fresh-host-event` — eligible for the Design A guard shape
  (`ex_hermes_dispatch_event` is the classified instance);
- `restored-carrier` — must restore an acquisition context per LLP 0040
  (operation completions, subscription delivery; the worklet scheduled
  records need an authenticated, generation-bound principal carrier added
  before they can be made hygienic);
- `nested-continuation` — must preserve the active drive's carrier and
  prove it belongs to that drive;
- `unattributable` — stays fail-closed no-user.

Tracked as its own issue; module events must additionally be split into
unsolicited events versus completion/subscription delivery before
classification.

### C. Residual-slot hardening (follow-up, required before class closure)

Centralize teardown as a two-runtime restoration helper: clear/synchronize
the outgoing VM's embedder slots *while the outgoing runtime is still
selected*, then switch `g_vm_runtime`, restore the incoming typed stack, and
synchronize the incoming VM. Apply to both the drive guard and
`ScopedRuntimeSecurityContext` teardown, with a regression that reads the VM
slot directly. The narrow Design A fix does not depend on this (a
successful entry clears the embedder-host slot), but the vulnerability
class is not "closed" until no teardown can strand a stale slot for a
future unguarded entry.

## Acceptance evidence

ibex (this repo):

1. **Positive input A/B** (`src/bin/ibex/engine/hermes.rs`): an
   `ex_hermes_dispatch_event`-seeded chain performing a granted first-party
   capability op directly (inside a Promise reaction), nested through a
   native async completion, and across a `setTimeout(0)` hop — all granted
   under an armed enforce host, with a zero-`capability_denied` audit
   assertion. (Pre-guard, the same harness produced `ERR_IBEX_STALE_SESSION`
   and pending outcomes.)
2. **No-shed witness** (existing,
   `src/engine/runtime_extension_conformance_tests.rs`): a compromised
   constrained stack stays denied across `setTimeout(0)`
   (`__deputyTimerResult`) and across native completions; a root-only
   control grants.
3. **Admission tests:** dispatch refused off-owner and after runtime
   shutdown (stale generation).
4. `./ref-check` green; focused armed conformance + full suite green.

Exact-side (downstream verification, from the originating ticket): the live
real-click A/B flips to granted on the direct path with zero
`capability_denied` audit events, the hop path agrees with the direct path,
and the cold-boot real-click navigation smoke passes. The Exact submodule
pointer bump lands separately with the standing mac compile check.

**Downstream result (2026-08-06, recorded):** ExactAppMac built green against
this tree (ibex main + fix; the future pointer-bump compile check), and a
cold-boot real-input smoke on macOS — isolated per-trial `HOME`, dev-table
session, one `windowSendEvent` click (real responder chain, root coordinate
space) on the labs-home `lab-contract-basics-lab` tile as the first action —
mounted the Contract Basics Lab with `EXACT_SECURITY_LOG=1` armed:
**91 `capability_granted`, 0 `capability_denied`** across the activation,
including the deferred route-module loads on the input-seeded chain that the
original ticket observed failing closed. ibex-side suite posture: the three
new regressions plus the conformance no-shed witness green; the full
observer-feature bin suite shows the same 19 environment-dependent failures
as pristine `origin/main` on this machine plus one load-order flake
(`legacy_host_path_variants_and_readdir_emit_only_bounded_observations`)
that passes in isolation and in four consecutive co-scheduled runs with the
new tests.

## Open questions

1. Design C helper ordering: is clear-outgoing-then-switch safe for the
   off-owner worker scopes that deliberately leave `g_vm_runtime` null?
2. Classification mechanics for §B: code-enforced enum at each
   `exactRuntimeEnterUserExecution` call site, or a generated inventory
   checked by ref-check-style tooling?
3. What is the minimal authenticated carrier shape for
   `ExWorkletScheduledCall` (LLP 0016 W2's structural fix for the worklet
   channel)?
4. Does the residual-seed regression (a deliberately seeded VM embedder-host
   slot that a fresh dispatch must clear) need a conformance-observer-gated
   test ABI, or can it be expressed through the existing constrained-eval
   conformance harness?
