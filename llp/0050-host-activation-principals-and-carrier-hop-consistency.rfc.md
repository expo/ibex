# LLP 0050: Host Activation Principals and Carrier Hop Consistency

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Host ABI, Runtime, CapSec
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-08-06
**Related:** LLP 0013 (compartments; Open Q3, patches 0007/0008), LLP 0040
(runtime-extension SDK; job-constrained principal carriers, Hermes patch
0013), LLP 0021 (typed effect model), LLP 0002 (host embedding ABI)

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

That is a double inversion of the intended trust model: a real user's click
is less trusted than an agent's synthetic activation, and a bare async hop
*changes* effective authority — in that observation, upward. Exact worked
around the module-loading instance with a detached macrotask
(`scheduleRuntimeInfrastructureTask`), a per-call-site opt-out; the class
(real input → async hop → any capability-gated call) remained open for all
app-authored code.

## Root cause (confirmed in this repo)

`ex_hermes_dispatch_event` (`src/engine/hermes_runtime_ios.cc`) was the only
public embedder ingress that entered JS **without** `ExactRuntimeDriveGuard`:
no generation/owner validation, no `ScopedRuntimeSecurityContext`, and — the
security-relevant part — no principal-boundary swap. Every guarded ingress
(eval, poll, module activation, animation-frame registration) resets, on
entry: the typed-principal TLS stack, the native-callback principal override,
the attribution-runtime binding, and (via
`exactSyncTypedPrincipalStackToHermes`) the Hermes embedder
constrained-principal slots. Input dispatch reset none of them, so an
activation executed under whatever residual principal/carrier state the
runtime thread last happened to hold, and every downstream capture
(Promise construction/settlement, job enqueue, native acquisition through
`exactCollectTypedPrincipalStack`) unioned that residue into the activation's
entire async chain. Two corroborating mechanics:

- **Residual-slot persistence.** `~ScopedRuntimeSecurityContext` and
  `~ScopedActiveAttributionRuntime` restore `g_vm_runtime` *before* the
  typed-stack restore performs its Hermes sync; when the restored
  attribution runtime is null the sync no-ops, so the VM-side embedder
  carrier slot can retain the extent's last non-empty value. Guarded entries
  clear it on their next entry sync; the guard-less dispatch entry inherited
  it. With patch 0007 semantics, any inherited no-frame/no-context capture
  collapses to `kNoUserPrincipal` — the observed fail-closed seed.
- **Harness witness.** In an armed enforce harness, calling
  `ex_hermes_dispatch_event` on a thread without an entered session made a
  first-party fs op in the activation's promise chain fail with
  `ERR_IBEX_STALE_SESSION` — direct evidence that the entry bypassed session
  establishment entirely, unlike every other ingress.

This also explains the agent-vs-real-input split (agent activations enter
through guarded surfaces, which clear residual state) and the intermittency
(the taint depends on what the thread's previous extents left behind —
module-table warmth removes the sensitive fetch altogether).

## Semantics verdict

**Direction 1 (real input fails closed): a deliberate fail-closed default
with a missing declaration step at one boundary — a gap, not a designed
posture.** LLP 0013 Open Q3 / patch 0007 made no-frame/no-context capture
collapse to no-user to stop a *dependency* laundering a detached deputy into
trusted root. Host-initiated delivery of real user input into first-party
dispatch code is the opposite case: the embedder knows exactly what it is
delivering and on whose behalf. LLP 0013 already ships the declaration
mechanisms for host-owned queues (`ScopedNativePrincipal`,
`ScopedTypedPrincipalStack`, ENG-22761/22759) and LLP 0040 ships
acquisition-carrier restoration for generic native completions. The input
ingress simply never declared anything. The web platform resolves the same
question the same way: a real user gesture is the *highest*-integrity
activation source, minted only by the user agent (HTML user activation;
`navigator.userActivation`, `Event.isTrusted`) — it confers authority
(transient activation gates) and never reduces it.

**Direction 2 (a hop escalates): a state-hygiene bug, not a designed queue
semantic.** At the current head, ibex's embedder queues already capture and
restore the typed-principal stack (`TimerEntry.principalStack`,
nextTick's `entry.principalStack`) and Hermes patch 0013 carries the
promise-job sets, with no-user members explicitly preserved as fail-closed
witnesses. A hop is therefore *designed* to preserve constraints. The
observed escalation is the flip side of the residual-state defect: the deny
side carried inherited residue that the legitimate capture/restore machinery
never owned. Fixing the boundary removes both directions at once — under a
declared entry, the direct chain and the hop agree (both carry the root
principal), so the hop neither grants nor sheds anything.

## Design

### A. Standard entry hygiene at the input-shaped ingresses

`ex_hermes_dispatch_event` takes `ExactRuntimeDriveGuard` (with the
`restricted` refusal) before `exactRuntimeEnterUserExecution`, exactly like
its sibling ingresses. The guard *is* the activation declaration: it
validates generation/owner, enters the session, and swaps the
principal-boundary TLS so the activation starts from a clean, declared
context in which frame attribution sees the live first-party frames. No new
principal kind and no new ABI surface: activation authority is exactly the
authority of the code the event handler runs as (the app root for first-party
dispatch), mirroring the web model where user activation confers no ambient
super-privilege. JS cannot forge the boundary — it exists only in the
embedding ABI, the analog of UA-only `isTrusted`.

The audit found the same bare-`exactRuntimeEnterUserExecution` shape on the
other input-shaped ingresses, which are swept in the same change:
`emit_module_event_impl` (native module events —
`ExactNativeView.sendEvent`-class delivery) and the three worklet dispatch
entries (`ex_hermes_dispatch_worklet_calls`,
`ex_hermes_dispatch_worklet_json_batch`,
`ex_hermes_dispatch_motion_rated_publish` — the gesture/motion → runtime
lane, which is itself a real-input path). The debugger ingress runs inside a
`triggerInterrupt` context with its own admission checks and is out of scope
here.

**Re-entrancy nuance.** The drive guard is exclusive (`drive_active`); an
ingress invoked from inside an already-active drive would see `REENTRANT`.
For these ingresses a nested invocation means a guarded ancestor already
declared the boundary, so the correct nested behavior is to inherit the
established context rather than refuse. Implementation options: (a) treat
`REENTRANT` as "boundary already declared" and proceed without the swap, or
(b) use the nonce-keyed `ScopedRuntimeSecurityContext`, whose semantics are
exactly boundary-swap-on-generation-crossing / preserve-on-nesting but which
skips the Running/owner validation the guard performs. Lean: (a) — keep the
validation, inherit on nesting.

Non-goals, recorded deliberately:

- The fail-closed no-user default for genuinely undeclared/unattributable
  contexts is **unchanged**. We do not flip any default to root.
- No "runtime-infrastructure detach" blessing is added (the Exact ticket's
  ask 2). Under a declared entry the direct path and the detached path carry
  the same principal, so the workaround pattern loses its security meaning;
  ENG-22631 scheduling semantics stay as they are.
- Transient-activation metadata (expiry, `isActive`) for future
  activation-gated capabilities is out of scope; the guard-based shape does
  not preclude adding it later.

### B. Hop-consistency witnesses (regression pins)

The no-escalation property must be pinned, not assumed:

1. **Input A/B regression** (`input_dispatch_seeded_chain_capability_ab_diagnostic`,
   `src/bin/ibex/engine/hermes.rs`): an `ex_hermes_dispatch_event`-seeded
   chain performs a granted first-party capability op directly, nested one
   continuation deeper, and across a `setTimeout(0)` hop — all three must be
   **granted** under an armed enforce host. Before the guard fix the harness
   run produced `ERR_IBEX_STALE_SESSION` / pending outcomes; after it,
   granted/granted/granted.
2. **No-shed witness**: a chain whose typed-principal carrier holds a
   constraining member must still be constrained after a `setTimeout(0)`
   hop (the timer capture/restore path), so the fix cannot be read as "hops
   normalize to root." (The existing deputy/timer red-team suite covers the
   scalar scheduler plane; this pins the carrier plane.)

### C. Residual-slot hardening (follow-up, same class)

The restore-order hazard in §Root cause (Hermes carrier slot surviving a
guard exit when the attribution runtime is restored first) deserves its own
closure so future guard-less entries cannot re-open the class: sync the
Hermes slots against the *outgoing* runtime before restoring `g_vm_runtime`,
or assert-clear the slots at guard exit. Tracked as a follow-up issue rather
than blocking the ingress fix.

## Acceptance evidence

- ibex: the two §B witnesses green in the armed conformance configuration;
  full ibex test suite green.
- Exact-side (downstream verification, from the originating ticket): the
  live real-click A/B flips to granted on the direct path with zero
  `capability_denied` audit events, the hop path agrees with the direct path,
  and the cold-boot real-click navigation smoke passes. The Exact submodule
  pointer bump lands separately with the standing mac compile check.

## Open questions

1. §C ordering: is sync-before-restore safe for the nested-drive case
   (worker scopes that deliberately leave `g_vm_runtime` null), or is
   assert-clear at guard exit the safer shape?
2. Should other `hermes_runtime_ios.cc` ingresses that use bare
   `exactRuntimeEnterUserExecution` (`ex_hermes_dispatch_*` siblings, if
   any remain) be swept onto the guard in the same change? (Audit performed
   in this RFC's implementation: `ex_hermes_dispatch_event` at line ~931 and
   the sibling entry at line ~836 — verify the sibling.)
3. Do we want a named, greppable "host activation" scope alias (a
   `ScopedHostActivation` typedef over the guard) so future input-shaped
   ingresses (gamepads, IME, accessibility actions) reach for the declared
   boundary by name?
