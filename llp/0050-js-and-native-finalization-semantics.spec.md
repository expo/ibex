# LLP 0050: JS and Native Finalization Semantics

**Type:** Spec
**Status:** Review
**Systems:** Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-08-06
**Revised:** 2026-08-06 (rev 2 — codex round 1 reconciliation: ownership-preserving refusal API, artifact-bound capability classification, cleanup-at-checkpoint mechanism, standard-only JS liveness with a non-normative qualification probe, sweep-ordering constraint, HandleRegistry residual restated as retained-authority debt, lockdown hardening gap adopted; artifact `llp/reviews/0050-js-and-native-finalization-semantics.codex.md`)
**Related:** LLP 0003 (Hermes engine bridge — event loop, FsHandle reclamation); LLP 0013 (lockdown/compartments); LLP 0026 (owner-thread drive); LLP 0040 (runtime extension SDK — completion tokens, extension close ordering); Exact RFC 0115 §7/OQ10 (WebGPU GC-driven resource reclamation, the external consumer contract this spec closes); Exact ENG-25093

## Summary

Ibex offers two finalization tiers with different guarantees, and the split is
deliberate:

1. **JS tier — `FinalizationRegistry`/`WeakRef`, standard weak guarantees and
   nothing more.** When the pinned Hermes artifact provides the native
   primitive, ibex does not substitute a polyfill and does not restrict it.
   Cleanup callbacks run **after** collection, when the engine reaches a
   **microtask checkpoint** (mechanism in §3), may be **delayed or batched**,
   and **may never run at all** — including when the runtime is destroyed
   with registrations still pending. These are exactly the web standard's
   guarantees (ECMA-262 §9.10 + WeakRef proposal host hooks; HTML grants
   agent shutdown the same latitude). Ibex adds nothing stronger.
   `cleanupSome` is not exposed (optional in the spec; absent from the
   pinned artifact).
2. **Native tier — the runtime finalizer queue.** `pushRuntimeFinalizer`
   gives every **accepted** entry exactly one owner-thread invocation
   attempt, provided the owner keeps polling or completes teardown; failure
   of one finalizer is logged and does not strand later entries. Enqueue
   **refusal** is part of the contract, not a wart — see §4, including the
   rev 2 ownership fix.

The governing rule joining them: **correctness-bearing native resource
reclamation must never live solely in a JS cleanup callback.** The JS tier is
an incremental optimization (reclaim earlier than teardown); authoritative
reclamation is native — the finalizer queue plus an owner-side sweep keyed to
runtime/realm death. This is the same stance Exact RFC 0115 §4 takes for GPU
handles ("the account/realm sweep is the authoritative reclamation path and
wrapper finalization is the incremental optimization over it").

**Consequence for consumers needing bounded live-runtime memory (WebGPU):
standard weak semantics alone cannot bound resource use in an indefinitely
live runtime.** A consumer whose correctness or memory ceiling depends on
reclamation must bring its own budget/pressure/sweep mechanism (RFC 0115's
accounting, caps, and account/realm sweep); the JS tier only makes
reclamation *earlier*, never *guaranteed before teardown*.

## 1. History and status

- The former bootstrap `FinalizationRegistry` **stub** (feature-detected
  true, never fired, strongly retained targets) was removed in 07ba47068
  (2026-07-17, refs ENG-25093). Engines without the primitive now leave the
  global **absent** — honest absence — and `FsHandle.revoke()` remains the
  deterministic fallback (LLP 0003; `src/engine/mod.rs::compat_and_fs_handle_sources_leave_finalization_absent_and_explicit_revoke_reclaims`).
- The pinned Hermes source profile (commit `e639a7bad8bf` on the
  260318099.0.0 train + `patches/hermes/` stack) **provides native
  `FinalizationRegistry` and `WeakRef`** (the train includes the WeakRef
  read-barrier fix; `scripts/hermes-version.sh`). Empirically (probe,
  2026-08-06): 100/100 cleanup callbacks fire at the first checkpoint after
  a forced GC; none fire synchronously inside `gc()`.
- CapSec's surface inventory classifies `FinalizationRegistry` and `WeakRef`
  as intrinsic global receivers. That inventory is static analysis; the
  lockdown hardening gap it does not cover is §6.

## 2. Decision D1 — artifact-bound capability classification

The repository previously refused to classify any Hermes artifact as
FinalizationRegistry-capable (07ba47068 kept the reclamation test
probe-guarded and vacuous-on-absence). This spec introduces classification
**keyed to the authenticated artifact, not the build OS**: the Hermes profile
provenance machinery (`build.rs`, `build_support/hermes_profile_provenance.rs`)
already validates the pinned commit, patch stack, build authorities, and
artifact digest; classification rides that identity.

- **Classified capable:** the reviewed source-patched profile (pinned commit
  `e639a7bad8bf` + current patch stack) as validated by the provenance
  receipt on desktop hosts (macOS, Linux, Windows). Mechanism: `build.rs`
  emits `cargo:rustc-cfg=ibex_hermes_finalization_capable` **only** when it
  has validated a receipt whose profile is on the classified list. Engine
  tests compiled under that cfg **hard-fail if the primitive is absent or
  does not fire** — a vacuous pass is a failure.
- **Unclassified (probe-guarded absence contract applies):** Android Maven
  (`250829098.0.14`), iOS device/simulator, portable exact-target artifacts,
  and custom/unreceipted builds (`HERMES_LIB_DIR` overrides without a
  receipt). Unclassified is not "incapable" — it means no hard test claim;
  the honest-absence branch remains the contract if the primitive is
  missing.
- The full artifact matrix (which of these rows are in fact capable, and
  whether classification should be advertised as a capability receipt —
  `finalization-registry`, `weakref`, `cleanup-at-checkpoint`,
  `cleanupSome-absent`) is OQ2.

Rationale: the capability is a consumer-visible contract (WebGPU OQ10 gates
its zero-config ecosystem claim on it). An unclassified capability that
happens to work is not a contract; a classified one with a hard test bound to
the authenticated artifact is.

## 3. Decision D2 — JS-tier semantics offered (and not offered)

**Mechanism (descriptive, this pinned Hermes):** cleanup callbacks are not
enqueued as individual jobs. At a microtask checkpoint (`drainMicrotasks` →
drain jobs → `clearKeptObjects` → `cleanUpFinalizationCallbacks`), Hermes
scans all registries and runs callbacks for dead registered targets. In ibex,
checkpoints are reached through the guarded microtask drains during
`ex_hermes_poll`, evaluations, and host-task servicing (LLP 0003). Nothing in
this paragraph is a consumer guarantee beyond what "Offered" states below.

Offered, matching the standard:

- Callbacks fire only after their target is collected, on the runtime's
  owner thread (LLP 0026), at a subsequent checkpoint.
- Delay and batching are unbounded. `unregister` prevents not-yet-run
  callbacks.
- Registries hold their **targets** weakly (WeakRef-corroborated in tests:
  no pinning). **Held values are held strongly** — a held value that
  transitively references its target keeps that target alive forever;
  consumers must use held values that do not retain their targets (primitive
  ids recommended, and what `FsHandle` does).

Explicitly not offered:

- **No promptness**: no bound between last-reference-drop and callback.
- **No per-registration liveness**: a specific registration may never fire,
  even in a live runtime. The **qualification probe** (§7 T1/T2) — forced GC
  plus continued checkpoints reclaims a synthetic population — is
  implementation evidence required of classified artifacts, **non-normative
  for individual registrations**, and not a substitute for a consumer-side
  budget (Summary).
- **No teardown flush**: registrations still pending at `ex_hermes_destroy`
  die with the VM; their callbacks never run and no user JS executes during
  teardown (LLP 0003).
- **No `cleanupSome`**, no ordering guarantee among callbacks. Cross-realm
  registration behavior is unspecified and untested here — do not rely on
  it.

## 4. Decision D3 — native-tier contract and the staleness story

`pushRuntimeFinalizer(target, fn)` (`src/engine/hermes_runtime.cc`):

- **Accepted enqueue ⇒ exactly one owner-thread invocation attempt**, made
  during any ordinary poll that reaches the finalizer-drain stage, or at one
  of the three teardown drain points (inside the producer-pin wait loop,
  after the last unpin, and after registry erasure) — provided the owner
  keeps driving the runtime or destroys it. A throwing finalizer is logged
  and skipped, never retried, and never strands later entries. Finalizer
  bodies must be effectively noexcept, non-blocking, must not run user JS,
  must not re-enter Hermes, and must be idempotent against the owner's
  authoritative sweep.
- **Refusal ⇒ nothing was transferred (rev 2 fix).** The pre-rev-2 signature
  takes `std::function<void()>` by value, so a refused enqueue destroys a
  moved-in closure's captures on the producer thread — contradicting the
  declared "no transfer on failure" contract and unusable for closures
  owning thread-affine or double-release-sensitive state. The
  implementation change: validate admission before taking ownership (accept
  by reference and move only on success, or return the refused closure),
  and report `Accepted | Stale | Invalid` instead of `bool` (`Stale`: the
  pointer+nonce generation is gone; `Invalid`: malformed target). Matching
  generations in `Closing`/`Quarantined` are accepted — admission tracks
  registry identity, not lifecycle phase.
- **Producer classes.** Every call site proves one of:
  - **Refusal-impossible** — a lifetime proof (e.g. a native-worker pin)
    keeps the generation admitted until the producer settles; refusal is
    therefore a producer-lifetime bug — fail loud (`std::terminate`), never
    leak. Current sole producer: the WebSocket final context release
    (`native_ws_release_context`).
  - **Fallback-backed** — refusal is safe because a **named authoritative
    fallback** owns reclamation of everything keyed to the dead generation
    (for GPU wrappers: RFC 0115's account/realm sweep). A fallback-backed
    producer without an actual fallback is a design error, not a supported
    configuration.

  New call sites carry a one-line class annotation
  (`@ref LLP 0050#4…`), mirroring the callback-affinity discipline, and a
  source-contract test keeps the classification visible on every CI host.

## 5. Decision D4 — honest teardown contract

At `ex_hermes_destroy` (after admission closes and producer pins drain):

- Queued JS callbacks are **not invoked**; their `ownerDisposition`s run,
  and their closure captures (including JSI owners) are destroyed on the
  owner thread (LLP 0040).
- JS finalization registrations still pending die with the VM (§3); no user
  JS executes during teardown.
- The native finalizer queue is drained at all three teardown points (§4).
- **Sweep ordering constraint:** `finishRuntimeTeardown` erases the
  runtime's registry generation **before** runtime-extension `close()` runs.
  A close-time authoritative sweep therefore **must release directly on the
  owner thread** — it cannot enqueue into the finalizer queue of its own
  dying runtime. Consumers needing queue access at teardown must hook
  earlier (before `finishRuntimeTeardown`), or design the sweep to be
  queue-free. WebGPU's account/realm sweep must satisfy this.
- **Documented residual — retained-authority debt:** host-level
  `HandleRegistry` grants whose only reclamation paths are a JS cleanup
  callback or an explicit `revoke()` are not swept at runtime death — the
  registry is host-global and carries no runtime key
  (`src/host/handles.rs`). Growth across runtime churn has **no fixed
  bound**, and an escaped handle id (a 53-bit possession token) **remains
  valid after its minting runtime dies**. This is legacy reclamation debt,
  not a claim of safety; a per-runtime grant sweep is tracked as a
  follow-up (OQ3 → filesystem ticket). The single-runtime CLI process
  boundary is the mitigation in practice today.

## 6. Decision D5 — lockdown hardening of the weak intrinsics

The lockdown hardening roots include `WeakMap`/`WeakSet` but omit `WeakRef`
and `FinalizationRegistry` (`src/engine/hermes_runtime.cc`, roots list in the
intrinsics freeze walk), while compartments share constructor identities —
leaving those constructors/prototypes plausibly mutable across packages under
lockdown. Since this spec promotes them to relied-upon primitives, they join
the hardening roots (conditionally, when present), with tests covering
constructor/prototype freezing and cross-package mutation attempts. If the
addition destabilizes existing capsec conformance suites, land the spec's
other pieces and file the hardening as its own ticket rather than blocking —
but the gap must be tracked either way. Cleanup-callback principal
attribution in armed compartments is OQ5.

## 7. Test obligations

All in `src/engine/mod.rs` unless noted. T1/T2 compile their hard-failure
form under `ibex_hermes_finalization_capable` (§2); on unclassified builds
they keep the probe-guarded shape.

- **T1 — user-level firing (the former stub's core lie):** register N plain
  objects with primitive held values in user JS, `unregister` a
  deterministic subset, drop references, forced GC + poll (bounded loop);
  every non-unregistered held value fires exactly once, no unregistered
  value fires, and a `WeakRef` to a sample dropped target derefs
  `undefined` (no pinning). Hard-fails on absence under the capable cfg.
- **T2 — WebGPU-shaped sustained load (ibex half of the split gate):** a JS
  "library" wraps synthetic GPU handles carrying declared byte weights,
  registers each wrapper with a release-recording callback; ~10 batches ×
  ~500 wrappers: create, drop, forced GC + poll until the batch's ids are
  released (bounded, hard-fail on timeout). Leak gates: cumulative
  unreleased **count** and unreleased **weighted bytes** stay bounded
  (≤ one batch) after each drain; total released == total created; a mixed
  retained/dropped batch releases only the dropped; explicit dispose
  followed by GC releases exactly once. Hermes `allocatedBytes` plateau
  (via the existing heap-info API) is a secondary, non-gating assertion.
- **T2b — Exact-side integration (the other half, out of this repo):** real
  WebGPU wrappers → release queue → account/realm sweep under repeated
  workload waves, gated on native live-byte accounting. Lives with Exact
  RFC 0115 Phase 1 evidence; this spec only names it so the ENG-25093 gate
  is read as the pair, not T2 alone.
- **T3 — teardown:** registrations pending at destroy (targets collected,
  checkpoint not reached) → destroy without polling: no fault, no user JS;
  plus the §5 residual pinned honestly: dropped-but-unfired FsHandle grants
  remain live in the host registry after destroy (`@ref LLP 0050#5` at the
  assertion so nobody "fixes" it into a false claim).
- **T4 — refusal semantics (with the rev 2 API fix):** enqueue accepted
  while alive (finalizer runs on a later poll); after destroy the same
  target yields `Stale`, the refused closure's RAII capture is destroyed on
  the producer's side untouched-by-the-queue (proving no transfer), and the
  finalizer never runs. Race cases: enqueue immediately before destroy;
  enqueue between zero-pin observation and registry erasure (teardown drains
  still execute it); throwing finalizer followed by a good one; reentrant
  enqueue from a finalizer.
- **T5 — existing pair stays:** native FsHandle reclamation and the
  honest-absence branch (07ba47068), with the persistent-runtime test's
  vacuous branch retired on classified builds (it becomes T1's hard form).
- **T6 — lockdown hardening (D5):** `WeakRef`/`FinalizationRegistry`
  constructors and prototypes frozen under lockdown; cross-package mutation
  attempts fail.

## 8. Open questions

- **OQ1:** the aggregate callback backlog already counts the finalizer
  queue. Add test-only accepted/executed/refused/high-water receipts first;
  promote to stable ABI only if an operational consumer materializes.
- **OQ2:** verify and classify the remaining artifact rows (Android Maven,
  iOS, portable exact-target); decide whether classification becomes an
  advertised capability receipt.
- **OQ3:** per-runtime HandleRegistry ownership + sweep (the §5 residual is
  a live counterexample to this spec's governing rule; tracked as a
  filesystem ticket at landing).
- **OQ4:** does the WebGPU wrapper actually need the finalizer queue (a
  HostObject destructor during GC already runs on the owner thread), or is
  owner-thread direct release + authoritative sweep sufficient? Decide in
  the RFC 0115 Phase 1 implementation; `jsi::setExternalMemoryPressure` is
  worth wiring there as a collection-pressure hint (advisory only — Hermes
  forgets the external bytes when the JS wrapper dies, which can precede
  the native release).
- **OQ5:** cleanup-callback principal attribution in armed compartments
  (which package's authority does a cleanup callback run under?).
