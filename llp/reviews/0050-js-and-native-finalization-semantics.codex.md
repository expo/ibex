# Review: LLP 0050 — JS and Native Finalization Semantics (codex, round 1)

**Document:** llp/0050-js-and-native-finalization-semantics.spec.md (rev 1, Draft)
**Reviewer family:** codex — `codex exec`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox read-only
**Session id:** 019fd826-3d92-7511-9e25-60480fe32770
**Date:** 2026-08-06
**Method:** Read-only repository access with explicit verify-these-claims instructions and a fixed output skeleton. Draft author is Claude-family (Fable 5), so this is the cross-family round. Orchestrator spot-verified the decisive findings before adopting them into rev 2 (by-value `std::function` refusal ownership; Hermes cleanup-at-checkpoint in `~/.cache/exact/hermes/hermes-src`; lockdown hardening roots; 53-bit handle ids; teardown-before-extension-close ordering) — all confirmed.
**Verdict line:** "strong design, substantive revision required" — keep in Draft, revise before implementation.

---

## Overall Assessment

The core proposal is a good idea: remove the lying polyfill, expose real Hermes weak primitives only where verified, and keep correctness-bearing reclamation native and sweep-backed. That is the right architecture for WebGPU.

I would not ratify this revision unchanged. The direction is sound, but several statements are factually or contractually too strong. Most importantly:

- `pushRuntimeFinalizer` does not currently preserve ownership on refusal as documented.
- OS-based profile classification is weaker than the repository’s artifact-provenance model.
- Standard `FinalizationRegistry` semantics cannot guarantee bounded resource use in an indefinitely live runtime.
- T1–T5 establish Ibex substrate behavior, but not the complete ENG-25093 ecosystem gate.
- The HandleRegistry residual and parts of the Hermes scheduling description are inaccurate.
- There is a likely CapSec lockdown hole around shared mutable `FinalizationRegistry`/`WeakRef` intrinsics.

My verdict is “strong design, substantive revision required.”

## Verified Claims

1. **Commit 07ba47068 removed the fake registry and added both named tests.** The old stub strongly retained targets and never invoked cleanup. The current compatibility source has no `FinalizationRegistry` reference; its former area proceeds directly into the Array polyfills ([compat-polyfills.js](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/bootstrap/compat-polyfills.js:632)). The tests remain at [the native reclamation test](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/mod.rs:2323) and [the honest-absence/explicit-revoke test](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/mod.rs:2432).

   Two caveats: the first test is currently vacuous on absence ([mod.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/mod.rs:2335)), and it exercises Hermes’s JS `FinalizationRegistry` driving `FsHandle.revoke`, not `pushRuntimeFinalizer`. It is also one 2,000-handle batch rather than sustained-load coverage.

2. **The native queue and teardown drains exist, but “every poll” needs qualification.** `pushRuntimeFinalizer` validates the pointer-plus-generation target and enqueues under the finalizer mutex ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3584)); ordinary polling drains it at [line 16902](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:16866). There are three teardown drain call sites: inside the pin-wait loop, after the final unpin, and after registry erasure ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3257)).

   It is not literally drained by every `ex_hermes_poll`: early lifecycle/error exits can occur before the drain. The accurate contract is “once during every ordinary poll that reaches the native-finalizer stage, plus the teardown drains.”

   Refusal means there is no matching registered pointer/nonce target, not specifically that a once-valid generation is stale; malformed targets also return false. Matching `Closing` and `Quarantined` generations are accepted ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:2785)).

   The sole current producer is WebSocket’s off-owner final context release, and it terminates on refusal ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3378)). Fetch uses the callback queue, not this API ([hermes_runtime_fetch.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime_fetch.cc:332)).

3. **Queued native JS callbacks are not invoked during teardown.** `discardRuntimeCallbacksOnOwnerThread` swaps out the callback queue, runs each optional `ownerDisposition`, and destroys the callback closures on the owner thread without invoking their JS bodies ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3245)). “Only ownerDispositions run” is slightly incomplete because closure-capture destructors and custom deleters also execute.

   This function only covers Ibex’s native callback queue. The pinned Hermes does not actually enqueue finalization cleanup as separate jobs: `drainMicrotasks` drains jobs, clears kept objects, then directly runs finalization cleanup ([hermes.cpp](/Users/ccheever/.cache/exact/hermes/hermes-src/API/hermes/hermes.cpp:2100)); cleanup scans all registries at the checkpoint ([Runtime.cpp](/Users/ccheever/.cache/exact/hermes/hermes-src/lib/VM/Runtime.cpp:2050)). Remaining registrations disappear with runtime destruction, but “queued cleanup jobs are discarded” describes the wrong mechanism.

4. **HandleRegistry has no per-runtime sweep.** Grants contain capability and parent information but no runtime or realm identity, and all grants occupy one map ([handles.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/host/handles.rs:16), [handles.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/host/handles.rs:27)). Its API provides create/check/revoke operations but no sweep ([handles.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/host/handles.rs:205)). The host shares one registry across clones/runtimes ([host/mod.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/host/mod.rs:182)).

5. **FsHandle registration is guarded.** `kFsHandleJS` constructs a registry only when `typeof FinalizationRegistry === "function"` and conditionally registers wrappers ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:6111), [hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:6121)). Explicit revoke unregisters before revoking the native handle ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:6162)). The source checks for a function-valued global; calling it “the native primitive” relies on trusted bootstrap ordering and the absence of the former stub.

6. **CapSec classifies it as an intrinsic receiver.** Both `FinalizationRegistry` and `WeakRef` are listed as intrinsic global receivers ([capsec-surface-inventory.mjs](/Users/ccheever/projects/ibex-finreg-20260806/packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:4281)); unshadowed/unassigned checks control that classification ([capsec-surface-inventory.mjs](/Users/ccheever/projects/ibex-finreg-20260806/packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:4344)). That inventory is static analysis, not proof that lockdown safely hardens the constructors.

## Findings

- **Definite blocker: refusal currently can transfer ownership.** The declaration promises “without transferring ownership on failure” ([hermes_runtime_internal.h](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime_internal.h:2590)), but the implementation takes `std::function<void()>` by value ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3584)). A caller passing `std::move(fn)` has already surrendered its captures before validation; false then destroys them on the producer thread. A future GPU closure holding an owning handle could release on the wrong thread or double-release against the sweep. T4’s “transfers nothing” cannot honestly pass until the API changes.

- **The JS contract contradicts itself.** The draft says callbacks may never run ([LLP 0050](/Users/ccheever/projects/ibex-finreg-20260806/llp/0050-js-and-native-finalization-semantics.spec.md:16)), but later says delay is “not indefinite” under continued progress ([LLP 0050](/Users/ccheever/projects/ibex-finreg-20260806/llp/0050-js-and-native-finalization-semantics.spec.md:77)) and that feature detection implies callbacks genuinely fire under sustained load ([LLP 0050](/Users/ccheever/projects/ibex-finreg-20260806/llp/0050-js-and-native-finalization-semantics.spec.md:139)). Standard semantics support the first statement, not the latter two as unconditional consumer promises.

  A profile-qualification test may require cleanup after test-forced GC plus checkpoints. That is useful implementation evidence, but should be explicitly non-normative for individual registrations. If WebGPU requires bounded resources during an indefinitely live runtime, realm-death sweep plus standard finalization is insufficient; an independent live-runtime budget, pressure mechanism, or sweep is necessary.

- **Hermes scheduling is over-described.** In this pinned Hermes, cleanup occurs during a microtask checkpoint by scanning registries, not “as jobs.” Checkpoints can occur after host tasks/evaluations as well as polls. Remove “coalesced,” “pending cleanup jobs,” and the poll-only implication. “Exposes untouched” would be clearer as “does not substitute a polyfill.”

- **Desktop classification is right in principle, wrong if implemented as `target_os` cfg.** A hard failure is appropriate for an exact reviewed artifact identity known to contain and execute the primitive. It is not appropriate merely because the build target is macOS/Linux/Windows. Ordinary builds may have no receipt ([build.rs](/Users/ccheever/projects/ibex-finreg-20260806/build.rs:340)), custom Hermes paths/refs are supported, and the repository already validates profile/source/patch identity ([build.rs](/Users/ccheever/projects/ibex-finreg-20260806/build.rs:396)). Portable exact-target mode also bypasses part of the legacy validation path ([build.rs](/Users/ccheever/projects/ibex-finreg-20260806/build.rs:1159)).

  Classify the authenticated artifact, not its OS. iOS is also missing from D1: current provenance selection names desktop and Android but not iOS ([build.rs](/Users/ccheever/projects/ibex-finreg-20260806/build.rs:1130)).

- **The producer split covers existing call sites, but its example and API shape need correction.** There is currently one `pushRuntimeFinalizer` caller, the pin-holding WebSocket final release; no existing call site fits neither class. Fetch should be removed from the example. For future callers, phrase the two proofs more generally:

  - refusal is impossible because a lifetime proof keeps admission valid;
  - refusal is safe because a named authoritative fallback owns reclamation.

  A sweep is one fallback. A boolean is too coarse because it conflates stale targets with invalid construction. Prefer `Accepted`, `Stale`, and `Invalid`, ideally encoded through separate typed APIs or a pin/fallback token.

- **“Lossless” is too strong without definition.** The drain invokes every accepted closure once, catches exceptions, logs, and continues ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:3206)). The actual guarantee is one owner-thread invocation attempt, assuming the host eventually polls or destroys the runtime. Exceptions are not retried. Native finalizers should be idempotent and forbidden from blocking, invoking user JS, or re-entering Hermes.

- **Sweep ordering must be explicit.** `finishRuntimeTeardown` performs all three finalizer drains and erases the generation before extension `close()` runs ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:10736)). A WebGPU account/realm sweep in extension close must therefore release directly on the owner thread; it cannot enqueue into the now-dead generation. If it needs the queue, its teardown hook must occur earlier.

- **The HandleRegistry residual is materially misstated.** IDs are masked to 53 bits for lossless JS-number representation, not 64 bits ([handles.rs](/Users/ccheever/projects/ibex-finreg-20260806/src/host/handles.rs:166)). Without revoke or sweep, growth across runtime churn has no fixed bound. Possession gating prevents guessing, but does not prove “not an authority leak”: an escaped bearer remains valid after its originating runtime dies. Either bring runtime-keyed sweeping into scope or describe this honestly as legacy reclamation and retained-authority debt with a tracked issue.

- **Likely CapSec hardening gap.** Compartments copy descriptor values and therefore share constructor identities ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:4014)), while lockdown’s hardening roots include `WeakMap`/`WeakSet` but omit `WeakRef` and `FinalizationRegistry` ([hermes_runtime.cc](/Users/ccheever/projects/ibex-finreg-20260806/src/engine/hermes_runtime.cc:6938)). That appears to leave their constructors/prototypes shared and mutable across compartments. This should be tested and likely fixed before treating them as trusted intrinsic receivers.

- **T1–T5 are necessary but insufficient for the literal ENG-25093 gate.** T2’s unreclaimed-handle count is a good, deterministic semantic oracle for fixed-weight synthetic handles. It is not proof that memory remains bounded: one handle could represent a four-byte object or a multi-gigabyte texture.

  Add native/mock allocator live-byte accounting and a downstream Exact/WebGPU test over the real wrapper → release → queue/sweep path. A post-forced-GC Hermes `allocatedBytes` plateau is a useful secondary assertion through the existing heap-info API ([exact_runtime.h](/Users/ccheever/projects/ibex-finreg-20260806/include/exact_runtime.h:2155)), but native GPU/account bytes are the primary metric. RSS and heap-capacity assertions would be too noisy.

## Suggested Changes

- Rewrite the public JS contract as standard weak semantics only. State separately that classified artifacts must pass a bounded, forced-GC qualification probe; do not turn that probe into per-registration liveness.

- Replace OS cfg classification with an artifact-bound capability receipt derived from the validated Hermes commit, patch stack, variant, and artifact digest. A particularly useful receipt could advertise `finalization-registry`, `weakref`, `cleanup-at-checkpoint`, and `cleanupSome-absent`.

- Change `pushRuntimeFinalizer` so refusal truly preserves producer ownership—either take a caller-owned lvalue and move only after validation, or return the refused closure. Use a result enum and test with an RAII-bearing capture.

- Replace “lossless” with: “Each accepted entry receives exactly one owner-thread invocation attempt if the owner continues ordinary polling or completes teardown; failure is logged and not retried.”

- Remove or correct:

  - the Fetch producer example;
  - “random 64-bit ids”;
  - “bounded memory growth” and categorical “not an authority leak”;
  - “as jobs,” “coalesced,” and “every poll”;
  - “no cross-realm registrations” unless Ibex actually enforces and tests it;
  - “held values do not retain targets.” Registries weakly hold targets, but held values are strong and can indirectly retain their target.

- Add `WeakRef` and `FinalizationRegistry` conditionally to lockdown hardening roots. Test constructor/prototype freezing and cross-package mutation, plus cleanup callback principal attribution in armed compartments.

- Expand T3/T4 with deterministic race cases: enqueue-before-destroy, final enqueue immediately before unpin, enqueue between zero-pin observation and registry erasure, throwing finalizer followed by a good one, reentrant enqueue, and stale refusal retaining an RAII closure.

- Add a T6 split gate:

  - Ibex synthetic native-wrapper/account ledger, with handle count, weighted live bytes, queue accepted/completed/backlog/high-water, mixed retained/dropped wrappers, and explicit-dispose-then-GC exactly-once checks.
  - Exact/WebGPU integration using actual wrappers and resource accounting, proving repeated workload waves complete without exhaustion and live native bytes plateau.

- Consider reporting GPU wrapper allocation sizes through JSI’s `setExternalMemoryPressure` ([jsi.h](/Users/ccheever/projects/ibex-finreg-20260806/ios/Frameworks/hermes-headers/jsi/jsi.h:1422)). This can make Hermes collect tiny JS wrappers that own large native resources sooner. It is only a pressure signal—Hermes considers the external bytes gone when the JS object dies, potentially before delayed native release—so native live-byte accounting and budgets remain authoritative.

- OQ1 should note that aggregate callback backlog already includes the finalizer queue. Add test-only accepted/executed/refused/high-water receipts first; promote them to stable ABI only if operational consumers need them.

## Open Questions

- What exact WebGPU object invokes `pushRuntimeFinalizer`: a native HostObject destructor during GC, a JS cleanup callback, or an external producer? A JS cleanup callback is already on the owner thread and may not need this queue.

- Does Exact require only standard weak semantics, or a stronger profile-scoped guarantee after a clearing GC and continued checkpoints? If only standard semantics, what independent mechanism bounds live-runtime GPU memory?

- Where exactly does the authoritative account/realm sweep run, and does its release path remain valid after runtime generation erasure?

- What is the complete artifact matrix for macOS, Linux, Windows, iOS device/simulator, Android Maven, portable exact-target, and custom/unreceipted builds?

- Should HandleRegistry acquire runtime ownership and sweeping now, given that the draft’s governing rule otherwise has an explicit counterexample?

- What byte metric and threshold constitutes the ENG-25093 pass condition: GPU service/account live bytes, mock allocator bytes, Hermes `allocatedBytes`, or a combination?

- Can locked-down package code mutate either weak intrinsic or affect callback authority attribution across compartments?

- Is a stale-tolerant queue actually needed for sweep-backed GPU wrappers, or would owner-thread direct release plus authoritative sweep be simpler and safer?

## Recommended Next Step

Keep LLP 0050 in Draft and revise it before implementation. The next revision should resolve four gates explicitly: the JS liveness contract, ownership-preserving native refusal API, artifact-identity capability classification, and the Ibex-plus-Exact sustained-load evidence split. After those changes, run a focused review against the exact WebGPU wrapper/sweep implementation plan.

Because this workspace is read-only, I could not persist the formal review artifact. This review should be recorded as `llp/reviews/0050-js-and-native-finalization-semantics.codex.md` when write access is available.