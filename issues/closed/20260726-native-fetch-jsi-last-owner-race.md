# Native fetch can destroy its final JSI callback owners on the network thread

**Status:** Closed
**Date:** 2026-07-26
**Priority:** High
**Related:** [ENG-23033](https://linear.app/expo/issue/ENG-23033/native-async-completions-can-destroy-jsi-handles-off-the-runtime),
[ENG-23459](https://linear.app/expo/issue/ENG-23459/ibex-native-services-dnsresolvenaptr-returns-androidiosworker-off),
[ENG-25006](https://linear.app/expo/issue/ENG-25006/vendored-ibex-hermes-runtimecc-erases-pending-fetch-entry-before)

## Problem

Snapback verification reproduced a macOS `SIGSEGV` in an Ibex native-fetch
completion. The faulting thread was `com.apple.NSURLSession-delegate`, and the
crash stack was destroying a
`std::shared_ptr<facebook::jsi::Function>`/`facebook::jsi::Function`.

`src/engine/hermes_runtime_fetch.cc` moves the request's `resolve` and `reject`
functions out of `fetchCallbacks`, but then copy-captures both local
`shared_ptr`s into the callback passed to `pushRuntimeCallback`:

```cpp
pushRuntimeCallback(
    target,
    [resolve, reject, /* ... */](facebook::jsi::Runtime& rt) {
      // ...
    });
```

This leaves one owner in the queued runtime callback and one in each local on
the NSURLSession/libcurl completion thread. The runtime thread can execute and
release its queued callback before the network completion returns. The
network-thread locals then become the final owners, so their destruction runs
the JSI `Function` destructor off the Hermes owner thread and can crash while
invalidating Hermes values.

Runtime teardown is not required. This is therefore a still-live sibling of
the off-thread JSI destruction class recorded in ENG-23033 and ENG-23459, even
though those issues are closed. It is distinct from ENG-25006's
pending-work-visibility window.

`ex_hermes_resolve_host_call` in `src/engine/hermes_runtime.cc` currently has
the same copy-capture shape and must be audited as part of this fix.

## Required fix

- Move-capture `resolve` and `reject` into the runtime callback so the network
  or producer thread retains no JSI-bearing owners after enqueue:

  ```cpp
  [resolve = std::move(resolve),
   reject = std::move(reject),
   /* ... */](facebook::jsi::Runtime& rt) {
    // ...
  }
  ```

- Apply the same ownership rule to `ex_hermes_resolve_host_call` if its audit
  confirms the equivalent race.
- Audit other cross-thread `pushRuntimeCallback` producers for JSI-bearing
  copy captures that can leave the final owner on the producer thread.

## Acceptance criteria

- A deterministic regression test makes the runtime callback finish before the
  native producer returns and proves no JSI callback owner is finally released
  on the producer thread.
- Native-fetch completion is stress-tested on macOS using the real
  NSURLSession path without a crash.
- The host-call sibling and all other JSI-bearing cross-thread callback
  producers are audited, with unsafe copies fixed or explicitly justified.
- Existing Ibex tests and LLP/ref checks pass.
- After the Ibex fix lands, Snapback advances its `vendor/ibex` submodule and
  reruns the verification that originally exposed the crash.

## Resolution (2026-07-26)

Fixed on `fix/insecure-startup-performance-completion`.

**Fixes (move-capture so the queued runtime callback is the sole JSI owner):**

- `src/engine/hermes_runtime_fetch.cc` — native fetch completion (the
  reported crash site).
- `src/engine/hermes_runtime.cc` `ex_hermes_resolve_host_call` — the known
  sibling, same shape.
- `src/engine/hermes_runtime.cc` `ex_hermes_resolve_exact_host_call` — found
  by the audit, same shape.
- `src/engine/hermes_runtime_android.cc` `android_animation_frame_callback` —
  found by the audit: `callback = entry.callback` copied from an lvalue while
  `entry` outlives the enqueue on the Choreographer thread.

**Audit of all 21 `pushRuntimeCallback`/`pushRuntimeFinalizer` producers:**

- WebSocket callbacks (6 sites) copy-captured `ws_instance` but were safe via
  the per-invocation context retain in the platform backends; hardened to
  move-capture anyway so they are locally sound.
- GPU decoded-image completion (`hermes_runtime_gpu_v2.cc`) legitimately needs
  `binding` after enqueue for its rejection fallback; safe because every
  strong-release path detaches `pending` (the only JSI-bearing state) on the
  runtime thread first — justified in a comment at the site.
- FS worker pool: the defensive `acquireForWorker` skip would destroy a
  JSI-capturing job on the worker thread if it were ever reachable; constraint
  documented at the site (unreachable today — cancelQueued erases atomically).
- All other sites move-capture already or carry no JSI state (HTTP, DNS, FS,
  GPU mailbox, crypto signal watcher, watchdog heartbeat, finalizer).

**Proof/instrumentation (observer builds only):**

- Fetch/host-call promise closures are allocated via
  `exactMakeTrackedJsiCallbackOwner`, whose deleter records whether the FINAL
  release ran on the runtime owner thread
  (`ibex_test_jsi_owner_final_releases_{on,off}_owner_thread`).
- `IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` parks a foreign-thread producer inside
  `pushRuntimeCallback` after publish+notify, forcing the runtime thread to
  run AND release the queued callback before the producer returns.
- `fetch_completion_releases_jsi_owners_on_runtime_thread_only` and
  `host_call_completion_releases_jsi_owners_on_runtime_thread_only`
  (src/engine/mod.rs) assert both final releases land on the runtime thread
  while the producer is provably still parked. Verified to FAIL deterministically
  against the pre-fix copy-capture and pass post-fix.
- `native_fetch_nsurlsession_stress_releases_owners_on_runtime_thread` runs 48
  concurrent fetches through the real macOS NSURLSession path: no crash, all
  96 final releases on the owner thread.

**Docs:** ownership rule added to LLP 0003 §The event loop; fixed sites carry
`@ref LLP 0003#the-event-loop`. `env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS`
registered in `capsec/registry/runtime-environment-inventory.json`.

**Known limitation:** `capsec/generated/surface-inventory.md` could not be
regenerated because the capsec regen chain is broken by pre-existing
unreviewed drift — see
[20260726-capsec-regen-chain-broken](../20260726-capsec-regen-chain-broken.md).

**Test-suite state:** the `--lib` engine suite is fully green (653/653,
including the three new tests) and ref-check passes. The `--bin ibex`
observer suite has 45 pre-existing armed/capsec-batch failures on this
branch, verified identical with this fix stashed (details in the regen-chain
ticket); the observer suite was unrunnable at all before the sanctioned
`build-hermes.sh --no-debugger` receipt restamp this fix required.
*(Correction 2026-07-27: those armed-batch failures were an
insecure-default-build artifact, not drift — the suite is green on an
explicit secure build. See
[20260727-armed-observer-suite-needs-secure-build](../20260727-armed-observer-suite-needs-secure-build.md).)*

**Follow-up (external):** after this lands, Snapback advances `vendor/ibex`
and reruns the verification that exposed the crash.
