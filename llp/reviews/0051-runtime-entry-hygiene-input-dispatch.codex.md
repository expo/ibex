# Review: LLP 0051 — Host Activation Principals and Carrier Hop Consistency

**Reviewer family:** OpenAI (codex)
**Provider / runtime:** Codex CLI v0.146.1 · model `gpt-5.6-sol` · reasoning effort ultra · sandbox read-only
**Session id:** 019fd83c-b023-7943-9d85-ea3559e543d4
**Date:** 2026-08-06
**Method:** `codex exec -s read-only` against the working tree at commit
593067def (draft numbered 0050 at run start; renumbered to 0051 in the same
tree before the run). Prompt supplied the standard LLP review questions plus
six load-bearing claims to verify with line citations. Orchestrator
spot-verified the decisive catches (ref-check failure, LLP 0016 W2 worklet
channel, `ExWorkletScheduledCall` carrying no principal carrier) before
accepting them into the revision. The draft author is Claude (Fable), so this
is the cross-family round.

---

## Overall Assessment

The narrow fix—adding `ExactRuntimeDriveGuard` to `ex_hermes_dispatch_event`—is a good idea and should be kept. It closes a real omission in runtime/session entry hygiene.

The RFC is not ready for acceptance as written. It conflates three different security concepts:

- runtime admission: which live runtime/session is being driven;
- principal propagation: whose authority constrains the work;
- user activation: why the host delivered the event.

That conflation makes the proposed sibling-ingress sweep and REENTRANT fallback potentially widening. My recommendation is: retain the dispatch guard, revise the model, classify every sibling ingress before changing it, and strengthen the regressions.

## Verified Claims (with line citations)

1. **Verified, with one wording correction.** In parent commit `27dd0b6a1`, `src/engine/hermes_runtime_ios.cc:931–940` went directly from `exactRuntimeEnterUserExecution` to `ScopedRuntimeExtensionHostTask`, with no drive guard or `ScopedRuntimeSecurityContext`. The working tree now adds the guard at [hermes_runtime_ios.cc:931](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_ios.cc:931). However, the old path did receive a later owner-thread check from `ScopedRuntimeExtensionHostTask` at [hermes_runtime.cc:7374](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:7374). Therefore “no drive-guard generation/session/principal-boundary validation” is accurate; “no owner validation” is too broad.

2. **Mostly verified.** A successful outer `ExactRuntimeDriveGuard` validates registry membership, lifecycle, nonce, owner and exclusivity at [hermes_runtime.cc:2883](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2883), selects the Host context at [hermes_runtime.cc:2927](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2927), clears the typed stack and native callback principal at [hermes_runtime.cc:2948](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2948), selects the attribution runtime, and synchronizes Hermes at [hermes_runtime.cc:2955](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2955). A null typed stack clears the Hermes embedder-host carrier at [hermes_runtime_fs.cc:150](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_fs.cc:150). Qualify “full reset” as **full embedder-owned entry-boundary reset**: Hermes also has distinct current-job and embedder-job carriers, intentionally separate from the host slot ([patch 0013:143](/Users/ccheever/projects/ibex-carrier-fix-20260806/patches/hermes/0013-native-job-constrained-principals.patch:143), [LLP 0040:403](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0040-native-runtime-extension-sdk.rfc.md:403)).

3. **The teardown hazard is verified; the claimed causal chain is not.** `~ScopedRuntimeSecurityContext` restores `g_vm_runtime` before restoring the typed stack at [hermes_runtime_internal.h:1489](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_internal.h:1489), and the drive-guard destructor has the same order at [hermes_runtime.cc:2993](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2993). Typed restoration synchronizes immediately, but synchronization no-ops when `g_vm_runtime == nullptr` at [hermes_runtime_fs.cc:150](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_fs.cc:150). `~ScopedActiveAttributionRuntime` does not itself restore a typed stack; it restores the runtime and synchronizes the currently installed stack at [hermes_runtime_internal.h:1719](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_internal.h:1719). The mechanism can leave an outgoing VM slot stale, but no current call trace or regression proves that it produced the observed no-user seed.

4. **Verified mechanically.** Timers capture `exactCollectTypedPrincipalStack()` at [hermes_runtime_timers.cc:97](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_timers.cc:97); `nextTick` captures it at [hermes_runtime_process_setup.cc:63](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_process_setup.cc:63). Delivery restores it immediately around the callback at [hermes_runtime.cc:7264](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:7264) and [hermes_runtime.cc:17126](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:17126). The collector unions live VM, typed and native scheduler principals at [hermes_runtime_fs.cc:371](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_fs.cc:371). This proves those queues do not intentionally shed what they capture; it does not prove the ingress supplied the correct initial carrier.

5. **Verified mechanically, but “input-shaped” is not verified.** `emit_module_event_impl` is bare at [hermes_runtime_ios.cc:829](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_ios.cc:829), as are the three worklet dispatches at [hermes_runtime_worklet.cc:1091](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_worklet.cc:1091), [hermes_runtime_worklet.cc:1168](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_worklet.cc:1168), and [hermes_runtime_worklet.cc:1204](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_worklet.cc:1204). But `scheduleOnAppRuntime` is explicitly an asynchronous escape at [hermes_runtime_worklet.cc:293](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_worklet.cc:293), and its record carries identity/order/generation but no principal carrier at [exact_runtime.h:2263](/Users/ccheever/projects/ibex-carrier-fix-20260806/include/exact_runtime.h:2263).

6. **Qualified yes.** The diagnostic genuinely asserts granted/granted/granted at [hermes.rs:16972](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/bin/ibex/engine/hermes.rs:16972), under an enforce fixture granting root filesystem access at [hermes.rs:7141](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/bin/ibex/engine/hermes.rs:7141). It is a useful positive integration witness. It does not seed a stale/constraining VM carrier, does not prove no-shed behavior, and its “direct” case is already inside a Promise reaction while “nested” is initiated from a native asynchronous completion ([hermes.rs:16914](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/bin/ibex/engine/hermes.rs:16914)). It also does not assert zero denial audits.

## Findings (numbered, each with severity: blocker/major/minor and a line-cited basis)

1. **blocker — The blanket sibling-ingress sweep can erase legitimate constraints.** The RFC groups module events and all worklet deliveries as fresh input activations ([LLP 0051:116](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:116)). At least one worklet path is explicitly deferred execution, and LLP 0016 already identifies it as a missing carrier channel ([LLP 0016:420](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0016-capability-security-architecture-assessment.research.md:420)). Native completions are required to restore their complete acquisition context ([LLP 0040:314](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0040-native-runtime-extension-sdk.rfc.md:314)). Resetting such a path to clean root would be laundering, not hygiene.

2. **major — A drive guard is not an activation declaration.** The RFC says the guard “is the activation declaration” ([LLP 0051:104](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:104)), but the implementation only validates/selects the runtime and resets embedder-owned dynamic state. Authority still comes from executing frames and explicit carriers. Calling it activation makes future reviewers likely to treat clean-root entry as proof of trusted human provenance.

3. **major — “Root cause confirmed” overstates the evidence.** History confirms the missing guard and the test demonstrates missing Host-session establishment, but it does not connect the real-click failure to a specific persisted Hermes slot. The RFC also says this was the “only public embedder ingress” and had “no owner validation” ([LLP 0051:34](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:34)); its own sibling inventory and the existing host-task owner check contradict those absolutes.

4. **major — The REENTRANT fallback is not sound as a generic rule.** `drive_active` proves only that the runtime is executing, not that a newly arriving event is an authorized continuation of the current work. The RFC proposes inheritance at [LLP 0051:127](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:127), while the guard intentionally returns `EXACT_RUNTIME_DRIVE_REENTRANT` at [hermes_runtime.cc:2906](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime.cc:2906), and the current dispatch implementation refuses it. A fresh external event should be queued for a new outer drive.

5. **blocker — The stated acceptance evidence is incomplete.** Section B and Acceptance Evidence require both the positive A/B and a no-shed witness ([LLP 0051:150](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:150), [LLP 0051:176](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0051-host-activation-principals-and-carrier-hop-consistency.rfc.md:176)). Only the positive diagnostic is present. Because all its callbacks are root-defined, a mutation that removed timer carrier restoration could still produce three grants.

6. **blocker — The current patch fails deterministic LLP validation.** `./ref-check` reports the annotation at [hermes_runtime_ios.cc:939](/Users/ccheever/projects/ibex-carrier-fix-20260806/src/engine/hermes_runtime_ios.cc:939) as malformed because it lacks the required ` — gloss` delimiter. The RFC also says the siblings are swept, while the working tree changes only `dispatch_event`.

## Security-Model Judgments

- **Drive guard versus activation principal:** Keep the guard, but name it runtime-drive/session hygiene. Do not mint a package-style “activation principal.” If Ibex later gates clipboard, fullscreen, payment, or similar APIs on human activation, represent that as a separate, unforgeable, runtime-generation-bound token with source class, event identity, expiry and consumption state. Package authority should still be intersected independently.

- **Laundering risk:** Clearing residual state is correct at a genuinely fresh host event because residue is never legitimate authority. It becomes widening if the caller is delivering a continuation, completion, subscription callback, or package-originated work item whose constraint should have been carried. The present ABI only says “renderer event” and does not encode that provenance ([exact_runtime.h:1864](/Users/ccheever/projects/ibex-carrier-fix-20260806/include/exact_runtime.h:1864)).

- **REENTRANT:** Retain refusal/requeue for externally arriving events. Permit inheritance only through an explicit “nested continuation” entry mode carrying proof that it belongs to the active drive and must preserve the existing carrier.

- **Residual-slot hardening:** Design C can remain a follow-up for the narrow `dispatch_event` fix, because successful entry clears the embedder-host slot. It is nevertheless required before claiming the vulnerability class closed. Apply it to both guard and security-context teardown, and test the VM slot directly. “Assert clear” alone is diagnostic, not production hardening.

- **Semantics verdict:** Direction 2 is well supported: timers, nextTick and Hermes jobs are designed to preserve constraints. Direction 1 should be described as a missing drive/session boundary plus a suspected carrier-hygiene defect—not a missing declaration of privileged user authority. `ScopedNativePrincipal` and `ScopedTypedPrincipalStack` restore captured constraints; they do not declare a fresh trusted host activation ([LLP 0013:1104](/Users/ccheever/projects/ibex-carrier-fix-20260806/llp/0013-per-package-capability-compartments.rfc.md:1104)).

- **Web analogy:** Narrow it substantially. HTML user activation is selected trusted-input provenance with transient/consumable state; DOM `isTrusted` identifies user-agent-dispatched events. Neither is a package principal or blanket ambient capability ([HTML user activation](https://html.spec.whatwg.org/multipage/interaction.html#tracking-user-activation), [DOM `isTrusted`](https://dom.spec.whatwg.org/#dom-event-istrusted)).

## Suggested Changes

1. Split the model into three explicit rails: `RuntimeDriveLease`, `PrincipalCarrier`, and optional future `HostActivationToken`.

2. Rename Design A to “runtime entry hygiene.” Remove “the guard is the activation declaration” and “highest-integrity activation source.”

3. Introduce an ingress classification enforced in code or generated inventory:

   - `fresh-host-event`
   - `restored-carrier`
   - `nested-continuation`
   - `unattributable/no-user`

   Every `exactRuntimeEnterUserExecution` entry should declare one mode.

4. Keep the current guard and REENTRANT refusal for `dispatch_event`. Document that the API may only deliver a fresh renderer event; package-derived continuations must use a carrier-bearing API.

5. Do not sweep worklet/module events until classified. Extend worklet scheduled records with an authenticated, generation-bound principal carrier. Distinguish unsolicited module events from operation completions/subscription delivery; the latter should restore the acquisition token required by LLP 0040.

6. Rewrite “Root cause (confirmed)” into:

   - confirmed missing drive/Host context;
   - confirmed teardown-order hazard;
   - residual-slot causation consistent with, but not yet proven to cause, the live symptom.

7. Add four regressions:

   - current positive flow, with accurate labels, handler/poll assertions, and zero denial-audit assertion;
   - a deliberately seeded VM embedder-host slot that must be cleared by fresh dispatch;
   - a true no-shed mutation witness: schedule a root-defined callback while the carrier is `[root, ungranted]`, and require denial after both `setTimeout` and `nextTick`, with a root-only granting control;
   - stale/off-owner/restricted/REENTRANT admission tests.

8. Implement Design C as a centralized two-runtime restoration helper: clear/synchronize the outgoing VM while it is selected, switch `g_vm_runtime`, restore the incoming typed stack, then synchronize the incoming VM.

## Recommended Next Step

Keep the narrow `dispatch_event` guard, but do not accept the RFC or expand the sibling sweep yet. First revise the model and ingress taxonomy, add the residual-seed and no-shed tests, fix the malformed `@ref`, and run `ref-check`, focused armed conformance, the full Ibex suite, and the downstream real-click A/B. Then promote the RFC to Review and run the formal multi-model loop.

This review was read-only, so I did not write a formal artifact under `llp/reviews/`.