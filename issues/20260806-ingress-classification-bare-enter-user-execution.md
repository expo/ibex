# Classify every bare exactRuntimeEnterUserExecution ingress before changing it (LLP 0051 §B)

- **Filed:** 2026-08-06 by the LLP 0051 lane, per the codex r1 review
  (blocker 1: a blanket guard sweep can launder).
- **Owner:** capsec / engine embedding ingress.

`emit_module_event_impl` (`ex_hermes_emit_module_event` /
`ex_hermes_emit_module_view_event`) and the three worklet dispatch entries
(`ex_hermes_dispatch_worklet_calls`, `ex_hermes_dispatch_worklet_json_batch`,
`ex_hermes_dispatch_motion_rated_publish`) enter JS through bare
`exactRuntimeEnterUserExecution`. They must NOT simply take the LLP 0051
Design A drive guard: `scheduleOnAppRuntime` is a deferred-execution channel
whose `ExWorkletScheduledCall` record (include/exact_runtime.h) carries
identity/order/generation but no principal carrier (LLP 0016 W2), and
resetting a continuation-delivering channel to a clean boundary would ERASE
a constraint that should have been carried (laundering, not hygiene).

Work:
1. Classify each ingress: fresh-host-event | restored-carrier |
   nested-continuation | unattributable (LLP 0051 §B taxonomy).
2. Module events: split unsolicited events from completion/subscription
   delivery before classification.
3. Worklet scheduled records: design the authenticated, generation-bound
   principal carrier (LLP 0051 open question 3) so the channel can restore
   acquisition context per LLP 0040.
4. Decide classification mechanics (code-enforced enum vs generated
   inventory — LLP 0051 open question 2).
