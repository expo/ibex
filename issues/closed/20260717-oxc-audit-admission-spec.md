# Draft the audit-admission Spec LLP

**Status:** Closed (2026-07-26 — LLP 0030 accepted)
**Impact:** 4
**Urgency:** 4
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Draft the audit-admission Spec LLP” shows the issue materially affects a supported product or engineering path; delay compounds an active rollout, reliability, or verification risk, while the implementation is localized and has concrete acceptance witnesses, with a direct reproduction or current implementation proof.
**Severity:** P2
**Systems:** Security, Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b, LLP 0026, LLP 0030

Snapshotless audit/diagnostic runtimes take the compat evaluator today
with no window check; the producer pipeline's admission is built on
armed-snapshot/deployment-graph/producer digests audit hosts
deliberately lack. Draft the normative audit-admission contract as its
own Spec LLP (scope decision: register item 5, assumed yes):
principal/`SourceId` derivation, hard fences, would-deny evidence
receipts, prepared-cache admission rules, denied/missing/cross-principal
fixtures — candidate design: ephemeral diagnostic snapshot that
structurally cannot mint executable authority; named fallback: audit
refuses source entries and accepts only prepared carriers. The
repointed loader conformance runner runs under audit, so this is a CI
dependency for window close. RFC deadline: drafted by end of step 1;
accepted before step 4.

**Done when:** Spec LLP drafted with the design + fallback and its own
review per LLP 0005 stakes; accepted before `oxc-window-close` starts.

## Progress — 2026-07-17

Draft LLP 0030 now owns the normative contract. It selects a sealed
`DiagnosticGraphSnapshotV1` with no authority rows and no conversion to
`ArmedSnapshot`; pins canonical principal/`SourceId` derivation, retained
source identity, local-only capture fences, missing-authority-only relaxation,
diagnostic execution receipts, disjoint prepared-cache rules, stable failure
classes, and the denied/missing/cross-principal real-Hermes matrix. Its safe
fallback is an explicit source-audit refusal, never compatibility evaluation.

The issue remains **In Progress** for LLP 0005 review and author acceptance;
those states cannot be fabricated or accepted on the author's behalf.

On 2026-07-18 the author explicitly requested the formal LLP 0005 review loop.
Review artifacts are recorded only when actually received; LLP 0030 remains
Draft pending that feedback and the author's eventual status decision.

Round 1 was actually received from the Claude/Fable family and is preserved in
`llp/reviews/0030-audit-graph-admission.fable.md` with `VERDICT: REVISE`. The
Draft addresses the material findings: it defines every unarmed decision input
and a host-protected cache/report baseline, separates foreground audit from the
historical armed schema arm, pins builtin and candidate behavior, retains
captured bytes, makes overflow explicit, requires production-grade target
advertisements, and selects inline-only v1 admission. The same reviewer then
spot-checked the revision, found C1–C8 resolved, and returned `VERDICT: READY`.
Its four wording notes are reconciled in LLP 0030 and LLP 0028. Author
acceptance remains; the review does not change LLP 0030's Draft status.

## Resolution — 2026-07-26

The author (Charlie, directing) instructed that this issue be completed;
the sole remaining step was acceptance, so LLP 0030's status moved
Draft → Accepted with a Revised entry recording the decision (per the
LLP 0027 precedent). The acceptance rests on the recorded READY verdict in
`llp/reviews/0030-audit-graph-admission.fable.md`; the four READY wording
notes were verified reconciled in LLP 0030 and LLP 0028's risk register. The
post-READY wording edits carry no recorded reviewer spot-check — the reviewer
pre-authorized proceeding without one, and the acceptance note says so
explicitly rather than claiming a re-review.

Timing: `issues/20260717-oxc-window-close.md` had not started (still blocked
on LLP 0031 acceptance, the audit-admission implementation, telemetry
archive, quarantine rows, and the script frontend), so the "accepted before
window close" ordering holds. Implementation continues under
`issues/20260717-oxc-audit-admission-impl.md`, which stays open.
