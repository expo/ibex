# Reviews: LLP 0039 — Secure and Insecure Modes (OpenAI Codex family)

## Round 1 — 2026-08-01 (cluster loop: LLP 0029 + 0039 + 0047)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc01a-2d68-7061-92a6-382ac991cd7d`
**Date:** 2026-08-01
**Redacted:** no (repository content only; no secrets present). The reviewer additionally issued one outbound web search for Apple TN2206 Mach-O code-signing documentation; that query carried no repository content.
**Revision reviewed:** LLP 0039 at git-blob `b8a6e07c79ad6931a52d10734895a40b9ad0e53f` (repo HEAD `54761987`)
**Brief:** `brief-r1.md`, hash `2d2438a011e9e43161263d6b58c45222bfa84552`
**Verdict:** NOT READY

**Topology note.** This was a lockstep cluster review of LLP 0029 + LLP 0039 +
LLP 0047, because LLP 0047 is a scoped amendment to LLP 0029's release
sequencing and LLP 0039's product defaults, and cross-document coherence was
the primary review axis. Per the review-artifact rule, the cluster review is
preserved **verbatim once**, in the primary target's artifact:

> `llp/reviews/0029-single-file-executable-packaging.codex.md`, Round 5 —
> 2026-08-01.

That file carries the full provenance block, the other targets' sections, and
the cross-document findings. What follows is this target's per-target verdict
section, excerpted from that single verbatim body for discoverability.

### Per-target section (excerpt from the verbatim cluster review)

- [MATERIAL] Coherence: The standalone exception does not reconcile the decision’s own release trip-wires. LLP 0039 says third-party code, generated/outside-team code, agent-driven execution, or a user-facing artifact invalidate the no-sandbox choice (`llp/0039-secure-and-insecure-modes.decision.md:104`). LLP 0047’s ambient path has exactly that no-enforcement posture and is intended for distributable, agent-facing executables; renaming it “ambient” and keeping it outside the Cargo `insecure` feature does not alter those threat conditions. Only one trip-wire is textually narrowed by the exception (`llp/0039-secure-and-insecure-modes.decision.md:120`). The decision must either explicitly supersede and justify the remaining trip-wires for this product surface or impose a scope that actually excludes them.

- [MATERIAL] Safety: The stated disclosure condition does not cover the ordinary recipient’s launch path. LLP 0039 conditions the exception on help, inspection, and release metadata making the posture explicit (`llp/0039-secure-and-insecure-modes.decision.md:115`), but LLP 0047 deliberately provides no runtime banner (`llp/0047-standalone-executable-finish-line.plan.md:237`). A copied standalone executable can therefore start in ambient mode without any colocated or launch-time indication that CapSec is inactive; the separate Ibex inspector is not necessarily available to its recipient. That leaves an unguarded ambient-default path on the precise user-facing surface the earlier decision treated as disqualifying.

- [MINOR] Correctness: The observer-test explanation reverses its `cfg` condition. `#[cfg(not(feature = "insecure"))]` means those tests are included in a default secure build and excluded when `insecure` is enabled, not that a default build “simply does not contain them” (`llp/0039-secure-and-insecure-modes.decision.md:145`).

- [MINOR] Correctness: The cited scale of approximately 22,000 unresolved Apple target edges (`llp/0039-secure-and-insecure-modes.decision.md:24`) is stale relative to the current generated inventory and later tracking documents. The months-scale rationale may remain valid, but the quantitative claim should be refreshed or described as historical.

**LLP 0039 verdict: NOT READY**

Cross-document findings bearing on this target (the LLP 0031 release-gate
contradiction, and the set-level threat-model/eligibility-boundary objection)
are in the cluster review's cross-document section.

## Rounds 2–3 — 2026-08-01 (delta rounds)

Both were lockstep cluster delta rounds. The verbatim bodies live once in
`llp/reviews/0029-single-file-executable-packaging.codex.md` (Round 6 and Round 7), together with the loop close-out,
the full verdict history, the round-3 disposition ledger, and the revision
hashes the final verdicts bind to.

- **Round 2 verdict (Codex): READY**
- **Round 3 verdict (Codex): READY**

Both rounds found **no MATERIAL concern in pre-existing text** — the
delta-convergence criterion. Every MATERIAL concern after round 1 was
IN-DELTA, i.e. introduced by the loop's own revisions.

The loop terminated on round-budget exhaustion and escalated to the author. A
later **unreviewed** revision exists, addressing every round-3 finding; its
hash is recorded in the close-out.
