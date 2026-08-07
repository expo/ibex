# Reviews: LLP 0047 — Standalone Executable Finish Line (OpenAI Codex family)

## Round 1 — 2026-08-01 (cluster loop: LLP 0029 + 0039 + 0047)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc01a-2d68-7061-92a6-382ac991cd7d`
**Date:** 2026-08-01
**Redacted:** no (repository content only; no secrets present). The reviewer additionally issued one outbound web search for Apple TN2206 Mach-O code-signing documentation; that query carried no repository content.
**Revision reviewed:** LLP 0047 at git-blob `9890e6bb6587ec906ef09049ba84c03b77ceaec6` (repo HEAD `54761987`)
**Brief:** `brief-r1.md`, hash `2d2438a011e9e43161263d6b58c45222bfa84552`
**Verdict:** NOT READY

**Topology note.** This was a lockstep cluster review of LLP 0029 + LLP 0039 +
LLP 0047. Per the review-artifact rule, the cluster review is preserved
**verbatim once**, in the primary target's artifact:

> `llp/reviews/0029-single-file-executable-packaging.codex.md`, Round 5 —
> 2026-08-01.

What follows is this target's per-target verdict section, excerpted from that
single verbatim body for discoverability.

### Per-target section (excerpt from the verbatim cluster review)

- [MATERIAL] Safety: The security meaning of the executable is not included in its authenticated compatibility contract. `StubContractV1` binds engine identity, ABI/schema versions, target, profile, and artifact digests, but contains neither the default boot mode, selector semantics, nor CapSec-advertisement identity (`crates/sfe-format/src/lib.rs:136`; `schemas/stub-contract-v1.schema.json:6`). `PackageProvenanceV1` and `CatalogEntry` omit them as well (`crates/sfe-format/src/lib.rs:95`; `crates/sfe-catalog/src/lib.rs:27`). Consequently, non-evaluating inspection cannot authenticate whether a stub is ambient-default, CapSec-default, or which CapSec evidence it contains, even though LLP 0047 requires those results and calls a future default reversal a versioned contract change (`llp/0047-standalone-executable-finish-line.plan.md:242`, `:292`). Boot-mode semantics must be bound into a digest-authenticated contract or an equivalently authenticated catalog identity.

- [MINOR] Feasibility: The dual-mode initialization sequence needs an explicit implementation constraint. The current stub captures and sanitizes the environment in platform pre-initialization before Rust `main` (`crates/compiled-stub/src/environment_preinit.c:48`, `:116`), whereas arguments are captured later (`crates/compiled-stub/src/main.rs:99`). Unconditional pre-init sanitation violates ambient mode’s promised inherited-environment behavior, while deferring mode selection until ordinary argument parsing is too late to preserve CapSec’s earliest-hook guarantee (`llp/0029-single-file-executable-packaging.rfc.md:755`). This is buildable, but milestone 2 should require selector capture during pre-init, before choosing whether sanitation occurs.

- [MINOR] Feasibility: Milestone sequencing omits the required catalog rotation. Milestone 1 pins a catalog and builds the release producer, while milestone 2 changes the cataloged stub’s boot behavior (`llp/0047-standalone-executable-finish-line.plan.md:147`, `:157`). Because catalog entries bind the exact stub-core digest (`crates/sfe-catalog/src/lib.rs:110`) and release `ibex` embeds the catalog digest (`src/bin/ibex/sfe.rs:74`), changing the stub necessarily requires rebuilding the catalog, re-pinning the producer, and rerunning reproducibility checks. This is implementation-phase detail, but the plan’s dependency ordering should state it.

**LLP 0047 verdict: NOT READY**

Cross-document findings bearing on this target (the LLP 0031 release-gate
contradiction, and the set-level threat-model/eligibility-boundary objection)
are in the cluster review's cross-document section.

## Rounds 2–3 — 2026-08-01 (delta rounds)

Both were lockstep cluster delta rounds. The verbatim bodies live once in
`llp/reviews/0029-single-file-executable-packaging.codex.md` (Round 6 and Round 7), together with the loop close-out,
the full verdict history, the round-3 disposition ledger, and the revision
hashes the final verdicts bind to.

- **Round 2 verdict (Codex): NOT READY**
- **Round 3 verdict (Codex): NOT READY**

Both rounds found **no MATERIAL concern in pre-existing text** — the
delta-convergence criterion. Every MATERIAL concern after round 1 was
IN-DELTA, i.e. introduced by the loop's own revisions.

The loop terminated on round-budget exhaustion and escalated to the author. A
later **unreviewed** revision exists, addressing every round-3 finding; its
hash is recorded in the close-out.

## 2026-08-03 external-script correction cluster

The independent-gate amendment at git-blob
`7af5eccc60142b40ef785d9c2bf2ca25df022d5b` was reviewed in the LLP 0048
cluster. The complete Codex-family bodies and provenance are recorded once in
`0048-external-script-admission-and-broker.codex.md`, Rounds 1–4. The final
full-cluster and delta verdicts were **READY** with no remaining MATERIAL or
MINOR findings. This later review supersedes the “unreviewed revision” note
above for the 2026-08-03 amendment only; it confirms that general standalone
completion does not claim the external worker implemented or evidenced.
