# Reviews of LLP 0041 — How Exact and Snapback Consume Ibex (Codex/OpenAI family)

Review artifacts for `llp/0041-consuming-ibex.decision.md`, recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

Administrative renumbering note: this decision and its reviews were
originally authored as LLP 0040. They became LLP 0041 when a separately
authored LLP 0040 landed on `main`; recorded digests and quoted review text
retain that original identity as historical provenance.

---

## Round 1 — 2026-07-27

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.145.0, `codex exec`, sandbox
  `read-only`, approval `never`, model `gpt-5.6-sol`, provider `openai`,
  session id `019fa30d-ca5a-7e00-9b4b-3eb675a27537`.
  Orchestrator: Claude Code (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `high` (`-c 'model_reasoning_effort="high"'`).
- **Date:** 2026-07-27
- **Revision under review:** `e7a988c9d605`
  (`shasum -a 256 llp/0040-consuming-ibex.decision.md | cut -c1-12`)
- **Authorization:** The directing author (Charlie Cheever) invoked
  `/llp-super-refine` on this document in the orchestrating session; he is
  the human with repository-disclosure authority for this external send, and
  the repository is public (expo/ibex) — the outbound capsule is the public
  working tree read-only.
- **Redacted:** No. The reviewer ran read-only against the repository
  working tree.
- **Independence:** Fresh non-interactive Codex session with no access to
  the concurrent Fable review of the same revision and no prior LLP 0041
  review artifact (none existed — this is round 1). Instructed not to read
  `llp/reviews/` or scratchpad notes; that exclusion is instruction-based
  and therefore self-attested.
- **Method:** cli-runner, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0040/brief-round1.md`, sha256 prefix
  `31e142f3263a`) — same brief as the concurrent Fable round-1 review.

### Verbatim review

1. **Overall assessment** — The central decision is sound and well motivated: consumer-specific forks demonstrably obstruct fix flow and create incompatible engine lineages. However, the document is not ready because its normative branch exception contradicts its headline rule, and important claims about the current compat branch and remediation target are contradicted by repository history.

2. **Strengths**

- Grounds the policy in a concrete failure involving a real crash fix, ABI divergence, and a severely stale merge base.
- States a clear upstream-first principle and assigns obligations to both Ibex and its consumers.
- Correctly identifies shared lineage—not necessarily identical pins—as the property needed for transferable testing and fixes.
- Explicitly addresses toolchain synchronization, secure/insecure feature selection, and generated artifact discipline.
- Honestly acknowledges the one-time reconciliation cost and Ibex’s resulting review burden.
- Considers the status quo, vendored copies, registry releases, and later tagged releases without foreclosing future release machinery.

3. **Concerns**

C1. [MATERIAL] The bounded-integration-branch exception contradicts the decision. Pin discipline says consumers must “never” point at a side branch, and upstream-first says capability must land on `main` before a consumer depends on it. Section 3 then permits a branch to be a pin target for “one advance cycle,” an undefined interval that could last weeks and recreates the prohibited state. Resolve this by distinguishing ephemeral local/CI integration from committed or shipping consumer state: temporary testing may use an override, but any shared, merged, or released submodule pin must already be reachable from `main`. Alternatively, define a deliberately narrower exception and revise the headline rule accordingly.

C2. [MATERIAL] The “unreviewed surface” argument materially overstates what repository history supports. The six-commit archive tip contains the three ABI symbols in the public header, LLP 0002 documentation, coverage-model entries and tests, generated implementation manifests, surface inventory, and registry bundles. The relevant commits are dated July 12–18, not “months” before July 27. The branch still lacks `main` lineage and may not have received normal main-branch review, but “none of the discipline” is factually wrong. Resolve this by separating the initial introduction gap from the archive tip’s later retrofit, correcting the duration, and framing the real defect as absence from the producer-owned, continuously integrated lineage.

C3. [MATERIAL] The remediation names the wrong current object for its claimed six-commit audit. `eng-25006-snapback-compat` currently ends at `b129c8e0` and has four commits absent from `main`; `archive/eng-25006-snapback-compat` and its tag end at `bfbc6133` and contain six. Auditing the named live branch therefore misses two archive-only commits, including security-related continuation work. Resolve this by recording Snapback’s exact pinned SHA, enumerating the commits to reconcile, naming the archive/tag where necessary, and making deletion contingent on disposition of every commit reachable from that actual pin.

C4. [minor] The prohibition and cadence remain purely procedural despite recurrence being the motivating failure. No owner or ancestry check is named, and “every few weeks” and “one advance cycle” are not operational definitions. Resolve this with implementation follow-ups assigning consumer-side ownership and a CI check that rejects committed submodule SHAs not reachable from the approved Ibex lineage; define the cadence or make it explicitly advisory.

4. **Verdict**

VERDICT: NOT READY


---

## Round 2 — 2026-07-27 (delta round)

**Provenance**

- **Reviewer family:** OpenAI (Codex) — Codex CLI v0.145.0, codex exec, sandbox read-only, approval never, reasoning effort high, model `gpt-5.6-sol`, session id `019fa317-356f-7870-827a-3b8fda4e3f51`
- **Date:** 2026-07-27
- **Revision under review:** `0437345e205c`
- **Round type:** delta (round-2 brief enumerates the round-1 revision delta
  and requires IN-DELTA vs PRE-EXISTING classification of every concern)
- **Independence:** fresh session; no access to the orchestrator
  conversation, the concurrent other-family review, or llp/reviews/ (the
  latter instruction-based, self-attested).
- **Method:** round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0040/brief-round2.md`, sha256 prefix
  recorded in the orchestrator run journal) — same brief for both families.

### Verbatim review

1. **Overall assessment** — The revision is decision-ready. The locally checkable history, ancestry, dates, commit count, branch tips, named cherry-picks, and main-lineage claims are accurate. No material concern remains; the issues below are precision fixes.

2. **Concerns**

C1. [minor] [IN-DELTA] Remediation steps 1 and 4 ambiguously describe the six commits as “reachable from `bfbc6133`.” Literally, every ancestor is reachable, making step 4’s completion criterion unbounded. Define the fixed set explicitly—such as `accb686f..bfbc6133`, or enumerate the six SHAs—and use it consistently.

C2. [minor] [IN-DELTA] Rules 4 and 6 do not define “pin age.” Commit author date, committer date, and elapsed time since consumer adoption can differ, while rule 6 also says “thresholds” remain implementation-phase despite the decided 30-day bound. Specify the authoritative timestamp and clarify which operational thresholds remain deferred.

C3. [minor] [PRE-EXISTING] The final consequence overstates what sharing a lineage guarantees: unless both consumers pin the same SHA, a finding in one is not necessarily about the exact engine revision the other ships. Rephrase this as shared lineage making findings more transferable and fixes directly consumable; reserve identical-engine claims for synchronized pins.

3. **Verdict**

VERDICT: READY


---

## Round 3 — 2026-07-27 (delta round)

**Provenance**

- **Reviewer family:** OpenAI (Codex) — Codex CLI v0.145.0, codex exec, sandbox read-only, approval never, reasoning effort high, model `gpt-5.6-sol`, session id `019fa320-f4db-7e82-859a-54246825897f`
- **Date:** 2026-07-27
- **Revision under review:** `6a3a689fff74`
- **Round type:** delta (round-3 brief enumerates the round-2 revision delta
  and requires IN-DELTA vs PRE-EXISTING classification of every concern)
- **Independence:** fresh session; no access to the orchestrator
  conversation, the concurrent other-family review, or llp/reviews/ (the
  latter instruction-based, self-attested).
- **Method:** round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0040/brief-round3.md`) — same brief
  for both families.

### Verbatim review

1. **Overall assessment** — The hash matches `6a3a689fff74`. Repository checks support the revised commit range, ancestry, pins, local refs, and incidental tag retention. The decision is coherent and implementable; no material concerns remain.

2. **Concerns**

C1. [minor] [IN-DELTA] Rule 6 calls the consumer-side check and adoption record the channel through which Ibex learns live pins, but rule 7 requires only a static adoption record. Neither explicitly requires publishing the current SHA or signaling when the consumer moves off it. Resolve by requiring the check to update an Ibex-visible live-pin record and withdrawal signal, while still deferring the venue and alerting mechanics.

C2. [minor] [IN-DELTA] Step 0 says the Hermes tag is subject to artifact-cache GC and release re-cuts, but the repository’s workflow establishes cache semantics without defining tag deletion or GC. The conclusion that this is non-obligation-bearing retention remains valid. Resolve by saying simply that the tag carries no retention guarantee, or cite the policy that permits its deletion.

3. **Verdict**

VERDICT: READY


---

## Loop close-out — 2026-07-27

Converged: **dual-READY on revision `6a3a689fff74`** (round 3; Fable READY,
Codex READY, same hash). No later revisions exist — the document on disk at
close-out is the reviewed revision. Rounds run: 3 (round 1 full, rounds 2–3
delta). Open concerns at convergence, dispositioned under the altitude rule
(all [minor], all IN-DELTA; none identifies a defective decision; each is
recorded here rather than revised in, so the verdicts stay bound to the
reviewed hash):

- Fable r3 C1 (overdue predicate when `main` itself idles >30 days) —
  hypothetical at current velocity; tighten when the rule-6 check is
  implemented.
- Fable r3 C2 / Codex r3 C1 (rule-7 record should carry the live pin SHA so
  ibex's retention duty has a defined information source) —
  implementation-phase scoping of the rule-6 channel; fold into the check's
  design and, if the author wishes, a one-line addendum at acceptance.
- Fable r3 C3 (step 0's hold wording weaker than step 4's retirement
  condition; step 4 governs) — wording alignment for the executor.
- Fable r3 C4 (where a tightened cadence bound is recorded) — normative-text
  ownership already stated in rule 7; make explicit when first tightened.
- Codex r3 C2 (say "no retention guarantee" rather than asserting
  cache-GC mechanics) — wording.

Proposed next step: the author applies `Accepted` (this loop never does),
optionally folding the five wording-level dispositions above into the
acceptance revision — which would then be a later, unreviewed revision and
should be labeled as such.
