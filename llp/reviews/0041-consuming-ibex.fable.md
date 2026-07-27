# Reviews of LLP 0041 — How Exact and Snapback Consume Ibex (Claude/Fable family)

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

- **Reviewer family:** Claude (Fable)
- **Provider / runtime:** Fresh Claude agent session (`claude-fable-5`)
  spawned by the orchestrating Claude Code session running
  `/llp-super-refine`; the orchestrator (who authored and will revise the
  document) did not perform this review.
- **Date:** 2026-07-27
- **Revision under review:** `e7a988c9d605`
  (`shasum -a 256 llp/0041-consuming-ibex.decision.md | cut -c1-12`)
- **Authorization:** The directing author (Charlie Cheever) invoked
  `/llp-super-refine` on this document in the orchestrating session. The
  repository is public (expo/ibex); the Codex-family review runs against the
  same working tree.
- **Redacted:** No. The reviewer ran read-only against the repository
  working tree.
- **Independence:** Fresh agent session with no access to the orchestrator's
  conversation, the concurrent Codex review, or any prior LLP 0041 review
  artifact (none existed — this is round 1). Instructed not to read
  `llp/reviews/` or scratchpad notes. Structural exclusion of this session's
  context is real (fresh agent); exclusion of the on-disk review artifacts is
  instruction-based and therefore self-attested.
- **Method:** agent-runner, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0040/brief-round1.md`, sha256 prefix
  `31e142f3263a`) — same brief as the concurrent Codex round-1 review.

### Verbatim review

**1. Overall assessment**

LLP 0041 addresses a real, well-evidenced problem and reaches the right decision. The core policy — pin `main`-lineage commits, upstream-first, prohibit long-lived compat branches, bounded integration branches, cadenced advances, breakage-flows-back — is sound, and nearly every checkable claim verifies against the repository: the fix commit `e523475f` is on `origin/main`; `archive/eng-25006-snapback-compat` carries exactly six commits whose merge-base (`accb686f`, 2026-07-11) is 891 commits behind current `origin/main`; the three named `ex_hermes_*` symbols exist on that branch and nowhere on `main`; the toolchain pin (1.97.0), `default = ["standard", "insecure"]`, the secure invocation, the watchdog-heartbeat ABI, the `tls-client-identity-openssl` PEM/PKCS#8 decoders, LLP 0013 Mechanism 1 evaluator taming, Exact's pin `1407af0e` (on `main`), and the owed Snapback rerun in `issues/closed/20260726-native-fetch-jsi-last-owner-race.md` all check out. However, the Context section — which the document itself designates as the argument ("the Context section is the argument") — contains two factual claims the repository contradicts, including an internal contradiction about who found the motivating SIGSEGV. And the decision's rules are stated purely as human obligations with no decided visibility mechanism, in a repo whose norms are deterministic fail-closed checks, for a policy whose diagnosed failure mode is precisely silent, invisible drift.

**2. Strengths**

- The problem is real and the diagnosis is precise, concrete, and (mostly) repository-verifiable: branch, commit count, symbol names, fix commit, and the structural "finder can't receive the fix" inversion are all accurate.
- The three-cost analysis (fix flow, unreviewed surface, consumer divergence) correctly generalizes LLP 0039's two-track rot argument across repositories, and the cross-reference is apt — LLP 0039 documents exactly this decay dynamic intra-repo.
- The decision is crisp and complete as policy text: five concrete rules, each with an operational test (e.g., "a branch someone is afraid to delete is a fork"; "never a pin target for longer than one advance cycle").
- "What consumers must absorb, knowingly" is an unusually honest section — it prices in the insecure-default inversion, toolchain pin movement, and artifact receipt discipline rather than pretending tracking `main` is free. All three bullets verify against `Cargo.toml`, `rust-toolchain.toml`, and the build scripts.
- Alternatives are honestly weighed; the crate-release option is correctly deferred rather than rejected, with the observation that tagged pins layer on top of this decision without changing it.
- The remediation section is specific and correctly sequenced (audit → upstream → advance pin → delete branch), and its expectations about what `main` has already subsumed (structural lockdown, watchdog ABI, TLS decoders) are all substantiated on `main`.

**3. Concerns**

**C1 [MATERIAL] — The SIGSEGV provenance contradicts itself and the repository record.** The Context paragraph says "Snapback's own verification had discovered a macOS SIGSEGV," which matches the repository record (`issues/closed/20260726-native-fetch-jsi-last-owner-race.md`: "Snapback verification reproduced a macOS SIGSEGV"). But cost 3 says "the SIGSEGV came out of the Exact-side Partitime matrix." These cannot both be right as written, and "Partitime" appears nowhere in this repository except LLP 0041 itself. The contradiction is load-bearing: the document's strongest rhetorical move ("the consumer that found the crash is the one consumer structurally unable to receive the fix") depends on Snapback having found it, while cost 3 cites the same crash as an Exact-side finding that "doesn't transfer." If there is a real dual-provenance story (e.g., a shared matrix running both consumers' verification), state it so the two claims reconcile; otherwise correct the cost-3 parenthetical to an example the repository supports.

**C2 [MATERIAL] — "Three ABI symbols existed for months" is contradicted by git history.** `ex_hermes_watch_time_limit`/`ex_hermes_unwatch_time_limit` were introduced in `24610d9e` (2026-07-12) and `ex_hermes_create_no_eval` in `c791baa2` (2026-07-18) — 9 to 15 days before the document's date, not months. The document explicitly leans on Context as the argument for rejecting the status quo, so its quantitative claims must survive checking. The fix is one word ("weeks"), and the honest number arguably strengthens the argument: 890 commits of divergence accrued in ~16 days makes the superlinear-drift point better than an inflated age does.

**C3 [MATERIAL] — The decision commits to no detection mechanism for its own diagnosed failure mode.** All five rules are human-discipline obligations ("promptly," "routinely, at least every few weeks," "same day") with nothing that makes a violation visible. The Context section's own analysis is that compat-branch cost accrues *silently* — the fork rotted for 890 commits with nobody noticing, and "it's faster to patch our copy" is a discipline failure by definition. This repository's norms are deterministic fail-closed checks (`check:drift`, `ref-check`, receipt restamps); a cross-repo policy — where visibility is worst — that relies solely on memory is incomplete at the decision level, and predictably reproduces the failure it remediates. This is not a demand for implementation detail: one decided sentence resolves it, e.g., "consumer CI verifies that the `vendor/ibex` SHA is reachable from ibex `main` and alarms when pin age exceeds the cadence bound," leaving the mechanism's venue and thresholds to implementation.

**C4 [minor] — Remediation step 4 does not match the observable repository state, and pin reachability is unaddressed.** `git ls-remote` shows no `eng-25006-snapback-compat` (nor any `archive/` or snapback-related ref) on `origin` (`expo/ibex`); the branch survives only as the local `archive/eng-25006-snapback-compat`. Either step 4 is already executed or the branch never lived on this origin — either way, the document presents as future work something the repo shows in a different state, and it silently implies a dependency it never states: Snapback's pinned commit (`bfbc6133`) is currently advertised by no origin ref, so fresh-clone submodule fetches depend on GitHub object retention, and the step-1 audit depends on the archive ref surviving. Resolve by updating the remediation to the actual state (branch archived locally as `archive/…`, retained until the audit completes) and stating explicitly that no advertised ref to the pinned commit may be dropped before step 3 completes — or that it already has been, and what that means.

**C5 [minor] — "Exist nowhere else" is imprecise, and existing salvage work goes unmentioned.** The three symbols also exist on other unmerged local branches (`eng-25006-pending-fetch`, `integrate/worktree-salvage-20260724`), and the ENG-24340 eval-time-limit commit has two later cherry-picked copies (`57b4fb5e`, 2026-07-15; `d93d3620`, committer date 2026-07-24 on the salvage branch) — evidence that partial upstreaming work already exists. Tighten the wording to "exist on no reviewed `main`-lineage commit," and have remediation step 2 point at the existing cherry-picks so the audit doesn't redo work.

**C6 [minor] — Cross-repo bindingness is undecided.** The decision imposes obligations on Exact and Snapback (pin cadence, same-change toolchain moves, issue-filing duties), but says nothing about where consumers record adoption so that their own agents and CI encounter the policy. The document already demonstrates the convention exists (it cites Exact's LLP 0180 and a snapback issue file). One sentence naming the consumer-side record (a mirroring decision or pointer doc in each consumer repo) would close it.

**C7 [minor] — "At least every few weeks" is a vague bound in an anti-drift policy.** Rule 4's routine-advance cadence is the parameter the C3 mechanism would check; as written it cannot be checked or even unambiguously violated. Pick a number (even a generous one) or explicitly delegate the number to the mechanism that enforces it.

**4. Verdict**

The decision itself is right, and most of the document is verifiably accurate. But the Context section — self-designated as the argument — contains an internal contradiction on the motivating incident's provenance (C1) and a repository-contradicted quantitative claim (C2), and the policy decides no visibility mechanism for a failure mode the document itself characterizes as silent (C3). All three are cheaply resolvable in revision.

VERDICT: NOT READY


---

## Round 2 — 2026-07-27 (delta round)

**Provenance**

- **Reviewer family:** Claude (Fable) — fresh agent session (claude-fable-5), agent-runner
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

**1. Overall assessment**

The round-1 revision substantially improved the document's factual grounding, and nearly all of its precise claims check out against the repositories: `bfbc6133` is the tip of local `archive/eng-25006-snapback-compat`, the live branch ends exactly two commits earlier at `b129c8e0`, the six commits and their 2026-07-12..18 dates are exact, the three `ex_hermes_*` symbols appear on no `main`-lineage commit (a `-S` sweep of `origin/main` finds only LLP 0041's own text), the merge-base-to-main distance is 884 commits (fairly rounded as "~890"), `e523475f` is on `main` and rewrites the same engine files the compat commits touch, the cherry-picks `57b4fb5e`/`d93d3620` exist where described, Snapback `main` pins `bfbc6133`, the unpushed `chore/advance-vendor-ibex-jsi-owner-fix` branch carries both the submodule bump (to `eaf7ff67`, on ibex `origin/main`) and the `rust-toolchain.toml` move, `default = ["standard", "insecure"]` and the 1.97.0 toolchain pin are current, and the narrowed decision rules (1, 3, 4, 6, 7) are coherent and decision-grade. However, the new remediation step 0 — added in this delta precisely to be exact about ref state — rests on a verifiably false premise: `bfbc6133` **is** advertised on `origin`, by `refs/tags/hermes-ac8c6e6c80ec-bcd8ab683229` (a Hermes artifact-cache release tag created 2026-07-19, before this revision). The step's prescribed action remains sound, but in a revision whose stated purpose was honest, exact ref accounting, a checkable "no ref on `origin`" claim that is wrong must be corrected before acceptance.

**2. Concerns**

**C1 [MATERIAL] [IN-DELTA] — Step 0's factual premise is false; `bfbc6133` is advertised on `origin` today.** Step 0 states the pin is "advertised by **no ref on `origin`**" and that "fresh-clone submodule fetches currently depend on GitHub object retention." Verified state: `git ls-remote origin` shows `refs/tags/hermes-ac8c6e6c80ec-bcd8ab683229` pointing directly at commit `bfbc6133af739ed2dabc2f44efa693d1412452e5`; the corresponding GitHub release ("Hermes artifact cache ac8c6e6c80ec-bcd8ab683229") was created 2026-07-19T03:21Z, so this predates the revision — the claim was wrong at writing, not overtaken by events. The same inaccuracy appears in the Context bullet ("surviving locally as `archive/…`"). The *decision* in step 0 is still correct and arguably stronger when stated truthfully: retention is currently incidental — a release tag that exists to host artifact assets, subject to artifact-cache GC or release re-cuts, and signaling nothing about retention intent — which is exactly why a deliberate archive ref with an explicit hold-until-step-3 obligation is warranted. Resolve by correcting both passages to acknowledge the artifact-release tag and reframe step 0 as replacing incidental retention with deliberate, obligation-bearing retention.

**C2 [minor] [PRE-EXISTING] — Step 5's Exact pin SHA is stale.** "Exact's pin (at `1407af0e` as of this writing)" is wrong: Exact `main` advanced its `vendor/ibex` pin on 2026-07-20 (`b2715888f` "Refresh Guide content and pin compatible Ibex") to `ef5b86a8` locally, with `002ba828` on Exact `origin/main` — both `main`-lineage ibex commits descending from `1407af0e`. The decision content (Exact advances at its next window, no reconciliation needed) is unaffected; fix the SHA or drop it.

**C3 [minor] [PRE-EXISTING] — The Related pointer cites an artifact that exists only on an unpushed local branch.** `snapback issues/20260727-vendor-ibex-advance-blocked-on-compat-abi.md` is not on Snapback `main`; it exists only on the local, unpushed `chore/advance-vendor-ibex-jsi-owner-fix` branch. Readers and agents in either repo cannot currently resolve the "motivating failure" citation. Resolve by pushing/landing that issue file (natural under rule 7's consumer adoption record) or noting its provisional location.

**C4 [minor] [IN-DELTA] — Rule 6's ibex-side obligation has no discovery mechanism.** Ibex must "keep every commit a consumer currently pins reachable from an advertised ref until the consumer has moved off it," but nothing decided here tells ibex what consumers currently pin — rule 7 records policy adoption, not the live pin. The document legitimately defers venue/thresholds to implementation phase, so this is not a defective decision; a one-clause note that the consumer-side CI check (or adoption record) is also the channel by which ibex learns of pins would close the loop.

**C5 [minor] [IN-DELTA] — The 30-day cadence bound is asserted, not calibrated against the document's own evidence.** The Context section shows ~890 commits of drift accumulating in roughly two weeks, including a capsec-registry redesign and a fetch-path rework; rule 4's routine backstop nonetheless permits 30 days. Rule 4(a)'s prompt fix-driven advances plausibly make this safe, but the document never says why 30 days is an acceptable ceiling given the demonstrated drift rate. One sentence of justification (or an explicit note that the bound is a starting value the rule-6 check can tighten) would resolve it.

**3. Verdict**

VERDICT: NOT READY


---

## Round 3 — 2026-07-27 (delta round)

**Provenance**

- **Reviewer family:** Claude (Fable) — fresh agent session (claude-fable-5), agent-runner
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

**1. Overall assessment**

The round-2 delta is accurate and verifiable, and I verified essentially all of it against the repositories directly. The revision hash matches (`6a3a689fff74`). The corrected retention claim is exactly right: enumerating all 23 origin heads and all origin tags, the *only* origin ref from which `bfbc6133` is reachable is `hermes-ac8c6e6c80ec-bcd8ab683229`, a genuine GitHub release ("Hermes artifact cache …") hosting tar.gz build assets — precisely the "incidental retention" the document now describes, and step 0's reframing (replace incidental with obligation-bearing retention) is the right decision-level response. The six-commit set `accb686f..bfbc6133` is exactly six commits, dated 2026-07-12..18, matching the listed contents, with `accb686f` on `main` and the branch commits on no `main`-lineage ref; the live branch tip is `b129c8e0`, two commits short, as stated. The `~890` figure is 891. The SIGSEGV fix `e523475f` is on `main`; the cherry-picks `57b4fb5e` (not on `main`) and `d93d3620` (on the local salvage branch) exist as described. Snapback's `origin/main` pins `bfbc6133`; its `chore/advance-vendor-ibex-jsi-owner-fix` branch exists, is unpushed, carries the submodule bump to `eaf7ff67` (on ibex `main`), the toolchain move, and the provisional issue file. Exact's `origin/main` pins `002ba828`, which is reachable from ibex `main`. `rust-toolchain.toml` is 1.97.0. The pin-age definition, the backstop justification, the rule-6 decided/deferred split, and the scoped lineage-transfer consequence are all sound decision-quality improvements. Remaining concerns are edge-case wording issues that identify no defective decision.

**2. Concerns**

C1. [minor] [IN-DELTA] Rule 4's overdue predicate has an unsatisfiable edge case. Pin age is measured from the pinned commit's committer date, so if ibex `main` itself went more than 30 days without a commit, even a pin at the tip of `main` would be "overdue" with no compliant action available. At ibex's current velocity this is hypothetical, and the document already frames the bound as a tunable starting value, so the decision is not defective — but one clause would close it (e.g., "overdue only if a newer `main`-lineage commit exists," or measure age as lag behind the `main` tip).

C2. [minor] [IN-DELTA] Rule 6's ibex-side retention obligation ("ibex keeps every commit a consumer currently pins reachable … until the consumer has moved off it") is decided, but its information source is only half-decided: the consumer-side check plus the rule-7 adoption record is named as the channel through which ibex learns live pins, yet nothing decided obligates that channel to actually carry the current pin SHA to ibex (the adoption record as described in rule 7 is a policy-adoption document, not a live pin register, and the CI check runs in the consumer's CI). A consumer that adopts the policy but whose check instrumentation lags could still lose a pinned commit to ref GC without ibex ever having known. One sentence scoping the obligation (e.g., ibex's retention duty attaches to pins declared in the rule-7 record, and the record must state the current pin) or explicitly deferring the discovery guarantee alongside venue/alerting would resolve it.

C3. [minor] [IN-DELTA] Step 0's hold condition ("drop no ref advertising the commit until step 3 completes") is weaker than step 4's retirement condition (step 3 landed *and* every commit has a recorded disposition). Step 4 governs deletion and is stricter, so the remediation is not defective, but a reader executing step 0 in isolation could believe the archive ref is droppable the moment the pin advance lands, before the disposition audit finishes. Aligning step 0's wording with step 4 ("until step 4's conditions are met") resolves the ambiguity.

C4. [minor] [IN-DELTA] Rule 4 says "the bound is a starting value the rule-6 check can tighten," but a CI check cannot itself tighten a normative bound — someone revises either this document or a consumer-local configuration, and the document does not say which artifact owns the effective value. Since rule 7 makes this document "the normative text," a tightened bound living only in a consumer's check config would silently diverge from the norm. A clause stating where the effective bound is recorded when tightened (this document, or the consumer's adoption record) resolves it.

**3. Verdict**

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

---

## Author acceptance — 2026-07-27

The author accepted LLP 0041 (`Status: Accepted`) after this loop converged.
The five wording-level minors dispositioned above were folded into the
acceptance revision; those edits are **post-READY and unreviewed** — the
round-3 dual-family READY verdicts bind to revision `6a3a689fff74`, not to
the accepted text. No decision changed: each edit answers a concern recorded
in the ledger above (rule-4 overdue predicate and bound ownership; rule-6
retention duty scoped to the pin declared in the rule-7 record; step 0's
retention-guarantee wording and its alignment with step 4's stricter
retirement condition).
