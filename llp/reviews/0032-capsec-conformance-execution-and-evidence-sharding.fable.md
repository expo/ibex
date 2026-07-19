# Reviews of LLP 0032 — CapSec Conformance Execution and Evidence Sharding (Fable family)

Review artifacts for
`llp/0032-capsec-conformance-execution-and-evidence-sharding.spec.md`, recorded
per [LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-19

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type:
  general-purpose` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator.
- **Date:** 2026-07-19
- **Revision under review:** `9c0d6d002c43`
  (`shasum -a 256 llp/0032-capsec-conformance-execution-and-evidence-sharding.spec.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly in
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context,
  no access to the concurrent Codex review of the same revision, and no access
  to any prior LLP 0032 review artifact (none existed — this is round 1).
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round1.md`). Brief supplied the
  target, required reading (LLP 0021, 0013, 0001), a required code-verification
  list (`compartment-conformance.yml`, `run-capsec-conformance.mjs`,
  `capsec/conformance/`, existing timeout/evidence machinery), the LLP 0005
  standard questions, and a fixed output structure ending in an explicit
  verdict line.

### Verbatim review

1. **Overall assessment**

LLP 0032 (verified at revision `9c0d6d002c43`) addresses a real, well-evidenced problem: `run-capsec-conformance.mjs` runs ~20+ commands sequentially through `spawnSync` with no per-command timeout, inside CI jobs bounded only by 180/240-minute `timeout-minutes`, so a hang burns the whole job and all completed work. The authority model is careful and defers correctly to LLP 0021. However, the phase graph omits the fixture-evidence pilot — the only report-crediting evidence producer in the current runner — and the current runner executes that pilot *after* the post-suite engine attestation, a fact the document's attestation-bracketing story never confronts. Stage 2's resumption value is also undercut by the document's own identity rules on ephemeral GitHub-hosted runners, and one Stage 1 acceptance criterion is arithmetically in tension with the proposed deadline table. Substantive revision is needed before acceptance.

2. **Strengths**

- **Motivation** is honest and matches reality. I verified that `packages/ibex-devtools/src/scripts/capsec-command-evidence.mjs` (`runObservedCommand`, `spawnSync` with no `timeout` option) gives no command an independent deadline, and that `.github/workflows/compartment-conformance.yml` runs the suite as one long step per job (macOS 180 min, Windows 240 min). The claim that "more hardware... cannot make an unbounded command bounded" is a correct diagnosis.
- **Authority boundary** is the best section. Its four "splitting does not broaden evidence" bullets faithfully restate LLP 0021 WP10's hard-won rules (broad suites are prerequisite-only; adapter/diagnostic evidence is rejected at publication; incomplete ≠ unsupported), and "Where the two conflict, LLP 0021's... requirements prevail" makes the deference unambiguous.
- **Cross-runner prohibition** (Sharding §Authoritative sharding) is grounded in the real code: engine binding uses `fs.realpathSync` paths and host-local file identity (`capsec-engine-identity.mjs` usage in the runner; LLP 0013 §Artifact provenance's dev/inode re-hash discipline). Deferring cross-runner authority to a separate accepted LLP (Stage 4) is the right call.
- **Secure diagnostics** correctly builds on the existing secured command-log machinery (owned regular file, `O_EXCL|O_NOFOLLOW`, nlink==1, digest + bounded tail in `capsec-command-evidence.mjs`) rather than inventing a parallel path, and correctly requires that timeout not weaken those checks.
- **Security properties** and the staged rollout (Stage 1 first, sharding only after measurements — echoed in Implementation notes) show good restraint; "Target honesty" (property 7) matches LLP 0021's incomplete-vs-unsupported distinction.

3. **Concerns**

1. **(major — Phase graph)** The phase graph omits the exact-fixture-evidence pilot. In the current runner, `exact-fixture-evidence-pilot` (`run-capsec-conformance.mjs` lines 564–596, via `EXACT_FIXTURE_EVIDENCE_COMMAND`) is a substantial observed command that produces the only evidence LLP 0021 credits as fixture passes (the nine credited mechanisms per WP10's 2026-07-16 status). It is not preflight, adapter, public-fixture, product, or aggregation — it fits none of the nine named phases. Worse, it runs *after* `engine-attestation-after` (line 423) in the current runner, so the document's phase order (attestation-after → final-aggregate) has no legal slot for it, and the "identity continuity" property plus the per-shard "attest before and after its work" rule leave it unclear whether the current ordering is conformant or a defect the spec intends to fix. Resolve by adding a fixture-evidence phase (and the fixture-evidence-binding construction and post-fixture source-tree recheck at lines 598–612) to the graph and stating explicitly how attestation brackets it.
2. **(major — Resumption / Stage 2)** Two of the three motivating costs (work lost at late failure or outer timeout) can only be recovered in a *new CI job*, which on GitHub-hosted `macos-14`/`windows-2022` runners is always a new machine. The document's own rules make that resumption authoritative only via "a trusted persisted environment that can prove every required identity" (Stage 2), which is never defined — and the same host-local-identity argument used to prohibit cross-runner sharding (paths, file identity) applies equally to a replacement runner. As written, Stage 2 either delivers only same-job retry (worth much less than the Motivation implies) or quietly requires the portable-provenance work deferred to Stage 4. Resolve by either (a) defining concretely what a trusted persisted environment must prove and how that differs from cross-runner authority, or (b) scoping Stage 2's claims to same-job/same-runner retry and saying plainly that outer-timeout recovery waits for Stage 4.
3. **(major — Acceptance criteria, Stage 1 vs Deadline policy)** "each conformance command has a declared deadline shorter than the remaining outer job timeout" is ambiguous and, under the natural reading (evaluated at command start), likely unsatisfiable with the proposed table: the product classes alone (90 + 120 + 6×~60 min) plus attestations and fixture batches sum to far more than the 180-minute macOS job timeout, so a late command's declared deadline will routinely exceed the remaining budget even when the command would finish quickly. The Implementation notes gesture at retuning `timeout-minutes` but the criterion is normative now. Resolve by stating the intended semantics (e.g., static: max single deadline + cleanup + upload < job timeout; or dynamic clamping of the effective deadline to remaining budget, with clamping recorded), and either adjusting the table or the workflow timeouts to make the criterion satisfiable on day one.
4. **(minor — Motivation / Command envelope)** The document does not acknowledge the existing timeout machinery, `scripts/with-timeout.sh` (LLP 0017), or explain why it is insufficient — which it is: GNU `timeout` signals the direct child and does not reliably reap detached grandchildren, exactly the "terminating only the direct child is insufficient" failure the spec targets. One sentence situating the envelope against `with-timeout.sh` would strengthen the motivation and prevent an implementer from reaching for it.
5. **(minor — Motivation / Scope)** "invokes the suite as one long-running CI step" is slightly inaccurate: the macOS job runs a second evidence-producing step, `run-capsec-inherited-intrinsic-alias-conformance.mjs` (workflow lines 117–121), outside the main runner, and Hermes build/verify steps precede it. The spec should say whether the command-envelope MUST applies to that second conformance entry point (and to the two child processes the runner currently spawns *outside* `runObservedCommand`: recipe generation at line 299 and report generation at line 677, both `execFileSync` with `stdio: "inherit"` and no evidence record).
6. **(minor — Shard manifest)** "MUST reject unknown fields when they could affect authority" is not mechanically decidable — a validator cannot know whether an unknown field affects authority. Make it testable: reject all unknown fields, or partition the manifest into a strictly-closed authority section and an extensible informational section.
7. **(minor — Command envelope)** The "atomic live-status record" updated "periodically while it runs" is impossible from the current single-threaded `spawnSync` runner; the open question about JS-vs-native envelope implicitly covers this, but the spec should note that the requirement forces async spawning or a helper process, and say where the live-status record is expected to be observable mid-run (CI log lines vs. a file only visible after upload).

4. **Suggestions**

- Record in the spec (or its plan artifact) the current measured per-command durations from recent CI runs before choosing final deadline values; the table is currently labeled "planning values" but nothing requires the Stage 1 implementation to retain measurements in a place that feeds retuning, even though "tune them from retained measurements" depends on it.
- The Aggregate validation list should explicitly include "manifest schema version unknown or unsupported" as a rejection cause, matching the schema-version field it mandates.
- Stage 1's "cleanup failure prevents subsequent authoritative work" acceptance test deserves a named mechanism (e.g., a poisoned-runner marker the next phase checks), since nothing in the current runner has a place to record runner contamination.
- Consider stating whether `--expect-incomplete` mode's refusal artifacts (`capsec-ci-status.json`) are diagnostic or authoritative under the new taxonomy; they are uploaded evidence today and sit awkwardly between the two classes.

5. **Open questions**

- Actual per-command wall-clock durations on the current macOS and Windows runners — the repo retains no timing data, so I could not verify whether the 90/120-minute Rust-suite deadlines are conservative or already tight (especially Windows, whose job timeout is 240 minutes presumably for cause).
- Whether same-runner parallel public-fixture shards can avoid shared mutable state in practice: all batches currently share one cargo `target/` build directory and one evidence directory; the spec's isolation preconditions may be expensive to satisfy (per-shard target dirs mean rebuilds) and the document does not estimate that cost.
- Whether `capsec/conformance/` (currently only `target-attestations.json`) is the intended home of the versioned plan/timeout-policy documents the spec requires; the spec never says where the plan lives or how its digest is bound into CI.

6. **Recommended next step**

Revise. Concerns 1–3 each require author decisions (fixture-evidence phase placement and attestation bracketing; honest Stage 2 scoping or a defined persisted-environment contract; deadline-vs-job-timeout semantics), then one more review round. The document's authority model is sound and close to acceptable; the gaps are in fidelity to the runner it restructures and in the deliverability of its middle stages.

VERDICT: NOT READY

---

## Round 2 — 2026-07-19

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type:
  general-purpose` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator.
- **Date:** 2026-07-19
- **Revision under review:** `545696dd751d` (post round-1 revision)
- **Redacted:** No.
- **Independence:** Fresh subagent with no orchestrator conversation context,
  no access to the concurrent Codex round-2 review, and instructed not to read
  `llp/reviews/` (so no access to round-1 artifacts).
- **Method:** subagent, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round2.md`) — round-1 brief with
  the revision hash updated; same required reading, code-verification list,
  and output structure.

### Verbatim review

1. **Overall assessment**

LLP 0032 is a well-scoped, unusually honest execution spec. I verified its factual claims against the repository and nearly all hold exactly: the 180/240-minute job timeouts, the single dominant runner step, the synchronous no-deadline `spawnSync` envelope in `capsec-command-evidence.mjs`, the two bare `execFileSync` children (recipe generation, report construction) outside the observed-command path, the second macOS entry point, the fixture/sweep digest naming (`planDigest`, `sweepPlanDigest`), the tagged-digest canonical form (`computeDomainDigest` with `omitFields`), and the current runner attesting the engine *before* the fixture-evidence pilot. The authority deference to LLP 0021 is coherent, and the document repeatedly refuses tempting overclaims (diagnostic-only recovery pre-Stage-4, "serial is an acceptable Stage 3 outcome"). It falls short of acceptance on two substantive normative gaps: an internal ambiguity about when the corrected attestation order binds relative to Stage 1, and an incomplete accounting of externally supplied fixture evidence — a real substitution channel in the current runner that the document's own completeness claim says it must classify.

2. **Strengths**

- **Motivation** is accurate against `.github/workflows/compartment-conformance.yml` and `run-capsec-conformance.mjs`: one job per target, `timeout-minutes: 180`/`240`, no per-command deadline, recipe generation (runner lines 299–312) and report construction (lines 653–680) via bare `execFileSync`, and the macOS-only inherited-intrinsic step (workflow lines 117–121). The diagnosis that these are execution/provenance problems rather than hardware problems is correct.
- **Deadline policy** is honest where most drafts hedge: it states outright that its own planning values do not fit the current 180-minute macOS budget and makes the reconciliation an explicit Stage 1 plan decision that changes the plan digest. Launch-time admission control and "refused launch is infrastructure failure, never absent-target" close a real target-honesty hole.
- **Terminology** does careful disambiguation work: `suitePlanDigest` vs the existing fixture-level `planDigest` (`capsec-fixture-evidence.mjs`) and `sweepPlanDigest` (`capsec-output-shape-sweep.mjs`) — I confirmed both exist and collide in name only; the mandated distinct field names prevent a genuine future confusion. The canonical-form rule matches the actual `computeDomainDigest` implementation in `capsec-contract.mjs` (domain tag, NUL separator, self-digest exclusion).
- **Phase graph** corresponds phase-for-phase to what the runner actually does, and correctly identifies the real ordering flaw: the post-suite attestation (runner lines 423–428) runs before the fixture-evidence pilot (line 568), so the current attestation bracket excludes an engine-using evidence producer.
- **Scope of authoritative resumption** and **Sharding** avoid the classic overreach: same-runner-only authority, "same-user sibling processes are not a security boundary," adversarial isolation testing rather than collision-avoidance, and the explicit statement that the Motivation's lost-work cost is only fully recovered at Stage 4. This is consistent with LLP 0013's host-local identity evidence (device/inode re-hash; Windows path-based identity explicitly insufficient).
- **Authority boundary** and **Aggregate validation** align with LLP 0021 WP10's posture (broad suites are prerequisites, adapter evidence is diagnostic, fail closed on missing/duplicate/stale), and the correct identification of `with-timeout.sh` as unusable for this purpose and `capsec-command-evidence.mjs` as the natural seam shows the author actually read the code.

3. **Concerns**

1. **(major — Phase graph / CI rollout / Security properties)** The attestation-order correction has no stage binding, creating an internal contradiction. The phase graph states "The final attestation MUST follow every engine-using evidence phase," but Stage 1 says "Keep one authoritative runner and the existing semantic order" — and the existing order is precisely the one the MUST forbids. Meanwhile "Security properties" claims identity continuity for "an implementation conforming to this specification," which a Stage-1 implementation, on the document's own reasoning, does not establish. Resolve by stating explicitly which stage adopts the corrected order, reconciling it with the Stage 1 acceptance criterion "same semantic report as before" (does moving the attestation change the report's canonical content or not?), and scoping the identity-continuity property to the stage where the reorder lands.

2. **(major — Phase graph)** The claim "Every evidence producer that feeds the LLP 0021 report has a place in this graph or an explicit classification outside it" is false for supplied fixture evidence. `run-capsec-conformance.mjs` lines 564–584: when `--fixture-evidence` is supplied, the pilot command is *not executed* and the externally produced artifact — the producer of exactly the evidence LLP 0021 credits as fixture passes — substitutes for phase 8's execution, gated only by `validateExactFixtureEvidenceArtifact` binding checks. The document gives this treatment to output-disposition evidence ("the supplying run must itself satisfy this specification to be authoritative") but is silent on the analogous, higher-stakes fixture-evidence channel. Resolve by classifying the supplied-fixture-evidence path identically (binding checks as acceptance gate plus the supplying-run rule), and optionally noting that `--public-surface-evidence` is only a redundancy cross-check against locally executed evidence (lines 519–538), not a producer.

3. **(minor — Command envelope, runner-loss classification)** On hosted CI the live-status record is uploaded by the runner itself ("uploaded on termination"), so after true runner loss in Stages 1–2 there is no surviving status record and no external observer inside the job — the mandated synthesis "from an incomplete live-status record whose heartbeat stopped" may have nothing to read. Resolve by stating where the record must be observable from outside the runner (e.g. streamed CI log lines suffice as the source, or a separate observer/aggregator job), or by scoping runner-loss synthesis to configurations with an external observer and relying on fail-closed absence otherwise.

4. **(minor — Command envelope, factual)** "The existing `scripts/with-timeout.sh` ... signals only the direct child" is inaccurate for its primary path: GNU `timeout` by default runs the child in its own process group and signals the group. The accurate deficiencies are group-escaping descendants, macOS dependence on Homebrew `gtimeout` (exit 127 otherwise), no Windows Job Object semantics, and no evidence record. The conclusion stands; correct the stated reason.

5. **(minor — Deadline policy)** The command-class table omits classes for several commands the phase graph itself names: recipe generation, the adapter-evidence batch, the fixture-evidence pilot, aggregate/report construction, and the inherited-intrinsic alias entry point. Since every command MUST have a declared deadline, state whether these fall under an existing class or require authored per-command deadlines, so implementers aren't inventing policy.

6. **(minor — Deadline policy, admission control)** Launch-time admission control needs the remaining job budget, which GitHub-hosted runners do not expose directly; the job's start time and declared `timeout-minutes` must be bound into the invocation (and hence the plan digest). State this input explicitly so the requirement is implementable as written.

7. **(minor — Command envelope / Secure diagnostics)** The Windows job's "Retain Windows engine-profile preflight state" step writes `target/capsec-suite-evidence-engine-preflight/status.txt` from a workflow step — a workflow-authored file inside the `capsec-suite-evidence-*` upload namespace, outside any envelope. The spec should classify workflow-authored diagnostic files or require them to live outside the secured evidence namespace, since the aggregate's exact-membership rule will otherwise meet uncontrolled files in evidence paths.

4. **Suggestions**

- Note explicitly that `spawnSync`'s built-in `timeout` option is *not* an acceptable envelope implementation (it cannot do tree cleanup, live status, or classification records) — it is the tempting half-measure an implementer will reach for first.
- The number of public-fixture shard commands is data-dependent (one per distinct probe command derived from the recipe catalog), so the critical-path budget is derived per target and revision; say that the budget computation consumes the generated catalog and is committed via the suite-plan digest.
- Stage 1 acceptance requires synthetic hang-kill tests on macOS, Linux, and Windows, but the conformance workflow has no Linux job; state where the Linux envelope tests run (ordinary CI) so the criterion is testable as written.
- Clarify that artifacts uploaded via `if: always()` are diagnostic copies and never the substrate for Stage 2 resumption (which is in-job or persistent-runner state) — the current text implies it but implementers of Stage 2 will ask.

5. **Open questions**

- Whether GitHub reliably runs `if: always()` upload steps to completion after a job-level `timeout-minutes` cancellation (grace-period limits vs large evidence bundles) — not resolvable from repo evidence; it bears on the "uploaded within a bounded cleanup interval" criterion.
- No measured per-command durations exist in the repo, so I could not evaluate whether the 90/120-minute Rust suite classes are realistic against actual runtimes; the document's own retain-measurements requirement is the right mitigation.
- I did not audit `run-capsec-inherited-intrinsic-alias-conformance.mjs` for its own child-process structure; whether it spawns further children affects how much work "run it under the command envelope" implies.

6. **Recommended next step**

Revise. The document is close: concerns 1 and 2 each need only a short normative addition (stage binding for the attestation reorder; classification of the supplied fixture-evidence channel), and the minor items are one-line fixes. After that targeted revision I would accept without a further full review round.

VERDICT: NOT READY

---

## Round 3 — 2026-07-19

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type:
  general-purpose` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator.
- **Date:** 2026-07-19
- **Revision under review:** `3a44e0d11831` (post round-2 revision)
- **Redacted:** No.
- **Independence:** Fresh subagent with no orchestrator conversation context,
  no access to the concurrent Codex round-3 review, and instructed not to read
  `llp/reviews/` (so no access to earlier round artifacts).
- **Method:** subagent, round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round3.md`) — same brief as
  earlier rounds with the revision hash updated.

### Verbatim review

**1. Overall assessment**

This is a well-grounded, honest, and carefully bounded specification. Every load-bearing factual claim I checked against the repository is accurate: the workflow shape and timeouts (180/240 minutes in `.github/workflows/compartment-conformance.yml`), the monolithic synchronous runner (`spawnSync` in `capsec-command-evidence.mjs`, no per-command deadline), the two children outside the observed-command path (recipe generation at `run-capsec-conformance.mjs:299` and report construction at `:677`, both bare `execFileSync`), the second macOS entry point (alias conformance step), the inadequacies of `scripts/with-timeout.sh` (Homebrew `gtimeout` dependency, no Windows path, no evidence record), the distinct `planDigest`/`sweepPlanDigest` fields, the domain-separated digest machinery (`computeDomainDigest` in `capsec-contract.mjs`), and the current attestation ordering (post-suite attestation at `:423-428` precedes the fixture-evidence pilot at `:568-584`, exactly as the document says its phase graph corrects). The phase graph is a faithful decomposition of what the runner actually does, including the awkward corners (`--expect-incomplete` refusal artifacts, supplied-evidence inputs, the redundancy-only role of `--public-surface-evidence`, which the code confirms via canonical-equality comparison). The deference to LLP 0021 is coherent and repeatedly reasserted at the right points. My concerns are all minor.

**2. Strengths**

- **Motivation** is verified-accurate and resists the easy framing: it explicitly separates "more hardware" from execution/provenance problems, which matches the actual failure modes of the current runner.
- **Terminology / Canonical form** does the unglamorous work of disambiguating three digests (`suitePlanDigest` vs. the existing fixture `planDigest` vs. `sweepPlanDigest`) that would otherwise certainly be confused, and anchors digesting in the existing tagged-digest tooling rather than inventing a parallel scheme.
- **Command envelope** correctly identifies `capsec-command-evidence.mjs` as the implementation seam, correctly rules out `with-timeout.sh` with specific, verifiable reasons, and closes the "bare `execFileSync` children" hole by name rather than by generality. The enumerated-helper exception for `git` metadata queries is scoped tightly.
- **Runner-loss classification** is unusually honest: it acknowledges a dead runner cannot record its own death, permits external synthesis only as a distinct record class, and — critically — specifies that the normal hosted-CI case needs no synthesis because fail-closed on missing output already covers it.
- **Scope of authoritative resumption** openly concedes that the Motivation's headline cost ("completed work is lost") is only fully recovered at Stage 4, and explains what Stages 1–3 actually buy. This kind of self-limiting candor is rare and valuable.
- **Phase graph** classifies every evidence producer, including the ones easy to forget (output-disposition sweep, supplied `--fixture-evidence`, adapter evidence's diagnostic-at-publication status, which WP10 of LLP 0021 confirms verbatim).
- **Authoritative sharding** pre-authorizes the "serial is fine" outcome of Stage 3 as a success, not a failure — this removes the incentive to force concurrency past its provenance cost. The adversarial-isolation test requirement ("collision-avoidance tests alone do not establish isolation") is exactly right.
- **Acceptance criteria** are largely testable as written, and the closing rule ("no stage is complete if the outer CI timeout is still the first expected deadline for an individual command") is a crisp, checkable summary of the whole document's point. The Stage 1 note that the Linux termination case runs in ordinary CI (the conformance workflow has no Linux job) is accurate.

**3. Concerns**

1. **Minor — Deadline policy (initial table).** The per-class values cannot be reconciled with reality without doing essentially all of the work the section defers: summed even minimally they exceed both job budgets (acknowledged), and the public-fixture-shard class multiplies across an unknown number of per-command batches (the runner emits one observed command per unique recipe command). The document is honest about this and mandates Stage 1 reconciliation with a complete per-command mapping, but the table as printed is close to un-adoptable. Resolution: state explicitly that the table is a placeholder superseded by the Stage 1 measured mapping, or seed it from existing CI run history.
2. **Minor — Admission control wording (Deadline policy).** "The job's start time and declared outer timeout MUST therefore be bound into the invocation and committed via the plan" conflates two things: the outer timeout is plan-committable; the start time is per-run and can only be invocation-bound (and is self-reported by the workflow, so it is operational input, not evidence). Resolution: split the sentence and state that admission control is an operational guard whose inputs are not authoritative evidence.
3. **Minor — Contamination marker persistence (Process-tree termination / Stage 2).** The marker must be "persistent" and checked before every launch, and Stage 2's persistent-runner resumption depends on markers surviving between jobs, but the document never says where the marker lives or what scope it must survive (job workspace cleanup would erase a workspace-local marker on a persistent runner). Resolution: one requirement specifying marker storage scope for the in-job and persistent-runner cases.
4. **Minor — Stage 1 "same semantic report" mechanics (CI rollout).** The criterion is coherent — I verified `buildConformanceReport` derives semantics from fixture executions and bindings, not from command-record shape — but Stage 1 envelope records must go somewhere, and the existing `ibex/capsec-executions/1` artifact's `commands` array and `suiteArtifactDigest` will change shape if they land there. Resolution: state whether Stage 1 bumps the executions schema or emits envelope records as a parallel artifact.
5. **Minor — Timing of the "supplying run must itself satisfy this specification" obligation (Phase graph).** That normative sentence retrofits this spec onto the separately orchestrated output-shape-sweep producer (and any supplied `--fixture-evidence` producer), yet no stage's acceptance criteria include that retrofit — and LLP 0021 promotion requires the sweep evidence, so completing Stages 1–3 does not make the full promotion evidence chain spec-compliant. No target is promotable today, so nothing regresses, but the obligation is dangling. Resolution: assign the external-producer retrofit to a stage or explicitly defer it with rationale.
6. **Minor — Existing violation of the evidence-namespace rule (Secure diagnostics).** The Windows job's "Retain Windows engine-profile preflight state" step writes a workflow-authored `status.txt` into `target/capsec-suite-evidence-engine-preflight`, inside the `capsec-suite-evidence-*` namespace the rule protects. The rule as written correctly forbids this, but the document never names the existing instance as a Stage 1 change item, so an implementer could satisfy the letter of Stage 1 while leaving it in place. Resolution: cite the step in Motivation or Stage 1.
7. **Minor — Grace periods (Command envelope / Deadline policy).** The envelope must record "configured deadline and grace period," but the deadline policy never says who authors grace periods or gives initial values. Resolution: one sentence placing grace periods in the plan alongside deadlines.

**4. Suggestions**

- The Motivation's "every validated phase output and the final aggregate are lost" slightly overstates: the evidence directory is uploaded via `if: always()`, so outputs survive as artifacts — they are lost *as resumption substrate*, which the document itself clarifies later. Aligning the Motivation phrasing with that later precision would forestall a cheap objection.
- The "raise a job timeout" reconciliation option has a hard ceiling on hosted runners (360 minutes); noting it would make the Stage 1 reconciliation trade-space concrete.
- Inherited-intrinsic alias conformance appears in two separate bullets of the phase-graph classification list (envelope requirement and authority class); merging them would remove a small redundancy.
- Consider recording the current count of public-fixture batch commands per target in the plan when Stage 1 lands, since exact-membership validation and the critical-path budget both depend on it.

**5. Open questions**

- Whether "in-job retry" is operationally reachable on the current hosted-CI workflow, whose conformance run is a single step — the retry orchestration mechanism (runner-internal retry loop vs. additional workflow steps) is not determinable from repo evidence and the document does not commit to one.
- Whether GitHub's post-cancellation grace window is reliably long enough to honor the "uploaded within a bounded cleanup interval" expectation when the *outer* job timeout fires; this is a platform behavior that cannot be verified from the repository.
- Actual measured durations of the current commands (the repo contains no retained duration data), so I could not independently judge how far the initial deadline classes are from reality — only that their sum exceeds the budgets, as the document itself states.

**6. Recommended next step**

Ready to accept. The seven concerns above are all resolvable with targeted edits — none changes the design, the authority boundary, the phase graph, or the staged rollout. I would fold concerns 2, 5, 6, and 7 into a final revision pass and land it.

VERDICT: READY
