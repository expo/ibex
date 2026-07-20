# Reviews of LLP 0032 — CapSec Conformance Execution and Evidence Sharding (Codex/OpenAI family)

Review artifacts for
`llp/0032-capsec-conformance-execution-and-evidence-sharding.spec.md`, recorded
per [LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-19

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.6, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f7c22-6e78-77d0-a215-a8046de13a79`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `high` (`-c 'model_reasoning_effort="high"'`; confirmed
  in the CLI banner).
- **Date:** 2026-07-19
- **Revision under review:** `9c0d6d002c43`
  (`shasum -a 256 llp/0032-capsec-conformance-execution-and-evidence-sharding.spec.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable review of the same revision and no prior LLP 0032 review
  artifact (none existed — this is round 1). Instructed not to read
  `llp/reviews/`.
- **Method:** cli-runner, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round1.md`) — same brief as the
  concurrent Fable round-1 review.

### Verbatim review

1. **Overall assessment**

The problem is real and worth solving: the current runner uses synchronous child execution without command deadlines, while CI relies on 180- and 240-minute outer timeouts. LLP 0032 has a sound fail-closed direction, but its phase graph and evidence model do not yet cover all authority-bearing work required by LLP 0021. Substantive revision is needed before acceptance.

2. **Strengths**

- **Authority boundary:** Correctly preserves LLP 0021’s distinction between fixture evidence, product prerequisites, diagnostics, and promotion authority.
- **Process-tree termination:** Treating incomplete cleanup as runner contamination is an appropriate security posture.
- **Diagnostic versus authoritative shards:** The explicit authority label, separate storage, and mandatory aggregate rejection prevent diagnostic evidence laundering.
- **Aggregate validation:** Exact membership, digest matching, deterministic aggregation, and rejection of incomplete attempts align well with LLP 0021’s fail-closed report model.
- **Engine identity:** Prohibiting cross-runner authoritative sharding matches LLP 0013 and the current host-local path/device/inode identity machinery.
- **Staged rollout:** Beginning with bounded sequential execution before attempting concurrency is appropriately conservative.

3. **Concerns**

1. **Blocking — Phase graph and authority completeness.** Applies to **Motivation**, **Phase graph**, and **Authority boundary**. The graph does not match the current runner or LLP 0021’s complete promotion input set. `run-capsec-conformance.mjs` performs the exact fixture-evidence pilot after `engine-attestation-after`, so the attestation is not actually after all engine-using evidence. It also invokes recipe generation and report generation outside `runObservedCommand`. Separately, LLP 0021 requires output-disposition evidence, produced by the existing output-shape sweep machinery, but LLP 0032 gives it no phase or assembly rule. The macOS workflow also runs inherited-intrinsic alias conformance after the main suite, with no stated authority classification here. Resolve this by inventorying every command and evidence producer, explicitly classifying each as authoritative, diagnostic, or external prerequisite, including output-disposition evidence in the plan, and placing the final engine attestation after every authority-bearing engine execution. Every invoked generator and evidence command must pass through the envelope.

2. **Major — Resumption cannot deliver the stated outer-timeout benefit on current CI.** Applies to **Motivation**, **Resumption**, and **CI rollout / Stage 2**. GitHub-hosted job retries receive new runners. Because the spec simultaneously prohibits cross-runner authority under the current engine identity model, work cannot be resumed authoritatively after the outer timeout, cancellation, or runner loss that Motivation identifies. “A trusted persisted environment that can prove every required identity” is not concrete enough and risks bypassing the stated prohibition. Resolve this by limiting Stage 2 to retries while the original runner remains alive, or defining a durable same-runner execution environment with enforceable continuity. State explicitly that job-loss recovery remains diagnostic-only until portable provenance exists.

3. **Major — Deadline classes do not fit the current whole-job budgets.** Applies to **Deadline policy**, **Acceptance criteria**, and **Implementation notes**. The macOS and Windows jobs have 180- and 240-minute outer limits that also include setup, dependency installation, Hermes acquisition, cleanup, uploads, and—in macOS—the later alias-conformance step. The proposed 90-minute default Rust deadline plus 120-minute all-features deadline already exceeds the entire macOS budget before the other product commands run. Requiring each command merely to be shorter than the remaining timeout does not reserve time for successors or upload. Resolve this with a per-target critical-path budget covering the complete workflow, explicit setup/cleanup/upload reserves, launch-time admission control, and either smaller deadlines, larger job limits, or job decomposition.

4. **Major — Runner-loss recording is impossible solely inside the command envelope.** Applies to **Command envelope**, **Secure diagnostics**, and **Stage 3 acceptance criteria**. A process on a lost runner cannot update its terminal status or record that the runner was lost. The current MUST conflates child termination observed locally with infrastructure failure inferred externally. Resolve this by defining an orchestrator/aggregator lease protocol: heartbeat freshness, the observer authorized to classify runner loss, clock and expiry rules, how an incomplete live record becomes a runner-loss record, and why that synthesized record cannot be mistaken for command-produced evidence.

5. **Major — Canonical manifest and digest contracts are underspecified.** Applies to **Terminology / Plan digest**, **Shard manifest**, **Resumption**, and **Open questions**. “Canonical” does not define serialization, hash domain, self-digest projection, exact allowed fields, or schema evolution. The repository already has fixture-level `planDigest` values and a versioned, domain-separated `sweepPlanDigest` with delegated-batch validation; introducing another generic “plan digest” without distinguishing it invites incorrect reuse. Deferring versioned manifests as an open question conflicts with Stage 2 and Stage 3 normative requirements. Resolve this by specifying versioned suite-plan, phase, shard, attempt, and live-status schemas; exact-field validation; JCS/digest domains and omitted self-fields; and explicit relationships to existing fixture and output-sweep plan digests.

6. **Major — Same-runner concurrency isolation is aspirational rather than enforceable.** Applies to **Authoritative sharding** and **Stage 3 acceptance criteria**. Separate paths and mode-private directories do not isolate sibling processes running as the same user. Current Cargo commands, caches, temporary directories, checkout state, and engine paths are shared unless explicitly redirected. “Cannot collide” tests would not prove that one shard cannot modify another shard’s evidence or engine artifact. Resolve this by either prohibiting authoritative concurrency initially or defining concrete isolation: shard-specific Cargo targets, caches and temporary roots; immutable/pinned engine access; separate users, containers, or equivalent process boundaries where needed; and adversarial mutation tests rather than collision-only tests.

7. **Minor — Motivation overstates loss and attempt selection is ambiguous.** Applies to **Motivation** and **Resumption**. Earlier secured command logs are currently retained under `target/capsec-suite-evidence-*` and uploaded with `if: always()` when the runner survives; what is lost is reusable validated phase evidence and the final aggregate, not all completed work. Also, requiring exactly one selected success while saying “multiple unselected successes” fail does not clearly define whether extra successful retries are permitted. Resolve this by tightening the motivation and specifying an immutable deterministic attempt-selection/supersession rule.

4. **Suggestions**

- Extend `capsec-command-evidence.mjs` as the natural command-envelope seam and state whether `scripts/with-timeout.sh` is reused or retired; it is POSIX-only and does not provide Windows Job Objects, tree-cleanup proof, or evidence records.
- Add acceptance tests for torn status writes, stale heartbeats, graceful-cleanup escalation, descendants escaping a process group, cancellation during artifact creation, and source or engine replacement between phases.
- Use distinct names such as `suitePlanDigest`, `fixturePlanDigest`, and `sweepPlanDigest`.
- Require redaction tests for arguments and environment-derived values; the current command evidence records full argument arrays.
- Define semantic-report equivalence for Stage 1 through the existing canonical validators rather than an informal comparison.

5. **Open questions**

- No retained CI timing data is present in the repository, so the proposed deadline values cannot be validated empirically.
- Is output-shape/output-disposition evidence intended to become part of this authoritative phase graph, or remain a separately orchestrated producer?
- Is the inherited-intrinsic alias ledger diagnostic only, a product prerequisite, or eventual promotion evidence?
- Is same-runner isolation intended to defend only against accidental interference, or against repository-controlled child processes deliberately modifying sibling evidence?
- What persistence mechanism, if any, is expected to preserve a GitHub-hosted runner across retries?

6. **Recommended next step**

Revise. First make the phase graph exhaustive and correctly ordered, then define the suite-level schema/digest and runner-loss protocols, and reconcile deadline and resumption claims with the actual GitHub Actions topology. The revised draft should receive another independent review before being considered for acceptance.

VERDICT: NOT READY

---

## Round 2 — 2026-07-19

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.6, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`.
  Orchestrator: Claude Code (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `high` (confirmed in the CLI banner).
- **Date:** 2026-07-19
- **Revision under review:** `545696dd751d` (post round-1 revision)
- **Redacted:** No.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-2 review and instructed not to read `llp/reviews/`
  (so no access to round-1 artifacts).
- **Method:** cli-runner, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round2.md`) — round-1 brief with
  the revision hash updated; same brief as the concurrent Fable round-2 review.

### Verbatim review

1. **Overall assessment**

The problem is real and worth solving: the repository confirms that CapSec execution is monolithic, synchronously supervised, and bounded only by 180-minute macOS and 240-minute Windows job timeouts. The proposal has a strong fail-closed direction and correctly recognizes the engine-provenance limit on cross-runner evidence. It is not ready for acceptance, however, because authoritative concurrency, runner-loss observation, digest schemas, deadline budgeting, and evidence authority still contain substantive contradictions or underspecified security boundaries.

2. **Strengths**

- **Motivation / Required execution model:** Correctly identifies the central operational defect. `capsec-command-evidence.mjs` uses blocking `spawnSync` with no timeout, heartbeat, duration, cancellation handling, or process-tree cleanup.
- **Authority boundary:** Preserves LLP 0021’s crucial distinction between fixture evidence, prerequisite suites, diagnostics, and promotion authority.
- **Phase graph:** Correctly notices that the current post-suite engine attestation occurs before the exact fixture-evidence pilot. Requiring the final attestation after every engine-using evidence producer is an important correction.
- **Resumption:** Honestly limits authoritative reuse to the same provable runner and states that hosted-job retries cannot recover promotion evidence under the current host-local engine identity.
- **Authoritative sharding / Aggregate validation:** Exact membership, diagnostic-authority labels, pre/post engine attestations, deterministic aggregation, and rejection of incomplete or mismatched inputs are sound properties.
- **Process-tree termination / Acceptance criteria:** Contamination markers and parent-plus-grandchild timeout tests are materially stronger than the existing `scripts/with-timeout.sh`.
- **Stage 4 boundary:** Correctly refuses to invent portable cross-runner authority before a separate provenance design exists.

3. **Concerns**

1. **blocking — Authoritative concurrency lacks an enforceable isolation boundary.** Applies to **Authoritative sharding**, **Stage 3**, and **Acceptance criteria**. The document acknowledges that same-user sibling processes are not a security boundary, yet permits authoritative concurrency based on separate paths, ownership, and adversarial detection. A same-UID process can generally alter protections, manifests, contamination markers, evidence, or the engine pathname. The text also says serial authoritative execution is an acceptable Stage 3 result, while Stage 3 acceptance unconditionally requires adversarial concurrent-shard isolation. Resolve this by either defining a concrete OS-enforced isolation and trusted-supervisor boundary, or making authoritative concurrency explicitly optional and adding a valid Stage 3 completion path that retains serial authority.

2. **major — Runner-loss classification has no durable observation path.** Applies to **Command envelope**, **Secure diagnostics**, and **Stage 3 acceptance**. The live-status file resides on the runner that may disappear; periodic CI log lines do not by themselves give an aggregator a structured, authenticated incomplete record. An upload step cannot recover a file from a lost runner. Resolve this by defining an external observer and durable heartbeat transport, including its trust and identity binding, or narrow the requirement so an externally observed missing result produces only a job-level infrastructure refusal.

3. **major — The digest and manifest contracts are not implementable exactly as written.** Applies to **Terminology — Canonical form** and **Shard manifest**. The repository currently uses both domain-separated digests and bare SHA-256 over canonical JSON. LLP 0032 supplies no exact domain strings or projections for suite plans, phases, shards, attempts, or status records. It also requires a “shard digest” without defining its field, and says manifests contain “at least” certain fields while requiring rejection of every unknown field. Resolve this with exact closed schemas, digest domain strings and framing, omitted fields, self-digest rules, and golden vectors.

4. **major — The proposed deadlines are not plausible against either current job timeout.** Applies to **Deadline policy** and **Stage 1**. A straightforward mapping gives five preflight commands at 10 minutes each, two attestations at 30 each, Rust deadlines of 90/120/120, and five other product prerequisites at 60 each—about 740 minutes before recipe generation, adapter execution, public batches, fixture evidence, reporting, setup, cleanup, or upload. The document acknowledges only the 180-minute macOS conflict, but the 240-minute Windows job also cannot fit. Job decomposition across hosted jobs would conflict with the same-runner authority rule. Resolve this with a complete per-command mapping for both current targets, measured deadlines, explicit reserves, and a concrete workflow shape that preserves engine identity.

5. **major — The current child-process inventory is incomplete.** Applies to **Motivation**, **Command envelope**, and **Stage 1 acceptance**. The runner has more than the two bare children named: its `git` helper repeatedly invokes `git` through `execFileSync`, and the report generator performs additional direct Git invocations. Resolve this with an exhaustive direct-child inventory and an enforceable test or architectural rule preventing suite code from spawning outside the envelope.

6. **major — Stage 1 contradicts the normative attestation ordering.** Applies to **Phase graph** and **Stage 1: bounded sequential execution**. The phase graph says the final attestation MUST move after fixture evidence, while Stage 1 says to retain the existing semantic order—the current runner attests before the fixture pilot. Resolve this by explicitly including that reorder in Stage 1, while preserving any earlier attestation as an optional checkpoint.

7. **major — Evidence authority deference is incomplete.** Applies to **Authority boundary**, **Phase graph**, and **Authoritative sharding**. LLP 0021 explicitly treats adapter-probe evidence as diagnostic and rejects it at publication, but LLP 0032’s `adapter-evidence` phase does not state that. The inherited-intrinsic step is deferred to “whatever LLP 0021 assigns,” but LLP 0021 does not assign it an authority class. Additionally, Windows currently lacks mapped-image provenance and cannot satisfy the “same exact mapped engine artifact” requirement. Resolve this with an explicit producer-by-producer and target-by-target authority table, including adapter evidence, inherited-intrinsic evidence, output-disposition evidence, and Windows eligibility.

8. **major — Stage 4 has no acceptance criteria.** Applies to **Stage 4: portable authoritative distribution** and **Acceptance criteria**. The rollout declares four stages but defines completion only for Stages 1–3. Resolve this by either declaring Stage 4 a non-implementable placeholder that requires revision of LLP 0032, or adding entry and completion criteria governed by the future portable-provenance LLP.

4. **Suggestions**

- Define the semantic projection used to compare pre- and post-restructure reports; validation alone does not define equivalence.
- Specify attempt-ID generation and ordering so retry selection cannot be manipulated by choosing a lexically earlier identifier.
- Add fault-injection coverage for process-group escape, partial manifest writes, heartbeat stalls, disk exhaustion, cancellation during cleanup, and cleanup-record corruption.
- Make phase reuse conditional on revalidating both outputs and the runner contamination state immediately before consumption.
- Keep cross-runner diagnostic sharding as the first parallel rollout and require measurements before opening the authoritative-concurrency path.

5. **Open questions**

- What are the observed per-command runtime distributions on macOS and Windows? The repository retains no duration evidence sufficient to choose defensible deadlines.
- Is the threat model for child commands accidental hangs only, or does it include hostile same-UID test code? The authoritative isolation and cleanup design depends on that answer.
- What authority, if any, should inherited-intrinsic alias conformance carry? LLP 0021 does not resolve it.
- Can Stage 3 be considered complete after consciously rejecting authoritative concurrency, or is concurrency itself intended to be mandatory?

6. **Recommended next step**

Revise before acceptance. Close the authoritative-isolation contradiction, define the external runner-loss path and exact digest schemas, provide a realistic current-command budget, and make all evidence authority classifications explicit. Given the security stakes, the revised document should receive another independent review round.

VERDICT: NOT READY

---

## Round 3 — 2026-07-19

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.6, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`.
  Orchestrator: Claude Code (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `high` (confirmed in the CLI banner).
- **Date:** 2026-07-19
- **Revision under review:** `3a44e0d11831` (post round-2 revision)
- **Redacted:** No.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-3 review and instructed not to read `llp/reviews/`
  (so no access to earlier round artifacts).
- **Method:** cli-runner, round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0032/brief-round3.md`) — same brief as the
  concurrent Fable round-3 review.

### Verbatim review

1. **Overall assessment**

The problem is real and worth solving, and the document accurately describes revision `3a44e0d11831` and the current repository. Its authority model coherently defers promotion semantics to LLP 0021 and does not alter LLP 0001’s target matrix. However, two central security properties—complete process-tree containment and proof that authoritative shards came from one runner—are not yet enforceable as specified. Substantive revision is required.

2. **Strengths**

- **Motivation:** Accurately describes the 180-minute macOS and 240-minute Windows jobs, the synchronous monolithic runner, bare `execFileSync` recipe/report generation, and the separate macOS alias-conformance step.
- **Authority boundary:** Correctly preserves LLP 0021’s distinction between prerequisite suites, fixture evidence, adapter diagnostics, and promotion authority.
- **Phase graph:** Corresponds closely to the runner’s actual work. It correctly moves the final engine attestation after the fixture-evidence pilot, which currently runs after the post-suite attestation.
- **Resumption:** Honestly limits authoritative reuse to the same runner under today’s host-local engine identity. The statement that hosted-job recovery remains diagnostic until portable provenance exists is consistent with LLP 0013 and LLP 0021.
- **Sharding:** The rejection of cross-runner authority is prudent, and the option to conclude that same-runner concurrency is not worthwhile is an important safety valve.
- **Aggregate validation:** Exact membership, deterministic selection, schema closure, digest checking, and rejection of diagnostic or incomplete inputs are appropriate fail-closed rules.
- **CI rollout:** The staged sequence sensibly delivers bounded sequential execution before introducing resumability or concurrency.

3. **Concerns**

1. **Blocking — Command envelope / Process-tree termination / Stage 1 acceptance.** The document rejects `scripts/with-timeout.sh` partly because descendants can escape a process group, but then recommends a dedicated POSIX process group as the principal termination mechanism. A descendant that calls `setsid`, double-forks, or otherwise leaves the group defeats that mechanism, and the contamination marker helps only if the escape is detected. The acceptance test covers an ordinary parent and grandchild, not an escaping descendant. Resolve this by specifying an enforceable containment or exhaustive detection contract for each supported OS, or by explicitly narrowing the threat model and command contract. Add adversarial tests for session/process-group escape, cleanup races, and PID reuse.

2. **Blocking — Authoritative sharding / Shard manifest / Aggregate validation.** The aggregate cannot prove the central “same runner” requirement from the proposed manifests. LLP 0013’s engine identity is deliberately host-local; identical binary digest, path, device/inode-shaped fields, and attestations do not prove that two manifests came from one machine. Likewise, `authorityClass: authoritative` is self-asserted unless anchored in a trusted assignment. Resolve this by defining the trusted supervisor and aggregation boundary: how it assigns shards, creates their output channels, binds a suite-run instance, and prevents externally transported or cross-runner manifests from entering the authoritative set. Tests should mix artifacts from two runner instances with otherwise identical fields and prove rejection.

3. **Major — Deadline policy / Suite-plan identity / Resumption.** The initial classes are not plausible under the current jobs: five preflights, two attestations, and eight product commands already total at least 680 minutes of declared ceilings before public batches, adapter evidence, generators, fixture evidence, report generation, alias conformance, or reserves. The document acknowledges this, but its treatment of dynamic job timing is ambiguous. Binding the job start time “via the plan” risks changing `suitePlanDigest` between persistent-runner jobs, while Stage 2 requires the same plan digest for reuse; leaving it outside the digest leaves admission-control inputs unbound. Resolve this by separating the immutable suite plan from a per-attempt, trusted outer-budget record, defining their respective digest bindings and resumption compatibility, and requiring a complete macOS/Windows command-budget map as a concrete Stage 1 deliverable.

4. **Major — Deadline policy / Phase graph / Failure reporting.** A timeout “MUST remain visible in the final report,” but the dependency rules prevent later phases and `final-aggregate` from running after a failed predecessor. The current runner illustrates the gap: `runObservedCommand` throws immediately, so logs remain for upload but its structured failure record never reaches the eventual execution artifact or report. Stage 1 acceptance requires uploaded diagnostics but not an always-produced aggregate failure record. Resolve this by defining an always-produced attempt/execution outcome artifact, distinguishing it from LLP 0021’s promotion-facing conformance report, and specifying which artifact must contain timeout, cancellation, cleanup, and refused-launch records.

5. **Major — Command envelope / Shard manifest.** The minimum command record is insufficiently bound to the plan. It does not explicitly require `suitePlanDigest`, phase and shard identity, or a digest of the complete command descriptor—executable, arguments, working directory, environment projection, inputs, deadline, and expected outputs. “Command identity” is undefined, while manifests require only expected command identifiers. That permits replay or substitution unless implementations infer unstated rules. Resolve this by defining command identity as a domain-separated digest of a closed descriptor, recording its plan/phase/shard bindings, and specifying how secret environment values are committed while the displayed invocation remains redacted. These schemas are needed in Stage 1, not only Stage 2.

6. **Major — Resumption / Acceptance criteria.** Stage 2 permits reuse across jobs on persistent runners, but monotonic attempt allocation and contamination state are not specified across supervisor crash or restart. A restarted supervisor could reuse an attempt identifier, lose a contamination marker, or accept rolled-back state. Existing tests for stale, duplicate, and ambiguous outputs do not necessarily cover that failure mode. Resolve this with atomic durable allocation/state rules and crash-recovery tests covering interruption between attempt allocation, command launch, cleanup, and manifest publication.

7. **Minor — Motivation.** It says every validated phase output is “lost,” but the current workflow uploads `target/capsec-suite-evidence-*/**` under `if: always()`, so many partial outputs survive diagnostically. They are lost for authoritative reuse on a replacement hosted runner, not necessarily lost altogether. State that distinction in Motivation, where the claim first appears.

4. **Suggestions**

- Add a current-runner-to-phase mapping table, including the five preflights, eight product commands, supplied-evidence branches, bare generators, and secondary entry points.
- Acknowledge `scripts/build-blocking.sh`, which already combines a heartbeat with `with-timeout.sh`, while explaining that it lacks evidence integration and robust tree containment.
- Add an explicit trust model distinguishing trusted orchestration, trusted evidence producers, adversarial fixture workloads, and potentially malicious sibling shards.
- Make the Stage 1 suite-plan schema and repository location concrete. Currently `capsec/conformance/` contains only `target-attestations.json`.
- Add cancellation tests to Stage 1 and forced runner-loss/missing-artifact tests to Stage 3, with clear expectations for which records can and cannot exist.

5. **Open questions**

- No retained duration data in the repository establishes practical per-command deadlines for the current macOS and Windows jobs.
- It is unclear which macOS primitive can provide the document’s required proof against process-group/session escape.
- It is unclear whether shard commands are trusted programs whose accidental collisions are in scope, or adversarial same-user processes; the current isolation requirements imply the latter.
- The repository does not establish how a trustworthy outer-job start and deadline would be passed to the runner on GitHub-hosted CI.
- It is unclear whether failure diagnostics belong in an extension of the LLP 0021 report schema or in a separate execution-outcome schema.

6. **Recommended next step**

Revise to define enforceable process containment, trusted same-runner aggregation, immutable-plan versus per-attempt budget identity, and always-produced failure records. Then gather another focused security/CI review before considering Draft→Accepted.

VERDICT: NOT READY
