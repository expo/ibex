# Reviews: LLP 0030 — Audit graph admission (Claude Fable family)

## Round 1 — 2026-07-18

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Claude Code CLI 2.1.214, model reported by reviewer as Fable 5, fresh external context
**Date:** 2026-07-18
**Redacted:** no (repository content only; no secrets present)
**Method:** read-only CLI runner; reviewer read LLP 0030, governing LLPs, and relevant implementation, was barred from `llp/reviews/`, and made no repository changes
**Verdict:** REVISE

### Review (verbatim)

# LLP 0005 Review — LLP 0030: Audit graph admission (Spec, Draft)

**Reviewer:** Claude (Fable 5), independent architecture/security review, 2026-07-18.
**Evidence base:** LLP 0030 read in full; LLP 0013, 0021, 0026, 0027, 0028, 0031, 0014, 0009 read in relevant part; implementation inspected in `crates/capsec-semantics/`, `src/bin/ibex/runtime.rs`, `src/host/abi.rs`, `src/module_loader/`, `capsec/schema/`, `capsec/registry/`, `capsec/generated/`. Nothing under `llp/reviews/` was read. No repository files were modified.

## Overall assessment

LLP 0030 is a well-aimed spec attacking exactly the right problem: after LLP 0028 retires the compatibility evaluator, `capsec audit` must either get a native execution path or die, and the tempting failure mode — manufacturing production-shaped authority from diagnostic state — is named and fenced repeatedly. The core security posture is correct and half of it already exists verified in code: the two-arm `Workflow` enum and the stratum-16-only missing-authority relaxation are implemented exactly as specified (`crates/capsec-semantics/src/decision.rs:341-346`, `1065-1089`; `capsec/registry/policy-rules.json:409-421`), and the spec's insistence that identity failures never launder into would-deny allows (§2) is the strongest line in the document.

However, the spec has a structural gap at its center: it defines what the diagnostic snapshot *lacks* (authorities, ceilings, floors, protected grants, policy digest — §1) but never defines what the decision engine *evaluates against* in their place, even though §4 requires ceiling, protected-object, and containment strata to keep blocking. It also never reconciles with the *armed* `diagnostic-audit` workflow that LLP 0021 and the shipped schema already define, leaves the audit run's own side effects free to poison the very caches and reports the spec protects from the runtime, and underspecifies candidate-table and builtin behavior in a policy-less run. These are resolvable with one focused revision; none undermines the architecture.

## Strengths (with sections)

1. **The relaxation surface is minimal and already machine-checked.** §Motivation's property split (trustworthy identity vs. non-blocking missing-authority) and §4's rule match the implemented decision core stratum-for-stratum: `ProductionEnforce` hard-denies and `DiagnosticAudit` sets `would_deny` only at `MissingAuthorityMode`, after all 15 preceding strata (`decision.rs:1065-1089`; registry proof table `registry.rs:761-771`). Spec and verified semantics agree.
2. **Identity failures cannot become would-deny allows.** §2's closing paragraph ("Symlink escape, root replacement, … Audit does not turn any of these into a would-deny allow") is precisely the fence that keeps property 2 from eroding property 1, and §6 encodes it as distinct failure classes.
3. **Anti-fallback posture.** §Summary and §3/§5 name the safe failure ("refuse audit source entries") and explicitly forbid the two dangerous fallbacks — silently reselecting the old evaluator or minting an `ArmedSnapshot`. This matches LLP 0028 §4b's named fallback exactly.
4. **Wire form as evidence, not credential** (§1), with no round-trip back to a live handle — closes the replay channel for the snapshot itself.
5. **Cache non-promotion is directional and asymmetric** (§5): diagnostic output never enters production namespaces by any mechanism (promotion, hard-link, rename, copy), while production entries may be read only via full independent re-admission. Narrowing-only flow is the right shape.
6. **Failure classification before prose** (§6) and the dead-code rule are good product-security hygiene; retaining LLP 0028's reserved-vocabulary failure-timing rule keeps the two specs consistent.
7. **Conformance is release-gated and anti-shape-test** (§7): making the denial/missing/cross-principal fixtures gates for LLP 0028 window close, and stating "Shape-only unit tests do not satisfy them," has real teeth.

## Concerns

**C1 (material) — The unarmed decision context is undefined.**
§4 says "The decision algorithm is unchanged through all denial and containment strata," but stratum 1 of that algorithm is "arm validity and authenticated profile/digest agreement" (LLP 0021, "Decision, staging, and principal semantics"), evidence records "carry all four loaded vocabulary, registry, policy, and armed-snapshot digests" (LLP 0021, "Canonicalization and digest domains"), and the implementation keys bootstrap-floor matching on `context.identity.armed_snapshot_digest` (`decision.rs:1044-1055`). §1 strips the diagnostic handle of the policy digest, ceilings, bootstrap floor, and protected grants — yet §4 requires "root ceiling" and "protected-object refusal" to remain *blocking*. Blocking against what? The spec never says whether ceilings/protected sets are empty, compiled-in baselines, or derived from the diagnostic snapshot, nor what fills the digest slots strata and evidence require.
*Resolution criterion:* the spec defines the diagnostic decision context field-by-field — which value stands in for each armed-context input (digests, ceilings, floors, protected-object set, generations), and which strata are vacuous vs. evaluated against a compiled baseline — such that an implementer could construct it without inventing semantics.

**C2 (material) — No reconciliation with the existing *armed* `diagnostic-audit` workflow.**
LLP 0021 states "An executable production or diagnostic-audit **snapshot may arm** only when its exact target triple … [is] advertised" (line 575), and the shipped schema defines `workflow: "diagnostic-audit"` on `ArmedSnapshot` with `effectiveMode: "audit"` (`capsec/schema/armed-snapshot.schema.json:47`, `247-253`). LLP 0030 introduces a *non-arming* handle for the same workflow name and never mentions the armed variant. This muddies the headline claim "no conversion exists from diagnostic to armed/production types" (§1) — an armed diagnostic-audit snapshot already exists as a schema concept — and leaves CLI dispatch ambiguous (does `capsec audit` with a supplied policy arm normally, while policy-less audit uses the new handle?).
*Resolution criterion:* a section states the relationship: either the armed diagnostic-audit variant is retired (with the 0021/schema update landed in the same change, per repo practice), or the two coexist with an explicit dispatch rule and distinct naming so "diagnostic-audit" is not both an armed workflow and an unarmed handle.

**C3 (material) — The audit run's own side effects can poison caches and reports; the protected baseline is unspecified.**
A relaxed decision "proceeds" (§4) — the audited program really executes its effects, and in a policy-less run nearly every effect is missing-authority. §5 forbids the *runtime* from promoting audit output into production namespaces, but nothing stops the *audited code* from writing into the `diagnostic-audit-v1` cache, a production prepared-cache namespace, or the audit report/receipt output path — all as would-deny-proceed writes. Digest re-verification at admission mitigates cache poisoning, but the report the operator reads (Open question 2) has no stated integrity protection, and §4's "protected-object refusal" cannot cover these paths because (per C1) no protected set is defined for unarmed audit.
*Resolution criterion:* the spec mandates a built-in protected-object baseline for unarmed audit that at minimum covers production and diagnostic cache namespaces and the receipt/report output, keeps those refusals blocking (not would-deny), and adds a §7 fixture in which audited code attempts exactly these writes.

**C4 (material) — Builtin admission bypasses a gate LLP 0027 requires.**
LLP 0027's builtin rule is "Package policy is checked by the no-probe armed resolver before the exact builtin target enters the graph." §2 steps 3/6 admit builtin edges via "the ordinary typed resolver" and the compiled builtin manifest — but audit has no policy and no armed resolver. If builtin reachability is policy-gated in production, audit silently widens the *graph shape* at capture time, outside the missing-authority stratum, contradicting §Motivation's claim that audit relaxes nothing but stratum 16.
*Resolution criterion:* the spec states the audit-time builtin rule explicitly — e.g. all builtin edges admitted at capture with builtin *effects* still flowing through the unchanged decision strata — and justifies it against LLP 0027, or specifies a diagnostic builtin gate.

**C5 (material) — Candidate-table behavior in a policy-less run is underspecified and silently diverges from enforce.**
Candidate rows exist only because the LLP 0014 generator joins reviewed manifest declarations (`ibex.computedCandidates.sites`) to producer site tables; a no-policy audit run structurally has zero rows, so *every* computed dynamic import fails at invocation under audit even when it works under enforce-with-policy. §6 collapses this to one row ("reached computed/candidate-less site") without acknowledging the divergence — which matters because audit's stated purpose is to report what enforce would deny, and here it under-reports (a plain throw, no would-deny evidence, at sites enforce would allow). Additionally, the current implementation rejects absent spellings with a link-time `bail!` (`src/engine/module_runner.rs:1995-1998`), not the invocation-time "ordinary rejected promise at the original source site" §6 requires, so the spec is prescribing a behavior change without listing it in §8.
*Resolution criterion:* the spec states whether audit may consume authored candidate-site declarations (and whether those count as "durable policy input" under §2), or explicitly documents the audit/enforce divergence; adds a §7 fixture for a graph containing computed imports; and §8 gains the invocation-time-rejection work item.

**C6 (material) — Evidence-stream bounding has no overflow semantics.**
§4 requires a "bounded run-local evidence stream" and §4's receipt carries "counts plus a digest of the ordered would-deny evidence stream"; the current audit log is a bounded 1024-entry buffer (LLP 0013). Nothing defines what happens at the bound: silent truncation lets a noisy or adversarial dependency flood the stream with benign would-denies and evict the interesting ones, while the receipt's counts and digest silently cover different populations. §7.10 tests "report bounds and digest determinism" but not adversarial eviction.
*Resolution criterion:* overflow behavior is normative (e.g. `truncated: true` on the receipt, per-class total counts always exact, digest defined over the retained prefix) and §7 gains a flood fixture proving a would-deny cannot be silently dropped without the receipt saying so.

**C7 (material) — "Advertised" is not bound to a source of truth, and the sequencing dependency on LLP 0031 is unsurfaced.**
§3's rule is right, but today the audit-relevant gate is a hardcoded `matches!((os,arch), ("macos","aarch64")|("linux","x86_64"))` (`src/bin/ibex/runtime.rs:42-49`), `capsec/generated/target-advertisements.json` contains `advertisements: []`, and production arming uses a separate, stronger verified-advertisement check. If audit's notion of "advertised" is the weak CLI gate, source audit could execute on a tuple lacking verified engine evidence — undermining property 1 (trustworthy identity depends on engine identity). The governing platform Decision, LLP 0031, is Draft and lists LLP 0030 as Related, but 0030's header does not cite 0031, and §7's release gates cannot be satisfied until 0031 is accepted and at least one advertisement is promoted.
*Resolution criterion:* the spec requires audit to use the same verified advertisement check as production arming (LLP 0021 §Default and target claim), adds LLP 0031 to Related, and names the acceptance-ordering dependency (0031 accepted, one tuple advertised) in §7 or Open questions.

**C8 (material) — The object-retention wording doesn't pin down the bytes of record.**
§1 says the live handle "retains the opened root/source/package objects"; §2.5 says to "retain enough object identity to reject replacement before production and again before evaluation." The implementation's actual mechanism is re-open with `O_NOFOLLOW` plus `dev`/`ino` comparison and a double inventory pass (`src/module_loader/mod.rs:1283-1539`) — it does not hold fds in the graph type, and dev/ino comparison detects neither in-place content rewrite of the same inode nor inode recycling after unlink. That is safe *only if* every later stage consumes the originally captured bytes; but the spec states that only for the §5 cache-miss branch ("rebuilds in memory from the already captured source bytes"), not as a general rule.
*Resolution criterion:* a normative statement that after capture no stage re-reads source bytes from the filesystem (or that any re-read re-verifies the integrity digest, not merely object identity), plus clarification of whether "retained objects" means held-open handles or identity facts with re-open-and-compare — including what identity means on Windows, which the CI matrix covers.

**C9 (minor) — Citations over-claim LLP 0021.**
§Summary ("LLP 0021's `DiagnosticAudit` workflow") and §Motivation ("the final missing-authority stratum already named by LLP 0021") attribute to 0021 things it doesn't contain: 0021 defines no `Workflow` enum and never states the relax-only-missing-authority rule; both are 0030/implementation constructs inferable from 0021's stratum 16 plus "Mode fallback can never mint a grant or handle."
*Resolution criterion:* citations point at what actually defines these (the semantics crate/registry, or a 0021 update landed alongside).

**C10 (minor) — SourceId variant taxonomy mismatch.**
§2.6 admits "File, package, and builtin" variants; LLP 0026 §2's derivation arms are "package, project, builtin, synthetic, and generated." "File" vs "project" should be aligned, and the generated arm's admissibility in audit is unstated.
*Resolution criterion:* §2.6 uses the 0026/0027 vocabulary and disposes of all five arms.

**C11 (minor) — The diagnostic prepared-carrier schema is unnamed.**
`ibex/module-carrier/2` binds a *deployment-graph* digest and split HBC engine identities (`loaded-file` vs `static-compatibility`); LLP 0027 already anticipates "Diagnostic source-carrier variants are tagged separately and cannot validate as release-eligible contracts," but §5 neither cites that hook nor says whether it reuses `module-carrier/2` or defines a diagnostic carrier schema. Minor because the prepared arm is optional for v1.
*Resolution criterion:* §5 names the carrier schema and cites 0027's diagnostic-variant rule.

**C12 (minor) — The third workflow value is unaddressed.**
The schema workflow enum has `production | diagnostic-audit | contract-fixture` (`armed-snapshot.schema.json:47`); §1's sealed linker enum has two arms. One sentence scoping `contract-fixture` (schema-only, per LLP 0021) out of the linker path would close the gap.
*Resolution criterion:* that sentence exists.

## Suggestions

- Close the spec's own Open question 1 by recommending inline-only for v1. Every material concern touching §5 (C3, C11) shrinks or disappears, and LLP 0028's deadline pressure argues for the smaller surface.
- Add an operator-facing warning requirement to §4 or the receipt: an unarmed audit run *executes* the effects it reports, so auditing untrusted code is running untrusted code. The spec's internals are honest about this; the product surface should be too.
- Add a short table to §4 (or an appendix) enumerating each of the 16 strata with its diagnostic-context input — this is the natural artifact resolving C1 and would double as implementation guidance for §8 step 2.
- State whether the would-deny evidence stream is intended as future input to LLP 0014 grant generation (audit → suggested policy). Even "out of scope for v1, evidence schema must not preclude it" would prevent an accidental schema dead-end.
- §7 could add: unadvertised-tuple stable-refusal fixture (§3's behavior is currently untested and today's code *falls back* to the compatibility loader inside the window, `runtime.rs:1590-1601`), and a receipt-replay fixture (a diagnostic receipt presented where a production execution receipt is expected must refuse — §7.6 covers cache output but not receipts).

## Open questions

1. Does `capsec audit` with a supplied policy exist as a product surface (arming a `workflow: diagnostic-audit` snapshot per LLP 0021), and if so, is that path in or out of this spec's scope? (C2)
2. Are authored `ibex.computedCandidates.sites` manifest declarations "durable policy input" that §2's preamble rejects, or capture-eligible graph facts? (C5)
3. What are the retention, garbage-collection, and cross-project-sharing rules for the `diagnostic-audit-v1` namespace, if implemented? A long-lived shared diagnostic cache changes C3's threat surface.
4. What does audit do for non-file entries (`ibex -e`, stdin, REPL) that have no `SourceId`? §2 assumes `capsec audit <entry>`; the refusal for everything else should be explicit.
5. How is "root directory object identity" (§1 wire projection) encoded portably across the platforms in the CI matrix — dev/ino on Unix, file IDs on Windows, or host-local and excluded from the digest? (C8)

## Recommended next step

One focused revision cycle before acceptance, prioritizing C1–C3 (define the unarmed decision context and protected baseline; reconcile the armed diagnostic-audit naming — likely with a small LLP 0021/schema touch in the same change; fence the audit run's own writes), then C4–C8, folding the new fixtures into §7. LLP 0028 requires this spec accepted before its step 4, so the revision should land promptly and re-enter review; the architecture does not need rethinking, and §8's implementation sequence can proceed through step 2 in parallel since the decision-layer semantics it depends on are already implemented and stable.

VERDICT: REVISE

## Round 1 re-review — 2026-07-18

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Claude Code CLI 2.1.214, model reported by reviewer as Fable 5, continued external review context
**Date:** 2026-07-18
**Redacted:** no (repository content only; no secrets present)
**Method:** read-only CLI runner; reviewer re-read revised LLP 0030 and its cross-references, was barred from `llp/reviews/`, and made no repository changes
**Verdict:** READY

### Re-review (verbatim)

# Re-review: LLP 0030 — Audit graph admission (revised 2026-07-18)

Independent architecture-security review, round 2. Reviewed the revised spec plus its cross-references: revised LLP 0021 (decision strata, foreground evidence slots), LLP 0027 (`SourceId`, `authenticated-graph-snapshot/1`, `module-carrier/2`), LLP 0028 (risk register, window-close gates), LLP 0031 (advertisement gating), the armed-snapshot schema (`workflow` enum), and the code sites named in Motivation (`current_module_runner_snapshot` at `src/host/abi.rs:548`, consumed at `src/module_loader/runner_pipeline.rs:865,1559`). Did not read `llp/reviews/`; no repository modifications.

## Overall assessment

The revision resolves all eight material concerns from round 1, and it does so with specific, testable language rather than reassurance: every fix is paired with a conformance item, and the cross-document claims it makes actually hold in the corpus (LLP 0021 was revised in lockstep with matching evidence-slot and decode-only language; LLP 0031 exists and its unadvertised-tuple posture matches §3; the schema's `diagnostic-audit` and `contract-fixture` arms exist exactly as described). The security architecture is now coherent end to end: one relaxed stratum (final missing-authority), everything else blocking; a decision context in which every production input has an explicit disposition instead of a silent default; a protected baseline that removes the cache/report poisoning surface that would-deny execution would otherwise create; and an inline-only v1 that shrinks the artifact attack surface to something reviewable. What remains is clarity-level: one fixture-constructibility ambiguity created by the new decision-context table, two small wording tensions, and one stale row in LLP 0028 that now disagrees with this spec's inline-only decision. None is architectural.

## Resolution audit

**C1 — Complete unarmed decision context: RESOLVED.** §1 "Diagnostic decision context" introduces an immutable `ForegroundAuditDecisionContextV1` that is explicitly "not an incomplete `ArmedExecutionContext`," with a table assigning every production decision input an explicit diagnostic disposition — exact vocabulary/registry digests (mismatch hard-refuses), a `foreground-audit-baseline/1` digest in the policy slot, the armed-snapshot digest absent *by type*, same target/engine checks as production, vacuous policy strata, blocking registry closures, fresh pinned generation, and non-serializable nonces. This matches revised LLP 0021's rule that foreground evidence "never fills a policy or armed-snapshot slot with a lookalike value."

**C2 — Armed-vs-foreground audit separation: RESOLVED.** `ForegroundAuditGraphSnapshotV1` / `ibex/diagnostic-graph-snapshot/1` with `workflow = "foreground-source-audit"` is name-disjoint from the armed schema's `diagnostic-audit` arm (confirmed present in `capsec/schema/armed-snapshot.schema.json:47,248`), which is now decode-only with no new arming — stated identically in revised LLP 0021. Separation is type-enforced: no conversion path, distinct `DiagnosticSourceModuleGraphV1`, sealed linker enum binding workflow to graph arm, receipts labeled `authorizesProduction: false` with no authority-bearing schema variant. Conformance 6 and 12 make it testable.

**C3 — Protected cache/report baseline: RESOLVED.** §1 defines a mandatory host-derived baseline (executable, loaded engine, captured project/package/source objects, production *and* diagnostic cache trees, report/receipt destination, loaded policy/artifact files) where writes/renames/links/deletes hard-refuse even though the same effect would otherwise proceed as would-deny; the host opens and retains the report destination before application code runs. Conformance 11 exercises exactly the poisoning attempts.

**C4 — Builtin and candidate behavior: RESOLVED.** §2 step 3: typed builtin edges enter the diagnostic graph; the import-axis decision is emitted at link/evaluation and may proceed only as final missing-authority would-deny; registry-closed builtins and malformed edges hard-refuse. §2 step 8: `ibex.computedCandidates.sites` is captured graph-authoring input, not durable policy, resolved under the same capture fences into digest-bound tables, granting no host authority, with reached-site-only rejection (§6 invocation class, conformance 5).

**C5 — Evidence overflow: RESOLVED.** §4 fully specifies the bound: latest 1,024 ordered entries retained, digest over exactly the retained suffix, per-terminal-class totals over *every* observed decision, and `observedCount`/`retainedCount`/`droppedCount`/`truncated` in the receipt — overflow can drop detail only with `truncated: true` and a nonzero dropped count. Conformance 10 tests determinism under repeated, concurrent, and flooding runs.

**C6 — Verified target source: RESOLVED.** §3 requires the same verified advertisement authority as production arming, explicitly *not* "the CLI's weaker OS/architecture allowlist," with a stable target-unavailable diagnostic and refusal before source capture (conformance 12). LLP 0031 confirms the gate from the other side (source audit listed as unavailable on unadvertised tuples; release coupled to verified CapSec advertisements), and revised LLP 0021 states "foreground source audit does not arm, but uses this same verified target."

**C7 — Captured-byte retention: RESOLVED.** §2 step 5: each source is opened once, integrity is derived from those bytes, and bytes plus handle are retained through evaluation; no later stage re-reads a pathname. The platform fallback (re-open must re-check both native object identity *and* content integrity) closes the TOCTOU gap, and excluding host-local device/inode facts from the portable graph digest avoids the digest-portability trap.

**C8 — Inline-only v1: RESOLVED.** §5: no production prepared-cache read or write, no diagnostic prepared namespace, no HBC consumption, no promotion; a future prepared-audit format requires its own schema revision and "cannot be inferred from `ibex/module-carrier/2`"; fallback is a stable refusal, never the compatibility evaluator. Conformance 13 additionally closes the unauthenticated-`SourceId` entry hole (`-e`, stdin, REPL, `.load` refuse).

## Remaining concerns

**R1 — Explicit-deny fixture constructibility (Minor).** The new decision-context table declares authored denials and escalation/root ceilings "empty; their policy-dependent strata are vacuous, not passed," yet §4 lists "explicit denial" and "root ceiling" as remaining blocking, and conformance 3 requires an explicit-deny hard refusal *through the real `ibex capsec audit` command* — which rejects every durable policy input. The spec never says what mechanism produces an explicit deny in a policyless run (presumably a registry hard closure, quarantine, or protected-object refusal). The risk is that an implementer "helpfully" accepts a denial-bearing policy input to build the fixture, violating the no-durable-policy fence. *Resolution criterion:* one sentence naming the fixture mechanism for conformance 3 and clarifying that policy-authored deny/ceiling strata are unreachable-vacuous in audit rather than merely unrelaxed.

**R2 — HBC wording tension (Minor).** Conformance 7 requires "stale … HBC versions refuse," but §5 says v1 never consumes HBC — a stale-version refusal presupposes a version check on an ingestion path that doesn't exist. Presumably intended as "any HBC carrier presented to diagnostic admission refuses regardless of version." *Resolution criterion:* reword conformance 7 to say HBC carriers refuse categorically under inline-only v1.

**R3 — Baseline digest self-reference (Low).** The `foreground-audit-baseline/1` digest is defined "over this table and the protected-object set," but the table itself contains the policy-digest row holding that digest — a definitional circularity implementers will resolve by exclusion, but the spec should say so. *Resolution criterion:* one line specifying the canonical encoding digested (dispositions plus protected set, excluding the digest slot itself).

**R4 — LLP 0028 stale fallback row (Low, cross-doc).** LLP 0028's risk register (line 475) names the audit fallback as "audit refuses source entries and accepts only prepared carriers," which now contradicts 0030's inline-only v1 (no prepared-cache access at all; conformance 6). 0030 governs and this is not a defect in 0030 itself, but per this repo's living-document rule the 0028 row should be reconciled when 0030 is accepted. *Resolution criterion:* update the 0028 register row (can land with the 0030 acceptance commit).

New contradiction check: R1 is the only tension introduced *by* the revision itself (the new table vs. the pre-existing §4 blocking list); R2–R4 are pre-existing or cross-document wording drift. I found no new contradiction in the security architecture — the separation, fences, and evidence model are internally consistent and consistent with the revised LLP 0021.

## Recommended next step

Apply the four wording fixes above (all are one-to-two-sentence edits; R4 lands in LLP 0028) and proceed toward acceptance. None requires re-architecture or another full review round from this reviewer — a spot-check of the edited sentences suffices.

VERDICT: READY
