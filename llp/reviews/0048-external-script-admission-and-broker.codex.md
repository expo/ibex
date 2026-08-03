# Reviews: LLP 0048 — Restricted External Script Admission and Broker ABI (OpenAI Codex family)

## Round 1 — 2026-08-03 (cluster review: LLP 0028 + 0029 + 0047 + 0048)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check --ephemeral -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc881-8ccc-7e71-a806-1d2a67a33406`
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0048 git-blob `3494746dcd8c83eacf95782024f7cfad65d32861`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `4168478214ceb7d3071b6435b26f0cb897eb6d77`; LLP 0047 git-blob `329c8989de471c6940dd915d5dc92084444f4c2e`
**Prompt:** Review the four-document cluster against LLPs 0002/0013/0014, Snapback LLP 0062 §§3/6/7, the current implementations, and the Snapback coordination ticket for correctness, security honesty, ABI/lifecycle/resource completeness, versioning feasibility, and exact closing-condition preservation. Findings were requested as MATERIAL/MINOR with concrete resolutions and per-document verdicts.
**Verdict:** NOT READY

### Draft-introduced findings

1. **MATERIAL — The external-script principal cannot be represented by the
   current CapSec policy or armed-runtime contracts.** The implemented
   principal vocabulary contains package/root/runtime/module-loader/quarantine
   principals, and canonical policy parsing rejects non-package rows. The
   reviewer required either a versioned `ExternalScript` policy/arming schema
   or a separate versioned restricted-worker arming contract binding the app,
   source, run nonce, broker, globals, limits, and dynamic-code posture.

2. **MATERIAL — The native construction and execution boundary is incomplete.**
   Existing constructors do not provide the required combination of armed
   policy, irreversible dynamic-code disablement, exact globals, heap limit,
   structured settlement, broker interruption, and lifecycle ownership. The
   actual public or private native seam must define versioned size-tagged
   options, buffer ownership, thread rules, generation/run-nonce checks, limits,
   broker callbacks, sealing, structured extraction, errors, and destruction.

3. **MATERIAL — The broker protocol is not a complete implementable schema.**
   `start.surface`, nested values/errors, timer operations, console projection,
   sequences, duplicate terminals, and post-terminal behavior were
   under-specified. The reviewer required a closed IDL or mechanically
   equivalent schema with invalid-frame vectors.

4. **MATERIAL — Lifecycle precedence and exit mapping are incomplete.** Engine
   failure and process signals were absent from precedence; catchable call
   failures were not distinguished from fatal witnessed ceilings; and the prose
   accidentally described exit 1 as usage although Snapback reserves it for
   engine-internal failure. The reviewer required one exact terminal-state and
   exit table covering success, internal failure, exits 2–11, and `128+n`.

5. **MATERIAL — Resource semantics are inconsistent.** A 16 MiB result cannot
   fit in one broker frame whose maximum is 4 MiB. The draft also did not state
   pre-allocation length rejection or transformed-source/AST bounds. The
   reviewer required settlement chunking or a smaller result, length-prefix
   enforcement, and transform bounds.

6. **MATERIAL — The proposed format rotations are names, not complete
   formats.** Stub V4, envelope V3, ApplicationBinding, CompilePlanV2, and
   PackageProvenanceV2 need exact structures, wire encodings, digest domains,
   ordering/cardinality/size rules, normalization, cross-binding equations, and
   malformed golden vectors.

7. **MATERIAL — The language profile is insufficiently fixed for portable
   behavior.** The same profile identifier could change semantics under a new
   digest; stdin dialect, type-only re-exports, wrapper/completion, source-map
   composition, and transformed-output limits were ambiguous. The reviewer
   required a dedicated canonical manifest and semantic-version rotation.

8. **MINOR — Cached-output “authentication” is overstated.** Rehashing an
   unauthenticated cache is verification, not authentication. Disable caching,
   define an authenticated receipt, or correct the term.

9. **MINOR — LLP 0029 misstates the app-binding chain.** The binding is covered
   by its own section through CompilePlanV2 and PackageProvenanceV2, not by the
   embedded graph.

### Pre-existing defects or implementation gaps

1. **MATERIAL — Existing Node code mode is not yet a parity oracle.** It lacks
   run IDs, monotonic sequences, canonical frames, structured console values,
   and the required fatal-ceiling behavior, and it shares the result/frame-size
   mismatch. Node and Ibex must migrate together from one definition and suite.

2. **MINOR — LLP 0014 retains the retracted Snapback computed-import
   rationale.** The governing corpus must be corrected with LLP 0028.

### Coordination and verdicts

The reviewer found that the cluster fulfills the coordination ticket's
requested direction and does not weaken its closing condition. It was not yet
closable because LLP 0048 had material gaps, the documents were not landed,
and identifiers/commits were not recorded.

- **LLP 0048:** NOT READY
- **LLP 0028 amendment:** READY
- **LLP 0029 amendment:** READY, with the minor binding-language correction
- **LLP 0047 amendment:** READY
- **Overall cluster:** NOT READY

The reviewer characterized the architecture and its non-sandbox security
boundary as directionally sound; the blockers were specification completeness.

## Round 2 — 2026-08-03 (full reconciliation review)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check --ephemeral -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc89f-061a-7f13-bf09-4cbf23f433c0`
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0002 git-blob `94cc6f3e275e123ed84bed6e27fb8ad8a6dee8ab`; LLP 0014 git-blob `39d5f59cce8b23697df81d456e56c8d17d7de062`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `11a0df773bc82046cd37085165f4426248d68a3a`; LLP 0047 git-blob `edaded0a317de3d5057d9e83e60d2fd35a822937`; LLP 0048 git-blob `7c1001a2b40461c323b6f3e0048a297036dacb8a`
**Prompt:** Re-review the reconciled cluster, verify every Round 1 finding, identify regressions or remaining ambiguities, and give independent per-document readiness verdicts. The review was explicitly asked to inspect the current Ibex and Snapback implementations, Snapback LLP 0062, and the coordination ticket.
**Verdict:** NOT READY

### Findings

1. **MATERIAL — The arming receipt does not yet bind the runtime actually
   started.** It binds raw source and a limits digest, but not the transformed
   source or source map buffers supplied to `start`; the native options and
   start frame also duplicate limits without an exact equality rule. Add both
   transformed-buffer digests, define complete `LimitsV1` equality, and keep the
   128-bit broker run identifier distinct from the native 64-bit control nonce.
2. **MATERIAL — The native event ABI remains under-specified.** Define closed
   event/fault enums, legal payload combinations, the final `CLOSED` event,
   buffer pointer and length rules, arming/start ceilings, concurrency and
   failed-start ownership, and post-destroy behavior.
3. **MATERIAL — An uncaught broker error has no terminal-frame carrier.** The
   precedence table says an escaped broker class 2–9 wins, but `failed` carries
   only script error 10. Add a closed broker-failure variant and state how a
   genuine delivered broker error is distinguished from a script forgery.
4. **MATERIAL — `StrictValue` has no aggregate safety bounds and the proposed
   object inspection can encounter proxies or recursion first.** Pin depth,
   node/property counts, iterative validation, and native proxy rejection
   before reflection or traps.
5. **MATERIAL — The V4/V2 reporting rotation is not a complete evidence
   contract.** Stub V4 must select standalone-info V2; reports need the
   language-profile and worker-policy identities; and a digest-bound,
   target-specific enforcement advertisement must connect catalog, stub, plan,
   report, and acceptance evidence.
6. **MATERIAL — Pre-worker failure mapping is ambiguous.** Define distinct
   outcomes for parse failures, refused syntax/profile forms, source/output/map
   ceilings, and native/profile invariant failures.

### Minor findings

1. Clarify that type-only re-exports erase while runtime re-exports are refused.
2. Require broker error codes to begin with an ASCII letter.
3. Pin the settlement-chunk digest algorithm and spelling.
4. Specify safe alias grammar and its reserved/hazard manifest.
5. Define timer token identity and `setTimeout` argument conversions.

### Verdicts

- **LLP 0048:** NOT READY
- **LLP 0002, 0014, 0028, 0029, and 0047 amendments:** READY
- **Overall cluster:** NOT READY

The reviewer confirmed that all Round 1 material findings had substantive
responses and that the remaining work was bounded contract precision, not an
architectural reversal. Existing implementation gaps were honestly left open.

## Round 3 — 2026-08-03 (final full-cluster review)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check --ephemeral -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc8ba-8690-78a1-a349-a025465af791`
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0000 git-blob `a74dea6986b501117f330bdd2327ff503923a8e9`; LLP 0002 git-blob `e10f490f0e25b93992295ef957923e759d643e14`; LLP 0014 git-blob `39d5f59cce8b23697df81d456e56c8d17d7de062`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `ad717b9578a650577be4b6177243126f56edb167`; LLP 0047 git-blob `7af5eccc60142b40ef785d9c2bf2ca25df022d5b`; LLP 0048 git-blob `0a8152604b1c27d45be9fb1141e12b8387788404`
**Prompt:** Perform a final reconciliation review of the exact current blobs against every Round 2 finding, both implementations, the governing LLPs, Snapback LLP 0062, and tickets 0062-07/0062-08. Identify only text defects, not honestly open implementation gaps; give per-document and overall readiness and assess the unchanged ticket condition.
**Verdict:** READY

### Prior-finding reconciliation

The reviewer found every Round 2 material and minor finding substantively
resolved: transformed-buffer/limits binding and distinct identifiers; exact
native input/thread/event/lifecycle ownership; branded broker-failure
transport; iterative bounded strict values with pre-reflection proxy refusal;
static timer/timeout and frame rules; settlement and pre-worker outcomes; alias
and type-only re-export grammar; and the complete target-specific evidence
chain through catalog, stub, plan, reports, and acceptance. It found no
dishonest isolation claim, digest cycle, semantic regression, or weakening of
the coordination-ticket condition.

### New minor findings

1. **MINOR — LLP 0014's “already quarantines” shorthand is stale.** Computed
   imports now have authenticated candidate-table semantics rather than one
   categorical quarantine. Say they contribute no static import-site grant;
   admitted rows may execute while missing/out-of-row candidates fail closed.
2. **MINOR — Catalog V2's advertisement descriptor needs its own closed
   type.** The draft called it the existing descriptor while requiring a role
   absent from the closed V1 role enum. Define a V2/new closed descriptor and
   pin the media type.

### Verdicts and ticket

- **LLP 0000, 0002, 0014, 0028, 0029, 0047, and 0048:** READY
- **Overall cluster:** READY

Landing the reviewed 0028/0029 corrections and LLP 0048, then recording the
identifiers and landing commit in 0062-07, satisfies that ticket's documentation
condition and unblocks—but does not complete—the implementation/evidence work
owned by 0062-08.

## Round 4 — 2026-08-03 (minor-finding delta review)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** `codex exec --skip-git-repo-check --ephemeral -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only`, codex-cli 0.146.0, session `019fc8c8-5f2e-77c1-b163-57a7c074e8a0`
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI delta review; no files edited by the reviewer
**Revision reviewed:** LLP 0014 git-blob `f3be1a003cba55cf413eecdd3a120359844617fd`; LLP 0048 git-blob `e612348c93b0a55851259e8c2466cb6f77f88cba`
**Prompt:** Verify only the five Round 3 minor reconciliations: computed-import grant wording, the complete function-id/frame reserve proof and failure owner, grace/timer wording, envelope-fetch limit ownership, and the closed Catalog V2 advertisement descriptor. Report regressions and whether the Round 3 READY verdict still holds.
**Verdict:** READY

### Findings and verdict

- **MATERIAL:** none
- **MINOR:** none
- **Delta:** READY
- **Overall cluster:** READY; Round 3 READY still holds

The reviewer verified the exact frame inequality, exit-7 surface refusal,
existing-timer grace behavior, `callEstablishmentMs` ownership, independent
closed catalog descriptor, and candidate-table distinction. It independently
confirmed `git diff --check` and `./ref-check` passed and ran no builds.
