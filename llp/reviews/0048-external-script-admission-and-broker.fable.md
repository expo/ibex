# Reviews: LLP 0048 — Restricted External Script Admission and Broker ABI (Claude Fable family)

## Round 1 — 2026-08-03 (cluster review: LLP 0028 + 0029 + 0047 + 0048)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** `claude -p --model claude-fable-5 --effort xhigh --permission-mode dontAsk --tools Read,Grep,Glob,Bash --no-session-persistence`, Claude Code 2.1.220
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Access note:** the permission mode refused every read outside the Ibex repo,
so this round could not independently inspect Snapback LLP 0062 or the
coordination ticket. Claims derived from them were therefore not assessed in
this round. The Ibex corpus and implementation were inspected.
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0048 git-blob `3494746dcd8c83eacf95782024f7cfad65d32861`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `4168478214ceb7d3071b6435b26f0cb897eb6d77`; LLP 0047 git-blob `329c8989de471c6940dd915d5dc92084444f4c2e`
**Prompt:** Review the four-document cluster against LLPs 0002/0013/0014, Snapback LLP 0062 §§3/6/7, the current implementations, and the Snapback coordination ticket for correctness, security honesty, ABI/lifecycle/resource completeness, versioning feasibility, and exact closing-condition preservation. Findings were requested as MATERIAL/MINOR with concrete resolutions and per-document verdicts.
**Verdict:** NOT READY (the coordination-ticket fulfillment question was not
assessable in this run because of the access limitation above)

### Draft-introduced findings

1. **MATERIAL — The settled-result maximum cannot cross the broker.** A 16 MiB
   hard result maximum cannot fit in the single `settled` frame whose hard
   maximum is 4 MiB; even equal 1 MiB defaults leave no envelope/escaping
   overhead. Add chunking or bind result limits below frame limits, then test the
   exact boundary.

2. **MATERIAL — Timers are parent-owned but absent from the broker ABI.** The
   child-process topology has no way to schedule, fire, clear, or refuse timers.
   Add timer frames or define a separate named lifecycle channel with a
   canonical test representation.

3. **MATERIAL — The lockstep rotation inventory omits two reporting schemas.**
   The strict `ibex/standalone-executable-info/1` schema pins envelope V2 and
   cannot report the new fields, and executable inspection is versioned too.
   The app-bound lockstep profile must include standalone-info V2 and executable
   inspection V4, mirrored in LLPs 0029 and 0047.

4. **MATERIAL — The enable/deny parent-policy fact has no carrier.** It fits
   neither strict policy V2 nor the shown binding. Name an exact StubContractV4
   or ApplicationBinding field, or coordinate policy V3, and test both states.

5. **MATERIAL — The attribution correction did not sweep LLP 0014.** LLP 0014
   still says Snapback 0.2 activated computed imports. Correct that stale
   attribution in the same commit.

### Minor findings

1. Pin stdin's parse dialect.
2. Map worker protocol violations to an exact terminal class and test it.
3. Define the `start` frame's `profile` and `surface` bodies and deterministic
   bounded console projection.
4. Specify the re-exec bootstrap mechanism (not argv/environment) and scope LLP
   0047's “complete v1 exception” wording to the general profile.
5. Add envelope fetch/authentication to the ordered admission transaction with
   its exit mapping.
6. Name the armed restricted-worker construction seam alongside the broker
   seam; current LLP 0002 constructors do not supply it.

### Pre-existing defect

The stale LLP 0014 attribution predates this draft; the new cross-document
contradiction and incomplete sweep are introduced by the correction cluster.

### Verified sound

The reviewer verified the armed-runtime generic-host-call prohibition and
nonce-authenticated interrupt path, the need for strict SFE format rotations,
the acyclic release-lineage ordering, LLP 0013-compatible non-sandbox threat
model, the internal consistency of LLP 0028's correction, the separation of
0047's general SFE finish line from the 0048 gate, and the two-tuple and timer
limit consistency.

### Verdicts

- **LLP 0048:** NOT READY
- **LLP 0028 amendment:** READY, conditional on correcting LLP 0014 in the same
  commit
- **LLP 0029 amendment:** READY, with the reporting-schema rotation mirrored
- **LLP 0047 amendment:** READY, with the re-exec-selector scope clarified
- **Overall cluster:** NOT READY

The reviewer said the defects were bounded specification-text fixes and did
not undermine the architecture.

## Round 2 — 2026-08-03 (full reconciliation review)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** `claude -p --model claude-fable-5 --effort xhigh --permission-mode dontAsk --tools Read,Grep,Glob,Bash --add-dir /Users/ccheever/projects/snapback --no-session-persistence`, Claude Code 2.1.220
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Access note:** this round successfully inspected both the Ibex and Snapback repositories.
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0002 git-blob `94cc6f3e275e123ed84bed6e27fb8ad8a6dee8ab`; LLP 0014 git-blob `39d5f59cce8b23697df81d456e56c8d17d7de062`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `11a0df773bc82046cd37085165f4426248d68a3a`; LLP 0047 git-blob `edaded0a317de3d5057d9e83e60d2fd35a822937`; LLP 0048 git-blob `7c1001a2b40461c323b6f3e0048a297036dacb8a`
**Prompt:** Re-review the reconciled cluster, verify every Round 1 finding, identify regressions or remaining ambiguities, and give independent per-document readiness verdicts. The review was explicitly asked to inspect the current Ibex and Snapback implementations, Snapback LLP 0062, and the coordination ticket.
**Verdict:** NOT READY

### Findings

1. **MATERIAL — An uncaught broker error has no terminal-frame carrier.** The
   precedence table permits broker classes 2–9, while `failed` is fixed to
   script error 10. Add a closed broker failure alternative and cover caught,
   rethrown, and forged errors.
2. **MATERIAL — Broker timeout and timer validity incorrectly depends on
   `remaining-run-ms`, which the worker cannot know.** Make wire validity use
   static bounds and let the parent clamp effective deadlines; an over-deadline
   timer is legal but never fires.
3. **MATERIAL — A 64 KiB console body plus frame envelope can exceed the 64 KiB
   minimum frame ceiling.** Derive the body bound from `frameBytes` with fixed
   framing reserve and add a boundary vector.
4. **MATERIAL — Script-authored oversized call/live arguments have conflicting
   exits 1, 2, and 11.** Require worker-side preflight that yields a catchable
   exit-2 broker error without emitting a frame, reserve exit 1 for invalid
   engine-authored frames, and scope witnessed frame overflow precisely.

### Minor findings

1. Make `abis.restrictedWorker` a string identifier rather than the only
   integer ABI value.
2. Require `start` digests and limits to equal the arming receipt and native
   construction values.
3. Cap the `start` frame and generated function surface before worker creation.
4. Pin the settlement-chunk digest spelling and algorithm.
5. Make the exit-2 versus exit-10 source-admission distinction explicit.
6. Pin `delayMs` wire grammar independently of run time remaining.
7. Constrain the Node parity implementation to the same one-shot timer surface.

### Verdicts

- **LLP 0048:** NOT READY
- **LLP 0002, 0014, 0028, 0029, and 0047 amendments:** READY
- **Overall cluster:** NOT READY

The reviewer verified that every Round 1 material finding was genuinely
resolved. The four remaining material findings were newly exposed boundary
conditions in the substantially expanded contract and did not change the
chosen topology or threat model.

## Round 3 — 2026-08-03 (final full-cluster review)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** `claude -p --model claude-fable-5 --effort xhigh --permission-mode dontAsk --tools Read,Grep,Glob,Bash --add-dir /Users/ccheever/projects/snapback --no-session-persistence`, Claude Code 2.1.220
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI review; no files edited by the reviewer
**Access note:** both repositories were inspected. The sandbox denied independent `git hash-object`, so the reviewer assessed the exact working-tree contents named in the prompt rather than independently recomputing their supplied hashes.
**Revision reviewed:** repo HEAD `6b324ac9ebde745c031c0d2f92cae2ce9bcddf02`; LLP 0000 git-blob `a74dea6986b501117f330bdd2327ff503923a8e9`; LLP 0002 git-blob `e10f490f0e25b93992295ef957923e759d643e14`; LLP 0014 git-blob `39d5f59cce8b23697df81d456e56c8d17d7de062`; LLP 0028 git-blob `095940436b53d9c839025a379bbc0a8ee0cbb97e`; LLP 0029 git-blob `ad717b9578a650577be4b6177243126f56edb167`; LLP 0047 git-blob `7af5eccc60142b40ef785d9c2bf2ca25df022d5b`; LLP 0048 git-blob `0a8152604b1c27d45be9fb1141e12b8387788404`
**Prompt:** Perform a final reconciliation review of the exact current blobs against every Round 2 finding, both implementations, the governing LLPs, Snapback LLP 0062, and tickets 0062-07/0062-08. Identify only text defects, not honestly open implementation gaps; give per-document and overall readiness and assess the unchanged ticket condition.
**Verdict:** READY

### Prior-finding reconciliation

The reviewer independently confirmed every Round 2 material and minor finding
resolved and verified the companion amendments, implementation-gap honesty,
non-sandbox boundary, acyclic release/evidence chain, and unchanged ticket
condition.

### New minor findings

1. **MINOR — Function ids can consume the fixed frame reserve.** A maximally
   escaped 512-byte function id plus the frame envelope can exceed the 1,024-
   byte reserve used for argument preflight. Constrain ids or preflight the
   complete encoded frame and refuse an offending surface at admission.
2. **MINOR — Acceptance grace shorthand is too broad.** §11 says grace refuses
   timer work, while §6 correctly permits a previously registered timer to
   fire. Say grace refuses new broker operations and timer registrations.
3. **MINOR — Envelope-establishment timeout has no explicit limits owner.**
   State which `LimitsV1` value bounds the initial envelope fetch.

### Verdicts and ticket

- **LLP 0000, 0002, 0014, 0028, 0029, 0047, and 0048:** READY
- **Overall cluster:** READY

Landing and recording the reviewed documents satisfies 0062-07's documentation
condition. The new contract and target evidence remain explicitly unimplemented
and are owned by 0062-08.

## Round 4 — 2026-08-03 (minor-finding delta review)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** `claude -p --model claude-fable-5 --effort xhigh --permission-mode dontAsk --tools Read,Grep,Glob,Bash --no-session-persistence`, Claude Code 2.1.220
**Date:** 2026-08-03
**Redacted:** no (repository content only; no secrets present)
**Method:** fresh-context, read-only CLI delta review; no files edited by the reviewer
**Access note:** Bash was denied in this permission mode, so the reviewer inspected the working-tree files matching the supplied content rather than independently recomputing hashes or checks.
**Revision reviewed:** LLP 0014 git-blob `f3be1a003cba55cf413eecdd3a120359844617fd`; LLP 0048 git-blob `e612348c93b0a55851259e8c2466cb6f77f88cba`
**Prompt:** Verify only the five Round 3 minor reconciliations: computed-import grant wording, the complete function-id/frame reserve proof and failure owner, grace/timer wording, envelope-fetch limit ownership, and the closed Catalog V2 advertisement descriptor. Report regressions and whether the Round 3 READY verdict still holds.
**Verdict:** READY

### Findings and verdict

- **MATERIAL:** none
- **MINOR:** none
- **Delta:** READY
- **Overall cluster:** READY; Round 3 READY still holds

The reviewer verified all five fixes. It noted only two non-blocking hygiene
observations outside the requested delta: a pre-existing builtin-fence shorthand
elsewhere in LLP 0014 and the fact that LLP 0014's header summarizes the larger
attribution correction rather than itemizing this sentence-level edit.
