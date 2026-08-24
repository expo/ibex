# Review artifact: ibex LLP 0053 — Plan-Artifact Update Admission, r3 delta pass (family: codex)

Delta-scoped confirmatory pass on Draft r3's fold of the r2 grok round
(`0053-plan-artifact-update-admission.r2.grok.md`), ordered by the
orchestration lane before landing r3. One review; recorded verbatim.

## Delta round (r3 working tree over r2 @ 62e8ae6aa) — 2026-08-23

**Round record (persisted with the artifact):**

- Target: `llp/0053-plan-artifact-update-admission.rfc.md`, r3 working
  tree in the branch worktree (diff base: r2 commit `62e8ae6aa`; review
  artifact commit `5dddfb10a` present).
- Reviewer: codex `gpt-5.6-sol` @ xhigh reasoning, headless
  (`codex exec --sandbox read-only --skip-git-repo-check`), single-shot,
  run in the worktree with the full ibex llp corpus readable.
- Scope: strictly the delta — per-finding resolution of the r2 round's
  M1–M6 + verified minors + Q9, regressions introduced by r3, internal
  consistency of the new text. Design decisions taken deliberately
  (staging-is-not-a-spend, committed-failure epoch cost, reset-admits,
  full-set-only v1) were out of scope by instruction.
- Prompt sha256: `d8b580e449e92c3366ed7a2a90103b1235d270ac022d1040b2f92ef56f17f4d4`
- Verbatim body sha256: `e5e853aee886be00de7a1e14d92460308e6cfc92a7e2324ade7a264f51fa1c30`
- Verdict: **DELTA-FINDINGS** — M2/M4/M6 and minors 1/3/4/5/7/11/12
  RESOLVED; M1/M3/M5, minor 6, and Q9 PARTIAL; four new findings
  (3 MATERIAL, 1 MINOR). Every PARTIAL and new finding was folded into
  the final r3 by the orchestrator the same day (see the r3 revision
  history); the fold-of-the-fold carries no further review round —
  Charlie takes the accept decision on the folded text.

---

codex
- M1 — PARTIAL — r3 adds fence re-hashing, digest-only bindings, snapshot reconstruction, and projection inclusion, but check 7(c)/obligation 4 omit LLP 0052 §6’s registry-generation advance and terminal lease revocation before exposing the changed projection.
- M2 — RESOLVED — r5 now re-runs “§3 checks 4–6(a)” against the live identity, explicitly including `minimumRuntime`.
- M3 — PARTIAL — r3 adds a distinct schema, registry, workflow, digest domain, trust-store class, and session-only posture, but never defines or obligates the development re-arm predicate or authenticated live-session binding.
- M4 — RESOLVED — check 6 defines genesis `0`, makes availability a platform predicate over LLP 0052’s matrix, and requires a separately namespaced anchor through obligation 4.
- M5 — PARTIAL — companion checks, relation outcomes, manifest obligation, new codes, and the class map are present, but §6 r4 is assigned both `digest-mismatch` and `revert-target-unavailable`, leaving the typed result ambiguous.
- M6 — RESOLVED — check 6 makes staging non-spending, while 7(c) specifies one guarded commit with explicit pre-/post-commit crash states and closes sibling-epoch swap.
- Minor 1 — RESOLVED — D5 now accurately says LLP 0038 “substitutes synthesized target advertisement and raises the synthesized root ceiling while retaining the other authenticators.”
- Minor 3 — RESOLVED — obligation 1 now requires correct header/certificate placement plus verification-material selection, key uniqueness, and algorithm-pin rules.
- Minor 4 — RESOLVED — obligation 2 requires an “authenticated, native, JS-unwritable” operand and explicitly excludes `process.versions` and compat-mode variation.
- Minor 5 — RESOLVED — r3 keeps the arming-commit/`N = 2` default explicit and states that a post-commit crash loop “today does not fall back,” with alternatives confined to §9 Q1.
- Minor 6 — PARTIAL — keyId-to-kind uniqueness is now required, but no expiry, `operationId`, equivalent revocation horizon, or distinct-key-material rule prevents stacked future-epoch updates.
- Minor 7 — RESOLVED — check 6 specifies runtime-minimum evaluation first, making the dual-failure result `runtime-below-minimum`.
- Minor 11 — RESOLVED — D5 permits JS-adjacent transport while stating that authority derives only from the signature and native presenter attribution.
- Minor 12 — RESOLVED — v1 retains exactly the immediately previous production unit plus baseline, and both directed and automatic targets are digest-bound.
- Q9 — PARTIAL — r3 correctly says “0553’s own text … does not name it,” but still cites “Exact 0553 §11 ask 7,” for which the recorded spot-verification found no corresponding text.

1. MATERIAL — D2 says admission “never parses plan tables,” while check 7(b), inside the admission predicate, regenerates policy “from the admitted content” and may refuse on LLP 0021 validation; suggested fix: scope D2 to checks 1–6 and define 7(b) as separate arming validation over an enumerated policy projection.
2. MATERIAL — r6 imports admission-specific 7(c), which advances the unit epoch, writes an admission receipt, and retains the previous unit, then substitutes a directive epoch even though automatic reverts have no directive; suggested fix: specify a separate revert commit, including 7(b), with no epoch change for automatic reverts and no retention of the failed unit.
3. MINOR — §6 r4 produces both `digest-mismatch` and `revert-target-unavailable`, contradicting the closed deterministic refusal set; suggested fix: reserve `revert-target-unavailable` for r3 lookup failure and use `digest-mismatch` for r4, with terminal baseline failure represented separately.
4. MATERIAL — check 7(c)’s atomic tuple omits LLP 0052 §6’s required registry-generation advance, lease revocation, and cancellation before publishing a changed durable-authority projection; suggested fix: add those conditional durable-facility mutations to the same guard and obligation 4.

DELTA-FINDINGS
tokens used
130,224
- M1 — PARTIAL — r3 adds fence re-hashing, digest-only bindings, snapshot reconstruction, and projection inclusion, but check 7(c)/obligation 4 omit LLP 0052 §6’s registry-generation advance and terminal lease revocation before exposing the changed projection.
- M2 — RESOLVED — r5 now re-runs “§3 checks 4–6(a)” against the live identity, explicitly including `minimumRuntime`.
- M3 — PARTIAL — r3 adds a distinct schema, registry, workflow, digest domain, trust-store class, and session-only posture, but never defines or obligates the development re-arm predicate or authenticated live-session binding.
- M4 — RESOLVED — check 6 defines genesis `0`, makes availability a platform predicate over LLP 0052’s matrix, and requires a separately namespaced anchor through obligation 4.
- M5 — PARTIAL — companion checks, relation outcomes, manifest obligation, new codes, and the class map are present, but §6 r4 is assigned both `digest-mismatch` and `revert-target-unavailable`, leaving the typed result ambiguous.
- M6 — RESOLVED — check 6 makes staging non-spending, while 7(c) specifies one guarded commit with explicit pre-/post-commit crash states and closes sibling-epoch swap.
- Minor 1 — RESOLVED — D5 now accurately says LLP 0038 “substitutes synthesized target advertisement and raises the synthesized root ceiling while retaining the other authenticators.”
- Minor 3 — RESOLVED — obligation 1 now requires correct header/certificate placement plus verification-material selection, key uniqueness, and algorithm-pin rules.
- Minor 4 — RESOLVED — obligation 2 requires an “authenticated, native, JS-unwritable” operand and explicitly excludes `process.versions` and compat-mode variation.
- Minor 5 — RESOLVED — r3 keeps the arming-commit/`N = 2` default explicit and states that a post-commit crash loop “today does not fall back,” with alternatives confined to §9 Q1.
- Minor 6 — PARTIAL — keyId-to-kind uniqueness is now required, but no expiry, `operationId`, equivalent revocation horizon, or distinct-key-material rule prevents stacked future-epoch updates.
- Minor 7 — RESOLVED — check 6 specifies runtime-minimum evaluation first, making the dual-failure result `runtime-below-minimum`.
- Minor 11 — RESOLVED — D5 permits JS-adjacent transport while stating that authority derives only from the signature and native presenter attribution.
- Minor 12 — RESOLVED — v1 retains exactly the immediately previous production unit plus baseline, and both directed and automatic targets are digest-bound.
- Q9 — PARTIAL — r3 correctly says “0553’s own text … does not name it,” but still cites “Exact 0553 §11 ask 7,” for which the recorded spot-verification found no corresponding text.

1. MATERIAL — D2 says admission “never parses plan tables,” while check 7(b), inside the admission predicate, regenerates policy “from the admitted content” and may refuse on LLP 0021 validation; suggested fix: scope D2 to checks 1–6 and define 7(b) as separate arming validation over an enumerated policy projection.
2. MATERIAL — r6 imports admission-specific 7(c), which advances the unit epoch, writes an admission receipt, and retains the previous unit, then substitutes a directive epoch even though automatic reverts have no directive; suggested fix: specify a separate revert commit, including 7(b), with no epoch change for automatic reverts and no retention of the failed unit.
3. MINOR — §6 r4 produces both `digest-mismatch` and `revert-target-unavailable`, contradicting the closed deterministic refusal set; suggested fix: reserve `revert-target-unavailable` for r3 lookup failure and use `digest-mismatch` for r4, with terminal baseline failure represented separately.
4. MATERIAL — check 7(c)’s atomic tuple omits LLP 0052 §6’s required registry-generation advance, lease revocation, and cancellation before publishing a changed durable-authority projection; suggested fix: add those conditional durable-facility mutations to the same guard and obligation 4.

DELTA-FINDINGS
