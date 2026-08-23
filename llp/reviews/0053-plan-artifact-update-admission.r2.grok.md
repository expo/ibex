# Review artifact: ibex LLP 0053 — Plan-Artifact Update Admission (family: grok)

Single blind cross-family review round on Draft r2, ordered by Charlie Cheever
before the acceptance decision. One review; recorded verbatim.

## Round 1 (r2) — 2026-08-23

**Round record (persisted with the artifact):**

- Target: `llp/0053-plan-artifact-update-admission.rfc.md` Draft r2.
- Capsule: branch `agent/update-admission-llp` @ commit `62e8ae6aa`.
- Target sha256: `65a31f8f6403f867cde8abb0636922c309cbcdaeab7ad551f934ca973ab2d313`
- Reviewer: grok `grok-4.6` @ xhigh, headless
  (`grok --prompt-file … --model grok-4.6 --effort xhigh --output-format plain`),
  single-shot, run from an isolated scratchpad directory containing only the
  prompt file — blind to `llp/reviews/`, to the r1→r2 gpt-5.6-sol pass, and to
  the rest of both repos.
- Method: full r2 document text inlined in one prompt, followed by the cited
  law: ibex LLP 0052 (full), 0042 (full), 0038 (full), 0012 (full), 0010
  (full), 0030 (lines 1–107), 0029 (Non-goals excerpt), 0021 (ArmedSnapshot
  excerpt, lines 1330–1375), and Exact LLP 0553 excerpts (§3 spine, §4 L-E,
  §9 D6). Adversarial brief: (a) admission-predicate bypasses
  (ordering/TOCTOU/partial-set/downgrade/epoch-rollback/revert abuse),
  (b) trust-boundary errors, (c) consistency with the cited law, (d) refusal-set
  totality, (e) weakening-grade underspecification. Mandatory verdict line.
- Prompt sha256: `b57de1c8c55429c07b6802b631261d837dad3291ee371d9f180e5501880ee176`
- Review body sha256 (verbatim capture below, leading narration included):
  `cb7d2be1fe57e3a2c813dd79ea1a96de2f07c6ab7775bd18a7ac0e3909b319f6`
- Orchestrator (Claude, Fable 5) neither reviewed nor revised the document;
  its spot-verification of the review's decisive claims is appended after the
  verbatim body, clearly separated.

**Verdict: NOT READY** (6 MATERIAL findings; verbatim below).

---

I'll start by reading the full review request and the target RFC so every finding can be grounded in the actual text.The prompt was truncated mid-excerpt. I’ll read the rest of the cited law and any remaining RFC text before writing findings.The RFC is a serious admission-law draft: digest-only full-set units, host-only presentation, a signed kind/audience join, a producer trust store that is correctly *not* LLP 0052’s device key, and a forward-only artifact epoch are the right bones. It is not yet sound as law. The load-bearing activation step is an open question rather than a construction; revert is a weaker predicate than admission and can arm content check 6 would refuse; the “structural” production/development split has no schema or kind to enforce it and cannot serve Exact 0553 L-E’s re-arm; composition with LLP 0052’s snapshot projection and §6 epoch anchor is wrong; and several declared coordinates and revert failures have no check, no code, or an ambiguous one. Two implementers could both claim this draft while only one is safe.

## MATERIAL FINDINGS

**1. Check 7 mints a new CapSec root without a construction, then asks to be adopted while the binding shape is still an open question.**

- **RFC:** §3 D3 check 7; §9 Q1; Related (admitted-update binding as a new `ArmedSnapshot` field); D6 r4 (contrast); Summary “generation-fenced activation”.
- **Law:** LLP 0042 production commitment (authenticated field, cache never authenticates itself, re-verify at use); LLP 0021 excerpt (`ArmedSnapshot` as the ingested authority root); LLP 0052 §3 stable durable-authority projection (closed classified top-level set; `preparedGraphs` already listed; “Any new or unclassified armed-snapshot field makes durable mint/verify unavailable until this projection is versioned”).
- **Unsoundness:** Admission becomes live only by taking “a **new `ArmedSnapshot`** whose artifact binding references the admitted unit”, called “the LLP 0042 pattern”, while §9 Q1 still has not chosen a new snapshot field versus a separate record. Check 3 hashes once, then checks 4–6 do not re-hash, and only the *revert* path (D6 r4) says retained bytes are never trusted from storage. A conforming implementer can therefore bind a path, skip re-verify at the fence, and activate bytes that are not the bytes that passed check 3 (classic hash-then-use TOCTOU). The same check also does not say which snapshot fields are copied from the install snapshot and which are rebuilt from admitted plan bytes. Reading “**regenerate-policy-and-restart**” together with Exact 0553 §3.1/§3.4 (patches may carry capability declarations; that class is authority drift) allows the producer key to widen CapSec policy on device. Reading “artifact binding” narrowly freezes policy and then 0553’s restart class has no ibex meaning. Either reading, a new snapshot top-level field that is not classified in LLP 0052 §3 makes durable mint/verify unavailable, or—if left out of the projection—leaves durable leases valid across an application replacement.
- **Fix:** Close Q1 as a §10 obligation, not an open question. Require: retained descriptors; digest-only binding (never a path); re-hash of every live byte at the fence before the new snapshot is published; an explicit snapshot recipe (copied vs replaced fields, including policy); 0021 validation on the result; and a 0052 projection amendment that classifies the new field as included (OTA must invalidate durable authority).

**2. Revert is a weaker predicate than admission and can activate content §3 would refuse today.**

- **RFC:** §6 D6 opening (“a revert is a re-arm, not an admission”); revert predicate r1–r6; r5 = “§3 checks 4–5”; automatic reverts run r3–r6 only.
- **Attack:** Check 6’s `minimumRuntime` is not in r1–r6. Concrete sequence: admit unit A with `minimumRuntime` = this binary; later the native binary is replaced with an older one (store rollback, sideload, backup of the app binary) while the retained unit and its binding remain; a directed `revert-directive` or the N=2 health fallback re-arms A. §3 check 6 would return `runtime-below-minimum`; revert will not. r5 only contemplated a *newer* binary dropping format/edition support, not a runtime that no longer satisfies the target’s own minimum. Same hole if a successor was admitted for a newer runtime and health-fallback lands on a retained unit whose minimum the current binary fails.
- **Fix:** Revert r5 must re-run the whole compatibility half of check 6 (`minimumRuntime` against the live LLP 0012 operand), not only checks 4–5. Keep epoch non-regression as an admission-only mark; do not skip runtime/format/edition.

**3. Production/development separation is prose, not structure, and cannot serve Exact 0553 L-E as specified.**

- **RFC:** §5 D5 “structural separation”; “in the shape of LLP 0042’s development commitment”; “a production envelope never rides a development credential and a development artifact never becomes the boot authority”; §1 (this document is L-E’s re-arm admission law); §3 check 2 (kinds are only `update-unit` and `revert-directive`); §8 (patch-granular HMR is 0553’s).
- **Law:** LLP 0042 design principle 3 and “Visible non-production”: distinct schema id, distinct digest domain, `workflow: "development"`, production admission refuses the dev schema *structurally*; `ArmedSnapshot::load` rejects the dev schema in `preparedGraphs`. Exact 0553 §4 L-E: embedded reload carries *plan patches with receipts*; “the restart class joins the host’s re-arm/boot path”. 0553 §3.1: that class is `regenerate-policy-and-restart`.
- **Unsoundness:** 0042’s never-interchangeable rule is a different *kind*, not a policy comment. 0053 restates it “at update granularity” without a distinct envelope schema, kind, workflow marker, digest domain, or trust-store class. A development-produced unit signed as `update-unit` with a key in the build-time pin set passes checks 1–7 and becomes boot authority. Conversely, if D5 is enforced as written, 0553 L-E cannot re-arm from a session-scoped development credential, which is exactly the credential class D5 assigns to “dev-served content” and 0553’s dev-loop lanes. The two kinds in check 2 do not encode this axis. LLP 0038 is correctly called an independent axis, but it is not a substitute for a structural update-class split.
- **Fix:** Give production and development update credentials distinct schema/kind/workflow (0042’s pattern), distinct trust-store classes, and a hard refuse in both directions. Then state which 0553 L-E restarts are allowed to mint a boot-authority snapshot (release/production envelopes only, or a named development re-arm that cannot outlive the session and cannot remain armed after the producing session dies). Do not claim 0042’s rule has been restated until that exists.

**4. The LLP 0052 §6 composition is not a real interface; snapshot-restore rollback is therefore the default, not an extension.**

- **RFC:** Related (“the §6 rollback-resistant epoch-anchor construction this RFC composes with where present”); §3 D3 check 6 (“Where a rollback-resistant external anchor of LLP 0052 §6’s class is available, the record MUST additionally bind to it”).
- **Law:** LLP 0052 §6 is a *per-operation* freshness epoch of the durable-authority facility, advanced under that facility’s lock to allocate `sealSequence` nonces for §5 GCM-SIV. It is not a published bind-a-foreign-record API. 0052 §3’s portable replay defense is `operationId` consumption, which 0053 does not use.
- **Attack / unsoundness:** There is no specified way to “bind” the plan-update high-water to that anchor. Sharing the counter would collide with durable-authority nonce allocation. Ignoring it is allowed whenever the implementer treats the anchor as “not available” (0052 §9 still lists the construction as unproven on every target). Absent a real anchor, a filesystem/journal restore rolls the high-water back and replays a previously admitted envelope (the textbook OTA rollback). The draft is honest that `anchor: none` claims no restore resistance, then still writes a MUST-bind to a facility that cannot accept the bind. Check 6’s claim that the epoch store “adds no new trust assumption” because it shares the armed-snapshot protection class is also only true for the *writable* post-OTA snapshot; the 0029 packaged baseline is not in that class.
- **Fix:** Either specify a 0053-owned rollback-resistant high-water (separate namespace, construction, and unavailability semantics) and drop the 0052 §6 citation, or add a real 0052 amendment that exports a named foreign-anchor namespace. “Where available” must be a platform predicate, not an implementer choice. Genesis values for `updateEpoch` and `directiveEpoch` need to be defined in the same construction.

**5. Declared coordinates and the revert path are not total in the predicate or in §4.**

- **RFC:** §2 D1 (pinned-format companion digests as “operands of §3’s predicate”; `minimumRuntime` grammar owned here); §3 checks 3–6 (no companion-register comparison; check 5 is binary compatible/incompatible); §4 D4 table; §6 D6 r2 (`directiveEpoch`), r3 (target lookup), baseline r4 terminal failure; Exact 0553 §3.2 (0485 §12.1.2 = `equal | compatible-widening | reset`).
- **Unsoundness:**
  - D1’s companion pinned-format digests (e.g. EXWF schema digest) are never evaluated in checks 1–7 and have no refusal code. A unit can close over bytes the runtime’s companion register does not support and still admit.
  - Check 5 cites Exact 0485 §12.1.2, whose outcomes in the 0553 excerpt are ternary. `reset` (and possibly `compatible-widening`) is not mapped to admit or refuse; two implementers can diverge.
  - `epoch-regression` is defined as “`updateEpoch` ≤ the recorded high-water”. A stale `directiveEpoch` does not match that meaning. r3 “target not resolvable” and “embedded baseline failing r4” have no code; they become `admission-internal` or, worse, a borrowed `unit-incomplete`/`digest-mismatch`. Fail-closed non-admission holds only because of the catch-all, not because the typed set is total. Exact 0553 §3.1 then maps *unclassified* refusals to `full-reload-current-authority`, which is not 0053’s `keep-last-good`.
- **Fix:** Add an explicit check (and code, e.g. `companion-format-unsupported`) for every D1 coordinate that is an operand. Map every 0485 §12.1.2 outcome. Add `directive-epoch-regression` and `revert-target-unavailable` (terminal vs fall-through). Publish a total map from D4 codes (and revert codes) to 0553 §3.1 classes. Put the `PlanUpdateUnitV1` manifest schema, digest algorithm/domain, uniqueness of `(kind, digest)`, and integer/epoch bounds in §10; they are load-bearing and are not obligation 1 (envelope framing only).

**6. “Atomically with admission” is not a construction, so epoch and the live binding can fork.**

- **RFC:** §3 D3 check 6 (“transitions atomically with admission”); check 7 (activation is a later fence); §4 `activation-unavailable`; §6 (epoch never decreases, including across revert).
- **Law:** LLP 0052 §4 steps 5–6 (one guard from last read through epoch advance and commit; “a separate before/after check is not sufficient”) is the corpus’s example of what “atomic” has to look like. 0053 cites 0052’s rule set for the envelope, not for this commit.
- **Attack:** Crash or power loss after high-water advance and before the check 7 snapshot commits spends the epoch; the signed unit can never be retried (`epoch-regression`) and the device stays on the previous content until a higher epoch appears (availability). The reverse order—new snapshot live, high-water still old—lets a second producer-signed unit with the *same* `updateEpoch` replace the first in the window (sibling-epoch swap). Two files plus a comment “atomically” lets both a transactional implementer and a forking one claim D3.
- **Fix:** Specify one linearizable commit (single guard covering epoch, admitted-update binding, retention of the previous unit, and receipt), with crash states named and fail-closed. Do not advance `updateEpoch` until the fence that makes the unit the boot authority has committed, or stage a verified-but-not-live record that is not an epoch spend.

## MINOR / QUESTIONS

1. **LLP 0038 characterization (§5 D5).** 0038 does not “bypass target advertisement only”: it also raises the synthesized root ceiling to the project subtree (and `insecure` turns enforcement off). The conclusion that 0038 is not this RFC’s production/development split is still right.

2. **§10 obligation 4 is diagnostic, not adversarial.** “Refusal-shape twins” and golden receipts will not catch mix-and-match, path TOCTOU, epoch restore, or a development credential in the production pin set. LLP 0042 named a self-consistent substitution gate; this RFC should too.

3. **Check 2 lists `kind` with header protected fields.** LLP 0052 §3 puts `kind` in the certificate, not the header, and allows lookup-before-auth only for record selection. Obligation 1/3 should copy 0052’s “never select HMAC from the message”, keyId uniqueness, and algorithm-pin rules verbatim so a sibling store cannot reintroduce them.

4. **LLP 0012 as check 6 operand.** 0012’s surface is JS-visible (`process.versions`, facade keys under Bun compat). Obligation 2 must name a native, JS-unwritable field. QUESTION: which 0012 field is the operand, and does `--compat=bun` change it?

5. **Health default (D6, §9 Q2).** `N = 2` failures to reach *arming-commit* makes a pre-commit crash loop a silent downgrade to retained content. After arming-commit, crash loops do not fall back at all. Both are currently lawful.

6. **No envelope expiry / operationId.** Replay defense is epoch-only. A stolen producer key that pre-signed a stack of epochs is a stacked-update oracle until the pin set changes, and pin-set changes are a binary update (§8). QUESTION: are `update-unit` and `revert-directive` required to use distinct keys (0052: one `keyId` maps to at most one kind)?

7. **Check 6 internal order** between `minimumRuntime` and `updateEpoch` is unspecified, so the first-failure code for a unit that fails both is implementer-defined.

8. **QUESTION (0029 excerpt).** The provided 0029 Non-goals confirm self-update is out of 0029’s scope; they do not contain “immutable embedded bytes” or “release pins”. Is the 0053 baseline the live package payload (store update replaces it) or a first-run disk snapshot that D6 then forbids overwriting?

9. **QUESTION (0553 excerpt).** D7 says Exact 0553 D6 “depends on this RFC existing and names it”. The excerpted D6/L-E text does not name LLP 0053. Is that claim in an elided sentence, or is it 0053’s gloss?

10. **QUESTION (0048, not excerpted).** Check 1 analogizes “trusted-embedder standing LLP 0048 requires of its parent”. Cannot verify from the supplied law.

11. **QUESTION.** If the embedder’s delivery path is JS `fetch` → staging dir → host present, is that “no admission input is JS-authored” (D5), or is authorship only about the envelope’s signer and check 1 attribution?

12. **QUESTION.** Does automatic health revert retain only the immediately previous armed unit, and is “retained unit” in a `revert-directive` bound by digest or by role (role-TOCTOU if a successor commits between sign and r3)?

VERDICT: NOT READY

---

## Orchestrator spot-verification (Claude, Fable 5 — not part of the review)

Each decisive claim checked against the actual r2 / law text before reporting
(per the standing verify-reviewer-claims rule). The verbatim body above is
untouched.

- **M1 — VERIFIED.** §3 check 7 + §9 Q1: the snapshot-binding shape is an open
  question, not a §10 obligation; the admit path nowhere requires digest
  re-verification at the boot fence (only revert r4 states "retained bytes are
  never trusted from storage"); and LLP 0052 §3's rule — "Any new or
  unclassified armed-snapshot field makes durable mint/verify unavailable until
  this projection is versioned" — is real text whose interaction the RFC never
  addresses despite proposing exactly such a field.
- **M2 — VERIFIED.** §6 r5 literally re-runs "§3 checks 4–5" only;
  `minimumRuntime` (check 6) is re-evaluated on no revert path, directed or
  automatic.
- **M3 — VERIFIED** as a structural/seam gap: D5's development-session
  credential class has no schema, kind, workflow marker, or trust-store class
  defined or obligated anywhere in the RFC, while §1 claims this document is
  the L-E re-arm's artifact-admission law and no development embedded-reload
  restart has any admission story.
- **M4 — PARTIALLY REFUTED.** The RFC asks for an anchor "of LLP 0052 §6's
  class … never claimed as an 0052 §6 construction" — it does not demand
  0052's facility accept a foreign bind, so "MUST-bind to a facility that
  cannot accept the bind" overstates. The residue stands: "where available" is
  an implementer choice with no platform predicate, and `updateEpoch` /
  `directiveEpoch` genesis values are undefined.
- **M5 — VERIFIED.** D1's companion pinned-format digests are declared
  "operands of §3's predicate" yet no check consumes them and no code covers
  them; the `PlanUpdateUnitV1` manifest schema is load-bearing (check 3
  refuses `manifest-invalid` against it) but is in no §10 obligation; a stale
  `directiveEpoch` and the baseline-fails-r4 terminal refusal map to no
  defined code (`epoch-regression` is defined solely as "updateEpoch ≤
  recorded high-water").
- **M6 — VERIFIED as underspecification, with a caveat.** "Transitions
  atomically with admission" has no commit construction while sibling law
  (0052 §4 step 5: one guard from last read through epoch advance and commit,
  "a separate before/after check is not sufficient") shows the corpus
  standard; the reverse-order sibling-epoch-swap window is real. Caveat: the
  crash-after-epoch-advance "unit can never be retried" half is partially
  deliberate per §6 ("a failed unit (same epoch) can never be re-presented,
  while a fixed successor (higher epoch) can") — an availability cost the RFC
  chose, though the crash-state ordering itself is still unconstructed.
- **Minor 1 — VERIFIED.** LLP 0038 makes two changes (synthetic target cells
  AND the root-authority-ceiling raise), so D5's "bypasses target
  advertisement only" is inaccurate as written; the RFC's conclusion (0038 is
  not the dev/production separation) survives.
- **Question 8 — ARTIFACT OF EXCERPTING, not a doc error.** The reviewer saw
  only 0029's Non-goals; the full LLP 0029 does carry the immutable embedded
  namespace (`/app`, line ~914) and release-pinned catalog language
  (lines ~425/585–609), so r2's 0029 characterization is accurate.
- **Question 9 — CONFIRMED INDEPENDENTLY (orchestrator's own finding too).**
  Exact LLP 0553 nowhere names ibex LLP 0053; its §9 D6 exit criteria state no
  dependency on an admission RFC. §7's "depends on this RFC existing and
  names it" is false on the "names it" half, and the Related header's "D6
  blocks on this document existing" is 0053's own assertion, recorded nowhere
  in 0553. (0504 §3 row 54c and
  `issues/20260821-eplan-ota-armed-snapshot-confirmation.md` were verified to
  exist and say what the RFC claims; the "0553 ask 7" pointer has no
  corresponding text in 0553.)
- **Question 10 — CONFIRMED for the RFC.** LLP 0048 (not excerpted to the
  reviewer) does ground its admission in a trusted parent/embedder throughout;
  check 1's analogy is accurate.

Orchestrator's read for the author: M1, M2, and M5 block acceptance as-is —
each is precise and fixable in one revision (fence re-verification + Q1
promoted to a §10 obligation + the 0052 projection interaction named; one
line adding `minimumRuntime` to r5; consuming or demoting the companion
digests, obligating the manifest schema, and completing the code map). M3 and
M6's verified halves belong in the same fold; M4's residue is two sentences.
