# Reviews of LLP 0037 — Public-Surface Authorization Attribution Patterns (Claude/Anthropic family)

Review artifacts for
`llp/0037-public-surface-authorization-attribution-patterns.decision.md`,
recorded per [LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

This round discharges the **independent security review owed** by the document's
own "Review status" section on D1, D2, and D4. It is a *code-verified* review:
each ruling was checked against the implementation it claims to describe, down to
syscall ordering, rather than adjudicated from the prose alone.

**Honesty note.** The reviewer is an AI model (Claude Opus 4.8), not an
independent human versed in the capsec model. This review materially advances
the owed review — every technical claim below is reproducible from the cited
code — but per LLP 0005 the author decides whether an AI code-verified review
discharges the "someone versed in the capsec authorization model" bar, or
whether a human sign-off is still wanted on top of it. The findings are written
so a human can confirm them quickly against the line references.

---

## Round 1 — 2026-07-24

**Provenance**

- **Reviewer family:** Anthropic (Claude)
- **Provider / runtime:** Claude Code, model `claude-opus-4-8`.
- **Method:** static verification against the branch
  `fix/stale-generated-authority-artifacts` (rebased onto `origin/main`).
  Primary sources read: `src/bin/ibex/engine/capsec_public_builtin_batch.rs`
  (the D1/D2/D4 validator generalizations) and `src/engine/hermes_runtime_fs.cc`
  (the engine open/authorize sequencing the rulings describe).
- **Scope:** the three security-relevant rulings the document flags as
  review-owed — D1 (ambient-root traversal crediting), D2 (`observed ⊇ declared`
  relaxation), D4 (open-then-act deny shape). D3 (observed sequences are pinned,
  never hand-authored) is a methodology ruling with no boundary-relaxation and
  is endorsed without qualification.

**Overall verdict: ACCEPT with two required documentation corrections and one
per-family authoring obligation.** No ruling is fail-open as landed for the two
families it covers (`fs:read`/`readFileSync`, `fs:write`/`writeFileSync`). The
corrections matter because these are *reusable patterns* replicated into every
future open-then-act family, so an overstated invariant becomes a latent hole
the first time a family that doesn't fit the pattern is authored against it.

### D1 — Ambient-mount authority for traversal decisions — SOUND

Verified in `capsec_public_builtin_batch.rs`:

- `opens_via_traversal` (l.781) is keyed on the family's *declared* action set
  being exactly `["fs:read"]` or `["fs:write"]`.
- `decision_is_traversal` (l.783–784) additionally requires that *every* effect
  in the specific decision is `fs:list`.
- Only such decisions accept `ambient-root` (l.823–824); everything else stays
  on `static-floor` or, in a deny scenario, `principal-denial`.

The review-status concern was "that the allowance is keyed narrowly enough that
a non-opening operation can never reach it." Confirmed: a stat export
(`statSync`, declared `["fs:list"]`) has `opens_via_traversal == false`, so its
`fs:list` — which *is* its operation — resolves on the static floor, never
ambient-root. The predicate cannot credit ambient-root to an operation whose
declared capability is not an open.

The deeper concern — "that the root principal's ambient-mount authority
genuinely covers every path it is credited for" — is a property of the *engine*,
not this validator (the batch validates the engine's emitted stratum, it does
not decide it). That property holds by two independent bounds established
elsewhere: ambient-root (decision step 15) is gated by the root authority
ceiling (decision step 6), and a traversal outside `/project` is refused at the
VFS mount boundary (`ERR_IBEX_OUTSIDE_MOUNT`) before any capability decision is
produced. So a credited traversal is necessarily in-mount. No change required.

### D2 — Declared vs. incidental capabilities — SOUND for the landed families, with a per-family obligation

Verified (`capsec_public_builtin_batch.rs` l.868–887): declared ⊆ observed is
enforced, and every *extra* observed capability must satisfy
`opens_via_traversal && extra == "fs:list"` — so the only tolerated surplus is
`fs:list`, and only on an fs:read/fs:write family. A genuinely undeclared
*operation* capability (e.g. an unexpected `fs:write` on a read family) is
`extra != "fs:list"` and remains a hard failure. This answers the primary
review-status concern (an undeclared real capability cannot slip through as a
"traversal").

**Finding D2-1 (per-family obligation, not a code defect).** The allowance keys
on capability *identity* (`extra == "fs:list"`), not on the decision being
*structurally* a traversal (same path as the open, non-terminal stage). For
`readFileSync`/`writeFileSync` this is safe because their only `fs:list` is
provably the open-traversal — the pinned observed sequence shows `fs:list` only
at requested/discovery/repeat stages, never as an operation. But the ruling is
explicitly a template for "every capability family whose operation acquires a
handle." A future family that legitimately performs a *real* directory listing
(a true `fs:list` effect) while declaring only `fs:read` would be waved through
as "traversal." **Required:** the per-family authoring checklist (LLP 0036's
loop) must include an explicit confirmation, from the observed sequence, that a
family's only surplus `fs:list` occurs at open/traversal stages — not an
assumption inherited from the pattern. Recommend recording this as an authoring
gate in LLP 0036 and referencing it from D2.

### D3 — Observed sequences pinned, never hand-authored — ENDORSED

No boundary relaxation; it forbids hand-loosening a sequence to pass. This is
the correct discipline and strengthens the other rulings (a pinned sequence is
what makes D1/D4's per-decision expectations falsifiable). No qualification.

### D4 — The deny shape of an open-then-act operation — SOUND on the critical property; "inert" is overstated for writes

This is the ruling that most needed verification, because the document's
evidence is entirely from `readFileSync` (a read-only open) while the code
(l.782) applies the same deny shape to `writeFileSync`, whose open is
`O_WRONLY | O_CREAT | O_TRUNC` (l.4771) — a *destructive* open. If a denied
write still truncated the file, permitting the open would be exactly the
partial-execution escalation D4 claims cannot happen.

**It does not truncate.** Verified in `hermes_runtime_fs.cc`
`openArmedWriteTarget` (l.2200–2244), whose own comment states the invariant —
"Preauthorize creation and delay truncation until the retained target commits":

1. the path is opened (l.2215),
2. `fs:write` is authorized at the commit stage (l.2231–2234), throwing on
   denial,
3. `::ftruncate` runs *only after* that authorization (l.2236).

So a denied `fs:write` never reaches the truncation — an existing file's
contents are preserved. `readFileSync`'s deny path is inert a fortiori: a
read-only open cannot mutate, and `requireFdRead` (l.816) gates `fs:read` before
any bytes are read. The core D4 claim — the operation is refused without
executing — is correct and well-engineered.

**Finding D4-1 (required documentation correction).** "Inert" is nonetheless
overstated for the write family. The `O_CREAT` half of the open runs *before*
the commit authorization, and the code deliberately does **not** unlink on
denial — l.2226 documents why: a name-bound rollback could race and delete a
different creator's object (LLP 0023 §4.1). Consequently a denied
`writeFileSync` against a *non-existent* path can leave a **zero-byte file**.
That is a real, if bounded, filesystem side effect occurring despite the
capability being denied. It is a deliberate, pre-existing engine contract — not
a hole introduced by this ruling — but D4's blanket "the opened descriptor is
inert … permitting the open is not an escalation" should be qualified to:
existing content is never destroyed (truncation is deferred past
authorization), while an `O_CREAT` open may leave an empty file, by the LLP 0023
§4.1 anti-TOCTOU contract. Cite that section from D4.

**Finding D4-2 (minor, optional).** Two definitions of `opens_via_traversal`
coexist: l.781 requires an exact single-element `["fs:read"]`/`["fs:write"]`
declaration, while l.877 accepts any element equal to `fs:read`/`fs:write`. A
family declaring both (`["fs:read","fs:write"]`) would satisfy l.877 (tolerate
an extra `fs:list`) but fail l.781 (its `fs:list` would be scored as a denied
operation in a deny scenario). Both directions fail *closed* (a mismatch breaks
the test rather than authorizing anything), so this is not a security defect,
but the divergence will surface as a confusing red test the first time a
multi-capability open family is authored. Recommend unifying on one predicate.

### Summary of required changes before an advertisement is published on these rulings

1. **D4 doc correction (required):** qualify "inert" to note the deferred
   truncation (existing content safe) and the deliberate empty-file creation on
   `O_CREAT` denial; cite LLP 0023 §4.1.
2. **D2 authoring gate (required for the pattern, not the landed families):**
   record in LLP 0036's per-family loop that a surplus `fs:list` must be
   confirmed from the observed sequence to be open-traversal, not a real listing.
3. **D4-2 predicate unification (optional cleanup):** one definition of
   `opens_via_traversal`.

None of these block the `fs:read`/`fs:write` families as landed; all three are
about keeping the *pattern* honest as it is replicated. With (1) and (2)
applied, this reviewer considers the technical content of the owed security
review discharged; the author decides whether human sign-off is additionally
required.
