# LLP 0037: Public-Surface Authorization Attribution Patterns

**Type:** Decision
**Status:** Accepted (provisional — see Review status)
**Systems:** Security, Runtime, Devtools, Verification
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-23
**Revised:** 2026-07-25 (aligns the promotion aggregate with the accepted D1/D2/D4 open-then-act rule: declared read/write actions must be observed, and the only permitted surplus is an ambient, path-occurrence-bound `fs:list` open traversal; the Rust producer and JavaScript aggregate now enforce the same invariant)
**Revised:** 2026-07-23 (author accepted the recommended rulings on D1/D2/D3)
**Related:** LLP 0021 (capsec registry / WP10 target proof); LLP 0023 (virtual filesystem namespace / staged authorization identity); LLP 0036 (target advertisement completion plan); ENG-24933; ENG-24578

## Review status

The author accepted the recommended rulings on D1, D2, and D3 (2026-07-23) to
unblock the per-family authoring loop, explicitly deferring to the
recommendation rather than adjudicating the security details independently. The
rulings were AI-proposed.

**Code-verified security review, 2026-07-24.** The owed review was performed
against the implementation and recorded at
[`llp/reviews/0037-public-surface-authorization-attribution-patterns.opus.md`](reviews/0037-public-surface-authorization-attribution-patterns.opus.md).
Verdict: **ACCEPT** — no ruling is fail-open for the two landed families
(`fs:read`, `fs:write`); each claim was checked down to syscall ordering. Two
documentation corrections were required and are now applied above: the D4 "inert"
qualification (deferred truncation vs. the deliberate `O_CREAT` empty-file
side effect, LLP 0023 §4.1) and the D2 per-family authoring gate (surplus
`fs:list` must be confirmed a traversal from the observed sequence). The reviewer
is an AI model; whether that discharges the "someone versed in the capsec model"
bar, or a human sign-off is still wanted on top of the code-verified findings,
is the author's call. The specific properties re-examined were:

- **D1:** that `ambient-root` traversal crediting cannot mask an unauthorized
  traversal — i.e. that the root principal's ambient-mount authority genuinely
  covers every path it is credited for, and that the allowance is keyed
  narrowly enough that a non-opening operation can never reach it.
- **D2:** that the `observed ⊇ declared` relaxation, with the traversal-capability
  allowance, cannot let a genuinely undeclared effect (a real capability the
  operation exercises but the edge omits) slip through as a "traversal".
- **D4:** that permitting the open of an operation whose capability is denied is
  genuinely inert (the descriptor confers nothing without the operation
  capability) and not a partial-execution escalation.

D4 was discovered while landing the `fs:read` family (the deny scenario is a
mixed allow-traversal / deny-operation sequence) and is the direct consequence
of D1; the author's acceptance of the recommended rulings is taken to cover it.

## Context

LLP 0036 established that the report-completeness gate (gate 2) blocking target
advertisement is a per-capability-family authoring program: the 18,266 reachable
recipe rows collapse to ~5,325 surfaces across a handful of capability families,
and one probe template per family fans out over every surface in it. Authoring a
family is nearly free; executing its probes on the bound engine and validating
the observed typed decisions is where the real cost lives.

The `fs:read` prototype (LLP 0036 step 2, built end to end on the bound engine
and then reverted) showed that the cost is not the template and not the tokens —
it is a small number of **security-model questions that recur across families**.
The public-surface batch executor
(`src/bin/ibex/engine/capsec_public_builtin_batch.rs`) currently encodes the
authorization shape of the one family authored so far (`fs:list` stat exports),
and any family whose runtime authorization differs trips those assertions. Rather
than rediscover and re-adjudicate the same questions once per family, this
document names the recurring patterns, states the observed evidence, and asks for
a single ruling on each. The rulings then apply mechanically to every remaining
family, converting the pacing bottleneck from per-family review into a one-time
decision.

**This document rules on patterns, not on individual surfaces. Status changes
remain an author decision.**

## Evidence: the observed `readFileSync` sequence

Driving `readFileSync` against the authenticated `/project` fixture file on the
bound engine (root principal, allow scenario) produced a **9-decision** sequence.
Ordered as `stage : capability : decisive stratum`:

| # | stage | cap | decisive stratum | sourceId |
| --- | --- | --- | --- | --- |
| 1 | requested | fs:list | ambient-root | null |
| 2 | requested | fs:list | ambient-root | null |
| 3 | discovery | fs:list | ambient-root | null |
| 4 | requested | fs:list | ambient-root | null |
| 5 | repeat | fs:list | ambient-root | null |
| 6 | commit | fs:read | static-floor | principal.000000.floor.000000 |
| 7 | repeat | fs:list | ambient-root | null |
| 8 | repeat | fs:read | static-floor | principal.000000.floor.000000 |
| 9 | repeat | fs:read | static-floor | principal.000000.floor.000000 |

By contrast, the already-authored `fs:list` stat exports (`statSync`) resolve
every non-discovery decision on the **static floor**; their `fs:list` *is* the
operation. `readFileSync` differs because it **opens** the file (a path
traversal that carries `fs:list`) and then **reads** it (the `fs:read` commit and
its retained repeats). This open-then-act shape is expected to recur for every
capability family whose operation acquires a handle before acting: `fs:write`,
`fs:list`-via-open stream constructors, and the `network` connect/listen
families.

## Decisions requested

### D1 — Ambient-mount authority for traversal decisions

**Observation.** The path-traversal decisions of an open (stages
`requested`/`discovery`/`repeat` carrying `fs:list`) resolve through the root
principal's **ambient-mount** authority (`stratum: ambient-root`,
`sourceId: null`), while the operation's own capability (`fs:read` at `commit`
and its repeats) resolves through the **authored static floor**
(`stratum: static-floor`, `sourceId: principal.000000.floor.*`).

**Question.** Is crediting ambient-mount authority for the traversal half of an
open the intended authorization model, with the operation capability still
gated by the static floor?

**Proposed ruling — YES.** The two-layer split is coherent and not a
fail-open: the root principal legitimately holds ambient authority over the
`/project` mount, so traversing within it is mount-level access; the specific
capability the operation exercises (`fs:read`) is independently and still gated
by the authored floor at commit. A probe validator should therefore accept
`ambient-root` for a decision whose capability is the *traversal* capability of
an open (not the operation's declared capability), and continue to require
`static-floor` for the operation capability itself. The predicate must be narrow
— keyed to traversal decisions of an open-then-act operation — so that families
whose declared capability *is* the traversal (the `fs:list` stat exports) stay on
the static floor.

**Alternative if NO.** Traversal must also cite an explicit floor grant. That
implies the armed floor should enumerate mount-traversal authority per principal,
a broader arming-model change, and every open-then-act family stays residual
until it lands.

### D2 — Declared vs. incidental capabilities in the coverage edge

**Observation.** The runtime observes **two** capabilities for `readFileSync` —
`fs:list` (traversal, during open) and `fs:read` (the read) — but the coverage
edge for `readFileSync` declares only `fs:read`. The batch's
`observed_actions == expected_action_ids` invariant consequently fails, because
observed `{fs:list, fs:read}` is a proper superset of declared `{fs:read}`.

**Question.** Should an operation's coverage edge declare every capability it
authorizes through (here `fs:list` + `fs:read`), or is the traversal capability
*incidental infrastructure* that the completeness invariant should tolerate as a
superset of the declared operation capability?

**Proposed ruling — incidental; relax the invariant to a superset with a
named allowance.** Declaring traversal capabilities on every path-taking
operation's edge would inflate the coverage model with infrastructure effects
and diverge the edge from the operation's *semantic* action, which is what the
registry is meant to name. Instead, the completeness invariant should require
`observed_actions ⊇ declared_actions` and that every *extra* observed capability
be a recognized **traversal capability** (e.g. `fs:list` for an fs open),
credited under D1. Anything observed that is neither declared nor a sanctioned
traversal capability remains a hard failure. This keeps the coverage edge
semantically honest while accepting the real, benign traversal effects.

**Alternative if declare.** Each path-taking operation's edge is amended to
enumerate its traversal capabilities. This is a large, cascading registry change
(coverage edges feed target cells, dispositions, and digests) and must be a
reviewed corpus-wide pass, not a per-family edit.

**Per-family authoring gate (from the code-verified review, 2026-07-24).** The
implemented allowance keys on the capability *identity* of the surplus effect
(`extra == "fs:list"`), not on its being *structurally* a traversal. For the
landed families this is safe — the pinned observed sequence shows `fs:list` only
at open stages, never as an operation — but the relaxation is a template for
every open-then-act family. Before pinning a new family, confirm **from its
observed sequence** that every surplus `fs:list` occurs at a traversal stage of
an open, not as a genuine directory listing the operation performs. A family
that legitimately lists a directory while declaring only `fs:read`/`fs:write`
must declare that `fs:list`, not inherit the traversal allowance. This
confirmation is an authoring-loop gate in LLP 0036, not an assumption carried
by the pattern.

### D3 — Observed typed sequences are pinned from a run, never authored by hand

**Observation.** `readFileSync`'s 9-decision sequence
(`requested, requested, discovery, requested, repeat, commit, repeat, repeat,
repeat`) cannot be predicted from the export name or from the `fs:list` stat
shape; a first-principles guess of 4 was wrong. Only executing the probe on the
bound engine reveals it.

**Question.** Is it acceptable for a family template to pin
`expectedTypedDecisionCount` / `expectedTypedStages` to the sequence *observed*
from a bound-engine batch run, recorded with the run that produced it?

**Proposed ruling — YES, and it is mandatory.** The observed sequence is the
evidence; a hand-authored sequence is a guess that either fails closed (harmless
but blocks) or, worse, is loosened to pass. Every family's pinned sequence must
be captured from an actual batch run and re-pinned whenever the engine or the
authorization model changes. The batch already reports the real sequence on
mismatch, so the authoring loop is: author template → run batch → pin observed
sequence → regenerate → confirm green.

### D4 — The deny shape of an open-then-act operation

**Observation.** When the `deny` scenario refuses `readFileSync`'s `fs:read`
capability, the open still succeeds: the `fs:list` traversal decisions are
**allowed** (ambient-mount authority, per D1) and only the terminal `fs:read`
commit is **denied** (`principal-denial`). The observed deny sequence is
therefore a 6-decision open chain ending at the refused commit
(`requested, requested, discovery, requested, repeat, commit`), not the uniform
single-deny of a direct operation such as a stat, whose one list request is
refused immediately. A probe validator that assumes every decision in a deny
scenario is refused fails on the allowed traversal decisions.

**Question.** Is it correct that denying an open-then-act operation's capability
still permits the ambient traversal (the file is opened but not read/written),
so the deny scenario is a mixed allow-traversal / deny-operation sequence?

**Proposed ruling — YES; it is the direct consequence of D1.** If traversal is
ambient-mount authority (D1), it is available to the root principal regardless of
whether the *operation* capability is granted; denying `fs:read` removes the
read, not the mount access. The opened descriptor confers no *operation* without
the operation capability, so permitting the open is not a partial-execution
escalation of the operation itself. The validator must therefore evaluate outcome
and stratum **per decision** — a traversal decision is always
`allow`/`ambient-root`, the operation decision reflects the scenario
(`allow`/`static-floor` or `deny`/`principal-denial`). This is exactly the
generalization landed in `capsec_public_builtin_batch.rs`. If ruled the other
way (a denied operation must also refuse the open), the engine's open-before-act
behavior would itself be the defect, a runtime change well outside this document.

**Qualification on "inert" (from the code-verified review, 2026-07-24).** "Inert"
is precise for the *destructive* effect that matters and slightly overstated for
creation. For `writeFileSync` (`O_WRONLY | O_CREAT | O_TRUNC`), the engine
deliberately **preauthorizes creation and delays truncation until the operation
capability commits**: `openArmedWriteTarget` in `hermes_runtime_fs.cc` opens,
then authorizes `fs:write`, then — only on success — `ftruncate`s. A denied
`fs:write` therefore **never destroys existing file content**. It can, however,
leave a **newly-created zero-byte file** when the target did not exist, because
`O_CREAT` precedes the commit and the engine intentionally does *not* unlink on
denial (a name-bound rollback could race and delete a different creator's
object — the LLP 0023 §4.1 anti-TOCTOU contract). So the deny shape is
non-destructive to existing objects but is not literally side-effect-free for
`O_CREAT` opens; the bounded creation side effect is an accepted, pre-existing
engine contract, not a defect introduced here.

## Consequences

With D1–D3 ruled, the per-family authoring loop is fully mechanical and needs no
further security adjudication unless a family surfaces an effect that is neither
its declared capability nor a sanctioned traversal capability (which D2 keeps a
hard failure — the one place a genuinely new question would still stop the line).
The batch executor gains two narrow, documented generalizations (traversal
stratum under D1; superset-with-traversal-allowance under D2), authored once and
referenced by `@ref` from this document. The remaining families (`fs:write`,
`fs:list` streams, `network`, `stdio`, `sys`, `process`) and then the other
surface-kinds (native-op, loader, startup, cli, host-abi) become a fan-out that
can be parallelized across agents and engine instances, bounded in wall-clock by
engine-lock contention rather than by review.

If D1 or D2 is ruled the other way, the corresponding open-then-act families stay
residual pending a broader arming-model or coverage-model change, and gate 2's
reachable set shrinks to the operations whose declared capability is their only
observed effect (the direct, non-opening operations) until that larger change
lands.

## Non-goals

- This document does not author any family template or edit the batch executor;
  it authorizes the two generalizations those edits will make.
- It does not change the coverage model or the armed floor; D1/D2's proposed
  rulings are chosen specifically to avoid those larger changes.
- It does not rule on the gate-1 GPU-authority residuals (LLP 0035) or the
  internally-verified invariant scenarios (LLP 0036 step 1), which are settled
  elsewhere.
