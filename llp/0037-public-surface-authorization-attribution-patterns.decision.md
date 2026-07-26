# LLP 0037: Public-Surface Authorization Attribution Patterns

**Type:** Decision
**Status:** Accepted (provisional — see Review status)
**Systems:** Security, Runtime, Devtools, Verification
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-23
**Revised:** 2026-07-25 (`node:fs.opendirSync` binds an empty-directory invocation to exact `__exactReaddir` authority, exact returned path, and mandatory `Dir.closeSync`; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.openSync` binds the exact `r`, `a`, and `r+` branches to read, write, and conjunctive read-write authority; every successful numeric descriptor is closed, file bytes remain unchanged, and fifteen Apple rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.readlinkSync` binds ambient link/target traversal separately from the corrected stored-byte `fs:read` commit and exact translated string; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.mkdirSync` binds absolute non-recursive creation to the reviewed `fs-mkdir:` absent-create chain and exact creation/no-creation postconditions; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.appendFileSync` joins the reviewed open/write family with exact prefix-plus-suffix and deny-no-mutation postconditions; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.truncateSync` binds a six-decision retained-object mutation chain, denies at `fs:write` commit, and proves the exact two-byte postcondition; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.existsSync` binds its swallowed permission denial to both the exact denied `fs:list` decision and an exact boolean `false` public result; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.statfsSync` extends the direct metadata family using an engine-observed six-decision allow sequence and first-request denial; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.realpathSync` binds its exact cwd/lstat auxiliary decisions, allow-path realpath terminal, and fail-closed lstat denial terminal; five Apple fixture rows move from residual to executable)
**Revised:** 2026-07-25 (`node:fs.accessSync` extends the direct metadata family using an engine-observed six-decision allow sequence and first-request denial; five Apple fixture rows move from residual to executable without relaxing route, action, stratum, or result validation)
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

### Additional direct-metadata evidence: `accessSync`

The same authoring loop was applied to `node:fs.accessSync` on the reviewed
Apple engine. Its allow path produces six `fs:list` decisions:
`requested, discovery, requested, repeat, repeat, repeat`. The exact operation
is source-bound to the generated `__exactAccess` coverage edge; requested and
retained-object checks resolve through the authored static floor, while mount
discovery resolves through ambient-root. Denial stops at the first `requested`
decision. The sequence was captured from a deliberately failing bound-engine
batch and then pinned; the completed 150-recipe builtin batch passes without
permitting an auxiliary action or terminal.

### Additional direct-metadata evidence: `statfsSync`

`node:fs.statfsSync` follows the same single-terminal authorization pattern on
the reviewed Apple engine, while retaining its own source-derived
`__exactStatfs` coverage edge. Its allow path produces six `fs:list` decisions:
`requested, discovery, requested, repeat, repeat, repeat`. Requested and repeat
checks resolve through the authored static floor, mount discovery resolves
through ambient-root, and denial stops at the first `requested` decision. A
deliberately failing bound-engine run exposed this sequence before it was
pinned. The complete 160-recipe builtin batch and the independent promotion
validator accept all five scenario observations without allowing another edge,
action, stage, result, or authority stratum.

### Denial-return evidence: `existsSync`

`node:fs.existsSync` deliberately converts filesystem failures into a boolean
result. On the reviewed Apple engine its successful lookup follows the same
six-decision `__exactAccess` sequence as `accessSync` and returns `true`. With
`fs:list` denied, the first requested-stage decision has a
`principal-denial` outcome, `existsSync` catches the resulting filesystem
error, and the public call returns `false`.

The result contract therefore binds both halves of the behavior: denial must
still appear as a typed denied decision on the source-derived
`__exactAccess` edge, and the returned value must be exactly boolean `false`.
An exception, a true result after denial, a false result on the allowed fixture,
or a decision on the route's initialization alternative fails validation. The
complete 165-recipe builtin batch and the independent promotion validator
accept all five scenario observations under that contract.

### Retained-object mutation evidence: `truncateSync`

`node:fs.truncateSync` exercises the armed runtime's direct retained-object
truncate path. On the reviewed Apple engine its allow path emits:

`requested, discovery, requested, repeat` for the ambient `fs:list` traversal
and exact target retention; then `commit, repeat` for `fs:write` on the retained
file.

The commit binds the actual target descriptor, and the final repeat occurs
immediately before `ftruncate`. Denial preserves the four ambient traversal
decisions, refuses the `fs:write` commit, emits no final repeat, and leaves the
fixture unchanged. The native batch independently verifies the filesystem
postcondition: every allowed scenario produces exactly the first two original
bytes, while denial preserves all original bytes. The promotion aggregate
accepts the incidental `fs:list` decisions only under the source-bound
`fs-truncate:` operation identity; they cannot borrow the broader `fs-open:`
allowance used by whole-file read/write carriers. The complete 170-recipe
builtin batch and independent validator accept all five scenario observations.

### Open/write mutation evidence: `appendFileSync`

`node:fs.appendFileSync` uses the reviewed `fs-open:` open-then-act family on
the bound Apple engine. Its allow path emits seven decisions:
`requested, requested, discovery, requested, repeat` for ambient `fs:list`
traversal, followed by `commit, repeat` for floor-gated `fs:write`. Denial stops
at the denied commit and emits no write repeat.

The native batch proves the observable mutation in addition to the decision
sequence. Allowed scenarios preserve the complete known prefix and append the
complete literal suffix; denial preserves the prefix byte-for-byte. The
producer and promotion aggregate both restrict incidental `fs:list` to this
exact reviewed export, declared `fs:write` action, and `fs-open:` operation
identity. The complete 175-recipe builtin batch and independent validator
accept all five real scenario observations.

### Retained-parent creation evidence: `mkdirSync`

`node:fs.mkdirSync` is open only for the non-recursive contract specified by
LLP 0023. The authored invocation passes an absolute `/project` fixture path and
a literal `{recursive: false}` option. Those values physically exclude the
relative-cwd `statSync` preflight and the closed recursive mutation branch even
though both remain conservative alternatives in the source-derived route.

The bound Apple engine emits five decisions for every scenario:
`requested, discovery, requested, requested, discovery`. The first four are
ambient `fs:list` authentication of the requested path and retained parent; the
last discovery-stage decision carries `fs:write` over the exact
`absent-create` occurrence immediately before the single `mkdirat`. Denial
refuses that last decision. The native batch verifies the corresponding
filesystem state: all allowed variants create exactly the expected directory,
while denial leaves it absent. Both the producer and promotion aggregate admit
incidental traversal only for the exact `mkdirSync` / `fs:write` /
`fs-mkdir:` tuple, and the independent validator derives
`native-op:__exactMkdir` from all five real observations. The complete
180-recipe builtin batch passes.

### Link-byte read and translation evidence: `readlinkSync`

`node:fs.readlinkSync` separates two authorities that the prior native
implementation accidentally conflated. Retaining the link and translating its
target are ambient `fs:list` traversal. Reading the stored link bytes is the
declared `fs:read` effect and now commits immediately before the first
`readlinkat`, with a repeat before every buffer-growth retry. The previous
stage-5 / no-read call authorized that disclosure as `fs:list`; the corrected
control denies before any stored byte is read when `fs:read` is absent.

The fixed relative-link fixture yields eight decisions on allow:
`requested, discovery, requested, repeat` for link retention; `commit` for
stored-byte `fs:read`; then `discovery, requested, repeat` for target
translation. Denial stops at the commit after the same four ambient decisions.
Every allowed scenario returns the exact source-owned string
`capsec-readlink-target.txt`; the aggregate rejects a substituted result. The
producer and aggregate restrict traversal surplus to the exact
`readlinkSync` / `fs:read` / `fs-readlink:` tuple, and the complete 185-recipe
batch plus independent validator accept all five real observations with
`native-op:__exactReadlink` as the derived terminal.

### Flag-selected descriptor evidence: `openSync`

`node:fs.openSync` is the first authored public carrier whose literal argument
selects among three capability sets on one native terminal. The fixture uses an
existing exact file with `r` for `fs:read`, `a` for `fs:write`, and `r+` for
the conjunction of `fs:read` and `fs:write`. The final mode deliberately avoids
truncation or creation so the public result can prove authority selection and
descriptor ownership without conflating either with a content mutation.

All three branches emit the same six stages on the bound Apple engine:
`requested, requested, discovery, requested, repeat, commit`. The first five
decisions are ambient `fs:list` traversal under the exact `fs-open:` operation
identity. The commit carries the branch-selected floor effect; `r+` carries two
effects in one conjunctive decision and successful evidence binds one decisive
static-floor row to each effect. A denied conjunction correctly needs only the
single decisive denial row that blocks it. The producer validates both
cardinalities rather than flattening the multi-effect decision to the
single-effect shape.

Every successful invocation must return a number and the harness must close
that exact descriptor before recording
`cleanup: "closed-fs-file-descriptor"`. The independent aggregate exact-checks
the result shape and rejects a missing or substituted cleanup marker. The
native harness also verifies that the fixture bytes are unchanged for every
allowed and denied scenario. Fifteen real effect rows (five scenarios for each
flag branch) are executable in the complete 200-recipe batch; the three
synthetic `branch-selection` rows remain honestly unresolved because no public
runtime input supplies registry branch facts.

### Materialized directory-object evidence: `opendirSync`

`node:fs.opendirSync` builds its `Dir` object by calling `readdirSync` and then
`lstatSync` once per returned entry. The authored fixture is an exact empty
directory. That input physically selects the `__exactReaddir` terminal and
excludes the conservative per-entry `__exactLstat` alternative without erasing
it from the source-derived route.

On the bound Apple engine, allow emits the same seven-stage direct-list
sequence as the existing directory-enumeration fixture:
`requested, discovery, requested, repeat, repeat, repeat, repeat`. Denial stops
at the first requested-stage `fs:list` decision. Because directory listing is
the operation itself rather than incidental traversal, the requested/repeat
checks resolve through the authored static floor; only mount discovery is
ambient.

A successful public result is accepted only when it is an object whose
source-owned `path` is exactly `/project/capsec-directory-fixture` and the
harness calls its `closeSync` method before recording
`cleanup: "closed-fs-directory"`. The aggregate independently requires that
cleanup contract and rejects a missing marker, substituted marker, substituted
path, or an authored recipe that omits cleanup. The native harness also proves
that the directory remains present and empty. The complete 205-recipe batch and
the independent aggregate accept all five real scenario observations, each
deriving `native-op:__exactReaddir`.

### Additional multi-edge metadata evidence: `realpathSync`

`node:fs.realpathSync` demonstrates a distinct public-carrier shape. On the
reviewed Apple engine its allow path produces twelve typed decisions:

`requested, commit` for `path:cwd-observe`; then
`requested, discovery, requested, repeat` for the `fs:list` lstat preflight;
then `requested, discovery, requested, repeat, repeat, repeat` for the
source-derived `fs:list` realpath terminal.

The invocation descriptor authenticates the exact cwd and lstat coverage edges
and their action sets as auxiliaries. The harness excludes those auxiliary
actions and terminals from the operation claim, requires the realpath edge on
allow, and still validates every decision's identity, target cell, stage,
outcome, and decisive stratum. When `fs:list` is denied, execution stops after
the two ambient-root cwd decisions and the requested-stage lstat denial; the
realpath edge is correctly never reached. The descriptor therefore binds lstat
as the one exact fail-closed denial terminal for this public carrier. No other
auxiliary edge or action is accepted. The complete 155-recipe builtin batch
passes with these constraints.

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
