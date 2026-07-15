# LLP 0024: Structured Evaluation and Session Semantics

**Type:** Spec
**Status:** Draft
**Systems:** Runtime, Engine, Module Loader, REPL
**Author:** Charlie Cheever / Claude / Codex
**Date:** 2026-07-12
**Revised:** 2026-07-15 (ENG-25065 defined runner-backed session cache identity per execution generation while preserving legacy retry behavior); 2026-07-15 (ENG-25063 reconciled dependency-level TLA through the
separate authenticated LLP 0026 runner while preserving the legacy session
loader's entry-only refusal)
**Revised:** 2026-07-12 (round-7 terminal two-family review — the last round of the
four-document effort, closed under the human's bounded endgame authorization as a minimal
pass; the document finishes **Draft**, not both-families-READY, matching all three siblings.
Both families verified the revision empirically and Fable stated it **could not construct the
next §7 algorithm defect** of the prior rounds' class — the first round the core algorithm
survived an adversarial pass. This pass: closed the **`function`-declaration laundering** of
the restricted-global predicate (`function` over a pre-existing own property no longer enters
`[[SessionCreatedVars]]`, so a later `let` stays restricted — ENG-24463-adjacent); made
**phase 5 a cancellation critical section** (Codex found "no user code" ≠ "uninterruptible");
made rollback **commit per-cell at `InitializeBinding`** (destructuring); retracted the
credential "circular" claim and adopted LLP 0022's single **`SubmissionCredential`**
vocabulary; corrected the stale round-6 revision **note** that credited a retired sequence-
range mechanism; fixed **OQ8**'s false "constants file exists"; narrowed **deviation (d)**'s
leak claim to the channels that actually leak (values + existence, not descriptors/
enumeration); scoped **module identity** to equal `SourceId` per LLP 0023; made **`require()`**
call-time transitive; split the **§9** async-failure envelope across the process boundary;
completed the **noun sweep** (handle→token at §1, identity→label, snapshot→capture/copied,
TLA control token→settlement sentinel, epoch wording); removed a **stale `$_` acceptance
criterion**; and **added a delegated-obligations ledger** whose most security-consequential
row is **`OBL-COMPARTMENT-BASELINE` (LLP 0013, = ENG-24463)** — the real fix for the live
session-`var` disclosure channel. Items needing a generated/executed artifact — the executable
model, the parser prototype, the ABI amendment — are **ledgered, not hand-written**. Previously
2026-07-12 for round 6: `[[SessionCreatedVars]]` — the
provenance set the round-5 note *described* but a silent replace never *landed* in the
predicate — is now defined in §7.1, populated by a matrix column, and is the actual key of
the restricted-global predicate, closing the `var undefined ⏎ let undefined` laundering that
had reopened. Rollback is restated as **one rule — commit iff the binding reached
initialization** — which resolves the AC12 self-contradiction (`let x = 1; throw` leaves
`x = 1`, an initialized lexical surviving like a `var`) and the cross-record displaced-cell
case (a `var` that commits does not get a dead `let` restored under it). Phase 5 re-checks
the **full** feasibility vector (lexical restrictions included) over **values materialized in
phase 4**, so CJS export Gets cannot run user code after the re-check. The **phase-4 microtask**
question is answered (no checkpoint in phases 1–5; import-queued jobs are background). Deviation
(d) now states its **residual leak** — sloppy and adopted-and-assigned spellings still forward,
and the complete fix is a compartment baseline, not a withhold list. `$_` ABA detection is
**honestly bounded** (exact-descriptor restoration is undetectable without a native counter).
The gates are **four**, with gate 2b's fresh-realm harness and owner-authored quirk-filter
pinned and the completion channel folded by `UpdateEmpty`. **"epoch"** is named as the fifth
noun-reuse casualty and **"unit"** split (work unit vs settlement unit); the §9 allocator
aligns the §9 sequence allocator with LLP 0025 on **at-receipt** numbering (both documents retired the worker-draws-ranges idea — a hostile worker can reorder within a range); and the *source label* sweep
is completed. Previously 2026-07-12 for round 5: **phase 5 now re-checks
`CanDeclareGlobal*` immediately before mutating** — the round-4 reorder moved the
interference window rather than closing it, since imports run arbitrary user code that can
invalidate phase 3's answers; because instantiation itself runs no user code, recheck-then-
mutate is atomic with **zero engine support**. The restricted-global predicate is re-keyed on
**provenance** (`[[SessionCreatedVars]]`), closing a laundering path in which `var undefined`
adopted the property and thereby admitted `let undefined`. §3's stale "imports run during
instantiation, bindings roll back" text is retired — it survived a full round after §7.3
removed its premise, which is itself the lesson now recorded in §3. Deviation (c) narrows to
**uninitialized** lexicals (an initialized `let x = 1; boom()` survives, like the neighbouring
`var`, matching Node and Deno). Deviation (d)'s package sub-case is corrected to the **truth**:
the shipping compartment is a forwarding Proxy, so packages *do* see session `var`s today —
a disclosure channel this design creates, now stated with the requirement that closes it.
§2 adopts LLP 0023's **SourceLabel** vocabulary and names **"handle"** as the fourth
noun-reuse casualty; the submission credential becomes **two affine capabilities**, closing a
circularity for `.load`; §6 gains native **unit publication** and a named **sequence-allocator
owner**; §4's source-map inventory becomes **generated** after a hand-written one both invented
a dead stage and missed two live ones; and **gate 2b** validates the model against real Script
semantics, because an engine-relative oracle is blind to a wrong model of ECMAScript in rows
the engine itself gets wrong. Previously 2026-07-12 for round 4: **import evaluation moves before
instantiation**, which dissolves a rollback that was not merely unimplemented but
*unimplementable* — a fresh session `var` is non-configurable and cannot be deleted, so a
failing import could never have removed the bindings it had already created; rollback now
never touches the object record. The cross-kind matrix is re-keyed on the **full
descriptor state** and stops conflating `var` with `function` (bare `var Object` is a
no-op; `function Object(){}` clobbers the builtin); §7.5 splits **created** from
**adopted** properties; the restricted-global predicate is stated as ECMAScript's,
modified; deviation (a) is widened to every cross-kind pair and (d) is split by
compartment (a **package** module sees neither session lexicals nor session `var`s, per
LLP 0013's private compartment global); the single oracle becomes **three gates** over an
owner-authored **executable reference model**, after the concatenating oracle was falsified
by a directive prologue; §6 adopts LLP 0025's **park** lifecycle (the call never unwinds,
state is *discarded*); §1 adopts LLP 0022's linear **SubmissionCredential** and drops
"decision evidence", a phrase 0022 names a category error; §2 separates **source label**
from **module identity** from **retained platform identity** — a noun-reuse conflation that
had made §7.9 demand module identities for scripts, which are not modules; the failing
module's cache entry is *deleted*, not kept; and the literal-dynamic-preflight
contradiction between §3 and the ACs is removed. Previously 2026-07-12 for round 3: §7 adopts ECMAScript's **shadow**
semantics — a lexical declaration never deletes a global property, fixing a defect
that would have made `let Object = 1` destroy `globalThis.Object`; that one correction
retires the "configurable globals" deviation, the `delete`-driven oracle divergence,
and two rollback-under-interference cases, so the model got *smaller* as it got more
correct. Rollback becomes a **journal** scoped to the input's declared names; the
oracle becomes **engine-relative**, so an engine quirk can no longer masquerade as a
session defect; imported modules' inability to see session lexicals is stated as
deviation (d); the free-identifier lowering is specified at **Reference-semantics**
fidelity; `var [a, a]` is corrected to legal; phase 3 uses ECMAScript's
`CanDeclareGlobal*` predicates; §6 gains capability strata, a `Pending` cancellation
state, and target ids; §8 owns the **unstyled** tree and the styled-IR language is
deleted (LLP 0025 §3 governs rendering); §7.9 cites LLP 0023 §2.3; and the `.load`
typed read, UTF-8 decoding, drain boundary, and broker sequence obligations land.
Previously 2026-07-12 for round 2: §7 is respecified as a
**modified ECMAScript `GlobalEnvironmentRecord`** — an object record on
`globalThis` for `var`/`function` and a checked declarative record for lexicals —
which fixes the previous draft's fatal omission (a free identifier with no cell
was specified to throw, which would have broken `Object`), and resolves `typeof`,
lexical/property coexistence, and the `$_` accessor by construction; the
**evaluation phases** are enumerated so that a throwing import and a throwing
statement have different, stated consequences; same-input collisions, the
cross-kind matrix, destructuring, and rollback values are pinned; a **false
empirical claim** about Bun and `const` is corrected — Bun does *not* enforce it,
and the divergence is now recorded; the fifth **lifecycle** outcome LLP 0025 §8
requires is added to §6; `require.main` is retired to match LLP 0022 §1's closure;
`.load` of JSON aligns with LLP 0022 §8; §8 defers the display IR to LLP 0025 §3
and names the three-part engine-patch program its safety rests on. Previously
2026-07-12 for round 1: the checked-cell record with **late binding by name**,
the engine premises, deletion of the `eval` clause, the LLP 0019 correction, and
the non-assimilating TLA settlement channel.)
**Related:** LLP 0002 (host embedding ABI — §6 is a semver-major change to its
narrow consumer contract); LLP 0003 (Hermes engine bridge); LLP 0004 (module
loading and builtins); LLP 0007 / LLP 0009 (the in-process transform this seam
extends); LLP 0019 (Hermes-compat transform authority); LLP 0021 (capsec effect
model); LLP 0022 (REPL behavior — the first consumer to demand this contract);
LLP 0023 (virtual namespace and path identity); LLP 0025 (terminal session
ownership)

## Summary

Ibex evaluates source that did not come from a file — prompt input, `.load`
content, piped stdin, `-e`/`-p` — and it must do so with the same language,
security, and diagnostic guarantees as file execution. Today it cannot: the
engine seam accepts a bare string, hardcodes the source name `<eval>`, returns
`Option<String>`, assimilates any thenable it finds, and consults an environment
variable for its timeout *after* arming.

This document specifies the seam that replaces it:

- an **in-memory source API** carrying source text, a synthetic source label, virtual
  referrer, source goal, parser dialect, source role, main-module flag,
  authenticated context, and execution mode;
- a **source-goal matrix** fixing what each input is (script or module) and how
  imports and top-level `await` extend a script without re-goaling it;
- a **structured evaluation outcome** — empty completion, value, throw,
  cancelled — that never assimilates a thenable and never times out silently;
- a **session record specified as an algorithm** — a checked-cell environment
  with late binding by name, an exhaustive cross-kind declaration matrix, an
  explicit commit/rollback rule, and a fixture-pinned deviation list;
- **safe inspection**: a display path that runs no user code, staged honestly
  behind the native trap-free primitive that is the only thing that can make it
  more than opaque; and
- a **structured asynchronous-failure envelope** carrying the original value, a
  safe stack, and the authenticated owning principal.

It is the mechanism layer behind LLP 0022's language and display guarantees, and
it serves `.load`, program stdin, and the one-shot evaluation surfaces equally.

## Motivation

An interactive session is not a sequence of unrelated one-line programs, and a
piped program is not a REPL transcript. Both are source that the runtime must
evaluate with an identity, a goal, and a result — and the current seam supplies
none of the three.

The consequences are not theoretical. Because the outcome is `Option<String>`,
an empty completion and the value `undefined` are indistinguishable, so a
declaration prints `undefined`. Because the source name is `<eval>`, an error on
line 3 of a multiline input reports a synthesized position computed from the
length of an internal wrapper. Because the transform emits no source map,
wrapping and lowering silently corrupt positions. Because native unwrapping
assimilates any object with a callable `then`, merely displaying a value can run
user code. Because statement-containing top-level `await` is lowered into an
async IIFE, `const x = await f()` evaluates and then throws its binding away.
And because the await-unwrap timeout is read from the environment after arming,
a runtime whose configuration was supposed to be frozen at arming is still
listening to its environment.

Each of these is a case of a convenience at the seam quietly overriding a
language or security rule. A structured seam makes the rule the default and the
convenience impossible.

## Scope

This document specifies the evaluation seam and the session semantics built on
it, for every mode that evaluates non-file source: interactive prompt input,
`.load`, plain transcript input, program-mode stdin, and the one-shot `-e`/`-p`
/`ibex eval` surfaces.

It does not specify the interactive product surface (LLP 0022), the virtual path
namespace (LLP 0023), or terminal ownership, interruption, and lifecycle
(LLP 0025) — though it defines what a cancellation request *means* to the
evaluator, which LLP 0025 triggers.

It does not admit a debugger, an inspector, a type checker, or dynamic authority
grants.

## Engine premises

Every claim below is constrained by what the shipping engine actually does, and
those constraints are load-bearing rather than incidental. Verified against the
bundled Hermes (`tools/hermes/hermes`) at the revision of this document. **The
premises are per advertised target** (LLP 0001), not per engine family: an
implementation claims conformance on a target only where they have been
re-verified there. One is already known to differ — the Windows eval path is
recorded as not supporting async function syntax, which is the shape the entry-TLA
lowering emits (open question 7).

| Premise | Observed |
| --- | --- |
| No native ESM, no native top-level `await` | the loader lowers every module into a **synchronous `require()` chain** (LLP 0004) |
| No temporal dead zone | a `let` read before its declaration yields `undefined`, not a `ReferenceError` |
| No runtime `const` enforcement | `const c = 1; c = 2` is a **compile-time** error ("invalid assignment left-hand side"), so it cannot be caught — and a *prior-input* `const` is not enforced at all |
| No `with` | "with statement is not supported" — a compile error |
| No lexical scope for direct `eval` | "Direct call to eval(), but lexical scope is not supported"; eval'd code cannot see enclosing locals |
| No per-iteration loop bindings | `for (let i…)` closures capture `3,3,3` — the premise LLP 0019 exists to compensate for |
| Global `var` is non-configurable | matching ECMAScript's `CreateGlobalVarBinding` for a Script |
| Lexical declarations do not persist across evaluations | each evaluation is its own Script; a top-level `let` is gone at the next call |
| *(harness note)* | the last row, and the "prior-input `const`" half of the third, need **two `ex_hermes_eval` calls on one runtime** — the standalone binary cannot show them. They are verified with a two-eval C-API probe (and reproduced through the live `ibex repl`), not with `tools/hermes/hermes` alone; the distinction is recorded so the claim is reproducible rather than merely asserted |

Three consequences follow, and the rest of this document depends on them:

1. **The session record cannot be the engine's global environment.** Neither
   TDZ, nor `const` immutability, nor cross-input lexical persistence exists to
   build on. §7's mechanism is therefore an **evaluator-owned record with checked
   cell access**, reached by lowering top-level declarations and free session
   names into cell operations. This is not one option among several; on this
   engine it is the only one — and it is sufficient: a checked-cell record run on
   the shipping binary delivers shared cells, late-bound redeclaration, a
   **runtime** `TypeError` on `const` assignment, and a real TDZ `ReferenceError`,
   none of which the engine provides natively.
2. **`with` is unavailable as a scope-injection trick**, so no implementation may
   assume it. A script input that *contains* `with` fails to compile — a
   documented engine-level narrowing of the sloppy-script goal (§3).
3. **Direct `eval` cannot see a lexical scope**, which is one of two independent
   reasons §7 specifies no `eval` semantics (the other being that LLP 0022 §1
   closes `eval` outright).

## Design

### 1. The in-memory source API

The engine accepts a **source request** — a closed type, not a bag of strings —
rather than source text. It is a **sum**, not a record with optional fields, because
not every payload has a source goal:

```
SourceRequest = Program { goal, dialect, role, kind, … }   // §3, §4
              | JsonData { … }                             // parsed, not evaluated
```

`.load` of a `.json` file and a JSON module take the second arm: JSON has no source
goal, and a type that pretends otherwise forces every consumer to carry a
meaningless `goal` field. The `Program` arm's fields:

| Field | Meaning |
| --- | --- |
| source text | the program, as **UTF-8**, with an explicit length (never NUL-terminated). Decoding is **strict**: invalid UTF-8 is a named refusal, not a lossy replacement, because a replacement character silently changes the program. **Empty source is valid** and yields an empty completion — the current ABI rejects a zero length, which would make `ibex -e ''` and an empty `.load` errors for no reason |
| synthetic **source label** | the source *name* errors and stack frames report (§2) — a string, not a key |
| virtual referrer | the **typed logical path identity** (LLP 0023 §2 — not a display string) that relative specifiers resolve from |
| source goal | script-with-extensions or module (§3) |
| parser dialect | which grammar parses the bytes (§4) — independent of the goal |
| source role | **entry** or **dependency** — the field that decides whether top-level `await` is admitted (§3). Distinct from the credential's **entry kind** (LLP 0022 §2's arming enum `file`/`stdin`/`repl`/`eval`): a `.load` body has *role* entry while the session's *entry kind* is `repl`. Two concepts, adjacent nouns — named here rather than left to collide |
| resolved module kind | ESM or CommonJS, for sources that have one (§4). **Not JSON** — JSON payloads take the `JsonData` arm, which is the point of the sum |
| main-module flag | whether this source is the session's main module. It feeds `import.meta.main` **only**: `require.main` and `process.mainModule` stay closed (LLP 0022 §1) |
| armed-session **token** | the opaque, authenticated reference to the armed snapshot, held by the ingress, unforgeable from JavaScript, and — unlike a value handle (§6) — it **does** cross into the worker. A *token*, not a handle (§2) |
| **submission credential** | the opaque, non-JavaScript-reachable **`SubmissionCredential`** LLP 0022 §7 owns, with a **linear four-stage lifecycle** — *minted → read-authorized → immutable byte capsule → evaluated* — consumed exactly once. The stages order the `.load` case correctly: the credential authorizes the read at the **read-authorized** stage and binds the source **bytes' digest** only at the **byte-capsule** stage that follows it, so "binds the digest" and "gates the read" are ordered, not circular. (An earlier draft here decomposed the same lifecycle into two affine permits and wrongly called 0022's single-credential form "circular for `.load`"; the two forms are equivalent, and this document adopts 0022's vocabulary since 0022 owns the contract.) It binds the byte digest together with the snapshot digest, run nonce, root identity, source label, referrer, goal, role, mode, entry kind, endowment projection, and **submission ordinal**, so a replayed, wrong-session, forged, or JavaScript-originated submission fails to authenticate. It is **not "decision evidence"** — evidence is an *output* the decision model emits after deciding and cannot authenticate an *input*. Every security-relevant field of the request is **derived from it**, never supplied alongside it (LLP 0022 §7) |
| principal | the authenticated principal, **derived by the ingress and never caller-supplied**. A source request cannot name its own principal |
| execution mode | interactive, transcript, program, or one-shot — which also fixes the **drain boundary** below |

**The drain boundary is defined, not adjectival.** "Drain to quiescence" and "ready
work only" are the two policies, and each names the exact point at which the
evaluation is considered settled:

| Mode | Drain policy |
| --- | --- |
| program, one-shot | **to quiescence**: the evaluation settles when the event loop has no ready work *and* no pending timer, native completion, or unsettled TLA unit that the runtime is keeping alive. A live server or a repeating timer keeps the process alive, exactly as in file execution |
| interactive, transcript | **ready work only**: the evaluation settles when its own unit settles and the microtask queue drains. Work that is merely *scheduled* — a pending timer, a live server — does not hold the prompt, and runs on the idle pump between inputs. One unresolved background handle must never wedge the next input (LLP 0022 §5) |

**`.load` reads through a typed session-effect route, not around one.** The bytes
`.load` submits are obtained by a **pre-read typed decision over a virtual path**
(LLP 0023), taken under the submission credential *before* any read occurs, and
returning authenticated bytes together with the read decision's evidence. The engine accepts
those bytes; it does not open files. This is the obligation LLP 0022 §7 places here,
and it is what makes `.load /etc/passwd` an outside-mount error and `.load` of a
policy-denied file a denial with evidence — rather than a host read that the session
layer performs and then apologizes for. Error precedence is §2's staging, which defers to LLP 0023 §7.2 — so an outside-mount
refusal and a policy denial both precede any disclosure of absence.

No caller may reach the engine with less. In particular there is no path by
which source text arrives with a host path as its identity — the current
`.load`, which passes the host path as the source URL, is retired by
construction. The generic bare-string ABI (`ex_hermes_eval`, which takes a
caller-chosen source name and can carry no attribution) is **not** this seam and
stays closed in armed production (LLP 0022 §1).

**One evaluation is in flight per session, at a time.** Submission is serialized:
the seam accepts no second source request while one is unsettled, *including*
while an input is suspended at a top-level `await`. This is not a REPL
convenience — §7.4's rollback is defined relative to "the record's state at the
start of the input", which has no meaning if two inputs can interleave. A
consumer that needs concurrency uses a second runtime.

**Trusted internal ingress is a separate route.** The runtime's own bootstrap
probes and embedded bytecode do not travel this path; they use a distinct
trusted-ingress entry point that takes no principal (it *is* the runtime) and no
session record. Reusing the operator-source path for bootstrap is what makes the
current seam's `is_bytecode` flag a policy input rather than a fact about bytes.

**Authority-bearing import forms are refused at this ingress, in every mode.**
LLP 0022 §6 fixes the table of forms; because the refusal belongs to the shared
ingress rather than to the REPL, it binds the one-shot surfaces (`-e`, `-p`,
`ibex eval`) identically — before resolution, authority mutation, or execution.

### 2. Source identity and reserved schemes

Every evaluated source has a deterministic synthetic **source label** (§2 vocabulary):

| Source | Identity |
| --- | --- |
| prompt / transcript input | `repl:<n>` (1-based) |
| `.load <file>` content | `repl:<n>:<virtual path>` |
| program-mode stdin | `ibex:stdin` |
| one-shot `-e`/`-p` | `ibex:eval` |
| imported file | its virtual `file:///project/…` URL (LLP 0023) |

The ordinal `n` counts **evaluated source**, and exactly that (LLP 0022 §5): it
advances for every prompt or transcript input that reaches the evaluator —
*including one that fails to parse*, since it was still submitted — and for every
source a command submits, namely a `.load` body and a `.time` argument. A command
that evaluates nothing does not advance it, and neither does a blank line or an
input abandoned in continuation.

`.load`'s identity is the single string `repl:<n>:<virtual path>`: one identity
carrying both the session ordinal that orders it and the virtual path that
explains it. A stack frame from loaded content is therefore attributable to the
file without inventing a second identity space, and it never carries a host path.

The schemes `repl:` and `ibex:` are **reserved in the module resolver** — a hard
error, like the unknown-builtin guard of LLP 0004 — so a synthetic identity can
collide with neither a virtual path nor a module specifier, and
`import("repl:1")` cannot be made to mean anything.

**A source *label* is a name, not a key — and this document keeps three things separate that
the word "identity" would happily blur.** The distinction is stated here
because the corpus has already been bitten by it:

| Concept | What it is | Owner |
| --- | --- | --- |
| **source label** (§2) — LLP 0023's noun, adopted here | a synthetic **name**, a string, that errors, stack frames, and the source-map registry report. Freely serializable; crosses a process boundary | this document |
| **`SourceId`** | LLP 0023's *authenticated* source key. **Not** a display name | LLP 0023 §2.3 |
| **module identity** (§7.9) | the **cache key** deciding which module instances are the same instance | LLP 0023 §2.3 |
| **retained platform identity** | an identity *record* for a file object — **never serialized, never rehydrated** | LLP 0023 |
| **value handle** (§6) | a rooted engine reference to a live JavaScript value. **Never crosses a process boundary** | this document |
| **session token** (§1) | the opaque authenticated reference to the armed snapshot. It **must** cross into the worker, so it is a *token*, not a handle | LLP 0022 §1 / LLP 0023 |
| **sequence epoch** (§9) | the counter a worker restart **advances** (never rewinds) so a consumer can tell "no events" from "the worker died". Advanced **once per worker restart** | this document ↔ LLP 0025 |
| **work epoch** *(0025-side term; retired there)* | the interrupt-latch unit an earlier LLP 0025 draft used; 0025 has since restructured its latch, so this document does **not** rely on the term and lists it only to disambiguate it from the *sequence epoch* below | (historical) |
| **work unit** (§6) | an individually cancellable execution slice with a target id — an evaluation, callback, timer, microtask drain, or query | this document |
| **settlement unit** (§7.4) | the *aggregate* of an input's evaluation and the jobs its TLA needs — the thing whose settlement is the input's outcome. Not a cancellation target on its own | this document |

They are not each other. A `repl:<n>` input has a **source label** and **no module
identity at all** — it is a script, not a module, and it never enters the module cache. A
source label is safe to put in a stack frame; a retained platform identity is not safe to
put anywhere.

**"Handle" was the fourth casualty of the same failure, and it is the sharpest**: §6 says a
handle "never crosses a process boundary", while §1 called the armed-snapshot reference a
"handle" — and *that one must cross*, since evaluation happens in the worker. One noun, one
crossing rule, two objects on opposite sides of it. The armed-snapshot reference is
therefore a **token** (LLP 0023's word), and §6's never-crosses rule is scoped explicitly to
**value handles**. Reusing a noun across two concepts is how a sibling's rule and this
document's have now silently diverged four times: *identity*, *defeated*, *private global*,
and *handle*. The table above exists to stop the fifth.

**Resolver and import-gate error taxonomy.** These classes are distinct, and a
consumer must be able to tell them apart rather than receive one generic failure
(LLP 0022 §2 requires the third; LLP 0023 §7 owns the path classes):

| Class | Meaning |
| --- | --- |
| reserved-scheme | a specifier naming `repl:` or `ibex:` |
| unknown-builtin | a `node:`/builtin specifier outside the allowlist (LLP 0004) |
| **out-of-snapshot** | a package outside the session's immutable graph — *not* a resolution failure and *not* a policy denial. The message names policy regeneration and a session restart as the remedy, because the graph cannot widen mid-session (LLP 0022 §2) |
| policy denial | an in-graph package refused by a typed decision, with the safe decision identifier |
| resolution failure | no such module |
| unsupported-dependency-TLA | §3's single named error |

**Ordering is a security property, and LLP 0023 §7.2 owns the total order.** A module
can be in several classes at once — a policy-denied module that also uses top-level
`await` — so the order is observable and two implementations must not differ. This
document does **not** restate it. It contributes its classes into LLP 0023 §7.2's staging
and states the invariant they must respect:

> **No class that discloses existence may precede an authorization decision that would
> have denied the caller.**

The normative content is the **decision staging** — what may be probed before what — not a
memorized list; ordering *between* shape-disjoint classes is vacuous. That single rule
forces the tiering:

| Tier | Decided using | This document's classes |
| --- | --- | --- |
| **shape-decidable** | the specifier text and static manifests — **no I/O, no snapshot** | reserved-scheme; unknown-builtin |
| **snapshot-decidable** | the armed snapshot — **no I/O**; discloses nothing about the filesystem | out-of-snapshot |
| **path / authorization** | the namespace and the typed decision, **before any disclosure** | *(LLP 0023 §7.2 owns and orders these, policy denial included)* |
| **graph-dependent** | reachable only **after** authorization, because it requires having observed or read something | module resolution failure; unsupported-dependency-TLA |

An earlier draft of this section got this exactly backwards — it reported **resolution
failure second**, ahead of the path and policy classes. That is an **existence oracle**: an
unauthorized caller learns whether a resource exists before any decision that would have
denied them. The rationale it offered ("what a specifier *is* precedes where it
*resolves*…") *sounded* principled and **was** the disclosure channel, which is exactly how
this class of defect survives review. "Where it resolves" is an **observation**, and
observations must be authorized first.

`unsupported-dependency-TLA` is **graph-dependent, not shape-decidable**: discovering that a
dependency uses top-level `await` requires resolving, authorizing, and *reading* it. Module
resolution failure is graph-dependent for the same reason — resolving a specifier means
probing paths, and a denied probe must yield the denial, never "not found".

Errors and stack frames report the source label with line and column positions
inside the *submitted text*, correct for multiline inputs and unaffected by any
internal wrapping the evaluator performs. This requires the transform to emit
source maps, which it does not do today; a position computed by adding a
wrapper's prefix length is not a conforming implementation.

### 3. Source goal

Non-file sources are **scripts** (sloppy by default) extended with two
module-goal constructs — top-level `await` and static import forms — except
program-mode stdin and imported files, which are **modules**.

The extension is semantic, not a re-goaling. The transform must lower imports
and top-level `await` **without** changing the enclosing input's strictness,
directive-prologue handling, top-level `this`, completion value, or declaration
behavior. A lowering that turns a sloppy script into a strict module because it
contained an import is not conforming: it would silently change whether an
undeclared assignment throws.

Concretely, the input must be **parsed under Script early-error rules extended
with `ImportDeclaration` and top-level `AwaitExpression`** — not parsed as a
Module and patched afterwards. Parsing as a Module imposes strict mode at parse
time and rejects sloppy-only forms before any later pass could restore them, so
"parse as a module, then lower" is non-conforming however the output looks.

**This goal does not exist in the pinned parser today, and the gap is named
rather than assumed away.** The parser offers Script and Module goals; its
program entry promotes to Module on seeing an `import`, and the Module goal
rejects sloppy-only *parse-level* forms — legacy octal literals, `delete
identifier`, duplicate parameters — that this goal must accept. A conforming
implementation therefore needs one of: a parser mode admitting the two
extensions under Script early errors, a maintained fork, or an independent Script
early-error validator run over the input *in addition to* the parse. Which of
these is taken is open question 5; what is **not** admissible is quietly using the
Module goal and declaring the difference cosmetic. The source-goal fixture family
(§4) therefore includes the sloppy-only *parse* forms, not merely the sloppy-only
*runtime* effects, so a Module-goal implementation fails the corpus rather than
passing it.

**`await` is a reserved word at the top level of a script input.** Admitting
top-level `AwaitExpression` into a sloppy Script — where `await` is otherwise a
legal identifier — makes `var await = 1`, `await(x)`, and `function await(){}`
ambiguous. v1 resolves the ambiguity in favor of the extension: at the *top level*
of a script input `await` may not be used as an identifier, mirroring the module
goal and Node's REPL. Inside a non-async function body within the input, `await`
remains an ordinary identifier, exactly as in a Script. This is a documented
narrowing, and it is pinned by a fixture.

| Input | Goal | Role | Strict by default | TLA | Static import | `this` at top level |
| --- | --- | --- | --- | --- | --- | --- |
| Prompt / transcript input | script + extensions | entry | no | yes | yes | `globalThis` |
| `.load <file>` | script + extensions | entry | no | yes | yes | `globalThis` |
| Program-mode stdin | module | entry | yes | yes | yes | `undefined` |
| One-shot `-e` / `-p` | script + extensions | entry | no | yes | yes | `globalThis` |
| Imported file on the legacy session loader | module | dependency | yes | **no (legacy v1)** | yes | `undefined` |
| Imported file on the LLP 0026 runner | module | dependency | yes | **yes** | yes | `undefined` |

**Top-level `await` is an entry-only extension on the legacy session path.** The engine has no native
ESM and no native TLA, and the module loader lowers every module into a
*synchronous* CommonJS `require()` chain — so a dependency that suspends has
nowhere to suspend to. Honest dependency-level TLA needs an asynchronous
linker/evaluator with dependency ordering, live bindings, async cycles, failure
propagation and caching, and defined CJS interoperation. None of that exists on
the legacy loader, and this document will not pretend otherwise. The
authenticated LLP 0026 runner is the separate implementation: it owns
dependency-first SCC scheduling, one handled internal evaluation promise per
record, fresh public `import()` promises, and sticky terminal failure.
Consumers become dependency-TLA-capable only when they migrate to that runner;
this document's legacy refusal does not silently widen them.

Therefore: top-level `await` is available in **prompt input, `.load` content,
program-mode stdin, and one-shot `-e`/`-p`** — the sources whose role is *entry*
— and an **imported module that uses top-level `await` is a loud, stable
unsupported error** naming the module and the construct. The rule is enforced on
the **source role**, which is why the role is a field of the source request
rather than a property inferred from the text.

That error must be *one* error. Today it is not: the SWC stage passes top-level
`await` through untouched, the Oxc candidate bails with an ad-hoc message, and
the loader's downlevel trigger does not detect plain top-level `await` at all —
three behaviors for one condition. Conformance requires:

- detection on the **resolved module kind and role**, not on a text scan, so a
  CommonJS file that merely uses `await` as an identifier is never misclassified;
- **one stable named error**, identical across every transform engine and every
  import form.

**Preflight covers the static graph, and only the static graph.** The transform emits a
**dependency manifest** for each module — static edges, resolved kind, role, and a TLA bit —
and the loader preflights that manifest transitively before the entry executes. A TLA
dependency reachable through *static* imports is therefore refused *before any of the graph
runs*. A synchronous **`require()`** — literal *or computed* — is checked at **call time**, like
`import()`: its target's static-import closure is preflighted transitively before the
`require` returns a body or inserts a cache entry, and a `require` on a never-taken branch
never fails. (An earlier draft called `require()` a "static edge", which left computed and
conditional `require()` undefined and conflicted with the dead-branch rule this section
gives for `import()`.) Only static `import` *declarations* are entry-preflighted.

**Every `import()` is checked at call time instead** — including one whose specifier
is a string literal. Preflighting literal dynamic imports would be worse than useless:
it would make `if (false) import("./tla.js")` fail before the entry runs while
`if (false) import("./" + name)` succeeds, because *static discoverability is not
dynamic reachability*. A dynamic import that is never evaluated must never fail. Its
target is refused at call time, with **the same named error**, before the selected
dependency is evaluated or enters the module cache; effects the entry already
performed stand, and no preflight can honestly claim otherwise.

An asynchronous module graph is a separate design, now specified by accepted
LLP 0026. The legacy path continues to state and enforce its limit rather than
shipping a plausible-looking lowering that is wrong under cycles.

**A note on how this document has been repaired, because the pattern is the point.** Three
times now a guarantee here proved unsupportable by the mechanism beneath it — a rollback
that required deleting a non-configurable property; a package isolation the compartment
does not actually provide; an import ordering that made "publishes nothing" false. Each
time the repair was **not a cleverer mechanism but a changed promise**: move the failure
earlier so nothing needing rollback ever exists; state the leak instead of asserting the
isolation; refuse dependency TLA rather than lower it wrongly.

The sibling documents converged on the same move independently — LLP 0025 rebuilt its
interrupt guarantee on an unconditional escape credit rather than case analysis, and
LLP 0023 closed name-bound mutation outright once it established that POSIX offers no
object-bound primitive to make the guarantee deliverable. **A spec must not promise what
the platform cannot deliver**; when it has, the fix is to shrink the promise, not to grow
the mechanism.

And a repair that *removes a premise* must be chased through every place that premise was
assumed. §3 asserted rollback of import-phase bindings for a full round after §7.3 had
made rollback unnecessary — and it read perfectly well in isolation, which is exactly why
it survived.

**Static imports are hoisted, and they evaluate *before* the input's bindings are
instantiated.** A static `import` in a script input is resolved and evaluated in
**phase 4** (§7.3), in source order — before any of the input's statements run, and
before any of its `var`, `function`, or lexical bindings exist. It is *not* executed as
a textual-position `require()` call. A directive prologue still applies, and an import's
side effects precede the input's first statement.

That ordering is what makes the next sentence true rather than aspirational: **an import
that throws publishes nothing at all**, because at the moment it throws the input has
declared nothing yet. `import "./boom"; var w` leaves no `w` — not because `w` is rolled
back, but because `w` was never created. Nothing needs undoing, which is essential: a
fresh session `var` is non-configurable and **cannot be deleted** (§7.4), so a design that
had to remove it would not be merely awkward, it would be *impossible*.

The imported module's own effects, and its module-cache entry, of course stand — those are
not session bindings. Import bindings are cells of kind `import`: read-only, and snapshots
rather than live bindings (deviation (b), §7.7).

A `"use strict"` prologue in an input applies to that input under ordinary
script rules. Modules imported from a script keep their own strictness.
Strictness is a language-ergonomics property only: **no security decision may
depend on it.** Assigning to an undeclared identifier in a script input creates
a persistent global binding, matching Node, Bun, and Deno interactive
precedent.

`import.meta` is a **syntax error in a script input** — it is a Module-goal production,
and admitting `import` declarations as an extension does not admit it (LLP 0022 §5 pins
the same at the prompt). `export` is likewise a syntax error in a script input. CommonJS `require` and
`require.resolve` are available in script inputs under the same builtin
allowlist, session graph, package-principal attribution, and typed decisions as
`import`; they are not a second loader with different rules.

**Engine narrowing.** Because Hermes rejects `with` at compile time (§Engine
premises), a sloppy script input containing `with` fails to compile. This is a
documented v1 divergence from the Script goal, not an implementation bug to be
worked around, and it is the only sloppy-only form the engine withholds.

### 4. Grammar selection

Extensionless sources — prompt input, transcript input, program stdin, `-e`/`-p`
— are parsed with the **TypeScript grammar, non-JSX**. There is no content
sniffing to choose between the JavaScript and TypeScript grammars, which overlap
with divergent semantics. The consequences are accepted and documented:
`a<b>(c)` parses as a call with a type argument rather than as comparison
chaining, and JSX/TSX is not accepted in extensionless input.

Sources that *have* an extension — `.load <file>` and imported files — are
parsed **by extension**, exactly as file execution parses them (LLP 0004). Two
tables govern them, and they are deliberately separate: **dialect** (how the
bytes are parsed) is not **module kind** (how the result is evaluated).

*Dialect, by extension:*

| Extension | Parser dialect |
| --- | --- |
| `.js`, `.mjs`, `.cjs` | JavaScript |
| `.jsx` | JavaScript + JSX |
| `.ts`, `.mts`, `.cts` | TypeScript, non-JSX |
| `.tsx` | TypeScript + JSX |
| `.json` | JSON (not a JavaScript source goal) |
| `.d.ts` | types only; not loadable as a program |
| extensionless (prompt, stdin, `-e`) | TypeScript, non-JSX (§4 above) |

*Evaluation, by resolved module kind:*

| Kind | Strict | `this` at top | Globals | TLA | Display result |
| --- | --- | --- | --- | --- | --- |
| ESM (`.mjs`, `.ts`/`.js` resolved as ESM) | yes | `undefined` | `import.meta`; plus `require`/`require.resolve` (Ibex extension) | entry role only (§3) | namespace object |
| CommonJS (`.cjs`, `.js` resolved as CJS) | no | `module.exports` | `require`, `module`, `exports`, `__filename`, `__dirname` | no | `module.exports` |
| JSON | n/a | n/a | n/a | n/a | the parsed value |
| script input (prompt, `.load`, `-e`) | no | `globalThis` | session record (§7); `require`/`require.resolve` | yes | completion value |

So a `.cjs` file is **not** an ESM module with `this === undefined`, and JSON has
no source goal at all — both of which the single-table formulation wrongly
implied. TLA is admitted by **role**, not by kind: program stdin is an ESM-shaped
*entry* and gets it; an imported ESM dependency does not.

Because Ibex lowers every module to CommonJS, `require` and `require.resolve` are
available in the ESM kind as a **documented extension**. **`require.main` and
`process.mainModule` remain closed, in every mode** (LLP 0022 §1): they are live
loader-state handles, not identity strings, and the main-module *fact* is carried
by `import.meta.main` and `import.meta.url` — which for program stdin are `true`
and `ibex:stdin`. `module`, `exports`, `__filename`, and `__dirname` are *not* ESM
globals, and `__filename`/`__dirname` are absent wherever there is no file
(LLP 0023 §6).

**Runtime-bearing TypeScript.** `enum`, a value-bearing `namespace`, and `import =`
are not type-only: they emit runtime bindings. **Session declarations are collected
from the source *after* TypeScript lowering**, so these arrive as ordinary `var`-kind
bindings and need no special cell kind.

That collection must be **hygienic**: a lowering introduces temporaries of its own —
the IIFE variable an `enum` desugars to, JSX factory aliases, helper functions — and
those must **not** become session bindings, must not appear in completion, and must
not collide with a user name. The transform therefore emits **origin-tagged**
declarations, and only the user-authored ones enter the record. A lowering that
cannot distinguish its own temporaries from the user's is not conforming.

`using` and `await using` tie disposal to scope exit. At the top level of a **script
input** the enclosing "scope" is the input, so a session-persisted `using` binding
would be disposed the moment the input that created it finished — never what the
author meant. v1 therefore **refuses `using` and `await using` at the top level of a
script input** with a named error; inside a block or function within the input they
are ordinary. At the top level of a **module-goal entry** (program stdin) the scope
is the module and disposal at module exit is coherent, so they are permitted there —
except that `await using` in an entry composes with the TLA lowering and inherits its
per-target limits (open question 7).

`.load` evaluates its file's *bytes* under the file's dialect but as a **script
input** (the last row), which is what makes its declarations persist into the
session; a consumer wanting module semantics imports the file instead. `.load`'s
relative imports resolve from the loaded file's virtual directory, not from the
session cwd. Its edges are pinned:

| `.load` of | Behavior |
| --- | --- |
| `.js`, `.jsx`, `.ts`, `.tsx` | script input under that dialect |
| `.json` | **parses and displays the value**; declares nothing, creates no cache entry (LLP 0022 §8). This is a parse-and-display special case, not a script input — JSON has no source goal |
| `.mjs`, `.cjs`, `.mts`, `.cts` | **named refusal**: the extension *asserts a module kind*, and `.load` is not a module load. `import` the file instead. The four are refused symmetrically — a `.cts` is as much a module-kind assertion as a `.cjs` |
| `.d.ts`, unknown extension, extensionless | **named refusal** (LLP 0022 §8) |

Static `import` declarations are **empty completions** — they display nothing.
Only dynamic `import()` produces a value (the namespace object) and therefore a
display result.

Type-only constructs are erased: they neither evaluate nor persist anything at
runtime. There is no type checking at any of these surfaces. The TypeScript
dialect is **pinned to a named parser and version** — the in-process lowering
stage's `swc_ecma_parser`, at the version recorded in `Cargo.lock`, with the pin
asserted by a build-time check — because dialect drift (`satisfies`, `using`,
decorators) silently changes the completeness judgments of §5. A second transform
engine may exist as a candidate (Oxc, per LLP 0007/0009) only while it is
**parse-equivalent to the pinned parser over the conformance corpus below**; a
divergence is a corpus failure, not a configuration choice.

**Transform authority.** This seam extends the **in-process TypeScript/ESM
lowering stage** (`src/module_loader/transpile.rs`) — the stage that strips types,
compiles JSX, and lowers `import`/`export` into the synchronous `require()` chain.

It does **not** extend LLP 0019's tiers, and this document does not claim that it
does. LLP 0019 governs the *Hermes-compat `for...of` and async-generator rewrite*,
whose two tiers are the build-time AST authority
(`packages/ibex-devtools/src/scripts/hermes-compat.mjs`) and the embedded
bootstrap string scanner (`src/engine/bootstrap/module-loader.js`). That rewrite
runs *after* this stage, is unaffected by it, and its corpus pins for-of and
async-generator behavior — so it would gate none of the obligations below.

Those obligations are new, so they need their own corpus, built to the LLP 0019
discipline: implementation-neutral fixtures, an oracle, and every accepted
divergence pinned by an explicit entry.

| Fixture family | Gates |
| --- | --- |
| Source-goal preservation | a sloppy script with an import stays sloppy; **sloppy-only *parse* forms survive** — legacy octal, `delete identifier`, duplicate parameters — which is what catches a Module-goal implementation; directive prologues; top-level `this`; undeclared assignment; `export` rejected; `await` reserved at top level; the `with` and `using` narrowings |
| Completion values | statement lists, blocks, `if`, loops, `try`/`finally`, abrupt completion, a declaration after an expression — before and after import and TLA lowering (§6) |
| Source maps | positions survive TypeScript stripping, import lowering, TLA lowering, **and the LLP 0019 Hermes-compat rewrite that runs after them** (§2) |
| Dependency TLA | one stable named error from every engine; **static-graph** preflight only; **every** `import()` — literal or computed — checked at call time, so an unevaluated `if (false) import("./tla.js")` never fails (§3) |
| Session lowering | the §7 environment operations: the cross-kind matrix, same-input collisions, the phases, and rollback |
| Parse equivalence | any candidate engine agrees with the pinned parser across every goal and dialect |

**Source maps compose across the whole pipeline, not just this stage.** Positions
must survive *every* rewrite between the submitted text and the bytes Hermes
compiles — TypeScript stripping, import lowering, TLA wrapping, the session lowering
of §7, and the LLP 0019 Hermes-compat rewrite that runs afterwards. Each stage emits
a map and the maps are **composed**; a stage that drops its map breaks §2 for every
stage before it. Because the sources are in memory, the maps live in an **in-memory
registry keyed by source label** — the current machinery, which looks for an
adjacent `.map` file on disk, cannot represent `repl:<n>` at all and is retired.

The **complete inventory of rewrite stages** between the submitted text and the bytes
Hermes compiles must be enumerated, and each must be retired, emit a map, or be bound by
a stated stability rule. Naming only LLP 0019's tier 2 was insufficient — the same
parser-less bootstrap performs *other* mapless rewrites that shift columns on every line
they touch: `aliasNodePathGlobals` regex-replaces `__dirname`/`__filename` with
`globalThis.`-prefixed forms, and the `import.meta.<prop>` replacement substitutes a
longer expression. AC2's "correct column" cannot survive either.

**The inventory must be *generated from the actual active transform graph*, not hand-written
— because a hand-written one was wrong in both directions.** An earlier draft listed
`aliasNodePathGlobals` as an active stage to retire; it is **dead code**, defined and never
called. It simultaneously *missed* live mapless stages (the dirname-binding transformation
and the eval-shim preamble). A list that both invents a stage and overlooks two is not an
inventory; it is a guess. Each stage the generator finds must **retire**, **emit a
composable map**, or **prove a stated stability property**:

| Stage | Disposition |
| --- | --- |
| TypeScript stripping, JSX, import lowering, TLA wrapping | **emit a map**; maps compose |
| §7 session lowering | **emits a map** |
| LLP 0019 tier 2 (for-of scanner) | **line-stable only.** It replaces the header and closing lines one-for-one, so *line* numbers survive — but it relocates the iterated expression and emits generated text on those lines, so **columns on rewritten lines do not survive**. An earlier draft claimed "line- **and column**-stable"; the scanner's own comment claims only line alignment. Either those lines carry a per-line map, or AC2's column guarantee is explicitly narrowed to exclude them |
| every other stage the generator finds | retire, map, or prove stability — no exceptions |

A stage that does none of the three, and silently moves code while §2's promise stands, is
non-conforming. Until the generated inventory passes end to end, the **source-positions
capability stratum (§6) advertises unavailable** — which is the honest state today, and
which `EngineFeature::SourceMaps => true` currently misreports.

If satisfying these changes what the Hermes-compat tiers emit, LLP 0019 is
amended in the same change rather than silently outgrown.

### 5. Completeness

Multiline continuation is judged by **parser-grade signals** — unterminated
blocks, strings, template literals, regular expressions, comments, or an
otherwise incomplete production — not by counting delimiters. Template-literal
interpolations, regex literals, and TypeScript syntax must not confuse the
judgment. The current hand-rolled bracket scanner does not satisfy this.

When completeness is genuinely ambiguous, the evaluator **fails safe**: it
submits and reports an ordinary recoverable syntax error rather than trapping
the caller in a continuation state that only a control command can escape.

### 6. Evaluation outcomes and the ABI

An evaluation returns a **discriminated outcome**, never a string:

| Outcome | Meaning |
| --- | --- |
| empty completion | the source produced no meaningful completion value (a declaration, an empty statement) |
| value | a completion value, delivered as a **value handle** — not pre-formatted text |
| throw | an exception: the thrown value as a handle, plus **optionally** a VM-captured message, stack, and source positions — with an explicit **`metadata unavailable`** discriminator when the engine cannot supply them without running user code (§8). A consumer must be able to tell "this stratum cannot capture error metadata" from "this value has none" |
| cancelled | evaluation was interrupted (LLP 0025) before completing |
| **lifecycle** | root code made a cooperative exit request (`process.exit(n)`). The native call **parks and never returns to JavaScript** — it does not unwind, because an unwind past `finally` is a mechanism no vendored Hermes interface offers (LLP 0025 §8). No code after the call in that input runs, `try`/`finally` cannot intercept it, and the outcome carrying `n` is delivered **out of band**, not returned from a frame that unwound. Because the parked worker is then disposed, the input's session state is **discarded, not rolled back** — there is no live evaluator frame to roll anything back, and the session is ending. No value handle is produced |

Empty completion and the value `undefined` are **distinct outcomes**, so a
consumer can display `undefined` for `void 0` and nothing for `let x = 1`
without string conventions.

That distinction is a **completion-record** fact, not a syntactic one: the seam
must recover whether the Script's completion record carried a value, per
ECMAScript's completion semantics (`UpdateEmpty` propagating through statement
lists, blocks, `if`, loops, and `try`/`finally`). Two implementations are
admissible — an engine primitive returning the completion record with an explicit
empty discriminator, or a semantics-preserving instrumentation that threads
`UpdateEmpty` — and one is not: a "take the last expression statement" heuristic
is **non-conforming**, because `if (false) { 1 }`, a trailing declaration, and a
`try`/`finally` whose `finally` completes normally all defeat it.

**Evaluator capability strata.** The evaluator advertises which of these it can supply,
and a consumer branches on the answer rather than guessing: **base** — structured
outcomes, handles, non-assimilation, and the *original thrown value* (which the engine can
surface without reading `.message`/`.stack` off it); **safe-throw** — VM-captured error
message, stack, and positions (§8 stage 1.5); **source-positions** — composed in-memory
maps through every rewrite stage (§4), which is **unavailable** until those maps exist end
to end, so `EngineFeature::SourceMaps` advertising `true` today is a lie the strata
retire; **rich-inspection** — the trap-free primitive (§8 stage 2).
The strata are versioned and independently testable, and *unavailable metadata is
always distinguishable from an ordinary opaque value*. Without this, §6's throw
outcome and §8's staging directly contradict each other, as an earlier draft did.

**The ABI is typed, length-bearing, and owns its handles.** The *result* half is
none of these: it returns a null pointer for `undefined` — collapsing it with empty
completion — and otherwise a NUL-terminated C string, which truncates a value
containing an embedded NUL *before* the consumer can escape it. (The *input* half is
already length-bearing — `ex_hermes_eval` takes `(data, len)` — so the defect is in
what comes back, not in what goes in.) The replacement fixes:

- an explicit **outcome tag** and an explicit **byte length** on every payload;
- a distinction between a **JavaScript throw** and an **engine fault** (an OOM, a
  rejected bytecode buffer, a poisoned runtime) — today both arrive as a non-zero
  return carrying a string;
- **value handles** — *engine references to live JavaScript values*, and only those; the
  armed-snapshot **token** of §1 is not one and does cross (§2) — rooted in, and scoped to,
  the runtime that produced them:
  explicitly retained and released, invalid once that runtime is destroyed, and
  usable only on that runtime's owning thread. A handle is **not** a serializable
  value and **never crosses a process boundary** — under LLP 0025 §7's presumptive
  supervisor/worker split, handles, the session record, and inspection all live in
  the **worker** with the engine, and what crosses to the supervisor is the outcome
  tag plus the bounded **inspection tree** of §8;
- **native publication of every work unit's begin and end.** A target id assigned in Rust
  around the FFI call cannot name a unit: one native poll drains a whole callback queue and
  several timers, so the boundaries exist only inside the engine. The seam therefore
  publishes them — for each of: an **evaluation**, a **background callback**, a **timer**, a
  **microtask drain**, and a **completion query**. LLP 0025 §6's interrupt machine cannot
  target what the engine does not name, and this is the obligation it places here;
- a **cancellation operation callable concurrently with an in-flight evaluation**.
  No such operation exists on the `Engine` trait today; the runtime lock is held
  across the whole native call, though the debugger thread deliberately bypasses it,
  so the lock is an obstacle to be designed around rather than a proof of
  impossibility;
- a capability split: the current `EngineFeature` reports `TopLevelAwait`,
  `EsmModules`, and `CommonJsModules` as `false`, which is true of the *native
  engine* and false of the *evaluator*. Native-engine capability and end-to-end
  evaluator capability are separate questions and get separate answers.

`ex_hermes_eval`'s current shape — `out_value` a malloc'd NUL-terminated string,
NULL meaning `undefined` — is part of **LLP 0002's narrow consumer contract**,
which is explicitly semver-major. Replacing it is therefore a semver-major change
to the embedding ABI, and **LLP 0002 (with LLP 0000, which moves with it) is
amended in the same change**, with a migration note for embedders.

This document fixes the ABI's *semantics* — the discriminants above, handle
ownership, the fault/throw split, and the concurrency rules. It deliberately does
not inline C structure layouts: the **normative byte-level schema is the LLP 0002
amendment's deliverable**, and it must carry a version field, explicit
discriminant values, allocation and free ownership, runtime and thread identity
checks with a defined error for a stale or wrong-runtime handle, and an
allocation-failure path that does not lose the outcome. It is verified from an
independent C consumer over the adversarial cases: embedded NUL, OOM with no
payload, stale handle, and a cancellation racing a normal return.

**A value is never assimilated.** A Promise or an arbitrary thenable that is an
input's value is returned as that object. The evaluator attaches no
continuations, calls no `then`, and performs no coercion in order to produce a
result — regardless of whether some other part of the input used `await`. The
input `await 0; ({ then() { sideEffect() } })` yields a thenable as its value
and never calls `then`. The current native unwrapping, which assimilates any
object with a callable `then` and waits on it, is retired. (It is also compiled
out on Windows today, so the platforms do not even agree with each other.)

**Settlement and delivery are separate channels.** An input containing top-level
`await` evaluates as one asynchronous unit; the caller awaits *that unit's*
settlement while the runtime drains the microtasks and ready native completions
needed for it. The unit must settle with a **private, non-thenable settlement
sentinel** (named to avoid colliding with the *session token* of §1/§2 — a different object), and the input's completion value must be delivered **out of band**, in a
rooted result slot.

This is not a stylistic preference. If the driving promise were resolved *with*
the user's value, ordinary Promise resolution would assimilate a thenable
completion value and call its `then` — reintroducing the exact defect the previous
paragraph retires. Non-assimilation must be **structural**, not a rule the
implementation is asked to remember.

A rejected unit is a `throw` outcome, delivered exactly once. There is **no
hidden result timeout**: a never-settling awaited evaluation waits until it is
cancelled. And no environment variable configures evaluation behavior after
arming — every knob the evaluator needs is captured before arming or is a fixed,
versioned constant. LLP 0025 §2 owns that inventory and its capture;
`IBEX_AWAIT_UNWRAP_TIMEOUT_MS` and its siblings are retired.

**Work has identity, and a request names it.** Each unit of work the engine executes
— a submitted evaluation, a background callback, a completion query — is assigned a
**monotonic target id** when it begins. A cancellation request **carries the id it
was raised against**, and the engine **discards a request whose id is not that of the
work it is currently executing** (LLP 0025 §6). Without the id, a request aimed at a
callback that has since finished would land on its successor: one native poll can run
several callbacks, and the engine's queued interrupt is documented to run exactly
once, so the hazard is real rather than theoretical.

**A request is `Pending` until it resolves, and it may never resolve.** `Pending` is
a state, not an outcome; the terminal results are: 

- **accepted** — the target stopped **because of the request**, producing the `cancelled`
  outcome, and the runtime passed its consistency check; state publishes per §7.4 for what
  completed; the runtime remains usable. A normal return that merely *races* the request is
  not accepted — it is *defeated*;
- **unavailable** — the engine declined to try; the caller is told so plainly and
  may escalate (LLP 0025 §6);
- **failed** — the runtime cannot be proven consistent afterwards; the session
  must end rather than continue on a suspect runtime;
- **defeated** — the request was delivered, the target kept running, and the target
  later ended **by another route** (it completed normally, or threw). The break did
  not take effect.

A request whose target is **permanently stuck** — an uninterruptible loop —
**remains `Pending` forever**, until runtime destruction or supervisor termination
resolves it `failed`. That is not an omission but the honest state, and LLP 0025 §6's
second-interrupt rule is the operator's only escape from it — which is exactly why
that rule may not depend on the engine cooperating.

*Accepted* is defined by the target **returning** and passing the consistency check —
never by a break having been raised. This document **does not assert whether a Hermes
async break is catchable**; LLP 0025 §6 enumerates three independent ways a request is
defeated or stuck (code compiled without break checks, a catchable break that user
code swallows, a non-returning native call), and every rule here holds under all
three. Silently continuing after a **failed** cancellation is never correct.

**Races.** At most one terminal result is delivered per request:

- a target that completes normally after a request was delivered yields its own
  outcome, and the request resolves **defeated** — not `accepted`;
- a request delivered after its target has already settled, or carrying a stale
  target id, is **discarded** and resolves `unavailable`;
- runtime destruction resolves every outstanding request `failed`.

**Every work unit is a cancellation target**, not just an evaluation: a submitted
input, a **background callback** (a timer or native completion running while no input
is in flight), and a **completion query** (LLP 0022 §9) each get a target id and
resolve under the same vocabulary, with one target-kind refinement stated so the two are
not read as contradictory: for an **evaluation** target, *accepted* means it stopped
because of the request and produced the **`cancelled` outcome**; for a **callback** or
**query** target, which has no outcome record, *accepted* means it **returned** and its
completed effects stand. `cancelled` is an evaluation outcome only.

### 7. The session record

A session is one environment that grows. Successful top-level declarations and
assignments in one input remain available to later inputs, **including** inputs
that contain top-level `await`: `const x = await f()` makes `x` available
afterwards. The async-IIFE lowering that discards such declarations today does
not conform.

**Target semantics.** One persistent environment in which redeclaration rules,
`const` immutability, and temporal-dead-zone behavior hold across inputs exactly
as if the session were one growing script — with the deviations enumerated in
§7.7, and no others.

**The v1 session record is an algorithm, not a table of adjectives.** A
publication table alone cannot answer whether

```
input 1:  let x = 1
input 2:  const f = () => x
input 3:  x = 2
input 4:  f()          // 1 under copy-out publication, 2 under shared bindings
```

yields `1` or `2`. The answer must be *specified*, not discovered. v1 specifies
**shared bindings**, so this yields `2` — a closure observes a later write from
another input, exactly as it would in one growing script. (Input boundaries are
part of every example and fixture below: the same four lines *as one input* are a
different program, and §7.7's corpus schema requires them to be marked.)

#### 7.1 The environment: a modified `GlobalEnvironmentRecord`

The session environment is ECMAScript's **`GlobalEnvironmentRecord`**, with the
modifications enumerated in §7.7 and no others. Saying it that way is not a
flourish — it imports two decades of specified edge cases (`typeof` on a missing
name, sloppy undeclared assignment, a lexical binding coexisting with a same-named
global property, accessor globals, inherited properties) instead of re-deriving
them, badly, here. An earlier draft did re-derive them and got them wrong.

It has the standard two halves plus the standard bookkeeping:

- an **object record** whose binding object is the **realm global object** — *not* the
  value of the `globalThis` property, which is writable. Replacing `globalThis` with
  another object does **not** move the environment: both Node and Hermes keep putting later
  `var`s on the retained realm object (measured). This document says "`globalThis`" as
  shorthand for the realm global throughout; where the two could differ, the realm global
  governs. It holds `var` and `function` bindings *and* every ordinary global — `Object`,
  `Promise`, `console`, the endowments — *and* anything reached through its prototype chain.
  **The property is the storage**: a `var` binding *is* a realm-global property, not a copy
  of one.
- a **declarative record**, evaluator-owned, holding the **lexical** bindings —
  `let`, `class`, `const`, `import`. Each is a **cell**: a **kind**, an
  **initialized** flag, and a **value**. These are not `globalThis` properties.
- **`[[VarDeclaredNames]]`** — the set of names the *session* has declared with `var`
  or `function`. This is ECMAScript's own list, and it distinguishes a session-declared
  `var x` from a realm builtin, an endowment, an inherited property, or a property some
  code merely assigned. It is bookkeeping; it is never the storage.
- **`[[SessionCreatedVars]]`** ⊆ `[[VarDeclaredNames]]` — the names for which the record
  **created** a realm-global property *at a point when the name had no **own** property*
  (`CreateGlobalVarBinding` or `CreateGlobalFunctionBinding` on such a name), as opposed to
  **adopting or overwriting** a pre-existing own property. **A `function` declaration that
  overwrites a pre-existing own property is *not* a create** — it changed the value of a
  name that already existed, so the name does not enter this set. This closes the `function`
  analogue of the `var undefined` launder: `function p(){}` over a non-configurable endowment
  leaves `p` restricted, so a later `let p` is refused, matching real Script semantics
  (measured: Node rejects `let p` after `function p` over a non-configurable property).
  Inherited-only names count as *no own property*, so declaring over one is a create. The
  distinction is the key of the restricted-global predicate (§7.3): a predicate on what a
  name *is* can be laundered by adopting or overwriting a builtin, while a predicate on how
  the name *came to exist* cannot. A name enters this set at creation; the exit path (a
  later `delete` re-freeing the name) is defensive only — created properties are
  non-configurable and cannot be deleted by user code, so on the current engine it is
  unreachable, and it is retained solely for a hypothetical configurable-bindings future.

> **Why this document is gated by an executable model and not by prose — a rule, not a
> preference.** This predicate was *described as re-keyed on `[[SessionCreatedVars]]` in a
> revision note one round before the predicate text was actually changed*: a silent edit
> that never matched, leaving the laundering path open while the note claimed it closed. That
> is the exact disease this whole corpus exists to catch — **a claim that reads true and is
> false** — turned on the author's own tooling. A revision note is a *claim about a change*,
> and a claim about a change is worth nothing until the change is verified to have happened —
> the identical rule to "an attestation without a content hash is not an attestation"
> (LLP 0025's ledger) and "provenance without a hash is a story you tell yourself" (LLP 0023's
> identity work). The four gates exist so that a session rule cannot be *asserted* correct,
> only *measured* correct: gate 2b would have failed the unpopulated predicate against real
> Script semantics without waiting for a human to re-read the file. **An unverified claim of
> completion is the failure mode wherever it appears** — in a predicate, an attestation, a
> provenance record — and the discipline is identical: verify the artifact, never the
> description of it. (This defect was found by two independent reviewers reading the file, and
> a *second* silent edit — a noun rename — was found the same way the next round; the count
> is why the model, not the prose, is normative.)

**Resolution order** for an identifier, exactly as ECMAScript resolves one:

1. the input's own lexical scopes (blocks, functions, parameters) — ordinary engine
   scoping, not session state;
2. the **declarative record** — a lexical session cell, which *shadows* any
   same-named global property;
3. the **object record** — `globalThis` **and its prototype chain**;
4. otherwise **unresolvable**.

From which the ordinary Script behaviors follow, and are required:

- `Object`, `Promise`, `console` resolve through step 3. A free identifier with no
  session cell does **not** throw merely for lacking one.
- **`typeof x` on an unresolvable name is `"undefined"`**, not a throw. But
  `typeof x` *inside `x`'s temporal dead zone* throws `ReferenceError`, as
  ECMAScript requires. Only an *evaluated reference* to an unresolvable name throws.
- Sloppy assignment to an unresolvable name creates an ordinary **configurable**
  `globalThis` property — and does **not** add the name to `[[VarDeclaredNames]]`,
  because no `var` was declared. `var x = 1` creates a **non-configurable** one and
  does.
- A lexical cell **coexists with** a same-named global property rather than
  replacing it — in **both** orders. After `let x = 1` then `globalThis.x = 2`,
  `x` is `1` and `globalThis.x` is `2`; after `globalThis.x = 2` then `let x = 1`,
  the same. **A lexical declaration never deletes a property.** This is ordinary
  Script semantics, and it is the rule an earlier draft got backwards — with the
  consequence that `let Object = 1` would have deleted `globalThis.Object` and
  broken every subsequent import.

**Cell kind is checked on every access**, which is where the engine's gaps are made
good (§Engine premises): assigning to a `const` cell throws a **`TypeError`**;
`import` cells are read-only; and reading an **uninitialized** cell throws a
`ReferenceError` (temporal dead zone).

**The mechanism.** Because the engine supplies none of those three checks, the
lowering rewrites **every free identifier in a session input** into an environment
operation against this record. The operations implement the resolution order above,
so the fallthrough to ordinary and inherited globals, and the `typeof` rule, come
for free rather than being re-implemented. The cost is confined to session inputs;
imported *modules* are ordinary source and are not rewritten at all — which is
exactly why session lexicals are invisible to them (deviation (d), §7.7).

**The lowering must preserve Reference semantics, not merely name resolution.** A
naïve rewrite changes observable behavior: `x++` has a defined coercion and
ordering, `x += f()` evaluates and stores in a defined order, a `const` initializer
must *initialize* an uninitialized cell where a later assignment must *throw*, and
an unresolvable write throws in strict mode and creates a global in sloppy mode. The
lowering is therefore specified as a **syntax-directed table over ECMAScript's
abstract operations** — `ResolveBinding`, `GetValue`, `PutValue`,
`InitializeReferencedBinding`, `CreateMutableBinding`, `CreateImmutableBinding`,
`typeof`, `delete` — covering at least: plain reference, call and `new` (which must
not acquire a receiver the source did not have), tagged templates, update
expressions, compound and logical assignment, destructuring assignment targets,
`for (x of …)` and `for (x in …)` heads, and strict-versus-sloppy unresolvable
writes. Side-effect-order fixtures are required for every reference-bearing form (§4), and the
inventory of reference-bearing AST contexts is **generated from the parser's node set**,
so a grammar addition that introduces a new one fails the build rather than silently
falling through to a wrong lowering.

**The lowering's own hooks are a private seam.** The environment operations the rewrite
emits are backed by intrinsics that user-authored source **cannot reach, name, or forge** —
they are not `globalThis` properties, not reachable through any endowment, and they carry a
registry row saying so (LLP 0021's no-unclassified-surface invariant), exactly as §8's
display seam does. A reachable `__session.set` would be a route to write any `const` in the
session.

#### 7.2 Binding time: late binding by name

**A free identifier resolves through the record by name, at each reference.** It
does not capture a cell. A closure created in one input therefore sees whatever its
names denote *when it runs*, including a cell installed by a later input.

This rule is chosen deliberately, and it is what makes the model uniform:

- It preserves the flagship result above (`f()` → `2`).
- It is the only rule that survives a *kind change*. A reference compiled while `x`
  was `var`-kind must still see the lexical cell that a later input puts in its
  place; a rule that captured cells, or that compiled `var` reads to raw global
  lookups, would answer `ReferenceError` after `var x = 1` is shadowed by
  `let x = 2`.
- It makes rollback (§7.4) coherent: a failed input's replacement can be undone
  without leaving a closure pointing at a cell that no longer exists.

**Precedent, measured rather than remembered — and claimed only as far as it goes.**
Of the runtimes that permit cross-input lexical redeclaration, **Deno 2.9.1 and Bun
1.3.12 both yield `2`** for `let x = 1` / `const f = () => x` / `let x = 2` / `f()`.
That rules out *retaining the old value*; it does **not** by itself distinguish
late name lookup into a replaced cell from mutation of one reused cell, and this
document does not claim it does. Late binding is chosen for the reasons above, and
the precedent is cited only for what it measures. (Node 25 sidesteps the question
entirely by refusing the redeclaration as a `SyntaxError` — the behavior deviation
(a) exists to avoid.)

On `const`, the precedents **disagree, and this document follows the language**:
Deno throws `TypeError` on assignment to a prior-input `const`; **Bun does not — it
silently accepts the write** (measured on 1.3.12: `const c = 9` then `c = 10` leaves
`c` as `10`). Ibex follows Deno and ECMAScript. A writable `const` is not a
compatibility concession but a different language, and LLP 0022's compatibility
order puts language correctness above REPL familiarity. The divergence from Bun is
deliberate and recorded here so that it is a decision rather than a surprise.

Names bound in the input's *own* inner scopes — a block, a function body, a `for`
head — are ordinary lexical bindings, not session names. Only **top-level**
declarations enter the record.

#### 7.3 Evaluation phases, collisions, and the cross-kind matrix

An input is evaluated in **phases**, and which phase an abrupt completion occurs in
decides what survives (§7.4):

1. **Parse and early errors.** The whole input is parsed and validated. Nothing mutates.
2. **Declaration collection.** The input's `VarDeclaredNames` and
   `LexicallyDeclaredNames` are collected from the source *after* TypeScript lowering
   (§4), so an `enum` or a value-bearing `namespace` arrives as a `var` name.
   Collisions are ECMAScript's Script static semantics, **keyed by kind** — not a
   blanket rule:
   - duplicate **lexical** `BoundNames` → `SyntaxError` (`let a; let a`; `let [a, a]`);
   - a lexical name colliding with a `var` name in the same input → `SyntaxError`;
   - an `import` binding colliding with either → `SyntaxError`;
   - duplicate **`var`** targets are **legal**: `var [a, a] = [1, 2]` yields `2`, as in
     any Script. An earlier draft made this a `SyntaxError`; that was simply wrong.

   A `var` inside a block still contributes to `VarDeclaredNames`; sloppy block-level
   function declarations follow **Annex B**. A same-input `var f; function f(){}` follows
   ECMAScript `GlobalDeclarationInstantiation` unchanged — the function binding wins — and is
   pinned by the model's fixtures (`OBL-EXEC-MODEL`), not hand-written here. Nothing mutates
   in this phase, so a collision leaves the session untouched.
3. **Feasibility.** ECMAScript's `CanDeclareGlobalVar` and `CanDeclareGlobalFunction`
   are evaluated for **every** name **before any** mutation, and the input fails
   atomically if any says no. These catch what a hand-rolled check misses: a
   non-extensible `globalThis` (a fresh `var` throws `TypeError` — measured), a
   non-writable or non-configurable existing property under a `function` declaration,
   and an accessor where a data property is required.

   The **restricted-global** predicate is ECMAScript's, *modified*, and the modification
   is stated because §7.1 promises there are no unstated ones. Standard
   `HasRestrictedGlobalProperty` is descriptor-based — any non-configurable own global
   property is restricted — and session `var`s **are** non-configurable, so importing it
   verbatim would refuse `var x ⏎ let x`, which the matrix requires to *shadow*. But the
   obvious repair — "restricted unless the name is in `[[VarDeclaredNames]]`" — is
   **launderable**: `var undefined` is legal and inert (it *adopts* the existing property),
   and it would add `undefined` to `[[VarDeclaredNames]]`, after which `let undefined` is
   admitted. `NaN`, `Infinity`, and every non-configurable endowment launder the same way.

   The session predicate therefore keys on **creation provenance**, not on `VarDeclaredNames`
   membership: **a lexical declaration is restricted iff the name has a non-configurable own
   global property that the session record did not itself *create*** — i.e. the name is not
   in `[[SessionCreatedVars]]` (§7.1). Adoption is not creation, so a builtin stays
   restricted forever: `var undefined ⏎ let undefined` is **refused**, while `var x ⏎ let x`
   **shadows**. This modification is the *mechanism* of deviation (a), not a separate
   deviation, and it is the reference model's, so gate 2b measures it against real Script
   semantics (`var undefined ⏎ let undefined` → `SyntaxError` on V8 — measured).
4. **Import evaluation.** Hoisted static imports evaluate in source order (§3).
5. **Re-check, then instantiate — one atomic step.** Phase 4 ran **arbitrary user code**
   (imported module bodies *and* the property Gets that extract each import binding's
   value — CommonJS named/default extraction is an ordinary Get, which can fire an accessor
   or a Proxy trap). So phase 3's answers are stale: an import can call
   `Object.preventExtensions(globalThis)`, or install a non-configurable property at a name
   this input declares. **All of that user code is confined to phase 4**: phase 4
   materializes and roots every import binding *value* before phase 5 begins, so phase 5
   reads only captured values and runs no Get.

   Phase 5 then **re-evaluates the complete phase-3 feasibility vector** — not only
   `CanDeclareGlobal*` for `var`/`function`, but the **modified restricted-global predicate
   for every lexical name too**, since an import can install a non-configurable property at
   a name the input `let`s. Only after the whole vector passes does it create bindings per
   the matrix, create lexical cells **uninitialized**, update `[[VarDeclaredNames]]` and
   `[[SessionCreatedVars]]`, and install the captured import values.

   This makes phase 5 **atomic without any engine support**, which is the whole point:
   between the re-check and the mutation **no user code runs** — an ordinary
   `DefineOwnProperty` on the realm global, from an already-captured value, fires no getter,
   setter, or trap.

   **"No user code" is not "uninterruptible", and phase 5 must be both.** Because §6 allows
   a cancellation request *concurrently* with an in-flight evaluation, an async break could
   otherwise land *between* two phase-5 mutations, after a non-configurable property has been
   created and before the rest — a partial state the "rollback never touches the object
   record" invariant cannot repair. Phase 5's re-check-plus-commit is therefore a
   **cancellation critical section**: a request delivered during it is **deferred to its
   boundary** (the commit is a bounded, user-code-free sequence, so the deferral is bounded),
   and an interruption that cannot be deferred resolves the evaluation **`failed` with worker
   disposal** (§6) rather than publishing a half-instantiated record. The mutation cannot
   fail partway, so there is never a half-instantiated record to undo. A **re-check failure is an ordinary `throw` outcome that publishes
   nothing**; the imports' own effects, having already happened, stand. (An engine *fault*
   during the inert commit — an OOM — is not a `throw`: it poisons the runtime and ends the
   session per §6, since a partially-mutated realm cannot be proven consistent.)

   Without the re-check, `import "./m"; var x = 1` — where `m` calls
   `preventExtensions(globalThis)` — would publish some non-configurable bindings and then
   fail on the rest, precisely the impossible-rollback state the phase reorder exists to
   eliminate. Moving imports earlier removed the *rollback* problem; only the full-vector
   re-check removes the *interference* problem.
6. **Statement evaluation.** The input's statements run; lexical cells initialize as
   their declarations evaluate.

**Imports evaluate *before* instantiation, and that ordering is load-bearing.** An
earlier draft instantiated first, which made a failing import require *removing* the
`var` properties phase 4 had already created — and a fresh session `var` is
**non-configurable**, so it cannot be deleted at all (measured: `delete globalThis.v`
returns `false`). The rule "an import that throws publishes nothing" was therefore not
merely unimplemented but *unimplementable*. With imports first, a failing import throws
before anything has been instantiated, so the rule is **trivially true**, no property
ever needs deleting, and rollback never has to touch the object record (§7.4). No VM
transaction API is required; ordinary JavaScript suffices.

The ordering is unobservable except in one direction: an imported module cannot see the
importing input's hoisted `var`s (they do not exist yet). A growing script has no
combined form to compare against — `import` is not a Script production — so this
introduces no oracle-checkable divergence.

**Redeclaration is replacement, not assignment.** A later input that declares an
existing name *replaces* the binding — new kind, new initialized flag, new value —
rather than assigning through the old one. This is what makes an interactive session
usable (`const x = 1` then `const x = 2` must work), and it is precisely
distinguishable from assignment: replacement does not throw for a `const`, it may
change the kind, and `let x` with no initializer resets the value to `undefined`
where an assignment would not.

**A lexical declaration never deletes a global property — it shadows it.** That is the
rule the matrix turns on, and it is what keeps `let Object = 1` from destroying
`Object`. The matrix is keyed on the **full state** of the name — declarative cell,
membership in `[[VarDeclaredNames]]`, and the own/inherited/absent property with its
descriptor — and it distinguishes `var` from `function`, which an earlier draft wrongly
merged:

The **populate** column records whether the name enters `[[SessionCreatedVars]]` —
*created* means the record made the property, *adopted* means one already existed — which
is the distinction the restricted-global predicate (§7.3) turns on.

| State of the name | New declaration | Result | Populate |
| --- | --- | --- | --- |
| nothing anywhere | `var` | create a **non-configurable**, writable, enumerable own property (`CreateGlobalVarBinding`); add to `[[VarDeclaredNames]]` | **created** |
| nothing anywhere | `function` | `CreateGlobalFunctionBinding`: **define** an own property (writable, enumerable, non-configurable) holding the function; add to `[[VarDeclaredNames]]` | **created** |
| in `[[VarDeclaredNames]]`, own property present | `var` | **no-op on the property** — a re-declaration without an initializer does **not** reset it (`var x = 1 ⏎ var x` leaves `x` as `1`) | unchanged |
| in `[[VarDeclaredNames]]`, own property present | `function` | **overwrite** with the reset descriptor above (a `DefineOwnProperty`, not a value-only write — measured: clobbering a configurable `Object` flips it to enumerable/non-configurable) | **unchanged** — the name already had a property; an overwrite is not a create |
| in `[[VarDeclaredNames]]`, own property **deleted** by user code | `var` / `function` | recreate it as if fresh | **created** |
| **kindless own property** (builtin, endowment, or one code merely assigned) | `var` | **adopt it**: `CreateGlobalVarBinding` leaves an existing own property **untouched, descriptor and all** — so bare `var Object` is a **no-op** and `Object` survives, and adopting a *configurable* property leaves it configurable and deletable (measured). Add the name to `[[VarDeclaredNames]]` | **adopted** — *not* created, so a later `let` of this name stays restricted (this is what closes `var undefined ⏎ let undefined`) |
| **kindless own property** | `function` | **overwrite it.** `function Object(){}` *does* clobber the builtin's value (measured) — `CreateGlobalFunctionBinding` is a `DefineOwnProperty`; the asymmetry with `var`'s no-op is ECMAScript's, not ours | **not created** — the name had an own property, so overwriting its value does **not** enter `[[SessionCreatedVars]]`; a later `let` of this name stays restricted (closes the `function` laundering path, ENG-24463-adjacent) |
| **inherited** name only | `var` | create a fresh **own** property initialized to `undefined` (it does not adopt the prototype's) | **created** |
| **inherited** name only | `function` | create a fresh own property holding the function | **created** |
| any of the above | `let` / `class` / `const` / `import` | **shadow**: create a lexical cell; the property is **left untouched**, whatever it is. `x` reads the cell; `globalThis.x` still reads the property | n/a (lexical) |
| a lexical cell exists | `var` / `function` | **replace**: remove the lexical cell from the declarative record (never a property deletion), revealing the object record beneath, then apply the appropriate row above | per that row |
| a lexical cell exists | `let` / `class` / `const` / `import` | **replace** the cell | n/a (lexical) |

The only deletion anywhere in this table is of a **lexical cell from the evaluator's own
declarative record**. **No rule deletes a `globalThis` property.**

One consequence looks odd until it is placed: after `var x = 1` then `let x = 2`, `x` is
`2` while `globalThis.x` is still `1`. That is not an oddity invented here — it is
exactly what ECMAScript does for the *legal* single-script analogue
`globalThis.x = 1; let x = 2`, which likewise leaves the property at `1` and the
identifier at `2`. A lexical binding **shadows** a property; it never owns it.

**Destructuring** declares every name in its pattern in phase 2 and initializes them
in evaluation order in phase 6. A pattern that throws partway leaves the names it had
already initialized initialized and the rest as phase 4 left them; §7.4 then decides
what survives.

**`eval` and `Function` are closed** in the v1 profile (LLP 0022 §1, LLP 0021). This
document therefore specifies **no** session semantics for direct or indirect `eval`,
and an implementation must not infer any. The closure is a **precondition of session
submission**, not an assumption: the engine is created with eval enabled today and
the taming lives in an environment-gated lockdown branch (though the CLI now force-sets
`IBEX_LOCKDOWN=1` unconditionally, so that gate is vestigial on the CLI path — the
**fixture**, not the env var, is the guarantee), so conformance requires a
fixture proving that direct `eval`, indirect `eval` aliases, `Function`, and every
reachable `%Function%` route are unavailable in the armed profile *before* any source
is submitted. The engine could not honor a lexical-scope contract for direct `eval`
in any case (§Engine premises).

#### 7.4 Commit and rollback

An input's bindings are **live from instantiation** — code that runs during the input,
including a callback that fires while the input is suspended at an `await`, sees them
(in TDZ if not yet initialized). What survives a *failure* is a transaction question,
answered by a journal rather than by prose.

**Rollback never touches the object record.** This is the invariant that makes the whole
thing implementable in ordinary JavaScript. Phase 5 creates `globalThis` properties; a
fresh session `var` is **non-configurable** and cannot be deleted, so if rollback had to
remove one it would be *impossible*, not merely awkward. It never has to:

- an abrupt completion **before** phase 5 (parse, collection, feasibility, or a throwing
  **import**) leaves the object record untouched because nothing was instantiated. This
  is what makes §3's "an import that throws publishes nothing" true rather than
  aspirational: `import "./boom"; var w` leaves **no** `w`, because `w` was never created.
- an abrupt completion **in phase 6** leaves every `var`/`function` binding the input
  created **in place**, holding the value it holds at that moment. `var w = 1; boom()`
  leaves `w` as **`1`** — a throw in a script does not un-hoist a `var`, and it does not
  undo the assignment that already ran. This is not a concession; it is what the growing
  script does.

So the **journal** covers exactly one record: the **declarative** one. It records each
lexical cell the input created or replaced, together with the **displaced binding** —
which may be a lexical cell *or* a realm-global property this input's `var`/`function`
took over.

**One rule decides every cell's fate: a binding the input declared *commits iff that
cell reached its own `InitializeBinding`*** — per **cell**, not per statement. A
`var`/`function` reaches initialization in phase 5 (it is created there), so it **always
commits** — a phase-6 throw never un-hoists it. A lexical cell reaches initialization when
*its own* binding is initialized: for `let x = boom()` whose initializer throws, or an input
that fails before reaching the declaration, the cell **never initializes**; for a
destructuring `let [a, b] = iter()` where `iter` yields `a` then throws, `a` initialized and
**commits** while `b` never did and is **removed** — the rule is per-target, matching
ECMAScript's ordered pattern binding, not "when the statement completes". Then:

- a cell that **committed** stays, and any binding it displaced is **gone** — an ordinary
  redeclaration. `let x = 1; boom()` leaves `x` as **1** (it initialized before `boom`);
  `let x = 1 ⏎ var x = 2; boom() ⏎ x` yields **2** with `globalThis.x` = **2** (the `var`
  committed in phase 5 and survives the throw; the displaced `let x = 1` is gone — there is
  no coherent state in which a restored cell shadows a surviving `var`);
- a cell that **never initialized** is removed, and any binding it displaced is
  **restored**. `const x = 1 ⏎ let x = boom()` leaves `x` as the original `const` holding
  **1** (the `let` never initialized, so it is removed and the `const` is restored); a
  fresh `let x = boom()` leaves `x` free again.

The slogan therefore narrows, exactly as the rule requires: **an input that fails *before
its replacement binding commits* cannot destroy a prior binding.** An input whose
replacement *does* commit (a `var`, or a `let` that initialized) and then throws has
performed an ordinary redeclaration, which is not a failure to undo.

Further consequences, each pinned:

- **Rollback is scoped to the names the input declared.** A module that writes
  `globalThis.fresh = 1` during phase 4, or a callback that writes anything during a
  suspension, is untouched. "The record is restored" never meant "the world is reverted".
- **`[[VarDeclaredNames]]` and `[[SessionCreatedVars]]` follow the property.** They are not
  rolled back for a `var`/`function` that committed (which is always, on a phase-6 throw),
  so after `var w = 1; boom()`, `w` is in both sets and a later `let w` **shadows** it. A
  property never created (a re-check failure at §7.3 phase 5, which precedes all mutation)
  leaves the sets untouched, because nothing was added.
- **A write through a binding that rollback removes is discarded with it.** If input 1
  leaves a callback that assigns `x`, and input 2 declares `let x` (replacing the cell) and
  then fails before initializing it, the write went into the replacement cell, which
  rollback removes. That is unavoidable: the binding it wrote to no longer exists.
- A **failed parse** publishes nothing and advances no state but the source ordinal.
- A **cancelled** evaluation publishes exactly what a throw at the same point would.
- The `$_` auto-update disable follows §7.8's fate table, which is journaled per its
  trigger.

**Phases 1–5 run within one job — no microtask checkpoint anywhere among them.** The
phase-5 re-check is atomic precisely because nothing drains the microtask queue between the
re-check and the mutation. A module imported in phase 4 that calls `queueMicrotask` does
**not** get that job drained before phase 5; the job runs at the input's **first phase-6
checkpoint** (a suspension at `await`, or settlement), and is classified **background**
(§9), not part of the input's outcome. So `import "./m"; firstStatement` — where `m` queues
a microtask — runs `firstStatement` before that microtask, and an import-queued throw is an
asynchronous failure event, never the input's throw. This is the only rule under which the
phase-5 atomicity argument holds, so it is stated rather than assumed.

**The settlement boundary.** An input's evaluation settles when *its own unit* settles and
the microtasks that unit needs have drained. A throw from an **unrelated** job drained in
the same native call — `let x = 1; queueMicrotask(() => { throw 0 })` — is an
**asynchronous failure event** (§9), not the input's outcome: the input succeeds and
publishes `x`. Jobs belonging to the input's own TLA settlement unit are part of it;
everything else — including import-queued jobs — is background. Without this line, an
unrelated timer's throw could silently unpublish a successful input.

**Background work is inside the input's window but outside its transaction.** Work that
runs while an input is suspended at an `await` commits its own effects immediately and
independently, and is not rolled back if the input later fails — subject to the
discarded-write rule above.

#### 7.5 `globalThis` reflection

`var` and `function` bindings **are** `globalThis` properties (§7.1). The descriptor
depends on how the binding came about, and the distinction is ECMAScript's:

- a property the record **created** for a `var` is writable, enumerable, and
  **non-configurable**, so `delete globalThis.x` returns `false` and the binding stands;
- a property the record **adopted** — one that already existed when a `var` declared the
  name — keeps **its own descriptor**. Adopting a configurable property leaves it
  configurable, and `delete globalThis.x` then **succeeds** (measured). The name stays in
  `[[VarDeclaredNames]]` with no own property: reads throw `ReferenceError`, `typeof` is
  `"undefined"`, and a later `var x` recreates it as if fresh;
- a property a `function` declaration defined is a `DefineOwnProperty`, so it overwrites
  whatever was there — including a builtin;
- a property code merely assigned (`globalThis.x = 1`, or a sloppy undeclared assignment)
  is an ordinary **configurable** data property and is **not** in `[[VarDeclaredNames]]`.

Lexical cells are not `globalThis` properties at all, and shadow same-named ones.

Because the property *is* the storage, ordinary object semantics apply and are required:
deleting an own property whose name is also inherited **reveals** the inherited one
rather than yielding a `ReferenceError`; an accessor defined over a configurable property
thereafter **controls identifier reads** of that name; and a lexical cell shadows all of
it while it exists, revealing it again when a later `var` declaration removes the cell.

#### 7.6 Temporal dead zone, and the engine-local semantics this document does *not* own

TDZ is enforced **for lexical session names**, by the cell's initialized flag — the only
place it *can* be enforced, since the engine has none (§Engine premises). `x; let x = 1`
in one input throws `ReferenceError`; so does `let x = f()` where `f` reads `x`; and so
does `typeof x` inside `x`'s dead zone.

TDZ for **block-local** bindings inside an input, and **per-iteration loop bindings**,
are the engine's behavior and **not this document's**: shipping Hermes has neither
(`for (let i…)` closures capture `3,3,3`). Compensating for that is LLP 0019's subject.
This matters for more than tone — it is why the gates below are engine-relative: a
session-versus-standards-engine comparison would attribute `3,3,3` to this document's
session model, when it is a fact about the engine that one growing script exhibits equally.

#### 7.7 Deviations, and the four gates that prove them

The complete list of deviations **from one growing script on the same engine**:

- **(a)** **any cross-input redeclaration a growing script would refuse** is permitted, as
  replacement — not only lexical-over-lexical but every cross-kind pair (`var`→`let`,
  `let`→`var`, `function`→lexical), each of which is a `SyntaxError` in one script
  (measured). The modified restricted-global predicate of §7.3 phase 3 is its mechanism;
- **(b)** `import` bindings are **values copied at import** rather than live bindings
  (the word "snapshot" is reserved for the armed snapshot — §2);
- **(c)** a lexical cell that an input declared but **never initialized** — because the
  input failed first — is removed rather than left permanently in the temporal dead zone,
  so its name is redeclarable (§7.4). A lexical cell that *did* initialize **survives**, as
  a `var` does: `let x = 1; boom()` leaves `x` as `1`, matching Node and Deno, and matching
  the neighbouring `var w = 1; boom()`. An earlier draft rolled back *every* lexical cell,
  which introduced a keyword-dependent asymmetry that no growing script exhibits and that
  would have surprised every operator who hit it. The deviation is only what TDZ poisoning
  forces, and no wider;
- **(d)** **session lexical bindings are invisible to imported modules**, because the
  declarative record is evaluator-owned and only rewritten session inputs consult it. In a
  realm with a real global declarative record a global `let` *is* visible realm-wide
  (measured). Two sub-cases, and they differ:
  - a **root / first-party** imported module sees session `var`s (they are real
    `globalThis` properties) but not session lexicals;
  - a **package** module *should* see **neither** — LLP 0013 gives each package a "private
    compartment global" whose properties are "exactly the policy's endowments" — but
    **today it sees session `var`s, and that is a disclosure channel this document's own
    design creates.** The shipping compartment is a `Proxy` whose `get` trap **forwards
    every non-withheld name to the real global**, withholding only `__exact*`/`__ibex*` and
    a finite powerful-name set. A session `var` is an ordinary name on the realm global, so
    a package's bare `secret` reads it. An operator typing `var apiKey = "…"` at the prompt
    hands it to every package in the graph.

    "Private global" therefore names a **forwarding view**, not isolated storage — the same
    noun-reuse failure that bit *identity* and *defeated*, and this time it is load-bearing
    for a security claim.

    **The requirement this document places on LLP 0013:** a package must not observe
    **session-authored global state** — not its values, its existence (`in`/`has`), its
    descriptors, or its enumeration. **What leaks *today* is narrower than all four, and
    stating it precisely matters:** the shipping compartment defines only `get`/`has`/`set`
    over a bare `Object.create(null)` target (`makeCompartment`, `hermes_runtime.cc:2628`),
    so **values and existence forward to the real global, while `getOwnPropertyDescriptor`
    returns `undefined` and `ownKeys` is empty** — descriptors and enumeration do *not* leak
    yet. The requirement forecloses all four (a future forwarding descriptor/`ownKeys` trap
    would open the other two); the *fact* is that get/has leak now. Overstating the live
    hazard would be its own dishonesty.

    **The withhold-`[[SessionCreatedVars]]` patch is a partial mitigation, not the fix, and
    this document does not overclaim it.** `[[SessionCreatedVars]]` is the *restricted-global*
    set (§7.3) — names whose property the record **created** — and it is deliberately
    narrower than "session-authored": it excludes a **sloppy assignment** (`apiKey = "…"`,
    which creates an ordinary property in no session set) and an **adopted-then-assigned var**
    (`var TextEncoder = 417`, which writes a session value into a builtin's slot). Both still
    forward to a package today. An operator cannot be expected to know that `var apiKey = s`
    would be withheld while `apiKey = s` is not.

    The **complete** fix is therefore not a withhold list at all: the compartment must stop
    forwarding to the *live* realm global and resolve bare names against a **baseline
    captured at arming** (its endowments plus the intrinsics frozen at lockdown), so that
    *no* session-authored name of *any* spelling is reachable, by construction. That is
    LLP 0013's to design; this document states the requirement and the residual precisely.
    Until it lands, deviation (d)'s package sub-case is **a stated leak, not an asserted
    isolation** — and the fixtures assert closure for every spelling (`var`, sloppy,
    adopted-and-assigned), all of which fail today.
- **(e)** **instantiation is per input, not per session.** A growing script hoists and
  instantiates over its whole text; a session cannot see the future. This covers both a
  call in one input failing to reach a `function` declared in a later one, *and*
  initialization-order effects — `var x = 1` then `function x(){}` leaves `x` as the
  function, where the growing script leaves `1`.

`const` immutability, TDZ for lexical session names, shared-binding closure semantics, the
resolution order, the descriptor rules of §7.5, and the matrix are **not** deviations —
they hold. **Narrowing a deviation is a versioned contract change.**

**§7 is normative executable data, not prose.** Every table above is *generated from* a
small owner-authored **reference model** (tracked as `OBL-EXEC-MODEL`; **the §7 tables in
this document are an interim projection of that model, not the normative source** — the
model, checked in and digest-bound, is) — a state machine over (declarative record,
object record, `[[VarDeclaredNames]]`, `[[SessionCreatedVars]]`, the journal, and `$_`'s
disable bit + accessor identity) with the declare / resolve / assign / rollback operations — and the fixtures are generated from the same model. This is not a
stylistic preference: this section's tables were falsified by hand-review in three
consecutive rounds (a rule that deleted `globalThis.Object`; a rollback that required
deleting a non-configurable property; a `var`/`function` conflation), and a table that
cannot be executed cannot be trusted. LLP 0025 reached the same conclusion about its
interrupt machine for the same reason.

**Four gates, with disjoint jobs**, because a single oracle conflated all of them:

| Gate | Compares | Domain | Catches |
| --- | --- | --- | --- |
| **1. Model conformance** | the implementation vs. the **reference model** | every session | session-semantics bugs |
| **2. Model validation** | the **reference model** vs. one growing script **on the same engine, through the same lowering** | the *restricted class* below | a wrong model |
| **2b. Model correctness** | the **reference model** vs. real **Script semantics on a standards engine** (`vm.runInThisContext`), quirk-filtered | the descriptor matrix and the created/adopted rows | **a wrong model of ECMAScript** |
| **3. Lowering fidelity** | one input through the lowering vs. the same input run directly | single inputs | rewrite bugs, Reference-semantics slips |

**Gate 2b exists because gate 2 is blind in exactly the rows that matter.** An
engine-relative oracle cannot see a wrong *model of ECMAScript* in a row the engine itself
gets wrong — and Hermes does get rows wrong: it does **not** preserve an adopted property's
descriptor (it rewrites `{writable:false, enumerable:false, configurable:true}` to
writable/enumerable/non-configurable, and turns a configurable accessor into a data
property — both measured). Two consequences, both normative. First, §7's descriptor
semantics (§7.5) must be **implemented by the lowering itself** — the record defines its own
properties and must not delegate declaration instantiation to the engine, which would
silently produce the wrong descriptors. Second, the matrix must be validated against a
*standards* engine, which is what gate 2b does. Every matrix defect of rounds 2–5 would
have been caught by this gate without waiting for a human reviewer.

Gate 2b's oracle is **a fresh realm per fixture — a subprocess or a Worker, not
`vm.createContext`**, whose contextified global has *different* descriptor and extensibility
behavior (a `var` there is configurable, where a real Script's is not — measured). Its
quirk-filter — the entries that excuse a Hermes/standards divergence as an engine quirk
rather than a model bug — is **owner-authored data pinned like LLP 0019's `loaderExpectations`**:
each entry carries the measured engine output and the measured standards output, so a real
quirk is recorded and a wrong model row cannot hide behind the adjective "quirk-filtered".
Two entry *kinds* are distinguished and must not be conflated: a **quirk** entry excuses a
Hermes-vs-standards engine divergence, while an **expected-deviation** entry records a row
where the model *intentionally* diverges from Script semantics (every deviation-(a)
replacement row does — `var x ⏎ let x` is a `SyntaxError` on V8 but a shadow in the model).
Gate 2b passes a row iff it matches Script semantics *or* carries an expected-deviation entry
naming the deviation; a divergence with neither is a model bug. Hiding an intentional
deviation in the quirk list is the laundering the pinning exists to prevent.

Gate 2's **restricted class** is where a divergence is unconditionally a bug, so it is also
where a fuzzer belongs. A session qualifies iff: no name is declared in more than one input; no input references,
assigns, or declares a name that a *later* input declares; no input fails; no imports; no
top-level `await`; **no input begins with a directive prologue** — *any* input, not only
those after the first, because a first-input `"use strict"` makes the whole concatenated
script strict while the session applies strictness per input (measured:
`0 ⏎ "use strict"; function f(){return this} ⏎ f()` yields `undefined` as a session,
`globalThis` concatenated); **no input dynamically mutates a `globalThis` property** whose
name any input declares (adoption and deletion are descriptor-visible and order-dependent);
and **no input references a runtime-owned binding** (`$_`), whose value depends on display
acknowledgements the one-script arm does not model. Outside that class, the deviations are
pinned by direct fixtures generated from the model — not by concatenation.

The **observation channel** is stated, because "any observable divergence" is not a test.
Gates 1 and 2 compare the **final** declarative record (names, kinds, initialized flags,
values), the **own-property table** of the realm global with descriptors, `[[VarDeclaredNames]]`,
`[[SessionCreatedVars]]`, and **per-input completion values folded by `UpdateEmpty`** — not
the whole script's single completion. The fold matters: `1 + 1 ⏎ let a = 2` completes `2`
as one script (`UpdateEmpty` carries the `1+1`) but the session's last input completes
*empty*, so comparing whole-script completion against per-input completion would fail a
correct implementation. A fixture is an **ordered list of inputs** with explicit boundaries
— `let x = 1; let x = 2` is a `SyntaxError` as one input and a redeclaration as two, and a
fixture that does not say which is testing nothing.

#### 7.8 The last-value binding

Consumers that offer one (LLP 0022's `$_`) get it from the evaluator: the last
successfully *displayed* value — not the last completion, and not a value the consumer
failed to render. The evaluator updates it on the consumer's **display acknowledgement**,
which LLP 0025 §3's broker raises at barrier completion. `$_` begins the session
initialized to `undefined`.

`$_` is a **reserved session binding** with its own row rather than the matrix's: the
runtime installs it as a **configurable accessor property it owns** on `globalThis`.
Auto-update disables permanently on the first **observed mutation from user code**, and
the observation is structural rather than syntactic:

- any write through the property — `$_ = v` (which resolves *to* that property, §7.1),
  `globalThis.$_ = v`, `Reflect.set` — invokes the runtime's setter, which records the
  write **and stores the value**, so `$_` reads back what the user assigned;
- before each auto-update the evaluator re-verifies that the descriptor still holds **its
  own getter/setter function objects**. A `defineProperty` that replaces them — including
  one restoring an identical-*looking* descriptor — fails the identity check, so **ABA
  restoration is caught**;
- a deletion removes the property, which the same check observes;
- **any top-level declaration of the name `$_`** — `var $_`, bare or initialized,
  `function $_`, or a lexical declaration — disables auto-update at instantiation,
  regardless of which matrix row it would otherwise take. Without this a bare `var $_`
  would no-op on the property, never fire the setter, and leave auto-update silently armed
  over a binding the user has taken over.

**The disable's fate follows whatever triggered it** — which is the only rule that keeps
"permanently" honest:

| Trigger | On a failed input |
| --- | --- |
| a **mutation** from user code (setter fired, descriptor replaced, deleted) | **never rolled back.** The mutation happened; "permanently" means permanently |
| a **lexical** declaration of `$_` whose cell **never initialized** (`let $_ = boom()`) | rolls back **with the cell** (§7.4): the cell is removed, so the disable goes with it |
| a **lexical** declaration of `$_` that **initialized** (`let $_;`, which initializes to `undefined`, or `let $_ = 5`) | **survives**, because the cell commits (§7.4). The user took the name over; the disable stands |
| a **`var`/`function`** declaration of `$_` | **survives**, because a `var`/`function` always commits — otherwise `var $_ = 5; boom()` would leave auto-update armed over a name the user has plainly taken over, the precise hazard this rule exists to prevent |

The disable simply follows §7.4's commit rule for whatever triggered it: it lives and dies
with its binding. An earlier draft pinned `let $_; boom()` as rolling the disable back — but
`let $_;` *initializes* the cell, so it commits and the disable survives; the case that
actually rolls back is `let $_ = boom()`.

**Honest limit on ABA detection.** The descriptor-identity check catches a `defineProperty`
that installs **new** getter/setter functions, and a deletion. It does **not** catch user
code that captures the runtime's *own* accessor functions via `getOwnPropertyDescriptor`,
deletes the property, and restores that exact descriptor — the identity check then passes
(measured: a saved descriptor's `.get` is `===` the original after delete-and-redefine). No
pure-JavaScript check can distinguish that from no mutation at all; the only complete
mechanism is a **native per-property mutation generation counter**, which joins the §8
engine-patch program. Until it lands, `$_` auto-update is a **best-effort convenience** —
disabled on every mutation the check *can* see, and this document says plainly that
exact-descriptor restoration is the one it cannot. It is a display nicety, not a security
boundary, so the residual is acceptable and stated rather than overclaimed. A syntactic
(AST) rule would miss every alias above and is not permitted. One notice is emitted at the
next display.

#### 7.9 Module cache

Module **identity** is LLP 0023 §2.3's, and this document does not restate the mechanism —
restating a sibling's mechanism inline is the drift hazard the split exists to remove, and
an earlier draft of this section proved it by going stale the moment 0023 revised the rule.

**Most of what this document evaluates is not a module at all.** A `repl:<n>` input, a
`.load` body, and `ibex:eval` are **scripts**: they have a *source label* (§2) and **no
module identity**, and they never enter the module cache. Only `ibex:stdin` — the synthetic
*module* entry of program mode — needs one. Demanding that module identity "cover the
sources this document mints" was a **category error**: it reused the word *identity* across
two different concepts (§2's table now separates them).

What this document states is the **requirement** identity must satisfy, and the session's
use of it:

- **One equal `SourceId` is one module instance**, whichever principal reached it:
  root's `import "foo/util.js"` and package `foo`'s own `require("./util")` share the
  instance when those requests resolve to the same defining-principal-relative source.
  Case/normalization aliases that LLP 0023 deliberately gives distinct `SourceId`s stay
  distinct instances. The two callers' *authorization* decisions are still taken against
  their own bindings; LLP 0023 §2.3 delivers caller-independent cache identity by keying
  on the **defining** principal inside `SourceId`.
- Identity must **not collapse compartments** when one inode is reachable from two package
  roots, or a filesystem coincidence would decide a package's execution compartment
  (LLP 0013).
- **The key covers root-owned sources, and LLP 0023 §2.3 now supplies the arm.** The most
  common module in an interactive session is first-party: a prompt `import "./util.js"`,
  where `util.js` is an ordinary project file inside no package, has defining principal
  **Root**. An earlier draft flagged that a package-only principal component (locator plus
  digest) would leave that case unkeyed; LLP 0023 §2.3 has since defined an explicit
  **project arm** (authenticated root identity + binding-relative canonical path), so the
  guarantee holds for first-party code. This bullet remains only to keep the requirement
  visible — the arm must not regress.
- The cache **persists for the session**.
- **A failing module's cache entry does not stand.** The loader deletes it, so a later
  import re-executes the module rather than resurrecting a half-initialized one — which is
  also what makes a retry after fixing the file work at the prompt. Its **completed
  dependencies remain** cached. An earlier draft said the failing entry "of course stands";
  that was false against the loader and wrong in principle.
- A session that adopts LLP 0026's module runner scopes this rule to an
  **execution graph generation**. Within one generation, ESM success and failure
  are sticky and one equal `SourceId` has one incarnation. Retrying after an
  accepted root-source edit atomically advances the coherent graph generation;
  it never deletes and recreates a record in place. Live cells, namespaces,
  promises, CommonJS exports, and errors never cross generations. The current
  legacy session loader keeps delete-on-failure until it adopts that runner
  transaction, so this amendment does not silently change shipped prompt
  behavior.
- **`.load` creates no cache entry** and re-evaluates on repeat.

### 8. Safe inspection

Formatting a value must run **no user code**: no getters, no Proxy traps, no
`valueOf`/`toString`/`then` coercions, no promise continuations. Merely looking
at a value is not consent to execute it.

The display seam is **private and not JavaScript-reachable**: neither the walk nor
the native primitive below is exposed to prompt or package code, and both carry a
registry row saying so (LLP 0021's no-unclassified-surface invariant — LLP 0022 §1
depends on exactly this).

**The obligation is only satisfiable with engine support, and the staging says so
plainly.** Pure-JavaScript reflection cannot deliver it at the limit:
`getOwnPropertyNames`, `getOwnPropertyDescriptor`, and `getPrototypeOf` all run
Proxy traps, and JavaScript cannot detect a Proxy without invoking one. A
"descriptor-only walk" implemented above the current seam therefore *still runs
user code* on any object that happens to be a Proxy — and any object might be.

The contract is consequently staged, with no pretence that the earlier stage is
the later one.

**Stage 1 — before the native primitive.** The trap-free toolkit is exactly
`typeof`, `Array.isArray`, and reference identity, taken from **primordials
captured at bootstrap** rather than read from the realm at display time — so
monkeypatching `Array.isArray` cannot alter a classification. The tag vocabulary
is derived from that toolkit and is no wider:

| Value | Rendering |
| --- | --- |
| primitives, including symbols and bigints | rendered fully |
| `typeof v === "function"` | `[Function]` |
| `Array.isArray(v)` is `true` | `[Array]` |
| any other object, **and any value for which `Array.isArray` throws** | `[Object]` |

The toolkit is safe but not *total*, and the gap is stated rather than assumed
away: **`Array.isArray` throws a `TypeError` on a revoked Proxy** (verified on the
shipping engine). That throw runs no user code — the revocation check precedes any
trap — so it is safe, but a conforming implementation must catch it and fall back
to `[Object]` rather than propagate it out of a display path.

Note what is **absent**, and why. `[Function: name]` would read `.name`, which a
Proxy traps and a getter can hijack. `[Array(3)]` would read `.length`, which a
Proxy over an array traps — `Array.isArray` is trap-transparent, so passing that
check proves nothing about `length`. Both tags appeared in an earlier draft of
this section, and both violate its own rule. Stage-1 display is
useless-but-safe rather than useful-but-exploitable.

**Errors are the hard case, and the honesty is in admitting it.** §6 says a
`throw` outcome carries an *engine-captured* message, stack, and positions. On
stock JSI that is not achievable: `jsi::JSError` populates its message and stack by
**reading `.message` and `.stack` off the thrown value**, so `throw {get message(){
sideEffect() }}` runs user code during capture. The current seam does exactly this.

So the error carve-out is not toolkit-only — it needs a narrow native slice, and
this document names it rather than implying the toolkit covers it:

- **capture at throw**: the VM's own thrown-value state — message, stack, position
  — recorded when the throw occurs, without a property read; and
- a trap-free **`IsNativeError` brand check** plus own-data-property read, so an
  ordinary `Error` can be distinguished from a hostile look-alike without invoking
  anything.

Until that slice exists, **stage 1 renders every thrown value by type tag**,
including ordinary errors — which is a severe usability cliff and is stated as
one. That slice is *much* cheaper than the full stage-2 primitive, and it is the
recommended first patch: call it **stage 1.5**, and it restores ordinary error
display on its own.

**One engine-patch program, three consumers.** The trap-free introspection
primitive (open question 1), the completion-record discriminator (open question 3),
and throw-time error capture (above) are three slices of the same VM surface and
should be scoped, costed, and landed as one program rather than three unrelated
asks.

**Stage 2 — with the native primitive.** A **trap-free introspection primitive**
in the patched engine that (a) identifies a Proxy without invoking a trap and (b)
reads own-property names, kinds, and promise/Proxy/`Error` state without property
reads. Rich display becomes available: own-property descriptors are surfaced
without Gets, accessors render as `[Getter]`/`[Setter]` without invocation,
promises show their state, and a Proxy renders opaquely *by detection* rather than
by luck. The primitive must give a defined answer for every exotic it can meet —
host objects, module namespaces, typed arrays, `Map`/`Set`, `Error` own properties
— and anything it cannot characterize renders opaque rather than best-effort.

**The output is a tree, not a string, and the tree cannot express styling.** This
document owns that schema; LLP 0025 §3 renders it. A node carries a **kind** (the
tag vocabulary above, plus descriptor/promise/exotic kinds at stage 2), an
**untrusted payload** (length-bearing raw text — never escaped, never styled), and
optional children, plus explicit cycle and truncation nodes and a deterministic key
order. It carries **no styling, no layout tokens, and no terminal control**, and a
producer cannot name any.

That is the trust boundary, and it is deliberately one-directional. The session
layer derives trusted styling from node **kinds** and applies it when it converts
the tree to bytes (LLP 0025 §3–§4). A producer that could *name a style* could emit
terminal control — and under LLP 0025 §7's worker split the producer may be
hostile — so the tree is designed to make that unrepresentable rather than merely
forbidden. A flat pre-colored string mixes styling and payload so that no escaper
can tell them apart, which is why `Exact.inspect(v, {colors: true})` is retired.

The tree is **versioned and serializable**, which is load-bearing: a value handle
cannot cross a process boundary (§6), so under the worker split the walk runs
**where the value lives** and the tree is what crosses. The session layer holds no
JavaScript value at all.

Formatting is bounded and deterministic in depth, breadth, string length, key
order, and cycle handling, with an explicit truncation marker. A bounded failure
yields a safe fallback tag: never a hang, never user code, never a
session-ending error. *Inert is acceptable; unsafe is not* — and until the
primitive lands, inert is what ships.

The same primitive backs completion (LLP 0022 §9): resolving `a.b.` for completion must
not invoke an accessor or a trap at any step, and where the primitive is unavailable,
member completion yields no candidates rather than falling back to evaluating the base
expression.

**The surface this section governs is evaluator-authored rendering** — displayed values,
error rendering, completion candidates, and the asynchronous-failure envelope. It does
**not** govern `console.*`, which is **program output**: a program that formats its own
object and writes it has deliberately run its own code, and LLP 0025 §3 routes it to its
stream unmodified. Conflating the two would either cripple `console.log` or pretend the
evaluator's safety extends somewhere it does not.

### 9. Asynchronous failures

An unhandled promise rejection or an uncaught exception from background work is
delivered to the consumer as a **structured event**, not reconstructed from a log
line. Two envelopes, split by the process boundary (§6): the **worker-local** envelope carries the original thrown/rejected value as a **value handle** (which never crosses to the supervisor) plus a trap-free inspection tree; the **wire** envelope the supervisor receives carries the tree, not the handle. The common fields: an
engine-captured safe stack, the promise or event identity, the authenticated
**owning principal** (so a package's failure is attributable to the package), the
association to the evaluation that scheduled the work if any, and a sequence
number drawn from the **same session-wide sequence as evaluation outcomes** — so a
consumer can order a background report against the evaluation it interleaved with.
LLP 0022 §3's transcript flush checkpoint depends on exactly that ordering.

The **owning principal is assigned by the scheduling source**, not inferred at
report time: a timer, a next-tick, a microtask continuation, and a native
completion each record the principal that scheduled them (LLP 0021's schedule-time
owner), and a failure inherits it. Where attribution is missing or ambiguous, the
event says so — it never guesses, and it never launders a package failure into
root. This is the one field the current implementation cannot supply, because it
scopes a captured principal around a callback and drops it before detached
microtasks drain.

The channel is **bounded and sequenced**: one **sequence allocator** issues numbers to
evaluation outcomes, asynchronous events, **and the session layer's broker events**
(LLP 0025 §3) alike — one domain, not two, or the ordering the transcript contract promises
cannot be proven.

**The session layer assigns sequence numbers at receipt — the worker never mints them, not
even in reserved ranges.** LLP 0025 §3 now agrees ("LLP 0024 is right and this document was
wrong"): a worker that mints its own numbers can forge ordering, and under LLP 0025 §7 the
worker is exactly the component that may be hostile. A pre-authorized *range* does not fix
this — a hostile worker can still number *within* the range in any order it likes — so
numbers are assigned where events are received, which also makes a **worker-death event**
naturally sequenceable after the worker can no longer participate. (My own round-6 draft
briefly adopted the range mechanism as 0025 then had it; both documents have since converged
on at-receipt, and the range idea is retired on both sides.) A **worker restart advances the
sequence epoch** (§2): the sequence does not rewind, the epoch rides on every event, and a
consumer can tell "no events" from "the worker died and was replaced". The *sequence* epoch
is not LLP 0025 §6's *work* epoch — different counters, different reset rules (§2). It **never blocks the runtime thread** — blocking a full
queue against the thread that must drain it is a deadlock — so on overflow it
coalesces within a documented window and emits an explicit **drop marker** carrying both the
count **and the highest dropped sequence number** *for drops that occurred after receipt*
(a count alone leaves a consumer unable to tell which side of a flush checkpoint the loss
straddled — LLP 0022 §3 reads on exactly that) — in sequence, and **releases the dropped
events' handles**. A **pre-receipt** loss (a worker-side queue overflowing before the
session layer assigns a number) has no sequence number to report, so it surfaces as a
worker-fault event carrying a dropped-count only; the two drop kinds are distinct and named. A lost event is
always visible as a drop, never as silence.

A rejection becomes reportable at a **pinned determination checkpoint** — the end
of the event-loop turn in which it became unhandled, concretely the poll-iteration
boundary (LLP 0003) — and a handler attached before that checkpoint cancels the
pending report.

**A rejected top-level-`await` unit is not a background failure.** It is that
evaluation's `throw` outcome (§6), reported once through the outcome channel and
never also through this one; the two are distinguished by the unit's identity, not
by timing. Where the armed model admits user
`unhandledRejection`/`uncaughtException` listeners, they take precedence and the
runtime does not double-report; where it does not (the initial profile), the
runtime is the only reporter. In neither case may a listener convert a throw into
a *successful* outcome, as the current handler path does.

Whether such a failure is fatal is the **consumer's** decision, not the engine's:
file and program execution may treat it as fatal, and an interactive session must
not (LLP 0022 §5). The **engine** therefore reports rather than decides, and sets
no exit code.

The current behavior does not conform, though the defect is narrower than "the
pump is poisoned": the fatal flag *is* one-shot, so the next poll does survive it
(LLP 0003 §Event loop). What is wrong is that the **engine layer decides fatality
at all** — an unconsumed async error is written straight to stderr and turned into
a `-1` from `poll`, so the consumer receives a return code where it should receive
a structured event, and an interactive session that must never die from a
background rejection is relying on a flag's one-shot-ness to survive. Reporting and
policy are separated: the engine emits the event; the consumer's lifecycle policy
(LLP 0025 §8) decides the process outcome.

## Delegated obligations and owed artifacts

This document, like its siblings, states requirements it does not itself implement — some on
other LLPs, some on artifacts (an executable model, a parser prototype, an ABI amendment)
that must exist before an implementation can be conforming. It is the last of the four to
gain this ledger; without it, these obligations were tracked nowhere. Each row is a stable
id, the obligation, its owner, and its gating fixture or acceptance criterion. **None is
discharged** at this revision — the document finishes `Draft`, and these become the
implementation tickets.

| Id | Obligation | Owner | Gate |
| --- | --- | --- | --- |
| **`OBL-COMPARTMENT-BASELINE`** | Deviation (d)'s real fix: a package compartment must resolve bare globals against a **baseline captured at arming** (endowments + frozen intrinsics), *not* forward to the live realm global — closing the session-`var` / sloppy-assignment / adopted-and-assigned disclosure channel that is **live today** (`var apiKey` at the prompt is read by every package). The `[[SessionCreatedVars]]` withhold-list patch is only a partial mitigation. **This is the document's most security-consequential owed item — filed as ENG-24463.** | **LLP 0013** | §7.7(d) fixtures for all three spellings (fail today) |
| `OBL-EXEC-MODEL` | The §7 tables, matrix, restricted-global predicate, rollback, and fixtures are **generated from a checked-in, digest-bound executable reference model** — the tables in §7 are an *interim projection* of it, not the normative source. Four rounds of hand-written tables were falsified by review (a rule that would have deleted `globalThis.Object`; an impossible rollback; a `var`/`function` conflation; a predicate whose edit silently never landed) — the model is why they cannot be *asserted* correct, only *measured*. | this document + tooling | gates 1/2/2b/3 (§7.7) run against it in CI |
| `OBL-PARSER-GOAL` | The **Script-plus-`import`-plus-TLA** source goal (§3) does not exist in the pinned parser and must be **prototyped on every advertised target**, proving sloppy-only parse forms, directive semantics, imports, TLA, and TypeScript before acceptance (open question 5). | this document | §4 source-goal fixture family |
| `OBL-ABI-AMEND` | The §6 result ABI is a **semver-major** change to LLP 0002's narrow consumer contract (LLP 0000 moves with it); the byte-level schema is LLP 0002's amendment, verified from an independent C consumer. | **LLP 0002** (+ LLP 0000) | AC 18 |
| `OBL-PRIVATE-SEAMS` | Registry rows classifying the §7.1 lowering hooks and the §8 display seam as **private, non-JavaScript-reachable** (no-unclassified-surface invariant). | **LLP 0021** registry | §8 AC 16; §7.1 hook-unforgeability fixture |
| `OBL-0019-TRIGGER` | If the session lowering changes what LLP 0019's Hermes-compat tiers emit, LLP 0019 is amended in the same change. | **LLP 0019** | §4 corpus |
| `OBL-ENGINE-SLICES` | The three engine slices §8 depends on — trap-free introspection (stage 2), the completion-record discriminator (§6), and throw-time error capture (stage 1.5) — scoped and landed as **one patch program**; first step is surveying the vendored debugger's inspection path for extant trap-free reads. | this document (engine) | §8 strata AC 16 |
| `OBL-MAX-INPUT` / constants | The completion budget and async-storm window join LLP 0025's `session-constants.json` once that file lands; maximum input size is already pinned at **1 MiB** by LLP 0025 §12. | **LLP 0025** §12 | §5/§9 bounds fixtures |

**Outstanding sibling-ledger corrections (reported, not this document's to edit):**

- **LLP 0022 §7** still says "LLP 0024 still uses the retired 'decision evidence'
  terminology" — **false since round 4**; and `OBL-SUBMIT-CREDENTIAL` still describes one
  linear permit where this document (adopting 0022's own four-stage lifecycle) is equivalent
  — the two should state whose decomposition is normative.
- **LLP 0025** `OBL-SUSPENDED-UNIT` looks **discharged** by §2's work-unit / settlement-unit
  split (a settling callback is its own work unit; the settlement unit aggregates it for
  outcome purposes only).
- **LLP 0022 §5**'s unqualified "any user mutation of `$_` permanently disables auto-update"
  is falsified by §7.8's honestly-bounded ABA case; 0022 should adopt or cite the bound.
- **LLP 0013 Mechanism 2**'s "a package global contains exactly the policy endowments"
  is contradicted by its own shipping forwarding-Proxy; `OBL-COMPARTMENT-BASELINE` is the
  reconciliation.

## Acceptance criteria

Fixtures are **ordered lists of inputs** with explicit boundaries (§7.7), each
carrying its expected outcome kind, record delta, `globalThis` delta, and display.
Below, `⏎` marks an input boundary — `let x = 1 ⏎ let x = 2` is a redeclaration,
while the same text as one input is a `SyntaxError`, and a criterion that does not
say which is testing nothing.

1. An empty completion and the value `undefined` are distinguishable at the seam:
   `let x = 1` yields empty completion; `void 0` yields the value `undefined`.
   Completion values are correct for statement lists, blocks, `if (false) { 1 }`,
   loops, `try`/`finally`, and a declaration following an expression — before and
   after import and TLA lowering. A value containing an embedded NUL survives the
   ABI intact (no truncation) and reaches the consumer for escaping.
2. An error on line 3 of a multiline input reports the source label with line 3
   and a correct column; the position survives TypeScript stripping, import
   lowering, TLA lowering, the §7 session lowering, **and the LLP 0019
   Hermes-compat rewrite that runs after them**; `.load`ed content reports
   `repl:<n>:<virtual path>`. The ordinal advances for a failed parse, a `.load`
   body, and a `.time` argument, and does not advance for a command that evaluates
   nothing, a blank line, or an abandoned continuation.
3. The §2 error classes are distinguishable and **staged**: reserved-scheme (`repl:x`,
   `ibex:x`), unknown-builtin, **out-of-snapshot**, policy denial, module resolution
   failure, and unsupported-dependency-TLA each produce their own class and are not
   collapsed — and **no class disclosing existence precedes an authorization decision**:
   `import "/etc/passwd"` reports outside-mount, and a policy-denied module that is also
   absent reports the denial, never "not found". The total order is LLP 0023 §7.2's.
4. Source goal: a sloppy prompt input containing an import stays sloppy (an
   undeclared assignment creates a global rather than throwing); **sloppy-only
   *parse* forms survive** — legacy octal, `delete identifier`, duplicate
   parameters — which fails a Module-goal implementation; a `"use strict"` input
   follows script rules; program stdin is strict with `this === undefined`;
   `export` in a script input is a syntax error; `await` is reserved at the top
   level of a script input but ordinary inside a non-async function within it;
   `using`/`await using` at the top level of a script input is a named refusal while
   being permitted at a module-goal entry; a hoisted import's side effects precede the
   input's first statement; and a transform-introduced temporary (an `enum` IIFE
   variable, a JSX factory alias) **never** becomes a session binding or a completion
   candidate.
5. Dialect and kind are separate: a `.cjs` file evaluates as CommonJS with
   `this === module.exports` and `__dirname` present, **not** as an ESM module; a
   `.json` import yields the parsed value; `.tsx` parses with JSX while
   extensionless input does not; `.d.ts` is not loadable. `.load` edges: `.json`
   displays the parsed value and declares nothing; `.mjs`, `.cjs`, `.mts`, and
   `.cts` are refused symmetrically as module-kind assertions; `.d.ts`, an unknown
   extension, and an extensionless file are refused. **`require.main` and
   `process.mainModule` are unreachable in every mode**, while `import.meta.main`
   holds for program stdin.
6. Grammar: `let x: number = 1 ⏎ x` yields `1`; `a<b>(c)` parses as the documented
   TypeScript reading in extensionless input; `.load foo.js` parses as JavaScript
   while a prompt input of the same text parses as TypeScript; an `enum` at the
   prompt persists as a `var`-kind binding; the pinned parser version is asserted
   at build time, and any candidate engine is parse-equivalent to it across the
   corpus.
7. Completeness (§5): unterminated blocks, strings, template literals **with
   interpolations**, regex literals, comments, and incomplete TypeScript
   productions each continue rather than submit; a delimiter inside a template
   interpolation or a regex does not confuse the judgment; a genuinely ambiguous
   input **submits** and reports a recoverable syntax error rather than trapping
   the caller in continuation.
8. Top-level `await`: it works in prompt input, `.load`, program stdin, and `-e`;
   `const x = await f()` publishes `x`; a rejected unit yields a `throw` outcome
   exactly once and **never also** an async-failure event. Dependency TLA fails
   with **one stable named error** from every transform engine, raised by
   **static-graph preflight before the entry runs**. **Every `import()` — literal or
   computed — is checked at call time**, before the selected dependency evaluates or
   enters the module cache, so an unevaluated `if (false) import("./tla.js")` **never
   fails**. A CommonJS module using `await` as an identifier is not misclassified.
9. No assimilation: an input whose value is an instrumented thenable is returned
   without `then` being called — including when the same input used `await`
   earlier, which is the case the private settlement sentinel exists to protect; a
   never-settling awaited evaluation does not time out on its own.
10. No post-arming environment consultation for evaluation behavior: the
    await-unwrap timeout and the transform-engine selection have no observable
    effect when set after arming. (The inventory itself is LLP 0025 §2's.)
11. **The environment model (§7) is pinned by an executable table**, and all of
    these hold:
    - ordinary and inherited globals resolve: `Object`, `Promise`, and the endowments
      are reachable from a session input; **`typeof neverDeclared` is `"undefined"`,
      not a throw**, while *evaluating* `neverDeclared` throws `ReferenceError`; and
      `typeof x` **inside `x`'s TDZ** throws `ReferenceError`;
    - **a lexical declaration never deletes a property**: `let Object = 1 ⏎ Object`
      leaves `globalThis.Object` **intact** and imported modules keep working; and
      coexistence holds in **both orders** — `let x = 1 ⏎ globalThis.x = 2` and
      `globalThis.x = 2 ⏎ let x = 1` each leave `x` as **1** and `globalThis.x` as
      **2**;
    - shared bindings: `let x = 1 ⏎ const f = () => x ⏎ x = 2 ⏎ f()` yields **2**;
    - late binding: `let x = 1 ⏎ const f = () => x ⏎ let x = 2 ⏎ f()` yields **2**,
      and a closure written *before* a name exists sees it once declared;
    - `var` correctness: `var v = 1 ⏎ const g = () => v ⏎ var v = 2 ⏎ g()` yields
      **2**; `var v = 1 ⏎ var v` leaves `v` as **1**; bare `var Object` is a
      **no-op** with `Object` intact; and `var` over an *inherited* name creates a
      fresh own property initialized to `undefined`;
    - `const`: assigning to a prior-input `const` throws `TypeError` **at runtime** —
      after any preceding side effect in the same input has run — while redeclaring it
      succeeds;
    - TDZ: `x; let x = 1` **in one input** throws `ReferenceError`, and so does
      `let x = f()` where `f` reads `x`;
    - collisions are keyed by kind: `let a; let a`, `let [a, a]`, `let a; var a`, and
      `let a; import { a } from …` — each as **one** input — are `SyntaxError` and
      mutate nothing, while **`var [a, a] = [1, 2]` is legal and yields `2`**;
    - feasibility (phase 3): a `var` on a non-extensible `globalThis` fails with
      `TypeError` and mutates nothing; the whole input fails atomically if any name
      fails its `CanDeclareGlobal*` predicate;
    - `globalThis` descriptors follow §7.5, and the *created* / *adopted* split is
      asserted: a property the record **created** for a `var` is non-configurable, so
      `delete globalThis.x` returns **false** and the binding stands; a property the
      record **adopted** (`globalThis.adopt = 7 ⏎ var adopt`) keeps its **configurable**
      descriptor, `delete` **succeeds**, and the name then sits in `[[VarDeclaredNames]]`
      with no own property — reads throw `ReferenceError`, `typeof` is `"undefined"`, and
      a later `var adopt` recreates it as if fresh;
    - `var` and `function` are **not** the same declaration: bare `var Object` is a no-op
      leaving `Object` intact, while **`function Object(){}` overwrites the builtin**;
    - deleting an own property whose name is also inherited **reveals** the inherited one
      rather than yielding a `ReferenceError`; an accessor defined over a configurable
      property **controls later identifier reads**;
    - a lexical cell is removed (revealing the object record beneath) when a later
      `var` declares the same name;
    - the restricted-global predicate keys on **creation provenance**: `let undefined` is a
      `SyntaxError`, and **`var undefined ⏎ let undefined` is *still* a `SyntaxError`**
      (`var undefined` adopts, does not create, so `undefined` never enters
      `[[SessionCreatedVars]]`) — while `var x ⏎ let x` shadows; `var undefined` alone is
      legal and inert;
    - **Reference fidelity**: `x++`, `x += f()`, `[x] = arr`, `for (x of …)`,
      `delete x`, and a strict-mode unresolvable write each behave exactly as in a
      Script, with PutValue ordering asserted by side-effect fixtures.
12. Phases and rollback (§7.4). **Rollback never touches the object record** — the
    invariant that makes it implementable, since a fresh session `var` is
    non-configurable and could not be deleted:
    - **imports evaluate before instantiation**: `import "./boom"; var w` — where the
      import throws — leaves **no `w`**, because `w` was never created; a
      `globalThis.fresh = 1` the failing module performed **stands**; and a prior
      `function f(){1}` is **not** overwritten by the input's `function f(){2}`, because
      instantiation never ran;
    - a write a callback made through a cell that rollback removes is **discarded with
      it** (`let x` in input 1 with an escaped writer, redeclared and failed in input 2);
    - the settlement boundary: `let x = 1; queueMicrotask(() => { throw 0 })` **succeeds**
      and publishes `x`, and the microtask's throw is an async-failure event — not the
      input's outcome;
    - **phase 6, commit-iff-initialized**: `var w = 1; boom()` leaves `w` as **1**;
      **`let x = 1; throw new Error()` leaves `x` as `1`** (the lexical initialized before
      the throw, so it commits — an initialized lexical survives, like the neighbouring
      `var`); `const x = 1 ⏎ let x = boom()` leaves `x` as the original `const` **1** (the
      `let` never initialized, so it is removed and the `const` restored);
      `let x = 1 ⏎ var x = 2; boom() ⏎ x` yields **2** with `globalThis.x` **2** (the `var`
      committed and survives; the displaced `let` is gone — no restored cell shadows a
      surviving `var`); a partially-destructured `var [a, b] = failingIterator()` leaves `a`
      with its value and `b` `undefined`;
    - **interference**: `import "./m"; var x` where `m` calls
      `Object.preventExtensions(globalThis)` — or installs a non-configurable property at a
      name the input `let`s — fails at the **phase-5 full-vector re-check** with an ordinary
      `throw` that publishes nothing (an OOM *during* the inert commit instead poisons the
      runtime, §6, and is not a `throw`);
    - **phase-4 microtask**: `import "./m"; first()` where `m` queues a microtask writing a
      global runs `first()` **before** that microtask, and an import-queued throw is an
      async-failure event (§9), not the input's outcome; a callback that runs during a TLA suspension and deletes a property the
      input created is not overridden by rollback (the property is not resurrected); and
      background work that ran during the suspension commits independently and is never
      rolled back;
    - `var w = 1; boom() ⏎ let w` **shadows** — `[[VarDeclaredNames]]` and
      `[[SessionCreatedVars]]` are not rolled back for a binding that survives;
    - `let x = 1; boom()` leaves `x` as **1** (an *initialized* lexical survives, like the
      neighbouring `var`); only a lexical still in TDZ is removed;
    - `$_` disable follows §7.8's commit rule: `let $_ = boom()` (cell never initialized →
      removed) rolls the disable **back**, while `let $_;` (initializes to `undefined` →
      commits) and `var $_ = 5; boom()` (always commits) leave it **disabled** — the
      round-5 draft had the `let $_;` case backwards;
    - a failed parse publishes nothing; a cancelled evaluation publishes what a throw at
      the same point would; a **lifecycle** outcome **discards** session state rather than
      rolling it back — the call parked, the worker is disposed, and no evaluator frame
      remains to roll anything back.
13. §7 is gated by **four gates with disjoint jobs** (§7.7), and the tables and fixtures
    are **generated from the reference model**, not hand-maintained:
    - **model conformance** — the implementation matches the reference model on every
      session, over the stated observation channel (declarative record; realm-global
      own-property table with descriptors; `[[VarDeclaredNames]]`; `[[SessionCreatedVars]]`;
      per-input completion folded by `UpdateEmpty`);
    - **model validation** — the model matches one growing script *on the same engine
      through the same lowering*, over the restricted class, where **any** divergence fails
      the build. The class excludes forward references, redeclarations, failures, imports,
      TLA, **a directive prologue on *any* input** (a first-input `"use strict"` makes the
      whole concatenation strict — measured), **dynamic `globalThis` mutation of a declared
      name**, and **references to `$_`**. A fuzzer runs inside this class;
    - **model correctness (gate 2b)** — the model matches **real Script semantics on a
      standards engine** (a fresh realm per fixture — subprocess or Worker, *not*
      `vm.createContext`) over the descriptor matrix and the created/adopted rows, because
      an engine-relative gate is blind to a wrong model of ECMAScript in a row Hermes itself
      gets wrong; its quirk-filter is owner-authored data carrying both measured outputs;
    - **lowering fidelity** — one input through the lowering behaves as the same input run
      directly, *excluding the transforms that deliberately repair Hermes* (TDZ, runtime
      `const`), which must differ from direct execution by design.
    Engine quirks cancel between the arms of gate 2, so `for (let i…)` yielding `3,3,3` is
    **not** a session divergence — it is an engine fact both arms exhibit (LLP 0019's
    charter). Each of (a)–(e) has at least one direct fixture, including (d)'s sub-cases (a
    first-party module sees session `var`s but not lexicals; a **package** module sees
    neither — *and the leak-closure fixtures for `var`, sloppy, and adopted-and-assigned
    spellings fail today*) and (e)'s initialization-order case
    (`var x = 1 ⏎ function x(){} ⏎ x` yields the **function**, where the growing script
    yields `1`).
14. The last-value binding: `$_` starts as `undefined`; auto-update disables on
    assignment, `globalThis.$_ =`, `Reflect.set`, a `defineProperty` installing **new**
    functions, deletion, a **same-value** write, and **any top-level declaration of the
    name — including a bare `var $_`, which the matrix would otherwise treat as a no-op
    reuse** — via the runtime-owned accessor pair, not an AST rule. The **stated limit**
    is asserted too: capturing the runtime's *own* accessor functions and restoring that
    exact descriptor after a delete is **not** detected (measured), and the fixture pins
    that documented gap rather than a guarantee the mechanism cannot keep — the complete
    fix is a native mutation counter (§7.8, §8 patch program).
    `$_` updates only on display acknowledgement (LLP 0025 §3), so a value the consumer
    failed to render does not become `$_`.
15. Module cache: the session cache satisfies **LLP 0023 §2.3** — one instance per
    **equal `SourceId`** (not per display spelling: case/normalization aliases that 0023
    gives *distinct* `SourceId`s are, deliberately, *distinct* instances), so module-level
    state and `instanceof` survive the root/package boundary while two *different* packages
    hard-linked to one inode remain **two** instances in two compartments; **`ibex:stdin` is
    the only synthetic *module*** and is keyed without a file object (prompt, `.load`, and
    `ibex:eval` are scripts with no module identity); and a `chdir` between imports creates
    no second entry — while `.load` creates no entry at all and re-evaluates on repeat.
16. Safe inspection runs no user code, per stratum, and the stratum is **advertised**
    so a consumer can tell *metadata unavailable* from *no metadata*. **Stage 1
    (base)** renders every non-primitive as `[Function]`, `[Array]`, or `[Object]`; an
    instrumented `name` getter, `length` getter, Proxy trap, `toString`, or `then` is
    never invoked; a **revoked Proxy** renders `[Object]` rather than propagating
    `Array.isArray`'s `TypeError`; monkeypatching `Array.isArray` does not change a
    classification; and **a thrown value renders by type tag** — including an ordinary
    `Error` — with the throw outcome carrying the explicit `metadata unavailable`
    discriminator. **Stage 1.5 (safe-throw)** renders ordinary errors with VM-captured
    message and stack while `throw {get message(){…}}` never runs its getter.
    **Stage 2 (rich-inspection)** renders descriptors and promise state, accessors show
    as `[Getter]`, a Proxy renders opaquely by detection, and the same instrumentation
    still never fires. Every stage emits the **semantic tree**, which *cannot express
    styling* — never a pre-colored string and never a style token; cycles and huge
    objects render within bounds with explicit truncation nodes; neither the walk nor
    the primitive is reachable from JavaScript.
17. Cancellation (§6): every work unit — a submitted input, a **background
    callback**, and a **completion query** — carries a **monotonic target id**, and a
    request bearing a **stale id is discarded** rather than landing on the successor
    work. An **accepted** cancellation is one where the target *returned* and the
    runtime is usable; **unavailable** is reported as such; **failed** ends the session;
    a target that ends by another route after a request was delivered resolves the
    request **defeated**; and a **permanently stuck** target leaves the request
    **`Pending`** — never falsely terminal — with LLP 0025 §6's second interrupt as the
    only escape. At most one terminal result per request; runtime destruction resolves
    every outstanding request `failed`.
18. The ABI: outcome tags (**five**, including lifecycle) and payload lengths are
    explicit; the **capability stratum** is advertised; an engine fault is
    distinguishable from a JavaScript throw; a value handle is invalid after its runtime
    is destroyed, is rejected with a defined error on the wrong runtime or thread, and
    never crosses a process boundary; a cancellation request is deliverable **while**
    an evaluation is in flight; the seam refuses a second source request while one is
    unsettled, including across a top-level `await`; **empty source is accepted** and
    yields an empty completion; **invalid UTF-8 is a named refusal**; and LLP 0002
    (with LLP 0000) is amended in the same change, verified from an independent C
    consumer over embedded NUL, OOM, stale-handle, and cancellation-race cases.
19. The armed profile's `eval` closure is **proved, not assumed**: a fixture shows
    direct `eval`, indirect `eval` aliases, `Function`, and every reachable
    `%Function%` route are unavailable before any source is submitted.
20. Asynchronous failures deliver a structured event with the original value and
    the **schedule-time** owning principal — asserted across a timer, a next-tick,
    a promise continuation, and a native completion, with a cross-principal chain
    attributed to the package and never laundered into root; a handler attached
    before the determination checkpoint cancels the report; the event sets no exit
    code; an async storm coalesces within the documented window and emits an
    explicit **drop marker** carrying both the **count and the highest dropped sequence
    number**, in sequence, releasing the dropped handles — a lost event is never silent.

## Consequences

- Display, error reporting, and session persistence stop depending on string
  conventions and wrapper arithmetic.
- Merely displaying a value can no longer run user code — the largest behavioral
  change, and the one that makes an interactive session safe to point at hostile
  objects. Until the throw-capture slice lands, that safety costs *error display
  itself*: a thrown value renders by type tag, and the outcome says so explicitly
  rather than looking like an object with no message. Stage 1.5 is the cheap way out
  and should be scheduled as such.
- The session environment is ECMAScript's `GlobalEnvironmentRecord` with **five**
  pinned deviations, reached by lowering every free identifier in a session input into
  a checked environment operation — because the engine supplies no TDZ, no runtime
  `const`, and no cross-evaluation lexical persistence to build on. Imported modules
  are untouched, which is cheap but is *why* deviation (d) exists: they cannot see
  session lexicals. An engine-level global environment record would retire both the
  lowering and that deviation.
- **A lexical declaration never deletes a global property, and rollback never touches
  the object record.** Two rules, one lineage. Making `var`s non-configurable (correct)
  made rollback of a failed import *impossible* — a non-configurable property cannot be
  deleted. Moving **import evaluation before instantiation** dissolves it: a failing
  import throws before anything exists, so "publishes nothing" is trivially true and no
  VM transaction API is needed. Ordinary JavaScript suffices.
- **§7 is executable data, not prose, and it is validated against a standards engine.** Its
  tables are generated from an owner-authored reference model; its fixtures from the same
  model; and gate 2b checks the model against real Script semantics, because an
  engine-relative oracle is blind to a wrong model of ECMAScript in the rows Hermes itself
  gets wrong. *Four* consecutive rounds of hand review falsified hand-written tables — a rule
  that would have deleted `globalThis.Object`, a rollback that required deleting a
  non-configurable property, a `var`/`function` conflation, and a provenance fix whose
  predicate edit silently never landed. A table that cannot be executed cannot be trusted,
  and a predicate keyed on what a name *is* can always be laundered — only one keyed on how
  it *came to exist* cannot.
- Ibex enforces `const` across inputs where **Bun does not**. A deliberate divergence
  from a shipping runtime, taken because a writable `const` is a different language.
- The result ABI is a **semver-major** change to LLP 0002's narrow consumer contract
  (and LLP 0000, which moves with it); embedders must migrate. The *input* half was
  already length-bearing; it is the result half that was not.
- The in-process lowering stage gains source maps that **compose through every later
  rewrite**, script-goal preservation, Reference-fidelity session lowering,
  completion-value fidelity, origin-tagged hygiene, a dependency manifest, and one
  dependency-TLA error — and a conformance corpus of its own, distinct from LLP 0019's.
- The deviation oracle is **engine-relative**: session conformance and engine
  conformance are measured separately, so an engine quirk can no longer masquerade as a
  session defect (or hide one).
- Three engine slices — trap-free introspection, the completion-record discriminator,
  and throw-time error capture — are one patch program, and the document's safety and
  fidelity claims are staged behind it rather than assumed.

## Open questions

1. Can Hermes provide a genuinely trap-free value **capture** — including Proxy detection
   and promise/`Error` state — on every advertised target, and at what patch cost?
   (Whether a release *ships* on stage 1 is LLP 0022 OQ 1's gate, not this document's:
   every stratum is specified here.) Worth checking first whether the vendored debugger
   build's variable-inspection and pause-state paths already read own properties,
   internal state, and thrown values without invoking traps — if so, both the stage-2
   primitive and the stage-1.5 throw capture may be largely extant behind an API Ibex
   already carries.
2. Can Hermes interrupt a running evaluation and leave a provably reusable runtime —
   can *accepted* cancellation exist at all — or is *unavailable* the only honest v1
   answer for a synchronous loop (LLP 0025 OQ 1)? Every rule in §6 holds under all
   three of LLP 0025's defeat modes, so this sets the *quality* of cancellation, not its
   safety.
3. Should the empty-completion discriminator come from a Hermes completion-record patch
   or from source instrumentation (§6)? It is slice 2 of the §8 patch program.
4. **Resolved by accepted LLP 0026:** dependency-level top-level `await` uses
   the authenticated asynchronous module runner, with dependency ordering,
   live cells, SCC scheduling, sticky failure, and defined CJS interop.
   Entry-only TLA remains the durable answer only for this document's legacy
   synchronous session loader until that consumer migrates.
5. **Which parser mechanism implements the Script-plus-`import`-plus-TLA goal** (§3) —
   a parser mode, a maintained fork, or a Script early-error validator run alongside a
   Module parse? The third is *not* sufficient on its own: a Module parse still rejects
   legacy octal and `delete identifier` before any validator sees them, and a Script
   parse still rejects `import`. This must be **prototyped before the source-goal
   fixtures are written**, because it decides whether the sloppy-only parse forms are
   achievable or must become documented narrowings.
6. Should a startup-only strict profile exist for consumers that want module-like
   semantics in script inputs, given §3 fixes sloppy as the default? (Shared with
   LLP 0022 OQ 3.)
7. **Do the engine premises hold per advertised target?** The Windows eval path is
   recorded as not supporting async function syntax, which is the shape the entry-TLA
   lowering emits — and which `await using` at a module entry also depends on. Either
   that comment is stale, or entry TLA needs a different lowering on Windows, or Windows
   does not advertise it. This must be settled before AC8 can be claimed there.
8. The **one versioned constants annex** is normatively pinned by LLP 0025 §12 (renderer
   depth/breadth/payload/truncation, and **maximum input size = 1 MiB** inline), but the
   digest-bound **file** `session-constants.json` **does not exist yet** and is owed
   (LLP 0025 `OBL-CONSTANTS-ANNEX`) — an earlier draft here wrongly said it existed. What
   remains genuinely open and must join it once the file lands: the **completion budget** and
   the **async-storm coalescing window**.
9. **Would an engine-level global environment record be cheaper than the lowering?**
   A native checked record could preserve Reference semantics, source positions, and
   *dependency visibility* — retiring deviation (d) and most of §7.1's syntax-directed
   table — at the cost of a larger patch. It should be costed against the three slices
   of the §8 patch program, since it is the same VM surface.
10. *(Resolved by LLP 0023 §2.3.)* `SourceLabel` is the volume-canonical virtual
    spelling of the retained object's canonical physical location: symlinks use the
    target spelling, while distinct hard-link entries use their own entry spellings.
    Import order never selects the source-map or stack-frame label.
11. Is a **background lifecycle request** — a root-attributed `process.exit(n)` from a timer
    when no evaluation is in flight — a new control-event variant, or a unit-generic
    extension of the evaluation-outcome union? The `lifecycle` outcome (§6) is input-scoped;
    a bare exit has no input to scope to. This is owed jointly with LLP 0025 §8.
