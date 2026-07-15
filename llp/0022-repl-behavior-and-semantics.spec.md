# LLP 0022: REPL Behavior and Semantics

**Type:** Spec
**Status:** Draft
**Systems:** CLI Runtime, REPL, Runtime, Module Loader, Security
**Author:** Charlie Cheever / Codex / Claude
**Date:** 2026-07-11
**Revised:** 2026-07-15 (ENG-25066 switched file-module execution to the authenticated runner while preserving this document's script/prompt goals and session semantics)
**Revised:** 2026-07-12 (round-8 revision, on dual-model round-7 review plus two
independent Codex runs of round 6: names the rule the whole document turns on —
*never tell the operator something untrue* — and applies it reflexively to §11,
whose status column is **removed**, because it went stale three times in one day in
both directions while claiming to be the control that prevents that; no mechanical
check can prove prose *delivers* an obligation, so the ledger now fails closed and
pins every verified discharge to the sibling revision it was checked against.
Retires the root-import lower bound (sound only against premises the artifact does
not attest) for a version cutover; makes the submission credential an input-side
object with a linear lifecycle, not "decision evidence" (a category error); moves
nonce freshness from the schema to CSPRNG construction; enforces the reserved-key
refusal at the loader's native boundary so an alias cannot evade it; and cites
LLP 0025 for the interrupt and exit mechanisms instead of paraphrasing them.)
**Related:** LLP 0023 (virtual filesystem namespace — paths at the prompt);
LLP 0024 (structured evaluation and session semantics — language and display);
LLP 0025 (terminal session ownership and lifecycle — terminal, interrupt, exit,
history); LLP 0004 (module loading and builtins); LLP 0006 (design principles);
LLP 0010 (Ibex binary ownership); LLP 0013 (per-package capability
compartments); LLP 0014 (import-site grants and generated policy); LLP 0019
(Hermes compat transform authority); LLP 0021 (capsec effect-model migration)

## Summary

The Ibex REPL is an interactive root-principal JavaScript/TypeScript session,
not a security bypass and not a sequence of unrelated one-line programs. It uses
the same armed runtime, module loader, builtins, capability decisions, and
event-loop semantics as ordinary Ibex execution, while adding persistent
interactive bindings, top-level `await`, inspection, history, completion, and
REPL commands.

This document is the **behavior contract** for that product surface: what counts
as REPL input and in which modes, how a session with no entry module is armed,
what the prompt may and may not reach, which affordances exist, and what the
prompt is *not* allowed to become. It delegates its mechanism to three
documents, each independently scoped and reviewable (they are not independently
*implementable* — LLP 0025's renderer consumes LLP 0024's inspection output, and
its lifecycle needs an outcome LLP 0024 must carry):

| Mechanism | Document |
| --- | --- |
| Paths, the `/project` namespace, path identity, virtual cwd | **LLP 0023** |
| Source goal, evaluation outcomes, session record, safe display | **LLP 0024** |
| Terminal ownership, fd 0, rendering, interrupt, exit, history | **LLP 0025** |

**Precedence.** This document governs **observable REPL behavior and security
properties**; each sibling governs **its own mechanism**. Neither silently
overrides the other: a contradiction between them is an *invalid corpus state*,
not a quiet win for whichever document is read second, and it is resolved by a
coordinated revision of both. §11 is the ledger of what this contract relies on
its siblings to deliver, so that a dangling dependency is visible rather than
assumed.

## Motivation

A REPL is where a security model gets tested by a human in a hurry. Every
convenience the prompt offers — display a value, complete a property, load a
file, print the environment, accept an import attribute — is an opportunity to
do something the armed runtime would otherwise refuse. Review of the current
implementation found that this had already happened, repeatedly:

- `.env` enumerates the raw host environment through the Rust process, around
  the armed environment gate entirely.
- `.load` performs a host-path read outside the module and capability pipeline
  and evaluates the source in the bare global scope, with the host path as its
  source identity.
- Tab completion resolves its base expression by evaluating it, structurally
  invoking accessor getters. (Lockdown often neutralizes the evaluation today,
  which makes completion inert rather than safe — a distinction worth keeping
  straight.)
- Prompt `with { … }` attributes are routed into the legacy capability oracle
  and acknowledged with a "capability granted" message describing an event that
  **provably did not occur**: armed enforce deletes `Exact.setModuleCapabilities`
  at the end-of-bootstrap seal, precisely because grants come from the generated
  policy artifact and not from runtime self-declaration.
- Raw native bridges — `__exactExit`, `__exactRealpath`, `__exactModuleResolve`,
  `__exactStdinRead` — remain reachable from the root global, so guarantees
  stated over `process`, `fs`, and the module facade are not guarantees at all.

Separately, the armed runtime's own path behavior makes the prompt nearly
unusable: `process.cwd()` falls back to `/`, `fs` resolves `README.md` to
`/README.md`, and the armed host refuses that as an unbindable host path — so a
session started in a repository reports a permission error for a file that
startup just authenticated. LLP 0023 fixes the mechanism; this document fixes
what the user sees.

Each of these is a REPL-local convenience quietly overriding a runtime-wide
rule. The contract below exists so that such an override is a conformance
failure rather than a matter of taste.

**One rule runs through all of it: never tell the operator something that is not
true — least of all something reassuring.** It is the thread connecting three
otherwise unrelated defects this document fixes. The prompt prints
`[capability granted]` for a grant that provably did not occur (§6). An earlier
revision of §2 told an operator to regenerate policy when regeneration provably
could not help them. And an interrupt notice promising "press again to end the
session" is worthless if a dirty edit buffer will silently swallow the next press
(§10). Three unrelated-looking bugs, one disease — and one remedy: a refusal the
operator can act on beats a reassurance they cannot. A false "yes" — in a message,
a diagnostic, or a ledger — is worse than an honest "no".

## Scope

This document covers `ibex` with no file argument and the explicit `ibex repl`
command — the same product surface — in interactive, program, and plain
transcript modes (§3).

The one-shot evaluation surfaces (`-e`, `-p`, `ibex eval`) are not this
document's subject, but they are the **same authenticated ingress** under a
different source identity, so §1's registry split binds them too, as do
LLP 0023's paths, LLP 0024's evaluation and display, and LLP 0025's rendering
rules. They must not grow a second ingress, a second resolver, a second
evaluator, or a second renderer.

This document does not define a debugger, an inspector, a shell escape, a
package manager, a type checker, or a framework console. None of them may be
inferred from REPL access.

## Design

### 1. Session execution ingress and the capability registry

**The REPL is an authenticated execution ingress, not a JavaScript-reachable
evaluator.** This distinction is load-bearing, and the registry does not draw
it — it instead contradicts itself about the same product surface:

| Surface | Classified today |
| --- | --- |
| `command:ibex` — the root parser node; with no file it dispatches to the REPL | `non-capability`, rationale `runtime-bootstrap-state` |
| `command:ibex run` | `non-capability`, `runtime-bootstrap-state` |
| `command:ibex repl` | `closed` under `vm:evaluate` |
| `cli:repl` | `closed` under `vm:evaluate` |
| `command:ibex eval`, `-e`, `-p` | `closed` under `vm:evaluate` |
| `ex_hermes_eval` | `closed` under `vm:evaluate` |

`vm:evaluate` is deny-only, terminal, `staticOnly`, risk tier 4, and its stated
risk is *unattributed code execution*. Read strictly, the armed model says the
REPL cannot exist; read loosely, it says `vm:evaluate` is open, which would hand
every package an `eval`. Neither is right.

The table also shows *why* the registry has not had to decide: **it inventories
parser nodes, not dispatch branches.** `ibex` with no file and `ibex repl` reach
the same REPL, but only the latter has a row of its own — so the same ingress is
simultaneously "trusted bootstrap" and "closed", depending on how the operator
spelled it, and the implicit branch that actually starts most sessions is not
individually classified at all. An ingress that no row describes is worse than
one classified wrongly.

The resolution:

- **Session execution ingress** — the authenticated route by which the CLI
  submits operator-authored source to the engine — is a **control-plane route,
  not a capability**. It carries the armed snapshot, the authenticated root
  identity, the source identity, the source goal, the endowments, and the
  submission provenance (§7), all of which the ingress supplies and none of which
  JavaScript can forge. Code arriving this way is *attributed*, which is exactly
  the property `vm:evaluate`'s risk note says ad-hoc evaluation lacks.
- **Why it is a non-capability at all.** The ingress performs **no external
  effect of its own**. It submits attributed source; every effect that source then
  attempts — a read, a spawn, a socket — is independently mediated at its own
  decision site, under root's ordinary authority and behind every denial stratum.
  The ingress's power is to *authenticate attribution*, not to exercise authority.
  That is exactly the property that makes a control-plane classification honest
  here and would make it dishonest for `eval`, which launders *unattributed* code
  into the same decision sites.
- **It nonetheless needs a new rationale, not an existing one.** It is tempting to
  reuse `authority-control-plane` (which `command:ibex policy` carries), but that
  rationale's predicate is *authority checking, delegation, revocation, or
  evidence bookkeeping without an external effect* — and code submission is not
  bookkeeping. It is also carried today by JavaScript-reachable rows, so it does
  not even mark a non-JavaScript-reachable route. The registry therefore mints a
  new non-capability rationale — **`authenticated-code-ingress`**, predicate
  *"authenticated submission of operator-authored source under a bound armed
  session; exercises no external authority itself, and every effect of the
  submitted code is independently mediated at its own decision site"* — whose
  obligations are the properties that make the route safe: an armed-session
  binding, derived (never caller-supplied) root attribution, a synthetic source
  identity and goal, projected endowments, and rejection of replayed,
  wrong-session, and JavaScript-originated submissions. This is a **vocabulary
  change**.
- **The rationale partitions cleanly with `runtime-bootstrap-state`.** The new
  rationale covers every route that *submits operator-authored source for
  execution* — both REPL spellings, the one-shots, and file execution, which is
  the same act with a file identity. `runtime-bootstrap-state` retains the routes
  that carry no source at all. Without that partition, the §1 critique simply
  recurs one door down at `ibex run`.
- **The classification attaches to the dispatch route, not to syntax metadata.**
  The registry generates several rows per CLI facet — parser node, option,
  spelling, positional — and they disagree today: `option:ibex:eval_code` is
  `non-capability` while `argument-parser:ibex:eval_code:utf8-string` is
  `closed`/`vm:evaluate`, which is *the same `-e` flag classified both ways*. But
  an arity or value-name row does not authenticate or submit anything, and
  pretending each satisfies the ingress predicate would be its own false precision.
  So the **canonical dispatch route** carries `authenticated-code-ingress`,
  structural parser rows *relate* to it, and the implicit no-file REPL branch gets
  a row of its own rather than inheriting the root parser node's.
- **The route inventory must be exhaustive, and the predicate is narrower than
  "any route that runs code".** `ibex capsec audit <file>` executes an
  operator-named file and is classified `runtime-bootstrap-state` today; under the
  partition it is code ingress. But `ibex run <name>` is **not** purely ingress — it
  may dispatch a package script, ambiently read `package.json` and `PATH`, and spawn
  a shell, which *does* exercise external authority and therefore cannot be a
  non-capability. The predicate is exact and must be applied exactly: a route is
  `authenticated-code-ingress` only when submitting attributed source is **all** it
  does; a route that also performs effects keeps its own classification for those
  effects. Naming these cases is the difference between a partition and a slogan —
  otherwise the §1 critique recurs one door down.
- **The obligations cannot live in the rationale.** A non-capability edge carries
  only `{id, surface, rationaleId, rationale}`, and a new rationale otherwise
  inherits a generic `.non-capability` fixture — so none of the properties above
  (session binding, derived attribution, replay rejection) would actually be
  generated or checked. They are carried as **target-cell fixtures or a checked
  obligations dataset keyed to the ingress edges**. A rationale string is prose;
  the guarantee has to be a fixture.
- **Runtime bootstrap is a separate, phase-limited ingress.** The engine's own
  bootstrap evaluates runtime source through the same bare seam today. That route
  is classified separately, is available only before project source begins, and is
  **sealed** at the end of bootstrap — it is not the operator ingress and must not
  become a second door into it.
- **`vm:evaluate` stays closed** as a JavaScript-reachable capability. No
  package, and no prompt code, gains `eval`, `new Function`, `vm`, or a route to
  the engine's evaluator; `global:eval` and `global:Function` remain closed, and
  lockdown's taming of `Function` is unaffected.
- **The generic bare-string ABI stays closed.** `ex_hermes_eval` takes source
  bytes and a caller-chosen source name and calls the engine's evaluator
  directly; it cannot carry attribution, so it is not the ingress and it remains
  closed in armed production. Embedder evaluation goes through the **structured
  session-submit seam** — LLP 0024 §1's source request, extended with the opaque
  armed-session binding and the submission provenance this section requires —
  which *derives* root identity, goal, endowments, and snapshot digest rather than
  trusting a caller to supply them.
- The registry gains the ingress rows for the REPL **and the one-shot surfaces**,
  and the REPL target cells gain the attribution and endowment fixtures they
  currently lack. Until those exist and pass, Ibex must not claim REPL support in
  an advertised target.

**Entry facts versus live loader state.** `Exact.inspect`, `require.cache`,
`require.main`, and `process.mainModule` are closed `runtime:inspect` surfaces
today, and they stay closed. The REPL's renderer therefore uses a **private,
non-JavaScript-reachable** display seam (LLP 0024 §8) rather than reopening
`Exact.inspect` to JavaScript, and loader cache state stays closed — if it is
ever exposed, it is as a principal-filtered immutable facade, not the live map.

This contract does **not** reopen `require.main` or `process.mainModule`, in any
mode. The distinction is not pedantic: `require.main` is not an identity string,
it is the main module's **live loader-graph node** — carrying `parent`,
`children`, `exports`, `loaded`, and mutability — so handing it to prompt or
package code hands over a walkable, writable view of the loader, which is exactly
why the registry closes it in the same breath as `require.cache`. The *identity*
fact that program-mode code legitimately wants is `import.meta.url` and
`import.meta.main` (§3), which are static facts about the source. This is the
same entry-fact-versus-live-state distinction the section draws for
`vm:evaluate`, applied to inspection. (LLP 0024 briefly asserted the opposite and
has since retired `require.main` to match this closure; the main-module flag now
feeds `import.meta.main` only.)

### 2. Startup, project identity, and session arming

The REPL uses the same enforced, armed production posture as ordinary execution.
Starting a REPL must not install a permissive host, weaken lockdown, collapse
package principals, expose the inspector, or restore a legacy capability oracle.

At startup the CLI selects the project candidate from the shell's current
directory, canonicalizes and authenticates it, and installs it as the snapshot's
logical `project` binding (LLP 0023 §1). Authentication happens before any
JavaScript evaluation. Failure to identify or arm the project is a startup
error, never a fallback to the host filesystem root.

**Arming a session with no entry.** Generated policy is entry-scoped (LLP 0014)
and the armed snapshot must contain every package node and edge it will admit
(LLP 0021), but an interactive session has no build-time entry module. The
session is armed from a **session manifest**, and its status is stated
precisely: it *is* the LLP 0021 armed snapshot, carrying a **synthetic entry**
rather than a file entry. It is not a new artifact class, it introduces no new
digest domain, and it is authenticated by exactly the machinery that
authenticates a file-execution snapshot — sealed under the existing armed digest
domain, verified before the first prompt. The entry is a **closed vocabulary**,
not a string convention: a kind — `file`, `stdin`, `repl`, or `eval` — and an
identity (`ibex:stdin` for program mode, `ibex:repl` for a promptful or transcript
session, `ibex:eval` for the one-shots, the virtual file URL for file execution).
The armed-snapshot schema has no entry field today and forbids unknown properties;
adding this one is an LLP 0021 schema obligation (§11), not a private REPL
convention.

The project candidate is chosen by LLP 0023's rule — **discovery origin, then
marker ascent** — not by taking the shell's cwd as the root.

What the synthetic entry changes, and only this:

- **The root import surface** is the set of packages the project's policy
  records as **root-imported** — those carrying a root import site. It is not
  "every package on disk," it is not "every principal in the artifact" (which
  would promote transitive-only dependencies to direct root imports), and it is
  not widened by anything typed at the prompt. The generated artifact does not
  record it today — the generator deliberately drops root edges — and the shipping
  code compensates by treating every principal as root-importable, which is
  precisely the widening this rule forbids. Emitting the row is an LLP 0014
  obligation (§11).

  Until it lands, a session **refuses to arm a root package-import surface at
  all**, with an upgrade diagnostic naming policy regeneration as the remedy — a
  remedy that, unlike the one an earlier revision printed, actually works.

  That earlier revision *inferred* the surface, admitting every package with **no
  incoming package→package edge** on the argument that such a package is provably
  root-imported. The inference is sound against today's generator — and that is
  precisely why it was dropped. It rests on two premises the artifact does not
  attest (every package is entry-reachable; root edges are the only ones dropped),
  so a hand-edited or future artifact could falsify it silently, and an **orphan
  principal would be admitted as "provably root-imported"** when it is nothing of
  the kind. This document says elsewhere that a guarantee holding only while some
  other component keeps behaving is *a coincidence with a shelf life, not a
  guarantee* (§7); accepting one here would be incoherent. It was also incomplete
  where operators would feel it: every shared `lodash`-class dependency has an
  incoming edge and would have been refused regardless.

  A version cutover is simpler, fails closed, and rests on nothing: regenerate, and
  the surface is **recorded** rather than **guessed**.

- **Root's escalation ceiling is empty**, so no dynamic grant taken at the prompt
  can widen anything, and the **dynamic-authority facades are sealed** (§6).
  Package principals are otherwise projected exactly as file execution projects
  them, so package code at the prompt behaves identically to package code under
  `ibex run` — with the single, stated exception §6 records.
- **Policy selection is unambiguous.** There is exactly one candidate: an
  explicit `--policy`, otherwise the project's committed artifact. Environment
  selection of a policy path is forbidden. If a future layout admits several
  candidates, ambiguity **fails** with a diagnostic naming them; it is never
  resolved by a heuristic, because silently preferring a test or tool policy over
  the application's is how test-only grants reach a production session.
- **Interactive and transcript modes** arm from the project's committed policy
  artifact. If none exists, the session arms with an **empty package graph** —
  builtin imports subject to the allowlist and to the same terminal closures (§7)
  still work, and any package import fails closed. It never falls back to an
  unauthenticated graph.
- **Program mode** arms from the *same committed artifact*, adding only the
  main-module identity `ibex:stdin`. Piped source **cannot shape the graph**:
  stdin is not analyzed to mint authority, and an import-site authority
  declaration appearing in piped source grants nothing (§6). Policy authorship is
  a build-time, reviewed act (LLP 0014); a pipe is not a review.
- An import of a package outside the session graph is refused with a distinct
  **out-of-snapshot** error, separable from a resolution failure and from a
  policy denial. The graph is immutable for the session's lifetime, so installing
  a package mid-session cannot widen it: the error names regenerating policy and
  restarting the session as the remedy.

**Piped source runs at full Root in v1. That is a decision, not an oversight.**
Calling piped bytes "unreviewed" explains why they cannot *author policy*; it does
not make them untrusted *code*. Running `ibex < script.js` is the same trust act as
`ibex run script.js` on a file nobody reviewed — the authority comes from the
operator's invocation, not from the source's provenance — and restricting it by
default would silently break `node`-parity for piped scripts, which this
document's own compatibility rule (priority 5) forbids doing *silently*.

This contract therefore does not pretend that graph immutability makes hostile
piped source safe: it does not constrain direct root effects at all. A restricted
profile — mapping piped source to the **Quarantine** principal, which the enum
already has — is the obvious shape of the alternative, and both review families
recommend shipping one. It is not specified here, and this document does not claim
a flag it has not designed (OQ 6).

The project's host path is runtime metadata. JavaScript does not learn it merely
because code is running at the prompt (LLP 0023 §6).

**No implicit startup file.** There is no rc file, init script, or profile that
runs before the first prompt; files with those names in the project or home
directories are inert. This is the highest-leverage regression this document
forbids — ambient file presence must never become root-principal code execution
— and it is fixture-enforced (AC2). An explicit opt-in flag may add one later,
but only by amending this contract.

**The banner** names the product, version, and engine and how to reach `.help`
and exit. It carries no host path, no environment value, and no armed-snapshot
detail beyond version identity. It appears only in interactive mode **with an
editor** — an interactive session with no output terminal prints none.

All REPL presentation configuration is captured before arming and is never
readable from JavaScript (LLP 0025 §2).

### 3. Input modes

**Semantic mode** is selected by whether **stdin** is a terminal. **Presentation
transport** — which descriptor carries the prompt, banner, and editor control —
is a separate axis, governed by LLP 0025 §1: piping results to a file while
typing at the terminal is supported, and where no output descriptor is a
terminal, the editor degrades to transcript behavior on the input.

- **Interactive** — `ibex` or `ibex repl` with a TTY stdin. Line editing,
  history, completion, banner, and prompt redrawing are active **where a
  controlling terminal exists to drive them**: editing needs an output terminal,
  so if neither stderr nor stdout is a TTY the editor degrades to transcript
  behavior on the input (LLP 0025 §1), and the session is interactive in goal but
  not in presentation.
- **Program** — `ibex` (no file) with a non-TTY stdin. Stdin is read to
  end-of-file and executed as one program with file-execution semantics: the
  module goal and TLA rules of LLP 0024 §3, the path namespace of LLP 0023, the
  event-loop-to-quiescence lifecycle of file execution, and file-execution exit
  codes. It is the session's main module with synthetic identity `ibex:stdin`
  (`import.meta.url === "ibex:stdin"`, `import.meta.main === true`, no
  `__filename`/`__dirname`, and **no `require.main`** — that surface stays closed,
  §1). Relative imports resolve from the virtual cwd. No banner, prompt, value
  echo, or history.
- **Plain transcript** — `ibex repl` with a non-TTY stdin. Full REPL semantics
  (persistence, `$_`, per-input display, commands) with no banner, prompts,
  line editing, completion, or history. **REPL-authored output carries no ANSI
  under any setting** (LLP 0025 §4) — program-authored output passes through
  unmodified, as it must, so "ANSI-free" is a property of the session's own
  framing and styling, never a claim about bytes a program deliberately writes.
  Input grouping follows LLP 0024 §5 completeness exactly as at the prompt.
  End-of-file with a pending incomplete input reports a recoverable syntax error
  and exits with the orderly code; recoverable evaluation errors do not change the
  exit code. After each input's result or error is written, asynchronous reports
  that became ready during that evaluation are flushed before the next input is
  read — a serialization checkpoint that the output broker (LLP 0025 §3)
  implements rather than merely hopes for. REPL-owned framing is byte-deterministic
  for a deterministic program, under a pinned renderer version and pinned bounds
  (§11); `.time` is excluded from byte fixtures; startup diagnostics go to stderr
  and are outside the transcript contract. This is the scriptable, testable
  projection of the interactive session; a machine-oriented framed protocol is
  deferred (OQ 4).

**Exit codes and fatality.** Program mode drains the event loop to quiescence
(LLP 0024 §1 makes the drain policy a property of the execution mode: quiescence
for program and one-shot, ready-work-only for interactive and transcript) and
exits 0; it honors a root-set `process.exitCode`; and it exits **1** — Node's
value — on an uncaught fatal error or on a syntax error detected before
evaluation. An unhandled rejection or uncaught exception from background work is
**fatal in program mode** (file-execution semantics) and **never fatal in the
REPL modes** (§5) — one event, two consumer decisions, exactly as LLP 0024 §9
assigns them.

**Input that is not valid UTF-8** is refused with a named error before
evaluation — not replaced, not silently lossy. In program mode that refusal is a
nonzero exit. In transcript mode, malformed bytes are **fatal** until a framed
protocol exists: LLP 0024 now specifies the strict refusal, but no sibling defines a
**resynchronization boundary**, and without one there is no defensible next-input
edge to recover to (`OBL-UTF8`).

The **session record** — persistent cells, `$_`, per-input display — exists only
in the REPL modes. Program mode is a module with one evaluation: no cells, no
`$_`, no echo.

In REPL modes the session owns fd 0 exclusively and `process.stdin` presents
end-of-file to prompt and package code alike (LLP 0025 §1) — no JavaScript can
consume the operator's next command.

### 4. Paths at the prompt

Paths obey LLP 0023 in full. The REPL-visible consequences:

The initial virtual cwd is `/project`, so these agree:

```js
process.cwd()                         // "/project"
path.resolve("README.md")             // "/project/README.md"
fs.readFileSync("README.md")          // project-root README.md
fs.readFileSync("/project/README.md") // the same file
```

Prompt-authored relative module specifiers resolve from the virtual cwd; imports
inside a module resolve from that module's virtual directory. `process.chdir()`
moves the session's virtual cwd and is root-only (LLP 0023 §5), so package code
cannot redirect a later root-relative read, import, or `.load`.

Habitual host spellings (`/etc/passwd`, `/home/you/x`, `/README.md`) produce a
clear **outside-mount error** — not `ENOENT`, not a host access — from every
**effectful** operation: `fs`, module resolution, `.load`, watches, file URLs.
`node:path` itself never errors and never touches the host: `path.resolve` and
`path.relative` *read session state* (the virtual cwd) and the rest are purely
lexical, but none of them is a containment gate and none takes a filesystem
decision (LLP 0023). So `path.resolve("/etc/passwd")` returns the string
`/etc/passwd` unchanged; it is the attempt to *use* it that fails.

**No JavaScript-visible surface discloses a backing host path** — not an error, a
stack, a banner, a completion, or a value. The rule binds what JavaScript can
observe. It does not bind the CLI's own **startup diagnostics**, which are written
to stderr before any evaluation, are unreachable from JavaScript, and address an
operator who already knows their own filesystem: an arming failure that must name
an out-of-project package root (LLP 0023) may name it there. Confusing these two
audiences is what would otherwise force a security rule to make a startup error
useless.

### 5. Language, session, and display at the prompt

Language and evaluation obey LLP 0024 in full. The REPL-visible consequences:

- Prompt input is **TypeScript grammar, non-JSX**, evaluated as a **sloppy
  script extended with imports and top-level `await`** (LLP 0024 §3–§4). `let x:
  number = 1` works; an undeclared assignment creates a persistent global.
  `export` is a syntax error — and so is `import.meta`, because a script has no
  module record and the prompt does not fabricate one. (Program-mode stdin *is* a
  module and does have it, §3.)
- **Declarations persist** across inputs under the session cell model
  (LLP 0024 §7), including `const x = await f()`. Assigning to a prior `const`
  throws; *redeclaring* it succeeds. A closure captured in one input sees later
  writes from another.
- **Top-level `await` is available at the prompt**, and an imported module that
  uses it fails with the stable unsupported error (LLP 0024 §3) — v1 has no
  asynchronous module graph, and this document will not imply one.
- **`$_`** holds the last successfully displayed value; it begins `undefined`;
  an error does not replace it — and neither does a *failed display*. The shipping
  REPL assigns `globalThis.$_` **before** it renders, so a value whose display
  throws already replaces `$_` today; that is a live contradiction of this rule,
  and AC 6 gates it. Any user mutation of `$_` permanently disables
  auto-update, with one notice. (Node spells this `_`. Ibex spells it `$_` and
  accepts the divergence under compatibility priority 5, because `_` is too
  valuable an identifier to reserve at a prompt where lodash is one import away.)
- The `repl:<n>` ordinal advances once per **submitted evaluation** (LLP 0024
  §2): each prompt or transcript input — *including one that fails to parse*,
  since it was still submitted — and each source a command submits, namely a
  `.load` body and a `.time` argument. A command that evaluates nothing does not
  advance it.
- **Display**: an input whose value is `undefined` displays `undefined`; a
  declaration or empty completion displays nothing (a deliberate divergence from
  Node, which echoes `undefined` for declarations). A value that is a Promise or
  thenable is *displayed*, never awaited and never `then`-ed. Display runs no
  user code, which — until the native trap-free primitive lands — means
  non-primitives render by type tag (LLP 0024 §8). Inert is acceptable; unsafe is
  not.
- **Errors** carry the `repl:<n>` source identity with correct positions inside
  the submitted text, even for multiline input, and never a host path.
- **Asynchronous failures** from background work are reported once, above a
  redrawn prompt, attributed to their owning principal, and **never terminate the
  session** — a deliberate divergence from the fatal-by-default behavior of
  non-interactive execution (§3).

Evaluations are serialized: one input at a time, in submission order. The prompt
does not wait for unrelated timers, servers, or watchers to go quiescent; one
unresolved background handle must not wedge later inputs.

### 6. Imports and authority

Prompt imports are ordinary Ibex module loads: same builtin allowlist, same
session graph (§2), same package principals, same import gates, same module
cache, same typed decisions. The REPL must not evaluate an import as runtime or
module-loader principal merely because it rewrites syntax internally. An
imported package runs under its **package** principal, never laundered into
root.

The v1 prompt import surface is exactly: default, named (with renaming),
namespace, side-effect-only, combined default-plus-named, combined
default-plus-namespace, dynamic `import()`, and CommonJS
`require`/`require.resolve` — all under the same rules. Static import declarations
are empty completions and display nothing; only dynamic `import()` displays a
value.

**Authority-bearing forms are refused, in every mode.** Under LLP 0014, import
authority is authored at build time and stripped before the engine sees it; under
LLP 0021 the armed snapshot is immutable. So no runtime form can grant, select,
or attenuate anything — and *accepting one and proceeding anyway would be
fail-open with respect to the user's intent*, since a user writing an attenuating
attribute would silently receive the broader pre-armed authority.

**The reserved key set is generated, not tabulated.** It is exactly LLP 0014's
`GRANT_ATTRIBUTE_KEYS` — today `authorities`, `grants`, `endow`, `builtins`,
`also` — plus the historical `needs`, taken from the build parser's own constant
so that the refusal cannot drift from what the grant syntax recognizes. A
hand-written table would have listed two of those six and silently accepted the
rest as ordinary attributes, which is the exact fail-open bug this rule exists to
prevent. Because the authoritative constant is JavaScript while the refusal runs
in the Rust session layer (whose parser knows only `needs` today), the set is
emitted as a **generated artifact both languages consume** — a hand-copied Rust
list would reintroduce the drift in the other direction.

**This does not contradict LLP 0014's "runnable in every mode."** That statement
is about *bundler-processed* source, whose grant attributes the pipeline strips
before execution, so the engine never sees the syntax. Prompt, `.load`,
transcript, and piped source never pass through that pipeline. The attribute
would therefore reach the engine, where the only choices are to ignore it — which
is fail-open with respect to the author's intent, as above — or to refuse it. We
refuse. (The remaining case, *unbundled direct file execution*, is not defined by
LLP 0014 today and is that document's to settle; §11 rows it.)

| Form | Prompt / `.load` / transcript | Program stdin |
| --- | --- | --- |
| `import … with { <reserved key>: … }` (any generated key) | hard error | hard error; piped source authors no policy (§2) |
| `require("pkg", { <reserved key>: … })` | hard error | hard error |
| dynamic `import(spec, { with: { <reserved key>: … } })` | hard error | hard error |
| ordinary attributes (`with { type: "json" }`) | supported | supported |

**Timing is stated per form, because "before evaluation" is not achievable for a
computed argument.** Static import declarations, and `require`/`import()` calls
whose option bag is a **data-only literal**, are rejected at **parse time**, before
any of the input's code runs. Anything else is **rejected outright in v1**,
because deciding whether an arbitrary object bears a reserved key means reading
properties off it, which can run a Proxy trap or a getter *inside the security
check itself*.

"Object literal" is not a strong enough grammar — an object literal can carry
getters, setters, methods, computed keys, spreads, and arbitrary nested
expressions. The admitted grammar is therefore **recursively data-only**: static
string or identifier keys; values that are literals, or nested data-only object or
array literals; **no** getters, setters, methods, computed keys, spreads, or
non-literal expressions, at any depth, including inside a nested `with`. This is
close to what the language already requires of static import attributes (whose
values must be string literals), and anything richer is refused rather than
inspected. In every case the refusal precedes module resolution, authority
interpretation, and module execution, and no legacy capability oracle is
consulted.

**A syntactic scan is necessary but not sufficient, so the refusal is also
enforced where it cannot be evaded.** `const r = require; r("pkg", bag)` defeats
any check keyed to the spelling `require`, and a locally shadowed `require` would
be falsely accused by one. The loader therefore rejects a second argument **at its
own native boundary, without reading it** — the check that cannot be aliased around
is the one that does not depend on recognizing a name. Fixtures cover aliasing,
shadowing, cross-input rebinding, getters, Proxies, spreads, and computed keys.

"Every mode" means **every route through the shared ingress** — prompt, `.load`,
transcript, program stdin, *and the one-shots* — not merely §3's three REPL modes.
Unbundled direct file execution is the one case LLP 0014 has not settled
(`OBL-FILE-GRANTS`), and this document does not silently claim it.

The current behavior — routing prompt attributes into
`Exact.setModuleCapabilities` and printing `[capability granted: …]` — is retired
outright. Armed enforce *deletes* that function at the bootstrap seal, so the
message reports a grant that could not have occurred; a false reassurance is
worse than a refusal.

**Dynamic authority is closed for the whole session in v1.**
`Ibex.permissions` and `Ibex.authority` (LLP 0021 WP8) are **sealed** — absent, not
present-but-denying — for prompt code and for packages imported at the prompt
alike. The prompt is not a self-grant channel, and a dynamic grant that names its
own grantee from the prompt has no reviewed provenance.

Two earlier revisions of this document got the mechanism wrong, and the second
error is worth recording because it is instructive. Projecting an empty endowment
row does not make an API absent: bootstrap installs both facades on the real root
global regardless of policy, so presence is a fact about **how the global is
constructed**, not about what the snapshot endows. But the natural repair — seal
them from *root* while packages keep them — is **not implementable over the
current compartment membrane either**: a compartment's global is a proxy that
returns the *same* underlying object from the shared real global, so deleting
`Ibex.permissions` from that one object deletes it for every principal. A contract
that promised root-only absence would be promising something the membrane cannot
express.

So v1 takes the honest option: **seal them session-wide**, at the same
end-of-bootstrap step that already deletes `Exact.setModuleCapabilities` under
enforce, with root's empty escalation ceiling (§2) as defense in depth. The cost
is stated plainly rather than hidden: **this is the one place where package code at
the prompt does *not* behave exactly as it does under `ibex run`** — a package that
would request a typed dynamic grant during file execution cannot request one in a
REPL session. That divergence is narrow, it fails closed, and it is visible.
Restoring parity requires **per-principal `Ibex` projections** — a sanitized root
facade and authenticated per-compartment facades — which is a real mechanism
obligation on LLP 0013's compartment composition (§11), not a line this document
can write into being.

### 7. Capabilities, principals, and affordance parity

Prompt-authored JavaScript is attributed to the authenticated **root principal**
and receives only the ambient-root authority the armed model admits. Root is not
*constrained* by its static floor: under LLP 0021's decision order a floor is a
**positive** authority source (stratum 10), and ambient root is another (stratum
14). What constrains root is everything that precedes them — arm validity,
attribution, definition lifecycle and exact target-cell closure, protected-resource
guards, the process-wide ceiling, principal denials, revocation, and quarantine.
**Every deny stratum precedes every positive authority source**, and no later
source, ambient root included, overrides an earlier ceiling or denial. Every WP7
closure that binds file execution binds the prompt identically: spawn, inspector,
VM, workers, WASI, native addons.

Package code retains its principal across synchronous calls, promises, timers,
native completions, and deputy operations. A package cannot gain authority by
being called from the prompt, by having its return value inspected, by having a
property completed, by moving session state (LLP 0023 §5), by terminating the
session (LLP 0025 §8), or by reaching terminal input (LLP 0025 §1).

Root-only operations are decided over the **complete constrained-principal set**
— live frames, schedule-time owner, deputy identity — with missing, ambiguous, or
`NoUser` attribution denying.

**Operator submission.** `.load`'s file read originates in the Rust session
layer, where there is no JavaScript frame to attribute. It is **not** a new
principal — the principal enum is Package / Root / Runtime / ModuleLoader /
Quarantine, and this document does not extend it. It is the **authenticated
session Root, carrying unforgeable operator-submission provenance** minted by the
ingress of §1. It records *which trusted route asserted this Root*, and it grants
nothing by itself. It binds the snapshot digest, the run nonce, the root identity, the source identity,
the ingress kind, and a submission ordinal, so that a replayed, wrong-session,
forged, or JavaScript-originated submission fails to authenticate rather than
being honored. It is a **one-shot permit**, validated and atomically consumed
before any effect — not a reusable evidence bag that a later caller can present
again.

It is **not** "decision evidence", and an earlier revision's use of that phrase was
a category error worth naming: evidence is an *output* the decision model emits
*after* deciding, and it structurally cannot authenticate an *input*. The credential
is an input-side object with a **linear lifecycle** — minted → read-authorized →
immutable byte capsule → evaluated — consumed exactly once, binding the source
**bytes' digest** along with the identity, referrer, goal, role, mode, entry kind,
endowment projection, and ordinal. Without the byte digest it would authorize *a*
read rather than *these bytes*.

**Anti-replay requires a nonce that is actually fresh, and today's is not.**
Production arming loads the canonical example snapshot and overrides the workflow,
mode, policy digest, and engine — but *not* the `runNonce`, which is the fixed test
vector baked into the example. Every armed production session therefore shares one
run nonce. The nonce must be generated by a **CSPRNG during runtime construction,
before the snapshot is digested**; artifact- or caller-supplied values are test-only.
This is a *construction* obligation and not, as an earlier revision claimed, a schema
one — a stateless schema can check an encoding, but it cannot establish entropy,
uniqueness, or freshness. (No permit consumer ships today, so this is a latent
prerequisite defect rather than a live replay channel; it is nonetheless a real
defect in shipped code, and it would silently void the guarantee above.)

**The provenance must reach the read, not merely the evaluation.** `.load`'s
bytes are fetched today by an ambient Rust filesystem call that happens *before*
any evaluation, so attaching provenance to the source request would authenticate
the wrong step — the decision would be taken after the disclosure it is supposed
to gate. The command therefore performs its read through a **typed session-effect
route** that takes the constrained-Root decision *before* reading, over a virtual
path (LLP 0023) and against the submission credential, and returns authenticated
bytes plus the logical referrer the evaluator needs. Ambient and direct engine
file reads are unreachable from session commands. The read is subject to every
ceiling, guard, protected object, and denial stratum above, and is never a bypass:
`.load /etc/passwd` gets the outside-mount error; `.load` of a policy-denied file
gets the denial, with evidence. The credential and the typed read route are
obligations on LLP 0024 §1 and LLP 0021 (`OBL-SUBMIT-CREDENTIAL`, `OBL-TYPED-READ`);
neither carries them today, and LLP 0024 still uses the retired "decision evidence"
terminology, which `OBL-SUBMIT-CREDENTIAL` records as outstanding.

**Raw native bridges are sealed or converted.** A guarantee stated over
`process`, `fs`, and the module facade is worthless if the same capability sits
one identifier away on the root global.

The honest statement of today's risk is narrower than an earlier revision of this
document claimed, and the correction matters: `__exactGetEnv` and
`__exactGetAllEnv` do read and enumerate the *host* environment, but they consult
the legacy capability oracle first, and under an armed host that check **fails
closed** — so they are not, at this moment, a live bypass of `process.env`'s armed
classification. They must still be sealed or converted, because a guarantee that
holds only while a *legacy oracle* keeps refusing is not a guarantee; it is a
coincidence with a shelf life. Overstating a hazard is its own kind of dishonesty,
and this document would rather be exactly right about what is broken.

The implementation maintains a **generated root-global disposition manifest**.
This is deliberately *not* framed as a projection of the capsec registry alone,
which an earlier revision claimed: the registry answers "what effect is this?", and
it admits unresolved `[[dynamic-table:…]]` surfaces precisely because it cannot
always enumerate what is installed. Reachability is a different axis, and it needs
its own generated artifact answering "is this property sealed, converted, private,
or exposed?" — recording, for **every** native install site: its branch, platform,
property key or symbol, aliases, install phase, private consumer, and disposition.

Conformance is a join of **three** sets, not an equality of two — sealed rows
belong in the manifest precisely *because* they must be **absent** from the live
surface:

1. **install sites**, derived from source;
2. the **permitted post-bootstrap reachable set** (install sites minus everything
   sealed); and
3. the **registry rows** that classify the survivors' effects.

A **post-bootstrap sweep on the live engine** enumerates what is actually reachable
from the root global — a finite, descriptor-only traversal that invokes no getter,
covering symbols, aliases, non-enumerable properties, prototypes, and nested
facades — and it must equal set 2 exactly. Natives are covered *regardless of
spelling*: `__exactStdinRead`, for instance, is installed from two different
translation units, and a name-enumerated list seals one and misses the other. Each
native is either **sealed** after the runtime captures it privately during
bootstrap, or **converted** to typed logical values and cooperative requests.
Red-team fixtures address bridges by name; an unresolved dynamic sentinel is not
admissible for a root-reachable global on a conformant target; and a new bridge
that is neither sealed nor converted fails the check and the build.

**Affordance parity.** No REPL feature — command, completion, hint, banner, or
error report — may read or disclose runtime state or host information that the
armed model closes to the session's JavaScript. The Rust CLI's ambient authority
exists to operate the terminal and the armed host, not to answer questions the
typed decision model would deny; and because session transcripts are shared,
logged, and increasingly consumed by tooling driving the terminal, **closed state
printed to the terminal is closed state exfiltrated**. Accordingly `.env` is
**absent in v1** — not reimplemented over a typed surface — and `process.env`
follows the armed classification: an empty base with per-principal overlays as
the registry admits, never the host environment, and never the REPL's
presentation variables.

The one exception is **terminal-operator state** — the history file, prompt and
color configuration, the CLI's private TTY determination — which the CLI owns for
the human at the terminal, captures before arming, and never exposes to
JavaScript (LLP 0025 §2). It is distinct from the typed `stdio:query` surface
JavaScript legitimately sees.

The runtime never solicits interactive consent during evaluation. Any future
consent UX is a separate design.

### 8. Commands

A command is a fresh input whose first non-space characters match `.` followed
by an ASCII letter, then letters, digits, `_`, or `-`, terminated by whitespace
or end of line. Anything else — including `.5 + 1`, which is JavaScript — is
evaluated as input. An unknown command is an error naming `.help`; it is never
evaluated as JavaScript. A command's argument is the remainder of the line after
the first whitespace run following the name, verbatim, so a path may contain
spaces. Command lines never enter multiline continuation: an incomplete argument
is an immediate recoverable error.

The v1 command and alias table is exhaustive and is generated from **the
runtime-surface manifest of LLP 0010** — the mechanism that already keeps the
CLI's flags from drifting — rather than from a second, parallel manifest. Each
row carries name, aliases, arity, admissible modes, output stream, help text, and
an **affordance-parity classification** (§7); `.help`, the dispatcher, and
completion are all generated from it, so `.help` cannot drift from what the
dispatcher accepts. (It currently omits four shipped aliases.) That manifest holds
only the *clap* surface today: growing it a `replSurface` section alongside
`clapSurface`, with the same in-process drift test, is an LLP 0010 obligation
(§11).

| Command | Aliases | Behavior |
| --- | --- | --- |
| `.help` | `.h` | documents every command and alias from the `replSurface` manifest, and every keybinding from LLP 0025's keybinding manifest — both generated, neither hand-maintained |
| `.exit` | `.quit`, `.q` | orderly shutdown (LLP 0025 §8) |
| `.clear` | `.cls` | clears the screen; resets no bindings, no module cache, no runtime; emits nothing in transcript mode |
| `.load <path>` | — | resolves via LLP 0023, takes the typed read decision under operator submission (§7), evaluates as one input (LLP 0024 §3–§4): dialect by extension, TLA available, declarations persist, result displayed. No module-cache entry; re-evaluates on repeat. Relative imports resolve from the loaded file's virtual directory. |
| `.time <input>` | — | evaluates the rest of the line with the prompt's exact semantics and reports elapsed time |
| `.break` | — | during a continuation, abandons the buffered input; the only command recognized mid-continuation, and recognized before the parser |
| `.mounts` | — | prints the virtual mount table and current virtual cwd — parity-safe by construction (it shows exactly what prompt code can discover by probing) and the operator's introspection tool for a novel namespace |

`.load` accepts exactly the dialects LLP 0024 §4 defines, and its edges are
pinned rather than left to the implementation:

| `.load` of | Behavior |
| --- | --- |
| `.js`, `.jsx`, `.ts`, `.tsx` | script input under that dialect; declarations persist |
| `.json` | parses and **displays the value**; declares nothing, creates no cache entry. Not a script input — JSON has no source goal |
| `.mjs`, `.cjs`, `.mts`, `.cts` | **named refusal** — the extension *asserts a module kind*, and `.load` is not a module load; `import` the file instead |
| `.d.ts`, unknown extension, extensionless | **named refusal** |

A new command requires an affordance-parity classification recorded in the
manifest. "Presentation-level" is not self-evident: a `.session` command that
prints graph or profile digests is only admissible if prompt JavaScript could
learn the same, and that must be argued, not asserted. Any command that performs
an external effect, discloses runtime state beyond prompt reach, or touches
authority requires a contract revision. A command that writes files (a future
`.save`) routes through the same typed decisions as prompt code performing the
same write.

### 9. Completion and hints

Completion is advisory, bounded, and **non-authorizing**. It must not import a
module, traverse the filesystem, request authority, perform network I/O,
evaluate user expressions, or run any user code merely because Tab was pressed.

v1 completes parser-tracked session binding names, the static builtin-module
manifest, and command names. **Member completion is gated on the native
trap-free introspection primitive** (LLP 0024 §8): resolving `a.b.` must invoke
no accessor and no Proxy trap at any step, and pure-JavaScript reflection
(`getOwnPropertyNames`, `getPrototypeOf`) runs traps and therefore does not
qualify. Where the primitive is unavailable, or a step in the chain is an
accessor or a Proxy, member completion yields **no candidates** — it never falls
back to evaluating the base expression. Syntactic screening (rejecting calls,
indexing, operators) is necessary but not sufficient.

Queries are bounded by a documented budget; a query that misses it yields no
candidates, leaves the session usable, and does not corrupt in-progress
evaluation. Completion *insertion* is specified separately from display: a
non-identifier property name is either omitted or inserted as correctly escaped
bracket notation, never as a broken identifier. Hints follow the same rules.
Completion of import specifiers may use the static builtin list but must not
traverse the filesystem or the package graph until a design admits it.

### 10. Terminal, interrupt, exit, and history

These obey LLP 0025 in full. The REPL-visible consequences: the prompt is `➤ `
(configurable, captured pre-arming); all REPL-authored output is escaped against
the full C0/DEL/C1 range so no value, error, or recalled history entry can inject
terminal control; one color predicate governs styling, and transcript mode is
unconditionally free of session-authored ANSI; `Ctrl+D` and `.exit` shut down in
order; `process.exit(n)` at the prompt is a cooperative, root-only, **uncatchable**
request that restores the terminal, and a package calling it is denied; the
terminal is restored on every process-controlled exit path; and history is
project-scoped, hardened, and **appended at submission** (LLP 0025 §9) — so
secrets typed in one project are not recalled in another, and no exit path has
history work to do.

**Interruption is target-based, and the operator-facing promise is that every
notice is true.** `Ctrl+C` cancels an input, a continuation, or an evaluation. The
state machine, the latch rules, and the trajectories are **LLP 0025 §6's, and this
document cites them rather than paraphrasing them** — paraphrase is how every
cross-document claim in this corpus has gone stale, this one included: a previous
revision inherited the word "unwind" for the exit mechanism, which LLP 0025 shows is
not what happens.

The REPL-visible guarantees are these, stated in LLP 0025 §6's own terms — over work
**class and epoch**, never over target identity. The distinction is not pedantry:
under a `setInterval` storm the callback being interrupted is a *different object*
each time, so a guarantee phrased over target identity would be **vacuous in exactly
the case a stuck operator needs it**. An epoch opens when work becomes in-flight from
quiescence and closes only on quiescence plus a republished prompt.

**Two interrupts within one work epoch** end the session — terminal restored, exit
**130** — without depending on the engine, the worker, or JavaScript cooperating. The
worst case from any reachable editor state is **three**, because an interrupt aimed at
a non-empty edit buffer spends itself discarding the buffer. A second interrupt at an
**idle** prompt ends the session by *orderly shutdown*, honoring root-set
`process.exitCode`, not by 130. Modes with **no editor** — transcript, program,
one-shot, and interactive-without-a-terminal — terminate on a **single** interrupt.

**The bound is not the property that matters; the honesty of the notice is.** The
guarantee worth making is that *every notice becomes true*: each press either ends
the session or prints another "press again" that is itself honored within the bound.
The failure being guarded against is not an operator pressing a key three times — it
is an operator reaching for `kill -9` because the session told them something false.
That is the same defect as `[capability granted]` (§6) and as a diagnostic naming a
remedy that cannot work (§2), and it gets the same answer.

The cooperative exit is an **evaluation outcome** distinct from a throw and from a
cancellation (LLP 0024 §6). Its mechanism is LLP 0025 §8's: the call **parks** — it
does not return, and it does not unwind past `finally`, which is a mechanism no
vendored Hermes interface offers.

### 11. Delegated obligations

This contract states behavior; its siblings state mechanism. This ledger names
every guarantee it borrows, so that a dangling dependency is visible and assigned
rather than silently assumed.

**This ledger does not assert delivery status, and that is deliberate.** Earlier
revisions carried "delivered today" columns. They went stale three times in one
day — in *both* directions, marking landed guarantees as missing and missing
guarantees as landed — while the section asserted it was the instrument that
prevents exactly that. The cause is not carelessness; it is structural, and it is
worth stating plainly because it generalizes:

- three siblings are under concurrent revision, so any status claim is a race; and
- **no mechanical check can prove that prose semantically delivers an
  obligation.** `./ref-check` can verify that an owner *marked* a row; it cannot
  verify that the marking is *true*. A generated table is traceability, not proof.

So the ledger **fails closed**, exactly as the rest of this document does: **every
obligation is treated as undischarged until its owner's attestation and its gating
fixture both pass.** The asymmetry is the whole point — a stale "not delivered" is
a false alarm, which is safe and self-correcting; a stale "delivered" is a *false
assurance*, which is the precise failure mode this document exists to prevent.
An unverifiable "yes" is a liability; an honest "no" is a control.

Where the orchestrator has verified a discharge, it is recorded **pinned to the
sibling revision it was verified against** — `verified at 0024 b0ff4ea3247e` is
permanently true and can only become *outdated*, which is an honest and detectable
state, unlike a bare "yes", which can become *false*. Status is otherwise computed
by the join in `OBL-LEDGER-CHECK`, which does not exist yet; until it does, this
table is **documentation of an intent, not a control**, and it says so rather than
implying a guarantee it cannot make.

Each row is **one semantic assertion**, so that a partial discharge cannot hide
inside a compound row.

| ID | Obligation (one assertion) | Owner | Gating criterion |
| --- | --- | --- | --- |
| `OBL-PATHS` | Virtual `/project` namespace, path identity, root-only virtual cwd, no-host-path observables | LLP 0023 | AC 5 |
| `OBL-EVAL-OUTCOMES` | The five-way outcome type (empty / value / throw / cancelled / lifecycle) | LLP 0024 §6 | AC 4, AC 6 |
| `OBL-EXIT-MECHANISM` | *One* cooperative-exit mechanism across the corpus. LLP 0025 specifies that the call **parks** and the session layer disposes of the worker; an "unwind past `finally`" is a mechanism no vendored Hermes interface offers. §10 cites 0025 rather than paraphrasing it | LLP 0024 §6 ↔ LLP 0025 §8 | AC 4 |
| `OBL-CELL-MODEL` | Session cell model, no thenable assimilation, entry-only TLA | LLP 0024 §§3, 7 | AC 6 |
| `OBL-SAFE-DISPLAY` | Display runs no user code, over a private, non-JavaScript-reachable seam | LLP 0024 §8 | AC 1, AC 6 |
| `OBL-DISPLAY-TREE` | Exactly one versioned, **unstyled** semantic tree crosses the worker boundary; the session layer derives styling from node kinds. *Verified discharged at 0024 `b0ff4ea3247e` / 0025 `43ff879a257a`* — and the deciding argument is a security argument, not an aesthetic one: under the worker split the producer may be hostile, so a producer that can **name a style** can emit terminal control. A tree that cannot express styling makes injection **structurally impossible rather than merely forbidden** — the same reasoning that seals a bridge instead of gating it | LLP 0025 §3 | AC 4 |
| `OBL-DISPLAY-ACK` | Display-success acknowledgement reaches the evaluator, so `$_` holds the last *successfully displayed* value | LLP 0024 §7 ↔ LLP 0025 §3 | AC 6 |
| `OBL-NO-EVAL` | `eval`/`Function` closed in the v1 profile, with no session semantics inferred for them | LLP 0024 §7, registry | AC 1 |
| `OBL-INGRESS-CTX` | Every security-relevant source-request field — principal, goal, role, referrer, mode, main-flag, **endowments** — is *derived* from authenticated session state, never caller-selectable | LLP 0024 §1 | AC 1 |
| `OBL-SUBMIT-CREDENTIAL` | An opaque, non-JavaScript-reachable `SubmissionCredential` with a **linear lifecycle** — minted → read-authorized → immutable byte capsule → evaluated — binding the byte digest, source identity, referrer, goal, role, mode, entry kind, endowment projection, and ordinal, consumed exactly once. It is **not** "decision evidence": evidence is an *output* of a decision and cannot authenticate an *input* | LLP 0024 §1 + LLP 0021 | AC 11 |
| `OBL-FRESH-NONCE` | The production `runNonce` is generated by a **CSPRNG at runtime construction**, before snapshot digesting; artifact- or caller-supplied values are test-only. A stateless schema cannot establish freshness, so this is a *construction* obligation, not a schema one | LLP 0021 arming | AC 11 |
| `OBL-TYPED-READ` | `.load`'s bytes are obtained by a typed, credential-verifying read whose decision precedes disclosure, returning authenticated bytes and a logical referrer, with TOCTOU/object-identity handling | LLP 0023 + LLP 0021 | AC 11 |
| `OBL-DRAIN` | Execution-mode-determined drain policy, with the readiness boundary defined rather than merely named | LLP 0024 §1 | AC 4 |
| `OBL-TERMINAL` | fd-0 brokerage, terminal-safe rendering, sequenced broker, target-based interrupt machine, history at submission | LLP 0025 §§1–9 | AC 4 |
| `OBL-SEQUENCE` | One cross-process sequence allocator across evaluation outcomes, async failures, and broker events — with a named owner, crash epochs, and worker-restart behavior | LLP 0024 ↔ LLP 0025 | AC 4 |
| `OBL-CANCEL-TARGETS` | Cancellation carries a target kind and id, admits background callbacks and completion queries, and distinguishes permanently-`Pending` from terminally-`defeated` | LLP 0024 §6 ↔ LLP 0025 §6 | AC 4 |
| `OBL-ASYNC-FATALITY` | The complete **mode × failure-class × exit-status** matrix — fatal in program/file, never fatal at the prompt, one-shot stated — including program mode's exit **1**. *Verified discharged at 0025 `7b89315f8ad7`*, whose §8 now carries the matrix both siblings delegated there. (An earlier revision of this row carried unpinned prose claiming it had "stood undischarged for four rounds" — a status claim, in the section whose entire rule is that unpinned status claims are the disease. It was false within a day. The rule now applies to itself.) | LLP 0025 §8 | AC 4, AC 15 |
| `OBL-ENTRY` | Armed snapshot carries a synthetic entry (closed enum `file`/`stdin`/`repl`/`eval` + identity) | LLP 0021 schema | AC 3 |
| `OBL-ROOT-IMPORTS` | A **versioned artifact** records the exact root-import surface; artifacts predating it are refused with an upgrade diagnostic (§2) | LLP 0014 generator | AC 3 |
| `OBL-ROOT-BUILTINS` | The exact root builtin set for a synthetic-entry session, authored rather than inferred | LLP 0014 / LLP 0021 | AC 3 |
| `OBL-ENV-BASE` | An explicitly empty session environment base plus admitted overlays, bound in the snapshot | LLP 0021 schema | AC 10 |
| `OBL-INGRESS-ROWS` | An `authenticated-code-ingress` rationale on the canonical **dispatch route**, with its obligations carried as target-cell fixtures or a checked dataset — a non-capability edge carries only `{id, surface, rationaleId, rationale}` and cannot express them | capsec registry | AC 1 |
| `OBL-LOADER-CLOSED` | `require.main`/`require.cache`/`process.mainModule` unreachable in every mode | registry + LLP 0024 | AC 1 |
| `OBL-IBEX-SEAL` | The end-of-bootstrap seal removes `Ibex.permissions`/`Ibex.authority` session-wide (§6) | LLP 0013 bootstrap seal | AC 7 |
| `OBL-IBEX-PROJECTION` | Per-principal `Ibex` projections, which would restore the parity §6 gives up — including **handle mint/revoke and bearer delegation**, not merely self-grant | LLP 0013 compartments | — (v1 does not depend on it) |
| `OBL-DISPOSITION` | A generated root-global disposition manifest from **one native registrar with stable install IDs**, with pinned sweep roots, cycles, budgets, symbols, aliases, prototypes, and platform branches | LLP 0013 + registry | AC 9 |
| `OBL-MODULE-IDENTITY` | One module-identity algebra: `ibex:stdin` is the sole synthetic *module*; `repl:<n>`, `ibex:eval`, and `.load` have source identities but never module identities or cache keys | LLP 0023 ↔ LLP 0024 | AC 6 |
| `OBL-REPL-SURFACE` | A `replSurface` manifest section with a **one-to-one join to coverage edges and target cells** — an affordance label alone does not satisfy LLP 0021's no-unclassified-surface invariant | LLP 0010 + registry | AC 12 |
| `OBL-KEYBINDINGS` | An exhaustive published keybinding manifest for `.help` to generate from | LLP 0025 §5 | AC 12 |
| `OBL-RESERVED-KEYS` | A cross-language generated reserved-key artifact, and a refusal enforced at the **loader's native boundary** so an aliased or shadowed loader cannot evade it | LLP 0014 | AC 7 |
| `OBL-FILE-GRANTS` | Reserved-key disposition for unbundled direct file execution | LLP 0014 | — |
| `OBL-UTF8` | Strict UTF-8 decoding with a named refusal, **and a defined transcript resynchronization boundary** — absent one, malformed bytes are fatal in transcript mode | LLP 0024 §1 | AC 4 |
| `OBL-BOUNDS` | Pinned renderer grammar and numeric bounds, without which transcript byte-fixtures cannot be pinned | LLP 0024, LLP 0025 (open in both) | AC 4, AC 13 |
| `OBL-INTERRUPT-CLASS` | An obligation LLP 0025 places on **this** document: state the escape guarantee over work **class and epoch**, never target identity, which a turnover storm falsifies. *Discharged in §10 against 0025 `7b89315f8ad7`* | this document (§10) | AC 15 |
| `OBL-ESCAPE` | Escape from an uninterruptible synchronous loop (supervisor/worker) | LLP 0025 §7 | AC 15 |
| `OBL-STARTUP-DIAG` | One owner for whether a startup diagnostic may name a host path. Three documents hold three positions today: §4 exempts pre-evaluation CLI diagnostics; LLP 0023 §1.2 mandates a **symbolic** package locator and attributes that rule to LLP 0025; LLP 0025 §9 disclaims having imposed it | LLP 0023 ↔ LLP 0025 ↔ this document | AC 5 |
| `OBL-PLAN` | A companion Plan sequencing the ABI, engine patches, supervisor, schemas, and harness, and naming a minimal conformant v1 | this corpus | — |
| `OBL-LEDGER-CHECK` | The obligation data file, owner-side attestations, and the `./ref-check` join that would let this table claim anything at all | LLP 0000 (process tooling) | — |

## Compatibility priorities

When goals conflict, the REPL applies this order:

1. armed-host integrity and correct principal attribution;
2. no external effect before its typed decision;
3. coherent virtual path and module semantics;
4. JavaScript language correctness and session persistence;
5. Node/Bun/Deno REPL familiarity;
6. cosmetic output compatibility.

Ibex reports an incompatibility rather than silently violating a higher item to
imitate a lower one.

## Acceptance criteria

The mechanism criteria live with their mechanisms (LLP 0023 §Acceptance,
LLP 0024 §Acceptance, LLP 0025 §Acceptance). These are the REPL's own,
exercised end to end through the product surface. Fixtures are generated from
the surface registry and the builtin manifest, so a new or aliased API cannot
escape them; source and vendored-generated builtins run the same fixtures.

1. **Registry coherence (§1):** `vm:evaluate` remains closed to JavaScript — no
   prompt or package route reaches `eval`, `new Function`, or the engine
   evaluator — while the session ingress executes operator source with full root
   attribution; the REPL **and one-shot** ingress rows, **and the implicit no-file
   dispatch branch**, carry the `authenticated-code-ingress` classification and
   its obligations (session binding, derived attribution, replay and wrong-session
   rejection); the structured session-submit seam carries a row of its own, per
   LLP 0021's no-unclassified-surface invariant; raw `ex_hermes_eval` remains
   closed in armed production; `require.main`, `require.cache`, and
   `process.mainModule` are unreachable in every mode; and the REPL target cells
   carry passing attribution and endowment fixtures.
2. **No implicit startup file (§2):** rc-named files planted in the project and
   home directories produce no marker effect.
3. **Arming (§2):** a project whose artifact records root imports can import an
   in-graph package at the prompt and is refused an out-of-graph one with the
   distinct out-of-snapshot error; **a package reachable only transitively
   (root → A → B) is refused a direct prompt import of B**, proving the root
   surface is the recorded root-import set rather than the principal list; an
   artifact predating the root-import row is refused an armed root package-import
   surface entirely, with the **upgrade diagnostic** naming policy regeneration —
   and a fixture asserts that an artifact containing an **orphan principal** (one no
   entry reaches) is never admitted as root-importable, the case the retired
   lower-bound inference would have silently allowed; a project with no policy arms
   with an empty graph;
   ambiguous policy candidates fail rather than being selected heuristically; **a
   tampered committed policy artifact fails its digest check and a tampered
   host↔engine arming handshake fails closed, both before the first prompt**; and
   **piped source containing an authority declaration grants nothing**.
4. **Modes (§3):** `ibex` and `ibex repl` share the **interactive** suite; `ibex
   repl` with non-TTY stdin runs the **transcript** suite while `ibex` with
   non-TTY stdin runs **program** mode; program mode runs stdin as the
   `ibex:stdin` main module with file-execution semantics and exit codes, and a
   background async failure is fatal there while non-fatal at the prompt;
   transcript mode is byte-deterministic and free of REPL-authored ANSI while
   program-authored ANSI passes through unmodified; its EOF-with-incomplete-input
   path reports a recoverable syntax error; its flush checkpoint orders a
   background report between inputs; invalid UTF-8 input is refused with a named
   error.
5. **Paths at the prompt (§4):** `process.cwd()` is `/project`;
   `fs.readFileSync("README.md")` reads the project file; effectful use of
   `/etc/passwd` and `/README.md` gives the outside-mount error, while
   `path.resolve("/etc/passwd")` returns the string unchanged; no REPL output
   contains a host path.
6. **Language and session (§5):** declarations and `$_` persist, including
   `const x = await f()`; assigning to a prior-input `const` throws while
   redeclaring succeeds; an imported module using top-level `await` fails with the
   stable unsupported error; an input whose value is an instrumented thenable is
   displayed without `then` being called; **a value whose display throws does not
   replace `$_`** — the shipping REPL assigns `$_` before rendering, so this fails
   today; a declaration displays nothing while
   `void 0` displays `undefined`; `export` and `import.meta` are syntax errors at
   the prompt while `import.meta.main` holds in program mode; an error on line 3
   of a multiline input reports `repl:<n>` at line 3.
7. **Imports and authority (§6):** **every key in LLP 0014's
   `GRANT_ATTRIBUTE_KEYS`, plus `needs`**, is a hard error in every mode and in
   every form (static, `require`, dynamic `import`), asserted *from the generated
   cross-language artifact*, so that adding a key to the grant syntax without
   adding it to the refusal fails the build; a non-literal option bag is refused;
   no module executes; no legacy oracle is invoked; `with { type: "json" }` still
   works; **an aliased loader (`const r = require; r("pkg", bag)`) is refused at the
   loader's native boundary without the bag being read**, while a locally shadowed
   `require` is not falsely accused;
   **`typeof Ibex.permissions` and `typeof Ibex.authority` are `undefined`
   — for prompt code *and* for a package imported at the prompt** (§6's stated
   v1 divergence), asserted against the *sealed* global with a fixture that would
   fail if the facades were merely present-but-denying; and a data-only-literal
   fixture set proves that a getter, a method, a computed key, a spread, and a
   nested non-literal in an option bag are each refused **without being
   evaluated**.
8. **Attribution (§7):** a package imported at the prompt stays package-attributed
   through direct, promise, timer, deputy, and native-completion effects;
   `NoUser`/ambiguous attribution denies; a package cannot move the cwd, exit the
   session, or read terminal input.
9. **Raw bridges (§7):** `globalThis.__exactExit`, `__exactRealpath`,
   `__exactModuleResolve`, `__exactStdinRead`, `__exactGetEnv`, `__exactGetAllEnv`,
   and every other native in the disposition manifest are unreachable or
   typed-and-cooperative; a red-team fixture asserts each by name; **a
   post-bootstrap descriptor-only sweep of the live root global — invoking no
   getter, and covering symbols, aliases, non-enumerable properties, prototypes,
   and nested facades — returns exactly the permitted reachable set**, so a sealed
   native appearing in the sweep and an un-dispositioned native alike fail; an
   unresolved dynamic sentinel for a root-reachable global fails the build, as does
   an unsealed new bridge.
10. **Affordance parity (§7):** a host-only marker environment variable set for
    the test never appears in any command output, banner, error, hint, or
    completion; `.env` is absent; `process.env` shows the armed base plus admitted
    overlays only.
11. **`.load` (§8):** `.load` of an outside-mount path gives the outside-mount
    error; `.load` of a policy-denied file gives the denial with decision
    evidence, **and the denial is taken before the bytes are read** — an
    instrumented ambient read observes no access; the submission credential is
    **consumed exactly once** — a replayed, cross-session, or wrong-bytes credential
    is refused; the production `runNonce` differs between two runtimes **and arming
    refuses any nonce equal to a `capsec/examples/` vector** — a denylist tripwire that
    costs nothing and would have caught the shipped defect mechanically;
    `.load foo.ts` works; `.load`
    declarations persist; `.load` creates no module-cache entry; `.load` of a
    `.json` displays the parsed value and declares nothing; `.load` of a `.d.ts`,
    `.mjs`, `.cjs`, `.mts`, `.cts`, unknown-extension, or extensionless file is
    refused with the named error.
12. **Commands (§8):** `.5 + 1` evaluates to `1.5`; `.unknown` errors naming
    `.help`; `.break` abandons a continuation; an incomplete `.time` argument is
    an immediate error; `.help` is a pinned fixture enumerating every command and
    alias **from the `replSurface` section of the LLP 0010 runtime-surface
    manifest**, so a dispatcher alias missing from help fails the build, exactly
    as a clap-surface drift does today.
13. **Completion (§9):** an instrumented getter anywhere on the completed chain
    and an instrumented Proxy trap are never invoked; no filesystem or network
    evidence is created; a budget miss yields no candidates and leaves evaluation
    correct; a non-identifier property inserts as escaped bracket notation.
14. **WP7 closures (§7):** spawn, inspector, VM, workers, WASI, and native-addon
    surfaces exercised from the prompt are denied exactly as in file execution.
15. **Terminal, interrupt, and exit (§10):** a PTY suite exercised **through the
    product surface**, importing LLP 0025's interruption, restoration, and lifecycle
    criteria by reference. Two interrupts **within one work epoch** end a runaway
    evaluation with exit 130 and a restored terminal — **including under a
    `setInterval` turnover storm**, where a target-identity rule would fail; at most
    three from any editor state; a single interrupt terminates the editorless modes;
    **every notice is true** (each press either ends the session or prints a further
    notice that is itself honored within the bound); root `process.exit(7)` exits 7
    with the terminal restored and no code after the call running; a package-attributed
    exit is denied.

## Consequences

- The REPL becomes usable — relative paths work — without weakening the armed
  posture, and the mechanism that makes that true is shared with file execution
  rather than special-cased for the prompt.
- The registry gains an explicit split between authenticated session ingress and
  JavaScript-reachable evaluation, and stops classifying one product surface two
  contradictory ways. Until those rows and fixtures exist, Ibex cannot honestly
  claim REPL support on an advertised target.
- The root import surface stops being an inference and becomes an artifact fact.
  Until LLP 0014 emits that row, an interactive session imports **no packages at
  all** and says so with an upgrade diagnostic. That is a real regression against
  today's behaviour — which silently promotes every transitive dependency to a
  direct root import — and it is taken deliberately: an inference sound only against
  the current generator would have admitted an orphan principal as "provably
  root-imported", and this document does not rest guarantees on premises its inputs
  do not attest.
- A computed second argument to `import()` or `require()` is rejected — a real, if
  rare, language divergence, accepted because deciding whether an attacker-supplied
  options object bears a reserved key would otherwise run a Proxy trap inside the
  security check itself.
- `.env` is gone. Prompt authority attributes become a hard error rather than a
  false reassurance — the one place this contract deliberately breaks a currently
  "working" flow, because what it currently reports never happened.
- Raw native bridges are sealed or typed, recorded in a generated disposition
  manifest joined to the registry, so the contract's guarantees hold across the
  whole root global rather than only over the public builtins or a hand-listed set
  of `__exact*` names.
- Dynamic authority (`Ibex.permissions`, `Ibex.authority`) is closed for the whole
  session in v1 — including for packages imported at the prompt. This is the one
  place the contract knowingly breaks prompt/file-execution parity, because the
  compartment membrane cannot express a root-only seal; restoring parity needs
  per-principal `Ibex` projections.
- Dependency-level top-level `await` is explicitly unsupported in v1 rather than
  silently mis-lowered.
- Display is inert (type tags) until the native trap-free primitive lands —
  visibly worse output, in exchange for a prompt that cannot be made to execute a
  hostile object's getter by looking at it.
- A PTY, transcript, and registry-generated conformance harness must be built;
  the REPL today has only unit tests, and nearly every criterion above is
  uncovered.

## Open questions

1. Should the REPL ship before the native trap-free introspection primitive
   (LLP 0024 OQ 2), accepting type-tag-only display in the interim, or is rich
   display a release requirement?
2. Which optional affordances are worth their surface area next — `.editor`,
   `.save`, `.session`, and a `.graph` that lists the session's in-graph package
   names (parity-safe by §8's own argument, since prompt code can already
   discover them by import probing, and a real improvement to out-of-snapshot
   UX)? Each needs an affordance-parity classification.
3. Should a startup-only strict profile exist for users who want module-like
   semantics at the prompt, given sloppy is the default?
4. Is a machine-oriented framed protocol for transcript mode worth specifying
   once the structured evaluation seam exists — and should it be the same wire
   format as the supervisor/worker event stream (LLP 0025 §7), so the two cannot
   drift?
5. Should transcript mode gain a flag making recoverable evaluation errors exit
   nonzero, for use as a CI harness?
6. §2 fixes **full Root** as v1's default for piped source. Should a **restricted
   route** ship alongside it — mapping piped source to the existing **Quarantine**
   principal, behind `--stdin-quarantine`? Both review families recommend shipping
   one; the flag's principal mapping, manifest row, and acceptance criteria are not
   designed, and this contract will not claim a flag it has not specified. The
   remaining decision is whether the *default* ever flips, which cannot be settled
   without usage evidence.
7. Does v1 accept the **dynamic-authority parity break** (§6) — packages imported
   at the prompt losing `Ibex.permissions`/`Ibex.authority` because the compartment
   membrane shares one `Ibex` object — or is `OBL-IBEX-PROJECTION` (per-principal
   facades) a release requirement? v1 assumes the former.
8. What is a **minimal conformant v1**? The obligations in §11 span an engine
   patch, a supervisor, a new ABI, schema and generator changes, and a PTY harness;
   "v1" must not silently mean all thirty rows. A companion Plan should sequence
   them — a defensible first slice is transcript mode over an empty package graph,
   with structured outcomes, typed stdin, inert display, and no dynamic authority,
   proving the ingress, attribution, and lifecycle seams before the interactive
   editor and rich inspection are built.
