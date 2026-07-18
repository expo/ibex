# LLP 0025: Terminal Session Ownership and Lifecycle

**Type:** Spec
**Status:** Draft
**Systems:** CLI Runtime, REPL, Runtime, Security
**Author:** Charlie Cheever / Claude / Codex
**Date:** 2026-07-12
**Revised:** 2026-07-18 (the any-thread structured-control ABI now requires a
captured runtime-generation nonce and a teardown-drained full-operation lease.)
**Revised:** 2026-07-15 (ENG-25066 routed default file-module execution through
the same TLA keepalive/cancellation unit); 2026-07-15 (ENG-25063 classified a
TLA-suspended module graph as one keepalive/cancellation unit rather than one
target per import waiter.)
**Revised:** 2026-07-15 (environment-inventory reconciliation now covers 156
source-derived rows and 338 exact occurrences, including closed child-process
environment construction, per-loader transform selection, armed-fresh
in-memory transpilation, armed-unreachable disk-fallback controls, and
diagnostic-only native enumeration.)
**Revised:** 2026-07-15 (implementation reconciliation: final cooked-mode
restoration now completes before scoped SIGINT dispositions are returned, with
a retained self-pipe reader keeping that mediation safe after its coordinator
joins; if cooked-mode restoration itself fails, the safe scoped SIGINT and fatal
signal dispositions plus the pipe remain process-lifetime instead of returning
default-killing handlers.
The fatal-handler fallback restores termios and exits without cosmetic TTY
writes, which are async-signal-safe as calls but can still block on a
flow-controlled terminal; ordinary supervisor paths retain the complete reset.)
**Revised:** 2026-07-15 (implementation reconciliation: launcher,
direct-execution, and terminal-session self-pipe bridges are one-shot per CLI
process. Teardown restores prior signal dispositions and joins ordinary
consumers, but retains the CLOEXEC pipes and global claims so a handler already
entered on another thread cannot write to a reused descriptor or notify a later
scope; isolated process fixtures cover delayed handler completion and the
explicit sequential-reinstallation refusal.)
**Revised:** 2026-07-15 (implementation reconciliation: ordinary input-lane
fullness is now diagnosed as backlog exhaustion instead of fabricated
per-submission overflow; the raw scanner keeps recognizing control bytes while
it discards ordinary input through an outside-paste boundary, and decoded
record length remains the sole 1 MiB test. Fresh bracketed-paste data uses its
arrival prompt provenance for the interrupt-run reset, and UTF-8 backspace
removes a complete final scalar while making safe bytewise progress over
malformed or incomplete suffixes.)
**Revised:** 2026-07-15 (implementation reconciliation: an editor-time external
SIGINT and a raw Ctrl+C byte now enter the same serialized generated interrupt
dispatch and priority event lane; authenticated PTY fixtures prove both routes
through a wedged completion and restoration. A watch controller now gives the
group-signaled child two seconds to finish its own direct-execution cleanup
before TERM/kill fallback, without sending a duplicate SIGINT. A real shell
fixture proves the grace/no-TERM boundary; the public watch-child fixture
remains blocked by ENG-24933's intentionally absent production advertisement.)
**Revised:** 2026-07-15 (implementation sync: Unix in-process one-shot and
direct-file adapters now install scoped SIGINT mediation before project source
executes. A self-pipe ordinary lane requests id-exact cancellation when an
executing target exists, restores fd 1/2 before bounded broker completion, and
exits 130 without waiting for Hermes; the handler-only fallback performs only
descriptor restoration and `_exit(130)`. Complete observer-cell process/pipe
fixtures exercise real Hermes `while(true){}` without promoting the
ENG-24933-blocked public target. Non-Unix direct execution remains refused and
has no claimed console-control evidence.)
**Revised:** 2026-07-15 (implementation sync: the Unix production editor now
owns raw input independently of a capacity-one static completion producer,
publishes queued/begin/finish identities into the generated interrupt machine,
and has authenticated adapter-level PTY evidence for interrupting a deliberately
wedged completion; public-binary advertisement and Windows ConPTY evidence remain
separate gates.)
**Revised:** 2026-07-15 (implementation sync: package-script and watch
launchers install SIGINT mediation before child spawn, remain alive to reap the
foreground-group child, never duplicate the group-delivered SIGINT, and return
the child's shell-style signal status or the controller's latched 130
after bounded fallback cleanup.)
**Revised:** 2026-07-15 (implementation reconciliation: the cooperative
lifecycle event, production-fresh armed run nonce, root-owned history option,
and published keybinding surface are now bound to their landed adapters and
tests; registry, completion/editor, environment-inventory, and ledger-check
rows retain their explicit residual gaps.)
**Revised:** 2026-07-14 (implementation sync: the startup-environment inventory
distinguishes launcher-time capture of fixed compatibility controls from
post-arming consumption of their digest-bound snapshot projection; principal
environment overlays are runtime data, never a host-environment fallback.)
**Revised:** 2026-07-13 (non-review implementation sync: discharges
`OBL-CONSTANTS-ANNEX` with canonical `session/session-constants.v1.json`, its
strict schema, generated Rust module, and code/model drift gate; records the
already-landed interrupt model artifacts; delivers the runtime half of
`OBL-UNIT-PUBLICATION` with the bounded native work-unit event ABI, exact
executing-target cancellation, and timer `Due{sched}`/Undue publication; no
normative value from the reviewed design changed.)
**Revised:** 2026-07-12 (round-10, terminal. Families **split** — Fable `READY`, Codex `NOT READY` — so `Status` stays
`Draft` (no both-READY on one revision). Codex's single Blocking was the scoped downstream straggler: `idle × CompletionQueued`
resolved two ways (rule 4 → idle prompt → `Orderly`; the "idle, work in flight" row → `Interrupt(130)`). Fixed single-valued
by stating the universal discriminant once — a `CompletionQueued` has not touched the engine, so it is **never running work**:
an interrupt abandons it and falls through; only an `Executing` completion query is running work. Rule 4, the idle row, and the
editing rows now agree, and AC 7 asserts the idle×queued cell single-valued. The four material one-liners: `accepted` made
target-generic (`cancelled` outcome only for evaluations); §1's launcher spellings corrected (top-level positional also
dispatches; `--watch` tested after package-shape, so `ibex --watch dev` runs once); the console route made length-bearing
(embedded NUL cannot truncate the counted payload; the async-enqueue claim narrowed to `print`/Windows-fallback); and
`OBL-UNIT-PUBLICATION` extended to require a due/undue publication seam for `Due{sched}`. Fable's minor seams applied
(AC 11 equality-proof carve-out; the in-flight-vs-running sentence; §8's terminate scoping by mechanism not mode; the
`evaluating` gloss). `OBL-HISTORY-LOCALITY` re-pinned `601cb5213dca` and **flipped to delivered** — current 0023 now names the
equality-proof digest as a by-design crossing. **This is the final revision; per the bounded authorization there is no round 11.**
**Revised:** 2026-07-12 (round-9 dual-model review. §6's latch deletion was correct *inside §6* — both reviewers derived
the trajectories and could not break it — but the deletion had not propagated to every place that assumed the removed
premises, the *downstream-dangling-assumption* tail of a deletion. This closing pass makes it total: §8's status table
now **cites §6's status axis** instead of hand-restating it (the round-8 target-derived bug had survived there); AC 11
asserts the history token's **absence** rather than requiring the token §9 removed; the `CompletionQueued` interval is
split from `Executing` (a queued query has no id, so it raises no request); the phase axis is made **independent** of the
live-unit set so the state space is total; both **no-promise rows** (editing-otherwise and undispatched-submission) are
named as the ≤3-worst-case rows; §3's display-ack becomes a **typed disposition** (`Displayed | Fallback | WriteFailed`,
only `Displayed` acks); `process.exitCode` is made **supervisor-authoritative** (setter mirrors synchronously) and the
async console route reserves its relay counter at enqueue, closing the two feasibility gaps; `K_channel` gets a
provenance; and the ledger re-pins 0023, OIDs the launcher row, and owns the unit-generic-lifecycle and 0024-epoch-vocab
seams. **Revision blocks below are non-normative historical narrative** — the body is the specification.
**Revised:** 2026-07-12 (round-8 dual-model review. The design held a **third** consecutive round — neither reviewer
could break the escape credit or the typed promise — but the typed-promise edit introduced the seam the orchestrator
predicted: a `credit ≻ promise` precedence let a credit-exhausting third press override the status the operator was
promised, and both reviewers independently prescribed the same fix — **delete the latch.** In every reachable state
latch-armed ⟺ promise-live, so the latch and the table's second column were a second copy of the truth, and this round's
Blocking bred there. The latch is now **deleted outright**: the interrupt table is single-column (first-interrupt
actions only), the second interrupt is governed solely by the promise, and precedence is stated on two axes —
*termination* is `cause ≻ promise ≻ credit`, *status* is `latched cause ≻ latched promise ≻ (unreachable) 130`. A cause
latched in the interim supersedes a promise's status but not its termination (a root `process.exit(7)` after an idle
promise still ends the session, with code 7). `Orderly` loses its captured payload — it latches the status *class*, and
an orderly exit's number is `process.exitCode` read at exit. §8's commit is stated as one mechanism (the worker's own
≤2 write-time relay counters) with the duplicate-phrase debris removed and the lifecycle outcome made unit-generic. §1's
topology matrix is rewritten to **current kernel-default** signal semantics (both Ibex and child die of the group SIGINT;
mediated propagation is ledgered as `OBL-LAUNCHER-SIGNALS`), the `ibex run` arg-shape dispatch and its shadowing footgun
are stated, and the watch child correctly carries its own mode's guarantees. §9 removes the purposeless worker token and
names the equality-proof key; §3's display-ack withholds on a fallback render; §12 pins maximum input size; §11 marks its
self-detection anecdote as unverifiable narrative and re-pins 0023.)
**Revised:** 2026-07-12 (round-7 dual-model review. **The bound and notice-truth both held a second consecutive round** —
neither reviewer could falsify either. What remained was revision debris: round-7 text contradicting other round-7 text,
the class of defect the document itself names ("an invariant stated in one place and violated in another reads perfectly
fine in both places"). The **promise is now typed** — `None | Orderly(exitCode) | Interrupt(130)`, latched at notice time —
because a bare bit could not say *which* status a promise implied when the target flipped underneath it; and it now has the
credit's exact **reset rule**, so a stale promise cannot end a session an operator has resumed. **Cause and final
disposition are separated**: the cause is latched once, and a cleanup-loss 141 is a disposition modifier on a *successful*
cause only, never a relatched cause — which resolves the shutdown/141 collision. A **dispatch precedence order** (cause ≻
credit ≻ promise ≻ table) is stated once, so the table cannot be transcribed into a machine that breaks the invariant.
`suspended` is **demoted from request-raising** — the corpus has no delivery mechanism for it, and the credit and promise
carry the escape without one. AC 7's press counts are recomputed (the promise makes the gappy-storm and completion-query
schedules terminate in *two*, not three), and AC 9 tests the idempotent commit on *both* branches. §1 gains a **topology
matrix** for `ibex run` and `--watch`, which are launcher routes, not engine execution; §7 states that **granting
`process:spawn` is a threat-profile transition**; §12 gives each constant its own **overflow behavior** and pins the flush
budget; and §11's digest ledger, having *detected* its own drift, is re-pinned and given git-blob attestations for its
artifact rows and a 0023 row for the locality dependency.)
**Related:** LLP 0021 (capsec effect model — the closed lifecycle and stdio surfaces this
document reopens under scope); LLP 0022 (REPL behavior — the consumer); LLP 0023 (virtual
namespace and identity); LLP 0024 (structured evaluation — cancellation outcomes and the
unstyled display tree this document renders); LLP 0010 (Ibex binary ownership); LLP 0006
(design principles)

## Summary

When Ibex owns a terminal, the **session layer** — not JavaScript, not the engine, not a
native `std::exit` — owns the file descriptors, the rendering, the interrupt, and the
exit. This document specifies that ownership:

- **fd 0 is brokered on every route** in the modes that own a terminal, so no JavaScript
  path can consume the operator's input, wedge the line editor, or close the terminal;
  fd 1 and fd 2 may be written but not closed or aliased; and the control, relay, and
  watchdog handles are a **protected descriptor class** no numeric descriptor API reaches;
- **all runtime-authored output is terminal-safe**, and the renderer's input is a tree that
  *cannot express* an escape sequence, because styling is the session layer's and never the
  producer's;
- **interruption is a state machine over a typed promise and an escape credit** — both arithmetic — generated and
  model-checked rather than hand-written, with an escape that does not depend on the engine
  cooperating — and **every notice it prints is true**;
- **process exit is a cooperative, root-only request** after which no JavaScript runs,
  because the call **parks** rather than returning — which needs no engine mechanism at all;
  and
- **history is project-scoped, hardened, and appended at submission**, under a
  supervisor-owned identity that is *not* a virtual-filesystem identity.

The central architectural question — whether the engine can be interrupted in place or must
run in a worker under a supervisor that owns the PTY — is §7's subject. §7 states the
invariants normatively, names the supervisor as the specified realization, and gives the
in-process alternative a conformance gate rather than a presumption.

## Motivation

The armed runtime closes process termination, shared exit-status mutation, and raw stdio as
capability surfaces; the interactive CLI must nevertheless terminate, set an exit code, and
read a terminal. The gap between those two facts is where a terminal session goes wrong, and
today it goes wrong in five distinct ways.

The line editor owns fd 0, but `process.stdin`, `fs.readSync(0)`, and the raw
`__exactStdinRead` bridge all reach the same descriptor — so prompt or package code can eat
the operator's next command. Value display arrives at the Rust layer as one pre-colored
string, so the terminal-injection escaping that ought to protect the operator cannot
distinguish the runtime's own styling from an attacker's escape sequence embedded in a value.

Interruption has **no controlled path at all**. There is no `SIGINT` handler on the REPL
path; `Ctrl+C` is a line-editor keystroke and nothing more. While an evaluation runs the
editor is not reading, the terminal is in cooked mode, and `Ctrl+C` reaches the process's
default disposition — so an accidental `while(true){}` is escaped by *killing the process
outright*, losing the terminal state and the session's unsaved history. While a background
callback runs, the first `Ctrl+C` is swallowed as a keystroke the busy engine never services.
And a member-completion query evaluates its base expression through `Function(…)` on the
engine thread under a budget that is a `recv_timeout` on the *editor* thread — it releases
the editor, never the engine, so a completion that does not return wedges the session as
thoroughly as a runaway loop and with less warning.

`process.exit()` reaches a native `std::exit` that bypasses terminal restoration, history
saving, and every principal check — a package can terminate the operator's session. And
history is a single machine-global file, written at exit into a directory that falls back to
the current working directory, so secrets pasted while working on one project are recalled
while working on another — and are lost entirely if the session does not end cleanly.

Each is a case of the session layer *not actually owning* something it is responsible for.

## Scope

This document specifies terminal and process-lifecycle ownership. Its sections bind different
modes, and §1's mode table says exactly which. Terminal *ownership* (fd 0, the editor, the
interrupt machine, history) binds only the modes that own a terminal; **rendering, color,
output brokering, and lifecycle bind every armed execution mode**, including ordinary file
execution — a package must not be able to inject an escape sequence into a stack trace,
silently lose a program's stdout, or terminate the process there either.

It does not specify the interactive product surface (LLP 0022), the path namespace and
identity model (LLP 0023), or the evaluation seam (LLP 0024) — though it triggers the
cancellation requests that LLP 0024 resolves and renders the tree that LLP 0024 produces.

## Design

### 1. Modes, descriptors, and topology

**Input mode is what the input *is*; presentation topology is what the terminal *is*.** They
are selected separately, and conflating them is how a spec promises a line editor to a session
with no terminal to draw on.

Mode is selected by stdin (LLP 0022). A **session mode** is one in which the session layer owns
fd 0 — the first three rows.

| Mode | Selected by | fd 0 | Editor |
| --- | --- | --- | --- |
| **interactive** | `ibex` / `ibex repl`, stdin is a TTY | **session-owned**: JavaScript sees the EOF view | yes, if a TTY output exists |
| **plain transcript** | `ibex repl`, stdin is not a TTY | **session-owned**: consumed as session input | no |
| **program** | `ibex` with no file, stdin is not a TTY | **session-owned**: consumed as source at startup | no |
| **one-shot** | `-e`, `-p`, `ibex eval` | **not session-owned**: the ordinary typed `stdio:read` surface | no |
| **file execution** | `ibex <file>`, `ibex run` | **not session-owned**: the ordinary typed `stdio:read` surface | no |

The last two rows are a decision, not an omission: the session layer owns no editor there and
holds no session input, so there is nothing for JavaScript to steal — `echo data | ibex -e '…'`
must keep working. **If a one-shot surface ever grows an editor, it acquires this section's fd-0
rule with it.**

In a session mode, fd-0 ownership is a **native session fact**. Every JavaScript-originated
operation that could reach fd 0 — `process.stdin`; `fs.read`, `readSync`, `readv`; a `FileHandle`
on it; tty queries; `close`; `dup`; poll/select; retained aliases; any raw native bridge —
observes the specified view **before the real descriptor is touched**, for root and package
callers alike.

**The view is pinned per route, in a generated table.** Every route returns the **EOF view**:
`process.stdin` is an empty, immediately-ended, non-TTY stream; `readSync(0)`/`readv` return 0
bytes; a callback or promise read completes with 0 bytes rather than rejecting; `close(0)` is a
**silent no-op**. A typed denial is used only where Node itself would throw. The table is a
projection of the surface registry joined to every stdio route and alias, so a new one cannot
escape it.

`process.stdin.isTTY` is therefore **`false` at an interactive prompt**, where Node reports
`true` — a deliberate divergence and the honest one: JavaScript genuinely cannot read that
terminal, and a library that believes it can will hang. It is a fact of the EOF view, not a
`stdio:query` decision, so the fd-0 branch owns it and there is exactly one classification.

**fd 1 and fd 2 are writable but not owned by JavaScript.** Writes are brokered (§3). `close(1)`
and `close(2)` are silent no-ops; `dup2` onto 0/1/2 and reopening them are refused with a typed
denial. Today `closeSync` reaches the real descriptor with no branch for 0, 1, or 2.

**The control, relay, and watchdog handles are a protected descriptor class.** They are not merely
unlisted: no numeric descriptor API — `fs`, `FileHandle`, `dup`, `close`, `readv`, or a raw bridge
— can name or operate on them, for **any** principal. Native policy today permits root and runtime
principals to operate on unknown numeric descriptors, which would make the session's control channel
reachable by guessing an integer. Obscurity is not a boundary.

**Terminal facts** about stdout and stderr — `isTTY`, dimensions — are the typed `stdio:query`
surface, with the registry's classification and per-principal rules. A denied query reports
`isTTY: false` rather than throwing.

**Presentation topology** (interactive mode only) selects where the editor draws:

| stdout | stderr | Editor target |
| --- | --- | --- |
| TTY | any | **stdout** — prompt, banner, editor control, and results to stdout |
| not a TTY | TTY | **stderr** — prompt, banner, editor control; **results to stdout** |
| not a TTY | not a TTY | **no editor** — interactive *semantics*, transcript *presentation* |

The controlling descriptor for editing is the first of **stdout, then stderr**, that is a TTY. The
third row is not a fourth mode: the session keeps interactive semantics and only its presentation
degrades.

Sections bind modes as follows:

| Mode | §3 render + broker | §4 color | §5 restore | §6 interrupt | §8 lifecycle | §9 history |
| --- | --- | --- | --- | --- | --- | --- |
| interactive, with editor | yes | predicate | yes | the §6 machine | yes | yes |
| interactive, no editor | yes | off | n/a | terminate | yes | no |
| plain transcript | yes | off | n/a | terminate | yes | no |
| program | yes | predicate | n/a | terminate | yes | no |
| one-shot | yes | predicate | n/a | terminate | yes | no |
| file execution | yes | predicate | n/a | terminate | yes | no |

**"Terminate"** means there is no prompt to return to — so there is no promise or credit to escalate through — and it has **two
tiers** that must not be conflated:

- the **ordinary path** — a single interrupt requests cancellation (id-exact), the terminal is
  restored, the broker flushes under its budget, and the process exits **130**. It **does not wait
  on the engine**: a one-shot running `while(true){}` must die on `Ctrl+C`, not hang;
- the **handler-only fallback**, when the ordinary path cannot run (the process is inside a fault
  handler): restore the terminal and `_exit(130)`. A broker flush is **not** async-signal-safe, so
  it is forfeited here, and that forfeiture is silent — the one place §3's accounting rule cannot
  apply, stated rather than hidden.

Non-session modes run **in-process** in v1 (they own no PTY); their escape needs no engine
cooperation and no supervisor.

**`ibex run` is an argument-shape dispatch, and some of its cases are not engine execution.** An argument that is an
existing path, is path-shaped, or has a JS/TS extension runs **in-process as file execution** (the mode-table row above
governs it); only a **bare name without a JS/TS extension** (`js|cjs|mjs|ts|tsx|jsx|mts|cts` force file execution) that names no existing file dispatches a **package script** — **from the top-level positional (`ibex dev`) as well as `ibex run dev`**, and package-shape is tested **before** `--watch`, so **`ibex --watch dev` runs the package script once** rather than entering the watch controller — a shell child that
inherits fds 0/1/2. A deliberate consequence, which this document owns rather than hides: an existing extensionless file
named `build` shadows a same-named package script — the *opposite* of the npm convention, and a real footgun worth
stating. `--watch` is a **controller** that repeatedly spawns an `ibex` child with an inherited terminal.

For the child-launcher cases the terminate tier's "request cancellation (id-exact)" wording is meaningless — there is no
engine in this process to cancel. Package-script and watch launchers now install their SIGINT listener **before** child
spawn. Ibex and its child remain in the same foreground process group, so a terminal `Ctrl+C` reaches both, but the
launcher holds the signal while the child retains its exec-time default disposition. Ibex then reaps the child and
turns its real signal disposition into the shell-style `128 + signal` status. It does **not** explicitly forward the
same SIGINT: foreground-group delivery already reached the child, and a second delivery could turn an application's
first graceful interrupt into its forced-interrupt path. The launcher allows two seconds for the child's real status;
if the signal was caught in the install-before-spawn interval, or the child remains alive, it terminates and reaps the
child without fabricating another SIGINT and returns the controller's 130 cause. The watch controller applies the same
two-second grace to its direct-execution child before its existing TERM/kill fallback, so descriptor restoration and
bounded broker close are not preempted by an immediate SIGTERM. Unix one-shot and direct-file engine
execution separately install the terminate tier only for the scoped lifetime of their authenticated execution adapter;
the prior disposition is restored before that adapter returns, so launcher and unrelated commands do not inherit it.
Each CLI process admits at most one launcher bridge. Teardown restores the prior disposition and joins the ordinary
consumer but retains the CLOEXEC pipe descriptors and global claim until process exit; POSIX disposition restoration
cannot join a handler already entered on another thread, so descriptor reuse or sequential bridge installation would
otherwise let that stale handler write into an unrelated fd or notify a later launcher scope.
The in-process direct-execution bridge follows the same one-shot rule. Its atomic `ACTIVE → FINALIZING` transition
prevents a delayed handler from claiming an already-settled execution; its prior SIGINT action is restored, while its
claim and CLOEXEC pipe remain process-lifetime so neither descriptor reuse nor a later direct-execution adapter can be
mistaken for the original scope. A second direct adapter in the same process is refused.
The matrix separates those two delivered realizations:

| Topology | Terminal owner | Broker | Interrupt | Exit status |
| --- | --- | --- | --- | --- |
| **direct one-shot / file execution** (`-e`, `-p`, `ibex eval`, `ibex <file>`, or `ibex run <file>`) | this process | in-process broker (§3) | **delivered on Unix**: a scoped handler claims one SIGINT and wakes an ordinary self-pipe lane; that lane requests cancellation only for the exact executing target, restores fd 1/2, closes the broker under its budget, and exits 130 without waiting for the engine. If the ordinary lane cannot be woken, the handler restores fd 1/2 and `_exit(130)` directly. Non-Unix direct execution remains refused rather than advertising unverified console-control behavior | one-shot / file-execution / lifecycle codes normally; **130** for SIGINT |
| **package-script execution** (`ibex run <bare-name>`) | the **shell child** (inherited fds) | none — the child writes the terminal directly | the group signal reaches both processes; the launcher holds it, waits, and reaps while the shell child handles or dies from exactly one SIGINT; the pre-spawn/still-live fallback terminates without a duplicate SIGINT | the child's explicit code, or **130** for the controller's SIGINT |
| **watch controller** (`--watch`) | the controller, between child runs | none | the controller holds group SIGINT, gives the already-signaled child two seconds for its own cleanup, then uses TERM/kill only as fallback; it reaps and exits without restarting or duplicating SIGINT | **130** for SIGINT; watcher-channel close remains orderly |
| **watch child** (each run) | the child (inherited fds) | **its own** file-execution broker | the group signal reaches the child under its own mode's disposition while the controller survives to reap it | its own mode's codes; controller returns 130 for the initiating SIGINT |

The **watch child carries its own mode's guarantees** — it *is* an Ibex engine runtime — so only the *controller* and the
*package-script shell child* are unarmed launcher routes carrying none of §§3–9. `launcher_signal_mediation` exercises
both launcher spellings in a private process group: the package parent survives the group SIGINT, observes exactly one
delivery, reaps its shell child, and exits 130; the watch controller's pre-spawn readiness boundary likewise survives
and exits 130. `watch_group_interrupt_grace_does_not_preempt_child_cleanup_with_sigterm` separately drives a real shell
child whose SIGINT trap publishes begin/finished cleanup markers and whose SIGTERM trap publishes a failure marker; it
proves the watch helper reaps code 130 after the grace path without sending TERM. That split is deliberate: the checked
production target-advertisement set is empty under ENG-24933, so a public watch child cannot honestly publish a
post-arming readiness marker yet. This discharges `OBL-LAUNCHER-SIGNALS`. The separate observer-only direct-execution
process fixture covers both one-shot and file adapters with real Hermes `while(true){}` and a real SIGINT, but does not
create or promote that blocked public target advertisement.

### 2. Startup configuration is captured before arming

Here, **startup configuration** means the fixed presentation and compatibility
inputs captured for the trusted bootstrap; it does not mean every host fact an
effectful runtime operation may later read.

Terminal presentation configuration — the prompt override (`IBEX_REPL_PROMPT`, legacy
`EX_REPL_PROMPT`), the color predicate's inputs (`NO_COLOR`, `CLICOLOR_FORCE`, `TERM`) and the
per-stream decision they produce, the history mode and location, the descriptor topology, and the
terminal's initial mode and capabilities — is **terminal-operator state** owned by the Rust CLI and
read into an **immutable startup configuration before the armed host is published for project
execution**. Those fixed presentation inputs have no later host-environment fallback, cannot be
changed through a principal overlay, and are never readable from JavaScript. This is not a claim
that every host fact is frozen: the trusted engine-bootstrap interval and effectful runtime
operations have the separately enumerated reads below.

**This document owns the post-arming environment inventory** as an artifact — the one generated list
of every variable the runtime reads and the stage at which it is read — so that an un-dispositioned
variable fails the build. It does not own every *rule* in it: the evaluation rows are LLP 0024's, and
LLP 0024 **retires** the await-unwrap timeout rather than capturing it pre-arming. This document
contributes the presentation rows.

The canonical artifact is `capsec/registry/runtime-environment-inventory.json`, generated by
`packages/ibex-devtools/src/scripts/generate-runtime-environment-inventory.mjs` and validated against
`capsec/schema/runtime-environment-inventory.schema.json`. Each exact source occurrence records its
accessor, direction, lexical scope, source evidence, and one of the closed stages
`launcher-pre-arm-read`, `armed-bootstrap-host-read`, `post-arm-host-read`,
`principal-overlay-read`, `trusted-bootstrap-host-write`, or `child-environment-construction`.
Discovery of a new static or dynamic occurrence, movement to a different scope, disappearance of a
reviewed occurrence, or a stage not admitted by the reviewed row fails the generator check. Every
`post-arm-host-read` additionally carries a typed disposition and source-anchored evidence; evidence
records why the occurrence is effect-gated, armed-unreachable, production-unreachable, or a
test-only effect hook, and is not itself permission to consult the host environment.

`armed-bootstrap-host-read` names the trusted bootstrap window after the authenticated armed
snapshot identity has been installed but **before package code is eligible to execute**. It is not
an ambient session read and does not admit a later fallback. `post-arm-host-read` is reserved for an
occurrence reachable during session operation: the production reads in that class are either behind
the typed effect decision for the operation (for example DNS resolution, storage/user information,
or child-process environment/PATH construction) or proved unreachable from an armed caller; the
remaining occurrences are explicit test-only effect hooks. The inventory records that distinction
per exact occurrence instead of deriving permission from a stage label.

The current checked projection has **156 rows / 338 exact occurrences**:
96 armed-bootstrap reads, 25 launcher reads, 103 principal-overlay reads, nine
trusted-bootstrap writes, 73 child-environment construction occurrences, and
32 post-arm host-read source sites. Those post-arm sites are dispositioned as
16 effect-gated reads, ten armed-unreachable reads, and six test-only hooks.
Child construction is modeled explicitly: each Rust `Command` starts with a
dynamic default-inheritance occurrence, while `env_clear`, exact `env` writes,
and removals record how the child is closed or rebuilt. The runtime JS tool,
policy, module-transpile, and Hermes compiler children clear inheritance and
receive only their fixed private directories, locale/timezone, and narrowly
reviewed test barriers. Transform-engine selection is captured per loader
before armed publication. The armed transition then permanently selects fresh
in-memory lowering; it never consults the diagnostic transpile cache or its
temporary fallback, so an earlier diagnostic loader cannot seed armed output,
path, or tooling state.

The inventory must distinguish a **source read** from a **bootstrap use**. An
admitted fixed compatibility control is read by the trusted launcher before
arming, normalized into the closed `bootstrapCompatibilityModes` set, and bound
by the final snapshot digest. Native and JavaScript bootstrap thereafter consume
only that authenticated projection; they do not read the launcher environment
again, and the temporary projection carrier is sealed before project code. An
inventory row that labels a compatibility-named environment variable as a
permitted post-arming read is therefore wrong even if it produces the same
value in a test process.

Armed `process.env` is not startup configuration. Its snapshot base is
explicitly empty, and later values live only in runtime-scoped per-principal
overlays reached through exact-name typed decisions. Reading, enumerating, or
mutating such an overlay is not consultation of the host environment and cannot
change a captured bootstrap mode. In particular, `Bun` is absent unless the
snapshot opted in before arming; if enabled it is the same object as `Exact`,
not a facade that can be switched by changing an overlay entry.

**Live terminal facts are not startup configuration.** Window dimensions change under `SIGWINCH` and
cannot be frozen; the terminal's mode changes as the session enters and leaves raw mode. These are
live session state, tracked by the session layer, never re-derived from the environment, and exposed
to JavaScript only through `stdio:query`.

### 3. Rendering, terminal safety, and the output broker

**All runtime-authored output is terminal-safe.** Whatever the session layer renders from runtime
values — displayed values, error names, messages, stack frames, source excerpts, asynchronous
reports, completion candidates, hints, recalled history — is escaped before it reaches the terminal:

> **all C0 controls, DEL (0x7F), and all C1 code points U+0080–U+009F, in any encoding (single-byte
> or UTF-8), in addition to `ESC`.**

Naming only CSI and OSC is insufficient: DCS, SOS, PM, APC, and ST are equally honored by terminals
that accept C1s, and in a UTF-8 stream the dangerous artifact is the *code point*, not a "single-byte
introducer". Unicode bidirectional-override controls (U+202A–U+202E, U+2066–U+2069) and the
line/paragraph separators (U+2028/U+2029) are escaped in **all** runtime-authored output, displayed
values included — a spoofable string is as likely to arrive in a filename as in a diagnostic.

**The prompt override is escaped as data too.** An earlier draft called it "trusted configuration,
rendered verbatim." That was wrong: `IBEX_REPL_PROMPT` comes from the **environment**, and the
environment is not the operator — a hostile `.envrc`, a compromised parent process, or a poisoned CI
variable would have had the one string the renderer waved through. A styled prompt is available
through the trusted style vocabulary, not through raw bytes.

**Exactly one object crosses the boundary, and it carries no styling.** LLP 0024 owns that schema and
this document renders it: a node carries a **kind**, an **untrusted payload** (raw, unescaped, for the
renderer to escape), and optional children — *and never styling*. The session layer derives trusted
styling from node **kinds**.

That is the trust boundary. The precise invariant — an earlier draft overstated it — is:

> A producer cannot emit an unescaped byte, cannot emit a terminal-control byte, and cannot select a
> byte in the **session-decoration** style vocabulary. It *can* influence which **kind-derived** style
> the renderer applies, by choosing a kind.

The kind→style map's codomain is therefore **disjoint from session decoration and control styling**,
so a hostile tree can render as a value but can never cosplay as session UI. A payload may contain any
code point, including `ESC` — it is data, and the renderer escapes it as data.

The tree is versioned and serializable, and the renderer treats it as **hostile input**: payloads are
length-bearing and may be invalid UTF-8 (rendered with the replacement policy, never passed through
raw); unknown kinds render opaquely; depth, breadth, and payload length are bounded (§12) with an
explicit truncation marker; a malformed or unknown-version tree yields a safe diagnostic, never raw
bytes.

`console.*` output from running code is **program output**, routed to its stream unmodified.

**One sequenced output broker.** All output passes through a **single broker that is the only writer to
a session-owned terminal**. Each event carries an **author** (session or program), a destination, a kind,
a payload, and a **sequence number drawn from the same session-wide sequence LLP 0024 defines** for
evaluation outcomes and asynchronous failures — one domain, not two.

- **Order is preserved per destination.** When stdout and stderr resolve to the same destination, one
  total order holds across both, including the program's own cross-stream write order — and the
  supervisor **constructs** that topology rather than detecting it: when both resolve to the session
  terminal, the worker's descriptors 1 and 2 are duplicates of **one open file description**, so the
  kernel orders them. There is no portable "same destination" predicate to detect, so the design does
  not depend on one.
- **Barriers carry a byte cutoff, and its scope is stated honestly.** Raw fd bytes carry no author, sequence,
  or barrier, so a control message can otherwise overtake relay bytes the supervisor has not yet read.
  - For **worker-authored** output, every fd-1/fd-2 write traverses a runtime write site, so the counter is
    advanced when bytes are **accepted for write** and the barrier snapshots it. **This includes the asynchronous
    console/`print` route** — today the `print`/native-console-fallback path enqueues to a separate writer thread (the
    *mandatory* path on Windows; the default non-Windows console routes through `process.stdout/stderr.write`), so
    `console.log("bye"); process.exit(0)` would otherwise lose `bye`: therefore every armed console/print/fallback route
    must **reserve its counted relay slot synchronously before returning to JavaScript**, advancing the counter at
    enqueue over a **length-bearing byte payload** — not a NUL-terminated C string, which an embedded NUL would truncate
    before it could be counted — so the lifecycle record's counter already covers enqueued-but-unwritten output and the
    supervisor drains to it before disposal. "Accepted for write" means **queue-accepted or fd-written**, one vocabulary. Counter reservation, the write,
    and the snapshot are serialized, so a snapshot never names a byte that was never issued, and partial writes are
    retried rather than double-counted. When both descriptors resolve to the session terminal they are duplicates of
    **one** open file description and therefore **one** relay with **one** counter; when they resolve to different
    destinations they are two relays with two counters. The earlier draft asserted both at once.
  - For a **child's** output there is no such write site — its bytes go to its own pipe — so no counter can be
    advanced at write time and no worker-created barrier can snapshot bytes still sitting unread in a kernel
    buffer. The guarantee is therefore the **observable** one, not the unobservable one: **child output is
    ordered as of relay acceptance — the bytes the supervisor had received when the barrier arrived — not as of
    the child's `write(2)`.** A child byte written before the barrier but not yet read may land after the result.
    This is a real weakening, and stating it is better than promising an order no one can observe without
    freezing the child.
- **The session layer assigns sequence numbers at receipt.** An earlier draft had the worker draw ranges from
  the supervisor; **LLP 0024 is right and this document was wrong** — a worker that mints its own sequence numbers
  can forge ordering, and under §7 the worker is exactly the component that may be hostile. Numbers are assigned
  where the events are received, which also makes a **worker-death event** naturally sequenceable after the worker
  can no longer participate.
- **The cutoff machinery is a supervisor-mode mechanism.** In-process modes have no relay: the broker is the sole
  writer in the same address space, and §1's fd-1/2 brokerage is what makes that true — a raw `write(1)` that
  reached the real descriptor would falsify it. §3's guarantees bind every mode; only their *realization* differs.
- **Child stdio modes are distinguished.** A child's `pipe` output belongs to **JavaScript**, not to the terminal
  broker, and is not brokered at all. Only a child that would otherwise **inherit** the session's terminal is
  relayed (§3's non-inheritance rule). A **detached** child is outside the session's ordering and lifetime guarantees — but *not* exempt from the
  non-inheritance rule: a `detached` child that also requested `inherit` of the session's terminal in a session mode is
  **refused that inheritance** (its terminal fds are relayed or null), because a live detached child writing the real
  terminal beside the broker would falsify §7's single-writer invariant. "Outside ownership" scopes to ordering and
  lifetime, never to descriptor inheritance.
- **Children do not inherit the session's terminal descriptors.** A spawned child that inherited fd 1/2
  would write bytes the worker's counter never observes, silently voiding every barrier. In session
  modes a child's stdout and stderr are **relayed** and framed as program output. The consequence is
  recorded: **a child cannot take over the terminal at the prompt in v1** — no full-screen child
  programs — and OQ 10 asks what a deliberate PTY hand-off would look like. In non-session modes
  inheritance is permitted and no barrier is promised, because there is no prompt to order around.
- **Display acknowledgement** — which LLP 0024 uses to update `$_`. A result event's barrier completes with a
  **typed disposition — `Displayed | Fallback | WriteFailed`** — and **only `Displayed` emits the acknowledgement.**
  `Fallback` (a malformed, unknown-version, or over-size tree that rendered a safe diagnostic) and `WriteFailed`
  (the broker accepted but could not write) both complete the barrier but raise **no** display-ack: a value that
  was never *successfully displayed* must not become `$_`, which stays at its prior value (0024's "last successfully
  displayed value"). It is not acked at enqueue.
- **A stalled destination cannot block another**, and a **reserved control lane** carries interrupt
  notices, cancellation and lifecycle diagnostics, and restoration bytes. It is never queued behind
  program output — that is why the second-interrupt notice prints even when stdout is a stalled pipe.
  Under §7 it is an **authenticated channel** (§7's control record), never bytes multiplexed into the
  program's stream where a program that printed one would be indistinguishable from the real thing.
- **Program output is never *silently* dropped while the session is live, in any execution mode.** This
  supersedes the console queue's drop-under-backpressure policy for the CLI. That policy correctly applies
  LLP 0006's *degrade diagnostics, never the caller* to the case it was written for — an embedded,
  long-lived host whose main thread must not block on a stalled console — and remains correct there. In a
  CLI pipeline, discarding a program's stdout is not degradation; it is data loss.
  **Forced termination is the one exception, and it is accounted:** a permanently stalled destination makes
  finite termination and lossless delivery mutually exclusive, so when the flush budget expires the broker
  abandons the remainder and **reports what was lost** — bytes per relay for program output, framed events
  for session output — on a still-usable destination. When *every* destination is stalled the report has
  nowhere to land; the exit status then carries it (§8's broken-pipe status), because a silent loss with a
  successful exit status would be the worst of both.
- A synchronous write that succeeds means **the session accepted the bytes, not that the destination did.**
  A later destination failure cannot retroactively fail the synchronous call; it ends the session for a
  session-authored write and raises an ordinary stream error for a program-authored one, as in Node.
- **Worker death is a broker event**: the supervisor synthesizes a sequence-numbered engine-fault event, so
  transcripts see the death in order rather than inferring it from a truncated stream.

### 4. Color

One predicate governs **session-authored** styling, per destination stream:

| Condition (in order) | Colors |
| --- | --- |
| plain transcript mode, or interactive with no editor | off, unconditionally |
| `NO_COLOR` set | off |
| `CLICOLOR_FORCE` set (non-`0`) | on |
| stream is not a TTY, or `TERM=dumb` | off |
| otherwise | on |

Transcript output is unconditionally free of **session-authored** ANSI. It is *not* claimed to be free of
**all** ANSI: `process.stdout.write("\x1b[31m")` from a program emits exactly those bytes, because §3 does
not modify program output. The narrower claim is the true one, and the one fixtures can assert.

**Editor control and screen clearing are functions of TTY presence, not of the color predicate**: with
`NO_COLOR` on a real terminal, the editor still redraws and clear-screen still clears.

### 5. Terminal presentation and restoration

**Editor input and session-authored rendering are UTF-8**; malformed input must not crash the session. This is
*not* a claim about program output, which stays **byte-exact** (§3) — a program may write any bytes it likes,
and a display-tree payload may be invalid UTF-8 and is rendered under the replacement policy. Bracketed paste is
supported so pasted text enters the buffer **inertly**. Window resize must not corrupt the edit buffer.
Emacs-style editing and reverse history search are v1 behavior. OSC 133 prompt marks are permitted under the TTY
predicate.

**The editor is non-blocking on Unix.** §6 requires that a `Ctrl+C` byte be consumed and acted on *while a completion
query is in flight* — the operator's `foo.` preserved and redrawn. The production adapter therefore keeps one
dedicated raw-input reader independent of one dedicated completion producer. Ordinary input crosses a fixed-size,
capacity-`MAX_INPUT_BYTES` byte lane; interrupt, EOF, and error events use an independent capacity-8 priority lane.
A full ordinary lane is accumulated backlog, not evidence that the current physical submission exceeded
`MAX_INPUT_BYTES`. The raw scanner diagnoses **backlog exhaustion**, discards queued/current ordinary input through the
next CR/LF outside bracketed paste, and continues recognizing `Ctrl+C`/`Ctrl+Z` on the independent control path; no
truncated suffix can execute. The editor consumer separately applies the size limit to each decoded submission and
rejects that whole record through its next CR/LF outside bracketed paste. The editor never waits inside a completion
callback. Completion receives only an immutable,
authority-free snapshot of parser-tracked bindings plus generated/static manifests; it cannot evaluate JavaScript,
import, inspect the filesystem, or reach `Host`. Its job lane and result lane each have capacity one, and only one
producer thread exists per interactive session. A full stale job slot makes a later Tab advisory no-op, not a session
failure.

Every query carries a monotonic request id and the exact input generation. The producer publishes `Began` with a
distinct target id and waits for the session's acknowledgement before it computes; `Finished` is adopted only if all
three identities still match. Buffer mutation, submission, or interrupt invalidates the generation, so an abandoned
result can never edit later input. The raw reader continues consuming bytes throughout. This discharges the Unix
feasibility obligation; it does not manufacture product-surface advertisement or Windows console evidence.

**The session holds the terminal in raw mode with `ISIG` off for as long as it owns it — including while
the engine is busy** (on Windows: ConPTY with `ENABLE_PROCESSED_INPUT` cleared). §6's byte-level interrupt
promise depends on it: an interrupt must arrive as a byte on a descriptor the session owns, not as a signal
the kernel may coalesce.

**A consequence that must be specified, not discovered: with `ISIG` off, typed `Ctrl+Z` is a byte, not a
kernel `SIGTSTP`.** Interactive suspension therefore does not happen by itself. `Ctrl+Z` is a **keybinding**
(§below) whose action is the suspend transaction of §7.

**Keybindings are a manifest** — generated, like LLP 0022's command table, so `.help` cannot drift from what
the editor accepts. It lives in the CLI surface manifest (LLP 0010), beside the command table, and it carries
`Ctrl+C`, `Ctrl+D`, `Ctrl+R`, and `Ctrl+Z`.

**The terminal is restored on every ordinary process-controlled exit path** — cooked mode, cursor visible,
alternate screen exited, bracketed paste off — for orderly exit, EOF, fatal error, cooperative exit, catchable
panic, every signal in §8's status table, and suspension. On Windows, restoration reinstates the console mode
flags and VT state captured at startup.

**Restoration precedes every potentially blocking step.** The order is: restore, then flush the broker under
budget, then release resources. A cleanup step that can block must never sit between the decision to exit and
the restoration. History needs no exit-path step at all (§9).

The terminal session's SIGINT/SIGTSTP/SIGWINCH bridge is likewise **one-shot per CLI process**. After the final
cooked-mode restore it returns the inherited dispositions and joins the coordinator, but retains its CLOEXEC
self-pipe and global claim until process exit. This makes a handler already entered on another runtime thread
harmless instead of allowing it to write through a reused descriptor or into a later session. A sequential
session capture in the same process is refused; test fixtures that need independent captures use isolated child
processes.

The **handler-only fatal fallback** guarantees cooked termios and `_exit` using only async-signal-safe
operations. It deliberately omits cursor/SGR writes: although `write` is async-signal-safe, a blocking,
flow-controlled TTY can still prevent the required `_exit`. Cosmetic restoration therefore belongs to the
ordinary supervisor path; a handler-only fault may leave presentation cosmetics unrestored.

**Fault classes.** Restoration is guaranteed for faults the process can still observe — a handler runs
(`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, `SIGABRT`) — and *not* for `SIGKILL`, power loss, or a stack too
corrupted to run a handler. Those are outside any in-process guarantee; covering them is the supervisor's
alone (§7).

### 6. Interruption and cancellation

**This machine is generated, not written.** *Five* successive hand-written versions of this section were each
falsified on review — by a stale latch, by an unbounded `setInterval` turnover storm, by typed-ahead, by a class-flip
that reset escalation, and by a `credit ≻ promise` precedence that let a credit press override a promised status — and
each time the prose looked right to its author. The transition relation is therefore **owner-authored data**: states, an
event alphabet, and transitions, from which the table below, the implementation's dispatch, and AC 7's exhaustive
trajectory enumeration are all **generated**, and over which the invariants are **model-checked** against an adversarial
scheduler. The owner-authored source is `session/interrupt-machine.v1.json`; its deterministic generator and checker are
`packages/ibex-devtools/src/scripts/generate-interrupt-machine.mjs`, and the Rust dispatch plus checked trajectories live
under `vendored-generated/`. The tables below are the human-readable projection of that checked relation
(`OBL-INTERRUPT-MODEL`).

This is the same reasoning that already governs the fd-0 route table, the command table, and the path observables:
a security-relevant table that is maintained by hand drifts. The interrupt machine was the last one still written in
prose, and it was wrong **every single time it was reviewed**. A future reader tempted to "simplify" it should read that
sentence twice — and should note that four of the five falsifications were *added* by a well-meaning simplification.

**Safety and ergonomics are separated, and that separation — carried by two fields, not three — is the whole design.**
The recurring failure was a *third* mechanism, a latch, asked to decide *which* second interrupt terminates early on top
of the credit and the promise; every change of target class destroyed its job while the prose kept promising it. The
latch is **deleted**. What remains is exactly two arithmetic fields, neither of which consults the target when the
terminating press arrives:

- the **typed promise** decides whether the *second* consecutive interrupt terminates, and with what status;
- the **escape credit** guarantees the ≤3 bound unconditionally, as a pure backstop.

**State.** The declared state must be sufficient to determine every transition — an earlier draft's four-tuple was not,
and the same tuple could select different targets. In full:

`(editor phase, buffer + buffer generation, typed-ahead bytes with their prompt-liveness provenance, pending submission,
live-unit set, in-flight completion query + its id, pending cancellation requests, escape credit, **typed promise**
`None | Orderly | Interrupt(130)`, latched termination cause)`.

**There is no latch.** Four consecutive versions of this section carried a latch to decide *which* second interrupt
terminates early, and it bred a new contradiction every round — most recently a `credit ≻ promise` precedence that let a
credit-exhausting third press override the status the operator was promised. The latch is now **deleted outright**,
because in every reachable state the promise already does its whole job: *latch-armed ⟺ promise-live*, so the latch was a
second copy of the truth, and the document's own thesis is that a second copy of the truth is where the next
contradiction breeds. The **promise** governs whether the *second* interrupt terminates; the **credit** is the
unconditional backstop. That is the entire machine.

- **The live-unit set** is discriminated so target selection is total: **`Executing{id}`**, **`Suspended{id}`** (awaiting),
  **`Due{sched}`** (ready but not begun — a scheduling identity `sched`, *not* a cancellation target id, so two due timers are distinct set members and the machine can tell after one begins whether another remains due), and **`CompletionQueued{request_id}`** (a completion query dispatched
  but not yet begun on its bounded producer — a request identity exists, but no executing target identity does). Work is **in
  flight** if the set is non-empty. A **scheduled-but-not-yet-due** timer is **not** in the set — LLP 0024 draws the same
  line, and a session holding a one-second repeating timer is quiescent between ticks, so `Ctrl+C Ctrl+C` at its prompt is
  an orderly exit, not an interrupt termination.
- **`Executing` versus `CompletionQueued` is the universal running-work discriminant, in every phase.** A completion query
  that has not begun on its producer (`CompletionQueued`) has touched nothing that can wedge, so an interrupt
  **abandons it** (invalidating it by buffer generation) and then proceeds **as if it were absent** — falling through to any
  `Executing`/`Suspended`/`Due` work, else to the phase's non-work target. Only an **`Executing`** completion query counts
  as **running work** (it can wedge the engine, so it needs the escape). This one rule makes target-selection rule 4, the
  "idle, work in flight" row, and the editing rows agree everywhere: an idle prompt whose only live unit is a
  `CompletionQueued` (a global Tab-complete at an empty prompt) abandons it and takes the **idle-prompt** path — an orderly
  exit — never `Interrupt(130)`. There is no `idle × CompletionQueued` fork.
- **Editor phase** — the *buffer's* state, an axis **independent of** the live-unit set (the table's domain is phase × live-unit set): `idle` (empty buffer at a live prompt), `editing` (non-empty buffer), `continuation` (multiline pending), `evaluating` (a submission accepted and not yet resolved to a prompt — carried by the pending-submission tuple component, *not* by the live-unit set, so it does not reuse "in flight"), `shutdown`. An empty buffer with a background callback executing is `idle` with a non-empty live-unit set — a cell the table's "idle, work in flight" row covers.
- **Editor input** means a byte **typed while a prompt was live that is *not* bound to interrupt.** The `Ctrl+C` byte is
  never editor input — reading it as such would cap the credit at 1 forever. Other keybinding bytes that do not edit the
  buffer (`Ctrl+Z`, `Ctrl+R`, Tab) **do** count as editor input and clear the credit and promise: they are the operator
  interacting at a live prompt, which is exactly what the reset is for. Bytes typed while an input is in flight
  (**typed-ahead**) are **not** editor input: they accumulate and reset nothing. **Provenance travels with the byte, not
  with the moment it is drained** — when work ends and those accumulated bytes reach a republished prompt, they still do
  not reset the credit or the promise, because the operator typed them *while stuck* and a byte cannot become evidence of
  an interactive operator by being delivered late. §1's fd-0 ownership makes this implementable: each byte is marked with
  prompt-liveness on arrival.
- **The escape credit** counts **consecutive interrupts**. It is reset **only** by editor input at a live prompt (as
  defined above), or by session end. It is **never** reset by work beginning or ending, by a turnover gap, by returning
  to idle, or by time.
- **The typed promise** follows the credit's reset rule exactly, and this symmetry is deliberate: it is **cleared by
  editor input accepted at a live prompt** (which typed-ahead, drained or not, is not) and by session end, and is
  otherwise irrevocable. Without this clause "irrevocable" would be a trap — an operator who runs a command, gets a
  clean prompt, and minutes later presses `Ctrl+C` to clear a typo would find a stale promise ending their session,
  the exact surprise the editing-row three-press case exists to prevent. A promise, like the credit, describes a
  *consecutive* run of interrupts; typing ends the run.
- **`Orderly` carries no captured value.** The promise latches the status *class* — orderly versus `Interrupt(130)` —
  and nothing more. An orderly exit's numeric status is `process.exitCode`, **read at exit** per §8, not captured when
  the notice printed. So a root-attributed timer that sets `process.exitCode = 7` after an idle promise was latched
  yields **7**, consistently: there is no notice-time-capture reading to fork against the exit-time read.

**Cancellation is id-exact against one unit of work** — each unit is assigned a **monotonic target id** at begin, and
a request carries the id it was raised against, so a request aimed at a callback that has already finished cannot land
on its successor. This is forced by the engine: the queued interrupt runs *exactly once*, and one native poll drains a
whole callback queue and several due timers, so a Rust id wrapped around the FFI call cannot name a unit — publishing
unit boundaries natively is an obligation on the engine seam (§11).

**The any-thread native control seam is generation-bearing and leased.** The terminal controller captures
`ex_hermes_runtime_nonce(runtime)` while it owns the live runtime and carries that nonce, unchanged, with every
work-unit take, cancellation-result take, active-target query, and id-exact cancellation request. It must never recover
the current nonce from a retained pointer when the control fires: an allocator may have reused that address for a later
runtime. Native admission validates the pointer-plus-nonce pair against the exact **Running** registry generation and
acquires a teardown-counted lease before dereferencing the handle; the lease remains held through the complete queue or
cancellation operation. A mismatched, zero, Closing, destroyed, or address-reused generation fails closed (`FAILED`, or
zero for the active-target query), without touching runtime-owned mutexes or Hermes. Teardown atomically changes Running
to **Closing**, refuses later leases, and does not erase or delete the generation until every already-admitted control
lease has completed. A check without the full-operation lease is non-conforming because it leaves a check-to-dereference
use-after-free race.

**More than one unit can be live at once**, so the target is chosen by an **ordered selection function**, not by a
singular "the in-flight work". LLP 0024 permits a background callback to execute *while* an input is suspended at a
top-level `await`, so the case is real:

> **A cancellation request is raised only against an *executing* unit.** A **suspended** unit (awaiting) is not
> executing, and a **due** unit has not begun and has no id yet — so an interrupt against either **promises but raises no
> request**. The escape credit and the typed promise guarantee the escape without one.

An LLP 0026 module graph suspended on dependency TLA is one such suspended
unit. Its retained internal record promise is keepalive state, not a separate
cancellation target, and individual public `import()` waiters do not acquire
target ids. Teardown abandons the whole runtime generation; it does not
partially cancel one waiter into a live graph.

This is a deliberate narrowing from an earlier `executing ≻ suspended ≻ due` selection that tried to *raise* a request
against a suspended unit. There is no delivery mechanism for that anywhere in the corpus: LLP 0024's engine discards any
request whose id is not the one *currently executing*, so a request aimed at a suspended unit would resolve `unavailable`
and change nothing. Rather than depend on a sibling primitive that does not exist, this document raises against executing
work only, and lets the credit and promise carry every other case. Nothing operator-visible is lost but the
`cancelling` wording — which would have been a lie anyway. An interrupt that raises no request must **not** claim it did:
its notice is `work is in flight — press Ctrl+C again to end the session`, never `cancelling`, and never `work is running`
for a unit that has not begun. The unit-boundary question the fuller selector would have
needed stays honestly ledgered (`OBL-SUSPENDED-UNIT`), unblocking this document rather than waiting on it.

**Target selection**, by phase — this chooses *what the first interrupt acts on*; the second interrupt is governed by the
promise, not by any per-row rule:

1. **shutdown** → the shutdown (a cause is already latched; see precedence).
2. **evaluating** → the executing unit if any, else the suspended unit, else the pending submission. Either way the
   interrupt **discards the pending submission and any typed-ahead**. The buffer does not compete in this phase, or a
   stray keystroke would steal the interrupt from a runaway evaluation.
3. **editing / continuation** → an **in-flight completion query** if one exists — the operator asked for that work by
   pressing Tab, and the buffer is **preserved** — otherwise the **buffer**.
4. **idle** → the `Executing`/`Suspended`/`Due` work if any (a lone `CompletionQueued` is abandoned, not a target — see the discriminant above); otherwise the **idle prompt**.

**The table has one column: what the *first* interrupt of a consecutive run does.** There is no second column, because the
second interrupt is decided uniformly — by the promise (if one was printed) or by the credit — never by a per-row rule.
This is the latch's deletion made concrete.

| (phase, work) | The first interrupt does |
| --- | --- |
| idle, no work in flight | print `press Ctrl+C again to end the session, or Ctrl+D to exit` — **promise `Orderly`** |
| idle, `Executing`/`Suspended`/`Due` work in flight (a lone `CompletionQueued` is abandoned and falls through to the idle-prompt row) | abandon a completion query's result; raise an id-exact request **only against an executing unit** (suspended/due/queued raise none); print `cancelling <what> — press Ctrl+C again to end the session` when a request was raised, else `work is in flight — press Ctrl+C again to end the session` — **promise `Interrupt(130)`** |
| editing / continuation, completion query `Executing{id}` | abandon its result; invalidate it by **buffer generation**; raise an id-exact request; **preserve the buffer**; print `cancelling completion — press Ctrl+C again to end the session` — **promise `Interrupt(130)`** |
| editing / continuation, completion query `CompletionQueued{request_id}` (dispatched, not begun — a request id but no unit id) | abandon its result; invalidate it by **buffer generation**; **raise no request** (there is no id yet); **preserve the buffer**; print `work is in flight — press Ctrl+C again to end the session` — **promise `Interrupt(130)`** |
| editing / continuation, otherwise | discard the buffer, fresh prompt. **Prints exactly `input discarded` — never the promise phrase**, so no promise is latched and none can be broken. If work is in flight, append `(work still running)` | *(no promise; the credit still counts this press)* |
| evaluating, work in flight (the submission, an earlier unit, or a suspended `await`) | discard the pending submission and typed-ahead; raise an id-exact request **only against an executing unit**; print the running-work notice — **promise `Interrupt(130)`** |
| evaluating, nothing in flight (submission not yet dispatched) | discard the pending submission and typed-ahead; nothing to cancel; return to idle | *(no promise; the credit still counts this press)* |

The **shutdown** phase has no row here because it never takes a *first* interrupt: reaching shutdown means a cause is
already latched, and every interrupt in shutdown is governed by cause precedence below (expedite, keep the status).

A **completion query is killable work**. It is advisory and bounded in queue occupancy (LLP 0022), so an interrupt
abandons its result — but if it is in flight it is live work the escape invariant covers — whether `Executing` (running
work, which a hostile test producer can wedge) or still `CompletionQueued` (abandoned, then fall-through). The production
query cannot run user code or hold engine authority; abandonment is enforced by exact request/target ids plus buffer
generation, and the second promised interrupt ends the session even if the producer never returns. A separate elapsed
completion budget remains one of §12's explicitly unbound engine-dependent constants; queue bounds and interrupt escape
do not pretend to choose that policy value.

**Two rules make the two guarantees true. Both are arithmetic; neither is case analysis.**

> **1. The promise.** Any notice that says *press Ctrl+C again to end the session* **atomically latches a typed promise**
> — `Orderly` when the promising interrupt targeted the idle prompt, `Interrupt(130)` otherwise. The next interrupt then
> **ends the session, whatever it targets, with the promise's own status class** — never the status the then-current
> *target* would imply. (A termination *cause* latched in the interim — a root `process.exit`, a signal — supersedes the
> promise's status but not its termination; the dispatch order below states that precedence. A cause is not a target.)
>
> **2. The escape credit.** Independently of any promise, **the third consecutive interrupt ends the session, whatever it
> targets.** It is the unconditional backstop that bounds the escape even if some future row failed to print a promise.

**The promise carries its status because a bare bit does not.** An idle promise means an *orderly* exit (honoring
`process.exitCode`, read at exit); a running-work promise means **130**. If the selected target flips between the promise
and the next press — a timer comes due beneath an idle prompt, or the promised work finishes — a boolean cannot say which
status was promised, and an implementation that re-derived the status from the flipped target would hand the operator a
*different* exit code than the one the notice implied. So the status class is written down at notice time, exactly as the
answer to "does this press terminate?" is.

**The credit almost never fires, and that is by design.** Two rows print no promise — the **editing-otherwise** row and the
**undispatched-submission** row (`evaluating, nothing in flight`) — and both *clear the buffer or return to idle*, so the
next consecutive press lands at a prompt that does print one. Therefore whenever the credit reaches 3, a promise is
already live and supplies the status — the credit's job is purely to *bound*, not to decide a status. There is no
reachable "unpromised credit termination." The credit is belt to the promise's suspenders: it guarantees ≤3 as arithmetic,
so the bound survives even a bug in the promise logic. (These two rows are why the worst case is **three**, not two: from
either, press 1 prints nothing, press 2 prints a promise, press 3 honors it.)

The typed promise is the same lesson applied twice. Four hand-written versions tried to *derive* the bound from case
analysis and were falsified four times; the fifth **asserted** it as arithmetic and survived. "Every notice is true" was
then falsified for precisely the same reason — it was still being derived. A notice printed at an idle prompt promised
that the next press would exit, and then a timer came due and the next press targeted running work instead; a notice
printed against running work promised the next press would end the session, and then the work finished and the next press
merely cleared a buffer. **A promise that the machine has to reason about is a promise the machine will break.** So the
machine no longer reasons about it: it writes the promise down and honors it.

An earlier draft tried to patch this with a "changed-situation notice" that would explain, on the *next* press, why the
previous promise had not been kept. That is not a repair — by the time it prints, the promise has already been broken. It
is **deleted**. A machine that keeps its promises does not need to apologize for them.

**Consequences of the promise, which are all good:** every first interrupt in the idle and running-work rows prints a
promise, so those cases now terminate in **two** presses unconditionally. Three are needed only from the two **no-promise
rows** (editing-otherwise and undispatched-submission), which print none. And the credit remains the backstop that bounds
even those cases.

**A global invariant must be checked against every row that could contradict it.** An earlier draft asserted "no row can
override the credit" and then wrote a shutdown row that did — reachable by the most ordinary gesture there is, hammering
`Ctrl+C` at an idle prompt. An invariant stated in one place and violated in another **reads perfectly fine in both
places**. Hence the cause-precedence rule below, and hence `OBL-INTERRUPT-MODEL`: this is the class of defect a
model-checker finds and a careful reader does not.

> **Cause precedence, and two fields the document was conflating.** A termination has a **cause** (the event that
> initiated it — orderly shutdown, cooperative exit, interrupt termination, or fault) and a **final disposition** (the
> exit status actually taken). The **cause is latched once and never changes**; a later interrupt may *shorten* the
> cleanup but cannot relatch a new cause. A third consecutive interrupt during an already-running orderly shutdown
> therefore *expedites and keeps the orderly status* — it does not become a 130.
>
> The **final disposition is the cause's status, with exactly one permitted modifier**: a cleanup that loses program
> output with **no destination left to report it on** (§3) upgrades a *successful* cause's status (an orderly
> `0`/`exitCode`, or a cooperative `n`) to **141** — and *only* a successful cause's. It never touches a fault (70) or
> an interrupt (130). This is not a competing cause re-entering the matrix; it is a disposition modifier applied once,
> at the end, to a cause that already succeeded. So the triple-idle-all-stalled trajectory latches *orderly* on press 2
> and, if press 3's abandonment loses unreportable output, takes **141** — the orderly cause is intact; only its
> disposition reflects a loss the cause could not have foreseen. A fault or interrupt in the same situation stays 70 or
> 130.

> **Interrupt dispatch order — two axes, stated once.** Each interrupt is resolved against a fixed precedence for
> *whether it terminates* and, separately, for *what status it takes*:
>
> - **Termination (does this press end the session?):** **(1)** a latched termination cause → *expedite*; else **(2)** a
>   promise latched on a **prior** press → *terminate*; else **(3)** the escape credit reaching 3 → *terminate*; else
>   **(4)** the table row runs (which may itself *print* a promise for the next press, but does not terminate).
> - **Status (what exit code?):** a **latched cause** supplies it (rule 1); else a **latched promise** supplies its class
>   (rule 2, and rule 3 in practice, since a credit-3 always has a live promise); else — only on the theoretically
>   unreachable unpromised-credit path — **130**, the safe default for "something is stuck."
>
> A cause latched **in the interim** therefore supersedes a promise's status but not its termination: a root
> `process.exit(7)` after an idle promise still ends the session on the next press (the notice's promise is kept), with
> code **7**, not the promised orderly `0`. That is correct — the operator's explicit exit request is a stronger
> statement than "I'll shut you down cleanly," and the notice only ever promised *that the session ends*, not a
> particular code. The table can never contradict rules 1–3, because it holds no termination power of its own;
> `OBL-INTERRUPT-MODEL` model-checks that.

The deletion of the latch is why this is only two axes and not three. An earlier draft carried a `(class, epoch)` latch
as a *third* mechanism deciding second-press termination, and its precedence against the credit was the seam that let a
credit-exhausting press override a promised status. With the latch gone, the promise is the only thing that decides the
second press, and it carries its own status — so the contradiction has no surface to live on.

**Interrupts are handled atomically.** **Non-coalescing is promised for terminal-generated interrupts only**: two `Ctrl+C`
keystrokes are two bytes on a descriptor the session owns (§5's raw-mode commitment), and are two interrupts even within one
quantum. Two external `SIGINT`s may be coalesced by the kernel before user space observes them; external counting is
best-effort, and a test that sends two must wait for the first to be acknowledged. Once observed, both sources enter the
same serialized `ReplInterruptIngress`: it calls the generated dispatch, performs the selected cancellation/force action,
and publishes the same priority `Interrupt` event. The signal path is not a second handwritten transition machine.

> **Escape invariant.** From **any** reachable state, **at most three consecutive interrupts** — no intervening editor input
> — end the session, with the terminal restored, and none of them depends on the engine, the worker, or JavaScript
> cooperating. **Two** suffice whenever the first press printed a promise, which is every idle and running-work row; three
> are needed only from the two **no-promise rows** (editing-otherwise and undispatched-submission), which print none.
>
> **Notice invariant.** If the session printed *"press Ctrl+C again to end the session"* and **no editor input has since
> been accepted at a live prompt**, the next interrupt **ends the session** — whatever it targets, whatever the engine has
> done in between. Its status is the **promise's own class**, *unless a termination cause was latched in the interim*
> (a root `process.exit`, a `SIGTERM`, a fault), in which case that cause's status is taken (dispatch rule 1) — the
> session still ends either way, which is the whole of what the notice promised. Editor input clears the promise (the
> operator interacted; the run ended), exactly as it resets the credit.

Both are **temporal properties of the transition data** (`OBL-INTERRUPT-MODEL`), model-checked against an adversarial
scheduler over an alphabet that includes editor-input, promise-set/clear, and cause-latch as first-class events. The two
properties are stated here and in AC 7 in **identical** terms so one checker verifies both:
`interrupts_without_editor_input ≤ 3`, and `(promised ∧ no_editor_input_since) ⇒ the next interrupt is terminal, with the
promised status class unless a cause latched in the interim`. Neither is a prose obligation sitting beside a machine that
might not honor it.

The scoping to **consecutive** interrupts is deliberate and is the honest answer to "does typing reset the escape?" Editor
input at a live prompt *does* reset escalation, and it should: an operator who is typing is interacting, not stuck. The
guarantee that matters is the one a stuck operator actually exercises — pressing `Ctrl+C` repeatedly — and that now
terminates in at most three presses, always, from every reachable state.

The three-press bound in the editing row is likewise deliberate. Letting an editing interrupt target running work would
restore a two-press bound at the cost of ending the session of an operator who pressed `Ctrl+C` to clear a typo while a
benign callback happened to be on-stack. A rare extra press is a better trade than a common session-ending surprise. The
*completion-query* row is the exception that proves the rule: there the operator asked for the work.

The two terminations differ deliberately: a second **idle** interrupt is a *requested* exit (orderly shutdown, honoring
`process.exitCode`); a second against **running work** is an *interrupt termination* (130).

**What a cancellation request can do, honestly.** This document adopts LLP 0024's cancellation algebra, **with the one refinement that the structured `cancelled` outcome
is emitted only for evaluation targets** — a callback or query `accepted` means the unit returned (0024 states the same).
Having previously garbled the algebra, it now tracks 0024: a request is **`Pending`** — *nonterminal* — until it resolves, and it **may never resolve at all**. Its
terminal resolutions are *accepted*, *unavailable*, *failed*, and *defeated*, where **defeated** means the request was
delivered, the target kept running, and the target **later ended by another route**. A permanently stuck target therefore
leaves the request **`Pending` forever** — it is not "defeated"; it is unresolved, and that is precisely why the escape
above may not depend on it.

A request fails to take effect in at least three ways:

- the executing code carries **no async-break checks**. Hermes emits them in eval'd code by default, but **Ibex's own
  `hermesc` invocation passes no break-check flag**, so the bytecode Ibex builds is not interruptible. Interruptibility is
  a property of *how the source was compiled*, not of the engine alone;
- the break surfaces as a **catchable** throw and user code swallows it; or
- execution is inside a **native call that does not return**.

*Accepted* means the work **stopped because of the request** and the runtime passed
its **consistency check**. Work that completes normally after a request was delivered yields its normal outcome and the
request resolves **defeated**, not accepted (LLP 0024 states the same race rule). The consistency check's probes are not
invented here: OQ 1's prototype must establish the minimum set that distinguishes a reusable runtime from a merely-alive
one, and an implementation that cannot perform it must report *failed* rather than guess. **`accepted` is target-generic**
— it means causally stopped and consistent — and only an **evaluation** target emits the structured `cancelled` *outcome*;
a callback or completion query `accepted` simply means the unit returned (LLP 0024 states the same). **Failed** ends the
session (status 70). The two `failed` triggers are distinct and do not contradict: a request whose target **returned** but whose
runtime cannot be proven consistent resolves `failed` **immediately**; a request whose target **never stops** stays
`Pending` and resolves `failed` only when the runtime is destroyed or the worker is terminated — never optimistically.

The first-interrupt notice therefore says **`cancelling`** (in progress), not `cancelled` (done): acceptance is not known when the
notice is printed, and a session that says "cancelled" before the engine has stopped is telling the operator something it
does not know.

This document deliberately **does not assert whether a Hermes async break is catchable.** The asymmetry justifies the
pessimism: **a spec that assumes the break is uncatchable and is wrong has merely kept a redundant escape; one that assumes
it is catchable and is wrong has promised an escape it cannot deliver.** Every guarantee here holds under either answer.

### 7. Architecture: the session layer must survive its worker

Ibex's engine seam has no cancellation operation, and evaluation holds serialized runtime access — the FFI lock — across
the whole native call, so nothing today can even *ask* a running evaluation to stop.

**The invariants are normative. The architecture is how you get them.**

> The session layer's guarantees must hold against a worker that is **stuck**, **crashed**, or running **hostile
> JavaScript**. Specifically: §6's escape invariant; terminal restoration after an engine death; a single writer for the
> terminal, transcript framing, and history; a structural barrier against a native `std::exit` bypassing session cleanup;
> and fd-0 ownership JavaScript cannot reach.

**The threat model has three profiles, and this document claims only the two it can enforce.** An earlier draft said
"hostile worker" and meant more than it could deliver.

| Profile | Claimed? |
| --- | --- |
| **Stuck or crashed engine** — code that never returns, or a native fault | **yes** — the supervisor is a different process and does not depend on the worker to act |
| **Hostile JavaScript behind intact native mediation** — a package doing anything JavaScript can do, through Ibex's own adapters | **yes** — this is the profile the fd brokerage, protected descriptors, and typed surfaces actually deliver |
| **A compromised *native* worker** — arbitrary same-UID native code | **no** — and saying otherwise would be a lie |

A same-UID native process can open the concrete terminal device, read `/proc/<supervisor>/fd`, `ptrace` where the platform
permits it, spawn a detached descendant, and pass descriptors over `SCM_RIGHTS`. It also **knows the session nonce**, so it
can forge a perfectly authenticated control record: **authentication proves channel membership, not truthfulness.** Closing
those routes "natively" constrains *intact Ibex adapters*, not arbitrary native code. Genuinely containing a compromised
native worker requires per-platform sandboxing or credential separation — process-tree containment, descriptor-passing
denial, and supervisor-side independent validation — which this document does not specify and therefore does not promise
(OQ 13).

**Granting `process:spawn` is a threat-profile transition, and it is stated as one.** The armed model can authorize
`process:spawn`, and a spawned child is arbitrary same-UID native code that inheritance policy and the fd allowlist do not
contain — it can reopen the terminal or receive a passed descriptor exactly as the compromised-native profile describes. So
a session that grants `process:spawn` **leaves the hostile-JS-behind-intact-mediation profile** for the third profile this
document does not claim to contain. This is not a defect to hide behind "the child does not inherit our descriptors"; it is a
boundary to surface, so an operator or policy author granting spawn knows the terminal-containment assurance is downgraded by
that grant, not preserved through it.

**The specified realization is a terminal supervisor process** that owns the PTY, history, startup configuration, signals,
and the final exit, with the engine in a worker it can terminate. It delivers those invariants *structurally*: a second
interrupt is serviced by a process that is **not** the one that is stuck; restoration survives an engine death the engine
cannot report; fd-0 ownership becomes an OS fact; and a native `std::exit` in the worker cannot take the terminal down.

**Worker isolation, control authentication, and signals are part of the design, not implementation details.**

- The **supervisor is the foreground process group**; the worker runs in its own. A worker in the foreground group dies on
  the kernel's group-wide `SIGINT` and the session layer learns of the interrupt from a corpse.
- The worker gets **no controlling terminal** and a **spawn-time fd allowlist** with close-on-exec control handles. That is
  necessary but **not sufficient**: removing the controlling terminal makes `/dev/tty` fail but does not prevent opening the
  **concrete terminal device**, `/dev/fd` or `/proc/*/fd` aliases, or receiving a descriptor over `SCM_RIGHTS`. Those routes
  are closed natively, and spawned descendants are inside the boundary (§3: they do not inherit session descriptors).
- **Control records are authenticated**, not merely addressed: each carries the **armed session nonce** and a **channel
  epoch**, and is bound to the spawned worker. The channel also has a symmetric key **`K_channel`**, supervisor-minted at
  spawn and delivered to the worker over the allowlisted control fd (§9's history equality proof is keyed with it); like
  the nonce, it is conceded to the compromised-native profile — a native worker that reads it can forge, which is why §7
  claims nothing against that profile. "It arrived on this fd" is not authentication, and **program bytes can never
  authenticate**.
- The worker's lifetime is bound to the supervisor's by a **kernel parent-death mechanism** (`PR_SET_PDEATHSIG`, `kqueue`
  `NOTE_EXIT`, Job Object) **or an engine-independent watchdog that takes no runtime or broker lock**. "Kill on relay EOF"
  is *not* sufficient: a worker stuck inside evaluation holds the FFI lock and can never service EOF — the very case the
  mechanism exists for.
- **`SIGWINCH` is relayed** to the worker (or delivered as a control-lane dimension event), because the worker answers the
  `stdio:query` that reports dimensions.
- **`SIGPIPE` is ignored**, so a broken pipe is a typed error and §8's status rather than a silent death.
- **Suspension is a transaction** (the `Ctrl+Z` keybinding of §5, and an external `SIGTSTP`): restore the terminal, stop the
  worker group, then stop the supervisor. On continue: reacquire and verify foreground ownership, reinstall raw mode, continue
  the worker, redraw. Without stopping the worker, background work keeps running while the operator has shelled out.

An **in-process design is a conforming alternative only against the whole list**, not against cancellation alone. It must
demonstrate, on every advertised target: (a) §6's escape invariant against code with **no async-break checks**; (b) restoration
after an **observable** engine fault (not `SIGKILL`, which no in-process design can cover and which this gate does not demand);
(c) §3's broker ordering, per-relay cutoffs, and control lane across every write path; (d) fd-0/1/2 ownership and the protected
descriptor class across every route in §1; and (e) §8's cooperative exit without a native hard-exit. The gate is **passable in
principle** and is stated so that passing it means having built all the guarantees, not one.

### 8. Exit and lifecycle

**Orderly shutdown** (`Ctrl+D` at an empty prompt, `.exit`, a second idle interrupt, end of transcript input): already-scheduled
work drains within a bounded budget — never waiting on unbounded background work — and then **one ordering, pinned everywhere:
restore the terminal, flush the broker under budget, release resources, exit.** Restoration is first on **every** path, with no
potentially blocking step before it; an earlier draft had §5 and §8 disagreeing about this, and a hung flush ahead of restoration
is exactly how an operator's terminal is left raw. The process exits with `process.exitCode` if root-attributed code set it, else
zero. **This bounded drain governs session *shutdown* only**; the normal completion of program and one-shot execution drains to
quiescence per LLP 0024 and is not narrowed here.

**JavaScript lifecycle surfaces are cooperative and root-only.**

- `process.exit(n)` from a **root-attributed** frame — decided over LLP 0021's complete constrained-principal set, with missing,
  ambiguous, or `NoUser` attribution denying — is a **cooperative lifecycle request**.
- **It is uncatchable because the call never returns — it *parks*, it does not unwind.** `try`/`finally` cannot run in a frame
  that never exits, so `process.exit(7); sideEffect()` cannot run `sideEffect`. An earlier draft asked for an "unwind past
  `finally`," which no vendored Hermes interface offers and which would have made this section unimplementable.
- **The two realizations differ, and the difference is not cosmetic.** Under §7 the call commits an **authenticated lifecycle
  record** and *then* parks; the supervisor drains each relay to the record's cutoffs under budget, disposes of the worker, and
  exits `n`. **In-process, parking alone is a hang**: the call runs on the engine thread holding the FFI lock, so no outer evaluator
  can ever resume to clean up, and runtime destruction would deadlock on the lock the parked frame holds. The in-process realization
  therefore performs restoration and the bounded flush **inside the accepted call**, then `_exit`s — never returning, never unwinding,
  never destructing the runtime, never joining a thread, never taking a lock it does not already hold. (`_exit`, not `std::exit`:
  static destructors would race the engine thread.)
- **Commit rule — one mechanism, stated once, and idempotent.** The lifecycle record is **fixed-size** and carries `n`, an
  **idempotent request id**, and the worker's own **write-time relay counters** — at most two, because the worker owns at most two
  relays; §3 orders *child* relays at relay acceptance, so no child cutoffs travel. Write-time counters (not the receipt-side
  numbers the supervisor already holds) are what make AC 9's `console.log("bye"); process.exit(0)` case work: §3 warns a control
  message can overtake relay bytes the supervisor has not yet read, so the supervisor **drains each relay up to the record's
  write-time counter before disposing the worker**, and `bye` cannot be lost in a still-unread relay. The control lane holds
  **preallocated, reserved capacity** for this fixed-size record, so the commit cannot fail for backpressure. It is
  **acknowledged**: the worker parks only after the supervisor has durably accepted it. If the acknowledgement does not arrive
  within its bound, the worker exits with a **reserved fatal disposition** (status 69, §12).
  **The supervisor then keys on what it *has*, not on how the worker left.** If it holds an accepted record, the commit
  *succeeded* and only the ACK was lost: it proceeds as a cooperative exit with code `n`. It is only when it holds **no** record
  that it restores, drains what it has, and exits with the fault status. An earlier draft directed the supervisor to report "the
  requested code was lost" while it was holding the record that said otherwise — a falsehood, in a document whose central claim
  is that the session never tells the operator something untrue. The request carries an **idempotent id**, so a retransmitted
  record is recognized rather than double-applied.
  The worker does **not** "take the in-process path": it owns no terminal to restore and no broker to flush.
- The evaluation seam reports a **lifecycle outcome** (LLP 0024 §6) — **unit-generic**, because a root-attributed *timer* may
  request exit with no in-flight evaluation at all: the outcome attaches to an evaluation when one is in flight, and is delivered
  as a bare out-of-band control event when none is. Either way it is not a value returned from a frame that unwound.
- A cooperative exit does **not** drain pending work; it flushes the broker and exits, as Node's does.
- **`exit` and `beforeExit` listeners never fire, in any mode, and are not stored.** Registration is a **no-effect branch**, not a
  throw: `process.on('exit', fn)` succeeds, is **diagnosed once per session with a stable code**, and the listener is discarded — so
  `listeners('exit')` is empty, `listenerCount` is 0, `removeListener`/`off` are no-ops, `prependListener`/`prependOnceListener`
  behave as `on`, and manual `emit('exit')` stays closed. A throwing denial would break common cleanup packages at *import* time in
  every mode; a listener that fired on some exit paths and not others would corrupt exactly the invariant such a handler exists to
  protect. Deferring the feature honestly (OQ 3) beats faking it. This is a deliberate divergence from Node.
- A **second request while one is in flight** changes nothing.
- **`process.exitCode` is supervisor-authoritative.** It cannot be a value the supervisor *reads from the worker at exit*,
  because a due timer can run `process.exitCode = 7; while(true){}` and then the engine is wedged when the exit is taken.
  Instead the setter **mirrors the value to the supervisor synchronously, before it returns to JavaScript** — so the last
  value set is always held by the process that owns the final exit, independent of any later wedge. The `Orderly` status
  is resolved from *that* mirrored value at exit; the setter, not a drain-time read, is the snapshot event. (In-process
  modes are trivially consistent — the same process holds both.)
- **Package-attributed** calls — and any call whose attribution is missing, ambiguous, or `NoUser` — receive the typed lifecycle denial.

There is **no "background-attributed" principal**; this document does not extend LLP 0021's principal set. A timer *scheduled by root*
is root-attributed and may request exit; a callback owned by a package may not.

**Exit-status values.** The argument to `process.exit(n)` and writes to `process.exitCode` are coerced by ordinary JavaScript number
conversion; a non-finite value is 0. On POSIX the status carries the **low 8 bits** (`exit(256)` is observed as 0); Windows uses the
full 32-bit value. Node throws on some invalid codes; Ibex coerces. Recorded as a divergence.

**Failure fatality is a mode × class matrix**, which both LLP 0022 and LLP 0024 delegate here and which this document has owed them:

| Failure class | REPL modes (interactive, transcript) | program / one-shot / file execution |
| --- | --- | --- |
| **undecodable input** — *interactive* | reported; the session continues (the editor resynchronizes at the byte level) | (n/a — interactive is a REPL mode) |
| **undecodable input** — *transcript* | **fatal**, until a framed protocol supplies a resynchronization boundary (LLP 0022's rule, honored here) | **fatal, exit 1** |
| parse / recoverable syntax error | reported; session continues; exit code unchanged | **fatal, exit 1** |
| foreground throw (an input's evaluation threw) | reported; session continues | **fatal, exit 1** |
| unhandled promise rejection | reported once, above a redrawn prompt; **never fatal** | **fatal, exit 1** |
| uncaught exception in background work | reported once; **never fatal** | **fatal, exit 1** |
| cancellation resolved **failed** (runtime not provably consistent) | **ends the session**, **70** | **fatal**, **70** |
| engine or armed-host fault | **ends the session**, **70**, after a stderr diagnostic | **fatal**, **70** |
| broker write failure on a session-authored event | ends the session, **141** | same |

The interactive row is the deliberate divergence LLP 0022 states as behavior: an asynchronous failure must not terminate an operator's
session. The non-interactive rows match Node.

**Exit statuses** (the same numbers on Windows, where console-control equivalents map onto them):

| Cause | Status |
| --- | --- |
| orderly shutdown | root-set `process.exitCode`, else 0 |
| cooperative `process.exit(n)` | `n` (low 8 bits on POSIX) |
| **any §6 interrupt termination** | **§6's status axis decides it, and this table does not restate it** — a *latched cause* if one is in flight, else the *latched promise's class* (`Interrupt(130)` → 130; `Orderly` → the orderly status: root-set `process.exitCode`, else 0), else — only on the unreachable unpromised-credit path — 130. This row carries no per-target classification of its own: it *cites* §6 so the two cannot diverge. A single interrupt in any mode where §1's table binds §6 to **terminate** (no editor — transcript, program, one-shot, file execution, or interactive-without-a-terminal) is always **130** (no promise machine exists there). An `Orderly`-class termination may take **141** only under a §3 cleanup loss with no destination to report it |
| **reserved worker disposition** — a lifecycle commit the worker could not get acknowledged; the supervisor interprets it, and reports the requested code as lost **only if it holds no record** (§8) | worker exits **69**; supervisor exits **70** on no-record, or the cooperative `n` if it holds the record |
| `SIGTERM` — orderly shutdown attempted, exits promptly regardless | **143** |
| `SIGHUP` / terminal death — restore and flush | **129** |
| `SIGQUIT` — restore, then re-raise with the default disposition | **131** |
| broken pipe on a session-authored write; or forced-termination loss with no destination to report it on | **141** |
| unhandled rejection / uncaught background exception / foreground throw / parse error, in non-interactive modes | **1** |
| fatal engine or armed-host failure, after a stderr diagnostic | **70** |
| startup failure, before any prompt | **78** |

**Status precedence** is pinned, because causes coincide and an unordered table is not a specification. There is exactly one
rule, used by §3, §6, and §8 alike:

> **The primary cause is the event that *initiated* termination, and it is latched.** Once latched it fixes the status. Later
> events may **shorten** cleanup but never change it. A failure that is a *consequence* of the termination — a cancellation
> resolving `failed` because the worker was killed by the escape, a broker write failing because the session is tearing down —
> does **not** re-enter the matrix as a new cause.

So a fault (70) or an interrupt termination (130) is never overridden by a cleanup failure; a third consecutive interrupt during
an orderly shutdown expedites it without changing its status; and a cleanup failure upgrades only a **successful** status — an
orderly 0/`exitCode`, or a cooperative `n` — and only to **141**, and only when forced-termination loss occurred with **no
destination able to carry the report** (§3). A cleanup failure that *can* be reported is reported, and the status stands.

`SIGQUIT`'s core, under §7, is the **supervisor's** — the engine's state is not captured, and an operator who wants an engine core should
attach a debugger. Promising otherwise would be a lie about which process dumps.

### 9. History

History is stored by the Rust CLI — under §7, by the **supervisor** — outside JavaScript authority. It exists only in interactive mode with
an editor (§1): history serves recall, and there is no recall without an editor.

**History is appended at submission, not saved at exit**, so **no exit path can lose a written entry** — not a second interrupt, not a signal
handler, not a crash. This retires today's save-on-exit behavior, which loses the whole session precisely when the session ends the way this
document exists to make survivable. The **durability boundary** is stated: an entry survives process termination, including `SIGKILL`, because
the write reached the operating system. It is **not** fsynced per entry, so a machine crash may lose recent entries — a deliberate trade against
a synchronous disk write on every submitted line.

**What is recorded**: every submitted, non-blank, non-space-prefixed input line, *including* command lines (`.load …`) and inputs that later fail
to parse or are cancelled — history is a record of what the operator *typed*, not of what succeeded, because an operator recalls a line precisely
to fix it. A pending submission discarded by an interrupt before it ran is still recorded. Continuation lines are recorded as **one** multiline
record at submission.

**The store is a recoverable journal.** "Append a line" does not survive the first multiline input, and "a corrupt file degrades to an empty
history" — combined with an unframed append — means **one killed append could erase recall of every earlier valid record**. Therefore:

- each record carries a **version, length, payload, checksum, and monotonic index**, framed so an embedded newline round-trips exactly;
- reading performs **valid-prefix recovery** **under the exclusive lock**, with the file's identity re-verified after acquiring it: records are read
  until one fails its checksum or length, and the file is **truncated to the last valid record** rather than discarded. A torn tail costs the last entry,
  never the history. The lock is not optional here — an unlocked reader could mistake **another session's in-progress append** for a torn tail and truncate
  a live write;
- a **stable sidecar lock** — in the same directory and on the same volume as the history file — guards it. Every append takes it; compaction takes
  it exclusively; an appender **reopens and re-verifies** the file's identity after acquiring, because a lock on the history file itself is
  inode-bound and does not survive compaction's rename;
- **compaction** (which enforces the §12 bounds) writes a new file and renames it under that lock;
- if the lock is not acquired within its bound, the entry is **not** persisted and the session says so, rather than blocking the prompt on history I/O.

**The storage root is pinned** to the per-platform user data directory, with **no current-directory fallback**. Today's code falls back to `.`, which
would drop a 0600 history file into whatever directory the operator happened to be in.

**History is project-scoped by default**, keyed by

> `HMAC-SHA-256(K_user, domain-separator ‖ ProjectHistoryScopeId)`, with a 32-byte key

so that inputs entered in one project are not recalled, completed, or searchable in another.

**`ProjectHistoryScopeId` is a distinct, versioned, supervisor-owned identifier — not a virtual-filesystem identity, and not LLP 0023's
record.** Two drafts got this wrong in two different ways, and the second failure is the more instructive. The first *reused* LLP 0023's
retained-object record, which violates 0023's rule that retained objects and every VFS identity "live and are derived in the process that owns
the engine" and are "never serialized to a supervisor and never rehydrated from one" — history is supervisor state that outlives the process, so
it cannot be that identity. The second kept the borrowed noun but quietly **answered an open question 0023 had not answered**: it defined the
generation as a birth timestamp with a path fallback, where 0023 names different primitives and leaves the choice open as its own OQ. Two documents
were then giving different answers to one document's open question, under a shared term.

The rule this document now follows, and states so the next author does not relearn it:

> **You cannot half-borrow a sibling's concept. Either you take its definition *and* its open questions, or you name your own thing.** Borrowing the
> noun while resolving its open question is how you assert an answer the owning document has not given.

So this is **its own identifier, owned here, defined here**, and it does not depend on LLP 0023's open primitive. It is authenticated **before spawn**.
**The worker holds no history-scope token at all** — history is supervisor-owned and appended at submission by the supervisor, and nothing in this
document has the worker perform a history operation, so the strongest opacity is *absence*: an earlier draft passed the worker an opaque token with no
consumer, and it is removed. (A worker "cannot derive, forge, or enumerate" the scope id only in the vacuous sense that it never receives it; and the §7
threat model already concedes a *compromised native* worker knows the session nonce, so no token-opacity claim would hold against it anyway.) Its content,
captured pre-arming from the authenticated project root:

- where the **filesystem** supplies a durable creation generation for a directory (`st_birthtime`, `statx` `STATX_BTIME`, Windows file id + creation
  time): `(durable volume id, file id, creation generation)`;
- otherwise: the **canonical project-root path**.

**Supervisor and worker must be talking about the same root.** The supervisor derives the scope id from the root it authenticated *before* spawn; the
worker independently authenticates its own VFS root at arming. A root replaced between those two derivations would associate one project's history with
another's session. The two sides therefore run a **nonce-bound equality proof** over the control channel: the supervisor sends a fresh challenge nonce,
each side computes `HMAC(K_channel, domain-separator ‖ nonce ‖ root-object-witness)` — **keyed with the session control-channel key `K_channel`**, held
by both endpoints of the authenticated channel and by nothing else — over the root object it independently authenticated, and the two digests are
compared. A mismatch is a startup failure, not a silent association. The nonce binding is what keeps this from becoming what it must not be — a *stable
serialized identity* for the root, which would be a VFS identity crossing the boundary under another name, and so a violation of LLP 0023's locality rule
by construction rather than by intent. An equality proof over a fresh nonce is not a rehydratable identity: the digest is different every session and
names nothing that outlives the challenge.

Consequences, pinned rather than implied:

- Under the first form, a project renamed or moved **within its volume keeps its history**; a **cross-volume move is a new object** and starts fresh; and a
  directory deleted and recreated — even at the same path, even reusing the file id — has a **new creation time** and starts fresh. That last case is the
  point: id reuse must not let an unrelated project inherit a dead one's history.
- Under the **path fallback**, a rename starts a fresh history and a recreated directory at the same path inherits — a **weaker** guarantee, stated plainly so
  that a filesystem without birth times does not silently pretend to the stronger one. (Birth-time availability is per-*filesystem* on Linux, not per-platform.)
- Two worktrees are two directories and keep separate histories under both forms.
- It reduces accidental reuse; it does not make it impossible. A restore from backup or a filesystem clone can reproduce it. This is a **scoping** mechanism,
  not an authentication mechanism, and the durable volume id must survive reboot and remount — `st_dev` alone does not.
- Orphaned files are never read and are not migrated.

**What the HMAC actually defends.** A bare hash of the project path is dictionary-guessable, so anyone who could see the *file names* could confirm which projects
a user works on. The HMAC closes that. It does **not** defend against an adversary who can read the history *contents* — the key sits in the same user-owned
directory, and such an adversary already has the secrets the scoping protects. The threat model is precise: **an adversary who observes file names but not
contents** — directory listings, backup and sync indexes, snapshot manifests, a `find` dump in a bug report.

**The key.** `K_user` and its check value (`HMAC(K_user, "check")`) are published as **one versioned record**, written **in full and fsynced to a temporary
name, then published by a no-clobber rename**, with the parent directory made durable. A losing creator **re-reads the winner's key** rather than replacing it.
Every clause is load-bearing: a plain temp-and-rename is not enough, because rename **replaces** — two concurrent first-run sessions would each mint a key and the
second would clobber the first, silently orphaning every entry the first had written, a de-facto rotation achieved by race, which is the exact failure the
never-rotate rule exists to prevent. And an exclusive-create *followed by* a write is not enough either, because a crash between the two leaves a permanently
malformed key that the never-rotate rule would then faithfully preserve forever. A key that exists but is **unreadable or malformed** degrades *that session* to no
persistence, with a diagnostic naming the remedy; it is **never rotated**, because rotating on a transient error would orphan every history the user has.

**File hardening.** Created **0600**, no-follow, in a runtime-owned directory that is not group- or world-writable, and used **only if it is a regular file, owned by
the invoking user, and already 0600** — a pre-existing group- or world-readable file is refused and diagnosed, not filled with new secrets. Windows uses the per-user
application-data equivalent with a default-private ACL.

**The operator-facing selection** is `--history=project` (default), `global` (explicit cross-project opt-in, keyed by a fixed domain constant with the same hardening),
or `off`. Per LLP 0010 it is a **root-level option** — bare `ibex` starts the REPL, so an option only on `ibex repl` would be unreachable from the spelling most people
use — with a stable clap id, an enumerated value shape, and a recorded default, added to the CLI surface manifest for both spellings. Because mode is selected by stdin at
runtime, an **explicitly supplied** value that cannot be honored is a one-line stderr startup diagnostic, **not** a usage error: the same command line must not be valid at
a terminal and invalid in a pipe. The recorded default is never diagnosed.

The legacy global history file is **not** migrated — importing another project's history into a project scope would defeat the isolation this change exists to create. It is
left in place and ignored, and reported once as a stderr startup diagnostic naming it **symbolically**, not by host path. That is **this document's choice, on its own
grounds** — the notice recurs at every startup and lands in logs and shared transcripts — and *not* an obligation imposed by LLP 0022, which expressly exempts CLI startup
diagnostics from its no-host-path rule. (An earlier draft cited 0022 for a rule 0022 disclaims.)

Recalled history is rendered under §3's escaping rules. Persistence failures are non-fatal and never broaden filesystem grants. Modes without an editor neither read nor write history.

### 10. Registry obligations

Per LLP 0021's no-unclassified-surface invariant, this document both **reopens** and **narrows** rows. These are regenerated with the implementation, and LLP 0021's
reconciliation gains the corresponding entries in the same change:

- **A named lifecycle capability.** The exit and exit-code surfaces (`process.exit`, `__exactExit`, `__exactHostExit`, `process.exitCode`, `_exactExiting`) are replaced by
  **`lifecycle:exit`** — typed, cooperative, root-only, with its own action, resource shape, and normalizers rather than a reuse of `process:signal` — carrying **separate
  dispositions** for the exit *request*, the `exitCode` *getter*, and the `exitCode` *setter*. The native hard-exit op is **retired**, not reclassified.
- **Process-event rows carry a no-effect branch** for `exit`/`beforeExit` across **every registration alias** (`on`, `addListener`, `once`, `prependListener`,
  `prependOnceListener`) and pin removal, introspection (`listeners`, `rawListeners`, `listenerCount`, `eventNames`), and manual `emit`. Every other process event stays closed.
- **fd-0 rows.** `__exactStdinRead` is today an `effects` edge under `stdio:read` whose `positiveSources` include `ambient-root` — the registry records a route by which root
  *may* read fd 0. In every session mode that must be false for **root and package alike**: the edge is sealed or carries a **mode-scoped no-effect branch** returning the EOF
  view. The same applies to every `process.stdin.*` op and to the `fs` read/close edges, which have no descriptor-zero branch today.
- **A mode-scoped branch needs new vocabulary.** LLP 0021's branch selection keys on argument and resource normalization; "fd 0 **in a session mode**" is a fact about arming.
  Extending the vocabulary is part of this change; hard-coding the mode outside the registry reintroduces the unclassified surface LLP 0021 forbids.
- **fd-1/2 rows**, and the **protected descriptor class** (§1) — control, relay, and watchdog handles unreachable from every numeric descriptor API, for every principal.
- **`stdio:query` rows** for stdout/stderr; `stdin`'s `isTTY` belongs to the fd-0 branch — one surface, one classification.
- **History-store rows.** History-directory discovery, key creation and read, lock acquisition, journal read/append, compaction, and legacy-file probing are runtime-internal
  filesystem effects performed by the session layer. They are classified as such, not left as ambient Rust I/O outside the model.
- **The worker-bootstrap route.** Spawning the worker on a non-`fork` platform needs an authenticated private entry point. If it is a hidden command or option it belongs in the
  CLI surface manifest per LLP 0010, and direct unauthenticated invocation is rejected.
- **`process:signal`** remains **closed** to JavaScript. §6 is not a capability.

### 11. Delegated obligations

**An attestation without a content hash is not an attestation.** That is the whole finding, and it took five failures to
learn. This ledger has now been wrong five times, in both directions, across five revisions — including once *inside the
revision that removed the status column to stop it*, where I replaced the column with rows pinned to a document **name and
a date**. LLP 0024 was revised four times that day; a date identifies nothing. The proof arrived within the hour: I computed
0024's digest, a reviewer computed it minutes later, and we got different values — **my attestation was meaningless on the
day I wrote it.** And once digests were in place, the mechanism did its job: the next review recomputed the pins and found
four 0024 rows stale (`88ebc6349bab` → `6416ccb8c3c2`), which is not the ledger failing but the ledger **working** — drift
became *detectable* instead of silent, and those rows are re-verified and re-pinned above. A ledger that surfaces its own
staleness is worth more than one that hides it. (The corpus files are untracked in Git, so the "before" digest in that
anecdote cannot itself be recomputed by a reader — this narration is **unverifiable narrative**, not a pinned claim, and
is marked as such; the *current* pins below are the verifiable part. Version-controlling the corpus is what would make
ledger history reproducible and is part of `OBL-LEDGER-CHECK`.)

The fix is not discipline. It is that a claim about another document must be **bound to a specific version of that
document**, or it is decoration that manufactures exactly the reliance it cannot honor. So:

- every row carries the sibling's **content digest** at the moment it was verified;
- **a digest mismatch invalidates the attestation** — a reader who recomputes and gets a different value must treat the row
  as unverified, not as merely old;
- rows state the **obligation**, not a status. "Delivered/outstanding" in the prose is the status column wearing a hat;
- ids are stable and owner-authored, and never cite section or open-question ordinals, which renumber nearly every round.

**Until `OBL-LEDGER-CHECK` lands, this is documentation of an intent and not a control.** Verify against the owner's current
text before acting on any row.

| Id | Obligation | Owner | Verified at |
| --- | --- | --- | --- |
| `OBL-UNIT-PUBLICATION` | **Native begin/end publication** of every unit of work so a target id can name one unit; **and due/undue transitions carrying the scheduling identity `sched`**, since begin/end alone cannot populate `Due{sched}` before begin and the native `TimerEntry.id` is not exposed (`ex_hermes_next_timer` gives only the earliest deadline). A Rust id wrapped around the FFI call cannot do this: one native poll drains a whole callback queue and several timers | LLP 0024 (engine seam) | **delivered for the production work sources** — the bounded `ExHermesWorkUnitEvent` queue publishes evaluation, callback, timer, and microtask-drain boundaries independently of submissions; timer `Due`/`Undue` records carry `TimerEntry.id`, and overflow is explicit. The production static completion producer separately publishes `CompletionQueued{request_id}`, acknowledges `Executing{target_id}` before computation, and finishes against both identities plus the input generation. The controller feeds those states into the same generated machine; completion has no engine authority and therefore does not fabricate a native engine event |
| `OBL-CANCEL-EDGES` | Cancellation edge semantics: `accepted` is **target-generic** (for a callback or query it means the unit returned; the structured `cancelled` *outcome* belongs to evaluations only); a consistency-check failure resolves **`failed` immediately**, not only at teardown; teardown failure is reserved for requests still `Pending` | LLP 0024 ↔ §6 | `0024@6416ccb8c3c2` — both documents were loose here; §6 now states the edges and 0024 must agree |
| `OBL-SEQUENCE-ALLOCATOR` | Sequence numbers assigned at **session-layer receipt**, never minted by the worker | LLP 0024 | `0024@6416ccb8c3c2` — **0024 is right and this document was wrong**; §3 now adopts it. A hostile worker must not be able to forge ordering |
| `OBL-SUSPENDED-UNIT` | The **unit boundary** for an input suspended at top-level `await`: its evaluation and each settling callback are distinct cancellable **work units** with their own target ids, while the input's **settlement unit** aggregates those jobs only for the one input outcome. A suspended settlement is not itself a cancellation target. | LLP 0024 | **delivered** — LLP 0024's shared vocabulary and §7.4 make the split normative; native work-unit publication emits callback and evaluation boundaries separately, and `suspended_top_level_await_resumes_without_assimilating_completion` binds the settlement behavior |
| `OBL-LIFECYCLE-UNITGENERIC` | §8's cooperative exit needs a **unit-generic lifecycle outcome**: a root-attributed *timer* may request exit with no in-flight evaluation, so 0024 §6's outcome must also admit a bare no-evaluation control event | LLP 0024 | **delivered** — `SessionLifecyclePort` publishes one root-only, idempotent `LifecycleExitRequest` independently of an input; the staged Host ABI commits an `AuthorizedWorkerLifecycleCommit`; `ControlMessage::LifecycleCommit` is a bare authenticated control event; and the supervisor preserves an accepted lifecycle request over later worker death. Bound tests are `root_operations_share_state_and_publish_one_idempotent_event`, `every_non_root_projection_denies_without_state_change`, `acknowledged_worker_lifecycle_commit_parks_without_returning`, `unacknowledged_worker_lifecycle_commit_uses_reserved_status`, and `accepted_lifecycle_wins_over_later_foreground_worker_death`. `EX_HERMES_POLL_LIFECYCLE_REQUESTED` exposes the engine-independent poll result; target promotion remains a separate conformance gate |
| `OBL-0024-EPOCH-VOCAB` | Retire the dangling "work epoch" alias for LLP 0025's deleted interrupt latch; only LLP 0024's worker-restart **sequence epoch**, work units, and settlement units remain current vocabulary. | LLP 0024 | **delivered** — the historical row was removed and current prose no longer treats a work epoch as a live LLP 0025 concept |
| `OBL-HISTORY-LOCALITY` | §9's nonce-bound equality proof crosses a *fresh-nonce-keyed, non-rehydratable* digest of the root, not an identity. LLP 0023's by-design-crossings parenthetical does not yet name it; one acknowledging line there closes the seam (the proof arguably already complies, being non-rehydratable) | LLP 0023 | `0023@a77e5a385f6a` at first review; **re-pinned `0023@601cb5213dca`** (2026-07-12) — **delivered**: current 0023's worker-locality section now explicitly names "LLP 0025's history-scope equality-proof digest" as a by-design crossing (0023 §7.1). The seam is closed; the ledger surfaced the favorable landing on its last outing |
| `OBL-INTERRUPT-EPOCH` | LLP 0022 must not recreate an epoch definition coupled to prompt publication; it cites this document's generated state and typed-promise machine directly | LLP 0022 | **delivered in current §10** — the deleted work-epoch alias no longer appears in its normative interrupt prose |
| `OBL-INTERRUPT-BOUND` | LLP 0022 must preserve this machine's exact bound: a promise is honored on the next press, while a no-promise edit-buffer discard can require the credit's third press | LLP 0022 | **delivered in current §10 and AC 15** — both cite the typed promise and escape credit without the false “two within one work epoch” paraphrase |
| `OBL-BRANCH-VOCAB` | Branch-selection vocabulary admitting a **mode-scoped** selection fact | LLP 0021 | not verified this round |
| `OBL-REGISTRY-ROWS` | `lifecycle:exit`; the protected-descriptor class; history-store rows; the worker-bootstrap route; listener no-effect branches across every registration alias; the reconciliation entries | capsec registry | **delivered** — the source-derived registry retains the typed `lifecycle:exit` effects, six protected-session-descriptor Host ABI routes, and ten supervisor-history discovery/read/write rows. The exact private constants `__ibex-session-worker-v1` / `private:ibex:session-worker-bootstrap:v1` produce one private, JavaScript-unreachable `terminal-session-control` row and fail classification if their evidence drifts. `addListener`, `listenerCount`, `listeners`, `off`, `on`, `once`, `prependListener`, `prependOnceListener`, `rawListeners`, `removeAllListeners`, and `removeListener` are closed by default and carry explicit no-effect `before-exit` / `exit` branches; `emit` and `emitWarning` remain wholly closed under `ipc:channel`, and `eventNames` remains wholly closed under `runtime:inspect` |
| `OBL-CLI-SURFACE` | `--history` rows on both spellings; the **keybinding manifest** (incl. `Ctrl+Z`) beside the command table | CLI surface manifest (LLP 0010) | **delivered** — root-owned `HistoryMode` accepts `--history` before `repl` and after the explicit `repl` spelling (`history_mode_is_root_owned_and_reaches_both_repl_spellings`), and the generated CLI inventory carries its option/default/enum rows. `runtime-surface.json#keybindingSurface` publishes Tab, `Ctrl+C`, `Ctrl+D`, `Ctrl+R`, and `Ctrl+Z`; `generate-repl-surface.mjs` validates their exact bytes and generates the Rust dispatcher/help projections used by `terminal_session.rs` |
| `OBL-LAUNCHER-SIGNALS` | Mediated interrupt propagation for launcher routes (`ibex run <bare-name>`, `--watch`): Ibex holds `SIGINT` while it waits on the child so `128 + signal` is real on `Ctrl+C`, rather than both dying of the group signal | this document + `src/bin/ibex/main.rs` | **delivered on Unix** — `LauncherInterrupt` is installed before child spawn; package scripts accept the foreground group's one SIGINT, wait for the real child status, and use bounded termination/reap plus controller status 130 only for the pre-spawn/still-live fallback. They never explicitly redeliver the group signal. Watch gives its already-signaled child a two-second direct-cleanup grace before TERM/kill fallback, reaps, and returns 130. `launcher_signal_mediation` proves package child delivery and both real controller routes; `watch_group_interrupt_grace_does_not_preempt_child_cleanup_with_sigterm` proves the watch grace with begin/finish/TERM markers in a real shell child. A public post-arming watch-child fixture remains honestly blocked by ENG-24933's empty advertisement set. Windows console-control mediation remains a platform-verification item rather than a POSIX-status claim |
| `OBL-FRESH-NONCE` | §7's control records authenticate with an **armed session nonce**. A nonce that is a fixed constant authenticates nothing — and note §7's own limit: authentication proves channel membership, not truthfulness | LLP 0021 / runtime | **delivered for production construction** — `prepare_embedder_artifacts` authenticates the template, replaces its reserved nonce with 16 bytes from the OS CSPRNG in `fresh_production_nonce`, recomputes the checked snapshot digest, and re-ingests the pair. `freshening_replaces_reserved_nonce_and_is_replay_distinct` proves two constructions differ and `freshening_binds_nonce_into_checked_digest` proves the digest binding. `ArmedSessionBinding::from_snapshot` requires the exact 16-byte nonce, and `frame_is_bound_to_exact_run_nonce_epoch_and_direction` proves the authenticated control frame refuses a different nonce. The schema remains only a shape check; freshness is a trusted-constructor invariant, not a claim that arbitrary supplied snapshot bytes become fresh |
| `OBL-INTERRUPT-MODEL` | The §6 transition data, its generator, and the model checker — checked in, digest-bound, CI-gated, with `interrupts_without_editor_input ≤ 3` and `promised_next_exit ⇒ next interrupt terminal` as checked temporal properties | this document + tooling | **delivered** — `session/interrupt-machine.v1.json`, `packages/ibex-devtools/src/scripts/generate-interrupt-machine.mjs`, and the generated dispatch/manifest/table/trajectories under `vendored-generated/` |
| `OBL-CONSTANTS-ANNEX` | `session/session-constants.v1.json` (§12) as a real, digest-bound file, cited by 0022 and 0024 rather than re-deferred | this document + tooling | **delivered** — strict schema at `session/schema/session-constants.schema.json`; deterministic generator/check at `packages/ibex-devtools/src/scripts/generate-session-constants.mjs`; Rust projection at `vendored-generated/session_constants.generated.rs` |
| `OBL-ENV-INVENTORY` | The §2 post-arming environment inventory as a named artifact with a schema, so an un-dispositioned variable fails the build | this document + tooling | **delivered** — canonical `capsec/registry/runtime-environment-inventory.json` (156 rows / 338 exact occurrences), strict `capsec/schema/runtime-environment-inventory.schema.json`, and `generate-runtime-environment-inventory.mjs` assign and check every static and dynamic occurrence. The checked projection has 32 post-arm host-read sites: 16 source-anchored effect-gated reads, ten armed-unreachable reads, and six test-only effect hooks. JavaScript reads are principal-overlay-only; full native enumeration is diagnostic-only; fixed compatibility and disk-fallback controls have no armed ambient fallback; subprocess scanners model default inheritance plus exact clearing/reconstruction; prohibited fixed controls fail even if reviewed; and package scripts plus generated-drift/conformance wiring make missing, moved, stale, or undispositioned occurrences build failures |
| `OBL-EDITOR-ASYNC` | A non-blocking editor integration. **This is a release gate, not a preference**: raw input must remain consumable while a completion producer is queued, executing, abandoned, or wedged | this document + tooling | **delivered on Unix at the authenticated adapter boundary** — `run_interactive_repl` owns the bounded raw-input lanes while `AsyncCompletionProducer` owns one capacity-one job lane, one capacity-one result lane, and no evaluator/Host authority. `production_editor_adapter_status` reports `BoundedAsynchronousCompletion`. `authenticated_interactive_adapter_consumes_ctrl_c_during_wedged_completion` uses a real PTY and complete authenticated interactive fixture: after an acknowledged test-owned wedge, the first byte prints the completion notice and redraws `foo.`, the second exits 130, and configurable termios state is restored. `authenticated_interactive_adapter_routes_external_sigint_during_wedged_completion` repeats that proof with real process-directed SIGINTs through the same generated ingress and excludes only the kernel-maintained transient `PENDIN` status bit from its restoration comparison. The tests are adapter-level because ENG-24933 still blocks honest public-binary target advertisement; Windows still needs the corresponding ConPTY fixture with processed input disabled |
| `OBL-LEDGER-CHECK` | Obligation-id machinery in `./ref-check` that recomputes each row's digest and **fails the build on a mismatch**, so this ledger becomes a control rather than a comment | process tooling | **open as ENG-25052** — `./ref-check` validates LLP metadata and `@ref` targets only; it has no obligation-table parser, digest recomputation, or stale-pin failure path. This document update does not turn prose into that control |

### 12. Constants

Bounds that are **user-visible and independent of the engine** are pinned **now**, with values, because a deterministic test clock makes a chosen bound *testable* but does not *choose* it —
and a conformance suite cannot assert a truncation marker it has not been given. An earlier draft claimed these were "pinned constants with a version" while supplying neither values nor an
artifact; that claim was simply false, and saying so is cheaper than leaving a reader to discover it.

They are normative **here and now**. The canonical file carrying them is
`session/session-constants.v1.json`, owned by this document and cited by the siblings rather
than re-deferred. Its strict schema is `session/schema/session-constants.schema.json`; the
deterministic generator embeds source, schema, and generator SHA-256 digests in
`vendored-generated/session_constants.generated.rs` and audits the Rust consumer and interrupt
status vocabulary for drift (`OBL-CONSTANTS-ANNEX`). The values below remain the contract.

| Constant | v1 value | on overflow |
| --- | --- | --- |
| renderer depth | 4 | truncate + marker |
| renderer breadth (entries per collection) | 128 | truncate + marker |
| renderer payload length (per string) | 10 000 Unicode scalar values | truncate + marker |
| truncation marker | `… +N more` | — |
| history entries retained | 10 000 | compact (drop oldest) |
| history bytes retained | 8 MiB | compact (drop oldest) |
| history record maximum size (bytes) | 1 MiB | **reject** the record; the session says so |
| broker queue bound, per destination (bytes) | 8 MiB | **backpressure** (never drop; §3) |
| display-tree maximum serialized size (bytes) | 16 MiB | render opaque + marker |
| broker flush budget | 500 ms | abandon + account (§3) |
| history-lock acquisition bound | 250 ms | skip persistence for that entry; say so |
| lifecycle-commit ACK bound | 2 s | worker exits 69 (§8) |
| reserved worker fatal disposition (commit unacknowledged) | exit status **69** | — |
| maximum live relays per session | 64 | refuse the 65th relay |
| maximum input size (bytes, per submitted input) | 1 MiB | **reject** the input; the session says so |

**Units and per-constant overflow are pinned too**, because "10 000 characters" is not a specification and "truncate everything" is wrong: renderer bounds truncate with the marker, but a history
record over its maximum is **rejected** (truncating a recalled command would be worse than dropping it), the broker's queue **backpressures** rather than drops (§3's lossless rule), and a display tree
over its size renders opaque. Each constant's overflow column above is normative.

These are revisable by bumping the annex version; they are not revisable by an implementation choosing differently. The budgets whose right values genuinely depend on the **cancellation
prototype** remain open — the shutdown drain, the cancellation budget, the completion budget, and the async-storm coalescing window — and v1 records each as explicitly unbound. The annex pins
the renderer/wire-format as little-endian **IBDX v1**, including field widths and node tags. Everything else user-visible and engine-independent — the flush budget, the history-lock bound, and maximum input size included, since they depend
on I/O or parse cost and not on Hermes — is pinned above, and **every criterion that depends on a budget runs against a deterministic test clock**, so conformance does not wait even on the open ones.

## Acceptance criteria

Fixtures are generated from the surface registry. The Unix editor/interrupt boundary now has an authenticated
**adapter-level PTY** fixture. That is real terminal evidence but not a claim that the advertised public binary target
is complete: ENG-24933 still blocks that product-surface route. Windows requires the parallel ConPTY fixture with
`ENABLE_PROCESSED_INPUT` cleared. Signal tests using null stdin and piped outputs cannot substitute for either PTY gate;
they are the correct topology for one-shot and direct-file execution, which own no editor or PTY.

1. **fd 0, per mode.** In every session mode, every fd-0 route observes the EOF view (or the typed denial where Node throws) — for root and package alike. In one-shot and file execution,
   `echo data | ibex -e '…'` reads `data`. The route table is verified to be *generated*.
2. **fd 1/2, protected class, terminal facts.** `close(1)`/`close(2)` are no-ops; `dup2` onto 0/1/2 is refused. **No numeric descriptor API can name or operate on a control, relay, or
   watchdog handle, for any principal — including a guessed integer.** `process.stdout.isTTY` and dimensions reflect `stdio:query`; **dimensions change after `SIGWINCH`**;
   `process.stdin.isTTY` is `false` at an interactive prompt; no startup configuration value is readable from JavaScript.
3. **No post-arming fallback for fixed startup inputs.** The inventory records
   fixed compatibility and presentation inputs as pre-arm launcher reads followed
   by snapshot/configuration-field consumption, never as permitted environment
   reads after arming; changing one of those fixed host variables after snapshot
   finalization has no effect. An un-dispositioned variable fails the build.
   Principal-overlay access is exercised separately and never falls through to
   the host environment. Separately enumerated runtime host facts remain reachable
   only behind their typed effect decision (or are proved armed-unreachable), as
   §2 states; this criterion does not misclassify an authorized DNS, system-info,
   or child-spawn read as fixed startup configuration.
4. **Terminal safety.** Every runtime-authored surface — value, error, stack frame, source excerpt, async report, completion candidate, live edit buffer, recalled history entry, **and the
   prompt override** — containing `ESC`, CSI, OSC, **APC or DCS** (single-byte C1 and UTF-8) renders escaped; bidi overrides and U+2028/2029 are escaped in displayed values too. A **hostile
   display tree** (unknown kind, invalid UTF-8, over-deep, over-wide, unknown version) renders safely. **A hostile tree cannot select a session-decoration style** — the kind→style codomain is
   asserted disjoint.
5. **Color.** Transcript emits no session-authored ANSI even with force-color, while program ANSI passes through byte-for-byte; `NO_COLOR` beats `CLICOLOR_FORCE`; editor control still emits with
   color off.
6. **The broker.** Program output emitted during an evaluation precedes that evaluation's result **because the barrier drains each relay to its own cutoff** — asserted with **unequal relay volumes
   and one relay deliberately lagging**. An async report never lands inside a prompt. With stdout a stalled pipe and stderr a TTY, an interrupt notice still prints and program output is
   **backpressured, not dropped — in `ibex -e` and file execution as well as the REPL**. Forced termination **reports what was lost**; when every destination is stalled, the exit status carries it.
   `$_` updates only after the result's barrier completes with a **`Displayed`** disposition — a **malformed, unknown-version, or over-size** display tree renders a fallback and completes its barrier as `Fallback` **without** updating `$_` (it stays at its prior value); with the **console writer thread paused between enqueue and fd write**, a lifecycle exit still emits the enqueued output (its counter was reserved at enqueue). **A spawned child's output is relayed, not inherited**, and lands in **relay-acceptance order** — a byte a child wrote before a barrier but that the relay had not yet accepted may land after the result, and the fixture asserts that achievable order, not the unobservable write order.
7. **Interruption under a PTY.** The machine is **generated from the transition data** (`OBL-INTERRUPT-MODEL`) and both invariants are **model-checked against an adversarial scheduler** over the
   event alphabet (interrupt, editor-input-at-prompt, typed-ahead byte, submit, dispatch, unit begin/end, suspend, settle, quiescence, **promise-set/clear, cause-latch**). The two properties are the
   **textually identical** ones stated in §6: `interrupts_without_editor_input ≤ 3`, and `(promised ∧ no_editor_input_since) ⇒ the next interrupt is terminal, with the promised status class unless a cause
   latched in the interim`. Exhaustive **trajectory** enumeration — not frozen tuples — asserts **at most three consecutive interrupts end the session from every reachable state**, and **two whenever the
   first press printed a promise** (every idle and running-work row). The named adversarial schedules are the five that falsified the five prior hand-written versions, and each is a fixture: **(a)** a tight
   `setInterval` storm whose callbacks individually complete — two presses; **(b)** a *gappy* storm (`busyWork(500)` every 1000 ms) where presses alternate callback/gap, flipping target — **two** (press 1
   prints a promise; press 2 honors it whatever it now targets), never three; **(c)** typed-ahead arriving between two presses during a runaway evaluation — the credit is not reset and the second press
   still terminates; **(d)** `editing` with a completion query executing and a background callback ready, where the query ends between presses — **two** (press 1 prints a promise; press 2 honors it though
   the query has ended and the buffer is now the target); **(e)** the round-8 killer — press 1 editing (no promise), press 2 idle sets an `Orderly` promise, a timer becomes due, **press 3 takes the promised
   `Orderly` status, not a target-derived 130** (the deleted-latch fix), and the dual, an `Interrupt(130)` promise honored as 130 after the work finishes. Further: a wedged **completion query** from a
   non-empty buffer exits in **two** with the **buffer preserved**; an input **suspended at top-level `await`** is **escapable in two** (the interrupt promises but raises no request) with notice `work is in
   flight`, not `cancelling`; code compiled **without async-break checks** exits in two; a **stale target id** is discarded rather than landing on the next unit; **an operator who resumes typing
   after a promise was printed does not have their session ended by a later `Ctrl+C`** (editor input cleared the promise); a session holding a **not-yet-due repeating timer** is quiescent, so `Ctrl+C Ctrl+C`
   there is an **orderly** exit, not 130; two terminal `Ctrl+C` bytes within one quantum are two interrupts; and the terminal is raw with `ISIG` off while the engine is busy. Further named schedules:
   **(f)** typed-ahead drained into a republished prompt does **not** reset the credit or promise; **(g)** three presses at an idle prompt — press 2 begins an orderly shutdown, press 3 **expedites with the
   same status**, never 130 (cause precedence); **(h)** a `Ctrl+C` promise `Interrupt(130)` latched, then a **root `process.exit(7)`** before the next press — the next press ends the session (notice kept)
   with status **7**, the cause superseding the promise's status but not its termination; **(i)** an interrupt while an input is suspended at `await` *and* a background callback executes selects the
   **executing** unit; **(j)** the **undispatched-submission** row also prints no promise, so from it three presses are needed (discard → idle promise → terminate) — a fixture asserts three, matching the editing row; **(k)** a `CompletionQueued` (dispatched, not begun) interrupt raises **no** request and its notice is `work is in flight`, while an `Executing` completion query raises the id-exact request — the two are distinct fixtures; **(l)** §8's status table is asserted to agree with §6 on trajectory (e): the credit-3 press takes the promised `Orderly`, not a target-derived 130; **(m)** an **idle prompt whose only live unit is a `CompletionQueued`** (a global Tab-complete at an empty prompt) — the interrupt abandons it and takes the **idle-prompt** path (`Orderly`), never `Interrupt(130)`, and this is asserted single-valued against both rule 4 and the idle-work row; **(n)** **two simultaneous due-but-not-begun timers** are distinct `Due{sched}` members and the machine determines after one begins whether another remains due (requires the due/undue publication seam of `OBL-UNIT-PUBLICATION`). The Unix authenticated adapter PTY test starts an acknowledged deliberately wedged completion, consumes a `Ctrl+C` byte, prints `cancelling completion`, redraws `foo.` without `^C`, then exits 130 on the second byte and proves termios was restored before child exit. For editorless direct execution, `direct_engine_execution_sigint_flushes_and_exits_130_without_engine_cooperation` starts separate one-shot and direct-file processes, proves each remains inside real Hermes `while(true){}` after a brokered readiness record, sends one real SIGINT, observes status 130 rather than kernel-default signal death, and verifies that the pre-interrupt record survived bounded broker close. Public-binary and Windows ConPTY evidence retain the scoped residuals above.
8. **Restoration.** Cooked mode and cursor visibility after every ordinary process-controlled exit path — orderly, EOF, cooperative, fatal, worker death, `SIGTERM`, `SIGHUP`,
   `SIGQUIT`, and suspend/resume via **both** the `Ctrl+Z` **byte** and an external `SIGTSTP`; a handler-only forced engine fault such as `SIGSEGV` guarantees cooked mode but not cosmetic writes. Restoration precedes a deliberately stalled flush. A supervisor `SIGKILL` leaves **no orphaned worker**, and the
   watchdog fires while the worker is stuck holding the FFI lock.
9. **Lifecycle.** Root `process.exit(7)` exits 7 with the terminal restored, and code after the call — **including a `finally` block** — does not run; `console.log("bye"); process.exit(0)` **emits `bye`**
   (the record carries the cutoffs); `process.on('exit', fn)` **registers without throwing, is diagnosed once, never fires, and is absent from `listeners()`/`listenerCount()`**; manual `emit('exit')` is
   closed; a root-scheduled timer may exit while a package-scheduled one may not; `process.exit(256)` is observed as 0 on POSIX. **A due timer running `process.exitCode = 7; while(true){}` after an `Orderly` promise exits 7** — the setter mirrored the value to the supervisor synchronously, so the wedge cannot lose it. **The idempotent commit is asserted on both branches**: with the record
   **accepted but its ACK lost**, the worker exits 69 **and the supervisor completes a cooperative exit `n`** because it holds the record; with **no record accepted by the deadline**, the worker exits 69 and
   the supervisor reports the code lost and takes the fault status — never an unexplained crash, and never a successful `n` it cannot substantiate. **The mode × failure-class matrix is asserted end to end** — an
   unhandled rejection exits 1 in program mode and does not end an interactive session. **Status precedence is asserted**: an interrupt termination whose flush loses bytes still exits 130, not 141; a
   *successful* exit that loses bytes with no destination to report on exits 141. The status table is asserted, `SIGQUIT` included. **Restoration precedes flush on every path**, asserted with a deliberately
   stalled destination.
10. **Bracketed paste** enters the buffer inertly. The keybinding manifest and `.help` agree, `Ctrl+Z` included.
11. **History.** 0600 in a pinned per-platform root with **no cwd fallback**; a pre-existing 0644 file is **refused**; key and check publish as one record by **no-clobber** create, and **two concurrent
    first-run sessions end with one key and both sessions' entries recallable**; an unreadable key degrades without rotating; entries are on disk immediately after submission and survive `SIGKILL`; a
    **multiline entry round-trips**; **a torn tail truncates to the last valid record rather than discarding the history**; compaction concurrent with another session's appends loses no accepted entry; a
    lock held past its bound degrades that entry rather than blocking the prompt; keyed by `ProjectHistoryScopeId`, a second project sees none of the first's entries, a directory recreated at the same path
    starts fresh where a creation generation exists, and two worktrees do not share; **the worker holds no history-scope token, and no history *data, scope identity, or token* crosses the control channel** — history is entirely supervisor-owned; the §9 root-equality proof crosses only a fresh-nonce-keyed digest that names nothing outliving the challenge; modes without an editor
    leave it untouched.
12. **Registry.** No route admits an fd-0 read in a session mode for any principal; `lifecycle:exit` is typed and root-only with separate request/getter/setter dispositions; listener aliases carry the
    no-effect branch; history-store and worker-bootstrap surfaces are classified; the native hard-exit op is absent; a new unclassified stdio or lifecycle surface fails the build.

## Consequences

- No JavaScript path can steal the operator's terminal input, and the control channel is not merely obscure but structurally unreachable. `process.stdin.isTTY` is `false` at a prompt — a deliberate divergence,
  and the honest report of a stream JavaScript cannot read.
- Terminal-injection escaping covers every runtime-authored path, **including the prompt override**, which is environment-sourced and therefore untrusted. The unstyled tree is the trust boundary; a hostile
  producer can render as a value but never as session UI.
- No runaway work — evaluation, background callback, completion query, suspended `await`, or an unbroken succession of them — can wedge the session beyond three consecutive interrupts, **and every notice the
  session prints is true**. Both properties are **arithmetic, not case analysis** — an unconditional escape credit and an irrevocable typed promise — because **four** hand-written versions that
  tried to *derive* them were each falsified on review; the fifth, which simply *asserted* them, has now held three rounds.
- The broker promises per-destination order, per-relay cutoffs, and a control lane a stalled pipe cannot block — and it backpressures program output rather than dropping it, with forced-termination loss
  accounted rather than silent. A child at the prompt no longer inherits the terminal, which is a real capability removed in exchange for a real guarantee.
- JavaScript lifecycle exits are cooperative, root-only, and uncatchable **because the call parks** — needing no engine mechanism. `exit`/`beforeExit` never fire and are not stored; registration is a diagnosed
  no-op rather than a throw, so cleanup packages still import. Both are deliberate divergences from Node. The failure-fatality matrix this document owed its siblings is now stated.
- History becomes project-scoped, hardened, journaled, and appended at submission, under a **supervisor-owned identity that is deliberately not a VFS identity** — because reusing LLP 0023's record would have
  violated its worker-locality rule.
- The supervisor/worker architecture changes the process model. An in-process implementation remains possible against a conformance gate covering every guarantee.

## Open questions

1. **Which exact Hermes mechanism can cancel running work, and does it leave a reusable runtime?** `asyncTriggerTimeout()` is any-thread and documented as *terminating* the current execution, but takes **no target
   parameter**, so a check-then-trigger race can land on a successor unit; `AsyncDebuggerAPI::triggerInterrupt_TS()` takes a callback where an id could be checked, but is an **empty no-op stub unless Hermes is built
   with `HERMES_ENABLE_DEBUGGER`**. The prototype must settle: which mechanism; whether the break is catchable; the minimum **consistency check** distinguishing a reusable runtime from a merely-alive one; and whether it
   works for **Ibex-built bytecode**, which carries no async-break checks. Prototype before implementing the interruption guarantees. (The *lifecycle* exit no longer depends on this — §8 parks. Neither does the *escape* —
   the credit is arithmetic.)
2. Should `AsyncBreakCheckInEval = true` be pinned as a **normative arming requirement**? The escape does not depend on it (the credit and promise carry every case), but §6 leans on "Hermes emits break checks in eval'd code by default" — a default that can be turned off, weakening the *redundant* cancellation path. Making it non-optional costs one arming assertion.
3. **What is the Windows realization of the now-delivered asynchronous editor contract?** Unix no longer has the
   feasibility question: the production raw reader and capacity-one static producer satisfy §5 and the authenticated
   PTY fixture exercises the wedged-query trajectory. Windows still needs a ConPTY adapter and equivalent evidence with
   `ENABLE_PROCESSED_INPUT` cleared; the Unix result must not be projected across that platform boundary by assertion.
4. Is the worker a separate **process** or a thread? §7 specifies a process; the cost has not been measured.
5. Should `exit`/`beforeExit` listeners be admitted once a safe mechanism exists, or is never the right answer?
6. Should a second interrupt against a wedged worker **respawn** it — returning the operator to a live but empty prompt — rather than end the session? §6 does not adopt it: a prompt that silently forgot every binding is
   close to a lost session. A checkpointed session restorable *without replaying external effects* would change that calculus.
7. Should sessions default to **no** persistent history, for operators who consider any recall a risk?
8. Should the supervisor own the one-shot and file-execution modes too, for uniformity? §1 pins them in-process for v1, which keeps two lifecycle realizations alive. Relatedly: under a supervisor, what do `process.pid`,
   `ppid`, and process-group observables report — the worker or the session?
9. What are the **engine-dependent** budgets — shutdown drain, cancellation budget, completion budget, async-storm window? §12 pins every engine-independent constant now (the flush and history-lock bounds included); only these four wait on OQ 1's prototype.
10. *(Resolved by LLP 0024's work-unit / settlement-unit split.)* A callback that
    settles a suspended top-level `await` is a separate target-id-bearing work unit; the
    evaluation and callback participate in the same input settlement unit only for the
    eventual structured outcome. The suspended settlement itself is not a cancellation
    target.
11. What would a deliberate **PTY hand-off** to a child look like, given §3 now forbids inheriting the session's descriptors? A full-screen child at the prompt is a real capability this version removes.
12. Should the display tree, the supervisor event stream, and the framed transcript protocol be literally **one** versioned wire format, or should `session/session-constants.v1.json` continue to bind the shared constants and IBDX display tree while the other protocols version independently?
13. **Should a compromised native worker be contained, and at what platform cost?** §7 claims only stuck/crashed engines and hostile JavaScript behind intact mediation. A same-UID native
    process defeats the fd allowlist and knows the session nonce. Genuine containment needs per-platform sandboxing, credential separation, and process-tree denial — a real cost against a
    threat the initial profile may reasonably decline. Decide explicitly rather than by silence.
14. Does OSC 133 prompt marking warrant being on by default once terminals and agent tooling that consume it are common?
