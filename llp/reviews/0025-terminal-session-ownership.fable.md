# Reviews of LLP 0025 — Claude Fable family

Review artifacts for `llp/0025-terminal-session-ownership.spec.md`, per LLP 0005.
One `## Round N` section per round, appended, never overwritten.

## Round 1 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `5c86bb7897e4` (sha256, first 12 — content hash of the
on-disk file, not a Git object; the document is not yet committed)
**Redaction status:** none — the reviewer read the unredacted document, the
sibling corpus (LLP 0022/0023/0024), the governing LLPs (0021/0010/0006), and
the repository source tree.
**Independence:** The reviewer was spawned as a fresh subagent with no access to
this conversation, no access to the Codex reviewer's session or output, and was
instructed not to read anything under `llp/reviews/`. No prior review artifacts
for LLP 0025 existed at launch, so none could be read. The two reviewers ran
concurrently on the same revision and could not observe each other.
**Method:** Full read of the target and the sibling corpus; verification of
load-bearing claims against `src/bin/ibex/repl/mod.rs`, `main.rs`, `cli.rs`,
`src/bin/ibex/engine/{mod.rs,hermes.rs}`, `src/engine/hermes_runtime*.cc`,
`src/builtins/{fs.js,process.js}`, `src/host/abi.rs`, and `capsec/registry/`;
LLP 0005 standard question set; structured output with severity-rated concerns
and a readiness verdict.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle (rev 5c86bb7897e4, round 1)

## 1. Overall assessment

This is a strong, honest spec attacking exactly the right problem. Every one of the five motivating defects is real and I verified each in the code: the raw stdin bridge reads fd 0 directly (`src/engine/hermes_runtime_crypto.cc:5046-5055`), value display arrives as one pre-colored string that is printed unescaped (`src/bin/ibex/repl/mod.rs:63-65`, `:886-887`), the Engine trait has no cancellation operation and no async-break machinery exists anywhere in the engine layer (`src/bin/ibex/engine/mod.rs:22-98`; zero hits for AsyncBreak/TimeLimit in `src/engine/`), `process.exit` reaches a native `std::exit` with no principal check or terminal concern (`src/engine/hermes_runtime.cc:588-604`, `:1704-1727`), and history is one machine-global file (`src/bin/ibex/repl/mod.rs:583-600`). The document's distinctive virtue is refusing to promise what the engine cannot deliver — defining *accepted* cancellation by the evaluation actually returning, not by the break being raised, is the correct response to Hermes' catchable async break, and the second-interrupt escape correctly does not depend on engine cooperation.

The main faults are at the edges of the state machine and at the new document seams: the interrupt latch has a stale-arm defect in the defeated-cancellation and background-work cases, one-shot surfaces are claimed in scope but never given fd-0 or ownership rows, the registry consequences of "fd 0 is brokered on every route" are unstated (and the current registry contradicts it), the history keying rests on a persistent "object identity" no document defines, and sibling 0022 still states an interrupt behavior this document's table contradicts. All are fixable without changing the design's shape.

## 2. Strengths (with citations)

- **§1's pinned per-route fd-0 table** ("Two conforming implementations must not disagree about whether `fs.readSync(0)` returns EOF or throws") imports 0023's generated-table discipline and prevents the classic divergence where each route improvises. The route inventory (readv, FileHandle, dup, poll, retained aliases, raw bridges) is unusually complete; `fs.readSync` today passes any fd straight to the native (`src/builtins/fs.js:3614-3645`), so the brokering is genuinely load-bearing.
- **§1's separation of terminal facts (`stdio:query`) from startup configuration** dissolves a real self-contradiction — "never exposed to JavaScript" vs. `process.stdout.isTTY` must work — and the denied-query-reports-`isTTY:false` rule keeps feature detection alive. Today both come from raw `isatty()` (`src/engine/hermes_runtime_process_setup.cc:280-281, 308`), so the distinction is a real change, correctly identified.
- **§3's escaping threat model is right**: full C0/DEL/C1 *as code points in any encoding*, not just ESC/CSI/OSC; extended to the live edit buffer, reverse-search display, recalled history, and bidi/U+2028-9 spoofing. "Escaping first, color second" honestly gates a visible feature (colored inspection) on the structured seam instead of shipping the unfixable pre-colored-string design (verified as today's design at `repl/mod.rs:63-81`).
- **§6's defeated-cancellation honesty** — the mandatory notice worded to be "true in both outcomes," and *accepted* defined by return-plus-consistency-check — is exactly right given a catchable break, and the second-interrupt rule "cannot itself depend on the engine cooperating" is the correct invariant.
- **§8's cooperative exit is quietly Node-parity** (Node's `process.exit` also runs no further code and no `finally`), so the "uncatchable structured completion" costs little compatibility while removing package-initiated session termination — and the registry rows it reopens are confirmed closed today (`capsec/registry/coverage-edges.json`: `surface.native.op.exactexit.0qrcb1d`, `global:process.exit`, `global:process.exitCode`, all `closed`).
- **§9 is a threat-modeled history design**, not a checklist: HMAC-vs-bare-hash reasoning, no-follow 0600 open, refusal to migrate the legacy global file *with the reason stated*, and the leading-space convention correctly demoted to a convenience (it exists today: `history_ignore_space(true)`, `repl/mod.rs:667`).
- **§7/OQ1/OQ5 honesty**: the supervisor is named presumptive with a prototype gate rather than asserted, and OQ5 correctly names today's arbitrary constants — I verified both (COMPLETION_DISPATCH_TIMEOUT 5s, `repl/mod.rs:32`; EOF_DRAIN_BUDGET 200ms, `src/bin/ibex/engine/hermes.rs:204-210`).
- **§1's descriptor topology row for TTY-stdin/piped-stdout** (prompt to stderr, results to stdout) supports a real workflow almost every REPL spec forgets, and the single-broker treatment of the idle-pump/line-editor race names a real defect (the pump prints from the engine thread while the reader thread owns the prompt, `repl/mod.rs:769-776` vs `:679-698`).

## 3. Concerns

**C1. The interrupt latch goes stale after a defeated-but-completed evaluation — Material.**
Evidence: §6 clears the latch on "exactly three events: a submitted input, a completed evaluation whose cancellation was *accepted*, or an edit keystroke." A defeated request (user code swallows the break) never resolves; the evaluation later completes *normally*, its result is displayed, and the prompt redraws — with the latch still armed. The operator's next single Ctrl+C at that fresh prompt hits row 1's second column and the session exits (orderly shutdown), with no warning beyond a notice printed before the result scrolled past. The "whose cancellation was accepted" qualifier buys nothing: unavailable/defeated requests either leave the evaluation running (not completed) or end in a normal completion, so an unqualified "completed evaluation" covers every case the qualifier does, without the stale arm. Resolution criterion: either drop the qualifier (any completed evaluation clears), or explicitly specify and justify the defeated-then-completed case and add it to AC6; the current text does neither.

**C2. Row 2 (background callback) has no coherent latch exit and no defined cancellation semantics — Material.**
Evidence: §6 row 2 "request[s] cancellation of the background work," but none of the three clearing events can fire for it — background work is not "a completed evaluation," so even an *accepted* background cancellation leaves the latch armed and the next idle Ctrl+C exits the session (same stale-arm shape as C1). Row 2's notice text is also unspecified (rows 1 and 4 pin theirs), and what accepted/unavailable/failed *mean* for a timer callback is defined nowhere (see cross-document finding D3). Resolution criterion: a clearing rule reachable from row 2 (e.g., "background work completing or being cancelled clears the latch"), pinned notice text, and a definition (here or in 0024) of cancellation resolution for non-evaluation work.

**C3. One-shot surfaces are claimed in scope but given no fd-0 or ownership rows — Material.**
Evidence: §Scope says the document covers "the one-shot evaluation surfaces (whose rendering obligations are the same)," but the §1 fd-0 table has exactly three rows (interactive, transcript, program) and AC1 names no mode. `echo data | ibex -e '…'` reading stdin is a legitimate Node workflow that an EOF view would break; `ibex -e '…'` with a TTY stdin is simply unspecified. §8's lifecycle rules presumably bind one-shot (`-e`/`-p` today hard-exits via the same native path, `src/bin/ibex/main.rs:1325-1327`), but only OQ4 gestures at it. Resolution criterion: a fourth fd-0 row (or an explicit statement that one-shot stdin is unbrokered and why that is safe), a statement of which of §5/§6/§8 bind one-shot, and mode coverage in AC1/AC8.

**C4. "fd 0 is brokered on every route" contradicts the current registry, and the document has no registry-obligations section — Material.**
Evidence: `capsec/registry/coverage-edges.json` classifies `__exactStdinRead` (`surface.native.op.exactstdinread.1shskfd`) as an `effects` edge under `stdio:read` with `positiveSources: ["ambient-root", "handle", "static-floor"]` — i.e., the registry currently records a route by which ambient root *may* read fd 0; `stdio:read` and `stdio:raw` are `authorable` in `capability-definitions.json`. §1 makes that unsatisfiable in terminal-owning modes "for root and package callers alike," which is a per-mode narrowing the registry must express (mode-scoped branches or new rows), yet §8's single sentence about updating rows covers only the lifecycle surfaces. LLP 0023 §8 sets the precedent (an explicit "Registry obligations" section); 0025, which reopens *and* narrows more rows than 0023 does, lacks one, and LLP 0021's no-unclassified-surface invariant (property 6) demands it. Resolution criterion: a §Registry-obligations section enumerating the reopened lifecycle rows, the mode-scoped stdio rows (`stdio:read`/`stdio:raw` on stdin in session modes), the `stdio:query` per-principal rows, and a commitment to revise LLP 0021's reconciliation in the same change.

**C5. Project history identity is built on a persistent "object identity" that nothing defines, and identity recycling reopens the channel this section closes — Material.**
Evidence: §9 keys history on "the authenticated root's object identity" so renames keep history and recreation starts fresh. But LLP 0023 §2's identity is a *retained platform object* — live, per-runtime, not serializable across sessions. A cross-session key must be some serialization (presumably device+inode), and then: (a) a cross-filesystem move is copy+delete, so "renamed or moved keeps its history" is false for moves across volumes; (b) inode recycling lets an unrelated new project inherit a dead project's digest and therefore its history — precisely the cross-project disclosure §9 exists to close; (c) the HMAC key file's permissions and loss/regeneration behavior are unstated (the 0600 sentence covers "the file," i.e., the history file). Resolution criterion: define the persisted identity (e.g., device+inode+birth-time, or a verification record stored in the history file header checked on open, mismatch → fresh history), bound the "moved keeps history" claim to same-filesystem moves, and pin key-file permissions and key-loss behavior.

**C6. The Motivation misstates today's failure mode for Ctrl+C during a submitted evaluation — Minor/Non-blocking.**
Evidence: "an accidental `while(true){}` wedges the prompt permanently" / "a prompt only `kill -9` can clear" (§Summary, §Motivation). During a submitted evaluation the reader thread has left `readline()` (blocked in `control_rx.recv()`, `repl/mod.rs:691-697`), so the terminal is in cooked mode and no SIGINT handler exists on the REPL path (the only `tokio::signal::ctrl_c` is in `run_debug_loop`, `src/bin/ibex/main.rs:1089-1096`) — Ctrl+C kills the process via default SIGINT disposition: an *uncontrolled death losing unsaved history*, not a kill-9-only wedge. (The busy-background-callback case comes closer: the first ^C is swallowed as a raw-mode byte the busy engine loop never services, and the second kills the process.) The design conclusion is unaffected — today there is no *controlled* path — but a normative spec should not overstate its evidence. Resolution criterion: restate the current behavior accurately (uncontrolled SIGINT death, first-interrupt swallowing while a callback runs, lost history/cleanup).

**C7. §7 overstates what "an in-process design cannot" deliver — Minor/Non-blocking.**
Evidence: bullet 1 claims the supervisor uniquely delivers the second-interrupt guarantee "without leaving the terminal raw," but an in-process SIGINT handler can restore cooked mode and exit 130 async-signal-safely (`tcsetattr`, `write`, `_exit` are all on the POSIX async-signal-safe list) — it cannot save history or flush C++ streams, which row 4's second column notably does not promise. Bullets 2 (uncatchable engine death) and 4 (structural `std::exit` barrier) are the genuinely supervisor-only arguments. Resolution criterion: reword bullet 1 as a quality difference (no history save, no stream flush, handler-context fragility) rather than an impossibility, so the §7/OQ1 tradeoff is argued from accurate premises.

**C8. Cooperative-exit mechanics leave three observables unpinned — Minor/Non-blocking.**
Evidence: §8 — (a) "A second request while one is in flight is ignored": ignored *how*? If it returns undefined to the caller (an `exit` listener), then code after *that* `process.exit` call runs, a deliberate exception to "no code after the call runs" that should be stated; (b) "admitted `exit` listeners" — admitted for which principals, under which registry row?; (c) running exit listeners requires re-entering the engine from inside the exit request delivered mid-evaluation — legal under JSI nested invocation, but the spec should say the request is serviced at the session layer, not inside the evaluation's native frame. Resolution criterion: pin all three (AC8 currently tests none of them).

**C9. EPIPE termination is unscoped and diverges from Node without saying so — Minor/Non-blocking.**
Evidence: §1 "A broken output pipe (`EPIPE`) on stdout terminates the session… rather than raising into JavaScript" does not say whether it covers program-authored writes (Node surfaces EPIPE to JS streams; today's native `process.stdout.write` loop throws a JSError on write failure, `hermes_runtime_process_setup.cc:260-263`). Terminating the session when the *results* stream dies is right; terminating because package code wrote to a broken pipe is a compat divergence that should be recorded under 0022's compatibility priorities. No AC covers EPIPE or the stderr-prompt topology row at all. Resolution criterion: scope the rule (session-authored writes vs all stdout writes), record the divergence, add topology/EPIPE acceptance coverage.

**C10. The broker's total order plus backpressure implies cross-destination head-of-line blocking, and it silently overrides LLP 0006's drop policy — Minor/Non-blocking.**
Evidence: §3 requires one broker that "applies backpressure, and preserves submission order" with destination as metadata. When stdout is a stalled pipe and stderr is the live TTY, a total order means a blocked stdout event stalls async reports and prompt redraw (arguably acceptable for a REPL — but it should be chosen, not implied). Separately, program `console.*` today rides a bounded queue that *drops* under backpressure by design (LLP 0006 "Degrade diagnostics, never the caller"; `src/host/abi.rs:157-225`) — routing it through a blocking broker in session modes reverses that principle for this context and should say so. Resolution criterion: one paragraph pinning ordering scope (global vs per-destination) under stall, and an explicit note that session modes supersede the console queue's drop policy.

**C11. State-machine edges left unspecified: shutdown phase, SIGTERM status, empty-submission latch effect — Minor/Non-blocking.**
Evidence: §6's phase enum includes **shutdown** but the table has no shutdown row (what does Ctrl+C during the §8 drain budget do — expedite?); "On `SIGTERM` the session attempts an orderly shutdown and exits promptly regardless" pins no exit status (143 vs orderly code); and whether an empty Enter at an armed-latch idle prompt is "a submitted input" (clearing) is ambiguous. Also §6's prose says the latch "is cleared by exactly three events" while the editing-row cell says "**clear latch**" — harmlessly redundant (the latch is provably already clear when that row is reachable), but "exactly three" plus a fourth table clear is sloppy in a spec that asks to be read this closely. Resolution criterion: a shutdown-phase row (or an explicit "interrupts during shutdown expedite exit"), a SIGTERM status, and reconciled latch wording.

**C12. `process.stdin.isTTY === false` in interactive mode is a real compat divergence the document doesn't surface — Minor/Non-blocking.**
Evidence: §1's interactive fd-0 view is a "non-TTY stream," so the standard `process.stdin.isTTY && process.stdout.isTTY` interactivity idiom reports false at an interactive prompt (Node reports true). It is arguably the *honest* view — JS cannot read the terminal, so advertising non-TTY steers libraries correctly — but it belongs in Consequences (and 0022's compat-priority ledger), not left for implementers to discover. Resolution criterion: one sentence in §1 or Consequences recording the divergence and its rationale.

## 4. Cross-document findings

**D1. Contradiction with LLP 0022 §10 (Material, amend 0022).** 0022 §10: "a second consecutive interrupt **always** ends the session (exit 130)." 0025 §6: a second interrupt at idle causes *orderly shutdown* (§8: exits with root-set `process.exitCode`, else 0 — not 130), and a second interrupt after an editing/continuation discard is "(a fresh first interrupt)" — not an exit at all. 0022's own governance clause ("the mechanism document governs its own layer and this one is amended") makes the fix direction clear, but the seam is currently contradictory and 0022's AC-facing summary would test the wrong behavior.

**D2. Contradiction with LLP 0024 §6's outcome enumeration (Material, amend 0024).** 0024 §6 normatively states a cancellation request "yields **one of**" accepted / unavailable / failed. 0025 §6 normatively adds "— **or not at all**" (the defeated case), and builds the latch design on it. 0024 concedes non-resolution only in OQ3; its normative §6 must be amended to admit the defeated/never-resolves case, or the two documents disagree about whether the evaluator is obligated to resolve every request.

**D3. Dangling dependency: background-work cancellation (Material).** 0025 §6 row 2 "request[s] cancellation of the background work," citing nothing; 0024 §6 defines cancellation resolution only for *an evaluation* (its outcomes are evaluation outcomes; §7 publication rules are per-input). Neither document says what accepted/unavailable/failed means for a timer or completion callback, nor how it interacts with 0024 §9's async-failure envelope if cancellation lands mid-callback.

**D4. Dangling dependency: persistent project identity (Material, same as C5).** 0025 §9's cross-session "object identity" has no definition in 0023 (whose identity tuple is live and per-runtime, §2/§5) or anywhere else in the corpus.

**D5. Duplicated normative territory: post-arming environment silence (Minor).** 0024 §6/AC9 and 0025 §2/AC3 both own the rule and both enumerate the same variables (await-unwrap timeout, transform config, engine tracing/fallback). Worse, they differ in strength: 0024 *retires* the await-unwrap timeout outright ("no hidden result timeout"), while 0025 §2's "captured pre-arming or is a fixed, versioned constant" phrasing would permit a pre-arming-captured timeout that 0024 forbids. One document should own the inventory (0024 owns evaluation knobs; 0025 should cite rather than restate), and 0025's list should not imply a captured await-unwrap timeout is conforming. (The variable is real and read at evaluation time today: `hermes_runtime.cc:3090`.)

**D6. Two miscitations of 0022 §2 (Minor).** 0025 §1 "Mode selection (LLP 0022 §2)" and §3 "the transcript-mode serialization checkpoint (LLP 0022 §2)" — both live in 0022 **§3** (Input modes). In a corpus this cross-referential, the seam citations should be checked mechanically.

**Positive seam checks that hold:** fd-0 EOF view ↔ 0022 §3's "presents end-of-file to prompt and package code alike"; checkpoint-as-broker-flush ↔ 0022 §3; escaping-before-color and structured pieces ↔ 0024 §8 and its Consequences; cancelled-outcome publication ↔ 0024 §7; presentation-config capture ↔ 0022 §2; `--history` manifest obligation ↔ LLP 0010 (and `Commands::Repl` is indeed optionless today, `src/bin/ibex/cli.rs:228`).

## 5. Suggestions

- **Simplify the latch to fix C1/C2**: arm the latch with a *referent* (the evaluation ordinal or background-work identity it was armed against) and clear it when that referent ends, however it ends; keep the idle-armed flag separate, cleared by any keystroke or submission. This makes "second interrupt" mean "second against the same stuck thing," which is what the operator means, and removes the accepted/defeated asymmetry entirely.
- **Give the worker a fresh PTY pair under §7**: if the supervisor allocates a PTY (or socketpair) for the worker's fds 1/2, program `console.*` and raw native writes become broker *inputs structurally* — no re-plumbing of the native write loop (`hermes_runtime_process_setup.cc:230-278`) — and the §3 ordering guarantee falls out of the event stream rather than requiring every write path to be converted. This also strengthens §7's case with a benefit the in-process design genuinely cannot mimic.
- **Unify the supervisor wire format with the transcript framed protocol** (0022 OQ4 already gestures at this) and say so in §7, so the two cannot drift and the transcript checkpoint becomes literally an event-stream flush.
- **History identity**: store a small authenticated header in each history file (HMAC of the identity it was created for); on open, recompute and compare — a recycled inode then yields a mismatch and a fresh history instead of inherited entries. This converts C5's hardest case into a self-healing one.
- **Add the missing acceptance coverage**: descriptor topology row 2 (prompt on stderr, results on stdout), EPIPE termination, SIGTERM, interrupt-during-shutdown, the latch's not-cleared-by-time property, and — once decided — the defeated-then-completed case.
- **Record the two deliberate compat divergences** (`process.stdin.isTTY === false` interactively; session-terminating EPIPE if that scoping is chosen) in Consequences and in 0022's compatibility-priority frame.
- Consider stating in §8 that in-process conformance for the uncatchable exit may be achieved by the native lifecycle call *never returning to JavaScript* (session cleanup hook, then exit) — it heads off an implementer reaching for a catchable JS throw, which cannot satisfy AC8's `finally` clause.

## 6. Open questions

1. Should a *defeated* cancellation whose evaluation later completes normally clear the latch (C1)? If not, is a single-Ctrl+C session exit at a fresh prompt really intended, and does the printed notice adequately license it?
2. What do accepted/unavailable/failed mean for background work (C2/D3), and which document owns that definition — 0024's evaluator contract or this one?
3. Are one-shot surfaces' stdin reads unbrokered (preserving `echo data | ibex -e` workflows), and if so, what confines them when stdin is the operator's TTY (C3, OQ4)?
4. How is persistent project identity serialized and verified across sessions, and what happens on identity recycling and cross-filesystem moves (C5/D4)?
5. Under a stalled non-TTY destination, does the broker preserve one global order (head-of-line blocking) or per-destination order (C10)?
6. What are the observable semantics of a second `process.exit` while one is in flight, and which principals' `exit` listeners are "admitted" (C8)?
7. Should the registry express the session-mode stdio narrowing as mode-scoped logical branches on the existing `stdio:read`/`stdio:raw` edges, or as distinct session-mode rows (C4) — and does LLP 0021 need a revision entry when its closed lifecycle rows are reopened under scope?

## 7. Readiness verdict

Material concerns C1–C5 (interrupt-latch correctness, background-cancellation semantics, one-shot scope, registry obligations, history identity) and cross-document findings D1–D4 are unresolved; the design direction is sound and none of these threaten its shape, but a normative Spec whose sibling contradicts its interrupt contract and whose central state machine has a reachable stale-latch defect is not yet done.

VERDICT: NOT READY

### Orchestrator verification notes

Spot-checks of the decisive claims, against the repository at the reviewed revision:

- **C4 registry claim — CONFIRMED.** `capsec/registry/coverage-edges.json` carries
  `surface.native.op.exactstdinread.1shskfd` as an `effects` edge under
  `stdio:read` with `positiveSources: ["ambient-root", "handle", "static-floor"]`,
  and `capability-definitions.json` lists `stdio:read`/`stdio:raw`/`stdio:query`
  as `authorable`. The registry does today admit an ambient-root read of fd 0,
  which §1 must narrow per mode. Accepted; a Registry-obligations section was added.
- **C6 "no SIGINT handler on the REPL path" — CONFIRMED.** The only
  `tokio::signal::ctrl_c` is at `src/bin/ibex/main.rs:1091`, inside the debug
  loop. The REPL's reader thread blocks on `control_rx.recv()`
  (`src/bin/ibex/repl/mod.rs:691-697`) while an evaluation runs, so the terminal
  is in cooked mode and default SIGINT disposition kills the process. The
  document's "wedges the prompt permanently / only `kill -9` can clear it" was
  therefore inaccurate about today's code. Accepted; the Motivation was rewritten.
- **C10 console drop policy — CONFIRMED.** `src/host/abi.rs` carries an explicit
  `@ref LLP 0006#degrade-diagnostics-never-the-caller` on the bounded console
  queue that "drops lines under" backpressure. Accepted; §3 now states that
  session modes supersede the drop policy for program output and reconciles with
  LLP 0006 explicitly.
- **C5 history identity — CONFIRMED as a real gap.** LLP 0023 §2's identity tuple
  is `(runtime, logical root, binding owner, normalized components, retained
  platform object)` — runtime-local and non-serializable. Nothing in the corpus
  defines a cross-session project identity. Accepted; §9 now defines the persisted
  identity record, its platform fallbacks, and its failure modes explicitly.
- **D6 miscitations — CONFIRMED.** LLP 0022 §2 is "Startup, project identity, and
  session arming"; mode selection and the transcript serialization checkpoint are
  both in 0022 §3 ("Input modes"). Both citations fixed.
- **D1/D2 sibling contradictions — CONFIRMED**, and reported rather than fixed
  (siblings are out of scope for this pass). 0022 §10's "a second consecutive
  interrupt always ends the session (exit 130)" is false for the idle row (which
  is an orderly shutdown honoring `process.exitCode`) and for the editing row
  (which never exits). 0024 §6's "yields **one of**" enumeration excludes the
  never-resolving case that 0024's own OQ3 concedes.
- **C1/C2 latch staleness — CONFIRMED by construction** and accepted. §6 was
  rebuilt around an interrupt *target*, with clearing on the target ending by any
  route, which dissolves both.
- **C7 — ACCEPTED.** `tcsetattr`/`write`/`_exit` are async-signal-safe, so an
  in-process handler can restore the terminal and exit 130; what it cannot do is
  save history or flush. §7's bullet 1 was reworded, and §9 now appends history at
  submission time so that no exit path — including a signal handler — loses entries.
- **C12 — ACCEPTED** as a real, deliberate divergence; recorded in §1 and
  Consequences.
- **Reviewer's "catchable async break" framing — NOT ADOPTED.** This reviewer
  accepted the document's premise that a Hermes async break is a catchable throw.
  The concurrent Codex review challenged it, and the vendored headers support the
  challenge: `ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:184-186`
  documents `asyncTriggerTimeout()` as *terminating* the current execution, not as
  raising a catchable throw. The document no longer asserts catchability in either
  direction; see the Codex artifact's Round 1 notes.

## Round 2 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `184a46b3ebb2` (sha256, first 12 — content hash of the
on-disk file; the document is not yet committed)
**Redaction status:** none — unredacted document, sibling corpus, governing LLPs,
and the repository source tree, including the vendored Hermes headers.
**Independence:** Fresh subagent, no access to this conversation, no access to the
Codex reviewer's session or output. **Both Round 1 artifacts were moved out of
`llp/reviews/` before either Round 2 reviewer was launched and restored only after
both had returned**, so no reviewer could read the prior round's findings or the
other family's. The two reviewers ran concurrently on the same revision.
**Method:** Full read of the target and the sibling corpus (which had itself been
revised since Round 1); verification of load-bearing claims against the Rust CLI,
the Hermes bridge, the vendored Hermes headers, the builtins, `src/host/abi.rs`,
`runtime-surface.json`, and `capsec/registry/`; LLP 0005 standard question set.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle (rev. 184a46b3ebb2, round 2)

## 1. Overall assessment

This is a strong, unusually honest round-2 spec. The round-1 retraction of the Hermes-break premise was the right move, and the rebuilt document is engineered around it consistently: every guarantee that matters is stated so that it holds whether or not the engine cooperates, the supervisor is specified rather than presumed, and the in-process alternative gets a gate instead of a wink. The load-bearing factual claims check out against the code — I verified essentially all of them (details below), and found no fabricated or exaggerated claim about the current implementation. The §1 mode/topology split, the §3 display-IR trust boundary, the narrowed broker promise with a control lane, the uncatchable cooperative exit, and the §9 history design are all good decisions with correctly-pinned consequences.

The document is not ready, for one central reason and a few attendant ones: the §6 interrupt machine's **escape invariant, as bolded and as encoded in AC7, is false in a reachable state that the machine's own table creates** — and the section's own row-walk half-admits this while the invariant statement and the acceptance criterion deny it. An implementer cannot satisfy the table, the invariant, and AC7 simultaneously. The state machine also has a reachable (phase, origin) combination with no row, the §8 uncatchable unwind carries an engine-feasibility risk that the document's own prototype-first discipline (OQ1) covers for cancellation but not for lifecycle, and the new 0022/0025 seam has three genuine contradictions. All are repairable, most textually; the design core is sound.

## 2. Strengths

- **The engine-independence posture (§6, §7).** "A spec that assumes the break is uncatchable and is wrong has merely kept a redundant escape; one that assumes it is catchable and is wrong has promised an escape it cannot deliver" is exactly right, and I verified the asymmetry it rests on: `asyncTriggerTimeout()` is documented "terminates the current execution... any thread" (`ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:184-186`), `triggerInterrupt_TS` schedules a runtime-thread callback (`hermes/AsyncDebuggerAPI.h:132-137`), `AsyncBreakCheckInEval` defaults true (`hermes/Public/RuntimeConfig.h:63`) while `emitAsyncBreakCheck` defaults **false** for prepared bytecode (`hermes/CompileJS.h:44,78`). The observation that interruptibility is a property of how source was compiled, not of the engine, is correct and important.
- **Defining *accepted* by the evaluation actually returning (§6)** — never by a break having been raised — is the only honest definition given catchable breaks and `try{}catch{}` loops, and it composes correctly with latch rule 3's target-end clause.
- **§7's normative-invariants-plus-gate structure.** The premises are real: Hermes evaluation holds serialized runtime access inside a native call (`src/bin/ibex/engine/hermes.rs:485-498`, `ffi_lock` held for the whole of `ex_hermes_eval`, per the comment at :556-563), and the `Engine` trait has no cancellation operation of any kind (`src/bin/ibex/engine/mod.rs:22-99`). Naming the tempting failure — "prototype a Hermes interrupt, declare the architecture question closed, and inherit none of the rest" — and gating against it is high-quality decision hygiene.
- **§3's display IR as the trust boundary.** Correct diagnosis that a flat pre-colored string cannot be escaped ("escaping first, color second"), and the current code is exactly the anti-pattern: the REPL asks JS for `Exact.inspect(_val, {colors: true, ...})` and prints the returned string (`src/bin/ibex/repl/mod.rs:63-80, 884-897`). The full C0/DEL/C1-in-any-encoding rule, including the live edit buffer and recalled history, is more complete than most terminal-injection specs.
- **§9 history.** The threat model ("an adversary who observes file names but not contents") is stated precisely, the identity record's consequences are pinned rather than implied (including the file-id-reuse case that birth time exists to defeat), and the fallback's weaker guarantee is stated plainly. Append-at-submission is right, and the current implementation is exactly the failure it retires: one machine-global file (`repl/mod.rs:583-600`), entries added in memory per line (:684) but `save_history` only on orderly reader exit (:699) — lost by every termination this document exists to make survivable. The §7 tie-in ("removes the one item on that list a signal handler could never have delivered") is a genuinely good structural argument.
- **§10 registry obligations are accurate to the artifact.** I verified the rows: `__exactExit`, `global:process.exit`, `global:process.exit.__exactHostExit` are `closed` under `process:signal`; `global:process.exitCode` and `global:process._exactExiting` are `closed` under `runtime:inspect`; and `__exactStdinRead` is an `effects` edge under `stdio:read` with `positiveSources: [ambient-root, handle, static-floor]` (`capsec/registry/coverage-edges.json`, edge `surface.native.op.exactstdinread.1shskfd`) — i.e., the registry today really does record a route by which root may read fd 0, exactly as §10 says. The mode-scoped no-effect-branch remedy matches LLP 0021's `logicalBranches` discipline.
- **Motivation section is verifiably true.** No SIGINT handler on the REPL path (`main.rs:1333-1366`; the only `ctrl_c` handling is in `run_debug_loop`, :1089-1096); `Ctrl+C` is a rustyline keystroke (`repl/mod.rs:734-739` prints `^C` and continues); `__exactStdinRead` does `::read(0, ...)` directly (`src/engine/hermes_runtime_crypto.cc:5028-5073`); `process.exit` reaches `std::exit` via `exactHostExit` (`src/engine/hermes_runtime.cc:588-604, 1704-1727`); `closeSync` reaches the real descriptor with no 0/1/2 branch (`src/builtins/fs.js:3608-3612`).
- **§1's mode/topology split** and its exhaustive tables, the pinned-per-route EOF view (with the generated-table discipline argument borrowed from LLP 0023), and the honest `process.stdin.isTTY === false` divergence recorded in Consequences.
- **§2's live-facts carve-out** (dimensions under SIGWINCH) catches a real current defect: columns/rows are captured once at stream setup (`src/engine/hermes_runtime_process_setup.cc:284-289`).
- **OQ6's candor** about the arbitrary constants is verifiable: `COMPLETION_DISPATCH_TIMEOUT` is 5 s (`repl/mod.rs:32`) and `EOF_DRAIN_BUDGET` is 200 ms (`engine/hermes.rs:210`) — precisely the two values it names.
- **LLP 0010 discipline in §9**: root-level `--history` with stable clap ID, enumerated value shape, recorded default, manifest rows for both spellings — consistent with the manifest's actual structure (`runtime-surface.json`: root `ibex` has 28 options, `ibex repl` has 0 today).

## 3. Concerns

**C1. (Blocking) The escape invariant is false in a reachable state, and AC7 encodes the false form.**
Evidence: §6 invariant block ("From **any state** in which the engine is executing work that does not return, **two interrupts** end the session"); AC7 ("from **every engine-busy state**, at most two interrupts yield exit 130"); versus the editing/continuation row ("discard the buffered input... **never terminates** — the next interrupt is a fresh first interrupt") and §6's own row-walk, which concedes the extra press ("one interrupt returns it to idle **where the invariant applies**"). Walk it: state (editing, background callback stuck) — the engine is executing work that does not return. Press 1 → editing row: discard buffer, clear every latch. Press 2 → (idle, background callback): first interrupt, request cancellation, latch. Press 3 → exit 130. Two interrupts do not end the session; three do. The table, the invariant, and AC7 cannot all be satisfied. Compounding this, the **target definition does not cover the editing case at all**: "the target is the work it is trying to stop — the submitted evaluation, or the background callback — or... the idle prompt" makes the *callback* the target during (editing, bg-busy), yet the row and latch rule 3's third clause treat the *buffer* as what the interrupt was aimed at.
Resolution criterion: (a) restate the invariant with the true quantifier — e.g., "two interrupts **whose target is the stuck work** end the session" or "at most three interrupts from any state; at most two once the buffer is empty" — (b) align AC7's property with it, and (c) add the edit buffer as a named target (or state the target-precedence rule: buffer > running work > idle prompt) so the editing row is derivable from the target model rather than an exception to it.

**C2. (Material) The state triple has reachable combinations with no row.**
Evidence: §6 defines state as (editor phase, engine-busy origin, latch) with phase ∈ {idle, editing, continuation, evaluating, shutdown} and origin ∈ {free, submitted evaluation, background callback, completion query}, but the table's rows cover only five (phase, origin) shapes. An operator at a live idle prompt with a background callback running (the case the origin axis exists for) can type a line and submit it: the input is accepted but cannot start while the callback holds the engine. What phase is a queued-but-unstarted submission — evaluating? If so, (evaluating, background callback) is reachable and unrowed: is the interrupt's target the stuck callback or the not-yet-started input, does it latch, and is the queued input discarded? AC7's list of "rows a four-row table omits" names editing-with-background, completion-in-flight, and shutdown — but not this one.
Resolution criterion: enumerate the reachable (phase, origin) pairs explicitly (the document does exactly this for modes and topology; the machine deserves the same), define the phase of a queued submission, and specify its fate on interrupt and on session end.

**C3. (Material) §8's uncatchable unwind carries the same engine-feasibility risk as cancellation, but no open question or fallback owns it.**
Evidence: §8 requires that the native lifecycle call "never returns to JavaScript: the evaluation unwinds as a lifecycle completion," that `finally` does not intercept, **and** that admitted root `exit` listeners then run under the shutdown budget — i.e., the unwind must both skip JS handlers (so it cannot be a catchable JS throw, per the document's own rule) and leave the runtime usable enough to execute listener JavaScript afterward. That is precisely the "provably reusable runtime after a non-cooperative unwind" property OQ1 says must be prototyped before implementing the *interruption* guarantees — Hermes holds serialized runtime access inside the native call (`hermes.rs:485-498`), and a foreign C++ unwind through the interpreter, or a termination-style break, has unproven reusability semantics. §7's gate (e) covers the in-process case, but the supervisor does not dissolve this: the unwind and the listeners both happen inside the worker on the same runtime.
Resolution criterion: extend OQ1 (or add an OQ) to name the lifecycle-unwind mechanism and its runtime-reusability question, and add the normative fallback for an unprovable runtime after the unwind — e.g., skip remaining listeners and proceed to restoration and exit with code `n`, mirroring the failed-cancellation rule. Without the fallback, the listener provision can render a conforming implementation impossible on this engine.

**C4. (Material) §7's in-process gate item (b) is ambiguous between "hard" and "impossible by construction," and §5 leans the other way.**
Evidence: §5 states "Uncatchable terminations (`SIGKILL`, hard native crashes) are **outside any in-process guarantee** — which is one of §7's arguments," while gate (b) requires an in-process implementation to demonstrate "terminal restoration after an **uncatchable engine death**." If "uncatchable engine death" includes worker-SIGKILL-equivalents, the gate is unpassable by construction and the "conforming alternative" is rhetorical; if it means SEGV-class deaths (where an async-signal-safe handler can `tcsetattr` + `_exit`, which §7 itself concedes is achievable), §5's sentence overstates. A reader cannot tell whether in-process conformance is intended to be achievable.
Resolution criterion: define the death classes gate (b) covers, and state plainly whether the gate is expected to be passable on any advertised target or is deliberately the argument that ends the discussion.

**C5. (Material) "Session modes" is used normatively but never defined, and the drop-policy boundary it draws is unargued for the CLI's non-session modes.**
Evidence: §3 ("In **session modes** this supersedes the console queue's drop-under-backpressure policy") and Consequences bullet 4. The console queue really does drop program output under backpressure (`src/host/abi.rs:330-371`), and the CLI's file-execution and one-shot paths route `console.*` through that same queue — so `echo data | ibex -e '…' | slow-consumer` may silently lose program stdout, which is the same "data loss, not degradation" the section condemns. LLP 0006's liveness rationale is about embedded long-lived hosts, not a CLI pipeline. The Scope section binds "rendering, color, and lifecycle" to every mode but is silent on the broker's backpressure rule.
Resolution criterion: define "session modes" in §1's binding table (add a broker/backpressure column), and either extend no-drop to all CLI executions or record the decision to keep drops in file/one-shot mode with its rationale.

**C6. (Minor/Non-blocking) The non-coalescing requirement is unimplementable for the external-SIGINT route.**
Evidence: §6 ("an implementation that coalesces a signal storm must not collapse them") and AC7 ("Two presses within one quantum are two interrupts"), tested "for both a terminal-generated Ctrl+C and an external SIGINT." The kernel coalesces pending non-RT signals; two external SIGINTs delivered while the process hasn't yet been scheduled are one pending signal, and no implementation can recover the count. The guarantee is deliverable for the session-owned raw-mode byte route (two 0x03 bytes) and best-effort for external signals.
Resolution criterion: scope the two-in-one-quantum guarantee to terminal-generated interrupts; state external-SIGINT counting as best-effort.

**C7. (Minor/Non-blocking) History durability and key lifecycle have two unhandled races.**
(a) Compaction "atomic (write-new, then rename)" racing another session's `O_APPEND` writes loses the concurrent appends — defeating "no exit path can lose it" via a path that isn't an exit; AC11's "concurrent sessions cannot interleave partial lines" doesn't cover it. (b) "Missing **or unreadable** → a new key is generated" permanently orphans every history on a transient read failure, and concurrent first runs can both generate keys. Evidence: §9 compaction and key paragraphs; AC11.
Resolution criterion: require an exclusive lock (or single-compactor rule) around compaction; generate the key only on *missing* with `O_CREAT|O_EXCL` and re-read on `EEXIST`; make an *unreadable* key degrade that session to no-persistence with a diagnostic rather than rotating.

**C8. (Minor/Non-blocking) The `--history` usage error is TTY-state-dependent.**
Evidence: §9 ("Supplying it with a mode that keeps no history is a usage error"). Mode is selected by stdin at runtime (§1), so `ibex repl --history=project` succeeds at a terminal and fails in a CI pipe — the same command line, different validity. Aliases and scripts become TTY-sensitive.
Resolution criterion: either error only for persistence-requesting values while accepting `off` everywhere, or downgrade to a startup diagnostic; record the choice and its rationale.

**C9. (Minor/Non-blocking) SIGQUIT is undispositioned.**
Evidence: §8's status table lists SIGINT/SIGTERM/SIGHUP/SIGPIPE; §5 restores on "every signal in §8's status table." Ctrl+\ (SIGQUIT, default: core dump) therefore leaves the terminal raw through a catchable, process-controlled-in-principle path — the exact defect class §5 calls out.
Resolution criterion: add a SIGQUIT row (restore then re-raise default, or handle like SIGTERM) or an explicit exclusion with rationale.

**C10. (Minor/Non-blocking) Broker and supervisor precision.**
(a) "One total order holds across both, which is what the operator actually sees" (§3) reads as promising that program cross-stream write order (stdout write then stderr write) survives to the terminal; two worker pipes cannot deliver that, and a plain terminal (shared open file description) does. Either promise it — one shared descriptor for fds 1/2 when both resolve to the same terminal — or state that the merged order may not preserve the program's cross-destination order. (b) §7's "fd-0 ownership becomes an OS fact" and "every program write becomes a broker input structurally" slightly overstate: §1's `close`/`dup2` refusals on descriptors 0–2 must still be enforced *inside the worker* (a worker-side `close(1)` severs its socketpair end and lets the next `open` capture the descriptor), so the supervisor discharges the read-ownership rule structurally but not the whole of §1. (c) In §1's "Terminate" semantics, whether the process waits (bounded) for the requested cancellation before exiting 130 is unstated. (d) Which registry row owns *stdin* tty queries in session modes — the fd-0 EOF-view branch or the `stdio:query` row — should be pinned, since LLP 0021 requires exactly one classification per surface.
Resolution criterion: one clarifying sentence each.

**C11. (Minor/Non-blocking) History record framing for multiline entries is unspecified.**
Evidence: §9 promises entry-level append atomicity, bounds, and no partial-line interleaving, but multiline inputs contain newlines and no record encoding is pinned (escaped, length-framed, or otherwise). rustyline's current format does not round-trip multiline entries.
Resolution criterion: pin the on-disk record encoding as part of the format the fixtures assert.

## 4. Cross-document findings

The 0022/0025 seam has real contradictions (0022's own Precedence rule calls this "an invalid corpus state... resolved by a coordinated revision of both"):

1. **0022 §10 vs. target §6 (contradiction).** 0022 §10: "a second consecutive interrupt **always ends the session**." The target's editing/continuation row *never* terminates, and its second interrupt is "a fresh first interrupt" — two consecutive interrupts starting from editing do not end the session (the target itself notes "a blanket 'a second interrupt always exits 130' is false of this machine"). 0022 §10 needs the same nuance.
2. **0022 §10 vs. target §9 (contradiction).** 0022 §10: `process.exit(n)` "restores the terminal **and saves history**." The target retires save-at-exit entirely — "History needs no exit-path step at all (§9)," "§8's shutdown budget has no history work to do." The save step 0022 names no longer exists.
3. **0022 §11 ledger drift (stale characterization + broken pointer).** The ledger's final row calls the second-interrupt escape "**architecturally open** — AC 4's interrupt cases are conditional on that decision." Round 2 made the invariants normative and explicitly independent of the architecture ("neither interrupt depends on the engine, the worker, or JavaScript cooperating"; §7: "The invariants are normative. The architecture is how you get them"). Also "AC 4" matches neither document's numbering (0022 AC4 is Modes; the interrupt criteria are 0025 AC7).
4. **0024 OQ3 vs. target §6 (factual-claim drift).** 0024 OQ3 asserts flatly that "a Hermes-style async break surfaces as a **catchable** JavaScript throw"; the target deliberately retracts exactly that assertion ("this document deliberately does not assert whether a Hermes async break is catchable" — OQ1). Since 0024 §6 is being amended in the same change anyway, soften OQ3 in that amendment.
5. **The LLP 0024 §6 amendment is handled honestly** (per the review instruction, not a defect): the target names it explicitly in §6 ("amended in the same change to admit both the unresolved case and the non-evaluation target") and §8 (fifth "lifecycle completion" outcome), and 0022 §11's ledger carries the lifecycle-outcome row. Note, though, that the *unresolved-cancellation* and *background-callback-target* amendments live only in target prose — no ledger row anywhere carries them, so they are the likeliest obligation to silently drop.
6. **0023: no contradiction found.** The target correctly distinguishes its cross-session identity record from 0023 §2's live retained platform identity, and says why the latter cannot key a file that outlives the process. The generated-table discipline references are consistent.
7. **0021: reopenings are properly declared** (§10 names the reconciliation entries in the same change; I verified the current closed rows and the `__exactStdinRead` `effects`/`ambient-root` edge match the target's description exactly). One unnamed schema question: a "mode-scoped no-effect branch" selects on an *arming/mode* fact, while 0021's `logicalBranches` selection facts are produced from argument/resource normalization — the branch-selection vocabulary may itself need a 0021 schema extension, which the target does not call out.
8. **No harmful duplication found.** §2 restates 0024's env-silence rule only to mark the difference in strength (retire vs. capture) — good seam hygiene; §1's mode table cites 0022 §3 as the selection authority rather than duplicating it.

## 5. Suggestions

- **Generate the §6 machine as data.** Encode states × events → (action, latch-op, notice, exit) as a machine-readable transition table; derive the implementation dispatch, the property tests, and the document's rendered table from it. This is the corpus's own discipline (0023's observables table, 0022's command manifest) applied to the artifact where a hand-walked quantifier just failed — it would have caught C1 and C2 mechanically, and AC7's property test becomes exhaustive enumeration rather than sampling.
- **One prototype, two answers.** Make the OQ1 prototype exercise the §8 lifecycle unwind alongside cancellation (same mechanism candidates, same reusability question), so the two riskiest engine facts are settled together before either is implemented.
- **Consider making the editing-row interrupt also deliver a cancellation request to running work** (while still discarding the buffer and not latching). That would restore the strong two-press invariant from every state at the cost of a slightly less pure "you aimed at your buffer" story — worth weighing before weakening the invariant text instead.
- **Key-check sidecar:** store `HMAC(K_user, "check")` next to the key so a wrong/rotated key is distinguishable from a corrupt history file; combine with the unreadable-key-degrades-to-off rule (C7).
- **Shared descriptor when destinations coincide:** under the supervisor, when stdout and stderr both resolve to the session terminal, give the worker one duplicated descriptor pair so program cross-stream ordering is kernel-preserved; use two pipes only when destinations differ (where no cross-order promise is needed).
- **Bidi scope:** consider extending the U+202A–U+202E/U+2066–U+2069/U+2028/U+2029 handling from "runtime-authored diagnostics" to displayed values (spoofable strings appear in inspected data too, e.g. filenames), or record why value display renders them verbatim.
- Add a short **dependency ledger** (0022 §11 style) or at minimum a single list of the obligations this document places on 0021/0022/0024, so the unresolved-cancellation amendment and the reconciliation entries cannot drop (finding 4.5, 4.7).

## 6. Open questions

Beyond the document's own eight (which are the right ones — OQ1 especially):

1. What is the phase of a submitted-but-unstarted input while a background callback holds the engine, and what does an interrupt do to it? (C2)
2. Is the §7 in-process gate intended to be passable on any advertised target, or is it a deliberate tombstone? The answer changes how much effort the gate's fixture set deserves. (C4)
3. Can the §8 unwind leave a Hermes runtime that is provably consistent enough to run exit listeners — and if not, do listeners silently become supervisor-mode-only? (C3)
4. Does the no-drop backpressure rule extend to CLI file execution and one-shots, where the console queue can drop program stdout today? (C5)
5. On Windows, what precisely is "restoration" (console mode flags, VT processing state), and can the ConPTY harness assert it with the same strength as `tcgetattr`?
6. Should the interrupt-during-`Terminate` path wait (bounded) for the cancellation it requests before exiting 130, or exit immediately under the flush budget? (C10c)

## 7. Readiness verdict

The design is sound and the honesty discipline is exemplary, but the spec's central provable property is misstated against its own transition table and acceptance criterion (C1), the machine is not exhaustive over its declared state space (C2), one normative §8 requirement lacks the feasibility ownership the document demands elsewhere (C3), a load-bearing conformance-gate clause is ambiguous (C4), an undefined term draws a data-loss boundary (C5), and the new seam has live contradictions with 0022 (§10 twice) and a factual-claim drift with 0024 OQ3. All have small, concrete fixes; until they land, an implementer or a sibling reader can follow this corpus into a wrong build.

VERDICT: NOT READY

### Orchestrator verification notes

- **C1 (blocking) — CONFIRMED, and independently found by the Codex reviewer in the
  same round.** The defect is mine, introduced in the Round 1 revision. From
  `(editing, background callback stuck)` the editing row spends the first interrupt
  on the buffer, so exit takes three presses, not two — while the invariant said
  "any state" and AC7 said "every engine-busy state". Accepted in full. §6 was
  rebuilt: the **edit buffer is now a named target** with an explicit
  target-selection rule, the invariant is restated truthfully (two interrupts
  against the same running work; **at most three** from any state), and AC7 now
  tests that form. The buffer-first rule is *kept* deliberately, and the document
  now says why: making the editing-row interrupt target the running work instead
  would mean an operator who pressed Ctrl+C to clear a typo, while a benign
  callback happened to be on-stack, could end their session on the next press. One
  extra press in a rare state is a better trade than a session-ending surprise in a
  common one. The reviewer's own suggestion 3 offered that alternative and I
  rejected it for this reason.
- **C2 — CONFIRMED and accepted.** `(evaluating, background callback still holding
  the engine)` is reachable and had no row. §6 now defines the phase of a submitted
  input as *evaluating from submission*, adds the row, and specifies that the
  interrupt targets the work actually executing and discards the not-yet-started
  submission.
- **The reviewer's completion-query claim was too kind, and the Codex reviewer
  caught what this one missed.** This document had said a completion query "is
  never an interrupt target ... and is never a reason to end a session." That is
  unsafe: today's member completion evaluates the base expression via
  `Function('return (' + __expr + ')')()` (`src/bin/ibex/repl/mod.rs:295-296`), and
  its 5-second budget is a `recv_timeout` on the *editor* thread
  (`src/bin/ibex/repl/mod.rs:256`) — it releases the editor, not the engine. A
  wedged completion query is therefore unescapable under the rule as written. §6
  now makes a completion query **killable work**: it is abandoned by an interrupt,
  and if the engine is still executing it, it is running work for the escape
  invariant.
- **C3 — CONFIRMED and resolved more decisively than the reviewer proposed.**
  Rather than add a fallback for an unprovable runtime after the lifecycle unwind,
  **v1 no longer admits JavaScript `exit` listeners at all.** With no JavaScript to
  run after the unwind, the exit path needs no reusable runtime, and the
  requirement becomes provable rather than merely gated. This is the same discipline
  the document applies to colored inspection and rich display: ship the inert,
  provable thing; add the feature when the mechanism exists. The process-event
  registry rows accordingly stay closed, which also dissolves the Codex reviewer's
  concern 10.
- **C4 — CONFIRMED.** §5 and §7 gate (b) did contradict each other. §7 now defines
  the death classes: the gate covers faults the process can still observe (a handler
  runs); `SIGKILL` and stack-corrupted deaths are outside any in-process guarantee
  and are the supervisor's alone. The gate is passable in principle, and the
  document now says so.
- **C5 — CONFIRMED and accepted, with the boundary drawn the other way from the
  reviewer's first option.** "Session mode" is now defined in §1, and the no-drop
  rule is extended to **every CLI execution mode**, not just session modes: silently
  dropping a program's stdout in `ibex -e … | slow-consumer` is data loss wherever it
  happens. LLP 0006's drop policy remains correct for the embedded long-lived host it
  was written for (`src/host/abi.rs:324-337`, whose own comment names the Xcode-console
  stall it exists to avoid).
- **C6, C7, C8, C9, C10, C11 — all CONFIRMED and accepted**, with one refinement: the
  key rule now creates only on *missing* (`O_CREAT|O_EXCL`, loser re-reads), and an
  *unreadable* key degrades that session to no persistence with a diagnostic rather
  than rotating — rotating on a transient read error would orphan every history the
  user has, which is worse than the failure it was guarding.
- **Cross-document findings 1–4 — CONFIRMED as sibling defects and reported, not
  fixed** (siblings are out of scope for this pass). The siblings were revised
  concurrently by parallel refinement runs, so the corpus moved under this document
  mid-round: LLP 0022 §10 has *already* absorbed the idle-versus-work exit-status
  split, and LLP 0024 §6 has *already* grown the fourth "defeated (unresolved)"
  outcome — which resolves the Round 1 cross-document finding. What remains is listed
  in the final report.
- **Finding 7 (0021 branch-selection vocabulary) — ACCEPTED**, and now named in §10:
  a mode-scoped branch selects on an arming fact rather than on argument or resource
  normalization, so LLP 0021's branch-selection vocabulary may need extending, and
  that extension is part of this change.

## Round 3 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `5001c0098469` (sha256, first 12 — content hash of the
on-disk file; the document is not yet committed)
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex
reviewer. **All Round 1 and Round 2 artifacts were moved out of `llp/reviews/`
before either Round 3 reviewer was launched and restored only after both had
returned.** The two reviewers ran concurrently on the same revision.
**Method:** Full read of the target and the sibling corpus; verification of
load-bearing claims against the Rust CLI, the Hermes bridge, the vendored Hermes
headers, the builtins, `src/host/abi.rs`, `capsec/registry/`, `runtime-surface.json`,
and `tests/signal_handling.rs`; LLP 0005 standard question set.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle (round 3, rev 5001c0098469)

## 1. Overall assessment

This is a strong, unusually honest spec. Its distinguishing virtue is that every load-bearing empirical claim I checked against the tree is true: the completion budget really is a 5s `recv_timeout` on the editor thread that releases the editor and never the engine (`src/bin/ibex/repl/mod.rs:32`, `:247-259`); member completion really evaluates its base through `Function('return (' + expr + ')')()` on the engine thread (`repl/mod.rs:296-297`); there really is no SIGINT handler on the REPL path — `Ctrl+C` is `ReadlineError::Interrupted` at an idle prompt and default disposition during evaluation (`repl/mod.rs:734-739`); history really is one machine-global file saved at exit (`repl/mod.rs:583-600`, `:699`); `process.exit` really reaches `std::exit` (`src/engine/hermes_runtime.cc:588-604`); `__exactStdinRead` really is `::read(0, …)` installed from two translation units (`hermes_runtime_crypto.cc:5028-5073`, `hermes_runtime_crypto_windows.cc:428-436`); `closeSync` really has no branch for fds 0/1/2 (`src/builtins/fs.js:3608-3612`); the `Engine` trait really has no cancellation operation (`src/bin/ibex/engine/mod.rs:22-99`); the eval FFI really holds `ffi_lock` for the whole native call (`hermes.rs:490`, `:545`, `:556-563`); Ibex's `hermesc` invocation really passes no break-check flag (`hermes.rs:1837-1847`) while `AsyncBreakCheckInEval` defaults true (`hermes-headers/hermes/Public/RuntimeConfig.h:62-63`); both Hermes interrupt mechanisms exist with exactly the documented semantics (`hermes-interfaces.h:183-186`; `AsyncDebuggerAPI.h:133-137`, including the "exactly once" note §6 leans on); the console queue really drops under backpressure (`src/host/abi.rs:330-371`); the registry rows are exactly as §10 describes them (`capsec/registry/coverage-edges.json`: `global:process.exit` closed under `process:signal`, `exitCode`/`_exactExiting` closed under `runtime:inspect`, `__exactStdinRead` an `effects` edge under `stdio:read` with `positiveSources: ["ambient-root", …]`); `ibex repl` records no options (`runtime-surface.json` `"path": "ibex repl"`, `cli.rs:228`); and the existing signal tests use null stdin and piped outputs (`tests/signal_handling.rs:76-78`).

The major decisions — pinned per-route EOF view, the tree-not-string renderer, the supervisor-with-gate posture, v1 without exit listeners, submission-time project-scoped history — are all defensible and mostly right. However, the document's centerpiece, §6's escape invariant, is **false again**, in two reachable trajectories the round-2 rebuild did not close: a typed-ahead buffer interacting with the not-yet-started-submission row yields a four-press sequence, and background-work turnover makes the interrupt escape unboundable while the mandated notice becomes untrue. Because AC7's property test as specified (static state enumeration, wedged work) would catch neither, this is a blocking correctness defect in the exact property the document exists to prove. There is also a real cross-document contradiction with LLP 0024 §8 about the display IR, and the §11 ledger has already drifted in the way LLP 0022 §11 predicts unchecked ledgers do.

## 2. Strengths

- **§6's work-identity discipline is genuinely needed and correctly derived.** Monotonic target ids, id-carrying cancellation requests, and stale-request discard are motivated by a documented engine fact (`AsyncDebuggerAPI.h:134`: callbacks run "exactly once", queued), not invented ceremony. The three defeat modes are each verified real (no break checks in `hermesc` output, hermes.rs:1837-1847; catchable-throw swallowing; non-returning native), and defining *accepted* by "returned + consistency check" rather than "break raised" is the only honest definition available before OQ1.
- **§6's deliberate agnosticism about break catchability** ("a spec that assumes the break is uncatchable and is wrong has merely kept a redundant escape…") is exactly the right asymmetry argument, and 0024 §6 mirrors it.
- **§8's v1-no-listeners decision is the right one** (see Concern 9 for one edge). Deferral is better than gating: it converts the uncatchable exit from "provable only after OQ1's prototype" into "provable today, because no JavaScript runs after the unwind," and it keeps the registry rows closed rather than half-open. The rejection of a "background-attributed" principal is also correct — it would be a second, weaker attribution model layered over LLP 0021's strata (0021:325-347).
- **§7's normative-invariants-plus-gate posture** is the best available decision structure: the supervisor is specified (with the correct process-group rule — a worker in the foreground group *does* die on the kernel's group delivery), while the in-process gate (a)–(e) is complete enough that passing it means having built all the guarantees, not one. The explicit "what the supervisor does not do for free" paragraph (relay framing, authenticated control lane, §1 enforcement still inside the worker) preempts the most likely implementation shortcut.
- **§3's broker contract is scoped to what is keepable** — per-destination order, the one-open-file-description trick for cross-stream program order, a control lane that a stalled pipe cannot block, barriers-not-hope, and display acknowledgement at barrier completion (which is the only reading under which `$_` is never a lie; 0024 §7.8 agrees). The supersession of the console queue's drop policy is argued precisely against LLP 0006's actual principle and its actual embedded-host rationale (0006:136-146) — supersede for the CLI, keep for the embedded host — which is model reasoning about a Principles doc.
- **§9's threat model is stated with rare precision** — the HMAC defends against filename observers, explicitly not content readers — and the identity-record consequences (rename keeps, cross-volume fresh, recreate-at-path fresh under birth times, worktrees separate) are pinned rather than implied. Never-rotate-on-unreadable is the right call. Append-at-submission removing all exit-path history work is the correct structural move and is honestly motivated by the shipping save-at-exit behavior (`repl/mod.rs:699`).
- **§1's mode/topology split** fixes a real conflation, and the pinned per-route EOF table (generated, joined to the registry) plus the honest `isTTY === false` divergence are the right calls; the stderr-editor topology row makes `ibex repl > out.txt` a supported workflow rather than an accident.
- **Acceptance criteria are unusually executable**: PTY/ConPTY, `tcgetattr` assertions, stalled-pipe-with-TTY-stderr, SIGWINCH, hostile display trees, compaction-vs-append races, stale-id discard, two-bytes-one-quantum.

## 3. Concerns

**C1. (Blocking) The §6 escape invariant is false as stated — two reachable counterexamples.** Evidence: §6's invariant ("From **any** reachable state, **at most three** interrupts end the session", doc lines 505-509) against the machine's own rules.
  - *(a) Typed-ahead × row 5 → four presses.* Reachable state: a submission is queued behind a running background callback W (phase **evaluating**, origin **background callback**), and the operator has typed ahead (§6 explicitly lets keystrokes accumulate during evaluating, line 451-452). Press 1 (row 5, line 459): discards the not-yet-started submission, latches W — but nothing discards the typed-ahead, so the phase becomes **editing**. Press 2 (selection rule 2, line 445-446): targets **the buffer** and **"clear[s] every latch"** (row 3, line 457) — the W latch is destroyed. Press 3: re-latches W. Press 4: exits 130. Four consecutive interrupts, no intervening input. The invariant's own rationale ("an interrupt taken while the … buffer is non-empty spends itself on that buffer, and every interrupt after it targets the work") assumes the buffer press comes *first*; here it comes second and resets progress.
  - *(b) Background-work turnover → unbounded.* Latch rule 3's first clause (lines 480-482) clears the latch when the latched target ends "by any route," including ordinary completion. Under `setInterval(f, 0)` with f taking ~50-200ms, each press latches the current callback C_n; C_n completes before the next press; the latch clears; the next press latches C_{n+1} as a *first* interrupt. No number of presses ends the session, and the mandated notice — "cancelling <what> — **press Ctrl+C again to end the session**" (line 457) — is false every time, in a document that elsewhere insists the notice "must be true in both outcomes" (lines 524-527). (The operator can still escape via `.exit`/Ctrl+D, so this is not a hard wedge — but the stated invariant, and the notice, are wrong.)
  - AC7's property test would catch neither: (a) requires buffer *content* not represented in the (phase, origin, latch) triple; (b) requires the target to *end and be replaced* between presses, while AC7 tests against work that never returns.
  - *Resolution criterion:* either fix the machine or restate the invariant, and extend AC7 either way. Concrete machine fixes that preserve the id-exact cancellation discipline (which is the part that must be per-unit): for (a), pin that an interrupt taken in the **evaluating** phase also discards the typed-ahead buffer (or that row 3's latch-clearing spares a latch on still-running work); for (b), clear a work latch on target end **only if the engine is then free**, or latch the *busy condition* (a busy-epoch/generation that survives same-class work turnover) for session-end purposes while cancellation requests keep per-unit ids. AC7 must add trajectory tests: typed-ahead present at each row, and an interval-storm turnover case asserting a bounded press count.

**C2. (Material) The §6 table has an undefined reachable cell: (evaluating, engine free).** The phase is defined as "a submitted input is in flight, **whether or not the engine has started it**" (line 423); origin `free` is a legal value; the combination is reachable in the window between a background callback finishing and the queued submission starting (and between submit and pickup). Selection rule 1 targets "the work the engine is executing" — nothing — and row 5 requires "earlier work still holds the engine" (line 459). AC7 promises exhaustive enumeration of the (phase, origin, latch) space, which will hit this undefined cell. *Resolution:* add the row (obvious content: discard the not-yet-started submission, no cancellation to raise, fall through to buffer/idle handling), and pin the disposition of typed-ahead when an evaluation ends, is cancelled, or is discarded — currently an unpinned observable.

**C3. (Material) The §11 ledger has already drifted and is not mechanically checked.** The row "Lifecycle-request evaluation outcome … LLP 0024 §6 | **not yet** — outcomes are empty/value/throw/cancelled" (line 871) is **false**: 0024 §6's outcome table carries the fifth **lifecycle** outcome today (0024:506, added by its round-2 revision explicitly "the fifth lifecycle outcome LLP 0025 §8 requires"), and 0024 AC18 asserts "outcome tags (**five**, including lifecycle)" (0024:1317). The row "Cancellation raised against a non-evaluation target … | not yet — the outcome vocabulary is evaluation-shaped" (line 872) is half-false: 0024 §6 already covers background callbacks ("Cancellation also targets background work", 0024:629-633; AC17), leaving only the completion-query target and the target id undelivered. Meanwhile LLP 0022 §11 mandates, for exactly this instrument, that "an uncheckable ledger is a comment" and requires stable obligation IDs verified by `./ref-check` (0022:745-754) — the target's ledger has neither, and `ref-check` today contains no obligation machinery. The drift this round proves the point. *Resolution:* correct the two rows, adopt the obligation-ID + `ref-check` join discipline (or state explicitly why this ledger is exempt), and add the missing row from C4.

**C4. (Material, cross-document — also listed in §4 below) The display-IR contradiction with 0024 §8 is live and un-rowed.** Target §3: the renderer's input is 0024's tree, which "carries no styling"; the tree is "versioned and serializable"; the walk runs in the worker and "the session layer — which holds no JavaScript value at all — escapes, **styles**, and writes" (lines 251-279) — i.e., the *tree* crosses and styling attaches supervisor-side, which is the only arrangement coherent with §7's hostile-worker premise and §3's own hostile-tree handling. 0024 §8 instead says "LLP 0025 §3 pins the **display IR** — the versioned, serializable form carrying **trusted style and layout tokens** from a closed enum alongside those untrusted payload spans" and "**only the IR crosses**" the process boundary (0024:1085-1096). Those are two different pipelines: 0024 has trusted style tokens serialized from the worker side (untrustable under §7), and it defers an "IR" definition to a §3 that defines no such thing. The target's ledger row 1 ("Display tree … | LLP 0024 §8 | **yes**", line 867) marks this delivered without surfacing the conflict. *Resolution:* reconcile in a coordinated revision (0022 §Precedence calls this an invalid corpus state): either 0024 drops the style-token IR and adopts tree-crossing/supervisor-styling, or the target defines the IR and explains how style tokens from a worker are trustworthy; and §11 gains a row tracking it until it lands.

**C5. (Minor/Non-blocking) §9's key-creation race is half-pinned and never-rotate makes a torn key permanent.** The spec pins `O_EXCL` create with the loser re-reading the winner's key (lines 780-787), but a loser can read the winner's file *before the key bytes are written* (create and write are not atomic), and a winner crash mid-write leaves a permanently invalid key that — under the (correct) never-rotate rule — degrades every future session forever. *Resolution:* pin atomic materialization (write to a temp name, `link(2)`/rename into place, or create under the same lock file compaction uses) so a visible key file is always complete; state that a reader treating a malformed key file as "unreadable" degrades without rotating, and name the operator remedy.

**C6. (Minor/Non-blocking) §9's append/compaction locking prose is internally ambiguous, and inode-bound locks don't survive the rename.** Three clauses coexist: small records are "a single `O_APPEND` write" (no lock mentioned); a large record "is written under the same exclusive lock compaction uses"; compaction "takes an exclusive lock **that appenders also take**" (lines 720-733). If all appenders lock, the large-record special case is redundant; if only large ones do, a small `O_APPEND` append races the compactor's rename into the unlinked-inode loss the section itself warns about. Also, a lock on the history file itself is inode-bound and does not exclude across the compactor's rename; the protocol needs a stable lock file plus reopen-and-verify. AC11 pins the observable, but the text claims to pin the mechanism and doesn't. *Resolution:* one crisp protocol (e.g., shared lock for every append on a stable lock file, exclusive for compaction, `O_APPEND` for interleaving; appenders re-verify identity after acquiring).

**C7. (Minor/Non-blocking) §7's signal design omits job control and worker lifetime.** With the worker in its own process group, `SIGTSTP` stops only the supervisor: background work keeps running while the operator has shelled out, and nothing states whether the supervisor forwards stop/continue to the worker group (§5 covers editor state on SIGCONT only, lines 396-399). Symmetrically, nothing binds the worker's lifetime to the supervisor's — after a supervisor `SIGKILL` (which §5 correctly excludes from restoration), a worker spinning in `while(true){}` is orphaned at 100% CPU. §7 says signal and process-group disposition "is part of the design, not an implementation detail" (lines 606-611); these two dispositions belong to that same status. *Resolution:* one paragraph pinning SIGTSTP/SIGCONT forwarding and a worker-death-on-supervisor-death mechanism (kill-on-relay-EOF at minimum; `PR_SET_PDEATHSIG`/kqueue as platform strengtheners).

**C8. (Minor/Non-blocking) §3's total-order clause is narrower than its own mechanism.** "When stdout and stderr resolve to the **same terminal**, one total order holds" (lines 309-315) — the one-open-file-description argument applies equally to `ibex repl 2>&1 | tee` (same *pipe*). As written, the promise silently lapses for the same-destination-non-terminal case the mechanism covers. *Resolution:* say "same destination (one open file description)".

**C9. (Minor/Non-blocking) The compat cost of denying `process.on('exit')` is undiscussed.** §8/§10 keep process-event registration closed and AC9 requires "registering one is denied." A typed *throwing* denial on `process.on('exit', …)` will break extremely common packages (cleanup/graceful-shutdown libraries) at import time, in every mode — a much wider blast radius than the REPL. The decision may still be right (honest refusal over a listener that never fires), but a spec this careful about divergences (`isTTY`, `$_`, Bun's `const`) should record this one and its shape (throw vs. once-diagnosed denial). *Resolution:* a sentence in §8 and a Consequences bullet acknowledging and pinning the denial's observable shape.

**C10. (Minor/Non-blocking) Two small overstatements.** (i) §7's "the async control path cannot enter a runtime stuck in synchronous JavaScript" is overbroad against §6's own premise that eval-compiled code carries break checks by default (RuntimeConfig.h:63) — `triggerInterrupt_TS` *can* enter such a runtime at a check; the true claim is about Ibex's current seam (no cancellation op; `ffi_lock` held across the native call, hermes.rs:490/545). (ii) §3 describes 0022 §11's ack row as "unstated on both sides"; 0022 row 17 actually says "partly — 0024 specifies the ack; 0025 has no ack lane" (0022:774). Also unpinned: exit-status masking for `process.exit(n)` with n outside 0–255. *Resolution:* wording fixes; pin the masking rule.

## 4. Cross-document findings

- **Contradiction (Material): display IR vs. display tree** — see C4. 0024 §8 defers a style-token-bearing, boundary-crossing "display IR" to 0025 §3 (0024:1085-1096); 0025 §3 defines a styleless tree that crosses, with styling attached supervisor-side (0025:251-279). One of the two pipelines must win; the hostile-worker premise of 0025 §7 argues for the target's.
- **Stale target ledger rows (Material)** — see C3: 0024 §6 already delivers the lifecycle outcome (0024:506, AC18) and background-callback cancellation (0024:629-633, AC17); target §11 rows say "not yet."
- **Sibling defect: LLP 0022 §10 is incompletely realigned to round-3 §6.** It enumerates latchable targets as "a still-latched evaluation or background callback" (0022:725-726), omitting the **completion query** that the target's round-2 revision promoted to killable work, and it never states the three-press bound its own buffer-interrupt sentence implies. Its lead phrase "from any state in which the engine is executing work that does not return, two interrupts end the session" survives only via the same-target qualifier a hurried reader will miss — and under C1(b) even the qualified form needs the turnover fix.
- **Sibling defect: LLP 0022 §11 rows 16 and 17 are stale** ("outcomes are empty/value/throw/cancelled" — false against current 0024; "0025 has no ack lane" — false against target §3's barrier-completion acknowledgement; 0022:773-774). Ironic given 0022 §11 is the document that mandates the mechanical check; `ref-check` contains no obligation machinery yet.
- **Minor ownership mismatch on the post-arming environment inventory:** 0024 §6 says "LLP 0025 §2 owns that inventory and its capture" (0024:589-590); target §2 claims only "the presentation rows" of a shared inventory (lines 227-233). Decide who owns the single inventory document and say the same thing in both.
- **Dangling-dependency hygiene otherwise good:** the remaining §11 rows check out against reality — `ibex repl` genuinely records no options (runtime-surface.json; cli.rs:228), LLP 0021's `logicalBranches` genuinely select only on post-normalization argument/resource facts (0021:184-192), and the reconciliation artifact exists to gain the entries (`capsec/registry/legacy-capability-reconciliation.json`). §5's keybinding manifest discharges 0022 ledger row 19 in substance, but the target never says *where* the manifest lives (presumably 0010's runtime-surface manifest, alongside 0022's `replSurface`) — worth a §11 row.

## 5. Suggestions

- **Fix C1 structurally, not rhetorically.** The cleanest repair preserving the design's spirit: cancellation *requests* stay id-exact (that part is forced by the exactly-once queue), but the *latch* clears on target end **only when the engine is free at that moment** — equivalently, a latch armed against background-class work covers any same-class work that begins while the engine has been continuously busy. This keeps the round-2 rationale (a latch must not survive into a healthy idle prompt) while making the second press reachable under turnover. Pair it with typed-ahead discard on evaluating-phase interrupts for C1(a).
- **State the raw-mode commitment.** §6's byte-level non-coalescing promise ("two interrupt bytes on a descriptor the session owns") implicitly requires the session to hold the terminal in raw/ISIG-off mode *while the engine is busy*, not just while editing. One sentence in §5 or §6 would keep an implementer from running busy phases in cooked mode and silently converting the promise into signal semantics.
- **Make the worker-death path a broker event.** §5 asserts restoration after worker death and §3 has a control lane; connect them — the supervisor synthesizes a structured, sequence-numbered "engine fault" event on worker death, so transcripts and tooling see the death in-order rather than inferring it from a truncated stream.
- **Seed the one wire format with the display tree now (OQ8).** §3 already pins the hostile-input rules, versioning, and bounds; declaring the tree chapter one of the §7 wire format costs little and prevents the three-format drift the document itself fears.
- **History records could carry `(session id, monotonic index)`** — cheap at format-pinning time, and it makes compaction dedup and any future merge/inspection tooling tractable. Also consider naming the OS-credential-store strengthening as a pinned optional profile rather than a parenthetical.
- **Record the `process.on('exit')` denial shape** (C9) and, if the throw is kept, say so in Consequences with the same candor as the `isTTY` divergence.

## 6. Open questions

Beyond the document's own OQ list (which is good — OQ1's single-prototype framing and OQ7's properties-here/values-there split are exactly right):

1. What is the disposition of the typed-ahead buffer when an evaluation ends, is cancelled, or is discarded (C1a/C2)? This is an observable the machine's correctness now depends on.
2. Should a work latch survive same-class target turnover (C1b), and does the interval case argue for cancelling the *scheduling chain* (the interval) rather than only the running callback when the operator interrupts background work?
3. What are the SIGTSTP/SIGCONT and orphan-reaping dispositions for the worker (C7)?
4. Who owns the single post-arming environment inventory — 0024's text and the target's disagree (cross-doc findings)?
5. Which document defines the serialized display form that crosses the process boundary, and can trusted style tokens exist worker-side at all (C4)?
6. Is the `process.on('exit')` denial a throw or a diagnosed no-op, and what does that do to package compatibility in file execution (C9)?

## 7. Readiness verdict

The document's decisions are sound — §8's deferral, §7's gate, §9's threat model, and §1's pinned EOF view should survive revision unchanged, and the three-press editing trade is right. But the escape invariant, the property this revision exists to state truthfully, is falsified by two reachable trajectories its own acceptance test cannot see (C1), the interrupt table has an undefined reachable cell (C2), the delegated-obligations ledger has already drifted against 0024 and lacks the checking discipline its sibling mandates (C3), and the display-IR contradiction with 0024 §8 leaves the corpus specifying two different trust pipelines for the same bytes (C4).

VERDICT: NOT READY

### Orchestrator verification notes

- **C1 (blocking) — CONFIRMED in both halves, and half of it was found independently
  by the Codex reviewer in the same round.** Both defects are mine.
  - *(a) the four-press path* — CONFIRMED. Row 5 discarded the queued submission but
    not the typed-ahead buffer, so the phase fell back to *editing* and the buffer ate
    a second interrupt, destroying the latch. Codex produced the same counterexample.
  - *(b) the unbounded escape under work turnover* — CONFIRMED, and this reviewer found
    it alone. It is the more serious of the two: under `setInterval(f, 0)` the latch
    cleared every time its target ended, so **no number of interrupts could ever end the
    session**, and the mandated notice ("press Ctrl+C again to end the session") was
    false on every press — in a document that elsewhere insists the notice must be true
    in both outcomes.
  - The root cause is now clear and was worth the three rounds to find: Round 1's
    stale-latch fix ("clear the latch when its target ends") and Round 3's turnover bug
    are the *same rule* pulling in opposite directions, because the latch was bound to a
    **work unit**. The repair is the two-level model the reviewer's suggestion points at:
    **cancellation requests stay id-exact against the unit** (forced by Hermes's
    exactly-once queued interrupt), while **the latch is armed against a target *class*
    — "running work" — that survives turnover.** With that, a latch is cleared by
    *editor input* (proof the operator got an interactive prompt back), never by work
    ending; the stale-latch case is excluded not by clearing but by *class mismatch* (an
    interrupt at a healthy idle prompt targets the idle prompt, a different class, and so
    is a fresh first interrupt); the interval storm exits in two presses; and the
    four-press path closes once an evaluating-phase interrupt discards the typed-ahead
    buffer along with the submission. The bound is now provably three, and the notice is
    always true.
- **C2 — CONFIRMED.** `(evaluating, engine free)` was reachable and unrowed. The
  four-class target model (idle prompt / operator input / running work / shutdown) makes
  it derivable rather than a special case.
- **C3 — CONFIRMED, and the ledger is corrected.** LLP 0024 §6 *does* now carry the fifth
  `lifecycle` outcome (`llp/0024-…:506`) and background-callback cancellation
  (`:629-633`); my rows saying "not yet" were stale within one round of being written —
  which is the reviewer's point about unchecked ledgers, made empirically. The rows are
  fixed, obligation IDs added, and the gap narrowed to what is genuinely undelivered: the
  **completion-query target** and the **target id**.
- **C4 — CONFIRMED as a live corpus contradiction, and resolved in this document's favour
  after checking both.** LLP 0024 §8 now says "LLP 0025 §3 pins the **display IR** … carrying
  trusted style and layout tokens … and **only the IR crosses**" (`llp/0024-…:1085-1096`).
  That would have the *worker* serialize trusted style tokens — authority it does not need
  and, under §7's hostile-worker premise, must not have. Both reviewers independently judged
  the style-free tree the better pipeline. §3 now states unambiguously that **exactly one
  object crosses** and it carries no styling; §11 carries a row tracking 0024's retraction.
- **C5, C6 (history key + lock protocol) — CONFIRMED and accepted.** The `O_EXCL`-then-write
  race, the permanently-torn-key hazard under never-rotate, and the inode-bound lock that
  does not survive compaction's rename are all real. §9 now pins one protocol: a **stable
  sidecar lock file** taken by every append and by compaction, atomic key materialization
  (temp + rename), and reopen-and-verify after acquiring.
- **C7, C8, C9, C10 — CONFIRMED and accepted.** In particular C9 changed a decision: a
  *throwing* denial of `process.on('exit', …)` would break common cleanup packages at import
  time in **every** mode, which is a far wider blast radius than the prompt. §8 now gives the
  surface a **no-effect branch** — registration succeeds, the listener never fires, and the
  first such registration is diagnosed once — using the same registry device §10 already uses
  for fd 0. That is honest (diagnosed, not silent) without being fatal.
- **The reviewer's "raw-mode commitment" suggestion — ACCEPTED.** The byte-level
  non-coalescing promise silently required the session to hold the terminal with `ISIG` off
  *while the engine is busy*, not merely while editing. §5 now says so.

## Round 4 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `43ff879a257a` (sha256, first 12 — content hash of the
on-disk file; the document is not yet committed)
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex
reviewer. **All prior-round artifacts were moved out of `llp/reviews/` before either
round-4 reviewer was launched and restored only after both had returned** — the stash
was independently verified empty of 0025 files while the Codex session ran. The two
reviewers ran concurrently on the same revision and could not observe each other.
**Method:** `brief-round4.md` verbatim; full read of the target and the sibling corpus;
verification of load-bearing claims against the Rust CLI, the Hermes bridge, the vendored
Hermes headers, the builtins, `src/host/abi.rs`, `capsec/registry/`, and
`runtime-surface.json`; LLP 0005 standard question set.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle (rev 43ff879a257a, round 4)

## 1. Overall assessment

This is a strong, unusually honest spec. Its empirical claims about the code are essentially all true — I verified every load-bearing one against the tree and found no fabricated premise (details under Strengths). The architecture decisions are right: the supervisor/worker split (§7) is the only structure that can deliver the escape invariant and restoration against a stuck or dead engine; the parking realization of uncatchable exit (§8) is a genuinely elegant move that removes the round-3 unimplementability; the broker's byte-cutoff barriers (§3) make a previously hand-waved ordering mechanically true; and §9's history design is careful down to the compaction/lock inode race.

But §6 — the part that has been wrong twice — is still not right. The two-level model (id-exact cancellation vs. class-armed latch) is the correct *shape*, and it does fix the two named prior defects as stated. Enumerating the machine over trajectories, however, yields two new falsifying trajectories of exactly the same defect class: (a) typed-ahead input during `evaluating` clears the running-work latch under the literal reading of latch rule 3, re-making the notice a lie; and (b) a press landing in a turnover *gap* of a storm re-targets the idle prompt, and latch replacement (rule 1) then permits an unbounded busy/gap alternation cycle, defeating both the two-press storm clause and the "at most three from any reachable state" bound. The document's own AC 7 — exhaustive enumeration over (phase, origin, latch) *and trajectories* — cannot pass against the machine as written. There are also a reachable state with no row (a submission suspended at top-level `await`), an AC-vs-machine contradiction on the wedged completion query, and a handful of material cross-document items, including one obligation both siblings assign to this document's §8 that round 4 still does not carry.

The judgment structure, honesty discipline, and testability posture are exemplary. The interrupt machine needs one more pass, and it should probably become a generated artifact like everything else this corpus has learned to distrust hand-maintaining.

## 2. Strengths

- **Every code-facing premise I checked is accurate.** No SIGINT handler on the REPL path; `Ctrl+C` is a rustyline keystroke result (`src/bin/ibex/repl/mod.rs:734-739`), and during evaluation the editor thread is parked in `control_rx.recv()` (repl/mod.rs:694), so the terminal is cooked and `Ctrl+C` hits the default disposition — exactly the Motivation's claim. Member completion evaluates its base via `Function('return (' + expr + ')')()` on the engine thread (repl/mod.rs:297) under a 5-second `recv_timeout` on the *editor* thread (repl/mod.rs:32, 256) — "releases the editor, never the engine" is precisely right. The engine seam has no cancellation operation of any kind (`src/bin/ibex/engine/mod.rs:22-98`), and `ffi_lock` serializes the whole native eval/poll call (`src/bin/ibex/engine/hermes.rs:487-490, 542-545`). `__exactExit` reaches `std::exit` (`src/engine/hermes_runtime.cc:588-602, 1704-1727`). One `ex_hermes_poll` drains the entire cross-thread callback queue, pending tasks, next-tick, microtasks, and *all* due timers (`hermes_runtime.cc:3541-3650`) — which is exactly why O-6's "a Rust id wrapped around the FFI call cannot name an individual callback" is true. `hermesc` is invoked with `-emit-binary`/`-out`/`-output-source-map` and **no** break-check flag (hermes.rs:1837-1847); `emitAsyncBreakCheck` defaults `false` (`ios/Frameworks/hermes-headers/hermes/CompileJS.h:78`) while `AsyncBreakCheckInEval` defaults `true` (`hermes/Public/RuntimeConfig.h:63`) — the §6 compiled-without-checks defeat mode is real. `asyncTriggerTimeout()` is any-thread, "terminates the current execution," and takes no target (`jsi/hermes-interfaces.h:184-186`); `triggerInterrupt_TS` is "exactly once" (`hermes/AsyncDebuggerAPI.h:133-137`) and an empty no-op stub in the `!HERMES_ENABLE_DEBUGGER` branch (`AsyncDebuggerAPI.h:269, 276`) — OQ 1 states all of this correctly. `fs.js` `closeSync`/`readSync` have no fd-0/1/2 branch (`src/builtins/fs.js:3608-3644`); `isTTY` is raw `isatty` and stdout writes are a native retry loop (`src/engine/hermes_runtime_process_setup.cc:243-262, 280-308`). The console queue drops under backpressure by design for embedded hosts (`src/host/abi.rs:330-373`) and `ex_host_console_flush` returns at deadline with lines pending (abi.rs:406-417) — §3's "supersedes for the CLI, remains correct for the embedded case" is the right adjudication of LLP 0006. The §10 registry claims match `capsec/registry/coverage-edges.json` exactly (`process:signal` closures, `runtime:inspect` on `exitCode`/`_exactExiting`, `__exactStdinRead` as an `effects` edge with `ambient-root` in `positiveSources`). `runtime-surface.json` shows `ibex repl` with zero options, confirming both O-12 and §9's root-level-option rationale. OQ 7's "arbitrary values" are real (5 s, 200 ms — repl/mod.rs:32, hermes.rs:210).
- **§8's parking mechanism** is the standout design move: it converts "uncatchable exit" from an engine-unwind ask no vendored interface offers into a plain no-return semantics that needs nothing from Hermes, and the `finally`-cannot-run argument is airtight. The listener no-effect branch is correctly reasoned (import-time blast radius vs. an invariant-corrupting partial fire) and recorded as a divergence.
- **§3's broker** is now stated as a set of keepable guarantees: the byte-cutoff barrier is the first version of this ordering story that is mechanically checkable (AC 6's deliberately-lagging-relay assertion is exactly the right fixture); the same-open-file-description total-order claim is kernel-true; forced-termination loss is accounted, not silent; and the prompt-override reversal (environment ≠ operator) is correct and overdue.
- **§7's** invariants-normative/architecture-realization framing, with an explicit five-part conformance gate for in-process, is exactly how to keep a future "we prototyped a Hermes interrupt" from quietly dropping the other four guarantees. The worker-isolation list (own process group, no controlling terminal, fd allowlist, in-worker fd refusals as defense-in-depth, PDEATHSIG-class binding, SIGPIPE ignored) shows real systems literacy.
- **§9** reuses LLP 0023 §2.3's `(volume, file, verification generation)` record rather than minting a second identity (verified against 0023:339-344), pins both directions of the birth-time/path-fallback consequences honestly, and the compaction/sidecar-lock/reopen-verify reasoning (inode-bound locks don't survive rename) is correct and subtle. Append-at-submission retiring save-at-exit is right, and the current save-at-exit defect is real (`repl/mod.rs:699`).
- **The deliberate-divergence discipline** — `isTTY: false` at a prompt, `$_`-style listener no-ops, the pessimism about async-break catchability with its asymmetry argument (§6) — is consistently argued rather than asserted.
- **§11's ledger is honest.** Every row I could adjudicate against current sibling text is correctly marked (O-1 yes, O-2 not-yet-and-contradicted, O-3/O-4 yes per 0024 §6, O-5/O-6/O-8/O-10/O-11/O-12 not yet, O-7 partly). It is incomplete, though — see Concern 6.

## 3. Concerns

**C1. Blocking — Typed-ahead during `evaluating` clears the running-work latch, re-creating the round-1 defect.**
Evidence: §6 latch rule 3 clears the latch on "**any editor input** ... — a keystroke, a bare Enter, or a submitted line" (0025:507-509), with no phase qualifier, while §6 also states "Keystrokes entered while an evaluation is in flight accumulate in the buffer but do not submit; the phase stays **evaluating**" (0025:477). Trajectory: runaway eval → press 1 (latch running-work, notice "press Ctrl+C again to end the session") → stray keystroke or Enter arrives typed-ahead (a keystroke *is* editor input; latch cleared) → press 2 is a *fresh first* interrupt, and the notice was a lie — the exact round-3 failure mode restated in the revision header (0025:8-12). The escape invariant's first clause ("two interrupts end the session" while work does not return, 0025:528-533) is false on this trajectory, and interleaved keystrokes extend it indefinitely. The gloss ("the operator demonstrating that they got an interactive prompt back") shows the intended rule, but during `evaluating` the operator demonstrably has *not* got a prompt back, and the normative trigger says "any." Target-selection rule 2's "the buffer does not compete in this phase" (0025:469) closes the front door; rule 3 bullet 1 reopens the back door.
Resolution criterion: restrict latch-clearing editor input to input consumed at a live prompt (phases idle/editing/continuation); state explicitly that bytes accumulated as typed-ahead during `evaluating` (and during shutdown) neither clear nor arm anything; add to AC 7 the assertion that a running-work latch survives typed-ahead arriving between two interrupts and the second interrupt still terminates.

**C2. Blocking — Turnover-gap alternation defeats the hard bound; latch *replacement* (rule 1) is the mechanism.**
Evidence: engine-busy origin is instantaneous ("whatever the engine is executing," 0025:434, 450), and target-selection rule 4 sends an idle-phase interrupt to the idle prompt whenever the engine is momentarily free (0025:473-474). Under a storm whose callbacks individually complete, the engine is free between callbacks. Enumerate: press 1 lands in a callback → latch(running-work); press 2 lands in a gap → target = idle prompt ≠ latched class → first-column notice, and rule 1 ("arming against a new class **replaces** any previous latch," 0025:500-501) discards the running-work progress; press 3 lands in a callback → fresh first against running work; press 4 in a gap → replaces again… The cycle (idle, free, latch=RW) ↔ (idle, callback, latch=IP) is reachable and unbounded, so both "two interrupts … whether one unit or a succession" and "at most three from any reachable state" (0025:528-533) are false, and AC 7's exhaustive enumeration over trajectories (0025:912-921) cannot pass as written. The stated justification for the three-bound considers only buffer-spending (0025:531-533) and never this cycle. Note the constraint that makes naive fixes wrong: AC 7 also (correctly) requires that a latch surviving its work's *end* must NOT make a single later `Ctrl+C` at a healthy prompt exit (0025:919-920), so "honor a running-work latch at idle-free" is not admissible as-is.
Resolution criterion: restore a hard bound without violating the healthy-prompt assertion — the cleanest repair I can see is to make the latch **accumulate** classes rather than replace (arming a new class adds it; an interrupt matching *any* armed class takes that class's second column; editor input at a live prompt still clears the whole set). That yields ≤3 under any busy/gap interleaving (press 1: {RW}; press 2 in a gap: notice, {RW, IP}; press 3: terminates either way) while a *single* press at a genuinely healthy prompt still only notices. Alternatively, fold "scheduled work due within the coalescing window" into the idle-phase busy predicate. Either way, re-run the enumeration with press timing adversarial to turnover gaps and update the invariant's wording to whatever is actually delivered.

**C3. Material — A submission suspended at top-level `await` matches no row of the machine.**
Evidence: phase `evaluating` covers an in-flight input "whether or not the engine has started it" (0025:432-433), and 0024 §1 serializes submission "*including* while an input is suspended at a top-level `await`" (0024:171-176); 0024 §6 states "a never-settling awaited evaluation waits until it is **cancelled**" (0024:587-589). But 0025's target-selection rule 2 offers only "running work if the engine is executing any; otherwise the **pending submission (accepted but not yet dispatched)**" (0025:466-469), and the only (evaluating, engine free) row is explicitly conditioned "submission not yet dispatched" (0025:486). `await new Promise(()=>{})` with the engine momentarily free is (evaluating, free, dispatched-and-suspended): no row. Misapplying the queued-submission row would "return to idle" with an unsettled input (violating 0024 §1's serialization) and never raise the cancellation 0024 §6 says is the only way out. Also, 0024 §6 defines a background callback as work executing "while no input is in flight" (0024:629-631), so the callback that would resolve the suspended await has no cancellation vocabulary either.
Resolution criterion: add the row — first interrupt requests id-exact cancellation of the suspended unit and latches running work; second terminates 130 — and define the running-work class over *in-flight* work (executing or suspended), not instantaneously-executing work; reconcile 0024 §6's "while no input is in flight" qualifier in the same change.

**C4. Material — AC 7's "a wedged completion query exits in two" contradicts the machine for the standard member-completion case.**
Evidence: a member-completion wedge arises from `foo.` + Tab, so the buffer is non-empty and the phase is editing; target-selection rule 3 sends press 1 to the **buffer** (0025:470, 483), press 2 arms running work, press 3 exits — three, not two. AC 7 asserts two (0025:918-919). Two is only true when the query was dispatched from an empty buffer (global completion). The editing-row trade's own rationale — protecting an operator clearing a typo from a *coincidental* background callback (0025:536-539) — does not apply here: the running work is work the operator just requested by pressing Tab.
Resolution criterion: either amend AC 7 to "at most three (two from an empty buffer)", or — better — make an in-flight completion query the interrupt's target from editing/continuation (press 1 abandons the result, requests cancellation, *preserves the buffer*, latches running work; press 2 exits 130). The second option is also better UX: discarding the operator's typed expression because their completion wedged punishes the wrong party.

**C5. Material — §8 still lacks the mode × async-failure fatality/status rule that both siblings delegate to it.**
Evidence: 0024 §9 ends "the consumer's lifecycle policy (**LLP 0025 §8**) decides the process outcome" (0024:1163-1164); 0022 §11 row `OBL-ASYNC-FATALITY` names LLP 0025 §8 as owner and records "0025 has no mode×event rule" (0022:888) — still true of round 4. §8's status table (0025:700-711) has no row for an unhandled rejection/uncaught background exception in program/one-shot/file modes (0022 §3 pins Node's exit **1**, 0022:400-409); its "fatal engine or armed-host failure" row is a different fault class, and two rows remain unpinned "nonzero" under a heading that says "Exit statuses are pinned."
Resolution criterion: §8 states the rule (fatal, exit 1, in program/one-shot/file; never fatal in REPL modes) and adds the status row, or explicitly declines ownership and gets 0022's ledger row retargeted in the same change; "pinned" and the residual "nonzero" rows reconciled.

**C6. Material — the §11 ledger omits the corrections this document requires of LLP 0022.**
Evidence: 0022 §10 states the escape invariant as "two interrupts **against the same running target**" (0022:829-835) — unit language that, under a storm, describes exactly the pre-round-4 machine this revision exists to bury (consecutive interrupts during a storm are against *different* units; only the class formulation makes 0022's sentence true). 0022 §10 also repeats the "**unwinding the evaluation** so that `try`/`finally` cannot intercept it" mechanism note (0022:844-846) that O-7 corrects — but O-7 names only LLP 0024 (0025:870). §11 has no LLP 0022 rows at all besides tooling, yet its stated purpose is that a dangling dependency "is visible rather than assumed" (0025:856-858). Not-yet-made sibling edits the ledger *names* are fine per the review brief; edits it *fails to name* are ledger defects.
Resolution criterion: add rows for (a) 0022 §10's class-language rewording and (b) 0022's unwind→park correction, or land the 0022 edits in the same change.

**C7. Material — the history key's "materialized atomically" does not cover concurrent first creation, and the race is a silent rotation.**
Evidence: §9 — "written to a temp name and renamed into place," "created **only when missing**," "**never rotated**, because rotating on a transient error would orphan every history the user has — a worse failure than the one it guards" (0025:786-794). Plain rename replaces silently: two concurrent first-run sessions can each generate a key, the second rename replaces the first, and every entry the first session appended is keyed under an HMAC no future session can reproduce — a de-facto rotation, the precise failure the never-rotate rule names, achieved by race instead of by error. AC 11 tests torn reads and no-rotation-on-unreadable but not this (0025:934-937).
Resolution criterion: require no-replace materialization (`O_EXCL`-create / link-then-unlink / `renameat2(RENAME_NOREPLACE)`-class semantics) with the losing creator adopting the winner's key; add an acceptance clause: two concurrent first sessions end with one key and both sessions' entries recallable.

**C8. Minor/Non-blocking — the barrier cutoff is written in the singular but must be per-relay.**
Evidence: "the value of the worker's **output counter**" then "the supervisor **drains each relay to that cutoff**" (0025:320-325). One scalar cannot tell the supervisor how to split the drain across the fd-1 and fd-2 relays.
Resolution criterion: state a per-relay counter vector (and that the counters are maintained at the worker's write sites, which is feasible because no package can reach a raw syscall — all fd-1/2 writes traverse runtime routes, e.g. `hermes_runtime_process_setup.cc:243-262`).

**C9. Minor/Non-blocking — "cannot cause a byte outside the payload to be written" is overstated.**
Evidence: 0025:268-271. A producer choosing a node *kind* does cause different kind-derived styling bytes to be written; the true invariant is that it cannot cause an unescaped/control byte, or a byte in the session-decoration style vocabulary.
Resolution criterion: restate as such, and add the (currently implicit) requirement that the kind→style map's codomain is disjoint from session-decoration/control styling, so a hostile tree cannot cosplay as session UI.

**C10. Minor/Non-blocking — the cooperative-exit path should reuse §3's cutoff.**
Evidence: §8's lifecycle record "parks... the supervisor restores, flushes, disposes of the worker" (0025:666-668). Without carrying the worker's per-relay byte counts at the moment of the call, the supervisor cannot know when `console.log("bye"); process.exit(0)`'s bytes are fully drained before disposal — the exact problem §3's barriers solve.
Resolution criterion: the authenticated lifecycle record carries the per-relay cutoff; the flush drains to it (under budget, with accounted abandonment).

**C11. Minor/Non-blocking — SIGWINCH relay to the worker is missing from §7's list.**
Evidence: §2 makes dimensions live session state exposed via `stdio:query` (0025:232-235); AC 2 asserts "dimensions change after `SIGWINCH`" (0025:891-892); §7's signal list forwards only `SIGTSTP`/`SIGCONT` (0025:615-616). The worker answers the typed query, so the supervisor must relay dimension changes.
Resolution criterion: add the relay (signal forwarding or a control-lane dimension event) to §7.

**C12. Minor/Non-blocking — the non-session "terminate" path conflates the signal-safe and non-signal-safe tiers.**
Evidence: 0025:202-210 — one sentence has the interrupt "flush under its budget" and exit 130, the next says "an async-signal-safe handler restores and `_exit`s." A broker flush is not async-signal-safe.
Resolution criterion: state the two tiers explicitly (ordinary path: restore, flush-under-budget, exit; handler-only fallback: restore + `_exit(130)`, flush forfeited and — if the accounting rule applies here — forfeited silently, which should be said). Relatedly, note that the in-process §8 realization must terminate via `_exit`-class exit after flush, since `std::exit`'s static destructors would race the parked engine thread.

## 4. Cross-document findings

- **O-2 adjudication (0024 §8 vs 0025 §3): 0025 is right; 0024 §8 is the defect.** 0024 currently has *two* objects with split ownership — its semantic inspection tree plus a "display IR — the versioned, serializable form carrying **trusted style and layout tokens** from a closed enum" that it attributes to 0025 §3 and says is what crosses the boundary (0024:1085-1095, and again in Consequences, 0024:1347-1350) — while 0025 §3 refuses to define any style-bearing IR and sends exactly one unstyled object across (0025:262-276, O-2 at 0025:865). The one-object model is superior: a worker-serialized style vocabulary, even a closed enum, hands the least-trusted component the ability to select presentation directly, including any style that overlaps session decoration; kind-derived styling keeps the entire style map session-owned, lets the renderer enforce structural invariants per kind, and keeps style-vocabulary versioning out of the trust boundary. The residual exposure (a hostile worker choosing kinds to pick among *result* styles) is inherent to any design and is bounded by C9's disjointness requirement. Both 0022 (`OBL-DISPLAY-WIRE`, 0022:900) and 0025 (O-2) record the contradiction, so the corpus is in the "named, not silent" state its own precedence rule requires — the 0024 §8 retraction should land promptly.
- **0022 §10 is stale against round 4** — unit-language invariant and the "unwinding" mechanism note (Concern 6). A sibling defect in origin, a ledger omission in the target.
- **0025 §9 mis-cites 0022 §4 on startup diagnostics.** 0025 justifies naming the legacy history file "symbolically, not by host path" with "LLP 0022 §4's no-host-path rule binds session output, and a startup diagnostic is session output" (0025:810-813) — but 0022 §4 says the opposite: the rule "binds what JavaScript can observe. It does **not** bind the CLI's own **startup diagnostics**," which may name host paths (0022:452-459). 0025's stricter choice is defensible on its own grounds (this notice recurs every startup and lands in logs/transcripts), but it must own that reasoning rather than attribute to the sibling a rule the sibling disclaims — as written this is a contradiction of the "invalid corpus state" kind 0022's precedence note forbids.
- **`OBL-ASYNC-FATALITY` remains dangling with 0025 as the delinquent owner** (Concern 5) — the one place where a sibling's ledger names an edit to *this* document that round 4 did not make.
- **0024 OQ 8 mis-cites the constants annex as "LLP 0025 OQ 6"; the values question is 0025 OQ 7** (0024:1405-1409 vs 0025:989-993; 0022's `OBL-BOUNDS` cites OQ 7 correctly). Sibling defect, minor.
- **Consistency checks that pass:** cancellation vocabulary and the defeated/race rule (O-3/O-4 verified against 0024:592-633); §2's inventory ownership matches 0024's retirement of `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` in both directions (0024:588-590, 0025:226-229); the transcript checkpoint as a broker flush (0022:393-397 ↔ 0025:328-329); mode tables and banner/editor conditions (0022 §3 ↔ 0025 §1); `$_` on display acknowledgement (0024 §7.8 ↔ 0025 §3); history reuse of 0023 §2.3's record (0023:339-344) — 0025's birth-time concretization of the verification generation extends rather than contradicts 0023, which leaves the generation source unpinned.

## 5. Suggestions

- **Make the §6 machine a generated artifact.** This corpus generates the fd-0 route table, keybindings, command tables, and path observables precisely because hand-maintained security-relevant tables drift; the interrupt machine has now been wrong three times and is still hand-prose. Publish the states, the event alphabet (interrupt, keystroke-at-prompt, typed-ahead byte, submit, dispatch, unit-begin/end, settle, suspend), and the transition table as owner-authored data from which both §6's tables and AC 7's enumerator are generated. The invariant should be a property *over that alphabet* — C1–C3 would all have been mechanically visible.
- Add a (phase × origin) **reachability matrix** stating which combinations exist and why (e.g., whether (evaluating, completion query) is unreachable), so AC 7's enumerator has a pinned domain.
- On interrupt against running work, print *what* is being cancelled with its source identity (`repl:<n>`, the completion query, the timer's owning principal) — the attribution machinery exists (0024 §9), and it materially helps the operator decide whether to press again.
- Pin the `process.exit(n)` argument-coercion divergence from Node as a recorded divergence: modern Node throws `ERR_INVALID_ARG_TYPE`/`ERR_OUT_OF_RANGE` for bad codes, while §8 specifies silent ToNumber-with-non-finite-as-0.
- §9: name the sidecar lock's derivation (per-history, same directory/volume as the file — a lock on another volume reintroduces NFS-class lock hazards), and s/platform supplies none/filesystem supplies none/ for `STATX_BTIME`, which is per-filesystem on Linux.
- §7: consider stating the Windows analogue of "raw with `ISIG` off" (ConPTY with `ENABLE_PROCESSED_INPUT` cleared) since §6's two-bytes-two-interrupts promise depends on it and §5 only covers restoration.
- Novel but cheap: since the supervisor owns the PTY and the control lane, a wedged-work notice can carry a live elapsed-time indicator ("cancelling — 3s — press Ctrl+C again to end the session") at trivial cost, which converts the operator's "did it hear me?" uncertainty — the actual cause of interrupt hammering — into information.

## 6. Open questions

1. For a suspended-TLA unit, is the callback that resolves its awaited promise part of the *unit* for target-id purposes, or a separate unit? (C3; ties directly to O-6's begin/end boundary publication.)
2. Is the accumulate-don't-replace latch (C2) the right generalization, or should the idle-phase busy predicate consult scheduled-and-due work within the coalescing window? Both restore the hard bound; they differ in which termination (orderly vs 130) a gap press produces.
3. Should typed-ahead be discarded on interrupt (as specified) or preserved and replayed at the next prompt? Discard matches Node; either way the choice should be stated as deliberate.
4. When the supervisor's forced termination abandons N events, on what surface does the "N events unwritten" report land when the *control-lane-reachable* destination is also the stalled one (stdout=stderr=one stalled pipe, no TTY)? Presumably nowhere — is that the accounted-vs-silent line, and should the exit status say so?
5. Does the §8 in-process realization exit from the engine thread or hand off to the session thread? (Affects whether restoration/flush can use non-signal-safe machinery; C12.)
6. Should the interim single-latch → latch-set change (if adopted) be visible in the notice text, which currently promises a single next-press outcome?

## 7. Readiness verdict

C1 and C2 falsify the escape invariant — the document's central promise and the specific thing this round was rebuilt to fix — and make AC 7 unsatisfiable as written; C3–C7 are material correctness/coherence gaps. The architecture, the broker, the exit mechanism, and the history design are sound and close; §6 needs one more, mechanically-checked, iteration.

VERDICT: NOT READY

### Orchestrator verification notes

- **C1 and C2 (blocking) — CONFIRMED**, and the Codex reviewer derived the same
  falsifying trajectories independently in the same round. This is the **third
  consecutive round** §6 has been falsified, and the third time by hand-analysis of a
  hand-written table.
  - *C1, typed-ahead clears the running-work latch* — CONFIRMED. Latch rule 3 cleared
    on "any editor input", and a keystroke during `evaluating` **is** editor input under
    the literal rule, so `C1, type, C2, type, …` never escalates. The gloss said the
    rule existed because the operator "got an interactive prompt back" — but during a
    runaway evaluation they demonstrably have not. The gloss knew what the rule should
    say; the rule did not say it.
  - *C2, turnover-gap alternation* — CONFIRMED, and the subtler of the two. Target
    selection keyed on **instantaneous** engine-busy, so a press landing in a gap between
    two callbacks of a storm re-targeted the idle prompt, and latch **replacement**
    (rule 1) then discarded the running-work progress — an unbounded busy/gap cycle.
  **Root cause, finally identified:** the state was missing the one variable that
  distinguishes *"the engine is momentarily between callbacks"* from *"the operator has a
  genuinely usable prompt back"*. Both reviewers independently prescribed the same repair
  and it is adopted: a **work epoch** closing only on authenticated quiescence **plus a
  republished prompt**, a **prompt generation** counter, and a latch armed against
  `(class, epoch-or-generation)`. Typed-ahead is now defined as *not* editor input.
  I considered this reviewer's **accumulating-latch** alternative and rejected it: it
  restores a bound but makes the *notice* imprecise in the gap case, and it leaves the
  machine still keyed on instantaneous busy-ness. The epoch model fixes the cause rather
  than the symptom, and it makes the storm exit in **two** presses rather than three.
- **The invariant is now scoped to *consecutive* interrupts**, which is this reviewer's
  open question 3 answered honestly: intervening editor input at a live prompt *does*
  reset escalation, and it should — an operator who is typing is interacting, not stuck.
  The guarantee that matters is the one a stuck operator actually exercises: pressing
  `Ctrl+C` repeatedly. That now terminates in at most three presses, always.
- **C3 (suspended TLA has no row) — CONFIRMED and accepted.** `await new Promise(()=>{})`
  with the engine momentarily free is `(evaluating, engine free, dispatched-and-suspended)`
  — no row, and the only row for `(evaluating, free)` was explicitly conditioned on "not
  yet dispatched". Fixed structurally: **running work** is now work *in flight* — executing,
  suspended, **or ready** — not "the engine is currently executing", which is the same
  redefinition the turnover fix requires. One change closes both.
- **C4 (wedged completion query takes three, not two) — CONFIRMED**, matching Codex's
  concern 2, and this reviewer's proposed resolution is the better one and is adopted: in
  the editing/continuation phase an **in-flight completion query is the target and the
  buffer is preserved**. The operator asked for that work by pressing Tab, so it is not the
  coincidental background callback the buffer-first trade was designed to protect —
  discarding their typed expression because *their own completion* wedged punishes the
  wrong party. AC 7's "exits in two" becomes true rather than being weakened to three.
- **C5 (async-failure fatality) — CONFIRMED and accepted.** Both siblings delegate this to
  this document's §8 and LLP 0022's ledger has recorded it undischarged for four rounds. §8
  now carries the **mode × failure-class matrix**.
- **C6 (the ledger omits the 0022 corrections) — CONFIRMED and accepted**; rows added.
- **C7 (key materialization race is a silent rotation) — CONFIRMED and accepted.** Sharp:
  plain rename **replaces**, so two concurrent first-run sessions can each mint a key and the
  second clobbers the first — a de-facto rotation achieved by race, which is precisely the
  failure the never-rotate rule exists to prevent. Now a **no-clobber** publication of key and
  check value as one record, with the loser re-reading the winner's.
- **C8, C9, C10, C11, C12 — all CONFIRMED and accepted.** C9 in particular improves the trust
  boundary: "a producer cannot cause a byte outside the payload to be written" was overstated —
  choosing a *kind* does select kind-derived styling bytes — so the real invariant is now
  stated, plus the requirement that the kind→style codomain be **disjoint from session
  decoration**, so a hostile tree cannot cosplay as session UI. C12's observation that a broker
  flush is not async-signal-safe splits the non-session terminate path into two honest tiers.
- **Cross-document: the LLP 0022 §4 miscitation — CONFIRMED**, and I had reached the same
  conclusion independently while verifying this reviewer's parallel finding. §9 justified
  symbolic naming of the legacy history file by attributing to LLP 0022 §4 a rule that 0022
  **explicitly disclaims**: "the rule binds what JavaScript can observe. It does not bind the
  CLI's own **startup diagnostics**." The *choice* is still right; the *reason* was borrowed
  from a sibling that refuses to lend it. §9 now argues it on its own terms.
- **The reviewer's adjudication of the display-tree conflict (O-2) is now moot in the best
  way:** LLP 0024 has amended itself. Its current text reads "§8 owns the **unstyled** tree and
  the styled-IR language is retired." Both reviewers judged the one-object, style-free pipeline
  correct, and the sibling agreed on the merits. The ledger row is flipped to delivered.
- **The suggestion to make §6 a generated, model-checked artifact — ACCEPTED as normative.**
  Three rounds of hand-analysis have now produced three falsifications, and both reviewers
  independently reached for the same remedy. The document no longer asks to be trusted on this:
  the transition relation is owner-authored data from which the §6 table, the implementation
  dispatch, and AC 7's exhaustive trajectory enumeration are all generated, and the escape
  invariant is model-checked over the event alphabet. This corpus already generates its fd-0
  route table, command table, keybinding manifest, and path observables for exactly this reason;
  the interrupt machine had been the one security-relevant table still maintained by hand, and it
  was wrong every single time it was reviewed.

## Round 5 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `7b89315f8ad7`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer.
All prior-round artifacts were moved out of `llp/reviews/` before either round-5 reviewer was
launched and restored only after both had returned. The two reviewers ran concurrently on the
same revision and could not observe each other.
**Method:** `brief-round5.md` verbatim; full read of the target and the sibling corpus;
verification against the Rust CLI, the Hermes bridge, the vendored Hermes headers, the builtins,
`src/host/abi.rs`, `capsec/registry/`, and `runtime-surface.json`.

### Verbatim review

# Review: LLP 0025 "Terminal Session Ownership and Lifecycle" (rev 7b89315f8ad7, round 5)

## 1. Overall assessment

This is a strong, unusually honest spec whose factual foundation checks out almost everywhere I probed it: every load-bearing code claim I verified is true (the `Function('return (' + expr + ')')()` completion evaluation, the editor-thread-only `recv_timeout` budget, the history cwd fallback, the FFI lock held across the whole eval, the absence of any cancellation operation, `__exactExit` → `std::exit`, root/runtime principals operating on unknown numeric descriptors, the `hermesc` invocation passing no break-check flag, the no-op `triggerInterrupt_TS` stub, the console drop-under-backpressure queue). The §9 history redesign and §8 parking analysis are genuinely correct engineering. But the document does not yet clear its own bar in the two places it matters most: **§6's rebuilt interrupt machine still admits falsifying trajectories** — the stated three-press bound fails under intermittent background work because latch replacement on class flip resets escalation progress, and two load-bearing terms ("ready and scheduled", "republishes a prompt") are left ambiguous in ways that flip the machine's behavior — and **§11 has again gone stale against the siblings in the false-alarm direction on three rows**, plus §6 contradicts LLP 0024's cancellation vocabulary. The move to a generated, model-checked machine is the right response and would in fact *catch* the defect I found — which is exactly why the design must be fixed before the data is authored, not discovered by the checker afterwards.

## 2. Strengths

- **§9 is the best section in the document.** The supervisor-owned `ProjectHistoryIdentity` correctly untangles itself from LLP 0023's worker-locality rule — I verified 0023's current text says retained/VFS identities "live and are derived in the process that owns the engine" and are "never serialized to a supervisor" (0023 §7.1), so the earlier reuse really was a violation, and the opaque-token-to-worker design is exactly what 0023 permits. The no-clobber key race analysis (a plain rename is a silent rotation), valid-prefix journal recovery, the inode-bound-lock gotcha under compaction rename, and the pinned storage root (retiring the real `dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))` fallback at `src/bin/ibex/repl/mod.rs:584`, and save-at-exit at `mod.rs:699`) are all correct and precisely scoped. The HMAC threat model ("file names but not contents") is honest.
- **§8's in-process parking realization is a real insight, correctly derived.** The FFI lock is genuinely held across the whole native call (`src/bin/ibex/engine/hermes.rs:490,542–559` — "the JS thread holds it for the whole of `ex_hermes_eval`"), so parking without exiting *is* a hang, runtime destruction *would* deadlock, and restore+flush+`_exit` inside the call is the only coherent in-process shape. The `_exit`-not-`std::exit` rationale (static destructors racing live threads) is right, and today's code does reach `std::exit` (`src/engine/hermes_runtime.cc:588–602`, via `__exactExit` at `:1704–1727`). The bounded flush is compatible with the "no new locks" rule (`ex_host_console_flush` spins on an atomic, `src/host/abi.rs:406–418`).
- **§1's protected descriptor class is motivated by a verified hole**, not a hypothetical: `principalMayUseUnknownFd` returns true for root and runtime principals and `requireOwnedFd` then synthesizes a read/write entry for any guessed integer (`src/engine/hermes_runtime_fs.cc:158–168, 221–234`). The `closeSync`-has-no-fd-0/1/2-branch claim is also true (`src/builtins/fs.js:3608–3612`).
- **§7's watchdog reasoning is correct against the real code**: a worker stuck in evaluation holds `ffi_lock` and can never poll a relay for EOF, so kill-on-relay-EOF genuinely fails in exactly the case that matters; the kernel-parent-death-or-independent-watchdog requirement follows.
- **§6's engine agnosticism is disciplined and verified**: `asyncTriggerTimeout()` takes no target (`ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:186`); `triggerInterrupt_TS` is an empty stub in the `!HERMES_ENABLE_DEBUGGER` branch (`hermes/AsyncDebuggerAPI.h:194,269`); `emitAsyncBreakCheck` defaults false (`hermes/CompileJS.h:78`) and Ibex's `hermesc` invocation passes only `-emit-binary`/`-out`/`-output-source-map` (`hermes.rs:1837–1847`) — so "interruptibility is a property of how the source was compiled" is exactly right. The asymmetry argument for not assuming break catchability is decision-quality writing.
- **§3's broker corrections are sound**: per-relay cutoff vectors (one scalar provably cannot serve two relays), *constructing* the same-destination topology as one open file description rather than detecting it, non-inheriting children (today's spawn does inherit — `src/engine/hermes_runtime_process.cc:712–836`), and accounting forced-termination loss. The supersession of drop-under-backpressure is correctly scoped against LLP 0006's "Degrade diagnostics, never the caller" (0006 line 136), and the current drop behavior is real (`src/host/abi.rs:330–371`).
- **§10's registry claims are accurate**: `__exactStdinRead` is an `effects` edge under `stdio:read` with `positiveSources` including `ambient-root` (`capsec/registry/coverage-edges.json` ~line 184044); no `lifecycle:exit` exists; `process:signal` exists and stays closed; `runtime-surface.json` has no keybinding/history/replSurface rows, so `OBL-CLI-SURFACE`'s "not yet" is true.

## 3. Concerns

**C1. (Blocking) §6's three-press bound is falsifiable: latch replacement on class flip resets escalation, so intermittent background work admits unbounded consecutive interrupts.**
Evidence: §6 latch rule 1 ("arming against a new class **replaces** it") + target selection rules 2/4 + the escape invariant ("From any reachable state, **at most three consecutive interrupts** end the session"). Derive the trajectory for `setInterval(() => busyWork(500), 1000)` at an idle prompt — a workload with real gaps, unlike the tight storm §6 fixed. A press landing during a callback targets `(running work, Eᵢ)`; a press landing in a gap targets `(idle prompt, G)` (in the gap nothing is executing, suspended, or due — see C2). Alternating presses — callback, gap, callback, gap — each target a *different class* than the latch, so each press **replaces** the latch and is a "fresh first interrupt", forever. No editor input intervenes, so these are consecutive interrupts by the document's own definition, and the session never ends. The bound is a universal worst-case claim over trajectories; this trajectory is reachable, so AC 7's model check of "at most three consecutive interrupts from any reachable state" cannot pass on this design. The same flapping also strings the operator along with an infinite alternation of two different notices, each individually "true while its condition holds" — satisfying the letter of the honesty rule while producing precisely the reach-for-`kill -9` experience 0022 §10 names as the failure being guarded against.
Resolution criterion: add an unconditional escalation backstop to the machine — e.g., a consecutive-interrupt counter cleared only by editor input at a live prompt, with the third consecutive interrupt ending the session regardless of class/epoch match — or an equivalent rule making class flips preserve progress; then show the model check of AC 7's trajectory enumeration passes with the gap/callback alternation and the generation-bumping storm (C2) as named adversarial schedules.

**C2. (Blocking, same root) Two load-bearing terms are undefined, and the document contradicts itself about one of them.**
Evidence: the state definition says work is in flight if "executing … suspended … **or it is ready and scheduled**", while target-selection rule 2 glosses in-flight as "(executing, suspended, or ready)" — "scheduled" silently disappears — and table row 2 glosses idle in-flight work as "(callback or completion query)". Whether a scheduled-but-not-due timer is in flight decides everything: if it is *not* (the reading the glosses support), C1's alternation exists; if it *is*, then (a) the epoch of any session holding a repeating timer or server never closes, the prompt generation never increments, and latch rule 4's "targets (idle prompt, G+1)" example is unreachable; (b) a first `Ctrl+C` at a healthy prompt requests id-exact cancellation of "the current unit" — but a unit that has not begun **has no id** ("each unit is assigned a monotonic target id **at begin**"), so the row is unsatisfiable; and (c) a second press exits 130 instead of orderly shutdown whenever any timer exists, silently making §8's "second idle interrupt" orderly path a rarity. Similarly, "closes only when the session reaches quiescence **and republishes a prompt**" does not say whether a quiet background callback completing beneath an undisturbed live prompt constitutes a republication; if every callback cycle increments the generation, then even two same-class gap presses never match `(idle prompt, G)` twice and an operator pressing `Ctrl+C` once a second at an idle-looking prompt never exits.
Resolution criterion: the transition data (and the prose rendering) pins (i) in-flight excludes scheduled-not-yet-due work, by name; (ii) "prompt republish" as a defined session event with stated triggers (evaluation completion, async report redraw — not quiet background completion), so the model's environment is grounded; (iii) what a first idle interrupt does about scheduled-but-unbegun work (nothing — it targets the idle prompt).

**C3. (Material) §6 contradicts LLP 0024's cancellation vocabulary on "defeated" — and is internally inconsistent about it.**
Evidence: 0025 §6: "A request resolves as *accepted*, *unavailable*, *failed*, or **not at all** (LLP 0024). It is **defeated** — never resolves — in at least three ways…" — but 0024 §6 (current text, lines ~677–709) defines **defeated** as a *terminal resolution* ("the request was delivered, the target kept running, and the target later ended by another route") and **`Pending`** as the never-resolving state ("a target that is permanently stuck … remains `Pending` forever"). Two sentences later 0025 itself uses defeated as a resolution ("the request resolves **defeated**, not accepted"), so the section uses one word in both senses. Of 0025's three listed ways, the swallowed-catchable-break and completed-despite-no-break-checks cases are 0024-*defeated* (resolved), while the non-returning-native case is 0024-*Pending* (unresolved). The ledger row `OBL-CANCEL-OUTCOMES`'s gloss "defeated (unresolved)" repeats the error.
Resolution criterion: §6 adopts 0024's vocabulary exactly — defeated = terminal, `Pending` = possibly-forever — and the ledger gloss is corrected.

**C4. (Material) §11 is stale in the false-alarm direction on three rows, against the siblings' current text.**
Evidence: `OBL-CANCEL-COMPLETION` ("not yet") — 0024 §6 already assigns a monotonic target id to "a submitted evaluation, a background callback, a completion query", makes the completion query a cancellation target under the same vocabulary, and AC 17 asserts stale-id discard; both halves of the row are delivered. `OBL-EXIT-PARK` ("not yet") — 0022 §10 (round 8) already states "the call **parks** — it does not return, and it does not unwind past `finally`" and its `OBL-EXIT-MECHANISM` row records citing 0025. `OBL-SEQUENCE-DOMAIN` ("not yet") — 0024 §9 already states "one sequence allocator issues numbers to evaluation outcomes, asynchronous events, **and the session layer's broker events** (LLP 0025 §3) alike — one domain, not two". The preamble's own confession ("read this as a to-do list") mitigates but does not excuse rows that would direct real work at delivered obligations; a fourth-in-one-day staleness event inside the very revision that added the confession is the strongest possible argument for the preamble's conclusion.
Resolution criterion: re-verify every row against named sibling revisions and either pin discharges 0022-style ("verified at 0024 `<rev>`") or drop the status column as 0022 did; the three rows above corrected.

**C5. (Material) §8's commit-rule fallback is incoherent under the supervisor topology it exists for.**
Evidence: "If the lifecycle record cannot be committed to the supervisor within a bound, the worker takes the in-process path instead of parking." The in-process path is "restoration and the bounded flush inside the accepted call, then `_exit`" — but the worker owns no terminal to restore (the supervisor does, §7), and a worker `_exit(n)` with no committed record is indistinguishable from a crash with status `n`; §3 then synthesizes an engine-fault event and §8's matrix ends the session as a fault (status 70), not as `process.exit(n)`. The operator's requested status is silently lost and reported as a fault.
Resolution criterion: specify the worker-side fallback observably — a reserved exit-status convention, a best-effort late record, or an explicit statement that a failed commit degrades to engine-fault semantics with the requested code lost — stated rather than discovered.

**C6. (Material) §12 claims pins that do not exist.**
Evidence: "Renderer depth, breadth, and payload length; the truncation marker; history entry and byte limits; and the broker's queue bounds **are pinned constants with a version**" in "a versioned annex shared with the sibling documents" — but no values appear and no artifact is named, and 0024 OQ 8's current text says the shared annex does not exist yet and 0022's byte-fixtures "cannot be pinned until it exists". AC 4 and AC 7 depend on §12's pins.
Resolution criterion: either the annex values (or the artifact's path and schema) appear, or §12 says "will be pinned" and rows it as an obligation with an owner.

**C7. (Minor/Non-blocking) `OBL-INTERRUPT-CLASS` mischaracterizes 0022's defect.** 0022's "two interrupts against the same running **target**" is not *false* under a turnover storm — it is vacuous there (its precondition never holds across turnover), which means 0022 under-promises rather than lies. In a corpus whose flagship rule is "never tell the operator something untrue," the ledger should not itself say "false" where it means "too weak to cover the case."
Resolution: reword the row.

**C8. (Minor/Non-blocking) The changed-situation notice is asserted but never specified.** The invariant says an operator whose epoch closed "is told *that* instead — a changed situation, not a broken promise," but no table row or notice text defines that event, and AC 7's "every notice printed is asserted true" sweep can only enumerate notices the spec names.
Resolution: name the notice and its trigger.

**C9. (Minor/Non-blocking) Windows suspension is unspecified.** §5 makes `Ctrl+Z` a keybinding whose action is §7's suspend transaction (stop worker group, stop supervisor — POSIX job control); ConPTY is named for raw mode but no Windows meaning for the keybinding is given, while AC 8 tests suspension only via the byte and `SIGTSTP`.
Resolution: one sentence pinning Windows behavior (no-op with notice, or an equivalent).

**C10. (Minor/Non-blocking) The failed-cancellation exit status is "nonzero" in the matrix but absent from the status table.** Presumably 70; the table should say so, since the table is asserted end-to-end by AC 9.

## 4. Cross-document findings

- **LLP 0024 §6's lifecycle outcome still describes the retired mechanism** — "the evaluation **unwinds** as a lifecycle completion carrying `n` … after the evaluation's native frame has unwound" — which 0025 §8 shows is unimplementable on the vendored interfaces and 0022 §10 has already corrected to parking. The target's ledger row (`OBL-LIFECYCLE-OUTCOME`: "partly — the mechanism note is wrong") is **accurate**; the sibling is the defective party and needs the correction landed. A frame that parks never unwinds, so 0024's "services it after the frame has unwound" is not merely stale wording but a wrong sequencing claim.
- **"defeated" vocabulary clash with 0024** — see C3; this is a live normative contradiction, not a nuance.
- **0022 §10 asserts the same "worst case … is three" bound** as 0025's escape invariant; if C1 stands, 0022's summary is exposed with it and both documents move together under the coordinated-revision rule 0022's precedence section prescribes.
- **0022 §11's `OBL-ASYNC-FATALITY` note is now outdated in the safe direction** ("has stood honestly undischarged for four rounds") — 0025 §8 delivers the mode × class matrix in this revision; 0022's fail-closed design tolerates this, but the orchestrator should pin a verified discharge.
- **Consistencies verified (no defects found):** §9 vs 0023 §7.1 worker locality (the quoted rule exists verbatim and the token design complies); §2 vs 0024 §6 (await-unwrap timeout retired, inventory owned by 0025 — both texts agree); §3's unstyled tree and single sequence domain vs 0024 §8/§9; §1's mode selection and fd-0 EOF view vs 0022 §3; §8's fatality rows vs 0022 §3/§5; single-interrupt termination for no-editor modes vs 0022 §10; the keybinding manifest vs 0022 §8's `.help` generation; §12's shared-annex intent vs 0024 OQ 8 (modulo C6's tense).

## 5. Suggestions

1. **Make the three-press bound true by construction**: a consecutive-interrupt counter, reset only by editor input at a live prompt or session end, with the third consecutive interrupt terminating unconditionally (130, or orderly if the latch class is idle-prompt). The class/epoch latch then governs *which* second press is honored early and what the notices say; the counter guarantees the ceiling. This is a smaller machine to model-check and makes C1/C2's ambiguities non-fatal instead of load-bearing.
2. **Stamp notices with the (class, epoch/generation) they were issued against** and define notice truth as a machine invariant: a promise is honored iff its stamp matches at the next interrupt, else the named changed-situation notice is emitted. That converts "every notice is true" from prose into a checkable property of the generated data — the strongest possible version of the document's own remedy.
3. **Name the artifacts**: §6 requires generation and model checking but names no checked-in transition-data file, checker, or CI wiring, unlike the fd-0 route table's registry projection. Give the machine data a path, an owner, and a build gate, and cite it from AC 7.
4. **Adopt 0022's ledger form outright** (no status column; pinned "verified at `<rev>`" attestations only). The target already concedes the column cannot be trusted; keeping it in a weaker form than the sibling's is the worst of both.
5. **Generate the non-session "terminate" tier from the same machine data** as a degenerate two-row machine, so the ordinary-path/handler-only-fallback split and the 130 path get model-checked and PTY-tested from one source of truth.
6. Cross-reference §7's "armed session nonce" to `OBL-FRESH-NONCE` (0022 §7's finding that the shipping `runNonce` is a fixed test vector) — control-record authentication inherits that prerequisite.

## 6. Open questions

1. When a background unit completes beneath an undisturbed live prompt, does the session emit a republish event (bumping the generation) or not? (C2 — this single answer decides which falsification applies.)
2. Is a scheduled-but-not-due timer "in flight" for target selection, and if a first idle interrupt targets running work that has not begun, what does an id-exact request name? (C2/OQ 9 interact: unit identity for not-yet-begun work.)
3. What is the worker's observable behavior when the lifecycle commit fails — reserved status, late record, or declared degradation to fault semantics? (C5.)
4. Should the third-consecutive-interrupt backstop terminate with 130 always, or honor orderly shutdown when the final target is the idle prompt? (Interacts with the deliberate 130-vs-orderly distinction §6 draws.)
5. Where does the §12 annex live, and which document owns its version? (0024 OQ 8 asks the same; one of the three must claim it.)
6. For OQ 6 (supervisor owning one-shot modes): what do `process.pid`/`ppid` report under the split? This is flagged in the document; it will need an answer before the registry rows for `process` observables can be regenerated.

## 7. Readiness verdict

The document's factual base is verified and most sections are sound, but the critical section's stated bound is falsifiable as written (C1) on top of definition ambiguities that flip its behavior (C2), §6 contradicts a sibling's normative vocabulary (C3), and the obligations ledger is again wrong in three rows against the siblings' current text (C4), with two further material gaps (C5, C6).

VERDICT: NOT READY

### Orchestrator verification notes

- **The escape bound is falsified for the FOURTH consecutive round — and both reviewers now
  independently prescribe the same fix.** Both trajectories check out, and the second one I
  would not have found:
  - *Fable*: `setInterval(() => busyWork(500), 1000)` — a workload with **real gaps**. A press in
    a callback targets `(running work, Eᵢ)`; a press in a gap targets `(idle prompt, G)`; latch
    rule 1 **replaces** on class flip, so alternating presses each reset escalation, forever.
  - *Codex*: `editing` with `foo.`, a completion query Q executing, a background callback B ready.
    I1 targets Q (buffer preserved, latch armed). Q ends but B keeps the epoch open. I2 now falls
    to the "editing, otherwise" row → targets the **buffer** → clears the latch. I3 is a fresh
    first against B. I4 terminates. **Four presses, no editor input, no epoch closure.**
  **Root cause:** the latch was doing two jobs — deciding *which* second press terminates early,
  and *guaranteeing* the bound. Any class flip destroys the second job. The two jobs must be
  separated.
  **Adopted (both reviewers converge; Codex calls it an "escape credit", Fable a
  "consecutive-interrupt counter"):** an unconditional **escape credit** that counts consecutive
  interrupts, is **never** reset by a class change, an epoch change, work ending, or time — only by
  **editor input at a live prompt** — and whose **third** interrupt ends the session *regardless of
  what it targets*. The class/epoch latch is demoted to an **ergonomic optimization** that lets the
  *second* press terminate early in the common cases (stuck work; `Ctrl+C Ctrl+C` at idle). The
  bound is now **true by construction** and no longer depends on getting the class/epoch algebra
  exactly right — which is the correct architecture, and is why four rounds of increasingly clever
  algebra kept failing. Safety from the counter; ergonomics from the latch.
- **Two load-bearing terms were ambiguous, and both are now pinned** (Fable C2): *in flight* =
  executing, suspended, or **ready-and-due** — a scheduled-but-not-yet-due timer is **not** in
  flight (LLP 0024 itself distinguishes them). And the **"prompt republish" coupling is deleted
  entirely**: the epoch closes at **quiescence**, full stop. It was the source of the ambiguity and,
  with the credit as backstop, it was never load-bearing for safety.
- **Cancellation vocabulary — CONFIRMED, and my text was wrong in both directions** (Fable C3,
  Codex 2). LLP 0024 defines `Pending` as the nonterminal state ("a permanently stuck target leaves
  the request `Pending` forever") and **defeated** as a *terminal* resolution ("delivered, the target
  kept running, and the target later ended by another route"). My §6 called defeated "never
  resolves" and then used it as a resolution two sentences later. Adopted 0024's algebra exactly;
  the ledger gloss is corrected.
- **The lifecycle commit fallback was infeasible — CONFIRMED** (Codex 3, Fable C5). A worker that
  cannot commit its record cannot "take the in-process path": it owns no terminal to restore and no
  broker to flush, and a bare `_exit(n)` is indistinguishable from a crash, so the operator's
  requested status is silently reported as a fault. Fixed: the control lane carries **preallocated,
  reserved capacity** for the lifecycle record and the commit is **acknowledged** — the worker parks
  only after the supervisor has durably accepted it. A failed commit exits with a **reserved fatal
  disposition** the supervisor recognizes. The in-process path now applies *only* to in-process modes.
- **Restoration ordering contradicted itself — CONFIRMED** (Codex 3). §5 said restore → flush →
  release; §8's orderly shutdown said drain → release → restore → flush. One ordering is now pinned
  everywhere: **restore first, always, with no potentially blocking step before it.**
- **The broker's cutoff vector missed child relays — CONFIRMED** (Codex 4). Child writes arrive
  through their own pipes and never traverse a worker write site, so a barrier could complete with
  child bytes unread. Every **child relay** is now part of the cutoff vector; counter reservation,
  write, and barrier snapshot have one atomic ordering rule; and the **supervisor owns the sequence
  allocator** (the worker requests ranges), which also fixes how a worker-death event is sequenced
  after the worker can no longer allocate. In-process modes have no relay and no cutoff — the broker
  is the sole writer, so ordering holds directly; the cutoff machinery is a supervisor-mode mechanism
  and is now scoped as one.
- **Exit-status precedence was undecidable — CONFIRMED** (Codex 5). Pinned: a fault or interrupt
  status is never overridden by a cleanup failure; cleanup loss upgrades only a *successful* status
  (0 or `n`) to 141, and only when no destination could carry the report. Cancellation `failed` is
  pinned to 70 rather than "nonzero".
- **§12's constants were claimed but absent — CONFIRMED** (both). The claim "are pinned" with no
  values and no artifact was simply false. Values are now given and the annex is named and owned.
- **§11 was wrong in five rows, all in the false-alarm direction — CONFIRMED against the siblings'
  current text**, and I verified each myself rather than taking either reviewer's word:
  `OBL-CANCEL-COMPLETION` (0024 assigns target ids to completion queries), `OBL-SEQUENCE-DOMAIN`
  (0024 puts broker events in the shared domain), `OBL-EXIT-PARK` (0022 already says the call
  **parks**), `OBL-DISPLAY-ACK` (jointly delivered), and `OBL-CANCEL-OUTCOMES` (wrong semantics).
  This is the **fourth** staleness event — and it happened *inside the very revision that added the
  confession that it goes stale*, which is as strong an argument as could be constructed. **The
  status column is therefore removed.** Rows now carry only a *pinned attestation* — "verified at
  `<sibling revision>` on `<date>`" — for rows actually checked, and no forward-looking claim
  otherwise. A column I have now proven four times that I cannot maintain has no business being in a
  normative document.
- **The "already generated" claim was false — CONFIRMED** (Codex 8). §6 said the corpus "already
  generates" the fd-0 table, command table, and keybinding manifest, while §11 marked those very
  artifacts outstanding. Generated artifacts are now described in the **future tense** until their
  checked-in source exists.
- **Completion-query interruption may not be feasible with the current editor — CONFIRMED and
  ACCEPTED as a feasibility limit** (Codex 9). Rustyline invokes the completer **synchronously** and
  blocks inside it awaiting the engine, so a blocked editor cannot consume a `Ctrl+C` byte and redraw
  `foo.`. Moving Hermes to another process does not fix that by itself. The document now states that
  the editor integration must be **non-blocking** — the session owns the input bytes and completion is
  asynchronous to the editor — and that rustyline's synchronous completer **cannot** satisfy §6, so the
  integration is replaced or completion is dispatched asynchronously. This is now part of §7's gate and
  an open question, rather than an assumption.
- **"Input and output are UTF-8" was overbroad — CONFIRMED** (Codex 10). Scoped to editor input and
  session-authored rendering; program output stays byte-exact.
- **The coordinator's inbound (LLP 0023 round 3) — CONFIRMED, and it is the same failure one level
  down.** My `ProjectHistoryIdentity` still **half-borrowed** 0023's concept: I named the generation
  as *birth time with a canonical-path fallback*, while 0023 names `st_gen`/`ATTR_CMNGEN` with a
  retained-descriptor fallback and leaves the primitive **open as its own OQ**. So two documents were
  answering 0023's open question *differently under a shared term*. Renamed to
  **`ProjectHistoryScopeId`**, with its own definition owned entirely here, and an explicit statement
  that it is not 0023's record and does not depend on 0023's open primitive. The lesson is now written
  into the document: **you cannot half-borrow a sibling's concept — either you take its definition
  *and* its open questions, or you name your own thing.** Borrowing the noun while quietly resolving
  its open question is how you assert an answer the owning document has not given.
- **Sibling defects found by Codex and reported, not fixed here**: 0022's submission-credential
  contradiction and its root-import consequence; 0023↔0024's disagreement on whether synthetic
  sources are module-cache keys; 0024's literal-dynamic-import TLA contradiction; 0024 still saying
  the lifecycle frame "unwinds"; and **0023 incorrectly attributing a broad symbolic-startup-diagnostic
  rule to this document** — 0025 says symbolic legacy-history reporting is its own *local* choice and
  expressly acknowledges 0022's startup-diagnostic exemption.

## Round 6 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `cfe6e1a65761`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer. All prior-round
artifacts were moved out of `llp/reviews/` before either round-6 reviewer was launched and restored only
after both had returned. The two reviewers ran concurrently on the same revision.
**Method:** `brief-round6.md` verbatim; full read of the target and the sibling corpus; verification against
the Rust CLI, the Hermes bridge, the vendored Hermes headers, the builtins, `src/host/abi.rs`,
`capsec/registry/`, and `runtime-surface.json`.

### Verbatim review

# Review: LLP 0025 "Terminal Session Ownership and Lifecycle" (round 6, cfe6e1a65761)

## 1. Overall assessment

This is the strongest revision of this document so far, and the §6 rebuild is architecturally correct: separating an unconditional monotone **escape credit** (safety) from a demoted **latch** (ergonomics) is the right decomposition, and I could not falsify the three-press bound by trajectory derivation over the defined event alphabet — including all four historical killers (tight storm, gappy alternating storm, typed-ahead, editing+query+callback) and the additional schedules I constructed. Safety really is arithmetic now. The document's code claims are uniformly accurate — I verified every load-bearing one against the tree, and all held, several with striking precision (the `recv_timeout` completer, the `hermesc` flag omission, the ambient-root `__exactStdinRead` registry row).

However, the document is not ready. I found one genuine internal contradiction in §6 (the credit vs. the shutdown row — reachable by the most ordinary operator action there is, hammering Ctrl+C at an idle prompt), and — bitterly, given the history — the redesigned §11 ledger is already broken in its first outing: its rows do not carry the revision pins its own preamble promises, and at least one attestation is demonstrably false against the sibling's current text, with a second mischaracterizing text the sibling no longer contains. The fifth consecutive ledger failure, inside the revision that redesigned the ledger to stop the first four. Additionally, §3's child-relay cutoff is not implementable as written, §8's acknowledged-commit has a lost-ack race that makes the session print a false report, and the "editor input at a live prompt" definition is ambiguous at exactly the boundary (typed-ahead drained into a republished prompt) that determines what "consecutive" means.

## 2. Strengths

- **§6's separation of safety from ergonomics is the right architecture, and the diagnosis is correct.** One latch was doing two jobs; the credit does the second job unconditionally. Derived independently: tight storm → 2 (epoch survives turnover); gappy storm alternating callback/gap → 3, never more (class flips cannot reset the credit); typed-ahead during a runaway eval → 2 (typed-ahead resets nothing, and the evaluating row discards it); queued submission behind stuck work → 2 (the round-3 four-press path is closed because the interrupt discards the pending submission); suspended top-level `await` → 2 (suspended is in-flight, epoch stays open); wedged completion query from `foo.`+Tab → 2 with buffer preserved; stale latch at a healthy prompt → fresh first interrupt, no surprise exit; not-yet-due repeating timer → quiescent, orderly `Ctrl+C Ctrl+C` (the *in flight* pin to exclude not-yet-due timers, §6, matches LLP 0024's drain table at 0024:213 exactly).
- **§6's generation posture is honest**: "until that source is checked in, the tables below are the specification and the generation obligation is outstanding" — the document does not claim an artifact it lacks, unlike the earlier constants claim it confesses to (§12).
- **The cancellation pessimism is verified and correct.** `asyncTriggerTimeout` is any-thread, terminates the current execution, takes no target (`ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177-193`); `triggerInterrupt_TS` is an empty stub without `HERMES_ENABLE_DEBUGGER` (`hermes/AsyncDebuggerAPI.h:269`); both `hermesc` invocations pass no break-check flag (`build.rs:778-783`, `build.rs:2190-2195`, plus the runtime invocation at `src/bin/ibex/engine/hermes.rs:1838-1840`; `hermes/CompileJS.h:78` defaults `emitAsyncBreakCheck{false}`); no cancellation op exists on the `Engine` trait (`src/bin/ibex/engine/mod.rs:22-99`) and the runtime lock is held across the whole FFI eval (`src/bin/ibex/engine/hermes.rs:877, 887-896`). §6's "may assume the break is uncatchable and merely keep a redundant escape" asymmetry argument is exactly right.
- **§5's feasibility limit is stated correctly and verified.** The shipping completer blocks on `recv_timeout(COMPLETION_DISPATCH_TIMEOUT)` inside rustyline's synchronous `Completer::complete` on the editor thread (`src/bin/ibex/repl/mod.rs:247-259, 32, 393-415`), and the base is evaluated via `Function('return (' + expr + ')')()` on the engine thread (`repl/mod.rs:297`). The budget releases the editor, never the engine — precisely as §6 asserts. Making non-blocking editing a feasibility obligation plus OQ 2, rather than an assumption, is the honest treatment.
- **§8's park mechanism is a real insight**: uncatchable-because-never-returns needs no engine mechanism; the in-process realization (restore + bounded flush inside the accepted call, then `_exit`, never `std::exit`, never destructing, never taking a lock) is exactly the analysis the FFI-lock deadlock demands. The status precedence rule (fault/interrupt never overridden; cleanup loss upgrades only success, only to 141, only when unreportable) is the first time this table has been an actual order.
- **§9 is the best section in the document.** The half-borrowing rule ("either you take its definition *and* its open questions, or you name your own thing") is corpus-quality guidance; `ProjectHistoryScopeId` verifiably does not violate LLP 0023 §7.1's worker-locality rule (supervisor-derived pre-spawn, opaque token to the worker, fingerprint comparison rather than serialized identity — 0023:1241-1249) and no longer shadows 0023's OQ 9 (creation generation ≠ verification generation, different primitive, different purpose). The key-publication analysis (fsync-to-temp + no-clobber rename, losing creator re-reads, never rotate; why exclusive-create-then-write and plain rename each fail) is genuinely careful, and the cwd-fallback and save-at-exit defects it retires are real (`repl/mod.rs:584` falls back to `.`; history persists only at `repl/mod.rs:699`, which a `std::exit` at `src/engine/hermes_runtime.cc:602` never reaches).
- **The motivation is code-true throughout**: one `ex_hermes_poll` drains the whole callback queue and all due timers with only an aggregate count returned (`hermes_runtime.cc:3541-3722, 946-987`); root/runtime principals fabricate read+write entries for unknown fds (`hermes_runtime_fs.cc:158-168, 220-234`); close has no 0/1/2 branch (`hermes_runtime_fs.cc:2776-2795`); children inherit fds 1/2 under `"inherit"` (`hermes_runtime_process.cc:976-998, 1777-1811`); `__exactStdinRead` reads fd 0 with no in-body check (`hermes_runtime_crypto.cc:5031-5073`) and its registry edge carries `positiveSources: ["ambient-root", "handle", "static-floor"]` under `stdio:read` (`capsec/registry/coverage-edges.json:184039-184063`) — §10's characterization is verbatim-accurate.
- **§1's mode/topology separation and the EOF-view honesty** (`process.stdin.isTTY === false` at a prompt, argued as the honest report) are good decisions, recorded as decisions.
- **§12 pins actual values**, closing the "pinned constants with a version" falsehood it confesses.

## 3. Concerns

**C1. (Blocking) §11's attestations violate their own stated form, and at least one is false — the fifth consecutive ledger failure, inside the redesign.**
Evidence: the §11 preamble promises "a *pinned attestation* — 'verified at `<revision>`' on `<date>`'", but every row pins only a document name and a date ("verified … at LLP 0024, 2026-07-12"). LLP 0024 was revised **four times on 2026-07-12**; a date identifies nothing. Both siblings demonstrate the correct form: 0022 pins `0024 b0ff4ea3247e`, `0025 7b89315f8ad7`, `0025 43ff879a257a` (0022:946, 963, 974, 991); 0023 pins `b0ff4ea3247e` (0023:1476). Consequences already realized: `OBL-LIFECYCLE-MECHANISM` is attested "verified outstanding at LLP 0024, 2026-07-12" but 0024's current text **delivers it** — "§6 adopts LLP 0025's **park** lifecycle" (0024:20-21) and the lifecycle outcome row states "The native call **parks and never returns to JavaScript** — it does not unwind … delivered **out of band**, not returned from a frame that unwound" (0024:626); no "after the native frame has unwound" sequencing claim remains. And `OBL-INTERRUPT-BOUND` characterizes 0022 as still saying "two interrupts against the same running **target**" — 0022 §10 no longer contains that language; it is already stated over class and epoch (0022:892-899) — while missing the defect 0022 *does* still have (see Cross-document findings). Removing the status column was right; shipping unpinned, already-wrong attestations in its place is the same disease.
Resolution criterion: every attestation carries a content-derived revision id (e.g., `git hash-object` of the sibling file, since these files are untracked), matching the preamble's own format; `OBL-LIFECYCLE-MECHANISM` and `OBL-INTERRUPT-BOUND` are re-verified against the siblings' current text and corrected.

**C2. (Blocking) §6's escape credit collides with the shutdown row, on the most ordinary trajectory there is.**
Evidence: press 1 at an idle prompt (credit 1, latch idle) → press 2 (same class) → **orderly shutdown begins** (credit 2) → press 3 lands during the drain. The shutdown row's first column says press 3 merely **expedites** (abandon the drain budget) and a *fourth* press exits "with the status already determined." The credit says "**the third consecutive interrupt ends the session, whatever it targets** … orderly shutdown if it targets the idle prompt, **else 130**" and "no row can override it" — press 3 targets the *shutdown* class, not the idle prompt, so the credit mandates immediate termination with **130**, converting a requested orderly exit (honoring `process.exitCode`) into an interrupt status. The two rules disagree on both behavior (expedite vs. terminate) and status (determined-status vs. 130), and §8's precedence ("a fault or interrupt status is never overridden") cannot arbitrate because it never says whether a credit-exhausting press during an already-orderly shutdown *is* an interrupt termination. An operator hammering Ctrl+C three times at an idle prompt — the canonical stuck-operator gesture — hits this.
Resolution criterion: one rule. Either the credit's status clause becomes "orderly if it targets the idle prompt **or an orderly shutdown in progress** (expedite-then-immediate, status already determined), else 130," or the shutdown class is excluded from the credit with an argument for why the bound still holds there (it does — the shutdown row's own two presses terminate). AC 7 gains the triple-press-at-idle trajectory with an asserted exit status.

**C3. (Material) "Editor input accepted at a live prompt" is ambiguous exactly where it decides the machine's arithmetic: typed-ahead drained into a republished prompt.**
Evidence: §6 says typed-ahead bytes "accumulate, they reset nothing … There is no live prompt to accept them" — a statement about typing time. But the credit's only reset is "editor input **accepted at a live prompt**" — and when work ends and the prompt republishes, the accumulated bytes *are* accepted at a live prompt. Trajectory: press 1 during running work (credit 1) → operator types `ab` (typed-ahead) → work ends, quiescence, prompt republishes with `ab` drained into the buffer → press 2. If the drain counts as editor input, credit reset to 0 and the operator needs up to four more presses (2: discard buffer; 3: idle notice; 4: exit) — the letter of the invariant survives only because "consecutive" is defined by the same ambiguous term, which is worse. If it does not count, press 3 ends the session. AC 7's event alphabet distinguishes "keystroke-at-prompt" from "typed-ahead byte" but never says which event a drained byte is. The transition data cannot be authored until this is pinned.
Resolution criterion: §6 states explicitly whether bytes physically typed while no prompt was live reset the credit/latch when later drained into a live prompt (I recommend: they do not — the operator typed them while stuck, and under §7 the session owns fd 0 and can timestamp bytes against prompt liveness, so it is implementable); AC 7 gains the drain-then-press fixture.

**C4. (Material) §3's per-relay byte cutoff is not implementable for child relays as written.**
Evidence: §3 pins "the counter is advanced when bytes are **accepted for write**" and "a barrier carries **the value of every relay's output counter** at the moment it was created," with the vector covering "every live child relay — a child's bytes arrive on its own pipe and **never pass a worker write site**." Those two sentences contradict: if a child's bytes never pass a session write site, there is no acceptance event to advance a counter, and the barrier's creator (the worker, which allocates the sequence number for the result event) cannot snapshot a number that only exists as unread bytes in a kernel pipe buffer. Bytes a child wrote before the barrier but that no relay has yet read are invisible to any snapshot, so AC 6's "program output emitted during an evaluation precedes that evaluation's result" is not deliverable for child output under any counter placement — child writes are only causally ordered once *read*.
Resolution criterion: §3 defines where the child-relay counter lives (bytes accepted by the relay *reader*), who snapshots it (the supervisor, on barrier arrival, not the worker at creation), and scopes the ordering guarantee honestly (child bytes are ordered as of relay acceptance, not as of the child's `write(2)`); or child pipes are routed through a worker-side pump so acceptance is a session event. AC 6's child fixture asserts the achievable property, not the unachievable one.

**C5. (Material) §8's acknowledged commit has a lost-ack race in which the session reports something false.**
Evidence: the worker parks "only after the supervisor has **durably accepted** the record"; on ack timeout it exits with the reserved fatal disposition, and the supervisor "restores the terminal, drains what relay bytes it has, and exits with the pinned fault status, **reporting that the requested code was lost**." If the supervisor durably accepted the record and the *acknowledgement* was lost or delayed past the bound, the supervisor holds the record — code `n`, cutoffs and all — while the spec directs it to exit with a fault status and print a report ("the requested code was lost") that is untrue. That collides with the document's own "every notice is true" ethic and needlessly converts a successful `process.exit(7)` into a fault.
Resolution criterion: the supervisor's handling of the reserved disposition keys on **record possession**, not on the worker's exit path: reserved disposition + accepted record ⇒ proceed as a cooperative exit `n` (the commit succeeded; only the ack was lost); reserved disposition + no record ⇒ the fault path as written. The ack bound itself joins §12 or OQ 8 — it is currently in neither. AC 9 gains the ack-lost-after-accept fixture.

**C6. (Material) §6's tables under-determine the machine in four named places — and the tables are, by §6's own declaration, the specification until the generated artifact lands.**
Evidence: (a) the idle-row first column prints "`cancellation requested: <what>`" — but for work that is merely *due* (no id yet) §6 says the interrupt "latches and notices **without raising a request**"; printing "cancellation requested" there would be false, and the alternative notice text is unspecified. (b) The changed-situation notices (`work finished — press Ctrl+C again to exit`, `now running <what>…`) exist only in the invariant prose; no table row emits them, and their trigger predicate (previous consecutive press's class ≠ current target class, presumably) is never stated — the deleted "prompt republish" event must not sneak back in as their implicit emission point. (c) The latch is `(class, epoch)` but the epoch component is undefined for non-work classes (idle prompt, operator input, shutdown) — whether an idle latch survives an intervening tick's epoch is undecidable from the text. (d) In the evaluating row with *both* a suspended unit and an executing callback in flight (same epoch), "request cancellation of the in-flight unit" is singular and does not say which id the request carries. None of these breaks the bound (the credit is class-blind), but a generated model must decide all four, and today the tables are normative.
Resolution criterion: the four decisions are written into the tables (or into the transition-data description) before OBL-INTERRUPT-MODEL is authored: the due-only notice text; the changed-situation trigger and emission point; the epoch value for non-work latches; the executing-over-suspended target-selection rule.

**C7. (Material) §8's mode × failure-class matrix — the table this document "has owed" its siblings — is missing the undecodable-input class that 0022 already depends on.**
Evidence: 0022 §3 states "In transcript mode, malformed bytes are **fatal** until a framed protocol exists" (0022:441-443, `OBL-UTF8`), and 0024 §1 owns the strict refusal. §8's matrix has no row for input that could not be decoded; its nearest row ("parse / recoverable syntax error — reported; session continues" in REPL modes) gives the opposite answer if the refusal is misfiled as a parse error. A matrix advertised as the complete delegated fatality table cannot be silent on a class a sibling has already dispositioned.
Resolution criterion: §8's matrix gains an undecodable-input row (interactive: recoverable at the byte-stream level or session-fatal — pick one; transcript: fatal with a named status until a resynchronization boundary exists; program/one-shot: fatal, matching 0022's nonzero exit), cross-checked with 0022 §3 in the same change.

**C8. (Minor/Non-blocking) §12's open-budget cross-reference is wrong twice.**
Evidence: "remain open (OQ 7)" (0025:869) — the budgets question is **OQ 8** (0025:958); OQ 7 is the supervisor-uniformity question. And the list's criterion, "budgets whose right values genuinely depend on OQ 1's prototype," does not cover the **history-lock bound**, which depends on disk and lock behavior, not on a Hermes cancellation prototype — by §12's own criterion it should be pinned now. (Ironically, §11 forbids ordinal citations because "open-question ordinals … have renumbered nearly every round"; §12 demonstrates why.)
Resolution criterion: fix the ordinal (or replace it with prose); either pin the history-lock bound in the annex or restate the deferral criterion.

**C9. (Minor/Non-blocking) The "adopts LLP 0024's algebra exactly … verbatim" claim is very slightly overstated, and "primary cause" is undefined for one reachable coincidence.**
Evidence: 0024 defines *accepted* as "the evaluation **actually returned** at a safe point and the runtime passed its consistency check … never by a break having been raised" (0024:738-741, 760); 0025 phrases it as "stopped because of the request — it produced the `cancelled` outcome" — equivalent for evaluations, but a completion query has no `cancelled` outcome channel (0024: for a callback or query, "*accepted* means it returned"). And 0024 resolves an eternal `Pending` as `failed` on "runtime destruction or **supervisor termination**" while 0025 says "the runtime is destroyed or the **worker** is terminated" — the worker phrasing is the operationally correct one, but "verbatim" it is not. Related: when the second interrupt terminates the worker, the outstanding request resolves `failed` — and §8's matrix says a `failed` cancellation "ends the session, **70**" while the interrupt termination is **130**; "the primary cause determines the status" is asserted but *primary* is never defined.
Resolution criterion: soften "verbatim" to "adopts … with the worker-termination reading," or reconcile the two sentences in one coordinated edit; define primary cause (the event that initiated termination; a `failed` resolution *caused by* escape or shutdown does not re-enter the matrix).

## 4. Cross-document findings

1. **Live contradiction — 0022 §10's epoch definition is the one this revision deleted.** 0022:896-897: "An epoch opens when work becomes in-flight from quiescence and closes only on quiescence **plus a republished prompt**." 0025 §6: the epoch "closes at **quiescence** alone — no in-flight work. **Nothing else**," explicitly retiring the undefined republish event. 0022 discharged its `OBL-INTERRUPT-CLASS` against 0025 `7b89315f8ad7` — a pre-round-6 revision — and is now stale in exactly the honest, detectable way its pin was designed to reveal. The sibling is defective here and must be revised in the same change.
2. **0022 §10 over-promises the two-press bound.** "**Two interrupts within one work epoch** end the session" (0022:899, AC 15 at 0022:1133) omits 0025's same-*class* condition: two presses within one epoch where the first targets a non-empty buffer (editing row) do not terminate. 0022's own "worst case … is three" sentence is correct; the two-press sentence as stated is falsified by 0025's machine.
3. **Target ledger vs. 0024:** `OBL-LIFECYCLE-MECHANISM` is stale-false (delivered at 0024:20-21, 626); `OBL-INTERRUPT-BOUND` mischaracterizes 0022's current text (see C1). The rows that attest "delivered" — `OBL-DISPLAY-TREE` (0024 §8 owns the unstyled tree, 0024:1365-1384), `OBL-CANCEL-ALGEBRA` (0024:736-770), `OBL-CANCEL-TARGETS` (0024:771-776), and the sequence-domain half of `OBL-SEQUENCE-ALLOCATOR` (0024:1425-1428, which indeed does not name the allocator owner) — all verify TRUE against current text, as do "outstanding" for `OBL-UNIT-PUBLICATION` (0024 assigns ids but specifies no native begin/end publication seam, and OQ 9's TLA-unit boundary is unanswered there), `OBL-REGISTRY-ROWS` (no `lifecycle:exit` capability exists; exit surfaces are `closed` under `process:signal`/`runtime:inspect`; no listener rows — `capsec/registry/capability-definitions.json`, `coverage-edges.json:174033-215921`), and `OBL-CLI-SURFACE` (`runtime-surface.json` is clapSurface-only; no history or keybinding rows).
4. **0022's ledger is itself stale against 0023.** `OBL-STARTUP-DIAG` (0022:993) reports a three-way conflict — "LLP 0023 §1.2 mandates a **symbolic** package locator and attributes that rule to LLP 0025" — but 0023's current §1.2 says the opposite: "The refusal diagnostic **names the host path**, and that is correct … **No such rule exists**" in 0025 (0023:299-315). The three documents are now consistent (0022 §4 exempts startup diagnostics; 0025 §9 makes its symbolic choice on its own grounds and correctly cites 0022's exemption; 0023 names host paths pre-JavaScript); only 0022's row still reports the resolved conflict. Likewise 0022's `OBL-BOUNDS` "(open in both)" is half-stale now that 0025 §12 pins values.
5. **§9 vs. 0023 — clean.** `ProjectHistoryScopeId` does not violate 0023 §7.1's worker-locality rule (supervisor-derived pre-spawn; only an opaque token crosses; the root fingerprint is a comparison value, not a rehydratable identity — and 0023:1247-1249 explicitly exempts non-authority-bearing data), and it no longer answers 0023's OQ 9 (creation generation via `st_birthtime`/`STATX_BTIME` is a different primitive from the verification generation `st_gen`/`ATTR_CMNGEN` that 0023 leaves open). The prior defect is genuinely fixed, and the stated rule is worth promoting corpus-wide.
6. **Bounds ownership is half-settled.** 0025 §12 pins "renderer depth/breadth/payload length," which 0024's OQ 8 still lists as open in "one versioned constants annex shared with LLP 0025" — the annex now exists, but 0024 §8 *also* bounds the worker-side walk "in depth, breadth, string length," and nothing says whether walk bounds and renderer bounds are the same constants. OQ 11 gestures at absorption without noticing §12 already partially did it.
7. **Consistency verified elsewhere:** display-acknowledgement-at-barrier (§3 ↔ 0024 §7.8); the shared sequence domain (§3 ↔ 0024 §9); the await-unwrap-timeout retirement and environment-inventory split (§2 ↔ 0024 §6/AC10); not-yet-due timers (§6 ↔ 0024's drain table); the fd-0 EOF view (§1 ↔ 0022 §3); the failure-matrix delegation (§8 ↔ 0022 §3, 0024 §9); `➤ ` and pre-arming capture (§2 ↔ 0022 §10); the completion-query treatment (§6 ↔ 0022 §9's no-candidates rule and 0024 §8's primitive gating).

## 5. Suggestions

- **Derive the latch instead of storing it.** The latch is exactly "the previous interrupt's `(class, epoch)` within the current consecutive run" — rules 1–4 all follow from that definition plus the credit's reset. Making it derived state removes a component from the generated model, shrinks the reachable space AC 7 must enumerate, and eliminates the arm/clear rules as a separate falsification surface. The credit is not a band-aid; this is the last step of the same simplification.
- **Make the credit visible.** Let notices carry the countdown ("press Ctrl+C again to end the session — 2 more presses force exit"). It makes the bound self-documenting and turns "every notice is true" into something the operator can see being honored.
- **Generate the notice texts from the transition data** and model-check "every notice is true" as a temporal property (every emitted promise formula holds on all suffixes under the adversarial scheduler), rather than leaving it a prose obligation beside a generated machine. This also forces C6(a)/(b) to be decided.
- **Pin the reserved fatal disposition value and the lifecycle-ack bound in §12** — both are constants the conformance suite must assert, and neither is currently in the annex or OQ 8's deferral list.
- **Adopt 0022's revision-pin discipline verbatim** (content hash of the sibling file), and land the 0022 §10 epoch/same-class fix in the same coordinated change as this document's next revision, per 0022's own invalid-corpus-state rule.
- For PTY testability, add to AC 7/8 a **byte-level fault harness**: inject `Ctrl+C` bytes through the PTY (not signals) while the worker is `SIGSTOP`ped, to exercise the raw-mode/ISIG-off premise itself and the supervisor's independence from the worker — the two facts the whole bound stands on.

## 6. Open questions

1. Does typed-ahead drained into a republished prompt reset the credit and latch (C3)? Recommended answer: no; requires byte-liveness tracking the supervisor can do.
2. Where does a child relay's counter live, and is child output ordered by write or by relay acceptance (C4)? This decides how strong AC 6's child clause can honestly be.
3. Should a third consecutive press during an already-orderly shutdown ever yield 130 (C2), or is expedite-then-immediate with the determined status the only sane behavior?
4. Are 0024 §8's walk bounds and §12's renderer bounds one constant set or two, and which annex rows do they read?
5. If OQ 5's respawn ever lands, what happens to the supervisor-owned sequence domain across worker generations — 0022's `OBL-SEQUENCE` already demands "crash epochs and worker-restart behavior" that neither §3 nor 0024 §9 yet states.
6. Once 0024 §8 retires base-expression evaluation for completion (no-candidates fallback, trap-free walk only), is the completion-query row's "killable work" framing still load-bearing — i.e., can a trap-free bounded walk still wedge, or does the row survive only as defense against the walk queuing behind a busy engine? Worth one sentence so a future simplifier doesn't delete the row for the wrong reason.

## 7. Readiness verdict

The §6 rebuild is the right machine and, for the first time in six rounds, I could not break its bound from any reachable state I could construct — but the shutdown-row collision is a genuine internal contradiction in the critical section, the ledger's first-outing attestation failures repeat the exact defect this revision existed to end, and §3/§8 each contain one mechanism that cannot be implemented or would print a falsehood as specified.

VERDICT: NOT READY

### Orchestrator verification notes

- **THE BOUND HELD.** For the first time in six rounds, **neither** reviewer could falsify §6.
  Both independently derived the full attack set — tight storm, gappy storm in both phasings,
  typed-ahead, queued submission, suspended TLA, wedged completion query, stale latch, future-only
  timer — and every trajectory landed at ≤3. Codex's judgment is the one to keep: *"escape credit is
  a monotone progress measure that no class or epoch transition can undo. I do not regard it as a
  band-aid. Separating safety from the latch's two-press ergonomics is the right architecture."*
  **The lesson is worth more than the fix.** Four rounds of increasingly clever latch algebra all
  failed; one round of *refusing to do algebra* survived. Safety stopped being **derived** from case
  analysis and started being **asserted** as arithmetic. A future author will be tempted to fold the
  credit back into the latch as a "simplification" — that is the mistake this section made four times,
  and the document now says so in place.
- **"Every notice is true" is FALSE — CONFIRMED**, and this is the round's most valuable finding
  (Codex 2; Fable C6b). The lies are concrete: (a) the idle notice promises the next interrupt exits,
  but if a scheduled timer becomes **due** before that press, the next interrupt targets running work,
  does not match the idle latch, and does not exit; (b) the running-work notice promises the next press
  ends the session, but if the work ends and the next press targets a preserved edit buffer, it only
  clears the buffer; (c) work that is merely **due** has no target id and raises no cancellation
  request, yet the table printed `cancellation requested`. And the changed-situation notice **cannot
  repair** any of it: if it is emitted on the second interrupt, the first promise has *already* failed.
  **Accepted, with the same move that fixed the bound.** Notice truth is now **arithmetic, not case
  analysis**: any notice that says "the next interrupt ends the session" atomically sets an
  **irrevocable promise** — and the next interrupt then ends the session, whatever it targets, with the
  status the notice implied. The promise cannot be invalidated by a class flip, a timer becoming due, or
  work ending, because *nothing* consults the target to decide whether to honor it. The changed-situation
  notice is **deleted**: it existed only to paper over promises the machine could not keep, and a machine
  that keeps its promises does not need it. This also collapses the common case to **two** presses
  whenever a promise was printed, leaving three only for the editing row, which prints none.
- **The shutdown-row collision — CONFIRMED** (Fable C2; Codex 8), and its *shape* is the lesson. I wrote
  "no row can override the credit" and then wrote a row that does, reachable by the most ordinary gesture
  there is: hammering `Ctrl+C` three times at an idle prompt (press 2 begins an orderly shutdown; press 3
  targets the *shutdown* class, so the credit demanded 130 while the shutdown row promised the
  already-determined status). **An invariant stated in one place and violated in another reads perfectly
  fine in both places.** The fix is a single cause-precedence rule: once a termination cause is latched,
  later interrupts may **shorten** cleanup but never **change** its status.
- **§6's declared state is insufficient — CONFIRMED** (Codex 1; Fable C6). The tuple could not determine
  transitions: completion-query presence and id, buffer generation, pending submission, **typed-ahead
  provenance**, the executing/suspended/ready unit sets, pending requests, and the determined shutdown
  status all select transitions and none were declared. The latch type `(class, epoch)` is ill-typed for
  idle and shutdown, which have no epoch. Accepted: the state is expanded, the latch becomes a sum
  (`Idle | Running(epoch) | Shutdown`), and — following Fable's suggestion — the latch is **derived**
  rather than stored (it is exactly the previous interrupt's target within the current consecutive run),
  which removes a whole component and its arm/clear rules from the model.
- **Typed-ahead drained into a republished prompt — CONFIRMED as ambiguous** (Fable C3; Codex 1) and now
  pinned: bytes typed while **no prompt was live** do **not** reset the credit or the promise when they are
  later drained into one. The operator typed them while stuck. This is implementable precisely because §1
  gives the session fd 0: it can mark each byte with prompt-liveness at arrival.
- **The completion-query row is not implementable by the shipping editor — CONFIRMED, and promoted from an
  open question to a release gate** (Codex 3). The completer blocks on `recv_timeout` *inside* rustyline's
  synchronous `Completer::complete` on the editor thread, so while a query is wedged rustyline **cannot
  consume a `Ctrl+C` byte at all** — the physical keypress never becomes a machine event. Moving Hermes to
  a worker does not change that. A PTY prototype that consumes `Ctrl+C` while the query is wedged, and
  redraws the exact preserved buffer, is now a **gate**, not a choice.
- **Suspended-TLA target selection — CONFIRMED ambiguous** (Codex 4). LLP 0024 permits background work to
  run *while* a TLA input is suspended, so "the in-flight work" was not singular. Now an **ordered
  selection function** over the live-unit set: executing ≻ suspended ≻ due. The cancellation edges are also
  corrected: consistency-check failure resolves `failed` **immediately** (not only at teardown), `accepted`
  is **target-generic**, and the structured `cancelled` outcome is restricted to evaluations.
- **§3's relay and sequence protocol — CONFIRMED broken in three ways** (both). (a) It said fds 1 and 2 are
  duplicates of *one* open file description and then described them as *separate* relays with separate
  counters. (b) The child-relay cutoff is **not implementable**: a child's bytes never pass a session write
  site, so there is no acceptance event to count and a worker-created barrier cannot snapshot bytes sitting
  unread in a kernel pipe. Accepted, with the honest narrowing both reviewers converged on: child output is
  ordered **as of relay acceptance**, not as of the child's `write(2)` — the observable property, stated
  instead of the unobservable one. (c) **A direct contradiction with LLP 0024, and 0024 is right**: it
  assigns sequence numbers at **session-layer receipt** precisely because a hostile worker must not mint
  them. I had the worker drawing ranges. Adopted 0024's rule; my §3 was the defect.
- **"Hostile worker" overclaimed — CONFIRMED** (Codex 6), and this is a genuine honesty failure I should
  not have shipped. A same-UID hostile **native** process can open the concrete terminal device, read
  `/proc/<supervisor>/fd`, ptrace where permitted, spawn detached descendants, and pass descriptors — and it
  **knows the session nonce**, so it can forge authenticated records. *Authentication proves channel
  membership, not truthfulness.* The threat model is now split into three profiles and the document claims
  only what the platform actually enforces: stuck/crashed engine; **hostile JavaScript behind intact native
  mediation** (the profile this design really delivers); and a compromised native worker, which needs
  platform sandboxing this document does not yet specify.
- **The lifecycle commit's lost-ACK race — CONFIRMED** (both): the supervisor could hold an accepted record
  for code `n` while the spec directed it to exit with a fault status and **print that the requested code was
  lost — a falsehood**, in a document whose thesis is that the session never tells the operator something
  untrue. Fixed with an **idempotent request id**: an accepted commit wins even if its ACK is lost. The
  unbounded per-child cutoff vector is replaced by a **fixed-size supervisor-owned snapshot token**.
- **§11 failed a FIFTH time, and the diagnosis is now final.** Removing the status column was right; what I
  put in its place was not an attestation. Every row pinned a document *name and date* — and LLP 0024 was
  revised **four times that day**. The proof is in this very round: I computed 0024 at `9bdcdf4479a6` and
  Codex, reading minutes later, computed `88ebc6349bab`. **My attestation was meaningless on the day I wrote
  it.** Multiple rows were already false: 0024 now *delivers* the park mechanism and native unit publication
  I attested as outstanding, and 0022 no longer contains the language I quoted. Codex also caught that moving
  "delivered/outstanding" into the obligation prose **preserved the status column under another name**.
  Adopted, in the coordinator's words: **an attestation without a content hash is not an attestation.** Rows
  now carry a structured attestation with an exact **content digest**, and a digest mismatch **visibly
  invalidates** the claim. This is the same discovery the review artifacts made about session ids —
  provenance without a hash is a story you tell yourself — and it is not a coincidence that both landed in the
  same session.
- **Sibling defects found and reported, not fixed here**: 0022's epoch definition (still "quiescence **plus a
  republished prompt**" — the coupling this revision deleted), its two-press over-promise (missing the
  same-class condition), and its stale startup-diagnostic ledger row; 0023's duplicated existence-oracle
  paragraph, its ledger's surviving `Landed?` status column, and a stale module-identity stamp; 0024's
  `[[SessionCreatedVars]]`/`[[VarDeclaredNames]]` mismatch, its self-contradictory rollback AC, its claim that
  0023 lacks a root-owned `SourceId` arm (0023 defines one), and its module-cache AC contradiction.

## Round 7 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `19de10797c67`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@ab8658a68b57`, `0024@88ebc6349bab`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer. All prior-round
artifacts were moved out of `llp/reviews/` before either round-7 reviewer was launched and restored only after
both had returned. The two reviewers ran concurrently on the same revision.
**Method:** `brief-round7.md` verbatim; full read of the target and the sibling corpus; verification against the
Rust CLI, the Hermes bridge, the vendored Hermes headers, the builtins, `capsec/schema/`, `capsec/registry/`,
and `runtime-surface.json`.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle (rev `19de10797c67`, round 7)

## 1. Overall assessment

This is a strong round on the axes that matter most, and a sloppy round on the axis this document claims as its identity. The two headline moves — the escape credit and the promise bit as *arithmetic* rather than case analysis — are the right design, and they survive adversarial analysis as mechanisms: I attacked the bound with every schedule named in AC 7 plus the drain-into-prompt case and several of my own (promise-then-timer-due, promise-then-work-finishes, drained typed-ahead refilling a buffer mid-run, non-promising chains through the evaluating-undispatched row) and could not construct a fourth consecutive press, nor a printed promise the machine's *rules* permit to be broken. Cause precedence correctly resolves the triple-`Ctrl+C`-at-idle trajectory. The threat-model narrowing in §7 is honest and correct; §8's idempotent commit and §9's equality-proof design are genuinely good decisions; and the empirical claims are unusually accurate — every load-bearing code claim I checked verified at file:line, without exception.

But the round shipped with revision debris that contradicts its own new machinery in four places: the termination *status* under a promise is specified two incompatible ways (§6 vs §6/§8); the promise bit's reset rule is unstated, and taken literally produces the exact "session-ending surprise on a typo-clearing `Ctrl+C`" that §6 forswears; a leftover `(class, epoch)` latch definition survives twenty lines below the paragraph that repudiates it; and AC 7's schedules (b) and (d) still assert round-6 press counts that the round-7 promise bit reduces to two. Every one of these is the defect class the document itself names — "an invariant stated in one place and violated in another reads perfectly fine in both places" — and every one is surgically fixable. The ledger's digest fix holds where it was applied and is only half-applied.

## 2. Strengths

- **§6's separation of safety from ergonomics is now real, and it holds.** The credit is unfalsifiable by construction: nothing but editor input at a live prompt resets it, so the three-press bound is a counting argument, not a case analysis (§6, escape credit; latch rules 1–4). My strongest attack — evaluating-undispatched (no promise, no latch) → idle → terminate — confirms that every credit-exhausting third press was *announced by the second*, because every path to press 3 passes through an idle row that promises. The machine cannot terminate unannounced.
- **Provenance-travels-with-the-byte (§6, editor-input definition) is a genuinely novel and correct idea.** Marking prompt-liveness on arrival, so typed-ahead drained into a republished prompt cannot masquerade as an interactive operator, closes the drain-into-prompt attack cleanly — and §1's fd-0 ownership is precisely what makes it implementable, a nice cross-section dependency stated rather than assumed.
- **Empirical grounding is exemplary.** §Motivation and §6/§7's claims all verify: `__exactExit` → `std::exit` (src/engine/hermes_runtime.cc:588-602, 1704-1727); the blocking completer (`recv_timeout` inside rustyline's synchronous `Completer::complete`, src/bin/ibex/repl/mod.rs:247-259, 393-411) evaluating its base via `Function('return (' + expr + ')')()` on the engine thread (297); history's cwd fallback (`unwrap_or_else(|| PathBuf::from("."))`, 584) and save-at-exit (699); the FFI lock held across the whole native call (src/bin/ibex/engine/hermes.rs:490, 545-561) with no cancellation op; `hermesc` invoked with no break-check flag (hermes.rs:1837-1847) against a compile default of off (ios/Frameworks/hermes-headers/hermes/CompileJS.h:78) while `AsyncBreakCheckInEval` defaults on (Public/RuntimeConfig.h:63) — both halves of §6's compilation claim; one `ex_hermes_poll` draining a whole callback queue plus due timers (src/engine/hermes_runtime.cc:3541-3628); `principalMayUseUnknownFd` waving root/runtime principals through on guessed integers (src/engine/hermes_runtime_fs.cc:158-168); `close` reaching the real descriptor with no 0/1/2 branch (fs.cc:2787-2790); `triggerInterrupt_TS` an empty stub without `HERMES_ENABLE_DEBUGGER` (AsyncDebuggerAPI.h:269,276); `runNonce` schema-checked as bare base64url (capsec/schema/armed-snapshot.schema.json:68-70); `__exactStdinRead` an effects edge with `positiveSources: ["ambient-root", …]` and no `lifecycle:exit` capability (capsec/registry/coverage-edges.json); no history/keybinding rows in runtime-surface.json; no SIGINT handler on the REPL path (the only `ctrl_c` is in `run_debug_loop`, src/bin/ibex/main.rs:1089).
- **§7's three-profile threat model draws the boundary in the right place.** "Authentication proves channel membership, not truthfulness" is exactly right about a nonce-holding native worker, and declining to claim containment of same-UID native code (OQ 12) is the honest scoping — claiming it would indeed be a lie on macOS/Linux without sandbox machinery.
- **§8's park-not-unwind and the idempotent commit are correct decisions.** Parking needs no engine mechanism (verified: no unwind interface exists in the vendored headers), the in-process `_exit`-inside-the-accepted-call analysis (deadlock on the held FFI lock) is exactly right, and keying the supervisor on *what it holds* rather than *how the worker died* removes a real falsehood.
- **§9 is the best history design in this corpus.** Append-at-submission with a recoverable framed journal, the lock-before-recovery rule (an unlocked reader truncating a live append is a subtle and real hazard), the two-failure key-publication analysis (rename-replaces vs crash-between-create-and-write), the precise HMAC threat model, and the "you cannot half-borrow a sibling's concept" rule are all decision-quality work. The nonce-bound equality proof is a genuinely novel resolution of the locality tension.
- **§11's digest discipline holds where applied.** I recomputed both pinned digests: `0022@88decefdc683` and `0024@88ebc6349bab` both match current files, and the rows' *claims* verify — 0022 really does still couple epochs to "a republished prompt" (0022:897) and really does state the falsified two-press sentence (0022:899); 0024 really does deliver unit publication (0024:762-767) and receipt-time allocation (0024:1603-1613). Mismatch-means-unverified is the right semantics: staleness becomes detectable instead of silent.

## 3. Concerns

**C1 — The latch's type is defined two incompatible ways in §6. (Material)**
Evidence: §6 states "Its type is a sum — `Idle | Running(epoch) | Shutdown` — because *operator input* never latches … the earlier `(class, epoch)` pair was ill-typed for two of its four cases" (target ~line 433-435), and twenty lines later a state bullet reads "**Latch** = `(class, epoch)`. Classes: **idle prompt**, **operator input** …, **running work**, **shutdown**" (~line 455-456) — the exact repudiated definition, surviving as normative text. Since `OBL-INTERRUPT-MODEL` is "not started," §6's prose *is* the specification (§6's own words, ~line 410), so the machine's core datum is ambiguous.
Resolution: delete the `(class, epoch)` bullet; the sum type and the "latch is derived" paragraph stand alone.

**C2 — The status of a promise-triggered termination is specified two contradictory ways. (Material)**
Evidence: §6 rule 2: the next interrupt ends the session "whatever it targets, **with the status that notice implied**" (~509-511). But §6's fallback sentence — "Where no cause is yet latched, a credit- or promise-triggered termination takes **130** if **its interrupt targets** running work or the operator's input, and the **orderly** status if it targets the idle prompt" (~544-546) — and §8's table ("**any §6 interrupt termination** — a promised second press … — **whose target is** running work or operator input | **130**"; "whose target is the **idle prompt** | the orderly status", ~761-762) key the status on the *terminating press's* target. On the two class-flip trajectories AC 7 itself names (~1025-1027) these disagree: idle promise → timer becomes due → press 2 targets running work (notice-implied: orderly; target-based: 130), and running-work promise → work finishes → press 2 targets the idle prompt (notice-implied: 130; target-based: orderly). The exit status — an operator- and script-visible contract — is formally contradictory, inside the round's flagship fix.
Resolution: bind the status into the promise bit at notice time (the reading consistent with "irrevocable" and with the revision note's "with the implied status"), and rewrite the §6 fallback sentence and both §8 rows to key promised terminations on the *promise's* target and only unpromised credit terminations on the press's target. AC 7's two flip assertions should then name the expected status, not just "exits."

**C3 — The promise bit has no stated reset, and "irrevocable" taken literally produces the surprise §6 forswears. (Material)**
Evidence: the credit has an explicit reset clause ("reset **only** by editor input at a live prompt, or by session end," ~452-453); the promise bit has none — §6's notice invariant says the next interrupt terminates "Unconditionally — whatever it targets, whatever the engine has done in between, and whatever class or epoch has changed" (~568-571). Trajectory: running-work promise printed; work finishes; operator *types a new command* (editor input — credit resets, latch clears per rule 3, ~550-552); minutes later presses `Ctrl+C` to clear a typo'd buffer. Under the literal text the bit is still set and that press **ends the session** — precisely the "common session-ending surprise" §6 rejects when it defends the editing row's three-press trade (~582-585). AC 7 quietly assumes the missing rule: it model-checks the notice invariant only "under arbitrary intervening **non-input** events" (~1024-1026). Normative text and checked property disagree about whether typing intervenes.
Resolution: add to §6, symmetric with the credit: *the promise bit is cleared by editor input accepted at a live prompt (which typed-ahead — including typed-ahead drained into a republished prompt — is not) and by session end; it is otherwise irrevocable*; qualify the notice invariant's "unconditionally" to match.

**C4 — AC 7's schedules (b) and (d) assert round-6 press counts the round-7 machine falsifies. (Material)**
Evidence: §6's consequences paragraph: "every first interrupt in the idle and running-work rows prints a promise, so those cases now terminate in **two** presses unconditionally. Three are needed only from the **editing** row" (~528-531); the escape invariant repeats it (~565-567). But AC 7(b) — the gappy storm, every press in an idle/running row — asserts "**three, never more**" (~1016-1017), and AC 7(d) — first press against an in-flight completion query, a row that *explicitly* "sets the promise bit" (~493) — asserts "**three, never four**" (~1018-1019). Under the promise bit both terminate in exactly two. A conformance suite asserting three would fail a conforming implementation (or force a broken one). Likewise AC 7's "**two** whenever both share a class and epoch" preamble states the old (latch) sufficient condition, not the new (promise) one.
Resolution: recompute every schedule's expected trajectory under the round-7 rules — (b) and (d) become two — and restate the two-press condition as "whenever the first press printed a promise." Keep the schedules; they are good regression anchors. (This is also the strongest possible argument for landing `OBL-INTERRUPT-MODEL`: trajectory enumeration would have caught both.)

**C5 — AC 9 re-asserts the pre-idempotency lifecycle behavior §8 just abolished. (Material)**
Evidence: §8: "If it holds an accepted record, the commit *succeeded* and only the ACK was lost: it proceeds as a cooperative exit with code `n`. It is **only** when it holds no record that it … exits with the fault status" (~712-715). AC 9: "A lifecycle commit that cannot be acknowledged exits with the reserved fatal disposition and the supervisor **reports the requested code as lost — not as a successful exit `n`**" (~1033-1034). "Cannot be acknowledged" includes the ACK-lost-in-transit case — the very case the idempotent rule exists for — where §8 mandates exit `n` and AC 9 forbids it. The criterion, as written, tests the falsehood §8's revision note says it removed.
Resolution: split the criterion: record-held/ACK-lost ⇒ worker exits with the reserved disposition **and** the supervisor completes a cooperative exit `n`; record-absent ⇒ supervisor (informed a code existed by the reserved disposition 69, though not its value) reports the code lost and exits the fault status.

**C6 — The ledger's digest fix is half-applied, and 0023 is unpinned entirely. (Material)**
Evidence: §11's own principle — "an attestation without a content hash is not an attestation"; "a date identifies nothing" (~922-927). Yet four rows attest mutable artifacts by date alone: `OBL-REGISTRY-ROWS` ("verified against the registry, 2026-07-12"), `OBL-CLI-SURFACE` ("verified against `runtime-surface.json`, 2026-07-12"), `OBL-FRESH-NONCE` (schema, date), `OBL-EDITOR-ASYNC` (`src/bin/ibex/repl/mod.rs`, date) (~950-956). The registry and surface manifest churn faster than the sibling LLPs; these rows are tomorrow's meaningless dates. (All four *claims* verify today — I checked each.) Separately, **no row pins LLP 0023** although §9 quotes 0023's worker-locality rule verbatim twice (~828-831, 851-853; source at 0023:1336-1344, digest `ab8658a68b57`) and §9's equality-proof legality depends on that rule's current wording. By this section's own standard, §9's central cross-document reliance is decoration.
Resolution: digest-pin the artifact rows (file digest or git blob hash) and add a 0023 row attesting the locality-rule text at `0023@ab8658a68b57`.

**C7 — Suspended-target cancellation has no delivery mechanism anywhere in the corpus. (Material, cross-document)**
Evidence: §6's selection function raises id-exact requests against a **suspended** unit ("executing ≻ suspended ≻ due", ~470-474), and AC 7 requires "an input **suspended at top-level `await`** is cancellable" (~1019). But 0024 has the engine "discard a request whose id is not that of the work it is **currently executing**" (0024:826-827), and a stale-id request "is **discarded** and resolves **unavailable**" (0024:864-865) — which, read together, forecloses delivery to a unit that is by definition not executing. Neither document says what delivering to a suspended unit *means* (settle its promise abruptly? mark-and-break-on-resume?). `OBL-SUSPENDED-UNIT` asks the unit-*boundary* question, not the delivery question, so the gap is not even ledgered.
Resolution: either 0024 specifies suspended-target delivery semantics (and narrows its discard rule to executing targets), or §6 demotes `suspended` from the selection order and AC 7 drops the criterion; the ledger row should name whichever is chosen.

**C8 — The broker flush budget is undispositioned. (Material, low)**
Evidence: §1's ordinary termination path ("the broker flushes under its budget," ~192-194), §5's exit ordering, and §8's pinned ordering all lean on a flush budget. §12 pins neither a value for it nor lists it among the four open engine-dependent budgets ("the shutdown drain, the cancellation budget, the completion budget, and the async-storm coalescing window," ~987-989) — and it is user-visible and engine-independent, so §12's own criterion ("pinned **now**, with values") demands it. The drain budget is listed; drain ≠ flush (§8 orders them as separate steps).
Resolution: pin a v1 flush-budget value in §12 (or explicitly add it to the open list with a stated reason it must wait — hard to see one, by the same argument that pinned the history-lock bound).

**C9 — §12 and OQ 8 contradict each other about the history-lock bound. (Minor)**
Evidence: §12 pins it at 250 ms and says expressly "The history-lock bound is *not* one of these: it depends on disk and lock behavior, not on Hermes, so it is pinned above" (~989-990); OQ 8 still lists "history-lock bound" among "the **engine-dependent** budgets … these wait on OQ 1's prototype" (~1082). One of the two is leftover text — ironically, in the exact spot whose parenthetical mocks an earlier draft for a stale deferral.
Resolution: strike "history-lock bound" from OQ 8.

**C10 — The due-only notice fails the document's own truth standard, pedantically. (Minor)**
Evidence: for a unit that is merely **due** — "work that … has not begun" (~473-474) — the specified notice is "`work is running — press Ctrl+C again to end the session`" (~474, 492). Work that has not begun is not running. This document deleted an entire notice for apologizing; its standard applies to its own example strings.
Resolution: "work is pending" / "work is in flight," or define "running" in the notice vocabulary to mean in-flight.

**C11 — Detached-child stdio in session modes is one ambiguous sentence away from breaking single-writer. (Minor)**
Evidence: §3 says children in session modes do not inherit terminal descriptors (~306-311) but also that "A **detached** child is outside the session's ownership entirely" (~304-305). The code supports `detached` and `inherit` independently (src/engine/hermes_runtime_process.cc:712-810, 1446-1480, 1748-1754), so `spawn(cmd, {detached: true, stdio: 'inherit'})` is expressible; if "outside ownership" is read as exempting it from the non-inheritance rule, a live detached child writes the real terminal beside the broker, falsifying §7's "single writer for the terminal." The blanket rule probably governs, but the exempting sentence invites the wrong reading.
Resolution: one sentence: detached+inherit in a session mode is refused / mapped to null / relayed-until-session-exit (pick one), and "outside ownership" scopes to ordering and lifetime only.

**C12 — `ibex run` and `--watch` do not fit the interrupt wording of the mode row they are filed under. (Minor)**
Evidence: §1's table files `ibex run` under file execution (~126), whose ordinary termination path "requests cancellation (id-exact)" (~191-193) — meaningless for a package script, which is a shell child with no engine; today its interrupt story is child-signal propagation, `128 + signal` (src/bin/ibex/main.rs:142-155), and `--watch` adds a respawning parent (src/bin/ibex/cli.rs:133,185). Not a contradiction — non-session modes leave `ISIG` on and the kernel's group SIGINT does the work — but the tier's wording presumes engine work exists.
Resolution: a clause in §1 noting that for child-process topologies (`ibex run`, `--watch`) the single-interrupt tier is realized by process-group signal delivery and status propagation, not id-exact cancellation.

**C13 — §8's lifecycle record is described as both "carrying the per-relay byte cutoffs" and "a fixed-size snapshot token, not a variable per-child cutoff vector." (Minor)**
Evidence: ~701-703 vs ~709-710. The reconciliation exists — worker relays number at most two, and §3 orders *child* relays at relay acceptance so they need no cutoff — but the reader must assemble it.
Resolution: one sentence stating exactly that.

**C14 — Dispatch precedence among cause, promise, credit, and table is implied, not stated. (Minor)**
Evidence: "no row can override it" is asserted for the credit (~487-488) but not with equal crispness for the promise bit, while "the tables below are the specification" until the generated artifact lands (~409-410). An implementer transcribing the table (whose second columns are conditioned on "same class *and epoch*") can build a machine that breaks the notice invariant on a class flip.
Resolution: state the interrupt dispatch order once: latched cause ≻ promise bit ≻ escape credit ≻ table row.

## 4. Cross-document findings

Digests at review time: `0022@88decefdc683`, `0023@ab8658a68b57`, `0024@88ebc6349bab`, target `0025@19de10797c67`.

- **0022 (`88decefdc683`) is defective in three ways 0025 already flags and one it does not.** (i) Its two-press guarantee — "Two interrupts within one work epoch end the session" (0022:899) — is falsified by 0025's editing row; 0025's `OBL-INTERRUPT-BOUND` says so, correctly, and 0022's own "worst case is three" sentence (0022:901) survives. (ii) Its epoch definition retains the "quiescence **plus a republished prompt**" coupling (0022:897) that 0025 deleted as undefinable; flagged by `OBL-INTERRUPT-EPOCH`, correctly. (iii) Its pins of 0025 (`7b89315f8ad7` at 0022:974,991; `43ff879a257a` at 0022:963) are outdated — the honest, detectable state its own ledger design intends. (iv) **Unflagged by anyone:** 0022's `OBL-STARTUP-DIAG` row (0022:993) describes a live three-way conflict in which "LLP 0023 §1.2 mandates a **symbolic** package locator and attributes that rule to LLP 0025" — but current 0023 has reversed that position and now prints the host path in arming refusals, expressly repudiating the mis-citation ("**No such rule exists** — the symbolic sentence there is a parenthetical about the legacy history file," 0023:339-355). 0022's row is stale, unpinned prose about 0023; 0023 and 0025 are now mutually consistent on this question and only 0022's description lags.
- **0024 (`88ebc6349bab`) delivers what 0025 cites from it** — native unit publication (0024:762-767), receipt-time sequence allocation with worker-restart epochs (0024:1603-1613), the five-way cancellation algebra with the defeated-race rule (0024:832-866), the retired await-unwrap timeout (0024:818-821), and the unstyled display tree (0024:1543-1562) all match 0025's §2/§3/§6 verbatim citations. Two defects in 0024 itself: (i) its background-callback definition — "running **while no input is in flight**" (0024:869) — contradicts its own §7.4 text, which twice has callbacks firing *while an input is suspended at an `await`* (0024:1170, 1234), i.e. while an input **is** in flight (0024:252); 0025's selection function exists precisely for that concurrency, so the parenthetical should be fixed at the source. (ii) The stale-id discard rule (0024:826-827, 864-865) forecloses the suspended-target delivery 0025 depends on — Concern C7.
- **0023 (`ab8658a68b57`)**: the worker-locality rule 0025 §9 quotes is accurate at 0023:1336-1344, including the parenthetical enumerating the by-design boundary crossings (evaluation outcomes, display trees, broker events). That enumeration does **not** yet include 0025 §9's nonce-bound equality digest — a value *derived from* the worker's authenticated VFS root that crosses to the supervisor. 0025's argument that a keyed, nonce-fresh, one-way digest is "an equality proof, not an identity" is sound in substance (nothing rehydratable or replayable crosses), but a strict reading of 0023's "only opaque, authenticated session tokens cross a process boundary" can refuse it. One line in 0023's parenthetical (or an explicit 0025 ledger row assigning 0023 that line) closes the seam. 0023:1319's worker-transfer note ("LLP 0025 leaves worker replacement itself open") is consistent with 0025 OQ 5.
- **Governing documents**: §8's attribution rule matches 0021's "`NoUser`, missing, or ambiguous denies" (0021:329, 355) and §10's regeneration posture matches 0021's no-unclassified-surface CI gate (0021:45, 540). §9's `--history` manifest plan matches 0010's clapSurface v4 (stable IDs, value shapes). §3's console-queue discussion correctly characterizes 0006's "Degrade diagnostics, never the caller" (0006:136-146) and correctly scopes the supersession to the CLI.

## 5. Suggestions

1. Apply the arithmetic lesson to the promise bit *completely*: make the bit a pair `(set, implied_status)` written at notice time, give it the credit's exact reset clause, and state the four-level dispatch precedence once (C2, C3, C14). That is three sentences and removes every contradiction I found in §6.
2. Regenerate AC 7's expected counts from the current rules by hand *now*, and treat the discrepancy as the motivating exhibit for `OBL-INTERRUPT-MODEL` — schedules (b) and (d) are literally the checker's first two theorems.
3. Extend digest attestation beyond LLPs: pin artifact rows to git blob hashes (`git hash-object`), which `OBL-LEDGER-CHECK` can recompute as cheaply as file digests. Add the missing 0023 row.
4. When fixing AC 9, also add the reserved disposition (69) to §8's status table or a footnote — it is currently defined only in §12, and it is the one worker exit status the supervisor must interpret.
5. Consider stating in §6 that a promise-triggered termination whose implied status is *orderly* still honors `process.exitCode` — the current text implies it via §8's orderly row but only for the target-based reading this review asks you to remove.
6. Ideas worth keeping and naming as principles for the corpus: provenance-travels-with-the-byte; the promise bit ("a promise the machine has to reason about is a promise the machine will break"); cause precedence as the single status rule; equality-proof-is-not-an-identity. All four generalize beyond this document.

## 6. Open questions

1. What is the equality proof's key (§9)? The session nonce, a dedicated channel key, or nothing (nonce alone suffices against the accidental-mismatch threat actually claimed)? Underspecified; any answer is implementable, but conformance fixtures need one.
2. Should `OBL-LEDGER-CHECK` verify only digest *freshness*, or also fail on rows that attest artifacts without digests (which would have caught C6 mechanically)?
3. For a promise consumed during a class flip, is the *notice text* the promise's content, or the status too? C2 forces the decision; the answer should be recorded as a principle so round 8 does not relitigate it.
4. Does the model checker's event alphabet include promise-set/promise-clear as first-class events (AC 7 lists only interrupt, keystroke, typed-ahead, submit, dispatch, unit begin/end, suspend, settle, quiescence)? If the bit is derived state, its reset-on-editor-input must be a transition consequence, and the alphabet as listed can express it — but the properties as stated (`promised_next_exit ⇒ next interrupt terminal`) should say which states set `promised_next_exit`.
5. Is `suspended` in the selection order worth its cost (C7), given that a suspended unit executes nothing an async break can reach? A machine that raised against `executing` only, and otherwise latched-and-promised, would lose no operator-visible guarantee except the "cancellation requested" wording for suspended targets.

## 7. Readiness verdict

Seven material concerns — four of them internal contradictions inside or against the round's two flagship fixes (C1–C5), one ledger half-application (C6), one cross-document dangling mechanism (C7) — are unresolved. All are surgical; none is architectural. The design is right; the text is not yet a consistent statement of it.

VERDICT: NOT READY

### Orchestrator verification notes

- **THE BOUND HELD A SECOND CONSECUTIVE ROUND, and so did notice-truth.** Both reviewers derived the full
  adversarial schedule set independently and neither could break either property. Codex: *"Escape credit: I
  found no counterexample. Promise bit: I found no reachable trace where a promise is printed and the next
  interrupt fails to begin termination. Timers becoming due, work completing, and target-class changes do not
  break the terminal suffix."* The escape-credit/promise-bit decomposition — **safety and honesty both
  arithmetic, never case analysis** — is settled. Every round-7 finding is text-consistency or a completeness
  gap; **not one is architectural**, and both reviewers say so explicitly.
- **The digest ledger detected its own drift — which is the mechanism WORKING.** Both reviewers recomputed the
  pinned digests and found the four `0024@88ebc6349bab` rows stale: 0024 had moved to `6416ccb8c3c2` (and 0023 to
  `a77e5a385f6a`) since I pinned them. This is precisely the outcome the redesign was for: *staleness is now
  detectable instead of silent.* A date-pinned ledger would have shown four confident, wrong rows and no signal.
  The honest reading is Codex's: "the arithmetic mechanism works: it makes drift objectively detectable." The
  round-8 fix is to re-verify against the current siblings and re-pin — accepting that a document refined in
  parallel will always carry *some* drift between pin and read, which the digest now surfaces rather than hides.
- **AC 7 press counts contradict the round-7 machine — CONFIRMED by both** (Fable C4, Codex 1). Schedules (b) and
  (d) still assert **three** presses, but the promise bit reduces both to **two**: every first press in an idle or
  running-work row now prints a promise, and a promise makes the second press terminal. The schedules are good
  regression anchors and are kept; only their expected counts are recomputed. This is the strongest possible
  argument for `OBL-INTERRUPT-MODEL`: trajectory enumeration would have caught the discrepancy mechanically, and it
  is exactly the "invariant in one place, count in another" seam a model-checker finds and a careful author misses.
- **A boolean promise bit does not carry the promised *status* — CONFIRMED by both** (Fable C2, Codex 2), and this
  is the sharpest finding of the round. An idle-origin promise implies **orderly** termination; a running-origin
  promise implies **130**. If the selected target flips between the promise and the next press, a bare bit cannot
  say which status was promised. Accepted: the promise is now **typed state** — `None | Orderly(exitCode) |
  Interrupt(130)` — latched *at notice time*, so the honored termination carries the status the operator was
  actually promised, not the status the current target would imply. This is the same lesson as the bound itself:
  write the answer down, do not re-derive it.
- **Cause precedence collides with the 141 cleanup-escalation — CONFIRMED** (Codex 3, Fable noted). §6/§8 say the
  first latched cause fixes the status; §3 says an all-destinations-stalled cleanup loss upgrades a successful
  status to 141. The triple-idle-all-stalled trajectory latches *orderly* on press 2 and then *becomes 141* when
  press 3 abandons the flush — "same status" violated. Resolved by **separating the two fields the document was
  conflating**: the **termination cause** (fixed once latched) and the **final disposition** (which may reflect a
  cleanup loss the cause could not foresee). 141 is a *disposition* modifier on a successful cause, applied once, at
  the end; it is not a competing cause and it never overrides a fault or interrupt. Stated as one rule used by all
  three sections.
- **The live-unit protocol cannot express the selector — CONFIRMED** (Codex 4, Fable C7). §6 raises id-exact
  requests against a **suspended** unit, but 0024 delivers only to the **currently executing** target and discards
  any other id as `unavailable`; and 0024's begin/end-only publication does not even model a suspended or due unit.
  There is no delivery mechanism for a suspended target anywhere in the corpus. **Resolved on this document's side,
  self-contained, per Fable's own suggestion:** `suspended` is **demoted from the request-raising order**. An
  interrupt against a suspended-only unit **latches and promises but raises no cancellation** — the escape credit
  and promise bit already guarantee the escape, so nothing operator-visible is lost except the "cancellation
  requested" wording. The selector is now `executing ≻ (suspended: latch+promise, no request) ≻ (due: latch+promise,
  no request)`, which asks nothing of 0024 that 0024 does not already deliver. The deeper unit-boundary question
  stays ledgered as `OBL-SUSPENDED-UNIT`/`OBL-UNIT-PUBLICATION`, honestly outstanding.
- **AC 9 re-asserts the pre-idempotency lifecycle behavior — CONFIRMED** (Fable C5, Codex 5). "Cannot be
  acknowledged" includes the ACK-lost-in-transit case that §8's idempotent rule exists for, where the supervisor
  *holds* the record. Split into two criteria keyed on **record possession**: record-held ⇒ cooperative exit `n`
  even with the ACK lost; record-absent ⇒ the fault path. The reserved disposition **69** is added to the status
  table (Codex 5, Fable suggestion) — it was defined only in §12.
- **The `(class, epoch)` latch bullet survived its own repudiation — CONFIRMED** (Fable C1). Deleted; the sum type
  `Idle | Running(epoch) | Shutdown` and the derived-latch paragraph stand alone.
- **The promise bit had no reset rule — CONFIRMED** (Fable C3, Codex OQ 1). Given the credit's exact clause: cleared
  by editor input at a live prompt (which typed-ahead, drained or not, is not) and by session end; otherwise it
  persists. This also answers Codex's OQ 1 (a promise does *not* survive genuine later editor input — the operator
  interacted, so it resets, exactly as the credit does).
- **Topology gap: `ibex run` package scripts and `--watch` — CONFIRMED** (Codex 9, Fable C12). `ibex run dev` is a
  package-script command that spawns a shell child inheriting fds 0/1/2, and `--watch` is a controller that
  respawns an `ibex` child with an inherited terminal — neither fits the single "file execution" row, whose
  interrupt tier presumes engine work. Added a **topology matrix** covering direct file execution, package-script
  execution, the watch controller, and the watch child, each with its terminal owner, broker placement, signal
  behavior (process-group `128+signal`, not id-exact cancellation), and status propagation.
- **The hostile-JS boundary is not closed under `process:spawn` — CONFIRMED** (Codex 10). A spawn grant admits
  arbitrary same-UID native code, which — per §7's own honesty — can reopen the terminal, read `/proc/*/fd`, and pass
  descriptors, and which authentication cannot make truthful. §7 now states that **a `process:spawn` grant is a
  threat-profile transition**: a session that grants it has left the hostile-JS-behind-intact-mediation profile and
  entered the compromised-native profile the document does not claim to contain. Making the downgrade visible is the
  honest treatment; silently promising containment it cannot deliver is not.
- **Undecodable-input cell holds two policies — CONFIRMED** (Codex 6, Fable noted): interactive and transcript split
  into their own rows, one outcome each. **Constants overflow policy — CONFIRMED** (Codex 13): "truncate with marker"
  is right for the renderer bounds but wrong for history-record size (reject) and contradicts lossless program output
  (backpressure); each constant now names its own overflow behavior. **OQ 8 stale** (Fable C9, Codex 13): the
  history-lock bound is struck from the open list, since §12 pins it. **AC 6 child ordering** (Codex 15, Fable): "lands
  in order" → "lands in relay-acceptance order". **Flush budget** (Fable C8): pinned in §12. **detached+inherit child**
  (Fable C11), **snapshot-token vs cutoff-vector wording** (Fable C13), **dispatch precedence order** (Fable C14): all
  taken as one-sentence clarifications.
- **`runNonce` freshness — CONFIRMED outstanding, and correctly a ledgered obligation, not a target defect** (Codex 7).
  `OBL-FRESH-NONCE` already carries it, verified against the schema (`armed-snapshot.schema.json:68` checks only
  base64url; `arming.rs` performs no freshness check). §7's control authentication depends on it, so the dependency is
  sharpened and the row strengthened — but the fix is runtime work, correctly deferred, not something this Spec resolves
  in prose.
- **Deferred deliberately, and recorded as such:** the **companion implementation Plan** both reviewers ask for (Codex
  14, Fable suggestion) — a Spec is not its own sequencing plan, and this belongs in a separate Plan LLP; the **full
  equality-proof protocol** (Codex 12) — directionally settled, protocol-level detail is a real open question; and the
  **model-checker and constants file** (`OBL-INTERRUPT-MODEL`, `OBL-CONSTANTS-ANNEX`) — honestly owed, with the tables
  and values normative in the interim. These are labeled non-blocking obligations, not hidden gaps.
- **Sibling defects found by the reviewers and reported, not fixed here** (all version-pinned): 0022 (`88decefdc683`)
  still carries the deleted epoch definition, over-promises the two-press bound, and has a stale startup-diagnostic
  ledger row; 0023 (`a77e5a385f6a`) has a `/dev/null` mount exception unstated against its single-mount rule, duplicated
  disposition tables, and a ledger still using `current`/line attestations; 0024 (`6416ccb8c3c2`) has an overflow marker
  that must name a pre-receipt sequence that cannot exist, a revision note still saying workers draw ranges (contradicting
  its own adopted receipt-time rule), a self-contradictory rollback AC, an AC15/§7.9 module-cache contradiction, and an
  async-failure envelope crossing a value handle against its own handles-stay-in-worker rule. And a governing-corpus
  item: LLP 0021's advertised-target promotion condition is unreconciled with an empty advertised-target set.

## Round 8 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `647072dedfb0`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@a77e5a385f6a`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer. All prior-round artifacts
were moved out of `llp/reviews/` before either round-8 reviewer was launched (the orchestrator re-stashed them after the
round-7 reconciliation had restored them) and restored only after both had returned. The two reviewers ran concurrently
on the same revision.
**Method:** `brief-round8.md` verbatim; full read of the target and the sibling corpus; verification against the Rust
CLI, the Hermes bridge, the vendored Hermes headers, `capsec/schema/`, `capsec/registry/`, and `runtime-surface.json`.

### Verbatim review

# Review: LLP 0025 — Terminal Session Ownership and Lifecycle
**Target:** `/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md` @ `647072dedfb0` (verified; round 8)
**Siblings read at:** 0022 @ `88decefdc683` · 0023 @ `a77e5a385f6a` · 0024 @ `6416ccb8c3c2` (all recomputed by me this round; every finding below is pinned to these)

## 1. Overall assessment

This is the strongest document in the corpus on the axis it cares most about: saying only what it can enforce, pinning what it cites, and refusing to claim artifacts it does not have. The core §6 design — an unconditional escape credit plus a typed, irrevocably-latched promise, both arithmetic rather than case analysis — is correct, and it survived my falsification attempts on the trajectories that killed earlier rounds: idle-promise→timer-due, running-promise→work-finishes, gappy storm, completion-query-ends-between-presses, triple-idle-all-stalled, interrupt-with-flush-loss. The §7 threat-profile split and the §9 history design are honest and implementable. Every load-bearing "today" claim I checked against code is true, including several a reviewer would normally have to take on faith (the unknown-fd policy, the missing hermesc break-check flag, the editor-thread-only completion timeout, the save-on-exit history with cwd fallback). The entire §11 ledger recomputes: all seven sibling digest pins and all four git-blob pins are current, and the content claims inside every pinned row verified against the registry, schema, surface manifest, and REPL source.

But the document's own base rate — "one new local contradiction per large revision" — held again, and this round's seams cluster exactly where the round changed text. The typed promise is now the machine's strongest mechanism, and two satellite passages still describe the pre-promise machine: §6's latch rule 4 and AC 7's latch-outlives-epoch fixture each assert that a press the promise makes terminal is not terminal — the fixture contradicts the notice invariant, the dispatch precedence, and another fixture *inside the same AC*. §8's commit rule was rewritten into a fixed-size token mid-edit and the old carries-the-cutoffs wording (plus a literally duplicated phrase, the smoking gun of the unfinished edit) survives on both sides of it. The §6 invariant box gained a "with the promised status" clause that cause precedence — the round's own rule 1 — falsifies on reachable trajectories. And the new §1 topology matrix, whose fd-inheritance and 128+signal cells verify, attributes signal propagation to a process that dies of the same signal. All of these are locally fixable without touching the design's core; none requires re-litigating §6's held invariants. One more focused pass.

## 2. Strengths

- **§6's two arithmetic rules, and the typed promise specifically.** Latching the status at notice time so a class flip cannot change what the operator was promised is the right generalization of the round-5 lesson, and the reset-rule symmetry with the credit (editor input at a live prompt, nothing else) correctly kills the stale-promise-ends-resumed-session trap the section itself narrates (§6, lines 469–474). Schedules (b) and (d) recompute to two presses exactly as claimed — I derived both independently.
- **Cause vs. final disposition (§6 cause precedence, §8 status precedence).** The 141-as-disposition-modifier-on-successful-causes-only rule is stated identically in §3 (lines 340–343), §6 (lines 575–588), and §8 (lines 845–848); the triple-idle-all-stalled and interrupt-with-flush-loss trajectories resolve consistently in all three. This fix is complete.
- **The suspended-unit demotion (§6, lines 486–498).** Verified against 0024's actual algebra: the engine "discards a request whose id is not that of the work it is currently executing" (0024 lines 850–851) and a discarded request resolves `unavailable` (0024 line 889) — so raising against a suspended unit really would have been a printed lie. Requiring the notice to say `work is in flight` rather than `cancellation requested` is the notice-truth discipline applied correctly, and `OBL-UNIT-PUBLICATION`'s "delivered — this suffices" is accurate (0024 lines 786–791 publish begin/end for all five unit kinds).
- **§7's threat honesty, including the `process:spawn` profile transition.** Verified real, not theoretical: `process:spawn` is a flat capability check (`/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1401-1402`) guarding `execvp` of a caller-supplied path (:1407, :1927), and `detached` composes freely with `inherit` (:1754-1811 — no interaction between the `setsid` block and the stdio chain), so §3's detached-inherit refusal addresses a combination the code can genuinely express today. Stating the grant as a profile exit rather than hiding behind fd-allowlists is the right call.
- **§6's engine pessimism is exactly calibrated to the code.** No cancellation op on the `Engine` trait; the FFI lock held across the whole native call (`/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:490, 544-554`); one `ex_hermes_poll` drains the callback queue, nextTick, microtasks, and every due timer (`/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541-3634`); `asyncTriggerTimeout` is any-thread, terminating, and target-less while `triggerInterrupt_TS` is an empty stub without `HERMES_ENABLE_DEBUGGER` (`/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177-186`, `hermes/AsyncDebuggerAPI.h:133-137, 269`); and no hermesc invocation in the repo passes a break-check flag (`build.rs:778-783, 2190-2195`; `hermes.rs:1837-1847`) while `AsyncBreakCheckInEval` defaults true for eval'd code (`hermes/Public/RuntimeConfig.h:63`) — precisely the compiled-vs-eval'd split §6 asserts (lines 652–654). OQ 1's framing of the mechanism choice is accurate to the headers.
- **§9 end to end.** Append-at-submission retires a verified defect (single `save_history` call at exit, `/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:699`; cwd fallback at :584); the key-publication protocol's clause-by-clause justification (why no-clobber rename, why not exclusive-create-then-write) is the best paragraph of applied crash-consistency reasoning in the corpus; the HMAC threat model names exactly what it defends; and the don't-half-borrow rule (lines 900–904) is a genuinely reusable corpus-governance principle, verified apt — 0023's generation primitives really are different ones (`st_gen`/`ATTR_CMN_GEN`, 0023 lines 711–715, 1732).
- **§11 as an instrument.** Every pin recomputes; the rows against code artifacts are word-for-word true (no `lifecycle:exit` anywhere in `capsec/registry/capability-definitions.json`; exit surfaces `closed` under `process:signal`/`runtime:inspect` at `coverage-edges.json:174033-174040, 215892-215920`; `runNonce` shape-checked only, `armed-snapshot.schema.json:68-70`; no `--history`, no keybindings, bare `ibex repl` stub in `runtime-surface.json:1237-1239`; the blocking completer at `repl/mod.rs:396-415, 247-259` with the 5s editor-side `recv_timeout` at :32,256). A ledger this checkable is rare.
- **§12's per-constant overflow column.** Reject-not-truncate for history records and backpressure-not-drop for the broker are the right per-case answers, and both agree with §3 and §9.

## 3. Concerns

**C1. (Blocking) §6 latch rule 4 and AC 7's latch-outlives-epoch fixture contradict the typed promise — the pre-promise machine survives in two places, one of them a CI gate.**
Evidence: latch rule 4 (lines 605–607) says a latch outliving its epoch is harmless because the next interrupt at a healthy prompt "is therefore a fresh first interrupt, not a surprise termination"; AC 7 (lines 1091–1092) asserts "a latch outliving its epoch does not make a single `Ctrl+C` at a healthy prompt exit." But every row that arms a latch also latches a promise in the same cell (lines 515–519; operator-input interrupts never latch, lines 449–450; the no-work evaluating row says "no latch," line 520), and the promise's clearing events (editor input at a live prompt, session end — lines 469–471) are a subset of the latch's (lines 601–603) whose one extra event — an interrupt against operator input — is unreachable while a promise is live, because dispatch rule 3 (lines 589–592) terminates before the table's editing row can be selected. So in *every* reachable state where a latch outlives its epoch, a promise is live, and the next press terminates with the promised status — which is exactly what dispatch rule 3, the notice invariant (lines 620–624), the "two presses unconditionally" consequence (lines 559–561), and AC 7's own schedule (b) (lines 1088–1089: "press 2 honors it whatever it now targets") require. The fixture asserts the negation of the model-checked property stated four lines below it (line 1096); as written, `OBL-INTERRUPT-MODEL`'s checker and this fixture can never both pass.
Resolution criterion: either exhibit a reachable state with an armed latch and no live promise (I could not construct one), or (a) rewrite rule 4's justification to say the latch outliving its epoch is harmless *for the second-column's purposes only, and the promise — not the latch — governs the next press, which does terminate as promised*, and (b) replace the AC 7 fixture with one whose setup clears the run (e.g., editor input after work ends, then a single `Ctrl+C` at the healthy prompt does not exit).

**C2. (Material) §8's lifecycle record both carries and does not carry the per-relay cutoffs, around a visibly unfinished edit.**
Evidence: line 763 — the call commits a record "carrying `n` and the **per-relay byte cutoffs** of §3"; AC 9 line 1103 — "`console.log("bye"); process.exit(0)` emits `bye` (the record carries the cutoffs)"; but the commit rule (lines 769–773) specifies a "fixed-size snapshot token," says the supervisor "resolves it to the durable per-relay cutoffs it already holds," and concludes "so neither needs to travel in the record." Lines 773–774 contain the duplicated fragment "cannot fail the commit for backpressure, for backpressure" — revision debris marking the edit as incomplete, the document's own named defect class. Worse than the wording: the token mechanism as stated is not sufficient for AC 9's guarantee. §3 itself establishes that a control message "can otherwise overtake relay bytes the supervisor has not yet read" (lines 287–289), and worker-side counters are advanced at the write site (lines 291–296) — so cutoffs "the supervisor already holds" are receipt-side, not write-time, and `bye` can be sitting unread in the relay when the token arrives. Either the record carries the worker's own (at most two, hence fixed-size) write-time counters, or the supervisor's post-disposal drain-to-EOF must be specified as the mechanism; the current text specifies neither and gestures at both.
Resolution criterion: one commit mechanism, stated once, from which AC 9's `bye` case is derivable; line 763 and AC 9's parenthetical reworded to match it; the duplicated phrase deleted.

**C3. (Material) The notice invariant's "takes the promise's own status" clause is falsified by the document's own dispatch rule 1 on reachable trajectories.**
Evidence: the invariant box (lines 620–624) and the model-checked property (lines 626–628: "…⇒ the next interrupt is terminal **with the promised status**") admit counterexamples the dispatch order (lines 589–595) itself produces: promise `Interrupt(130)` latched, then root code calls `process.exit(7)` (or `SIGTERM` latches 143, or a fault latches 70) before the next press — the press dispatches under rule 1, expedites, and keeps the cause's status per the shutdown row (line 521) and §8 (lines 829–834, 837–848). The session ends (the notice's core promise is kept) but not with the promised status. Note also that AC 7 states the checked property *without* the status conjunct (line 1096) while §6 states it *with* — two different properties for one checker. If `OBL-INTERRUPT-MODEL` is authored against §6's version, CI is red against the machine's own correct semantics.
Resolution criterion: scope the status clause in both the invariant box and the checked property — "with the promise's own status *unless a termination cause was latched in the interim, whose status rule 1 preserves*" — and make §6's and AC 7's statements of the property textually identical.

**C4. (Material) `Orderly(exitCode)`'s payload is ambiguous between notice-time capture and exit-time read, and the two readings produce different observable exit codes.**
Evidence: the header says the promise is "latched at notice time" (lines 8–11) and the state carries `Orderly(exitCode)` (line 442, 515, 534) — a constructor with a value parameter, suggesting the number is captured when the notice prints. But §8 pins "`process.exitCode` is root-session state, **read at orderly exit**" (line 793), and the status table recomputes it — "a promise that latched `Orderly` … | the orderly status (root-set `process.exitCode`, else 0)" (lines 826–827), payload dropped. Reachable divergence: idle promise latched with `exitCode` unset; a root-attributed timer runs and sets `process.exitCode = 7` (§8 explicitly makes root-scheduled timers root-attributed, lines 796–797); press 2 → exit 0 under notice-time capture, 7 under exit-time read. The section that exists to make statuses unambiguous on flips has one two-way fork left in it.
Resolution criterion: pin one reading in §6 and make §8 agree. Recommended: the promise latches the status *class* (orderly vs. 130), with orderly's numeric value resolved per §8 at exit — then rename or annotate the constructor so it cannot be read as a captured number.

**C5. (Material) The §1 topology matrix's interrupt and status cells describe signal flows the cited code cannot produce on the described path.**
Evidence: the child-inherits-fds and 128+signal claims verify — `Stdio::inherit()` on all three fds (`/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:577-579`, watch child :873-875) and the shell-style status computation (`package_script_exit_code`, main.rs:139-156). But: (a) the package-script row says "the kernel delivers `SIGINT` to the foreground group; **Ibex propagates the child's status**" — no signal handler exists anywhere on the `run`/`watch` paths (the only handlers in the binary are in `run_debug_loop`, main.rs:1089-1110, reachable solely via `--keep-alive`), and Ibex sits in the same foreground group as the child, so a terminal `Ctrl+C` kills Ibex by default disposition *before* the propagation code can run; main.rs:139-156 executes only when the child dies and Ibex survives (child crashed on its own, external `kill`). The observed 130 after `Ctrl+C` is Ibex's own signal death, not propagation, and a child that traps SIGINT and exits 3 would still yield 130, falsifying the cell. (b) The watch-controller row says "`SIGINT` stops the controller; **it terminates the current child** and does not respawn," with exit status "the controller's own orderly status" — `run_watch` (main.rs:825-968) installs nothing; the SIGTERM machinery (main.rs:192-242) serves file-change restarts, not interrupts; on `Ctrl+C` both processes die of the kernel's group delivery and the controller has no orderly status (it exits by signal; its only orderly exit is the watcher-channel-closed path, main.rs:938, 887). The matrix's framing sentence ("their behavior is process-group signal delivery," lines 198–199) is exactly right; the cells then contradict it.
Resolution criterion: restate the three interrupt/status cells in kernel-group-default terms consistent with the framing sentence, or explicitly mark them as normative targets and add the launcher-route signal-handling obligation (Ibex must ignore/hold SIGINT while waiting on the child in order to propagate) to §11 — currently no OBL row covers it.

**C6. (Minor) §6's `Pending`-resolution sentence contradicts its own preceding rule and the ledger row that claims the fix.**
Evidence: lines 662–664 — "an implementation that cannot perform [the consistency check] must report *failed* rather than guess. … A `Pending` request is resolved `failed` **only when the runtime is destroyed or the worker is terminated**." Since every request is `Pending` until resolution, the second sentence strictly forbids the immediate check-failure resolution the first sentence just required — and which `OBL-CANCEL-EDGES` (line 1013) says "§6 now states." 0024 states the intended split correctly (failed-on-unprovable-consistency at lines 865–866; teardown resolution for the permanently stuck at 871–873, 890).
Resolution criterion: "a request **whose target never stops** is resolved `failed` only when the runtime is destroyed or the worker is terminated."

**C7. (Minor) The `ibex run` dispatch rule that reconciles §1's mode table with the topology matrix exists only in code.**
Evidence: the mode table lists `ibex run` under file execution (line 119); the matrix classifies `ibex run <script>` as a launcher route the file-execution row does not govern (lines 195–204). Both are true only because of an unstated argument-shape dispatch: an existing, path-shaped, or JS-extension argument runs as an in-process file with priority; only a bare, extensionless, nonexistent name dispatches a package script (`should_run_package_script`, main.rs:483-504; dispatch at :344-378). Consequence the spec should own: an existing extensionless file named `build` shadows a same-named package script — the opposite of npm convention. As written, each table's unqualified `ibex run` contradicts the other on its face.
Resolution criterion: state the dispatch rule in §1 and qualify both rows (`ibex run <file>` vs `ibex run <script>`), including the shadowing behavior or its reversal.

**C8. (Minor) §8's lifecycle-outcome cross-reference points at the wrong section.**
Evidence: "The evaluation seam reports a **lifecycle outcome** for the in-flight evaluation (§11)" (lines 783–784) — §11's ledger contains no such row, and none is needed: 0024 already defines and delivers the lifecycle outcome (0024 line 738, matching §8's park semantics exactly).
Resolution criterion: cite LLP 0024 §6 instead of §11.

**C9. (Minor) The token rationale "a variable per-child cutoff vector whose size no one can bound" is contradicted by the document's own §12.**
Evidence: lines 771–772 vs. §12's "maximum live relays per session | 64 | refuse the 65th relay" (line 1053) — the vector is bounded, by this document, at roughly a kilobyte.
Resolution criterion: justify the fixed-size token by its real grounds (preallocated reserved control-lane capacity; child cutoffs unnecessary because §3 orders child relays at acceptance) and drop the unboundedness claim.

**C10. (Minor) The §11 preamble's self-detection anecdote is itself an unpinnable claim.**
Evidence: lines 991–995 narrate the `88ebc6349bab → 6416ccb8c3c2` re-pin as evidence the mechanism works. The corpus files are untracked (`git status`: all four are `??`), so no prior revision exists in-repo and a reader cannot recompute the "before" digest — the anecdote is credible (the "after" value matches my recomputation) but has the exact epistemic shape the section bans: a historical claim bound to nothing. All *current* pins verify, so nothing operative is wrong.
Resolution criterion: version-control or archive the corpus so digest history is reproducible (this also unblocks `OBL-LEDGER-CHECK` meaningfully), or mark the anecdote explicitly as unverifiable narrative.

**C11. (Minor) "Editor input" as defined includes the interrupt byte itself.**
Evidence: "**Editor input** means a byte typed while a prompt was live" (lines 461–462). A `Ctrl+C` pressed at a live prompt is such a byte; read literally, each interrupt at a prompt resets the credit it is supposed to advance, capping the idle-row credit at 1 forever. Context (the credit counts "consecutive interrupts — no intervening editor input") makes the intent obvious, but the transition-data author for `OBL-INTERRUPT-MODEL` needs the exclusion stated, and needs to know whether non-buffer keybinding bytes (`Ctrl+Z`, `Ctrl+R`, Tab) count as promise-clearing editor input (the current definition says yes; that is probably intended and should be said).
Resolution criterion: define editor input to exclude bytes bound to interrupt, and state explicitly which keybinding bytes clear the credit/promise.

## 4. Cross-document findings

All pins recomputed by me this round; every 0025 ledger pin is **current** (0022 `88decefdc683`; 0023 `a77e5a385f6a`; 0024 `6416ccb8c3c2` ×4 rows; blobs `d495d9d6318f`, `2ad526bc2fa9`, `7d7784994b9e`, `c4bcf99bbcb7` — all match).

- **0024 @ 6416ccb8c3c2 is internally defective in one spot, and 0025 is aligned with the correct side.** 0024's revision header (line 25) says "the §9 allocator adopts LLP 0025's supervisor-owns-**worker-draws-ranges** mechanism," while its §9 body (lines 1730–1738) specifies at-receipt allocation, "not even in reserved ranges," and says "the range idea is retired on both sides." The header note is stale against its own body. 0025 §3 and `OBL-SEQUENCE-ALLOCATOR` agree with the body; no 0025 action needed, but 0024 should fix the header before freeze.
- **0024 otherwise corroborates every dependency 0025 places on it:** unit publication delivered (786–791); the id-exact discard rule and `unavailable` resolution grounding the suspended-unit demotion (850–851, 888–889); permanently-stuck-stays-`Pending` (871–873) matching §6; the park lifecycle outcome (738); `$_` on display acknowledgement at barrier completion (1488–1489); `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` retired with the inventory assigned to 0025 §2 (842–845); and the work-epoch row (330) already matching 0025's closes-at-quiescence definition — so 0022 is the only sibling still carrying the old epoch.
- **0022 @ 88decefdc683: both flagged defects verified real, and the pinning is honest.** Line 896–897 still couples epoch closure to "a republished prompt" (`OBL-INTERRUPT-EPOCH` accurate); lines 899–900 still claim "two interrupts within one work epoch end the session," which 0025's editing row falsifies while 0022's own "worst case is three" (line 901) is right (`OBL-INTERRUPT-BOUND` accurate). Judging the practice: pinning a sibling's current digest and stating that the text at that digest is wrong is exactly what version-binding is for — the rows are claims about a specific text, verifiable by any reader, with the owner (0022, re-run last) named. This is the honest form; the alternative — waiting on 0022 — would block 0025 on a document scheduled to move.
- **0022 carries additional staleness for its terminal re-run** (not 0025's problem, but the freeze plan should sweep them): its pins of 0025 (`7b89315f8ad7` in OBL-INTERRUPT-CLASS and OBL-ASYNC-FATALITY; `43ff879a257a` in OBL-DISPLAY-TREE) and of 0024 (`b0ff4ea3247e`) are all superseded; `OBL-STARTUP-DIAG`'s "three documents hold three positions today" is resolved — current 0023 (lines 357–373) now names the host path in arming refusals on 0022's own JavaScript-visibility rule, and 0025 §9 correctly disclaims imposing any general rule; and `OBL-BOUNDS`' "open in both" is false now that 0025 §12 pins the renderer bounds (0024 line 2130 already acknowledges this).
- **0023 @ a77e5a385f6a: healthy, and 0025's use of it is exact.** The worker-locality rule is quoted accurately (0023 lines 1440–1448), and its by-design-crossings parenthetical ("evaluation outcomes, display trees, and broker events") indeed does not name §9's nonce-bound equality proof — `OBL-HISTORY-LOCALITY` is correctly scoped and correctly small (the proof, being fresh-nonce-bound and non-rehydratable, arguably already complies; one acknowledging line in 0023 closes it). 0023's retained-object generation uses different primitives (`st_gen`/`ATTR_CMN_GEN`, lines 711–715) with the naming left to `OBL-OBJECT-GENERATION` (line 1732) — supporting 0025 §9's don't-half-borrow rationale, with one cosmetic slip: 0025 calls 0023's opening "its own OQ" where it is actually an obligation row.
- **No dangling dependency found beyond those already ledgered.** The failure-fatality matrix both siblings delegate to 0025 §8 exists and is complete; 0022's transcript-resynchronization rule (line 442, OBL-UTF8) and startup-diagnostic exemption (lines 480–487) are honored, not paraphrased, exactly as 0025 §8/§9 claim.

## 5. Suggestions

1. **Delete the latch, or demote it to a derived display.** In every reachable state, latch-armed ⟺ promise-live (proof in C1), the second columns' actions coincide with the promise's status wherever both apply, and dispatch rule 3 preempts rule 4 — so the latch, its four rules, and the table's second columns are machinery with no reachable decision left to make. This document's own thesis is that a second copy of the truth is where the next contradiction breeds, and this round's blocking defect bred exactly there. Fold the second columns into generated consequences of rules 2–3, and AC 7's stale "two whenever both share a class and epoch" phrasing becomes "two whenever the first press printed a promise" for free.
2. **Pin the editing-row notice string.** The row must not emit the promise phrase ("press Ctrl+C again to end the session") or rule 2 latches a promise the row is defined not to make; the constraint is currently only derivable. Give the row its exact string alongside the two already pinned.
3. **State whether suspension round-trips clear the promise.** `Ctrl+Z` is a keybinding byte at a live prompt (C11 makes it editor input, clearing credit and promise); after `fg`, is the operator re-warned? Probably yes and probably fine — say it, and add a suspend/resume schedule to AC 7.
4. **Name the worker-held history-scope token's purpose (§9), or delete it.** History is supervisor-owned and appended at submission by the supervisor; nothing in the document has the worker perform a history operation, yet an opaque token crosses to it and AC 11 tests its opacity. If it exists for a future operation, name that; if not, the strongest opacity is absence.
5. **Name the equality proof's key (§9).** "A keyed digest over that nonce and the root object" — keyed with what, held by whom? `K_user` is supervisor-side; presumably the control-channel/session key. One clause prevents an implementer inventing it.
6. **Connect §7's spawn-grant transition to an operator affordance.** The profile downgrade is stated for "an operator or policy author granting spawn" — consider obligating a grant-time or arming-time diagnostic (a registry/armed-snapshot concern, one ledger row), so the statement has an enforcement surface.
7. **Endorsing OQ 11:** one versioned wire format for display tree, supervisor events, and framed transcript — plus `session-constants.json` absorbing the siblings' bounds — would collapse three deferral cycles into one artifact; the corpus's re-pinning overhead this round is the cost signal.

## 6. Open questions

Beyond the document's own list (OQ 1 and OQ 2 remain the right top two, and both are honestly gated):

1. Is `Orderly`'s payload the *rule* or a *captured value* (C4)? This must be answered before `OBL-INTERRUPT-MODEL`'s alphabet is authored, since promise-set events carry it.
2. Does the checked notice property quantify over cause-latching interim events (C3)? The answer determines whether the property carries a rule-1 side condition or the machine forbids cause latching while a promise is live (it should not — a root `process.exit` must win).
3. Do launcher routes (`ibex run <script>`, `--watch`) get minimal signal ownership so the matrix's propagation cells become true (Ibex holding SIGINT while waiting, shell-style), or do they stay kernel-default with the matrix corrected (C5)? Today they are kernel-default in fact.
4. Does the §8 exit path need worker-side cutoffs at all, or is dispose-then-drain-relays-to-EOF sufficient and simpler (C2)? If EOF-draining suffices, the token can genuinely carry nothing.
5. Should the spec pin `AsyncBreakCheckInEval = true` as a normative arming requirement? The escape does not depend on it, but §6's "Hermes emits them in eval'd code by default" is a default someone can turn off; the redundant defense is worth a sentence making it non-optional.

## 7. Readiness verdict

The core design is sound and its two invariants survived another adversarial pass, but one blocking contradiction (C1 — an acceptance fixture asserting the negation of the notice invariant, alongside a normative rule paragraph describing the pre-promise machine) and four material seams (C2–C5, all in this round's changed text) mean the text does not yet consistently specify the machine it designed.

VERDICT: NOT READY

### Orchestrator verification notes

- **The design held a THIRD consecutive round — but the typed-promise edit introduced the seam I predicted.** Both
  reviewers derived the killer trajectories (idle-promise→timer-due, running-promise→work-finishes, gappy storm,
  completion-query-ends-between-presses, triple-idle-all-stalled) and neither could break the escape credit or the
  promise itself. What both caught, independently, is the same Blocking: **the credit/promise precedence and the
  leftover latch machinery describe the *pre-promise* machine.** This is the one-new-seam-per-large-revision rate the
  orchestrator predicted before the round, landing exactly on the biggest edit. My post-revision grep caught one seam
  (the stale selection order); a fresh adversarial read caught this one. That is the two-reviewer loop working as
  designed — a self-grep and an independent read are not substitutes.
- **Codex Concern 1 / Fable C1, C3 — the Blocking, CONFIRMED in my own text.** My dispatch order (line 591) put
  **`(2) escape credit at 3` ABOVE `(3) latched promise`** — so a credit-exhausting third press terminates and derives
  its status from the *current target*, ignoring the promise the operator was shown. Reachable both directions
  (Codex): press 1 editing (no promise), press 2 idle sets `Orderly`, timer becomes due, press 3 credit-3 derives `130`
  from the now-running target — contradicting the promised orderly status; and the dual, an `Interrupt(130)` promise
  overridden to orderly after work finishes. And Fable's C1: latch rule 4 and AC 7's latch-outlives-epoch fixture
  *assert the negation of the notice invariant stated four lines below*, so `OBL-INTERRUPT-MODEL`'s checker and that
  fixture can never both pass.
- **THE FIX BOTH REVIEWERS CONVERGE ON — delete the latch, and reorder to promise ≻ credit.** In every reachable
  state, **latch-armed ⟺ promise-live** (Fable's proof, which I re-derived: the only no-promise row is editing, which
  empties the buffer and lands the next press at idle, which *sets* a promise — so every path to credit-3 passes through
  a promise at press 2). The latch, its four rules, and the table's entire second column are therefore **dead
  machinery — a second copy of the truth**, and this round's Blocking bred there. Accepted in full:
  - **The latch is deleted.** The interrupt table is now single-column (first-interrupt actions only). The "second
    interrupt terminates early" job is done entirely by the **promise**: a promise printed on a prior press makes the
    next interrupt terminal.
  - **Precedence is reordered and split into two axes**, stated once: *termination* precedence is **cause ≻ promise ≻
    credit** (a latched cause expedites; else a prior-press promise terminates; else the credit at 3 is the backstop);
    *status* precedence is **latched cause ≻ latched promise ≻ target-derivation**. Because every reachable credit-3 has
    a live promise, the credit never derives status in practice — it is a pure arithmetic backstop that guarantees the
    bound even if the promise logic had a hole. Safety is still arithmetic; the promise now carries status.
  - **The notice invariant is narrowed to *termination*** ("the next interrupt ends the session"), with a stated
    carve-out that a **cause latched in the interim** (a root `process.exit(7)`, a `SIGTERM`) supplies the status — the
    session still ends, so the notice's core promise holds, but the code is the cause's. This resolves Codex's second
    counterexample and Fable C3 together. `OBL-INTERRUPT-MODEL`'s property and AC 7's are made textually identical.
- **Fable C4 — `Orderly(exitCode)` payload ambiguity, CONFIRMED and resolved.** The promise latches the status *class*
  (orderly vs 130), not a captured number; an orderly exit's numeric value is resolved per §8 (`process.exitCode` read
  at exit) — so a root timer setting `process.exitCode = 7` after an idle promise yields 7, consistently. The
  constructor is renamed `Orderly` (no payload) to kill the notice-time-capture reading.
- **Codex Concern 2 / Fable C2 — §8 commit rule, CONFIRMED including the smoking gun.** The record was described as both
  "carrying the per-relay cutoffs" (line 763, AC 9) and "a fixed-size snapshot token … neither needs to travel" — an
  unfinished mid-edit, with the literal duplicate **"for backpressure, for backpressure"** as proof. One mechanism now,
  stated once: the worker commits its own **at-most-two write-time relay counters** (fixed size by construction), and the
  supervisor drains each relay to those before disposing the worker — which is what makes AC 9's `bye` case derivable
  (the receipt-side cutoffs the earlier text leaned on cannot see bytes still unread in the relay, Codex's decisive
  point). Duplicate phrase deleted.
- **Codex Concern 5 / Fable C5, C7 — §1 topology matrix signal cells, CONFIRMED false against the code.** I verified
  it myself: the only `tokio::signal::ctrl_c` is the unrelated debug loop (`main.rs:1091`); `run_watch` installs no
  handler and calls `stop_watch_child` only after `await_restart_trigger`, which selects on `child.wait()` or fs-events
  only (`main.rs:904-940`). So a terminal `Ctrl+C` kills Ibex by **default disposition in the same foreground group as
  the child, before any propagation code runs** — my matrix's "Ibex propagates the child's status" and "SIGINT stops
  the controller; it terminates the child" describe behavior that does not exist. Rewritten to **current kernel-group
  semantics**: both processes die of the group SIGINT; `128+signal` marked POSIX-specific and applying only when the
  child dies while Ibex survives (external kill / child self-exit). The **watch-child row** is corrected: it *is* an
  engine runtime and carries its own mode's guarantees (the "carry none of §§3-9" blanket was wrong for it). The
  **`ibex run` arg-shape dispatch** (Fable C7) is now stated: an existing/path/JS-extension argument runs in-process;
  only a bare extensionless nonexistent name dispatches a package script — including the npm-inverting shadowing
  consequence (`should_run_package_script`, `main.rs:483-504`).
- **Codex Concern 3 — cancellation-state totality, ACCEPTED.** The live-unit set is now discriminated (`Executing{id}`,
  `Suspended{id}`, `Due{no id}`, `CompletionQueued{request_id}` for the post-Tab/pre-begin interval), the selection order
  `executing ≻ suspended ≻ due` is stated for *target choice* while requests are raised only against `Executing`, and
  `accepted` is made target-generic (the structured `cancelled` outcome is evaluation-only; a callback/query `accepted`
  means it returned).
- **Fable C6 / Codex Concern 3 — the `Pending`-resolution self-contradiction, CONFIRMED.** "must report `failed` rather
  than guess" (immediate) sat beside "`Pending` resolved `failed` **only** at destruction." Fixed to Fable's exact
  wording: a request **whose target never stops** resolves `failed` only at teardown; a *returned* target that fails the
  consistency check resolves `failed` immediately.
- **Codex Concern 8 / Fable C8 — lifecycle/display-ack totality, ACCEPTED.** The lifecycle outcome is made **unit-generic**
  (a root *timer* may exit with no in-flight evaluation), and the §8 cross-ref is corrected from §11 to **LLP 0024 §6**.
  Display acknowledgement now **withholds** on a fallback diagnostic — a rendered safe-fallback must not update `$_` to a
  value that was never displayed.
- **Codex Concern 7 — §12 completeness claim, CONFIRMED false.** Maximum input size is unpinned (0024 flags it as
  security-relevant — it bounds identifier-lowering cost). Added it to §12 with a value, and softened the "only four
  remain" claim; the renderer/wire-format version is ledgered as owed (`OBL-CONSTANTS-ANNEX`), not asserted present.
- **Fable C9, C10, C11 + minors — ACCEPTED.** Token rationale no longer claims "unbounded" (§12 caps relays at 64);
  the §11 preamble anecdote is marked explicitly as unverifiable narrative until the corpus is version-controlled (the
  files are untracked, so the "before" digest cannot be recomputed — Fable's sharp epistemic catch); "editor input" now
  **excludes the interrupt byte itself** and states which keybinding bytes clear the credit/promise; the editing-row
  notice string is pinned (it must **not** emit the promise phrase, or it would latch a promise it is defined not to
  make).
- **All digest pins recomputed by both reviewers: every one CURRENT at review time** (0022@88decefdc683, 0023@a77e5a385f6a,
  0024@6416ccb8c3c2, and all four git-blobs). 0023 has since moved to `2b4c28230caf`; the `OBL-HISTORY-LOCALITY` pin is
  re-verified and re-pinned in this revision — the mechanism surfacing drift again, as intended.
- **Sibling defects found by the reviewers, REPORTED not fixed** (version-pinned): 0022 (`88decefdc683`) still couples
  epoch closure to "a republished prompt", over-promises the two-press bound, and carries superseded pins of 0025/0024
  plus a resolved `OBL-STARTUP-DIAG` row — all for its terminal re-run; 0023 (`a77e5a385f6a`) attributes-and-denies an
  `interim` class and misnumbers its error table; 0024 (`6416ccb8c3c2`) has a revision header still claiming
  "worker-draws-ranges" against its own retired-that body, and an AC 12 giving both outcomes for `let $_; boom()`; and
  governing 0021 has an unqualified `ibex run` armed-enforcement seam against the package-script launcher branch.

## Round 9 — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `b964c18f8bb5`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@ed6599c16ea9`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer. All prior-round artifacts
were re-stashed out of `llp/reviews/` before either round-9 reviewer was launched (the round-8 reconciliation had
restored them) and restored only after both had returned. The two reviewers ran concurrently on the same revision.
**Method:** `brief-round9.md` verbatim; full read of the target and the sibling corpus; verification against the Rust
CLI, the Hermes bridge, the vendored Hermes headers, `capsec/schema/`, `capsec/registry/`, and `runtime-surface.json`.

### Verbatim review

# Independent Design Review — LLP 0025 (round 9, revision `b964c18f8bb5`)

**Corpus digests at review time** (recomputed): 0022 `88decefdc683` · 0023 `ed6599c16ea9` · 0024 `6416ccb8c3c2` · 0025 `b964c18f8bb5`.

## 1. Overall assessment

The latch deletion is the right fix and it is *correctly executed inside §6*. I derived the reachable trajectories independently: the dispatch order, the two-rules block, the notice invariant, and AC 7 are mutually consistent, the round-8 killer now takes the promised `Orderly` status, its dual takes 130, an interim cause supersedes a promise's status but not its termination, the ≤3 bound holds, and every reachable credit-3 press carries a live promise. §6 and AC 7 state the two checked properties in literally identical strings, as promised.

But the document's own eight-round pattern — one new local contradiction per large revision — held for a ninth. The deletion did not propagate outside §6: **§8's exit-status table still derives the credit-exhausting third press's status from its *target*** ("against running work" → 130, "at the idle prompt" → orderly), which is precisely the target-derived reading the deletion exists to kill, and it disagrees with §6 on *reachable* trajectories — including the very trajectory AC 7(e) enshrines. Two more deletions also failed to propagate: AC 11 still asserts the worker "holds only an opaque token" that §9 removed this round, and §1 still explains the terminate tier by contrast to "the latch." The code-facing claims are in excellent shape — I verified essentially every "today" claim against source and found only one mischaracterization (the "extensionless" dispatch claim) plus two matrix-labeling nits. The ledger discipline mostly held: of the twelve pins I could recompute, ten are fresh, one (0023) is stale, and one (main.rs) carries no digest at all — the exact defect §11's first sentence names.

Good idea? Yes — two arithmetic fields with a stated precedence is the smallest machine that delivers both invariants, and the document's honesty discipline (is/ought separation in §1, three-profile threat model in §7, keys-on-what-it-has in §8) is the best in the corpus. Good plan? Yes, conditional on reconciling §8 with §6 and finishing the deletion's propagation.

## 2. Strengths

- **§6's two-axis precedence is coherent and complete within the section.** Termination (cause ≻ promise ≻ credit) and status (latched cause ≻ latched promise ≻ unreachable-130) resolve every trajectory I could construct, including the crossed cases (promise latched idle, honored against work; promise latched against work, honored at idle; cause latched mid-run per AC 7(h)). The single-column table plus uniform second-press rule removes the surface the round-8 seam lived on, exactly as the deletion argument (§6, "The deletion of the latch is why this is only two axes and not three") claims.
- **`Orderly` declassing (§6) fully landed.** No notice-time-capture reading survives in normative text; the exitCode-read-at-exit statement is identical in §6, §8, and the status table. (The round-7 revision note's `Orderly(exitCode)` is correctly historical.)
- **§1's topology matrix is honest and verified.** No handler on run/watch paths — the only handlers in the binary are inside `run_debug_loop` (`src/bin/ibex/main.rs:1091`, `:1100`), reachable only under `--keep-alive` (`main.rs:791`, `:1320`); the package-script child inherits fds 0/1/2 (`main.rs:577-579`); `128 + signal` maps only a child status Ibex survives to observe (`main.rs:139-156`); the shadowing footgun is real (`main.rs:485`, also `:252`); the watch controller spawns an `ibex run` child with inherited stdio (`main.rs:862-877`) and its only orderly exit is watcher-channel-closed (`main.rs:938`). `OBL-LAUNCHER-SIGNALS` correctly ledgers the mediated target as not-current.
- **§8's commit is now one mechanism and it composes with §3.** ≤2 write-time counters is consistent with §3's one-open-file-description rule; child relays correctly excluded (ordered at acceptance per §3); single backpressure statement; supervisor keys on the record it holds. Cross-ref verified: 0024 §6 is "Evaluation outcomes and the ABI."
- **§9 is the strongest section.** Token removal as absence-over-opacity; the nonce-bound `K_channel` equality proof genuinely is non-rehydratable and honors 0023's locality rule (verified at 0023:1533-1542, current digest); the half-borrow rule is a real contribution to the corpus.
- **§6's engine pessimism is verified fact**: no cancellation op on the seam (`src/bin/ibex/engine/mod.rs:22-99`); FFI serialized (`hermes.rs:490`, `:542-545`); `asyncTriggerTimeout` any-thread/no-target (`hermes-interfaces.h:184-186`); `triggerInterrupt_TS` a no-op stub without `HERMES_ENABLE_DEBUGGER` (`AsyncDebuggerAPI.h:269`); `AsyncBreakCheckInEval` default-true (`RuntimeConfig.h:63`); Ibex's hermesc invocation passes no break-check flag (`hermes.rs:1837-1847`); the blocking completer is exactly as described (`repl/mod.rs:247-259`, `:393-415`, `:297`).
- **§11/§12 discipline**: ten of twelve recomputable pins fresh; the unverifiable-narrative marking is present and correct; per-constant overflow semantics and the max input size are pinned.

## 3. Concerns

1. **Blocking — §8's status table contradicts §6's status axis on reachable trajectories.** §8 rows (0025:878-879) classify a "credit-exhausting third press" by its *target*: "against running work or operator input" → 130; "at the idle prompt" → orderly. Under §6, a third press's status is the *promise's* class (rule 2 fires before rule 3; §6 proves every reachable credit-3 has a live promise), never target-derived. Reachable divergences: (a) AC 7(e) itself — press 1 editing, press 2 idle latches `Orderly`, timer due, press 3: §6/AC 7 say orderly; §8's "third press against running work" says 130. (b) The dual — press 1 editing, press 2 idle-with-work latches `Interrupt(130)`, work finishes, press 3 at a clean prompt: §6 says 130; §8's "third press at the idle prompt" says orderly. (c) Even on the unreachable unpromised branch, §6 says 130 unconditionally while §8 splits by target. AC 9's "status precedence is asserted" fixture would be authored from this table. This is the round-9 contradiction, same class as round 8's Blocking. *Resolution criterion:* rewrite the two §8 interrupt rows to mirror §6's status axis verbatim (latched cause; else latched promise's class; else — unreachable — 130), deleting both target-derived clauses, and add trajectory (a) to AC 9's status assertions.

2. **Material — AC 11 asserts the mechanism §9 deleted this round.** AC 11 (0025:1182): "the worker cannot derive, forge, or enumerate the identity — **it holds only an opaque token**" vs §9 (0025:958-961): "**The worker holds no history-scope token at all** … it is removed." A conforming implementation fails this AC. *Resolution:* rewrite the clause to assert absence ("the worker holds no history-scope token; no history operation crosses the control channel").

3. **Material — the "only the editing row prints no promise" universal is false.** The table has *two* no-promise rows: editing-otherwise and "evaluating, nothing in flight" (0025:556, 558). Yet the credit paragraph says "the only row that prints none is the editing row" (0025:588) and the escape invariant says "three are needed only from the **editing** row" (0025:661-662; echoed at 608). From the undispatched-submission row, three presses are needed (discard → idle promise → terminate). The ≤3 bound and the credit-3-has-promise theorem survive (both no-promise rows land the next press at a promising prompt), but the stated lemma is false, AC 7 has no fixture for this path, and the row's gloss "*(no promise; a fresh run continues)*" is ambiguous against the credit's reset rule (returning to idle is explicitly not a reset — say "the credit still counts this press," as the editing row does). *Resolution:* name both no-promise rows in both sentences, fix the gloss, add the three-press undispatched-submission schedule to AC 7.

4. **Material — the phase set is not total, violating the section's own sufficiency requirement.** `idle` is defined as "(empty buffer, **no work in flight**)" (0025:487), yet the table's second row is "idle, **work in flight**" (0025:554). An empty buffer at a live prompt with an executing background callback — the exact state AC 7's gappy-storm presses land in — has *no* phase under the definitions. The (phase, work) table requires phase and work-status to be independent coordinates. *Resolution:* define `idle` as "empty buffer at a live prompt" and let phase × live-unit set be the table's domain.

5. **Material — the completion-query row contradicts the new discriminated live-unit set.** `CompletionQueued{request_id}` is "dispatched but **not yet begun** on the engine thread" (0025:484), but the editing-with-query row justifies raising an id-exact request with "(an in-flight query **is executing**)" (0025:555). A queued query has no unit target id — 0024 assigns ids at begin (0024:848-850) — so the request is unraisable in exactly the interval the row names as real, and printing a raised-request notice there is the notice-truth failure mode. *Resolution:* split the row's action by discriminant (Executing → raise id-exact; CompletionQueued → abandon + invalidate by buffer generation, promise, raise nothing, in-flight notice), mirroring the idle row's "(suspended/due raise none)".

6. **Material — the revision note claims a §3 edit the body does not contain.** The header says "§3's display-ack withholds on a fallback render" (0025:23), but §3's display-ack bullet (0025:355-357) withholds only when the broker "could not write." A malformed/hostile tree renders a safe diagnostic and an over-size tree renders opaque (§3, §12) — those barriers *complete*, so as written the ack fires and 0024 updates `$_` to a value that was never displayed, contradicting 0024's "last **successfully displayed** value" (0024:1486-1490) on a reachable path. *Resolution:* add the withholding sentence to §3 (a result event that rendered as a fallback completes its barrier but raises no display-ack) and assert it in AC 6.

7. **Material — ledger defects, per §11's own rules.** (a) `OBL-HISTORY-LOCALITY` pins "now `0023@2b4c28230caf`"; current 0023 is `ed6599c16ea9` — the row is formally unverified. (I re-verified the substance at the current digest: 0023's locality parenthetical, 0023:1539-1542, still does not name the equality proof; obligation stands — re-pin.) (b) `OBL-LAUNCHER-SIGNALS`'s cell is "`main.rs`@blob (2026-07-12)" with **no content hash** — the defect §11's first sentence names as its whole finding. Current blob: `09e0b170d16b` (substance verified: no run/watch handlers). All other recomputable pins are fresh: 0024 rows @`6416ccb8c3c2`, 0022 rows @`88decefdc683`, `coverage-edges.json`@`d495d9d6318f`, `runtime-surface.json`@`2ad526bc2fa9`, `armed-snapshot.schema.json`@`7d7784994b9e`, `repl/mod.rs`@`c4bcf99bbcb7` — and their substance checks out (no `lifecycle:exit`; exit surfaces closed under `process:signal`/`runtime:inspect`; `__exactStdinRead` an effects edge under `stdio:read` with `ambient-root`; `runNonce` base64url-only; no history/keybinding rows; completer blocks synchronously).

8. **Minor — §1 still explains the terminate tier via the deleted latch**: "so there is no latch" (0025:198). Under round 9 *no* mode has one; the contrast should be "no prompt → no promise or credit to escalate through."

9. **Minor — the `ibex run` dispatch claim is narrower than the code.** "Only a **bare, extensionless, nonexistent** name dispatches a package script" (0025:213-216) — but `should_run_package_script` (`main.rs:483-504`) also dispatches bare nonexistent names with non-JS extensions (`lint.fix`, `test.sh`); only `js|cjs|mjs|ts|tsx|jsx|mts|cts` force file execution. Say "without a JS/TS extension."

10. **Minor — two matrix cells under the "(current, kernel-default)" header are not current.** Row 1's interrupt cell states the terminate tier ("id-exact request, then `_exit` 130") — a target; today `ibex <file>` dies of kernel default like the launcher rows (no handler exists; §7 says no cancellation op exists to request with). Row 4's "the controller reaps it on the next loop" cannot happen on the terminal `Ctrl+C` the column describes — row 3 says the controller dies of the same group signal; reaping (`main.rs:917`, `:881`) applies to child self-exit/external kill.

11. **Minor — notice-string divergence.** The raised-request notice is `` `cancelling <what> — press Ctrl+C again to end the session` `` in the table (0025:554) but `` `cancellation requested` `` in prose (0025:531-532, 715) and AC 7 (0025:1158) — all backticked as literals. Exact-notice fixtures need one spelling.

12. **Minor — `K_channel` is named but never established.** §9 keys the equality proof with "the session control-channel key `K_channel`, held by both endpoints… and by nothing else" (0025:971-972), but §7 authenticates control records with a nonce + epoch and defines no channel key, its minting, or its distribution; no ledger row owns it.

## 4. Cross-document findings

- **0024 (`6416ccb8c3c2`) line 330 — dangling latch reference.** Its shared-vocabulary table defines "work epoch" as "**LLP 0025 §6's interrupt-latch unit** (opens when work starts from quiescence, closes at quiescence)." 0025 now has neither a latch nor a work-epoch unit. Note it also *disagrees with 0022's definition of the same term* (0022:897 adds "plus a republished prompt"). 0025's ledger covers 0022's epoch reference (`OBL-INTERRUPT-EPOCH`) but has **no row** for 0024's — a gap, given §11 re-verified its 0024 rows this round.
- **0022 (`88decefdc683`) line 886 — dangling latch reference**: "the state machine, **the latch rules**, and the trajectories are LLP 0025 §6's."
- **0022's stale rows are exactly as 0025 ledgers them** (verified at the pinned digest): the epoch coupling (0022:896-897) and "Two interrupts within one work epoch end the session … exit **130**" (0022:899) — the latter additionally tension with 0022's own idle-orderly sentence two lines later. Also: 0022 pins 0025 at `7b89315f8ad7` (0022:974, 991) — stale against `b964c18f8bb5` — and `OBL-INTERRUPT-CLASS`'s discharged obligation ("state the guarantee over work **class and epoch**") describes a formulation 0025 no longer uses. All are 0022's to fix on its final re-run; reported, not charged to 0025.
- **Unledgered dependency:** 0025 §8 cites "LLP 0024 §6" for a "**unit-generic**" lifecycle outcome, but 0024 §6's lifecycle row (0024:738) is input-scoped ("the *input's* session state is discarded") and nowhere admits the bare no-evaluation control event a root timer exit needs. Not a contradiction — 0024 doesn't deny it — but it is a half-borrow with no `OBL-*` row, in a ledger that names every other 0024 seam.
- **Verified consistent** (current digests): 0024's id-discard rule (0024:850-852) ↔ §6's raise-only-against-executing; 0024's cancellation algebra and race rules (0024:856-889) ↔ §6 verbatim; sequence-at-receipt (0024:1730) ↔ §3; scheduled-work-doesn't-hold-the-prompt (0024:250-251) ↔ §6's due-timer line; background-callback-during-await (0024:272, 1309) ↔ §6's multi-unit premise; 0022's UTF-8 transcript fatality (0022:438-442) ↔ §8's matrix; 0022's startup-diagnostic host-path exemption (0022:480-483) ↔ §9's disclaimer; 0023's locality rule ↔ §9's design (substance re-verified at `ed6599c16ea9`); 0023's `st_gen`-flavored generation obligation (0023:760-765, 1851) ↔ §9's "different primitives, own OQ" characterization.

## 5. Suggestions

- **Generate §8's two interrupt-status rows from the §6 transition data** (extend `OBL-INTERRUPT-MODEL`): concern 1 is a transcription of §6 into §8 by hand — the exact failure mode the document abolished for the table itself.
- Name the no-promise rows as a class ("non-promising rows: editing-otherwise, undispatched-submission") and have AC 7 enumerate one schedule per member mechanically.
- Have `OBL-LEDGER-CHECK` require a content digest in every "Verified at" cell — that rule would have caught the `main.rs` row this round.
- The `OBL-INTERRUPT-MODEL` row abbreviates the second property (`promised_next_exit ⇒ next interrupt terminal`), dropping the status-class-unless-cause clause that §6/AC 7 state identically; use the identical string there too.
- Reconcile the narrative round-arithmetic: the header says the design "held a **third** consecutive round" while Consequences says the fifth version "has now held **two** rounds" (0025:8, 1195).
- When fixing concern 6, decide and state what `$_` is after a withheld ack (stale previous value, per 0024's "last successfully displayed" — say so explicitly).
- Place one line in 0024 (or a ledger row) retiring its "work epoch" vocabulary entry, and one row for the unit-generic lifecycle outcome.
- Define `K_channel`'s provenance in §7 in one sentence (supervisor-minted at spawn, delivered over the allowlisted control fd, conceded to the compromised-native profile like the nonce).

## 6. Open questions

1. Should the corpus treat §8's status table as *derived output* of the §6 machine (one source, two renderings), making concern 1 structurally unrecurrable?
2. After a fallback render, is retaining the previous `$_` right, or should a sentinel mark "last result was not displayable"? (0024's wording implies retain; neither document says it aloud.)
3. An `Interrupt(130)` promise honored at a now-clean prompt exits 130 though every unit completed (AC 7(e)'s dual). The *termination* is unquestionably right; is the *status class* right for script consumers keying on 130 = "something was interrupted"? Deliberate today — worth one sentence of rationale where the dual is stated.
4. When precisely does the cooperative cause latch for dispatch rule 1 — at the JS call, or at supervisor record-acceptance? An interrupt landing in the ≤2s commit window is governed by promise/credit and could race a mid-commit cooperative `n`; who wins is currently unstated.
5. Does the `CompletionQueued → Executing` transition emit a machine event (so a request raised the instant a query begins is well-formed), or must the interrupt in that interval always fall back to promise-only? (Feeds concern 5's resolution.)
6. For `OBL-LAUNCHER-SIGNALS`: when mediation lands, does the watch *controller* also hold `SIGINT` (keeping row 4's reap claim true on Ctrl+C), or only the package-script wait?

## 7. Readiness verdict

The §6 machine itself is the best version of this section the corpus has had — internally reconciled, honestly bounded, and code-grounded. But §8's status table contradicts it on reachable trajectories (including AC 7(e)'s own schedule), an acceptance criterion asserts a mechanism deleted this round, and four further material textual defects (no-promise universal, phase totality, CompletionQueued row, missing §3 fallback-ack) sit in the two sections whose textual reconciliation was this round's explicit charter. Each has a mechanical fix; none is resolved in the text under review.

VERDICT: NOT READY

### Orchestrator verification notes

- **§6 itself is now sound — both reviewers say so, and I verified.** Fable: "the §6 machine itself is the best version of
  this section the corpus has had — internally reconciled, honestly bounded, and code-grounded." Codex derived the four
  named trajectories and found the dispatch order, two-rules block, notice invariant, and AC 7 mutually consistent. The
  latch deletion was *correct inside §6*. The failure this round is the coordinator's exact prediction: **a deletion is
  low-risk for adding a contradiction and high-risk for leaving a removed premise assumed downstream.** Every blocker is a
  place §8, AC 11, or §1 still assumes the latch / token / `Orderly`-payload that §6 removed. Round 10 is a minimal-edit
  *closing pass* that makes the deletions total; it introduces nothing.
- **Blocker 1 (both, the sharpest) — §8's status table hand-transcribes §6 and got the round-8 bug.** §8 classified a
  credit-3 press by its *target* ("against running work" → 130; "at the idle prompt" → orderly), exactly the target-derived
  reading the latch deletion exists to kill — and it disagrees with §6 on the trajectory **AC 7(e) itself enshrines**. I
  fixed §6's status axis in the round-9 revision but not §8's mirror of it. Fable's structural point is decisive and is
  adopted: §8's rows now **defer to §6's status axis by reference** rather than restating it, so there is one source, and
  the row cannot re-acquire the target-derived clause. (Codex's suggestion — generate §8's rows from the §6 transition
  data — is the same idea; the reference is the prose form of it until `OBL-INTERRUPT-MODEL` lands.)
- **Blocker 7 / Fable C2 — AC 11 still requires the token §9 deleted this round.** "holds only an opaque token" vs §9's
  "the worker holds no history-scope token at all." Both cannot pass. AC 11 now asserts **absence** — the worker bootstrap
  and control schema contain no history token or history route.
- **Blocker 3 / Fable C5 — CompletionQueued treated as executing.** The editing/completion row raised an id-exact request
  "an in-flight query is executing," but `CompletionQueued{request_id}` is dispatched-but-not-begun and has no target id
  (0024 assigns ids at begin). The row is **split by discriminant**: `Executing` raises the id-exact request; `CompletionQueued`
  abandons/invalidates, promises, raises nothing, and prints `work is in flight` — mirroring the idle row's suspended/due handling.
- **Fable C3 — the "only the editing row prints no promise" universal is false.** The undispatched-submission row also
  prints none, and needs three presses. The ≤3 bound and the credit-3-has-promise theorem survive (both no-promise rows
  land the next press at a promising prompt), but the *lemma* was wrong. Both no-promise rows are now named as a class in
  both sentences, the ambiguous gloss is fixed to "the credit still counts this press," and AC 7 gains the
  undispatched-submission three-press schedule.
- **Fable C4 — the phase set is not total.** `idle` was defined "(empty buffer, no work in flight)" yet the table has an
  "idle, work in flight" row — the exact state the gappy storm lands in has no phase. Fixed: `idle` = "empty buffer at a
  live prompt," and the table's domain is **phase × live-unit set** as independent coordinates.
- **Fable C6 / Codex C8 — the revision note claimed a §3 fallback-ack edit the body did not contain.** §3's display-ack
  withheld only on "could not write," not on a fallback render — so a malformed/oversize tree that renders a *safe
  diagnostic* completes its barrier and would ack, updating `$_` to a value never displayed (against 0024's "last
  successfully **displayed** value"). Broker completion is now typed **`Displayed | Fallback | WriteFailed`**, and **only
  `Displayed` emits the display acknowledgement**; AC 6 gains the malformed/oversize fixtures preserving prior `$_`.
- **Codex C5 — payload-free `Orderly` lacks numeric-status ownership under the supervisor.** Real feasibility gap:
  `process.exitCode` is worker/engine state read after eval returns, but a due timer can run `process.exitCode = 7;
  while(true){}` after the promise, and the supervisor must return 7 without depending on the stuck engine. §8 now makes
  `process.exitCode` **supervisor-authoritative**: its setter is **synchronously mirrored to the supervisor before the
  setter returns**, so the last value set is always available to the final exit regardless of a subsequent wedge; the
  snapshot event is the setter, not a read at drain-end. AC 9 gains the setter-then-wedge trajectory.
- **Codex C6 — relay cutoffs miss the worker-local console queue.** Also real: native `console.*` enqueues async to a
  separate writer thread (mandatory on Windows), and today's hard-exit explicitly drains it or `console.log();
  process.exit()` loses output. §3/§8 now require **every armed console/print/fallback route to reserve its counted relay
  slot synchronously before returning to JavaScript**, so the write-time counter the lifecycle record carries already
  covers enqueued-but-unwritten output, and the supervisor drains to it before disposal. AC adds a console-writer-paused
  fixture.
- **Codex C4 — `Due{}` doesn't make the state transition-complete.** Two due timers collapse to one identical set member.
  `Due{}` gains an **internal scheduling identity** (not a cancellation target id — it has none) so the machine can tell
  whether due work remains after one begins.
- **Material/cheap, all accepted:** §1's "so there is no latch" → "no prompt, so no promise or credit to escalate through"
  (C8); `ibex run` dispatch corrected to "without a **JS/TS** extension" — the code forces file execution only for
  `js|cjs|mjs|ts|tsx|jsx|mts|cts` (C9/Codex C10); §1 matrix row-1 direct-file interrupt and row-4 reap cells corrected to
  *current* behavior under the "(current)" header, with the terminate tier marked as target (C10/Codex C9); the
  raised-request notice spelled **one way** (`cancelling <what>`) everywhere (C11); `K_channel` provenance stated in §7 —
  supervisor-minted at spawn, delivered over the allowlisted control fd, conceded to the compromised-native profile like
  the nonce (C12); "adopts 0024's algebra exactly" softened to "with `cancelled` emitted only for evaluation targets"
  (Codex C12); the round-count narrative reconciled (Consequences' "held two rounds" → "held three rounds"); the round-7
  `Revised` block's `Orderly(exitCode)` left as historical but a note added that revision blocks are non-normative
  narrative (Codex C14).
- **§11 ledger — re-pinned and OID'd.** `OBL-HISTORY-LOCALITY` re-pinned `2b4c28230caf` → **`ed6599c16ea9`** (0023 moved
  again; substance re-verified — the locality parenthetical still does not name the equality proof); `OBL-LAUNCHER-SIGNALS`
  given its content hash **`main.rs@blob:09e0b170d16b`** (the exact "an attestation without a content hash is not an
  attestation" defect the section names); the two `OBL-UNIT-PUBLICATION` references that should be `OBL-SUSPENDED-UNIT`
  corrected; a new row owns 0024's stale "work epoch = interrupt-latch unit" vocabulary reference; and a row owns the
  **unit-generic lifecycle event** as a 0025→0024 obligation (0024 §6's lifecycle outcome is input-scoped and does not yet
  admit the bare no-evaluation event a root-timer exit needs) — Codex C11 and Fable's unledgered-dependency both caught
  that half-borrow.
- **Sibling defects found and REPORTED, not fixed** (version-pinned): 0022 (`88decefdc683`) — dangling "latch rules"
  reference at §10, stale epoch coupling, over-promised two-press bound, superseded 0025 pins, a discharged
  `OBL-INTERRUPT-CLASS` describing a class/epoch formulation 0025 no longer uses; 0023 (`ed6599c16ea9`) — duplicated,
  contradictory `module.parent`/`module.children` disposition rows; 0024 (`6416ccb8c3c2`) — the stale "work epoch =
  interrupt-latch unit" vocabulary row (now owned by my `OBL-0024-EPOCH-VOCAB`), an OQ 8 falsely claiming
  `session-constants.json` exists and max input unpinned, and a self-contradictory AC 12. All for the freeze sweep /
  0022's terminal re-run.

## Round 10 (terminal) — 2026-07-12

**Reviewer family:** Claude Fable
**Provider / runtime:** Anthropic, Claude Code Agent SDK subagent (`general-purpose`)
**Model:** Claude Fable 5 (`model: fable`)
**Effort:** max (inherited orchestrator runtime)
**Date:** 2026-07-12
**Revision under review:** `259eca9d5db6`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@601cb5213dca`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** Fresh subagent, no access to this conversation or to the Codex reviewer. All prior-round artifacts
were re-stashed out of `llp/reviews/` before either round-10 reviewer was launched (a post-round-9 restore had raced them
back; the orchestrator re-stashed and re-verified `llp/reviews/` empty before spawning) and restored only after both had
returned. The two reviewers ran concurrently on the same revision.
**Method:** `brief-round10.md` verbatim; full read of the target and the sibling corpus; verification against the Rust
CLI, the Hermes bridge, the vendored Hermes headers, `capsec/schema/`, `capsec/registry/`, and `runtime-surface.json`.

### Verbatim review

**1. Overall assessment**

The closing pass did what it set out to do: the latch deletion is now total. I hunted specifically for the round-over-round pattern — a new local contradiction bred by the revision — and did not find one of load-bearing size. §8's interrupt-status row now defers to §6's status axis with an explicit subordination clause and a matching three-clause paraphrase, and AC 7(l) pins their agreement on the round-8 killer trajectory; the two can no longer diverge silently. AC 11 asserts token absence, matching §9. The `Executing`/`CompletionQueued` split is coherent with 0024's id-at-begin rule (0024:847-849, 894 — a dispatched-not-begun query has no id, so raising no request is *forced*, not chosen). The phase axis is genuinely independent and the "idle, work in flight" cell is reachable (0024:251's idle-pump rule makes it real) and total. Both feasibility closures are sound: the exitCode setter-as-snapshot-event survives the wedge trajectory, and enqueue-time counter reservation is consistent with §8's commit rule because §3 defines "accepted for write" to include enqueue. Every "today" claim I checked against code is accurate, several verbatim (the `exactly once` interrupt guarantee is quoted from the Hermes header). What remains is a handful of Minor wording seams — the largest being AC 11's blanket phrase colliding with §9's own equality proof — and one stale ledger row that is actually the ledger *working*: 0023's drafted acknowledgement landed after this revision was pinned, so the row now understates reality and fails its digest check exactly as designed.

**2. Strengths** (with citations)

- **The §8→§6 citation structure (§8 status table, §6 dispatch order).** Replacing a restated classification with "§6's status axis decides it, and this table does not restate it" plus a subordinated paraphrase is the right repair for a target-derived-status bug that survived a round in §8 after being fixed in §6. AC 7(l) and AC 9's precedence assertions make the agreement testable, not just asserted.
- **The two-field machine held again.** I re-derived the worst-case trajectories: consecutive no-promise presses cannot chain (both no-promise rows clear to a state whose next consecutive press lands in a promise-printing row, and any path to a new buffer or pending submission passes through editor input, which resets the run), so "a credit-3 always has a live promise" (§6) is actually a theorem of the table, and the unpromised-130 default is correctly labeled unreachable.
- **The `CompletionQueued` split is honest in both directions (§6 table, rows 3-4).** It refuses to claim `cancelling` for a request it cannot raise, and its `work is in flight` notice is *true under the document's own definition* (the set is non-empty). The narrative at §6 even pre-bans the tempting lie ("never `work is running` for a unit that has not begun").
- **The `process.exitCode` mirror (§8) is the cheapest correct design.** Making the setter the snapshot event — rather than a drain-time read from a possibly-wedged engine — is verified necessary by the code: today's `ffi_lock` is held across the whole native call (src/bin/ibex/engine/hermes.rs:490, 559), so a drain-time read of a wedged worker is impossible, and AC 9's `exitCode = 7; while(true){}` fixture pins it.
- **The enqueue-reservation rule (§3) fixes a real, present bug class.** Today's console path is exactly as described: all `console.*` goes through a bounded queue to a writer thread that drops under backpressure (src/host/abi.rs:324-398), the queue is the mandatory path on Windows (console_enhance force-skipped, src/engine/hermes_runtime_console.cc), and the current hard exit already had to grow a bounded drain to stop losing `bye` (src/engine/hermes_runtime.cc:588-604, ENG-23639). The spec's mechanism is the principled generalization of that patch.
- **§1's launcher matrix describes what is.** Every cell checks out: `should_run_package_script` (src/bin/ibex/main.rs:483-504) matches the dispatch and the shadowing footgun literally, including the exact extension list; the only signal handlers in the binary are the keep-alive debug loop's (main.rs:1089-1110); `run_watch` spawns `ibex run <file>` children with inherited stdio (main.rs:864-877); `await_restart_trigger` returns false only on watcher-channel close (main.rs:902-938); and `package_script_exit_code`'s `128 + signal` applies only when Ibex survives to reap (main.rs:139-156). Marking the direct-file row target-vs-current was needed — there is indeed no handler there today.
- **The ledger's self-protective clause did its job (§11).** "Verify against the owner's current text before acting on any row" is precisely the instruction that neutralizes the one stale row I found.

**3. Concerns**

1. **Minor/Non-blocking (mechanical fix required at freeze): the OBL-HISTORY-LOCALITY row is stale in both pin and content.** Evidence: §11 pins `0023@ed6599c16ea9` and says the parenthetical "still do[es] not name the equality-proof carve-out"; current 0023 is `601cb5213dca`, and its worker-locality section *now names* "LLP 0025's history-scope equality-proof digest" as a by-design crossing (llp/0023-virtual-filesystem-namespace.spec.md:1626-1636; its revision block at line 32 confirms this is the acknowledgement 0025 drafted, landed after this revision was pinned — both files are timestamped 12:43). By the ledger's own rule the row is unverified. Resolution: re-pin to `0023@601cb5213dca` and mark the obligation **delivered**. This is the ledger detecting a favorable landing, not a design defect.
2. **Minor: AC 11's "no history operation crosses the control channel" collides with §9's own mechanism.** Evidence: §9 mandates a nonce-bound equality proof "over the control channel," keyed with `K_channel`, whose sole purpose is history scoping; AC 11 asserts "no history operation crosses the control channel." A strict fixture author could read AC 11 as forbidding the proof §9 requires. Mitigating: §10's history-store row list excludes the proof, and the digest "names nothing that outlives the challenge." Resolution: add the carve-out to AC 11 — e.g. "no history data, scope identity, or token crosses the control channel; the §9 root-equality proof crosses only a fresh-nonce-keyed digest" — or define "history operation" by §10's enumerated rows.
3. **Minor: one pre-split sentence still conflates in-flight with running.** Evidence: §6's completion-query paragraph — "if it is in flight, it is running work and the escape invariant covers it" — is false for the `CompletionQueued` interval the same section now defines (in the set, hence in flight; not begun, hence not running — the distinction the new row exists to draw, and whose notice deliberately avoids "running"). Behavior is unaffected (the rows are dispositive and the invariant does cover both), but this is the residue class the pass exists to purge. Resolution: reword to "if it is in flight it is live work the escape invariant covers, whether executing or still queued."
4. **Minor: §8's "non-interactive mode" scoping leaves interactive-no-editor formally unassigned.** Evidence: §8's interrupt row says "A single interrupt in a **non-interactive** mode is always 130 (no promise machine exists there)," but §1's binding table gives the machine only to "interactive, with editor" — interactive-no-editor is machine-less yet nominally interactive. 0022:904-905 gets the grouping right ("interactive-without-a-terminal" terminates on a single interrupt). Resolution: scope by mechanism, not mode name — "in any mode where §1's table binds §6 to *terminate*."
5. **Minor: the phase gloss reuses the defined term "in flight" against its definition.** Evidence: §6 defines "Work is **in flight** if the set is non-empty," then glosses `evaluating` as "a submitted input is in flight," while the table carries an "evaluating, nothing in flight (submission not yet dispatched)" row — literally "a submitted input is in flight, and nothing is in flight." The independence claim is correct in substance (the pending-submission tuple component carries it); the gloss undermines it verbally. Resolution: gloss `evaluating` as "a submission accepted and not yet resolved to a prompt," reserving "in flight" for the live-unit set.

**4. Cross-document findings**

Digests: 0022 `88decefdc683`, 0023 `601cb5213dca`, 0024 `6416ccb8c3c2`; target confirmed `259eca9d5db6`. Pin recomputation: all six `0024@6416ccb8c3c2` rows and both `0022@88decefdc683` rows current; **`0023@ed6599c16ea9` stale** (Concern 1); all five artifact blob OIDs verified current (`coverage-edges.json@d495d9d6318f`, `runtime-surface.json@2ad526bc2fa9`, `main.rs@09e0b170d16b`, `armed-snapshot.schema.json@7d7784994b9e`, `repl/mod.rs@c4bcf99bbcb7`), and each artifact row's *content* claim re-verified against the artifact (no `lifecycle:exit`; `__exactStdinRead` is an `effects` edge under `stdio:read` with `ambient-root` in `positiveSources`; exit surfaces `closed` under `process:signal`/`runtime:inspect`; `runNonce` checked as base64url only; no history/keybinding rows in the CLI surface).

- **0024 agreements verified:** id-at-begin and completion-query units (847-849, 894, AC 17 at 2013); engine discards non-current ids (850-851); `Pending`-forever and destruction-resolves-failed (871-890); accepted-means-returned for queries (895-897); `$_` = "last successfully *displayed* value... not a value the consumer failed to render" (1486-1490, 1988-1989) — the `Fallback`-does-not-ack rule is exactly what 0024's wording requires; unstyled tree (1670); one sequence domain, allocated at session-layer receipt (1712, 1730); await-unwrap timeout retired (845; no `IBEX_AWAIT_UNWRAP_TIMEOUT` in src); scheduled-not-due work outside the prompt-holding set (250-251); background callbacks during suspension (272, 1225, 1309).
- **0024 dangling deps, correctly ledgered:** the vocabulary table still defines "work epoch" as "LLP 0025 §6's interrupt-latch unit" (0024:330 — `OBL-0024-EPOCH-VOCAB` accurate); the lifecycle outcome at 0024:738 is input-scoped ("the input's session state is discarded") with no bare no-evaluation event (`OBL-LIFECYCLE-UNITGENERIC` accurate).
- **0022 staleness, correctly ledgered:** epoch closes on "quiescence plus a republished prompt" (0022:896-897) and "two interrupts within one work epoch end the session" (0022:899, echoed at 1133) — both exactly as `OBL-INTERRUPT-EPOCH`/`OBL-INTERRUPT-BOUND` state, with 0022's own worst-case-three sentence (901) compatible. Note 0022:991 pins 0025 at `7b89315f8ad7` (pre-round-7) — 0022's planned last re-run must re-pin against the freeze revision. 0022's mode selection (394-409), completion advisory/bounded rule (848, 862), and startup-diagnostics host-path exemption (480-483) all match this document's citations of them.
- **0023:** beyond the delivered acknowledgement, 0023:411-412's characterization of 0025's symbolic-naming parenthetical is consistent with §9's actual text.

Code verification of remaining "today" claims, all confirmed: blocking completer via `recv_timeout` inside a synchronous `Completer::complete` (repl/mod.rs:247-259, 396-415); base-expression evaluation via `Function('return (' + expr + ')')()` on the engine thread (repl/mod.rs:297, 712-715); history cwd fallback and save-at-exit (repl/mod.rs:584, 699); `Ctrl+C` as a rustyline keystroke with no SIGINT handler (repl/mod.rs:734-739); `closeSync` → `__exactFsClose` → `::close(fd)` with no 0/1/2 branch (fs.js:3608-3611; hermes_runtime_fs.cc:2774-2794); root/runtime may operate on unknown descriptors (`principalMayUseUnknownFd`, hermes_runtime_fs.cc:158-168, 224-227); no cancellation op on the engine trait (engine/mod.rs:24-98); `asyncTriggerTimeout` any-thread/no-target (hermes-interfaces.h:178-186), `triggerInterrupt_TS` empty stub without `HERMES_ENABLE_DEBUGGER` (AsyncDebuggerAPI.h:134-137, 269), `AsyncBreakCheckInEval` default true (RuntimeConfig.h:62-63), and hermesc invoked with no break-check flag against a false compiler default (hermes.rs:1837-1847; CompileJS.h:78).

**5. Suggestions**

- Rename or gloss §8's "write-time relay counters" now that §3 advances the counter at enqueue for the async route — "accepted-for-write counters" keeps the §3/§8 vocabulary in lockstep and prevents a future reader from "fixing" the enqueue reservation to match the name.
- Pin the mirror semantics of the `exitCode` setter one notch harder: state whether "mirrors synchronously" means supervisor-received (ACK'd, like the lifecycle commit) or written-to-channel, and that the setter may block under control-lane backpressure. AC 9's fixture passes under either reading; the sentence "the last value set is always held by the process that owns the final exit" is literally true only under the ACK'd reading.
- Extend the idle row's parenthetical "(suspended/due raise none)" to "(suspended/due/queued raise none)" — the governing "only against an executing unit" clause is total, but the parenthetical now enumerates three of four non-executing variants.
- §8's orderly-shutdown trigger list ("`Ctrl+D`…, `.exit`, a second idle interrupt, end of transcript input") could add the promise-honored case — trajectory (e)'s press 3 initiates an orderly shutdown without being a *second idle* interrupt.
- Add a "re-pin sweep" step to the freeze plan itself: until `OBL-LEDGER-CHECK` exists, any sibling edit landing after a revision (as 0023's just did) will stale a pin by construction, and 0022's final re-run will do it again to the two 0022 rows.

**6. Open questions**

- When an abandoned `CompletionQueued` query later begins on the engine (it was dispatched; nothing recalls it), should the session raise an id-exact request at its begin-event, or let it run to a discarded result? The machine is safe either way; the wasted-work policy is unspecified.
- Does the `exitCode` mirror need reserved control-lane capacity like the lifecycle record, or is setter-blocking-under-backpressure the intended (and acceptable) behavior for a hostile tight-loop setter?
- The document's own OQs 1 (which Hermes cancellation mechanism, and is the break catchable), 3 (non-blocking editor or replacement — the release gate), 8 (supervisor for one-shot/file modes, and what `process.pid` reports), and 13 (compromised-native containment) remain the largest genuinely open design questions; none blocks this document by its own architecture, and I agree with that assessment — the escape and lifecycle designs are constructed not to depend on OQ 1's answer.
- After 0022's final re-run re-states its interrupt guarantees in promise/credit terms, who owns deleting `OBL-INTERRUPT-EPOCH`/`OBL-INTERRUPT-BOUND` here — the 0022 revision or a 0025 data-only follow-up? (The ledger discipline suggests the latter, in the same change that re-pins.)

**7. Readiness verdict**

The propagation is complete: every downstream site the round-9 reviews named (§8 status table, AC 11, §1) now matches §6, the §6 machine survived a fourth adversarial derivation here, both feasibility closures are sound and mutually consistent, and all sibling and code attestations check out except one row whose staleness is the favorable kind — the sibling delivered the obligation after the pin was cut, and the ledger's own protocol ("verify against the owner's current text before acting") already contains the hazard. Concerns 2-5 are wording-level polish with no reachable behavioral ambiguity; Concern 1 is a one-line data refresh. The outstanding obligations (`OBL-INTERRUPT-MODEL`, `OBL-CONSTANTS-ANNEX`, `OBL-FRESH-NONCE`, `OBL-LAUNCHER-SIGNALS`, the 0024 edits, the 0022 re-run) are honestly ledgered and are the kind this document is entitled to place.

VERDICT: READY

### Orchestrator verification notes

- **The two families SPLIT this round: Fable READY, Codex NOT READY.** That is **not** convergence — convergence requires
  both families to mark the *same* revision READY — so `Status` stays **Draft**. This is the honest terminal outcome and it
  is recorded faithfully: Fable's is the first and only READY verdict of the ten-round effort ("the propagation is complete
  … the §6 machine survived a fourth adversarial derivation here"); Codex found one real Blocking and four material
  one-liners. Neither is downgraded.
- **The split is the value of two families, demonstrated on the last round.** Codex's single Blocking —
  `idle × CompletionQueued` has two statuses — is a genuine fork Fable read past. I verified it against my own text:
  target-selection **rule 4** (idle → *executing/suspended/due* work, else the idle prompt → `Orderly`) and the table's
  **"idle, work in flight"** row (any non-empty live set → `Interrupt(130)`) give *different* answers for an idle prompt
  holding a `CompletionQueued` (a completion dispatched from an empty-buffer Tab, not begun). Fable judged "the rows are
  dispositive" and passed it; Codex traced the rule-4-vs-row disagreement. Codex is right that it is ambiguous as written.
- **The single-valued blocker fix — the discriminant is `Executing` vs `CompletionQueued`, universally, not idle-vs-editing.**
  A `CompletionQueued` query has **not touched the engine**, so it can never wedge and is therefore **never "running work"**
  for escalation. Stated once at the live-unit definition: *an interrupt abandons a `CompletionQueued` (invalidating it) and
  proceeds as if it were absent — falling through to executing/suspended/due work, else the phase's non-work target; only an
  `Executing` completion query counts as running work.* This makes rule 4, the "idle, work in flight" row, and the editing
  rows all agree — a queued completion at idle → abandon → idle prompt → `Orderly`, single-valued, no generated artifact
  needed. This is the fix the coordinator scoped ("if it can't be single-valued in one line, ledger it" — it can, so it is
  applied, not ledgered). I grepped the touched concepts afterward to confirm the fix is total and spawned no new straggler.
- **Codex Material 3 / Fable Concern 3 — `accepted` had two meanings.** §6 said per-target (callback/query accepted =
  returned) but then universally "produced the `cancelled` outcome." Fixed to one definition: *accepted* = the work stopped
  **because of** the request and the runtime is consistent; the structured `cancelled` **outcome** is emitted **only for
  evaluation targets** — a callback or query `accepted` means it returned. (This is `OBL-CANCEL-EDGES`'s content; 0024 states
  the same, so the row is accurate once §6 is single-meaning.)
- **Codex Material 4 — §1 launcher spellings/precedence.** Package-script dispatch also fires from the **top-level positional**
  (`ibex dev`, not only `ibex run dev`), and both branches test package-shape **before** `--watch`, so `ibex --watch dev`
  runs a package script **once** rather than watching. §1 now states both spellings and the watch-runs-once consequence, and
  notes controller-driven restart also reaps. (`OBL-LAUNCHER-SIGNALS` extended to name the top-level spelling.)
- **Codex Material 5 — the native console route is not length-bearing.** `console.*`/`print` pass `message.c_str()` and Rust
  rebuilds with `CStr::from_ptr`, so an embedded NUL truncates before counting. §3 now requires a **length-bearing byte ABI**
  and defines the counter's unit ("accepted for write" = queue-accepted). The "today `console.*` enqueues" claim is narrowed:
  the default non-Windows console routes through `process.stdout/stderr.write`; the writer-thread queue is the `print`/native
  fallback and the **mandatory** path on Windows.
- **Codex Material 2 — `Due{sched}` has no publication seam.** Begin/end unit publication cannot populate `Due{sched}` before
  begin; the native scheduling identity (`TimerEntry.id`) is not exposed. `OBL-UNIT-PUBLICATION` is extended to require
  **due/undue transitions carrying the scheduling identity**, and a two-simultaneous-due-timers fixture is added to AC 7.
- **OBL-HISTORY-LOCALITY — the ledger detected a FAVORABLE landing.** Both reviewers found the pin stale (0023 moved
  `ed6599c16ea9` → **`601cb5213dca`**), and the drift is *good news*: current 0023 now **explicitly names** "LLP 0025's
  history-scope equality-proof digest" as a by-design crossing (0023:1626-1636) — the acknowledgement §9 asked for, landed
  after the pin was cut. Re-pinned to `601cb5213dca` and the obligation **flipped to delivered**. The ledger working exactly
  as designed on its last outing: "verify against the owner's current text before acting" caught it.
- **Fable's minor wording seams — all applied** (the residue class this pass exists to purge): AC 11 gains a carve-out
  ("no history *data, scope identity, or token* crosses; the §9 root-equality proof crosses only a fresh-nonce-keyed digest");
  the one "in flight, it is running work" sentence is reworded to "live work … whether executing or still queued"; §8's
  "non-interactive mode" 130 is rescoped "in any mode where §1's table binds §6 to *terminate*"; and the `evaluating` gloss
  no longer reuses "in flight" against its own definition.
- **This is the terminal revision.** Per the bounded authorization there is no round 11: the minimal single-valued blocker
  fix and the material one-liners produce the final revision, reviewed by neither family (a re-review would be round 11).
  `Status` stays `Draft`. The residual is entirely honestly-ledgered owed artifacts — the model-checker
  (`OBL-INTERRUPT-MODEL`), the constants file (`OBL-CONSTANTS-ANNEX`), nonce freshness (`OBL-FRESH-NONCE`), launcher-signal
  mediation (`OBL-LAUNCHER-SIGNALS`), the two 0024 edits (`OBL-0024-EPOCH-VOCAB`, `OBL-LIFECYCLE-UNITGENERIC`), and 0022's
  final re-run — which become implementation/coordination tickets, not more review rounds.
- **Sibling defects reported, not fixed** (version-pinned): 0022 (`88decefdc683`) — dangling latch-rule/epoch references and
  a stale pre-round-7 pin of 0025, for its final re-run; 0024 (`6416ccb8c3c2`) — the "work epoch = interrupt-latch unit"
  vocabulary row, input-scoped lifecycle, a `session-constants.json`-exists falsehood, and a self-contradictory `$_` AC 12;
  0023 (`601cb5213dca`) — a `SourceLabel`/AC-18a hard-link-spelling tension. All for the freeze sweep.
