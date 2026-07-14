# Reviews of LLP 0025 — Codex / OpenAI family

Review artifacts for `llp/0025-terminal-session-ownership.spec.md`, per LLP 0005.
One `## Round N` section per round, appended, never overwritten.

## Round 1 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`,
approval `never`, CWD `/Users/ccheever/projects/ibex`
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"`
**Codex session id:** `019f5573-4c4b-7c90-82e7-c77b04339223`
**Date:** 2026-07-12
**Revision under review:** `5c86bb7897e4` (sha256, first 12 — content hash of the
on-disk file, not a Git object; the document is not yet committed. The reviewer
noted this in its own provenance line.)
**Redaction status:** none — the reviewer read the unredacted document, the
sibling corpus (LLP 0022/0023/0024), the governing LLPs (0021/0010/0006), and
the repository source tree, including the vendored Hermes headers.
**Independence:** Launched as a fresh `codex exec` session with no conversation
history, no access to the Fable reviewer's session or output, and instructed not
to read anything under `llp/reviews/`. No prior review artifacts for LLP 0025
existed at launch, so none could be read. The two reviewers ran concurrently on
the same revision and could not observe each other.
**Method:** Full read of the target and the sibling corpus; verification of
load-bearing claims against the Rust CLI, the Hermes engine bridge, the vendored
Hermes headers (`ios/Frameworks/hermes-headers/`), the builtins, `runtime-surface.json`,
and `capsec/registry/`; LLP 0005 standard question set; structured output with
severity-rated concerns and a readiness verdict.

### Verbatim review

1. **Overall assessment**

The proposal’s core idea is good: the terminal-facing session, not JavaScript or Hermes, should own terminal input, rendering, interruption, and final process lifecycle. Splitting this mechanism out of LLP 0022 is sensible.

As a normative Spec, however, it is not ready. The two-interrupt guarantee is false for reachable states; the strongest guarantees effectively require a supervisor process while that architecture remains merely presumptive; cooperative uncatchable exit has no implementable protocol; and the output broker cannot provide the claimed ordering without a specified worker wire protocol and fd virtualization.

Provenance note: revision `5c86bb7897e4` is not present as a Git object in this checkout. I reviewed the entire current on-disk target and sibling documents, which are untracked relative to HEAD.

2. **Strengths**

- The central descriptor invariant is excellent: fd 0 mediation must happen before the real descriptor is touched, across public APIs, aliases, and raw bridges ([LLP 0025 §1:75](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:75)). This addresses a real hole: `__exactStdinRead` changes fd 0 flags and calls `read(0, …)` directly ([hermes_runtime_crypto.cc:5027](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:5027)), while `fs.readSync` has no descriptor-zero branch ([fs.js:3614](/Users/ccheever/projects/ibex/src/builtins/fs.js:3614)).

- The terminal-injection model is unusually thorough: full C0/DEL/C1 coverage, trusted style separated from escaped payload, and protection of live editing and recalled history ([LLP 0025 §3:150](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:150)). Current inspection requests a flat pre-colored string and prints it directly, confirming why structured rendering is necessary ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63), [repl/mod.rs:884](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:884)).

- Defining accepted cancellation by actual evaluation return and runtime consistency, rather than merely by delivering an interrupt, is the right safety standard ([LLP 0025 §6:286](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:286)).

- The supervisor rationale correctly identifies the current architectural constraints: Hermes evaluation occupies the runtime’s serialized native call, and the current `Engine` trait has no cancellation operation ([LLP 0025 §7:300](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:300), [engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869)).

- Root-only lifecycle authority based on the complete constrained-principal set is well aligned with LLP 0021’s attribution and deny-precedence rules ([LLP 0025 §8:335](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:335), [LLP 0021:324](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:324)).

- Project-scoped history is a sound default direction. The permissions, no-follow, ownership, corruption, concurrency, and size requirements are strong improvements over today’s single global migrated file ([LLP 0025 §9:367](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:367), [repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582)).

- The acceptance criteria appropriately emphasize PTY behavior, infinite loops, terminal restoration, hostile control bytes, bracketed paste, and lifecycle cleanup ([LLP 0025 Acceptance:416](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:416)).

3. **Concerns**

1. **Blocking — The architecture cannot remain merely “presumptive.”**

   Evidence: §7 permits an in-process design if any-thread cancellation leaves Hermes reusable ([LLP 0025 §7:300](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:300)). That proves only accepted cancellation, not independent second-interrupt handling, hard-exit containment, terminal recovery after worker death, fd isolation, or output sequencing. Today evaluation holds the runtime mutex and `ffi_lock` across `ex_hermes_eval` ([hermes.rs:485](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:485), [hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869)); the REPL awaits it inside the only engine loop ([repl/mod.rs:706](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:706), [repl/mod.rs:884](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:884)).

   Resolution criterion: make a separate supervisor/worker process normative for terminal sessions, or define an alternative-conformance gate proving every guarantee—not merely reusable cancellation—including signals, terminal restoration, native exit containment, fd ownership, and broker ordering on every target.

2. **Blocking — The interrupt state machine is incomplete, and a terminating second interrupt is not reachable in every row.**

   Evidence: §6 defines state as `(editor phase, engine-busy origin, latch)` but provides only four rows ([LLP 0025 §6:247](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:247)).

   - `idle, engine free`: the second interrupt is reachable if no edit occurs.
   - `idle, background callback`: the second is actionable only through an engine-independent controller; an accepted-cancellation race may clear the latch first.
   - `editing / continuation`: the first explicitly clears the latch, so the second is a fresh first interrupt. Exit requires a third press.
   - `evaluating`: current code cannot service another REPL event while evaluation is blocked; even with a supervisor, accepted cancellation clears the latch before a later second press.
   - `editing/continuation + background callback`: reachable but omitted. Readline remains active while the engine pumps callbacks ([repl/mod.rs:634](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:634), [repl/mod.rs:762](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:762)). Applying the editing row discards input and clears the latch without cancelling the stuck callback.
   - Completion evaluation is another omitted busy origin ([repl/mod.rs:710](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:710)).
   - `shutdown` is named as a phase but has no row.

   “Edit keystroke” also does not explicitly exclude the interrupt key itself.

   Resolution criterion: publish an exhaustive transition table over every reachable phase × busy-origin × latch state, define event precedence and races atomically, include completion and shutdown, and property-test a precise invariant such as “from every engine-busy state, at most two interrupts produce restored exit 130.”

3. **Blocking — The claimed catchable Hermes break is unverified and appears to conflate different Hermes APIs.**

   Evidence: the Spec treats a Hermes asynchronous break as a JavaScript throw that user code can swallow ([LLP 0025 §6:286](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:286)). The pinned public interface instead exposes `asyncTriggerTimeout()` as an any-thread operation that “terminates the current execution” ([hermes-interfaces.h:177](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177)); async-break checks in eval are enabled by default ([RuntimeConfig.h:62](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/Public/RuntimeConfig.h:62)). Official Hermes guidance states that a `watchTimeLimit` timeout cannot be caught in JavaScript ([facebook/hermes issue #1177](https://github.com/facebook/hermes/issues/1177)). `AsyncDebuggerAPI::triggerInterrupt_TS`, meanwhile, schedules a runtime-thread callback; it is not itself specified as a JavaScript throw ([AsyncDebuggerAPI.h:133](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:133)).

   Resolution criterion: name the exact pinned Hermes API and prototype it on every advertised target. Tests must cover `try/catch/finally` around an infinite loop, prepared bytecode and eval code, native-call stalls, runtime reuse, and repeated interruption. Then revise the `defeated` state and architecture rationale to match the observed mechanism.

4. **Blocking — Cooperative, uncatchable exit has no realizable control protocol.**

   Evidence: §8 requires no following code or `finally` to run, while still allowing exit listeners, broker flush, history save, and terminal restoration ([LLP 0025 §8:326](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:326)). Current uncatchability comes solely from native process death: `exactHostExit` calls `std::exit`/`ExitProcess` ([hermes_runtime.cc:588](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588)), and `__exactExit` invokes it directly ([hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)). Current JavaScript runs listeners before taking that hard bridge ([process.ts:1936](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/node/process.ts:1936)). LLP 0024’s exhaustive evaluation outcomes contain no lifecycle completion.

   A bounded listener budget is also ineffective if checked only after a synchronous callback returns; the existing EOF deadline has that limitation around `ex_hermes_poll` ([hermes.rs:1554](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1554)).

   Resolution criterion: specify a lifecycle frame in the worker protocol and an irreversible worker-side transition. Define listener attribution, recursive exit, listener throws, exit-code mutation, budget exhaustion, when the worker becomes unable to resume JavaScript, and the supervisor’s cleanup/kill ordering.

5. **Material — The single global output-order promise is not implementable from the described paths.**

   Evidence: §3 promises one total sequence across program stdout/stderr, results, errors, async reports, and prompt redraw ([LLP 0025 §3:189](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:189)). Currently:

   - `process.stdout` and `stderr` call `write(2)` directly ([hermes_runtime_process_setup.cc:250](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:250));
   - `fs.writeSync` routes independently through `__exactFsWrite` ([fs.js:3691](/Users/ccheever/projects/ibex/src/builtins/fs.js:3691));
   - results and errors use Rust `println!`/`eprintln!` ([repl/mod.rs:884](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:884));
   - rustyline draws the prompt itself ([repl/mod.rs:679](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:679));
   - console uses a bounded queue that drops under backpressure ([host/abi.rs:324](/Users/ccheever/projects/ibex/src/host/abi.rs:324)).

   Separate stdout/stderr pipes cannot reconstruct original submission order after the fact. Conversely, one globally backpressured FIFO can block an interrupt notice on a terminal stderr behind a slow piped stdout, conflicting with LLP 0006’s drop-diagnostics-before-stalling principle ([LLP 0006:136](/Users/ccheever/projects/ibex/llp/0006-design-principles.principles.md:136)). fd 1/2 close and alias behavior is also unspecified; current `closeSync` reaches the real descriptor ([fs.js:3608](/Users/ccheever/projects/ibex/src/builtins/fs.js:3608)).

   Resolution criterion: either virtualize every worker output route into one framed sequence at the write origin or weaken the promise to per-destination ordering plus explicit evaluation barriers and atomic redraw transactions. Specify partial writes, fd close/dup, buffer bounds, EPIPE, drop policy, and a reserved lifecycle/interrupt control lane.

6. **Material — The structured display dependency is dangling across the worker boundary.**

   Evidence: §3 requires structured style tokens and cites LLP 0024 §8 ([LLP 0025 §3:167](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:167)). LLP 0024 defines safe inspection behavior but no normative style-token schema ([LLP 0024 §8:405](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:405)); its evaluation result is a value handle ([LLP 0024 §6:249](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:249)), which cannot cross a worker-process boundary.

   Resolution criterion: define a versioned, serializable display IR produced inside the worker: trusted style/layout enums, escaped length-bearing payload spans, structural line-break tokens, truncation bounds, and no raw ANSI. The supervisor should never receive a Hermes value handle.

7. **Material — Mode selection, descriptor topology, and scope are inconsistent.**

   Evidence: LLP 0022 says TTY stdin selects interactive mode with editing, completion, history, banner, and prompt ([LLP 0022 §3:196](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:196)). LLP 0025 instead creates an unnamed transcript-like fallback when stdin is a TTY but neither output is a TTY ([LLP 0025 §1:118](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:118)). In the TTY/TTY row, prompt/editor output goes to stdout, but the following rule selects the first of `stderr, stdout`, which selects stderr.

   The fd table covers only interactive, transcript, and stdin-program modes, while Scope also names one-shot surfaces and broadly says every mode owning a standard stream. Ordinary named-file execution leaves stdin available as program input ([main.rs:438](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438)).

   Resolution criterion: separate input semantic mode from presentation topology. Publish one exhaustive stdin/stdout/stderr matrix, fix the controlling-descriptor preference, and state independently for file, stdin-program, transcript, interactive, and one-shot modes which fd, rendering, lifecycle, and history rules apply.

8. **Material — The capsec reopening lacks exact registry obligations.**

   Evidence: the registry currently closes `__exactExit`, `process.exit`, and `process.exitCode` ([coverage-edges.json:174033](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:174033), [coverage-edges.json:215893](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215893)). In contrast, `__exactStdinRead` is a `stdio:read` effect ([coverage-edges.json:184040](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:184040)), `process.stdin` is likewise effectful ([coverage-edges.json:218282](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:218282)), and `__exactFsRead` is an unconditional `fs:read` edge with no fd-0 branch ([coverage-edges.json:176544](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:176544)). LLP 0021 requires exact logical branches for parameter-dependent surfaces ([LLP 0021:176](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:176)).

   Resolution criterion: add a registry-obligations table covering every fd-0 route, stdout/stderr route, TTY query, lifecycle request, and `exitCode` get/set. Pin mode branches, effects versus no-effect EOF, principal sources, typed denials, source identities, target cells, and generated fixtures.

9. **Material — Persistent history identity and HMAC privacy are underspecified.**

   Evidence: §9 promises rename/move stability, separate worktrees, and fresh identity after replacement ([LLP 0025 §9:373](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:373)). LLP 0023 only defines runtime-local retained identities, including `runtime` in the tuple ([LLP 0023 §2:114](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114)); that cannot directly key history across processes. Inode/file-ID reuse and cross-volume moves also defeat the stated absolutes.

   The HMAC is said to protect against anyone able to read the history directory while its key is stored in that directory. That helps a listing-only adversary, not one who can read the key. Key creation races, permissions, loss, corruption, and rotation are unspecified. Reporting the ignored legacy file’s host path also conflicts with LLP 0022’s no-host-path rule.

   Resolution criterion: define a persistent cross-platform project identifier and exact threat model; specify key creation, 0600/no-follow protection, directory ACL, concurrency, rotation/loss, and unsupported filesystems. Qualify move guarantees appropriately and report the legacy file symbolically rather than exposing a host path.

10. **Material — “Unconditionally ANSI-free transcript” contradicts unmodified program output.**

   Evidence: §3 says program-authored bytes are unmodified ([LLP 0025 §3:184](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:184)), while §4 and its acceptance criterion call transcript mode unconditionally ANSI-free ([LLP 0025 §4:201](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:201), [LLP 0025 AC5:434](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:434)). `process.stdout.write("\x1b[31m")` disproves the absolute claim.

   Resolution criterion: narrow the contract everywhere to “Ibex/session-authored styling introduces no ANSI in transcript mode,” or explicitly choose to transform program output and document the compatibility break.

11. **Material — Lifecycle bounds and signal behavior remain open despite being normative to liveness.**

   Evidence: shutdown/listener budgets and history limits are deferred by open question 5, while SIGHUP behavior remains open in question 7 ([LLP 0025 Open questions:497](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:497)). Current EOF drain uses 200 ms ([hermes.rs:204](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:204)), but that deadline cannot stop one synchronous callback already inside `ex_hermes_poll`.

   EPIPE status is called “platform-conventional”; SIGTERM is “prompt”; SIGTSTP/SIGCONT is required without platform scoping; and cleanup order may leave terminal restoration behind a blocked broker or history operation.

   Resolution criterion: pin versioned limits, monotonic timing points, expiry behavior, cleanup order, SIGTERM/SIGHUP/EPIPE statuses, and POSIX-versus-Windows applicability. Supervisor terminal restoration must precede potentially blocking best-effort work.

12. **Material — “Background-attributed” is not a governing principal category.**

   Evidence: §8 first applies the complete constrained-principal set, then denies every “background-attributed” lifecycle request ([LLP 0025 §8:341](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:341)). LLP 0021 instead carries root/package identity through schedule-time owner and deputy dimensions ([LLP 0021:353](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:353)). A timer scheduled by root remains root-attributed under that model.

   Resolution criterion: either apply ordinary constrained-principal attribution uniformly or define a separate authenticated foreground-submission provenance gate. Explicitly disposition root timers, package timers, native completions, and ambiguous callbacks.

13. **Material — Startup capture duplicates other LLPs and conflates immutable configuration with dynamic terminal facts.**

   Evidence: §2 pulls transform controls, tracing, executable lookup, and await timeouts into this terminal Spec ([LLP 0025 §2:133](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:133)), duplicating LLP 0024’s evaluator rule and LLP 0021’s arming ownership. Current prompt configuration is indeed read only after runtime creation and bundle loading ([main.rs:1333](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1333), [repl/mod.rs:91](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:91)). Window dimensions, however, must change on resize and cannot be frozen startup state.

   Resolution criterion: put the authoritative closed startup-input inventory in the arming/evaluation LLP, have 0025 own only presentation inputs, and distinguish immutable terminal identity/capabilities from dynamic window state.

14. **Material — The `--history` option’s exact CLI placement is unresolved.**

   Evidence: §9 names `--history=project|global|off` without saying whether it belongs to the root command, `ibex repl`, or both ([LLP 0025 §9:388](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:388)). `Commands::Repl` is currently a unit variant with no options ([cli.rs:227](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:227)); bare `ibex` also starts the REPL ([main.rs:462](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:462)); and the manifest records no REPL options ([runtime-surface.json:1238](/Users/ccheever/projects/ibex/runtime-surface.json:1238)).

   Resolution criterion: pin the Clap ID, command paths, enumerated values, default, aliases, implicit-REPL spelling, and behavior when another execution mode is selected; update the Clap tree, manifest, tests, LLP 0010, and documentation together.

15. **Material — The PTY acceptance suite is not exhaustive enough for the concurrency contract.**

   Evidence: AC6 covers an infinite submitted loop but not editing-plus-background busy, completion busy, shutdown, rapid/coalesced signals, or accepted-cancellation races ([LLP 0025 AC6:439](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:439)). Existing signal integration tests use null stdin and piped outputs, not a PTY ([tests/signal_handling.rs:59](/Users/ccheever/projects/ibex/tests/signal_handling.rs:59)).

   Resolution criterion: require deterministic reducer tests plus PTY/ConPTY tests for every state combination, terminal-generated Ctrl+C and external SIGINT, synchronized infinite work, signal races, process-group routing, saturated pipes, worker death, SIGWINCH, SIGTSTP/SIGCONT, and post-exit `tcgetattr` restoration.

16. **Minor/Non-blocking — The fd-0 result rule and document references need editorial reconciliation.**

   Evidence: §1 first permits a typed denial as an alternative, then says implementations may not disagree and pins EOF/no-op behavior ([LLP 0025 §1:93](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:93), [LLP 0025 §1:99](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:99)). References to LLP 0022 §2 for modes and transcript checkpoints point to material now located in §3.

   Resolution criterion: remove the broad alternative-denial sentence, publish the exact per-route result table, and repair section references.

4. **Cross-document findings**

- **Contradiction — second interrupt:** LLP 0022 says a second consecutive interrupt “always” ends the session ([LLP 0022 §10:445](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:445)); LLP 0025 clears the latch for editing/continuation and accepted cancellation ([LLP 0025 §6:260](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:260)).

- **Contradiction — cancellation state:** LLP 0024 normatively says cancellation resolves as accepted, unavailable, or failed ([LLP 0024 §6:289](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:289)); LLP 0025 adds “or not at all”/defeated ([LLP 0025 §6:286](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:286)). LLP 0024’s own open question acknowledges the unresolved case, contradicting its normative section.

- **Dangling dependency — lifecycle completion:** LLP 0024’s exhaustive outcomes are empty/value/throw/cancelled; LLP 0025’s uncatchable lifecycle completion has no representation ([LLP 0024 §6:249](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:249)).

- **Dangling dependency — worker display:** LLP 0024 returns an in-process value handle, while LLP 0025 presumes a process worker and supervisor-owned renderer. No serializable display IR or common sequence protocol is defined.

- **Contradiction — modes:** LLP 0022’s TTY-stdin interactive mode guarantees editing/banner/history, while LLP 0025 introduces an unnamed transcript-like degradation when both output streams are non-TTY.

- **Contradiction — ANSI:** Both documents say transcript mode is unconditionally ANSI-free, but LLP 0025 preserves program-authored ANSI unchanged.

- **Dangling dependency — persistent project identity:** LLP 0025 requires cross-session object identity; LLP 0023 defines runtime-local retained path/module identities, not a persistent history key.

- **Contradiction — host-path disclosure:** LLP 0025 says the ignored legacy history path is reported; LLP 0022 forbids host paths in REPL output ([LLP 0022 §4:243](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:243)).

- **Duplication with demonstrated drift:** LLP 0022 §3 and §10 repeat mode, interrupt, exit, ANSI, and history behavior owned by LLP 0025. The interrupt and topology summaries have already diverged. Those sections should be generated summaries or reduced to references.

- **Minor dangling references:** LLP 0025 cites LLP 0022 §2 for material in §3; LLP 0024 cites LLP 0022 §9 for async-failure behavior actually in §5; LLP 0024 says “four” session deviations while listing three ([LLP 0024:367](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:367), [LLP 0024:542](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:542)).

5. **Suggestions**

- Make a supervisor process normative for v1 terminal sessions. Put the process-model choice in a small Decision LLP; let this Spec remain the observable conformance contract.

- Implement interruption as a pure reducer over phase, busy origin, latch, and shutdown state. Generate both documentation and property tests from the same transition table.

- Prototype Hermes `asyncTriggerTimeout` as the cooperative first interrupt; retain supervisor termination as the guaranteed second escape.

- Define a framed worker protocol containing sequence, evaluation ID, destination, event kind, payload, cancellation state, lifecycle request, and explicit flush barriers.

- Replace global byte-total-ordering with enforceable guarantees: per-destination order, evaluation-completion barriers, and an atomic print-above/redraw transaction.

- Give interrupt and lifecycle diagnostics a reserved control lane that cannot be blocked behind program output.

- Add a machine-oriented JSONL transcript mode. Plain transcript can preserve program bytes while promising only that Ibex-authored decoration is ANSI-free.

- Store the history master key through an OS credential store where available, or at least in a separately protected state directory rather than beside the history leaves.

6. **Open questions**

1. Is a worker process mandatory for interactive sessions only, or also transcript, program-stdin, file, and one-shot modes?
2. Which exact Hermes API implements first cancellation, and is it catchable, reusable, and available on every advertised target and source form?
3. When editing and background JavaScript overlap, does the first interrupt discard the buffer, cancel the engine, or both?
4. Does accepted cancellation leave the latch armed so the promised next interrupt exits?
5. Is the broker promising a true cross-stream total order, or per-stream order plus barriers?
6. How are raw fd 1/2 writes, close, dup, partial writes, and EPIPE represented?
7. What do `process.pid`, `ppid`, process groups, and `process.kill` mean in a worker architecture?
8. Can exit listeners change the requested code, and what happens on listener throw, recursion, or timeout?
9. May a root-scheduled timer call `process.exit`, or is foreground operator-submission provenance additionally required?
10. What is the persistent project identifier on POSIX, Windows, network filesystems, inode reuse, and cross-volume moves?
11. Does “ANSI-free transcript” cover only session-authored bytes or every byte?
12. What are the normative shutdown, listener, queue, history, and coalescing limits?
13. Where exactly is `--history` accepted for explicit and implicit REPL entry?

7. **Readiness verdict**

The direction is strong, but unresolved correctness, feasibility, coherence, and testability issues remain in every load-bearing mechanism.

VERDICT: NOT READY
### Orchestrator verification notes

Spot-checks of the decisive claims, against the repository at the reviewed revision:

- **Concern 3 (the "catchable Hermes break") — CONFIRMED, and this is the most
  consequential finding of the round.** The document asserted as fact that "a
  Hermes-style asynchronous break surfaces as a catchable JavaScript throw." The
  vendored headers do not support that and arguably contradict it:
  `ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:184-186` documents
  `asyncTriggerTimeout()` as "Asynchronously **terminates** the current execution.
  This can be called on any thread"; `hermes/AsyncDebuggerAPI.h:133`'s
  `triggerInterrupt_TS()` is a different mechanism that schedules a runtime-thread
  callback. The reviewer's cited upstream issue could not be checked from this
  sandbox and is not relied on. **A further fact neither reviewer surfaced, found
  during this check and now recorded in the document:**
  `ios/Frameworks/hermes-headers/hermes/CompileJS.h:44,54,78` defaults
  `emitAsyncBreakCheck` to `false`, while
  `hermes/Public/RuntimeConfig.h:63` defaults `AsyncBreakCheckInEval` to `true` —
  so *eval'd* code carries async-break checks but *prepared bytecode* need not, and
  Ibex has a bytecode build path. Interruptibility is therefore a property of how
  the source was compiled, not of the engine alone. The document no longer asserts
  catchability in either direction: §6 now enumerates the three ways a request can
  be defeated (no async-break checks in the executing code; a break that surfaces
  as a catchable throw and is swallowed; a native call that never returns), and
  §7/OQ1 now require the *exact* mechanism to be named and prototyped, naming both
  candidate APIs. The load-bearing conclusion — that the second-interrupt escape
  must not depend on the engine cooperating — survives under either answer, which
  is why it was safe to specify before this is settled.
- **Concern 7, the topology self-contradiction — CONFIRMED.** §1's TTY/TTY row sent
  the prompt to stdout while the following rule said the controlling descriptor is
  "the first of **stderr, stdout** that is a TTY," which selects stderr. The
  preference order was simply backwards; it is now "the first of **stdout, then
  stderr**," which yields stdout for TTY/TTY and stderr for TTY/pipe. Accepted.
- **Concern 10, "unconditionally ANSI-free transcript" — CONFIRMED as a genuine
  internal contradiction.** §3 held program-authored bytes unmodified while §4 and
  AC5 called transcript mode unconditionally ANSI-free; `process.stdout.write("\x1b[31m")`
  falsifies the absolute claim. Narrowed everywhere to *session-authored* output.
  The same overclaim exists in sibling LLP 0022 §3 and its AC4 and is reported, not
  fixed here.
- **Concern 12, "background-attributed" — CONFIRMED.** LLP 0021 carries principal
  identity through the constrained-principal set (live frames, schedule-time owner,
  deputy identity); "background-attributed" is not one of its categories, and LLP
  0022 §7 explicitly refuses to extend the principal enum. A root-scheduled timer is
  root-attributed. Accepted: §8 now denies on *package* attribution and on missing,
  ambiguous, or `NoUser` attribution only, and states explicitly that a
  root-scheduled callback may request exit and that no separate "foreground"
  category is introduced.
- **Concern 5, the broker — PARTIALLY ACCEPTED.** The evidence is confirmed:
  `process.stdout`/`stderr` write(2) directly
  (`src/engine/hermes_runtime_process_setup.cc:250`), `fs.writeSync` routes through
  `__exactFsWrite` (`src/builtins/fs.js:3691`), results use Rust `println!`
  (`src/bin/ibex/repl/mod.rs:884`), rustyline draws the prompt itself, and the
  console queue drops under backpressure with an explicit
  `@ref LLP 0006#degrade-diagnostics-never-the-caller` (`src/host/abi.rs:324`).
  `closeSync` reaches the real descriptor with no fd-0/1/2 branch
  (`src/builtins/fs.js:3608`). The *promise* was weakened as the reviewer asked:
  §3 now specifies per-destination order, one total order only where destinations
  resolve to the same terminal, a reserved control lane that cannot be blocked
  behind program output, and explicit barriers. What was **not** accepted is the
  implication that this is only achievable with a worker wire protocol — §1 now
  extends descriptor ownership to fd 1/2 (write brokered, close/dup refused), which
  closes the alias holes in-process as well.
- **Concern 14, `--history` placement — CONFIRMED.** Bare `ibex` starts the REPL
  (`src/bin/ibex/main.rs:464`), `Commands::Repl` is a unit variant
  (`src/bin/ibex/cli.rs:228`), and `runtime-surface.json`'s `clapSurface.commands`
  carries `ibex repl` with no options. LLP 0010 requires a stable clap ID, canonical
  spellings, and a `valueShape` with an enumerated domain. §9 now pins the option as
  root-level (so the implicit REPL spelling can reach it), enumerated, defaulted, and
  a usage error in modes that keep no history.
- **Concern 1, "the architecture cannot remain presumptive" — ACCEPTED in substance,
  with a narrower resolution than the reviewer proposed.** Making a *process model*
  normative in a Spec whose own OQ2 concedes the cost is unmeasured would be
  specifying an implementation. §7 was restructured instead: the **invariants** are
  normative (the session layer must survive a worker that is stuck, crashed, or
  hostile), the supervisor/worker process is the **specified realization**, and an
  in-process implementation conforms only against an enumerated alternative-conformance
  gate covering every guarantee — not merely reusable cancellation. That meets the
  reviewer's stated resolution criterion without freezing the process model.
- **Concern 13, dynamic window state — CONFIRMED.** Window dimensions cannot be
  frozen startup state; §2 now separates immutable startup configuration from live
  terminal facts, which the session tracks across `SIGWINCH` and exposes only
  through `stdio:query`.
- **Concern 9's HMAC critique — CONFIRMED and sharpened.** An adversary who can read
  the key file can also read the history contents, so the HMAC cannot defend against
  them. §9 now states the actual threat model: the HMAC defends against an adversary
  who observes *file names* but not contents — directory listings, backup and sync
  indexes, snapshot manifests — and explicitly concedes that an adversary who can
  read the history files has already obtained the secrets the scoping exists to
  protect.
- **The reviewer's provenance note is correct and expected**: `5c86bb7897e4` is a
  sha256 content hash of the working-tree file, not a Git object; the document is
  not yet committed.
- **Not accepted: Concern 11's request to pin all budgets now.** The cleanup-order
  point *was* accepted (terminal restoration now precedes every potentially blocking
  best-effort step, and history is appended at submission so no exit path can lose
  it), as were the SIGTERM/SIGHUP/EPIPE statuses. But the numeric values of the
  drain, listener, and coalescing budgets remain OQ5: they are tuning constants whose
  right values depend on the prototype OQ1 demands, and inventing them now would pin
  numbers no evidence supports. The document states the *properties* they must have.

## Round 2 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`,
approval `never`, CWD `/Users/ccheever/projects/ibex`
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"`
**Codex session id:** `019f5596-7c98-76a0-b8b3-0fe071e3eaa0`
**Date:** 2026-07-12
**Revision under review:** `184a46b3ebb2` (sha256, first 12 — content hash of the
on-disk file; the document is not yet committed)
**Redaction status:** none — unredacted document, sibling corpus, governing LLPs,
the repository source tree, the vendored Hermes headers, `runtime-surface.json`,
and `capsec/registry/`.
**Independence:** Fresh `codex exec` session with no conversation history and no
access to the Fable reviewer's session or output. **Both Round 1 artifacts were
moved out of `llp/reviews/` before either Round 2 reviewer was launched and
restored only after both had returned**, so no reviewer could read the prior
round's findings or the other family's. The two reviewers ran concurrently on the
same revision.
**Method:** Full read of the target and the sibling corpus (itself revised since
Round 1); verification of load-bearing claims against the Rust CLI, the Hermes
bridge, the vendored Hermes headers, the builtins, `src/host/abi.rs`, the capsec
registry, and the CLI manifest; LLP 0005 standard question set.

### Verbatim review

1. **Overall assessment**

The proposal is a good idea and its security direction is strong: terminal ownership belongs outside JavaScript, cancellation needs a non-cooperative escape, display needs a structured trust boundary, and lifecycle must stop bypassing session cleanup.

However, revision `184a46b3ebb2` is not ready as a normative Spec. The §6 escape invariant is false in reachable states, and the uncatchable lifecycle completion has no demonstrated Hermes mechanism. Material protocol, history-concurrency, registry, and sibling-seam issues also remain.

2. **Strengths**

- The §1 distinction between semantic input mode and presentation topology is clear and useful ([0025:99–186](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:99)). It aligns with LLP 0022’s stdin-versus-transport split ([0022:268–319](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:268)) and correctly exposes missing current dispatch: bare `ibex` always starts the REPL without inspecting stdin ([main.rs:438–465](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438)).

- Native-before-descriptor brokerage is the right rule. Today `__exactStdinRead` changes fd 0 flags and reads it directly ([hermes_runtime_crypto.cc:5027–5073](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:5027)); `fs.readSync`, `readv`, async reads, closes, and `FileHandle` routes have no fd-0 branch ([fs.js:3608–3644](/Users/ccheever/projects/ibex/src/builtins/fs.js:3608), [fs.js:3769–3803](/Users/ccheever/projects/ibex/src/builtins/fs.js:3769), [fs.js:6029–6099](/Users/ccheever/projects/ibex/src/builtins/fs.js:6029)).

- The display IR is the correct trust-boundary decision (§3). Current display is a flat, pre-colored `Exact.inspect` string ([repl/mod.rs:63–79](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63)), which cannot distinguish trusted styling from hostile payload.

- The broker’s narrowed ordering promises, destination isolation, control lane, barriers, and refusal to drop program output are sound goals ([0025:275–312](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:275)). The distinction from LLP 0006’s best-effort diagnostics is persuasive: today the console queue explicitly drops lines under backpressure ([host/abi.rs:324–397](/Users/ccheever/projects/ibex/src/host/abi.rs:324)).

- The cancellation analysis is appropriately pessimistic. Ordinary engine calls hold serialized runtime access across native evaluation ([hermes.rs:869–896](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869), [hermes.rs:542–563](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542)), and `Engine` has no cancellation operation ([engine/mod.rs:22–99](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)). Hermes’s any-thread timeout still depends on emitted break checks ([hermes-interfaces.h:177–193](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177)); Ibex’s standalone bytecode compiler supplies no break-check option ([hermes.rs:1837–1849](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1837)).

- Defining accepted cancellation by actual return plus runtime consistency, rather than merely observing a break request, is exactly right ([0025:456–478](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:456)).

- Root-only lifecycle attribution is carefully grounded in LLP 0021’s constrained-principal model, including scheduled callbacks and deputy identity ([0025:555–594](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:555)). Retiring native hard exit is necessary: current `__exactExit` calls `std::exit`/`ExitProcess` inside the host function ([hermes_runtime.cc:588–637](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588), [hermes_runtime.cc:1704–1727](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)).

- Project-scoped history, append-at-submission, a keyed filename, no-follow/private storage, and a root-level enumerated CLI option are good defaults (§9). The option’s manifest obligation correctly follows LLP 0010’s exact CLI discipline ([0010:43–101](/Users/ccheever/projects/ibex/llp/0010-ibex-binary-ownership.decision.md:43)). Current history is global and saved only when the reader thread exits ([repl/mod.rs:582–600](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), [repl/mod.rs:674–700](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:674)).

- The PTY acceptance criteria are substantially stronger than today’s coverage. Existing signal tests launch file execution with null stdin and piped output, not a PTY ([signal_handling.rs:59–78](/Users/ccheever/projects/ibex/tests/signal_handling.rs:59)).

3. **Concerns**

1. **Blocking — the §6 escape invariant is false.**

   Evidence: the state model admits editing while background work is busy, but the editing row only discards the buffer and clears every latch ([0025:374–395](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:374), [0025:402–416](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:402)). From `(editing, stuck background callback, no latch)`, interrupt one returns to idle; interrupt two is then only the first interrupt against the callback and merely latches it. Exit requires interrupt three, contradicting the two-interrupt invariant and AC7 ([0025:432–445](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:432), [0025:768–778](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:768)). This state is reachable because readline and background engine pumping operate independently ([repl/mod.rs:634–645](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:634), [repl/mod.rs:659–681](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:659), [repl/mod.rs:762–776](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:762)).

   Completion adds further counterexamples. It is never a target or latch ([0025:397–400](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:397)), yet the current query invokes `Function`, `Object.getOwnPropertyNames`, and `getPrototypeOf`, allowing a Proxy trap to wedge the engine ([repl/mod.rs:283–348](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)). Its five-second timeout only releases the waiting editor thread; it does not cancel the engine ([repl/mod.rs:242–258](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:242)). Shutdown with a wedged exit listener also exits with the already-selected status, not 130.

   Resolution criterion: publish an executable transition function covering buffer, evaluation, background, completion, and shutdown targets. Either make an editing interrupt simultaneously clear the buffer and arm/cancel busy work, and make wedged completion killable, or weaken the invariant honestly. The table, prose proof, and AC7 must quantify over the same states and statuses.

2. **Material — target identity, races, and the latch’s linearization are underspecified.**

   Evidence: the stored state records an origin category, not a unique work identity, although “same target” must distinguish callback A from callback B ([0025:374–387](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:374)). The declared target list omits the edit buffer even though the latch rules later say the operator targeted it ([0025:384–415](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:384)). A single native poll can execute multiple callbacks and timers without exposing target boundaries ([hermes_runtime.cc:3555–3583](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3555), [hermes_runtime.cc:3634–3710](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3634)). Hermes also promises a queued debugger interrupt callback runs exactly once, creating a stale-request hazard after target A ends ([AsyncDebuggerAPI.h:133–137](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:133)). “Runtime-consistency check” is required but never defined ([0025:472–476](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:472)).

   Resolution criterion: define monotonic target IDs/generations; begin/end/cancel/interrupt linearization; ordering for target completion racing an interrupt; cancellation epochs preventing an A request from hitting B; and minimum post-cancellation consistency checks.

3. **Material — external `SIGINT` cannot satisfy the absolute non-coalescing promise.**

   Evidence: §6 makes terminal Ctrl+C and external `SIGINT` equivalent, then promises two interrupts within one quantum remain two events ([0025:382–430](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:382)). Standard POSIX signals may coalesce before user space observes them. The existing per-signal counters preserve handler invocations after delivery but cannot reconstruct a delivery the kernel coalesced ([hermes_runtime_crypto.cc:85–118](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:85), [hermes_runtime_crypto.cc:4907–4937](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:4907)).

   Resolution criterion: promise non-coalescing for raw terminal interrupt events and for distinct signals actually observed by the supervisor. External-signal tests should wait for acknowledgement of the first delivery before sending the second. Specify foreground process-group and worker signal dispositions so terminal-generated SIGINT cannot kill the worker before the supervisor handles it.

4. **Blocking — uncatchable cooperative exit lacks a demonstrated Hermes mechanism.**

   Evidence: §8 simultaneously requires the native call never to return to JavaScript, no `catch` or `finally` interception, safe unwind to a fifth outcome, later servicing outside the native frame, and a reusable runtime for exit listeners ([0025:565–583](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:565)). Current `Engine::eval` can return only `Result<Option<String>>` ([engine/mod.rs:32–39](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:32)); `ex_hermes_eval` has ordinary success/error handling and catches JavaScript and native exceptions as evaluation failures ([hermes_runtime.cc:2924–2948](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2924), [hermes_runtime.cc:3177–3235](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3177)). Killing the worker supplies uncatchability but cannot then use that runtime to run exit listeners.

   Resolution criterion: prototype a Hermes/embedding-level lifecycle completion that bypasses JavaScript exception/finally machinery, returns a distinct ABI tag, unwinds safely, and leaves the runtime valid for admitted listeners. If that is unavailable, simplify v1—for example, omit JavaScript exit listeners and terminate the worker after an authenticated supervisor request.

5. **Material — the §7 conformance alternative is effectively empty.**

   Evidence: §5 correctly excludes SIGKILL and hard native crashes from any in-process restoration guarantee ([0025:365–370](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:365)), but §7 requires an in-process alternative to restore after an uncatchable engine death ([0025:504–540](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:504)). OQ2 nevertheless reopens process versus thread while acknowledging that a thread cannot be killed safely ([0025:837–840](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:837)). The current serialized evaluation/destruction locks reinforce that conclusion ([hermes.rs:542–599](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542)).

   Resolution criterion: make a separate worker process normative for terminal-owning modes, or narrow the guarantees to a genuinely recoverable class of in-process faults. Then specify process group, job control, signal masks, worker death classification, and whether JavaScript observes worker or supervisor PID/PPID; it currently observes the engine process directly ([hermes_runtime_process_setup.cc:322–323](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:322)).

6. **Material — fd redirection alone does not deliver the broker contract.**

   Evidence: §7 says routing worker fds to a PTY/socket makes every write a broker input and makes ordering “fall out” ([0025:514–528](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:514)). But raw fd streams carry no author, event boundary, sequence, evaluation barrier, or authenticated control marker. Separate control and output channels can reorder; a final destination failure may occur after the worker’s synchronous write into the relay already succeeded. Current output paths include direct blocking fd writes ([hermes_runtime_process_setup.cc:241–278](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:241)) and an asynchronous lossy console writer ([host/abi.rs:324–397](/Users/ccheever/projects/ibex/src/host/abi.rs:324)).

   Resolution criterion: define a supervisor protocol with authenticated control messages, per-stream drain/barrier acknowledgement, one sequence domain, console-queue retirement, final-write failure semantics, queue bounds, and nonblocking/chunked control-lane behavior. State exactly what guarantee raw synchronous writers receive when the downstream destination breaks.

7. **Material — the display IR is directionally right but not yet a normative trust boundary.**

   Evidence: §3 says nodes carry trusted style/layout tokens and payload text, that the IR contains no raw escape sequences, and that an ESC-bearing payload must survive to the renderer as data ([0025:237–260](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:237), [0025:753–758](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:753)). Literally, those statements conflict unless “no raw escape” means “no producer-authorized terminal-control node.” Payload encoding, schema, validation, size limits, unknown-version handling, and malformed hostile-worker behavior are unspecified. The live editor currently returns buffer text unchanged ([repl/mod.rs:458–472](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:458)), so byte-versus-Unicode handling is load-bearing.

   Resolution criterion: publish one versioned grammar or two explicit layers (`InspectionTree → DisplayIR`), including closed node enums, child grammar, payload encoding, invalid UTF-8 policy, bounds, decoder failure, and a rule that only supervisor-originated control events can emit terminal-control bytes.

8. **Material — the history storage protocol can lose accepted entries.**

   Evidence: §9 combines concurrent append with write-new/rename compaction ([0025:619–626](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:619)). A session can retain the old inode, another session can rename a compacted replacement over the pathname, and later appends can disappear into the unlinked old inode. “Platform atomic-append size” is neither defined nor portable here, multiline framing is absent, and the entry bound that would make one-write append possible remains open ([0025:849–853](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:849)).

   The identity/crypto portion is also underdefined: HMAC algorithm, key size, canonical field encoding, and format version are missing; `(volume id, file id, birth time)` greatly reduces accidental reuse but cannot guarantee that restoration, cloning, or timestamp-resolution collisions never reproduce the tuple ([0025:628–673](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:628)). After key loss, files become unlocatable by normal lookup, not literally unreadable—the document itself says contents are plaintext to an adversary that can read them.

   Resolution criterion: add a versioned history annex specifying entry framing, oversize behavior, HMAC suite and canonical encoding, durability boundary (`write` versus sync), interprocess lock/generation protocol, compaction recovery, global-mode semantics, and identity limitations. Test append-versus-compaction and compactor-versus-compactor races with no lost accepted entries.

9. **Material — descriptor behavior is claimed to be pinned but still admits implementation choice.**

   Evidence: §1 says every fd-0 route receives a fixed EOF view, but gives concrete outcomes only for a few routes; “typed denial where Node throws” does not determine callback, promise, `readv`, `FileHandle`, poll, alias, `.fd`, and tty-operation behavior ([0025:121–151](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:121)). AC2 allows fd-1/2 close/dup behavior to be “refused or no-ops” ([0025:739–749](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:739)), contrary to the Spec’s stated goal that conforming implementations not disagree.

   Resolution criterion: include a generated route-by-route behavior table with mode branch, return/error shape, descriptor side effect, alias behavior, and principal handling for every inventoried stdio surface.

10. **Material — lifecycle registry obligations omit required reopened branches.**

   Evidence: §8 admits root-only `exit` listener registration, but §10 names exit, exitCode, fd, query, and signal rows without the process-event aliases ([0025:576–579](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:576), [0025:706–731](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:706)). Today `process.addListener`, `on`, `once`, and removal/introspection APIs are closed under `runtime:inspect` ([coverage-edges.json:214208–215](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:214208), [coverage-edges.json:216945–972](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:216945), [coverage-edges.json:217399–416](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:217399)). The new cooperative lifecycle action/resource schema is also unnamed, while `process:signal` remains deny-only ([capability-definitions.json:338–351](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:338)).

   Resolution criterion: enumerate exact registry definitions and logical branches for lifecycle request, exitCode read/write, `event === "exit"` registration/removal, attribution, listener introspection, and all aliases. Other process events must remain closed.

11. **Material — load-bearing bounds remain open, limiting conformance testability.**

   Evidence: shutdown drain, exit listeners, broker queues, diagnostic coalescing, completion, history entries, and history bytes are all normative “bounded” behaviors without values ([0025:849–853](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:849)). Current arbitrary values include a five-second completion wait ([repl/mod.rs:27–32](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:27)) and a 200 ms EOF drain ([hermes.rs:204–218](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:204)). PTY AC7 also omits the malicious nonreturning completion and the editing-plus-background-wedge counterexample.

   Resolution criterion: land the shared versioned constants annex before acceptance, plus an executable state-model test and PTY/ConPTY tests covering every repaired transition, process-group routing, hostile completion, terminal restoration, and interrupt/completion races.

12. **Minor/Non-blocking — two formulations should be narrowed.**

   Evidence: “prepared bytecode” being non-interruptible by default is too broad; the vendored JSI contract says `prepareJS`/`evaluateJS` honor `AsyncBreakCheckInEval`, while the standalone `CompileJSOptions` default is false ([hermes-interfaces.h:177–182](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177), [CompileJS.h:70–80](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/CompileJS.h:70)). The verified statement is specifically about Ibex/hermesc-produced bytecode. Also, “supplying” `--history` in a historyless mode must mean explicitly supplied; otherwise its recorded default would make every normal file/eval invocation erroneous ([0025:675–681](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:675)).

   Resolution criterion: narrow the bytecode wording and define global Clap inheritance, accepted spellings, explicit-versus-default detection, and `--history=off` behavior when topology yields no editor.

4. **Cross-document findings**

- **Contradiction — LLP 0022 interrupt summary.** LLP 0022 says a second consecutive interrupt “always ends the session” ([0022:599–614](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:599)); LLP 0025’s editing row explicitly makes the next interrupt a fresh first interrupt ([0025:389–416](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:389)). After repairing §6, LLP 0022 should project the exact same-target rule rather than duplicate it.

- **Contradiction — LLP 0022 history wording.** LLP 0022 says cooperative exit “saves history” ([0022:610–614](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:610)); LLP 0025 explicitly eliminates exit-time history saving ([0025:619–623](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:619)).

- **Ambiguity — interactive topology.** LLP 0022 says line editing, history, completion, banner, and redraw are active in interactive mode ([0022:270–277](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:270)), while LLP 0025 disables all of them when neither output is a TTY ([0025:161–175](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:161)). LLP 0022’s bullet should say “when an editor target exists.”

- **Contradiction — Hermes break catchability.** LLP 0025 deliberately refuses to assert catchability ([0025:480–488](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:480)), while LLP 0024 says a Hermes break is catchable and repeats that premise in OQ2 ([0024:480–495](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:480), [0024:994–999](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:994)). The header documents asynchronous termination, not catchability ([hermes-interfaces.h:177–193](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177)).

- **Duplication/ownership conflict — display schema.** LLP 0024 says it owns an inspection tree of kind/payload/children with “never styling” ([0024:797–803](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:797)); LLP 0025 says each display node carries trusted style/layout tokens ([0025:237–260](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:237)). Either define two layers or choose one schema owner.

- **Honest declared dependency — LLP 0024 §6 amendment.** LLP 0025 candidly declares the background-target and fifth lifecycle-outcome amendment ([0025:490–494](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:490), [0025:565–572](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:565)); LLP 0022’s ledger also records the missing lifecycle outcome ([0022:629–642](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:629)). This is honest and not a target defect. Current LLP 0024 already includes defeated/unresolved cancellation but still has only four evaluation outcomes and no non-evaluation target ([0024:395–405](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:395), [0024:480–495](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:480)).

- **Dangling lifecycle semantic.** LLP 0024’s commit/rollback algorithm covers normal completion, throw, and cancellation only ([0024:618–640](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:618)). Because LLP 0025 runs exit listeners after lifecycle unwind, the coordinated amendment must decide what session cells those listeners observe.

- **Dangling display acknowledgement.** LLP 0024 updates `$_` only after display acknowledgement ([0024:701–707](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:701)); LLP 0025 never defines whether acknowledgement occurs on enqueue, write completion, or barrier completion. LLP 0022 already marks this missing ([0022:639–641](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:639)).

- **Dangling sequence ownership.** LLP 0024 assigns evaluation outcomes and async failures one session-wide sequence ([0024:818–826](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:818)); LLP 0025 assigns broker sequence numbers without defining whether they share that domain or how raw writes map into it ([0025:275–301](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:275)).

- **Architecture-status drift.** LLP 0025 names a supervisor process as the specified realization, but its OQ2 says “if” it is adopted ([0025:514–540](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:514), [0025:837–840](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:837)). LLP 0022 calls the architecture open ([0022:642](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:642)); LLP 0024 calls it presumptive ([0024:430–436](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:430)).

- **Dangling keybinding manifest.** LLP 0022 says `.help` is generated from “LLP 0025’s keybinding manifest” ([0022:543–555](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:543)); LLP 0025 defines no such manifest.

- **Stale references.** LLP 0022 and LLP 0024 point renderer bounds to LLP 0025 OQ5 ([0022:640–642](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:640), [0024:1011–1014](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1011)); bounds are OQ6, while OQ5 concerns one-shot/file supervision ([0025:847–853](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:847)).

- **LLP 0023:** no material contradiction found. LLP 0025 explicitly and correctly distinguishes persistent history identity from LLP 0023’s live retained platform-object identity ([0025:636–656](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:636), [0023:114–165](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114)).

5. **Suggestions**

- Make the §6 transition function a generated artifact consumed by documentation, implementation, model tests, and PTY tests. This prevents prose summaries in LLP 0022 from drifting.

- Treat the supervisor as a small “terminal kernel”: it alone owns the real terminal, signal policy, history, renderer, and final status. Give the worker no real stdin and only authenticated control/output transports.

- Separate raw program-byte channels from trusted lifecycle/render-control messages. Require barrier acknowledgements on each raw stream before publishing a result or display-success ACK.

- Put the display grammar, supervisor protocol, bounds, and history format into versioned annexes rather than leaving them distributed across prose and open questions.

- Gate exit listeners on the lifecycle-completion prototype. If Hermes cannot provide a noncatchable-but-runtime-reusable completion, remove listeners from v1 rather than approximating the requirement with a catchable exception.

- A non-standard but potentially valuable extension would be crash-only worker recovery backed by a safe session checkpoint. Respawn should be offered only if bindings can be restored without replaying external effects; otherwise the current honest exit is preferable to a silently empty prompt.

6. **Open questions**

1. When both a user buffer and engine work exist, does one interrupt target both, or does busy work take priority?
2. Can a completion query ever remain nonreturning after the proposed trap-free primitive, and if so why is it not a killable target?
3. What are target boundaries for nextTicks, microtasks, and multiple callbacks batched within one native poll?
4. What exact probes establish runtime consistency after accepted cancellation?
5. Can Hermes produce a lifecycle completion that skips `catch`/`finally` yet leaves the runtime reusable for exit listeners?
6. Is a separate worker process mandatory for terminal-owning modes, and which noninteractive modes also use it?
7. What PID/PPID, process-group, job-control, and Windows console-control semantics does the supervisor expose?
8. How are raw writes, evaluator outcomes, async reports, barriers, and display acknowledgements placed in one sequence?
9. What state do exit listeners observe, and what are `beforeExit`, exit-code coercion/range, listener-order, and listener-throw semantics?
10. What are the history HMAC suite, identity encoding, durability boundary, locking/compaction protocol, and global-mode format?
11. Which exact values govern every bounded queue, drain, listener, history, completion, and diagnostic window?
12. Does “two interrupts” mean two terminal bytes, two handler deliveries, or two externally requested signals?

7. **Readiness verdict**

The core direction should be retained, but the false escape invariant and unproven lifecycle mechanism are blocking. The material protocol, history, registry, and sibling-seam issues also prevent normative readiness.

VERDICT: NOT READY
### Orchestrator verification notes

- **Concern 1 (blocking, the false escape invariant) — CONFIRMED**, and found
  independently by the Fable reviewer in the same round from the same state. The
  defect is mine, introduced in the Round 1 revision. Accepted in full; §6 was
  rebuilt around a named **edit-buffer target** and the invariant restated as *two
  interrupts against the same running work; at most three from any state*. See the
  Fable artifact's Round 2 notes for why the buffer-first rule was kept rather than
  making the editing interrupt target running work.
- **The completion-query half of Concern 1 — CONFIRMED, and this reviewer caught
  what the other missed.** The document had declared a completion query "never an
  interrupt target ... never a reason to end a session." That is unsafe: member
  completion today evaluates the base expression through
  `Function('return (' + __expr + ')')()` (`src/bin/ibex/repl/mod.rs:295-296`), and
  the 5-second `COMPLETION_DISPATCH_TIMEOUT` is a `recv_timeout` on the *editor*
  thread (`src/bin/ibex/repl/mod.rs:250-257`) — it releases the editor and never
  cancels the engine. A wedged completion query was therefore unescapable under the
  rule as written. §6 now makes a completion query killable work covered by the
  escape invariant. The reviewer's related point about a wedged **exit listener**
  during shutdown is also accepted: §6's shutdown row now escalates, and §8 no
  longer admits JavaScript exit listeners at all.
- **Concern 4 (blocking, no demonstrated mechanism for the uncatchable exit) —
  CONFIRMED and resolved by removing the requirement rather than by gating it.**
  The reviewer's own suggestion 5 ("If Hermes cannot provide a noncatchable-but-
  runtime-reusable completion, remove listeners from v1 rather than approximating
  the requirement") is the right call, and it is what this revision does: **v1
  admits no JavaScript `exit` listeners.** With no JavaScript running after the
  unwind, the exit path requires no reusable runtime, and the mechanism reduces to
  "the native lifecycle call does not return; the session layer restores, flushes,
  and exits" — provable rather than merely hoped for. `ex_hermes_eval`'s current
  success/error handling (`src/engine/hermes_runtime.cc:2924-2948`, `:3177-3235`)
  confirms there is no lifecycle path there today; OQ 1 now covers the lifecycle
  unwind alongside cancellation, and a new OQ asks whether listeners should be
  admitted once that mechanism exists.
- **Concern 2 (target identity and linearization) — CONFIRMED and accepted.** §6 now
  assigns each unit of work a **monotonic target id**, defines "same target" as the
  same id, and requires cancellation requests to carry the target's id so a request
  aimed at target A cannot be honored by target B. The reviewer's evidence that one
  native poll can run several callbacks (`src/engine/hermes_runtime.cc:3555-3583`,
  `:3634-3710`) and that Hermes's queued debugger interrupt runs "exactly once"
  (`AsyncDebuggerAPI.h:133-137`) is exactly why the epoch is needed. The
  *runtime-consistency check* remains undefined by name — it is now stated as an
  obligation with a floor and assigned to OQ 1's prototype, rather than being
  invented here.
- **Concern 5 (the §7 gate is effectively empty) — PARTIALLY ACCEPTED.** The
  ambiguity was real and is fixed: the gate now names the fault classes it covers
  (faults the process can still observe) and excludes `SIGKILL` and stack-corrupted
  deaths, which no in-process design can cover and which §5 already conceded. I did
  **not** make a separate worker process normative. A Spec that fixes the process
  model forecloses OQ 2 with no measurement, and the invariants — not the process
  count — are what conformance should test. The reviewer's supporting request was
  accepted in substance: §7 now pins **foreground process-group and signal
  disposition** (the supervisor is the foreground group; the worker must not receive
  terminal-generated `SIGINT`), which was a genuine hole, and `process.pid` under a
  supervisor is now an open question.
- **Concern 6 (fd redirection alone does not deliver the broker contract) —
  CONFIRMED and accepted.** The Round 1 text overstated: raw fd bytes carry no
  author, sequence, or barrier. §3/§7 now separate the **program byte transport**
  (raw fds, framed with `author = program` by the relay that owns them) from an
  **authenticated control channel** (lifecycle, interrupt, barrier acknowledgements),
  and state that a synchronous worker write succeeding into the relay is not a
  promise that the final destination accepted it.
- **Concern 7 (display IR) — CONFIRMED, and it exposed a real ownership conflict
  with a sibling that had moved.** LLP 0024 §8 now normatively owns the schema and
  says a node carries "a **kind**, an untrusted **payload** ... and optional children
  — and never styling. Trusted styling is the renderer's, applied to node kinds"
  (`llp/0024-structured-evaluation-and-session.spec.md:797-803`). This document's
  §3 said each node carries "trusted structure — style and layout tokens," which
  contradicts it. **The sibling is right and this document is now aligned to it**:
  the tree carries structure and payload and *no* styling; the session layer derives
  styling from node kinds. That is strictly safer — a hostile producer cannot even
  name a style — and it removes the duplicate schema.
- **Concerns 3, 8, 9, 11, 12 — CONFIRMED and accepted** (signal coalescing scoped to
  terminal-generated interrupts; history compaction/append and key-creation races;
  the fd-route table and the "refused or no-ops" laxity in AC2; explicit-vs-default
  `--history`; the bytecode wording). On the last: the claim is now narrowed exactly
  as asked — Ibex's own `hermesc` invocation passes no break-check flag
  (`src/bin/ibex/engine/hermes.rs:1837-1849`), which is the verified statement, rather
  than a broad claim about all prepared bytecode.
- **Concern 10 (process-event registry rows) — DISSOLVED** by removing exit listeners
  from v1: the `process.addListener`/`on`/`once` rows the reviewer cites stay
  **closed**, which is what the registry already says, so there is nothing to reopen.
- **Concern 11's request to land the bounds annex before acceptance — NOT ACCEPTED.**
  The numeric budgets remain OQ 6. They are tuning constants whose right values depend
  on the OQ 1 prototype, and inventing them now would pin numbers no evidence supports.
  The *properties* they must satisfy are normative here; the values are pinned there.
  This is a deliberate, recorded disagreement with the reviewer.
- **Cross-document findings — CONFIRMED and reported, not fixed.** The siblings moved
  under this document mid-round (parallel refinement runs): LLP 0022 has grown a §11
  "Delegated obligations" ledger, and LLP 0024 §6 has already added the fourth
  "defeated (unresolved)" cancellation outcome. The remaining seam defects — 0022 §10's
  "always ends the session" and its "saves history"; 0022 §11's "architecturally open"
  row and its `AC 4` pointer; 0024's still-asserted "catchable JavaScript throw"; the
  stale OQ5/OQ6 pointers; and 0022's reference to a "keybinding manifest" this document
  did not define — are listed in the final report. The last one was **fixed here rather
  than reported**, since it was a dangling dependency the sibling had assigned to this
  document: §5 now defines the keybinding manifest.
- **The `$_` display-acknowledgement seam — ACCEPTED.** LLP 0024 §7.8 updates `$_` on
  "the consumer's **display acknowledgement**"
  (`llp/0024-structured-evaluation-and-session.spec.md:701-707`), and LLP 0022 §11's
  ledger records the seam as "unstated on both sides." §3 now states this side of it:
  acknowledgement is at **barrier completion for that result event**, not on enqueue.
  Likewise the broker's sequence numbers are now explicitly drawn from the same
  session-wide sequence LLP 0024 §9 defines, rather than a second domain.

## Round 3 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`,
approval `never`, CWD `/Users/ccheever/projects/ibex`
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"`
**Codex session id:** `019f55b3-2011-7712-954d-f68618475353`
**Date:** 2026-07-12
**Revision under review:** `5001c0098469` (sha256, first 12 — content hash of the
on-disk file; the document is not yet committed)
**Redaction status:** none.
**Independence:** Fresh `codex exec` session with no conversation history and no
access to the Fable reviewer. **All Round 1 and Round 2 artifacts were moved out of
`llp/reviews/` before either Round 3 reviewer was launched and restored only after
both had returned.** The two reviewers ran concurrently on the same revision.
**Method:** Full read of the target and the sibling corpus; verification against the
Rust CLI, the Hermes bridge, the vendored Hermes headers, the builtins,
`src/host/abi.rs`, `capsec/registry/`, and `runtime-surface.json`; LLP 0005 standard
question set.

### Verbatim review

1. **Overall assessment**

The proposal’s direction is excellent: terminal ownership belongs above the engine, the style-free display tree is the right trust boundary, supervisor/worker isolation is the right default, listener-free cooperative exit is a sensible v1 scope, and project-scoped history is a major security improvement.

It is not yet ready as a normative Spec. The three-interrupt invariant is false in a reachable state even while work remains stuck; several interrupt states have no target; the broker cannot yet implement its sequencing, acknowledgement, error, and no-drop promises simultaneously; the uncatchable lifecycle unwind is unproven; and the supervisor, history, registry, and sibling contracts remain materially incomplete or contradictory.

2. **Strengths**

- The input-mode/presentation-topology split in §1 is well chosen. In particular, stderr-hosted editing while stdout remains the result channel is useful and testable, and the no-editor degradation preserves semantic mode without pretending a terminal exists ([0025 §1:108–205](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:108)).

- The generated, per-route fd-0 EOF view is stronger than special-casing `process.stdin`. Reporting `process.stdin.isTTY === false` is the honest divergence when JavaScript cannot read the terminal. Current code confirms the need: `__exactStdinRead` manipulates and reads real fd 0 ([hermes_runtime_crypto.cc:5027–5073](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:5027)), while `fs.readSync` and `closeSync` have no standard-descriptor branch ([fs.js:3599–3645](/Users/ccheever/projects/ibex/src/builtins/fs.js:3599)).

- §3’s style-free tree—kind, untrusted payload, children—is the right terminal-injection boundary. The comprehensive C0/DEL/C1, bidi, and separator escaping rules are unusually careful. Current display mixes trusted color with payload in one JavaScript-produced string and updates `$_` before printing, demonstrating exactly why the new seam is needed ([repl/mod.rs:63–80](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63), [repl/mod.rs:876–897](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:876)).

- Named cancellation targets, target IDs, stale-request rejection, and inclusion of completion queries are the correct conceptual basis for §6. The current completion query really does evaluate through `Function(...)`, while the five-second bound only times out the readline-side receiver ([repl/mod.rs:247–348](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247)). Treating that query as killable work is necessary.

- The three-press trade for a nonempty edit buffer is good. Clearing a typo should not unexpectedly terminate a session merely because benign background work is active. The problem is the stronger universal bound, not buffer priority.

- §7’s invariants-first, supervisor-default, in-process-conformance-gate posture is sound. Current evaluation holds both the runtime mutex and serialized FFI access throughout `ex_hermes_eval`, and `Engine` has no cancellation operation ([engine/hermes.rs:869–896](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869), [engine/mod.rs:22–99](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)). Pessimism is justified.

- Deferring all JavaScript `exit` listeners and `beforeExit` is better than gating them. Gating would create target-dependent lifecycle semantics while still requiring an unproven reusable-runtime property. Current code preserves recursive listener semantics before reaching the hard exit, so this is an explicit compatibility retirement rather than an accidental omission ([hermes_runtime.cc:2041–2055](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2041)).

- §9’s direction is strong: project-scoped HMAC names, creation-time identity, append-at-submission, create-only key handling, and explicit threat-model limits are all good decisions. Today history is one machine-global file and is saved only as the reader thread exits ([repl/mod.rs:582–599](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), [repl/mod.rs:674–700](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:674)).

3. **Concerns**

1. **Blocking — §6’s global three-interrupt invariant is false.**

   Evidence: §6 defines phase without separately recording the typed-ahead buffer, even though keystrokes may accumulate while phase remains `evaluating`; it then claims every reachable state ends within three interrupts ([0025 §6:421–460](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:421), [0025 §6:472–517](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:472)).

   Exhaustive reachable-state summary, where `P` is the idle prompt, `B` the buffer, `W` background/completion work, and `E` a submitted evaluation:

   | Phase / engine | Reachable latch | Selected target | Presses while target remains stable |
   | --- | --- | --- | --- |
   | idle / free | none or `P` | `P` | 2 or 1 |
   | idle / background `W` | none, `P`, or `W` | `W` | 2, 2, or 1 |
   | idle / completion `W` | none or `W` | `W` | 2 or 1 |
   | editing or continuation / free | none | `B` | 3 |
   | editing or continuation / `W` | none or `W` | `B` | 3 |
   | evaluating / current `E` | none or `E`; hidden buffer may exist | `E` | 2 or 1 |
   | evaluating / queued behind `W` | none or `W`; hidden buffer may exist | `W` | not bounded as claimed |
   | evaluating / engine free | none | no defined target | undefined |
   | shutdown | inherited/undefined | shutdown ambiguously | undefined |

   Concrete four-press counterexample with continuously stuck work:

   1. A submission is queued behind stuck work `W`; typed-ahead buffer `B` is nonempty; no latch exists.
   2. Interrupt 1 targets `W`, discards the queued submission, and latches `W`.
   3. With that submission gone, `B` makes the phase editing; interrupt 2 targets `B` and clears every latch.
   4. Interrupt 3 targets and latches still-stuck `W`.
   5. Interrupt 4 exits.

   The literal bound also fails when work returns after its cancellation interrupt: buffer-clear, work-latch, target completion clears the latch, idle-latch, exit. The conditional theorem—two interrupts actually selected against the same still-running work—is sound.

   Further gaps include `evaluating + engine-free` before dispatch, an undefined shutdown latch/identity, and no monotonic identity rule for idle or shutdown. AC7 also omits editing-with-completion despite calling its enumeration exhaustive ([0025 AC7:913–924](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:913)).

   Resolution criterion: include typed-ahead-buffer presence, queued submission, delivery stage, current target ID, and shutdown subphase in the state; define all non-work target identities and shutdown latching; close the four-press path; and restate the global property as progress-sensitive—at most three while one non-returning work target remains current. Property-test target-end/start interleavings, not only frozen tuples.

2. **Material — per-work target identity lacks an implementable publication and race protocol.**

   Evidence: one `ex_hermes_poll` drains an entire callback queue, pending task vector, and multiple due timers ([hermes_runtime.cc:946–986](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:946), [hermes_runtime.cc:3541–3683](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)). A Rust ID around that FFI call cannot identify individual callbacks. `asyncTriggerTimeout()` has no target-ID parameter ([hermes-interfaces.h:177–193](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177)); a check-then-trigger race can therefore affect a successor. `triggerInterrupt_TS()` offers an exactly-once runtime-thread callback where an ID could be checked, but is a no-op in non-debugger builds ([AsyncDebuggerAPI.h:133–137](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:133), [AsyncDebuggerAPI.h:240–269](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:240)).

   Resolution criterion: define the ID-assignment authority and instrument native begin/end publication around every evaluation, callback, microtask, timer, and completion query. OQ1 and AC7 must prove that a delayed request for `Wᵢ` cannot affect `Wᵢ₊₁`.

3. **Blocking — the broker has no implementable ordering and acknowledgement protocol.**

   Evidence: §3 gives every event one session-wide sequence and requires result barriers, while §7 acknowledges that raw fd bytes carry no author, sequence, or barrier and travel separately from authenticated control messages ([0025 §3:295–349](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:295), [0025 §7:613–622](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:613)). A control-channel barrier can overtake unread relay bytes. Assigning sequence numbers when the supervisor happens to read each channel does not reconstruct causal order.

   A synchronous write that already succeeded into the relay also cannot later receive a synchronous final-destination failure. This matters for `fs.writeSync(1)`, not just callback-based streams. Current paths include direct retrying fd writes, separately queued console output, and direct REPL printing ([hermes_runtime_process_setup.cc:241–277](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:241), [abi.rs:324–397](/Users/ccheever/projects/ibex/src/host/abi.rs:324), [repl/mod.rs:884–895](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:884)).

   §3 gives asynchronous reports a print-above transaction but does not pin equivalent prompt-preserving behavior for arbitrary background program output.

   Resolution criterion: specify and prototype one complete relay protocol covering allocator ownership, authenticated fences across raw and control channels, per-evaluation byte cutoffs, destination acknowledgement, synchronous versus asynchronous error delivery per API, partial-line prompt redraw, and `$_` acknowledgement. Stress it with concurrent stdout/stderr/raw writes and separate destinations.

4. **Blocking — “program output is never dropped” conflicts with bounded and forced shutdown.**

   Evidence: §3 promises never-drop behavior in every CLI mode; §5 permits only a budgeted flush; §6 explicitly abandons the flush on escalation ([0025 §3:336–349](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:336), [0025 §5:401–405](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:401), [0025 §6:460](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:460)). A permanently stalled destination makes finite termination and lossless delivery mutually exclusive. The current bounded flush simply returns with queued lines still pending when its deadline expires ([abi.rs:400–416](/Users/ccheever/projects/ibex/src/host/abi.rs:400)).

   Resolution criterion: either remove finite forced termination or narrow the guarantee to “never silently dropped while the writer/session remains live.” Forced termination should explicitly permit abandonment, account for the unwritten bytes/events, and report that fact through any still-usable control destination.

5. **Blocking — listener deferral does not supply the promised uncatchable lifecycle completion.**

   Evidence: §8 requires the native call never to return, to bypass `catch` and `finally`, and to surface a lifecycle outcome only after the native frame unwinds; OQ1 admits this has not been demonstrated ([0025 §8:653–675](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:653), [0025 OQ1:977–984](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:977)). Current implementation only has `std::exit`/`ExitProcess` ([hermes_runtime.cc:588–603](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588), [hermes_runtime.cc:1704–1727](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)). The available timeout and debugger interfaces do not document a host-call completion that skips JavaScript `finally`.

   Resolution criterion: demonstrate the lifecycle outcome—including `try/finally`—on every advertised target before readiness, or change the realization. A simpler conforming direction would send an authenticated lifecycle record, park the allowed root call permanently, and let the supervisor dispose of the worker; that requires revising the “native frame unwinds first” and LLP 0024 outcome requirements.

6. **Material — process-group separation is necessary but not a complete worker-isolation or signal design.**

   Evidence: §7 moves the worker outside the foreground process group, but does not require removal of inherited descriptor aliases or the controlling terminal itself ([0025 §7:605–622](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:605)). Without `setsid` or equivalent, the worker may still reopen `/dev/tty`; current raw code demonstrates why structural fd isolation matters ([hermes_runtime_crypto.cc:5027–5055](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_crypto.cc:5027)).

   The Spec also omits worker behavior for `SIGTSTP`/`SIGCONT`, `SIGHUP`, `SIGTERM`, `SIGQUIT`, supervisor death, and reaping. Otherwise the worker can continue side effects while the foreground supervisor is suspended. Re-raising `SIGQUIT` in the supervisor produces a supervisor core, not necessarily a useful engine core. `SIGPIPE` must be ignored or blocked before writes if restoration and typed EPIPE handling are to run.

   Resolution criterion: add a per-signal supervisor/worker table and require a spawn-time fd allowlist, no controlling terminal, close-on-exec control handles, parent-death cleanup, worker stop/resume/kill/reap rules, SIGPIPE disposition, core ownership, and Windows Job Object/ConPTY equivalents.

7. **Material — topology remains unresolved for modes whose guarantees already bind.**

   Evidence: §1 applies rendering, brokering, lifecycle, and immediate interrupt termination to one-shot and file execution, while §7 specifies a terminal supervisor and OQ6 still asks whether the supervisor owns those modes ([0025 §1:190–205](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:190), [0025 OQ6:996–998](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:996)). Current routes all construct and use the runtime in-process; bare `ibex` also unconditionally starts the REPL rather than selecting program mode from stdin ([main.rs:438–465](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438), [main.rs:1332–1366](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1332)).

   Resolution criterion: pin the process topology for every §1 row. Either supervise every armed CLI mode or state the complete alternative mechanism by which each in-process route satisfies broker, lifecycle, signal, and forced-interrupt guarantees.

8. **Material — §9’s history protocol does not yet prove its durability or isolation claims.**

   Evidence: §9 does not define the alleged platform atomic-append threshold, short-write handling, the stable object being locked, when appenders reopen after compaction, or partial-tail recovery ([0025 §9:714–733](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:714)). Locking the renamed history inode would not prevent later appends to an unlinked inode; a stable sidecar lock is required.

   Additional problems:

   - “Each accepted input” is never lost, but persistence failure is nonfatal, so accepted input can proceed without a record.
   - `O_CREAT|O_EXCL` alone does not stop the losing key creator from reading while the winner is still writing.
   - Existing history files need only be owned regular files; an existing mode-0644 file would receive new secrets.
   - The HMAC suite, canonical encoding, record framing, global-mode behavior, bounds, and crash recovery are promised as pinned but are absent.
   - A blocked compaction lock is session work before engine execution, yet §6 has no history-I/O target.

   Resolution criterion: provide a versioned format/constants annex; use one stable lock domain; define reopen/write-all/close ordering, partial-tail validation, atomic key publication, compaction and fsync semantics, strict existing-file/key permissions, global-mode behavior, and the exact transition when persistence degrades to off.

9. **Material — lifecycle API and registry semantics are incomplete.**

   Evidence: §8 does not specify no-argument behavior, accepted types, coercion, range, or platform normalization for `process.exit(n)` or `process.exitCode`. Current native exit casts numbers, parses strings, and defaults failures to zero, while orderly exit separately parses nonzero `i32` values ([hermes_runtime.cc:606–636](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:606), [main.rs:810–821](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:810)).

   §10 promises a new named action and resource shape without naming either. Current `process:signal` is deny-only, while `process.exit`, `__exactExit`, and `process.exitCode` are closed under existing classifications ([capability-definitions.json:339–351](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:339), [coverage-edges.json:174033–174040](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:174033), [coverage-edges.json:215892–215920](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215892)).

   Resolution criterion: specify exact JavaScript algorithms and descriptors, including getter visibility and reset semantics; name the lifecycle action, resource/occurrence normalizers, and principal rule; and give separate dispositions to request, getter, setter, `_exactExiting`, and `exit.__exactHostExit`.

10. **Material — §11’s ledger is stale and incomplete.**

    Evidence: the lifecycle row says LLP 0024 lacks the fifth outcome, but 0024 now defines and tests it ([0025 §11:865–875](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:865), [0024 §6:496–506](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:496)). Background cancellation is also already present in 0024; completion-query targets and IDs are the remaining gap. The display row is marked delivered despite a direct IR ownership contradiction described below.

    Missing obligations include lifecycle capability-definition/schema/digest/target-cell work, trusted supervisor spawn/IPC/signal classification, post-arming history filesystem effects, the keybinding manifest schema, and the shared constants annex.

    The explicitly listed pending rows for broker sequence membership, acknowledgement timing, mode-scoped branches, registry reconciliation, and `--history` are honest obligations; their pending status is not itself a target defect.

    Resolution criterion: give every obligation a stable ID checked by `./ref-check`, as LLP 0022 requires for its ledger, and make every delivery status and owner mechanically accurate.

11. **Material — open numeric bounds prevent deterministic conformance.**

    Evidence: OQ7 leaves shutdown, completion, broker, storm, renderer, and history bounds unset even though the acceptance criteria depend on them ([0025 OQ7:999–1003](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:999)). Current implementation happens to use five seconds for completion, 200 ms for EOF drain, and 1,024 polls per idle pump ([repl/mod.rs:27–32](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:27), [engine/hermes.rs:204–222](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:204)); the Spec neither adopts nor replaces them.

    Resolution criterion: publish one versioned constants annex shared with LLPs 0022 and 0024, with normative maxima and deterministic test-clock behavior per supported platform.

4. **Cross-document findings**

- **LLP 0022 has sibling defects.** Its §10 says two interrupts suffice “from any state” with executing work, then immediately acknowledges that a nonempty buffer spends the first interrupt ([0022 §10:720–731](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:720)). Its ledger says 0025 has no display-ack lane even though 0025 now defines barrier-completion acknowledgement, and says lifecycle is absent despite 0024’s current outcome ([0022 §11:756–780](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:756)). It correctly identifies that 0025 publishes no actual keybinding table.

- **LLP 0023 has no substantive contradiction with the target.** LLP 0025 correctly distinguishes persistent history identity from 0023’s live retained platform-object identity ([0025 §9:744–769](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:744), [0023 §2:114–165](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114)). The fallback host path is HMAC input held natively, not a JavaScript-visible path.

- **LLP 0024 directly contradicts the target’s display decision.** LLP 0025 says the one serializable object crossing the boundary is the style-free kind/payload/children tree. LLP 0024 says it owns a semantic tree but 0025 owns a distinct display IR containing trusted style/layout tokens, and that only this IR crosses ([0024 §8:1077–1095](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1077)). The target’s decision is better: the worker should emit one style-free tree, and the supervisor should derive all styling.

- **Cancellation vocabulary conflicts with LLP 0024.** LLP 0025 defines accepted by work returning plus consistency and defeated as unresolved. LLP 0024 says accepted wins only with a `cancelled` outcome, while normal completion after a delivered request resolves “defeated”—despite also calling defeated unresolved ([0024 §6:592–632](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:592)). A two-axis model—request state versus work outcome—would remove this contradiction.

- **Lifecycle delivery status is stale, not pending.** LLP 0024 now carries the lifecycle outcome and AC18 tests five outcomes ([0024 AC18:1317–1325](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1317)); its Summary still lists only four, which is another sibling defect.

- **Normal drain ownership is ambiguous.** LLPs 0022 and 0024 require program and one-shot modes to drain to quiescence ([0022 §3:354–362](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:354), [0024 §1:159–163](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:159)). LLP 0025 should explicitly limit its bounded orderly drain to REPL/transcript shutdown and leave normal program/one-shot completion with 0024.

- **The LLP 0021 dependency is only partly ledgered.** Mode-scoped branch vocabulary and reconciliation are honestly named as pending. The new lifecycle definition, normalizers, digest projections, supervisor control routes, and history-side effects are not.

5. **Suggestions**

- Generate implementation code, documentation, and property tests from one declarative interrupt transition table. Include non-engine session work—history append, result barrier, broker flush—as named targets.

- Make the supervisor a small nonblocking control kernel: signal intake, terminal restoration, and escalation must never share an executor with destination writes, history I/O, or worker teardown.

- Consider supervising every armed CLI mode. Give session workers an EOF fd 0 and non-session workers a brokered stdin relay; this makes lifecycle and output semantics uniform.

- Prefer authenticated lifecycle notification followed by disposal of a parked worker over inventing a reusable uncatchable Hermes unwind. The listener-free v1 decision makes this unusually clean.

- Replace the raw-relay/control-channel ambiguity with a trusted relay component that owns output counters and authenticated barrier markers.

- Consider one hardened per-user SQLite/WAL history database keyed by the HMAC project identity. It eliminates filename correlation and delegates locking, compaction, and crash recovery to a transactional format, at the cost of a shared corruption domain.

- Escape prompt overrides as data by default. If operators need raw terminal controls in a custom prompt, expose that as an explicit unsafe or typed-template option rather than treating arbitrary environment bytes as inherently trusted.

6. **Open questions**

1. Is the intended escape property universal, or specifically bounded while one non-returning target remains current? What happens to typed-ahead input when a queued submission is interrupted?

2. Is cooperative exit implemented as a genuine Hermes completion or as authenticated worker disposal?

3. Who owns the session-wide sequence, and what exact fence proves that all pre-result raw bytes reached their destinations?

4. What error does each write API observe when relay acceptance succeeds but final delivery later fails?

5. Do all armed CLI modes use workers, and what should `pid`, `ppid`, process group, and signal observables report?

6. Which process receives or generates a `SIGQUIT` core, and how are worker stop/resume and supervisor death handled?

7. What durability is history promising: survival of process termination/SIGKILL, or also machine crash and power loss?

8. What exact value algorithms govern `process.exit` and `process.exitCode` across POSIX and Windows?

9. Should external `SIGINT` really share buffer-clearing semantics with terminal Ctrl+C, given that an external sender is more likely trying to interrupt work than clear a typo?

10. Is there one style-free display wire object, or both a semantic tree and a display IR? Which document owns its schema and bounds?

7. **Readiness verdict**

The proposal should remain Draft. The ownership model and most high-level decisions are worth preserving, but the false escape invariant, missing target states, unimplementable broker promises, unproven lifecycle mechanism, and unresolved cross-document contracts are material blockers.

VERDICT: NOT READY
### Orchestrator verification notes

- **Concern 1 (blocking, the four-press counterexample) — CONFIRMED**, and the Fable
  reviewer produced the identical trajectory independently in the same round. The defect
  is mine: row 5 discarded the queued submission but left the typed-ahead buffer, so the
  phase fell back to *editing*, the buffer ate a second interrupt, and row 3's "clear every
  latch" destroyed the progress. The reviewer's second observation — that the literal bound
  also fails "when work returns after its cancellation interrupt" — is the same root cause
  as the Fable reviewer's unbounded-turnover case, and it is the deeper of the two.
  **Root cause:** the latch was bound to a *work unit*, so Round 1's stale-latch fix
  ("clear when the target ends") and this round's turnover bug are one rule pulling in two
  directions. §6 now uses a two-level model: **cancellation requests stay id-exact against
  the unit** (forced by the exactly-once queued interrupt the reviewer cites), while the
  **latch is armed against a target *class*** — running work — that survives turnover and is
  cleared only by editor input. The bound is now provably three, the interval storm exits in
  two, and the notice is always true.
- **Concern 2 (target identity has no implementable publication protocol) — CONFIRMED and
  accepted.** The evidence is decisive: one `ex_hermes_poll` drains the whole callback
  queue, the pending-task vector, and multiple due timers
  (`src/engine/hermes_runtime.cc:946-986`, `:3541-3683`), so a Rust-side id wrapped around
  the FFI call cannot name an individual callback; and `asyncTriggerTimeout()` takes no
  target parameter (`hermes-interfaces.h:177-193`). §6 now requires **native begin/end
  publication** for every unit — evaluation, callback, microtask drain, timer, completion
  query — as an obligation on the engine seam, and assigns the check-then-trigger race to
  OQ 1 rather than asserting a solution.
  **A further fact this check turned up, which strengthens the reviewer's point:**
  `AsyncDebuggerAPI::triggerInterrupt_TS` is an **empty no-op stub** in the vendored headers
  unless Hermes is built with `HERMES_ENABLE_DEBUGGER`
  (`ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:269` — the body is `{}` in the
  `#if !HERMES_ENABLE_DEBUGGER` branch), and Ibex's build only defines that flag
  conditionally (`build.rs:1129`, `:2640`). Choosing that mechanism would therefore bind the
  runtime's interruptibility to a debugger build. OQ 1 now records this.
- **Concern 3 (the broker has no implementable ordering protocol) — CONFIRMED and accepted.**
  The reviewer is right that a control-channel barrier can overtake unread relay bytes and
  that assigning sequence numbers at read time does not reconstruct causal order. §3 now
  pins the mechanism: a barrier carries a **program-byte cutoff** — the value of the worker's
  output counter when the barrier was created — and the supervisor drains each relay *to that
  cutoff* before emitting the barrier's event. It also states plainly that a synchronous write
  succeeding into the relay means the **session accepted the bytes, not that the destination
  did**, so a later destination failure cannot retroactively fail the synchronous call.
- **Concern 4 ("never dropped" conflicts with bounded and forced shutdown) — CONFIRMED and
  accepted.** The contradiction is real and the current code proves the shape:
  `ex_host_console_flush` returns with lines still queued when its deadline expires
  (`src/host/abi.rs:400-416`). §3 now says program output is never **silently** dropped while
  the session is live, and that a forced termination's abandonment is **explicit and
  accounted** — the unwritten count is reported on a still-usable destination.
- **Concern 5 (listener deferral does not supply the uncatchable completion) — CONFIRMED, and
  the reviewer's own alternative is adopted.** Removing exit listeners removed the
  *reusable-runtime* requirement but not the *unwind* requirement: the document still asked for
  a completion that skips `catch`/`finally`, which no vendored interface offers. The reviewer's
  suggested realization — "send an authenticated lifecycle record, park the allowed root call
  permanently, and let the supervisor dispose of the worker" — dissolves it, and §8 now adopts
  it: **the call does not return because it parks, not because it unwinds.** `finally` cannot
  run in a frame that never exits, so no engine mechanism is required at all; in-process the
  same call performs restoration and flush and then terminates without returning. The lifecycle
  question is removed from OQ 1 entirely. This also means LLP 0024 §6's new lifecycle row —
  which says "the evaluation **unwinds** as a lifecycle completion"
  (`llp/0024-…:506`) — describes a mechanism that need not exist; §11 carries the correction.
- **Concerns 6, 7, 8, 9, 11 — CONFIRMED and accepted.** Worker isolation now requires no
  controlling terminal, a spawn-time fd allowlist, close-on-exec control handles,
  parent-death cleanup, `SIGTSTP`/`SIGCONT` forwarding, and an ignored `SIGPIPE`; the
  `SIGQUIT` row now admits honestly that the core is the *supervisor's* and the engine's state
  is not captured; §1 pins non-session modes as in-process in v1 (their escape is the signal
  handler, which needs no engine cooperation); §9's history protocol is rebuilt on a stable
  sidecar lock; §8 pins the exit-status coercion and POSIX 8-bit masking; and §10 names the
  lifecycle action rather than promising one.
- **Concern 10 (stale ledger) — CONFIRMED and corrected**; see the Fable artifact's notes.
- **Concern 11's renewed request to land the bounds annex before readiness — STILL NOT
  ACCEPTED, but the objection behind it is now answered.** The reviewer is right that
  conformance must be deterministic. The fix is not to invent production constants before OQ 1's
  prototype; it is to decouple the two: the acceptance criteria now run against a **deterministic
  test clock**, so every bounded behavior is testable without pinning a production value. The
  properties are normative here; the values are pinned by the prototype. This remains a recorded
  disagreement.
- **The reviewer's suggestion to escape the prompt override as data — ACCEPTED, and it closed a
  real hole.** The document had called the operator's `IBEX_REPL_PROMPT` "trusted configuration…
  rendered verbatim," but the *environment* is not the operator: a hostile `.envrc`, a compromised
  parent process, or a poisoned CI variable could inject terminal control through the one string
  the renderer waved through. §3 now escapes the prompt override as data like everything else, and
  styling is available only through the trusted style vocabulary.

## Round 4 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval
`never`, CWD `/Users/ccheever/projects/ibex`. Launched from the main session under
the coordinator's handoff protocol (a detached `codex exec` started from inside a
subagent turn is killed when that turn ends; rounds 1–3 survived by luck, not by
mechanism).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f55d3-cc32-74e0-8860-6ee04fad51ec`
**Rollout:** `~/.codex/sessions/2026/07/12/rollout-2026-07-12T03-16-11-019f55d3-….jsonl`
**Integrity check:** the final assistant message was extracted from that rollout and
md5'd — **`6209179200a7`** — and matches the captured review body byte-for-byte. The
body recorded below is provably the output of the session cited above. This check is
now standard for this corpus after a sibling artifact once cited a session id against
a body that session did not produce (a log-path collision — a real body with wrong
provenance, and catchable).
**Date:** 2026-07-12
**Revision under review:** `43ff879a257a`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating
session, to the concurrent Fable round-4 review of the same revision, or to any prior
LLP 0025 artifact — `llp/reviews/` was verified to contain no 0025 files while it ran.
**Method:** `brief-round4.md` verbatim; full read of the target, the sibling corpus,
the governing LLPs, and the named implementation surfaces.

### Verbatim review

## 1. Overall assessment

I reviewed the complete SHA-256 revision `43ff879a257a…`, all three siblings, the governing LLPs, and the named implementation surfaces.

The proposal’s central idea is good: terminal ownership belongs in a session layer that survives the engine, and a supervisor process is the strongest way to make that ownership structural. The unstyled display tree and parked lifecycle exit are also substantial improvements.

It is not ready as a normative Spec. Three areas still have material correctness failures:

- §6’s escape invariant remains false under reachable input and turnover trajectories.
- §3/§7 do not yet define an implementable, tamper-resistant broker and worker-isolation protocol for every promised writer.
- §9’s cross-session identity and persistence protocol conflicts with LLP 0023 and lacks the crash/concurrency semantics required by its durability claims.

These are defects in the target’s current contract, not merely implementation work that remains. By contrast, several pending sibling edits already identified in §11—especially O-2, O-5 through O-9, and O-10 through O-12—are honestly ledgered and are not defects of the target merely because they have not landed.

## 2. Strengths

- §1 makes the mode/topology distinction clearly and correctly. It also follows LLP 0010’s root-option discipline: bare `ibex` and `ibex repl` both dispatch to the same REPL today, while `Commands::Repl` is optionless ([main.rs:344](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:344), [main.rs:438](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438), [cli.rs:175](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:175)).

- §3’s trust boundary is the right one. Current code asks JavaScript for a pre-colored string and prints it directly ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63), [repl/mod.rs:864](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:864)). A versioned tree of kind, untrusted payload, and children, with all styling chosen by the supervisor/session renderer, is a sound replacement. The prompt override should indeed be escaped as data; today it is read directly from the environment and styled without such a boundary ([repl/mod.rs:50](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:50), [repl/mod.rs:91](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:91)).

- §3 correctly supersedes the embedded-host console policy for the CLI. The current queue deliberately drops lines under backpressure, and its bounded flush may return with accepted lines still pending ([abi.rs:324](/Users/ccheever/projects/ibex/src/host/abi.rs:324), [abi.rs:351](/Users/ccheever/projects/ibex/src/host/abi.rs:351), [abi.rs:400](/Users/ccheever/projects/ibex/src/host/abi.rs:400)). Treating CLI stdout as data rather than best-effort diagnostics is the right decision.

- §6’s separation between id-exact cancellation requests and a class-level escalation latch is conceptually correct. The engine evidence motivating pessimism is accurate: the `Engine` trait has no cancellation operation ([engine/mod.rs:20](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:20)); evaluation holds serialized runtime access across `ex_hermes_eval` ([hermes.rs:542](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542), [hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869)); and one native poll drains a callback snapshot and several timers ([hermes_runtime.cc:946](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:946), [hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)).

- The Hermes interrupt analysis is accurate. `asyncTriggerTimeout()` is any-thread and untargeted ([hermes-interfaces.h:177](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177)); debugger interruption is exactly-once only in debugger builds and is a no-op stub otherwise ([AsyncDebuggerAPI.h:133](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:133), [AsyncDebuggerAPI.h:269](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:269)); and interruptible bytecode requires `emitAsyncBreakCheck`, while the current `hermesc` command supplies no such option ([CompileJS.h:39](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/CompileJS.h:39), [hermes.rs:1837](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1837)).

- §7’s supervisor is the right default architecture. It is the only proposed realization that can restore the terminal after worker death, enforce the second interrupt without engine cooperation, and contain the current native hard exit, which calls `std::exit`/`ExitProcess` directly ([hermes_runtime.cc:588](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588), [hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)).

- §8’s parking insight is sound under a supervisor: a host function that never returns cannot execute subsequent statements or unwind through `finally`. This removes the invented “unwind past finally” engine requirement.

- Diagnosed no-effect registration for `exit` and `beforeExit` is directionally preferable to an import-time throw. It preserves compatibility for packages that register cleanup hooks opportunistically, while honestly refusing to promise that the hooks run.

- §9’s project scoping, HMAC filename privacy, append-at-submission direction, stable sidecar lock, reopen-after-lock rule, hardening, and refusal to rotate a malformed key are all good decisions. They address real current behavior: one global file is loaded once and rewritten on REPL exit ([repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), [repl/mod.rs:674](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:674)).

- The acceptance section correctly demands PTY/ConPTY tests, deterministic clocks, trajectory testing rather than frozen tuples, hostile display-tree tests, and generated route coverage.

## 3. Concerns

1. **Blocking — §6’s escape invariant remains false under reachable trajectories.**

   **Evidence:** The declared state is `(phase, engine-busy origin, latch)` in [0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:428). The actually reachable state families are:

   | Phase | Reachable engine origins | Stable latch values |
   | --- | --- | --- |
   | idle | free, background callback, completion query | none, idle-prompt, running-work |
   | editing / continuation | free, background callback, completion query | normally none; input clears any prior latch |
   | evaluating | free/pending submission, current submitted evaluation, earlier callback/query | none or running-work |
   | shutdown | any engine state retained during teardown | none or inherited idle/running; a shutdown latch is implied but never specified |

   The advertised tuple is incomplete: typed-ahead presence is hidden while the phase remains evaluating ([0025:476](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:476)); pending completion work and scheduler backlog are absent; and there is no state distinguishing a transient free turnover gap from a genuinely returned prompt.

   Latch rule 3 clears the latch on any keystroke or bare Enter ([0025:499](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:499)). Therefore one non-returning evaluation has this trajectory:

   ```text
   (evaluating, submitted, none)
     C1 → (evaluating, submitted, running-work)
     type x → (evaluating, submitted, none)
     C2 → (evaluating, submitted, running-work)
     type y → (evaluating, submitted, none)
     ... indefinitely
   ```

   Work never returned, but every pair of interrupts can be defeated by typed-ahead input. That directly refutes the unconditional two-interrupt and at-most-three claims in [0025:527](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:527).

   The queued-submission path can still take four presses:

   ```text
   (evaluating, background, none; submission queued)
     C1 → discard submission/buffer; (idle, background, running-work)
     type x → (editing, background, none)
     C2 → clear buffer; (idle, background, none)
     C3 → (idle, background, running-work)
     C4 → exit 130
   ```

   Turnover also remains unbounded because target selection switches to idle whenever the engine is momentarily free:

   ```text
   (idle, callback B1, none)
     C1 → running-work latch
     B1 ends → (idle, free, running-work)
     C2 in gap → idle-prompt latch
     B2 begins
     C3 during B2 → running-work latch
     B2 ends
     C4 in gap → idle-prompt latch
     ... indefinitely
   ```

   Current polling makes such boundaries concrete: repeating timers are rescheduled and the poll returns ([hermes_runtime.cc:3621](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3621)); Rust invokes separately bounded poll calls ([hermes.rs:1113](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1113)).

   The “notice is always true” claim is likewise false after input, work completion, or an idle-to-running class change. Finally, the shutdown row relies on a shutdown latch to distinguish its first and second interrupts but never arms one; the operator-input class is named but deliberately never latched.

   **Resolution criterion:** Define a running-work epoch that ends only on authenticated quiescence plus prompt-ready acknowledgement—not on a unit boundary. Typed-ahead input received before that acknowledgement must not clear a running-work latch. Publish a complete event/transition table including buffer presence, pending submissions/completions, work epoch, prompt generation, and shutdown substate, then model-check every interleaving of key input, interrupts, unit end/begin, poll return, dispatch, and prompt acknowledgement. Narrow the guarantee if intervening operator input is intended to reset it.

2. **Material — a wedged completion query naturally takes three interrupts, not two, and queued completion work is unmodeled.**

   **Evidence:** A member-completion query originates from a non-empty edit buffer: the current parser extracts the base from the current line ([repl/mod.rs:261](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:261)), then dispatches a query through `Function(...)` on the engine thread ([repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)). Under §6’s editing row:

   ```text
   (editing, completion, none)
     C1 → clear buffer; (idle, completion, none)
     C2 → running-work latch
     C3 → exit 130
   ```

   That contradicts AC7’s “wedged completion query exits in two” assertion ([0025:912](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:912)).

   The present five-second editor timeout only abandons the receiver; it does not cancel or remove the request from the unbounded engine channel ([repl/mod.rs:247](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247), [repl/mod.rs:652](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:652), [repl/mod.rs:710](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:710)). A stale query can therefore begin after its buffer changed.

   The three-press editing trade is reasonable for an incidental benign background callback: preserving “Ctrl+C clears my typo” is valuable. It is not the right uniform treatment for a completion query caused by the editor itself.

   **Resolution criterion:** Add a `completing` phase or explicit precedence rule under which the first interrupt abandons the result, invalidates the query by buffer generation, requests cancellation, and arms running work. Include accepted-but-unstarted completion requests in the machine. Otherwise revise the acceptance criterion to three presses from editing.

3. **Blocking — §3’s byte-cutoff barrier is not yet a complete implementable ordering protocol.**

   **Evidence:** §3 describes one “program-byte cutoff” and requires the supervisor to drain “each relay” to it ([0025:320](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:320)). Distinct stdout and stderr relays cannot share one scalar cutoff. Waiting for every relay also contradicts the guarantee that a stalled destination cannot block another ([0025:334](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:334)).

   Every producer must participate in the cutoff’s happens-before relation:

   - native process streams call `write(2)` directly ([hermes_runtime_process_setup.cc:241](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:241));
   - `fs.writeSync` has another direct descriptor route ([hermes_runtime_fs.cc:3017](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3017));
   - console output currently passes through a separate writer thread ([abi.rs:376](/Users/ccheever/projects/ibex/src/host/abi.rs:376));
   - authorized subprocesses can inherit or redirect the descriptors directly ([hermes_runtime_process.cc:1442](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1442), [hermes_runtime_process.cc:1777](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1777)).

   A worker-local counter does not observe descendant writes. Raw streams also have no event boundaries, yet forced termination promises a count of “unwritten events” ([0025:348](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:348)). The same-open-file-description predicate is not given a portable detection rule.

   Display acknowledgement at result-barrier completion is a good rule, but it becomes implementable only after these ordering semantics exist.

   **Resolution criterion:** Define a per-relay cutoff vector with epochs, exact counter-commit semantics, and destination-local barrier completion. State which completed writes fall before a barrier, how partial writes count, and whether raw loss is reported in bytes, writes, or framed events. Route every writer—including console threads and authorized descendants—through the counting/framing point, forbid inherited session stdio, or narrow the guarantee. Define a portable topology predicate or have the supervisor construct the topology it promises. Test unequal relay volumes, concurrent/partial writes, child output, and one stalled destination while another continues.

4. **Blocking — the authenticated lane and worker isolation are not structurally protected yet.**

   **Evidence:** §7’s no-controlling-terminal and fd-allowlist rules are necessary but insufficient ([0025:603](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:603)). A control descriptor inside the worker cannot merely be obscure: current native policy permits root/runtime principals to use unknown numeric descriptors ([hermes_runtime_fs.cc:158](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:158), [hermes_runtime_fs.cc:220](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:220)). A guessed control fd can therefore reach the ordinary raw write route unless explicitly protected.

   Removing the controlling terminal makes `/dev/tty` fail but does not by itself prevent opening the concrete terminal device, `/dev/fd` or `/proc/.../fd` aliases, receiving one over `SCM_RIGHTS`, or an authorized child doing so. The virtual namespace closes many direct JavaScript path routes, but the guarantee must either include or explicitly exclude spawned descendants.

   “Kill-on-relay-EOF at minimum” is also incomplete: a worker stuck inside evaluation cannot service EOF on the engine thread, which may hold `ffi_lock` indefinitely ([hermes.rs:542](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542), [hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869)).

   **Resolution criterion:** Put control, watchdog, and relay-management handles in a native protected-fd class unreachable from every numeric JS descriptor API. Bind framed control records to the spawned worker, armed session nonce/channel epoch, record type, and replay state; program bytes must never authenticate. Require a kernel parent-death mechanism or an engine-independent watchdog that never takes runtime/broker locks, including the parent-death setup-race check. Define the terminal-device and descendant threat boundary and add PTY attacks using guessed fds, concrete device paths, fd aliases, `SCM_RIGHTS`, spawned children, and supervisor `SIGKILL`.

5. **Material — parking is sound under the supervisor, but the in-process exit realization remains underspecified.**

   **Evidence:** §8 correctly states that a parked call does not unwind ([0025:654](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:654)). Under the supervisor, the worker can commit an authenticated lifecycle record, park, and be killed after restoration and flushing.

   In-process one-shot and file execution are different. The current evaluator and session loop run on the engine-owning thread ([repl/mod.rs:632](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:632), [repl/mod.rs:706](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:706)), and evaluation holds the runtime/FFI locks. If the host call parks, the outer evaluator cannot resume to perform cleanup, and runtime destruction would deadlock on the held lock. Thus “no engine unwind mechanism” is true, but “no mechanism at all” is too broad.

   The lifecycle record also needs a commit rule: if its send fails or blocks before the supervisor observes it, parking forever is not a cooperative exit.

   **Resolution criterion:** Specify either synchronous restoration plus bounded broker flush inside the accepted host call followed by `_exit`/`TerminateProcess`, or an independent lifecycle coordinator with reserved nonblocking capacity that owns restoration and flushing. After parking, require no runtime destruction, joins, or lock acquisition. Define the control-record commit/failure path and test `-e`, file execution, and no-editor modes with a saturated destination.

6. **Material — the no-effect listener branch is the right policy but does not cover the actual EventEmitter surface.**

   **Evidence:** §8 and §10 name `on`, `addListener`, and `once` only ([0025:674](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:674), [0025:833](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:833)). Current Process also exposes `prependListener`, `prependOnceListener`, `removeListener`, `off`, `listeners`, `rawListeners`, `listenerCount`, `eventNames`, and manual `emit` behavior ([stream-enhance.js:20](/Users/ccheever/projects/ibex/src/engine/bootstrap/stream-enhance.js:20), [stream-enhance.js:46](/Users/ccheever/projects/ibex/src/engine/bootstrap/stream-enhance.js:46), [coverage-edges.json:217153](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:217153)). Current exit code explicitly emits `exit` listeners before hard exit ([stream-enhance.js:615](/Users/ccheever/projects/ibex/src/engine/bootstrap/stream-enhance.js:615)).

   If a “no-effect” listener is stored, introspection and manual `emit('exit')` can still observe or invoke it. If it is not stored, those results must be specified.

   **Resolution criterion:** Generate branches for every registration alias and pin removal, introspection, and manual-emission behavior. Prefer not storing the listener and keeping manual lifecycle emission closed. Give the warning a stable code and define whether “once” means per event, call site, or session.

7. **Material — §9’s history identity conflicts with LLP 0023’s worker-locality rule and is not yet a durable cross-session identity.**

   **Evidence:** The supervisor owns history under §7, while §9 persists LLP 0023’s retained-object record across sessions ([0025:594](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:594), [0025:756](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:756)). LLP 0023, however, requires every retained/VFS identity to live and be derived in the engine worker and forbids serializing retained identity to the supervisor ([0023:791](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:791)).

   The target also extends rather than merely reuses 0023’s record by defining cross-session creation-time and path-fallback semantics. Current `ObjectIdentity` contains only platform, volume, and file—no verification generation ([model.rs:614](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:614))—and current arming serializes `st_dev`/`st_ino`, which is not a durable cross-reboot/remount volume identity ([runtime.rs:1681](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1681)).

   **Resolution criterion:** Choose one owner. A clean design would define a separately named, versioned `ProjectHistoryIdentity`, authenticated by the supervisor before spawn, with durable platform-specific volume/file/generation encodings and an explicit path-fallback variant. Amend LLP 0023’s worker-locality rule or make this clearly not a VFS retained identity. Pass only an opaque history-scope token to the worker, and test restart, rename, delete/recreate, remount, clone/restore, spoofing, and worker replacement.

8. **Material — the history key and append log do not yet satisfy the stated concurrency and crash guarantees.**

   **Evidence:** Temp-plus-rename key publication is atomic against torn reads but not no-clobber: two first sessions can generate different keys, and an ordinary rename can replace the winner, effectively rotating the key despite §9’s promise ([0025:787](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:787)). A separately stored check value creates an additional transaction boundary.

   The append format is described only as “framed” ([0025:731](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:731)). The Spec does not define exclusive append serialization, partial-record recovery, checksums, valid-prefix preservation, startup-read locking, or how compaction treats a torn tail. Combined with “corrupt file degrades to empty,” one killed append could erase recall of every earlier valid record—contradicting the durability claim.

   “Accepted input” is also undefined at command, syntax-error, queued-cancel, and continuation boundaries. Current code adds every nonblank readline result before command or evaluation dispatch ([repl/mod.rs:681](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:681)). The storage root is not pinned; current code falls back to the current directory if no data directory exists ([repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582)).

   **Resolution criterion:** Publish key+check as one versioned record using no-clobber creation or a stable key lock; losers must reread the installed key. Pin an exclusive append protocol, length/checksum format, valid-prefix recovery, tail truncation, load locking, and compaction recovery. Define the symbolic per-platform history home with no cwd fallback, and enumerate exactly which submissions enter history. Add two-process first-use tests and kill/fault injection at every write, lock, and rename boundary.

9. **Material — §10 and §11 omit authority-bearing history and worker-bootstrap surfaces.**

   **Evidence:** LLP 0021 defines surfaces to include startup routes and requires every authority-bearing route to be classified ([0021:132](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:132)). §10 covers lifecycle, stdio, and supervisor control, but not history-directory discovery, key creation/read, lock acquisition, history read/append, compaction, or legacy-file probing ([0025:820](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:820)). Shipping history uses ambient Rust filesystem calls ([repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582)).

   A process worker also needs an authenticated private entry route on non-fork platforms. If that is a hidden command or option, LLP 0010 requires it in `runtime-surface.json`; the manifest currently lists only `self-test` and `compat` as hidden commands ([runtime-surface.json:1](/Users/ccheever/projects/ibex/runtime-surface.json:1)).

   **Resolution criterion:** Add generated runtime-internal history-store rows and fixtures, protected internal-fd/control rows, complete lifecycle-listener branches, and the chosen worker-bootstrap route. If worker startup touches Clap, add the manifest and §11 obligation and reject unauthenticated direct invocation. Add explicit/default `--history` provenance tests so a recorded default is not diagnosed while an explicitly supplied unusable value is.

10. **Material — asynchronous-failure fatality and exit status have no current normative owner.**

    **Evidence:** LLP 0024 says the engine only reports and delegates fatality to consumer lifecycle policy, citing LLP 0025 §8 ([0024:1151](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1151)). LLP 0022 pins fatality in program/file execution and non-fatality at the prompt, and its ledger explicitly says 0025 lacks the corresponding matrix ([0022:401](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:401), [0022:887](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:887)). The target’s status table omits syntax/foreground throws and background rejection/exception outcomes.

    Current code confirms that the engine still decides: it writes the error and sets `fatal_async_error` itself ([hermes_runtime.cc:673](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:673), [hermes_runtime.cc:3712](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3712)).

    **Resolution criterion:** Add a mode × event-class matrix covering parse failure, foreground throw, unhandled rejection, background uncaught exception, cancellation failure, engine fault, and broker failure, with exact status and continuation behavior; or assign that matrix explicitly to another normative owner and correct every citation and ledger row.

11. **Material — raw mode disables terminal-generated Ctrl+Z, while §7 specifies only signal forwarding.**

    **Evidence:** §5 requires `ISIG` off for the whole terminal-owning session ([0025:394](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:394)). Consequently, typed Ctrl+Z is a byte, not a kernel-generated `SIGTSTP`. Forwarding `SIGTSTP`/`SIGCONT` in §7 does not implement ordinary interactive suspension. The current key help has no Ctrl+Z behavior ([repl/mod.rs:621](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:621)).

    **Resolution criterion:** Put Ctrl+Z in the keybinding manifest and specify the supervisor transaction: restore terminal, stop worker group, stop supervisor; on continuation, reacquire/verify foreground ownership, reinstall raw mode, continue the worker, and redraw. Test both the byte-level key and externally delivered `SIGTSTP`.

12. **Material — normative wire formats and observable bounds remain open.**

    **Evidence:** OQ7 leaves shutdown, broker, completion, history-lock, renderer, and history limits unspecified ([0025:989](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:989)). OQ8 leaves the display/event/transcript wire relationship open ([0025:994](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:994)). LLP 0022 correctly notes that transcript byte fixtures cannot be pinned without these values ([0022:905](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:905)). The history section likewise says its format is pinned without actually giving the byte schema.

    Deterministic test clocks make a chosen bound testable; they do not choose the observable bound.

    **Resolution criterion:** Add a versioned constants and wire-schema annex covering all numeric limits, truncation markers, queue/backpressure behavior, history framing, control records, and schema-version negotiation. A normative Spec can leave implementation technique open, but not user-visible values needed for conformance.

## 4. Cross-document findings

1. **LLP 0022 contradicts the target’s revised interrupt and exit mechanisms.** Its §10 still says two interrupts against the “same running target,” omitting class-surviving succession, and says lifecycle “unwinds” so `finally` cannot intercept ([0022:828](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:828), [0022:844](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:844)). These required 0022 edits are missing from target §11. Unlike already-ledgered sibling changes, that omission is a target ledger defect.

2. **O-1 and O-2 are both honest.** LLP 0024 does define the unstyled semantic tree—kind, untrusted payload spans, children ([0024:1077](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1077))—so O-1 is delivered. It then incorrectly says a style-bearing IR is what crosses the worker boundary ([0024:1085](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1085)), so O-2 accurately identifies a live contradiction. The target’s “one unstyled object crosses” trust boundary is the correct one.

3. **O-3 through O-9 are substantially accurate.** LLP 0024 contains defeated cancellation, the normal-completion race, background callback cancellation, lifecycle outcome, sequence domain, and display acknowledgement; it lacks completion targeting, target IDs, native unit publication, broker membership, and the correct parking mechanism exactly as the ledger says. O-7’s pending correction is not a target defect.

4. **The history identity creates an unledgered contradiction with LLP 0023.** LLP 0023 forbids retained identity from crossing to the supervisor, while §9 requires supervisor-owned cross-session persistence of that record. The target also duplicates/extends 0023’s identity semantics with creation-time and path-fallback rules. This needs a new stable obligation and coordinated ownership decision.

5. **Async fatality is a dangling dependency acknowledged by 0022 but absent from 0025’s ledger.** LLP 0024 delegates it to lifecycle policy; LLP 0022 says 0025 has no mode/event rule. That corpus state is invalid until an owner is chosen.

6. **O-13 has the right status but the wrong owner and identifier discipline.** Current LLP 0022 assigns `OBL-LEDGER-CHECK` to LLP 0000/process tooling, not to 0022 itself ([0022:908](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:908)). LLP 0022 also explicitly rejects ordinal IDs as unstable, while target §11 uses `O-1`, `O-2`, and so on ([0022:857](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:857)). The target must adopt the shared owner-authored semantic IDs and generated table, not merely add a checker around ordinal rows.

7. **O-10 through O-12 are otherwise accurate.** The current registry has only argument/resource-normalized branch vocabulary, lifecycle surfaces remain closed, and `runtime-surface.json` has no history option or keybinding manifest ([coverage-edge.schema.json:117](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:117), [coverage-edges.json:215892](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215892), [runtime-surface.json:1237](/Users/ccheever/projects/ibex/runtime-surface.json:1237)). Pending implementation is honestly marked.

8. **The §2 environment-inventory dependency is not ledgered.** The target owns the combined post-arming inventory while delegating evaluation rows to LLP 0024, but §11 has no stable obligation proving that 0024’s evaluation variables and retirement rules are complete.

9. **The legacy-history diagnostic citation is wrong.** §9 says LLP 0022’s no-host-path rule requires a symbolic startup diagnostic. LLP 0022 explicitly limits that rule to JavaScript-visible observables and exempts CLI startup diagnostics ([0022:452](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:452)). Keeping the diagnostic symbolic is a good stricter local choice; it is not an obligation imposed by 0022.

10. **There are sibling-only defects that the target need not repair locally.** LLP 0024’s module-cache identity still omits LLP 0023’s defining principal ([0024:980](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:980), [0023:311](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:311)); its lifecycle row simultaneously says the native call never returns and the native frame unwinds; and its OQ8 points to the target’s old OQ6 rather than current OQ7. These are sibling defects, not reasons to weaken 0025.

Overall, §11 is candid and useful, but not yet complete or mechanically stable.

## 5. Suggestions

- Replace §6’s prose table with an executable transition relation or small model checked with TLA+/PlusCal, Alloy, or an exhaustive Rust model. Include key input, prompt generations, queue insertion/removal, worker begin/end records, quiescence, and broker/lifecycle transitions.

- Make escalation attach to a **running-work epoch**, not instantaneous engine busy state. End the epoch only when the scheduler proves no ready work and the session has published a prompt-ready generation. Clear the latch only on input accepted against a newer prompt generation.

- Consider supervising every CLI execution mode. It would eliminate the separate in-process exit mechanism, give all modes one broker and worker-death model, and simplify status handling. The cost is startup latency and precise `pid`/`ppid` semantics, but the current split creates substantial duplicated lifecycle machinery.

- Make the broker’s wire protocol one versioned schema with separate authenticated control records and per-destination framed data. Give only the broker the relay write handles. If arbitrary inherited child stdout remains supported, explicitly accept that exact evaluation barriers cannot cover it—or route child output through the supervisor.

- Separate `ProjectHistoryIdentity` from the worker’s VFS retained-object identity. A history scope is durable supervisor state; a VFS handle is ephemeral engine-local authorization state. Reusing the same words for both is creating the current ownership contradiction.

- Use a recoverable append journal: version, length, payload, checksum, and monotonic record index, with exclusive append locking and valid-prefix recovery. Store the HMAC key and check value in one atomic no-clobber record.

- Add stable diagnostic codes for lifecycle no-effect listeners, forced-output loss, history degradation, and cancellation/quiescence transitions. PTY fixtures can then assert semantics without depending on prose.

- Write a companion Plan sequencing the supervisor, structured evaluator, broker, registry changes, PTY harness, and history migration. The Spec currently implies a large multi-subsystem cutover without an implementation order.

## 6. Open questions

1. What exact event proves that running work has “returned”: unit end, no ready queue, poll return, or prompt-ready acknowledgement?

2. Does intervening editor input intentionally reset escalation? If so, is the invariant limited to consecutive interrupts with no non-interrupt input?

3. Should completion have its own phase, with running work taking precedence over the edit buffer?

4. Will all CLI modes use the supervisor, or what exact independent coordinator implements parked exit in in-process modes?

5. What is the broker’s accounting unit—bytes, accepted writes, framed events, or a combination—and how do authorized descendants participate?

6. How is stdout/stderr destination identity determined portably, and should any cross-stream ordering be promised when the supervisor did not construct the shared destination?

7. What authenticates control records beyond “they arrived on this fd,” and how are control/watchdog descriptors made unreachable from numeric JavaScript APIs?

8. Are spawned descendants in scope for terminal ownership? If yes, what prevents them from opening the concrete terminal or passing terminal descriptors?

9. What are the observable listener-introspection results after a diagnosed no-effect registration?

10. Which process owns and derives project history identity, and what durable volume identifier works across reboot/remount on each advertised target?

11. What exact history inputs are persisted: commands, syntax errors, `.exit`, pending submissions later cancelled, and failed `.load` requests?

12. What is the complete mode × synchronous/async failure × exit-status matrix?

13. What are the production values for every bounded budget and queue, and where is the versioned wire/constants annex?

14. What do `pid`, `ppid`, process group, signal, and child-inheritance observables mean under the supervisor topology?

## 7. Readiness verdict

The proposal has a strong architectural center, but the interrupt liveness property is still false, and the broker, isolation, lifecycle, history, and cross-document contracts retain unresolved material correctness and feasibility gaps.

VERDICT: NOT READY
### Orchestrator verification notes

- **Concern 1 (blocking, the escape invariant is still false) — CONFIRMED**, and the
  Fable reviewer derived the same falsifying trajectories independently in the same
  round. This is the **third consecutive round** §6 has been falsified, and the third
  time by hand-analysis of a hand-written table. Both reviewers' three trajectories all
  check out:
  - *typed-ahead defeats the latch*: latch rule 3 cleared on "any editor input", and a
    keystroke during `evaluating` is editor input, so `C1, type, C2, type, …` never
    escalates and the notice is a lie again;
  - *queued submission → four presses*: the discard left the typed-ahead behind;
  - *turnover gap → unbounded*: target selection keyed on **instantaneous** engine-busy,
    so a press landing between two callbacks of a storm re-targets the idle prompt, and
    latch *replacement* discarded the running-work progress.
  **Root cause, finally identified:** the state was missing the one variable that
  distinguishes *"the engine is momentarily between callbacks"* from *"the operator has a
  genuinely usable prompt back"*. Both reviewers independently prescribed the same fix,
  and it is adopted: a **work epoch** that closes only on authenticated **quiescence plus
  a republished prompt** (not on a unit boundary), a **prompt generation** counter, and a
  latch armed against `(class, epoch-or-generation)`. Typed-ahead is defined as *not*
  editor input (there is no live prompt to accept it), so it cannot clear anything. The
  invariant is restated over **consecutive** interrupts, which is the honest scope — an
  operator who types between presses is interacting, not stuck.
- **Concern 2 (completion query takes three, not two) — CONFIRMED**, matching Fable's
  C4. A member-completion wedge arises from `foo.` + Tab, so the buffer is non-empty and
  the editing row spent the first press on the buffer, contradicting AC 7. Accepted, with
  the reviewer's better resolution: in the editing/continuation phase an **in-flight
  completion query is the target and the buffer is preserved** — the operator asked for
  that work by pressing Tab, so it is not the coincidental background callback the
  buffer-first trade was designed to protect. The reviewer's **buffer-generation
  invalidation** point is also taken: today's 5-second budget abandons only the receiver
  (`src/bin/ibex/repl/mod.rs:247`), so a stale query can start after the buffer changed.
- **Concern 3 (the byte-cutoff barrier is not a complete protocol) — CONFIRMED and
  accepted.** One scalar cutoff cannot serve two relays; a per-relay **vector** is now
  specified. The deeper finding is the one I had missed: **authorized subprocesses that
  inherit fd 1/2 write bytes a worker-local counter never observes**
  (`src/engine/hermes_runtime_process.cc:1442`, `:1777`), so the barrier could not cover
  descendant output. Resolved by construction: in **session modes a child does not inherit
  the session's terminal descriptors** — its output is relayed as program output — and the
  consequence (no terminal-inheriting child at the prompt in v1) is recorded as a
  divergence with an OQ. The reviewer's point that the same-open-file-description predicate
  has no portable detection rule is also accepted, with its own suggested fix: the
  supervisor **constructs** the topology it promises rather than detecting it.
- **Concern 4 (the control lane is not structurally protected) — CONFIRMED and accepted.**
  This was a genuine hole: the control descriptor was protected only by obscurity, and
  native policy today permits root/runtime principals to operate on unknown numeric
  descriptors. §1/§7 now put control, relay, and watchdog handles in a **native protected
  descriptor class** unreachable from every numeric JS descriptor API; control records are
  authenticated by an **armed session nonce and channel epoch** rather than by "they arrived
  on this fd"; and the reviewer's observation that **kill-on-relay-EOF cannot work** — a
  worker stuck in evaluation holds the FFI lock and can never service EOF — forces a
  **kernel parent-death mechanism or an engine-independent watchdog that takes no runtime or
  broker lock**. The terminal-device threat boundary (concrete device path, `/dev/fd`,
  `/proc/*/fd`, `SCM_RIGHTS`) is now stated rather than assumed away by `setsid`.
- **Concern 5 (in-process parked exit underspecified) — CONFIRMED and accepted.** Sharp:
  if the host call parks on the engine thread holding the FFI lock, the outer evaluator can
  never resume to clean up and runtime destruction would deadlock on the held lock. So
  "parking" is only the *supervisor's* realization. §8 now specifies the in-process
  realization explicitly: the accepted call performs restoration and a bounded broker flush
  **inside the call**, then `_exit`s — never returning, never unwinding, never destructing
  the runtime, never joining, never taking a lock it does not already hold. The reviewer's
  **commit rule** is also adopted: if the lifecycle record cannot be committed to the
  supervisor within a bound, the worker takes the in-process path rather than parking
  forever, because a park whose record never arrived is not a cooperative exit — it is a hang.
- **Concern 6 (the listener no-effect branch misses the EventEmitter surface) — CONFIRMED
  and accepted**, with the reviewer's preferred shape: the listener is **not stored**, so
  `listeners`/`rawListeners`/`listenerCount`/`eventNames` report it absent, `removeListener`/
  `off` are no-ops, `prependListener`/`prependOnceListener` behave as `on`, and manual
  `emit('exit')` stays closed. The diagnostic gains a stable code and is once per session.
- **Concern 7 (history identity conflicts with LLP 0023's worker-locality rule) — CONFIRMED,
  and it reverses last round's decision.** LLP 0023 now states that "retained platform
  objects, the sealed cwd identity, and every VFS identity **live and are derived in the
  process that owns the engine** … a retained object identity is **never serialized to a
  supervisor and never rehydrated from one**." §9 had the **supervisor** persist exactly that
  record across sessions — a direct violation. The irony is instructive: last round I
  *stopped* restating 0023's mechanism and started **reusing** it, on good advice; reusing it
  is what created the conflict. Resolved as the reviewer proposes: a separately named,
  versioned **`ProjectHistoryIdentity`** — durable **supervisor** state, authenticated before
  spawn, explicitly **not** a VFS retained identity, with only an opaque history-scope token
  crossing to the worker. It *resembles* 0023's record in shape; sharing the *word* is what
  made two different things look like one.
- **Concern 8 (history durability) — CONFIRMED and accepted**, including a real data-loss
  bug of my own making: "a corrupt file degrades to an empty history" combined with an
  unframed append means **one killed append could erase recall of every earlier valid
  record**. §9 now specifies a recoverable journal (version, length, payload, checksum,
  monotonic index), **valid-prefix recovery** with tail truncation rather than whole-file
  discard, no-clobber key+check publication as one record with the loser re-reading, and a
  **pinned storage root with no cwd fallback** — today's code really does fall back to the
  current directory (`src/bin/ibex/repl/mod.rs:584`:
  `dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))`), which would drop a
  0600 history file into whatever directory the operator happened to be in.
- **Concerns 9, 10, 11, 12 — CONFIRMED and accepted.** §10 gains the history-store and
  worker-bootstrap rows; §8 gains the **mode × failure-class fatality matrix** that both
  siblings delegate to it (LLP 0022's ledger has named this undischarged for four rounds);
  and **Ctrl+Z** is a direct consequence of my own §5 raw-mode commitment that I had missed —
  with `ISIG` off, typed `Ctrl+Z` is a byte, not a kernel `SIGTSTP`, so §7's signal forwarding
  does not implement interactive suspension at all. The keybinding manifest now carries it and
  §7 specifies the suspend transaction.
- **Concern 12's bounds annex — NOW PARTLY ACCEPTED**, reversing two rounds of my declining
  it. The reviewer's framing finally lands: "deterministic test clocks make a chosen bound
  testable; they do not *choose* the observable bound." That is right, and my previous answer
  conflated the two. The bounds now split: those that are **user-visible and independent of the
  engine** — renderer depth/breadth/string length, the truncation marker, history entry and byte
  limits — are pinned **now**, in a versioned constants annex; only the budgets whose right
  values genuinely depend on OQ 1's prototype remain open. Pinning a renderer's truncation
  marker never required knowing whether Hermes can be interrupted.
- **Cross-document finding 6 (ordinal ledger ids) — CONFIRMED**, and independently raised by
  the coordinator. LLP 0022 rejects ordinal ids as unstable; §11 used `O-1`…`O-13`. Converted
  to owner-authored stable `OBL-*` ids, and — more importantly — §11 now says **in those words**
  that it is documentation of an intent, **not a control**, until `ref-check` can mechanically
  join the rows. A hand-maintained table that claims to be the mechanism preventing
  hand-maintenance errors is worse than no table: this ledger went stale within one round of
  being written, in both directions, which is the fourth such event across four documents today.
- **Cross-document finding 9 (the legacy-history diagnostic citation) — CONFIRMED**, and this
  one I had already caught myself while verifying Fable's parallel finding: I justified symbolic
  naming by attributing to LLP 0022 §4 a rule that 0022 **explicitly disclaims** ("the rule binds
  what JavaScript can observe. It does not bind the CLI's own startup diagnostics"). The choice
  is still right; the *reason* was borrowed from a sibling that refuses to lend it. §9 now owns
  the argument on its own terms — the notice recurs at every startup and lands in logs and shared
  transcripts.

## Round 5 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f55f4-d727-7773-9c72-a2566ba94000`
**Integrity check:** rollout final-message md5 **`1714fde47d8e`** == captured file md5,
byte-for-byte. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `7b89315f8ad7`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the
concurrent Fable round-5 review of the same revision, or to any prior LLP 0025 artifact — the
stash was verified to hold while it ran.
**Method:** `brief-round5.md` verbatim.

### Verbatim review

## 1. Overall assessment

The proposal’s architectural direction is good: terminal ownership belongs in a supervisor outside the engine, lifecycle requests should be cooperative, control descriptors must be structurally unreachable, and history must be supervisor-owned without reusing VFS identity.

It is not ready as a normative Spec. The critical §6 guarantee is still false: there are reachable four-interrupt trajectories with no editor input or epoch closure, and ordinary target/epoch churn can postpone termination indefinitely. The cooperative-exit fallback is also infeasible under the specified supervisor topology. Broker ordering, history recovery, constants, exit-status precedence, and §11’s ledger remain materially incomplete or contradictory.

## 2. Strengths

- **The protected-descriptor class is necessary and correctly scoped (§1).** Current native policy lets root and runtime principals fabricate authority over any unknown numeric fd, after which reads, writes, or closes touch the real descriptor ([hermes_runtime_fs.cc:158–233](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:158)). The requirement that control, relay, and watchdog handles be unreachable for every principal is the right structural response ([LLP 0025 §1:148–152](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:148)).

- **The supervisor/worker architecture addresses real engine constraints (§7).** The engine trait has no cancellation operation ([engine/mod.rs:22–99](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); evaluation holds the serialized FFI lock across the native call ([engine/hermes.rs:485–560](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:485)). An engine-independent watchdog, authenticated control records, no controlling terminal in the worker, and supervisor-owned restoration are sound choices ([LLP 0025 §7:490–527](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:490)).

- **The broker identifies the right failure classes (§3).** Per-relay cutoffs are better than one scalar, child descriptor inheritance really does invalidate barriers, and forced loss must be observable. Current spawn explicitly supports inherited stdout/stderr ([hermes_runtime_process.cc:1450–1461](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1450), [1777–1811](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1777)), while console output currently drops under bounded-queue pressure ([host/abi.rs:324–417](/Users/ccheever/projects/ibex/src/host/abi.rs:324)).

- **Parking is the right basis for uncatchable cooperative exit (§8).** A native call that never returns cannot run JavaScript `finally`. The document correctly recognizes that in-process parking alone deadlocks cleanup because the FFI lock remains held. This directly improves on today’s `__exactExit` → bounded console flush → `std::exit` path ([hermes_runtime.cc:588–603](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588), [1704–1727](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)).

- **The history redesign is substantially better (§9).** Submission-time journaling, valid-prefix recovery, no-clobber key publication, refusal of malformed keys, and removal of the cwd fallback all address real defects. Today history is one global file, falls back to `.`, and is saved wholesale only when the readline thread exits ([repl/mod.rs:582–599](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), [674–699](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:674)).

- **`ProjectHistoryIdentity` is correctly separated from VFS identity.** LLP 0023 requires VFS identities and retained objects to remain in the engine-owning process ([LLP 0023 §7.1:1074–1082](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1074)); the supervisor-owned identity and opaque worker token in §9 respect that rule ([LLP 0025 §9:643–648](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:643)).

## 3. Concerns

1. **Blocking — §6’s three-interrupt bound and notice invariant are false.**

   **Evidence:** Consider `editing` with nonempty `foo.`, completion query Q executing, background callback B ready, and epoch E. Interrupt 1 targets Q, preserves the buffer, and arms `(running,E)`. Q ends, but B remains ready, so E remains open. Interrupt 2 now follows the “editing, otherwise” row: it targets the buffer and clears the latch. Interrupt 3 is a fresh first interrupt against B; interrupt 4 terminates. There was no editor input and no epoch closure. This follows the specified priority and latch rules exactly ([LLP 0025 §6:398–445](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:398)) and refutes AC 7 ([lines 773–780](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:773)).

   Ordinary interval churn also refutes the unconditional bound: an idle latch can be replaced by a running latch when a timer fires, then the epoch can close while the next interval deadline is merely pending, returning to a new idle generation. Current sibling semantics explicitly distinguish scheduled timers from ready work ([LLP 0024 §1:188–195](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:188)).

   Typed-ahead remains ambiguous when work settles before queued input dispatches, and ready-but-unbegun work counts as in flight even though target IDs are assigned only “at begin.” The declared four-tuple omits buffer state, prompt liveness, completion state, typed-ahead, pending submissions, work membership, and cancellation state. No transition-data or model-check artifact exists in the reviewed tree despite the claim that prose is generated.

   Current completion mechanics validate the risk: the editor blocks on `recv_timeout`, while the query evaluates through `Function(...)` on the engine thread ([repl/mod.rs:247–349](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247)); one native poll drains whole callback and timer batches ([hermes_runtime.cc:3541–3721](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)).

   **Resolution criterion:** Choose one coherent property:

   - preserve a supervisor-owned consecutive-interrupt credit across target/class/epoch changes, making the next interrupt fatal; or
   - weaken the endpoint to “the session ends or a healthy prompt is returned,” removing the unconditional termination bound.

   Then check in the complete state data, generator, generated-table digest, adversarial-scheduler model, implementation-refinement tests, and the exact counterexamples above. Exact displayed notices must be temporal properties. “Cancelling” should become “cancellation requested” unless acceptance is known.

2. **Blocking — cancellation vocabulary is internally and cross-document inconsistent.**

   **Evidence:** §6 calls `defeated` “never resolves,” then says normal completion makes the request “resolve defeated” ([LLP 0025 §6:464–477](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:464)). LLP 0024 instead defines unresolved work as `Pending` and `defeated` as a terminal result when work later completes or throws by another route ([LLP 0024 §6:676–709](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:676)). §11 repeats the incorrect phrase “defeated (unresolved)” ([LLP 0025 §11:730](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:730)).

   **Resolution criterion:** Adopt one shared algebra: `Pending` is nonterminal; terminal results are `accepted`, `unavailable`, `failed`, and `defeated`. A nonreturning target remains `Pending` until supervisor/runtime destruction resolves it `failed`; a target that completes normally after delivery resolves `defeated`.

3. **Blocking — the supervised lifecycle commit fallback cannot perform the promised cleanup.**

   **Evidence:** §7 gives the worker no controlling terminal and assigns restoration, broker ownership, and final exit to the supervisor ([LLP 0025 §7:495–514](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:495)). Yet §8 says a worker unable to commit its lifecycle record “takes the in-process path,” whose defining operations are restore, flush, and `_exit` inside the call ([LLP 0025 §8:544–552](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:544)). That worker cannot restore or flush supervisor-owned resources, and `_exit(n)` cannot substitute for an authenticated record carrying cutoffs without making a native hard exit indistinguishable from cooperation.

   There is also an ordering contradiction: §5 requires restore → flush → release ([lines 352–354](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:352)), while orderly shutdown says drain → release → restore → flush ([lines 531–533](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:531)).

   **Resolution criterion:** Require an acknowledged, bounded, preallocated lifecycle commit path that needs no engine or broker lock. If commit fails, the worker exits with a reserved fatal disposition and the supervisor treats it as worker failure, restores the terminal, accounts for available relay bytes, and chooses the pinned fatal status. Pin one restoration-first ordering with no potentially blocking operation before restoration.

4. **Material — the broker’s cutoff and ordering contract is incomplete.**

   **Evidence:** §3 says counters at worker write sites suffice because every fd-1/2 write traverses such a route, but child writes do not traverse worker write sites; they arrive through separate child pipes. Bytes written before a barrier may remain unread and absent from the vector ([LLP 0025 §3:271–282](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:271)). Counter increment, partial write, and barrier snapshot also need one atomic ordering rule.

   The same-destination total-order promise relies on a supervisor-constructed topology ([lines 265–270](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:265)), but §3 also binds in-process one-shot and file modes, for which §1 specifies no supervisor ([lines 192–193](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:192)). Current output already has two differently ordered paths: direct native writes ([process_setup.cc:241–303](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:241)) and the asynchronous console queue ([host/abi.rs:324–417](/Users/ccheever/projects/ibex/src/host/abi.rs:324)).

   The cross-process sequence domain also lacks an allocator owner, range/epoch protocol, wrap rule, and a definition of how the supervisor sequences worker death after the worker can no longer allocate.

   **Resolution criterion:** Specify topology per mode; serialize counter reservation, actual writes, and barrier snapshots; include every child relay in the cutoff protocol or weaken child ordering; and assign sequence ownership and crash epochs explicitly, preferably to the supervisor.

5. **Material — the failure matrix and exit-status table are not complete or mutually ordered.**

   **Evidence:** §6 promises exit 130 for the escape path ([LLP 0025 §6:441–445](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:441)), while §3 says forced-termination loss with no usable destination must be carried by status 141 ([§3:296–301](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:296), [§8:588–601](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:588)). No precedence decides an interrupt termination whose flush loses bytes. Cancellation `failed` is merely “nonzero,” despite the claim that this is a complete mode × class matrix ([§8:573–583](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:573)).

   **Resolution criterion:** Define primary-versus-cleanup failure precedence and pin every matrix cell to one status, including cancellation `failed`, broker loss during interrupt exit, and lifecycle-record commit failure.

6. **Material — §12 claims a versioned constants annex that does not exist.**

   **Evidence:** §12 says renderer, history, and broker constants and the truncation marker “are pinned here” ([LLP 0025 §12:744–750](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:744)), but supplies neither values nor an annex identifier. LLP 0024 still lists the same values as open ([LLP 0024 OQ 8:1611–1615](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1611)), and LLP 0022 calls them open in both documents ([LLP 0022 §11:977](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:977)).

   **Resolution criterion:** Add a named, versioned, digest-bound artifact containing every numeric and string constant, or retract the claim and leave readiness blocked until values are chosen.

7. **Material — history recovery and identity bootstrap need additional atomicity rules.**

   **Evidence:** Valid-prefix recovery can truncate the file, but §9 explicitly assigns locking only to append and compaction, not startup read/repair ([LLP 0025 §9:622–632](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:622)). A reader could otherwise mistake another session’s in-progress append for a torn tail and truncate it.

   Similarly, creating the final key file exclusively and then writing it permits a crash to leave a permanently malformed key, which the never-rotate rule will preserve ([lines 673–677](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:673)). Finally, the supervisor’s history identity and the worker’s independently derived VFS root need one authenticated same-object startup transaction; otherwise root replacement between those derivations can associate old history with a new worker root.

   **Resolution criterion:** Require exclusive locking and post-lock identity revalidation for recovery; fully write and fsync a temporary key record before no-replace publication and parent-directory durability; and specify a protected bootstrap-root transaction proving supervisor and worker refer to the same root without serializing a VFS identity.

8. **Material — §11 is wrong in five rows, and the “already generated” claim is false.**

   **Evidence:** `OBL-CANCEL-COMPLETION`, `OBL-SEQUENCE-DOMAIN`, `OBL-DISPLAY-ACK`, and `OBL-EXIT-PARK` are already delivered by current sibling text; `OBL-CANCEL-OUTCOMES` states the wrong semantics. The complete audit is in §4 below. Separately, §6 says the corpus already generates its fd-0 table and keybinding manifest ([LLP 0025 §6:365–372](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:365)), while §11 marks those registry/CLI obligations outstanding and the current manifest contains only an empty `ibex repl` command row ([runtime-surface.json:1237–1239](/Users/ccheever/projects/ibex/runtime-surface.json:1237)).

   **Resolution criterion:** Remove the status column until the mechanical join exists, or pin every verification to an exact sibling digest. Correct all five rows and describe generated artifacts in future tense until their checked-in source exists.

9. **Material — PTY feasibility for interrupting a completion query is not demonstrated.**

   **Evidence:** Rustyline invokes completion synchronously and blocks inside the completer waiting for the engine response ([repl/mod.rs:247–258](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247), [393–415](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:393)). The engine thread services that request through `eval_immediate` ([lines 710–715](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:710)). Moving Hermes to another process does not by itself let the blocked editor consume a Ctrl+C byte while preserving and redrawing `foo.`.

   **Resolution criterion:** Prototype a sole supervisor-side byte owner and nonblocking editor/completion integration—or select another editor—and demonstrate the wedged-query trajectory under a real PTY before claiming feasibility.

10. **Minor/Non-blocking — “Input and output are UTF-8” is overbroad.**

   **Evidence:** §5 makes that unconditional statement ([LLP 0025 §5:329](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:329)), while §3 permits byte-exact arbitrary program output and invalid-UTF-8 tree payloads ([§3:252–258](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:252), [320–322](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:320)). Native stdout accepts raw bytes today ([process_setup.cc:251–268](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process_setup.cc:251)).

   **Resolution criterion:** Scope UTF-8 to editor input and session-authored rendering; retain byte-oriented program output.

## 4. Cross-document findings

### §11 row-by-row audit

| Row | Current judgment |
| --- | --- |
| `OBL-DISPLAY-TREE` | Accurate and delivered by LLP 0024’s unstyled, serializable tree ([0024:1239–1258](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1239)). |
| `OBL-CANCEL-OUTCOMES` | Wrong: unresolved is `Pending`, not `defeated` ([0024:676–709](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:676)). |
| `OBL-CANCEL-BACKGROUND` | Accurate and delivered ([0024:711–716](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:711)). |
| `OBL-CANCEL-COMPLETION` | Stale: current 0024 explicitly includes completion queries and target IDs ([0024:667–716](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:667)). |
| `OBL-UNIT-PUBLICATION` | Accurately outstanding; native begin/end publication, particularly microtask boundaries, is absent. |
| `OBL-LIFECYCLE-OUTCOME` | Accurately “partly”: the outcome exists, but 0024 still incorrectly says the frame unwinds ([0024:562–570](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:562)). |
| `OBL-SEQUENCE-DOMAIN` | Stale: current 0024 explicitly includes broker events in the shared domain ([0024:1292–1299](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1292)). Allocator ownership remains a separate gap. |
| `OBL-DISPLAY-ACK` | Stale: 0024 consumes the acknowledgement and 0025 defines barrier completion, so the stated obligation is jointly delivered ([0024:1104–1108](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1104)). |
| `OBL-INTERRUPT-CLASS` | Accurately outstanding: 0022 still says “same running target” ([0022:885–890](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:885)). |
| `OBL-EXIT-PARK` | Stale: current 0022 already says the call parks and does not unwind ([0022:902–905](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:902)). |
| `OBL-BRANCH-VOCAB` | Accurately outstanding in LLP 0021. |
| `OBL-REGISTRY-ROWS` | Accurately outstanding; lifecycle remains closed under `process:signal`, and the new rows are absent ([coverage-edges.json:215893–215920](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215893)). |
| `OBL-CLI-SURFACE` | Accurately outstanding; there is no `--history` or keybinding manifest ([runtime-surface.json:1237–1239](/Users/ccheever/projects/ibex/runtime-surface.json:1237)). |
| `OBL-LEDGER-CHECK` | Accurately outstanding ([0023:1245–1249](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1245)). |

### Defects in the current siblings

- **LLP 0022 is internally contradictory about submission credentials.** It first calls the object “decision evidence,” then correctly says that is a category error and requires a linear byte-bound credential ([0022:673–695](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:673)). LLP 0024 retains the stale, smaller “decision evidence” form ([0024:173–186](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173)).

- **LLP 0022’s root-import consequence contradicts its design.** The design retires the no-incoming-edge inference and refuses until a versioned row exists ([0022:300–318](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:300)); its consequences still say that inference is used ([1124–1128](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1124)).

- **LLP 0023 and LLP 0024 disagree on module identity.** LLP 0023 says `repl:<n>`, `ibex:eval`, and `.load` are script source identities and never module-cache keys ([0023:455–462](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:455)); LLP 0024 still requires module identity/cache coverage for those synthetic sources ([0024:1132–1153](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1132), [1482–1487](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1482)).

- **LLP 0024 contradicts itself about literal dynamic-import TLA.** Its design correctly says every dynamic import, including a literal one, checks at call time ([0024:355–368](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:355)); its fixture table and AC still demand preflight for literal dynamic imports ([518–525](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:518), [1387–1393](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1387)).

- **LLP 0023 incorrectly attributes a broad symbolic-startup-diagnostic rule to LLP 0025** ([0023:267–271](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:267)). LLP 0025 says symbolic legacy-history reporting is its own local choice, while acknowledging the general startup-diagnostic exemption ([0025:689–692](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:689)).

- **Transcript UTF-8 remains partly dangling.** LLP 0022 says no sibling owns strict decoding ([0022:432–436](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:432)), but LLP 0024 now does ([0024:173–175](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173)). What remains missing is the transcript resynchronization boundary.

## 5. Suggestions

- Replace target-class latching with a supervisor-owned **escape credit** or explicitly weaken the property to “termination or healthy prompt.” The current document tries to guarantee both unconditional bounded termination and harmless stale latches after recovery; those goals conflict.

- Use a small executable formal model—TLA+/PlusCal, Alloy, or a pure Rust transition kernel—with adversarial interleavings. Generate the prose table, implementation dispatch, PTY trace fixtures, and counterexample corpus from it, but also test that every runtime event producer refines the model.

- Make control and lifecycle commits use a preallocated, lock-free, acknowledged channel or shared slot. A worker should park only after the supervisor has durably accepted the authenticated record and cutoff vector.

- Treat child output as its own broker protocol, not merely “another pipe.” Either route child spawn/output ownership through the supervisor or explicitly weaken ordering to bytes observed by the worker before the barrier.

- Add a companion Plan sequencing a minimal conformant v1: supervisor and raw-byte input ownership; protected descriptors; broker/control channel; cooperative exit; interrupt model; then history and richer display. The current Spec spans too many ABI, engine, CLI, and PTY changes to function as an implementation plan by itself.

- Add failure-injection PTY tests for control-channel saturation, supervisor death, worker death while holding the FFI lock, partial child writes, torn history/key publication, resize/redraw during escalation, and all destinations stalled during forced termination.

## 6. Open questions

1. Is the desired interrupt property “the process terminates” or “the operator regains a healthy prompt”? What should happen when work ends between presses?
2. What event, exactly, resets escalation: prompt publication, explicit editor input after publication, submission, or something else?
3. When is a target ID assigned to ready work, and how are simultaneous executing, suspended, and ready units prioritized?
4. Which Hermes interrupt mechanism will be used, and what consistency check proves the runtime reusable after an accepted break?
5. What is the authenticated supervisor-mode behavior when lifecycle commit fails?
6. Who owns the cross-process sequence allocator, and how are child relays, crash epochs, worker replacement, and synthesized death events ordered?
7. How are the supervisor’s history identity and the worker’s independently derived VFS root bound to the same startup object without violating LLP 0023 locality?
8. What exact constants, budgets, status precedence, durable-volume algorithms, and no-replace primitives form the portable v1 contract?
9. Can rustyline support the required raw-byte and asynchronous-completion behavior, or should the editor be replaced?
10. Is the full supervisor/broker/history/display scope really v1, or should transcript mode and a smaller structured lifecycle seam land first?

## 7. Readiness verdict

The proposal has a sound architectural core, but the critical interrupt invariant is falsified, cooperative-exit fallback is infeasible as written, and several normative/cross-document contracts remain materially incomplete.

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

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f560e-63be-79f3-bf26-b299b67cf6d1`
**Integrity check:** rollout final-message md5 **`b9e41706aeab`** == captured file md5, byte-for-byte,
verified independently by the orchestrator. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `cfe6e1a65761`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@ab8658a68b57`,
`0024@88ebc6349bab`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the
concurrent Fable round-6 review of the same revision, or to any prior LLP 0025 artifact — the stash was
verified to hold while it ran.
**Method:** `brief-round6.md` verbatim.

### Verbatim review

## 1. Overall assessment

Reviewed at these content digests: target `0025@cfe6e1a65761`, `0022@88decefdc683`, `0023@ab8658a68b57`, and `0024@88ebc6349bab`.

This is a strong proposal with the right central idea: the terminal/session layer must own the resources needed to survive an uncooperative engine. The supervisor boundary, protected descriptors, restoration-first shutdown, unstyled display tree, and project-scoped history are all good design decisions.

The rebuilt §6 is materially better. Within its stated transition rules, the three-interrupt bound is now true: escape credit is a monotone progress measure that no class or epoch transition can undo. I do not regard it as a band-aid. Separating safety from the latch’s two-press ergonomics is the right architecture.

However:

- “Every notice is true” is false.
- The declared state is insufficient to define the transition relation.
- The shipping editor cannot deliver the required completion-query interrupt.
- Suspended-TLA target selection is ambiguous.
- The child-relay cutoff protocol and lifecycle commit are not yet coherent.
- “Hostile worker” promises more isolation than the specified mechanism supplies.
- §11’s attestations are neither revision-pinned nor accurate against the current siblings.

For §6 specifically, let `C` be escape credit. Every handled interrupt advances `C`; only live-prompt editor input resets it, and such input breaks the “consecutive interrupts” sequence. Thus `C=3` is terminal regardless of latch state:

| Attack | Derived trajectory | Result |
| --- | --- | --- |
| Gappy interval, callback → gap → callback | `I1: Running(E1), C1`; quiescence; `I2: Idle, C2`; new epoch; `I3: Running(E2), C3` | 130 on press 3 |
| Gappy interval, gap → callback → gap | `Idle,C1 → Running(E1),C2 → Idle,C3` | orderly exit on press 3 |
| Typed-ahead during stuck work | Typed-ahead resets nothing; if work remains, the matching second press exits; if work ends and the accumulated buffer becomes the next target, that press reaches `C2` and the third exits | at most 3 |
| Submission queued behind stuck work | First press discards the queued submission and targets the earlier unit; matching second exits, or a class transition consumes `C2` and the third exits | at most 3 |
| Suspended top-level `await` | If it is the only unit, two presses; if a background callback also runs, exact target selection is undefined, but credit still reaches terminal on the third | bound holds; target semantics defective |
| `foo.` completion query | If query remains in flight, two; if it ends and editing then targets the preserved buffer despite background work, the second clears the buffer and the third exits | at most 3 |
| Latch outlives epoch | The next idle interrupt mismatches the old running key and does not surprise-exit; it raises `C2`; the third exits | at most 3 |
| Only a future timer | If it stays future, two idle presses exit orderly; if it becomes due between presses, class flips and the third exits | at most 3 |

No fourth machine-handled interrupt is reachable under the reset rule in [0025:421](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:421) and the unconditional terminal rule in [0025:468](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:468). That does not yet establish the end-to-end product claim: the state space is incomplete, and the current synchronous completer can prevent a physical `Ctrl+C` from becoming a machine event at all.

## 2. Strengths

- §1 correctly separates input mode from presentation topology and treats fd ownership as a native fact rather than a JavaScript convention ([0025:108](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:108)). The protected-descriptor requirement is justified by the implementation: root/runtime principals may use unknown numeric descriptors ([hermes_runtime_fs.cc:158](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:158)), including closing a real descriptor ([hermes_runtime_fs.cc:2773](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2773)).

- §3’s unstyled display-tree boundary aligns well with current LLP 0024: payloads cannot select styling or terminal control ([0024:1543](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1543)). This is a strong way to contain a compromised producer.

- §5 states the editor feasibility limit honestly and correctly: moving Hermes into a worker does not make a synchronous rustyline completer non-blocking ([0025:350](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:350)). Restoration-first ordering is also exactly right ([0025:370](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:370)).

- §6’s escape-credit/latch split fixes the architectural cause of the previous failures ([0025:402](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:402)). Scheduled-but-not-yet-due timers are correctly excluded from interactive in-flight work, consistent with LLP 0024’s ready-work-only boundary ([0024:226](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:226)).

- The supervisor architecture is well motivated by the code. The `Engine` trait has no cancellation operation ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); the FFI mutex is held across `ex_hermes_eval` ([engine/hermes.rs:544](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:544), [engine/hermes.rs:887](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:887)); and `__exactExit` reaches `std::exit` directly ([hermes_runtime.cc:588](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588), [hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)). A structural boundary is warranted.

- §8’s parking decision is substantially better than an impossible unwind. Preallocation, acknowledgement, and the explicit rejection of “the worker restores the terminal” are sound design directions ([0025:605](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:605)).

- §9 correctly replaces save-on-exit global history with append-at-submission, project scoping, no-clobber key publication, and valid-prefix recovery under a sidecar lock ([0025:691](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:691), [0025:702](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:702), [0025:768](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:768)). Current code does use one global history file with cwd fallback and save-on-exit ([repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), [repl/mod.rs:674](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:674), [repl/mod.rs:699](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:699)).

- §10 properly treats lifecycle and stdio as an explicit reopening of LLP 0021’s closed surfaces. The current registry still marks `__exactExit`, `process.exit`, and `process.exitCode` closed ([coverage-edges.json:174033](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:174033), [coverage-edges.json:215893](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215893)) and currently admits `__exactStdinRead` through `stdio:read` ([coverage-edges.json:184040](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:184040)).

- The PTY acceptance criteria are unusually concrete and attack the right schedules ([0025:893](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:893)). The document correctly notes that today’s signal tests use null stdin and pipes, not a PTY ([signal_handling.rs:59](/Users/ccheever/projects/ibex/tests/signal_handling.rs:59)).

## 3. Concerns

1. **Blocking — §6 is not yet a complete normative state machine.**

   **Evidence.** The declared state is only `(editor phase, work epoch, escape credit, latch)` ([0025:409](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:409)), but transition choice also depends on completion-query presence and id, buffer generation and provenance, pending submission, typed-ahead bytes, executing/suspended/ready unit sets, pending cancellation requests, determined shutdown status, and notice state. The same declared tuple can therefore select different targets. Typed-ahead provenance is particularly load-bearing: an implementation must not later reset credit when buffered bytes are finally handed to a live editor.

   The latch type `(class, epoch)` is also incomplete for idle and shutdown, which have no defined epoch. Operator input is named as a class but deliberately does not arm a latch. There is no initial state or complete non-interrupt transition relation. §6 says the data, generator, and checker are named in §12 ([0025:388](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:388)), but §12 names only `session-constants.json`.

   This matters because one native poll drains an entire callback queue and several due timers ([hermes_runtime.cc:946](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:946), [hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)); the missing unit and quiescence transitions are not implementation trivia.

   **Resolution criterion.** Check in a named, digest-bound transition source containing the full state, initial state, ordered event alphabet, every non-interrupt transition, target selection, outputs/notices, and status transition. Generate the prose table and dispatch from it, model-check the three-press invariant and notice properties, and make the PTY fixtures consume the same generated cases.

2. **Blocking — “Every notice is true” is demonstrably false.**

   **Evidence.** The idle notice promises that the next interrupt exits ([0025:454](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:454)). If a future timer becomes due before that next press, the next interrupt targets running work, does not match the idle latch, and does not exit. Conversely, the running-work notice promises that the next press ends the session ([0025:455](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:455)); if the work ends and the next press targets a preserved edit buffer, it only clears the buffer.

   The changed-situation notice cannot repair the original unconditional promise ([0025:499](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:499)). If emitted on the second interrupt, the first promise has already failed. If emitted proactively on a work transition, another class change can make its own “next press” promise false while credit remains only one.

   There is also a direct due-only lie: due work is “in flight,” but has no target id and raises no cancellation request ([0025:430](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:430)); the table nevertheless prints `cancellation requested`.

   **Resolution criterion.** Either make notices conditional—“press again if this target remains; regardless, at most two more interrupts”—or make printing a promise atomically set an irrevocable `next_interrupt_exits` state. Add the temporal property `promise-next-exit ⇒ the next interrupt terminates`, including arbitrary intervening non-input events.

3. **Blocking — the completion-query row is not implementable by the shipping editor.**

   **Evidence.** The document diagnoses this correctly ([0025:350](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:350)). `dispatch_completion_query` blocks on `recv_timeout` inside the completer ([repl/mod.rs:247](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247)); `Completer::complete` calls the engine query synchronously ([repl/mod.rs:393](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:393)); and the engine thread synchronously services it with `eval_immediate` ([repl/mod.rs:710](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:710)). While that callback is blocked, rustyline cannot consume a `Ctrl+C` byte. The timeout releases the editor; it does not cancel the engine.

   The query is also not safely read-only: it evaluates the base with `Function(...)` and walks properties/prototypes ([repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)). LLP 0024 correctly requires trap-free completion or no candidates ([0024:1570](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1570)).

   **Resolution criterion.** Land a PTY prototype with an asynchronous editor or replacement integration that consumes `Ctrl+C` while the query remains wedged, invalidates the result by buffer generation, and redraws the exact preserved buffer. This is a release gate, not an implementation choice that can remain open.

4. **Blocking — suspended-TLA target selection and the cancellation algebra are not fully coherent.**

   **Evidence.** During a suspended input, LLP 0024 permits independently executing background work ([0024:1169](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1169), [0024:1225](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1225)). §6 nevertheless refers to “the in-flight work” of the epoch as though it were singular ([0025:439](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:439)). It does not say whether an interrupt targets the suspended input, the callback currently executing, or a ready successor. Meanwhile LLP 0024 says stale requests are discarded unless their id is currently executing ([0024:823](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:823)), which does not explain how a suspended id is cancellable while another unit executes.

   The `Pending`/`defeated` distinction itself now matches the sibling’s current text. The edge semantics do not. Target §6 says a `Pending` request resolves `failed` only on runtime destruction or worker termination ([0025:533](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:533)), but both documents also define immediate failure when a returned target cannot pass the consistency check ([0024:835](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:835)). Both also use evaluation-specific `cancelled` outcome language for generic work, then separately say callback/query acceptance merely means return ([0024:868](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:868)).

   **Resolution criterion.** Define an ordered target-selection function over the complete live-unit set, including a suspended evaluation plus an executing callback. State how the target id remains actionable. Make `accepted` target-generic, restrict the structured `cancelled` outcome to evaluations, state that consistency failure resolves `failed` immediately, and reserve teardown failure for requests still `Pending`.

5. **Blocking — §3’s relay cutoff and sequence protocol is not implementable as written.**

   **Evidence.** §3 first says descriptors 1 and 2 are duplicates of one open file description, implying one kernel-ordered relay, then describes fd-1 and fd-2 as separate relays with separate counters ([0025:264](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:264), [0025:275](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:275)).

   More seriously, an arbitrary child writing a raw pipe cannot participate in the specified atomic “reserve counter → write → snapshot” operation. A worker-created barrier cannot snapshot bytes already accepted into a child pipe but not yet observed by the supervisor. The current child API supports `pipe`, `inherit`, `ignore`, fd redirects, and detached sessions ([hermes_runtime_process.cc:1450](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1450)); inherited fd 1/2 are left untouched today ([hermes_runtime_process.cc:1777](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1777)). The spec must also distinguish inherited terminal output from a child’s `pipe` output, which belongs to JavaScript rather than the terminal broker.

   There is now a direct sibling contradiction: target §3 says the worker draws sequence ranges from the supervisor ([0025:285](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:285)); current LLP 0024 says the session layer assigns sequence numbers at receipt because a hostile worker must not mint them ([0024:1603](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1603)).

   In-process modes are also underexplained: if raw `write(1)` reaches the real descriptor, the broker is not the sole writer; if fd 1 is redirected through a pipe, there is in fact a relay.

   **Resolution criterion.** Pin one topology per destination and one sequence rule. Define which child stdio modes are rewritten, how detached children are contained, and what causal guarantee is actually promised. Either supply a concrete freeze/drain or framed-write protocol that can snapshot child output, or narrow ordering to bytes the supervisor had received before the barrier. Resolve the at-receipt versus worker-range contradiction with LLP 0024.

6. **Blocking — “hostile worker” exceeds the stated isolation mechanism.**

   **Evidence.** §7 promises invariants against a stuck, crashed, or hostile worker ([0025:556](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:556)). A same-UID hostile native process can open the concrete terminal device, inspect `/proc/<supervisor>/fd`, signal or ptrace the supervisor where permitted, spawn a detached descendant, or pass descriptors. A spawn-time fd allowlist and no controlling terminal do not prevent those operations. Saying the routes are “closed natively” ([0025:566](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:566)) constrains intact Ibex adapters, not arbitrary hostile native code.

   Likewise, the worker knows the session nonce and can authenticate forged lifecycle, cutoff, or outcome records if “hostile” means the native process itself. Authentication proves channel membership, not truthfulness.

   **Resolution criterion.** Either narrow the threat model to hostile JavaScript behind intact native mediation plus stuck/crashed native code, or specify enforceable per-platform sandboxing/credential separation, process-tree containment, descriptor-passing denial, and supervisor-side independent validation sufficient for a genuinely hostile native worker.

7. **Blocking — the acknowledged lifecycle commit has unresolved two-party and sizing states.**

   **Evidence.** If the supervisor accepts a lifecycle record but its acknowledgement is lost, the worker times out and exits with the reserved fatal disposition. The supervisor then has both an accepted request for `n` and a fatal worker status. The text says the requested code was lost ([0025:619](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:619)), but it was not.

   The preallocated record also carries a per-live-child cutoff vector, whose size is unbounded unless the spec pins a relay maximum or uses indirection. Neither the acknowledgement timeout nor the reserved worker disposition has an actual value in §12 or the status table. In-process `_exit` also leaves no consumer to receive the stated evaluation-seam lifecycle outcome.

   **Resolution criterion.** Define an idempotent request id and precedence rule: an accepted commit wins even if its ACK is lost. Replace the variable vector with a fixed-size supervisor-owned snapshot token or pin a maximum. Assign the timeout and fatal disposition, including their wire/OS representations. Clarify whether the in-process lifecycle outcome is observable at all or only a supervisor-mode record.

8. **Material — status precedence is good in principle but internally inconsistent.**

   **Evidence.** §8 correctly says fault 70 and interrupt 130 are never overridden by cleanup loss ([0025:677](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:677)). §3 more broadly says otherwise: when every destination is stalled, “the exit status then carries” forced loss as 141 ([0025:310](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:310)).

   The status table mentions only a second interrupt against running work ([0025:662](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:662)), omitting third-interrupt termination and completion/operator-input targets.

   There is also a shutdown conflict. Escape credit is not reset when shutdown begins. If shutdown begins at `C=2`, the next interrupt is the unconditional third and §6 assigns 130 because shutdown is not idle, while the shutdown row says the already-determined status is preserved ([0025:460](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:460)).

   **Resolution criterion.** State one cause-precedence function used by §3, §6, and §8. Once a primary shutdown cause is latched, later interrupts may shorten cleanup but must not change its status. Replace the status row with “any §6 interrupt termination,” and add pairwise fixtures for fault/interrupt/cooperative status crossed with cleanup loss.

9. **Material — the mode table omits real command topologies.**

   **Evidence.** `ibex run` is not only file execution: a missing path-like argument may be interpreted as a package script ([main.rs:438](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438), [main.rs:483](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:483)), and that script runs through a shell with inherited stdin/stdout/stderr ([main.rs:523](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:523)). `--watch` adds an Ibex parent that repeatedly launches a child with inherited stdio ([main.rs:862](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:862)). The target currently places all `ibex run` behavior in one file-execution row ([0025:117](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:117)).

   **Resolution criterion.** Expand the topology table to include package-script dispatch and watch parent/child execution, or explicitly exclude them as unarmed external-command routes. For each, state terminal owner, broker path, signal/process-group behavior, lifecycle semantics, and exit-status propagation.

10. **Material — ProjectHistoryScopeId is directionally correct, but the equality and journal protocols remain incomplete.**

   **Evidence.** Owning a distinct supervisor history identifier is the right correction and does not, by itself, violate LLP 0023’s worker-locality rule. Only an opaque token crosses, and the identifier is not used as VFS authority ([0025:725](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:725), [0023:1336](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1336)). It also does not answer LLP 0023’s verification-generation question: creation generation and verification generation are different problems ([0023:1895](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1895)).

   The undefined “root fingerprint,” however, could easily become a serialized derivative of the VFS identity despite the prose saying otherwise ([0025:746](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:746)). Append locking is not explicitly exclusive even though monotonic indices require serialization. Compaction does not pin temp-file fsync and directory fsync. Only lock acquisition is bounded; a slow append or compaction after acquisition can still block the supervisor’s input/control path. Maximum record size and index rollover are absent.

   **Resolution criterion.** Define the fingerprint as a nonce-bound equality proof rather than a stable serialized identity. Require exclusive append serialization, durable temp-and-rename compaction, bounded/off-thread history I/O, maximum record size, and rollover behavior. Pin the per-platform no-clobber publication primitive.

11. **Material — removing the status column was the right instinct, but §11 did not actually produce revision-pinned attestations.**

   **Evidence.** The prose requires “verified at `<revision>`” ([0025:827](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:827)); every row gives only a document name and date. The current digests are `0022@88decefdc683`, `0023@ab8658a68b57`, and `0024@88ebc6349bab`, none of which appears in the table. “Delivered” and “outstanding” have also been moved into the obligation text, effectively preserving the stale status column in prose.

   Against the current siblings:

   - `OBL-DISPLAY-TREE` and `OBL-CANCEL-TARGETS` are accurate ([0024:1543](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1543), [0024:868](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:868)).
   - `OBL-CANCEL-ALGEBRA` is accurate for `Pending` and `defeated`, but the claim that 0025 adopts it exactly is not, due to immediate consistency failure and generic callback/query semantics.
   - `OBL-UNIT-PUBLICATION` is stale: current 0024 now explicitly specifies native begin/end publication for evaluation, callbacks, timers, microtask drains, and completion queries ([0024:762](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:762)).
   - `OBL-LIFECYCLE-MECHANISM` is stale: current 0024 already says the call parks and state is discarded ([0024:704](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:704)).
   - `OBL-SEQUENCE-ALLOCATOR` is stale and contradictory: current 0024 assigns ownership to the session layer and numbers at receipt ([0024:1608](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1608)).
   - `OBL-INTERRUPT-BOUND` misdescribes current 0022, which already speaks in class/epoch terms rather than target identity ([0022:892](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:892)).
   - The registry and CLI-surface rows remain accurately outstanding; `runtime-surface.json` still contains only the clap surface and no `replSurface`, history option, or keybinding section ([runtime-surface.json:31](/Users/ccheever/projects/ibex/runtime-surface.json:31)).

   **Resolution criterion.** Use a separate structured attestation field containing owner, exact content digest, date, and evidence anchors. Make each row one atomic assertion. Remove “delivered/outstanding” from obligation prose, or generate it from the owner-side join. Until `OBL-LEDGER-CHECK` lands, any digest mismatch must visibly invalidate the attestation.

12. **Material — §12 supplies useful prose values but not the claimed constants annex.**

   **Evidence.** The values in the §12 table are concrete and useful ([0025:848](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:848)), but no `session-constants.json` exists in the repository. Current LLP 0022 still calls the bounds open ([0022:990](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990), and current LLP 0024 still asks for the shared annex ([0024:1971](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1971)).

   Missing values include the lifecycle ACK timeout, reserved fatal disposition, maximum relay count/cutoff size, maximum input/history-record size, and several framing/overflow limits. “10,000 characters” also needs a unit: Unicode scalar values, UTF-16 code units, grapheme clusters, or bytes.

   **Resolution criterion.** Add the actual versioned, contract-file/digest-bound annex; define units, encodings, overflow rules, and all engine-independent bounds; then update 0022 and 0024 to cite that exact version.

13. **Material — startup capture and nonce freshness are still assertions without a complete artifact/protocol.**

   **Evidence.** §2 claims ownership of a generated post-arming environment inventory but gives no artifact path or schema ([0025:199](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:199)). Current code creates and loads the runtime before starting the REPL ([main.rs:1333](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1333)), then reads the prompt environment inside the REPL ([repl/mod.rs:91](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:91)). The engine loop reads trace variables dynamically ([engine/hermes.rs:1026](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1026)), and native evaluation reads `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` during evaluation ([hermes_runtime.cc:3081](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3081)).

   The armed-snapshot schema checks only that `runNonce` is base64url ([armed-snapshot.schema.json:68](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:68)); snapshot loading validates digests and posture but not nonce freshness or uniqueness ([arming.rs:78](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:78)). That is insufficient for §7’s control-record authentication.

   **Resolution criterion.** Name and check in the environment inventory, bind it into contract files, and remove or pre-capture every post-arm read. Define the nonce generator, entropy, uniqueness/replay scope, verifier, channel-epoch binding, and failure behavior; then test fixed/reused nonce rejection.

14. **Minor/Non-blocking — the historical falsification count is inconsistent.**

   **Evidence.** §6 says four hand-written versions were falsified ([0025:388](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:388)); the consequences say three ([0025:931](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:931)).

   **Resolution criterion.** Use four consistently.

## 4. Cross-document findings

| Finding | Assessment |
| --- | --- |
| 0022 epoch closure | Direct contradiction. 0025 closes an epoch at quiescence alone ([0025:417](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:417)); 0022 still requires quiescence plus a republished prompt ([0022:896](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:896)). |
| 0022 two-press guarantee | Direct contradiction. 0022 says any two interrupts within one work epoch end the session ([0022:899](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:899)); 0025 requires matching class and epoch, with class flips needing three. The 0022 acceptance criterion repeats the broader claim ([0022:1131](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1131)). 0022 is defective here. |
| 0022 startup diagnostic ledger | Stale. It says 0023 mandates symbolic-only package diagnostics ([0022:993](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:993)); current 0023 explicitly requires the host path in that pre-JavaScript refusal ([0023:339](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:339)). |
| ProjectHistoryScopeId versus 0023 | No intrinsic contradiction. A separate, non-authorizing supervisor identifier with only an opaque token crossing the boundary respects 0023’s worker-locality rule. The undefined root fingerprint remains a dangling dependency, and 0025 correctly must not resolve 0023’s verification-generation OQ on its behalf. |
| 0023 defects | 0023 duplicates the native `fs.open` existence-oracle paragraph almost verbatim ([0023:1435](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1435), [0023:1444](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1444)). Its ledger still contains a `Landed?` status column despite explaining drift, and carries an explicitly stale module-identity stamp ([0023:1591](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1591), [0023:1613](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1613)). |
| 0024 lifecycle/publication | Target ledger is stale: current 0024 already contains parking and native work-unit publication. |
| 0024 sequence allocator | Direct contradiction. 0024 says session-layer allocation at receipt; 0025 says supervisor-provided worker ranges. This affects hostile-worker safety and transcript order and must be resolved, not treated as wording. |
| 0024 cancellation | Core `Pending`/`defeated` algebra aligns. Both documents remain ambiguous about accepted callback/query cancellation versus an evaluation’s structured `cancelled` outcome, and 0025 incorrectly restricts immediate `failed` resolution. |
| 0024 suspended input | Dangling dependency. 0024 permits background work while a TLA input is suspended; 0025 does not define which live unit an interrupt selects. |
| 0024 internal defects | Its header says the restricted-global predicate is keyed on `[[SessionCreatedVars]]`, but the normative predicate still keys on `[[VarDeclaredNames]]` ([0024:1064](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1064)); `[[SessionCreatedVars]]` is referenced but absent from the declared reference-model state ([0024:1204](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1204), [0024:1330](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1330)). Its rollback AC says both that `let x = 1; throw` removes `x` and that it preserves `x` ([0024:1787](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1787), [0024:1801](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1801)). It also claims 0023 lacks a root-owned `SourceId` arm even though current 0023 defines one ([0024:1444](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1444), [0023:604](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:604)). The sibling is independently defective. |
| 0024 module-cache AC | Internal contradiction: normative §7.9 says only `ibex:stdin` among synthetic inputs is a module ([0024:1425](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1425)); AC15 says the synthetic sources of §2 are keyed without a file object ([0024:1837](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1837)). |
| Shared constants | Both 0022 and current 0024 still describe the annex as unresolved, contradicting 0025’s claim that it exists. |

## 5. Suggestions

- Keep escape credit. Represent the ergonomic latch as a small sum such as `Idle | Running(epoch) | Shutdown`, with operator input explicitly ineligible, rather than an ill-typed `(class, epoch)` pair.

- Make notice honesty structural. A particularly simple design is: any notice that literally says “the next interrupt exits” sets an irrevocable `next_interrupt_exits` bit. If that behavior is too surprising after a class change, never print the unconditional promise.

- Model-check notices as outputs, not just terminal reachability. The useful properties are both `interrupts_without_input ≤ 3` and `promised_next_exit ⇒ next interrupt is terminal`.

- Replace lifecycle cutoff vectors in worker records with fixed-size supervisor snapshot tokens. This solves both preallocation and ACK retransmission.

- Define output ordering causally. “All bytes the child wrote before result creation” is not observable without freezing or cooperation; “all bytes received before the barrier control record” is observable but weaker. Pick one and build the protocol around it.

- Split the worker threat model into profiles: stuck/crashed engine, hostile JavaScript with intact mediation, and compromised native worker. Claim only the profiles the platform sandbox actually enforces.

- Put history I/O on a dedicated supervisor-owned worker or queue so key creation, append, recovery, and compaction cannot block input or interrupt handling.

- Add a companion Plan sequencing the minimal conformant v1: registry/schema work, editor prototype, engine unit publication and cancellation prototype, supervisor and relay protocol, lifecycle handshake, PTY harness, then history. The current Spec describes too many interdependent mechanisms to serve as its own executable plan.

## 6. Open questions

1. Should the UI make the next-interrupt promise irrevocable, or should all notices become explicitly conditional?

2. What is the exact state and priority function when a TLA evaluation is suspended while a callback or completion query executes?

3. Which editor architecture will actually meet the completion-interrupt PTY criterion on Unix and ConPTY?

4. Does “hostile worker” mean hostile JavaScript, compromised engine code, or an arbitrary same-UID native process?

5. What child-output ordering is truly required, and how do `pipe`, `inherit`, `ignore`, fd redirects, detached children, and future PTY handoff interact with it?

6. Does the sequence allocator assign at supervisor receipt, as current 0024 requires, or may the worker draw ranges? How are unused ranges, worker death, and replay represented?

7. What is the lifecycle commit’s idempotence rule when the record arrives but the ACK does not? What exact fatal disposition and timeout are reserved?

8. What nonce-bound equality proof lets supervisor and worker confirm the same project root without serializing or creating a stable VFS identity?

9. Are package scripts and watch mode armed execution modes governed by this Spec, or external process-launch surfaces with a separate contract?

10. Which constants are engine-independent and must enter annex v1 now, including units and overflow behavior?

11. What is the minimal conformant release slice if cancellation remains unavailable but supervisor termination supplies the escape invariant?

12. Is the accepted-cancellation result target-generic, or must evaluations, callbacks, and queries have distinct terminal result shapes?

## 7. Readiness verdict

The core ownership model and rebuilt escape credit are good ideas, and the three-interrupt arithmetic survives the requested adversarial schedules. The proposal is not ready as a normative Spec because notice truth, state-machine completeness, completion feasibility, target selection, relay ordering, worker threat scope, lifecycle commit semantics, sibling coherence, and ledger attestations still contain unresolved material or blocking defects.

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

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f5638-c889-77f3-82fb-03c7ca219d77`
**Integrity check:** rollout final-message md5 **`108acac3a2bf`** == captured file md5, byte-for-byte,
verified independently by the orchestrator. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `19de10797c67`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@a77e5a385f6a`,
`0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the concurrent
Fable round-7 review of the same revision, or to any prior LLP 0025 artifact — the stash was verified to hold.
**Method:** `brief-round7.md` verbatim.

### Verbatim review

1. **Overall assessment**

This is a strong architectural proposal and a substantial improvement over earlier rounds, but it is not yet a coherent normative Spec.

The central idea is good: make a session supervisor own terminal state, output ordering, history, lifecycle, and worker containment. The revised interrupt design also makes real progress:

- **Escape credit:** I found no counterexample under the intended disjoint event model. Without qualifying live-prompt editor input, the third consecutive interrupt always terminates. Typed-ahead bytes—including bytes later drained into a republished prompt—do not reset the credit.
- **Promise bit:** I found no reachable trace where a promise is printed and the next interrupt fails to begin termination. Timers becoming due, work completing, and target-class changes do not break the terminal suffix.
- **Cause precedence:** This still fails normatively because the cleanup-failure rule can change the supposedly fixed status.
- **Target selection:** `executing ≻ suspended ≻ due` is conceptually sound, including due work having no cancellation ID, but the inter-document protocol cannot represent it.
- **Digest attestations:** The arithmetic mechanism works: it makes drift objectively detectable. It has detected that all four 0024 attestations are stale. Therefore those rows are currently unverified, and the ledger does not presently hold.

The proposal is a good idea, but the plan remains incomplete around lifecycle commit, nonce generation, spawned-native-code boundaries, package-script/watch topology, input provenance, and the 0024 work/cancellation seam.

2. **Strengths**

- Section 3 now places sequence allocation at observable session-layer receipt and limits child ordering to relay acceptance, which is the strongest honest guarantee available. It correctly distinguishes a shared open file description from two independent destinations and keeps child `pipe` output in JavaScript rather than treating it as broker output ([0025:273](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:273), [0025:287](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:287)).

- Section 6 replaces fragile case analysis with monotone state: escape credit plus an irrevocable promise. The tight-turnover, gappy-turnover, query-flip, and typed-ahead-drain schedules all respect the three-interrupt bound under the intended event alphabet ([0025:446](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:446), [0025:489](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:489)).

- Due work is correctly distinguished from executing work: it has no target ID, receives no cancellation request, and should not produce “cancellation requested” ([0025:468](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:468)).

- Section 7’s three-profile threat model is much more honest than treating a session nonce as proof that a native worker is truthful. “Authentication proves channel membership, not truthfulness” is the right principle ([0025:633](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:633)).

- Section 8’s accepted-record-wins rule is the correct foundation for idempotent lifecycle commit. Losing an ACK must not make a supervisor discard a code it already possesses ([0025:708](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:708)).

- Section 9 correctly avoids exporting a stable serialized VFS identity. A nonce-bound, one-shot equality assertion is directionally compatible with worker-local VFS identity ([0025:826](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:826)).

- Section 12 is materially better for pinning units and previously implicit bounds, while honestly marking the constants annex as owed rather than pretending it exists ([0025:965](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:965), [0025:977](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:977)).

- The motivation is well grounded in the implementation. Today the engine API has no cancellation operation ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); the Hermes lock remains held across evaluation ([hermes.rs:485](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:485), [hermes.rs:887](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:887)); `__exactExit` reaches `std::exit` ([hermes_runtime.cc:588](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588)); and one poll drains a callback batch plus multiple due timers ([hermes_runtime.cc:946](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:946), [hermes_runtime.cc:3621](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3621)). Process isolation is consequently justified.

3. **Concerns**

1. **Blocking — The interrupt machine and its acceptance criteria disagree.**

   **Evidence:** The promise rule makes the next interrupt terminal regardless of target changes ([0025:489](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:489), [0025:507](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:507)), while AC7 says gappy storms and query-class flips take three presses ([0025:1016](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1016)). They take two whenever the first press printed a promise. Also, “editor input” is broad enough to require an explicit statement that the decoded interrupt event itself is not editor input ([0025:446](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:446)). Finally, a due-only notice says work “is running” even though due work has not begun ([0025:468](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:468)).

   **Resolution criterion:** Publish one closed transition table with disjoint `Interrupt` and `EditorInput` events; correct AC7’s expected press counts; and describe due work as pending/ready, not running.

2. **Blocking — A boolean promise does not preserve the promised disposition.**

   **Evidence:** An idle-origin promise implies orderly termination, while a running-origin promise implies interrupt termination. If work finishes or a timer becomes the selected target before the next interrupt, a bare bit does not encode which status was promised. The rules otherwise select status from the current target/cause ([0025:539](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:539)).

   **Resolution criterion:** Replace the bit with typed state such as `None | Orderly(status) | Interrupt(130)`, or normatively define an equivalent latched promised disposition. Test both idle→due and running→idle class flips.

3. **Blocking — Cause precedence conflicts with cleanup-failure status escalation.**

   **Evidence:** Sections 6 and 8 say the first termination cause fixes status and later interrupts merely shorten cleanup ([0025:539](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:539), [0025:774](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:774)). Yet cleanup output loss may upgrade successful orderly/cooperative termination to 141 ([0025:779](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:779)). Thus the triple-idle trajectory can latch orderly status on press two and become 141 when press three forces abandonment, contradicting “same status.”

   **Resolution criterion:** Either make cause and final disposition separate fields and narrow the “status is fixed” claim, or prohibit cleanup failures from changing status. Add the all-destinations-stalled triple-idle trace to the acceptance criteria.

4. **Blocking — The live-unit algebra and 0024 protocol cannot implement target selection.**

   **Evidence:** The state tuple describes due units as if they have target IDs, while the due-work rule says they do not ([0025:427](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:427), [0025:468](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:468)). Current 0024 publishes only begin/end and models only the currently executing target ([0024@6416ccb8c3c2:786](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:786), [0024@6416ccb8c3c2:847](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:847)). Its cancellation rules variously define accepted cancellation as “stopped because of the request,” normal return being defeated, and callbacks/queries merely returning ([0024@6416ccb8c3c2:859](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:859), [0024@6416ccb8c3c2:884](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:884), [0024@6416ccb8c3c2:892](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:892)). The actual poll implementation drains multiple callbacks and timers in one call, further obscuring the unit boundary ([hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)).

   **Resolution criterion:** Define due/begin/suspend/resume/end/cancel/settle publications, their ID rules, and a target-independent cancellation outcome. Reconcile those definitions in 0024 before treating the selector as implementable.

5. **Blocking — Lifecycle commit still has an ACK contradiction and an underdefined snapshot token.**

   **Evidence:** Section 8 correctly says an accepted lifecycle record wins even if its ACK is lost ([0025:708](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:708)). AC9 nevertheless says a commit that “cannot be acknowledged” takes the fatal lost-code disposition ([0025:1031](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1031)), which is indistinguishable to the worker from accepted-record/ACK-lost. The fixed-size snapshot token is not specified sufficiently to reconstruct per-relay cutoffs, survive worker loss, or establish idempotence. The disposition table also omits reserved worker disposition 69 while §12 assigns it ([0025:755](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:755), [0025:981](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:981)).

   **Resolution criterion:** Split `record accepted, ACK lost` from `no record accepted by deadline`; define token contents, durability, namespace, lifetime, collision behavior, and retry semantics; and include both worker 69 and supervisor fault 70 in the status model.

6. **Material — The undecodable-input matrix contains two policies in one cell.**

   **Evidence:** The REPL column combines interactive and transcript behavior, saying both “continue” and “transcript fatal” for undecodable input ([0025:743](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:743)). Current 0022 makes malformed transcript input fatal ([0022@88decefdc683:438](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:438)).

   **Resolution criterion:** Give interactive REPL and transcript replay separate columns or rows with one outcome per cell.

7. **Blocking — `runNonce` is syntactically validated but not fresh or unique.**

   **Evidence:** Section 7 depends on the armed session nonce and §11 admits freshness is unverified ([0025:663](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:663), [0025:952](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:952)). The schema checks only the encoded form ([armed-snapshot.schema.json:68](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:68)); `ExpectedArmingIdentity` has no nonce expectation, and snapshot loading performs no freshness/uniqueness check ([arming.rs:28](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:28), [arming.rs:78](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:78)).

   **Resolution criterion:** Generate at least 128 CSPRNG bits during runtime/session construction, before snapshot authentication; forbid caller- or artifact-selected production nonces; and test uniqueness, replay rejection, and malformed/zero nonce handling.

8. **Blocking — The content-digest ledger has correctly detected that its own attestations are stale.**

   **Evidence:** Recomputed digests are:

   - 0022: `88decefdc683` — both target rows match.
   - 0023: `a77e5a385f6a` — no target attestation exists.
   - 0024: `6416ccb8c3c2` — all four target rows still pin `88ebc6349bab` ([0025:943](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:943)).
   - 0025: `19de10797c67`.

   By the target’s own rule, every mismatched row is unverified ([0025:933](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:933)). The checker itself remains owed ([0025:938](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:938)).

   **Resolution criterion:** Reverify the four dependencies against 0024 at `6416ccb8c3c2` or later, add a digest-pinned 0023 root-identity obligation, define the digest algorithm/canonical bytes, and make the deterministic checker reject stale rows.

9. **Blocking — `ibex run` package scripts and watch mode are absent from the topology model.**

   **Evidence:** The target describes file execution and treats non-session modes as in-process ([0025:120](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:120), [0025:199](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:199)). But `ibex run dev` is a package-script command ([cli.rs:20](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:20)); package-script dispatch precedes watch dispatch ([main.rs:344](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:344)); package scripts spawn shell children inheriting descriptors 0/1/2 ([main.rs:523](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:523)); and watch mode is a controller that repeatedly spawns an `ibex` child with inherited terminal descriptors ([main.rs:824](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:824)). Package child statuses are also preserved separately ([main.rs:117](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:117)).

   **Resolution criterion:** Add a topology matrix for direct file execution, package-script execution, watch controller, and watch child, defining terminal ownership, broker placement, signals, lifecycle commit, and final-status precedence for each.

10. **Blocking — The hostile-JS boundary is not closed when native spawning is authorized.**

    **Evidence:** Section 7 excludes a compromised native worker but treats descendants as controlled by descriptor allowlisting and noninheritance ([0025:648](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:648), [0025:659](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:659)). The registry authorizes `process:spawn` as a capability ([capability-definitions.json:354](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:354)). Native children support pipe/inherit/ignore and detached modes ([hermes_runtime_process.cc:1442](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1442), [hermes_runtime_process.cc:1745](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1745)). A same-UID arbitrary native child can reopen the terminal, inspect process descriptors, or transfer descriptors; inheritance policy alone does not contain it. Unknown numeric descriptors also receive root/runtime principals rather than being categorically rejected ([hermes_runtime_fs.cc:158](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:158)).

    **Resolution criterion:** State that arbitrary native spawn exits the hostile-JS assurance profile, constrain spawn to mediated/sandboxed descendants, or provide an OS-level isolation design that prevents terminal reopening and descriptor discovery/transfer.

11. **Material — Input provenance is not implementable through the current rustyline control flow.**

    **Evidence:** The target requires nonblocking editor behavior and receipt-time provenance ([0025:365](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:365), [0025:446](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:446)). The existing completer performs synchronous runtime work ([repl/mod.rs:242](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:242), [repl/mod.rs:393](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:393)). After submission the REPL blocks on its control channel and no longer consumes terminal input ([repl/mod.rs:681](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:681)); typed-ahead bytes therefore remain in the kernel and can later appear to have arrived at a republished prompt. History currently falls back silently to the working directory ([repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582)).

    **Resolution criterion:** Specify a continuous raw-input pump owned by the supervisor that timestamps/classifies bytes at receipt independently of prompt/editor state, plus an asynchronous bounded-completion protocol and deterministic PTY tests for drain-into-prompt schedules.

12. **Material — The root equality proof is directionally correct but not yet a protocol.**

    **Evidence:** The target separates history scope from VFS identity and proposes nonce-bound equality ([0025:826](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:826)), consistent with 0023’s worker-local retained identities ([0023@a77e5a385f6a:1440](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1440)). But 0023 says the required generation-aware verification does not exist and leaves it open ([0023@a77e5a385f6a:706](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:706), [0023@a77e5a385f6a:2057](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2057)). The target does not fully define witness canonicalization, key derivation, domain separation, message ordering, generation binding, or the opaque history-scope token’s consumer and lifetime ([0025:839](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:839)).

    **Resolution criterion:** Define a versioned, one-session witness protocol bound to live handles or VFS generations, with canonical bytes, domain separation, nonce size, nonpersistence, and rename/replacement/inode-reuse tests. Explain why the worker receives the history-scope token or keep it supervisor-local.

13. **Material — Constants have units, but their overflow policies are not valid as a single rule.**

    **Evidence:** Section 12 says every bounded field truncates and emits a marker rather than producing an error ([0025:984](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:984)). That conflicts with lossless program-output/backpressure requirements ([0025:320](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:320)) and is inappropriate for unrelated bounds such as history-record size. OQ8 also still calls the history-lock bound open after §12 pins it ([0025:979](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:979), [0025:1082](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1082)).

    **Resolution criterion:** Assign an explicit overflow behavior to each constant—backpressure, reject, truncate-with-marker, or fatal—and remove the stale open question.

14. **Material — The implementation path lacks a verified Hermes and capability-surface closure plan.**

    **Evidence:** The engine has no cancellation method and serializes evaluation under the FFI lock ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes.rs:542](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542)). The `hermesc` invocation does not enable an async-break feature ([hermes.rs:1837](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1837)). Bundled headers expose an async trigger and compile flag, but their availability and semantics in this build have not been demonstrated ([hermes-interfaces.h:177](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177), [CompileJS.h:44](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/CompileJS.h:44), [AsyncDebuggerAPI.h:133](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:133)). The registry has no completed lifecycle-exit surface, and `runtime-surface.json` still exposes only the existing CLI surface ([coverage-edges.json:174033](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:174033), [runtime-surface.json:31](/Users/ccheever/projects/ibex/runtime-surface.json:31)).

    **Resolution criterion:** Add a staged implementation plan proving cancellation support in the actual Hermes build, define the non-cancellable fallback behavior, and land registry/runtime-surface changes as explicit preconditions rather than post-spec aspirations.

15. **Minor/Non-blocking — AC6 overstates child-output ordering.**

    **Evidence:** Section 3 carefully limits ordering to relay acceptance ([0025:287](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:287)), while AC6 merely says child output “lands in order” ([0025:1012](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1012)). Bytes written by a child before the barrier but not yet accepted by the relay may legitimately appear afterward.

    **Resolution criterion:** State the acceptance criterion in terms of relay-acceptance order and include a pre-barrier-write/post-barrier-acceptance test.

4. **Cross-document findings**

The sibling texts reviewed were exactly:

- `0022@88decefdc683`
- `0023@a77e5a385f6a`
- `0024@6416ccb8c3c2`

**0022 contradictions and defects**

- 0022 says an epoch closes only after quiescence plus prompt republication and any two interrupts in one epoch terminate ([0022@88decefdc683:896](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:896)). The target closes escalation differently and allows an editing/no-promise trajectory to require three. This is duplicate ownership with conflicting semantics.

- 0022 says every nonterminal interrupt prints a further promise ([0022@88decefdc683:907](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:907)); the target’s editor-input rows do not always do so.

- 0022’s transcript-fatal malformed-input rule conflicts with the mixed interactive/transcript cell in target §8 ([0022@88decefdc683:438](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:438)).

- 0022 itself is stale: its ledger still calls the relevant terminal bounds open ([0022@88decefdc683:990](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990)), and several dependency assertions remain line-pinned or semantically outdated. Target §11’s two 0022 digest rows match the bytes, but a matching digest does not make those assertions substantively correct.

**0023 compatibility and defects**

- The target’s one-shot equality-proof direction is compatible with 0023’s worker-local identity rule ([0023@a77e5a385f6a:1440](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1440)), but the target has no digest-pinned 0023 attestation and relies on verification machinery 0023 explicitly says is absent.

- 0023 itself gives contradictory interim sequence-ownership accounts: one passage assigns interim minting outside the session layer, while a later passage says the worker does not mint session sequence numbers ([0023@a77e5a385f6a:1462](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1462), [0023@a77e5a385f6a:1516](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1516)).

- Its claim that only `/project` is mounted and non-mount paths are refused conflicts with the later synthetic `/dev/null` behavior unless that exception is made explicit ([0023@a77e5a385f6a:161](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:161), [0023@a77e5a385f6a:1315](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1315)).

- Its observable-disposition tables duplicate module/Dirent cases with inconsistent outcomes ([0023@a77e5a385f6a:1304](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1304), [0023@a77e5a385f6a:1321](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1321)). Its own ledger also still uses `current`/line-reference attestations despite requiring content-pinned evidence ([0023@a77e5a385f6a:1714](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1714), [0023@a77e5a385f6a:1733](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1733)).

**0024 contradictions and defects**

- Receipt-time sequence ownership now agrees with target §3 ([0024@6416ccb8c3c2:1730](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1730)). However, its overflow marker must report the highest dropped session sequence ([0024@6416ccb8c3c2:1741](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1741)). An event dropped before receipt cannot have such a sequence. The revision note also still says workers draw ranges ([0024@6416ccb8c3c2:23](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:23)).

- Its begin/end-only unit publication and executing-only cancellation contradict target §6’s suspended and due units, as detailed in Concern 4.

- AC12 directly gives both outcomes for `let $_; boom()` ([0024@6416ccb8c3c2:1917](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1917), [0024@6416ccb8c3c2:1943](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1943)).

- AC15 describes plural synthetic sources as module-cache keyed, while §7.9 says only `ibex:stdin` has module identity and the other named sources are scripts ([0024@6416ccb8c3c2:1546](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1546), [0024@6416ccb8c3c2:1990](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1990)).

- The async-failure envelope crosses the boundary with a value “handle,” contradicting its own rule that handles stay in the worker and only inspection trees cross ([0024@6416ccb8c3c2:777](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:777), [0024@6416ccb8c3c2:1704](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1704)).

- It claims `session-constants.json` exists, while the file is absent and target §12 correctly marks it owed ([0024@6416ccb8c3c2:2129](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2129)).

**Governing-corpus issue**

- LLP 0021 calls the migration target an unadvertised candidate in its status and body, but later says only an advertised target can be complete ([0021:8](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:8), [0021:458](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:458), [0021:930](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:930)). The current registry’s advertised-target set is empty ([policy-rules.json:787](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:787)). That promotion condition must be reconciled. I found no separate architectural contradiction with LLP 0010 or LLP 0006.

5. **Suggestions**

- Encode §6 as a tiny executable state model and exhaustively enumerate traces. State should include at least `credit`, `promiseDisposition`, `terminationCause`, `cleanupDisposition`, `promptGeneration`, and the executing/suspended/due unit sets.

- Give session events two coordinates where needed: a trusted session receipt sequence and an untrusted producer-local ordinal/loss count. Do not require pre-receipt loss to name a nonexistent session sequence.

- Make the fixed snapshot token a supervisor-owned receipt seal over a fixed 64-relay table. The worker should submit only the token; the supervisor should resolve it to durable per-relay cutoffs.

- Add a topology diagram or matrix covering direct execution, package scripts, and watch mode before selecting a worker-process layout.

- Build PTY acceptance tests around a controllable byte source, relay acceptance barriers, and a fake worker clock. Include running→idle, idle→due, TLA-suspended→callback-executing, query-class flip, typed-ahead drain, lost ACK, and all-relays-stalled cleanup.

- Treat `process:spawn` as an explicit threat-profile transition. A policy grant that permits arbitrary native code should visibly downgrade terminal-containment assurances.

- Generate the constants annex from one schema and have `ref-check` verify sibling digests, units, duplicate ownership, and annex existence.

6. **Open questions**

1. Should a promise survive genuine later editor input indefinitely, making the next interrupt hours later terminal? If yes, that surprising behavior needs an explicit acceptance test.

2. Is cleanup failure part of the termination cause, a separate final disposition, or merely diagnostic metadata?

3. How can a pre-receipt drop marker identify loss after session sequence allocation moves exclusively to receipt?

4. What exact publication marks a TLA input suspended, a callback due, that callback executing, and the TLA input resumed?

5. Which process owns the PTY and broker for package scripts and each level of watch mode?

6. Does granting `process:spawn` intentionally exit the hostile-JS assurance profile?

7. Why does the worker need the stable history-scope token, and how is it prevented from becoming a cross-session root pseudonym?

8. What durable supervisor state does the fixed-size lifecycle snapshot token reference, and when may it be reclaimed?

9. Which Hermes interruption mechanism is supported by the actual linked build, including production builds without debugger support?

10. Is v1 allowed to ship with worker termination as the only reliable cancellation mechanism? If so, which semantics are deliberately deferred?

7. **Readiness verdict**

The core architecture is worth pursuing, and the escape-credit bound plus promise terminal suffix survived the requested adversarial schedules. The Spec is nevertheless not ready: its interrupt acceptance criteria and status rules conflict, four digest attestations are stale, lifecycle commit remains ambiguous, the unit protocol cannot express its selector, nonce freshness is absent, major CLI topologies are missing, and the hostile-JS boundary is not closed under native spawn.

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

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f578a-744e-7fc1-ae4c-f28a74ea4412`
**Integrity check:** rollout final-message md5 **`07fa4b3d6c0e`** == captured file md5, byte-for-byte,
verified independently by the orchestrator. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `647072dedfb0`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@a77e5a385f6a`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the concurrent
Fable round-8 review of the same revision, or to any prior LLP 0025 artifact — the stash was verified to hold (the
orchestrator re-stashed after the round-7 reconciliation had restored the artifacts).
**Method:** `brief-round8.md` verbatim.

### Verbatim review

## 1. Overall assessment

The proposal’s architectural direction is good: terminal ownership belongs outside hostile or stuck JavaScript, lifecycle exits should be cooperative, and interruption must have an engine-independent escape. The supervisor realization is well motivated by the current FFI lock, synchronous completion integration, and native hard-exit behavior.

I reviewed the complete target at SHA-256 prefix `647072dedfb0`, all three complete current siblings, the governing LLPs, and the requested code. No files were modified.

Round 8 is not text-consistent yet. The central typed-promise idea is sound, and the two named class-flip trajectories work, but the declared dispatch precedence produces a different reachable class-flip that violates the promise’s latched status. Cause precedence creates a second counterexample. Several other state/table and topology seams remain material.

## 2. Strengths

- The supervisor architecture addresses real implementation constraints. Runtime FFI is serialized across the entire engine call in [hermes.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:487), while today’s lifecycle path still reaches `std::exit` in [hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588). Structural isolation is therefore a better foundation than assuming in-place interruption.

- The typed promise fixes the original boolean-status ambiguity for promises armed on press 1. Idle promise → timer due retains the notice-time orderly status; running promise → work finishes retains 130. Live-prompt editor input clears both credit and promise, so I found no stale-promise trajectory that ends a session after the operator actually resumed typing ([§6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:466)).

- Demoting suspended and due work from request-raising is correct. LLP 0024 discards requests not naming the currently executing unit, so claiming cancellation against suspended work would be false. AC 7 now correctly says suspended work is escapable in two but receives no request ([§6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:486), [AC 7](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1085)).

- The recomputed AC 7 counts are correct:

  - Gappy storm: press 1 sets a promise; press 2 consumes it despite the class/epoch flip.
  - Completion query finishing between presses: press 1 sets `Interrupt(130)`; press 2 consumes it after the query ends.

  No remaining 0025 acceptance criterion explicitly says either schedule needs three presses.

- Interrupt termination with flush loss is consistently 130 in §§6 and 8 and AC 9. The idempotent lifecycle commit also agrees across §8 and AC 9: record held/ACK lost yields cooperative `n`; no record yields supervisor fault 70 ([§8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:769), [AC 9](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1102)).

- The package-script branch is grounded in code: it invokes a shell, inherits fds 0/1/2, and has a Unix `128 + signal` helper ([main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:139), [main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:523)). The watch defects are separate, below.

- Treating `process:spawn` as a threat-profile transition is the right call. It is an authorable terminal capability ([capability-definitions.json](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:354)), and the native route accepts a caller-selected executable and reaches `execvp` ([hermes_runtime_process.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1392), [hermes_runtime_process.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1921)). Descriptor inheritance policy cannot contain arbitrary same-UID native code.

- §12 now correctly distinguishes truncation, rejection, backpressure, compaction, refusal, and budget expiry. Renderer lengths are Unicode scalar counts; serialized/history/broker limits are bytes; the flush budget is pinned.

- Every current §11 digest or git-blob pin recomputes successfully:

| Item | Recomputed pin | Result |
| --- | --- | --- |
| Target 0025 | `647072dedfb0` | matches requested revision |
| Sibling 0022 | `88decefdc683` | matches both rows |
| Sibling 0023 | `a77e5a385f6a` | matches |
| Sibling 0024 | `6416ccb8c3c2` | matches all four rows |
| `coverage-edges.json` | `blob:d495d9d6318f` | matches |
| `runtime-surface.json` | `blob:2ad526bc2fa9` | matches |
| `armed-snapshot.schema.json` | `blob:7d7784994b9e` | matches |
| `repl/mod.rs` | `blob:c4bcf99bbcb7` | matches |

No current pin is stale. In the two 0022 rows, “stale” accurately describes 0022’s semantics, not the digest. Those rows honestly pin and identify sibling defects.

## 3. Concerns

1. **Blocking — `credit ≻ promise` falsifies the typed promise’s latched status.**

   Evidence: §6 says credit wins before promise, while a credit-triggered termination derives status from the terminating press’s current target ([dispatch](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:585)).

   Reachable counterexample:

   1. Start with a non-empty edit buffer.
   2. Press 1 uses the editing row: buffer discarded, no promise, credit = 1.
   3. Press 2 at idle sets `Orderly(exitCode)`, credit = 2.
   4. A timer becomes due.
   5. Press 3 reaches credit 3. Credit wins before promise and derives interrupt cause 130 from the now-running target, rather than consuming the promised orderly status.

   The dual trajectory sets `Interrupt(130)` on press 2, lets the work finish, then lets credit derive orderly status on press 3. This contradicts the promise and notice rules ([promise](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:529), [notice invariant](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:614)).

   Cause precedence creates another counterexample: idle press 1 promises `Orderly(0)`; an allowed root timer commits `process.exit(7)` while cleanup stalls; press 2 expedites cause 7, not promised 0 ([§8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:796)). AC 7 checks terminality but not promised-status equality and omits cause-latch events from its alphabet ([AC 7](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1085)).

   **Resolution criterion:** when credit and promise coincide, the promise must supply the base status. Separately define whether an independently latched cause retires the promise and narrows the notice invariant. Model-check `terminal ∧ base_status = promised_status`, including count-2 promise/count-3 credit, lifecycle, fault, cause-latch, and cleanup events.

2. **Material — the latch/table machinery is now dead or ill-typed, and shutdown escalation is ambiguous.**

   The latch is typed `Idle | Running(epoch) | Shutdown`, with no epoch for Idle or Shutdown, yet the table and latch rule require “same class and epoch” ([state](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:445), [table](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:513), [latch rules](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:597)).

   More fundamentally, every row that could terminate through the second column also sets a promise, and promise precedence reaches termination first. The editing row sets no promise but explicitly never latch-terminates; evaluating/no-work sets no latch; shutdown is preempted by cause precedence. Thus the claim that the second columns are a count-2 “optimization” is false.

   The shutdown row is likewise unreachable because shutdown already has a cause. It distinguishes first shutdown interrupt from second, but cause precedence merely says “expedite.” In the named triple-idle trajectory, press 2 initiates shutdown and press 3 is the first interrupt received while in shutdown. The table says abandon only drain; the disposition prose assumes press 3 can abandon flush and produce 141 ([shutdown row](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:521), [triple-idle prose](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:570)).

   **Resolution criterion:** either delete the obsolete target latch/second columns or identify a reachable transition where they matter. Define shutdown escalation entirely inside the cause-precedence submachine, including whether cause initiation counts as stage one and exactly what the next interrupt abandons.

3. **Material — cancellation state and target selection are not a total, implementable relation.**

   The declared state gives `{executing, suspended, due}` units target IDs, but the demotion rule correctly says due work has not begun and has no ID ([state](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:440), [demotion](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:486)). LLP 0024 assigns IDs at begin ([0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:847)).

   The text promises an ordered selection function but does not specify the order among simultaneous executing, suspended, and due work. AC 7 says executing wins when a suspended input and background callback coexist, but the normative selector only says “in-flight work.”

   Asynchronous completion also introduces a missing state: after Tab dispatch but before native unit begin, the request is pending and has no executing target ID. Nevertheless, the table says an in-flight query is always executing. The shipping completer demonstrates why this interval matters: it synchronously blocks awaiting the engine today ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247), [repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:393)).

   Finally, §6 says accepted work generically produces a `cancelled` outcome, while its ledger correctly says that outcome exists only for evaluations; callback/query acceptance merely means the unit returned ([§6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:658), [ledger](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1013)). Immediate consistency-check failure is also placed beside an apparently contradictory “Pending resolves failed only at destruction” rule.

   **Resolution criterion:** use discriminated states such as `Executing{id}`, `Suspended{id}`, `Due{no_target_id}`, and `CompletionQueued{request_id}`; specify `executing ≻ suspended ≻ due` selection while raising requests only for `Executing`; and define accepted observables per target kind plus immediate versus teardown-only `failed`.

4. **Material — base status, final disposition, and 141’s loss domain remain inconsistent.**

   The cause/disposition distinction is directionally right, and interrupt + flush loss consistently remains 130. However:

   - Promise rules say the final exit uses the promise’s own status, while an `Orderly(x)` promise may become final disposition 141 after unreportable cleanup loss ([promise](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:533), [modifier](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:576)).
   - §3 accounts both program bytes and session-authored framed events, §8 says forced-termination loss generally, but §6 limits the modifier to lost “program output” ([§3](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:338), [§8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:820)).
   - The “complete” fatality matrix leaves malformed transcript input merely “fatal,” with no exit status ([§8 matrix](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:803)).

   **Resolution criterion:** call the promise field a base/primary status, expressly allow the sole 141 final modifier, choose whether all accounted broker loss or only program data triggers it, and assign malformed transcript input an exact status.

5. **Material — §1’s launcher topology does not match either itself or the current watch implementation.**

   `ibex run` is a conditional union: existing paths and recognized file extensions run in-engine, while other bare names dispatch package scripts ([main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:344), [main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:483)). The matrix should include the direct-file branch of `ibex run`; the sentence that `ibex run <script>` dispatches a package script is too broad.

   The package-script branch does inherit fds and its child-only Unix status mapping is `128 + signal`. But foreground-terminal `SIGINT` reaches parent and child because no separate group or parent signal handler is installed, so the parent is not guaranteed to survive and execute that propagation helper.

   The watch claims are more clearly false. The controller:

   - spawns an inherited-fd child without a new process group;
   - waits only for child exit or filesystem events;
   - has no `Ctrl+C` branch;
   - calls its SIGTERM/kill shutdown helper only after a restart trigger.

   See [run_watch](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:824), [await_restart_trigger](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:904), and [stop_watch_child](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:193). The only `tokio::signal::ctrl_c()` call in this file is the unrelated debugger loop ([main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1088)). Current Unix behavior is foreground-group delivery to both processes and signal termination, not “controller orderly status after terminating/reaping the child.”

   Internally, the watch-child row says it runs with its own file-execution broker, while the following paragraph says these routes carry none of §§3–9’s guarantees ([§1](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:195)). A watch child is an Ibex engine runtime and does carry its own mode’s guarantees.

   **Resolution criterion:** split direct-file, package-launcher, watch-controller, and watch-child routes explicitly. Either document current foreground-group semantics or require a controller signal branch/process-group design and test its status, reaping, and no-respawn behavior. Mark `128 + signal` POSIX-specific.

6. **Material — the history root-equality protocol is underspecified and contradicts its own crossing/threat claims.**

   §9 says only an opaque history token crosses, then immediately requires a challenge nonce and comparison witness to cross ([§9](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:905)). More importantly, the proof does not define:

   - the key and domain/version;
   - canonical root-object bytes;
   - which party sends which witness;
   - replay and lifetime rules;
   - how the fallback path form detects replacement;
   - whether it depends on LLP 0023’s still-open verification-generation primitive.

   AC 11 tests project separation and token opacity but not startup failure after a root swap.

   “The worker cannot derive, forge, or enumerate” is also unqualified, while §7 correctly says a compromised native worker knows the nonce and can forge authenticated records ([§7](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:695)). That claim is valid only for hostile JavaScript behind intact native mediation.

   **Resolution criterion:** specify the complete domain-separated proof transcript and add a replace-between-authentications fixture; qualify token claims by threat profile. An alternative is a one-way transfer of an already-authenticated sealed directory handle, subject to an explicit LLP 0023 bootstrap carve-out.

7. **Material — §12’s completeness claim is false despite the improved per-constant rules.**

   LLP 0024 identifies maximum input size as unpinned and security/performance-relevant because it bounds identifier lowering cost ([0024 OQ 8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2129)). Yet §12 says only four engine-dependent budgets remain and every user-visible engine-independent constant is pinned ([§12](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1059)). A renderer/wire-format version also remains referenced by 0022 without a concrete current value.

   **Resolution criterion:** pin maximum input size and renderer/wire version, or explicitly ledger them as open and remove the claim that only four constants remain.

8. **Material — lifecycle and display acknowledgement are not total across LLP 0024’s outcome model.**

   A root-owned background timer may request exit, but §8 says the lifecycle outcome is reported “for the in-flight evaluation”; at an idle prompt there may be none ([§8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:783)). LLP 0024 currently models lifecycle as an evaluation-outcome variant.

   Separately, malformed/unknown/oversize display trees render a safe fallback diagnostic, while display acknowledgement is defined only by barrier completion ([§3](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:269), [display ACK](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:325)). Without a render disposition, successful delivery of the fallback diagnostic could incorrectly update `$_` to the original value that was never displayed.

   **Resolution criterion:** make lifecycle commit a unit-generic control event, attaching an evaluation outcome only when one exists; make display ACK carry successful-value-render disposition and withhold it for fallback diagnostics.

9. **Minor/Non-blocking — the ledger’s declared schema contradicts its rows.**

   §11 says rows state obligations, not statuses, explicitly calling “delivered/outstanding” prose a hidden status column. The table immediately uses “delivered,” “open,” “stale,” “not started,” and “does not exist yet” ([ledger rules](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:998), [ledger rows](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1010)). It also says IDs are owner-authored, but `OBL-HISTORY-LOCALITY` is absent from current 0023.

   The pins themselves are valid, and the ledger honestly says it is not yet an automated control.

   **Resolution criterion:** formally add a digest-bound “verified finding/status” column, or remove status prose; distinguish 0025-authored dependency requests from IDs accepted and authored by the sibling owner.

## 4. Cross-document findings

- **LLP 0022 — `88decefdc683`: defective and stale relative to 0025.**

  Its epoch closes only after quiescence plus prompt republication, and it says two interrupts within one epoch always terminate, while its own next sentence admits the editing-row three-press case ([0022 §10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:892)). It derives a second idle press’s status from the current idle target, contradicting 0025’s notice-time `Interrupt(130)` class-flip behavior. It also omits the live-editor-input reset condition and says Ctrl+C “cancels” an evaluation even when suspended/due work gets no request.

  AC 15 repeats the stale two-within-epoch and unqualified notice claims ([0022 AC 15](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1131)). Its malformed-transcript status is missing, its bounds ledger still says open, and completion’s budget/usable-session promise remains dependent on the unresolved asynchronous editor and cancellation mechanism.

  The two 0025 ledger rows are therefore honest but incomplete: they correctly identify real defects at the current digest, while additional reset, status-latching, and cancellation wording defects remain.

- **LLP 0023 — `a77e5a385f6a`: the history separation is good, but the equality-witness dependency is dangling.**

  0025 correctly stopped reusing a worker-local VFS identity. Current 0023 keeps retained/VFS identities in the engine-owning process and does not expressly admit the proposed equality witness ([0023 locality](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1440)). A properly specified non-replayable witness could be ordinary control data rather than an identity, but that classification is not yet established. The current pin and ledger wording are honest.

  0025 should also bind the supervisor’s project-root input to 0023’s exact discovery algorithm, including `--project` and the marker-set version ([0023 §1.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:190)).

  0023 itself is defective: it both attributes and denies the existence of an `interim` class, says there are four tiers while listing 0–4, and misnumbers denial/absence/ELOOP after its normative table ([0023 §7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1462), [error table](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1526)).

- **LLP 0024 — `6416ccb8c3c2`: normative alignment is mixed.**

  Normative at-receipt sequence allocation, executing-ID discard, unstyled trees, park/no-unwind lifecycle, and consumer-owned fatality agree with 0025.

  Material seams remain:

  - accepted cancellation is described as evaluation-specific `cancelled` and later target-generic return;
  - display failure versus ACK is unresolved;
  - lifecycle is evaluation-shaped despite background exit;
  - sequence epoch is required on every event but omitted from 0025’s broker schema;
  - it falsely says `session-constants.json` exists and identifies the missing maximum-input constant.

  0024 is itself defective: its revision summary still says worker-drawn sequence ranges while normative §9 rejects them ([metadata](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:23), [§9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1730)); AC 12 gives both outcomes for `let $_; boom()` ([AC 12](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1917)); and its session-created-var and synthetic-source cache assertions disagree with their normative definitions.

- **Governing LLP 0021 has an unqualified `ibex run` seam.**

  LLP 0021 says normal project-code execution and plain `ibex run` enforce the armed profile ([0021 target model](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:216), [WP9 acceptance](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:914)). The package-script branch instead launches an unarmed shell. Either 0021 means only the direct-file branch and must say so, or package-script dispatch contradicts its default-enforcement promise.

## 5. Suggestions

- Replace the prose/table hybrid with one typed transition source immediately. Generate both dispatch and acceptance trajectories from it; do not retain a second handwritten interpretation.

- Represent termination as three explicit values: primary cause, base status, and final disposition modifier. Let the promise carry the first two, not an ambiguously named final “status.”

- Split §1 into engine-execution routes and launcher routes. For every spelling, state whether it creates a runtime, arms capsec, owns a process group, brokers stdio, and maps signals.

- Remove the opaque history token unless the worker genuinely needs it. A session-bound submission channel may be sufficient; the supervisor already knows which history store it owns.

- Surface the `process:spawn` threat transition in policy review and runtime diagnostics, not only prose. A terminal session granting it should visibly state that same-UID native containment is no longer claimed.

- Add PTY fixtures for the currently missing transitions: count-2 promise/count-3 credit with both class flips; promise followed by independent lifecycle cause; first interrupt during shutdown; pending-but-not-executing completion; and actual watch-controller `SIGINT`.

- Correct the minor duplicate phrase “for backpressure, for backpressure” in §8.

## 6. Open questions

1. Does an independent termination cause legitimately supersede a prior promised base status, or must the promise constrain later cooperative causes? Faults and cooperative exits may need different answers.

2. What is the exact total target order when executing, suspended, due, and queued completion work coexist?

3. Should watch mode use one foreground group, a controller-owned group with explicit forwarding, or a separate child group? Which process’s status is authoritative?

4. What exact root-object representation and keying protocol can both supervisor and worker compute without serializing a VFS identity or importing 0023’s unresolved generation primitive?

5. Should terminal-owning sessions permit `process:spawn` at all without a deliberate PTY hand-off or stronger sandbox profile?

6. Can Hermes cancellation and reusable-runtime validation be prototyped on both eval source and Ibex-built bytecode, and can the editor consume input while that work is pending?

7. What maximum input size and renderer/wire version complete the constants contract?

## 7. Readiness verdict

The unimplemented model checker, constants file, and sibling repairs are honestly ledgered and are not by themselves the reason for this verdict. The blocker is a reachable contradiction in the target’s own typed-promise dispatch, accompanied by unresolved material state, topology, disposition, and protocol seams.

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

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f57b8-61ec-7af3-b606-90b945753099`
**Integrity check:** rollout final-message md5 **`ece9f60c08a2`** == captured file md5, byte-for-byte,
verified independently by the orchestrator. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `b964c18f8bb5`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@ed6599c16ea9`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the concurrent
Fable round-9 review of the same revision, or to any prior LLP 0025 artifact — the stash was verified to hold (the
orchestrator re-stashed after the round-8 reconciliation had restored the artifacts).
**Method:** `brief-round9.md` verbatim.

### Verbatim review

## 1. **Overall assessment**

The proposal’s central architecture is a good idea: terminal and lifecycle authority belongs in a supervisor that survives the engine worker. The latch deletion is also conceptually correct. However, round 9 is not freeze-ready: several normative passages still describe mutually exclusive machines, including the exact target-derived credit status that round 9 intended to remove.

The requested §6 trajectories, treating the two-axis dispatch block as authoritative, derive as follows:

| Trajectory | Derived result |
|---|---|
| Editing press 1; idle press 2; timer becomes due; press 3 | Press 1 leaves credit 1/no promise; press 2 runs the idle row and sets `Orderly`; press 3 sees the prior promise before credit and terminates orderly—not 130. |
| `Interrupt(130)` promise; work finishes | The next interrupt terminates 130 regardless of the now-idle target. |
| Promise followed by root `process.exit(7)` | The cooperative-exit cause takes precedence; the next interrupt expedites termination with 7, preserving the notice’s termination promise. |
| No-promise starting rows | Editing clears the buffer; undispatched evaluation returns idle. The next nonterminal interrupt prints a promise, so the following interrupt terminates. Thus the intended machine has a ≤3 bound and every reachable credit-3 state has a live promise. |

AC 7 agrees with those results. Unfortunately, the table-scope prose and §8 status table do not. The document therefore does not specify that machine unambiguously.

Review basis: target `b964c18f8bb5`; current siblings `0022@88decefdc683`, `0023@ed6599c16ea9`, and `0024@6416ccb8c3c2`.

## 2. **Strengths**

- The two-axis distinction—termination `cause ≻ promise ≻ credit`, status `cause ≻ promise ≻ unreachable 130`—is the right simplification and fixes the round-8 trajectory when applied consistently ([0025 §6:632](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:632)).

- The notice invariant is now framed as a temporal property with editor-input reset, rather than inferred from target classes ([0025 §6:654](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:654)). The normative `Orderly` definition carries only a class and explicitly calls for an exit-time `process.exitCode` read ([0025 §6:507](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:507)).

- The supervisor/worker threat model is unusually honest. It distinguishes stuck/crashed engines, hostile JavaScript behind intact mediation, and compromised native workers; it also correctly treats `process:spawn` as a threat-profile transition ([0025 §7:735](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:735)). Current spawning code confirms why this distinction matters: it gates `process:spawn`, creates native children and process groups, and directly redirects descriptors ([hermes_runtime_process.cc:1401](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1401), [hermes_runtime_process.cc:1746](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_process.cc:1746)).

- The “today” engine premises are accurate. `Engine` exposes no cancellation operation ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); evaluation retains runtime and FFI serialization across `ex_hermes_eval` ([engine/hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869), [engine/hermes.rs:485](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:485)). Ibex’s `hermesc` command supplies no async-break flag ([engine/hermes.rs:1837](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1837)), while the vendored interfaces document any-thread `asyncTriggerTimeout`, eval break checks defaulting true, and a debugger interrupt that becomes a no-op stub without debugger support ([hermes-interfaces.h:177](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/jsi/hermes-interfaces.h:177), [RuntimeConfig.h:62](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/Public/RuntimeConfig.h:62), [AsyncDebuggerAPI.h:240](/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers/hermes/AsyncDebuggerAPI.h:240)).

- The receipt-side versus write-side ordering distinction is sound. Once every producer participates in the relay counter, draining to its cutoff handles a lifecycle record overtaking unread relay bytes ([0025 §3:314](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:314), [0025 §8:818](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:818)). Child relays are correctly limited to receipt ordering.

- The `Pending` versus immediate/teardown `failed` split is coherent with current 0024: stale requests resolve `unavailable`, permanently stuck work remains `Pending`, and destruction resolves outstanding requests `failed` ([0024 §6:856](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:856)).

- §9’s hardened journal, no-current-directory fallback, no-clobber key publication, and fresh-nonce `K_channel` equality proof are strong designs. Removing the unused history token is the correct locality-preserving choice ([0025 §9:957](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:957)).

- §12 now pins concrete values and distinct overflow behavior, including maximum input size ([0025 §12:1099](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1099)). The document also accurately says the annex, interrupt model, and environment inventory do not exist yet.

## 3. **Concerns**

1. **Blocking — §8 resurrects the exact round-8 target-derived credit status.**  
   Evidence: §6 proves credit-3 always carries a live promise and gives promise precedence ([0025 §6:587](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:587), [0025 §6:632](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:632)); AC 7 pins the killer and its dual ([0025 AC 7:1155](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1155)). Yet §8 classifies a credit-3 press “against running work or operator input” as 130 and one “at the idle prompt” as orderly ([0025 §8:878](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:878)). The killer reaches credit 3 against due work with an `Orderly` promise; the dual can reach credit 3 at idle with an `Interrupt(130)` promise.  
   Resolution criterion: remove every current-target classification of interactive credit-3 status. Reachable credit-3 must take its prior promise; only the explicitly unreachable unpromised-credit fallback may say 130.

2. **Blocking — the table cannot be “first-interrupt-only.”**  
   Evidence: §6 says the table describes only the first interrupt and that the second is never decided by a row ([0025 §6:536](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:536), [0025 §6:547](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:547)). But dispatch falls through to the table whenever there is no cause, no promise, and credit is below 3 ([0025 §6:635](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:635)). AC 7’s editing trajectory requires press 2 to do exactly that: it runs the idle row and creates the promise.  
   Resolution criterion: define the table as the action for any nonterminal step-4 fall-through interrupt, including press 2 after an unpromising editing/undispatched-evaluation press. Qualify “the second interrupt is promise-governed” with “when a prior press created a promise.”

3. **Blocking — `CompletionQueued` is treated as executing.**  
   Evidence: `CompletionQueued{request_id}` is dispatched but not begun and has no target id ([0025 §6:481](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:481)); requests may be raised only against `Executing{id}` ([0025 §6:522](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:522)). Nevertheless, the editing/completion row unconditionally raises an id-exact request because “an in-flight query is executing” ([0025 §6:543](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:543)). Current 0024 assigns the target id only when work begins ([0024 §6:847](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:847)).  
   Resolution criterion: split queued and executing completion transitions. Both abandon/invalidate the result and preserve the buffer; queued raises no request and uses the truthful “work is in flight” notice. Add a generated queued-query trajectory, not only the existing executing-query AC.

4. **Material — `Due{}` does not make the declared state transition-complete.**  
   Evidence: the design calls this a live-unit “set,” represents due work as an empty `Due{}` record, and says multiple units may be live simultaneously ([0025 §6:466](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:466), [0025 §6:481](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:481), [0025 §6:518](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:518)). Two due timers collapse to one identical set member; after one begins, the state cannot determine whether another remains due.  
   Resolution criterion: use an internal non-cancellation identity, a count, or explicitly defined “one-or-more due” state whose begin event carries whether due work remains. The checked transition data must determine the next state without hidden scheduler state.

5. **Blocking — payload-free `Orderly` lacks a coherent numeric-status ownership and snapshot rule.**  
   Evidence: §6 says read `process.exitCode` at exit, and orderly shutdown drains scheduled work first ([0025 §6:507](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:507), [0025 §8:796](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:796)); §8 later says cause latching fixes the status and later events never change it ([0025 §8:892](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:892)). More importantly, the supervisor owns final exit, but `process.exitCode` currently remains worker/engine state queried only after evaluation returns ([main.rs:811](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:811)); the native exit bridge mutates the worker’s process object ([hermes_runtime.cc:627](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:627)). A due timer can execute `process.exitCode=7; while(true){}` after the promise: the supervisor must return 7 without depending on the stuck engine.  
   Resolution criterion: define cause latching as fixing the `Orderly` status rule, not its number; define the exact snapshot event relative to shutdown drain; and make `process.exitCode` supervisor-authoritative or synchronously/acknowledged mirrored before its setter returns. Add the setter-then-wedge trajectory.

6. **Blocking — relay cutoffs do not cover accepted output still in the worker-local console queue.**  
   Evidence: §3 advances counters at the runtime write site and §8 snapshots them before parking/disposal ([0025 §3:316](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:316), [0025 §8:818](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:818)). Native `console.*` currently enqueues asynchronously ([hermes_runtime.cc:540](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:540), [host/abi.rs:351](/Users/ccheever/projects/ibex/src/host/abi.rs:351)); a separate thread writes later ([host/abi.rs:376](/Users/ccheever/projects/ibex/src/host/abi.rs:376)). This path is mandatory on Windows and remains a fallback elsewhere ([hermes_runtime_console.cc:86](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_console.cc:86)). Current hard exit explicitly drains it because same-tick `console.log(); process.exit()` otherwise loses output ([hermes_runtime.cc:588](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:588)).  
   Resolution criterion: every armed CLI console/print/fallback route must synchronously reserve the counted relay before lifecycle snapshot, with the worker retained until the reserved cutoff drains, or the record must carry an additional producer-accepted cutoff. Add an AC that pauses the console writer between enqueue and fd write.

7. **Blocking — the deleted history token remains mandatory in AC 11.**  
   Evidence: §9 says the worker receives no history-scope token and performs no history operation ([0025 §9:957](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:957)); AC 11 says the worker “holds only an opaque token” ([0025 AC 11:1181](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1181)). Both cannot pass.  
   Resolution criterion: AC 11 must assert that worker bootstrap and control schemas contain no history token or history-operation route. Test the equality proof separately.

8. **Material — fallback rendering still can acknowledge an undisplayed value.**  
   Evidence: malformed/unknown trees produce a safe diagnostic ([0025 §3:295](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:295)), but display acknowledgement is defined only by barrier completion ([0025 §3:351](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:351)); AC 6 repeats that rule without excluding a fallback ([0025 AC 6:1143](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1143)). Current 0024 requires that a failed render not update `$_` ([0024 §7.8:1486](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1486)), while today’s REPL updates `$_` before inspection/rendering ([repl/mod.rs:67](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:67), [repl/mod.rs:884](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:884)).  
   Resolution criterion: define broker completion as at least `Displayed | Fallback | WriteFailed`, and permit only `Displayed` to emit the evaluator acknowledgement. Add malformed, unknown-version, and oversize-tree fixtures preserving the prior `$_`.

9. **Material — §1’s “current” topology matrix mixes current and target behavior.**  
   Evidence: prose correctly says run/watch paths install no handler ([0025 §1:219](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:219)), but the direct-file row promises id-exact cancellation and `_exit(130)` under a “current, kernel-default” header ([0025 §1:225](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:225)). Current file execution awaits the engine before the optional keep-alive handler exists; the only explicit CLI `Ctrl+C` handler is inside that later loop ([main.rs:782](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:782), [main.rs:1088](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1088)). The watch-child row also says the simultaneously killed controller reaps the child “on the next loop”; reaping happens only after `await_restart_trigger` returns ([main.rs:879](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:879)).  
   Resolution criterion: separate current kernel behavior from the specified target. State current direct-file default signal death and current lack of controller reaping, then ledger both mediated implementations.

10. **Material — `ibex run` argument-shape and watch claims do not match dispatch.**  
    Evidence: the spec says only a bare, extensionless, nonexistent name selects a package script and says `--watch` is a controller ([0025 §1:212](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:212)). Code rejects only recognized JS/TS extensions, so nonexistent `foo.txt` or `lint.prod` selects a package script ([main.rs:483](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:483)). Package-script dispatch also occurs before the watch branch, so a package script with `--watch` is run once ([main.rs:345](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:345)); the CLI advertises one combined file-or-script command ([cli.rs:175](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:175)).  
    Resolution criterion: decide dotted-name and package-script watch semantics, align implementation and prose, and add fixtures for existing extensionless shadowing, unknown extensions, path-shaped names, JS/TS extensions, and package script plus `--watch`.

11. **Material — the claimed unit-generic lifecycle dependency does not exist in current 0024.**  
    Evidence: §8 says LLP 0024 §6 supplies either an evaluation-attached lifecycle outcome or a bare event for a timer exit with no evaluation ([0025 §8:834](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:834)). Current `0024@6416ccb8c3c2` defines only “An evaluation returns” the five outcomes and has no bare no-evaluation lifecycle event ([0024 §6:728](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:728)).  
    Resolution criterion: land and repin the unit-generic event schema in 0024, or own the bare event in 0025 and add an explicit ledger obligation.

12. **Material — “adopts LLP 0024’s algebra exactly” is false.**  
    Evidence: 0025 says accepted cancellation produces the evaluation-specific `cancelled` outcome ([0025 §6:691](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:691), [0025 §6:706](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:706)). Current 0024 says callback/query acceptance merely means the unit returned, with no evaluation transaction ([0024 §6:892](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:892)). The target ledger itself admits both documents remain loose ([0025 §11:1073](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1073)).  
    Resolution criterion: define acceptance target-generically, with `cancelled` emitted only for evaluation targets, and update/repin 0024.

13. **Material — §11 still violates its own attestation discipline.**  
    Evidence:

    - `OBL-LAUNCHER-SIGNALS` says only `main.rs@blob`, without an OID, despite “an attestation without a content hash is not an attestation” ([0025 §11:1045](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1045), [0025 §11:1082](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1082)). Current blob is `09e0b170d16b`.
    - `OBL-REGISTRY-ROWS` binds only `coverage-edges.json`, although its assertion also depends on capability definitions and reconciliation files ([0025 §11:1080](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1080)). A new `lifecycle:exit` definition could appear while that blob remained unchanged.
    - Lines 534 and 1223 assign the suspended-settlement question to `OBL-UNIT-PUBLICATION`, which line 1072 calls delivered; line 1075 correctly owns it as `OBL-SUSPENDED-UNIT`.
    - The 0023 pin is stale: actual `ed6599c16ea9`, not the claimed current `2b4c28230caf`.

    Resolution criterion: pin `main.rs@blob:09e0b170d16b`; attest the registry through a combined registry digest or all relevant blobs; change both wrong references to `OBL-SUSPENDED-UNIT`; and repin 0023.

14. **Minor/Non-blocking — notice-time payload wording survives in historical metadata.**  
    Evidence: the superseded round-7 `Revised` block still says `Orderly(exitCode)` is captured at notice time ([0025 metadata:25](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:25)). The normative body is payload-free, but the requested “no reading survives” condition is not literally met.  
    Resolution criterion: collapse the revision metadata or mark older blocks explicitly superseded/non-normative.

## 4. **Cross-document findings**

Pin recomputation:

| Ledger input | Result |
|---|---|
| `0022@88decefdc683` | Current; both 0022 rows match. |
| `0023@2b4c28230caf` | **Stale**; current is `ed6599c16ea9`. |
| `0024@6416ccb8c3c2` | Current; all four 0024 rows match. |
| `coverage-edges.json@blob:d495d9d6318f` | Matches, but does not cover the complete multi-file registry assertion. |
| `runtime-surface.json@blob:2ad526bc2fa9` | Matches; it remains clap-only, with no history/keybinding section ([runtime-surface.json:31](/Users/ccheever/projects/ibex/runtime-surface.json:31)). |
| `main.rs@blob` | Invalid/missing OID; current is `09e0b170d16b`. |
| `armed-snapshot.schema.json@blob:7d7784994b9e` | Matches; `runNonce` is only a base64url reference, with no freshness property ([armed-snapshot.schema.json:68](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:68)). |
| `repl/mod.rs@blob:c4bcf99bbcb7` | Matches; the completer still blocks on `recv_timeout` ([repl/mod.rs:247](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247)). |
| Model, constants annex, environment inventory, ledger checker | Their stated absence is accurate. |

Target-to-sibling dependencies:

- At `0023@ed6599c16ea9`, worker locality still says only opaque authenticated session tokens and enumerated by-design events cross; it does not acknowledge the fresh-nonce equality proof ([0023 §7.1:1533](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1533)). This is an honestly ledgered dangling dependency, though its pin needs refresh.

- At `0024@6416ccb8c3c2`, lifecycle remains evaluation-only, and callback/query cancellation acceptance remains different from 0025. The lifecycle dependency is not currently ledgered; the cancellation mismatch is.

Sibling-owned defects, reported but not charged to 0025:

- `0022@88decefdc683` still says “latch rules,” defines a work epoch closed by quiescence plus a republished prompt, and promises two interrupts within that epoch ([0022 §10:884](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:884)); AC 15 repeats it ([0022 AC 15:1131](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1131)). Its bounds row still says bounds are open in both siblings ([0022 §11:990](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990)). Its startup-diagnostic row is stale even though its own §4 and current 0023 now permit a pre-JavaScript host path. It also incorrectly says current 0024 still uses retired “decision evidence” terminology ([0022 §7:727](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:727)).

- `0024@6416ccb8c3c2` still names an LLP 0025 “interrupt-latch” work epoch ([0024 §2:330](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:330), [0024 §9:1741](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1741)). Its OQ 8 falsely says `session-constants.json` exists and maximum input is unpinned ([0024 OQ 8:2129](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2129)). Its AC 12 says `let $_; boom()` both does not and does leave auto-update disabled ([0024 AC 12:1917](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1917), [0024 AC 12:1943](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1943)).

- `0023@ed6599c16ea9` duplicates and contradicts its `module.parent`/`module.children` disposition: one row mixes them into `virtual-absolute / closed`, while a later row correctly calls the container objects non-path ([0023 §6:1392](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1392), [0023 §6:1412](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1412)).

- Current 0024 says one module instance “however spelled,” while current 0023 deliberately splits case aliases into two `SourceId`s on aliasing volumes ([0024 §7.9:1556](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1556), [0023 §2.3:675](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:675)). 0023 already ledgers this as a 0024-owned defect.

## 5. **Suggestions**

- Generate §8’s interrupt-status rows from the same transition data as §6. The most serious round-9 contradiction survived because status was copied into a second hand-maintained table.

- Represent transition state with types that make invalid actions impossible: `QueuedCompletion(request_id)` should not expose a cancellation `target_id`; `Executing(target_id)` should.

- Define one explicit status object, such as `TerminationCause { class, numeric_rule }`, with a named `process.exitCode` snapshot event. Avoid using “status” for both class and already-captured number.

- Make broker completion and lifecycle cutoffs typed: `Displayed`, `Fallback`, `WriteFailed`; `ReservedThrough(n)`, `WrittenThrough(n)`, and `ReceivedThrough(n)`. This would expose the console pre-relay buffering seam mechanically.

- Split §1 into “current topology” and “normative target topology.” Mixing them in one column is what produced the direct-file and reaping contradictions.

- Add a companion implementation Plan. The design spans engine ABI, a supervisor, signal handling, registry vocabulary, renderer protocol, history storage, and PTY tests; the obligations ledger is traceability, not sequencing.

- Before freeze, update 0023 and 0024, repin 0025, then re-run 0022 last as planned. Consolidate historical `Revised` prose so superseded mechanisms cannot look normative.

- Make history-record maximum either explicitly a payload limit or larger than maximum input plus framing. At present both are 1 MiB, so an accepted maximum-size input cannot fit in a 1 MiB framed history record.

## 6. **Open questions**

1. Where is authoritative `process.exitCode` stored under the supervisor architecture, and what operation synchronizes a setter with a concurrent interrupt?

2. Will every CLI output producer—including native Windows/fallback console and `print()`—reserve the relay counter synchronously, or is a producer-queue cutoff required?

3. Is queued completion cancellable through a separate queue request id, or deliberately only abandonable before it begins?

4. Should `Due` retain an internal scheduling identity/count even though it has no cancellation target id?

5. Does package-script `--watch` exist, and should dotted nonexistent names be package scripts or files?

6. Will LLP 0024 own the bare lifecycle event for a root timer with no evaluation in flight?

7. Can LLP 0023 explicitly admit the fresh-nonce equality proof while preserving its ban on serialized/rehydrated VFS identity?

8. Which Hermes cancellation mechanism and which non-blocking editor integration pass the release gates on every advertised target?

## 7. **Readiness verdict**

The proposal is directionally strong and not wrongheaded, but it has unresolved blocking correctness and implementability defects. In particular, §8 still restates the round-8 status bug, the transition table is not total for its own declared states, the history AC contradicts token deletion, and the lifecycle cutoff does not yet cover all accepted output paths.

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

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** `codex exec`, non-interactive, sandbox `read-only`, approval `never`,
CWD `/Users/ccheever/projects/ibex`. Launched from the main session (handoff protocol).
**CLI version:** `codex-cli 0.144.1`
**Model:** `gpt-5.6-sol`
**Effort:** `model_reasoning_effort="ultra"` — confirmed in the log; **no substitution**
**Codex session id:** `019f57dd-96c0-77a2-9e06-6934603254fb`
**Integrity check:** rollout final-message md5 **`b37e0013c7c5`** == captured file md5, byte-for-byte,
verified independently by the orchestrator. The body below is provably the output of the session cited.
**Date:** 2026-07-12
**Revision under review:** `259eca9d5db6`
**Sibling digests at review time (reviewer-reported):** `0022@88decefdc683`, `0023@601cb5213dca`, `0024@6416ccb8c3c2`
**Redaction status:** none.
**Independence:** fresh non-interactive session; no access to the orchestrating session, to the concurrent
Fable round-10 review of the same revision, or to any prior LLP 0025 artifact — the stash was verified to hold.
**Method:** `brief-round10.md` verbatim.

### Verbatim review

1. **Overall assessment**

The architecture remains a good idea, and the two-field promise/credit machine is still unfalsified. Round 10 correctly propagated most latch-deletion consequences, including §8 status precedence, AC 11, display acknowledgement, and supervisor-owned exit status.

However, the closing pass found one blocking state-classification contradiction and four material coherence or feasibility gaps. This revision is not ready yet.

2. **Strengths**

- §6’s termination and status axes remain coherent: cause ≻ promise ≻ credit for termination, with status supplied by cause, then promise, then unreachable-default 130 ([0025:652](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:652)). §8 is subordinate to that axis ([0025:901](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:901)); AC 7(l) checks the round-8 killer trajectory, while AC 9 asserts the table and cleanup precedence.
- Both no-promise worst cases are now named correctly: editing-otherwise and undispatched submission ([0025:606](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:606)).
- Splitting queued from executing completion is consistent with 0024’s id-at-begin rule. The current implementation likewise enqueues before engine-thread receipt and execution ([repl/mod.rs:247](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:247), [repl/mod.rs:710](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:710)).
- Making phase independent of live work correctly admits idle prompts with background execution. The current REPL already keeps `readline` live while independently pumping ready work ([repl/mod.rs:646](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:646)).
- `Displayed | Fallback | WriteFailed`, with acknowledgement only for `Displayed`, matches 0024’s “last successfully displayed value” rule. It also fixes today’s pre-render assignment to `$_` ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63)).
- Supervisor-authoritative `process.exitCode` is feasible and addresses a real gap: today the CLI reads it only by evaluating JavaScript after execution returns ([main.rs:796](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:796)), which cannot work after a wedged timer.
- AC 11 now correctly requires complete absence of a worker history token ([0025:1208](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1208)).
- `K_channel` provenance, nonce limitations, revision-block non-normativity, and the relevant code-blob pins are stated accurately.

3. **Concerns**

1. **Blocking — `idle × CompletionQueued` has two different statuses.**

   §6 includes `CompletionQueued{request_id}` in the live set and declares phase independent of that set ([0025:500](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:500)). But target-selection rule 4 considers only executing/suspended/due work in idle, otherwise selecting the idle prompt ([0025:554](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:554)). The table instead classifies any `idle, work in flight` state as running work and promises `Interrupt(130)` ([0025:569](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:569)).

   This is reachable under the required asynchronous editor by emptying a buffer after dispatch but before query begin. The selector yields `Orderly`; the table yields `Interrupt(130)`—the exact target-derived status fork this round intended to eliminate.

   **Resolution criterion:** Make this cell single-valued, specify queued-query invalidation/removal on ordinary buffer changes, and add the trajectory to AC 7 and the generated model. Prefer one canonical query-state sum rather than separate query and live-set truths.

2. **Material — `Due{sched}` has no ready-state publication seam.**

   §6 requires the supervisor-visible state to distinguish multiple due-but-not-begun timers ([0025:500](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:500)), while §11 calls begin/end unit publication sufficient ([0025:1100](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1100)).

   A suitable scheduling identity exists in `TimerEntry.id` ([hermes_runtime_internal.h:51](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_internal.h:51)), and native poll distinguishes due timers by deadline plus id ([hermes_runtime.cc:3621](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3621)). But this remains native-internal; `ex_hermes_next_timer` exposes only the earliest deadline ([hermes_runtime.cc:3724](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3724)). Begin/end publication cannot populate `Due{sched}` before begin.

   **Resolution criterion:** Require due/undue/begin transitions carrying scheduling identity, or make the supervisor own scheduling. Update `OBL-UNIT-PUBLICATION` and add a simultaneous-two-due-timers fixture.

3. **Material — the cancellation algebra still gives `accepted` two incompatible meanings.**

   §6 first says only evaluation targets emit structured `cancelled`, while callback/query acceptance means the unit returned ([0025:711](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:711)). It later states universally that accepted work “produced the `cancelled` outcome” ([0025:727](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:727)). `OBL-CANCEL-EDGES` therefore overstates that §6 has settled the edge.

   **Resolution criterion:** Define `accepted` uniformly as causally stopped by the request and runtime-consistent; then state per target that evaluations emit `cancelled`, while callbacks and queries emit no evaluation outcome. Make 0024 use the same definition.

4. **Material — §1’s launcher topology omits accepted spellings and dispatch precedence.**

   Package-script dispatch is not limited to `ibex run`: the top-level positional branch also invokes it ([main.rs:438](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438)). Both dispatch branches test package-script shape before `--watch` ([main.rs:344](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:344), [main.rs:438](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438)). Consequently, `ibex --watch dev` and `ibex run --watch dev` run a package script once rather than entering the watch controller.

   §1 documents only `ibex run <bare-name>` as package execution and describes `--watch` without this qualification ([0025:224](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:224)); `OBL-LAUNCHER-SIGNALS` also omits the top-level spelling. Its statement that reaping applies only to self-exit/external kill additionally omits controller-driven restart, which terminates and reaps the child ([main.rs:216](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:216), [main.rs:879](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:879)).

   **Resolution criterion:** Specify a spelling × argument-shape × watch-flag dispatch table, include every package-launch spelling in §1 and §11, and decide whether watch-on-package is rejected, ignored, or supported.

5. **Material — the counted native console route is not length-bearing.**

   §3 requires unmodified output and exact byte reservations for every console/print/fallback route ([0025:328](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:328)). Native console and `print` pass `message.c_str()` ([hermes_runtime_console.cc:55](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_console.cc:55)); Rust reconstructs it with `CStr::from_ptr` ([abi.rs:3395](/Users/ccheever/projects/ibex/src/host/abi.rs:3395)). Embedded NUL therefore truncates the payload before it can be counted, particularly on Windows where native console enhancement is skipped.

   The accompanying “today `console.*` enqueues” claim is also too broad: default non-Windows console routes through `process.stdout/stderr.write` ([console-enhance.js:840](/Users/ccheever/projects/ibex/src/engine/bootstrap/console-enhance.js:840)); the writer-thread queue is principally `print`/native fallback and mandatory on Windows.

   **Resolution criterion:** Specify a length-bearing byte ABI, reserve the exact framed byte length at enqueue, enumerate both enhanced and fallback routes, and add embedded-NUL fixtures. Define “issued” as queue-accepted or fd-written so the cutoff vocabulary is unambiguous.

4. **Cross-document findings**

Current SHA-256 prefixes:

- 0022: `88decefdc683`
- 0023: `601cb5213dca`
- 0024: `6416ccb8c3c2`
- 0025: `259eca9d5db6` — requested revision confirmed

Target §11 pin audit:

- All 0022 and 0024 pins match current.
- All code blob pins match: coverage `d495d9d6318f`, runtime surface `2ad526bc2fa9`, launcher `09e0b170d16b`, armed schema `7d7784994b9e`, REPL `c4bcf99bbcb7`.
- The sole stale target pin is `OBL-HISTORY-LOCALITY`: §11 says `0023@ed6599c16ea9`, but current is `0023@601cb5213dca`. Drift is favorable: current 0023 explicitly permits the non-rehydratable history equality-proof digest and says the seam is closed ([0023:1626](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1626)).

Version-pinned sibling contradictions:

- At `0022@88decefdc683`, §10/AC 15 still use a work epoch, mention latch rules, and promise two interrupts per epoch. Target rows `OBL-INTERRUPT-EPOCH` and `OBL-INTERRUPT-BOUND` correctly record this.
- At `0024@6416ccb8c3c2`, “work epoch” still means an interrupt-latch unit, and lifecycle remains input-scoped. Target rows `OBL-0024-EPOCH-VOCAB` and `OBL-LIFECYCLE-UNITGENERIC` correctly record both.
- The same 0024 revision has the cancellation ambiguity described above and incorrectly says `session-constants.json` exists ([0024:2129](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2129)).
- 0024’s `$_` acceptance criteria contradict its own normative rule: AC 12 first says `let $_; boom()` does not leave auto-update disabled ([0024:1917](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1917)), then says it does ([0024:1943](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1943)).
- At `0023@601cb5213dca`, §2.3 gives each hard-link entry its own `SourceLabel`, while AC 18a still requires a lexically least shared spelling ([0023:2145](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2145)).
- The existing 0023/0024 module-identity mismatch remains correctly ledgered by 0023: case aliases and synthetic-module cardinality disagree at current 0024.
- 0024 OQ 10 still says 0023 leaves `SourceLabel` open, although current 0023 now pins it.

The already-ledgered sibling/tooling obligations are not themselves reasons for the NOT READY verdict; the target-local and unledgered feasibility issues above are.

5. **Suggestions**

- Represent completion as one sum such as `None | Queued{request_id,generation} | Executing{request_id,unit_id,generation}`, deriving its live-set projection.
- Extend the generated interrupt alphabet with explicit `timer-due(sched)`, `timer-undue(sched)`, and completion-queue transitions.
- Generate the launcher topology from the actual dispatch predicate, as §6 intends for its own table.
- Make output-route inventory and byte-count semantics machine-readable alongside the broker model.
- Re-pin 0023 only after these target edits, then reconcile 0024 and rerun 0022 last as planned.

6. **Open questions**

- Does the worker publish timer readiness, or does the supervisor own enough scheduling state to derive `Due{sched}`?
- Can more than one completion request be queued, and what invariant relates query state to the live-unit set?
- For callback/query cancellation, what observable proves the request caused the return rather than merely racing it?
- Should `--watch` reject package-script shapes or supervise package scripts?
- Are relay counters defined over bytes accepted into a lossless queue or bytes issued to the fd?

7. **Readiness verdict**

The promise/credit design remains strong, but the idle/queued classification directly reintroduces a status fork, and the due-state, cancellation, launcher, and native-output seams remain materially underspecified.

VERDICT: NOT READY
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
