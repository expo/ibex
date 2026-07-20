# Compiled process semantics: argv, lifecycle, signals

**Status:** In Progress
**Severity:** P2
**Systems:** Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §6, LLP 0025, LLP 0022
**Depends-on:** sfe-compile-cli

Argv belongs to the application: no interception, no runtime flags;
reserved Ibex words reach the program; Unicode argv contract with
boot-time rejection naming the offending argument index
(surrogate-escape recorded as the fallback if field friction demands);
`process.argv = [execPath, "<entry designation>", ...args]`, `argv0`
invoked name, `execArgv` empty. Lifecycle/signal rows adopted from LLP
0025's file-execution obligations and landed, not delegated:
event-loop drain, pending-async semantics, uncaught exception/rejection
exits, `process.exit`/`exitCode` with output-broker flush before
termination, SIGINT/SIGTERM/SIGHUP + signal-derived status, stdio
brokering per LLP 0022/0025. Stdio/cwd implicit-vs-policy is register
item 1 (**blocked-on-decision**, before `Accepted`).

**Done when:** end-to-end fixtures per row on both tuples, including
reserved-word and non-UTF-8-argv cases; the LLP 0025 rows this depends
on are landed and cross-referenced.

## Progress — 2026-07-18

Compiled boot now captures `args_os` without a command parser and rejects a
non-Unicode value with a stable error naming its zero-based argument index.
Reserved Ibex option/subcommand spellings remain ordinary application data.
Before any authenticated record is linked, the stub installs
`process.argv = [execPath, entryDesignation, ...args]`, preserves the invoked
name as `argv0`, and sets `execArgv` to the empty list. Focused native-Hermes
tests pin that exact projection, and the signed relocation smoke remains green.

Compiled boot now reuses Hermes' native monotonic timer clock, pending-work
predicate, poll result, and background-callback wake hook to drive referenced
work to quiescence after entry evaluation. An unconsumed asynchronous callback
failure refuses the run, the final numeric `process.exitCode` selects the
orderly process status, and the stub gives the output broker LLP 0025's 500 ms
flush budget before termination. The signed relocation fixture schedules a
timer, emits a brokered line, selects status 7, and proves both the line and
status survive. SIGINT/SIGTERM/SIGHUP cleanup, privileged `process.exit`
control-plane migration/inert exit-listener behavior, non-UTF-8 subprocess
execution, both release tuples, and the decision-gated stdio/cwd rows remain.
