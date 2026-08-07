# Compiled process semantics: argv, lifecycle, signals

**Status:** Closed
**Impact:** 4
**Urgency:** 3
**Ease:** 3
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Compiled process semantics: argv, lifecycle, signals” shows the issue materially affects a supported product or engineering path; it belongs in the current program but is not an immediate blocker, while the fix requires a few coordinated implementation and test surfaces, with specific cited code, progress, or acceptance criteria.
**Progress:** Complete
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

## Historical remaining list — 2026-07-31

This snapshot is retained for provenance and is superseded by the 2026-08-02
checkpoint below.

- DONE (dev tuple, behind `sfe-dev-spike`): argv pass-through incl.
  reserved words, `process.argv`/`argv0`/`execArgv` shape, event-loop
  drain, `process.exitCode`, output-broker flush on all exit paths.
- Unicode argv rejection is unit-tested only; no end-to-end
  non-UTF-8-argv fixture exists.
- NOT started: uncaught-exception/unhandled-rejection exit semantics,
  privileged `process.exit` (still throws), all signal handling in the
  compiled stub (SIGINT/SIGTERM/SIGHUP + signal-derived status).
- Release tuples: release compiled arming remains closed; everything
  landed is dev-spike-gated and the signed relocation smoke is
  macOS-only.
- stdio/cwd remains blocked on LLP 0029 register item 1 (author
  decision).

## LLP 0047 reconciliation — 2026-08-01

The original “no interception, no runtime flags” statement is superseded.
Milestone 2 reserves `--ibex-capsec` only at argv[1], removes a leading `--`
escape, and forwards every other spelling. Pre-init mode selection is the
single authority for both environment handling and Rust boot dispatch.
Milestone 4 retains the lifecycle/signal/flush rows above on both modes and
both tuples; ambient cwd/environment are inherited, while the CapSec path uses
the brokered contracts.

## Implementation checkpoint — 2026-08-01

Release boot now implements and exercises the exact first-position selector,
the leading-`--` escape, application argv projection, immutable boot-mode
metadata, inherited ambient environment, referenced timer drain, stdout flush,
and numeric `process.exitCode` in real macOS and Linux artifacts. A
CapSec-selected run refuses before entry without ambient fallback on both, and
Linux also proves the leading-`--` escape. Signal handling,
exception/rejection coverage, non-UTF-8 end-to-end argv, and the full process
matrix keep the ticket open.

## Implementation checkpoint — 2026-08-02

The final macOS arm64 and Linux x86-64 release-kit gates now exercise the M4
ambient lifecycle matrix from relocated, source-free executables. Numeric
`process.exitCode` selects status 24, immediate `process.exit(23)` flushes the
preceding output and does not return, and foreground exceptions, detached
timer exceptions, and unhandled promise rejections all exit 1 with a stable
compiled-background-failure diagnostic where applicable. The compiled graph
record table is retained through referenced-work quiescence, closing the stale
live-import failure previously exposed by a Fetch continuation.

The stub blocks SIGINT, SIGTERM, and SIGHUP before starting runtime threads and
uses a dedicated `sigwait` coordinator to flush brokered output for at most
500 ms before `_exit(128 + signal)`. Both final target gates prove statuses
130, 143, and 129 while application JavaScript keeps the engine busy. This is
reported honestly as a limited signal backend: JavaScript signal dispatch is
not available.

The ticket remained open at this checkpoint for the promised end-to-end
non-UTF-8 argv fixture and for exercising the privileged lifecycle route once a
target has a successful CapSec advertisement. The ambient v1 M4 process rows
were complete on both target tuples.

## Resolution — 2026-08-02

The release-kit gate now invokes the relocated final executable with a raw
invalid UTF-8 argument through POSIX `execve` on both v1 tuples. Both the macOS
arm64 and Ubuntu 22.04 Linux x86-64 artifacts refuse with status 1 before
application output and name zero-based argument index 1. This closes the last
standalone-v1 process row together with the already-green selector, escape,
argv projection, lifecycle, flush, exception/rejection, and signal matrices.

A successful privileged lifecycle call through an advertised CapSec target is
not a standalone-v1 release criterion under LLP 0047; it remains part of the
v1.1 advertisement program and does not keep this ambient-v1 process ticket
open.
