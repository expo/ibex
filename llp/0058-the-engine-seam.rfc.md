# LLP 0058: The engine seam — Hermes by default, swappable

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Runtime, Host ABI, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-27
**Revised:** 2026-08-27 (initial draft)
**Related:** LLP 0057 (Ibex 2 — the inversion this completes), LLP 0003 (Hermes engine bridge — the current single-engine binding), LLP 0002 (host embedding ABI)

## Summary

Once the standard library is Rust (LLP 0057), the JavaScript engine stops
being the foundation and becomes a component: the thing that executes
application code and supplies the intrinsics Rust cannot own. This document
specifies what an engine must provide to sit in that slot, why **Hermes is the
default**, and what swapping actually costs.

The headline is a caution, not an invitation. **Engine-swappable does not mean
engine-agnostic.** The seam is worth having because it forces the boundary to
be honest and keeps a bad engine bet from being fatal — not because swapping
will be cheap.

## 1. What an engine must provide

Four things, in decreasing order of how much they constrain the choice.

**1. Ahead-of-time bytecode that we actually ship.** This dominates everything
else and is the reason the seam is not neutral between candidates. Measured
with the repository's own Hermes on a synthetic module graph:

| graph | from bytecode | from source |
|---|---|---|
| 500 modules | 6.3ms | 72.6ms |
| 1,000 modules | 6.5ms | 158.7ms |
| 2,000 modules | 7.7ms | 338.3ms |

Bytecode evaluation is flat in graph size; source parse is linear in bytes.
An engine without a real AOT bytecode story cannot meet a startup budget
measured in tens of milliseconds, whatever else it offers.

**2. Host functions over primitives and handles.** The whole standard library
reaches JavaScript through this. If the engine's embedding API forces
serialization at the boundary, LLP 0057's boundary rule is unimplementable on
it.

**3. A job queue we can interleave with.** See §3.

**4. Enough of the language.** Not "all of it" — enough for the application
tier the runtime targets. This is a real threshold and it is lower than total
conformance, but it is not near zero.

## 2. Why Hermes is the default

Hermes is the default because of item 1, not by inheritance. Its bytecode
format is the product feature: `hbc` is mmap-able, requires no parse, and is
produced at build time. On the real 570-module macOS boot graph, `hermesc`
compiles the whole thing in 201ms once, at build time, against 155ms of parse
on every single launch.

Its conformance is mid-tier — roughly 55% of Test262, against ~88% for V8,
JavaScriptCore, and SpiderMonkey. That has been survivable for React Native at
very large scale, and it is more survivable here, because LLP 0057 moves the
standard library out of JavaScript: less JavaScript runs, so less of the
language surface is load-bearing.

**Candidates and what would move the decision:**

- **QuickJS** — far smaller, starts fast on trivial workloads, has a bytecode
  format. The open question is whether its bytecode story holds at a 570-module
  graph the way `hbc` does. Worth measuring before assuming the size win
  transfers.
- **V8** — best conformance and peak throughput, largest binary, JIT
  unavailable on iOS. A plausible desktop and server option, a poor default.
- **AOT compilers (Porffor and kin)** — compile JavaScript to native and skip
  the engine entirely. Porffor is at roughly 61% of Test262 and describes
  itself as a research project not intended for serious use. Not a candidate.
  But its thesis — *nothing is compiled at runtime, ever* — is the rule
  `rules/RULES.md` already carries, and the direction LLP 0057 approaches from
  the other side.

## 3. The part that cannot move

LLP 0057 §2 names the engine-intrinsic category. This is where it gets
specified, and it is the hardest open problem in either document.

`Promise`, the microtask queue, `async`/`await`, module resolution semantics,
GC interaction, error stacks, and `WeakRef` belong to the engine. A Rust
standard library returning futures must resolve them into the engine's job
queue with correct ordering: a microtask enqueued by a host call must drain
before the next macrotask, and a Rust task completing off-thread must not
reorder relative to JavaScript-enqueued jobs.

**Every engine solves this differently, and this is where a swap actually
costs.** The seam's job is to make that cost visible and bounded — one adapter
per engine implementing a stated contract — rather than diffuse.

## 4. What swapping costs, honestly

Bounded: the host-function binding layer, the bytecode build step, the job-queue
adapter.

Not bounded, and the reason to keep expectations low: **behavior differences in
the language itself.** Two engines at different conformance levels do not run
the same application code identically. A swap needs a conformance gate over the
application tier, and the runtime should state which engine its guarantees are
made against.

The seam therefore buys three things and not a fourth. It buys: a forcing
function that keeps engine assumptions out of the standard library; the ability
to run a different engine per platform where one is unavailable; and insurance
against a bad bet. It does not buy interchangeability at the application level,
and this document should not be cited as though it does.

## 5. Open questions

**OQ1 — The job-queue contract.** What exactly must an engine adapter
guarantee about ordering between host-completed futures and engine-enqueued
jobs? This is the gating design work and it should be answered before any
second engine is attempted.

**OQ2 — Does QuickJS's bytecode hold at scale?** The measurement in §1 has only
been run against Hermes. Running it against QuickJS at 500/1,000/2,000 modules
is cheap and would either promote it to a real candidate or close the question.

**OQ3 — What is the conformance floor?** "Enough of the language" needs a
number, expressed as a suite over the application tier rather than a Test262
percentage — the percentage measures the wrong population once the standard
library is Rust.
