# LLP 0063: Where startup time goes

**Type:** Research
**Status:** Draft
**Systems:** Runtime, Engine, Module Loader, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-29, night (500 modules from bytecode load in **1.8 ms, 3.6 µs a module**: `ibex2 build` now writes every artifact into one bundle beside the manifest, read once at start — 0.06 ms for 500 against 4.7 ms of per-file opens — and a key the bundle lacks falls back to its file. Async host tasks run on a pool that grows on demand rather than a thread each; the `fs.readFile` round trip is ~36 µs. The floor, not the graph, is now the larger part of a boot.) 2026-08-29, evening (the per-module bytecode load cost is 15 µs — 500 modules in 7.5 ms — after `loader::ResolveCache`; it had been 36 µs, and the breakdown now in `examples/speed.rs` put 26 of those in resolution, two `realpath` and up to five `stat` per module from the containment fix, not in the per-module bindings the ticket had blamed. What remains is 14 µs of artifact read per module; a single bundle would remove it.) 2026-08-29, later (the JS bindings ship as bytecode, compiled by `build.rs`: the bindings line of the floor went from ~0.7 ms to 0.04 ms, and the floor is ~1.2–1.4 ms warm. The freeze is unchanged at ~0.7 ms — its cost is the walk, not parsing.) 2026-08-29 (the numbers here are now reproducible in one run — `node scripts/metrics.mjs`, backed by `crates/ibex2/examples/speed.rs` — and the first run revised two of them. The floor is 1.8 ms warm with the freeze at 0.7 ms since LLP 0062 §3 stopped freezing the global object. The 570-module bytecode boot is **23 ms today, not 13**: per-module load cost went from ~23 to ~41 µs as `fs`, `process.env`, and `import.meta` became per-module constructions after §5.1 was measured; `issues/20260829-per-module-bindings-doubled-load-cost.md` has the accounting and the fix. An async host op round trip was ~1.3 ms — a 1 ms polling sleep in the loop, fixed the same day to 36 µs — and a precompiled process paid 25 ms hashing the engine dylib before its floor, fixed the same day to 7 ms by binding the engine at link time; both in `issues/closed/20260829-*`. Neither changes the conclusion: the parser was the cost, and bytecode still meets the budget at 22.6 ms floor-plus-graph.)
**Revised:** 2026-08-28 (§5.1 and §5.2 added after building it: the real loader lands at 13ms rather than the isolated 3ms, and getting there needed a build manifest — without one a "precompiled" run still read and hashed every source file, leaving it at 157ms. §5.2 records the buffer-lifetime trap HBC has and source does not.) 2026-08-28 (initial draft)
**Related:** LLP 0057 (Ibex 2 — whose §7 admits nothing had been measured), LLP 0058 (the engine seam — whose §1 measurement this extends), LLP 0062 (reachable authority — whose R3 this justifies), LLP 0059.000 (the boundary, whose §1.3 holds the crossing costs), `rules/RULES.md` (the 30 ms budget)

## Summary

LLP 0057 §7 is explicit that the startup figures it quotes "establish that the
current design pays a large avoidable cost, not that the proposed one hits any
particular budget. Nothing here has been measured against it, because nothing
here is built." Enough is built now. This is the measurement.

The headline, on a 570-module / 5.7 MB graph — the scale LLP 0057 §1 records
for Exact's real boot:

| what | time |
|---|---|
| runtime floor, before any module | **4.0 ms** |
| the graph, loaded from source, one unit per module | **851 ms** |
| the graph, loaded from source, bundled into one unit | **~150 ms** |
| **the graph, loaded from ahead-of-time bytecode** | **13 ms** |

The budget is 30 ms. Source loading misses it by 28×; bytecode makes it with
room to spare, and the reason is not the one that looks obvious.

**Parsing is not the bottleneck.** Hermes parses at 62 MB/s, which is the same
throughput LLP 0057 §1's figure for the *current* runtime implies. What costs
is a fixed price of roughly 2 ms per `evaluateJavaScript` call, and a loader
that evaluates one unit per module pays it 570 times. Ahead-of-time bytecode
takes that fixed price from ~2 ms to **~9 microseconds**.

That single fact decides an architectural question: bundling is not required.
570 *separate* bytecode modules load in about 3 ms, so the loader can keep one
module per compile unit — the shape per-module injection wants anyway
(LLP 0062 R2) — and take the AOT step on its own.

## 1. How to reproduce

Every number here comes from an `#[ignore]d` test in the tree, so it is
reproducible rather than remembered:

| test | what it measures |
|---|---|
| `boot_floor.rs` | construction, stdlib, bindings, freeze, first eval |
| `boot_real.rs` | a real graph, by module count |
| `eval_overhead.rs` | per-`evaluateJavaScript` cost vs parse throughput |
| `bytecode_vs_source.rs` | source and bytecode, separate and bundled |
| `intrinsic_harden.rs` | the LLP 0062 §3 freeze |

Measured on an Apple M5 (10-core, 32 GB), release builds, vanilla Hermes.
**Absolute numbers are machine-specific and the laptop was in use**; §6 says why
that matters more than it sounds.

## 2. The floor

What a program pays before a line of its own code exists.

| phase | cold | warm |
|---|---|---|
| runtime construction | 1.94 ms | 0.36 ms |
| stdlib host functions | 0.02 ms | 0.02 ms |
| JS bindings | ~1.0 ms | ~1.0 ms |
| intrinsic freeze (LLP 0062 §3) | 1.70 ms | 1.72 ms |
| first evaluation | 0.15 ms | 0.15 ms |
| **total** | **4.03 ms** | **1.52 ms** |

Four milliseconds of a thirty-millisecond budget, and the largest single item is
the security property from LLP 0062 R4 rather than anything about JavaScript.
The floor is not the problem and never was.

## 3. The graph, from source

Loading a real module graph, one `evaluateJavaScript` per module, with the
debugger-enabled engine everything was first measured against:

| modules | source | floor | modules | total |
|---|---|---|---|---|
| 1 | 0.01 MB | 5.07 ms | 2.42 ms | 7.49 ms |
| 10 | 0.09 MB | 4.35 ms | 22.6 ms | 26.9 ms |
| 100 | 0.93 MB | 3.82 ms | 199 ms | 203 ms |
| 250 | 2.32 MB | 3.69 ms | 511 ms | 515 ms |
| **570** | **5.28 MB** | 3.92 ms | **1316 ms** | **1320 ms** |

Linear, at roughly 2.3 ms per module. And **worse than the design being
replaced**: LLP 0057 §1 measures the current runtime at 155 ms of parse for the
same graph. A per-module loader reading source is 8.5× slower than the thing
Ibex 2 exists to improve on.

That reading is correct and the conclusion drawn from it would have been wrong.

## 4. It is not the parser

The same 5.24 MB, evaluated two ways:

| | time | throughput |
|---|---|---|
| 570 separate `evaluateJavaScript` calls | 2.11 s | 2.5 MB/s |
| the same bytes, one call | 148 ms | 35.4 MB/s |
| **fixed cost per call** | **~3.4 ms** | |

Hermes parses at 35 MB/s with the debugger on and 62 MB/s without — and 5.47 MB
at 35 MB/s is 156 ms, which is LLP 0057 §1's figure for the current runtime
almost exactly. **The parser has been performing correctly the whole time.**

What costs is a fixed per-compile-unit price. The loader's architecture — one
unit per module, which is what makes per-module injection natural — is what
multiplies it by 570.

## 5. Bytecode

Whether that fixed price belongs to *parsing* or to *creating a compile unit*
is the question that decides the loader's architecture. If parsing, bytecode
alone fixes it. If unit creation, bundling is required as well and 570 `.hbc`
files would be no better than 570 `.js` files.

570 modules, 5.71 MB of source, 7.16 MB of bytecode:

| | total | per module |
|---|---|---|
| source, 570 units | ~5210 ms | 9.14 ms |
| source, 1 unit | ~150 ms | 0.26 ms |
| **bytecode, 570 units** | **2.5–5 ms** | **0.004–0.009 ms** |
| bytecode, 1 unit | 0.01 ms | — |

It was parsing. The per-unit cost falls from ~2 ms to ~9 µs, and **bundling
stops mattering**: 570 separate bytecode modules load in about 3 ms.

### 5.1 What the real loader gets, and the gap

The 3 ms above is bytecode already in memory. A loader has to find and read it
too, and the built implementation lands at **13.2 ms** for the same graph —
2.35 ms of floor and 10.85 ms of modules. Still comfortably inside the budget,
with about 17 ms left for what an application actually does, but four times the
isolated figure. The difference is file I/O and module-scope execution, neither
of which bytecode removes.

**Getting there required a correction worth more than the number.** The first
implementation derived each module's artifact key by hashing its wrapped
source — so a "precompiled" run still opened, read, and hashed all 5.28 MB to
discover artifacts it already had, and the boot sat at **157 ms**. `ibex2 build`
now emits a manifest of resolved specifier to artifact key, and the runtime
never touches a source file. That single change was **157 ms to 13 ms**, and it
is the difference between *precompiled* meaning the compile step ran and
meaning the runtime does no work.

### 5.2 A trap in HBC that source does not have

Hermes **retains** a bytecode buffer for the life of the module — that is what
makes HBC mmap-able and copy-free — where it parses and copies source. A buffer
that borrows memory the caller frees therefore yields a module whose
synchronous body runs perfectly and whose callbacks later execute against freed
memory.

The failure is silent, and that is the part worth recording: the bytecode is
*gone* rather than *wrong*, so a `fetch` never resolves and a timer never fires.
It presents as an async bug. Anything handing Hermes bytecode must own the bytes
for at least as long as the runtime does.

This is the same shape LLP 0058 §1 measured from the other direction — bytecode
evaluation flat in graph size, source parse linear in bytes — and it is the
property that makes a startup budget survive an application growing, rather
than degrading with it.

## 6. The engine build costs 35%

Everything was first measured against a vanilla Hermes built with the debugger
enabled, which is the build script's default and which typically disables lazy
compilation.

| | debugger on | debugger off |
|---|---|---|
| 570-module boot | 1316 ms | 851 ms |
| fixed cost per evaluation | 3.4 ms | 2.1 ms |
| parse throughput | 35 MB/s | 62 MB/s |
| boot floor, cold | 6.5 ms | 4.0 ms |
| framework size | 74 MB | 63 MB |

Build the shipping engine with `--release`. It is free, it is a third of boot,
and Ibex 2 has no debugger integration to lose. `build-hermes.sh` still defaults
the debugger on; changing that default is a decision rather than a measurement's
conclusion.

## 7. What this means

**AOT bytecode was the next piece of loader work, and nothing else in the
startup path was close.** Not more APIs, not bundling, not a faster parser.
Built since: `ibex2 build` compiles the reachable graph and `ibex2 run
--precompiled` compiles nothing, from anywhere — which is what
`rules/RULES.md` has required all along.

**The loader keeps one module per compile unit.** Bundling buys nothing once
bytecode is in play, and per-module units are what LLP 0062 R2's injection
wants.

**LLP 0062 R3 is justified rather than assumed.** It required ahead-of-time
wrappers; this says the requirement is worth roughly 280× on the dominant term.

**The floor has headroom.** 4 ms of 30, with the intrinsic freeze the largest
line — so LLP 0062's security posture is affordable, and OQ2 (a native freeze)
stays a refinement rather than a necessity.

## 8. What is not measured

Read the numbers as narrowly as they were taken.

**Execution.** The module wrappers are created and never called. Hermes compiles
function bodies lazily from bytecode as well, so first-call cost still exists —
paid once, for code that actually runs. A real graph also does work at module
scope, and none of that changes with how the module arrived. The ~3 ms is a
floor for a 570-module graph, not a whole boot.

**Bytecode is larger on disk**: 7.16 MB against 5.71 MB of source. That is I/O
and memory rather than time, and mmap makes it lazy, but it is a trade.

**Device and platform.** Everything here is macOS on an M5 laptop. iOS, cold
storage, and slower hardware are unmeasured, and the budget in `rules/RULES.md`
is derived from Exact's first-frame target on a device.

**Real module bodies.** The graph is synthetic: plausible JavaScript of a
realistic size, chained by `require`, but not Exact's actual modules.

## 9. Methodology, and three measurements that were wrong

All three produced *plausible* numbers, which is why they are recorded.

**The floor was reported as 28 ms.** The first run measured runtime construction
at 28 ms and the total at 33 ms — over budget before a module loads. It was the
first execution after linking, so the binary's pages were cold. Twelve further
runs put construction at a 2.5 ms median. The cold column is a single sample;
the test now says so, because a number in a table looks authoritative regardless
of its variance.

**Bytecode was reported as free.** The first bytecode run showed 570 modules
loading in 2.56 ms with the bytecode 40× smaller than the source. It was
measuring nothing: the generated modules ended in `return 0`, so `-O`
dead-code-eliminated every helper — 9.7 KB of source with 90 functions compiled
to 224 bytes containing 2. The generator now keeps every helper reachable from
`exports`, and the test asserts bytecode exceeds 2 KB per module so the same
mistake fails loudly rather than flattering the design.

**The machine was not quiet.** Twelve boot-floor samples spanned 6.5 ms to
102 ms, a 16× spread, on a laptop doing other work. Latency measurements should
take the minimum, and a figure anyone intends to defend belongs on an idle
machine — the fleet has one.

The general rule these three suggest: **a measurement that confirms what you
expected deserves the same scrutiny as one that does not.** Two of these were
caught only because the number was implausibly good.
