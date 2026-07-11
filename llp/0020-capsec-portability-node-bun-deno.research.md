# LLP 0020: Porting the Capsec Model to Node, Bun, and Deno

**Type:** Research
**Status:** Draft
**Systems:** Engine, Host ABI, Module Loader, Runtime, Build
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-07
**Related:** LLP 0013 (the compartments RFC — the model being ported); LLP 0014
(import-site grants — the authoring plane, which turns out to be portable);
LLP 0016 (architecture assessment — positions capsec against these runtimes at
the survey level); LLP 0003 (Hermes bridge); LLP 0006 (design principles)

> Provenance discipline, extending LLP 0016's: `[observed]` claims are
> verified against this tree or its LLP corpus. Claims about Node, Bun, Deno,
> V8, and JSC internals are `[inferred: external]` — written from general
> knowledge with a January 2026 cutoff, **not** verified against those source
> trees. Version-specific claims (flag names, what landed in which release)
> should be re-verified before anyone acts on this document; §Validation
> checklist lists the ones that matter. `[assessment]` marks judgment.

## Summary and verdict

Question: what would it take to implement Ibex's capability-security model —
LLP 0013's lockdown + per-package compartments + frame-derived attribution +
default-deny native boundary, with LLP 0014's generated policy — in Node,
Bun, or Deno? A fork? A carried patch series? Something else? How hard, how
slow, and what does it cost to keep alive?

The verdict, stated up front `[assessment]`:

1. **The form of the work is different in each runtime, and none of them is
   "fork the engine."** Ibex's fork lives in the *engine* (eight small Hermes
   patches) while the runtime layer was already owned. In all three targets
   that inverts: V8 and JSC expose enough via embedder API (stack provenance,
   async-context propagation, microtask hooks) that the engine needs **no
   patches at all** — but the *runtime* layer, which Ibex got for free by
   owning it, becomes the fork. Concretely: **Deno** is an *embedding project*
   (assemble a runtime from Deno's published crates; the enforcement boundary
   is pluggable by design — likely no fork of anything). **Node** is a
   *carried patch series* on the LTS line (the Electron/N|Solid model),
   anchored on its existing process-level permission code. **Bun** is a *hard
   fork of a monolith* with no chokepoint to anchor on and the fastest-moving
   upstream in the ecosystem.

2. **Every port caps below Ibex's mechanism ceiling.** Mechanism 2
   (per-package compartment globals) can never go engine-native in V8 or JSC
   at acceptable cost — global access is specialized across four JIT tiers
   against realm-coupled intrinsics, so the change Hermes absorbed in one
   interpreter case plus a `Domain` field is a realm-scale refactor there.
   All three ports therefore carry compartments as a build/load-time rewrite
   plus SES-style lockdown forever (Ibex Phase 1 semantics), while frame
   attribution and the native boundary can reach Phase-2-grade claims.

3. **Difficulty ranking: Deno < Node ≪ Bun.** Deno's op boundary and
   permission traits are the closest architectural match to Ibex's host ABI;
   Node has the pieces but scattered across a huge legacy surface; Bun has no
   permission layer at all, a product identity (speed, zero-config) that a
   default-deny boundary works against, and a release cadence that erodes
   enforcement completeness between rebases.

4. **Performance penalty guesses** (typical real app / adversarial
   microbenchmark, vs the same runtime unmodified): Node fork ~1–5% / 10–25%;
   Deno ~1–3% / 5–15%; Bun ~2–8% / 10–30% (least certain). Ibex measured
   ≈0% steady-state `[observed]` (`benches/compartment_overhead.rs`). The
   honest caveat: percentages are against different baselines — see §The
   baseline honesty paragraph.

5. **Maintenance is where the comparison is starkest.** Ibex's cost profile —
   eight patches, five Class C sites, a slow-moving pinned upstream, half-day
   pin bumps `[observed]` (LLP 0013 §Upstream tracking) — is a structural
   consequence of *what Hermes is* (single-tier interpreter, `Domain`
   abstraction, intrinsics on `Runtime`, release-branch cadence) and *what
   Ibex owns* (loader, bundler, host ABI). No port reproduces it. Estimated
   ongoing cost: Deno-as-embedding ≈ dependency-update cost (~0.05–0.15 FTE);
   Node patch series ~0.2–0.4 FTE in lockstep with security releases; Bun
   fork ~0.5–1+ FTE with completeness decaying between rebases. Ibex today:
   ~0.05–0.1 FTE `[assessment]`.

The strategic reading `[assessment]`: the portable assets are the
**conformance/red-team suite** and the **LLP 0014 authoring plane** (both
runtime-independent), not the engine patches. If the model is ever ported to
prove generality, Deno is the demonstration target; Bun should only ever get
the userland layer; and the fact that no port matches the Hermes cost profile
is itself the moat LLP 0016 §S1 describes, restated from the other side.

## What the model actually requires

Six load-bearing requirements, distilled from LLP 0013's mechanisms and the
hardening history recorded in its Implementation status. Each port is scored
against these. Labels CS-1…CS-6 are used throughout.

- **CS-1 — Unforgeable execution provenance.** Host-boundary checks must
  identify the calling *package* from engine truth (executing code identity),
  not from anything JS can set — including across async boundaries
  (schedule-time principal capture; the patch 0007/0008 + ENG-22759 history
  shows this is the hard half `[observed]` LLP 0013 §Implementation status).
- **CS-2 — A native default-deny boundary.** Parameterized capability checks
  (`fs:read:<path>`, `network:fetch:<host>`, `env:read:<key>`) at a layer
  outside the JS reachability graph, plus possession-checked handles for
  delegation (LLP 0013 §Delegation).
- **CS-3 — A closed, frozen shared surface.** Lockdown of shared intrinsics,
  evaluator taming, and a *closed global inventory* — every ambient global
  classified and the escape hatches sealed (Mechanism 1 + the Phase 1
  inventory).
- **CS-4 — Per-package global scoping** (Mechanism 2): bare globals and
  `globalThis` resolve per package to an endowment-populated private global,
  while intrinsics stay shared so npm object flow survives.
- **CS-5 — Loader-level import gating and provenance-preserving module
  identity.** The loader knows which package is requesting every import and
  can deny it (Policy surface 3); and module→package identity must survive
  to runtime — the per-package-chunks lesson (ENG-22681): a flat bundle
  collapses attribution `[observed]`.
- **CS-6 — A policy plane outside JS reach, fed by the generated artifact.**
  The LLP 0014 authoring plane (import-site grants → drift-checked artifact)
  is build-time static analysis over source + lockfile — notably
  **runtime-independent**.

## The engine substrate: Hermes vs V8 vs JSC

The per-runtime analyses share engine facts; stated once here.
`[inferred: external]` throughout except the Hermes column.

| Property | Hermes (Ibex pin) | V8 (Node, Deno) | JSC (Bun) |
|---|---|---|---|
| Execution tiers | 1 (interpreter; AOT via Static Hermes trajectory) | 4 (Ignition, Sparkplug, Maglev, TurboFan) | 4 (LLInt, Baseline, DFG, FTL) |
| Global resolution | one interpreter case (`GetGlobalObject`) `[observed]` (LLP 0013 §Mechanism 2) | per-tier ICs, script contexts, global property cells | per-tier `resolve_scope`/`get_from_scope` + watchpoints |
| Intrinsics live on | `Runtime` (84 fields), *separate from* the JS global | the native `Context` (= the realm), coupled to its global | `JSGlobalObject`, coupled to its global |
| Code→provenance | `CodeBlock → RuntimeModule → Domain` (+ patched `packageId_`) | `StackFrame → ScriptId` via **public** `v8::StackTrace` API | `CodeBlock → SourceProvider/SourceOrigin` via internal `StackVisitor` |
| Async schedule hook | none stock — patches 0007/0008 added capture `[observed]` | continuation-preserved embedder data (CPED) — a structural chokepoint; `PromiseHook` as the slow legacy path | embedder `queueMicrotask` hook on the global object table (per-job, schedule-time) |
| Frozen intrinsics | verified viable on-pin `[observed]` (LLP 0013 Phase 0 findings) | production-proven (SES/Endo on Node; MetaMask Snaps) | production-proven (SES in Safari/browser contexts) |
| Engine patches needed | yes — 8 small ones | **none** (embedder API suffices) | none strictly (runtime-side hooks suffice) |

Four consequences that shape everything below:

**Mechanism 2 does not go native in V8 or JSC — ever, at acceptable cost.**
`[assessment]` Hermes made native compartments cheap because global
resolution is one interpreter case and intrinsics live on `Runtime`, not the
global object — re-pointing "which global does this frame see" touched five
surgical sites total `[observed]` (LLP 0013 §Upstream tracking). In V8 the
same question is answered in four tiers of inline caches, script contexts,
and property-cell fast paths, all specialized against the native context
that *is* the realm; JSC is isomorphic (scope-resolution ops plus
watchpoint-based global specialization per tier). Redirecting global loads
by code provenance means either per-compartment code duplication (defeats
code caching, multiplies JIT footprint) or new IC machinery in every tier —
exactly the "maintaining a divergent engine" line LLP 0013's patch-shape
discipline prohibits. Every port therefore carries CS-4 as a **build/load
time free-global rewrite** (the Ibex Phase 1 implementation, which Ibex
still ships alongside the native path) plus SES lockdown with evaluator
taming. This is a real ceiling: the sloppy-`this` escape and `eval` binding
close via strict-mode emission and taming rather than natively, unbundled
third-party code must pass through a rewriting loader, and the rewrite's
compat deltas (direct-eval semantics, strict-mode emission) become permanent
rather than a Phase 1 way-station.

**Frame attribution is available without engine forks — with new forgery
channels to close.** V8 exposes stack capture with per-frame `ScriptId`
through public embedder API; a loader that records ScriptId→package at
compile time gets engine-truth attribution. The subtlety: attribution must
key on `ScriptId`/script identity, **never** on script *names* — a
`//# sourceURL=` magic comment lets any eval'd code adopt an arbitrary name
(the V8-world analog of the forgeable thread-local this model exists to
kill). Eval'd code gets fresh ScriptIds; under lockdown the evaluators are
tamed anyway, and V8's code-generation-from-strings callback gives the
embedder a gate on every `eval`/`Function` compilation. JSC's equivalent
walk (`StackVisitor`, CodeOrigin-aware through DFG/FTL inlining) is internal
API — but Bun already links WebKit internals freely, and Bun's own
`bun:jsc` module exposes a `callerSourceOrigin()` today, which is an
existence proof of per-frame source provenance in that stack
`[inferred: external]`.

**Async scheduler capture has a *better* story on V8 than the one Ibex had
to build.** Ibex closed the detached-deputy family channel-by-channel —
Promise queue in the VM (patch 0008), embedder timer queues host-side
(ENG-22759) — because stock Hermes has no async-context primitive
`[observed]`. V8 ships one: continuation-preserved embedder data propagates
a value across promise reactions and `await` resumptions in the engine
itself, and Node's modern `AsyncLocalStorage` implementation rides it. A
port would set the current principal into CPED at schedule time and read it
at check time — the structural chokepoint LLP 0016 R2 asks for, essentially
for free. JSC has no public CPED equivalent `[inferred: external]`; a Bun
port would capture at the embedder `queueMicrotask` hook (schedule-time,
caller frames still live — conceptually the same move as patch 0008, made
at a hook that already exists) plus Bun's own host queues. Bun's historical
`AsyncLocalStorage` correctness troubles suggest this plumbing is the risky
part there `[inferred: external]`.

**JIT tiers complicate the boundary, not the walk.** Public stack APIs
handle inlined frames correctly (deopt metadata), so correctness survives
optimization. The costs show up elsewhere: (a) stack capture costs hundreds
of nanoseconds to microseconds per call, so per-call attribution belongs on
acquisition-shaped operations (open, connect, spawn) rather than per-read —
which is how these runtimes already meter permissions (fd/resource-id
models are possession handles, CS-2's shape, already idiomatic); (b) V8
"fast API" op paths (Deno's fast ops, Node's fast-path bindings) can't
capture stacks mid-call, so capability-gated ops get demoted to the slow
path when capsec is armed — a real but bounded cost since gated ops are
I/O-shaped.

## Node.js

### What exists to build on

`[inferred: external]` Node is further along than its reputation suggests:

- **A process-level permission model** (`--permission`, with
  `--allow-fs-read/--allow-fs-write/--allow-child-process/--allow-worker/
  --allow-addons/--allow-wasi`), enforced in C++ at the binding layer with a
  central check surface. It is instance-granularity (LLP 0016's table) and
  incomplete for capsec purposes — network gating was absent or experimental
  and **env reads are not gated at all** as of the knowledge cutoff — but it
  is an anchor: the fork's per-package dimension extends an existing
  chokepoint rather than inventing one.
- **`--frozen-intrinsics`** — an experimental SES-lite lockdown flag; plus
  Node core's **primordials** discipline (internal frozen copies of
  intrinsics), which means the deputy layer (Node's large internal JS) was
  already written to survive a mutated-intrinsics world. That materially
  shrinks the CS-3 TCB problem relative to a naive reading.
- **Synchronous module customization hooks** (`module.registerHooks`)
  covering both `require` and `import` — the CS-5 gate and the CS-4 rewrite
  injection point, in-process, without a fork.
- **CPED-backed async context** (`AsyncContextFrame`, default in current
  LTS) — the CS-1 async chokepoint, already battle-tested by
  `AsyncLocalStorage`.

### The ladder: three deliverable shapes

**(a) Userland only — exists today, weeks of work.** SES lockdown +
LavaMoat-style per-package compartments is a shipping ecosystem on Node;
the genuinely new work is porting the **LLP 0014 authoring plane** (grants
declared at root import sites, compiled to a drift-checked artifact) to
drive LavaMoat-shaped enforcement instead of usage-inferred policy — the
policy-direction difference LLP 0016 calls the deep one. Ceiling: Ibex
Phase 1 (reachability containment, forgeable attribution, no native
boundary). Estimate: 2–6 weeks to a credible demo `[assessment]`.

**(b) Hybrid: preload + native addon, no fork.** A boot preload freezes
intrinsics, installs the rewrite via `registerHooks`, wraps the builtin
deputies (`fs`, `net`, `child_process`, …) so every privileged call funnels
through a check implemented in a **native addon** that walks the V8 stack
(ScriptId→package map maintained by the loader hooks) and consults a policy
engine living in the addon (outside JS reach). The process-level permission
model runs as the outer wall; `vm`, `inspector`, `worker_threads`, addons,
and WASI are denied to package principals via the import gate. Ceiling:
*nearly* Phase 2 — attribution is engine truth, but the enforcement point is
a trusted same-realm JS deputy layer rather than the C++ boundary, so the
claim rests on lockdown + inventory closure protecting the deputies
(LavaMoat-class reachability argument) with unforgeable attribution layered
on. Estimate: +1–2 months over (a) `[assessment]`.

**(c) Carried patch series — the real Phase-2 answer.** The Electron /
N|Solid precedent: a patch stack on the LTS line, rebased per release.
Contents `[assessment]`:

1. **Principal dimension in the permission layer**: the C++ permission
   checks take a caller principal; a per-package policy table (the
   `CapabilityManager` equivalent) lives beside the existing process-level
   model, which remains the outer wall.
2. **Frame attribution**: nearest-non-internal-frame walk via the stack API,
   keyed by ScriptId→package registered from the (patched) loader;
   runtime-principal transparency for Node's internal JS (its scripts are
   enumerable — same deputy-transparency rule as Ibex's `0xFFFFFFFF`
   `[observed]` LLP 0013 §Mechanism 3); fail-closed no-user-frame sentinel.
3. **Async capture** on CPED; host-queue coverage for timers/`nextTick`/
   `setImmediate` (Node-owned queues, patched at their drain sites — the
   ENG-22759 lesson applied on day one).
4. **New gates Ibex has that Node lacks**: `env:read:<key>` (Node's
   `process.env` is a real-time binding proxy in C++ — gateable), network
   (fetch/undici + `net`/`dgram`/`tls`), plus DNS (`network:resolve`,
   the ENG-22903 lesson).
5. **Escape-hatch closure** under enforce: `vm`, `inspector` (self-inspection
   is arbitrary code injection), `process.binding`, `--expose-internals`,
   diagnostics channels that leak handles; workers spawn with inherited
   policy + hooks natively rather than by execArgv convention.
6. **CS-4/CS-3 carried from the hybrid**: rewrite in the loader, lockdown at
   boot. No engine patch.

**The bundler problem is Node's distinctive structural weakness for CS-5.**
`[assessment]` Ibex owns its bundler and made enforce/audit auto-enable
per-package chunks (ENG-22681) `[observed]`; Deno executes source graphs
directly. Node apps arrive *pre-bundled by arbitrary tools*, and a webpack
output file is one Script — attribution collapses to the app principal
exactly like Ibex's flat-bundle case. The port either requires unbundled
node_modules execution (viable server-side, where node_modules-on-disk is
normal), or ships per-bundler plugins (the LavaMoat ecosystem tax), or
declares bundled apps out of scope for per-package claims. There is no
fourth option, because provenance destroyed at build time cannot be
recovered at run time.

### Difficulty, performance, maintenance

**Difficulty**: fork route to a credible Phase-2 demo: ~3–6 months for one
person fluent in Node internals, agent-assisted; production-grade coverage
(binding-surface audit, escape hatches, compat corpus) 9–18 months elapsed
`[assessment]`. The dominant cost is not any single mechanism — it is the
*breadth* of a 15-year-old binding surface that was never enumerated against
this threat model, the job Ibex's narrow ABI (LLP 0002) made tractable.

**Performance guess** `[assessment]`: typical real app ~1–5% (lockdown ≈
free at steady state; rewrite adds one property load per free-global access,
IC-friendly; CPED cost low single digits on promise-heavy code; boundary
checks amortized behind fd/handle acquisition). Adversarial micro: 10–25%
on syscall-per-iteration loops (per-call stack capture) and on code that
hammers rewritten globals in hot loops. Mitigations mirror Ibex's: memoized
import decisions, capability bitmask fast paths, check-at-open.

**Maintenance** `[assessment]`: ~0.2–0.4 FTE. Two majors a year plus
security releases you must ship *same-day* (server runtime; the fork
inherits the CVE clock — a pressure Ibex's held-pin posture deliberately
avoids `[observed]` LLP 0013 §Contingencies). Churn concentrates in the ESM
loader (rewritten repeatedly in recent memory) and the still-evolving
permission model; the V8-facing code uses only public embedder API, so the
engine never joins the fork. Anchoring patches on the permission layer keeps
most of the series Class B (insertion points at existing check sites), but
the binding surface guarantees a steady trickle of new ungated paths —
a ratchet CI job ("no privileged binding without a classified check", the
LLP 0016 R10 checklist as code) is mandatory, not optional.

## Deno

### The closest architectural match — and probably not a fork

`[inferred: external]` Deno's architecture rhymes with Ibex's host ABI to a
striking degree:

- **All privileged operations pass through ops** — a single generated
  JS↔Rust boundary (`deno_core`), with permission checks against a central
  `PermissionsContainer` inside the privileged op implementations. This is
  CS-2's chokepoint, already built, already parameterized: Deno's permission
  descriptors (`--allow-read=/path`, `--allow-net=host`, `--allow-env=KEY`,
  `--allow-run`, `--allow-ffi`) map nearly 1:1 onto Ibex capability strings
  `[observed]` for the Ibex side (`src/host/capability_bits.rs`).
- **Interactive tri-state prompts** (allow/deny/prompt at runtime) — Ibex's
  Phase 4 tri-state grant status, already shipped at instance granularity.
- **Per-worker permission subsets** — an existing precedent for
  sub-instance permission scoping in the product's own vocabulary.
- **The module graph executes unbundled** — `deno run` preserves per-module
  identity end-to-end, so CS-5 provenance survives by default; and the
  loader is embedder-owned (a `ModuleLoader` trait), so import gating is an
  implementation of an existing extension point, not a patch.
- **Resource table**: rid-based resources are possession handles — CS-2's
  handle model, idiomatic since day one. Checks meter acquisition;
  steady-state reads don't re-walk stacks.
- **Startup snapshots**: intrinsics frozen *before* snapshotting bake CS-3's
  lockdown into the heap image — boot cost ≈ zero, an option no other target
  has. `deno_core`'s internal JS also adopted the primordials discipline.

The deepest structural fact `[inferred: external]`: Deno's extension crates
are **parameterized over permission traits** (`FsPermissions`,
`NetPermissions`, `FetchPermissions`, …) that the *embedder* implements, and
the module loader and snapshot are likewise embedder-supplied. So the
delivery shape is not "fork Deno": it is **assemble a runtime binary from
Deno's published crates** — `deno_core` + the `ext/*` stack + a custom
permissions implementation that adds the principal dimension + a custom
`ModuleLoader` that does import gating and the CS-4 rewrite (an swc pass,
already in the toolchain) — exactly the relationship Ibex has to Hermes:
an embedding with owned policy, not a divergent copy. The trait impls
capture the caller principal by walking the V8 stack (ScriptId→module via
the loader's records; isolate handle reachable from op state or a
thread-local) and consult CPED for the scheduling principal.

What a fork-less build cannot get: if some op or a corner of the
node-compat layer checks permissions outside the pluggable traits, those
sites need upstream PRs or a small patch set. The **node-compat extension is
the coverage risk** — it is large, it reimplements Node surface at speed,
and its permission plumbing is the least uniform part of the stack
`[inferred: external]`; the coverage audit there is the long pole.

### The structural bonus: an enumerable boundary

The op registry makes LLP 0016's R2 enumerator *natural*: every op is
declared, so CI can require every privileged op to carry a capability
classification and a principal-aware check — the "no queue without capture,
no op without a class" invariant as a build failure. Ibex approximates this
by review discipline; Deno's architecture would enforce it mechanically
`[assessment]`. This is the only target where enforcement *completeness* has
a structural story rather than a vigilance story.

### Difficulty, performance, maintenance

**Difficulty** `[assessment]`: crate-assembly demo with frame attribution,
per-package permissions on fs/net/env/run, import gating, lockdown-in-
snapshot, and the rewrite: ~4–8 weeks for one person fluent in Rust and
deno_core, agent-assisted. Production-grade: 4–8 months, dominated by the
node-compat audit and the compat corpus, not by mechanism.

**Performance guess** `[assessment]`: typical app ~1–3%. Lockdown is free at
boot (snapshot) and near-free at steady state; gated ops already pay a
permission check, so the delta is the stack walk on acquisition-shaped ops
plus fast-op demotion for gated ops when capsec is armed; CPED cost as on
Node. Adversarial micro: 5–15% (tight loops over gated ops that were
previously fast-path).

**Maintenance** `[assessment]`: the best of the three by a distance.
Crate-assembly tracks published versions — dependency updates, not rebases;
the Rust type system turns upstream drift into compile errors rather than
silent holes; ~0.05–0.15 FTE. A patch-set variant (if trait coverage gaps
force it) still lands around 0.15–0.3 FTE against a ~6-weekly cadence.
Upstreaming odds are also best-of-three: Deno's company narrative is
security and supply chain (JSR provenance, permission UX), and "per-package
permissions" is a legible extension of their existing story — worth an
exploratory conversation before writing any code, since every upstreamed
trait hook deletes carried surface `[assessment]`.

## Bun

### The mismatch, stated plainly

`[inferred: external]` throughout; `[assessment]` where judged.

Bun has the strongest *loader-side* story and the weakest *boundary-side*
story, and the boundary is where the security lives:

- **Loader/CS-4/CS-5: genuinely good.** Bun transpiles every file through
  its own transpiler at load time — a natural injection point for the
  per-package rewrite, with full provenance (Bun owns resolution end to
  end). Tagging JSC `SourceOrigin`s with package identity is squarely within
  what Bun already does with WebKit internals; `bun:jsc`'s
  `callerSourceOrigin()` shows the frame-provenance primitive already
  surfaced once. `StackVisitor` handles DFG/FTL inlining; the embedder
  `queueMicrotask` hook enables schedule-time capture without touching JSC.
- **Boundary/CS-2: nothing to anchor on.** Bun has **no permission model at
  all** (LLP 0016's table row is "none / — / —" `[observed]` for the row,
  `[inferred: external]` for the fact). Privileged operations are
  implemented as many independent Zig fast paths engineered specifically to
  minimize per-call overhead — the opposite of a chokepoint. The port's
  first job is to *invent* the central boundary, then herd every syscall
  site through it: `Bun.file`/`Bun.write`, `Bun.serve`, sockets, `Bun.$`
  (a shell!), `bun:ffi` (ungated native code loading — game over if missed),
  `bun:sqlite`, the spawn family, plus the node-compat layer's own native
  paths. Each is an independently implemented site; nothing forces new ones
  through the boundary.
- **CS-3**: SES-style lockdown on JSC is proven; Bun's internal JS layer is
  comparatively thin (much of the runtime is Zig), which modestly shrinks
  the deputy-JS TCB relative to Node — the one security-relevant advantage.
- **CS-1 async**: no CPED equivalent; capture rides the microtask hook and
  Bun's own event-loop queues. Bun's `AsyncLocalStorage` correctness history
  suggests the async plumbing is where soundness bugs would live.

**Form of the work**: a hard fork. Bun is a monolith with no supported
embedding surface and no crate/library form; there is no "assemble from
parts" route and no permission layer to patch. It would be a fork of a
codebase that ships large diffs on a near-weekly cadence, in Zig (smaller
contributor and reviewer pool), which itself carries a WebKit fork
(precedent that carrying engine patches is *possible* — and evidence of
what that costs a team). Every upstream release adds API surface that lands
ungated by default; enforcement completeness *decays between rebases*
unless upstream cooperates, and a default-deny boundary runs directly
against the product identity (speed above all) that drives that cadence —
so cooperation is unlikely `[assessment]`.

### Difficulty, performance, maintenance

**Difficulty** `[assessment]`: 3–6 months to a demo that gates the core
surfaces; 12–18+ months to defensible coverage — and "done" never stabilizes
(see above). **Performance guess**: 2–8% typical / 10–30% adversarial, the
least certain numbers in this document — Bun's margins over Node come
precisely from the fast paths a boundary must interpose on, so the port
both costs more *and* shows up more visibly in Bun's own benchmarks.
**Maintenance**: 0.5–1+ FTE indefinitely; the fork is a permanent divergent
runtime, not a patch series — it violates the spirit of the Class-C budget
discipline (LLP 0013 §Patch shape discipline) from day one.

**Recommendation**: Bun gets the userland layer (SES + rewrite via its
plugin/transpiler hooks + the LLP 0014 artifact for policy) or nothing.
Phase-1 claims only, stated honestly per the claim-ceiling table
`[assessment]`.

## Comparison

### The table

`[assessment]` throughout; Ibex row `[observed]` where cited.

| | **Ibex / Hermes** | **Node** | **Deno** | **Bun** |
|---|---|---|---|---|
| Form of the work | 8-patch engine series; runtime already owned `[observed]` | carried patch series on LTS (Electron/N\|Solid model) | **embedding**: assemble from published crates; little or no fork | hard fork of a monolith |
| Engine patches | 8 (5 Class C sites) `[observed]` | none (public V8 API) | none (public V8 API) | none strictly (WebKit-internal calls, Bun-normal) |
| CS-1 attribution | native frame walk + schedule capture (patches) | V8 stack API + ScriptId map + CPED | same, inside op layer / permission traits | JSC StackVisitor + microtask-hook capture |
| CS-2 boundary | existing host ABI, narrow `[observed]` (LLP 0002) | extend the permission layer; add env/net gates; wide legacy surface | existing op + permission-trait chokepoint; near-1:1 semantics | must be invented site-by-site |
| CS-4 compartments | build-time **and** engine-native `[observed]` | build/load-time rewrite only, forever | rewrite in owned loader (swc), forever | rewrite in owned transpiler, forever |
| CS-5 provenance | owned bundler; per-package chunks auto-enabled `[observed]` | the bundler problem: unbundled-only, per-bundler plugins, or reduced claims | source graphs run unbundled — best-in-class | owned loader good; `bun build` bundles re-open the hazard |
| Claim ceiling | Phase 3+ (native) `[observed]` | Phase 2 (fork) / ~Phase 2-minus (hybrid) / Phase 1 (userland) | Phase 2 | Phase 2 on paper; completeness decays; Phase 1 recommended |
| Demo effort | (landed) | 3–6 months (fork route) | **4–8 weeks** | 3–6 months |
| Production effort | (in progress: evidence phase) | 9–18 months | 4–8 months | 12–18+ months, unstable "done" |
| Perf, typical / micro | ≈0% measured `[observed]` / boot-only | 1–5% / 10–25% | 1–3% / 5–15% | 2–8% / 10–30% |
| Ongoing maintenance | ~0.05–0.1 FTE | ~0.2–0.4 FTE + CVE-clock lockstep | ~0.05–0.15 FTE (crates) | ~0.5–1+ FTE |
| Upstream cadence risk | pinned, slow branch; bump ≤ half-day target `[observed]` | 2 majors/yr + security releases; loader churn | ~6-week minors; Rust surfaces drift loudly | near-weekly; large diffs; adversarial fit |
| Upstreaming odds | plausible for primitives (MetaMask interest) `[observed]` (LLP 0013) | low (per-package rejected historically; policy mechanism removed) | **best of three** (supply-chain narrative fit) | ≈ zero (identity conflict) |

### Why Ibex/Hermes is structurally cheap — the update story, grounded

The user-visible intuition — "updating Ibex generally won't be too bad" — is
correct, and it is worth recording *why* it is structural rather than
fortunate, because none of the five reasons transfers to a port
`[assessment]`:

1. **One execution tier.** Every capsec-relevant semantic (global
   resolution, frame identity, eval binding) exists in exactly one place in
   an interpreter. V8/JSC ports interact with four tiers each — which is
   precisely why their engine work stays confined to public APIs and CS-4
   never goes native.
2. **The engine had the right abstractions lying around.** `Domain` and
   `RuntimeModule` gave per-package identity a place to live (one field);
   intrinsics-on-`Runtime` made same-realm compartments a re-pointing
   exercise. The patches *annotate* Hermes's architecture rather than
   fighting it — that is what keeps them Class A/B with five Class C sites
   `[observed]` (LLP 0013 §Upstream tracking).
3. **Slow, pinned upstream with a held-pin option.** Hermes stable branches
   move slowly; Ibex bumps on its own schedule and can hold a pin through
   upstream turbulence `[observed]` (LLP 0013 §Contingencies). A Node fork
   inherits Node's security-release clock; a Bun fork inherits a weekly
   treadmill. (The trade: a server runtime *must* chase CVEs; an embedded
   runtime with instance isolation can afford a held pin — the cost profile
   difference is partly a deployment-model difference.)
4. **Full-stack ownership.** Loader, bundler, host ABI, builtins are all in
   this repo, so per-package chunking, import gating, endowment wiring, and
   deputy transparency were integration work, not negotiation with an
   ecosystem. Node's bundler problem and Bun's boundary problem are both
   "the port doesn't own a layer Ibex owns."
5. **A narrow, enumerable host surface.** LLP 0002's small ABI and the
   subtractive worklet posture (LLP 0016 §Layer 1) made the boundary
   auditable. Node's binding surface and Bun's fast-path spread are the
   opposing cautionary cases; Deno's op registry is the one comparable
   surface, which is exactly why Deno ranks best.

The re-derivation posture completes the story: the durable asset is the
spec plus the conformance suite, not the diff `[observed]` (LLP 0013
§Upstream tracking) — so even the worst Hermes-side outcome (Static Hermes
reshapes the interpreter) is a re-derivation measured in weeks. A Bun fork
has no equivalent floor: its "spec" would be chasing an undocumented,
fast-moving runtime surface.

### The baseline honesty paragraph

Percent overheads above are against **different baselines** and should not
be compared across columns naively `[assessment]`. Hermes is an interpreter:
on CPU-bound code, stock Node/Bun/Deno are commonly several-fold faster than
stock Hermes, so "capsec-Node at 5% overhead" still executes compute-heavy
workloads much faster than Ibex at 0%. Ibex's ≈0% is the statement that
*capsec is free where Ibex runs*, not that Ibex wins throughput contests;
Ibex's consumers chose Hermes for embeddability, startup, memory, and AOT
bytecode (LLP 0000; LLP 0003), and the Static Hermes trajectory moves the
compute baseline over time. On I/O-bound real workloads the gap compresses
and the overhead percentages converge toward the syscall-metering costs,
which are similar everywhere. The honest cross-runtime statement: **the
capsec *mechanism* costs roughly the same few percent anywhere it is built;
what differs is who pays an engine-baseline tax and who pays a
fork-maintenance tax.**

## What "something else" looks like — the portable assets

Three pieces of the system port without any runtime work, and they are the
highest-leverage moves if the goal is influence rather than product
`[assessment]`:

1. **The LLP 0014 authoring plane.** Import-site grants → generated,
   provenance-carrying, drift-checked artifact is static analysis over
   source + lockfile. It could drive LavaMoat policy on stock Node *today*,
   replacing usage-inferred policy with declared grants — attacking the
   maintenance-economics layer (LLP 0016 §S2) on a runtime Ibex doesn't
   ship. A small `@ibex/policy` toolchain targeting LavaMoat as the
   enforcement substrate would be the cheapest way to test whether the
   authoring model wins adoption arguments on neutral ground.
2. **The conformance/red-team suite.** Impersonation, laundering, detached
   deputies, symlink escapes, bundling collapses — the suite defines "done"
   for *any* implementation (it is already the fork's re-derivation oracle
   `[observed]` LLP 0013). Porting the suite before porting any mechanism
   converts every port estimate above from faith to measurement, and a
   published cross-runtime scorecard is itself a differentiation artifact.
3. **The threat-model language.** Supply-chain integrity, not sandbox; claim
   ceilings per phase; residual-risk honesty. Any port that skips this
   inherits the overclaiming risk (LLP 0013 Risk 3) with none of the
   discipline.

## Recommendations

`[assessment]`, ordered by leverage:

- **R1 — Do not port for product reasons.** No port reaches Ibex's
  mechanism ceiling (CS-4 native) or its cost profile, and Ibex's consumers
  (Exact, Snapback) already run on Ibex. The comparison in this document is
  the moat statement of LLP 0016 §S1 with numbers attached; its main use is
  strategic clarity, not a build plan.
- **R2 — If generality must be demonstrated, demonstrate on Deno.** The
  crate-assembly route is 4–8 weeks to a demo, produces no fork, exercises
  the portable suite, and lands in the runtime whose architecture flatters
  the model most. Open the upstream conversation first — per-package
  permissions fit Deno's public narrative, and an upstreamed trait hook is
  cheaper than any carried code.
- **R3 — Ship the authoring plane to Node as tooling, not a runtime.** The
  LLP 0014 generator targeting LavaMoat (per §Portable assets) tests the
  most novel part of the system on the largest ecosystem for weeks of work,
  with zero fork liability.
- **R4 — Port the conformance suite before any mechanism, wherever a port
  happens.** It is the oracle for every estimate in this document.
- **R5 — Leave Bun alone** beyond the userland layer, and say so when asked:
  the honest claim ceiling there is Phase 1, and the fork economics are the
  worst available.
- **R6 — Re-verify the external claims before acting** (§Validation
  checklist). This document's engine-API claims are load-bearing for the
  estimates and were written from a January 2026 cutoff.

## Validation checklist

The `[inferred: external]` claims that most change the conclusions if wrong,
each checkable in under an hour against current sources:

1. Node: current status of network and env permissions in `--permission`;
   `module.registerHooks` stability and CJS coverage; `AsyncContextFrame`
   (CPED) default status and measured overhead.
2. V8: `v8::StackTrace`/`ScriptId` capture cost at small frame counts;
   CPED propagation semantics across all deferral channels (thenables,
   `queueMicrotask`, async generators); fast-API-call restrictions.
3. Deno: which extension crates still take embedder permission traits and
   whether all privileged ops route through them; node-compat permission
   plumbing uniformity; rusty_v8 exposure of stack + CPED APIs; op registry
   introspection for the completeness enumerator.
4. JSC/Bun: embedder `queueMicrotask` hook semantics (schedule-time, caller
   frames live?); `SourceOrigin`/`sourceURL` forgery interaction in
   `StackVisitor` output; Bun's current plugin hooks' ability to transform
   all loads including node_modules.
5. Ecosystem: LavaMoat's current policy schema (R3 feasibility); whether any
   runtime has since shipped sub-process package-granularity permissions
   (which would obsolete parts of this analysis).

## Open questions

1. **Package identity outside node_modules.** Ibex principals are
   `name@version` derived from package.json boundaries `[observed]`
   (LLP 0013 Resolved Q1). Deno's URL/JSR imports and Bun's non-npm loaders
   need an equivalent boundary rule (JSR scope? URL origin? — the selector/
   locator split ports, the boundary heuristic does not).
2. **CPED contention.** Capsec wants CPED for the scheduling principal;
   `AsyncLocalStorage` and (eventually) TC39 AsyncContext want the same
   slot. Composition (a frame object carrying both) is straightforward but
   must be owned by the port, and misuse is a laundering channel.
3. **Enforcement of the rewrite on already-bundled Node apps** — is there
   any recoverable provenance signal (source maps? package boundaries in
   comments?) trustworthy enough to attribute inside a foreign bundle, or
   is unbundled-only the permanent answer? (Lean: unbundled-only; source
   maps are attacker-controlled `[assessment]`.)
4. **Whether a Deno demo should share the policy artifact format** with
   Ibex byte-for-byte (one generator, two enforcement substrates) or merely
   the schema — sharing the generator is the stronger proof of LLP 0014's
   claim that authoring is runtime-independent.

## References

- LLP 0013 (mechanisms, threat model, patch stack, upstream tracking);
  LLP 0014 (authoring plane); LLP 0016 (assessment; the cross-runtime
  survey table this document expands); LLP 0002 (host ABI); LLP 0003
  (Hermes bridge); LLP 0007 (owned bundler pipeline).
- External `[inferred]`: Node.js permission model, `--frozen-intrinsics`,
  module customization hooks, primordials, AsyncContextFrame/
  AsyncLocalStorage; V8 embedder APIs (StackTrace/ScriptId, continuation-
  preserved embedder data, code-generation-from-strings callback, fast API
  calls, snapshots); Deno (`deno_core`, ops, `PermissionsContainer`,
  extension permission traits, `ModuleLoader`, per-worker permissions,
  prompts, JSR); Bun (Zig runtime, WebKit fork, transpiler/plugin hooks,
  `bun:jsc`, `bun:ffi`, `Bun.$`); JSC (StackVisitor, SourceProvider/
  SourceOrigin, global-object method table microtask hook); Agoric SES/Endo;
  MetaMask LavaMoat (incl. lavamoat-node and bundler plugins); Electron and
  N|Solid as carried-patch precedents; vm2 escape history (negative
  precedent for same-realm membranes, per LLP 0016).
