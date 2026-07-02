# LLP 0013: Per-Package Capability Enforcement via Hardened Compartments

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Host ABI, Module Loader, Runtime, Build
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-02
**Revised:** 2026-07-02 (author decisions recorded on questions 1, 2, 5, 6, 7)
**Related:** LLP 0000; LLP 0002 (host ABI); LLP 0003 (Hermes bridge); LLP 0004 (module loading); LLP 0006 (design principles); LLP 0007 (transform pipeline)

> Citation convention: `hermes:` paths refer to the pinned Hermes source
> (`IBEX_HERMES_SOURCE_REF`, currently `260318099.0.0-stable`
> `[observed]` (`scripts/hermes-version.sh:9-10`)), verified against the local
> build checkout of that ref. Line numbers drift with the pin; treat them as
> anchors, not contracts.

## Summary

Ibex's capability model enforces at two granularities today: the runtime
instance (sound) and the module (advisory — trivially forgeable, see
[Current state](#current-state)). This RFC scopes the work to make
**per-package** capability enforcement sound for a **supply-chain threat
model**, using the hardened-JavaScript compartment design rather than
realm-per-module:

1. **Lockdown** — freeze all shared intrinsics at boot, after Ibex's own
   repairs/builtins install.
2. **Per-package compartment globals** — each package's code resolves bare
   globals against a private global object populated only with its policy's
   endowments; intrinsics stay shared (and frozen), so normal cross-package
   object flow, classes, and `instanceof` keep working.
3. **Frame-derived attribution** — host-boundary capability checks identify
   the caller from the executing bytecode frame
   (`CodeBlock → RuntimeModule → package`), which JS cannot forge, replacing
   the current thread-local module id.

The plan is phased so that the first two phases require **no Hermes fork** and
deliver most of the supply-chain value (build-time compartmentalization via
the LLP 0007 bundler pipeline, plus audit-mode rollout). The fork phases make
the design native: frame attribution, native lockdown, and per-`Domain`
global resolution — a surgical change, not a realm refactor. A dedicated
section defines how the fork tracks upstream Hermes releases and how the work
is re-derived cheaply if upstream shifts under it.

All phases are green-lit (author decision, 2026-07-02 — see Resolved
questions §6): the fork phases proceed without waiting on upstream's Static
Hermes trajectory, with re-derivation as the plan of record when upstream
reshapes the interpreter. The Phase 0–1 kill criteria remain in force as
evidence-based aborts.

## Motivation

### The per-module layer is currently advisory, not enforcement

The capability model's instance-level story is sound: policy lives in Rust
behind the C ABI (`src/host/capability.rs`; `src/host/abi.rs:729-745`),
outside the JS reachability graph. The per-module story is not:

- Attribution is a thread-local integer set around module evaluation
  `[observed]` (`src/engine/hermes_runtime.cc:172`;
  `src/engine/hermes_runtime_internal.h:168-179`). JS control flow does not
  respect module boundaries: a stored callback or patched prototype method
  executes under whatever id the loader last set.
- The setter and a grant function are ordinary mutable globals reachable by
  any module: `__exactSetActiveModuleId` `[observed]`
  (`src/engine/hermes_runtime.cc:962-979`;
  `src/engine/bootstrap/module-loader.js:4077-4082` calls it via
  `globalThis`) and `__exactGrantCapability` `[observed]`
  (`src/engine/hermes_runtime_crypto.cc:4653-4670`). One line of user code
  impersonates module 0 or grants itself anything.
- Shared mutable intrinsics allow identity theft without touching either
  global: patch `Array.prototype.map`, and the patch body runs during a
  privileged module's turn with that module's attribution.
- Objects carry authority: once any module legitimately holds a handle, it
  can pass it anywhere; check-time enforcement never sees the flow.

### Why per-package enforcement is worth having

- **Supply-chain containment** is the concrete goal: a compromised transitive
  npm dependency should not be able to read `~/.ssh`, exfiltrate `process.env`,
  or wrap the host bridge, even though the app can. This is the attack class
  behind recurring npm incidents, and it is the one a runtime can actually
  address at package granularity.
- **Ibex's consumers raise the stakes**: Exact runs third-party experiences,
  Snapback builds on the same runtime, and agent-generated code is a growing
  input. `[inferred: these are the same trust posture — code the app author
  did not write, running with the app's ambient authority.]`
- **Instance isolation stays layer 1.** Genuinely hostile code (an Exact
  view) gets its own runtime instance with its own `HostConfig`. Compartments
  are layer 2, inside an instance, for the dependency graph the app chose to
  install. The two layers answer different questions and neither substitutes
  for the other.

### Why now, and why this design

Prior analysis in this corpus (LLP 0006 §"Capability-gated host") and the
conversation leading to this RFC established that sound per-module
enforcement requires three structural properties — unforgeable caller
identity, unpatchable shared state, mediated authority flow — that no amount
of bookkeeping in a shared mutable realm can provide. Realm-per-module
provides them but breaks npm semantics (live objects cannot cross realm
boundaries). Compartments provide them while preserving object flow, and the
design is production-proven in userland (Agoric SES/Endo; MetaMask LavaMoat)
`[inferred: external projects]`. Hermes's architecture makes the engine-native
version unusually tractable — see [Design](#design-overview).

## Current state

Observed mechanism, recorded here because no dedicated capability-model LLP
exists yet (this section serves as the interim record):

- **Rust host**: `SecurityMode` is `Permissive | Capability | Strict`
  `[observed]` (`src/host/mod.rs:29-37`); `CapabilityManager` normalizes
  (`net:`→`network:`, lowercasing, fs path canonicalization), matches base
  grants against parameterized values plus `*` wildcards, applies
  module-then-global deny-before-allow, defaults deny outside Permissive, and
  keeps a bounded 1024-entry audit log `[observed]`
  (`src/host/capability.rs:46-129, 296-346`). `crypto:random` and `time:now`
  are always allowed `[observed]` (`src/host/capability.rs:46`).
- **Canonical manifest**: 56 capabilities with stable bits in a u64
  `[observed]` (`src/host/capability_bits.rs:13-70`), generated to TS via
  `packages/ibex-devtools/src/scripts/generate-capability-bits.mjs`.
- **Enforcement points**: C++ `checkCapability()` gates fs, fetch, and
  process surfaces `[observed]` (`src/engine/hermes_runtime_fs.cc`;
  `src/engine/hermes_runtime_fetch.cc:66,364`;
  `src/engine/hermes_runtime_internal.h:168-179`). Module resolution enforces
  `fs:read:<path>` under module id `module-loader` `[observed]`
  (`src/host/mod.rs:160-173`).
- **JS layer**: `checkCapability`/`requireCapability` with typed denial
  reasons and a per-module bitmask fast path `[observed]`
  (`packages/ibex-runtime-js/src/security/Capabilities.ts:351-435, 971-986`);
  bootstrap bridges `__exactCapabilityCheck` and enables strict mode when
  present, else lax allow-with-warning `[observed]`
  (`packages/ibex-runtime-js/src/bootstrap.ts:768-780`;
  `Capabilities.ts:405-434`).
- **Defaults are permissive on every real entry point**: CLI `--capsec`
  defaults `permissive` `[observed]` (`src/bin/ibex/cli.rs:61-63`); the C ABI
  installs a permissive legacy host (LLP 0006; `src/host/abi.rs:586-599`).
- **Known defects** (tracked here; some are fixed by this RFC's phases,
  none require it): `SecurityMode::Capability` and `Strict` behave
  identically `[observed]` (`src/host/capability.rs:100-129` branches only on
  `Permissive`); `HostConfig.root_dir`/`allowed_hosts` are declared but never
  enforced `[observed]` (`src/host/mod.rs:51-53`); process surfaces check the
  string `child_process`, which is absent from the canonical manifest
  `[observed]` (`src/engine/hermes_runtime_process.cc:105,236,390,814`);
  source comments cite `SECURITY_DESIGN.md` / `JS_RUNTIME_SECURITY.md`, which
  do not exist in this repo `[observed]` (`src/host/capability.rs:1-4`;
  `Capabilities.ts:4-13`).

## Threat model

### In scope (what enforcement must stop)

- A malicious or compromised **package** in the dependency graph attempting:
  ambient authority theft (reading/patching shared globals or prototypes to
  capture handles or run code under another package's identity); direct host
  access beyond its declared capabilities; impersonation of another package
  at the host boundary; tampering with the capability system itself from JS.
- Honest-but-buggy overreach (a package using authority it didn't declare),
  surfaced in audit mode and blocked in enforce mode.
- Audit-trail integrity: attribution in logs must reflect the true executing
  code.

### Out of scope (accepted, documented residual risk)

- **Deputy-by-design**: an exported API acts with its own authority on behalf
  of callers (`db.query()` doing I/O for anyone who calls it). This is what
  libraries are. Optional mitigation for high-stakes capability classes is
  stack-intersection checking (Phase 5), not a default.
- **Deliberate authority passing**: objects are capabilities; a package may
  hand a granted handle to another. Endowment policy plus attenuators bound
  what exists to be passed.
- **Engine and native bugs**: memory-safety escapes bypass everything in this
  RFC. Instance/process isolation remains the containment layer for hostile
  code.
- **Side channels** (timing, Spectre-class).

Any public description of this feature must state this boundary. The honest
name is *supply-chain integrity*, not *sandbox*.

## Design overview

### Mechanism 1: Lockdown

At runtime boot, after Ibex's own builtins/polyfills install (the "repairs"
phase), freeze the full intrinsics graph — every prototype, constructor, and
shared object reachable from them. This kills prototype pollution and
prototype-patch identity theft. Intrinsics remain **shared**: cross-package
values, classes, and `instanceof` keep working, which is the property that
makes this compatible with real npm code where realms are not.

The SES shim's `lockdown()` defines the reference semantics
`[inferred: external — Agoric Endo]`; Phase 0 measures its behavior on the
pinned Hermes; Phase 2 makes it native (and movable to build time given the
AOT pipeline).

### Mechanism 2: Per-package compartment globals

Each **package** (not module — intra-package files trust each other, and
package granularity cuts object count ~10× and matches how policy is
authored) gets a private global object. Its properties are exactly the
policy's endowments: the safe shared surface plus whatever powerful objects
(attenuated `fs`, scoped `fetch`) the manifest grants. Bare-global resolution
and `globalThis` inside that package's code resolve against it.

Two implementations, one semantics:

- **Build-time (Phase 1, no fork)**: the bundler rewrites free global
  references per package to a compartment scope object. Ibex owns the whole
  transform pipeline (LLP 0007; Oxc transforms in
  `packages/ibex-devtools`), so this is a transform plugin, not a runtime
  `with`+Proxy shim. LavaMoat ships the equivalent as bundler plugins
  `[inferred: external]`.
- **Engine-native (Phase 3, fork)**: global resolution is already a single
  interpreter case — `CASE(GetGlobalObject)` reads `runtime.getGlobal()` in
  one place `[observed]` (`hermes:lib/VM/Interpreter.cpp:1842-1844`;
  opcode at `hermes:include/hermes/BCGen/HBC/BytecodeList.def:316`, plus its
  documented cached-variant ops). Re-point it through the executing frame's
  `RuntimeModule`/`Domain` (`hermes:include/hermes/VM/Domain.h`,
  `RuntimeModule.h`), which the frame already knows `[observed]`
  (`hermes:include/hermes/VM/CodeBlock.h:167`). The 84 intrinsic fields on
  `Runtime` and their ~320 VM use sites are untouched `[observed]`
  (`hermes:include/hermes/VM/RuntimeHermesValueFields.def`) — this is the
  structural reason compartments are cheap where realms are not.

`eval` and `Function` must bind produced code to the calling package's
compartment (the engine knows the caller's `CodeBlock`) or be tamed off per
policy. JSI `NativeFunction`s carry a compartment slot for attribution of
host-created callables.

### Mechanism 3: Frame-derived attribution

Host-boundary checks (`ex_host_check_capability`,
`src/host/abi.rs:729-745`) key on the executing frame's
`CodeBlock → RuntimeModule → package id` instead of the forgeable
thread-local. Bytecode provenance is engine truth: in the prototype-patch
attack, the patch body's frames belong to its true author. Native frames and
microtask boundaries need explicit rules (see Open questions). The
thread-local id, `__exactSetActiveModuleId`, and `__exactGrantCapability`
are removed from the reachable global surface.

### Policy

The existing capability manifest (`src/host/capability_bits.rs`) plus the
package manifest pipeline (LLP 0004; `src/module_loader`) extend to
per-package declarations: each package declares capabilities; the app's
policy (existing `PolicyFile`, `src/host/policy.rs`) grants or attenuates
them; default-deny under enforce mode. Parameterized capabilities
(`fs:read:<path>`) become endowed attenuated objects rather than string
checks where practical.

### Non-realm design, stated once

ShadowRealm-style realms (fresh intrinsics per realm, callable-only
boundary) are the right tool for *trust domains*, approximated today by
runtime instances. They are the wrong tool for a dependency graph: the
boundary that provides their isolation is the same one that breaks shared
live objects. A realm refactor of Hermes would also rewrite its hottest
files (84 `Runtime` intrinsic fields, ~320 use sites, no realm slot on
`Callable` `[observed]` (`hermes:include/hermes/VM/Callable.h`)) — rejected
on both grounds. Dynamic per-object ownership/taint tracking is rejected for
its per-access cost (defeats inline caches; research systems run integer
factors slower) and incoherent ownership semantics.

## Goals

1. A compromised package in enforce mode cannot exceed its declared,
   granted capabilities via ambient authority, identity forgery, or
   capability-system tampering (within the stated threat model).
2. Normal npm code that does not mutate intrinsics runs unmodified; packages
   that do are handled by repairs, per-package compat shims, or documented
   exclusion.
3. Steady-state overhead ≤1% on the runtime benchmark suite; memory overhead
   ≤ ~2KB per package; lockdown cost paid once at boot or at build time.
4. Attribution in audit logs is frame-accurate in both audit and enforce
   modes.
5. Each phase ships value independently; the fork is opt-in after evidence.
6. Hermes pin bumps with the patch stack remain routine (target: half a day;
   see Upstream tracking).

## Non-goals

- Realm-per-module / ShadowRealm implementation in Hermes.
- Replacing instance isolation for hostile code (Exact views keep their own
  instances/processes).
- Default stack-intersection enforcement (Java `SecurityManager`-style);
  optional per-capability-class only (Phase 5).
- Blocking on upstreaming any patch (upstreaming shrinks the carried set but
  never gates a phase).
- Solving deputy-by-design, deliberate authority passing, engine bugs, or
  side channels (see Threat model).

## Plan

Effort figures assume one person fluent in the relevant layer, agent-assisted.

### Phase 0 — Prove semantics on stock Hermes (days–2 weeks)

- Run the SES shim's `lockdown()` in the ibex REPL against the pinned build;
  triage failures into: conformance gaps (candidate upstream/overlay
  patches), repairs-ordering issues, hard blockers.
- Hide/remove the `__exact*` escape hatches at end-of-bootstrap. This is a
  standalone defect fix and lands regardless of this RFC's fate.
- Decide package identity (see Open questions) and draft the policy format
  as an extension of the existing manifests.
- **Deliverable**: findings appended to this LLP; go/no-go for Phase 1.
- **Kill criterion**: SES fundamentally cannot run and the gaps are not
  small patches → stop; instance-level isolation remains the model, and this
  RFC moves to `llp/tombstones/` with the findings recorded.

### Phase 1 — Userland compartments, audit mode (2–6 weeks, no fork)

- Bundler-level compartmentalization: per-package free-global rewrite in the
  Oxc/Rolldown pipeline (LLP 0007), endowments wired by the loader, SES
  lockdown at boot.
- Audit mode: violations logged with frame-accurate-as-available
  attribution; nothing blocked. Runs against real Exact/Snapback app graphs
  to build the compat corpus.
- **The conformance suite is born here** — lockdown semantics, compartment
  isolation properties, endowment behavior, capability enforcement
  end-to-end, red-team cases (prototype patching, identity forgery, host
  tampering). This suite is the durable asset the fork phases and every
  future rebase are measured against.
- **Deliverable**: `ibex run --capsec audit` (or equivalent); compat report.
- **Kill criterion**: unmanageable breakage across top dependencies →
  remain audit-only indefinitely (still valuable: honest attribution +
  drift detection) and do not start fork phases.

### Phase 2 — Fork, additive patches (2–4 weeks)

- Frame-provenance attribution at the host boundary (replaces the
  thread-local in `hermes_runtime_internal.h:168-179`).
- Native `lockdown()` / freeze-at-boot (build-time snapshot if the AOT
  pipeline allows).
- Host-bridge globals made unreachable natively.
- Patch classes: new files + small insertion points (see Upstream tracking).
- **Deliverable**: enforce-mode attribution that the red-team suite cannot
  forge.

### Phase 3 — Fork, native compartments (2–4 months)

- Per-`Domain` global object; `GetGlobalObject` and cached-variant ops
  resolve through the executing frame; removes the build-time rewrite.
- `eval`/`Function` compartment binding; `NativeFunction` compartment slots;
  JSI API to create/endow compartments.
- test262-subset coverage for the changed semantics; boundary fuzzing; perf
  gates per Goals §3.
- **Entry criterion** (revised 2026-07-02 per Resolved questions §6):
  Phase 1's conformance suite exists and passes on the userland
  implementation — technical sequencing only, no upstream-waiting gate. If
  Static Hermes later reshapes the interpreter, re-derive per
  [Upstream tracking](#upstream-tracking-and-re-derivation).

### Phase 4 — Policy, attenuators, rollout (parallel, ongoing)

- Attenuated builtins for parameterized capabilities; policy toolchain on
  the manifest; per-app audit→enforce migration; compat triage/repairs.
- Fold the `child_process`→`process:spawn` unification and the
  `Capability`≡`Strict` mode collapse into this work.

### Phase 5 — Optional: stack-intersection enforcement

- Effective capability = AND of frame owners' capability masks (u64 masks
  make this a walk-and-AND), offered per capability class for
  deputy-sensitive capabilities (`fs:write`, `process:spawn`). Off by
  default; Java's `SecurityManager` history (deprecated by JEP 411) is the
  cautionary reference `[inferred: external]`.

## Upstream tracking and re-derivation

How this work stays cheap as Hermes evolves. Written to survive personnel
and model changes; the runbook is designed to be agent-executable with the
conformance suite as oracle.

### Current consumption and the patch mechanism

Ibex builds stock Hermes from a pinned stable branch: `hermes-version.sh`
defines `IBEX_HERMES_SOURCE_REF`, `build-hermes-*.sh` shallow-clone and
build it, `update-hermes.sh` drives updates `[observed]`
(`scripts/hermes-version.sh`; `scripts/build-hermes-macos.sh:85`;
`scripts/update-hermes.sh`). The fork adds a `patches/hermes/` directory —
an ordered `git am`/`git apply` series applied immediately after clone by
the same scripts (the Electron model at small scale
`[inferred: external]`). No separate long-lived fork repository unless the
patch count forces one; the pin + patch stack **is** the fork.

### Patch shape discipline

Every carried patch is classified, and the class is recorded in its header:

- **Class A — additive files** (new `.cpp`/`.h`, new JSI surface): rebase
  cost ~zero.
- **Class B — insertion points** (an `#include`, a call, a field added at a
  marked site): rebase cost minutes; conflicts are mechanical.
- **Class C — surgical semantic changes** (the `GetGlobalObject` case and
  its cached variants; `eval`/`Function` binding): the only patches that can
  conflict meaningfully. Budgeted: single-digit sites total. Any proposed
  Class C patch beyond this budget triggers design review here first.

A cross-cutting rewrite (realm-shaped) is prohibited by this discipline —
that is the line between "carrying patches" and "maintaining a divergent
engine."

### The pin-bump runbook

1. Update `IBEX_HERMES_SOURCE_REF` to the new stable branch.
2. Apply the patch series; resolve conflicts under the class rules
   (Class A/B mechanically; Class C re-read the surrounding upstream change
   before resolving).
3. Build all platforms; run the conformance suite (Phase 1's), the red-team
   suite, the perf gates, and the existing runtime tests.
4. Land pin bump + patch updates + any conformance-suite adjustments in one
   commit, with a note in this LLP's revision log if semantics moved.

Target: routine bump ≤ half a day. Two consecutive bumps exceeding ~2 days
each is the signal to reassess the carried set (see Contingencies).

### Canary CI

A scheduled job (weekly) applies the patch stack to the newest upstream
stable branch — and optionally `main` — builds one platform, and runs the
conformance suite. Failures file issues immediately. This amortizes drift
into small, early, agent-fixable deltas instead of a cliff at bump time,
matching the repo's existing preflight-CI posture `[observed]`
(`.github/` hermetic preflight; commit `b861d07`).

### The durable asset is the spec, not the diff

If upstream refactors the interpreter or module structures (e.g., Static
Hermes evolution) such that patches stop applying meaningfully, the recovery
path is **re-derivation, not archaeology**: this LLP's Design section
specifies the semantics; the conformance suite defines done; Class A/B
patches re-apply nearly as-is; Class C is re-implemented against the new
code (bounded by the same single-digit-site budget). The estimate for a
full re-derivation after a major upstream interpreter refactor is weeks, not
months, **provided the suite and this document are current** — keeping them
current is therefore part of every phase's definition of done.

### Upstreaming to shrink the carried set

Frame-provenance attribution and native lockdown primitives are plausible
upstream contributions — MetaMask has pursued hardened-Hermes needs for
years, so allies exist `[inferred: external]`. Native compartments are less
likely to land upstream. Every landed piece deletes a carried patch. Track
upstream's Static Hermes trajectory; the design intentionally touches
surfaces that persist across it (bytecode global resolution, module/domain
structures), but this assumption is re-validated at each pin bump.

### Contingencies

- **Upstream stalls or diverges hard**: hold the pin. Ibex controls its
  release cadence; a held pin is fully functional, and security backports
  can be cherry-picked. Re-derive when there's a reason to move.
- **Rebase cost exceeds budget twice in a row**: drop the costliest Class C
  patches back to their Phase 1 (userland) equivalents and keep A/B.
- **Upstream ships equivalent primitives** (lockdown, provenance, realms):
  migrate to them and delete patches; this is a win condition, not a risk.

## Risks

1. **Lockdown ecosystem breakage** (top risk). Packages that mutate
   intrinsics break. Mitigations: repairs-before-lockdown; per-package compat
   shims; audit-mode default; per-app permissive fallback; compat corpus in
   CI from Phase 1. Kill criteria in Phases 0–1 exist because of this risk.
2. **Fork ownership drag.** Mitigated by patch-shape discipline, canary CI,
   the runbook, and the re-derivation posture; measured by the bump-cost
   budget with an explicit fallback (drop Class C, keep A/B).
3. **Overclaiming.** If this ships described as a sandbox for hostile code,
   the deputy/object-passing/engine-bug residuals become vulnerabilities in
   the product story. Mitigation: the Threat model section is normative for
   docs and marketing language.
4. **Perf regressions** at the interpreter change or from frozen-object
   paths on Hermes. Mitigation: budgets in Goals §3 enforced as CI gates
   from Phase 2 on.
5. **Attribution edge cases** — native frames, microtask/promise-job
   boundaries, bound functions, JSI-created callables. Wrong answers here
   are silent policy holes. Mitigation: explicit semantics decided in
   Phase 2 design review (see Open questions); red-team cases for each.
6. **Hermes upstream direction.** Static Hermes may reshape the interpreter.
   Mitigation: minimal-surface design + canary CI + re-derivation posture.

## Acceptance criteria

- A deliberately compromised transitive dependency in a demo app, in enforce
  mode, cannot read a file outside its grants, exfiltrate `process.env`, or
  call the network — demonstrated by red-team tests in CI (the same tests
  that currently succeed against the advisory model must fail against
  enforcement).
- Attribution in the audit log is frame-accurate under the red-team suite's
  forgery attempts.
- Perf and memory within Goals §3 budgets on the benchmark suite.
- The pin-bump runbook executed on ≥2 real upstream releases within budget.
- `--capsec audit` and `--capsec enforce` (naming TBD) shipped in the CLI;
  defaults unchanged until a separate decision LLP.
- Audit mode running on at least one real Exact app graph and one Snapback
  app graph (Resolved questions §7), feeding the compat corpus.
- The escape-hatch globals are unreachable in all modes (Phase 0, ships
  first).
- Threat model published in user-facing docs with the residual risks stated.

## Resolved questions

Author decisions, 2026-07-02. Numbering is stable across this section and
Open questions below.

1. **Package identity** — policy is keyed by package **name** (survives
   version bumps; matches LavaMoat and how humans author rules); coexisting
   `name@version` instances get separate compartment globals (they do not
   share mutable state); version pins are opt-in tightening for high-risk
   packages. First-party code and workspace members default to the trusted
   root principal; vendored code without a `package.json` belongs to its
   enclosing package. Accepted "ok for now": Phase 0 re-validates against
   real Exact/Snapback graphs (aliasing, pnpm layouts, workspace edges)
   before the policy format freezes.
2. **Dynamic import and plugins** — default-deny: code outside the build
   graph runs as a no-capability quarantine principal (refused outright in
   enforce mode unless policy names it), and the runtime loader applies the
   same free-global rewrite at load time where it already transforms
   sources (LLP 0007/0009). Phase 3's engine-native model subsumes this
   naturally.
5. **`ses` sourcing** — Phase 0 spikes with the full Agoric `ses` shim
   (fastest conformance signal); shipping builds vendor a lockdown-only
   subset (no Compartment shim — compartments come from the bundler),
   consistent with the hermetic vendoring posture (LLP 0005). Small Hermes
   conformance fixes are upstreamed opportunistically, where MetaMask's
   standing interest provides allies.
6. **Sequencing vs Static Hermes** — **do not wait.** All phases proceed
   now; when Static Hermes materially reshapes the interpreter, the work is
   re-derived per [Upstream tracking](#upstream-tracking-and-re-derivation)
   — the spec and conformance suite, not the diff, are the carried asset.
   This supersedes the earlier hold-until-settled lean and relaxes Phase 3's
   entry criterion (see Plan). The Phase 0–1 kill criteria stay in force as
   evidence-based aborts.
7. **Adoption order** — the primary rollout target is **Exact and Snapback
   app graphs** (audit mode first, enforce as the compat corpus allows);
   the ibex CLI serves as the demo and development harness rather than the
   adoption path.

## Open questions

*Lean* lines record the current recommendation so a future resolution can
agree or push back against something concrete. Question 3 resolves in
Phase 2 design review; 4 and 8 wait for evidence.

3. **Microtask/native attribution semantics**: attribute promise jobs to the
   compartment that scheduled them (recorded at schedule time) or to the
   frame that resolves? Host calls with no JS frame on the stack?
   *Lean:* skip runtime-internal frames, attribute to the nearest user
   frame, fall back to a schedule-time-recorded principal (async-context
   propagation) when none exists. Pin down in Phase 2 design review with
   red-team cases — attributing internal frames to a trusted "runtime"
   principal is a deputy surface and must not be the accidental default.
4. **Granularity escape hatch**: do we ever need per-module (not package)
   compartments for specific high-risk packages?
   *Lean:* no — the compromise unit is the published package, and the tool
   for a scary dependency is harder attenuation of its grants. Revisit only
   with a concrete case.
8. **Defaults**: when, if ever, does enforce mode become a default for any
   entry point? (Separate decision LLP when the compat corpus supports it.)
   *Lean:* set a revisit trigger now rather than a decision — e.g., when N
   real apps have run audit-clean for M consecutive weeks — so this cannot
   silently become permanently-permissive machinery (the failure mode this
   RFC exists to avoid).

## References

- LLP 0002 §Host ABI (capability check/grant/log surface); LLP 0004
  (module manifest and loader); LLP 0006 §"Capability-gated host"; LLP 0007
  (bundler/transform pipeline used by Phase 1).
- Hermes pin: `scripts/hermes-version.sh` (`260318099.0.0-stable`).
- External `[inferred]`: Agoric SES/Endo & Hardened JavaScript; MetaMask
  LavaMoat; TC39 ShadowRealm proposal (rejected here for this use);
  Node.js process-level permission model and the removal of its per-module
  policy mechanism; Deno permissions; Java JEP 411 (SecurityManager
  deprecation); Electron's chromium patch-stack maintenance model.
