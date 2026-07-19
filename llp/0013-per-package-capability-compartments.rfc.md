# LLP 0013: Per-Package Capability Enforcement via Hardened Compartments

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Host ABI, Module Loader, Runtime, Build
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-02
**Revised:** 2026-07-19 (ENG-24933 physically verifies the repaired Windows deputy stack as `1,0` and all nine startup-environment recipes, then narrows the next refusal to exact artifact-root identity opening with excessive generic-read access)
**Revised:** 2026-07-19 (ENG-24933 traces the physical Windows deputy stack to `0,1,0`, identifies the Windows-only second disk evaluation that replaced the authenticated native-bootstrap bundle as root, and makes every platform reuse a successfully installed native bundle)
**Revised:** 2026-07-19 (ENG-24933 materializes the exact process.env deputy call chain with an inaccessible no-I/O sentinel before binding after physical Windows accepted every retained anchor readback but still replaced or bypassed those pre-execution Domains on first use)
**Revised:** 2026-07-19 (ENG-24933 replaces the insufficient single process.cwd shared-runtime anchor with a bootstrap-only exact process.env deputy-function list after physical Windows proved source bootstrap creates multiple lazy Domains inside the bundle)
**Revised:** 2026-07-19 (ENG-24933 extends exact retained-function Domain binding/readback to the shared runtime bundle and non-compartmented builtin deputies after physical Windows proved the package wrapper and callback correct but the immediately following process.env deputy call root-attributed)
**Revised:** 2026-07-19 (ENG-24933 makes the CommonJS Domain binder fail closed and requires an exact post-bind package-principal readback after physical Windows evidence disproved the original write-only convergence claim)
**Revised:** 2026-07-18 (ENG-24933 added the first direct CommonJS Domain principal bind; subsequent physical Windows evidence showed that write-only binding was insufficient)
**Revised:** 2026-07-15 (ENG-25066 made ordinary ESM use authenticated per-principal native records; the legacy chunk path remains only for unsupported interop during the 0.1 window)
**Revised:** 2026-07-02 (author decisions recorded on questions 1, 2, 5, 6, 7); 2026-07-02 (revision for the OpenAI family review — `llp/reviews/0013-per-package-capability-compartments.openai.md` — plus an author-side deep pass — `llp/reviews/0013-per-package-capability-compartments.claude-fable.md`); 2026-07-02 (first implementation landed on branch `llp-0013-compartments` — see [Implementation status](#implementation-status)); 2026-07-02 (delegation model + authority-flow section added; resolved question 10, open question 11); 2026-07-02 (dynamic user-facing permissions: runtime mechanism contract recorded, embedder/broker design explicitly deferred to embedder corpora); 2026-07-02 (import-site declarations become the root-principal grant-authoring surface and the policy artifact becomes generated — LLP 0014; resolved question 11, opened question 12); 2026-07-02 (Phase 2 frame-derived attribution built and wired end-to-end on macOS — patch stack 0001-0003, loader/host integration, conformance tests; Phase 5 stack-intersection wired to real frame stacks; deputy-transparency via a reserved runtime principal resolves Open question 3's lean into a concrete rule); 2026-07-02 (Phase 1 real-global inventory closed — eager-install-then-seal + self-grant channel removed; Phase 3 native compartment globals landed — patch 0004, interpreter-level per-Domain global resolution, closing the sloppy-`this` escape natively; import gating wired as Policy surface 3); 2026-07-02 (Phase 4 landed — authority-bearing `FsHandle` attenuators with `scoped()` re-attenuation and a revocation cascade, the primary delegation mechanism; tri-state grant status and ceiling-bounded runtime permission grants); 2026-07-02 (Phase 3 refinements landed — patch 0006: `eval`/`Function`-produced code binds to the caller's compartment + principal, captured at the eval call site into a GC-rooted pending slot; native transitive deep-freeze `__exactDeepFreeze` behind `IBEX_NATIVE_LOCKDOWN`; `Ibex.permissions.onChange` grant-change signal for embedder UIs; per-package chunks resolve siblings via a source-relative `__exactChunkDir`); 2026-07-02 (`process.env` laundering channel closed — the ungated `process.__exactPlainEnv` snapshot removed; compartment steady-state overhead benchmarked ≈0% (`benches/compartment_overhead.rs`); enforce mode made usable by default — `decide()` trusts the first-party root and `module-loader` principals, ceiling-exempt to preserve Phase 4, and the policy artifact's `mode` field drives `SecurityMode` when no `--capsec` is passed); 2026-07-03 (adversarial review + fixes — patch 0007 fails closed on the async/deputy attribution boundary (`kNoUserPrincipal` sentinel + internal-bytecode runtime-principal stamp) so a package cannot launder a detached deputy op into trusted root; endowment config injected via `__ibexEndowRaw` not gated `process.env`; explicit `--capsec permissive` distinguished from the `Auto` default; `ceiling_configured` fails closed on lock poison; native deep-freeze per-root try/catch; chunk-basename traversal guard); 2026-07-03 (patch 0008 closes the async deputy-class laundering hole ENG-22631 — the schedule-time principal is captured at `enqueueJob` and appended to the deputy-class stack, so `Promise.resolve(x).then(deputy.method)` under `deputyClasses` is attributed to its scheduler; resolves Open question 3's schedule-time half); 2026-07-03 (deep-review fixes ENG-22681/22682/22683/22684/22621: enforce/audit auto-enable per-package chunking so a bundled dependency is attributed to its own principal, not root — plus a per-key bundle-cache subdir and the shared `rolldown-runtime.js` chunk redirect that makes chunking robust for ESM apps and safe under concurrent runs; path-scoped `fs` grants resolve symlinks before matching, and `lutimes`/`lchmod`/symlink-target/hardlink-source gates close the last path-mutator holes; `IBEX_ENDOW` can no longer widen policy endowments under enforce/audit without `--allow-env-endowments`; the generated policy emits an explicit observed `builtins` allowlist so the import axis is default-deny; and package identity is now version-distinguished end-to-end — `name@version` principals/compartments/chunks with bare-name policy selectors, so coexisting versions receive distinct policy treatment)
**Revised:** 2026-07-04 (deep-review fixes ENG-22716/ENG-22717/ENG-22718/ENG-22720/ENG-22722: no-follow-final link metadata gates, `access(W_OK)` write gating, caller-referrer dynamic imports, `Bun.which` spawn gating, and native server/socket network gates)
**Revised:** 2026-07-04 (follow-up hardening ENG-22741/ENG-22742/ENG-22743/ENG-22744/ENG-22745: native handles carry owner/capability metadata, fetch/WebSocket checks use endpoint-scoped grants, fs-write tests use temporary copies, stale security-document comments were retargeted to local LLPs, and formatting/lint drift was cleaned up)
**Revised:** 2026-07-04 (capability-security deep review ENG-22761..ENG-22774: fail-closed endowment resolution, two-sided import reachability, safer generated/runtime builtin classification, path and selector hardening, audit-mode non-interference, and native-callback principal stamps for no-user async host re-entry)
**Revised:** 2026-07-04 (ENG-22759: close the async deputy-class laundering hole through the HOST callback queues — `setTimeout`/`setInterval`/`setImmediate`/`process.nextTick`/the non-JSI `queueMicrotask` fallback. ENG-22761 already captures the scheduling principal for these queues but only consults it on a no-user-frame re-entry; a detached deputy *method* runs with its own frame live, so `checkCapabilityWithFsMode` now also appends that captured scheduler to the deputy-class stack, matching patch 0008's Promise-queue append. Also repairs corrupt `@@` hunk headers in patch 0008 that blocked `apply-hermes-patches.sh`.)
**Revised:** 2026-07-05 (ENG-22903..ENG-22909 native hardening: DNS resolution is a `network:resolve` capability, raw WebSocket ids and async callbacks carry owner/principal metadata, host allow-all is queried live after host replacement, child-process `fd:N` stdio redirects validate fd ownership before fork, native ArrayBuffer-view consumers share bounds checks, HTTP waits are worker-bounded, and fetch raw headers are validated at the C++ boundary.)
**Revised:** 2026-07-07 (document drift cleanup: canonical SecurityMode is `Permissive | Audit | Enforce`; historical `Capability`/`Strict` aliases collapse to Enforce)
**Revised:** 2026-07-10 (ENG-24144 factual drift repair: manifest count is 57 after `network:resolve`; package-selector precedence and enforced host fences recorded; typed successor contract is LLP 0021)
**Revised:** 2026-07-12 (ENG-24263 retirement reconciliation: the legacy binary policy suite and its string-policy fixtures were removed; every former case is mapped to a live named revision-2 test, production closure, or an explicitly migrated compatibility regression in `tests/fixtures/capsec-rev2/llp0013-retirement-map.json`)
**Revised:** 2026-07-12 (ENG-24463 isolates post-bootstrap global property bindings and existence: native bootstrap installs a closure-private registry, the selected runtime path performs a required one-shot baseline refresh, package reads resolve against that detached view, and package lookup/binding failures refuse rather than falling back to the real global; ENG-24526 adds exact-importer lexical scope imports and strict flat chunks; shared nested descriptor values and all-free flat rewriting remain explicit follow-ups ENG-24514 and ENG-24527)
**Revised:** 2026-07-13 (`allowed_hosts` remains a hard outbound fence but no longer conflates remote-host policy with local `network:listen` authority — ENG-24285)
**Related:** LLP 0000; LLP 0002 (host ABI); LLP 0003 (Hermes bridge); LLP 0004 (module loading); LLP 0006 (design principles); LLP 0007 (transform pipeline); LLP 0014 (import-site grants and the generated policy artifact)

> **Current implementation (2026-07-12):** LLP 0021 supersedes this RFC's
> legacy string-policy, mode-selection, and rollout mechanics. Ordinary
> execution is typed, armed, enforce-only, and structurally locked down. The
> old permissive/audit flags and `PolicyFile` passages below are retained only
> as historical rationale; they are not operator guidance. Foreground diagnosis
> is `ibex capsec audit`. No exact target is currently advertised complete, so
> ordinary production execution refuses before project code; LLP 0021 §WP10
> records `aarch64-apple-darwin` only as a candidate pending complete evidence.
> Named `tests/llp0013_compartments.rs` cases and `tests/fixtures/llp0013/`
> paths later in this document describe the retired implementation history.
> The checked retirement map above is the authoritative join from every old
> case to the current authenticated callback, typed semantic, armed-engine,
> production-closure, or migrated diagnostic test that replaces it.

> Citation convention: `hermes:` paths refer to the pinned Hermes source
> (`IBEX_HERMES_SOURCE_COMMIT` on the `260318099.0.0-stable` release branch
> `[observed]` (`scripts/hermes-version.sh`)), verified against the local
> build checkout of that commit. The branch name moves; the commit is the pin
> (ENG-23092). Line numbers drift with the pin; treat them as anchors, not
> contracts.
>
> Reproducibility: the Hermes source is not in this repo's committed tree.
> `scripts/update-hermes.sh` (or any `build-hermes-*.sh`) materializes it;
> this document's `hermes:` citations were verified against the checkout at
> `~/.cache/exact/hermes/hermes-src`, commit
> `ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138` (HEAD of
> `origin/260318099.0.0-stable`). Equivalent:
> `git clone --branch 260318099.0.0-stable https://github.com/facebook/hermes.git`.

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

- **Rust host**: `SecurityMode` is `Permissive | Audit | Enforce`
  `[observed]` (`src/host/mod.rs:37-45`); `CapabilityManager` normalizes
  (`net:`→`network:`, lowercasing, fs path canonicalization), matches base
  grants against parameterized values plus `*` wildcards, applies
  module, package-selector (locator then name), and global
  deny-before-allow tiers, defaults deny outside Permissive, logs
  would-deny decisions while proceeding in Audit, blocks them in Enforce, and
  keeps a bounded 1024-entry audit log `[observed]`
  (`src/host/capability.rs:46-129, 296-346`). `crypto:random` and `time:now`
  are always allowed `[observed]` (`src/host/capability.rs:46`).
- **Canonical manifest**: 57 capabilities with stable bits in a u64
  `[observed]` (`src/host/capability_bits.rs:16-74`), generated to TS via
  `packages/ibex-devtools/src/scripts/generate-capability-bits.mjs`. LLP 0021's
  WP0 reconciliation records the typed destination of every legacy bit.
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
  defaults through `Auto` to the policy mode or permissive `[observed]`
  (`src/bin/ibex/cli.rs:369-386`); the C ABI installs a permissive legacy host
  `[observed]` (`src/host/abi.rs:782-791`;
  LLP 0006 §"Capability-gated host").
- **Boundary fences**: the historical `SecurityMode::Capability`/`Strict`
  split has been collapsed into canonical `Enforce` (the old strings remain
  aliases). `HostConfig.root_dir` and the outbound-only `allowed_hosts` remote
  host allowlist are now hard host-boundary fences in every mode and cannot be
  widened by policy; `network:listen` remains a separate policy decision
  `[observed]` (`src/host/capability.rs`).

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
  what exists to be passed. (Stated here from the attacker's side; the same
  channel is the *intended* delegation mechanism between cooperating
  packages — see Design §Delegation and authority flow.)
- **Shared mutable module exports**: CJS export objects are shared live
  values; a package that is legitimately imported can have its exports
  mutated by one importer to attack later importers (exports pollution).
  Freeze-on-load is a candidate mitigation with real compat cost — see Open
  question 9.
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

Lockdown includes **evaluator taming**: the intrinsic function constructors
(`%Function%`, `%GeneratorFunction%`, `%AsyncFunction%`,
`%AsyncGeneratorFunction%`) and indirect `eval` are replaced with
tamed/throwing forms. This is load-bearing, not optional hardening — the
intrinsics are reachable from any object via prototype walks
(`({}).constructor.constructor`), so without taming every compartment can
mint code that evaluates against the real global scope regardless of its
endowments.

### Mechanism 2: Per-package compartment globals

Each **package** (not module — intra-package files trust each other, and
package granularity cuts object count ~10× and matches how policy is
authored) gets a private global object. Its properties are exactly the
policy's endowments: the safe shared surface plus whatever powerful objects
(attenuated `fs`, scoped `fetch`) the manifest grants. Bare-global resolution
and `globalThis` inside that package's code resolve against it.

Two delivery paths target the same resolution semantics, but they do not yet
provide the same independent security boundary:

- **Build-time (Phase 1, no fork)**: the bundler rewrites free global
  references per package to a compartment scope object. Ibex owns the whole
  transform pipeline (LLP 0007; Oxc transforms in
  `packages/ibex-devtools`), so this is a transform plugin, not a runtime
  `with`+Proxy shim. LavaMoat ships the equivalent as bundler plugins
  `[inferred: external]`. The plugin now generates an exact-importer-bound
  virtual module which exports only that module's package compartment, then
  routes each configured free-global access through a hygienic lexical import.
  Resolver checks reject copied, unknown, and cross-module scope imports;
  authored `__compartments` reads route through the scoped view; and every
  package-bearing output chunk is strict so sloppy-function `this` cannot
  recover the realm global (ENG-24526). The virtual module performs the
  registry lookup once, retaining the ENG-22644 one-compartment-trap steady
  state.

  This transform still recognizes a finite configured global set rather than
  every lexically unbound identifier. An arbitrary name such as a post-arming
  `apiKey` therefore remains a realm-global lookup when a package is collapsed
  into a flat root Domain. All-free rewriting, including CJS implicit bindings
  and free-call receiver semantics, is tracked by ENG-24527. Until that lands,
  the flat transform is compatibility routing and defense in depth; the native
  per-package Domain below is the production property-binding boundary.
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

The build-time implementation must close three escape channels, not one:

1. **Free identifiers** — the rewrite itself: bare `process`, `fetch`, and
   `globalThis` resolve to the compartment global.
2. **`this`-based escapes** — in sloppy mode, `(function(){return this})()`
   yields the *real* global (the classic UMD idiom). Package code is
   therefore emitted in strict mode (ESM already is; CJS wrappers add it),
   with the sloppy-mode compat fallout (`arguments.callee`/`caller`
   linkage, octal literals, silent-write semantics) tracked in the Phase 1
   compat corpus and handled by per-package repairs where it bites.
3. **Dynamic evaluators** — direct `eval` rewrites to a compartment-bound
   evaluator (its scope semantics change from direct to indirect eval, a
   documented compat delta); `Function` is endowed tamed or not at all; and
   the *intrinsic* evaluators are tamed by lockdown (Mechanism 1), which is
   what makes denial effective against prototype walks.

In the engine-native implementation, `eval` and `Function` instead bind
produced code to the calling package's compartment (the engine knows the
caller's `CodeBlock`) — landed in patch 0006. A per-`NativeFunction` compartment
slot for host-created callables is a planned refinement (Phase 3 list below), not
yet built: today host callables attribute correctly via the reserved
runtime-principal deputy-transparency rule (Mechanism 3), which the frame walk
skips over to reach the true caller.

### Mechanism 3: Frame-derived attribution

Host-boundary checks (`ex_host_check_capability`,
`src/host/abi.rs:729-745`) key on the executing frame's
`CodeBlock → RuntimeModule → package id` instead of the forgeable
thread-local. Bytecode provenance is engine truth: in the prototype-patch
attack, the patch body's frames belong to its true author. Native frames and
microtask boundaries need explicit rules (see Open questions). The
thread-local id, `__exactSetActiveModuleId`, and `__exactGrantCapability`
are removed from the reachable global surface.

Attribution granularity must align with evaluation units. A `CodeBlock` is a
function inside one `RuntimeModule`, and a single bundled HBC file is one
`RuntimeModule` — so `RuntimeModule → package` only works if the build emits
**per-package module units** (Rolldown chunking; also the natural
`Domain`-per-package structure for Phase 3), or, failing that, a build-time
function-range → package table the host consults. Phase 2 selects one;
per-package units are the lean. Audit entries carry both the human policy
selector (package name) and the resolved runtime principal (name plus
lockfile locator — Resolved questions §1), so coexisting versions stay
distinguishable.

### Policy

The existing capability manifest (`src/host/capability_bits.rs`) plus the
package manifest pipeline (LLP 0004; `src/module_loader`) extend to
per-package declarations; the app's policy (existing `PolicyFile`,
`src/host/policy.rs`) grants or attenuates them; default-deny under enforce
mode. The app's `PolicyFile` is a **generated artifact**, not a
hand-maintained file: compiled from root-principal import-site grant
declarations plus the delegation cascade, committed like a lockfile, and
drift-checked in CI with per-entry provenance (LLP 0014). Policy governs
**three surfaces**, not one:

1. **Host capabilities** — what the package's frames may do at the host
   boundary (`network:fetch:api.example.com`).
2. **Endowed globals** — which objects exist on the package's compartment
   global. Parameterized capabilities (`fs:read:<path>`) become endowed
   attenuated objects rather than string checks where practical.
3. **The import graph** — which builtin modules (`node:fs`,
   `node:child_process`) and which dependency packages a package may load,
   enforced by the loader (which Ibex owns). Builtins are reachable by
   `require`, so import policy is the *primary* gate for them: a
   compartment with no `fs` endowment but unrestricted `require('node:fs')`
   is not contained. The host memoizes ALLOWED `(principal, specifier)`
   import decisions (invalidated on policy application and principal
   re-registration), so a steady-state repeated `require()` is one native
   call plus a hash hit; denials always re-run the full decision and keep
   their audit entries, and the memo lives host-side — NOT in the JS loader —
   because only the host knows the frame-derived requesting principal
   (ENG-22644).

Runtime-internal modules (the `packages/ibex-runtime-js` security layer and
bootstrap internals) are their own trusted principal and are not importable
from package compartments; development/test toggles (`enableTestMode`,
`disableStrictMode` — `Capabilities.ts:246-333`) are compiled out or
unreachable in production builds.

A policy sketch, forcing the selector/principal split to be concrete:

```json
{
  "packages": {
    "left-pad":     {},
    "node-fetch":   { "capabilities": ["network:fetch"],
                      "builtins": ["node:http", "node:https"] },
    "node-fetch@2": { "capabilities": ["network:fetch:internal.example.com"] }
  }
}
```

Both `node-fetch` versions in a graph match the `node-fetch` selector; the
`@2` entry narrows that version; audit logs record resolved locators so the
two principals remain distinguishable.

### Delegation and authority flow

Motivating case (author discussion, 2026-07-02): the app intentionally
installs an image-processing package and grants it read/write on
`/app/images/**`; that package legitimately needs to hand part of that
authority to its own codec dependency. Delegation between cooperating
packages is a requirement, not a threat.

Authority reaches a package through two channels with different semantics:

1. **Ambient authority** — what policy places on the package's compartment
   global (endowments) and grants to its frames at the host boundary.
   Scoped to the package principal; sourced from the app's policy,
   exclusively.
2. **Passed handles** — capability objects received as ordinary arguments,
   return values, or fields. Scoped to whoever holds the object; sourced
   from any holder, voluntarily.

Passed handles are the **primary delegation mechanism**. The image-lib case
needs no policy machinery at all:

```js
// inside image-lib: fsHandle is its endowed attenuator for /app/images/**
const codec = require('fast-codec');
codec.decode(buf, fsHandle);                  // delegate the whole grant
codec.decode(buf, fsHandle.scoped('cache/')); // or re-attenuate first
```

`fast-codec`'s compartment global has no `fs`; it cannot reach the
filesystem ambiently, but it can use exactly the handle it was handed.
Authority flows along the call graph the way data does — the property
compartments were chosen to preserve (see §Non-realm design).

**Attenuators are authority-bearing (normative for Phases 2 and 4).** An
endowed attenuator carries its grant, fixed at creation from the app's
policy; for handle-mediated operations the host checks possession, not the
identity of the calling frame. Frame attribution (Mechanism 3) supplies the
audit record — the acting-principal chain ("codec wrote, via image-lib's
grant") — and gates *ambient* operations. Keying handle-mediated checks on
the calling frame's package would deny every legitimately passed handle:
the Java `SecurityManager` failure mode, silently converting the delegation
model into an identity ACL. Phase 5's `deputyClasses` is the deliberate,
opt-in exception — for configured capability classes, stack-intersection
reintroduces exactly that denial where deputy risk outweighs delegation.

**Requests vs grants (ambient delegation).** For dependencies that need
*ambient* authority (their own `require('node:fs')`, bare `fetch`) rather
than accepting handles, a package may ship a capability manifest (an `ibex`
field in its `package.json`, read by the existing manifest pipeline —
LLP 0004): the capabilities it needs, and what it delegates to each
dependency edge. A shipped manifest is a **request**; the app's policy is
the only grant root. Effective ambient authority cascades by intersection
down dependency edges:

```
effective(dep, via pkg) = delegates(pkg → dep) ∩ effective(pkg)
```

```jsonc
// image-lib/package.json — a request, authored by the package (or inferred)
{ "ibex": {
    "capabilities": ["fs:read", "fs:write"],
    "delegates": { "fast-codec": ["fs:read"] }
} }
```

With the app policy granting `image-lib` `fs:read:/app/images/**` +
`fs:write:/app/images/**`, `fast-codec`'s effective ambient grant is
`fs:read:/app/images/**`. A compromised package can request and delegate
anything; it never obtains more than the app granted its subtree. The build
resolves the cascade and emits the full effective-policy artifact — every
package's grants plus the delegation chain that produced each — as the
reviewable record; per-package manifests are inputs, not the record.
Requests are inferable by static analysis (LavaMoat `generate` precedent
`[inferred: external]`), which turns version-over-version request growth
into a supply-chain signal rather than paperwork.

**Union across importers.** A package is one principal with one compartment;
if several importers delegate different scopes to it, its ambient grant is
the union of the per-edge intersections. Per-edge precision exists only on
the passed-handle channel — the structural reason handles are the idiomatic
delegation path and ambient delegation is the coarse fallback.

Import-site declaration syntax (`import lib from "image-lib" with
{ grants: "…" }`) is the **grant-authoring surface for root-principal code,
and only there**: the build compiles first-party import-site declarations
(with union across sites, scoped to the entry's module graph) together with
the request cascade above into the effective-policy artifact the app
commits and reviews. In package code the same syntax is never a grant — it
is stripped, ignored, and surfaced as a supply-chain signal. Specified in
LLP 0014, which supersedes the "requests-only sugar" lean previously
recorded here; the pre-extraction Exact planning corpus's import-attribute
sketch is its ancestor (see References).

### Interaction with user-facing dynamic permissions

(Added 2026-07-02. Embedders — Exact, Snapback — sit under OS permission
systems that prompt the user at runtime: location, camera, contacts. The
pre-extraction Exact planning corpus modeled this as a four-layer
intersection, `OS ∩ App Root ∩ View Broker Grant ∩ Module Declared` — see
References. This section records only the runtime mechanism that model
needs from Ibex; the broker UX, per-view grants, persistence policy, and
OS mapping tables are embedder design and belong in the embedder's corpus,
referencing this LLP as substrate.)

The layer split: a user prompt is a **dynamic mutation of the root
principal's grant set** — the OS knows only apps, never packages. This
LLP's policy cascade distributes from that root; it can narrow an OS grant,
never widen it. Effective authority for a package is
`OS-grant ∩ app-policy(package)`, evaluated at check time. Four mechanism
requirements follow, binding Phases 2 and 4:

1. **Check-time evaluation, never cached.** Grant state changes behind the
   runtime's back (the user in Settings mid-session); device-class
   capability checks consult current state per call — TOCTOU is the failure
   mode. `CapabilityManager::check` already evaluates per call; this pins
   that property for device capabilities.
2. **Acquisition is async and lives in the attenuator; the boundary check
   stays synchronous.** `ex_host_check_capability` cannot block on a UI
   prompt. The endowed device attenuator runs the broker flow
   (`await camera.capture()` suspends on the prompt, resolves or throws);
   the synchronous boundary check only ever consults already-resolved
   grant state. Compartments govern *reachability* (who holds a camera
   object — static); the dynamic layer governs *exercisability* (whether
   calls succeed right now). Grant status is therefore tri-state at the
   host surface — granted / denied / prompt — not today's boolean.
3. **The static policy is the ceiling; prompts move the floor.**
   Triggering a prompt is itself gated: only a package whose manifest
   requests the capability and whose app policy grants it may cause the
   broker to ask. A transitive dependency the policy never named cannot
   spend user attention. Frame attribution (Mechanism 3) identifies the
   requesting principal to the broker for logging, rate-limiting, and
   honest prompt copy.
4. **Revocation cascades through delegation.** Handles are
   authority-bearing and passable (§Delegation), so attenuators hold a
   live link to the root grant, not a copy of its state: revoking the root
   kills every derived attenuation, tears down live resources (watches,
   sessions) fail-closed, and subsequent use fails with a typed error.

Host-ABI surface implied: a runtime mutation entry point for the root
principal's grant set, the tri-state status query, and a revocation signal
handles subscribe to. When these land they are specified in LLP 0002 (host
embedding ABI); this section is their design rationale.

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
5. Each phase ships value independently; the Phase 0–1 kill criteria are the
   only aborts (all phases otherwise green-lit — Resolved questions §6).
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

Security claims by phase — the ceiling on what may honestly be stated at
each point; anything stronger is overclaiming (Risk 3):

| Phase | Claim ceiling |
|---|---|
| 0 | None — spike results plus standalone defect fixes. |
| 1 | Reachability containment (lockdown + compartments + closed inventory) against ambient-authority theft; audit attribution is best-effort and forgeable; **no enforcement claims at the host boundary**. |
| 2 | Frame-accurate attribution; enforce mode defensible at the host boundary. |
| 3 | Engine-native compartments; dynamic code bound natively; build-time rewrite retired. |
| 4 | Productized package containment (policy, attenuators, rollout). |
| 5 | Optional deputy hardening for selected capability classes. |

### Phase 0 — Prove semantics on stock Hermes (days–2 weeks)

- Run the SES shim's `lockdown()` in the ibex REPL against the pinned build;
  triage failures into: conformance gaps (candidate upstream/overlay
  patches), repairs-ordering issues, hard blockers.
- Standalone defect fixes that land regardless of this RFC's fate:
  hide/remove the `__exact*` escape hatches at end-of-bootstrap; unify
  `child_process` → `process:spawn` against the canonical manifest; collapse
  the historical `Capability`/`Strict` split into one enforced mode. (The
  naming and mode defects would otherwise pollute Phase 1 audit data.)
- Begin the **real-global inventory**: enumerate every property bootstrap
  installs on the true global, including the lazy `__exactEnsure*`
  installers `[observed]` (`src/engine/hermes_runtime.cc:1056-1074`), as
  input to the Phase 1 classification.
- Validate the package-identity decision (Resolved questions §1) against
  real Exact/Snapback graphs and draft the policy format as an extension of
  the existing manifests.
- **Deliverable**: findings appended to this LLP; go/no-go for Phase 1.
- **Kill criterion**: SES fundamentally cannot run and the gaps are not
  small patches → stop; instance-level isolation remains the model, and this
  RFC moves to `llp/tombstones/` with the findings recorded.

### Phase 1 — Userland compartments, audit mode (2–6 weeks, no fork)

- Bundler-level compartmentalization: per-package free-global rewrite plus
  strict-mode emission in the Oxc/Rolldown pipeline (LLP 0007), endowments
  wired by the loader, SES lockdown (with evaluator taming) at boot.
- **Dynamic-code handling is a Phase 1 deliverable, not deferred**: `eval`
  and `Function` tamed or denied by default under compartment mode;
  indirect-eval semantics defined; the runtime compiler hook covers
  transform-at-load and dynamic import per Resolved questions §2.
- **Complete the real-global inventory**: every installed native global
  classified — removed, hidden, endowed via attenuator, or retained inert —
  and the lazy `__exactEnsure*` pattern becomes eager-install-then-seal so
  the true global is closed before package code runs. The `__exact*` family
  is a subset of this checklist, not the whole checklist.
- Audit mode: **would-deny decisions are logged while the operation
  proceeds** (the compat corpus needs the would-deny data), with best-effort
  transform-derived attribution that is explicitly forgeable —
  frame-accurate claims begin in Phase 2. Runs against real Exact/Snapback
  app graphs.
- **The conformance suite is born here** — lockdown semantics, compartment
  isolation properties, endowment behavior, capability enforcement
  end-to-end, and named red-team cases: *recover the real global*,
  *dynamic-code escape*, *sloppy-`this` escape*, prototype patching,
  identity forgery, host tampering. This suite is the durable asset the
  fork phases and every future rebase are measured against.
- **Historical deliverable**: the rollout used an audit selector. The current
  equivalent is the non-durable `ibex capsec audit` command; compat reports
  include lockdown and direct-eval semantic deltas.
- **Kill criterion**: unmanageable breakage across top dependencies →
  remain audit-only indefinitely (still valuable: honest attribution +
  drift detection) and do not start fork phases.

### Phase 2 — Fork, additive patches (2–4 weeks)

- Frame-provenance attribution at the host boundary (replaces the
  thread-local in `hermes_runtime_internal.h:168-179`), including the
  evaluation-unit alignment decision from Mechanism 3 (per-package module
  units vs a function-range table).
- Native `lockdown()` / freeze-at-boot (build-time snapshot if the AOT
  pipeline allows).
- Host-bridge globals made unreachable natively.
- Microtask/native attribution semantics pinned down here (Open question 3),
  with red-team cases for each rule.
- Host-boundary check semantics distinguish **ambient** operations
  (frame-keyed) from **handle-mediated** operations (authority baked into
  the attenuator at creation) per Design §Delegation and authority flow —
  frame identity must not deny a legitimately passed handle. Red-team/
  conformance cases cover delegation-through-passing explicitly.
- Patch classes: new files + small insertion points (see Upstream tracking).
- **Deliverable**: the first phase entitled to claim frame-accurate
  attribution — demonstrated against red-team cases covering callbacks,
  prototype patches, promise jobs, native frames, and host-created
  callables.

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
- Attenuators built authority-bearing with a re-attenuation surface
  (`fsHandle.scoped(...)`) per Design §Delegation and authority flow.
- Dynamic-permission mechanism (Design §Interaction with user-facing
  dynamic permissions): tri-state grant status, root-grant runtime
  mutation, revocation cascade into handles; ABI entry points specified in
  LLP 0002 when they land.
- Request-manifest cascade: per-package `ibex` manifests as intersected
  requests down dependency edges; the build emits the resolved
  effective-policy artifact as the reviewable record; request inference
  tooling (Open question 11).
- (The `child_process`→`process:spawn` and `Capability`/`Strict` mode defect
  fixes moved to Phase 0 so audit data starts clean.)

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

Ibex builds stock Hermes from a pinned commit on a stable release branch:
`hermes-version.sh` defines `IBEX_HERMES_SOURCE_COMMIT` (the pin; the
`IBEX_HERMES_SOURCE_REF` branch name is kept for humans and the canary's
drift leg but moves upstream — ENG-23092), `build-hermes.sh` /
`build-hermes-linux.sh` clone and build it, `update-hermes.sh` drives updates
`[observed]` (`scripts/hermes-version.sh`; `scripts/build-hermes.sh`;
`scripts/update-hermes.sh`; the stale `build-hermes-macos.sh`, which still
called the removed `configure.py` flow and was invoked by nothing, was
deleted). The fork adds a `patches/hermes/` directory —
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

1. Update `IBEX_HERMES_SOURCE_REF` to the new stable branch and
   `IBEX_HERMES_SOURCE_COMMIT` to the chosen commit on it (the commit is what
   the build scripts check out).
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
   CI from Phase 1 (which also tracks the strict-mode emission and
   direct-eval semantic deltas). Kill criteria in Phases 0–1 exist because
   of this risk.
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
   Phase 2 design review (see Open questions), including the
   evaluation-unit ↔ package alignment from Mechanism 3; red-team cases for
   each.
6. **Hermes upstream direction.** Static Hermes may reshape the interpreter.
   Mitigation: minimal-surface design + canary CI + re-derivation posture.

## Acceptance criteria

### For accepting this RFC

- The Threat model section is normative for all user-facing descriptions,
  and the security-claims-by-phase table is consistent with the Plan.
- The named red-team cases are specified well enough to implement without
  further design work.
- Phase 0 findings are recorded in this document before Phase 1 begins
  (post-spike revision).

### Feature / phase exit criteria

- The escape-hatch globals are unreachable in all modes. *(Phase 0; ships
  first.)*
- Audit mode running on at least one real Exact app graph and one Snapback
  app graph (Resolved questions §7), feeding the compat corpus, with
  would-deny logging. *(Phase 1.)*
- A deliberately compromised transitive dependency in a demo app, in enforce
  mode, cannot read a file outside its grants, exfiltrate `process.env`, or
  call the network — demonstrated by red-team tests in CI (the same tests
  that currently succeed against the advisory model must fail against
  enforcement). *(Phase 2+.)*
- Attribution in the audit log is frame-accurate under the red-team suite's
  forgery attempts. *(Phase 2+; Phase 1 claims best-effort only.)*
- Perf and memory within Goals §3 budgets on the benchmark suite.
  *(Gated from Phase 2 on.)* Steady-state compartment overhead is measured by
  `benches/compartment_overhead.rs` (A/B on the `anyCompartmentActive_` guard):
  ≈0% on a dev machine, within the ≤1% budget. A broader workload/memory sweep
  remains for a real-app benchmark corpus.
- The pin-bump runbook executed on ≥2 real upstream releases within budget.
  *(Phase 3/4 operational readiness — not RFC acceptance.)*
- `--capsec audit` and `--capsec enforce` (naming TBD) shipped in the CLI;
  defaults unchanged until a separate decision LLP.
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
   before the policy format freezes. *Refinement (2026-07-02 review):* the
   package name is the policy **selector**; the runtime **principal** is the
   name plus resolved locator (lockfile identity / path / integrity as
   available). Current Ibex uses the path-derived package name plus the package's
   self-reported `version` field to form `name@version`; this distinguishes
   coexisting installed copies but is not a trust boundary against a malicious
   package that forges its manifest version. Audit logs emit both, so coexisting
   versions and aliased packages stay distinguishable (see the policy sketch in
   Design §Policy).
2. **Dynamic import and plugins** — default-deny: code outside the build
   graph runs as a no-capability quarantine principal (refused outright in
   enforce mode unless policy names it), and the runtime loader applies the
   same free-global rewrite at load time where it already transforms
   sources (LLP 0007/0009). Phase 3's engine-native model subsumes this
   naturally. *Clarification (2026-07-02 review):* in enforce mode the
   static transform may reject packages that use dynamic code unless policy
   opts them into the runtime compiler hook; direct `eval` under the rewrite
   becomes compartment-bound indirect eval — a documented semantic delta.
5. **`ses` sourcing** — Phase 0 spikes with the full Agoric `ses` shim
   (fastest conformance signal); shipping builds vendor a lockdown-only
   subset (no Compartment shim — compartments come from the bundler),
   consistent with the hermetic vendoring posture (LLP 0005). Small Hermes
   conformance fixes are upstreamed opportunistically, where MetaMask's
   standing interest provides allies. *Clarification (2026-07-02 review):*
   the vendored subset includes the freeze walk, the repairs, **and
   evaluator taming** — taming is load-bearing (Mechanism 1), not optional
   hardening.
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
10. **Delegation model** (2026-07-02) — passed attenuated handles are the
    primary delegation mechanism between packages; per-package manifests
    are intersected **requests** cascaded down dependency edges, with the
    app's policy as the sole grant root (Design §Delegation and authority
    flow). Corollary, normative for Phase 2: handle-mediated host
    operations check possession, not calling-frame identity — frame
    attribution serves audit and ambient checks.
11. **Grant authoring surface** (2026-07-02) — the app's policy artifact is
    **generated** from static analysis of root-principal import-site grant
    declarations (union across sites; entry-scoped; fail-closed on
    anything non-static) composed with the request/delegation cascade. The
    committed artifact with per-entry provenance is the reviewable record,
    drift-checked in CI with capability *expansions* reported as the
    review tripwire. Import-site syntax is a grant channel in
    root-principal code only; in package code it is inert (stripped and
    reported). Grants are declared, never inferred from usage — a
    malicious update needing new ambient authority fails closed until the
    app author edits their own import site. Runtime/dynamic grants are
    bounded by the artifact as a ceiling. Co-located `also:` exceptions
    cover transitive packages the cascade can't reach, with the honesty
    rule that their edge-association is provenance, not enforcement. Full
    specification: LLP 0014.

## Open questions

*Lean* lines record the current recommendation so a future resolution can
agree or push back against something concrete. Question 3 resolves in
Phase 2 design review; 4, 8, and 9 wait for evidence; 12 waits on
Phases 2 and 4.

3. **Microtask/native attribution semantics**: attribute promise jobs to the
   compartment that scheduled them (recorded at schedule time) or to the
   frame that resolves? Host calls with no JS frame on the stack?
   *Lean:* skip runtime-internal frames, attribute to the nearest user
   frame, fall back to a schedule-time-recorded principal (async-context
   propagation) when none exists. Pin down in Phase 2 design review with
   red-team cases — attributing internal frames to a trusted "runtime"
   principal is a deputy surface and must not be the accidental default.
   Audit entries for deputy-shaped flows should make the acting-principal
   chain visible: at minimum the top user frame's principal plus the
   schedule-time principal when they differ.
   *Resolved (both halves landed).* Nearest-user-frame with runtime-internal
   frames skipped is patch 0002's `getCurrentPackageId`; the no-user-frame host
   call fails closed via patch 0007's `kNoUserPrincipal`. The schedule-time
   fallback is patch 0008 (ENG-22631): the scheduling principal is captured at
   `enqueueJob` and appended to the deputy-class stack so a deputy op detached
   across a microtask is attributed to its scheduler, not just the bare deputy
   frame. The embedder-owned queues (timers, `nextTick`, `setImmediate`, the
   non-JSI `queueMicrotask` fallback) get the same treatment (ENG-22759): the
   scheduling principal captured for each host callback (ENG-22761's
   `g_native_callback_principal_id`) is appended to the deputy-class stack in
   `checkCapabilityWithFsMode`, so a deputy method detached across
   `setTimeout(deputy.method, 0)` is attributed to its scheduler just like the
   Promise case. The remaining "make the acting-principal chain visible in audit
   entries" refinement (surfacing scheduler ≠ top-frame in the audit log) is
   deferred, tracked with the deputy audit-chain work.
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
9. **Module-exports freezing**: CJS export objects are shared mutable
   surface (see Threat model); freeze exports at load, per-package by
   policy, or accept the channel?
   *Lean:* offer freeze-on-load as per-package policy (default off), measure
   breakage in the Phase 1 compat corpus, and revisit a stronger default
   with evidence — blanket freezing breaks lazy-export and circular-require
   patterns common in real npm code.
12. **Runtime grant surfaces** (successor to the dynamic half of resolved
    question 11): dynamic `import(spec, { with: { permissions } })` waits
    on Phase 2 attribution (a dynamic grant needs a soundly identified
    grantor) and Phase 4 attenuators; effective grant is
    caller-authority ∩ requested, bounded by the generated artifact as
    ceiling (LLP 0014 §Dynamic grants and the static ceiling); re-import
    with differing permissions in enforce mode should error. Post-import
    grant to an instantiated compartment is disfavored — retroactive
    amplification of every importer. Extent-scoped delegation (the
    React-context/`AsyncLocalStorage` shape) is considered and deferred in
    LLP 0014 with the confused-deputy hazard recorded; request-manifest
    inference tooling continues as LLP 0014 Open question 3.
    *Lean:* handles first; revisit only with a concrete case the cascade
    and handles cannot express.

## Implementation status

First implementation landed on branch `llp-0013-compartments` (2026-07-02).
This section is the living record of what exists in the tree and doubles as the
stable anchor set for `@ref LLP 0013#…` code annotations (the short slugs below).

Phase 0 findings (recorded per the acceptance criteria, from the on-engine
spike against the pinned Hermes `260318099.0.0-stable`):

- **SES semantics are viable on this Hermes.** `Object.freeze` is honored:
  after freezing a prototype, a strict-mode write throws and the original value
  persists, while normal use (`[].map`, `instanceof`) is unaffected. Sloppy-mode
  writes silently no-op rather than throw — the reason strict-mode emission
  (Mechanism 2, channel #2) is load-bearing.
- **Evaluators are reachable and must be tamed.** `({}).constructor.constructor`
  reaches `Function`; `(function*(){}).constructor` reaches
  `%GeneratorFunction%`; indirect `eval` works. Lockdown tames all of these.
- **No async generators.** This Hermes rejects `async function*` source, so
  there is no reachable `%AsyncGeneratorFunction%` intrinsic to tame (and the
  build pipeline already lowers async generators — LLP 0007).
- **Real-global inventory.** The ambient-authority escape hatches on the true
  global are `__exactSetActiveModuleId` (attribution setter) and
  `__exactGrantCapability` (self-grant); both are now captured privately by
  trusted code and deleted at end-of-bootstrap. The lazy `__exactEnsure*`
  installers remain (eager-install-then-seal is deferred; see Phase 1 note).

Security-claim ceiling reached so far: **Phase 2** on macOS — frame-accurate
host-boundary attribution is wired end-to-end against the built patched engine
and demonstrated by the conformance suite (a compromised dependency's *deferred*
host access, through the same async path and the same trusted deputy as the
app's own, is attributed to the dependency and denied). Phase 1 (reachability
containment, real-global inventory closed) and the Phase 0 defect fixes remain in
force. **Phase 3** native compartment globals are landed (patch 0004): the
interpreter resolves bare globals and sloppy-`this` through the per-package
Domain compartment with no source rewrite; its refinements are landed too
(patch 0006): `eval`/`Function`-produced code binds to the caller's compartment
and principal (captured at the eval call site), and a native transitive
deep-freeze (`__exactDeepFreeze`, behind `IBEX_NATIVE_LOCKDOWN`) does the
intrinsics freeze in C++. **Phase 5** (opt-in stack-intersection) is wired to
real frame stacks. **Phase 4** authority-bearing attenuators (possession-based
`FsHandle` with `scoped()` re-attenuation and a revocation cascade), the
dynamic-permission mechanism (tri-state grant status + ceiling-bounded runtime
grants), and a grant-change signal (`Ibex.permissions.onChange`) for embedder
UIs are landed; the OS-broker UX / async-acquisition / per-view-grant layer
remains embedder work per §Interaction with user-facing dynamic permissions. See
[Upstream tracking](#upstream-tracking-and-re-derivation) and
`patches/hermes/README.md` for the carried patch stack (0001–0008) and the
Ibex-side integration.

Phase 2 finding (recorded per the acceptance criteria): the trusted runtime
**deputies** must be transparent to attribution. Ibex's high-level host surfaces
(`fs`, `process`, `fetch`) are JS modules layered over the native `__exact*`
functions; the frame walk reaches the true caller only because those deputy
Domains carry a reserved *runtime principal* (`0xFFFFFFFF`) that the walk skips
(Open question 3's "skip runtime-internal frames" rule, now concrete). Two
surfaces surprised the spike: `process.env` and `fs.writeFileSync` both had
enforcement gaps orthogonal to attribution. Both are now fixed.

The `fs:write` gap: the fd-based `__exactFsOpen` path checks the capability
after parsing the open flags and gates on the actual access intent
(`O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND` → `fs:write`, read-only → `fs:read`),
so a write through the fd path is attributed and enforced
(`tests/llp0013_compartments.rs::fs_write_requires_fs_write_capability`). The open
gate also treats an exotic/invalid access mode (`O_ACCMODE == 3`) as requiring at
least `fs:read`, so flag math can only widen the requirement, never skip it
(ENG-22639). Enforcement is not limited to the fd path: the standalone
path-based mutators — `symlink`, `link`, `truncate`, `chown`, `lchown`, `utimes`,
`lutimes`, `lchmod`, `rename` (both `from` **and** `to`) — each gate `fs:write`,
and `readlink`/`statfs` gate `fs:read`, so no path-based `fs` mutator bypasses the
gate (ENG-22627; `lutimes`/`lchmod` were the last two ungated link mutators,
closed in ENG-22682).

Path-scoped grants resolve symlinks before matching (ENG-22682). A grant string
names a path prefix (`fs:write:/app/safe/**`), and the check value is built from
the raw path the operation targets — but the OS follows symlinks when it runs the
syscall. So `normalize_fs_resource` (`src/host/capability.rs`) resolves the
symlink-bearing prefix of *both* the grant pattern and the checked value to the
path the kernel will actually reach, walking the deepest existing ancestor when
the leaf does not yet exist (the `O_CREAT` case a purely lexical fallback missed):
a write to `/app/safe/link/new` where `/app/safe/link → /outside` is a symlink now
normalizes to `/outside/new` and no longer matches the `/app/safe/**` grant.
Symlink *creation* additionally gates its resolved target, and hard-link creation
gates `fs:write` on the source inode (not just `fs:read`), so a scoped principal
cannot plant an escaping alias for a later in-grant traversal to follow. The
guarantee is traversal-time denial at the normalize choke point every mutator
shares; the residual check-vs-syscall TOCTOU (low risk under single-threaded,
same-principal JS) is noted for a possible `openat`/`O_NOFOLLOW` follow-up.

**Closed follow-ups (from the ENG-22682 and ENG-22716–ENG-22722 reviews).**
The fd-based metadata mutators `fchmod`/`fchown`/`futimes` now use the fd→path
registry captured at open time and gate `fs:write` on the underlying path before
the metadata syscall. The link-only mutators (`lchmod`/`lutimes`/`lchown`) now
use no-follow-final normalization, so a grant on the symlink target does not
authorize metadata mutation of the symlink entry itself (ENG-22716). POSIX
`access(W_OK)` requires `fs:write` rather than only `fs:read` (ENG-22717).
Dynamic relative `import()` preserves the caller referrer for both resolution and
import-gate attribution (ENG-22718). `Bun.which` probes are gated by
`process:spawn` (ENG-22720). Native TCP, UDP, Unix-domain, and HTTP serving
operations gate the relevant `network:connect`, `network:listen`, or
`network:local` capability at the host boundary before probing, connecting,
binding, listening, or sending (ENG-22722). The residual check-vs-syscall TOCTOU
from path normalization remains the known possible `openat`/`O_NOFOLLOW`
follow-up.

The `process.env` gap: `process.env` is a JS Proxy whose reads funnel every key
through the capability-checked native `__exactGetEnv`/`__exactGetAllEnv`
(`env:read:<key>` / `env:read:*`) — so env reads are gated per principal under
`--capsec enforce` (`capability.rs::env_read_is_gated_per_principal`), on top of
Mechanism-2 withholding, which contains a non-endowed package regardless of
capsec mode. The residual was a laundering channel: a former
`process.__exactPlainEnv` plain-object *snapshot* (a `--lockdown`-era workaround
for a since-replaced native env HostObject) copied the whole environment ungated
at boot, so any code reaching `process` could read it past its `env:read` grant.
It had no readers and is removed, so env reads have exactly one gated path
(`tests/llp0013_compartments.rs::env_reads_are_gated_with_no_plain_snapshot_bypass`).

**Enforce mode is usable by default.** `--capsec enforce` is where the capability
checks (env, fs, network, spawn) actually block, so it must be runnable without
the app declaring grants for its own operation. Two rules make it so, mirroring
`decide_import`'s trust of the first-party principal (RFC Resolved Q1):
`decide()` trusts the **root principal** (`"0"`, the first-party app — its
nearest attributable frame reports principal 0) and the synthetic
**`module-loader`** principal (Ibex's own bundle/module reads, governed by the
import gate, not the capability system). So the app has ambient authority and
only third-party packages (non-zero principals) are gated. The exception
preserves Phase 4: when the policy declares a **ceiling** (the app opted into
dynamic user-facing permissions), root is no longer blanket-trusted — it falls
through to the normal allow-list + dynamic-grant precedence bounded by the
ceiling, so a capability outside the ceiling stays denied and the tri-state
permission model holds. Consequence: the capability gates and audit-mode
would-deny reporting apply to *dependencies*, not first-party code (the app's own
usage is authored through import-site grants, LLP 0014, not discovered by audit).
Tested by `capability.rs::{root_principal_is_trusted_without_a_ceiling,
module_loader_principal_is_trusted, ceiling_restores_root_gating_for_dynamic_permissions}`.

Trusting root 0 forced closing the async/deputy attribution boundary (Open
question 3) so it could not be laundered. `getCurrentPackageId` previously
returned 0 both for a genuine first-party frame and for a stack with *no* user
frame; the latter let a package detach a deputy from its own frame
(`Promise.resolve(x).then(fs.readFileSync)` — the reaction runs with no package
frame) and have the op attributed to trusted root. Patch 0007 makes the
no-user-frame case return a distinct `kNoUserPrincipal` (`0xFFFFFFFE`) that fails
closed, and stamps Hermes's internal bytecode (the JS Promise implementation,
whose `tryCallOne` reaction trampoline otherwise carried packageId 0) with the
runtime principal so it is skipped as a deputy. The app's own async work is
still trusted (its callback frame carries principal 0); a dependency's detached
deputy reaches no user frame and is denied. Because the endowment config
(`IBEX_ENDOW`) is read by the compartment registry — a deputy with no user frame,
now failing closed — it is injected directly by the host (`__ibexEndowRaw`)
instead of through the capability-gated `process.env`. Red-team:
`tests/llp0013_compartments.rs::detached_deputy_read_is_contained_but_app_wrapped_read_works`.

Patch 0007 closed the *native* detached-callback case (empty stack → fail
closed), but not the deputy-class case where the detached callback is a JS deputy
**method** (ENG-22631): `Promise.resolve(SECRET).then(deputy.readFor)` under
`deputyClasses: ["fs:read"]` drains with the deputy's own frame live, so the
collected stack is `[deputy]` (len 1), the stack-intersection AND is skipped, and
the read is allowed for an ungranted scheduler. This is Open question 3's
schedule-time-principal case made concrete, and it is not soundly closable from
the stack alone — a len-1 package stack is *also* the normal shape of a granted
package running its own async continuation. Patch 0008 resolves it by recording
the scheduling principal at `enqueueJob` (where the scheduler's frame is still
live — the frame walk reaches past the native enqueue frame and the runtime-
internal Promise trampoline to the real caller), carrying it in a job-parallel
queue, restoring it as ambient runtime state across the job's drain, and
**appending** it to the deputy-class stack. The detached read then collects
`[deputy, scheduler]`: an ungranted scheduler makes the AND deny, while a granted
package's own continuation (scheduler == running principal) collapses to a single
principal and is **not** false-denied. The enqueue-time walk is armed whenever
the patched engine is present; the host consumes the captured scheduler only for
live deputy-class stack checks or the `kNoUserPrincipal` fallback, so a boot-time
absence of deputy classes cannot permanently disable later hardening.
Host-scheduled callbacks outside Hermes's Promise queue (timers, `nextTick`,
`setImmediate`, the non-JSI `queueMicrotask` fallback, and native fetch/HTTP wait
completions) also capture the caller principal in the embedding
(`g_native_callback_principal_id`, set by `ScopedNativePrincipal` around each
detached drain); stored native handles still enforce their owner and capability
metadata before operating. That capture originally applied only when a
host-boundary check re-entered from a *no-user-frame* callback — which left the
deputy-class case open (ENG-22759): a deputy **method** detached across a host
timer (`setTimeout(deputy.readFor, 0, SECRET)`) fires with the deputy's *own*
frame live, so the walk returns the deputy (not `kNoUserPrincipal`) and the
captured scheduler was never consulted, leaving `[deputy]` (len 1) and the
deputy-class AND skipped — the same laundering patch 0008 closed for the Promise
queue, on a different (embedder-owned) queue. `checkCapabilityWithFsMode` now
**appends** the captured host-queue scheduler to the deputy-class stack exactly as
`collectStackPackageIds` appends the Promise-queue scheduler (the Promise queue
lives in the VM; the timer/nextTick queues live in the embedder, so the append is
done host-side): `[deputy, evil]` denies, while a granted package's own timer
continuation (scheduler == the innermost frame) collapses and is not false-denied.
Red-team:
`tests/llp0013_compartments.rs::async_detached_deputy_read_is_contained_but_granted_self_async_works`
and `::host_scheduled_detached_deputy_read_is_contained_across_timer_channels`
(setTimeout + `process.nextTick` + `setImmediate`, each with a permissive control
that leaks). Residual, out of scope by default: a deputy that itself re-schedules
the op across a further async hop is "deputy by design" (RFC §What this does not
attempt to solve).

The `ScopedNativePrincipal` override must cover **only** the host callback's own
invocation, never the queue drains that follow it. The timer fire loop originally
scoped it over `runNextTickQueue` **and** `drainMicrotasks`, so while pending
Promise microtasks drained, `g_native_callback_principal_id` stayed pinned to the
timer owner. An ungranted dependency's *detached* deputy read — the fs deputy
passed straight to `.then` (`Promise.resolve(SECRET).then(fs.readFileSync)`), which
runs with no user frame so `getCurrentPackageId` reaches `kNoUserPrincipal` and the
top-level poll denies it — then resolved, when scheduled inside the owner's timer
callback, to that pinned owner via the `currentPrincipalId` `kNoUserPrincipal`
fallback instead of failing closed. That laundered the read into the timer owner's
authority in the **default** enforce mode with **no** `deputyClasses` configured (a
capability escalation, distinct from the deputy-class host-queue laundering closed
by ENG-22759). The identical read fails closed both at the top-level poll and when
the ungranted dependency schedules it itself — proving the timer scope was the
fault (ENG-23112, finding H). The fix restricts the override to just
`callback.call(...)`; `runNextTickQueue` already re-scopes per entry, and the
microtask drain now matches the top-level poll. Red-team:
`tests/llp0013_compartments.rs::timer_microtask_drain_does_not_launder_detached_deputy_into_owner`
(ungranted `evil-pkg` detached read contained at the top level and, post-fix,
inside root's timer; the owner's own timer read is not false-denied).

#### Mechanism 1

Lockdown (`--lockdown` / `IBEX_LOCKDOWN`): at end-of-bootstrap the shared
intrinsics graph is frozen and the `%Function%` family + indirect `eval` are
tamed (`src/engine/hermes_runtime.cc`, `<lockdown>` eval). The module loader
captures the real `Function` privately so it can still compile CommonJS bodies.
Verified against the named red-team cases (`tests/llp0013_compartments.rs`).
The intrinsics freeze runs in userland by default (the SES `harden` graph walk);
under `IBEX_NATIVE_LOCKDOWN=1` the harness instead freezes each intrinsic root
with the native `__exactDeepFreeze` (patch 0006) — a transitive freeze that walks
property *descriptors* (getters/setters read without invoking) and prototypes in
C++ via an iterative worklist with an explicit GC-safe visited set (distinct from
the frozen bit, no recursion-depth cap), retiring the JS walk. Both produce
an identically locked-down runtime; tested by
`native_lockdown_freezes_intrinsics_and_contains_redteam`. The freeze primitives
`__exactDeepFreeze`/`__exactNativeFreeze` are **internal**: the bootstrap lockdown
pass is their only consumer. They were originally kept out of the end-of-bootstrap
escape-hatch seal because that pass runs after the seal, but that left them
reachable from package code in the default (non-lockdown) enforce/audit mode —
where the compartment membrane that would withhold `__exact*` never runs — as
ungated native integrity/DoS primitives (`globalThis.__exactDeepFreeze(x)` freezes
shared intrinsics or another package's graph). A dedicated freeze seal now deletes
both from the global in **all** modes, immediately after the lockdown pass
consumes them, restoring the "escape-hatch globals unreachable in all modes"
acceptance criterion (ENG-23112, finding L). Regression:
`native_deep_freeze_freezes_a_graph_without_invoking_getters` and
`native_freeze_primitive_freezes_objects` now assert the globals are sealed away.

#### Mechanism 2

Per-package compartment globals have two delivery paths. The engine-native
Domain path is the production security boundary; the build-time rewrite is
currently compatibility routing and defense in depth on top of it:

- **Build-time (Phase 1)**: the rewrite (`rewriteFreeGlobals` /
  `createCompartmentGlobalsPlugin` in
  `packages/ibex-devtools/src/scripts/transforms.mjs`, wired through
  `rolldown-bundle.mjs` and gated by `run_bundler`) routes each package's bare
  globals to `__compartments[<pkg>]`. The runtime registry
  (`<compartment-registry>` in `hermes_runtime.cc`) installs a detached
  descriptor baseline and prototype-chain copy during native bootstrap. A
  required one-shot hook refreshes that baseline only after the selected
  embedded, disk-fallback, preinstalled, or Windows-minimal runtime path has
  finished; a non-configurable final marker makes the handshake fail-closed and
  idempotent. Own lazy accessors initialize once against the real global and
  memoize their value, while every global alias (including `window`) resolves to
  the requesting package's compartment rather than the realm global.

  The trusted loader holds the root registry view. Through the native Domain
  path, a package sees only a read-only view scoped to its exact identity, so
  it cannot retrieve, poison,
  delete, enumerate, or freeze away another package's compartment. When the
  registry is armed, missing lookup state or a failed native Domain bind refuses
  module execution rather than silently using the real global. Each compartment
  otherwise has a private mutable target whose reads resolve only against the
  final baseline. Prompt/session declarations, sloppy assignments, later
  top-level bindings, and replaced builtin slots therefore do not cross the
  boundary; powerful baseline bindings remain withheld unless endowed
  (`IBEX_ENDOW` / `globalThis.__ibexEndowments`), and writes/reflection remain
  package-local.

  This is a **property-binding and existence boundary**, not a claim that every
  object reachable as a captured descriptor value is deep-isolated. Shared
  values such as `console` or `crypto` can still carry nested mutable state when
  lockdown has not frozen or replaced them; per-principal facades/hardening and
  root/package/sibling mutation tests are tracked by ENG-24514. End-to-end here:
  a compromised dependency cannot acquire `process` or a post-finalization root
  session binding through its compartment.

  The build-time rewrite no longer reads a source-shadowable root-registry
  identifier. Its exact-importer-bound virtual module exports only the caller's
  package compartment into a hygienic lexical import; authored raw-registry
  reads route through that compartment's scoped registry, cross-scope imports
  fail the build, and package-bearing chunks are emitted strict (ENG-24526).
  Flat output nevertheless remains defense in depth rather than the production
  boundary: the transform's finite global set does not yet route arbitrary
  unbound names such as a post-arming `apiKey`. ENG-24527 tracks all-free
  rewriting and its CJS/call-semantics constraints. Production package modules
  execute inside native Domains, where every global resolution is scoped
  independently of the finite transform.
- **Engine-native (Phase 3) — landed (patch 0004).** The interpreter resolves
  `GetGlobalObject` and sloppy-`this` (`CoerceThisNS`/`LoadThisNS`) through the
  executing frame's `Domain` compartment global (`globalForFrame`), so a
  package's bare globals and its `(function(){return this})()` UMD escape both
  resolve through its compartment **with no build-time rewrite**. Top-level `var`
  declarations resolve the same way (`DeclareGlobalVar` /
  `Interpreter::declareGlobalVarImpl`), so an indirect `eval("var x = 1")` in a
  compartment defines `x` on the compartment global instead of splitting the
  declaration onto the shared real global. The loader sets
  each package's Domain compartment via the native `__exactSetCompartmentFor`
  (captured privately, sealed at end-of-bootstrap). Patch 0009 makes that same
  retained-function binder validate, stamp, and read back the authenticated
  numeric principal directly on the Domain after compilation. Package modules
  supply their compartment; root and runtime-deputy units bind without one.
  Invalid functions, supplied compartments, principals, and missing
  RuntimeModule/Domain state refuse execution; every caller requires the
  returned ID to match. Focused physical Windows source-profile evidence proved
  the CommonJS wrapper and its exported callback both carried the package
  principal, but the immediately following `process.env` deputy call observed
  root. A second physical Windows run accepted a retained `process.cwd` Domain
  bind/readback but still root-attributed the environment decision. The bundle
  therefore publishes the exact `process.env` Proxy trap and helper functions to
  the already-reviewed private shared-runtime marker as a bootstrap-only anchor
  list; native startup binds and reads back every listed Domain, then restores
  the marker to its ordinary boolean before package code runs. Lazy builtin
  functions go through the same exact binder. A third physical Windows run
  accepted the non-empty exact anchor list and all readbacks but still observed
  root on first package use. A conformance-only native stack trace then recorded
  `0,1,0` for the failing Windows call versus `1,0` for the same source-profile
  call locally, while naming the inner helpers from the disk-loaded vendored
  bundle. The cause was above Hermes: after native bootstrap had installed and
  authenticated the source bundle, `HermesEngine::load_runtime` hard-coded the
  Windows installed probe to false and evaluated that disk bundle a second time
  as root, replacing `process.env` and its retained helpers. Windows now runs the
  same installed-bundle probe as every other platform and reuses the native
  bundle; the speculative no-I/O materialization warmup was removed. This
  The next physical Windows run recorded the repaired `1,0` package call stack
  and passed all nine startup-environment recipes. Its callback smoke proceeded
  past deputy attribution and refused later while building the Exact artifact
  pair: armed-root identity opening requested generic read, which includes
  directory enumeration and returned access denied for a valid metadata-only
  root. Windows root identity now requests only `FILE_READ_ATTRIBUTES` and
  `SYNCHRONIZE`; that later artifact gate still requires a physical rerun. This
  closes channel #2
  (sloppy-`this`) natively and works for unbundled/dynamically-required code the
  rewrite never touches. Tested by
  `tests/llp0013_compartments.rs::native_compartment_withholds_globals_without_rewrite`.
  Refinements landed (patch 0005): a `Runtime::anyCompartmentActive_` hot-path
  guard so code that never uses a compartment skips the Domain walk, and a native
  `__exactNativeFreeze` freeze primitive. **`eval`/`Function` compartment binding
  is landed (patch 0006).** The capture happens in `evalInEnvironment`, where the
  caller's frame is still on the stack (it is gone by `runBytecode`): it reads the
  caller's principal + compartment (`getCurrentPackageId` /
  `getCurrentCompartmentGlobal`) into a pending slot — the compartment held in the
  GC-rooted `Runtime::pendingCompartment_` — and `runBytecode` stamps both onto
  the Domain it mints, so `eval` and `new Function` produced code inherits the
  caller's compartment (it cannot reach the root realm's globals) and attribution.
  When the eval has no attributable user caller, `getCurrentPackageId` returns the
  `kNoUserPrincipal` sentinel (patch 0007); the capture pins only a real package
  principal (it excludes both `0` and `kNoUserPrincipal`), leaving such a Domain
  unlabelled rather than stamping the sentinel as if it were a package id.
  The capture is skipped when a principal was labelled explicitly, so loader-driven
  module compiles keep their own principal; the loader `clearPendingPackageId()`s
  (distinct from pinning 0) after each compile so a later eval reads as unlabelled
  and inherits its caller. Tested by
  `tests/llp0013_compartments.rs::eval_and_function_inherit_the_caller_compartment`.

#### Mechanism 3

Frame-derived attribution: **wired end-to-end and tested** (macOS). The carried
Hermes patch stack (`patches/hermes/0001-0003`) adds `Domain::packageId_`, a
pending/default package id on `Runtime` consumed in `runBytecode`,
`getCurrentPackageId` (nearest non-runtime user frame), `collectStackPackageIds`
(Phase 5), and exported `ex_hermes_vm_*` C bridges reachable via
`IHermes::getVMRuntimeUnsafe()`. The module loader assigns and registers a
principal per package and stamps each module's Domain: first through the
creation-time pending principal, then through the private post-compile binder
(patch 0009), whose exact readback is checked before execution. The shared
runtime bundle and lazy builtins are bound and read back as runtime principal
`0xFFFFFFFF`, transparent to the walk; `checkCapability` reads the
frame principal via `currentPrincipalId()` behind the `EXACT_HAVE_FRAME_ATTRIBUTION`
build probe (unpatched engines fall back to the thread-local). The
thread-local, `__exactSetActiveModuleId`, and `__exactGrantCapability` are still
sealed at end-of-bootstrap (the deletion-outright cleanup is deferred to keep the
fallback path intact for unpatched targets). Red-team coverage:
`tests/llp0013_compartments.rs::frame_attribution_denies_deferred_dependency_but_allows_app`
(and its permissive-mode control). **Per-package bundled units:**
`IBEX_PER_PACKAGE_CHUNKS` makes the bundler emit one Rolldown chunk per npm
package (named `__ibexpkg__<pkg>`), which the loader compiles into its own Domain
stamped with the package principal — so a *bundled* app gets per-package
attribution too, not just the unbundled/dynamic-require path. In this mode the
loader resolves the `__ibexpkg__<pkg>` sibling specifiers — and the shared
`rolldown-runtime.js` interop chunk an ESM app emits — absolutely against the
chunk cache directory (`globalThis.__exactChunkDir`, the entry's parent) so the
split chunks find each other, while the entry module keeps its **source-relative**
`__dirname` / `__filename` (the entry-path remap is unaffected — only the chunk
specifiers are redirected; the runtime-chunk redirect is ENG-22681, without which
a chunked ESM app fails to resolve `./rolldown-runtime.js`). Tested by
`tests/llp0013_compartments.rs::per_package_chunks_give_bundled_apps_frame_attribution`
(with a flat-bundle control). The deputy caveat above still applies.

**Enforce/audit auto-enable this (ENG-22681).** Selecting enforce or audit — via
`--capsec` or a generated artifact's `mode` field — only changes the host-boundary
*decision* logic; on its own it does not give a bundled dependency its own
principal. A default flat bundle collapses to one Domain, so every `node_modules`
frame carries the trusted **root** principal and the capability gate (which only
bites non-root principals) never fires for a dependency — a `ibex run --policy
generated.json` that *looks* like enforcement while a dependency's `fs`/`env`/
network access is silently attributed to root. So enforce **and** audit now set
`IBEX_PER_PACKAGE_CHUNKS` by default (`enable_isolation_prerequisites` in
`src/bin/ibex/runtime.rs`); `IBEX_PER_PACKAGE_CHUNKS=0` is the explicit opt-out (all
three read sites use the shared truthiness parse so `=0` is honored — ENG-22634),
but enforce now treats that opt-out as advisory and fails closed unless the
operator also passes `--capsec-allow-advisory`. Audit emits the same
readiness report and warning but continues. Reachability hardening (Mechanism 1
lockdown + Mechanism 2 withholding) stays **opt-in** under `--lockdown`: freezing
intrinsics is the RFC's documented top compat risk (Risks §1) and is orthogonal to
the attribution footgun this closes — an ungranted dependency's dangerous op is
already denied at the host boundary once it is attributed to its own principal.
Tested by `tests/llp0013_compartments.rs::policy_declared_enforce_auto_enables_bundled_attribution`
(with an `IBEX_PER_PACKAGE_CHUNKS=0` opt-out control).

**Package identity — version-distinguished (Resolved Q1, ENG-22621).** The
canonical runtime identity is `name@version`: the package **name** is the policy
**selector** (it survives version bumps), and `name@version` is the runtime
**locator/principal** (`PackagePrincipal { name, locator }`). The version is read
from the resolved module's own nearest `package.json` — at resolve time in Rust
for the unbundled/native path (`ResolvedModule::package_version` → the loader's
`packageIdentityFor`), and at bundle time in devtools for the bundled path
(`packageIdentityOfModuleId`). This identity is used **uniformly** across every
boundary a package-name key used to cross:

- **Principals.** The loader keys `__packagePrincipals` by `name@version`, so two
  coexisting versions get **separate** principals (and Domains), and registers the
  bare name as the selector plus `name@version` as the locator.
- **Host policy lookup.** `decide` / `decide_import` consult the locator selector
  **before** the bare name (`PackagePrincipal::selectors`), so a policy can pin a
  specific version (`shared-pkg@1.0.0`) while the bare `shared-pkg` entry remains
  the default that applies to every version — the opt-in tightening Resolved Q1
  describes.
- **Compartments.** The runtime compartment registry, the loader's compartment
  binding (`compartmentForRecord`), and the devtools free-global rewrite
  (`createCompartmentGlobalsPlugin`) all key by `name@version`, so coexisting
  versions never share a mutable compartment global. Endowment lookup falls back
  from `name@version` to the bare name (`isEndowed`, `bareNameOf`), so a
  name-level `endow` entry applies to all versions while a pinned entry narrows.
- **Chunks.** The bundler groups by `name@version`, so two versions become
  separate `__ibexpkg__<name>@<version>` chunks → separate Domains → separate
  principals in a *bundled* app too.

Tested by `capability.rs::{version_locator_selector_overrides_name,
bare_name_selector_matches_all_versions}`,
`llp0013_compartments.rs::coexisting_versions_get_distinct_policy_treatment`
(unbundled + bundled), and `transforms.test.mjs::packageIdentityOfModuleId`.
Remaining scoped follow-up: matching human-friendly semver **ranges**
(`pkg@^2`) rather than exact `name@version` pins — the exact pin satisfies the
"version pins are opt-in tightening" language; range matching waits on a concrete
need. The artifact `packages` keys stay name-keyed by design (LLP 0014 §Residual
risks — "name-keyed grants survive version bumps"); a version pin is authored by
hand.

#### Import gating (Policy surface 3)

The import-graph gate is now wired end-to-end. The loader calls
`__exactCheckImport(requesterPrincipal, specifier)` → `ex_host_check_import`
before every `require`/import (before the module cache short-circuit), keyed on
the *requesting* package's principal; the host logs (audit) or denies (enforce)
per the requesting package's `builtins`/`packages` allowlists. Inert for the
root and runtime principals and for packages the policy does not restrict.
Closes the "no `fs` endowment but unrestricted `require('node:fs')`" hole. Tested
by `tests/llp0013_compartments.rs::import_gate_denies_restricted_package_builtin`
and `import_gate_is_inert_without_restriction`.

**Import-gate hardening (deep-review round 2).** Three escape channels closed:
(1) **Builtin aliases** — `is_builtin_specifier` now classifies the runtime's
`exact:`/`bun:` alias namespaces (`exact:sqlite`, `bun:sqlite`, `bun:fs`) as
builtins, so `builtins: []` denies them; previously they fell through to the
allow-by-default `packages` axis, a fail-open hole (ENG-22697). (2) **Detached
require** — `decide_import` fails closed for the `NO_USER_PRINCIPAL` sentinel, so
a detached callback with no package frame (`Promise.resolve("fs").then(globalThis.require)`)
cannot launder an import into trusted/root, mirroring `decide()`'s capability
rule (ENG-22696). (3) **Runtime self-grant** — the legacy
`Exact.setModuleCapabilities` / `require(spec, { needs })` channel is refused
host-side under enforce and audited without changing behavior under audit
(`CapabilityManager::runtime_self_grant` records a would-deny there) AND the JS
function is deleted at boot under enforce (`IBEX_SEAL_SELF_GRANT`), not just
under lockdown — so a package cannot escalate its own capabilities on the plain
`--capsec enforce` path once it learns its package id (ENG-22695/ENG-22770, was
**Urgent**: the seal previously only ran on the lockdown/compartment path).
Tested by
`tests/llp0013_compartments.rs::enforce_closes_runtime_capability_escapes` (with
a permissive control) and `capability.rs::{builtins_deny_covers_exact_and_bun_aliases,
import_from_no_user_principal_fails_closed, runtime_self_grant_is_refused_under_enforce_but_works_permissive}`.

#### Phase 0

The historical `capability`/`strict` mode spellings collapsed into canonical
`Enforce` (`strict` and `capability` kept as hidden CLI aliases); the process
spawn check unified to the canonical `process:spawn`; the escape-hatch globals
sealed.

#### Phase 1

Historically, audit mode (`--capsec audit`) logged would-deny decisions while
letting operations proceed, and the LLP 0013 binary/fixture corpus was the
durable red-team asset. LLP 0021 retired that string-policy plane and corpus;
the loaded-engine conformance batches plus the checked retirement map are now
the durable assets. **Real-global inventory closed:**
under lockdown/compartment mode the lazy `__exactEnsure*` installers are
eager-run then deleted before the intrinsics freeze (so no host surface can
appear on a frozen global mid-run), and the ambient self-grant channel
(`Exact.setModuleCapabilities`) is removed — grants come from the generated
policy artifact, not runtime self-declaration
(`tests/llp0013_compartments.rs::lockdown_seals_lazy_installers_and_self_grant_channel`).

#### Phase 4

Authority-bearing attenuators and dynamic permissions:

- **Attenuator handles** (`src/host/handles.rs`, `HandleRegistry`): a handle
  carries a capability grant fixed at creation; host operations mediated by a
  handle check **possession** (the handle's grant), not the calling frame — so a
  package with no ambient `fs` uses a handle it was handed, but only within that
  handle's grant. Handle grants use the same path algebra as ambient matching:
  an exact resource covers only that exact resource, and only a trailing `/**`
  covers the subtree (ENG-22882). `Ibex.fs.readHandle(dir)` mints a subtree
  handle carrying `fs:read:<dir>/**` (frame-checked: only a frame that holds
  that subtree capability may mint it); `handle.scoped(sub)` re-attenuates to
  the narrower `<dir>/<sub>/**` subtree (pass a full capability string to
  attenuate to a single exact resource); `handle.revoke()` fail-closes the
  handle and every handle derived from it (the revocation cascade, via an
  ancestor walk). Handle ids are 53-bit OS-random so possession cannot be
  forged by guessing. Tested by
  `tests/llp0013_compartments.rs::attenuator_handle_delegation_scoping_and_revocation`
  and `tests/llp0013_compartments.rs::exact_fs_grant_cannot_mint_subtree_handle`
  (+ `src/host/handles.rs` unit tests).
- **Dynamic permissions**: grant status is tri-state at the host surface
  (`grant_status` → granted / prompt / denied), and a runtime grant
  (`Ibex.permissions.request`) mutates the root principal's grant set **bounded
  by the policy `ceiling`** — the static artifact is the ceiling, a prompt moves
  the floor, never past it. `revoke` moves the floor back down. Acquisition is
  **async and lives in the attenuator** (`Ibex.permissions.acquire` returns a
  Promise that suspends on the broker decision) while the boundary check stays
  synchronous and consults the resolved state — never the prompt (the TOCTOU
  failure mode); the broker is pluggable (`Ibex.permissions.broker`), defaulting
  to resolve against the ceiling. A grant-change signal
  (`Ibex.permissions.onChange(cb)`) fires the registered listeners on every
  `request`/`revoke` with `{capability, status}`, so an embedder's UI (an OS
  permission sheet, a per-view indicator) can reflect live grant state without
  polling — the runtime provides the mechanism; the actual sheet/indicator UX
  stays embedder work. Tested by
  `dynamic_permissions_are_tri_state_and_bounded_by_the_ceiling`,
  `permission_acquisition_is_async_with_a_pluggable_broker`, and
  `permission_onchange_signals_grants_and_revocations`. The broker UX, per-view
  grants, and OS mapping remain embedder work per §Interaction with user-facing
  dynamic permissions.

#### Phase 5

Optional stack-intersection enforcement (`CapabilityManager::check_stack`,
policy `deputyClasses`): the effective permission for a configured capability
class is the AND of every principal on the call stack. **Wired to real frame
stacks:** `collectStackPackageIds` (Hermes patch 0002) →
`ex_host_check_capability_stack`; `checkCapability` takes the stack path only
when `ex_host_has_deputy_classes()`. Off by default. Tested by
`tests/llp0013_compartments.rs::stack_intersection_denies_deputy_driven_by_ungranted_caller`
and `stack_intersection_is_off_by_default` (a granted deputy reads for the app
but is denied when driven by an ungranted package, only under `deputyClasses`).

#### Policy generation

The grant-authoring surface and generator are specified and tracked in
LLP 0014: root-principal import-site grants compiled (with the request
cascade) into a provenance-carrying generated `PolicyFile` artifact;
`ibex policy generate|check`; boot-time endowment wiring from
`packages.*.endow` so the artifact drives Mechanism 2 end-to-end.

#### Upstream tracking

The pin plus the ordered `patches/hermes/` series (0001 Domain principal; 0002
frame attribution + stack collector + exported C bridge; 0003 Runtime
pending/default id; 0004 native compartment globals; 0005 native-compartment
refinements; 0006 `eval`/`Function` binding + native deep-freeze; 0007
fail-closed async/deputy attribution; 0008 schedule-time principal capture; 0009
post-compile package-principal binding) is the fork; `scripts/apply-hermes-patches.sh`
applies it after clone in every `build-hermes*.sh` and is exercised by the
`hermes-patch-canary` workflow. Class breakdown (per `patches/hermes/README.md`):
every patch is base A/B; the surgical Class C sites total **five** — 0003 (+1,
the `runBytecode` stamping insertion), 0004 (+3, the interpreter
`GetGlobalObject`/`this` cases), and 0005 (+1) — still within the single-digit
Class C budget the patch-shape discipline gates on.

## References

- LLP 0002 §Host ABI (capability check/grant/log surface); LLP 0004
  (module manifest and loader); LLP 0006 §"Capability-gated host"; LLP 0007
  (bundler/transform pipeline used by Phase 1).
- Reviews: `llp/reviews/0013-per-package-capability-compartments.openai.md`
  (independent family review, 2026-07-02, addressed by this revision);
  `llp/reviews/0013-per-package-capability-compartments.claude-fable.md`
  (author-side deep pass, 2026-07-02).
- Hermes pin: `scripts/hermes-version.sh` (`260318099.0.0-stable`).
- Inherited planning corpus (pre-extraction `exact` monorepo):
  `docs/plans/js-capability-security-master.md` — §7: permission
  declaration surfaces (import attributes, dynamic `import()` options bag)
  and the importer-intersection rule adopted by Design §Delegation and
  authority flow; §2/§13: the four-layer OS-intersection model and OS
  alignment rules underlying Design §Interaction with user-facing dynamic
  permissions; §10–11: revocable fail-closed handle semantics carried
  forward. Historical ancestry, not a normative reference; its
  `__moduleId` attribution mechanism (§9) is superseded by Mechanism 3.
- External `[inferred]`: Agoric SES/Endo & Hardened JavaScript; MetaMask
  LavaMoat; TC39 ShadowRealm proposal (rejected here for this use);
  Node.js process-level permission model and the removal of its per-module
  policy mechanism; Deno permissions; Java JEP 411 (SecurityManager
  deprecation); Electron's chromium patch-stack maintenance model.
