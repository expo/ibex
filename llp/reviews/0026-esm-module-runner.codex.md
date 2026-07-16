# Reviews of LLP 0026 — ESM Module Runner and Runtime Module Graph (Codex/OpenAI family)

Review artifacts for `llp/0026-esm-module-runner.rfc.md`, recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f654c-eee2-7d12-83ad-dc5c3558957f`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `48920030446b`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable review of the same revision and no prior LLP 0026 review
  artifact (none existed — this is round 1). Instructed not to read
  `llp/reviews/`.
- **Method:** cli-runner, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round1.md`) — same brief as the
  Fable reviewer: target, governing/related LLPs, required code-verification
  list, LLP 0005 standard questions, fixed output structure ending in an
  explicit verdict line.

### Verbatim review

## 1. Overall assessment

LLP 0026 is directionally correct and addresses a real architectural limit. The code supports its diagnosis: the raw loader relies on a large string scanner, synchronous CommonJS-shaped execution, snapshot bindings, and an ineffective dependency-TLA shim. Replacing that path with authenticated module records, linking, live cells, and asynchronous graph evaluation is a good idea.

At revision `48920030446b`, however, this is not yet decision-complete. The stable artifact/factory ABI is unspecified and unproven on the pinned toolchain; `SourceId` and exact-edge prerequisites do not exist in the current resolver; mixed-principal bytecode conflicts with Hermes attribution granularity; and async evaluation, cancellation, session parsing, interop, and several security-sensitive loader surfaces remain unresolved. This is a strong problem statement and migration skeleton, but not yet an implementable RFC with closed correctness and security semantics.

## 2. Strengths

- The diagnosis of the raw fallback is accurate. RFC §Motivation correctly says TS/JSX-like files and selected JavaScript are transformed while ordinary ESM may pass through unchanged (`llp/0026-esm-module-runner.rfc.md:55-78`). `needs_transpile` covers only `ts/tsx/jsx/mts/cts`, while JavaScript transforms only when the content scanners request downleveling (`src/module_loader/mod.rs:354-394`). `resolve_with_oxc_at` explicitly calls untransformed ESM the hot path and stores its source verbatim (`src/module_loader/mod.rs:928-946`).

- The scanner criticism is well founded. `transformEsmToCjs` spans approximately 842 lines (`src/engine/bootstrap/module-loader.js:4224-5065`) atop raw-source lexical helpers that distinguish comments, templates, regex literals, and division (`src/engine/bootstrap/module-loader.js:3743-3761`). It classifies imports and exports with regular expressions (`src/engine/bootstrap/module-loader.js:4545-4582`) and maintains multiline delimiter state (`src/engine/bootstrap/module-loader.js:4651-4755`). This is exactly the parser/linker responsibility identified in RFC §Motivation.

- The RFC accurately distinguishes CommonJS compatibility from full ESM semantics. Modules are compiled with a six-argument CommonJS-shaped `Function` wrapper (`src/engine/bootstrap/module-loader.js:235-272`), published to cache before evaluation (`src/engine/bootstrap/module-loader.js:5340-5368`), and invoked synchronously with the return value ignored (`src/engine/bootstrap/module-loader.js:5500-5506`). That preserves ordinary CommonJS early-publication cycles. It does not preserve ESM bindings: named imports are copied into variables (`src/engine/bootstrap/module-loader.js:4594-4616`), star exports copy property values (`src/engine/bootstrap/module-loader.js:4868-4876`), and exported variables are assigned to `module.exports` after declaration (`src/engine/bootstrap/module-loader.js:5031-5047`). RFC §5’s cells, TDZ, linking, and shared evaluation promise are therefore the right replacement (`llp/0026-esm-module-runner.rfc.md:307-334`).

- The dependency-TLA motivation is also correct. The loader may wrap a body in an async IIFE (`src/engine/bootstrap/module-loader.js:5415-5417`, `:5657-5675`), but synchronous invocation does not retain or await its promise and the module is immediately marked loaded (`src/engine/bootstrap/module-loader.js:5797-5798`). Dynamic import is Promise-shaped but invokes synchronous `load` inside the microtask (`src/engine/bootstrap/module-loader.js:6082-6149`). The separate CLI entry shim handles entry TLA (`src/bin/ibex/runtime.rs:1627-1653`, `:1685-1735`), confirming the RFC’s entry-versus-dependency distinction.

- The toolchain account is honest. SWC crates are present (`Cargo.toml:98-106`), SWC is the default (`src/module_loader/transpile.rs:38-77`), and it performs TS erasure, JSX lowering, CommonJS conversion, and helper injection (`src/module_loader/transpile.rs:109-196`). Oxc is already used for resolution and as an opt-in transform candidate (`Cargo.toml:44-53`; `src/module_loader/mod.rs:824-978`), but that candidate explicitly rejects TLA and remaining general ESM syntax (`src/module_loader/transpile.rs:199-264`). This supports the architectural fork described in RFC §§3 and Migration rather than concealing it.

- The proposed identity and authorization direction is strong. `(runtime, SourceId)` matches LLP 0023 exactly (`llp/0023-virtual-filesystem-namespace.spec.md:655-710`), and RFC §1’s authorize-before-resolve/read order (`llp/0026-esm-module-runner.rfc.md:208-228`) preserves the current host’s strongest property: armed preflight happens before resolver probing (`src/host/mod.rs:2201-2239`, `:2262-2272`), followed by authenticated owner/root/integrity verification (`src/host/mod.rs:2273-2346`). Current package principal registration is also checked against exact authenticated name, locator, and integrity rather than accepted from JavaScript (`src/host/mod.rs:1943-1977`).

- The behavioral corpus, fail-loud requirements, phased migration, source-map requirement, and source/prepared equivalence gates are unusually good (`llp/0026-esm-module-runner.rfc.md:447-550`, `:611-635`). In particular, requiring real Hermes execution and non-zero case counts correctly follows LLP 0018’s governing rule (`llp/0018-agent-tooling-fail-loud.plan.md:117-135`, `:196-230`).

## 3. Concerns

1. **The proposed stable artifact/factory boundary is neither specified nor demonstrated feasible.**

   **Severity:** Material

   **Evidence:** RFC §§2–4 list metadata and assign ownership between Rust and Hermes, but never define how factory code addresses import cells, initializes exports, enforces TDZ, reports star-export ambiguity, distinguishes declaration from execution, or suspends and resumes async execution (`llp/0026-esm-module-runner.rfc.md:230-305`). The three proposed implementations—Oxc ModuleRunner, custom AST code generation, or Rolldown runtime API—have materially different capabilities (`:261-267`). Today’s compiling Oxc candidate rejects TLA and general ESM output (`src/module_loader/transpile.rs:199-264`), while accepted LLP 0009 records that newer Rolldown/Oxc combinations do not compile under pinned Rust 1.93.1 (`llp/0009-runtime-transform-candidate-scope.decision.md:39-55`; `rust-toolchain.toml:1-3`). There is no Rolldown Rust dependency in Cargo. In addition, accepted LLP 0019’s canonical AST compatibility implementation is a JavaScript/build-time pass, while its only embedded implementation is the scanner this RFC retires (`llp/0019-hermes-compat-transform-authority.decision.md:10-48`).

   **Resolution criterion:** Before acceptance, select and prototype one integration on the supported Rust toolchain—or explicitly approve the required toolchain upgrade. Specify a versioned factory ABI with generated examples for live mutation, TDZ, direct and indirect cycles, star ambiguity, `import.meta`, and TLA. Define the hermetic Oxc/Rust successor to LLP 0019’s compatibility pass, revise that Decision, and prove it through the existing real-Hermes corpus with composed source maps.

2. **Phase 1 assumes `SourceId` and exact request-edge facilities that do not exist, and the artifact duplicates principal identity contrary to LLP 0023.**

   **Severity:** Material

   **Evidence:** RFC Phase 1 says artifacts will be verified against the “existing resolver and CapSec graph” (`llp/0026-esm-module-runner.rfc.md:487-493`). LLP 0023 marks the `SourceId` algebra, carrier provenance, and exact importer/request/target map as not landed (`llp/0023-virtual-filesystem-namespace.spec.md:2053-2068`). Current `ResolvedModule` has a string `id`, host path, and package fields but no `SourceId`, `SourceLabel`, or `ModuleKey` (`src/module_loader/mod.rs:30-57`); resolution sets `id` to a lossy host-path string (`src/module_loader/mod.rs:969-978`), and JavaScript caches user modules by that value (`src/engine/bootstrap/module-loader.js:5297-5305`). The armed graph stores only principal-to-principal edges (`crates/capsec-semantics/src/arming.rs:550-570`), not authored specifier/alias/conditions to exact target identity. Finally, `ModuleArtifact` serializes both `source_id` and `defining_principal` (`llp/0026-esm-module-runner.rfc.md:230-249`), while LLP 0023 explicitly requires the defining principal to appear exactly once, inside `SourceId` (`llp/0023-virtual-filesystem-namespace.spec.md:691-710`).

   **Resolution criterion:** Make LLP 0023’s `SourceId` constructors, canonical encoding, equality, provenance registry, and exact importer/request/target map explicit prerequisites to artifact publication or graph shadowing. Type resolver output around a native authenticated-source handle and a digest-bound `ImportEdgeId`. Remove the separate principal field or define it strictly as a redundant verified assertion with an exact mismatch failure and coordinated LLP 0023 amendment. Separate runtime-local record caches from cross-runtime immutable artifact-byte caches.

3. **Mixed-principal bytecode carriers do not have a sound Hermes attribution mechanism.**

   **Severity:** Material

   **Evidence:** The RFC allows several factories with different principals to share one physical chunk or HBC carrier (`llp/0026-esm-module-runner.rfc.md:39-44`, `:397-407`) and says the correct compartment will be bound before invocation (`:287-302`). That works for current source factories because each `new Function` compile creates and stamps a fresh Domain (`src/engine/bootstrap/module-loader.js:235-272`). LLP 0013 warns, however, that one bundled HBC file is one Hermes `RuntimeModule`; frame attribution works only with per-package module units or a function-range-to-package map (`llp/0013-per-package-capability-compartments.rfc.md:317-337`). Current production mitigation emits per-package chunks, and enforce/audit fails closed against flat attribution (`llp/0013-per-package-capability-compartments.rfc.md:1341-1391`). Invoking a precompiled function under a compartment does not by itself change its code provenance.

   **Resolution criterion:** Constrain executable HBC carriers to one authenticated principal/package boundary, or specify and prototype a native per-factory Domain/function-range attribution mechanism. Require static, dynamic, cyclic, cached, async, and HMR attribution tests on every advertised engine build. A provenance manifest alone is insufficient unless Hermes frame lookup consumes it.

4. **The asynchronous graph is not normatively connected to structured evaluation, cancellation, rooting, or the complete CapSec context.**

   **Severity:** Material

   **Evidence:** RFC §§4–6 describe one shared record promise and say continuations retain an owning or scheduling principal, but leave event-loop keepalive, cancellation, and failure attribution to a Phase 3 integration bullet (`llp/0026-esm-module-runner.rfc.md:287-354`, `:503-509`). LLP 0024 requires typed outcomes and owned handles, private non-assimilating TLA settlement, exact work-unit identity, and exactly-once foreground reporting of rejected TLA (`llp/0024-structured-evaluation-and-session.spec.md:753-880`, `:1840-1852`). LLP 0025 makes cancellation target-id-exact and distinguishes executing from suspended work (`llp/0025-terminal-session-ownership.spec.md:553-600`). The existing embedding ABI still returns a synchronous string result (`llp/0002-host-embedding-abi.spec.md:29-61`) over a host-pumped event loop (`llp/0003-hermes-engine-bridge.explainer.md:109-158`).

   The CapSec wording is also too singular. LLP 0021 requires live frames, schedule-time identity, owner/deputy identities, and a deduplicated constrained-principal set whose relevant dimensions intersect (`llp/0021-capsec-effect-model-migration.plan.md:327-385`). Current engine code already walks frames and folds in scheduler/deputy context (`src/engine/hermes_runtime_internal.h:500-571`).

   **Resolution criterion:** Define the evaluation context carried by every graph operation: runtime generation, requesting record, defining actor, effect owner, scheduling identity, complete constrained-principal set, snapshot/generations, and operation lease. Specify internal record promises versus per-call public import promises, rooting and keepalive, work/settlement units, cancellation state transitions, exactly-once rejection classification, thread/worker ownership, and stale-handle behavior. State whether LLP 0024’s ABI is a prerequisite or how the existing embedding contract drives async graphs, then add nested deputy/TLA/cache-hit/cancellation tests.

5. **The no-partial-execution promise for synchronous `require(ESM)` is not achievable as written in mixed graphs.**

   **Severity:** Material

   **Evidence:** The RFC promises that `require()` returns an ESM namespace only when the complete reachable graph is proven synchronous and that an async graph never partially runs (`llp/0026-esm-module-runner.rfc.md:33-37`, `:365-376`). Yet it defines computed `require()` as a dynamic edge discovered only during execution (`:161-167`, `:226-228`). Consider synchronous ESM A importing CJS B, where B performs effects and then computes `require(ESM-C-with-TLA)`. The runner cannot know that edge before running B, and cannot roll B’s effects back. LLP 0024 already recognizes that computed `require()` and `import()` are call-time edges and that prior effects stand (`llp/0024-structured-evaluation-and-session.spec.md:497-515`).

   **Resolution criterion:** Define precisely whether “graph” means only the statically manifestable closure. Either weaken the guarantee so only the newly selected async target graph remains unexecuted, explicitly allowing prior caller effects; require a complete authenticated CJS dependency manifest and refuse unmanifested re-entrant `require(ESM)` during synchronous ESM evaluation; or prohibit that mixed re-entry. Add a fixture for the scenario above.

6. **Global SWC retirement conflicts with the governing session parser contract.**

   **Severity:** Material

   **Evidence:** The RFC makes session lexical behavior a non-goal but calls for eventual removal of SWC crates (`llp/0026-esm-module-runner.rfc.md:129-142`, `:519-529`, `:632-635`). LLP 0024 pins the TypeScript dialect to `swc_ecma_parser` and admits Oxc only when parse-equivalent over its corpus (`llp/0024-structured-evaluation-and-session.spec.md:666-674`). Its required sloppy Script-plus-static-import-plus-TLA source goal does not exist in the pinned parser and remains a prototype obligation (`llp/0024-structured-evaluation-and-session.spec.md:422-453`, `:2236-2242`). Retiring the module transform does not automatically retire that parser dependency.

   **Resolution criterion:** Add a source-surface migration matrix covering file entries, dependencies, program stdin, prompt/transcript input, `.load`, and one-shot evaluation. Gate SWC removal on an Oxc implementation of LLP 0024’s source goal and parse-equivalence contract, a coordinated change to that contract, or an explicitly retained parser-only dependency. A one-release compatibility window does not resolve a permanent parser requirement.

7. **The replacement contract is not total over existing loader kinds and security-sensitive observables.**

   **Severity:** Material

   **Evidence:** `ModuleArtifact.source_kind` names only ESM and CommonJS (`llp/0026-esm-module-runner.rfc.md:230-249`), while the current native loader also has JSON and builtin kinds (`src/module_loader/mod.rs:22-28`). Builtin admission is security-sensitive and includes hard terminal-builtin denials (`src/host/mod.rs:3520-3546`). The RFC does not state whether JSON, builtins, synthetic modules, or text/bytes adapters use ModuleRecords, old caches, or separate identity rules.

   LLP 0023 also requires virtual `SourceLabel`-derived `import.meta`, retained/revalidated dynamic referrers, and a closed `require.cache` (`llp/0023-virtual-filesystem-namespace.spec.md:1525-1540`, `:1882-1902`). Today `import.meta` is synthesized from host `__filename` (`src/engine/bootstrap/module-loader.js:3587-3603`) and mutable cache objects are exposed through three require surfaces (`src/engine/bootstrap/module-loader.js:5479-5486`, `:5831-5842`, `:5873-5883`). Finally, prepared builds strip LLP 0014 grant attributes before execution (`packages/ibex-devtools/src/scripts/import-grants.mjs:390-438`, `:620-640`), while LLP 0022 explicitly leaves their disposition in unbundled direct-file execution unresolved (`llp/0022-repl-behavior-and-semantics.spec.md:571-618`).

   **Resolution criterion:** Add a total `ModuleRecordKind` and observable-surface matrix. For every kind, define SourceId construction, namespace/interop, integrity, authorization timing, cache behavior, and prepared/source parity—or explicitly retain it outside the runner behind a typed boundary. Bind `import.meta` and dynamic referrers to authenticated SourceLabel/retained identities, close or safely replace `require.cache`, and settle direct-file grant attributes as trusted preprocessing or fail-closed refusal.

8. **ESM failure caching conflicts with the current session contract.**

   **Severity:** Material

   **Evidence:** RFC §5 retains an errored ESM record until explicit generation invalidation (`llp/0026-esm-module-runner.rfc.md:332-334`). LLP 0024 says a failed module cache entry is deleted so a later prompt import re-executes after the source is fixed (`llp/0024-structured-evaluation-and-session.spec.md:1623-1662`). The RFC identifies only the dependency-TLA rule as requiring later reconciliation, even though migrated sessions would also observe this difference (`llp/0026-esm-module-runner.rfc.md:351-354`).

   **Resolution criterion:** Specify failure caching by module kind and consumer. If ESM adopts standards-shaped sticky failures, define the file-change or explicit session action that advances the generation before a prompt retry. If unmigrated sessions preserve delete-on-failure, state the boundary. Reconcile LLP 0024 and add source/prepared/session fixtures.

9. **Some current-state and migration wording needs tighter scope.**

   **Severity:** Minor/Non-blocking

   **Evidence:** Normal CLI file execution often prepares a graph bundle with Rolldown before reaching the raw loader (`src/bin/ibex/runtime.rs:1382-1400`, `:3074-3192`). That path already has source maps, content-bound cache manifests, and per-package chunks (`src/bin/ibex/runtime.rs:4999-5049`; `packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:303-415`). The RFC correctly labels its motivation “current fallback,” but §Alternatives categorically says SWC does not solve live bindings or cycles (`llp/0026-esm-module-runner.rfc.md:560-565`); current CommonJS cycles do work, and SWC may emulate simple exports even though it cannot provide the complete ESM contract. Also, a Draft RFC only proposes to resolve LLP 0007’s fork (`llp/0026-esm-module-runner.rfc.md:46-51`).

   **Resolution criterion:** Qualify the semantic claim as “does not provide complete ESM live-binding/cycle semantics,” say the RFC “proposes the ModuleRunner branch,” and add a migration inventory mapping the existing Rolldown cache, integrity manifest, per-package chunks, HBC entry cache, and source fallback into Phases 1–4.

## 4. Cross-document findings

- LLP 0007 has a clean architectural seam: if the single-file candidate cannot meet the loader contract, it calls for a separate ModuleRunner RFC (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:45-48`, `:279-282`, `:412-426`). LLP 0026 is the right document to make that decision.

- LLP 0024 strongly supports the proposal’s central premise. It says honest dependency TLA requires async ordering, live bindings, cycles, failure caching, and CJS interop (`llp/0024-structured-evaluation-and-session.spec.md:472-519`) and asks whether to build precisely this linker (`:2232-2235`). Its static-preflight/dynamic-call-time rules also align with RFC §1.

- The `(runtime, SourceId)` key, carrier-independent identity, and `SourceLabel` separation align cleanly with LLP 0023 (`llp/0023-virtual-filesystem-namespace.spec.md:676-764`). The drift is in prerequisites and duplicated principal representation, not in the chosen identity model.

- LLPs 0013 and 0021 support the native-owner/opaque-handle design, but impose stronger attribution requirements than the RFC currently states: per-package executable units or explicit range metadata, and a full constrained-principal set rather than one “correct package principal.”

- LLP 0019 is a real authority conflict, not mere documentation lag. Its accepted two-tier topology has no hermetic Oxc-AST runtime tier once the scanner is removed. It must change when the experimental path begins, not only at final retirement.

- LLPs 0005, 0006, and 0018 are clean seams. Hermetic source/prepared execution, bytecode-version keys, no rerun after evaluation effects, source-map publication, and fail-loud non-zero corpus execution all fit the proposal (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:30-47`, `:92-132`; `llp/0006-design-principles.principles.md:49-61`).

- LLPs 0022 and 0025 are normative consumers but are absent from the RFC’s `Related` metadata. Their session import rules, work-unit identity, cancellation, and suspended-TLA obligations materially constrain Phase 3.

- The proposal partly duplicates an existing prepared-execution system. Current Rolldown graph bundling, authenticated cache manifests, per-package chunks, and entry HBC should be treated as migration inputs rather than a greenfield Phase 4.

## 5. Suggestions

- Prototype a private `System.register`-shaped factory ABI: a declaration phase returning dependency setters plus a sync/async `execute`, with an opaque host-selected export callback. It provides concrete vocabulary for live cells, cycles, and TLA without exposing a global `System`.

- Check in small canonical examples of serialized `ModuleArtifact`s and their generated factories. They would make ABI review, cache compatibility, and cross-version migration much more concrete.

- Build an executable reference linker/evaluator before optimizing. Property-generate small graphs and compare event traces, namespace descriptors, error identity, and settlement ordering against the adopted Node/V8 oracle.

- Keep internal graph promises permanently handled and create a fresh public promise for each `import()` call. This helps prevent an internal rejection from becoming both a foreground outcome and an `unhandledrejection`.

- Treat `role` as contextual record/evaluation metadata unless output genuinely differs. The same SourceId may be an entry in one invocation and a dependency in another; that should not unnecessarily fragment content-addressed artifacts.

- Make bytecode carrier admission atomic before evaluating any included factory. Preserve LLP 0005’s rule that source fallback is allowed only for a pre-execution bytecode load failure, never after program effects.

- Add an opt-in graph trace containing SourceId hashes, lifecycle transitions, edge decisions, principal-set hashes, and promise dependencies. It would be valuable for differential failures without exposing host paths or authority-bearing data.

- Add LLPs 0022 and 0025 to `Related`, and distinguish the internal module-runner ABI version from the public embedding ABI version in the artifact fingerprint.

## 6. Open questions

- What exact factory ABI represents imports, exports, hoisting, TDZ, namespace creation, and sync/async execution?

- Which Oxc/Rolldown integration compiles on the supported Rust toolchain and can emit that ABI without reimplementing most of a bundler?

- Who owns the hermetic in-process Hermes-compat AST pass after LLP 0019’s scanner is retired?

- What lands `SourceId`, SourceLabel, exact request-edge identity, and carrier provenance before ModuleArtifact cache publication begins?

- Are HBC carriers necessarily per-principal, or can Hermes expose trustworthy per-factory Domain or function-range attribution?

- What complete evaluation context is retained across TLA, dynamic import, cache reuse, microtasks, timers, and native completions?

- How do cancellation and HMR affect a shared evaluation promise and its ModuleRecord state?

- What exactly does the no-partial-execution guarantee cover when CommonJS discovers a new ESM edge during execution?

- Which parser owns every file/session source surface, and is parser-only SWC retention acceptable?

- How do JSON, builtins, synthetic modules, text/bytes modules, import attributes, `require.cache`, and virtual-path observables enter—or stay outside—the runner?

- Which Node version defines namespace descriptors, CJS named exports, `require(ESM)`, error identity, and async-cycle behavior?

- Are ESM failures sticky in interactive sessions, and what event advances the generation after a file edit?

- Can the existing Rolldown cache/chunk/HBC pipeline be upgraded in place, or must it be replaced to carry per-original-module SourceId and exact policy edges?

## 7. Readiness verdict

The core architectural choice is good and should be pursued. The draft has unusually strong motivation, security intent, migration discipline, and conformance planning. It is not ready for acceptance because several load-bearing contracts are still open or conflict with governing LLPs: the executable artifact ABI, toolchain feasibility, identity prerequisites, mixed-principal HBC attribution, async work/cancellation semantics, session parser ownership, total loader-surface security, and failure caching.

VERDICT: NOT READY

---

## Round 2 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f6560-0757-77a3-9353-63c106d0ce8e`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `8e12e2b92ab0`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-2 review of the same revision and no access to any
  prior LLP 0026 review artifact — the round-1 artifacts were moved out of
  `llp/reviews/` into a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** cli-runner, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round2.md`) — the round-1 brief
  updated to the new revision hash; same brief as the Fable round-2 reviewer.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes the right architectural direction. The repository evidence strongly supports replacing the bootstrap ESM scanner with an authenticated module graph, real module records, live binding cells, and asynchronous evaluation. The separation between native policy/identity state and Hermes-owned JavaScript objects is also sound.

I would not accept the RFC at revision `8e12e2b92ab0` yet. Several central contracts remain either internally inconsistent or deferred despite materially affecting correctness and security: the serialized artifact/factory ABI, host-visible asynchronous completion and cancellation, authorization context for graph operations, generation identity, direct-file grant processing, and CommonJS interop. The migration also needs an explicit body-read-free resolver milestone and earlier reconciliation with the accepted transform decisions.

The principal `[observed]` claims are accurate, with one scope qualification: the fire-and-forget TLA defect is specifically the bootstrap dependency-loading fallback. Entry TLA already has separate awaited CLI machinery.

## 2. Strengths

- The diagnosis of the current fallback is accurate and compelling. In §Motivation, the RFC says TypeScript/JSX-like files and a scanner-selected JavaScript subset are transformed in Rust, while ordinary ESM-heavy JavaScript passes that layer verbatim (`llp/0026-esm-module-runner.rfc.md:54-79`). The code confirms `.ts`, `.tsx`, `.jsx`, `.mts`, and `.cts` always transform, while `.js`, `.mjs`, and `.cjs` transform only for the narrow async-generator, `using`, or loop-scope scans (`src/module_loader/mod.rs:364-421`, `src/module_loader/mod.rs:772-790`). Ordinary Oxc-classified ESM is read and retained verbatim at `src/module_loader/mod.rs:928-945`.

- The scanner fragility is not hypothetical. `transformEsmToCjs` spans `src/engine/bootstrap/module-loader.js:4224-5065`, on top of raw character, regex/division, template, comment, and delimiter scanners at `src/engine/bootstrap/module-loader.js:3743-4223`. Its own comments record bugs where comments, templates, and regex literals swallowed or misclassified real code (`src/engine/bootstrap/module-loader.js:4138-4142`, `src/engine/bootstrap/module-loader.js:4361-4367`, `src/engine/bootstrap/module-loader.js:4694-4702`). This strongly supports §Design principles’ decision that grammar facts must come from an AST (`llp/0026-esm-module-runner.rfc.md:182-197`).

- The RFC correctly distinguishes full ESM semantics from CommonJS cycle behavior. The current loader compiles a synchronous `new Function(require, module, exports, …)` body and discards its return (`src/engine/bootstrap/module-loader.js:240-253`, `src/engine/bootstrap/module-loader.js:5500-5506`). Named imports become snapshot `var` assignments, and exports/re-exports become property copies (`src/engine/bootstrap/module-loader.js:4594-4648`, `src/engine/bootstrap/module-loader.js:4860-4877`, `src/engine/bootstrap/module-loader.js:5031-5047`). CommonJS cycles do receive early partial exports because the cache record is published before execution (`src/engine/bootstrap/module-loader.js:5297-5305`, `src/engine/bootstrap/module-loader.js:5340-5364`), but that is not ESM declaration instantiation, TDZ, live cells, or star-resolution semantics. The distinction in §File-at-a-time CommonJS lowering is therefore correct (`llp/0026-esm-module-runner.rfc.md:81-96`).

- The dependency-TLA observation is also correct. `wrapAsyncModule` creates a fire-and-forget async IIFE (`src/engine/bootstrap/module-loader.js:5415-5417`); the wrapper promise is discarded and the module is marked loaded (`src/engine/bootstrap/module-loader.js:5500-5506`, `src/engine/bootstrap/module-loader.js:5797-5798`). Invocation-time retry deliberately re-executes the prefix before the failing `await` (`src/engine/bootstrap/module-loader.js:5677-5695`, `src/engine/bootstrap/module-loader.js:5744-5760`). This substantiates §Motivation’s claim (`llp/0026-esm-module-runner.rfc.md:98-108`).

- The transform migration is grounded in the actual tree. SWC remains the default and performs TypeScript stripping, JSX compilation, CommonJS lowering, and helper injection (`src/module_loader/transpile.rs:64-94`, `src/module_loader/transpile.rs:109-196`; `Cargo.toml:98-106`). Oxc is already a substantial direct dependency used for resolution and an opt-in transform candidate (`Cargo.toml:44-53`; `src/module_loader/transpile.rs:199-264`), but that candidate rejects TLA and fails when general ESM syntax remains. Current Rolldown use is through repository JavaScript tooling rather than a Cargo dependency (`package.json:10,36`; `src/bin/ibex/runtime.rs:4158-4177`, `src/bin/ibex/runtime.rs:4268-4302`). Treating the precise in-process integration as a Phase 1 feasibility gate is honest (`llp/0026-esm-module-runner.rfc.md:291-338`).

- The SourceId prerequisite is handled responsibly. The current Rust record has a path-string `id`, optional path, and no module `SourceId` or `ModuleKey` (`src/module_loader/mod.rs:30-57`); the JavaScript cache is keyed by that path-based id (`src/engine/bootstrap/module-loader.js:5297-5304`). §Phase 1 correctly refuses to publish artifacts or shadow the graph until LLP 0023’s canonical `SourceId` exists (`llp/0026-esm-module-runner.rfc.md:625-645`).

- The security-aware production-carrier rule is particularly strong. LLP 0013 explains that one HBC file is one `RuntimeModule`, requiring per-package units or a trustworthy function-range mapping (`llp/0013-per-package-capability-compartments.rfc.md:317-337`). LLP 0026 correspondingly requires per-principal executable carriers until native per-factory attribution is proven (`llp/0026-esm-module-runner.rfc.md:508-532`). This is a clean, conservative seam.

- The migration and conformance plan is behavior-oriented rather than output-shape-oriented. The Node/test262 corpus, named divergences, real-Hermes execution, non-zero case counts, source/prepared equivalence, and prohibition on dual-executing application effects are all appropriate (`llp/0026-esm-module-runner.rfc.md:572-603`, `llp/0026-esm-module-runner.rfc.md:605-674`). They align well with LLP 0018’s fail-loud rule (`llp/0018-agent-tooling-fail-loud.plan.md:117-135`).

## 3. Concerns

1. **The proposed ModuleArtifact and factory boundary is still a field sketch, not the stable contract the RFC needs.**

   **Severity:** Material

   **Evidence:** §ModuleArtifact calls the artifact the stable transform boundary but gives only untyped `static_edges[]`, `export_descriptors[]`, and `factory_source | factory_bytecode` placeholders (`llp/0026-esm-module-runner.rfc.md:243-274`, `llp/0026-esm-module-runner.rfc.md:291-297`). It also puts `role` inside the artifact and then says role is contextual and must not fragment content-addressed artifacts (`llp/0026-esm-module-runner.rfc.md:248-260`, `llp/0026-esm-module-runner.rfc.md:276-281`). LLP 0024 already places role on the evaluation/source request (`llp/0024-structured-evaluation-and-session.spec.md:236-264`).

   The `System.register`-shaped description does not define how uninitialized cells, indirect exports, star conflicts, namespace properties, hoisted declarations, or async SCC state are represented (`llp/0026-esm-module-runner.rfc.md:364-400`). That precision is load-bearing because shipping Hermes does not provide the required TDZ behavior; evaluator-owned checked cells are necessary (`llp/0024-structured-evaluation-and-session.spec.md:193-226`). The current scanner’s snapshot imports and rewritten function declarations demonstrate the failures an underspecified ABI can reproduce (`src/engine/bootstrap/module-loader.js:4594-4616`, `src/engine/bootstrap/module-loader.js:4980-5021`).

   Prepared-artifact trust is similarly incomplete. The RFC requires native verification of edge, export, identity, and factory metadata (`llp/0026-esm-module-runner.rfc.md:549-570`), but it does not define the canonical serialized bytes, whole-artifact digest domain, or trusted issuer that makes those facts verifiable without reparsing and retransformation.

   **Resolution criterion:** Replace the field sketch with a normative, versioned schema and lifecycle algorithm. Separate intrinsic artifact facts from `EvaluationRequest`/`ModuleRecord` context; move `role` out of the content artifact. Define binding-cell operations and the uninitialized sentinel, import/export descriptor variants, star-conflict resolution, namespace construction, sync/async execute results, and SCC transitions. Define canonical encoding and a hash chain covering exact factory bytes, descriptors, edges, source digest, transform fingerprint, and source map. State which in-process and prepared producers are trusted and how their authority is bound into the armed snapshot. Golden artifacts should accompany, not substitute for, this contract.

2. **The asynchronous graph has no conforming host-visible start, settlement, or cancellation contract.**

   **Severity:** Material

   **Evidence:** §Top-level await says records expose shared evaluation promises, but also says LLP 0002’s synchronous embedding entry points remain unchanged and graphs complete through the host-pumped loop (`llp/0026-esm-module-runner.rfc.md:411-438`). The present ABI returns a synchronous status and malloc-owned string (`llp/0002-host-embedding-abi.spec.md:29-61`), while LLP 0024 requires a typed semver-major replacement with structured outcomes, value handles, explicit work-unit publication, and concurrent cancellation (`llp/0024-structured-evaluation-and-session.spec.md:753-841`). Its settlement contract also forbids thenable assimilation and hidden timeouts (`llp/0024-structured-evaluation-and-session.spec.md:843-900`).

   Current native evaluation does the opposite: it detects an arbitrary thenable, attaches handlers, repeatedly calls `ex_hermes_poll`, and eventually returns the still-pending value after a configurable budget (`src/engine/hermes_runtime.cc:4026-4051`, `src/engine/hermes_runtime.cc:4080-4135`). No API named by LLP 0026 lets an embedder initiate an asynchronous graph and later observe its foreground rejection exactly once.

   Cancellation also needs module-specific semantics beyond merely citing LLP 0024/0025. The RFC says every importer shares one evaluation promise (`llp/0026-esm-module-runner.rfc.md:386-389`), while LLP 0025 requires cancellation to target one exact currently executing work unit (`llp/0025-terminal-session-ownership.spec.md:553-575`, `llp/0025-terminal-session-ownership.spec.md:734-767`). It is undefined whether cancelling one waiting import cancels shared graph evaluation, only detaches that waiter, or poisons the module generation.

   **Resolution criterion:** Specify an asynchronous runner API or handle with start, wake/pump, settlement, rejection, retention/release, and id-exact cancellation semantics. Define waiter cancellation separately from shared module evaluation, the resulting record state, completed dependency effects, retry/generation behavior, and exactly-once outcome versus background-failure delivery. Either amend LLP 0002 through LLP 0024’s typed ABI before exposing async graphs, or explicitly scope the runner to a private API that already supplies equivalent semantics. No timeout or raw Promise may stand in for settlement.

3. **The migration does not explicitly close the current resolver’s read-before-authentication violation.**

   **Severity:** Material

   **Evidence:** §Source admission requires authorize → resolve/authenticate → verify SourceId and principal → create record → only then read executable bytes (`llp/0026-esm-module-runner.rfc.md:221-241`). The current Host performs useful requester preflight before calling the resolver (`src/host/mod.rs:2191-2272`) and later authenticates canonical target ownership and integrity (`src/host/mod.rs:2273-2359`). However, `resolve_meta` calls `resolve_with_oxc`, whose ESM classification reads an ordinary `.js`/`.mjs` body at `src/module_loader/mod.rs:928-945` before that later target authentication. This contradicts the Host comment claiming metadata resolution does not read the body (`src/host/mod.rs:2161-2173`) and LLP 0004’s equivalent claim (`llp/0004-module-loading-and-builtins.explainer.md:53-63`).

   The existing regression test misses the defect because it uses `.ts`, whose kind is extension-classified without a source read (`src/module_loader/mod.rs:2606-2633`). The later authenticated load discards the prefetched copy and reauthenticates bytes (`src/module_loader/mod.rs:327-351`; `src/host/mod.rs:2107-2158`), so this is not presently an unauthenticated-execution path; it remains an unauthorized body read and potential probe. LLP 0023 already records it as the unlanded `OBL-RESOLVE-GATE` (`llp/0023-virtual-filesystem-namespace.spec.md:2067-2069`).

   **Resolution criterion:** Add a pre-graph milestone that splits resolution/classification from body loading and closes `OBL-RESOLVE-GATE`. The typed resolver used by the runner must be body-read-free until the exact target edge, binding owner, locator, integrity, and SourceId are authenticated. Add instrumented denial/non-disclosure fixtures using ordinary ESM `.js` and `.mjs`, including missing, unreadable, and policy-denied targets; a `.ts` fixture is insufficient.

4. **“Carry the full evaluation context” is not yet an authorization rule or implementable native interface.**

   **Severity:** Material

   **Evidence:** §Native graph owner says every graph operation carries the requester, effect owner, schedule-time identity, full constrained-principal set, and generation (`llp/0026-esm-module-runner.rfc.md:340-362`). LLP 0021 requires live, schedule-time, owner, and deputy identities to form a deduplicated set whose non-transparent dimensions intersect (`llp/0021-capsec-effect-model-migration.plan.md:368-378`).

   The typed effect model can represent that context (`crates/capsec-semantics/src/model.rs:1473-1496`), and filesystem decisions already construct principal-relative projections for the constrained set (`src/host/mod.rs:462-524`, `src/host/mod.rs:638-665`). The import gate cannot: its ABI carries only `(module_id, specifier)`, and Host selects one principal and one import policy (`src/host/abi.rs:3016-3033`; `src/host/mod.rs:1983-2023`). Current dynamic import has to gate and pre-resolve synchronously because the subsequent microtask has lost the requesting frame (`src/engine/bootstrap/module-loader.js:6082-6129`).

   The RFC does not say whether import-edge authorization is solely the authenticated requesting record’s policy, whether every constrained principal’s graph dimension must allow, or how the filesystem read effects of a load combine with that edge decision. Those choices determine confused-deputy behavior.

   **Resolution criterion:** Define a typed `GraphEvaluationContext` and a native authorization operation for static import, re-export, dynamic import, literal/computed `require`, JSON, and prepared-chunk loading. Specify actor, requester, effect owner, schedule owner, constrained-set intersection, generation capture, and restoration across TLA, promises, timers, HMR, and CJS re-entry. Add fixtures where the requesting module, live frame, and schedule owner are three different principals.

5. **Direct-file grant attributes are deferred until after the point at which authority must already be immutable.**

   **Severity:** Material

   **Evidence:** §CommonJS interop defers direct-file grant attributes to Phase 2, choosing later between trusted preprocessing and fail-closed refusal (`llp/0026-esm-module-runner.rfc.md:474-482`). LLP 0014 requires grants to be root-authored, analyzed before code runs, unioned across the entry graph, and stripped before execution (`llp/0014-import-site-grants-and-generated-policy.spec.md:44-66`, `llp/0014-import-site-grants-and-generated-policy.spec.md:97-123`, `llp/0014-import-site-grants-and-generated-policy.spec.md:228-236`). The armed snapshot is immutable before runtime evaluation (`llp/0021-capsec-effect-model-migration.plan.md:1139-1171`). An on-demand linker therefore cannot discover an attribute and widen authority during evaluation.

   The citation to an LLP 0022 “open question” is also inaccurate. LLP 0022 has settled session inputs on fail-closed refusal and delegates only unbundled file execution to `OBL-FILE-GRANTS` (`llp/0022-repl-behavior-and-semantics.spec.md:553-618`, `llp/0022-repl-behavior-and-semantics.spec.md:987-989`).

   **Resolution criterion:** Choose the v1 direct-file behavior in this RFC. Either refuse every generated reserved grant key, or define a separate authenticated, no-probe, pre-runtime graph-analysis phase whose resulting policy and stripped-source artifact are digest-bound into the snapshot before runtime creation. If preprocessing is chosen, state clearly that it precedes and is not performed by the on-demand evaluator.

6. **Runtime identity, graph generation, and source-map identity are not yet one coherent contract.**

   **Severity:** Material

   **Evidence:** The RFC defines `ModuleKey` as `(runtime identity, SourceId)` and later makes the development record key effectively `(runtime, SourceId, generation)` (`llp/0026-esm-module-runner.rfc.md:159-173`, `llp/0026-esm-module-runner.rfc.md:484-502`). “Runtime identity” is ambiguous in this repository: LLP 0012 uses that noun for the product identity exposed through `process.versions` (`llp/0012-runtime-identity.decision.md:10-33`), while LLP 0023 means an opaque runtime/session handle carrying a generation (`llp/0023-virtual-filesystem-namespace.spec.md:1620-1667`).

   The code has several distinct candidates. A raw runtime pointer is explicitly not an identity because of ABA reuse; asynchronous callbacks use pointer plus nonce (`src/engine/hermes_runtime_internal.h:98-110`). A runtime also carries separate `host_context_id` and `runtime_nonce` fields (`src/engine/hermes_runtime_internal.h:124-138`), and Host contexts are random claimed capabilities (`src/host/abi.rs:278-309`, `src/host/abi.rs:452-531`).

   HMR makes the ambiguity observable. Old and new generations may coexist (`llp/0026-esm-module-runner.rfc.md:493-502`), but LLP 0024’s in-memory source-map registry is keyed only by `SourceLabel` (`llp/0024-structured-evaluation-and-session.spec.md:701-708`). A late rejection from an old generation could therefore be mapped using a newer generation’s map. The exact HMR transaction is itself still open (`llp/0026-esm-module-runner.rfc.md:816-817`).

   **Resolution criterion:** Define distinct nouns and keys: immutable `ModuleIdentity = SourceId`, runtime-local `ModuleInstanceKey = (runtime/session generation, SourceId, graph generation)`, and a compilation-unit/source-map key including artifact digest or generation. State creation, atomic generation publication, retained-importer behavior, stale completion rejection, invalidation, retry, GC, and teardown. Add two-runtime, destroy/recreate ABA, old-generation late-error, and HMR-during-TLA fixtures.

7. **The CommonJS interoperability contract is described as explicit while its deciding rule and oracle remain open.**

   **Severity:** Material

   **Evidence:** §CommonJS interop promises “one documented Node-compatible rule” for synthetic named exports but does not state the rule (`llp/0026-esm-module-runner.rfc.md:440-469`). Open question 3 still asks which Node release governs both named exports and `require(ESM)` (`llp/0026-esm-module-runner.rfc.md:808-815`). These details affect namespace key creation, analysis timing, default behavior, `module.exports` replacement, error identities, and whether source and prepared paths agree.

   The repository already has an authority for this choice: LLP 0012 says `runtime-identity.json` pins the Node compatibility target (`llp/0012-runtime-identity.decision.md:23-37`), and that file currently names Node `24.13.1` (`runtime-identity.json:7-11`).

   **Resolution criterion:** Before acceptance, either adopt the existing Node `24.13.1` target or explicitly revise LLP 0012. Specify the named-export detection rule, namespace contents and identity, default and `module.exports` behavior, mutations after evaluation, `require(ESM)` eligibility, and exact asynchronous-graph error. Make those rules normative and run the same fixtures through source, cached, bundled, and bytecode carriers.

8. **The migration sequence implements a new architecture before reconciling the accepted decisions that currently prohibit it.**

   **Severity:** Material

   **Evidence:** LLP 0009 is Accepted and says Oxc/Rolldown may reshape the loader only after a later Decision explicitly changes the architecture (`llp/0009-runtime-transform-candidate-scope.decision.md:11-37`). LLP 0007 likewise requires either an Accepted revision or a Decision choosing the ModuleRunner redesign (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:412-426`). LLP 0019 currently permits exactly two Hermes-compat implementation tiers (`llp/0019-hermes-compat-transform-authority.decision.md:10-48`).

   LLP 0026 appropriately schedules the LLP 0019 amendment in Phase 1 (`llp/0026-esm-module-runner.rfc.md:313-323`, `llp/0026-esm-module-runner.rfc.md:642-643`), but leaves reconciliation of LLPs 0007 and 0009 until Phase 5, after experimental graph implementation, synchronous/async evaluation, and prepared carriers have landed (`llp/0026-esm-module-runner.rfc.md:625-689`).

   **Resolution criterion:** Add a pre-implementation decision gate: LLP 0026 becomes Accepted or a separate Decision adopts it; LLP 0009 is explicitly amended/superseded; LLP 0007 records the selected branch; and LLP 0019 is amended in the same change that introduces its third tier. Phase 5 may update descriptive shipped-state documents, but normative authorization cannot wait until retirement.

9. **The current-state description should more sharply distinguish the bootstrap dependency fallback from other entry paths.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The dependency-TLA description itself is accurate (`llp/0026-esm-module-runner.rfc.md:98-108`). However, entry TLA already has a separate CLI path that lowers the entry, wraps it, and invokes native evaluation (`src/bin/ibex/runtime.rs:1685-1735`); native evaluation pumps the returned thenable toward settlement (`src/engine/hermes_runtime.cc:4026-4051`, `src/engine/hermes_runtime.cc:4096-4125`). The prepared Rolldown path can also retry a TLA entry as ESM (`src/bin/ibex/runtime.rs:3142-3154`).

   **Resolution criterion:** Add one sentence stating that the fire-and-forget defect is the bootstrap/file-at-a-time dependency path, not every current entry path. Make Phase 0 report separate baselines for scanner-lowered ESM, SWC-lowered TS/JSX, prepared Rolldown entries, and the entry-TLA shim.

## 4. Cross-document findings

- LLP 0007 and LLP 0009 form a clean architectural lead-in: they retain SWC because the current loader is synchronous and explicitly route an asynchronous ModuleRunner redesign to a later decision (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:124-172`, `llp/0009-runtime-transform-candidate-scope.decision.md:39-73`). LLP 0026 is the right document to resolve that fork; only the adoption sequence is wrong.

- LLP 0019 is handled honestly. LLP 0026 explicitly recognizes that a hermetic in-process Oxc implementation would be a third tier and requires an amendment plus real-Hermes corpus coverage (`llp/0026-esm-module-runner.rfc.md:313-323`). That is a clean seam rather than a silent exception.

- LLPs 0013 and 0021 align well with the proposed graph. Per-principal HBC carriers follow LLP 0013’s `RuntimeModule` attribution constraint (`llp/0013-per-package-capability-compartments.rfc.md:317-337`), and LLP 0026 retains LLP 0021’s complete constrained-principal context rather than reducing attribution to a single current package (`llp/0021-capsec-effect-model-migration.plan.md:368-384`). The missing piece is the graph-specific authorization operation identified in Concern 4.

- LLP 0023 is the correct owner of SourceId, and LLP 0026 properly gates graph publication on its unlanded constructor and provenance obligations (`llp/0023-virtual-filesystem-namespace.spec.md:655-729`, `llp/0023-virtual-filesystem-namespace.spec.md:2053-2059`). The RFC should reword its earlier statement that identity derives from “SourceId and the defining principal” (`llp/0026-esm-module-runner.rfc.md:119-122`), because the principal occurs exactly once inside SourceId (`llp/0023-virtual-filesystem-namespace.spec.md:691-710`).

- Some LLP 0023 implementation-status prose has drifted behind the code. It still describes Host as only a process-global singleton and `OBL-HOST-SESSION` as unlanded (`llp/0023-virtual-filesystem-namespace.spec.md:1632-1654`, `llp/0023-virtual-filesystem-namespace.spec.md:2063-2064`), while the code now has claimed per-runtime Host contexts and active-context selection (`src/host/abi.rs:151-175`, `src/host/abi.rs:278-354`, `src/host/abi.rs:427-531`). It similarly says per-principal path projections are absent, while `PrincipalPathProjections` and fail-closed completeness checks now exist (`crates/capsec-semantics/src/decision.rs:338-351`, `crates/capsec-semantics/src/decision.rs:991-1080`). SourceId itself remains genuinely absent.

- LLP 0004’s metadata-only description has drifted from the ESM resolver implementation. Its body-read-free claim (`llp/0004-module-loading-and-builtins.explainer.md:53-63`) conflicts with `src/module_loader/mod.rs:928-945`. This is the same issue already tracked by LLP 0023’s `OBL-RESOLVE-GATE`, so 0026 should consume that obligation instead of creating a parallel description.

- LLP 0024 cleanly predicts the need for this RFC: dependency TLA requires an asynchronous linker with live bindings, cycles, failure propagation, caching, and CJS interop (`llp/0024-structured-evaluation-and-session.spec.md:472-519`). Its ABI, cancellation, failure-caching, and source-map contracts must, however, be reconciled before the general graph is presented as consumable by sessions.

- LLP 0022 has settled session grant-bearing forms on refusal and delegates only direct-file behavior to LLP 0014 (`llp/0022-repl-behavior-and-semantics.spec.md:553-618`). LLP 0026 should refer to that obligation, not an open question.

- LLP 0005’s fallback rule is carried through correctly: source fallback may follow a pre-execution bytecode load rejection, never a program error after effects (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:107-132`; `llp/0026-esm-module-runner.rfc.md:520-532`).

- LLP 0007’s current call-site wording has minor drift: it describes a direct `transpile_to_cjs` call, while the code now dispatches through `transpile_source_to_cjs`. The substantive claim remains true because the default SWC branch still drops the selected `target` (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:143-165`; `src/module_loader/transpile.rs:84-94`).

## 5. Suggestions

- Use four explicit layers instead of one broad artifact structure: `AuthenticatedResolvedSource`, intrinsic `ModuleArtifact`, runtime-local `ModuleRecord`, and per-invocation `EvaluationContext`. This would make it structurally difficult for role, HMR generation, or caller identity to leak into content identity.

- Build a small executable reference model of linking and evaluation before implementing the Hermes runner. Model uninitialized cells, indirect exports, star ambiguity, sync and async SCCs, shared evaluation, cancellation, failure caching, and generation replacement. Differentially drive the same event trace through Node and the implementation.

- Add deterministic scheduling and fault injection for TLA graphs. Record a compact schedule trace covering promise fulfillment, dynamic import, cancellation, invalidation, and old-generation completion so every concurrency failure can be replayed.

- Treat HMR generations as an MVCC/RCU problem: atomically publish a new graph root, keep old records immutable while namespace objects or promises retain them, and reclaim only after the last generation-bearing handle is released.

- Add a carrier-invariance property test that randomly changes module-to-chunk grouping, cache location, source versus HBC representation, and load order. `SourceId`, principal, static edge set, namespace behavior, and CapSec effect trace must remain invariant.

- Expand the SourceId negative corpus to include two projects with the same relative path, two principals hard-linking identical bytes, raw/bundled/HBC versions of one source, two live runtimes, destroy/recreate ABA, and tampered principal/SourceId pairs. The current production root identity is the constant `"project-root"` (`src/bin/ibex/runtime.rs:2020-2034`), making the project-arm cases especially important.

- Time-box an engine-native Hermes ESM prototype after the artifact and corpus contracts are precise. It need not replace this proposal, but it would provide a useful complexity and performance kill criterion against maintaining a permanent user-space linker.

## 6. Open questions

1. What is the exact versioned factory ABI, including checked-cell access, TDZ, indirect exports, star ambiguity, namespace construction, and sync/async execute results?

2. Which bytes are canonicalized and digested for a ModuleArtifact, and what trusted issuer or snapshot binding lets native code accept prepared metadata without reparsing it?

3. What host API starts an asynchronous graph and reports fulfillment, rejection, lifecycle, cancellation, and engine faults without thenable assimilation or hidden timeouts?

4. When several importers share one evaluating record, what does cancellation of one waiter do to the shared evaluation, its dependencies, and future imports?

5. Does graph-edge authorization use only the authenticated requesting record, or must every constrained principal’s graph dimension also allow? How does that combine with the filesystem effects of loading source?

6. Which exact runtime/session identity and generation constitute a record namespace, and how are ABA, worker replacement, HMR publication, stale completions, source maps, and GC handled?

7. Will unbundled direct-file grant attributes be refused in v1, or processed by a separate pre-runtime authenticated graph pass? If processed, how is its result bound into the immutable snapshot?

8. Will the existing Node `24.13.1` compatibility target govern CommonJS named exports and `require(ESM)`? If not, which authority changes?

9. Which Oxc/Rolldown Rust integration can emit the normative artifact on the pinned toolchain, and what is the fallback decision if no current Rolldown Rust API satisfies the contract?

10. When sessions adopt the graph, where do the Rust graph owner and Hermes-owned handles live in LLP 0025’s supervisor/worker topology, and what may cross that process boundary?

## 7. Readiness verdict

The proposal is directionally strong and the case for replacing the current scanner-based path is proven. The security posture, SourceId gating, per-principal carrier rule, and behavior-oriented migration plan are all promising.

It is not ready for acceptance because the artifact ABI, asynchronous embedding contract, resolver read ordering, graph authorization semantics, direct-file grant disposition, generation identity, CommonJS oracle, and governing-decision sequence remain material unresolved design issues. These are central contracts rather than optional implementation polish.

VERDICT: NOT READY
---

## Round 3 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f6572-6a3a-7630-b00b-dd846b218a55`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `6fd42d559714`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-3 review of the same revision and no access to any
  prior LLP 0026 review artifact — rounds 1–2 artifacts were moved out of
  `llp/reviews/` into a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** cli-runner, round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round3.md`) — the round-2 brief
  updated to the new revision hash; same brief as the Fable round-3 reviewer.
- **Orchestrator verification note (outside the verbatim body):** Concern 1's
  claim that the resolver body-read is dormant was verified true —
  `ResolveOptions` leaves `module_type` detection at its disabled default
  (`src/module_loader/mod.rs:105-135`) and the test note at
  `src/module_loader/mod.rs:3849-3852` records the `kind == Esm` prefetch
  branch as dormant — so LLP 0023's `OBL-RESOLVE-GATE` ledger row and the
  revision-2 RFC text describing a live body-read overstate current behavior.

### Verbatim review

## 1. Overall assessment

The requested revision matches SHA-256 prefix `6fd42d559714`.

The proposal’s central direction is sound: Ibex needs a real module graph rather than further extending its file-at-a-time ESM-to-CommonJS compatibility layer. The RFC correctly identifies the current scanner’s fragility, the dependency-level top-level-`await` defect, and the need to preserve authenticated source identity and package attribution.

It is not ready, however. Material gaps remain in resolution/source-goal selection, HMR identity, artifact integrity and portability, source-factory attribution, producer feasibility, and cancellation semantics. Several governing LLP contracts would also be changed despite the RFC listing them as non-goals or deferring their reconciliation too late.

## 2. Strengths

- The present-state diagnosis in RFC §Motivation is substantially correct. Rust transforms TypeScript/JSX extensions and only scanner-selected `.js`/`.mjs`/`.cjs` content (`src/module_loader/mod.rs:331-388`), so ordinary import/export-heavy JavaScript reaches the bootstrap unchanged. Hermes then compiles modules as CommonJS-shaped function bodies taking `require`, `module`, `exports`, filenames, and a dynamic-import helper (`src/engine/bootstrap/module-loader.js:235-253,5500-5506`). `transformEsmToCjs` is an approximately 842-line non-AST transformer (`src/engine/bootstrap/module-loader.js:4224-5065`), supported by raw scanners for `import.meta`, regexes, templates, delimiters, and dynamic import (`src/engine/bootstrap/module-loader.js:3587-4223`). This strongly supports RFC §Motivation (`llp/0026-esm-module-runner.rfc.md:54-79`).

- The RFC correctly distinguishes CommonJS cycles from ESM cyclic instantiation. The current loader publishes a CommonJS record before executing its body and returns cached partial exports during cycles (`src/engine/bootstrap/module-loader.js:5297-5305,5340-5364`). Its scanner-lowered ESM, however, snapshots imported and exported values and eagerly copies star exports (`src/engine/bootstrap/module-loader.js:4594-4650,4860-4900,5031-5059`), so it cannot supply ESM cells, TDZ behavior, or star-ambiguity semantics. RFC §Motivation’s graph-level conclusion is therefore justified (`llp/0026-esm-module-runner.rfc.md:81-96`).

- The dependency-TLA defect is described accurately. `wrapAsyncModule` emits a fire-and-forget IIFE (`src/engine/bootstrap/module-loader.js:5415-5417`); module-body invocation ignores the return value (`src/engine/bootstrap/module-loader.js:5500-5506`); retry paths explicitly allow the pre-`await` prefix to execute twice (`src/engine/bootstrap/module-loader.js:5680-5695,5752-5760`); and the module is marked loaded immediately (`src/engine/bootstrap/module-loader.js:5797-5798`). Dynamic import merely schedules the same synchronous loader (`src/engine/bootstrap/module-loader.js:6082-6149`). RFC §Motivation and §6 correctly demand graph-level settlement instead (`llp/0026-esm-module-runner.rfc.md:98-112,468-510`).

- The native-owner/Hermes-object split in RFC §4 is a good architectural seam (`llp/0026-esm-module-runner.rfc.md:374-429`). Keeping authenticated identity, policy, lifecycle, and scheduling native while leaving namespace objects, cells, and factories in JavaScript fits LLP 0013 and LLP 0021. Existing code already has useful substrate: runtime callback identity is pointer-plus-nonce and validates against ABA reuse (`src/engine/hermes_runtime_internal.h:98-109`; `src/engine/hermes_runtime.cc:828-840,884-906`), and runtime-scoped Host contexts exist (`src/host/abi.rs:151-176,278-309,427-449`).

- The migration and conformance posture is appropriately evidence-driven. RFC §11 and the acceptance criteria require real-Hermes execution, fail-loud nonzero case counts, prepared/source equivalence, source maps, attribution, and performance gates (`llp/0026-esm-module-runner.rfc.md:660-695,697-821,886-915`). That matches LLP 0018’s fail-loud discipline. It also correctly treats Oxc and SWC as existing foundations rather than hypothetical dependencies: both are in the Rust tree (`Cargo.toml:44-53,98-106`), and the current implementation exposes Oxc as an opt-in candidate while retaining SWC as default (`src/module_loader/transpile.rs:41-95`).

## 3. Concerns

1. **Resolution mode and source-goal selection are unspecified, while the stated current resolver defect is stale.**

   **Severity:** Material

   **Evidence:** RFC §1 says the existing resolver remains authoritative for conditions and claims metadata resolution currently reads ordinary `.js`/`.mjs` bodies before authentication (`llp/0026-esm-module-runner.rfc.md:232-259`). That observed claim is false in this revision:

   - `ResolveOptions.module_type` is not enabled (`src/module_loader/mod.rs:105-135`).
   - The repository explicitly records that module-type detection is disabled and the `kind == Esm` prefetch branch is dormant (`src/module_loader/mod.rs:3848-3852`).
   - `resolve_meta` is tested to leave source unset (`src/module_loader/mod.rs:2606-2633`).
   - Armed resolution authenticates the requester and preflights the target before resolver probing, then validates the resolved binding, locator, and integrity (`src/host/mod.rs:2201-2267,2267-2367`); executable bytes are loaded afterward (`src/host/mod.rs:2107-2158`).
   - LLP 0004 likewise describes metadata resolution as body-free (`llp/0004-module-loading-and-builtins.explainer.md:53-63,463-468`).

   The dormant ESM branch would read the body if module-type detection were re-enabled (`src/module_loader/mod.rs:928-945`), so removing that hazard is worthwhile, but it is not current behavior.

   More importantly, the current resolver is intentionally CommonJS-shaped: its single condition set contains both `require` and `import` (`src/module_loader/mod.rs:117-122`); private package imports explicitly prioritize `require` because this loader runs CommonJS (`src/module_loader/mod.rs:1617-1641,2662-2674`); and an unclassified module defaults to CommonJS (`src/module_loader/mod.rs:907-922`). RFC §“Parse once” incorrectly says source goal “comes from” parsing (`llp/0026-esm-module-runner.rfc.md:195-201`), although Script versus Module is an input to parsing and can change strictness and top-level semantics for otherwise ambiguous `.js` text. RFC §6 also specifies only `import(specifier)`, while §2 models attributes only on static edges (`llp/0026-esm-module-runner.rfc.md:317-323,475-481`).

   **Resolution criterion:** Re-audit and correct `OBL-RESOLVE-GATE`, describing the body read as a latent branch that must be removed before module-type detection is enabled. Define a typed resolution contract distinguishing ESM static import/re-export/dynamic import, CommonJS `require`, and entry resolution; specify their condition sets, package-`type` and extension classification, source-goal selection before parsing, cache-key isolation, and dynamic-import options/import attributes. Add fixtures in which `import` and `require` select different conditional exports/imports and in which syntactically ambiguous `.js` bodies receive different goals.

2. **Graph generations contradict the governing module-identity and immutable-authority contracts.**

   **Severity:** Material

   **Evidence:** The RFC declares module identity to be `(runtime, SourceId)` but keys records by `(runtime, SourceId, generation)` (`llp/0026-esm-module-runner.rfc.md:165-177`). RFC §8 then permits old and new records for the same `SourceId` to coexist and scopes the one-instance invariant per generation (`llp/0026-esm-module-runner.rfc.md:575-584`), while the security invariant and acceptance criteria still require one record and identity `(runtime, SourceId)` (`llp/0026-esm-module-runner.rfc.md:656-658,898-901`).

   LLP 0023 does not limit its identity rule to production; it applies to every armed execution mode (`llp/0023-virtual-filesystem-namespace.spec.md:154-172`) and defines the sole key shape as `(runtime, SourceId)` (`llp/0023-virtual-filesystem-namespace.spec.md:655-710`). LLP 0024 likewise requires one instance per equal `SourceId` for the session (`llp/0024-structured-evaluation-and-session.spec.md:1623-1661,2110-2117`). Thus RFC §8’s assertion that these documents assume a single production generation is unsupported.

   HMR also operates beside an immutable CapSec graph. LLP 0021 binds package graph, import axes, principal bindings, policy, and protected objects into the armed snapshot (`llp/0021-capsec-effect-model-migration.plan.md:193-214,380-393`), while LLP 0022 requires regeneration and restart to widen a session graph (`llp/0022-repl-behavior-and-semantics.spec.md:337-351`). RFC §8 does not separate an execution-record generation from that authority snapshot.

   **Resolution criterion:** Define distinct `ModuleIdentity`, `ModuleIncarnationKey`, `ExecutionGraphGeneration`, and `AuthoritySnapshotGeneration` concepts. Either revise LLPs 0023/0024 to permit multiple coherent incarnations per logical identity or make each HMR generation a distinct runtime/session identity. State exactly which first-party artifacts may change within one armed snapshot; package principals, integrity-bound bytes, import axes, bindings, or edges must require a newly armed runtime. Reconcile CommonJS records, namespaces, error caching, and late dynamic-import completion under the same algebra before adoption.

3. **The artifact’s authenticated and portable representation is incomplete.**

   **Severity:** Material

   **Evidence:** RFC §2 lists `source_id`, `source_label`, kind, dialect, principal, integrity, TLA, factory, and link metadata in `ModuleArtifact`, but its normative digest-coverage sentence enumerates only factory bytes, descriptors, edges, source digest, transform fingerprint, and source map (`llp/0026-esm-module-runner.rfc.md:265-315`). The omission is security-critical: an unbound `has_top_level_await` or source kind could invalidate the synchronous-`require` proof, while an unbound `SourceId` or principal could misattribute code.

   `source_label` also conflicts with artifact portability. LLP 0023 defines `SourceId` as machine-portable but `SourceLabel` as a machine-local, volume-canonical display spelling (`llp/0023-virtual-filesystem-namespace.spec.md:749-790`). A build-machine label cannot silently become the authoritative runtime label on another machine while the RFC simultaneously claims one canonical logical artifact across source, cache, bundle, and bytecode carriers.

   Finally, `defining_principal` is duplicated as a field and verification value (`llp/0026-esm-module-runner.rfc.md:270-315`) even though LLP 0023 requires it to appear exactly once inside `SourceId` (`llp/0023-virtual-filesystem-namespace.spec.md:691-696`).

   **Resolution criterion:** Specify a versioned canonical wire schema whose digest covers every semantic field, or explicitly identifies fields derived and recomputed from covered data. Derive the principal from `SourceId`. Keep the runtime `SourceLabel` outside portable artifact identity or define a non-authoritative display hint plus authenticated runtime remapping. Include malformed-field, field-substitution, cross-machine-label, and TLA-bit tampering fixtures.

4. **Source-factory compilation and physical carrier attribution are not specified.**

   **Severity:** Material

   **Evidence:** RFC §4 says attribution is bound “before invoking” a factory, but a source factory’s `CodeBlock`/`Domain` attribution is determined when it is compiled, not merely when called (`llp/0026-esm-module-runner.rfc.md:374-429`). The current loader demonstrates the required ordering: it sets the pending principal before `new Function`, then binds the created function’s compartment (`src/engine/bootstrap/module-loader.js:235-272`). LLP 0013 requires structural `CodeBlock → RuntimeModule → package` attribution and explains that one HBC is one `RuntimeModule` (`llp/0013-per-package-capability-compartments.rfc.md:317-336`).

   RFC §2 models `factory_source | factory_bytecode` as a per-module field whose exact bytes are digested, while §9 permits per-principal multi-module HBC carriers (`llp/0026-esm-module-runner.rfc.md:270-295,590-614`). A shared HBC is not naturally the bytecode of each individual factory; the contract needs an authenticated carrier digest plus per-module entry references. The current text does not define that mapping or the source-mode equivalent of the prepared carrier’s attribution rule.

   **Resolution criterion:** Define a native-only `compile/load factory` operation that verifies the complete artifact and carrier, stamps the authenticated principal and compartment before compilation/load, returns an opaque callable handle, and is unreachable from package JavaScript. Split logical module metadata from physical carrier blobs and define authenticated per-module entry references. Require attribution fixtures for cold source, warm cached source, prepared source, per-module HBC, and multi-module per-principal HBC.

5. **No core artifact producer has yet been demonstrated on the required hermetic toolchain.**

   **Severity:** Material

   **Evidence:** RFC §3 leaves three materially different implementations open—Oxc ModuleRunner, custom Oxc code generation, or a Rolldown runtime API—and defers selection to Phase 1 (`llp/0026-esm-module-runner.rfc.md:325-363,741-752`). Current Oxc 0.121 parses and transforms syntax but explicitly rejects top-level await and fails when general ESM remains (`src/module_loader/transpile.rs:199-264,401-421`). Rolldown is presently a JavaScript development dependency, loaded from `node_modules` by a Bun/Node-side script (`package.json:30-39`; `packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:20-27,304-317`), not an in-process Rust dependency.

   LLP 0009 records that newer Rolldown/Oxc Rust versions exceed the pinned Rust 1.93.1 toolchain, while Oxc 0.121 compiles but lacks the current general module lowering (`llp/0009-runtime-transform-candidate-scope.decision.md:39-65`; `rust-toolchain.toml:1-3`). A custom `System.register`-shaped emitter is plausible, but plausibility is not yet evidence that it can deliver live-update instrumentation, TLA, Hermes compatibility, and composed maps.

   **Resolution criterion:** Before accepting the architecture, land or attach a bounded spike proving one selected in-process path on the pinned toolchain—or an explicit toolchain-upgrade decision. It must emit and execute representative canonical artifacts for live mutation, cycles, TDZ, re-exports, TLA, dynamic import, TypeScript/JSX, Hermes compatibility, and source maps on real Hermes.

6. **“Waiter-exact cancellation” invents a primitive not supplied by the delegated contracts.**

   **Severity:** Material

   **Evidence:** RFC §6 says it reuses LLP 0024/0025 cancellation semantics, then promises that cancelling one waiting import rejects only that waiter’s public promise (`llp/0026-esm-module-runner.rfc.md:483-498`). It does not define who can cancel an `import()` waiter, how a waiter is identified, or how cancellation reaches an ordinary JavaScript Promise.

   LLP 0024 cancellation targets the currently executing work unit by a monotonic target ID (`llp/0024-structured-evaluation-and-session.spec.md:872-925`). LLP 0025 explicitly says a suspended unit receives no cancellation request because no delivery mechanism exists (`llp/0025-terminal-session-ownership.spec.md:553-575`). Therefore the RFC is not merely delegating existing semantics.

   **Resolution criterion:** Either remove per-waiter cancellation from v1 and limit cancellation to existing structured-evaluation/session teardown, or define a new waiter-token/API with ownership, target identity, settlement, race, and teardown rules in LLPs 0024/0025. Specify how detaching the final waiter affects a still-running shared evaluation and its keepalive ownership.

7. **The SWC alternative overstates what the current path cannot preserve.**

   **Severity:** Minor/Non-blocking

   **Evidence:** RFC §Alternatives says file-at-a-time SWC cannot provide live exported bindings (`llp/0026-esm-module-runner.rfc.md:831-837`). Ibex actually invokes SWC’s CommonJS module transform (`src/module_loader/transpile.rs:166-179`), whose pinned implementation emits getter-backed exports and rewrites imported identifiers as module-property reads. The repository also contains getter-shaped transformed output in its loader fixtures (`src/bin/ibex/runtime.rs:7347-7355`). SWC still does not provide the complete ESM graph contract—namespace exotic behavior, exact cyclic instantiation, star ambiguity, and dependency TLA remain missing—but it preserves more ordinary live-binding cases than the bootstrap scanner.

   **Resolution criterion:** Revise the alternative to say that SWC preserves some live-binding and simple-cycle cases but does not guarantee the complete linked-ESM contract. Make Phase 0 measure scanner-lowered JavaScript and SWC-lowered TypeScript/JSX separately.

## 4. Cross-document findings

- **Clean seam:** LLP 0007 explicitly reserves a separate ModuleRunner decision when transform convergence requires a loader redesign (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:45-48,248-282`), and LLP 0009 permits that later architecture (`llp/0009-runtime-transform-candidate-scope.decision.md:63-73`). RFC 0026 is the correct document in which to resolve that fork.

- **Clean seam:** RFC §3 does not silently violate LLP 0019’s exactly-two-tier decision. It explicitly requires an amendment for a Rust/Oxc AST tier and subjects it to the existing real-Hermes corpus (`llp/0026-esm-module-runner.rfc.md:347-357`; `llp/0019-hermes-compat-transform-authority.decision.md:10-48,79-100`).

- **Clean seam:** `GraphEvaluationContext`’s complete constrained-principal set matches LLP 0021’s intersection rule (`llp/0026-esm-module-runner.rfc.md:386-405`; `llp/0021-capsec-effect-model-migration.plan.md:368-378`). Per-principal executable carriers likewise align with LLP 0013’s `RuntimeModule` attribution granularity (`llp/0026-esm-module-runner.rfc.md:590-614`; `llp/0013-per-package-capability-compartments.rfc.md:328-336`).

- **Intentional but unresolved replacement:** LLP 0024’s entry-only dependency-TLA refusal and delete-on-failure cache behavior are explicitly superseded by RFC §§5–6 (`llp/0026-esm-module-runner.rfc.md:459-510`; `llp/0024-structured-evaluation-and-session.spec.md:472-519,1656-1661`). Those edits must land when the first consumer adopts the runner, not wait for Phase 5 cleanup.

- **Conflict:** Graph generations contradict LLP 0023/0024’s all-modes one-instance identity, and HMR is not separated from LLP 0021/0022’s immutable armed graph. This is a normative change despite RFC §Non-goals saying source identity and capability policy are unchanged (`llp/0026-esm-module-runner.rfc.md:149-159`).

- **Drift:** RFC 0026 and LLP 0023 still describe a metadata body-read bug that current code and LLP 0004 say has been removed. The dormant branch remains hazardous, but the ledger and RFC must be revised to distinguish landed behavior from latent work.

- **Incomplete reconciliation set:** The adoption gate names only LLPs 0007, 0009, and 0019, and Phase 5/acceptance omit LLPs 0002 and 0014 (`llp/0026-esm-module-runner.rfc.md:699-710,787-800,911-915`). Resolver ABI claims implicate LLP 0002, while standard and reserved import attributes, direct-file grants, and generated graph policy implicate LLP 0014. Reconciliation should be phase-specific rather than deferred wholesale.

## 5. Suggestions

- Build a small executable reference model of module records, cells, SCC evaluation, CJS adapters, and sync-`require` refusal. Exhaustively enumerate small mixed ESM/CJS graphs with cycles, TLA, failures, and re-entry, then compare observable traces with Node. This would find lifecycle bugs before they are embedded in native/Hermes glue.

- Introduce the new resolver and artifact producer first in non-executing shadow mode: compare resolved targets, source goals, static edges, principals, and authorization traces against the current path without invoking factories.

- Make `ResolutionKind`, `ModuleIdentity`, `ModuleIncarnationKey`, `AuthoritySnapshotGeneration`, `ExecutionGraphGeneration`, `LogicalArtifact`, and `PhysicalCarrier` distinct Rust types. The current prose repeatedly relies on distinctions that the proposed structures do not yet encode.

- Version the selected CommonJS named-export detector and include that version in `transform_fingerprint`; “the cjs-module-lexer contract” is observable compatibility behavior, not merely an implementation detail.

- Add conformance cases for conditional `exports`/`imports`, dynamic JSON import attributes, multiple concurrent importers with different constrained-principal sets, cancellation during an async SCC, and prepared multi-module HBC entry mapping.

- Resolve the small SWC exit-criteria inconsistency: RFC §3 allows a parser-only SWC dependency to remain after module-transform retirement (`llp/0026-esm-module-runner.rfc.md:365-372`), while acceptance criterion 11 requires removal or one time-bounded exception (`llp/0026-esm-module-runner.rfc.md:909-910`). State the criterion separately for the transform and parser roles.

## 6. Open questions

1. What exact resolution mode, condition set, package-kind algorithm, and parser source goal applies to each static import, dynamic import, `require`, and entry request?
2. Which in-process Oxc/Rolldown integration has actually demonstrated the complete factory contract on Rust 1.93.1 and real Hermes?
3. Is graph generation part of module-instance identity, runtime identity, or merely an HMR transaction—and how does that reconcile with armed snapshot immutability?
4. What exact canonical bytes are digested for a logical artifact, and how are machine-local labels and shared physical carriers represented outside that identity?
5. How are source factories compiled into correctly attributed Domains/RuntimeModules before any code can run?
6. When multiple importers concurrently reach one unevaluated record with different schedule-time or deputy contexts, which evaluation context owns its one-time initialization, and can import order change an authority result?
7. Is per-waiter cancellation required in v1? If so, what object names the waiter and how does it compose with LLP 0024/0025 target IDs?
8. How are dynamic import options and JSON attributes represented, validated, authorized, and included in cache/link identity?
9. What exact Node 24 namespace behavior is required for `require(ESM)`, including `__esModule`, default handling, and the `"module.exports"` export marker?
10. How does a per-principal multi-module HBC identify and authenticate each factory entry without treating the whole carrier as each module’s bytecode?

## 7. Readiness verdict

The architecture is promising and addresses a genuine correctness and maintainability problem, but the unresolved resolution, identity, artifact-security, attribution, feasibility, and cancellation issues are material. The RFC should remain Draft until those contracts are made coherent and at least one producer/runner spike proves the central ABI on the pinned toolchain.

VERDICT: NOT READY
---

## Round 4 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f6585-0d59-7042-b74a-32fd13080d65`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `19962358a06f`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`. The review
  cites two public nodejs.org documentation URLs; no repository content was
  sent anywhere by the orchestrator beyond the authorized Codex run itself.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-4 review of the same revision and no access to any
  prior LLP 0026 review artifact — rounds 1–3 artifacts were kept out of
  `llp/reviews/` in a scratch stash for the duration of the round. Instructed
  not to read `llp/reviews/`.
- **Method:** cli-runner, round-4 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round4.md`) — the round-3 brief
  updated to the new revision hash; same brief as the Fable round-4 reviewer.
- **Orchestrator verification note (outside the verbatim body):** spot-checks
  confirmed the decisive new claims: `require.cache`/`main` are exposed today
  (`module-loader.js:5485,5841,5868,5882`; trusted bootstrap reads
  `__exactRequire.cache`, `exact-global.js:2829`), the Hermes scheduling patch
  stores a single `uint32_t` principal per job
  (`patches/hermes/0008-schedule-time-principal-capture.patch`), and no LLP
  mentions Node's `module-sync` condition. The Node 24 `'module.exports'`
  marker/`require(ESM)` return-selection behavior matches the pinned target's
  documented semantics.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes the right architectural replacement for Ibex’s current ESM compatibility path. The existing bootstrap transformer is performing parser, linker, and evaluator work through hand-written scanners, and dependency-level top-level `await` is genuinely unsound. A native-owned authenticated graph, explicit module records, binding cells, asynchronous evaluation, and per-module provenance are the correct direction.

The RFC is unusually strong on migration discipline: it preserves CommonJS as synchronous, requires real-Hermes artifacts before broad implementation, keeps SWC until independent gates pass, and demands behavior-level rather than transformed-text conformance.

It is not ready for acceptance at revision `19962358a06f`. Several material contracts remain contradictory or incomplete: ambiguous-source classification cannot satisfy the stated parse-once rule; the pinned Node interop behavior is not fully represented; no-probe resolution lacks required authenticated graph data; shared evaluation has no deterministic CapSec-context algebra; the artifact wire/digest treatment of `SourceLabel` is inconsistent; the allegedly closed loader cache is exposed and used; and synchronous `require()` over an overlapping asynchronous graph remains an acknowledged open state-machine question.

## 2. Strengths

- The central diagnosis is accurate. Rust transforms TypeScript/JSX extensions and scanner-selected JavaScript, while ordinary `.js`/`.mjs` content can pass through unchanged ([LLP 0026 §Motivation](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:54), [src/module_loader/mod.rs:354](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:354), [src/module_loader/mod.rs:364](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:364), [src/module_loader/mod.rs:371](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:371)). The resolver currently classifies unrecognized modules as CommonJS, and its ESM-prefetch branch is dormant because module-type detection is disabled ([src/module_loader/mod.rs:907](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:907), [src/module_loader/mod.rs:928](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:928), [src/module_loader/mod.rs:3848](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:3848)).

- The RFC does not exaggerate the bootstrap transformer’s role. Its lexical machinery begins around [module-loader.js:3743](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3743), while `transformEsmToCjs` itself spans roughly [module-loader.js:4224](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4224) through line 5065. It manually handles templates, comments, delimiter balance, regular expressions, statement splitting, import forms, exports, and re-exports. Its generated imports and exports are often snapshots rather than live cells ([module-loader.js:4594](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4594), [module-loader.js:4868](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4868), [module-loader.js:5031](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5031)). The RFC is correct that repairing individual defects is reasonable but extending this into a second module implementation is not ([LLP 0026 §Motivation](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:67)).

- The dependency-TLA finding is verified. `wrapAsyncModule` creates a fire-and-forget async IIFE ([module-loader.js:5415](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5415)); wrapper invocation discards its return value ([module-loader.js:5500](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5500)); and the module is then marked loaded synchronously ([module-loader.js:5797](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5797)). The narrow invocation-time retry can execute a prefix twice. The RFC correctly distinguishes this dependency path from the separately awaited CLI-entry machinery ([LLP 0026 §Motivation](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:98)).

- The proposed graph semantics address the actual abstraction gap. The declare/execute factory ABI, checked binding cells, TDZ sentinel, namespace construction, star-export ambiguity handling, linked lifecycle, SCC ordering, and shared evaluation promise are the right responsibilities ([LLP 0026 §4](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:462), [LLP 0026 §5](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:492)). This is materially better than attempting increasingly elaborate CommonJS wrappers.

- The identity model is directionally sound. LLP 0023 defines module identity as `(runtime, SourceId)` and places the defining principal exactly once inside `SourceId` ([llp/0023-virtual-filesystem-namespace.spec.md:676](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:676), [llp/0023-virtual-filesystem-namespace.spec.md:691](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:691)). The runtime side already has an ABA-resistant pointer-plus-nonce identity: callback lookup validates both ([src/engine/hermes_runtime.cc:885](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:885)), and creation assigns a fresh nonce ([src/engine/hermes_runtime.cc:3656](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3656)). The RFC also honestly treats `SourceId` as unimplemented prerequisite work rather than silently using the current path-based cache key ([LLP 0026 §Phase 1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:832), [module-loader.js:5297](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5297)).

- Toolchain status and feasibility are represented accurately. SWC is the default runtime-transform engine and performs parsing, TypeScript stripping, JSX lowering, CommonJS lowering, helpers, hygiene, and emission ([src/module_loader/transpile.rs:64](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:64), [src/module_loader/transpile.rs:109](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:109)). Oxc parser/AST/transform crates and `oxc_resolver` are already direct dependencies ([Cargo.toml:44](/Users/ccheever/projects/ibex/Cargo.toml:44)), but the current Oxc candidate rejects TLA and cannot lower general ESM for the synchronous loader ([src/module_loader/transpile.rs:199](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:199), [src/module_loader/transpile.rs:258](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:258)). Requiring a bounded, real-Hermes producer spike before acceptance is therefore exactly the right gate ([LLP 0026 §Adoption gate](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:785)).

- The migration and conformance strategy is strong. It names distinct current paths, prohibits production shadow execution of side effects, requires source/prepared equivalence, and includes live bindings, cycles, TLA, interop, attribution, two-runtime behavior, generation races, source maps, and unauthorized-edge non-disclosure ([LLP 0026 §Compatibility contract](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:741), [LLP 0026 §Migration plan](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:812)).

## 3. Concerns

1. **The ambiguous-source algorithm contradicts “parse once,” and the resolution-condition contract is not exact enough.**

   **Severity:** Material

   **Evidence:** The RFC says the source goal is selected before parsing and that every source is parsed once ([LLP 0026 §Design principles](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:204)). It then requires ambiguous `.js` to follow Node’s unambiguous-module-syntax detection ([LLP 0026 §1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:278)). Node’s algorithm itself parses the ambiguous source as a module to detect static import/export, `import.meta`, TLA, and lexical redeclarations of CommonJS wrapper names; this cannot be done exactly by selecting the goal before the only parse. See the official [Node 24 ESM documentation](https://nodejs.org/download/release/latest-v24.x/docs/api/esm.html).

   The condition vectors are also underspecified. The current resolver merges `node`, `require`, `import`, and `default` ([src/module_loader/mod.rs:105](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:105)); the RFC says `ResolutionKind` selects “import versus require” but does not enumerate the full ordered vectors or account for Node 24’s `module-sync` condition, which is directly relevant to synchronous `require(ESM)`. Node documents that condition in its [package-resolution contract](https://nodejs.org/download/release/latest-v24.x/docs/api/packages.html).

   **Resolution criterion:** Specify a complete authenticated classification algorithm. It should state when bytes are read, whether ambiguous input gets a preliminary module parse or a reusable goal-neutral parse, and which parse result feeds transformation. Revise “parse once” if exact Node classification requires two goal-sensitive parses. Enumerate the ordered active conditions and cache-key fields for every `ResolutionKind`, including `node`, `default`, user conditions, and `module-sync` disposition. Add oracle fixtures for TLA, `import.meta`, wrapper-variable redeclarations, and `module-sync` exports.

2. **The explicit Node 24 interop rules omit pinned behavior in both directions.**

   **Severity:** Material

   **Evidence:** The RFC says ESM importing CommonJS receives detected named exports plus `default = module.exports` ([LLP 0026 §7](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:585)). Since Node 23, a CommonJS namespace also always contains a named `'module.exports'` marker referring to that same value; this behavior is present in the pinned Node 24 family and documented in the official [Node 24 ESM documentation](https://nodejs.org/download/release/latest-v24.x/docs/api/esm.html).

   Conversely, the RFC says synchronous `require(ESM)` returns the namespace object ([LLP 0026 §7](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:598)). Node 24 instead returns an ESM export named `'module.exports'` directly when one exists and conditionally supplies `__esModule` on namespace results with a default export; see [Node’s CommonJS documentation](https://nodejs.org/api/modules.html). The repository explicitly pins Node 24.13.1 as its compatibility target ([runtime-identity.json:10](/Users/ccheever/projects/ibex/runtime-identity.json:10)). These behaviors are neither implemented in the prose nor named as divergences.

   **Resolution criterion:** Add an exact bidirectional interop table covering namespace keys and descriptors, `'module.exports'`, `__esModule`, falsy defaults, static named-export snapshots, replacement of `module.exports`, and `require(ESM)` return selection. Either match pinned Node 24 and add corpus cases, or declare each intentional divergence explicitly under the expected-divergence mechanism.

3. **The no-probe ordering depends on authenticated graph-location data that Phase 1 does not require.**

   **Severity:** Material

   **Evidence:** The RFC requires authorizing a requested edge before resolver probing, then authenticating the exact target principal, locator, integrity, and `SourceId` ([LLP 0026 §1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:243)); exact edge authorization is also a security invariant ([LLP 0026 §Security invariants](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:718)).

   LLP 0023’s unlanded `OBL-GRAPH-LOCATION` says this ordering requires a digest-bound `(importer, request specifier/alias, exact imported principal)` map ([llp/0023-virtual-filesystem-namespace.spec.md:2067](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2067)). The current armed schema stores only graph nodes and `(importer, imported)` edges ([crates/capsec-semantics/src/arming.rs:550](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:550)). Consequently, current preflight reconstructs targets by package name and refuses multiple matching locators; `#` aliases are not mapped to an exact imported principal at that stage ([src/host/mod.rs:2570](/Users/ccheever/projects/ibex/src/host/mod.rs:2570), [src/host/mod.rs:2582](/Users/ccheever/projects/ibex/src/host/mod.rs:2582)). Phase 1 names `OBL-SOURCE-ID`, provenance, module identity, and resolve-gate correction, but not `OBL-GRAPH-LOCATION` ([LLP 0026 §Phase 1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:832)).

   **Resolution criterion:** Make `OBL-GRAPH-LOCATION` a Phase 1 prerequisite or co-implementation. Define and digest-bind the lookup key, including authenticated requester, authored spelling or alias, `ResolutionKind`, relevant conditions/attributes, and exact target principal. Require every artifact edge to verify against that map before any ambient resolver operation, with ambiguous-name, conditional-export, and `#`-alias non-disclosure fixtures.

4. **A shared module evaluation has no deterministic CapSec-context algebra or adequate async carrier.**

   **Severity:** Material

   **Evidence:** Records are keyed independently of request context, and one evaluation promise is shared by every importer ([LLP 0026 §Terminology](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:172), [LLP 0026 §5](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:501)). At the same time, every graph operation and continuation is said to retain requesting record, effect owner, scheduling identity, and the complete constrained-principal set ([LLP 0026 §4](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:443)). LLP 0021 requires every nontransparent dimension to allow and says dimensions intersect rather than union ([llp/0021-capsec-effect-model-migration.plan.md:368](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:368)); the semantic model separately represents actor, effect owner, and canonical constrained set ([crates/capsec-semantics/src/model.rs:1473](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1473)).

   The RFC does not define what happens when A and C concurrently import an unevaluated B under different constrained contexts. First-request-wins makes initialization authority race-dependent; union is unsound; intersecting current waiters cannot account for future importers; keying by context breaks singleton module identity.

   The current Hermes job patch cannot carry the promised structure: it stores one `uint32_t` scheduler principal per Promise job and explicitly notes that a further async hop loses the original caller ([patches/hermes/0008-schedule-time-principal-capture.patch:18](/Users/ccheever/projects/ibex/patches/hermes/0008-schedule-time-principal-capture.patch:18), [patches/hermes/0008-schedule-time-principal-capture.patch:43](/Users/ccheever/projects/ibex/patches/hermes/0008-schedule-time-principal-capture.patch:43), [patches/hermes/0008-schedule-time-principal-capture.patch:139](/Users/ccheever/projects/ibex/patches/hermes/0008-schedule-time-principal-capture.patch:139)).

   **Resolution criterion:** Define context separately for edge authorization, source reads, one-time factory evaluation, each continuation, and each waiter. Specify deterministic behavior for concurrent cold imports, cached success/error, TLA resumption, CJS re-entry, and HMR. Define an opaque native context token with runtime-nonce and generation validation, nesting, ownership, capture/restore rules, teardown behavior, and transport through Hermes jobs and host queues. Add race fixtures in which requester, module actor, and scheduler have distinct grants.

5. **The canonical artifact and `SourceLabel` rules are internally inconsistent.**

   **Severity:** Material

   **Evidence:** `source_label` appears inside `ModuleArtifact` ([LLP 0026 §2](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:297)). The same section requires one canonical byte encoding per logical artifact and says every field is either digest-covered or derived from covered data, with “no third category” ([LLP 0026 §2](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:322)). It later calls `source_label` a machine-local, nondigest, nonidentity display hint remapped by the consumer ([LLP 0026 §2](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:355)). That is presently a third category, and different labels can produce different serialized artifacts with the same semantic digest. Digest-covered source maps may independently embed those machine-local labels.

   LLP 0023 correctly distinguishes portable authenticated `SourceId` from machine-local `SourceLabel` used in source maps and diagnostics ([llp/0023-virtual-filesystem-namespace.spec.md:758](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:758)).

   **Resolution criterion:** Define two explicit types: a canonical, digest-covered portable artifact core and a local diagnostic envelope derived from authenticated runtime source records. Remove `source_label` from the portable wire or make its derivation canonical and covered. Define source-map source entries in terms of stable `SourceId` indices plus a local remapping table, and add same-digest/different-label rejection and cross-machine round-trip fixtures.

6. **The “loader state stays closed” premise is false in shipped code, and migration work is missing.**

   **Severity:** Material

   **Evidence:** The RFC says `require.cache` and sibling state “stay closed per LLP 0022” ([LLP 0026 §7](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:621)); LLP 0022 itself says these surfaces are closed today ([llp/0022-repl-behavior-and-semantics.spec.md:243](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:243)).

   In reality, local requires expose the live cache and main record ([module-loader.js:5485](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5485)); global `require` exposes `cache` and `main` ([module-loader.js:5841](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5841), [module-loader.js:5868](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5868)); `__exactRequire` exposes them too ([module-loader.js:5882](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5882)); and `module.createRequire()` copies them ([src/builtins/module.js:68](/Users/ccheever/projects/ibex/src/builtins/module.js:68)). Trusted bootstrap code also mutates `__exactRequire.cache` ([exact-global.js:2827](/Users/ccheever/projects/ibex/src/engine/bootstrap/exact-global.js:2827)).

   **Resolution criterion:** Correct the current-state claims in LLPs 0022 and 0026. Name closure as an intentional compatibility and security change, assign it to a migration phase, replace trusted cache mutation with a private typed invalidation operation, and add reachability tests covering local/global/createRequire/legacy surfaces in every runtime mode.

7. **Synchronous `require()` over an overlapping asynchronous graph is still undefined.**

   **Severity:** Material

   **Evidence:** The RFC defines deterministic failure when `require()` directly reaches a record already loading, linking, or evaluating asynchronously ([LLP 0026 §6](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:564)). It also promises preflight refusal before executing any module in a newly selected asynchronous target graph ([LLP 0026 §7](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:598)). Open question 13 acknowledges that overlapping—but not directly identical—subgraphs are not covered and even leaves thread ownership unresolved ([LLP 0026 §Open questions](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1059)).

   This is a central evaluator state transition, not optional polish. An incorrect answer can deadlock, re-enter execution, return a partially initialized namespace, or violate the no-partial-target-execution guarantee.

   **Resolution criterion:** Specify the complete transition matrix for synchronous drive versus every overlapping record/SCC state, including thread ownership, lock ordering, async-taint proof timing, and error selection. Define whether any new synchronous records may be linked before overlap is detected and what state survives refusal. Add direct, transitive, cyclic, and disjoint-overlap interleaving fixtures.

8. **The Phase 0 “zero parse” performance baseline is overstated.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The RFC says ordinary ESM is currently served verbatim with zero parse ([LLP 0026 §Phase 0](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:818)). It is served unchanged by the Rust transform layer, but it is subsequently scanned by the bootstrap transformer and parsed by Hermes as a generated function; prepared entries are also Rolldown-parsed. The code supports “zero Rust AST transform,” not “zero parse” ([src/module_loader/mod.rs:354](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:354), [module-loader.js:4224](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4224)).

   **Resolution criterion:** Change the wording to “zero Rust AST parse/transform before bootstrap” and baseline direct-source, SWC-lowered, scanner-lowered, and prepared paths separately.

9. **`SourceId` and module identity are occasionally conflated.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The RFC correctly defines `ModuleKey` as `(runtime identity, SourceId)` but later calls `SourceId` alone “the immutable module identity” ([LLP 0026 §Terminology](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:172)). LLP 0023 calls `SourceId` source identity and reserves `(runtime, SourceId)` for module identity ([llp/0023-virtual-filesystem-namespace.spec.md:676](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:676), [llp/0023-virtual-filesystem-namespace.spec.md:698](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:698)).

   **Resolution criterion:** Use `SourceId` consistently for authenticated source identity, `ModuleKey` for module identity, and `(ModuleKey, execution generation)` for an incarnation.

10. **Runtime import attributes and build-only authority annotations need separate types.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The RFC includes import attributes in edge/link identity ([LLP 0026 §1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:285), [LLP 0026 §2](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:365)). LLP 0014 requires `authorities` and legacy grant forms to be consumed into generated policy and stripped before execution ([llp/0014-import-site-grants-and-generated-policy.spec.md:228](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:228)). The RFC’s direct-file refusal is safe, but it does not explicitly say that prepared `ModuleArtifact.static_edges` cannot carry reserved authority annotations into the runtime graph ([LLP 0026 §7](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:628)).

   **Resolution criterion:** Define distinct `RuntimeImportAttributes` and `BuildPolicyAnnotations` types. The latter must be consumed and stripped before artifact emission, with its effect represented only in the digest-bound armed policy; runtime artifact validation should reject any reserved policy key.

## 4. Cross-document findings

- LLP 0026 is the correct document boundary for the fork LLP 0007 deliberately left open. LLP 0007 assigns transform convergence to Oxc/Rolldown but calls for a separate ModuleRunner design if file-at-a-time lowering cannot meet the runtime contract ([llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:31](/Users/ccheever/projects/ibex/llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:31)). LLP 0026 cleanly owns graph/link/evaluation semantics while retaining LLP 0007 as transform authority.

- Its treatment of LLP 0009 and LLP 0019 is coherent. LLP 0009 keeps SWC as the accepted current implementation until a compatible replacement or ModuleRunner redesign exists ([llp/0009-runtime-transform-candidate-scope.decision.md:13](/Users/ccheever/projects/ibex/llp/0009-runtime-transform-candidate-scope.decision.md:13), [llp/0009-runtime-transform-candidate-scope.decision.md:57](/Users/ccheever/projects/ibex/llp/0009-runtime-transform-candidate-scope.decision.md:57)). LLP 0019 currently permits only build-time AST transformation and the embedded scanner tier; LLP 0026 correctly treats a Rust/Oxc tier as an amendment rather than an implicit exception ([llp/0019-hermes-compat-transform-authority.decision.md:10](/Users/ccheever/projects/ibex/llp/0019-hermes-compat-transform-authority.decision.md:10), [LLP 0026 §3](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:395)).

- The proposed retirement of LLP 0024’s dependency-TLA refusal and delete-on-failure cache rule is properly scoped to consumers that adopt the graph. LLP 0024 currently specifies entry-only TLA and treats a general async graph as separate work; it also currently deletes failed cache entries ([llp/0024-structured-evaluation-and-session.spec.md:472](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:472), [llp/0024-structured-evaluation-and-session.spec.md:517](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:517), [llp/0024-structured-evaluation-and-session.spec.md:1656](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1656)). LLP 0026 explicitly schedules both amendments rather than silently superseding them.

- The per-principal carrier rule is a clean seam with LLP 0013. LLP 0013 explains that one HBC file maps to one Hermes `RuntimeModule`, so frame attribution requires per-package units or a trustworthy function-range table ([llp/0013-per-package-capability-compartments.rfc.md:328](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:328)). LLP 0026’s per-principal multi-module carrier constraint preserves that invariant.

- LLP 0023’s `OBL-RESOLVE-GATE` current-state prose has drifted: it describes the resolver’s source-reading branch as live, while the code and LLP 0026 correctly identify it as dormant because module-type detection is disabled ([src/module_loader/mod.rs:3848](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:3848), [LLP 0026 §1](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:261)). The planned ledger correction is warranted.

- LLP 0023’s claim that the host is only process-global is now partially stale. A legacy global remains, but the code also has a host-context registry, thread-bound creation handoff, active-context selection, and explicit claim/enter/restore/release operations ([src/host/abi.rs:151](/Users/ccheever/projects/ibex/src/host/abi.rs:151), [src/host/abi.rs:327](/Users/ccheever/projects/ibex/src/host/abi.rs:327), [src/host/abi.rs:427](/Users/ccheever/projects/ibex/src/host/abi.rs:427), [src/host/abi.rs:498](/Users/ccheever/projects/ibex/src/host/abi.rs:498)). Reconciliation should distinguish what remains missing from what has already landed.

- LLP 0023 deliberately makes query/fragment variants share one file-backed `SourceId`, unlike Node ESM ([llp/0023-virtual-filesystem-namespace.spec.md:796](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:796)). Because LLP 0026 adopts Node as its general oracle, that divergence must be imported explicitly into the module-runner expected-divergence corpus.

## 5. Suggestions

- Build a small executable state-machine model before implementing the evaluator. Generate tiny graphs containing cycles, star exports, TLA, CJS re-entry, and concurrent imports; explore scheduler interleavings and compare observable traces with Node. This is more likely to expose record-state defects than example-by-example tests.

- Extend the differential oracle from final values to semantic traces: record resolution choice, link order, cell initialization/update, TDZ reads, SCC transitions, promise settlement, actor/owner context, and emitted effects. Source, runtime-transformed, prepared, and HBC carriers should produce equivalent normalized traces.

- Consider a digest-covered “link certificate” containing resolved export tables, SCC condensation, and async-taint facts. The runtime must verify rather than blindly trust it, but such a certificate could make prepared startup faster and give synchronous `require(ESM)` an auditable proof object.

- Keep the native-Hermes ESM prototype proposed in open question 10 small and parallel. Even if it is not adopted, it can serve as a second implementation against the same artifact corpus and reveal assumptions accidentally specific to the `System.register` lowering.

- Add explicit resource budgets for graph records, namespace/cell counts, retained generations, source maps, and pending async parents. Exercise limits with adversarial deep graphs and wide star-export fans.

- Treat package HMR and first-party HMR separately. Package principals are integrity-bound, so package-source changes should normally require rearming and a new runtime; mutable first-party root source may support generation-only invalidation.

## 6. Open questions

1. What exact parser/classifier sequence reproduces Node’s ambiguous `.js` rule without reintroducing authoritative scanners, and which parts can truly be parse-once?

2. What are the complete ordered condition sets for static import, dynamic import, `require`, and entry resolution, including `module-sync` and custom conditions?

3. Whose actor, effect owner, and constrained-principal set governs a module’s one-time evaluation when multiple callers race to instantiate it?

4. What opaque carrier preserves the complete `GraphEvaluationContext` across Promise jobs, TLA resumptions, timers, native completions, nested hops, teardown, and worker boundaries?

5. What exact authenticated graph-location key authorizes aliases and conditional exports before probing, and how is it bound into the armed snapshot?

6. Is Node 24 interop normative for `'module.exports'`, `__esModule`, namespace descriptors, and `require(ESM)` return selection, or are any of those intentional Ibex divergences?

7. What is the complete state transition and error rule for synchronous `require()` overlapping an already-evaluating async SCC?

8. Is `SourceLabel` absent from the portable artifact core, or can it be canonically derived? How do source maps refer to sources before machine-local remapping?

9. Which existing `require.cache`, `require.main`, `createRequire`, and trusted invalidation uses must be migrated before closure can be claimed?

10. What is the exact transaction boundary for HMR during TLA, and which source kinds can change without invalidating the immutable authority snapshot?

## 7. Readiness verdict

The architecture should continue, and the bounded producer spike is an excellent acceptance gate. The current revision nevertheless leaves material correctness, security, integrity, compatibility, and evaluator-state questions unresolved. The RFC should be revised to close those contracts before it is accepted or implementation proceeds beyond spike scope.

VERDICT: NOT READY
---

## Round 5 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f6597-27e4-7e41-bc9d-b98b7047fe62`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `00abb645d5a7`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`. The review
  cites one public nodejs.org documentation URL.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-5 review of the same revision and no access to any
  prior LLP 0026 review artifact — rounds 1–4 artifacts were kept out of
  `llp/reviews/` in a scratch stash for the duration of the round. Instructed
  not to read `llp/reviews/`.
- **Method:** cli-runner, round-5 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round5.md`) — the round-4 brief
  updated to the new revision hash; same brief as the Fable round-5 reviewer.
- **Orchestrator disposition note (outside the verbatim body):** Concerns 2–9
  were accepted and addressed in the round-5 revision. Concern 1's resolution
  criterion ("complete and incorporate the required real-Hermes spike") was
  **rejected in part** with this rationale: the spike is executed engineering
  work that a Draft RFC cannot contain; the document already makes the spike a
  hard precondition of `Accepted` (Adoption gate), and `/llp-super-refine`
  advances a document only to `Review` — the status under which the spike is
  performed. The revision instead tightened what the document *can* do: it
  decides binding-cell ownership (Hermes-side cells behind opaque
  nonce-validated native handles), specifies stale-handle and reclamation
  rules, and enumerates the spike's required proof list including the items
  this concern named (namespace descriptors, mixed cycles, generation
  teardown, owner-thread destruction, source-map composition).

### Verbatim review

## 1. Overall assessment

LLP 0026 is directionally strong and addresses the right architectural problem. The current ESM compatibility layer is a large parser-like string transformer over a synchronous CommonJS loader; a real authenticated module graph is the appropriate way to obtain live bindings, cyclic instantiation, namespace semantics, and dependency-level top-level `await` on Hermes.

The requested revision matches digest `00abb645d5a7`. Its code observations are mostly accurate, its security posture is substantially better than a conventional JavaScript-owned module runner, and its staged migration is unusually thoughtful.

It is not ready for acceptance, however. Core feasibility is intentionally still unproved, and the document has unresolved material contradictions in module-initialization authority, artifact identity, Node condition resolution, CapSec registry migration, session-transform retirement, failure caching, and mixed ESM/CommonJS cycles. These are repairable; they argue for another revision, not for abandoning the design.

## 2. Strengths

- The diagnosis of the current loader is accurate, with one important boundary the RFC mostly conveys correctly: ordinary `.js`/`.mjs` source passes through the Rust transform stage unchanged unless a narrow downlevel scanner fires, but it is subsequently rewritten by the bootstrap scanner. `needs_transpile` covers only TypeScript/JSX-like extensions, while `needs_js_downlevel` covers selected syntax ([RFC §Motivation:58-65](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:58); [src/module_loader/mod.rs:354-388](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:354)). The dormant ESM-prefetch branch and its disabled-by-default module-type detection are explicitly documented in code ([src/module_loader/mod.rs:907-945](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:907); [src/module_loader/mod.rs:3848-3854](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:3848)).

- The scanner fragility is not exaggerated. `transformEsmToCjs` spans roughly 842 lines, above several hundred lines of lexical, delimiter, regex, template, and dynamic-import scanning ([RFC §Motivation:56-79](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:56); [src/engine/bootstrap/module-loader.js:3743-4223](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3743); [src/engine/bootstrap/module-loader.js:4224-5065](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4224)). Its lowered imports and exports copy values rather than implementing general live bindings ([src/engine/bootstrap/module-loader.js:4594-4616](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4594); [src/engine/bootstrap/module-loader.js:4868-4900](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4868); [src/engine/bootstrap/module-loader.js:5031-5047](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5031)).

- The RFC characterizes current execution semantics fairly. Modules compile as synchronous `new Function(require, module, exports, ...)` bodies, with cache publication before invocation, so ordinary CommonJS partial-export cycles do work ([src/engine/bootstrap/module-loader.js:235-273](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:235); [src/engine/bootstrap/module-loader.js:5340-5365](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5340); [src/engine/bootstrap/module-loader.js:5500-5507](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5500)). What is missing is ESM declaration instantiation and graph linking. The RFC also correctly acknowledges that SWC’s getter-backed lowering preserves some ordinary cases rather than claiming that nothing works ([RFC §Alternatives:1051-1059](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1051)).

- The dependency-TLA defect is exactly as described. The bootstrap emits a fire-and-forget async IIFE, ignores the body return value, can deliberately re-run a prefix, and marks the module loaded synchronously ([RFC §Motivation:98-112](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:98); [src/engine/bootstrap/module-loader.js:5415-5417](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5415); [src/engine/bootstrap/module-loader.js:5677-5695](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5677); [src/engine/bootstrap/module-loader.js:5797-5798](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5797)). Entry TLA really does use separate awaited CLI/native machinery ([src/bin/ibex/runtime.rs:1627-1735](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1627); [src/engine/hermes_runtime.cc:4026-4134](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:4026)).

- The toolchain account is honest. SWC is present and is the default in-process TypeScript/JSX/CommonJS transform ([Cargo.toml:98-106](/Users/ccheever/projects/ibex/Cargo.toml:98); [src/module_loader/transpile.rs:38-100](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:38)). Oxc parser, AST, codegen, transformer, and resolver crates are already dependencies ([Cargo.toml:44-53](/Users/ccheever/projects/ibex/Cargo.toml:44)), but the transform path is only an opt-in candidate and currently rejects TLA and residual general ESM ([src/module_loader/transpile.rs:199-265](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:199)). The RFC correctly treats the proposed factory producer as new work rather than crediting today’s Oxc dependency with capabilities it lacks.

- The proposed `ModuleKey = (runtime, SourceId)` and single placement of the defining principal match LLP 0023 exactly ([RFC §Terminology:168-181](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:168); [LLP 0023 §2.3:676-710](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:676)). Those types do not exist in code yet—the current cache remains path/string keyed ([src/engine/bootstrap/module-loader.js:5297-5305](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5297))—so Phase 1’s refusal to introduce an interim path-keyed graph is a good gate ([RFC Phase 1:939-948](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:939)).

- There is credible substrate for runtime-local identity and attribution. Hermes runtimes already carry a nonce, callback targets validate pointer plus nonce, and compile-time principal stamping occurs before `new Function` ([src/engine/hermes_runtime_internal.h:124-138](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_internal.h:124); [src/engine/hermes_runtime.cc:893-923](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:893); [src/engine/bootstrap/module-loader.js:235-272](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:235)). The per-principal HBC carrier restriction also follows Hermes’s present attribution granularity instead of pretending a manifest alone can restore frame identity ([RFC §9:779-796](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:779); [LLP 0013:317-337](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:317)).

- The migration discipline is strong: real-Hermes tests, fail-on-zero corpus execution, no production dual execution of side effects, source/prepared equivalence, explicit performance gates, and pre-execution-only bytecode fallback are all appropriate ([RFC §Compatibility corpus:842-886](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:842); [RFC Phases 0-5:917-1016](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:917); [LLP 0005:117-125](/Users/ccheever/projects/ibex/llp/0005-build-pipeline-and-hermetic-default.explainer.md:117); [LLP 0018:117-135](/Users/ccheever/projects/ibex/llp/0018-agent-tooling-fail-loud.plan.md:117)).

## 3. Concerns

1. **The central producer and runner ABI remain unproved.**

   **Severity:** Material

   **Evidence:** Neither Oxc nor Rolldown emits the proposed factory ABI; the intended producer is a new Ibex-authored lowering responsible for TDZ, live updates, cycles, TLA, dynamic import, Hermes compatibility, and composed maps ([RFC §3:413-453](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:413)). Binding-cell ownership is still open, while the ownership section asserts cross-heap cycles are unrepresentable without defining stale-handle and retained-export lifetimes ([RFC §4:471-547](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:471); [RFC Risks:1099-1104](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1099); [RFC Open question 2:1148-1151](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1148)). The RFC itself requires a real-Hermes spike before acceptance ([RFC Adoption gate:903-908](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:903)); current Oxc code cannot yet lower general ESM or TLA ([src/module_loader/transpile.rs:199-265](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:199)).

   **Resolution criterion:** Complete and incorporate the required pinned-toolchain, real-Hermes spike. It should additionally prove namespace descriptors/immutability, mixed ESM/CommonJS cycles, retained closures and namespaces across generation teardown, stale opaque-handle behavior, owner-thread JSI destruction, and source-map composition. Close enough of the cell/record ownership design to make the ABI and reclamation rules reviewable.

2. **Record initialization has contradictory authority semantics.**

   **Severity:** Material

   **Evidence:** The RFC first says source-read effects use the complete requesting/live/scheduling constrained-principal set ([RFC §4:484-499](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:484)), then says the same source reads, factory execution, and continuations use a requester-independent record task and that importer context governs only its edge and waiter ([RFC §4:504-512](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:504)). LLP 0021 requires live frames plus authenticated schedule/owner identities to intersect ([LLP 0021:368-378](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:368); [LLP 0021:1102-1112](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:1102)). The conflict is concrete for CJS: `localRequire` enters the dependency synchronously while the importer frame remains live ([src/engine/bootstrap/module-loader.js:5435-5454](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5435); [src/engine/bootstrap/module-loader.js:5500-5507](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5500)). Dropping that frame weakens deputy intersection; retaining it makes cold initialization requester-dependent.

   **Resolution criterion:** Normatively choose whether module initialization is an exception to causal principal intersection. If record-owned initialization is intended, amend LLP 0021, justify the threat-model change, define a native task-boundary/stack-stop mechanism for synchronous CJS, and specify cold/warm behavior. If full intersection remains, define deterministic first-import and concurrent-importer semantics. Add CJS, static ESM, dynamic import, cold/warm, and concurrent-distinct-importer fixtures.

3. **The plan omits the generated CapSec surface-registry and target-cell migration.**

   **Severity:** Material

   **Evidence:** The runner introduces new native loader, edge-gate, artifact, cache, carrier, compile-factory, and asynchronous callback surfaces ([RFC §4:464-502](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:464)), but the phases mention only metadata verification and effect-trace comparison ([RFC Phase 1-2:957-981](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:957)). LLP 0021 requires every authority-bearing loader/native/callback surface to have generated coverage edges and target cells, with missing cells refusing arming ([LLP 0021:132-180](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:132); [LLP 0021:1505-1520](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:1505)). The existing registry already inventories current CJS, ESM, dynamic-import, resolution, and source-read operations ([capsec/generated/surface-inventory.md:3675-3690](/Users/ccheever/projects/ibex/capsec/generated/surface-inventory.md:3675); [capsec/generated/surface-inventory.md:3884-3907](/Users/ccheever/projects/ibex/capsec/generated/surface-inventory.md:3884)).

   Source-read ownership also needs clarification: today module source reads use a trusted `module-loader` principal after the import gate ([src/host/capability.rs:699-706](/Users/ccheever/projects/ibex/src/host/capability.rs:699); [LLP 0021:1163-1169](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:1163)), whereas the RFC appears to charge the read to the complete requester set. Taken literally, that could require importers to hold raw filesystem authority over dependencies.

   Finally, “every advertised target” is presently vacuous because the authoritative target list is empty ([capsec/registry/policy-rules.json:788-795](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:788)).

   **Resolution criterion:** Add a migration gate that enumerates new, changed, and retired surfaces; regenerates coverage/implementation manifests and registry digests; starts new target cells unsupported; defines source-read effect owner and constrained principals; and requires allow/deny/wrong-principal/missing-attribution/cache-hit/prepared-carrier fixtures. Require at least one report-derived advertised target before the default-switch and per-target criteria can pass.

4. **“One logical artifact” conflicts with the canonical digest schema.**

   **Severity:** Material

   **Evidence:** The design says raw source, cache entries, chunks, and HBC are physical encodings of the same logical `ModuleArtifact` ([RFC Design principles:232-236](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:232)). But `factory_source | carrier_entry_ref` is a semantic field, and the canonical digest covers the exact selected source bytes or carrier reference ([RFC §2:320-366](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:320)). An inline factory and the same factory inside a carrier therefore have different canonical values and digests. That leaves cache equivalence, provenance identity, and “same artifact” assertions ambiguous.

   **Resolution criterion:** Either split the model into a carrier-independent canonical `ModuleDescriptor`/semantic digest plus a separately authenticated executable-payload binding, or explicitly define source and carrier forms as distinct artifacts for one `SourceId`. Then revise the equivalence, cache-key, manifest, and acceptance language consistently and rule out any carrier/artifact digest cycle.

5. **The normative condition model does not match Node resolution.**

   **Severity:** Material

   **Evidence:** The RFC defines ordered condition vectors such as `node, import, default`, with user conditions “spliced” into the order ([RFC §1:278-305](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:278)). Node selects conditional-export branches in package-object key order; conditions are membership tests, while `default` is unconditional. Treating the RFC vector as precedence changes resolution for objects such as `{ "default": ..., "import": ... }`, which can change both executed code and defining principal. This is documented in the [Node 24 packages documentation](https://nodejs.org/download/release/v24.0.1/docs/api/packages.html#conditional-exports). The current resolver does use one merged condition-name list, illustrating why the replacement must state the distinction precisely ([src/module_loader/mod.rs:105-135](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:105)).

   **Resolution criterion:** Define `ResolutionKind` as selecting a condition membership set; preserve package-object key order; treat `default` as unconditional; canonicalize cache identity by the set rather than an invented precedence order; and specify `node-addons`, `module-sync`, and user-condition membership for the pinned release. Add reversed-key-order and nested-condition oracle fixtures.

6. **The SWC retirement end state overlooks LLP 0024’s transform role.**

   **Severity:** Material

   **Evidence:** LLP 0026 reduces LLP 0024’s SWC dependency to a parser-equivalence gate and says any residual SWC dependency will be parser-only ([RFC §3:455-462](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:455); [RFC Phase 5:1012-1014](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1012); [RFC AC 11:1135-1137](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1135)). LLP 0024 also extends the SWC-based in-process lowering stage for script-goal preservation, TypeScript/JSX, import/TLA/session lowering, hygiene, and composed maps ([LLP 0024:668-731](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:668); [LLP 0024:2204-2207](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2204)). LLP 0026 explicitly excludes session lexical semantics and contains no migration for those transforms.

   **Resolution criterion:** Add a separate Oxc session-lowering migration with LLP 0024’s source-goal, completion, session, hygiene, and source-map corpus as its gate, or allow SWC to retain a bounded session-transform role and narrow the parser-only acceptance criterion.

7. **Failure caching and session generations do not yet form a coherent lifecycle.**

   **Severity:** Material

   **Evidence:** The RFC correctly caches ESM failure within a generation and says session retry is preserved through a new generation ([RFC §5:577-584](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:577)). It nevertheless defers the generation dimension until Phase 4 and supports exactly one generation beforehand, while allowing LLP 0024 failure-cache reconciliation in Phases 2-3 ([RFC §8:742-755](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:742); [RFC Adoption gate:910-913](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:910)). LLP 0024 currently deletes only the failing module and preserves its completed dependencies, enabling ordinary retry after editing ([LLP 0024 §7.9:1656-1662](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1656)). A fresh coherent generation may instead replay those dependencies; cross-generation reuse would need its own rules. The CommonJS section also omits delete-on-throw, which the current loader implements ([src/engine/bootstrap/module-loader.js:5764-5766](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5764)).

   **Resolution criterion:** Specify ESM error caching, CommonJS/JSON failure eviction, the exact session retry/invalidation transaction, whether successful dependencies are reused or replayed, and late completion/source-map behavior. Require generation support before any session adopts cached ESM failures, or explicitly revise away the present retry guarantee.

8. **Synchronous mixed ESM/CommonJS cycles are unspecified.**

   **Severity:** Material

   **Evidence:** The RFC specifies `require()` encountering `loading`, `linking`, or `evaluating` records only when they belong to an in-flight asynchronous operation ([RFC §6:624-638](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:624)). It separately permits ESM importing CJS and CJS synchronously requiring ESM ([RFC §7:647-699](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:647)), but does not define ESM → CJS → currently-linking/evaluating ESM, or re-entry through Ibex’s `require`-inside-ESM extension. Current CJS cycles work through early cache publication, so the migration needs an explicit mixed-cycle rule rather than a generic “require cycles” corpus label.

   **Resolution criterion:** Define the direct and transitive mixed-cycle algorithm or stable error family, record-state transitions, namespace visibility, and no-partial-effect scope. Add pinned Node-or-divergence fixtures for ESM→CJS→ESM, CJS→ESM→CJS, self-re-entry, and cycles containing TLA.

9. **The planned LLP 0019 amendment does not define the new authority relationship.**

   **Severity:** Material

   **Evidence:** LLP 0019’s accepted decision is one canonical AST implementation plus a constrained bootstrap scanner/mirror, not merely an arbitrary list of tiers ([LLP 0019:10-48](/Users/ccheever/projects/ibex/llp/0019-hermes-compat-transform-authority.decision.md:10)). LLP 0026 proposes a second complete AST implementation in Rust/Oxc and eventually leaves the JavaScript and Rust AST implementations together, but only says to “name the tier” and run the corpus ([RFC §3:437-447](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:437); [RFC Adoption gate:892-901](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:892)). Without a defined authority/mirror relationship, pass additions and bug fixes can drift between two nominal authorities.

   **Resolution criterion:** The LLP 0019 amendment must designate the canonical implementation and zero-divergence mirror, or replace implementation authority with an implementation-neutral executable pass specification. Define synchronization, accepted divergences, source-map parity, and real-Hermes gates.

10. **JSON format admission and `SourceId` terminology conflict.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The RFC says a “JSON `SourceId` arm” is reachable only through an attribute ([RFC §1:296-302](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:296)). LLP 0023 has no JSON-specific arm: a JSON file uses the same package/project file-backed `SourceId` as any other source, while format belongs in `source_kind` ([LLP 0023:698-710](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:698)). Attribute-only wording also conflicts with ordinary CommonJS `.json` loading, which the current resolver and loader support ([src/module_loader/mod.rs:923-927](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:923); [src/engine/bootstrap/module-loader.js:5375-5383](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5375)).

   **Resolution criterion:** Separate source identity from format admission. Require the JSON attribute for ESM where the pinned oracle does, retain extension-based CJS `require(.json)`, and state whether both routes share the same record/cache instance.

11. **The diagnostic generation claim is false as written.**

   **Severity:** Minor/Non-blocking

   **Evidence:** The RFC says an artifact digest is “therefore the generation that produced it” ([RFC §10:808-812](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:808)), but execution generation is deliberately record state and is absent from `ModuleArtifact`; identical transformed bytes may be reused across generations ([RFC §Terminology:178-181](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:178); [RFC §2:320-360](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:320)). The same section also cites LLP 0006 for structured error preservation, although LLP 0024 is the direct authority.

   **Resolution criterion:** Key maps by artifact digest plus the local `SourceId`→`SourceLabel` envelope; add record generation only where lifecycle diagnostics need it. Remove the claimed implication and point error preservation to LLP 0024.

## 4. Cross-document findings

- **Clean seam:** LLP 0026 directly answers the ModuleRunner fork LLP 0007 left open and respects LLP 0009’s “SWC until a later architecture decision” boundary ([LLP 0007:45-48](/Users/ccheever/projects/ibex/llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:45); [LLP 0009:63-73](/Users/ccheever/projects/ibex/llp/0009-runtime-transform-candidate-scope.decision.md:63)).

- **Clean seam:** LLP 0024 explicitly says honest dependency TLA requires an asynchronous linker/evaluator with live bindings, cycles, failure caching, and CJS interop; LLP 0026 is the missing design it requested ([LLP 0024:472-519](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:472)). Keeping entry/dependency role on the evaluation request rather than the artifact also matches LLP 0024.

- **Clean seam:** `ModuleKey = (runtime, SourceId)`, defining principal inside `SourceId`, carrier-independent source identity, and query/fragment unification align with LLP 0023. The RFC properly identifies `OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE`, and `OBL-GRAPH-LOCATION` as prerequisites rather than claiming they exist.

- **Clean seam:** No per-waiter import cancellation matches LLP 0025’s executing-unit cancellation model, and worker teardown remains the integrity boundary for abandoned suspended graphs ([LLP 0025:560-575](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:560); [RFC §6:612-622](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:612)).

- **Useful drift correction:** LLP 0022 says loader state is closed today, but `require.cache`, `require.main`, global require surfaces, and `module.createRequire()` remain exposed. LLP 0026 correctly treats closure as Phase 2 migration work ([LLP 0022:243-260](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:243); [RFC §7:704-719](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:704); [src/engine/bootstrap/module-loader.js:5841-5884](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5841)).

- **Useful drift correction:** LLP 0023’s `OBL-RESOLVE-GATE` describes the resolve-time body read as live, but code makes it dormant because module-type detection is disabled. LLP 0026’s “latent branch” correction is supported by code.

- **Remaining drift:** LLP 0004 calls scanner-selected JS “down-leveled,” while LLP 0007 and the transform code show the default SWC path does not apply the requested compatibility target. Correct this during Phase 0, not only at final retirement ([LLP 0004:75-87](/Users/ccheever/projects/ibex/llp/0004-module-loading-and-builtins.explainer.md:75); [LLP 0007:143-165](/Users/ccheever/projects/ibex/llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:143)).

- **Remaining drift:** LLP 0023 still describes runtime/session Host indexing as absent, while runtime-scoped Host contexts and pointer-plus-nonce teardown now exist. `SourceId` and the session-local module cache remain absent, so this is partial implementation drift that the phase-specific reconciliation should record.

- **Prepared-path seam:** LLP 0007 records a live Babel `--lower-classes` exception. The production artifact plan should either carry it as a fingerprinted temporary stage or explicitly gate its retirement ([LLP 0007:116-122](/Users/ccheever/projects/ibex/llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:116)).

- **Worker-locality seam:** LLP 0023 requires authority-bearing VFS identities to remain in the engine process, LLP 0024 keeps session handles there, and LLP 0025 puts Hermes in the worker. The RFC’s final topology question is therefore largely answered: graph records, native authority state, and Hermes handles should be worker-local; only authenticated non-authority outcomes and control records should cross.

## 5. Suggestions

- Model the security pipeline as Rust typestates, for example: `ResolvedCandidate → AuthenticatedSource<SourceId> → VerifiedArtifact → AttributedFactory → LinkedRecord`. This would make premature cache publication or compilation difficult to express.

- Make `GraphEvaluationContext` an affine native token carrying runtime nonce, claimed Host context, armed-snapshot digest, graph generation, actor, effect owner, and constrained-principal set. Distinct `fork_waiter` and `fork_record_task` operations would force the authority choice in Concern 2 to be explicit.

- Reuse the full-principal-vector carriers already present for host timers and callbacks. The current one-hop limitation is specifically in Hermes Promise jobs, not every host queue ([patches/hermes/0008-schedule-time-principal-capture.patch:18-48](/Users/ccheever/projects/ibex/patches/hermes/0008-schedule-time-principal-capture.patch:18)).

- Add an executable reference model of record states, SCC ordering, and failure caching. Generate transition traces from it and compare Node and Hermes, rather than relying only on output assertions.

- Differentially compare normalized CapSec effect traces for cold and warm loads. Cache hits otherwise make it easy for an initialization-attribution defect to disappear from the warm corpus.

- Fuzz the producer at the AST level using small cyclic graphs, export mutations, destructuring assignments, `typeof` on TDZ imports, star ambiguity, and TLA placement. Compare both observable values and record/security traces.

- Name digest-covered CJS detector output in the canonical artifact schema—detected export names, re-export hints, detector version, and failure behavior—rather than relying only on `transform_fingerprint`.

- For Rolldown production preparation, explicitly forbid scope hoisting or cross-module optimization that erases factory/record boundaries unless an optimization has a proof and corpus demonstrating preserved identity, attribution, and evaluation order.

## 6. Open questions

1. What exact producer and cell/record ownership design survives the real-Hermes spike?
2. Does a cold module initialize under its causal importer chain or under a new record-owned authority task, and why?
3. Is module source acquisition a trusted loader effect after exact edge authorization, or an ordinary filesystem effect constrained by importing principals?
4. What are the exact condition memberships for import, require, entry, `module-sync`, `node-addons`, and user conditions under Node 24.13.1?
5. Are carrier-bound and inline forms distinct artifacts, or two payload bindings of one carrier-independent descriptor?
6. What exact transaction gives an interactive session retry after ESM failure without unexpectedly replaying completed dependencies?
7. What are the specified results for synchronous ESM↔CJS re-entry cycles?
8. Which implementation is canonical for LLP 0019’s Hermes-compat passes, and how is the other kept synchronized?
9. When does the session transform migrate away from SWC, independently of module-runner adoption?
10. Which new CapSec registry surfaces and logical branches does the runner create, and what nonempty target matrix gates their reachability?
11. Are graph records and all authority-bearing handles unconditionally worker-local when sessions adopt the runner?
12. Which production optimizations may cross logical module boundaries without ceasing to implement the same record graph?

## 7. Readiness verdict

The proposal is a good architectural direction and should continue. Its current-loader analysis, identity model, staged authorization posture, per-principal carrier constraint, and test strategy are strong. It is not ready for acceptance at this revision because several core semantics and security boundaries remain contradictory or unproved, including items the RFC’s own adoption gate requires before acceptance.

VERDICT: NOT READY
---

## Round 6 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f65ad-8ac0-7482-88f2-986415da3eb5`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (`-c 'model_reasoning_effort="ultra"'`;
  confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `d6120aba94c3`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer ran read-only against the repository working
  tree, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  concurrent Fable round-6 review of the same revision and no access to any
  prior LLP 0026 review artifact — rounds 1–5 artifacts were kept out of
  `llp/reviews/` in a scratch stash for the duration of the round. Instructed
  not to read `llp/reviews/`.
- **Method:** cli-runner, round-6 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round6.md`) — the round-5 brief
  updated to the new revision hash; same brief as the Fable round-6 reviewer.
- **Orchestrator verification and disposition notes (outside the verbatim
  body):** Concern 2's registry contradiction was verified
  (`capsec/registry/coverage-edges.json:143729-143731` sources principal and
  effect owner from `loader-referrer`, while `src/host/capability.rs:699-706`
  trusts the synthetic loader principal). Concerns 1–4 and 6 were accepted and
  addressed in the round-6 revision. Concern 5 has two halves: the
  checked-reads-everywhere ABI correction was accepted (the "statically
  proven" elision clause was unsound for graph-independent artifacts and was
  removed); the "complete the spike before readiness" half carries the same
  disposition recorded for round 5's Concern 1 — the spike is executed work
  the document gates before `Accepted`, and `/llp-super-refine` advances only
  to `Review`, the status under which the spike is performed.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes the right architectural direction. The current ESM-to-CommonJS compatibility layer cannot provide standards-complete ESM semantics, and an authenticated graph with explicit module records, binding cells, linking, and asynchronous evaluation is the appropriate replacement. The Rust/Hermes ownership split and `ModuleArtifact` boundary are especially well conceived.

The migration plan is also unusually honest about toolchain limits, corpus requirements, and the need for a real-Hermes producer spike. However, this revision is not ready for adoption. Two capability-authority rules conflict with LLP 0021, project `SourceId` portability remains undefined, cross-generation record sharing conflicts with the generation and teardown algebra, and the normative factory ABI still depends on an unperformed spike. There is also one incorrect current-state claim about `require.resolve`.

## 2. Strengths

- The diagnosis of the current loader is accurate. LLP 0026 §“Motivation: the current fallback” (`llp/0026-esm-module-runner.rfc.md:56-112`) correctly says ordinary ESM-heavy JavaScript generally bypasses the Rust transform: only TS/TSX/JSX/MTS/CTS always transpile, while JS/MJS/CJS are selected by narrow content scanners (`src/module_loader/mod.rs:340-388`, `src/module_loader/mod.rs:390-422`). The resolver’s ESM prefetch branch exists (`src/module_loader/mod.rs:928-946`) but is dormant because `module_type` remains at its false default (`src/module_loader/mod.rs:105-135`, `src/module_loader/mod.rs:3848-3854`).

- The RFC fairly characterizes the bootstrap transformer as a fragile lexical reimplementation. Its scanner helpers occupy `src/engine/bootstrap/module-loader.js:3743-4089`, dynamic-import scanning continues through `:4090-4223`, and `transformEsmToCjs` itself spans `:4224-5065`. Named imports become copied locals (`:4601-4615`, `:4860-4865`), local exports are generally assigned once (`:5031-5047`), and star exports copy properties without ESM ambiguity semantics (`:4868-4877`). Comments record previous swallowed-code and dropped-binding bugs (`:3743-3749`, `:4361-4367`, `:4453-4458`).

- The current-semantics assessment is properly about complete ESM semantics. Modules are compiled as six-argument function bodies (`src/engine/bootstrap/module-loader.js:235-253`) and invoked synchronously (`:5497-5506`). The cache is published before execution, so ordinary CommonJS partial-export cycles do work (`:5297-5368`); the current path is therefore not cycle-free. It nevertheless lacks ESM graph instantiation, TDZ-correct imported bindings, complete live bindings, and standards cycle ordering. Dependency TLA is particularly unsound: the fallback creates a fire-and-forget async IIFE (`:5415-5417`), ignores the wrapper result (`:5500-5506`), and marks the record loaded immediately (`:5797-5798`). Entry TLA is a separate awaited path (`src/bin/ibex/runtime.rs:1627-1653`, `:1685-1735`, `:3901-3938`; `src/engine/hermes_runtime.cc:4026-4051`). LLP 0026 §§5–7 are therefore solving a real semantic gap.

- The `ModuleArtifact` design is disciplined. LLP 0026 §2 (`llp/0026-esm-module-runner.rfc.md:333-421`) separates semantic identity from physical carriers, digest-covers every semantic field, excludes machine-local `SourceLabel`, and rejects reserved policy metadata. Its nominal `ModuleKey = (runtime identity, SourceId)` agrees with LLP 0023, while the existing pointer-plus-nonce machinery supplies the intended runtime-identity class (`src/engine/hermes_runtime_internal.h:98-109`, `:124-128`; `src/engine/hermes_runtime.cc:884-906`, `:3517-3531`). The RFC correctly treats `SourceId` and `ModuleKey` themselves as new work: current `ResolvedModule` still carries a string `id`, path, source, and package metadata only (`src/module_loader/mod.rs:22-57`), and the JS cache remains path/string keyed (`src/engine/bootstrap/module-loader.js:5297-5305`).

- The resolution and attribution boundaries are sound in outline. LLP 0026 §§1 and 4 require authorization before probing or reading, authenticated record-derived principals, and compile-time—not merely invocation-time—factory attribution (`llp/0026-esm-module-runner.rfc.md:247-331`, `:495-534`). Current code already establishes useful substrate: package principal state is installed before `new Function` and compartment binding (`src/engine/bootstrap/module-loader.js:193-272`), native compilation consumes the pending principal (`src/engine/hermes_runtime.cc:2048-2082`), and armed resolution preflights requester/import policy before resolver probes (`src/host/mod.rs:2191-2272`, `:2554-2627`).

- The transform and migration discussion is evidence-based. SWC is genuinely the current default, with direct dependencies (`Cargo.toml:98-106`) and TS stripping, JSX, CommonJS lowering, helpers, hygiene, and code generation (`src/module_loader/transpile.rs:97-196`). Oxc is also already substantial (`Cargo.toml:44-53`) but its current candidate rejects TLA and general residual ESM (`src/module_loader/transpile.rs:199-264`, `:401-422`). LLP 0026 §3 and the adoption gate (`llp/0026-esm-module-runner.rfc.md:432-493`, `:978-996`) correctly avoid pretending that this wiring already produces the proposed ABI.

- The conformance strategy is appropriately behavioral and fail-loud. LLP 0026’s corpus covers ESM/CJS interop, cycles, namespaces, TLA, source maps, attribution, prepared carriers, and generation teardown (`llp/0026-esm-module-runner.rfc.md:929-974`). Requiring real Hermes and non-zero case counts matches LLP 0019’s existing dual-runner discipline and LLP 0018’s no-silent-green rule.

## 3. Concerns

1. **Async module initialization silently changes capability authority** — **Severity:** Material

   **Evidence:** LLP 0026 §4 first says every graph operation carries the complete LLP 0021 context (`llp/0026-esm-module-runner.rfc.md:507-531`). It then gives synchronous and asynchronous initialization different authority rules: synchronous initialization retains importer frames in the constrained intersection, while asynchronous ESM initialization becomes requester-independent and carries the record’s own schedule-time identity (`:536-552`).

   LLP 0021 instead requires live frames plus authenticated schedule-time and owner/deputy identities to form one conjunctive constrained set (`llp/0021-capsec-effect-model-migration.plan.md:368-378`). Its async rule preserves the complete schedule-time stack specifically so an async operation cannot shed an outer constrained scheduler (`:1102-1112`). The current Hermes patch also documents that the originating principal is lost after a deputy schedules another hop (`patches/hermes/0008-schedule-time-principal-capture.patch:18-48`).

   As written, module B can change an initialization effect from `A ∩ B` to `B` merely by inserting `await 0`. Cold versus warm loading, or which of two differently constrained importers wins a cold-load race, may likewise change authority.

   **Resolution criterion:** Choose one deterministic authority rule before adoption. Either carry the initiating constrained context through the complete graph evaluation and define concurrent-importer behavior, or define ESM initialization as deliberately autonomous record-owned execution and amend LLP 0021 accordingly. Apply the selected rule consistently across sync/async initialization and add fixtures for `await 0` insertion, cold/warm state, and concurrent importers with distinct grants.

2. **The source-acquisition policy selects one side of an unresolved authoritative corpus conflict** — **Severity:** Material

   **Evidence:** LLP 0026 calls capability-policy changes a non-goal (`llp/0026-esm-module-runner.rfc.md:149-160`) but defines source acquisition as a trusted-loader effect never charged to importer filesystem authority (`:536-542`) and directs Phase 2 to register it that way (`:1085-1091`). That agrees with LLP 0013’s trusted `module-loader` principal (`llp/0013-per-package-capability-compartments.rfc.md:1124-1141`), LLP 0021’s later shipped-state prose (`llp/0021-capsec-effect-model-migration.plan.md:1163-1169`), and current code (`src/host/capability.rs:699-706`; authenticated reads in `src/host/mod.rs:2107-2158`).

   However, LLP 0021 declares generated coverage edges authoritative for effects, principal source, and effect owner (`llp/0021-capsec-effect-model-migration.plan.md:132-167`). The generated CommonJS and dynamic-import rows classify on-disk loading as `fs:list` plus `fs:read`, with both principal and effect owner sourced from `loader-referrer` (`capsec/registry/coverage-edges.json:146817-147017`, `:147020-147063`). This is a security-semantic contradiction, not merely a renamed surface.

   **Resolution criterion:** Resolve the policy before acceptance and amend LLP 0021 plus its generated registry in the adoption set. If trusted-loader acquisition wins, define it as a narrow, non-delegable operation bound to an already-authorized exact edge, `SourceId`, binding, locator, and integrity—not as general loader filesystem authority. If loader-referrer effects win, `GraphEvaluationContext` must authorize those occurrences against the complete constrained set. In either case, revise the “non-goal” claim and add denial, no-probe, cache-hit, prepared-carrier, and wrong-principal fixtures.

3. **Portable project `SourceId` identity is still undefined** — **Severity:** Material

   **Evidence:** LLP 0023 defines module identity as `(runtime, SourceId)` and the root arm as `(authenticated root identity, binding-relative path)` (`llp/0023-virtual-filesystem-namespace.spec.md:676-710`). It explicitly states that this root identity must be project-stable and host-independent; otherwise project `SourceId`s are session-local and the portability claim must be narrowed (`:723-729`).

   LLP 0026 places `source_id` in the portable artifact’s semantic digest and claims cross-machine artifact equivalence (`llp/0026-esm-module-runner.rfc.md:360-380`, `:406-414`), but Phase 1 only says to land LLP 0023’s constructor and encoding (`:1032-1050`). Current arming assigns every project the literal identity `"project-root"` (`src/bin/ibex/runtime.rs:2020-2033`). Runtime identity prevents live-record collision between runtimes, but it does not prevent two projects with the same relative path from receiving the same portable source provenance.

   **Resolution criterion:** Define and authenticate a stable project-identity derivation and its collision domain before artifact publication. If that cannot be done yet, explicitly scope project-arm `SourceId`s and artifacts to one project/session and prohibit portable cross-project cache reuse. Test two distinct authenticated project roots containing identical relative paths and bytes.

4. **Cross-generation record reuse conflicts with record identity and teardown** — **Severity:** Material

   **Evidence:** LLP 0026 defines a record incarnation as `(ModuleKey, execution generation)` (`llp/0026-esm-module-runner.rfc.md:178-181`), rejects generation-mismatched handles, and says generation teardown releases native handles to cells, namespaces, and factories (`:554-562`). Section 8 repeats that records, namespace objects, errors, and late completions are generation-keyed (`:823-836`).

   Section 5 nevertheless says unchanged-artifact “records may be structurally shared across generations” and completed dependencies are reused rather than replayed (`:641-646`). If this means sharing live `ModuleRecord`s, cells, namespaces, evaluation promises, or error objects, one object belongs to multiple generations and cannot be safely invalidated by one generation’s teardown. If only immutable `ModuleArtifact`s are shared, the phrase “records” and the promise to reuse completed dependencies are incorrect.

   **Resolution criterion:** For v1, either share immutable artifacts only and create distinct live records per generation, or specify multi-generation membership, reference counting, handle validation, namespace/error identity, and teardown semantics. If HMR is deferred, remove the live-record-sharing claim and keep exactly one generation. Cover retained namespaces, stateful dependencies, old-generation TLA settlement, and teardown while a newer generation remains live.

5. **The normative factory ABI remains unvalidated and partly underspecified** — **Severity:** Material

   **Evidence:** LLP 0026 §3 acknowledges that neither Oxc nor Rolldown emits the proposed factory ABI and that v1 requires a custom lowering (`llp/0026-esm-module-runner.rfc.md:434-442`). The current Oxc path rejects both TLA and general ESM (`src/module_loader/transpile.rs:211-217`, `:253-264`). Section 4 delegates normative lowering details to checked-in canonical factories that do not yet exist (`llp/0026-esm-module-runner.rfc.md:578-607`), including an optimization that emits unchecked plain reads wherever initialization is “statically proven” (`:590-593`). In a content-addressed, graph-independent artifact, whether an imported lexical binding is initialized can depend on the eventual cycle and evaluation order.

   The RFC correctly makes a real-Hermes producer spike an acceptance prerequisite (`:991-996`). Under the stated readiness standard, that means feasibility and the normative ABI are still unresolved rather than merely implementation work.

   **Resolution criterion:** Complete the bounded spike and check in the versioned wire schema plus representative generated factories running on real Hermes. The artifacts must demonstrate declaration hoisting, every assignment/update/destructuring form affecting live exports, TDZ in direct and indirect cycles, namespace descriptors and immutability, star ambiguity, async SCC settlement, TypeScript/JSX, Hermes compatibility, and composed maps. V1 should use checked cell reads everywhere unless a sound, reviewable proof for each elision is supplied.

6. **The claim that `require.resolve` bypasses the import gate entirely is incorrect** — **Severity:** Minor/Non-blocking

   **Evidence:** LLP 0026 §7 says today’s `require.resolve` bypasses the import gate entirely (`llp/0026-esm-module-runner.rfc.md:797-800`). The JavaScript closure does bypass the JavaScript `checkImportGate` helper (`src/engine/bootstrap/module-loader.js:5479-5481`), but it calls the native metadata bridge (`:5842-5863`). That bridge supplies `currentPrincipalId()` (`src/engine/hermes_runtime.cc:2697-2715`), and the armed host authenticates the requester and preflights import policy before resolver probing (`src/host/mod.rs:2191-2236`, `:2262-2272`, `:2582-2627`). It also has a distinct resolve-disclosure authorization stage (`:2241-2258`).

   **Resolution criterion:** Change the claim to say that `require.resolve` bypasses the JavaScript helper and does not yet use the proposed unified typed edge path, while the armed native metadata path already enforces requester-aware preflight. Correct LLP 0023’s matching stale ledger claim at the same time; retain Phase 2’s unification and non-disclosure work.

## 4. Cross-document findings

- **Transform authority is a clean seam.** LLP 0007 explicitly names a ModuleRunner redesign as the correct outcome if single-file lowering cannot satisfy the loader contract (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:45-48`, `:279-282`, `:421-426`). LLP 0009 keeps SWC only because the current Oxc candidate cannot handle general ESM/TLA under the synchronous loader (`llp/0009-runtime-transform-candidate-scope.decision.md:13-23`, `:39-65`). LLP 0026 correctly requires both decisions to be reconciled before implementation beyond spike scope.

- **The LLP 0019 seam is explicit and coherent.** LLP 0019 currently permits exactly two Hermes-compat tiers (`llp/0019-hermes-compat-transform-authority.decision.md:12-35`) and gates both through one real-engine corpus (`:79-97`). LLP 0026 correctly treats Rust/Oxc as a third-tier amendment during migration rather than silently claiming existing authority.

- **The nominal source-identity algebra is clean.** LLP 0026’s `(runtime, SourceId)` definition and single occurrence of the defining principal agree exactly with LLP 0023 (`llp/0023-virtual-filesystem-namespace.spec.md:655-710`). The unresolved project-root derivation in Concern 3 is the important exception.

- **Dependency TLA and session adoption form a good seam.** LLP 0024’s entry-only rule exists specifically because the synchronous loader lacks dependency ordering, live bindings, async cycles, error caching, and CJS interop (`llp/0024-structured-evaluation-and-session.spec.md:472-519`, `:2232-2235`). LLP 0026 supplies that missing design and delays retiring the restriction until a consumer adopts it. It also correctly stages standards ESM error caching against LLP 0024’s current delete-and-retry session behavior (`llp/0024-structured-evaluation-and-session.spec.md:1656-1661`).

- **Cancellation and worker locality are aligned.** LLP 0026’s rule that an interrupt does not deliver cancellation into a suspended TLA graph matches LLP 0025’s executing-only cancellation rule (`llp/0025-terminal-session-ownership.spec.md:553-575`). Keeping graph records and Hermes handles worker-local also matches LLP 0025’s supervisor/worker topology (`:806-820`).

- **Build and embedding seams are conservative.** The runner remains private pending LLP 0024’s structured ABI, and the prepared-bytecode fallback rule preserves LLP 0005’s prohibition on rerunning source after program execution has begun (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:107-125`).

- **Several current-state documents have drifted.** LLP 0004 says scanner-selected JS is “down-leveled” (`llp/0004-module-loading-and-builtins.explainer.md:75-87`), but the default SWC pipeline performs no target-compat pass (`src/module_loader/transpile.rs:109-196`). LLP 0022 says `require.cache` and `require.main` are closed (`llp/0022-repl-behavior-and-semantics.spec.md:243-260`), while the bootstrap still exposes them (`src/engine/bootstrap/module-loader.js:5479-5486`, `:5831-5890`). LLP 0023’s resolve-gate account overstates both the active ESM body-read branch and the absence of native `require.resolve` preflight (`llp/0023-virtual-filesystem-namespace.spec.md:1755-1772`, `:2067-2068`). LLP 0026 correctly identifies most of this drift, except for the “bypasses entirely” wording.

- **Corpus duplication remains a process risk.** The RFC explicitly relates its fixtures to LLP 0007’s corpus, but it should apply the same single-owner/import-or-reference rule to LLP 0019’s Hermes corpus and LLP 0024’s session/source-map corpus. One fixture definition with multiple runners is safer than copied cases that can diverge.

## 5. Suggestions

These are non-blocking improvements once the material concerns are resolved.

- Use separate Rust types and stores for immutable `ModuleArtifact`, linked-but-unevaluated state, and live generation-owned `ModuleRecord`. Making cross-generation record reuse a type error would reinforce the intended lifecycle.

- Start v1 with checked reads for all imported lexical bindings. Add unchecked-read specialization only after conformance and profiling show it matters.

- Add an executable graph-event trace: `Resolve`, `AuthorizeEdge`, `CreateRecord`, `CreateCell`, `Initialize`, `Execute`, `Suspend`, `Resume`, `Settle`, `Publish`, and `Teardown`. Differential traces would make cycle/TLA failures easier to diagnose than output-only fixtures.

- Model-check a small graph state machine over cycles, TLA, concurrent importers, `require(ESM)`, and generation invalidation. Exhaustive small graphs are likely to expose lifecycle combinations that hand-authored fixtures miss.

- Preserve the old scanner as a fuzzing oracle during migration. Feed parser-generated semicolonless, multiline, template, regex, and comment-heavy modules through both paths; every disagreement either becomes a named expected divergence or a regression fixture before retirement.

- Provide a privileged, redacted graph-explanation trace for diagnostics: which requester authorized an edge, which `SourceId` was selected, which artifact digest loaded, and why a denial occurred. It must be observational only and never become an authority token.

## 6. Open questions

1. Is ESM initialization constrained by the initiating importer, or is it autonomous record-owned execution? How is the answer invariant across sync/async, cold/warm, and concurrent importers?

2. Is module source acquisition a trusted-loader operation after edge authorization, or a loader-referrer `fs:list`/`fs:read` effect? Which LLP 0021 representation is authoritative?

3. What authenticated value supplies project-stable root identity, and what is the intended collision and portability domain for project-arm `SourceId`s?

4. Are unchanged dependencies re-instantiated per generation, or are live records shared? If shared, who owns their cells, namespaces, errors, promises, and teardown?

5. Which producer emits ABI v1, and where does the proof for eliding checked TDZ reads live when artifacts are graph-independent?

6. What exact LLP 0021 fields correspond to `GraphEvaluationContext.requesting_record`, `effect_owner`, schedule-time identity, and constrained principals? How are contexts combined for concurrent graph requests?

7. What exact namespace-object representation on Hermes preserves null prototype, property ordering, descriptors, non-extensibility, assignment/delete behavior, identity, and `Symbol.toStringTag`?

8. Which HMR behavior is actually in v1, and what transaction contract governs invalidation during TLA, retained namespaces, late rejection, and partially migrated importers?

## 7. Readiness verdict

The central proposal is a good idea, and most of the plan is strong. The current loader evidence supports replacing the scanner with a real authenticated module graph. Nevertheless, the async authority rule, source-acquisition policy conflict, unresolved project identity, generation-sharing ambiguity, and unvalidated factory ABI are material correctness, security, and feasibility issues. The RFC should remain in spike/revision scope until those are resolved; the `require.resolve` correction is minor and does not drive the verdict.

VERDICT: NOT READY
---

## Round 7 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f65d1-7836-7741-be3e-0975d27a7930`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `6f3be27b997e`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. Read-only against the repository working tree, authorized
  by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session; no access to the
  concurrent Fable round-7 review or any prior LLP 0026 artifact (rounds 1–6
  stashed outside `llp/reviews/` for the round). Instructed not to read
  `llp/reviews/`.
- **Method:** cli-runner, round-7 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round7.md`) — same brief as the
  Fable round-7 reviewer.
- **Orchestrator disposition note (outside the verbatim body):** Concerns 2–5
  and 6–8 were accepted and addressed in the round-7 revision (initialization
  authority became an explicit, digest-bound aspect of the import-edge grant
  with LLP 0014/0021 amendments added to the adoption gate; a normative TLA
  admission matrix replaced the contradictory §1 wording; the total
  `SourceId → principal` derivation and project-root constructor became
  Phase 1 acceptance prerequisites; the source-map registry became sum-keyed
  over module artifacts and session scripts; LLPs 0003/0005 joined the
  reconciliation set). Concern 1 (supply the spike) retains the standing
  disposition recorded in rounds 5–6: the spike is executed work gated before
  `Accepted`; `/llp-super-refine` advances only to `Review`.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes the right architectural direction. Replacing file-at-a-time ESM-to-CommonJS rewriting with authenticated module records, explicit linking, live binding cells, and asynchronous graph evaluation is well motivated. The load-bearing observations about the current implementation are largely accurate, and the proposed split between native identity/policy ownership and Hermes-side JavaScript semantics is sensible.

The RFC is not ready for acceptance at revision `6f3be27b997e`. Its own required producer spike is absent, and several central contracts remain contradictory or incomplete: dependency-TLA admission, initialization authority, portable `SourceId` identity, and session source-map identity. These are material correctness, feasibility, and security concerns rather than optional polish.

## 2. Strengths

- The current-state diagnosis in RFC §Motivation is accurate. Ordinary `.js`/`.mjs` source bypasses Rust transformation unless handwritten downlevel scans recognize a small set of constructs; import/export syntax is not itself a trigger (`src/module_loader/mod.rs:342-422`). Resolver module-type detection is disabled, unclassified files default to CommonJS, and the apparent ESM-prefetch branch is dormant (`src/module_loader/mod.rs:907-945,3848-3854`). This supports the RFC’s claim that ESM-heavy JavaScript can reach the bootstrap transformer verbatim.

- The characterization of `transformEsmToCjs` as parser/linker work implemented with string, delimiter, and regex scanning is fair. The transform occupies approximately 842 lines (`src/engine/bootstrap/module-loader.js:4224-5065`) on top of handwritten lexical machinery (`src/engine/bootstrap/module-loader.js:3743-4089`). Imports become local snapshots, exports are copied by assignment, and `export *` copies properties without live views or ambiguity resolution (`src/engine/bootstrap/module-loader.js:4594-4648,4791-4900,5031-5047`). RFC §§Motivation and 4 correctly identify the missing declaration-instantiation, TDZ, namespace, and async-SCC machinery.

- The RFC’s dependency-TLA defect report is exact. Modules are compiled as synchronous function bodies (`src/engine/bootstrap/module-loader.js:235-253,5500-5507`); the await fallback emits an unreturned async IIFE (`src/engine/bootstrap/module-loader.js:5415-5417`), can execute the prefix twice (`src/engine/bootstrap/module-loader.js:5680-5695,5747-5760`), and marks the record loaded immediately (`src/engine/bootstrap/module-loader.js:5797`). Dynamic import merely schedules the same synchronous loader (`src/engine/bootstrap/module-loader.js:6082-6149`). RFC §§Motivation and 6 are right that this is not an asynchronous module graph.

- RFC §3 accurately describes the current transform-toolchain boundary. SWC is present and is the default runtime transform engine (`Cargo.toml:98-106`; `src/module_loader/transpile.rs:41-78`), performing TypeScript stripping, JSX lowering, CommonJS module lowering, helpers, hygiene, and code generation (`src/module_loader/transpile.rs:109-196`). Oxc parser, AST, semantic, transformer, codegen, and resolver crates are already direct dependencies (`Cargo.toml:45-53`), but the opt-in Oxc path refuses TLA and fails when general ESM remains (`src/module_loader/transpile.rs:199-264`). The RFC correctly treats a factory producer as new work, not as capability Oxc already supplies.

- RFC §§1, 2, 4, and 8 take security and identity seriously. Authorization precedes probing and source acquisition; artifact fields are digest-covered; physical carriers are separated from logical artifacts; runtime attributes cannot smuggle build-time grants; and executable carriers retain per-principal attribution. The pointer-plus-nonce runtime identity cited by the RFC is real (`src/engine/hermes_runtime.cc:884-906,3517-3531,3656-3668`).

- The RFC correctly treats `(runtime identity, SourceId)` as a target architecture rather than describing existing code. Today `ResolvedModule.id` is a string constructed from a lossy host path (`src/module_loader/mod.rs:30-57,969-978`), and the JavaScript cache uses that resolved ID (`src/engine/bootstrap/module-loader.js:5297-5305`). Refusing an interim path-keyed runner identity in Phase 1 is a strong migration decision.

- RFC §§5, 6, and 9 provide good lifecycle boundaries: sticky ESM errors versus CommonJS/JSON eviction, immutable-artifact-only generation sharing, no partial cancellation of an evaluating record, per-principal HBC carriers, and no post-effect source fallback. The last rule aligns with the existing bytecode fallback invariant in LLP 0005 (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:107-125`).

- The adoption gate is unusually honest about feasibility. It requires canonical generated artifacts, real-Hermes execution, source-map composition, and fail-loud oracle cases rather than accepting shape tests. That is the right standard even though the required evidence has not yet been supplied.

## 3. Concerns

1. **The required producer and runner feasibility spike does not exist**

   - **Severity:** Material
   - **Evidence:** RFC §3 acknowledges that neither Oxc nor Rolldown emits the proposed factory ABI and that Ibex would own a new lowering (`llp/0026-esm-module-runner.rfc.md:434-444`). Toolchain compatibility is still unresolved (`llp/0026-esm-module-runner.rfc.md:478-482`), while the existing Oxc candidate cannot lower general ESM or TLA (`src/module_loader/transpile.rs:199-264`). The Adoption gate itself requires representative artifacts executed on real Hermes before acceptance (`llp/0026-esm-module-runner.rfc.md:1025-1030`). No `ModuleArtifact`, `ModuleRecord`, `GraphEvaluationContext`, factory ABI, or canonical factory implementation exists in the current code.
   - **Resolution criterion:** Supply the required bounded spike on the pinned toolchain, or record the explicit toolchain-upgrade decision. It must check in canonical artifacts and demonstrate live mutation, TDZ, direct and indirect cycles, namespace behavior, star ambiguity, dependency TLA, dynamic import, TS/JSX, Hermes compatibility, and composed source maps on real Hermes.

2. **Autonomous initialization changes capability semantics without an explicit delegation model**

   - **Severity:** Material
   - **Evidence:** RFC §4 excludes importer frames from the constrained-principal set during module initialization and argues that import reachability makes this non-widening (`llp/0026-esm-module-runner.rfc.md:538-574`). LLP 0021 currently requires live, scheduling, owner, and deputy principals to intersect (`llp/0021-capsec-effect-model-migration.plan.md:368-378`), and the engine implements live-frame plus scheduler attribution (`src/engine/hermes_runtime_internal.h:500-571`). LLP 0014 states that import permission permits loading but is not a host-capability grant (`llp/0014-import-site-grants-and-generated-policy.spec.md:137-146`). Consequently, a low-authority importer could trigger cold initialization effects of a more privileged dependency that the same importer could not trigger later through an exported function. The determinism argument explains why causal intersection is awkward, but it does not establish who is authorized to trigger initializer effects. Although the RFC calls this part of the “adoption set,” LLP 0021 is absent from the actual Adoption gate at `llp/0026-esm-module-runner.rfc.md:1012-1023`.
   - **Resolution criterion:** Define initialization as an explicit authority operation. Either retain causal intersection, add a reviewed digest-bound initialization delegation to import edges, or use deterministic supervisor-driven eager initialization with a separately defined dynamic-import rule. Amend LLPs 0021 and 0014 at adoption time and add low-authority-importer/high-authority-initializer fixtures for cold, warm, concurrent, synchronous, asynchronous, and `await 0` cases.

3. **TLA admission has two incompatible governing rules**

   - **Severity:** Material
   - **Evidence:** RFC §1 says LLP 0024’s evaluation-request role “governs TLA admission,” and §2 retains entry/dependency role on the request (`llp/0026-esm-module-runner.rfc.md:299-300,355-360`). LLP 0024 explicitly defines that field as admitting entry TLA while refusing dependency TLA (`llp/0024-structured-evaluation-and-session.spec.md:258-259,464-515`). RFC §6 instead permits TLA in both ESM entries and dependencies and only later says LLP 0024 will be revised when consumers migrate (`llp/0026-esm-module-runner.rfc.md:677-682,744-749`).
   - **Resolution criterion:** Add one normative admission matrix. It should state that new-runner ESM admits TLA for entry and dependency roles, script-with-extensions retains LLP 0024’s entry semantics, and unmigrated synchronous consumers retain dependency refusal. Replace the unqualified “role governs TLA admission” statement and specify exactly when LLP 0024 changes.

4. **Portable artifact identity depends on an unresolved and incomplete `SourceId` contract**

   - **Severity:** Material
   - **Evidence:** RFC §2 digest-binds `SourceId`, excludes a separate principal field, and claims a portable artifact core (`llp/0026-esm-module-runner.rfc.md:362-416`). LLP 0023 says project-file `SourceId` is portable only if the root identity is project-stable and host-independent; otherwise the project arm is session-local (`llp/0023-virtual-filesystem-namespace.spec.md:712-729`). Current snapshot construction uses the literal identity `"project-root"` (`src/bin/ibex/runtime.rs:2020-2034`). LLP 0023’s builtin and synthetic arms also do not yet specify a total authenticated mapping from every `SourceId` variant to a concrete defining principal, while current builtins receive the runtime principal separately (`src/engine/bootstrap/module-loader.js:195-199`). Phase 1 names `OBL-SOURCE-ID`, but the portability fork and total principal derivation are not acceptance prerequisites.
   - **Resolution criterion:** Define a canonical encoding and total authenticated `SourceId → defining Principal` derivation for package, project, builtin, synthetic, and generated arms. Define and fixture-test the project-root identity constructor and collision domain. If host-independent project identity is unavailable, explicitly limit portable prepared artifacts and cross-machine semantic-digest equivalence to the supported arms.

5. **The proposed source-map key cannot represent session scripts**

   - **Severity:** Material
   - **Evidence:** RFC §10 replaces LLP 0024’s source-label registry with a key based on artifact semantic digest and a `SourceId → SourceLabel` envelope when sessions adopt the runner (`llp/0026-esm-module-runner.rfc.md:923-930`). Prompt inputs, `.load`, and `ibex:eval` are scripts with no `SourceId`, `ModuleArtifact`, or module identity (`llp/0023-virtual-filesystem-namespace.spec.md:808-815`; `llp/0024-structured-evaluation-and-session.spec.md:356-359,1629-1634`). LLP 0024 intentionally keys their maps by source label (`llp/0024-structured-evaluation-and-session.spec.md:701-708`).
   - **Resolution criterion:** Define a sum-keyed registry. Module entries may use artifact digest, `SourceId`, and the local label envelope; script/session entries need session identity, submission ordinal or source label, and source digest. State explicitly that only imported modules migrate to module-artifact identity.

6. **`GraphEvaluationContext` is not mapped completely to the CapSec decision model**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** RFC §4 lists requesting record, effect owner, schedule-time identity, constrained principals, and generation (`llp/0026-esm-module-runner.rfc.md:517-536`). The semantic core’s `DecisionContext` requires stage, actor, canonical constrained principals, and presented handle IDs; occurrences separately require actor and effect owner to belong to the constrained set unless transparent (`crates/capsec-semantics/src/model.rs:1473-1496,1586-1616`). Some fields may be derived or inapplicable to an edge, but that mapping is unstated.
   - **Resolution criterion:** Specify the native structure’s normative fields and construction rules and map each operation explicitly to `DecisionContext`, including actor, stage, effect owner, handle disposition, nesting, capture/restore, and generation validation.

7. **The observed entry-TLA comparison is directionally right but overstated**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** RFC §Motivation contrasts dependency behavior with entry machinery that already awaits asynchronous entries (`llp/0026-esm-module-runner.rfc.md:98-112`). Detected standalone entries do use an async shim (`src/bin/ibex/runtime.rs:1627-1711`), but detection only recognizes `await` at brace depth zero and treats templates as opaque (`src/bin/ibex/runtime.rs:3956-3973,4019-4037,4075-4080`). Native thenable unwrapping is skipped on Windows and otherwise has a default ten-second bound that may return a pending promise (`src/engine/hermes_runtime.cc:4026-4051,4074-4149`).
   - **Resolution criterion:** Qualify the observation as applying to detected entries on the non-Windows bounded-wait path, and make the missed-block/template, timeout, and Windows cases explicit Phase 0 baselines.

8. **The final corpus-reconciliation list omits affected governing documents**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** Phase 5 and Acceptance Criterion 12 omit LLPs 0003 and 0005 (`llp/0026-esm-module-runner.rfc.md:1169-1170,1297-1303`). Native compile/load-factory operations, graph scheduling, and promise-context transport change the engine bridge described by LLP 0003 (`llp/0003-hermes-engine-bridge.explainer.md:11-18,88-140`). New artifact chunks and HBC carriers change the prepared-build and bytecode pipeline described by LLP 0005 (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:11-26,92-132`).
   - **Resolution criterion:** Add LLPs 0003 and 0005 to phase-specific reconciliation and Acceptance Criterion 12. Also make the adoption-time LLP 0021 amendment explicit rather than deferring it to shipped-state cleanup.

## 4. Cross-document findings

- LLPs 0007 and 0009 provide a clean architectural handoff. Both deliberately leave a separate ModuleRunner architecture open if single-file lowering cannot satisfy module semantics (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:279-282,421-426`; `llp/0009-runtime-transform-candidate-scope.decision.md:63-73`). LLP 0026 is a legitimate resolution of that fork.

- The proposed Rust/Oxc Hermes-compat tier is a genuine amendment to LLP 0019’s two-tier authority model, and the RFC correctly acknowledges it (`llp/0019-hermes-compat-transform-authority.decision.md:20-48`; `llp/0026-esm-module-runner.rfc.md:460-476`).

- LLP 0024 already identifies an asynchronous linker/evaluator as the missing prerequisite for dependency TLA (`llp/0024-structured-evaluation-and-session.spec.md:472-519,2232-2235`). LLP 0026 supplies the appropriate architectural answer, subject to resolving the role contradiction in Concern 3.

- The public embedding seam is clean: LLP 0002 remains synchronous and the host pumps the event loop, while eventual structured asynchronous evaluation belongs to LLP 0024 (`llp/0002-host-embedding-abi.spec.md:29-55,366-383`; `llp/0026-esm-module-runner.rfc.md:692-701`).

- Worker-local records and authority-bearing handles align with LLP 0025’s supervisor/worker ownership boundary (`llp/0025-terminal-session-ownership.spec.md:769-841`). The proposed lack of per-import-waiter cancellation also matches the existing structured-evaluation model.

- The RFC correctly identifies existing corpus drift:
  - LLP 0004’s “down-leveled” description is too broad because the default SWC path applies no target-compat pass.
  - LLP 0022 says mutable loader state is closed, but `require.cache` remains directly exposed (`src/engine/bootstrap/module-loader.js:5485-5486`).
  - LLP 0023’s `OBL-RESOLVE-GATE` describes a live body read, while module-type detection is disabled and the branch is currently dormant (`src/module_loader/mod.rs:907-945,3848-3854`).

- `OBL-FILE-GRANTS` is ledgered in LLP 0022 with LLP 0014 as owner (`llp/0022-repl-behavior-and-semantics.spec.md:987-988`), rather than being defined directly in LLP 0014. The RFC’s wording should preserve that traceability.

## 5. Suggestions

- Separate the overloaded term “transform authority” into parser/syntax authority, module-lowering authority, Hermes-compat authority, and physical carrier producer. Oxc, the versioned runner ABI, LLP 0019, Rolldown, and `hermesc` occupy different roles.

- Use an existing System.register transform strictly as an independent differential oracle for canonical factories. It need not become a runtime dependency to provide valuable comparison coverage.

- Make `ModuleArtifact.static_edges` the canonical dependency-manifest schema and define LLP 0024’s manifest as a projection when a consumer migrates.

- Add property-based state-machine testing for linking/evaluation and model-check small cyclic graphs. Randomized schedules around async SCCs, CJS overlap, failure caching, and generation teardown would exercise cases that hand-authored fixtures may miss.

- Specify how namespace objects achieve exotic-object observables on Hermes. The corpus should cover property descriptors, ordering, non-extensibility, `Reflect.set`, `defineProperty`, deletion, `Symbol.toStringTag`, and stable identity.

- Generate a phase/owner reconciliation manifest consumable by `ref-check`, so amendment timing and final document ownership cannot drift from the RFC.

## 6. Open questions

1. Which concrete Oxc/Rolldown integration will produce the ABI, and how much custom lowering does it require on the pinned toolchain?
2. What explicit authority permits an importer to trigger privileged initialization effects?
3. Is project-root identity genuinely host-independent, and what is the total `SourceId → Principal` function?
4. What is the exact TLA admission matrix across runner ESM, session scripts, and unmigrated consumers?
5. What source-map key algebra covers both module artifacts and non-module session scripts?
6. How does `GraphEvaluationContext` map field-for-field to CapSec `DecisionContext`?
7. How will Hermes namespace objects implement the required exotic semantics?
8. Which algorithm and oracle cases define async-SCC evaluation and mixed ESM/CommonJS cycles?
9. What numeric performance budgets determine whether checked binding reads and setters are acceptable?
10. What is the transactional relationship among module-record generations, Vite HMR, and session retry?
11. Does import authorization need separate “instantiate” and “trigger initialization” effects?
12. Which prepared-carrier form best preserves attribution without excessive per-module HBC overhead?

## 7. Readiness verdict

The proposal is a strong and worthwhile replacement for the current loader, and its principal diagnosis is supported by the code. It should not yet be accepted: the required feasibility evidence is absent, and the initialization-authority, TLA-admission, portable-identity, and session source-map contracts remain materially unresolved.

VERDICT: NOT READY
---

## Round 8 — 2026-07-15

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** OpenAI Codex CLI v0.144.4, `codex exec`, model
  `gpt-5.6-sol`, provider `openai`, sandbox `read-only`, approval `never`,
  session id `019f65e2-9a13-73a1-9dae-5c1b684d0d54`. Orchestrator: Claude Code
  (`claude-fable-5`) running `/llp-super-refine`.
- **Reasoning effort:** `ultra` (confirmed in the CLI banner).
- **Date:** 2026-07-15
- **Revision under review:** `1b523e2d9fc1`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. Read-only against the repository working tree, authorized
  by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session; no access to the
  concurrent Fable round-8 review or any prior LLP 0026 artifact (rounds 1–7
  stashed outside `llp/reviews/` for the round). Instructed not to read
  `llp/reviews/`.
- **Method:** cli-runner, round-8 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round8.md`) — same brief as the
  Fable round-8 reviewer.
- **Orchestrator disposition note (outside the verbatim body):** the
  text-fixable parts of Concerns 1–7 were accepted and addressed in the
  round-8 revision (Module-goal strict-execution ABI clause; the
  `DecisionContext` mapping corrected to a normative `DecisionSet`
  construction; the owner-thread contract added as an LLP 0002/0003
  amendment with enforced refusals; runner error classes integrated into
  LLP 0023's authorization-first total order; the exact runtime identity of
  `ModuleKey`'s outer component defined; the LLP 0014 legacy-grant-forms
  correction; and the three precision fixes). The "supply the executed
  spike" component of Concern 1 retains the standing disposition from rounds
  5–7. The orchestrator notes this is the fourth consecutive round in which
  the executed-spike demand is the irreducible blocker; the run was paused
  after this round for the author's decision rather than continuing the
  loop.

### Verbatim review

## 1. Overall assessment

LLP 0026 chooses the right architectural direction. Replacing file-at-a-time ESM-to-CommonJS rewriting with authenticated module records, real linking, binding cells, and asynchronous graph evaluation is a substantial correctness and security improvement. The migration plan is unusually candid about prerequisites, compatibility risk, and the need to preserve CapSec attribution.

The load-bearing `[observed]` claims are largely accurate. Ordinary JavaScript bypasses Rust AST transformation unless narrow scanners select it; the bootstrap then performs a large regex/string-based ESM rewrite. Its top-level-await fallback is fire-and-forget and can execute the pre-`await` prefix twice. The qualification is that current SWC-lowered paths preserve some live-binding and simple-cycle behavior; the RFC acknowledges this in its alternatives analysis.

The proposal is not ready for acceptance. Its required real-Hermes producer proof has not landed, and several security and embedding contracts remain materially incomplete or incorrectly stated: the CapSec mapping names the wrong semantic-core type, the synchronous overlap proof relies on unenforced owner-thread serialization, new graph-state errors lack a total security ordering, and the outer runtime component of `ModuleKey` remains ambiguous.

## 2. Strengths

- The motivation is verified and compelling. Rust transforms TypeScript/JSX-family files and scanner-selected JavaScript, otherwise returning source unchanged (`src/module_loader/mod.rs:320-388`). Ordinary resolver results currently default to CommonJS, while the ESM-prefetch branch is dormant because module-type detection is disabled (`src/module_loader/mod.rs:907-945,3848-3854`). This supports RFC §“The current fallback is doing a parser and linker’s job” (`llp/0026-esm-module-runner.rfc.md:56-79`).

- The bootstrap transformer really is carrying parser/linker responsibilities. Its hand-maintained lexical machinery covers strings, comments, regular expressions, templates, and delimiter state (`src/engine/bootstrap/module-loader.js:3743-4089`); `transformEsmToCjs` spans `:4224-5065`. Named imports and exports are copied into local variables or properties rather than represented as ESM binding cells (`:4594-4647`), and star exports copy current properties without ambiguity resolution (`:4868-4877`). RFC §§Motivation and Design principles correctly identify this as an unsustainable semantic authority (`llp/0026-esm-module-runner.rfc.md:67-96,207-230`).

- The current execution and TLA diagnosis is accurate. Modules are six-argument CommonJS-style `Function` bodies (`src/engine/bootstrap/module-loader.js:235-253`), inserted into cache before execution (`:5340-5364`), and invoked synchronously with their return value ignored (`:5500-5506`). The async fallback wraps the body in an unobserved async IIFE (`:5637-5708`), may deliberately rerun the prefix (`:5680-5695,5747-5760`), and then marks the record loaded (`:5797-5798`). RFC §Motivation accurately characterizes this as fire-and-forget dependency TLA (`llp/0026-esm-module-runner.rfc.md:98-115`).

- The proposed separation of transformation, linking, and carriers is strong. `ModuleArtifact`, `ModuleRecord`, and physical carrier identity are kept distinct; semantic fields and exact factory bytes are digest-bound; machine-local labels remain outside the portable artifact (`llp/0026-esm-module-runner.rfc.md:225-243,346-440`). This is a sound foundation for source, cache, chunk, and HBC equivalence.

- The identity design follows LLP 0023 instead of blessing current pathname identity. Current `ResolvedModule` still uses a string id and host-path metadata (`src/module_loader/mod.rs:30-57,969-978`), while the bootstrap cache is string-keyed (`src/engine/bootstrap/module-loader.js:5297-5305`). RFC §§Terminology and Migration correctly require `(runtime, SourceId)`, preserve the defining principal exactly once, and prohibit an interim path-keyed cache (`llp/0026-esm-module-runner.rfc.md:171-205,395-430,1139-1158`).

- The toolchain account is nuanced. SWC is present and remains the default (`Cargo.toml:98-106`; `src/module_loader/transpile.rs:41-95,109-196`), while Oxc already serves resolution and an experimental in-process transform role (`Cargo.toml:44-53`; `src/module_loader/transpile.rs:199-264`). RFC §Transform authority correctly avoids pretending that removing SWC’s module role automatically retires LLP 0024’s parser and session-lowering dependencies (`llp/0026-esm-module-runner.rfc.md:458-519`).

- The security design contains several good fail-closed choices: exact edge authorization before source acquisition, authenticated compile-time attribution, per-principal executable carriers, no JavaScript-authored graph metadata, and a richer async-context carrier as a prerequisite rather than an assumption (`llp/0026-esm-module-runner.rfc.md:521-645,944-1011`). The promise-job gap is real: current host queues retain fuller principal vectors, while Hermes jobs retain only a scheduler principal across the first hop (`patches/hermes/0008-capability-context-propagation.patch:18-47,65-79`).

- The migration and conformance strategy is excellent in shape. It calls for real-Hermes execution, non-zero case counts, test262 module/TLA coverage, source/prepared equivalence, explicit expected divergences, scanner-regression fixture recovery, and effect-trace comparison rather than dual execution of application side effects (`llp/0026-esm-module-runner.rfc.md:1013-1061,1105-1238`).

## 3. Concerns

1. **The core producer/factory contract remains unproven and omits an explicit Module-goal execution rule.**

   - **Severity:** Material
   - **Evidence:** RFC §3 concedes that neither Oxc nor Rolldown emits the proposed factory and that v1 likely requires a custom Ibex-authored lowering (`llp/0026-esm-module-runner.rfc.md:460-468`). The existing Oxc candidate is only a file transform: it refuses TLA and errors if ESM remains (`src/module_loader/transpile.rs:199-264`). The RFC itself makes a real-Hermes spike prerequisite evidence and says plausibility is insufficient (`llp/0026-esm-module-runner.rfc.md:1081-1093`). In addition, the proposed ABI says `execute` runs the module body but never normatively requires strict execution, an undefined top-level receiver, or hygiene against wrapper bindings (`:647-679`). That matters because the current `new Function` wrapper is non-strict unless the input supplies a directive and invokes the body as an ordinary function (`src/engine/bootstrap/module-loader.js:235-253,5500-5506`).
   - **Resolution criterion:** Complete and record the pre-acceptance spike on real Hermes with a precommitted fixture list and test262 threshold. Amend the ABI to require Module-goal strict semantics explicitly, including top-level `this`, undeclared assignment, `arguments`, wrapper-name hygiene, and directive handling; include canonical factories and source-map fixtures for those cases.

2. **`GraphEvaluationContext` is mapped to the wrong CapSec semantic type.**

   - **Severity:** Material
   - **Evidence:** RFC §4 claims a field-for-field mapping to `DecisionContext` including `effect owner` (`llp/0026-esm-module-runner.rfc.md:542-552`). In the actual semantic core, `DecisionContext` contains only stage, actor, constrained principals, and presented handles (`crates/capsec-semantics/src/model.rs:1586-1594`). `effect_owner` belongs on each `Effect` (`:1577-1584`), and a `DecisionSet` combines one context with one or more effects plus operation and atomicity identity (`:1608-1631`). LLP 0021 likewise defines a coverage edge as mapping a surface to one or more normalized effects (`llp/0021-capsec-effect-model-migration.plan.md:128-148`).
   - **Resolution criterion:** Replace the claimed `DecisionContext` mapping with a normative construction of a complete `DecisionSet`: context fields, emitted effects, effect owner per effect, normalized resources, operation id, atomicity group, stage, and target-cell/coverage-edge mapping. Add missing-owner, wrong-owner, and multi-effect fail-closed fixtures.

3. **The synchronous-overlap proof assumes an owner-thread contract that is not currently enforced.**

   - **Severity:** Material
   - **Evidence:** RFC §6 makes one-JavaScript-thread-per-runtime load-bearing and treats overlap as a state check rather than a race (`llp/0026-esm-module-runner.rfc.md:762-779`). LLP 0003 records an owning thread and describes poll work as occurring there, but does not normatively prohibit concurrent or off-owner `eval`/`poll` calls (`llp/0003-hermes-engine-bridge.explainer.md:26-45,109-116`). LLP 0002 expressly requires owner-thread destruction only (`llp/0002-host-embedding-abi.spec.md:366-383`). Code records `runtime_thread` (`src/engine/hermes_runtime.cc:3656-3659`) and checks it during destruction (`:3850-3854`), but `ex_hermes_eval` and `ex_hermes_poll` have no equivalent check (`:3900-3932,4925-4935`).
   - **Resolution criterion:** Amend LLPs 0002/0003 to make all runtime-driving entry points owner-thread-only and serialized, enforce this at `eval`, `poll`, and runner ingresses with a stable refusal, and test concurrent/off-owner calls. Alternatively, specify synchronization that preserves the state-machine proof.

4. **The new graph errors are not integrated into LLP 0023’s security-owned total order.**

   - **Severity:** Material
   - **Evidence:** RFC §1 correctly puts authorization before resolution and body acquisition (`llp/0026-esm-module-runner.rfc.md:261-270`), but later introduces in-flight-async, cycle, TLA, link, interop, evaluation, cache, and carrier failures without assigning their precedence (`:762-789,843-852,985-988`). LLP 0023 explicitly owns resolver error ordering and requires all graph-derived facts to follow authorization (`llp/0023-virtual-filesystem-namespace.spec.md:1695-1735`). The RFC’s reconciliation list mentions the latent resolve-read correction but not these new classes (`llp/0026-esm-module-runner.rfc.md:1368-1375`). An unauthorized caller must not learn that a target record exists, is evaluating, belongs to an async SCC, has TLA, or failed linking.
   - **Resolution criterion:** Extend LLP 0023’s graph tier with every stable runner error and the stage at which it becomes observable. Add pairwise tests proving snapshot/import/path authorization precedes cache state, artifact validation, parse, transform, link, cycle, TLA, and carrier errors.

5. **The outer runtime component of `ModuleKey` is not exact enough.**

   - **Severity:** Material
   - **Evidence:** RFC §Terminology describes runtime identity as both an opaque runtime/session handle and the pointer-plus-nonce “class” already used for ABA defense (`llp/0026-esm-module-runner.rfc.md:173-186`). Current code has distinct identities: the opaque runtime pointer, `runtime_nonce`, and `host_context_id` (`src/engine/hermes_runtime_internal.h:98-109,124-127`), while the armed snapshot separately has `runNonce` (`capsec/schema/armed-snapshot.schema.json:89-93`). LLP 0023 defines a session handle with its own generation lifecycle (`llp/0023-virtual-filesystem-namespace.spec.md:1622-1666`). These are related but not interchangeable.
   - **Resolution criterion:** State whether the graph is runtime-owned, making the outer key implicit, or globally keyed. In either case, normatively define the exact identity type, equality, construction, destruction, generation/ABA behavior, and relationship among runtime nonce, host-context id, session handle, and snapshot run nonce. Require two-runtime and destroy/recreate collision fixtures.

6. **Legacy authority-annotation handling contradicts LLP 0014.**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** RFC §2 says canonical `authorities` and legacy grant forms are consumed into policy and stripped (`llp/0026-esm-module-runner.rfc.md:442-447`). LLP 0014 says only typed `authorities` is canonical and legacy colon-delimited `grants`/`also` forms are rejected (`llp/0014-import-site-grants-and-generated-policy.spec.md:228-236`).
   - **Resolution criterion:** State that canonical `authorities` is consumed and stripped, while legacy spellings fail generation. Add accepted-canonical, rejected-legacy, and artifact-smuggling fixtures.

7. **A few current-state and migration descriptions need precision.**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** Oxc is already an in-process parser/semantic/transform/codegen candidate, not merely a future dependency (`Cargo.toml:44-53`; `src/module_loader/transpile.rs:199-264`); the unsolved work is module-factory lowering and metadata. Current compilation stamps the principal before `new Function`, but binds the compartment afterward (`src/engine/bootstrap/module-loader.js:240-272`), so RFC §4’s comparison should not imply that both are currently pre-compilation-stamped. Finally, RFC §2 keeps entry/dependency role off the artifact (`llp/0026-esm-module-runner.rfc.md:366-371`), while LLP 0024 still places role in its transform-emitted dependency manifest (`llp/0024-structured-evaluation-and-session.spec.md:497-499`).
   - **Resolution criterion:** Reframe the spike around the already-landed Oxc foundation, narrow the current-attribution comparison to pending principal ordering, and explicitly amend LLP 0024 so role remains on the evaluation request rather than immutable per-source artifact metadata.

## 4. Cross-document findings

- LLP 0026 cleanly resolves the fork that LLP 0007 intentionally left open. LLP 0007 routes graph semantics to a separate ModuleRunner design (`llp/0007-vite-rolldown-oxc-runtime-transforms.rfc.md:248-282,419-426`), and LLP 0009 preserves SWC pending exactly such a decision (`llp/0009-runtime-transform-candidate-scope.decision.md:44-73`). The adoption gate correctly requires both documents to be amended (`llp/0026-esm-module-runner.rfc.md:1067-1074`).

- The LLP 0019 seam is clean. LLP 0019 currently permits exactly two Hermes-compat tiers (`llp/0019-hermes-compat-transform-authority.decision.md:10-36`); LLP 0026 explicitly identifies the Rust/Oxc implementation as a temporary third-tier amendment and plans a two-tier end state after scanner retirement (`llp/0026-esm-module-runner.rfc.md:484-500,1067-1079`).

- Source identity aligns closely with LLP 0023: `(runtime, SourceId)`, principal normalization, carrier-independent provenance, and separation from `SourceLabel` (`llp/0023-virtual-filesystem-namespace.spec.md:655-710,749-790`). LLP 0026 is also honest that `OBL-SOURCE-ID`, provenance, and exact graph location remain unlanded (`llp/0023-virtual-filesystem-namespace.spec.md:2057-2058,2067`; `llp/0026-esm-module-runner.rfc.md:1139-1158`).

- LLP 0026 correctly identifies existing corpus drift. LLP 0004 overstates scanner-selected JavaScript as down-leveled (`llp/0004-module-loading-and-builtins.explainer.md:75-87`), and LLP 0023’s `OBL-RESOLVE-GATE` incorrectly describes a currently dormant body-read branch as live (`llp/0023-virtual-filesystem-namespace.spec.md:2068`). Phase 0/1 assign both corrections (`llp/0026-esm-module-runner.rfc.md:1129-1135,1161-1166`).

- The TLA seam with LLP 0024 is coherent. LLP 0024’s entry-only restriction explicitly exists because no async graph currently exists (`llp/0024-structured-evaluation-and-session.spec.md:464-519`); LLP 0026 preserves that rule for unmigrated consumers and retires it only when they adopt the graph (`llp/0026-esm-module-runner.rfc.md:303-311,791-796`).

- Failure caching and session source maps are treated as explicit amendments rather than silent changes (`llp/0026-esm-module-runner.rfc.md:709-722,971-983`). Worker-local graph state also aligns with LLPs 0023/0025 (`llp/0026-esm-module-runner.rfc.md:642-645`; `llp/0023-virtual-filesystem-namespace.spec.md:1682-1692`).

- The initialization-boundary change is coherent but high-stakes. It deliberately amends LLP 0021’s full-live-chain intersection and LLP 0014’s characterization of import permission (`llp/0026-esm-module-runner.rfc.md:567-621`). The first-import poisoning argument is persuasive, but the amendment must land before implementation, as the adoption gate requires.

- LLP 0022’s statement that live loader state is already closed is stale: it says `require.cache`, `require.main`, and `process.mainModule` are closed today (`llp/0022-repl-behavior-and-semantics.spec.md:243-261`), while current bootstrap code exposes them. LLP 0026 correctly records the discrepancy and assigns closure to Phase 2 (`llp/0026-esm-module-runner.rfc.md:857-878`).

- The hermeticity, pre-execution-only bytecode fallback, diagnostic preservation, and fail-loud corpus rules align cleanly with LLPs 0005, 0006, and 0018.

## 5. Suggestions

- Defer multi-generation HMR to a follow-up RFC. A one-generation runner is sufficient to replace the current semantic path; HMR adds identity amendments, stale completions, transaction boundaries, and package-edit policy before the base evaluator is proven.

- Build a small executable reference model for record states, SCC ordering, async-parent propagation, and sync-require overlap. Model-check bounded cyclic graphs and use its canonical transition trace as an oracle alongside Node.

- Emit a canonical graph trace covering resolution, authorization, record transitions, cell initialization/update, SCC scheduling, and settlement. This would compare source and prepared execution without running application side effects twice.

- Consider making a declarative factory/binding IR the semantic digest domain, with generated JavaScript and HBC treated as authenticated carriers. That would let independently implemented producers agree semantically without requiring byte-identical generated source.

- Surface “may trigger target-owned initialization” as a high-risk policy-diff fact even if it remains semantically bundled with import permission. The rule is defensible, but reviewers should not have to infer its authority consequence from an ordinary graph edge.

- Frame the producer spike around the existing Oxc 0.121 parser/semantic/codegen path. The uncertain work is factory lowering, Hermes compatibility, linking metadata, maps, and performance—not basic in-process Oxc integration.

## 6. Open questions

1. Which exact Oxc/Rolldown versions and Rust toolchain will implement the producer, and what corpus threshold is committed before seeing results?
2. What complete `DecisionSet` does each static import, re-export, dynamic import, `require`, source acquisition, cache hit, and prepared-carrier operation emit?
3. What exact native/session identity is the outer component of `ModuleKey`?
4. Is owner-thread-only serialized runtime driving a public embedding rule, and what stable error reports violations?
5. What total error precedence applies when authorization denial, target absence, cached async state, TLA, cycle, link failure, and carrier failure coincide?
6. Should import permission intrinsically authorize target-owned initialization, or should policy artifacts expose a distinct reviewed initialization capability?
7. Can checked import reads and export-setter fan-out meet the steady-state budget on realistic hot graphs?
8. Can Hermes return correctly attributed per-factory handles from per-principal multi-module HBC carriers?
9. Should HMR/generations remain in v1, or follow after the single-generation evaluator is proven?
10. Which LLP 0024 session surfaces should reuse the graph directly, and which should retain session-specific lowering and retry semantics?

## 7. Readiness verdict

This is a strong proposal with the right destination and a credible staged plan. Its observed diagnosis is supported by the code, and its handling of source identity, provenance, asynchronous evaluation, and migration risk is substantially better than the current path.

It is not ready for acceptance because the RFC’s own required producer evidence is absent and several load-bearing security and embedding contracts remain unresolved. The most urgent fixes are the real-Hermes spike, a type-correct `DecisionSet` mapping, an enforced runtime-threading contract, a total error order, and an exact runtime identity definition.

VERDICT: NOT READY