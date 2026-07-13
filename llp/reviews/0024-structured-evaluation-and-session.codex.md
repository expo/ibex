# LLP 0024 review — Codex (OpenAI)

Reviews of `llp/0024-structured-evaluation-and-session.spec.md`, recorded per
LLP 0005. One `## Round N` section per round; earlier rounds are never
overwritten.

## Round 1 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra`
**Codex session id:** `019f5574-8c3f-7351-8e1e-f22ee6b04c89`
**Revision under review:** `9561404fa4e8`
**Redaction:** none — the reviewer received the unredacted brief and full
read access to the repository.
**Independence:** launched concurrently with the Fable reviewer on the same
revision, in a separate process with no shared context. No `llp/reviews/0024-*`
artifact existed at launch (this is round 1), and the brief forbade reading
`llp/reviews/`, so neither reviewer could see the other's findings.
**Method:** read the full target document, the sibling corpus (LLP 0022, 0023,
0025) and the governing LLPs (0003, 0004, 0019, 0021), then verified
load-bearing claims against `src/bin/ibex/engine/{mod,hermes}.rs`,
`src/engine/hermes_runtime.cc`, `src/module_loader/{mod,transpile}.rs`,
`src/bin/ibex/repl/mod.rs`, and `packages/ibex-runtime-js/src/inspect/inspect.ts`.

### Verbatim review

1. **Overall assessment**

The proposal has strong high-level defaults: shared cells, preserved `const` immutability, entry-only TLA, non-assimilating results, and fail-safe inspection are all good decisions for Hermes. Its diagnosis of the current implementation is largely accurate.

It is not yet a normative Spec that two independent implementers could reproduce. The session model lacks complete state transitions; the result ABI does not define value-handle ownership or completion-record recovery; Script-plus-import/TLA lowering lacks a concrete parsing algorithm; and the supposedly safe pre-native display still requires observable property reads. Several new seams with LLPs 0022–0025 also contradict or depend on one another without a protocol.

The design direction should be retained, but the document needs another algorithm-and-ABI revision before implementation.

2. **Strengths** (with section citations)

- The critique of the current seam is accurate. `Engine::eval` is `&str -> Result<Option<String>>` (`src/bin/ibex/engine/mod.rs:22-39`), Hermes hardcodes `<eval>` (`src/bin/ibex/engine/hermes.rs:1515-1524`), the FFI is an untagged `char **` (`src/bin/ibex/engine/hermes.rs:87-95`), and `undefined` becomes a null pointer (`src/engine/hermes_runtime.cc:3161-3174`). LLP 0024 §§1 and 6 correctly identify this as insufficient.

- Entry-only TLA is the right v1 boundary. LLP 0024 §3 honestly accounts for Hermes’s lack of ESM/TLA and the synchronous CJS graph (`llp/0024-structured-evaluation-and-session.spec.md:145-160`). The existing transform lowers imports through CommonJS (`src/module_loader/transpile.rs:97-102,166-180`), so dependency-level suspension really would require a different linker/evaluator.

- The shared-cell choice in §7 is better than copy-out publication. Closures should observe later assignment through the same cell, while a deliberate redeclaration should create a new cell and leave old closures attached to the old one (`llp/0024-structured-evaluation-and-session.spec.md:313-353`). Preserving `const` and import immutability is also the right compatibility default.

- The staged-inspection principle in §8 is sound. The document correctly recognizes that exception-safe JavaScript reflection is not side-effect-free. The current inspector performs Gets (`packages/ibex-runtime-js/src/inspect/inspect.ts:85-95`), calls methods and iterators (`inspect.ts:182-384`), and invokes Proxy-sensitive enumeration and descriptor operations (`inspect.ts:393-449`).

- The structured asynchronous-failure direction in §9 is substantially better than today’s log-and-poison behavior. Currently errors are logged and set fatal state (`src/engine/hermes_runtime.cc:673-691,3712-3719`), which Rust reduces to a generic task failure (`src/bin/ibex/engine/hermes.rs:1026-1058`).

- The acceptance criteria are unusually adversarial and observable. In particular, the thenable, old-cell closure, failure-publication, hostile-inspection, principal-attribution, and embedded-NUL cases are valuable tests. The concern is that important branches of the claimed algorithms are still absent.

3. **Concerns** — numbered; each with severity (Blocking | Material | Minor/Non-blocking), evidence (doc section + file:line), and a concrete resolution criterion

1. **Blocking — the session cell model is not yet a deterministic state-transition algorithm.**

   Evidence: §7 says declaration instantiation applies ECMAScript collision rules (`llp/0024-structured-evaluation-and-session.spec.md:337-340`), then permits cross-kind replacement (`:346-353`). Cells bind before execution but publish only at completion, and failed lexical cells become unpublished (`:354-360`). It does not answer:

   - Whether `let x=1`, followed by `let x=2; throw`, restores the old `x`, removes it, or leaves another state.
   - Whether `var`/function-to-`var`/function redeclarations reuse a cell or replace it.
   - Which collisions are same-input early errors versus cross-input replacements.
   - What callbacks running while a TLA input is suspended see: the old mapping, the provisional cell, or its TDZ.
   - What leaked closures over a failed provisional cell continue to observe.
   - How destructuring allocates and initializes multiple cells when defaults, getters, or iterators fail partway through.

   AC10–11 cover only scalar examples (`:501-509`). The current REPL’s global-property imports and async IIFEs illustrate how far the implementation is from such a model (`src/bin/ibex/repl/mod.rs:812-884,1080-1184`).

   Resolution criterion: specify `Parse → Prepare provisional environment → Instantiate → Execute → Commit/Abort`, including a complete old-kind/new-kind matrix for `var`, function, `let`, class, `const`, import, and object-only globals; rollback/restoration rules; escaped provisional closures; destructuring; TLA suspension/rejection; and cancellation.

2. **Blocking — direct/indirect `eval` makes the proposed implementation mechanisms observably non-equivalent.**

   Evidence: §7 says direct eval sees the session record and indirect eval behaves as a global Script (`llp/0024-structured-evaluation-and-session.spec.md:362-365`), while OQ1 treats a native persistent environment and synthetic “cell module” as cost alternatives (`:551-555`). A static cell transform cannot transparently process dynamically introduced `var`, indirect-eval source, or `Function` constructor source. Current REPL import lowering explicitly uses `globalThis` because evaluated lexical scope does not provide the desired persistence (`src/bin/ibex/repl/mod.rs:1080-1085`).

   Ambiguous examples include:

   - `let x=1`; `const f=()=>eval("x")`; redeclare `let x=2`; should `f()` see its old cell or the current session mapping?
   - Does top-level `eval("var y=1")` publish `y`?
   - Does `(0,eval)("let x=3")` perform cell replacement or ordinary global-Script declaration checks?
   - What does `Function("return x")` resolve?

   Resolution criterion: either close dynamic code in v1 and state that explicitly, or specify these cases and prove the selected native/transform mechanism implements them. Do not leave native environments and synthetic cell modules described as observably interchangeable without that proof.

3. **Blocking — empty completion versus the value `undefined` has no recovery algorithm.**

   Evidence: §6 and AC1 require the distinction (`llp/0024-structured-evaluation-and-session.spec.md:249-270,469-472`), but Hermes exposes a single `jsi::Value` from `evaluateJavaScript` (`src/engine/hermes_runtime.cc:2982-3011`) and maps `undefined` to null (`:3161-3164`). Rust then maps null to `None` (`src/bin/ibex/engine/hermes.rs:911-917`). Current REPL prefix heuristics discard all statement completions (`src/bin/ibex/repl/mod.rs:812-857`).

   This cannot be solved by “take the last expression”: statement-list `UpdateEmpty`, blocks, `if`, loops, and `try/finally` all propagate completions differently.

   Resolution criterion: choose either a Hermes patch exposing Completion Records or a fully specified source-instrumentation algorithm equivalent to ECMAScript Script evaluation. Add fixtures for statement lists, blocks, conditionals, loops, `try/finally`, abrupt completion, declarations following expressions, and the same forms across TLA lowering.

4. **Blocking — the promised structured outcome is not yet an ABI.**

   Evidence: §6 promises typed outcomes and a value handle (`llp/0024-structured-evaluation-and-session.spec.md:249-278`), but defines no rooting, retain/release, runtime identity, invalidation, thread affinity, allocator ownership, or engine-fault-versus-JavaScript-throw taxonomy. Hermes is creating-thread-bound (`src/bin/ibex/engine/hermes.rs:795-817`); the present `jsi::Value` is local and formatted before return (`src/engine/hermes_runtime.cc:2982-3011,3161-3174`). The current `Engine` trait also has no concurrently callable cancellation operation (`src/bin/ibex/engine/mod.rs:22-99`), and evaluation holds the runtime mutex throughout the native call (`src/bin/ibex/engine/hermes.rs:869-918`).

   `EngineFeature` is similarly ambiguous: Hermes reports native TLA/ESM/CJS as false (`src/bin/ibex/engine/hermes.rs:1653-1661`), while LLP 0024 makes transform-provided TLA part of the evaluator contract.

   Resolution criterion: define concrete Rust and C representations, such as `Result<EvaluationOutcome, EngineFault>`, runtime-scoped rooted handles with retain/drop operations, lengths and allocator ownership, an evaluation handle with a concurrent cancellation method, and separate native-engine versus end-to-end evaluator capabilities.

5. **Blocking — “sloppy Script plus imports/TLA” is an obligation, not a specified feasible transform.**

   Evidence: §3 requires imports and TLA without module strictness or changes to directives, top-level `this`, declarations, or completions (`llp/0024-structured-evaluation-and-session.spec.md:124-167`). The current transform has no goal or entry/dependency role (`src/module_loader/transpile.rs:84-102`), parses through `parse_program` (`:114-136`), and applies generic CommonJS lowering (`:166-180`). Parsing as a Module can itself reject sloppy-only syntax before a later transform can restore Script semantics.

   The document also mischaracterizes LLP 0019: that Decision’s tiers are the build-time Hermes-compat AST authority and embedded bootstrap scanner (`llp/0019-hermes-compat-transform-authority.decision.md:20-36`). The Rust SWC/Oxc TypeScript/ESM pipeline is a separate transform responsibility (`src/module_loader/transpile.rs:1-6,41-94`).

   Resolution criterion: specify a mixed-goal parser/lowerer that validates the body as Script while admitting only the two extensions. Its corpus must cover `with`, legacy octal/sloppy forms, duplicate parameters, unqualified delete, directive placement, Annex B functions, top-level `this`, undeclared assignment, direct eval, and completion propagation. Give this source-goal transform its own authority and corpus; use LLP 0019 only for the Hermes-compat pass it actually governs.

6. **Material — dependency-TLA routing is inconsistent and lacks a source-role contract.**

   Evidence: SWC explicitly passes TLA through (`src/module_loader/transpile.rs:97-102,348-353`), and that transform is generically applied to dependency files (`src/module_loader/mod.rs:242-248`). Oxc rejects TLA unconditionally (`src/module_loader/transpile.rs:211-217,414-423`). Ordinary TLA is absent from the JavaScript downlevel trigger (`src/module_loader/mod.rs:284-295`), so pass-through JavaScript may bypass detection.

   LLP 0024 also says all imported files are modules in §3 (`llp/0024-structured-evaluation-and-session.spec.md:126-143`), while §4 correctly gives resolved CommonJS files sloppy CJS semantics (`:200-213`). CJS use of an `await` identifier must not be misclassified as ESM TLA.

   Resolution criterion: add explicit `SourceRole` and resolved goal/kind to the transform contract. Detect dependency TLA for every ESM dialect before execution/cache publication, emit one stable named error across SWC/Oxc and static/dynamic/transitive imports, and separately pin `.cjs`, `.cts`, and CJS-resolved `.js` behavior.

7. **Material — TLA control settlement and user-result delivery must be separate.**

   Evidence: §6 requires the generated asynchronous unit to settle while returning a final thenable untouched (`llp/0024-structured-evaluation-and-session.spec.md:272-287`). If the async driver resolves its Promise with that final value, Promise resolution assimilates the thenable. Today native code explicitly gets and calls `.then` (`src/engine/hermes_runtime.cc:3033-3058`).

   Static import semantics are also underdefined: §3/§4 says imports are snapshots and empty completions, but does not say whether they instantiate before the body or execute as textual-position `require()` calls. The difference affects directives, TDZ, side-effect ordering, and dependency failure.

   Resolution criterion: make the async unit settle with a private non-thenable control token while placing the untouched completion handle in a rooted result slot. Specify static-import resolution, evaluation, snapshot initialization, failure, and cache ordering. Test throwing `then` getters, multiply-calling thenables, Promises, and `await 0; finalThenable`.

8. **Blocking — the pre-native inspection stratum is not safe as written.**

   Evidence: §8 promises `[Function: name]` and `[Array(3)]` while also saying no property is read (`llp/0024-structured-evaluation-and-session.spec.md:421-424`). A callable Proxy can trap `name`; an array Proxy can trap `length`. The current inspector performs exactly those reads (`packages/ibex-runtime-js/src/inspect/inspect.ts:138-164`). Current native formatting is also unsafe: it performs property Gets, `JSON.stringify`, and `toString` (`src/engine/hermes_runtime.cc:493-537`).

   The rich primitive contract does not define HostObjects, module namespaces, typed arrays, Map/Set, Error custom properties, or how descriptor values become rooted handles. Nor does §8 define the structured token/tree format promised in Consequences (`llp/0024-structured-evaluation-and-session.spec.md:539-541`).

   Resolution criterion: stage one must use only metadata demonstrably available without Gets—at most generic `[Function]`, `[Array]`, and `[Object]`, or simply `[Object]`—with native or captured/hardened primitive formatting. Define a typed, length-bearing inspection tree separating trusted style from untrusted payload, and specify opaque handling for every exotic or host object without guaranteed native metadata.

9. **Material — `$_` mutation detection is impossible under the stated no-hook implementation.**

   Evidence: §7 claims descriptor-identity polling detects assignment, `Reflect.set`, `defineProperty`, and deletion without an engine hook (`llp/0024-structured-evaluation-and-session.spec.md:382-392`; AC12 at `:510-512`). Polling cannot detect a same-value assignment, nor deletion/recreation or `defineProperty` ABA that restores an identical descriptor before the next check. Current REPL simply assigns `globalThis.$_` (`src/bin/ibex/repl/mod.rs:67-80`).

   “Last successfully displayed” also requires acknowledgement from the consumer; the evaluator cannot infer whether a handle was actually rendered and brokered successfully.

   Resolution criterion: either narrow the contract to state divergence observable at a checkpoint, or add a native/cell mutation generation hook covering assignment, definition, and deletion. Define a display acknowledgement before auto-update and test same-value writes and ABA restoration.

10. **Material — the source request is a field list, not yet a closed type.**

    Evidence: §1 includes text, identity, referrer, goal, main flag, principal, and mode (`llp/0024-structured-evaluation-and-session.spec.md:82-99`), but omits:

    - Parser dialect and resolved CJS/JSON/ESM kind.
    - Entry versus dependency role.
    - A typed authenticated LLP 0023 referrer rather than a display string.
    - An unforgeable evaluation/principal context.
    - Event-loop/drain semantics for execution mode.
    - A trusted bootstrap/bytecode variant.

    The engine currently accepts only bytes, a C-string source URL, and a bytecode flag (`src/bin/ibex/engine/hermes.rs:87-94`). Yet internal probes and embedded HBC legitimately use the same path (`src/bin/ibex/engine/hermes.rs:924-970,1473-1479`).

    `.load` is internally ambiguous: its identity is `repl:<n>` “annotated” with a virtual path (`llp/0024-structured-evaluation-and-session.spec.md:103-110`), while AC2 says it reports the virtual path (`:473-476`).

    Resolution criterion: define enums/opaque handles for payload, origin, role, dialect, resolved goal/kind, authenticated principal context, typed referrer, main status, and mode; provide a per-surface mapping table and a distinct trusted bootstrap/bytecode ingress.

11. **Material — asynchronous-failure classification and delivery are incomplete.**

    Evidence: §9 specifies envelope contents but not the queue/callback API, capacity, backpressure, handle lifetime, loss policy, or how sequence numbers relate to evaluation outcomes (`llp/0024-structured-evaluation-and-session.spec.md:444-465`). Evaluation currently drains next ticks and microtasks inside its own native evaluation (`src/engine/hermes_runtime.cc:3015-3025`), so the boundary between a TLA-unit rejection and detached background failure must be explicitly tracked.

    Synchronous listener precedence is also unstated: current eval invokes `__exactUncaughtExceptionHandler`, constructs a replacement Error, and may convert a throw into success/empty (`src/engine/hermes_runtime.cc:3178-3193`).

    Resolution criterion: specify a bounded sequenced event channel, ownership/backpressure, evaluation association, original-value handle lifetime, and exact classification of unit rejection versus detached failure. Pin listener behavior for syntax errors, ordinary throws, rejected TLA, unhandled rejections, and background callback throws while preserving original values.

12. **Material — normative choices remain open after the body claims they are fixed.**

    Evidence:

    - §4 says the TypeScript dialect is pinned to a named parser/toolchain version, but names none (`llp/0024-structured-evaluation-and-session.spec.md:221-225`). Runtime exposes both SWC and Oxc (`src/module_loader/transpile.rs:41-94`), and current SWC parses every extension as TypeScript, toggling only TSX (`:114-124`).
    - §8 says opaque display “is what ships,” while OQ2 reopens whether the primitive is a release blocker (`llp/0024-structured-evaluation-and-session.spec.md:433-437,556-559`).
    - Depth, breadth, string length, key order, truncation, completion budget, and input bounds are called deterministic but left unresolved (`:433-435,572-575`).
    - `.load` of JSON is not given a result: §4 calls JSON non-JavaScript, then says `.load` evaluates file bytes as Script (`:183-213`).

    Resolution criterion: name the parser/version and conformance oracle; choose the inspection release stage; specify versioned ordering and bounds; and define `.load` behavior for every extension in the dialect table.

13. **Minor/Non-blocking — two factual inconsistencies should be corrected.**

    Evidence: §7 declares exactly three deviations (`llp/0024-structured-evaluation-and-session.spec.md:367-380`), while Consequences says four (`:542-543`). Also, the Summary’s statement that today’s seam assimilates any thenable is only true on non-Windows: the unwrap path is compiled out on Windows (`src/engine/hermes_runtime.cc:3033-3039`).

    Resolution criterion: correct the deviation count and qualify the current thenable behavior by platform; ensure the replacement conformance corpus covers Windows.

4. **Cross-document findings** (contradictions/dangling deps with 0022/0023/0025)

1. **Contradiction — cancellation algebra.** LLP 0024 says every request yields accepted/unavailable/failed (`llp/0024-structured-evaluation-and-session.spec.md:289-299`), while LLP 0025 explicitly adds “or not at all” when a catchable Hermes break is swallowed (`llp/0025-terminal-session-ownership.spec.md:286-294`). LLP 0024’s own OQ3 admits this (`0024:561-565`). One shared state machine must distinguish pending/defeated requests from eventual evaluation outcomes.

2. **Contradiction — `eval` is both specified and forbidden.** LLP 0024 gives direct/indirect eval session semantics (`0024:362-365`), while LLP 0022 says prompt and package code gain no `eval` or `new Function` (`llp/0022-repl-behavior-and-semantics.spec.md:121-123`), consistent with LLP 0021’s deny-only VM/eval posture (`llp/0021-capsec-effect-model-migration.plan.md:308-316`). Choose one profile contract and fixture it.

3. **Dangling dependency — value handles versus the supervisor process.** LLP 0024 delivers engine-owned value handles and original async values (`0024:249-278,444-451`); LLP 0025 makes a separate supervisor process presumptive and gives it rendering/output ownership (`0025:167-199,300-324`). The documents need an IPC schema, handle lifetime model, worker-side inspection rule, and display acknowledgement for `$_`.

4. **Dangling dependency — virtual referrer and `.load` identity.** LLP 0024 calls the referrer a logical path (`0024:84-95`), while LLP 0023 forbids text as an authorization/resolution key and requires typed logical identity (`llp/0023-virtual-filesystem-namespace.spec.md:114-125,401-409`). `.load` simultaneously uses `repl:<n>` and promises virtual-path diagnostics (`0024:103-110,473-476`). Define the retained identity, capture time, source URL, source-map source, and display spelling.

5. **Contradiction/dangling dependency — program stdin and `require.main`.** LLP 0022 makes stdin an ESM-style module but says `require.main` names `ibex:stdin` (`0022:203-210`). LLP 0024 gives ESM only `import.meta` globals and admits `require` explicitly for CJS and Script inputs (`0024:169-172,200-207`). State whether program ESM receives a nonstandard `require`, or define a synthetic main record visible only from imported CJS.

6. **Dangling dependency — authority-bearing imports on one-shot surfaces.** LLP 0022’s mandatory pre-evaluation rejection table covers prompt, `.load`, transcript, and program stdin (`0022:301-318`), but not `-e`, `-p`, or `ibex eval`, which LLP 0024 includes (`0024:65-70`). Assign this rule to the shared evaluation ingress and cover every mode.

7. **Duplication/ownership ambiguity — environment configuration.** LLP 0024 retires the await timeout (`0024:280-287`) and repeats a no-post-arming inventory in AC9 (`:496-500`); LLP 0025 owns startup capture and repeats the same categories (`0025:133-146,425-427`). Centralize the inventory and state explicitly that the await timeout is ignored even when present at launch.

8. **Duplication — module identity.** LLP 0023 owns retained-object module identity and its fixture (`0023:149-165,477-482`). LLP 0024 repeats both almost verbatim (`0024:394-403,513-516`). Leave identity semantics in LLP 0023; LLP 0024 should specify only cache lifetime and `.load`’s no-cache behavior.

9. **Observable ambiguity — asynchronous listener precedence.** LLP 0024 says admitted user listeners suppress runtime double-reporting (`0024:453-458`), while LLP 0022 says background failures are reported once above the prompt without qualification (`0022:277-280`). Pin whether listeners exist in the initial profile and what “reported once” means.

10. **Dangling authenticated-context seam.** LLP 0022 says ingress supplies the armed snapshot, authenticated root identity, source goal, and endowments (`0022:104-125`). LLP 0024’s mandatory request has only a bare `principal` and no snapshot/context handle (`0024:82-99`). Define whether these are immutable runtime state or an unforgeable per-request context; callers must not be able to supply a spoofable principal enum.

5. **Suggestions**

- Model session state with binding generations. Each input gets a provisional generation; the current-name index switches atomically on commit and restores on abort. Closures retain direct cell/generation handles, so old and escaped orphan cells remain meaningful. This cleanly expresses replacement and rollback, though `eval` and `globalThis` likely still require Hermes support.

- Introduce two result channels for TLA: a non-thenable control completion used only to signal settlement, and a rooted value slot carrying the untouched user completion. This makes non-assimilation structural.

- Prefer a native “safe snapshot capsule” over many piecemeal introspection calls. It should return a bounded immutable tree of primitive payloads and rooted descriptor-value handles, marking Proxy/HostObject/unsupported exotics opaque.

- Make the API types explicit: `SourceRequest`, `AuthenticatedEvaluationContext`, `EvaluationHandle`, `EvaluationOutcome`, `ValueHandle`, `AsyncFailureEvent`, and `InspectionTree`. Treat their ownership and threading rules as part of the Spec.

- Create three separate corpora:

  - Session-state transitions and ECMAScript completions.
  - Script-plus-extensions parsing/lowering and dependency-TLA rejection.
  - ABI, handle lifetime, inspection safety, cancellation, and asynchronous events.

  LLP 0019’s corpus should remain responsible only for its Hermes-compat transform.

- Consider keeping direct/indirect eval closed in v1. That is nonstandard, but it is already the security posture and removes the hardest source-transform equivalence problem. If interactive eval is a product requirement, native environment-record support is likely preferable to ever more invasive identifier rewriting.

- Consider preflighting the statically discoverable dependency graph for TLA before executing the entry. It would make the “unsupported dependency TLA” error deterministic and avoid partially executing parents merely because their textual `require()` precedes the failing dependency.

6. **Open questions**

1. After a failed lexical replacement, is the previous binding restored, removed, or superseded by another state?

2. What is the complete old-kind/new-kind matrix, especially `var`/function reuse, import collisions, and object-only global properties?

3. Are direct eval, indirect eval, and `Function` available in the initial profile? If so, which mechanism implements their cell semantics?

4. What is the exact property-to-cell relationship for deletion, `defineProperty`, accessors, undeclared assignment, and `var`→lexical replacement?

5. Will empty completions come from a Hermes Completion Record patch or source instrumentation?

6. Do static imports instantiate before the Script body, or execute as textual-position synchronous requires? When is the snapshot binding captured?

7. Is dependency TLA rejected during graph preflight or at first attempted load, and what partial effects/cache state are permitted?

8. Which process owns value handles and inspection under the supervisor/worker architecture, and how does successful display acknowledge `$_`?

9. Is type-tag-only display the v1 release contract, or is a native primitive required? What are the exact limits, ordering rules, and truncation marker?

10. Which parser/version is normative, and must SWC and Oxc be fully parse-equivalent across every source goal and dialect?

11. How is the singular “owning principal” selected from LLP 0021’s complete constrained-principal set for cross-principal promise chains and deputy work?

12. What exact state distinguishes a TLA-unit rejection from an unrelated microtask or background callback failure drained during the same native call?

7. **Readiness verdict**

The high-level defaults are worth preserving, but unresolved algorithmic, ABI, transform-feasibility, safety, and sibling-coherence issues prevent this from serving as a normative implementation contract.

VERDICT: NOT READY

### Orchestrator verification notes

Every decisive claim in the review above was independently checked against the
repository and, where it concerned engine behavior, against the bundled shipping
engine (`tools/hermes/hermes`) and the Node/Deno/Bun REPLs. Findings:

**Confirmed (code).**

- `Engine::eval` is `&str -> Result<Option<String>>` (`src/bin/ibex/engine/mod.rs:34`);
  the FFI is an untagged NUL-terminated `*mut *mut c_char`
  (`src/bin/ibex/engine/hermes.rs:87-95`); `undefined` becomes a null pointer
  (`src/engine/hermes_runtime.cc:3161-3164`) that Rust maps to `Ok(None)`
  (`hermes.rs:911-917`). Empty completion and `undefined` are indeed indistinguishable.
- `<eval>` is hardcoded (`hermes.rs:1517,1524`; C++ default at `hermes_runtime.cc:2960`).
- The unwrap shim gets and calls `p.then` (`hermes_runtime.cc:3044-3057`).
- `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` is `getenv`'d *inside* the eval call with a hidden
  10 000 ms default (`hermes_runtime.cc:3089-3100`).
- **Concern 5 (LLP 0019 mischaracterization) — confirmed, and it is the sharpest
  finding in the review.** LLP 0019's two tiers are the *Hermes-compat `for...of`
  / async-generator rewrite*: Tier 1 is the build-time AST authority
  `packages/ibex-devtools/src/scripts/hermes-compat.mjs`; Tier 2 is the embedded
  bootstrap string scanner in `src/engine/bootstrap/module-loader.js` (LLP 0019
  §Tier 1, §Tier 2). The TypeScript/ESM→CJS lowering this document actually needs
  is `src/module_loader/transpile.rs` (SWC default, Oxc candidate) — neither tier.
  §4's "the in-process runtime transform tier — the same tier that handles
  on-the-fly file transpilation" was a category error, and "join the LLP 0019
  corpus over the same fixtures" would have gated none of this document's
  obligations, since that corpus pins for-of/async-generator behavior only.
- **Concern 6 (dependency-TLA routing) — confirmed.** SWC passes TLA through
  untouched (`transpile.rs:99-101`); Oxc bails unconditionally with an ad-hoc
  message (`transpile.rs:212-217`); and `source_needs_async_downlevel` does not
  detect plain top-level `await` at all (`src/module_loader/mod.rs:286-295`). The
  two engines disagree, and neither emits the stable named error §3 requires.
- **Concern 8 (stage-1 inspection unsafe) — confirmed.** `[Function: name]` reads
  `name` and `[Array(3)]` reads `length`; both are Proxy-trappable. Native
  `valueToString` additionally performs `message`/`stack` Gets and
  `JSON.stringify`/`toString` (`hermes_runtime.cc:493-537`).
- **Concern 9 (`$_` polling) — confirmed.** Descriptor polling cannot see a
  same-value write or a `defineProperty` ABA. Current code just assigns
  `globalThis.$_` (`repl/mod.rs:64,70,76`).
- Concern 4's `EngineFeature` point — confirmed: `TopLevelAwait`, `EsmModules`,
  and `CommonJsModules` all report `false` (`hermes.rs:1653-1661`), conflating
  *native engine* capability with *end-to-end evaluator* capability.
- Concern 11's listener point — confirmed: `disposeAsyncCallbackError` sets
  `fatal_async_error` so the next poll returns −1 (`hermes_runtime.cc:673-692`),
  and the `JSError` catch path can convert a throw into a success/empty result
  (`hermes_runtime.cc:3178-3193`).
- Minor concern 13 — confirmed on both counts: §7 lists three deviations while
  §Consequences said "four", and the thenable unwrap is compiled out on Windows
  (`#if !defined(_WIN32)`, `hermes_runtime.cc:3032`).

**Confirmed (engine probes, `tools/hermes/hermes`).** These bear on concerns 1–3
and 5: shipping Hermes has **no TDZ** (a `let` read before its declaration yields
`undefined`), reports `const` reassignment as a **compile-time** error rather than
a runtime `TypeError`, rejects `with` outright, gives direct `eval` **no lexical
scope** ("Direct call to eval(), but lexical scope is not supported"), captures
`3,3,3` from `for (let i…)` closures, and makes a global `var` **non-configurable**.

**Adopted with a different frame.**

- Concern 2 (eval): the review is right that a source-rewriting mechanism cannot
  transparently handle dynamically introduced `var`, indirect-eval source, or
  `Function` source. The resolution taken is the one the review offers as its
  alternative — `eval`/`Function` are already **closed** by LLP 0022 §1 and
  LLP 0021, so §7's direct/indirect-eval clause was dead text that contradicted a
  sibling *and* the engine. It is deleted, and the closure is stated explicitly.
- Concern 12 (open normative choices): accepted for the parser version, the
  bounds, and `.load`-by-extension. **Partially rejected** for the inspection
  stage: this document specifies *both* strata normatively; which stratum a
  release ships is LLP 0022 OQ1's gate, not this document's. OQ2 is narrowed to
  the engine-feasibility question rather than the release question.
- Cross-doc 8 (module-identity duplication): accepted. LLP 0023 §2 now owns
  identity; §7 keeps only cache lifetime, the cross-principal instance
  consequence, and `.load`'s no-cache rule.

**Refuted / not adopted.**

- Concern 1's implication (shared with the Fable review) that cell *replacement
  with old-closure staleness* is a sound default. It is not, and the code
  disagrees: under that rule `var v = 1; const g = () => v; var v = 2; g()` yields
  `1`, but every conforming JavaScript engine yields `2` (a `var` redeclaration is
  the same binding). I probed the precedent directly — Deno 2.9.1 and Bun 1.3.12
  both yield **2** for the `let`/closure/redeclare sequence, and Node 25 refuses
  cross-input `let` redeclaration as a `SyntaxError` outright. So *every* REPL that
  permits redeclaration makes it visible to earlier closures. The revision
  therefore replaces cell-capture with **late binding by name through the session
  record**, which keeps the flagship shared-cell result, keeps `const` immutable
  against assignment (Deno confirms `TypeError`), fixes `var`, and makes rollback
  coherent. I verified on the shipping Hermes binary that a checked-cell record
  delivers exactly this — shared cells, late-bound redeclaration, a **runtime**
  `const` `TypeError`, and a real TDZ `ReferenceError` — none of which Hermes
  provides natively. OQ1's claim that the mechanisms are "observably
  interchangeable" was false and is retired: the rewrite is now named as the v1
  mechanism.


## Round 2 — 2026-07-12

**Reviewer family:** Codex (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra`
**Codex session id:** `019f5598-109c-7b01-abdb-181d789a0270`
**Revision under review:** `33b29b0e83d4` — the first 12 hex digits of
`shasum -a 256` over the target file, *not* a Git object. (The reviewer noted it
could not resolve it as a Git blob; that is expected, and the convention is
recorded here so no later reader mistakes it for one.)
**Redaction:** none.
**Independence:** launched concurrently with the Fable reviewer on the same
revision, in a separate process with no shared context. **Both round-1 artifacts
were moved out of `llp/reviews/` before launch and restored only after both
round-2 reviews were in**, so neither reviewer could see the previous round or
each other.
**Sibling drift (material to this round):** between round 1 and round 2 the
sibling corpus was revised concurrently by other work — LLP 0022 grew from 580 to
866 lines and LLP 0025 from 507 to 858. This reviewer therefore read siblings that
had changed under the target, which is why several of its cross-document findings
are new and correct: LLP 0022 had newly *closed* `require.main`, newly pinned
`.load` of JSON to display, and newly obliged LLP 0024 §6 to carry a fifth
lifecycle outcome. The findings are recorded as made.
**Method:** read the full target, the sibling corpus (0022, 0023, 0025) and the
governing LLPs (0002, 0003, 0004, 0019, 0021), then verified load-bearing claims
against the engine, module-loader, REPL, and inspection sources.

### Verbatim review

1. **Overall assessment**

This is a strong architectural direction with unusually good defaults: late-bound session cells, runtime-enforced `const`, entry-only TLA, non-assimilating results, and type-tag-only inspection are all defensible choices for Hermes.

It is not yet ready as a normative Spec. The cell model still lacks the abstract operations needed for two independent implementers to agree on ordinary globals, strict assignment, `typeof`, descriptors, same-input collisions, TypeScript declarations, and rollback. The Script-plus-import/TLA grammar has no demonstrated parser route, dynamic-import preflight is impossible as written, and the ABI and inspection tree are descriptions rather than interoperable schemas. Several sibling contracts also directly contradict it.

Revision note: `33b29b0e83d4` is not resolvable as a Git object in this checkout. I reviewed the entire 1,014-line on-disk target, whose Git blob is `e70eb7c09e34a794c17fcf5930c215c7b42881e4`.

2. **Strengths**

- The diagnosis of the current seam is accurate. The engine accepts only `&str` and returns `Result<Option<String>>` ([engine/mod.rs:22–39](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); Hermes hardcodes `<eval>` ([hermes.rs:1515–1525](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1515)); and `undefined` becomes a null pointer, then `None` ([hermes_runtime.cc:3161–3174](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3161), [hermes.rs:911–917](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:911)). LLP 0024 §6 correctly replaces this with completion-record outcomes ([0024:395–449](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:395)).

- The session defaults are good decisions. Shared observation of later writes, late binding by name, runtime `const` enforcement, and redeclaration as replacement rather than assignment are clearly chosen and fixture-oriented ([0024 §7.1–7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:528)). In particular, preserving `const` immutability while allowing cross-input redeclaration is better than silently making prior constants writable.

- Entry-only TLA is the honest v1 boundary for a synchronous loader ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:227)). Current SWC passes TLA through, Oxc emits a separate ad hoc rejection, and the downlevel trigger misses plain TLA ([transpile.rs:97–102](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97), [transpile.rs:211–217](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:211), [module_loader/mod.rs:278–295](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:278)). Refusing to pretend this is an async module graph is correct.

- The requirement that imports/TLA not re-goal a sloppy Script is semantically right ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:200)). Preserving directive prologues, top-level `this`, undeclared assignment, and completion values avoids a large class of invisible compatibility bugs.

- §4 now correctly separates the in-process TypeScript/ESM lowering from LLP 0019’s two Hermes-compat tiers ([0024:355–381](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:355), [0019:10–36](/Users/ccheever/projects/ibex/llp/0019-hermes-compat-transform-authority.decision.md:10)). The current pipeline indeed performs type stripping and CommonJS lowering in-process ([transpile.rs:147–179](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:147)).

- The non-assimilation contract and private settlement token are excellent. Current native code reads `p.then` and invokes it for every object result ([hermes_runtime.cc:3033–3058](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033)), consults an environment timeout during evaluation ([hermes_runtime.cc:3081–3100](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3081)), and omits the whole shim on Windows. §6’s out-of-band value slot structurally eliminates that defect ([0024:451–478](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:451)).

- Staged inspection is the right safety posture. Current native formatting reads properties, invokes `JSON.stringify`, and falls back to coercion ([hermes_runtime.cc:493–537](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:493)); current TypeScript inspection reads function names, probes thenables, enumerates keys, and invokes Proxy-sensitive reflection ([inspect.ts:86–143](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:86), [inspect.ts:353–445](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:353)). Shipping inert type tags until a native primitive exists is an excellent default ([0024 §8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:741)).

- The parser-grade completeness and behavior-first corpus requirements are strong. The current REPL uses a hand-written bracket/string scanner ([repl/mod.rs:486–563](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:486)), while §4–§5 require parser equivalence and behavioral fixtures rather than textual-shape assertions ([0024:367–393](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:367)).

3. **Concerns**

1. **Blocking — free-name resolution is not a complete algorithm.**  
   Evidence: §7.2 says every free identifier resolves through the session record and an absent cell throws `ReferenceError` ([0024:542–570](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:542)). That leaves no stated fallback or precedence for ordinary realm globals and endowments such as `Object`, `Promise`, `console`, `globalThis`, or `require`; the current engine uses a substantial ordinary global object ([hermes_runtime.cc:493–512](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:493), [hermes_runtime.cc:2851–2853](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2851)). The model also omits `typeof missing`, strict versus sloppy unresolvable assignment, compound/update/logical assignment, destructuring assignment, `for (x of y)`, and identifier deletion.  
   Resolution criterion: specify normative `ResolveBinding`, `Get`, `Set(strict)`, `Initialize`, `Typeof`, and `Delete` operations, including precedence among input-local scopes, session cells, the ordinary global-object record, and an unresolvable reference. Add fixtures for nested shadowing, class/function self-references, all assignment forms, builtins, inherited globals, and strict/sloppy behavior.

2. **Blocking — `globalThis` reflection is internally inconsistent and lacks a storage algorithm.**  
   Evidence: §7.3 requires `var`→lexical replacement to delete the global property, while §7.5 permits `Object.defineProperty` over a `var` cell and requires deletion, property assignment, and identifier lookup to remain synchronized ([0024:589–658](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:589)). A successful `defineProperty(..., {configurable:false})`, `preventExtensions`, or `freeze` can make the required later replacement impossible. The document does not say whether an installed accessor controls identifier reads, how property-only globals interact with cells, or how mutations are journaled during a failed input. Current REPL import persistence simply writes ordinary global properties ([repl/mod.rs:1080–1167](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1080)).  
   Resolution criterion: define the relationship between cell operations and the global object’s `[[Get]]`, `[[Set]]`, `[[DefineOwnProperty]]`, and `[[Delete]]`, including non-configurable descriptors, property-only globals, saved aliases, and rollback. Demonstrate either a native global-environment hook or explicitly pin every accessor/polling deviation.

3. **Blocking — declaration instantiation does not cover same-input semantics.**  
   Evidence: §7.3 gives a cross-input matrix but not whole-input validation and collection ([0024:572–604](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:572)). It does not decide duplicate lexical declarations, `let`/`var` and import collisions, duplicate destructuring targets, block-contained global `var`, `for (var …)`, or sloppy Annex B block functions. Sequentially applying the cross-input matrix would produce the wrong result for several of these.  
   Resolution criterion: define declaration collection using explicit `VarDeclaredNames`/`LexicallyDeclaredNames`-equivalent operations, validate the complete input before mutating cells, state the Annex B policy, and specify function/import/declaration initialization order. Add exhaustive same-input collision fixtures.

4. **Material — runtime-bearing TypeScript declarations have no session semantics.**  
   Evidence: §4 admits a pinned TypeScript grammar, while §7’s cell kinds cover only JavaScript declarations and imports ([0024:286–353](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:286), [0024:528–532](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:528)). `enum`, runtime `namespace`, `import =`, `using`, and `await using` are not type-only. Current SWC applies TypeScript lowering before CommonJS lowering ([transpile.rs:147–179](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:147)), and the loader already treats `using` forms as runtime transform triggers ([module_loader/mod.rs:284–295](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:284)). Collecting declarations before versus after lowering changes persistence, merging, completion, disposal, and rollback.  
   Resolution criterion: either reject these constructs in v1 or specify their transform order, cell classification, redeclaration, disposal, completion, and failure behavior. Pin transformer semantics and options, not just the parser version.

5. **Material — import failure conflicts with rollback.**  
   Evidence: §3 says a throwing hoisted import means the input “publishes nothing” ([0024:260–267](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:260)), while §7.4 says newly declared `var` and `function` cells survive any abrupt completion ([0024:618–640](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:618)). For `import "./boom"; var x`, both cannot hold unless import evaluation precedes declaration instantiation, which is not stated.  
   Resolution criterion: specify the exact phases—graph preflight, import linking/evaluation, session declaration instantiation, and statement evaluation—and decide whether this example leaves `x`. Update both prose and acceptance fixtures.

6. **Blocking — dynamic-import graph preflight is impossible as written.**  
   Evidence: §3 limits preflight to the statically discoverable graph but requires one error across static, dynamic, and transitive imports ([0024:242–254](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:242)); AC8 then requires the dynamic-import TLA error to be raised by graph preflight before entry execution ([0024:891–897](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:891)). A computed `import("./" + name)` cannot be known then. The current loader resolves and loads requests incrementally ([module_loader/mod.rs:162–247](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:162)).  
   Resolution criterion: preflight static edges and optionally literal dynamic edges; require computed dynamic imports to reject before the selected dependency executes or mutates its cache, but acknowledge that prior entry effects stand. Alternatively, close computed dynamic import in v1.

7. **Blocking — the Script-plus-import/TLA parser route is unspecified.**  
   Evidence: §3 correctly forbids parsing as Module and trying to restore Script semantics later ([0024:202–217](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:202)), but §4 pins the current parser without identifying a Script grammar extension. Current code uses `parse_program()` and then CommonJS lowering, with `Syntax::Typescript` even for JavaScript extensions ([transpile.rs:109–136](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:109), [transpile.rs:166–179](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:166)). The proposal also does not resolve whether `await` remains a valid sloppy-script identifier when TLA is admitted.  
   Resolution criterion: specify and prototype a parser fork, extension mode, or independent Script early-error validator before acceptance. Pin fixtures for legacy octal, duplicate parameters, `delete identifier`, `await` bindings, directive prologues, `import.meta`, and every supported dialect.

8. **Material — source maps do not cover the complete transform pipeline.**  
   Evidence: §2 requires positions to survive all wrapping and lowering, while §4 says the LLP 0019 rewrite runs afterward and is “unaffected” ([0024:194–198](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:194), [0024:355–365](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:355)). The current SWC emitter supplies no source-map writer ([transpile.rs:183–193](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:183)), and the later LLP 0019 scanner is line-shape-sensitive with accepted bails ([0019:113–138](/Users/ccheever/projects/ibex/llp/0019-hermes-compat-transform-authority.decision.md:113)). Current error rewriting only looks for adjacent filesystem `.map` files, which cannot represent `repl:n` in-memory sources ([hermes.rs:1161–1209](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1161)).  
   Resolution criterion: define the complete ordered pipeline, an in-memory source-map registry, and map composition through every later rewrite. Add combined session/TLA/import/for-of fixtures through the real engine.

9. **Material — the claimed executable deviation gate lacks a viable oracle.**  
   Evidence: §7.7 calls deviations (a)–(e) exhaustive and proposes replaying inputs as one growing script ([0024:673–699](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:673)). The reviewed document therefore has five deviations, not the three mentioned in the review prompt. A literal growing script cannot parse deliberate cross-input lexical redeclarations, and §7.6 separately admits engine behavior without block TDZ and per-iteration bindings. LLP 0019 also retains a pinned capture-last hole.  
   Resolution criterion: scope “exhaustive” explicitly to session-record behavior and define an evaluator-independent reference machine. Use explicit transcript expectations for deliberate deviations and differential testing against a standards engine only where the comparison program is valid.

10. **Blocking — §6 calls itself an ABI but does not specify one.**  
    Evidence: the proposed ABI has no numeric tags, concrete C layouts, version field, allocation rules, retain/release functions, stale/wrong-runtime error behavior, cancellation entry point, or sequence/evaluation identifiers ([0024:395–449](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:395)). The current ABI’s exact shape is a `char **` result with no length ([hermes.rs:87–95](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:87), [hermes_runtime.cc:2924–2943](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2924)); JavaScript throws, bytecode rejection, and C++ faults all share status `1` plus the same string channel ([hermes_runtime.cc:3178–3238](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3178)).  
    Resolution criterion: land a normative LLP 0002 amendment or ABI annex with layouts, discriminants, functions, ownership, thread/runtime checks, allocation-failure behavior, and version negotiation. Verify it from an independent C consumer, including embedded NULs, OOM/no-payload, stale handles, and cancellation races.

11. **Material — cancellation is vocabulary, not yet a race/state machine.**  
    Evidence: §6 defines accepted/unavailable/failed/defeated but not the relationship between the cancellation request and the evaluation’s `cancelled` outcome, normal completion racing cancellation, runtime destruction, or a swallowed break followed by eventual normal return ([0024:437–499](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:437)). Current evaluation holds both the Tokio runtime mutex and native FFI lock for the whole call ([hermes.rs:869–896](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869), [hermes.rs:542–563](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542)); no cancellation API exists.  
    Resolution criterion: specify a concurrent state machine with one terminal result per request and evaluation, including late return after a defeated attempt. It is acceptable for v1 to return `unavailable`, provided that answer is prompt and independently deliverable.

12. **Material — the inspection tree and bounds are not normative enough for interoperability.**  
    Evidence: §8 names only `kind`, payload, and optional children, while leaving node enums, key representation, string encoding, cycle nodes, truncation nodes, ordering, and all numeric limits open ([0024:797–814](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:797), [0024 OQ6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1011)). Stage 1 also does not say whether it uses native intrinsics or captured untamperable primordials; `Array.isArray` on a revoked Proxy can throw even though it runs no trap.  
    Resolution criterion: add a closed, versioned schema and constants annex, including encoding of lone surrogates, cycle/reference representation, deterministic key ordering, and revoked-Proxy fallback. Specify that realm-global monkeypatching cannot alter classification.

13. **Material — asynchronous ownership, sequencing, and overflow are not algorithms.**  
    Evidence: §9 requires authenticated owning principal, evaluation association, shared sequencing, backpressure, coalescing, and reported drops without defining how any are assigned ([0024:816–853](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:816)). This is subtle in current code: timers scope a captured principal only around the callback and deliberately remove it before detached microtasks drain ([hermes_runtime.cc:3653–3683](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3653)), while generic callbacks fall back to logging and a fatal flag ([hermes_runtime.cc:946–984](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:946)). Blocking the runtime thread on a full queue could deadlock, and dropped handle ownership is unspecified.  
    Resolution criterion: define provenance for each scheduling source, a single sequence allocator, nonblocking overflow/coalescing rules, explicit drop-marker ordering, and automatic release of dropped handles. Test cross-principal promises, timers, next ticks, native completions, rethrows, and storms.

14. **Material — omitting `eval` semantics is valid only if closure is a proved ingress precondition.**  
    Evidence: §7.3 delegates closure of direct/indirect `eval` and `Function` to LLPs 0022/0021 ([0024:609–616](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:609)). Current Hermes is created with eval enabled ([hermes_runtime.cc:2788–2793](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2788)), and evaluator taming is inside an environment-gated lockdown branch ([hermes_runtime.cc:2398–2454](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2398)).  
    Resolution criterion: make successful proof of the closed profile a precondition for session submission and add fixtures for direct eval, indirect aliases, global `Function`, and every reachable `%Function%` constructor. Otherwise the Spec must define their interaction with session cells.

15. **Material — `.mts` and `.cts` receive an unexplained asymmetric policy.**  
    Evidence: §4 rejects `.mjs` and `.cjs` from `.load` because they assert module kind, but permits `.mts` and `.cts` as sloppy script inputs ([0024:331–339](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:331)). Those are the corresponding TypeScript module-kind assertions. Current helper classification is itself inconsistent, treating `.mts` differently from `.mjs` in one path ([module_loader/mod.rs:982–991](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:982)).  
    Resolution criterion: either reject `.mts`/`.cts` symmetrically or explicitly justify, name, and fixture the divergence.

4. **Cross-document findings**

1. **Blocking — `.load` JSON has opposite contracts.** LLP 0024 requires a hard error ([0024:331–339](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:331)); LLP 0022 requires parsing and displaying the JSON value without declarations ([0022:561–564](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:561), [0022:731–736](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:731)). Choose one and update both acceptance suites.

2. **Blocking — `require.main` is exposed and closed simultaneously.** LLP 0024 says it names `ibex:stdin` ([0024:325–329](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:325)); LLP 0022 keeps `require.main`, `process.mainModule`, and `require.cache` closed and says program stdin has none ([0022:161–170](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:161), [0022:278–285](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:278)). If closure is intended, the main-module flag should feed only `import.meta.main`.

3. **Blocking — the outcome type omits LLP 0025’s lifecycle completion.** LLP 0024 has four outcomes ([0024:395–405](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:395)); LLP 0025 requires a fifth, uncatchable lifecycle request for `process.exit(n)` ([0025:560–575](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:560)); LLP 0022 records the omission explicitly ([0022:616–640](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:616)). Add the discriminant and define its transaction, TLA, sequencing, and handle behavior.

4. **Material — the display schema is duplicated with conflicting ownership.** LLP 0024 says the tree never carries styling and claims ownership ([0024:797–803](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:797)); LLP 0025 says it pins a display IR containing trusted style and layout tokens ([0025:237–260](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:237)). Define two explicit layers—semantic inspection tree and renderer IR—or choose one owner.

5. **Material — cancellation premises conflict.** LLP 0024 states that a Hermes-style break is catchable and uses that as the defeated case ([0024:480–495](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:480)); LLP 0025 explicitly refuses to assert catchability and includes no-break-check and non-returning-native defeat modes ([0025:456–494](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:456)). LLP 0025 also requires background-callback targets that LLP 0024 does not admit. Use an engine-independent defeated definition and align both state machines.

6. **Material — authenticated ingress fields and error taxonomy are dangling.** LLP 0022 requires an opaque armed-session binding and submission provenance binding the digest, nonce, root, source identity, and ingress kind ([0022:148–155](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:148), [0022:478–492](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:478)); LLP 0024’s authenticated context does not include those values ([0024:135–160](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:135)). LLP 0022 also assigns the distinct out-of-snapshot error to LLP 0024 §2, which defines only identity and reserved-scheme errors ([0022:634–639](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:634), [0024:167–198](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:167)). Add the fields and taxonomy or reassign ownership explicitly.

7. **Material — display acknowledgement, sequencing, and worker handle ownership are unresolved across all three siblings.** LLP 0024 says `$_` updates on display acknowledgement but defines no acknowledgement operation ([0024:701–726](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:701)); LLP 0022’s ledger marks the seam missing ([0022:639–641](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:639)); LLP 0025’s broker has no return protocol ([0025:275–312](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:275)). LLP 0024 also says handles stay in the worker, yet §9 gives the “consumer” the original handle, while LLP 0025 says the session layer never receives one. Define separate worker and wire events, one sequence allocator, the exact acknowledgement point, and handle release timing.

8. **Material — rollback depends on serialization owned only by LLP 0022.** LLP 0024 defines rollback relative to “the start of the input” ([0024:618–640](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:618)); only LLP 0022 says evaluations are serialized ([0022:386–388](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:386)). The shared embedder/session-submit contract must itself require one in-flight input per session, including while TLA is suspended, or define concurrency conflicts.

9. **Material — internal module cache and JavaScript cache exposure are blurred.** LLP 0024 specifies an internal persistent cache ([0024:728–739](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:728)); LLP 0022 closes `require.cache` ([0022:161–170](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:161)); LLP 0023 nevertheless gives `require.cache` keys a normative virtual spelling ([0023:368–376](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:368)). Mark the 0023 row as conditional on a future admitted facade or remove it.

10. **Material — bounds remain duplicated and unowned.** LLP 0024 leaves inspection, completion, input, and storm bounds open ([0024:1011–1014](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1011)); LLP 0022 nevertheless promises byte-deterministic transcripts and records the missing dependency ([0022:299–304](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:299), [0022:641](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:641)); LLP 0025 leaves the larger budget set open too ([0025:847–856](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:847)). Land one shared constants annex before claiming deterministic fixtures.

11. **Minor/Non-blocking — `.load` extension coverage drifts.** LLP 0022 explicitly refuses unknown and extensionless files ([0022:561–564](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:561)); LLP 0024 does not dispose those cases explicitly. `$_` also begins `undefined` only in LLP 0022, while LLP 0024 does not state its initial cell flag/value.

12. **Minor/Non-blocking — several seam references are already stale.** LLP 0022 OQ1 points to LLP 0024 OQ2, but inspection is OQ1; LLP 0024 OQ6 and LLP 0022’s ledger point to LLP 0025 OQ5, but bounds are OQ6; LLP 0022’s ledger cites LLP 0025 AC4 for interruption, but interruption is AC7. These should be generated or checked rather than manually mirrored.

5. **Suggestions**

- Model the session as a transactional analogue of ECMAScript’s `GlobalEnvironmentRecord`: a declarative cell record, an object/global record, explicit binding operations, and a per-input replacement overlay.

- Consider a small Hermes `SessionEnvironmentRecord` or compiler-level binding hook instead of source-lowering every JavaScript `Reference` operation. Ibex already carries engine patches; a native environment abstraction may be less risky than reproducing `typeof`, strict assignment, descriptors, Annex B, and global property synchronization in SWC.

- Build a tiny executable reference machine for session cells and generate tests from it. Differentially fuzz no-deviation cases against a standards engine and replay all fixtures through real Ibex/Hermes.

- Have the transform emit a dependency manifest containing static edges, literal dynamic edges, source kind, role, and a TLA bit. Preflight that manifest recursively; treat computed imports as explicitly on-demand.

- Separate three schemas: engine outcome ABI, semantic inspection tree, and supervisor/rendering wire IR. Each should be versioned, length-bearing, and independently testable.

- Narrow v1 TypeScript if necessary. Supporting type annotations plus ordinary JavaScript declarations while initially rejecting namespaces, enums, `import =`, and resource-management syntax would be more honest than leaving their persistence semantics implicit.

- Generate a sibling seam matrix from machine-readable facts such as `.load` extension behavior, exposed globals, outcome tags, ownership, and bounds. Make contradictory rows fail `ref-check`.

6. **Open questions**

1. Does a missing session cell fall through to the ordinary global environment, and exactly when does a global property become a session `var` cell?

2. Can Hermes expose a native global-environment hook sufficient to implement cell/property synchronization and transactional replacement without observable accessor shims?

3. What are the same-input declaration and Annex B rules, including block-contained `var`, block functions, and import collisions?

4. Which runtime-bearing TypeScript constructs are in v1, and are declarations collected before or after TypeScript lowering?

5. What parser mechanism implements Script early errors plus static import and TLA, and is `await` still usable as an identifier?

6. Are computed dynamic imports supported? If so, what weaker preflight guarantee replaces “before entry executes”?

7. Does a throwing import run before or after session declaration instantiation, and what survives that failure?

8. What exact ABI and wire schemas carry source requests, lifecycle outcomes, evaluation IDs, sequence numbers, display acknowledgements, and async failures?

9. Is accepted in-place cancellation feasible on every advertised target, or should v1 explicitly return `unavailable` and rely on supervisor termination?

10. Does the safe-inspection contract cover only evaluator display/completion/errors, or also `console.log`, whose native formatter is currently unsafe?

11. Should `.mts`/`.cts` be rejected from `.load` like `.mjs`/`.cjs`?

12. Which sibling wins on `.load` JSON and `require.main`, and can those choices be moved into one generated behavior table?

7. **Readiness verdict**

The proposal has the right architecture and several excellent defaults, but unresolved binding semantics, parser feasibility, dynamic-import correctness, ABI/schema definition, and sibling contradictions are material and in several cases blocking.

VERDICT: NOT READY

### Orchestrator verification notes

**Confirmed (code / engine), and accepted.**

- **Blocking 1 (free-name resolution) — the most important finding of the round.**
  The previous draft's §7.2 said a free identifier with no cell throws
  `ReferenceError`, which would have made `Object` a `ReferenceError`. §7 is
  rewritten as a **modified ECMAScript `GlobalEnvironmentRecord`** — an object
  record on `globalThis` (holding `var`/`function` *and* the realm globals) plus a
  declarative record for lexicals — with the standard resolution order. `typeof`,
  sloppy undeclared assignment, and lexical/property coexistence now follow by
  construction rather than by re-derivation.
- **Blocking 2 (`globalThis` storage)** — accepted, and resolved the same way: the
  property *is* the storage, so accessors, `delete`, and `defineProperty` behave per
  object-environment semantics. The non-configurable/frozen case the review raised
  is real and now has a stated answer: a declaration requiring removal of a property
  user code made non-configurable fails in phase 3 with a `TypeError`, rather than
  silently diverging.
- **Blocking 3 (same-input semantics)** — accepted. §7.3 now enumerates the
  evaluation phases and puts declaration collection and same-input collisions
  (`VarDeclaredNames`/`LexicallyDeclaredNames`, Annex B) in a phase that **mutates
  nothing**, so a collision leaves the session untouched.
- **Material 4 (runtime-bearing TypeScript)** — accepted. Declarations are now
  collected *after* TypeScript lowering, so `enum`/`namespace`/`import =` arrive as
  `var` bindings; `using`/`await using` are refused at the top level of a script
  input, because scope-exit disposal cannot compose with a persistent session.
- **Material 5 (import failure vs rollback)** — accepted; this was a genuine
  self-contradiction. Phase-5 abrupt completion now publishes **nothing**, so
  `import "./boom"; var w` leaves no `w`, and §7.4's exception (i) is scoped to
  phase 6 only.
- **Blocking 6 (dynamic-import preflight)** — accepted and confirmed: a computed
  specifier is not statically discoverable. §3 now preflights static and
  literal-dynamic edges via a transform-emitted dependency manifest, and refuses a
  computed import **at call time with the same named error**, before the dependency
  evaluates or enters the cache — while stating plainly that prior entry effects
  stand. AC8 is split accordingly.
- **Blocking 7 (parser route)** — accepted. Verified: `parse_program` promotes to
  Module on seeing `import`, and the Module goal rejects sloppy-only parse forms. §3
  now names the gap, requires one of three concrete mechanisms, adds the sloppy-only
  *parse* forms to the fixture family (so a Module-goal implementation fails the
  corpus), and makes it open question 5. `await` is reserved at the top level of
  script inputs.
- **Material 8 (source maps)** — accepted: maps must **compose** through the
  LLP 0019 rewrite that runs afterwards, and must live in an in-memory registry,
  since the current machinery reads adjacent `.map` files and cannot represent
  `repl:<n>`.
- **Material 9 (oracle)** — accepted, and it was a real hole: a session that *uses*
  deviation (a) is not a legal Script and cannot be replayed as one. §7.7 now scopes
  the oracle to redeclaration-free, failure-free, import-free, TLA-free sessions and
  pins everything else with direct per-input fixtures.
- **Blocking 10 (ABI)** — accepted at the right altitude: §6 fixes the *semantics*
  (five discriminants, handle ownership, fault/throw split, concurrency), and names
  the byte-level schema as the **LLP 0002 amendment's deliverable**, verified from an
  independent C consumer over embedded-NUL, OOM, stale-handle, and cancellation-race
  cases. Inlining C layouts into a design Spec would be the wrong altitude.
- **Material 11 (cancellation races)** — accepted; §6 now has one terminal result
  per request, with the normal-completion race, the post-settlement request, and
  runtime destruction each resolved.
- **Material 12 (inspection tree)** — accepted, and the revoked-Proxy point is
  **confirmed by probe**: `Array.isArray` throws `TypeError` on a revoked Proxy on
  the shipping engine. The toolkit is now stated as safe-but-not-total, with the
  throw caught and rendered `[Object]`, and primordials captured at bootstrap so
  monkeypatching cannot alter classification.
- **Material 13 (async provenance/sequencing)** — accepted: schedule-time principal
  per source, one sequence allocator, non-blocking overflow, explicit drop markers,
  handle release on drop.
- **Material 14 (eval closure as a precondition)** — accepted and confirmed: the
  runtime is created with eval enabled and taming lives in an env-gated lockdown
  branch. AC19 now requires the closure to be **proved** before submission.
- **Material 15 (`.mts`/`.cts` asymmetry)** — accepted; the four module-kind-
  asserting extensions are now refused symmetrically by `.load`.
- **Minor 13-equivalents** — the deviation count is five and internally consistent.

**Cross-document findings — all accepted, and all traced to live sibling text.**
`require.main` is retired from §4 (LLP 0022 §1 now closes it); `.load` of JSON now
displays the parsed value (LLP 0022 §8); the fifth **lifecycle** outcome is added
to §6 (LLP 0025 §8 requires it); the display-IR ownership is split (this document
owns the semantic inspection tree, LLP 0025 §3 owns the wire IR); the cancellation
premise no longer asserts catchability, matching LLP 0025 §6's three defeat modes;
submission provenance and the armed-session binding are added to §1's source
request; the out-of-snapshot error joins §2's taxonomy; §1 now states the
one-in-flight-input rule that §7.4's rollback depends on; and the stale
cross-references are corrected.

**Not adopted.**

- The suggestion to consider a native `SessionEnvironmentRecord` **instead of**
  source lowering is recorded as a design alternative but not taken for v1: it is a
  larger engine patch than the three slices §8 already depends on, and the lowering
  is proven to work on the shipping binary today. It remains the right answer if the
  patch program grows.
- Narrowing v1 TypeScript by rejecting `enum`/`namespace`/`import =` was not taken
  — collecting declarations after lowering gives them correct semantics for free.
  The `using` refusal *was* taken, because that one has no correct answer.


## Round 3 — 2026-07-12

**Reviewer family:** Codex / GPT (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`.
Run from the **main session** rather than from this orchestrator: a detached
`codex exec` launched from inside a subagent turn is killed when that turn ends,
which silently destroyed this round's first attempt (no output, no status file).
The run was therefore handed off to main, which owns a turn that outlives it.
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra` (confirmed in the log — no substitution)
**Codex session id:** `019f55bc-5e42-77f2-88d6-9fb774214ef6` (rollout on disk at
`~/.codex/sessions/2026/07/12/rollout-2026-07-12T02-50-36-019f55bc-….jsonl`)
**Revision under review:** `3071f3c6d074` (first 12 hex of `shasum -a 256` over
the target file — a content hash, not a Git object)
**Redaction:** none — run under the user's OpenAI account, authorized by the human
invocation of the refinement skill.
**Independence:** fresh non-interactive session with no access to this
orchestrating session, to the concurrent Fable round-3 review of the same
revision, or to any prior LLP 0024 artifact. Both earlier rounds' artifacts were
moved out of `llp/reviews/` for the duration and restored only after both round-3
reviews were in; the absence of 0024 files from `llp/reviews/` during the run was
verified independently by main.
**Method:** `brief-round3.md` verbatim. The brief explicitly instructed the
reviewer **not to trust the document's empirical claims** — the engine premises,
the revoked-Proxy behavior, and the Deno/Bun precedent — but to re-measure them,
after a false empirical claim survived round 1 by being taken on trust.

### Verbatim review

1. **Overall assessment**

The proposal is directionally strong but not ready as a normative Spec. Structured source requests, entry-only TLA, non-assimilating outcomes, a persistent environment, and staged trap-free inspection are all good decisions. However, §7 still permits contradictory results for ordinary global properties, inherited properties, rollback, callbacks during TLA, and several declaration forms. The parser strategy is also unresolved, Stage 1 contradicts the required throw outcome, and the sibling corpus has materially drifted.

I independently checked the requested empirical claims. Bundled Hermes 1.0.0/HBC 99 reproduces no TDZ, compile-time same-input `const` assignment failure, no `with`, no lexical direct eval, non-configurable global `var`, lexical non-persistence, and `3,3,3` loop capture. A revoked Proxy makes `Array.isArray` throw without invoking traps. Deno 2.9.1 and Bun 1.3.12 both produce `2` for the redeclaration probe; Deno enforces prior-input `const`, while Bun does not. None of those named observations was falsified.

I did find a different definite language error: duplicate targets are legal in `var` destructuring. I also found several empirical overstatements about the current ABI and what the Deno/Bun probe proves.

2. **Strengths**

- **Entry-only TLA is the right default for v1.** [§3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:287>) correctly refuses to fake an asynchronous dependency graph atop synchronous `require()`. The current code validates the premise: SWC passes TLA through, Oxc rejects it ad hoc, and the downlevel detector misses plain TLA ([transpile.rs:97](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97), [transpile.rs:211](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:211), [module_loader/mod.rs:278](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:278)).

- **Structured outcomes and non-assimilation directly address real defects.** [§6](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:496>) distinguishes empty completion, `undefined`, values, throws, cancellation, and lifecycle. The shipping seam currently assimilates arbitrary thenables by reading and calling `.then` ([hermes_runtime.cc:3033](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033)) and collapses results into nullable NUL-terminated strings ([hermes_runtime.cc:3161](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3161)).

- **The move from a flat cell map to a modified `GlobalEnvironmentRecord` is conceptually correct.** [§7.1–§7.3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:663>) recognizes lexical/property coexistence, late binding, declaration instantiation, TDZ, and cross-kind replacement. That is a much better foundation than copy-out publication.

- **Inspection is staged honestly.** [§8](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:993>) correctly admits that pure-JavaScript descriptor walking is unsafe for Proxies. The existing inspector demonstrably performs Gets, Proxy-visible enumeration, descriptor queries, method calls, and direct fallback reads ([inspect.ts:90](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:90), [inspect.ts:274](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:274), [inspect.ts:393](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:393)). Stage 1’s deliberately inert tags are a sound safety trade.

- **The acceptance criteria are unusually concrete.** [The fixture schema and ACs](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1166>) explicitly preserve input boundaries, outcome kinds, record deltas, global deltas, and display. That is the right test shape for session semantics.

- **The proposal correctly treats the ABI change as semver-major.** It explicitly assigns byte-level schema ownership to LLP 0002 rather than silently changing its narrow consumer contract, whose current five-function surface still exposes the old eval ABI ([LLP 0002](</Users/ccheever/projects/ibex/llp/0002-host-embedding-abi.spec.md:26>)).

3. **Concerns**

1. **Blocking — the object-record matrix is not the `GlobalEnvironmentRecord` it claims to be.**

   Evidence: [§7.1](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:663>) says ordinary properties without kind entries behave as `var` for every later rule, while [§7.3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:765>) deletes a `var` property when a lexical replaces it. That makes `globalThis.x = 1 ⏎ let x = 2` delete `globalThis.x`; an ordinary GER preserves the configurable property and lets the lexical shadow it. Bundled Hermes confirms the one-Script result is `x === 2` and `globalThis.x === 1`.

   The same model conflates inherited lookup with declared `var`: ordinary Script `var inheritedName` creates an own `undefined` property rather than reusing a prototype property. Likewise, deleting an own property need not make the identifier unresolvable—it can reveal an inherited property, contrary to §7.5. The current REPL’s raw `globalThis` persistence demonstrates that these descriptor distinctions are observable ([repl/mod.rs:1080](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1080)).

   Resolution criterion: distinguish at least session-declared `var`/`function`, ordinary own property, inherited property, and declarative cell; maintain the equivalent of `[[VarDeclaredNames]]`; specify whether sloppy-created properties enter it; and add own/inherited/accessor/delete-then-reveal fixtures.

2. **Blocking — rollback is contradictory or physically impossible once properties are storage.**

   Evidence: [§7.4](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:835>) promises restoration while writes through surviving bindings and external effects stand; [§7.5](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:870>) lets user code delete, accessorize, or make the storage property non-configurable.

   For example:

   ```js
   let x = 1
   // next input
   var x = 2
   await Promise.resolve().then(() =>
     Object.defineProperty(globalThis, "x", {
       value: 3, writable: true, configurable: false
     })
   )
   throw 0
   ```

   Restoring the prior lexical requires removing a now non-configurable property. A simpler ambiguity is `var x=1 ⏎ let x=2; globalThis.x=3; throw 0`: “restore 1” and “external write 3 stands” cannot both determine the property value.

   This is not theoretical concurrency. The current TLA shim polls the entire runtime while waiting ([hermes_runtime.cc:3112](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3112)), and polling executes unrelated callbacks and microtasks ([hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541)). Those callbacks can mutate temporary bindings during suspension.

   Resolution criterion: define a descriptor-level journal and merge policy; state whether background work joins, merges with, or is deferred outside the input transaction; cover phase-5 import effects; and define a fail-stop outcome when an inverse mutation is impossible.

3. **Material — phase-3 feasibility does not cover every phase-4 operation.**

   Evidence: [§7.3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:783>) checks removals, non-configurability, and a frozen global, but instantiation may instead need to create or overwrite a property. `Object.preventExtensions(globalThis)` is not necessarily frozen; a function replacement can encounter a non-writable data property or accessor; several declarations can pass the stated checks and then fail halfway through phase 4. The shipping evaluator has no transaction layer to repair partial instantiation—it is a single direct eval call ([engine/mod.rs:32](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:32)).

   Resolution criterion: define adapted `CanDeclareGlobalVar` and `CanDeclareGlobalFunction` predicates for every matrix cell, including extensibility, ownership, inherited properties, accessors, and descriptor flags; run all checks before any mutation; and pin error class plus multi-name atomicity.

4. **Material — the same-input destructuring rule is definitely wrong.**

   Evidence: [§7.3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:772>) and AC11 make a “duplicate destructuring target” unconditionally a `SyntaxError`. `var [a, a] = [1, 2]` is valid Script and yields `2`; I verified it on Hermes, Deno, and Bun. Duplicate lexical `BoundNames` are different. The existing transform correctly delegates actual early errors to the parser rather than imposing this blanket rule ([transpile.rs:133](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:133)).

   Resolution criterion: use the Script static-semantics predicates precisely and fixture duplicate `var`, duplicate lexical binding, import collisions, and assignment destructuring separately.

5. **Blocking — the free-identifier lowering is not specified at Reference-semantics fidelity.**

   Evidence: [§7.1](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:712>) names only `get`, `set`, `typeof`, and `delete`. It lacks `CreateMutableBinding`/`CreateImmutableBinding`/`InitializeBinding`, and no syntax-directed rules cover calls, `new`, tagged templates, update expressions, compound/logical assignment, destructuring assignment, loop targets, or strict versus sloppy unresolvable writes.

   A naïve `f()` → `env.get("f")()` rewrite, for example, supplies `env` as the call receiver and changes `this`. A naïve `x++` rewrite can change coercion, ordering, and returned value. A `const` initializer must initialize an uninitialized cell, while later `set` must throw.

   The current transform API returns only a string ([transpile.rs:84](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:84)), and the REPL currently relies on textual wrappers and statement heuristics ([repl/mod.rs:812](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:812)).

   Resolution criterion: normatively define the transform in terms of ECMAScript References and Environment Record abstract operations, with a syntax-directed table and side-effect-order fixtures for every reference-bearing form.

6. **Material — untouched dependencies cannot observe the claimed session global lexical record.**

   Evidence: [§7.1](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:675>) makes lexical storage evaluator-owned because Hermes lacks it, but [the mechanism](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:721>) says imported modules are never rewritten. An imported module therefore resolves free globals against Hermes’s real global environment, not the evaluator-owned declarative record. `let x=1 ⏎ import "./m.js"` where `m.js` reads `x` cannot behave like the stated realm GER.

   The current loader lowers modules to CommonJS without carrying any session-environment handle ([transpile.rs:147](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:147)); `ResolvedModule` has no such field ([module_loader/mod.rs:28](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:28)).

   Resolution criterion: either make module global resolution consult the session record, or explicitly add and fixture a deviation that dependencies see only the object record.

7. **Blocking — the “five deviations and no others” claim makes the oracle impossible.**

   Evidence: [§7 target semantics](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:642>) and [§7.7](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:904>) promise growing-Script behavior with only deviations (a)–(e), while [§7.6](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:891>) expressly declines block-local TDZ and per-iteration semantics. A successful single input containing classic `for (let i=0; i<3; i++)` closures is oracle-eligible and returns `3,3,3` on shipping Hermes instead of `0,1,2`.

   LLP 0019 governs a narrower transform and permits explicit capture-last bails ([LLP 0019](</Users/ccheever/projects/ibex/llp/0019-hermes-compat-transform-authority.decision.md:113>)). The current loader’s loop detector selects a target ([module_loader/mod.rs:652](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:652)), but the SWC branch ignores that target parameter ([transpile.rs:88](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:88)).

   Resolution criterion: either implement all local semantics required by the oracle, or enumerate them as deviations and narrow the oracle domain. “Any observable divergence fails” cannot remain as written.

8. **Blocking — the Script-plus-import-plus-TLA parser and transform pipeline remain unproven.**

   Evidence: [§3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:243>) correctly says the pinned parser lacks the required goal, but one proposed remedy—an independent Script early-error validator alongside parsing—does not make a Module parse accept legacy octal, `delete identifier`, or duplicate parameters, nor make a Script parse accept imports/TLA.

   Current SWC calls generic `parse_program()` ([transpile.rs:109](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:109)), then performs TS lowering followed by CommonJS lowering that erases imports ([transpile.rs:147](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:147)). It emits no source map ([transpile.rs:183](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:183)), and its API has no role, TLA bit, dependency manifest, or origin tags. Collecting declarations after TS lowering also risks persisting decorator/JSX/helper temporaries alongside intended `enum`/namespace bindings.

   Resolution criterion: prototype one viable parser route before accepting the Spec, then pin a pass order with origin-tagged private bindings, import/TLA side metadata, composed source maps, and no generated-name leakage.

9. **Material — literal dynamic-import preflight is a form-dependent semantic change missing from the six phases.**

   Evidence: [§3](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:312>) preflights string-literal `import()` transitively before entry execution, while computed imports fail at call time. Thus `if (false) import("./tla.js")` fails before entry execution, while `if (false) import("./" + name)` succeeds. Static discoverability is not dynamic reachability.

   Preflight is also absent from [the six phases](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:765>) and requires source reads, resolution, typed decisions, and transform work that the current resolver performs only when `resolve`/`load_source` is called ([module_loader/mod.rs:162](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:162)).

   Resolution criterion: preferably preflight only static imports and check every `import()` at call time. Otherwise add an explicit phase, define authorization/read/cache effects, document the unreachable-literal deviation, and fixture literal versus computed forms.

10. **Blocking — Stage 1 both conforms and cannot satisfy the required throw outcome.**

    Evidence: [§6](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:500>) unconditionally requires a thrown handle plus engine-captured message, stack, and positions. [§8](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1040>) says stock JSI cannot safely obtain those fields and Stage 1 renders every thrown value only by type tag until Stage 1.5 exists. The ABI has no discriminator expressing that metadata is unavailable at Stage 1.

    Current code catches `JSError`, invokes a JavaScript handler, and then calls `getMessage()`/`getStack()` ([hermes_runtime.cc:3178](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3178)); it is exactly the path the Spec says must be retired.

    Resolution criterion: either make Stage 1.5 a prerequisite for a conforming throw outcome, or version/discriminate the outcome as opaque-tag versus VM-captured metadata and update §6, §8, async-failure envelopes, and acceptance criteria consistently.

11. **Material — the cancellation result vocabulary contradicts its own state machine.**

    Evidence: [§6](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:592>) calls `defeated` an unresolved request that “never resolves at all”; the race rules then say an evaluation that completes normally after delivery makes the request “resolve defeated” ([same section](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:615>)). It also promises exactly one terminal result per request while admitting a permanently unresolved request. The current `Engine` interface has no cancellation operation or target identity ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)).

    Resolution criterion: define `Pending` separately from terminal results. A coherent model would transition `Pending → Accepted | Unavailable | Failed | Defeated-after-normal-return`; permanently stuck work remains pending until runtime destruction or supervisor termination.

12. **Material — `$_` has two incompatible declaration rules.**

    Evidence: [§7.8](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:949>) calls `$_` a `var`-kind accessor; [the matrix](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:807>) says a later `var` reuses a `var` binding; §7.8 then says any declaration replaces it. `var $_` therefore has two descriptor outcomes. The current REPL updates `$_` directly before display, not through acknowledgement ([repl/mod.rs:67](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:67)), so this ambiguity must be resolved during migration.

    Resolution criterion: add an explicit reserved-binding matrix row. Pin uninitialized `var $_`, initialized `var`, function, lexical declaration, direct assignment, deletion, and descriptor replacement.

13. **Material — the “closed” source request and ABI contract still have representational holes.**

    Evidence: [§1](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:144>) makes source goal mandatory and permits only Script-with-extensions or Module, while [§4](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:419>) puts `.load .json` in scope and says JSON has no source goal. The implementation already models JSON as a distinct module kind ([module_loader/mod.rs:20](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:20)).

    The byte-level result ABI is also explicitly deferred, while governing LLP 0002 still normatively specifies the old contract. Finally, the current C ABI rejects `len == 0` ([hermes_runtime.cc:2950](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2950)); the replacement does not state whether empty `.load`, stdin, or one-shot source is valid.

    Resolution criterion: define a sum such as `Program{goal,...} | JsonData`, specify empty-source behavior, and review the companion LLP 0002 byte schema before accepting this Spec.

14. **Minor/Non-blocking — several empirical statements need narrower wording.**

    Evidence:

    - The current input ABI is already length-bearing: `ex_hermes_eval` takes `(data, len)` and Rust passes `data.len()` ([hermes_runtime.cc:2924](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2924), [hermes.rs:887](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:887)). Only the output is NUL-terminated and lengthless. “The current one is none of these” is too broad.
    - Normal eval holds the runtime lock, but debugger-thread FFI deliberately bypasses it and can issue pause ([hermes.rs:544](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:544), [hermes.rs:556](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:556), [hermes.rs:742](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:742)). Cancellation is absent, but “cannot even be delivered because of the lock” is not established.
    - Deno/Bun returning `2` rules out retaining the old value, but does not distinguish name lookup into a replaced cell from mutating/reusing one captured cell.
    - Schedule-time attribution is partly present for next-ticks and timers even though no structured event envelope consumes it ([hermes_runtime.cc:2706](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2706), [hermes_runtime.cc:3654](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3654)).

    Resolution criterion: edit these as narrowly scoped implementation observations without changing the proposal’s conclusions.

4. **Cross-document findings**

1. **Blocking — module identity contradicts LLP 0023.** LLP 0024 §7.9 states `(runtime, retained object identity)` and cites “0023 AC11” ([0024](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:980>)). LLP 0023 requires the tagged `(runtime, defining principal, retained file object)` key to prevent cross-package hard-link compartment collapse ([0023 §2.3](</Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:290>)). Its relevant criteria are AC16–18; AC11 concerns `chdir`.

2. **Blocking — display-wire ownership is contradictory.** LLP 0024 §6 says the inspection tree crosses the worker boundary ([0024 §6](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:532>)); §8 says a separate LLP-0025-owned display IR crosses ([0024 §8](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1077>)). LLP 0025 instead specifies the tree itself as the versioned serializable wire object and defines no separate style/layout IR ([0025 §3](</Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:251>)).

3. **Material — the delegated-obligation ledgers are stale after the concurrent revision.** LLP 0022 and LLP 0025 still say the lifecycle outcome is absent ([0022 §10–§11](</Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:733>), [0025 §11](</Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:865>)), although LLP 0024 now defines it. They similarly misreport display acknowledgement, submission provenance, background-callback cancellation, and the resolver taxonomy. This directly contradicts LLP 0022’s claim that the join is mechanically checked ([0022 §11](</Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:746>)).

4. **Material — `.load` has a dangling pre-read dependency.** LLP 0022 requires a typed decision before `.load` bytes are read ([0022 §7](</Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:555>)). LLP 0024 authenticates the later source request, but does not define the pre-read session-effect route, its evidence, or its error precedence.

5. **Material — the interrupt bound differs.** LLP 0022 says two interrupts suffice from any engine-running state ([0022 §10](</Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:720>)); LLP 0025 correctly says a non-empty edit buffer can consume the first, giving a global bound of three ([0025 §6](</Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:453>)).

6. **Material — the sequence domain is dangling.** LLP 0024 allocates across evaluation outcomes and async failures ([0024 §9](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1129>)); LLP 0025 additionally puts broker events in the same allocator ([0025 §3](</Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:295>)). Reuse versus allocation of a second sequence number for result display is unspecified.

7. **Material — source identity depends on an unresolved LLP 0023 question.** LLP 0024 assigns imported files a canonical virtual URL and keys source maps by identity ([0024 §§2, 4](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:189>)). LLP 0023 deliberately leaves canonical display spelling unresolved when aliases share one module identity ([0023 OQ7](</Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1113>)). Import order can therefore change stack/source-map identity unless one rule is chosen.

8. **Duplication is already producing drift.** The complete `.load` behavior table appears in both LLP 0022 and 0024 ([0022 §8](</Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:663>), [0024 §4](</Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:419>)); language/display behavior is repeated across 0022/0024; display, cancellation, and lifecycle shapes are repeated across 0024/0025. The trap-free and bounds open-question references have also drifted: 0024 OQ1/OQ8 and 0025 OQ7 are cited elsewhere as OQ2/OQ6. One document should own each machine-readable row, with sibling projections generated or join-checked.

5. **Suggestions**

- Build an executable reference model for §7 before building the source transform. Feed it declaration traces, descriptor mutations, suspension/resumption, callbacks, imports, and abrupt completions; property-test the implementation against it.

- Prototype a Hermes global-resolution patch alongside AST rewriting. A native checked global lexical record may preserve Reference/call semantics, source positions, and dependency visibility with less semantic surface than rewriting every free identifier.

- Make the transformation product typed: transformed code, origin-tagged binding declarations, dependency manifest, import-cell metadata, completion instrumentation, and composed source map should be one artifact—not a string plus inferred facts.

- Preflight only truly static imports unless there is a compelling, documented reason to change literal dynamic-import semantics.

- Define versioned evaluator capability strata: base structured outcomes, safe throw capture, and rich trap-free inspection. Consumers should be able to distinguish unavailable metadata from an ordinary opaque value.

- Replace duplicated sibling tables and ledgers with stable obligation IDs and generated projections checked by `ref-check`.

6. **Open questions**

1. When rollback and direct `globalThis` mutation affect the same name, which wins?

2. Is background work executed during TLA suspension part of the input transaction, independently committed, or deferred?

3. Do imported modules observe session lexicals, or only the object/global-property half?

4. Are block-local TDZ, local `const`, and general per-iteration bindings v1 guarantees or explicit engine deviations?

5. Which proven parser mechanism implements Script early errors plus static imports and TLA without Module re-goaling?

6. Is early failure for unreachable literal `import()` intentional and worth its authorization and compatibility consequences?

7. Is Stage 1 a conforming release stratum without safe throw metadata, or must Stage 1.5 land first?

8. Is the worker wire object the semantic inspection tree or a separate display IR, and where is trusted styling derived?

9. What canonical source URL identifies an alias-unified module, independently of import order?

10. What is the exact descriptor behavior of `var $_`, `function $_`, and lexical redeclaration?

11. What terminal state does a cancellation request have while work remains permanently stuck?

12. Will the companion LLP 0002 ABI schema and the JSON/empty-source request variants be reviewed before this Spec is accepted?

7. **Readiness verdict**

The central design is worth pursuing, but unresolved correctness and coherence defects remain in §7, the parser/transform plan, inspection staging, cancellation, and the sibling contracts.

VERDICT: NOT READY

### Orchestrator verification notes

Both round-3 reviewers independently converged on the same core defects, which is
strong evidence they are real. I re-measured every decisive claim.

**Confirmed, and accepted.**

- **Blocking 1 (the matrix is not a `GlobalEnvironmentRecord`)** — confirmed, and
  it is the round's most serious finding. Composing §7.1's "a property with no kind
  entry behaves as `var`-kind **for every rule below**" with §7.3's "`var` + new
  lexical → replace; the `globalThis` property is **deleted**" meant **`let Object =
  1` would delete `globalThis.Object`** — and since imported modules are not
  rewritten and resolve only through the object record, every later import would
  break. Node confirms ECMAScript **shadows** rather than deletes
  (`globalThis.q = 2; let q = 1` leaves `q === 1` and `globalThis.q === 2`), and a
  bare `var Object` is a **no-op** with `Object` intact. §7 now adopts the shadow
  model: a lexical declaration never removes a property.
  This single rule was generating four separate defects. Removing it also removes
  the *reason* deviation (d) (configurable globals) existed — global `var` returns
  to ECMAScript's **non-configurable** — and with it the `delete globalThis.x`
  oracle divergence and both rollback-under-interference cases. The document got
  smaller and more correct at once.
- **Blocking 5 (Reference-semantics fidelity)** — accepted. Naming only `get`,
  `set`, `typeof`, `delete` was not enough: `x++`, compound and logical assignment,
  destructuring assignment, `for (x of …)` heads, `delete x`, and strict-vs-sloppy
  unresolvable writes each need a rule, and PutValue ordering is observable. §7.2
  now requires a syntax-directed lowering table stated in terms of ECMAScript
  References, with side-effect-order fixtures.
- **Blocking 6 (dependencies cannot see session lexicals)** — confirmed by probe:
  a global `let` **is** visible to other code in the realm
  (`vm.runInThisContext('let gx=41')`, then a second script reads `gx` → 41). An
  evaluator-owned declarative record that only rewritten session inputs consult
  therefore hides session lexicals from imported modules, which a growing script
  would not. This is a real, previously unstated deviation, and it is now **(d)** in
  the list.
- **Blocking 7 (the oracle)** — confirmed, and the fix is a factorization the review
  points at without naming: `for (let i…)` in **one** input is oracle-eligible under
  the old domain and returns `3,3,3` on Hermes against `0,1,2` on a standards
  engine — an *engine* defect, not a *session* defect. The oracle is now
  **engine-relative**: a growing script on Hermes versus the session on Hermes, which
  cancels engine quirks and isolates exactly the session deviations. Engine-local
  semantics (block TDZ, per-iteration bindings) are LLP 0019's subject and are
  explicitly outside this document's deviation list.
- **Blocking 10 (Stage 1 cannot satisfy the throw outcome)** — confirmed as a real
  self-contradiction: §6 unconditionally promised engine-captured message/stack while
  §8 said stock JSI cannot obtain them safely. §6's throw outcome now carries
  **optional** VM-captured metadata with an explicit *unavailable* discriminator, and
  the document defines **evaluator capability strata** so a consumer can tell
  "metadata unavailable at this stratum" from "an ordinary opaque value".
- **Material 3 (phase-3 feasibility)** — confirmed: `var` on a non-extensible
  `globalThis` throws `TypeError` (measured). Phase 3 now runs ECMAScript's own
  `CanDeclareGlobalVar`/`CanDeclareGlobalFunction` for **every** name before **any**
  mutation, atomically.
- **Material 4 (duplicate destructuring)** — confirmed and it was a definite language
  error of mine: `var [a, a] = [1, 2]` is **legal** Script and yields `2`, while
  `let [a, a]` is a `SyntaxError`. The collision rule is now keyed by kind.
- **Material 9 (literal dynamic-import preflight)** — accepted, and the review's
  recommendation is taken: preflighting string-literal `import()` would make
  `if (false) import("./tla.js")` fail while `if (false) import("./" + name)`
  succeeds — static discoverability is not dynamic reachability. **Only static
  imports are preflighted; every `import()` is checked at call time.**
- **Material 11 (`Pending` is not a terminal state)** — accepted; the state machine is
  now `Pending → Accepted | Unavailable | Failed | Defeated`, with permanently stuck
  work remaining *pending* until runtime destruction. Target ids (LLP 0025 §6) are
  added with the stale-id discard rule.
- **Material 12 (`$_`)**, **Material 13 (source-request sum type, empty source)** —
  accepted.
- **Minor 14 (empirical overstatements)** — all four confirmed and narrowed. The
  input ABI **is** length-bearing (`ex_hermes_eval(data, len, …)`); only the *output*
  is NUL-terminated and lengthless, so "the current one is none of these" was too
  broad. The runtime-lock claim is narrowed (the debugger thread deliberately
  bypasses it). And the reviewer is right that Deno/Bun yielding `2` rules out
  *retaining the old value* but does **not** distinguish name-lookup-into-a-replaced-cell
  from mutating one reused cell — the precedent supports late binding without proving
  the mechanism, and §7.2 now says only what the measurement supports.

**Cross-document — accepted.** Module identity now cites **LLP 0023 §2.3** (the
tagged algebra keyed on the *defining* principal) with no inline restatement and no
AC number, since restating a sibling's mechanism inline is what let it go stale.
The display-wire conflict is resolved **in LLP 0025's favor** (see below). The
`.load` pre-read, UTF-8 decoding, drain boundary, and broker-sequence obligations
are landed.

**Display-wire ownership — decided, not left standing.** LLP 0025 §3 says *this*
document owns the tree schema, that the tree carries **no** styling, and that the
session layer derives styling from node kinds. My §8 said the reverse (that 0025
pins a styled IR). **LLP 0025 is right and §8 is amended.** The deciding argument is
0025's own trust posture: under the worker split the producer may be hostile, so a
producer that can *name a style* can emit terminal control; a tree that cannot
express styling at all makes that structurally impossible. Both statements are not
left standing.

**Not adopted.**

- The suggestion to prototype a native Hermes global-resolution patch *instead of*
  AST rewriting is recorded as a design alternative, not taken for v1 — but the
  review is right that it would preserve Reference semantics, source positions, and
  dependency visibility (deviation (d)) with less semantic surface. It is now named
  in the open questions as the thing that would retire deviation (d) outright.
- Cross-document 5 (the interrupt bound: LLP 0022 says two, LLP 0025 says three
  because a non-empty edit buffer can consume the first) is a **0022↔0025** conflict,
  not this document's. Reported to the coordinator rather than resolved here.


## Round 4 — 2026-07-12

**Reviewer family:** Codex / GPT (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`.
Run from the **main session** (a detached `codex exec` launched inside a subagent
turn is killed when that turn ends — it destroyed round 3's first attempt).
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra` — confirmed in the log, no substitution
**Codex session id:** `019f55e4-2183-7121-abaa-71724dbef15b`
**Integrity:** the session rollout's final message hashes to md5 `dc5c3b794c2a`,
byte-for-byte equal to the captured file recorded below. This check is stronger
than citing a session id alone, and it is recorded because a sibling artifact in
this corpus once cited a session id against a body that session did not produce
(a log-path collision).
**Revision under review:** `b0ff4ea3247e` (first 12 hex of `shasum -a 256` over the
target — a content hash, not a Git object). Sibling revisions observed by the
reviewer: `0022@826d4120`, `0023@a1ba44b3`, `0025@7b89315f`.
**Redaction:** none — read under the user's OpenAI account, authorized by the human
invocation of the refinement skill.
**Independence:** fresh non-interactive session with no access to this orchestrating
session, to the concurrent Fable round-4 review of the same revision, or to any prior
LLP 0024 artifact. Both earlier artifacts were stashed out of `llp/reviews/` for the
duration; main independently verified `llp/reviews/` held no 0024 files while it ran.
**Method:** `brief-round4.md` verbatim. The brief instructed the reviewer **not to
trust the document's empirical claims** but to re-measure them — after an earlier
round's false claim survived by being taken on trust, and a later round's
catastrophic rule survived after two reviewers *praised* it.

### Verbatim review

## 1. Overall assessment

The proposal has a strong architectural direction, but it is not ready as a normative Spec. Structured source requests, typed outcomes, entry-only TLA, and staged trap-free inspection are all good decisions. I also re-measured every expressly asserted empirical premise; none of those claims failed.

The blocking problem is §7 itself. Its phase-4 bindings cannot be rolled back as specified, its `var`/`function` matrix is observably wrong or contradictory in several descriptor states, background effects cannot always remain independent, and the engine-relative oracle rejects valid per-input behavior. There are also direct lifecycle, credential, and module-identity contradictions with the concurrently revised siblings.

The review used target revision `b0ff4ea3247e` and the final observed sibling revisions `0022@826d4120`, `0023@a1ba44b3`, and `0025@7b89315f`. It was read-only; no review artifacts or repository files were modified.

## 2. Strengths

- The diagnosis of the current evaluation seam is accurate. The Rust trait accepts a bare string and returns `Option<String>` ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22)); the C ABI returns `char **` ([hermes.rs:87](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:87)); native evaluation rejects empty source, collapses `undefined` with empty completion, stringifies values, and conflates throws with engine faults ([hermes_runtime.cc:2950](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2950), [hermes_runtime.cc:3161](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3161), [hermes_runtime.cc:3178](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3178)). §6’s typed outcome and handle-owning ABI is the right replacement.

- §3 correctly refuses to pretend Hermes has asynchronous modules. The shipping transform lowers ESM into a synchronous CommonJS chain and passes TLA through ([transpile.rs:97](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97)); Hermes advertises no native ESM or TLA ([hermes.rs:1653](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1653)). Entry-only TLA with dependency refusal is a defensible v1 boundary.

- §7’s move from property deletion to lexical shadowing is correct. `let Object = 1` must not destroy `globalThis.Object`, and late lookup by name is a coherent way to support cross-input kind replacement and closures. The document is also unusually explicit about TDZ, reference fidelity, destructuring, partial failure, and input boundaries.

- §8’s staged safety model is well judged. Stage 1 openly accepts poor-but-inert output, stage 1.5 isolates safe error capture, and stage 2 requires real VM support. The unstyled semantic tree aligns with current LLP 0025’s trust boundary ([0024:1239](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1239), [0025:237](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:237)).

- The proposed non-assimilation rule addresses a real defect: current native evaluation reads and calls arbitrary `.then` properties ([hermes_runtime.cc:3033](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033)). Using a private settlement token and an out-of-band result slot is structurally safer.

- The empirical foundation was sound. On bundled Hermes 1.0.0/HBC 99, Node 24.14.0, Deno 2.9.1, and Bun 1.3.12, I confirmed:

  - Hermes’s missing TLA/ESM, TDZ, runtime `const`, lexical persistence, direct-eval scope, and per-iteration bindings;
  - revoked-Proxy `Array.isArray` throwing without user traps;
  - lexical shadowing without property deletion, inert bare `var Object`, duplicate `var` destructuring, lexical duplicate errors, TDZ `typeof`, non-extensible-global failure, inherited-property behavior, and same-realm lexical visibility;
  - Deno and Bun late binding, Deno’s cross-input `const` enforcement, and Bun’s lack of it.

## 3. Concerns

1. **Blocking — Phase-5 rollback is impossible for the properties phase 4 creates.**

   **Evidence:** Phase 4 creates `var` and `function` properties ([0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:897)); §7.5 requires them to be non-configurable ([0024:1012](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1012)); phase-5 failure requires removing them ([0024:976](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:976), [0024:985](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:985)). An ordinary ECMAScript operation cannot delete a non-configurable property. The document’s “made non-configurable mid-input” fault case overlooks that a fresh session `var` begins non-configurable.

   The journal is also incomplete for `var f = 1 ⏎ import "./boom"; function f(){}`: phase 4 overwrites `f`, but the journal records no displaced property descriptor/value and explicitly says values are not restored ([0024:964](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:964)). The current engine seam exposes only ordinary evaluation, with no privileged global transaction operation ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes_runtime.cc:3004](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3004)).

   **Resolution criterion:** Prototype and specify either a VM-level transactional global-object API capable of restoring complete descriptors despite non-configurability, or a different publication design—such as provisional configurable properties, import-before-binding publication, or weaker rollback—with every observable deviation listed and fixture-pinned.

2. **Blocking — The cross-kind matrix incorrectly conflates `var` and `function` and does not define the complete global state.**

   **Evidence:** The kindless-property row invokes `CreateGlobalVarBinding` for both declarations ([0024:917](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:917)). Re-measurement shows:

   - a function declaration replaces a configurable own data property;
   - it replaces a configurable accessor without invoking the accessor;
   - it creates a function-valued own property over an inherited name, not `undefined`;
   - it may overwrite a non-configurable writable/enumerable data property;
   - `function Object(){}` overwrites the builtin even though bare `var Object` preserves its value.

   Separately, the matrix says a pre-existing own property is left alone by `var` ([0024:922](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:922)), while §7.5 says every session `var` becomes non-configurable. Node separate Scripts preserve a configurable descriptor; bundled Hermes flips it to non-configurable. The Spec currently chooses both.

   Other missing states include arbitrary non-configurable own properties—ECMAScript’s restricted-global test is not limited to `undefined`, `NaN`, and `Infinity`—and membership in `[[VarDeclaredNames]]` after the associated configurable property was deleted. Finally, “binding object is `globalThis`” does not distinguish the stable realm global from the writable `globalThis` property ([0024:758](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:758)); both Hermes and Node continue putting later `var`s on the actual realm global after `globalThis = {}`.

   **Resolution criterion:** Replace the matrix with a closed state machine keyed by declarative cell, `[[VarDeclaredNames]]`, own/inherited/absent property, and full property descriptor. Distinguish `CreateGlobalVarBinding` from `CreateGlobalFunctionBinding`, name the captured realm-global object, choose Hermes or ECMAScript descriptor behavior explicitly, and list any additional deviation.

3. **Blocking — Background/module effects cannot always commit independently of the journal.**

   **Evidence:** §7.4 restores a displaced cell’s kind, initialization state, and value ([0024:973](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:973)), while promising that work during a TLA suspension is never rolled back ([0024:1004](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1004)).

   Counterexample:

   ```js
   // input 1
   let x = 1;
   globalThis.cb = () => { x = 5 };

   // input 2
   let x = 2;
   await somethingThatRuns(cb);
   throw 0;
   ```

   Late binding makes `cb` write the replacement cell. Restoring the displaced cell containing `1` necessarily discards the callback’s `5`. Likewise, if `import "./boom"; var w` creates `w`, and the failing module writes `globalThis.w = 42`, removing `w` erases the module’s effect despite the promise that module effects stand.

   The six phases also omit the settlement boundary. Current evaluation runs next ticks and drains microtasks before returning ([hermes_runtime.cc:3015](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3015)); a drain throw reaches the evaluation catch ([hermes_runtime.cc:3178](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3178)). The Spec does not decide whether `let x=1; queueMicrotask(() => { throw 0 })` is a successful evaluation plus async event or an evaluation throw affecting publication.

   **Resolution criterion:** Define work origin and write ownership for same-name interference, add an explicit settlement/commit phase, and specify which jobs belong to the TLA unit versus background work. Add fixtures for same-name module writes, replaced cells, microtask throws, and mixed TLA/background rejection.

4. **Material — The promised Reference-semantics algorithm is not actually specified.**

   **Evidence:** §7.1 says the lowering “is therefore specified as a syntax-directed table,” but supplies only an open-ended list of contexts ([0024:813](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:813)). A JavaScript transform cannot materialize ECMAScript Reference Records directly; every AST context must preserve receiver formation, `GetValue`/`PutValue`, abrupt completion, and evaluation order explicitly.

   The existing transform has no source-goal or session-reference machinery ([transpile.rs:109](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:109)), while the REPL currently uses ad hoc global assignments and async wrappers ([repl/mod.rs:1080](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1080), [repl/mod.rs:1174](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1174)).

   **Resolution criterion:** Provide a closed normative transform/IR table or a generated exhaustive inventory of reference-bearing AST contexts, including optional calls, shorthand properties, JSX-generated references, destructuring, receiver-preserving calls, updates, deletes, and all strict/sloppy unresolvable cases.

5. **Material — `$_` is not integrated with rollback, and takeover storage is undefined.**

   **Evidence:** Any declaration of `$_` permanently disables auto-update during phase 4 ([0024:1110](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1110)), while a phase-5 failure publishes nothing. Thus `import "./boom"; let $_` either permanently disables `$_` despite publishing nothing, or re-enables it despite “permanently.” Auto-update state is absent from the journal.

   The runtime-owned accessor’s post-takeover semantics are also unspecified: after `$_ = 7`, does the setter store `7` or only record that auto-update was disabled? Display acknowledgement may also race a background mutation before the barrier completes.

   **Resolution criterion:** State whether takeover state is transactional, journal it if necessary, define getter/setter storage after disablement, and add phase-5 failure, phase-6 failure, declaration, deletion, and acknowledgement-race fixtures.

6. **Blocking — The engine-relative oracle’s checkable domain is false.**

   **Evidence:** Each input has its own Script directive prologue and strictness ([0024:286](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:286), [0024:387](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:387)), but §7.7 concatenates inputs and claims its restricted domain cannot exhibit a deviation ([0024:1079](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1079)).

   Re-measured on bundled Hermes:

   ```js
   0
   ⏎ "use strict"; function f() { return this }
   ⏎ f()
   ```

   The session’s second input is strict, so `f()` returns `undefined`. In one concatenated growing script, `"use strict"` is no longer a directive prologue, so `f()` returns `globalThis`. This satisfies the current oracle-checkable restrictions.

   Raw concatenation also has ASI/token-fusion hazards, and one execution cannot expose each input’s completion without instrumentation that may itself change directives and hoisting. “Through the same lowering” is ambiguous: applying session-name lowering to the oracle arm risks making the oracle circular; omitting it means the two arms are not using the same lowering.

   **Resolution criterion:** Define exact boundary stitching, per-input completion instrumentation, initial realm state, and which transforms apply to each arm. Exclude directive- and boundary-sensitive sessions or list them as deviations with direct fixtures.

7. **Blocking — Dynamic-import timing contradicts itself.**

   **Evidence:** The normative rule correctly says every `import()`, including a literal, is checked at call time ([0024:355](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:355)). The fixture table instead requires literal-dynamic preflight ([0024:523](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:523)), and AC8 repeats that requirement ([0024:1387](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1387)). Current dynamic import is genuinely call-time through a Promise reaction ([module-loader.js:6008](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:6008), [module-loader.js:6050](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:6050)).

   **Resolution criterion:** Delete literal-dynamic preflight everywhere. Require every `import()` to check at call time and reject its Promise, in ECMAScript ordering, before target evaluation or cache insertion.

8. **Material — Static-graph TLA preflight and the extended Script goal lack an implementable plan.**

   **Evidence:** The required Script-plus-import-plus-TLA goal does not exist in the pinned parser and remains an open mechanism choice ([0024:299](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:299)). `ResolvedModule` carries no role, dependency manifest, or TLA bit ([module_loader/mod.rs:20](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:20)); source loading is lazy and one-module-at-a-time ([module_loader/mod.rs:162](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:162)); plain sources may bypass transformation ([module_loader/mod.rs:242](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:242)). SWC passes TLA through, while Oxc rejects it differently ([transpile.rs:97](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97), [transpile.rs:211](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:211)).

   The current bootstrap can wrap a dependency in an async IIFE, ignore its Promise, and mark it loaded; one fallback can also execute its prefix twice ([module-loader.js:5362](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5362), [module-loader.js:5603](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5603), [module-loader.js:5723](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5723)).

   **Resolution criterion:** Prototype the selected parser mechanism first. Then specify that every ESM source passes through the manifest pass, plus traversal order, cycles, deterministic error selection, cache identity, authorization/read ordering, and checks for CJS-mediated loads.

9. **Blocking — Lifecycle semantics contradict LLP 0025 and cannot execute target rollback.**

   **Evidence:** The target says the native call unwinds and the session journal rolls back ([0024:569](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:569)). Current LLP 0025 says the call parks, explicitly rejects unwinding, and emits the lifecycle outcome out of band ([0025:541](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:541), [0025:553](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:553)). Under the supervisor realization the parked worker is disposed, so no evaluator frame remains to run target rollback.

   Cancellation language is also incoherent across the corpus: target makes `defeated` terminal and permanently stuck work remain `Pending` ([0024:676](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:676)); 0025 says “defeated—never resolves” and then says a normal completion “resolves defeated” ([0025:464](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:464), [0025:473](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:473)).

   **Resolution criterion:** Adopt one lifecycle mechanism—currently 0025’s park/out-of-band record—and define the session state as discarded rather than rolled back by dead code. Use `Pending` solely for unresolved requests and `defeated` solely as a terminal result.

10. **Blocking — The source request carries the wrong submission credential.**

    **Evidence:** The target calls its permit “decision evidence” and binds only snapshot digest, nonce, root identity, source identity, and ingress kind ([0024:183](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:183)). Current 0022 explicitly says this is not decision evidence and requires a linear credential binding byte digest, referrer, goal, role, mode, entry kind, endowment projection, and ordinal ([0022:687](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:687), [0022:953](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:953)). The target also omits endowment projection from its source-request fields and explicitly derives only the principal.

    **Resolution criterion:** Replace submission provenance with the full opaque `SubmissionCredential`, specify its mint/read-authorize/byte-capsule/evaluate lifecycle and one-shot consumption, and require every security-relevant request field to be derived from authenticated session state.

11. **Blocking — Module identity directly contradicts LLP 0023; failure caching is undecided.**

    **Evidence:** The target says module identity must cover `ibex:eval` and `repl:<n>` ([0024:1147](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1147)). LLP 0023 says these are scripts with source identities only; only `ibex:stdin` is a synthetic module ([0023:455](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:455)).

    Separately, §7.4 says a throwing imported module’s cache entry “of course” stands ([0024:985](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:985)), but the synchronous loader deletes the failing entry ([module-loader.js:5690](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5690)). Entries are inserted before execution for cycles ([module-loader.js:5311](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5311)), so failure semantics affect cycles and retries.

    **Resolution criterion:** Remove script identities from the module-key algebra. Decide explicitly whether the failing module, completed predecessors, and partial-cycle records remain cached, and pin static-import, dynamic-import, retry, and cycle cases.

12. **Material — Stage 1 may require a native raw-exception slice, and its surface scope needs to be explicit.**

    **Evidence:** Stage 1 promises a handle and type-tag rendering for every thrown value while metadata remains unavailable ([0024:1202](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1202), [0024:1217](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1217)). Current catch handling reads JSI error message and stack ([hermes_runtime.cc:3178](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3178)). The Spec must prove that the original thrown value can be captured without the unsafe JSI metadata path; otherwise raw exception capture belongs in base, not stage 1.5.

    The replacement is necessary: today the REPL invokes JavaScript `Exact.inspect` ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63)), whose “safe” reads still execute getters and Proxy traps ([inspect.ts:90](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:90), [inspect.ts:395](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:395)). Native formatting separately reads properties and invokes `JSON.stringify` and coercion ([hermes_runtime.cc:493](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:493)). LLP 0025 now treats `console.*` as program output, not safe evaluator display ([0025:258](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:258)); 0024 should state the same scope.

    **Resolution criterion:** Demonstrate trap-free raw thrown-value capture as part of the base stratum, and publish a rendering-surface inventory distinguishing evaluator display/error rendering from explicitly excluded program-authored console formatting.

13. **Material — Source-position support is not represented honestly as an evaluator capability.**

    **Evidence:** Correct composed source maps are an acceptance requirement ([0024:527](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:527)), yet Hermes advertises source maps unconditionally ([hermes.rs:1653](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1653)). Its remapper only searches adjacent on-disk maps ([hermes.rs:1161](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1161)), and the SWC emitter produces no map ([transpile.rs:183](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:183)).

    **Resolution criterion:** Add composed in-memory source-position fidelity to the evaluator capability matrix and leave it unavailable until TypeScript, import, TLA, session, and LLP 0019 rewrite maps pass end-to-end fixtures.

14. **Material — “Imported modules resolve against the object record” ignores package compartments.**

    **Evidence:** The target explains lexical invisibility by saying unrewritten imports resolve against “the object record” ([0024:805](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:805), [0024:1060](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1060)). LLP 0013 requires package code’s bare globals and `globalThis` to resolve against that package’s private compartment global ([0013:237](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:237), [0013:1246](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:1246)). Therefore package modules do not necessarily see session `var` properties either.

    **Resolution criterion:** Define visibility separately for root/first-party imported modules and package-compartment modules. Add fixtures for session `var`, session lexical, root globals, and endowments in both kinds of module.

## 4. Cross-document findings

- **0022 submission credential:** 0022 currently contains both the stale “decision evidence” formulation and its immediate retraction ([0022:673](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:673), [0022:687](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:687)). Its obligations ledger clearly selects the latter; 0024 still implements the stale former.

- **0022/0025 lifecycle:** 0022 and 0025 now agree on parking ([0022:902](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:902), [0025:541](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:541)); 0024 is the outlier with unwinding.

- **0023 module identity:** 0023 explicitly excludes `repl:<n>`, `ibex:eval`, and `.load` from module identity. Its own ledger is stale in the other direction: it still claims 0024 uses retained-object identity ([0023:1265](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1265)); 0024 now uses defining-principal identity correctly, but still wrongly includes script sources.

- **Resolver taxonomy duplication:** 0024 owns a partial import taxonomy ([0024:261](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:261)), while 0023 claims ownership of the closed total resolver union ([0023:1096](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1096)). The 0023 union omits target-local conditions such as unknown builtin, resolution failure, and dependency TLA. These need layered unions with one composition order, not two competing ownership claims.

- **Typed-read ownership:** 0024 says 0022 places the typed-read obligation there ([0024:197](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:197)); 0022 prose says 0024 + 0021, while its ledger assigns 0023 + 0021 ([0022:708](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:708), [0022:956](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:956)). Ownership is dangling.

- **0025 cancellation:** 0025 still uses “defeated” for both an unresolved request and a terminal race result. That directly contradicts 0024’s `Pending`/terminal distinction.

- **0025 ledger stale in both directions:** `OBL-CANCEL-COMPLETION` says target IDs/completion queries are absent although 0024 states them; `OBL-SEQUENCE-DOMAIN` says broker membership is absent although 0024 includes it; `OBL-DISPLAY-ACK` remains partial although both sides now define the barrier acknowledgement ([0025:727](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:727), [0024:667](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:667), [0024:1292](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1292), [0025:283](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:283)).

For the current 0022 obligations ledger, the following target-owned or jointly owned rows are false or incomplete. The ledger itself intentionally treats every row as undischarged until attestation and fixtures; this table concerns semantic alignment only.

| Obligation | Finding |
| --- | --- |
| `OBL-EXIT-MECHANISM` | **False:** 0024 says unwind; 0022/0025 require park. |
| `OBL-INGRESS-CTX` | **Incomplete:** endowment projection and authenticated derivation of every semantic field are absent. |
| `OBL-SUBMIT-CREDENTIAL` | **False:** wrong category, incomplete bindings, and no full linear lifecycle/byte capsule. |
| `OBL-SEQUENCE` | **Incomplete:** the three event classes are included, but allocator owner, crash epoch, and worker-restart behavior are undefined. |
| `OBL-CANCEL-TARGETS` | **Incomplete/inconsistent:** 0024 has ids and work units, but no explicit target-kind field, and 0025 contradicts the `Pending`/`defeated` distinction. |
| `OBL-MODULE-IDENTITY` | **False:** 0024 assigns module identity to script sources. |
| `OBL-UTF8` | **Incomplete:** strict refusal exists, but transcript resynchronization is undefined. |
| `OBL-BOUNDS` | **Incomplete:** normative values remain open, so byte-exact fixtures cannot yet be pinned. |
| `OBL-LOADER-CLOSED` | **Partial:** 0024 states `require.main` and `process.mainModule` closure, but not `require.cache`; the row relies on the registry for the remainder. |

`OBL-CELL-MODEL`, `OBL-SAFE-DISPLAY`, and the other textually present rows are not contradicted as intentions, but they cannot be considered semantically discharged until the algorithmic blockers above are fixed.

## 5. Suggestions

- Make §7 owner-authored executable data, as current 0025 now does for interruption. A small reference state machine over cells, descriptors, declared-name membership, journal entries, and work-origin writes could generate the prose table and fixtures. This is much safer than manually maintaining another large matrix.

- Strongly consider a native transactional `GlobalEnvironmentRecord` or global-object overlay. An engine-level record can make provisional non-configurable properties observable during evaluation while still reverting them internally—something ordinary JavaScript property operations cannot do.

- If that VM patch is too large for v1, simplify semantics honestly: evaluate/preflight static imports before publishing session bindings, or narrow cross-kind replacement and rollback. Either choice is preferable to specifying atomicity the implementation cannot supply.

- Split the oracle into two gates:

  - an engine-relative single-input gate for Hermes quirks and lowering fidelity;
  - an executable session-state reference model for cross-input behavior.

  Raw concatenation is not a reliable oracle for input boundaries.

- Put explicit prototype gates before implementation: extended Script parser, transactional globals, raw exception capture, composed source maps, and dependency-manifest traversal.

- Write the companion Plan requested by 0022. A defensible minimal slice is transcript mode, structured outcomes, inert display, no background interleaving during TLA, and an empty package graph—then add cross-kind replacement and rich inspection only after their native seams exist.

## 6. Open questions

1. What concrete mechanism can reverse a non-configurable phase-4 property after a phase-5 failure?
2. Who wins when a module or background callback writes an input-declared name during the transaction?
3. Is descriptor behavior meant to follow ECMAScript separate Scripts or bundled Hermes’s current multi-evaluation behavior?
4. What exact source transformation and instrumentation constructs the engine-relative oracle without changing directive prologues, ASI, hoisting, or completion values?
5. Which parser mechanism implements sloppy Script plus static imports and TLA, and has it been prototyped on every advertised target?
6. What are the retry and cache semantics for a failing module, its completed dependencies, and partial cycles?
7. How is lifecycle state described when the evaluator parks forever and its worker is disposed—rollback, discard, or never-published state?
8. Are package-compartment modules intended to see session `var` properties, and if so, how can that coexist with LLP 0013?
9. Can the base evaluator obtain the original thrown value without triggering JSI’s message/stack capture path?
10. Who owns the cross-process sequence allocator, and what happens across worker death and restart?
11. Where is transcript recovery after invalid UTF-8 framed?
12. Which unresolved bounds and native prototypes are release gates for the minimal conformant v1?

## 7. Readiness verdict

The architectural direction is worth pursuing, but the current text contains multiple unresolved blocking correctness, feasibility, and cross-corpus coherence defects.

VERDICT: NOT READY

### Orchestrator verification notes

Both round-4 reviewers converged again. I re-measured every decisive claim; all held.

**Blocking 1 — confirmed, and it is a defect my own round-3 fix created.** Making
session `var`s non-configurable (the right call) made phase-5 rollback **impossible**:
`delete globalThis.v` on a non-configurable property returns `false` (measured). The
fix is not a VM transaction API but a **phase reorder**: import evaluation moves
*before* instantiation. A failing import then throws before anything was instantiated,
so "publishes nothing" is trivially true and no property ever needs deleting. Rollback
now touches **only the evaluator's own declarative record** — never the object record —
which also disposes of the review's `var f = 1 ⏎ import "./boom"; function f(){}`
journal case (with import-first, `f` is never overwritten).

**Blocking 2 — confirmed on both halves.** `function Object(){}` **does** clobber the
builtin (`typeof Object.keys` → `undefined`) while bare `var Object` is a no-op — so
the matrix's single `CreateGlobalVarBinding` row for both was wrong;
`CreateGlobalFunctionBinding` is a `DefineOwnProperty` and overwrites. And a `var`
**adopting** a pre-existing configurable property leaves it **configurable**
(measured), falsifying §7.5's blanket "every session `var` is non-configurable". The
matrix is now keyed on the full descriptor state, and §7.5 is qualified to properties
the record *created*.

**Blocking 3 — confirmed and stated rather than hand-waved.** A callback that writes
through a cell the failed input created loses that write when rollback removes the
cell. That is unavoidable and correct — the binding ceased to exist — so the document
now says so explicitly: "background work commits independently" means its *own*
effects, not writes into a binding that rollback removes.

**Blocking 6 — confirmed by measurement, and it is a lovely catch.** `0 ⏎ "use strict";
function f(){return this} ⏎ f()` returns `undefined` as a session (input 2's directive
prologue is its own) and `globalThis` when concatenated (the directive is no longer in
a prologue position). Measured on V8: session → `undefined`, concatenated → `object`.
The oracle's checkable class was unsound. Adopted the review's own suggestion — **split
the gates** — which both reviewers proposed independently and which 0025 has already
proven by making its interrupt machine generated data after prose falsified it three
rounds running.

**Blocking 7 — confirmed, and it was sloppiness on my part.** Round 3 moved §3's rule to
call-time-only and left the §4 fixture table and AC8 mandating literal-dynamic preflight.
Deleted everywhere.

**Blocking 9, 10, 11 — confirmed against the live siblings and adopted.** Lifecycle:
LLP 0025 §8 specifies the call **parks** and never unwinds; §6 adopts park and the
session state is **discarded, not rolled back**. Credential: LLP 0022 now requires a
full opaque linear `SubmissionCredential` and explicitly names "decision evidence" as a
**category error** — which is the exact phrase my §1 still carried. Module identity:
LLP 0023 rules that script inputs are **not modules and have no module identity**; only
`ibex:stdin` is a synthetic module. My §7.9 demanded identity "cover the sources this
document mints", which was precisely the **conflation** the coordinator warned about —
I had reused the *noun* "identity" across two different concepts. §2 now states that a
**source identity** is a synthetic *name* for frames and source maps, is not a module
identity and not a retained platform identity, and is safe to serialize; §7.9 covers
only real modules. And the failing module's cache entry does **not** stand — the loader
deletes it (`delete cache[cacheKey]`), so my "of course stands" was simply false.

**Material 14 — confirmed, and it sharpens deviation (d).** LLP 0013 Mechanism 2 gives
each package a **private compartment global**, so package-compartment modules see
neither session lexicals *nor* session `var` properties. Deviation (d) now distinguishes
root/first-party imported modules from package-compartment modules.

**Not adopted.** The suggestion to weaken cross-kind replacement or to drop rollback
rather than specify atomicity the implementation cannot supply: the phase reorder
supplies the atomicity in plain JavaScript, with no VM patch, so the trade is not
needed.


## Round 5 — 2026-07-12

**Reviewer family:** Codex / GPT (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`.
Run from the **main session**, whose turn outlives the process.
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra` — confirmed in the log, no substitution
**Codex session id:** `019f5608-669f-7aa3-8907-4bb6bb33ee85`
**Integrity:** the session rollout's final message hashes to md5 `61776e81cd39`,
byte-for-byte equal to the captured file recorded below.
**Revision under review:** `c264085e7ebf` (first 12 hex of `shasum -a 256` over the
target). Siblings observed: `0022@88decefd`, `0023@b6040097`, `0025@cfe6e1a6`.
**Redaction:** none.
**Independence:** fresh non-interactive session; no access to this orchestrating
session, to the concurrent Fable round-5 attempt on the same revision, or to any
prior LLP 0024 artifact. Both earlier artifacts were stashed out of `llp/reviews/`
for the duration; main independently verified the stash held.
**Method:** `brief-round5.md` verbatim. The brief instructed the reviewer to
**re-measure** every empirical claim rather than trust it, and additionally to hunt
for *noun reuse* — a shared word silently covering two concepts — after that failure
mode had already bitten this corpus twice.

**Round status — two-family.** *(Correction: an earlier draft of this provenance block
recorded round 5 as single-family, on the belief that the concurrent Fable reviewer had
not returned. It returned shortly afterwards. The claim was wrong when written and is
struck here rather than silently edited away — a provenance block that has been wrong
once should say so.)* Both families reviewed revision `c264085e7ebf`; the Fable artifact
is recorded in its own file. Both returned **NOT READY**.

### Verbatim review

1. **Overall assessment**

The proposal’s direction is good: a typed evaluation seam, explicit Hermes deviations, a persistent session record, staged safe inspection, and entry-only TLA are substantially better than the current wrapper-based REPL. The three-gate verification strategy is also the right response to prior oracle failures.

It is not yet a correct normative algorithm. I found four blocking issues: imports invalidate declaration feasibility before instantiation; the restricted-global predicate can be laundered through `var`; the submission credential’s one-shot lifecycle is circular for `.load`; and the claimed package isolation is false in the shipping compartment implementation. Several material ambiguities remain around rollback, `$_`, identity terminology, work-unit ownership, source maps, and error precedence.

I independently measured Hermes 1.0.0/HBC 99, Node 24.14.0, Deno 2.9.1, and Bun 1.3.12. The document’s ECMAScript, revoked-Proxy, Deno/Bun, and most Hermes claims reproduced. The important exception is that shipping Hermes does not preserve an adopted configurable property’s descriptor on `var`; §7 must implement that behavior itself.

Review snapshots: target `c264085e7ebf…`; siblings `0022=88decefd…`, `0023=b6040097…`, and the concurrently revised `0025=cfe6e1a6…`.

2. **Strengths**

- §§1 and 6 correctly replace the stringly ABI with closed request and outcome types, distinguish empty completion from `undefined`, prohibit thenable assimilation, and separate native-engine capability from evaluator capability. The current `Option<String>` seam, runtime lock, result collapse, and thenable assimilation are accurately identified in [engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes.rs:869](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:869), and [hermes_runtime.cc:3033](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033).

- §3’s entry-only TLA rule is a sensible v1 boundary for a synchronous `require()` runtime: static graphs are preflighted, while every executed `import()` is checked at call time. This avoids pretending Hermes has an asynchronous ESM linker.

- §7’s decision to start from a modified ECMAScript `GlobalEnvironmentRecord`, preserve object-versus-declarative records, and use late name lookup is conceptually sound. Independent measurements confirmed lexical shadowing, `var`/function asymmetry, adopted-property deletion, duplicate-`var` destructuring, TDZ `typeof`, non-extensible-global failure, inherited reveal, accessor reads, and directive-prologue relocation.

- The Deno/Bun precedent is accurate: both late-bind the closure example to `2`; Deno enforces a prior-input `const`, while Bun allows mutation to `10`.

- §7.7’s separation of model conformance, model validation, and lowering fidelity is a strong design. Excluding later directive prologues from concatenation is specifically justified by the measured strictness change.

- §8 is unusually honest about pure-JavaScript inspection. The current inspector invokes live property reads and Proxy traps at [inspect.ts:86](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:86) and [inspect.ts:393](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:393); completion evaluates through `Function` and reflective walks at [repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283). The staged base/safe-throw/rich-inspection contract is therefore appropriate.

- §7.9’s failing-module cache rule matches the loader: insertion precedes execution and only the failing entry is removed, leaving completed dependencies cached at [module-loader.js:5311](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5311) and [module-loader.js:5690](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5690).

3. **Concerns**

1. **Blocking — import evaluation invalidates the feasibility pass.**

   Evidence: §7.3 checks every `CanDeclareGlobal*` predicate in phase 3, then runs arbitrary imports in phase 4, then mutates the object record in phase 5 ([LLP 0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:956)). Root imports execute synchronously against the real global through [module-loader.js:5382](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5382) and [module-loader.js:5636](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5636).

   An import can prevent extensions or replace a later declaration target with an incompatible non-configurable descriptor. Sequential phase-5 instantiation can then publish an earlier non-configurable function/`var` before failing on the changed target—exactly the impossible rollback §7 was intended to eliminate. Import snapshot extraction in phase 5 can also invoke a throwing export getter after object mutations begin.

   §3 additionally retains the contradictory earlier story that imports execute “during instantiation” and roll back created bindings ([LLP 0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:418)).

   Resolution criterion: complete all import evaluation and potentially abrupt snapshot reads first; then rerun the full all-name feasibility pass immediately before mutation. Phase 5 must be demonstrably non-abrupt, or have an atomic reservation mechanism. Specify that successful import effects stand if post-import feasibility fails.

2. **Blocking — the cross-kind state is insufficient, and restricted names can be laundered.**

   Evidence: the modified predicate permits a lexical declaration over a non-configurable property whenever the name is in `[[VarDeclaredNames]]` ([§7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:963)). But `var undefined` legally adopts the existing property and adds `undefined` to that set ([matrix](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1017)). A later `let undefined` is therefore admitted, contradicting §7 and AC11. The same laundering applies to `NaN`, `Infinity`, and non-configurable endowments.

   The supposedly descriptor-keyed matrix also collapses materially different function cases. A configurable property becomes writable/enumerable/non-configurable; compatible non-configurable writable+enumerable data changes value only; a non-configurable accessor or incompatible data property must fail. Same-input function/`var` ordering, including reverse function scanning and Annex B, is not stated.

   Node confirmed the proposed adopted-`var` rule, but Hermes changed `{writable:false, enumerable:false, configurable:true}` into writable/enumerable/non-configurable, and turned configurable accessors into data properties. Native Hermes declaration instantiation therefore cannot be delegated this work.

   Resolution criterion: add provenance distinguishing session-created globals from adopted restricted properties; encode exact preconditions and post-descriptors for every function row; specify ordered `VarScopedDeclarations`; and generate fixtures for `var undefined ⏎ let undefined`, non-configurable endowments, multiple functions, `var`+function, configurable accessors, and all compatible/incompatible descriptors.

3. **Blocking — the submission credential lifecycle is circular for `.load`.**

   Evidence: §1 says the credential binds the source-byte digest and is atomically consumed exactly once before any effect ([§1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:202)), while `.load` must use that credential to authorize the read that first produces those bytes ([§1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:215)). The digest is generally unavailable before the gated effect.

   Current `.load` indeed reads ambiently before evaluation at [hermes.rs:1145](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1145) via [repl/mod.rs:930](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930), so this is a load-bearing replacement seam.

   Resolution criterion: specify two affine capabilities—an intent/read permit consumed by the typed read, producing an authenticated immutable byte capsule that is separately consumed by evaluation—or an equivalently precise state machine whose transition atomicity and “once” scope are unambiguous.

4. **Material — phase-6 cross-kind rollback has no unique observable result.**

   Evidence: for `const x=1` followed by `var x; boom()`, phase 5 removes the lexical cell and creates an object binding. §7.4 says object changes and `[[VarDeclaredNames]]` survive, the journal restores displaced lexical cells, and a failed input cannot destroy a prior binding ([§7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1071)). It never explicitly says whether removal by `var`/function counts as a journaled lexical replacement.

   One implementation will restore the old `const`, leaving the new non-configurable property and `[[VarDeclaredNames]]` hidden beneath it; another will publish the new `var`. Closures, `globalThis.x`, and the next redeclaration then differ. AC12’s “impossible inverse” case is also stale because §7.4 now forbids any object-record inverse ([AC12](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1602)).

   Resolution criterion: add a phase-by-phase failure table for every cross-kind pair, explicitly covering the declarative cell, object descriptor/value, `[[VarDeclaredNames]]`, closure lookup, and a subsequent declaration. Remove the obsolete object-inverse acceptance cases. Qualify the adopted-property deletion rule for inherited reveal.

5. **Material — `$_` cannot detect the ABA mutation it promises.**

   Evidence: §7.8 detects replacement by rechecking the getter/setter function identities and claims this catches identical-looking ABA restoration ([§7.8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1233)). User code can capture the original descriptor, delete the property, and restore that exact descriptor—including the exact same function objects. The check then passes. Attribute-only `defineProperty` mutations that retain those accessors also escape.

   The failure journal is separately ambiguous: `let $_; boom()` should roll back the declaration disable, but `var $_; boom()` leaves its adopted binding and `[[VarDeclaredNames]]` published, so its takeover should remain disabled. A user setter mutation during a failed lexical transaction must likewise not be undone. Current behavior simply writes `globalThis.$_` before rendering at [repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63).

   Resolution criterion: either add a native per-property mutation generation/watch and journal cause-tagged generations, or weaken the contract to mutations detectable at update time. Pin lexical-failure, `var`/function-failure, captured-descriptor ABA, attribute-only mutation, and background mutation during TLA.

6. **Material — the identity separation still reuses nouns, and `globalThis` names two objects.**

   Evidence: §2 calls its display string “source identity,” but LLP 0023 calls that `SourceLabel` and separately defines authenticated module `SourceId` ([LLP 0023 §2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:516), [SourceLabel](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:537)). There are therefore four concepts, not three: source label, `SourceId`, module cache identity, and retained-object evidence. §2 also calls retained platform identity a “live handle,” while 0023 defines a retained identity record, with a descriptor only as fallback ([LLP 0023 §2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:575)).

   Separately, §7.1 says the object-record binding object “is `globalThis`” ([§7.1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:818)). The retained realm global object is distinct from the writable `globalThis` property value. Both Node and Hermes continued putting later `var` properties on the retained realm object after `globalThis` was replaced with another object.

   Resolution criterion: use `SourceLabel` for serializable display names, reserve `SourceId` for 0023’s authenticated source, name the retained object record accurately, and call the environment’s binding object `RealmGlobalObject`/`[[ObjectRecordBindingObject]]`. Add overwrite/delete/accessor fixtures for the `globalThis` property. AC15 must name only `ibex:stdin` as a synthetic module key.

7. **Blocking — package isolation in deviation (d) is false in the shipping compartment.**

   Evidence: §7.7 says package modules see neither session lexicals nor session `var`s because their private global does not contain the latter ([§7.7](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1160)). LLP 0013 normatively says the compartment contains exactly its endowments ([LLP 0013](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:241)).

   In code, however, a package compartment is a Proxy that forwards every non-withheld read to the real global at [hermes_runtime.cc:2627](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2627) and reports real-global membership at [hermes_runtime.cc:2649](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2649). Only a finite powerful-name list is withheld. The loader binds package functions to that compartment at [module-loader.js:83](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:83). A session `var secret` is therefore visible to package bare `secret`.

   This is another noun-reuse failure: “private global” currently means a forwarding view, not isolated storage.

   Resolution criterion: change compartment lookup to a captured/generated safe-global and endowment set with no fallback to later arbitrary root properties, or revise deviation (d). Add package fixtures for session-created names and a session function that clobbers a shared builtin.

8. **Material — the three gates are well chosen but not yet executable or independent.**

   Evidence: §7.7 states in the present tense that every table is generated from an owner-authored executable model ([§7.7](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1180)), but no model, generator, schema, or generated fixture artifact exists in the repository.

   Gate 2’s “same lowering” is ambiguous: if the growing-script arm uses §7’s session-environment lowering, it validates the model against the implementation of that same model; if it excludes that lowering, the shared pipeline must be named. Gate 3 cannot run TS/import/TLA input “directly” on Hermes without defining a narrower domain. The current parser is only the existing `parse_program` path at [transpile.rs:120](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:120).

   Resolution criterion: check in and version the reference model and generator; name generated outputs and CI commands; define each gate’s exact source domain and transform pipeline; and ensure the growing-script oracle excludes the session-record implementation being validated.

9. **Material — §4’s source-map inventory contains a false stability claim.**

   Evidence: §4 calls LLP 0019’s tier-2 `for…of` rewrite line- and column-stable ([§4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:590)). The scanner preserves line count but moves the user’s RHS and emits substantial generated text at [module-loader.js:3512](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3512) and [module-loader.js:3524](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3524).

   SWC currently emits no map at [transpile.rs:183](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:183). Active unlisted mapless stages include the dirname-binding transformation and eval-shim preamble at [module-loader.js:5523](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5523), while `aliasNodePathGlobals`, which §4 treats as active, is merely an unused definition at [module-loader.js:3545](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3545).

   Resolution criterion: generate the actual active transform graph; each stage must retire, emit a composable map, or prove both line and column stability. Keep the source-position capability unavailable until an end-to-end adversarial fixture passes.

10. **Material — “unit” conflates evaluation lineage with cancellation work, leaving TLA/background behavior open.**

   Evidence: §6 calls a suspended TLA evaluation one asynchronous unit, then calls evaluations, callbacks, and completion queries work units with target IDs; §7.4 refers to jobs “belonging to” the TLA unit ([§6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:707), [§7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1097)). LLP 0025 OQ9 still asks whether the callback settling TLA is that unit or a separate unit.

   Cancellation is also internally inconsistent: accepted is described as the target returning, while normal return after delivery is defeated; for callbacks, §6 again says accepted merely means “it returned” ([§6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:756)). Current polling drains queues, timers, and microtasks without native unit boundaries at [hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541). Async reporting receives no owner metadata at [hermes_runtime.cc:681](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:681), and timer ownership scope ends before reporting at [hermes_runtime.cc:3653](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3653).

   Resolution criterion: define distinct `EvaluationId`, `WorkTargetId`, parent/settlement association, schedule-time principal, and sequence epoch. Specify native begin/end publication, TLA-settlement ownership, cancellation arbitration, and double-report prevention. Accepted must mean the work stopped because of the request and produced `cancelled`; normal or throwing completion is defeated.

11. **Material — the entry-only TLA rule lacks a reliable carrier in the current loader.**

   Evidence: `ResolvedModule` carries one `kind` at [module_loader/mod.rs:20](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:20), then changes logical ESM into `CommonJs` merely because transformation is needed at [module_loader/mod.rs:751](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:751). A secondary classifier omits `.mts` from ESM at [module_loader/mod.rs:982](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:982). SWC passes TLA through, Oxc rejects it independently, and dynamic import gates policy but does not consult a TLA manifest at [transpile.rs:97](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97), [transpile.rs:211](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:211), and [module-loader.js:6011](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:6011).

   Resolution criterion: split logical source kind from lowered execution representation; attach role, AST-derived TLA bit, and resolved dependency manifest before caching or execution; and route every dynamic-import target through the same manifest check. Prototype the Script-plus-import-plus-TLA parser on every advertised target before freezing fixtures.

12. **Material — error precedence is internally and cross-document inconsistent.**

   Evidence: §1 says `.load` precedence is outside-mount → policy denial → resolution failure ([§1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:222)); §2’s total order says resolution failure → outside-mount/path → … → policy denial ([§2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:309)). LLP 0023’s owned path order authorizes before absence ([LLP 0023 §7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1273)). The `interim` class claims LLP 0022 §2 ownership, but no such class now exists there.

   Resolution criterion: define one generated discriminated error algebra with operation-specific applicability and a single precedence relation. Add multi-failure fixtures for `.load`, static import, dynamic import, builtin, outside-mount, denial, absence, TLA, and out-of-snapshot cases; remove or re-home `interim`.

4. **Cross-document findings**

| Stable ID / dependency | Current finding |
| --- | --- |
| `0025/OBL-LIFECYCLE-MECHANISM` | False in the outstanding→delivered direction: 0024 §6 now explicitly parks, reports out of band, and disposes the worker. |
| `0025/OBL-CANCEL-ALGEBRA` | Its “delivered” attestation is too strong: 0024 still conflates accepted with returning for callbacks and queries. |
| `0025/OBL-UNIT-PUBLICATION` | Correctly outstanding. 0024 assigns IDs but does not define native begin/end publication for timers, callback drains, or microtasks; 0025 OQ9 remains open. |
| `0025/OBL-SEQUENCE-ALLOCATOR` and `0022/OBL-SEQUENCE` | Partial only. 0024 includes broker events in the domain but does not name the supervisor as allocator owner or specify crash epochs and worker restart. |
| `0022/OBL-SUBMIT-CREDENTIAL` | Textually present, but not discharged until the read-permit/byte-capsule consumption cycle is made implementable. Separately, 0022 lines 727–728 are stale in the opposite direction: 0024 no longer lacks the credential or uses “decision evidence” as input provenance. |
| `0022/OBL-CANCEL-TARGETS` | Partial: 0024 carries a target ID, but the request does not carry the target kind that this row requires. |
| `0022/OBL-UTF8` | Partial: strict UTF-8 refusal is specified, but transcript resynchronization is not. |
| `0022/0023 OBL-MODULE-IDENTITY` | §7.9 is aligned, but AC15 reintroduces “synthetic sources … keyed without a file object,” wrongly including scripts. 0023’s old pinned attestation is outdated. |
| `0022/OBL-BOUNDS` | Stale: current 0025 §12 now pins several renderer/tree constants, while 0024 OQ8 still calls them open. The claimed `session-constants.json` artifact is itself absent. |

The rows that are directionally satisfied at the specification level include `OBL-EVAL-OUTCOMES`, `OBL-EXIT-MECHANISM`, `OBL-CELL-MODEL`, `OBL-SAFE-DISPLAY`, `OBL-DISPLAY-ACK`, `OBL-NO-EVAL`, `OBL-INGRESS-CTX`, `OBL-DRAIN`, and `OBL-DISPLAY-TREE`.

Additional drift:

- LLP 0023 §2.3 still lists `repl:<n>` and `ibex:eval` among modules without file objects at lines 491–495, then correctly says they are not modules at lines 545–552.
- LLP 0022 OQ1 cites “LLP 0024 OQ2” for trap-free inspection; it is currently 0024 OQ1.
- The source-identity/`SourceId`/`SourceLabel` terminology and retained-handle description conflict as described in Concern 6.
- The import-phase prose, error order, and `interim` class are dangling dependencies rather than merely editorial duplication.
- “Unit” means evaluation lineage in 0024 but interruptible work target in 0025; the unstated mapping is a semantic dependency.

5. **Suggestions**

- Recast phases 3–5 as a prepared binding plan: imports and snapshot reads run first; the evaluator captures descriptors and provenance; a pure model computes an immutable plan; one non-abrupt commit applies it. This makes the no-object-rollback invariant constructive.

- Seriously prototype the native global-environment-record option from OQ9. The lowering now needs complete Reference rewriting, source maps, mutation-aware `$_`, a realm-global distinction, and closure fidelity. Since several Hermes patches are already required, a native checked record may be the smaller and safer total change.

- Check in the executable reference model before another prose review. Generate the matrix, rollback table, acceptance fixtures, and stable obligation claims from it; otherwise the section remains the kind of hand-maintained table it correctly argues against.

- Make cross-document joins machine-readable: error tags, obligation IDs, source-label/`SourceId` types, session constants, and unit identifiers should each have one owning artifact.

- Correct §8’s console carve-out wording. `console.log(obj)` currently invokes runtime-authored inspection that may execute getters or Proxy traps; it is an accepted program-output risk, but the program did not literally “format its own object.”

6. **Open questions**

1. Can the chosen parser actually admit sloppy Script grammar plus static imports and entry TLA without silently imposing Module early errors, including on Windows?

2. Is a native session global-environment record cheaper and more verifiable than complete free-reference lowering once source maps, descriptors, TDZ, cancellation, and `$_` mutation observation are included?

3. What is the exact relationship between a suspended evaluation, the callback that settles its TLA promise, microtasks it needs, and separately cancellable background work?

4. What primitive can provide both causal cancellation and a reusable-runtime consistency check, and can it publish target boundaries without relying on the current whole-poll FFI call?

5. Will package globals become captured safe surfaces, or is session-`var` visibility into packages an intentional deviation? The current corpus and implementation answer differently.

6. Which worker/VM hooks jointly own safe throw capture, async-failure principal metadata, completion records, trap-free inspection, and `$_` mutation generations? The current “three slices” patch program omits at least the async-owner and mutation-observation requirements.

7. Which canonical `SourceLabel` represents an aliased module instance, and can LLP 0023 close that question without making import order observable?

7. **Readiness verdict**

The central design is promising, but the phase-ordering failure, restricted-name laundering, credential cycle, and false package-isolation premise are unresolved correctness/security blockers. The rollback, `$_`, identity, work-unit, loader, source-map, and error-order gaps are independently material.

VERDICT: NOT READY

### Orchestrator verification notes

Both round-5 reviewers converged on the same two blocking findings, and both are real. I
re-measured every decisive claim.

**The error order (Codex 12 / Fable C1) — confirmed, and mine was the security defect.**
My §2 put `resolution failure` *second*, ahead of the path classes and policy denial. That
is an **existence oracle**: an unauthorized caller learns whether a resource exists before
any decision that would have denied them. It also contradicted my own §1. The galling part
is that **LLP 0023 already had this right** — its §7.2 row 8 is annotated "*after*
authorization, never before", its AC is named "No existence oracle", and it had already
fixed one instance of the same bug. My rationale ("what a specifier *is* precedes where it
*resolves*…") *sounded* principled and **was** the disclosure channel. §2 now defers the
total order to LLP 0023 §7.2 and states only the staging invariant.

**Phase-5 interference (Codex 1 / Fable C2) — confirmed, and it is a defect my own round-4
fix created.** Moving imports before instantiation removed the *rollback* problem but not
the *interference* problem: phase 4 runs arbitrary user code, so phase 3's feasibility
answers are stale. `import "./m"; var x` where `m` calls `preventExtensions(globalThis)`
would publish some non-configurable bindings and then fail on the rest. Both reviewers
independently proposed the same fix and it is right: **re-check every `CanDeclareGlobal*`
immediately before mutating**. Because instantiation runs no user code — an ordinary
`DefineOwnProperty` fires no getter, setter, or trap — recheck-then-mutate is atomic with
**zero engine support**.

**Restricted-name laundering (Codex 2) — confirmed by construction, and Fable missed it.**
Fable measured `let undefined` → `SyntaxError` and pronounced the predicate "the minimal
correct modification"; it had not tried `var undefined ⏎ let undefined`. `var undefined` is
legal and inert — it *adopts* the property — and under the old `[[VarDeclaredNames]]`
predicate it thereby admitted `let undefined`. Re-keying on **provenance**
(`[[SessionCreatedVars]]` — names whose property the record *created*) closes it, since
adoption is not creation. A good illustration that a passing measurement of the *stated*
case proves nothing about the *laundered* one.

**Package isolation (Codex 7) — confirmed against the code, and this one is a genuine
security finding.** LLP 0013 says the compartment's properties are "exactly the policy's
endowments". The shipping compartment is a `Proxy` whose `get` trap **forwards every
non-withheld name to the real global**, withholding only `__exact*`/`__ibex*` and a finite
powerful-name set. A session `var` is an ordinary name on the realm global — so a package's
bare `secret` reads it, and an operator typing `var apiKey = "…"` at the prompt hands it to
every package in the graph. **This is a disclosure channel my own design creates**, by
making session `var`s real realm-global properties. Deviation (d) now states the truth
rather than asserting an isolation the platform does not provide, and places the closing
requirement on LLP 0013 (`isWithheld` must not forward a name in `[[SessionCreatedVars]]` —
a small change at a seam that already exists). Fable checked the *document* and reported
agreement; Codex checked the *code* and found the divergence. That difference is the whole
argument for a two-family loop.

**"Handle" is the fourth noun-reuse casualty (Fable C8) — confirmed, and the sharpest yet.**
§6 said a handle "never crosses a process boundary"; §1 called the armed-snapshot reference
a "handle" — and *that one must cross*. One noun, one crossing rule, two objects on opposite
sides of it. The snapshot reference is now a **token** (0023's word) and §6's rule is scoped
to **value handles**. Also adopted: 0023's **SourceLabel** for display names.

**Deviation (c) narrowed (Fable suggestion 4) — a real improvement.** Rolling back *every*
lexical cell created a keyword-dependent asymmetry (`var w = 1; boom()` keeps `w`;
`let x = 1; boom()` loses `x`) that no growing script exhibits and that diverges from Node
and Deno. The deviation is now only what TDZ poisoning actually forces: an **uninitialized**
cell is removed; an initialized one survives.

**Gate 2b (Fable suggestion 2) — adopted, and it closes a hole in my own oracle.** An
engine-relative gate cannot see a wrong *model of ECMAScript* in a row the engine itself gets
wrong — and Codex measured that Hermes **does** get rows wrong (it rewrites an adopted
property's descriptor and turns configurable accessors into data properties). Two normative
consequences now stated: the lowering must define its own properties rather than delegate
declaration instantiation to the engine, and the matrix must be validated against a standards
engine.

**Also confirmed and fixed:** the `interim` class cited a state LLP 0022 has retired (deleted);
AC12 carried "engine fault / failed transaction" vocabulary from the retired property-rollback
model (deleted); `[[VarDeclaredNames]]` survival on a phase-6 failure was observable and
unpinned; the `$_` disable's rollback contradicted both §7.4 and its own "permanently" (now
tied to whatever triggered it); the sequence allocator had no owner (the session layer, at
receipt — the only party the threat model trusts); native **unit publication** was owed to
LLP 0025 §6 and uncarried; and my source-map inventory was wrong in *both* directions —
`aliasNodePathGlobals` is dead code I listed as active, while two live mapless stages went
unlisted. It is now generated, and tier-2 is claimed **line-stable only**, which is all the
scanner's own comment ever claimed.

**Not adopted.** Nothing material was rejected this round. Fable C13's harness point was
accepted as a *provenance* correction rather than a defect: two premises genuinely cannot be
shown with the standalone binary, and the premises table now says which harness shows them.


## Round 6 — 2026-07-12

**Reviewer family:** Codex / GPT (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`.
Run from the **main session**.
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra` — confirmed in the log, no substitution
**Codex session id:** `019f562b-5f62-7812-adf2-986c3497f3e8`
**Integrity:** the session rollout's final message hashes to md5 `e2639e46b30b`,
byte-for-byte equal to the captured file recorded below.
**Revision under review:** `88ebc6349bab` (first 12 hex of `shasum -a 256`; content
hash, not a Git object — LLP 0025 independently stamps the target `0024@88ebc6349bab`).
**Redaction:** none.
**Independence:** fresh non-interactive session; no access to this orchestrating
session, to the concurrent Fable round-6 review of the same revision, or to any prior
LLP 0024 artifact. Both earlier artifacts were stashed out of `llp/reviews/` for the
duration; main independently verified the stash held.
**Method:** `brief-round6.md` verbatim — re-measure every empirical claim, hunt the
fifth noun-reuse casualty, and independently probe the shipping compartment leak.

### Verbatim review

1. **Overall assessment**

The proposal has a strong architectural direction, and all asserted empirical premises reproduced on macOS/arm64 with Hermes 1.0/HBC 99, Node 24.14.0, Deno 2.9.1, and Bun 1.3.12. This includes the Hermes limitations, revoked-Proxy behavior, GlobalEnvironmentRecord semantics, Deno/Bun precedent, descriptor behavior, and the shipping package-compartment leak.

It is nevertheless not ready as a normative Spec. §7 still contains several independently blocking algorithm defects: the provenance repair is absent from the normative state machine, phase 5 is not atomic, rollback does not determine a unique state, and `$_` promises ABA detection its mechanism cannot provide. The validation gates, work-unit model, dynamic-TLA preflight, vocabulary separation, and sibling obligations also remain materially incomplete.

Provenance caveat: `88ebc6349bab` is not a Git object in this checkout, and 0022–0025 are untracked working-tree files. LLP 0025 itself stamps the target as `0024@88ebc6349bab`; this review covers the complete current bytes at the requested paths.

2. **Strengths**

- The engine premises are unusually honest and technically important. The document correctly refuses to build on nonexistent Hermes TDZ, runtime `const`, native ESM, native TLA, direct-eval lexical scope, or per-iteration bindings ([0024:153](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:153)). The current capability flags corroborate the native ESM/TLA limits ([hermes.rs:1653](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1653)).

- §1–§4 separate source role, entry kind, dialect, goal, and module kind, and correctly refuse to disguise entry-only TLA as an asynchronous module linker ([0024:198](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:198), [0024:428](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:428)). The shipping loader really is a synchronous `require()` architecture, and the document accurately identifies its inconsistent SWC/Oxc/bootstrap TLA behavior ([transpile.rs:84](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:84), [module-loader.js:5588](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5588)).

- §7 imports the GlobalEnvironmentRecord model instead of inventing identifier semantics from scratch. The real-realm-global rule, lexical/property shadowing, late-bound closures, created/adopted descriptor matrix, inherited-property behavior, and “never delete the object record” invariant are sound design choices ([0024:904](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:904), [0024:998](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:998), [0024:1121](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1121)).

- The empirical ECMAScript claims are correct: lexicals shadow rather than delete properties; bare `var Object` is inert while `function Object(){}` overwrites it; adopted descriptors survive on a standards engine; fresh `var`s are non-configurable; `var [a,a]` is legal while `let [a,a]` is not; TDZ `typeof` throws; and `var` on a non-extensible global throws. The separate standards-engine gate is therefore genuinely necessary.

- §6 and §8 correctly identify the current ABI and inspection hazards. The current engine collapses `undefined` with empty completion, returns NUL-terminated strings, assimilates thenables, and has no cancellation operation ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes_runtime.cc:3033](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033)). Current inspection invokes getters and Proxy traps ([inspect.ts:85](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:85), [inspect.ts:393](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:393)). The staged, advertised inspection strata are the right response.

- The package-security disclosure is truthful. The shipping compartment really is a forwarding Proxy: ordinary reads fall through to `g[prop]`, while only a finite powerful-name set is withheld ([hermes_runtime.cc:2620](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2620)). An empirical probe returned a session `var` through a package compartment while withholding `process`.

- Making §7 executable reference data and separating model conformance, model validation, standards correctness, and lowering fidelity is an excellent decision in principle ([0024:1330](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1330)).

3. **Concerns**

1. **Blocking — the provenance-keyed restricted-global repair is not in the normative algorithm.**

   Evidence: The revision note says the predicate was re-keyed to `[[SessionCreatedVars]]`, but §7.1 never defines that set, phase 5 never updates it, and §7.3 still exempts every name in `[[VarDeclaredNames]]` ([0024:913](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:913), [0024:1064](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1064), [0024:1075](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1075)). Consequently, `var undefined ⏎ let undefined` is admitted, contradicting measured Script semantics and AC11 ([0024:1768](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1768)). The reference-model tuple and observation channel also omit the purported state ([0024:1330](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1330), [0024:1372](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1372)).

   Resolution criterion: Define property-creation provenance, all created/adopted/deleted/recreated transitions, rollback behavior, model state, observation channel, and generated fixtures. The exact laundering sequence must fail.

2. **Blocking — `[[SessionCreatedVars]]` conflates property provenance with package-disclosure provenance.**

   Evidence: The restricted predicate needs a set that excludes adopted properties such as `undefined`. The package rule instead needs every name whose current realm-global value was supplied or overwritten by session code ([0024:1135](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1135), [0024:1313](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1313)). Those are different sets. Empirically, `var TextEncoder = 417` adopted an existing non-configurable but writable property, and the package compartment returned `417`. Moreover, changing only `isWithheld`’s `get` path still leaves the Proxy’s `has` trap reporting `(prop in g)` ([hermes_runtime.cc:2627](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2627), [hermes_runtime.cc:2649](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2649)).

   Resolution criterion: Use distinct, precisely named state for property-creation provenance and package-visible session writes, or preferably give package compartments a stable baseline endowment table rather than a live fallback to the realm global. Specify bare reads, `typeof`, `in`, `has`, descriptors, and enumeration.

3. **Blocking — phase 5 is non-atomic in two independent ways.**

   Evidence: First, phase 4 may create a new non-configurable property at a pending lexical name, but phase 5 rechecks only `CanDeclareGlobal*`; it does not rerun the modified restricted-global predicate ([0024:1074](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1074)). Thus a module in `import "./m"; let x` can install non-configurable `x` after phase 3 and still have the lexical instantiated.

   Second, phase 5 says it takes import snapshot values after the final recheck while asserting that no user code runs. CommonJS named/default extraction performs ordinary property Gets, so an accessor or Proxy can mutate the global, call `preventExtensions`, or throw after the recheck ([module-loader.js:4558](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4558), [module-loader.js:4761](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4761), [module-loader.js:4807](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:4807)).

   Resolution criterion: Phase 4 must evaluate imports and materialize/root every effectful interop and export Get. Phase 5 must then rerun the complete feasibility vector—including lexical restrictions—and perform only inert mutations from captured values. Engine faults during commit must poison/discard the runtime rather than imply rollback.

4. **Blocking — rollback does not define a unique declarative-record state.**

   Evidence: §7.4 says initialized lexicals survive failure and a displaced cell is restored “underneath either way” ([0024:1189](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1189)). A single declarative record cannot simultaneously expose an initialized replacement and hold a same-name prior cell underneath it. AC12 says both that `let x=1; throw` does not publish `x` and that it leaves `x=1` ([0024:1787](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1787), [0024:1801](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1801)). It also treats `let $_; boom()` as uninitialized, although `let $_;` initializes the binding to `undefined` before `boom()`.

   Resolution criterion: Choose one per-cell rule. If initialized replacements commit, discard the displaced cell and weaken “a failed input cannot destroy a prior binding.” Restore the displaced cell only when the replacement remains uninitialized and is removed. Replace the `$_` fixture with `boom(); let $_` or `let $_ = boom()`.

5. **Blocking — the specified `$_` ABA detection is impossible.**

   Evidence: `$_` is a configurable accessor whose getter and setter are observable through `Object.getOwnPropertyDescriptor`. User code can save the exact descriptor, delete or replace the property, and restore the exact same descriptor. The later function-identity check passes, contradicting §7.8 and AC14 ([0024:1388](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1388), [0024:1829](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1829)).

   Resolution criterion: Add a native, monotonic mutation version for the realm-global `$_` property, or explicitly weaken the guarantee. Descriptor identity can detect newly created functions, not restoration of the original functions.

6. **Blocking — the validation gates are internally inconsistent and partly unsatisfiable.**

   Evidence:

   - §7.7 says “three gates” but lists 1, 2, 2b, and 3. AC13 again says three and omits gate 2b ([0024:1340](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1340), [0024:1809](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1809)).
   - Gate 3 compares lowering with direct execution, but conforming lowering must deliberately differ from direct Hermes for TDZ and runtime `const`.
   - Gate 2 excludes directive prologues only after the first input. A first-input `"use strict"` makes the concatenated oracle strict for all later text, while the session applies strictness per input ([0024:1361](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1361)).
   - Gate 2b needs fresh actual realms or subprocesses. `vm.createContext` is not equivalent: its contextified global has different descriptor and extensibility behavior.

   Resolution criterion: Normatively specify four gates and include 2b in acceptance. Restrict gate 3 to transformations that do not intentionally repair Hermes, or compare with the reference/standards oracle. Exclude all directive-prologue cases from gate 2 unless effective strictness is proven equal. Pin fresh-process isolation for gate 2b.

7. **Material — the vocabulary separation does not hold, and the fifth noun casualty is `unit`.**

   Evidence: After §2 distinguishes `SourceLabel`, `SourceId`, module identity, value handle, and session token, the request schema still says “synthetic identity,” the security credential binds an unqualified “source identity,” the armed-session token is still called a handle, and source maps are keyed by “source identity” ([0024:214](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:214), [0024:221](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:221), [0024:658](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:658)).

   More seriously, `unit` denotes both an aggregate TLA evaluation/outcome owner and individually targetable evaluation, callback, timer, microtask-drain, and query activations ([0024:762](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:762), [0024:803](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:803), [0024:1225](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1225)). `Epoch` is a likely sixth casualty: worker-restart epoch, LLP 0025 work epoch, and LLP 0025 control-channel epoch are different concepts ([0024:1608](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1608), [0025:439](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:439), [0025:663](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:663)). `Entry` is explicitly separated and `snapshot` is sufficiently qualified; neither appears to be the fifth defect.

   Resolution criterion: Use exact schema types everywhere. Split, for example, `EvaluationTaskId` from `ExecutionSliceId`, and rename the epochs `WorkerIncarnation`, `WorkEpoch`, and `ControlChannelEpoch`.

8. **Material — job checkpoints, nesting, and cancellation ownership are undefined.**

   Evidence: The current native eval drains next ticks and microtasks only after the entire source evaluation ([hermes_runtime.cc:3004](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3004)). A phase-4 implementation using a separate eval call would instead run imported modules’ queued jobs before phase 5, changing feasibility. The spec does not select either behavior.

   One poll also drains callback queues, pending tasks, next ticks, microtasks, and several timers ([hermes_runtime.cc:3541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3541), [hermes_runtime.cc:3634](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3634)). No target stack explains which ID is current during callback → nextTick → microtask nesting or whether cancellation of an awaiting evaluation propagates. The generic `accepted` definition says it produces a `cancelled` outcome, while the callback/query rule says accepted merely means the unit returned ([0024:832](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:832), [0024:868](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:868)).

   Resolution criterion: Pin whether any job checkpoint exists between phases 4, 5, and the initial synchronous portion of phase 6. Define task/slice parentage, target stacks, cancellation propagation, settlement ownership, and per-target terminal results.

9. **Material — dynamic dependency-TLA refusal is not explicitly transitive, and `require()` is uncovered.**

   Evidence: Static entry preflight is expressly transitive, but `import()` says only that the selected target is checked ([0024:453](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:453)). If dynamic target A contains no TLA but statically imports B that does, checking only A begins execution before refusal. Synchronous `require()` is not assigned either the static-entry or `import()` rule.

   Current resolved-module and transform results contain no dependency/TLA manifest ([module_loader/mod.rs:28](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:28), [transpile.rs:84](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:84)); dynamic import simply enters `load()` in a microtask ([module-loader.js:6011](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:6011)).

   Resolution criterion: Define manifest edge kinds and require call-time transitive preflight of a selected dynamic target’s complete static closure before cache insertion or evaluation. State the corresponding rule for every executed `require()`.

10. **Material — feasibility is plausible, but the implementation plan is not yet adequate.**

    Evidence: The required Script-plus-import/TLA goal does not exist in the pinned parser, and the mechanism remains an open question ([0024:397](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:397)). The current emitter produces no source map ([transpile.rs:183](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:183)). The engine seam returns `Option<String>`, has no cancellation method, and serializes runtime FFI through a mutex ([engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), [hermes.rs:542](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:542)). Current REPL wrappers lose declarations under TLA and use unsafe JavaScript inspection/completion paths ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63), [repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283), [repl/mod.rs:1174](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1174)).

    Resolution criterion: Produce the companion Plan requested by `OBL-PLAN`, selecting a parser strategy and separately prototyping the environment lowering, concurrent cancellation/reuse check, unit publication, source-map pipeline, and trap-free VM inspection. Define a minimal conformant v1 and dependency order.

4. **Cross-document findings**

- **LLP 0022 obligations:**

  - `OBL-SUBMIT-CREDENTIAL` is false in both the body and ledger: 0022 specifies one one-shot linear credential, while 0024 deliberately requires two affine permits to avoid the `.load` circularity ([0022:680](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:680), [0022:967](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:967), [0024:222](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:222)). The nearby claim that 0024 still uses “decision evidence” is also now false.
  - `OBL-CELL-MODEL` is not discharged because the provenance, phase-5, and rollback algorithms are defective.
  - `OBL-CANCEL-TARGETS` requires target kind plus ID; 0024 normatively carries only an ID and has conflicting generic/evaluation acceptance semantics ([0022:973](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:973)).
  - `OBL-MODULE-IDENTITY` is contradicted by 0024 itself: §7.9 correctly says only `ibex:stdin` is a synthetic module, but AC15 says the plural “synthetic sources of §2” are keyed ([0022:984](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:984), [0024:1837](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1837)).
  - `OBL-UTF8` is only half-delivered: strict refusal is specified, but transcript resynchronization or fatality is not ([0022:989](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:989)).
  - `OBL-BOUNDS` says bounds are open in both documents. That is now false: LLP 0025 normatively pins the engine-independent values, although `session-constants.json` remains owed ([0022:990](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990), [0025:956](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:956)).
  - `OBL-EXIT-MECHANISM` describes worker park/disposal corpus-wide, while LLP 0025 has distinct worker and in-process `_exit` realizations. How an in-process `_exit` exposes 0024’s lifecycle outcome remains dangling ([0022:960](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:960), [0025:701](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:701)).
  - `OBL-SEQUENCE` is now aligned: both documents assign sequence numbers at session-layer receipt. It should not be reported stale.
  - LLP 0022’s inspection open question points to “0024 OQ 2,” but trap-free inspection is now OQ 1 ([0022:1184](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1184)).

- **LLP 0025 obligations:**

  - `OBL-UNIT-PUBLICATION` is marked delivered, but that overstates the result while the immediately adjacent `OBL-SUSPENDED-UNIT` remains open. Publication kinds are listed; their boundaries and nesting are not defined ([0025:940](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:940), [0025:943](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:943)).
  - `OBL-CANCEL-EDGES` correctly records an unmet obligation: 0024 must separate evaluation `cancelled` outcomes from callback/query return semantics ([0025:941](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:941)).
  - `OBL-SEQUENCE-ALLOCATOR` is true and aligned at this revision ([0025:942](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:942)).
  - `OBL-SUSPENDED-UNIT` is an explicit dangling dependency that blocks cancellation selection and async-failure deduplication.

- **Other sibling contradictions:**

  - LLP 0022 says a work epoch closes on quiescence plus prompt republication and that two interrupts within an epoch terminate. LLP 0025 defines closure at quiescence alone and requires the same class and epoch for the two-press optimization ([0022:892](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:892), [0025:439](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:439), [0025:944](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:944)).
  - LLP 0023 first lists `repl:<n>` and `ibex:eval` as no-file modules, then correctly states that they are scripts without module identity ([0023:566](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:566), [0023:647](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:647)).
  - 0024’s warning that LLP 0023 lacks a Root `SourceId` arm is stale; 0023 now defines it explicitly ([0024:1444](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1444), [0023:604](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:604)).
  - LLP 0023’s `OBL-MODULE-IDENTITY` and `OBL-ERROR-ORDER` attestations are stale against the current target ([0023:1613](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1613)).

- **Governing-document contradiction:** LLP 0013 normatively says a package global’s properties are exactly its policy endowments, whereas shipping code and 0024 describe a forwarding view of the realm global ([0013:239](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:239), [0024:1294](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1294)). Stating the leak truthfully is good, but the corpus presently has two incompatible normative meanings of “private global.”

5. **Suggestions**

- Redesign phases 4–5 around an explicit commit capsule: rooted import snapshot values, the complete feasibility result, and no remaining property access capable of executing code.

- Replace `[[SessionCreatedVars]]` with separately named provenance concepts, or eliminate live realm-global forwarding from package compartments entirely.

- Add a native per-realm/global-property mutation counter. It would provide honest `$_` ABA detection and could assist phase-interference diagnostics.

- Consider the engine-native session GlobalEnvironmentRecord proposed in OQ9 more seriously. Given that native work is already required for cancellation, work publication, inspection, and error capture, it may be smaller and safer than a whole-program free-identifier lowering plus five deviations.

- Turn each discovered counterexample into generated model data: lexical restriction introduced by an import, CJS export getter after recheck, exact-descriptor `$_` ABA, initialized replacement over an old cell, first-input strict prologue, and dynamic A → static B(TLA).

- Run gate 2b in a fresh Node subprocess or worker per fixture. Do not substitute `vm.createContext`.

- Make obligation-ledger validation executable. Several rows are already false despite being revision-stamped, exactly the failure the ledgers are intended to prevent.

6. **Open questions**

- What are the exact two—or more—provenance sets needed for restricted globals, session writes, and package visibility?

- On failed input, does an initialized replacement commit and destroy the displaced cell, or does the prior binding win? There is no coherent middle state.

- Is there a microtask checkpoint between phases 4 and 5? Which jobs belong to a suspended TLA evaluation rather than background work?

- Is the callback settling a TLA promise part of the evaluation target or a separately cancellable execution slice?

- Must `require()` apply the same transitive dependency-TLA refusal as static and dynamic import, and at what exact point relative to cache insertion?

- Is package isolation intended to hide only session values, or also property existence, descriptor shape, and later mutations of shared intrinsic bindings?

- Which parser implementation will supply Script early errors plus static imports and TLA, and has it been prototyped against the sloppy-only corpus?

- How is a lifecycle outcome observed in in-process modes that terminate through `_exit` inside the accepted call?

- Should the native environment-record patch replace the session lowerer before the corpus commits to its extensive Reference-preserving rewrite?

7. **Readiness verdict**

The direction is good, but the current text contains unresolved blocking correctness, atomicity, security, test-oracle, and state-model defects.

VERDICT: NOT READY

### Orchestrator verification notes

Both round-6 reviewers converged on the two blockers, and the first is a **process failure of
mine that is the exact disease the document diagnoses**: my round-5 python replace for the
restricted-global predicate *silently did not match*, so I wrote a revision note claiming the
predicate was re-keyed on `[[SessionCreatedVars]]`, referenced the set in four places, and
never changed the predicate itself. The laundering path the note said was closed was open. I
re-verified every decisive claim.

**Blocking 1 (Codex B1, Fable C1) — confirmed by grep against my own file.** §7.3's predicate
still read `[[VarDeclaredNames]]`; §7.1 never defined `[[SessionCreatedVars]]`; the matrix
never populated it. Now: §7.1 defines the set, the matrix has a **Populate** column (created
vs adopted), the predicate keys on it, the reference-model tuple carries it, and AC11 pins
`var undefined ⏎ let undefined` → `SyntaxError`. The lesson I recorded in §3 last round — *a
fix that removes a premise must be chased through every place it was assumed* — applies to my
own tooling: an `assert`-less replace that no-ops is invisible, so I now assert every edit and
grep after. This is the second silent-replace miss (the first was AC8 in round 5); the
discipline is now mechanical.

**Blocking 2 (Codex B4, Fable C2) — confirmed.** AC12 demanded both "`let x = 1; throw` does
not publish `x`" (round-4) and "`let x = 1; boom()` leaves `x` as 1" (round-5) — the same
program, opposite outcomes. Resolved with **one rule**: a binding commits iff it reached
initialization. `let x = 1` initializes before the throw, so it commits and `x` is 1; the
round-4 line is deleted. Codex B4/Fable C3's cross-record case is resolved the same way: a
`var` that commits does not get a dead `let` restored under it (there is no coherent state
where a restored cell shadows a surviving `var`), so `let x=1 ⏎ var x=2; boom() ⏎ x` is 2. The
slogan narrows to "an input that fails *before its replacement commits* cannot destroy a prior
binding", exactly as both reviewers required.

**Codex B2 (two different provenance sets) — confirmed and honored.** The restricted-predicate
set (`[[SessionCreatedVars]]` = *created*) is genuinely different from the package-visibility
set (session-*authored* values, which includes adopted-and-assigned like `var TextEncoder=417`
and sloppy `apiKey=s`). I did **not** force one set to serve both. `[[SessionCreatedVars]]` is
the predicate's; deviation (d) now states that the withhold-`[[SessionCreatedVars]]` patch is a
*partial* mitigation and the complete fix is a compartment **baseline captured at arming** that
does not forward to the live realm global at all — which closes existence (`in`/`has`),
descriptors, and every spelling. Fable C7 independently found the sloppy-spelling residual;
both are now stated with the fixtures that fail today.

**Codex B3 (phase 5 non-atomic two ways) — confirmed and both closed.** (1) Phase 5 rechecked
only `CanDeclareGlobal*`, not the lexical restricted predicate — now it rechecks the **full**
vector. (2) CJS export extraction does property Gets that can run accessors after the recheck —
now **phase 4 materializes and roots every import value** before phase 5, so phase 5 reads only
captured values and runs no Get. An OOM during the inert commit poisons the runtime (§6) rather
than implying rollback.

**Codex B5 (`$_` ABA impossible) — confirmed by measurement** (`d.get === original` after
delete-and-redefine with the captured descriptor). I over-claimed. §7.8 now states the honest
limit: descriptor-identity catches new functions and deletion but **not** exact-descriptor
restoration; the complete fix is a native mutation counter joining the §8 patch program; and
`$_` is framed as a best-effort convenience, not a security boundary — so the residual is
acceptable *and stated*. Same "shrink the promise" move.

**Codex B6 / Fable C4 (gates: four, not three; AC13 omits 2b) — confirmed.** §7.7 and AC13 now
say **four**; gate 2b's harness is a **fresh realm per fixture (subprocess/Worker, not
`vm.createContext`** — I measured that `vm.createContext` gives a *configurable* var, unsound as
the oracle); the quirk-filter is owner-authored data carrying both measured outputs; gate 3
excludes the deliberate Hermes-repairs; and gate 2 excludes a directive prologue on **any**
input (Codex's first-input case). Fable C6's completion-fold defect is fixed: the observation
channel folds per-input completions by `UpdateEmpty` rather than comparing whole-script
completion, and `$_`-referencing inputs are excluded from the class.

**Fable C5 / Codex M8 (phase-4 microtask) — answered.** Phases 1–5 run within one job, no
checkpoint; import-queued jobs drain at the first phase-6 checkpoint and are classified
background. This is the only rule under which the phase-5 atomicity argument holds, so it is
stated.

**Fable C8 (fifth noun = "epoch") — confirmed and fixed.** Sequence epoch (worker-restart) vs
0025's work epoch (interrupt latch) vs channel epoch — three counters, one word, incompatible
reset rules. §2's table gains rows for both epochs and for **work unit vs settlement unit**
(the sixth latent one). "snapshot" is disambiguated (deviation (b) → "values copied at
import"). The *source label* sweep is completed (0 residual "source identity").

**Cross-document, both reviewers:**
- **Sequence allocator** — 0025 says the supervisor owns it and the worker draws ranges; I said
  session-layer-at-receipt and forbade worker minting. These reconcile: a *drawn range is
  pre-authorized*, so within-range worker numbering is not unsupervised minting. I adopted
  0025's mechanism and said so. **Reported to coordinator.**
- **Credential shape** — 0022 §7 specifies one one-shot credential binding the byte digest; my
  §1 keeps **two affine capabilities** because binding the byte digest before the `.load` read
  that *produces* the bytes is circular. I did **not** defer to 0022 here — 0022's contract has
  the defect, and the mechanism-consumer found it. **Reported to coordinator that 0022 §7 needs
  the two-permit revision**, plus its stale "0024 still uses 'decision evidence'" sentence
  removed (false since round 4).
- 0025 ledger rows now delivered (`OBL-UNIT-PUBLICATION`, `OBL-LIFECYCLE-MECHANISM`); 0023's
  root `SourceId` arm has landed, so my §7.9 conditional is softened; OQ8's constants annex now
  exists (0025 §12) and OQ8 is narrowed to what remains open.

**Not adopted.** Nothing material was rejected. Fable's suggestion to run gate 2b against *two*
standards engines is recorded as a CI refinement in the gate-2b prose (a filter entry needed by
both engines is a model bug; by one, a quirk) rather than mandated, since one fresh-realm V8 is
sufficient for conformance and the second engine is a strengthening, not a requirement.


## Round 7 — 2026-07-12 — TERMINAL two-family round

**Reviewer family:** Codex / GPT (OpenAI)
**Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
(non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`.
Run from the **main session** under the human's bounded endgame authorization.
**Model:** `gpt-5.6-sol`
**Reasoning effort:** `ultra` — confirmed in the log, no substitution
**Codex session id:** `019f57f4-9c7d-79d2-8428-3d8286742876`
**Integrity:** the session rollout's final message hashes to md5 `77eb6668ec91`,
byte-for-byte equal to the captured file recorded below (hash-verified by the coordinator).
**Revision under review:** `6416ccb8c3c2` — the same revision the concurrent Fable half
reviewed, so round 7 is a complete two-family round.
**Redaction:** none.
**Independence:** fresh non-interactive session; no access to this orchestrating session, to
the held-open Fable half of the same revision, or to any prior LLP 0024 artifact (the rounds
1–6 artifacts and the held Fable r7 were kept in a scratch stash, out of `llp/reviews/`, for
the duration — verified absent while it ran).
**Method:** `brief-round7.md` verbatim — re-measure every empirical claim including the
laundered/adversarial form, hunt the sixth noun-reuse casualty, and independently probe the
compartment leak per channel.
**Terminal status:** this is the **last review of the whole four-document effort**. The human
authorized a terminal minimal-close pass, not a further round; the document finishes at
**Status: Draft**. Codex's verdict is NOT READY (4 Blocking + 4 Material), and it found the
next §7 algorithm-class defect (a phase-5/concurrent-cancellation hole) plus a second
restricted-global laundering path through `function` declarations — the latter security-
relevant and tied to ENG-24463.

### Verbatim review

1. **Overall assessment**

The design direction is good: a typed evaluator seam, explicit session environment, entry-only TLA, non-assimilating outcomes, staged inspection, and a worker-aware event protocol are the right architecture for Hermes. The document is substantially stronger than earlier rounds and is unusually candid about engine limitations.

It is not ready as a normative Spec. I found the next §7 algorithm-class defect: phase 5 is claimed atomic because no user code runs, but concurrent cancellation can interrupt its multi-step mutation after a non-configurable global has been created. I also found a second restricted-global laundering path through `function` declarations, a direct `$_` contradiction, and several unresolved cross-document seams.

I re-measured the requested claims on Node 24.14, Deno 2.9.1, Bun 1.3.12, and Hermes 1.0.0/HBC99:

- Node and Deno reject both `var undefined ⏎ let undefined` and `var x ⏎ let x`; Bun accepts both, including the unsafe laundering case. No installed runtime implements the target distinction.
- Bun reproduces all three requested commit-if-initialized outcomes.
- Node confirms `var Object` is inert while `function Object(){}` clobbers and makes the property enumerable/non-configurable.
- Hermes confirms its adopted-property descriptor behavior is wrong, so §7 cannot delegate declaration instantiation to Hermes.
- `vm.createContext` creates a configurable `var`; fresh `vm.runInThisContext` creates a non-configurable one.
- Exact-descriptor `cat` ABA restoration is undetectable as claimed.
- The shipping compartment forwards session values and existence for `var`, sloppy assignment, and adopted-and-assigned names, but not descriptors or enumeration.

2. **Strengths**

- The `SourceRequest` sum and two-permit `.load` design avoid the read-before-digest circularity and properly separate authenticated bytes from evaluation authority. [LLP 0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:220)

- Entry-only TLA is the honest boundary for a synchronous CommonJS loader. Static-import preflight and call-time dynamic checks are directionally right, and refusing dependency TLA is much safer than the current async-IIFE fallback. [LLP 0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:450) The current loader can otherwise async-wrap and even execute a prefix twice. [module-loader.js](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5583)

- The five-way outcome model, value handles, non-assimilation, fault/throw split, and capability strata are appropriate replacements for `Option<String>`. [LLP 0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:728) Today the trait returns `Result<Option<String>>`, [engine/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:32) while native evaluation assimilates arbitrary thenables. [hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033)

- The object-record/declarative-record split, late lookup by name, import-value materialization before the full-vector recheck, and “rollback never touches the object record” invariant are strong design choices. [LLP 0024 §7.1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:928) [LLP 0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1113) [LLP 0024 §7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1229)

- The four-gate decomposition is conceptually excellent: implementation/model, model/same-engine, model/standards-engine, and lowering/direct execution test different failure modes. [LLP 0024 §7.7](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1431)

- Safe inspection is staged honestly. Stage 1’s deliberately sparse tags, stage 1.5 throw capture, and stage 2 native reflection primitive correctly recognize that JavaScript reflection cannot be trap-free. [LLP 0024 §8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1581) The current inspector demonstrably invokes property reads and Proxy-sensitive reflection. [inspect.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/inspect/inspect.ts:274)

- The bounded `$_` ABA statement is accurate: restoring the exact saved accessor descriptor defeats a JavaScript identity check. [LLP 0024 §7.8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1526)

3. **Concerns**

1. **Blocking — Phase 5 is not atomic against concurrent cancellation.**  
   Evidence: §7 says the full-vector recheck and all property/cell/set mutations “cannot fail partway” because no user code runs. [LLP 0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1114) But §6 requires cancellation callable concurrently with evaluation, [LLP 0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:792) and cancellation publishes like a throw. [LLP 0024 §7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1285) An async break can land between phase-5 mutations after a non-configurable `var` property has been created; the stated rollback invariant cannot repair that. The existing runtime already has out-of-band debugger operations that bypass the evaluation lock. [hermes.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:487)  
   Resolution criterion: make recheck-plus-commit a cancellation critical section, defer requests until it ends, or classify any interruption there as `failed` with worker disposal. Inject cancellation at every mutation boundary and prove no partial state can be published.

2. **Blocking — `function` declarations reopen restricted-global laundering.**  
   Evidence: `[[SessionCreatedVars]]` is defined only for a property created where no own property previously existed. [LLP 0024 §7.1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:955) The matrix nevertheless marks `function` over a kindless existing property as “created.” [LLP 0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1189) For a pre-existing non-configurable, writable, enumerable property, `function p(){}` is legal and leaves it non-configurable; adding `p` to the set would then admit `let p`. Fresh Node measurement instead rejects that later lexical declaration. This is the function analogue of the `var undefined` laundering bug.  
   Resolution criterion: distinguish fresh-created, configurable-taken-over, and non-configurable-overwritten provenance. Pin the last case with a gate-2b fixture and define explicitly whether it may ever admit a later lexical declaration.

3. **Blocking — Commit-if-initialized is internally contradictory.**  
   Evidence: destructuring initializes individual cells in order, [LLP 0024 §7.3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1205) but §7.4 says initialization occurs when the declaration statement’s initializer completes. [LLP 0024 §7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1249) Those rules disagree for an iterator that initializes `a` and throws before `b`. More directly, AC12 says `let $_; boom()` does not leave auto-update disabled, [LLP 0024 AC12](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1917) while §7.8 and a later AC12 bullet say it initializes, commits, and leaves the disable set. [LLP 0024 §7.8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1517) [LLP 0024 AC12](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1943)  
   Resolution criterion: define commitment from each cell’s actual `InitializeBinding` transition, covering bare `let`, `class`, import, and per-name destructuring. Add partial lexical-destructuring fixtures and remove the stale `$_` criterion.

4. **Material — The four gates are not yet executable or cleanly partitioned.**  
   Evidence: the document says every table is generated from an executable reference model, [LLP 0024 §7.7](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1421) but no model, schema, generator, fixture path, or invocation exists in the repository outside the prose. Gate 2b also compares the model with standard Script semantics while the model deliberately permits `var x ⏎ let x`, which standards engines reject. The owner-authored “quirk filter” is described for Hermes-versus-standards quirks, not intentional session deviations.  
   Resolution criterion: check in and name the reference model and generation command. Split gate 2b into standard-equivalent transitions, explicit intentional deviations, and engine quirks; deviation entries must not be hidden inside the engine-quirk list.

5. **Blocking — The core Script-plus-import-plus-TLA source goal remains unproven.**  
   Evidence: open question 5 concedes that the parser mechanism may force semantic narrowing and must be prototyped. [LLP 0024 OQ5](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2114) Current SWC uses `Syntax::Typescript` plus `parse_program`, which can re-goal on import, [transpile.rs](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:109) while the REPL uses handwritten recognition and string replacement. [repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:860)  
   Resolution criterion: prototype and select the parser strategy on every advertised target, proving sloppy-only forms, directive semantics, imports, TLA, and TypeScript parsing before this Spec can be accepted.

6. **Material — `require()` TLA checking is not defined consistently.**  
   Evidence: preflight covers “the static graph, and only the static graph,” yet synchronous `require()` is called a static edge. [LLP 0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:475) That leaves conditional and computed `require()` undefined and conflicts with the dead-branch rationale immediately given for `import()`. AC8 specifies call-time checking only for `import()`. [LLP 0024 AC8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1838) The current loader accepts arbitrary `require(next)`. [module-loader.js](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5382)  
   Resolution criterion: require call-time transitive-TLA validation for every evaluated `require()`, literal or computed, before cache insertion or body execution; reserve entry preflight for actual static import declarations. Add false-branch and computed-require fixtures.

7. **Material — Work-unit, cancellation, and lifecycle semantics still diverge.**  
   Evidence: §6 first says accepted cancellation stops the target and produces `cancelled`, [LLP 0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:856) then says callback/query acceptance merely means it returned. [LLP 0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:892) “Jobs belonging to” a TLA settlement unit has no causal-membership algorithm. [LLP 0024 §7.4](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1300) The lifecycle outcome is input-scoped, so it does not cover a root timer calling `process.exit` with no evaluation active.  
   Resolution criterion: adopt one target-generic cancellation transition table with `cancelled` restricted to evaluation outcomes; specify promise/native-completion ownership propagation; publish due/undue scheduling transitions; and add a bare lifecycle control event.

8. **Material — The asynchronous-failure envelope conflicts with the process boundary.**  
   Evidence: §6 says value handles never cross a process boundary and only an inspection tree reaches the supervisor. [LLP 0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:777) §9 says the event delivered to the consumer carries the original value as a handle, [LLP 0024 §9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1706) while the session layer assigns its sequence at receipt. [LLP 0024 §9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1730) A pre-receipt drop also cannot report the “highest dropped sequence,” because none has yet been assigned.  
   Resolution criterion: define a worker-local `{handle,…}` envelope, trap-free inspection and release, then a wire `{tree,…}` envelope stamped by the supervisor. Locate every queue and specify release/drop behavior on backpressure, crash, and pre-receipt loss.

9. **Material — The vocabulary separation does not hold.**  
   Evidence: §2 still calls `repl:n` and related display strings “identity” immediately before insisting they are source labels, not keys. [LLP 0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:288) The armed-session token is still called a “handle” in §1. [LLP 0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:239) Bare `unit` alternates between work unit and settlement unit, including “its own unit” and “unit’s identity.” [LLP 0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:250) [LLP 0024 §9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1754) `work epoch` names a deleted LLP 0025 latch concept. [LLP 0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:330)  
   The sixth noun casualty is bare **unit**; **token** is another, since session token and private TLA control token are unrelated. “Created” in concern 2 is load-bearing reuse as well.  
   Resolution criterion: replace every occurrence with the vocabulary-table noun, rename the TLA control token a settlement sentinel, retire `work epoch`, and add a terminology check over normative prose and generated data.

10. **Material — Deviation (d) contains a false empirical security claim.**  
    Evidence: it says the shipping Proxy leaks descriptors and enumeration through `get`/`has`. [LLP 0024 §7.7(d)](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1389) The actual handler defines only `get`, `set`, and `has`; values and existence forward, but own descriptors are `undefined` and own-key enumeration is empty. [hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2627)  
    Resolution criterion: state that values and existence leak today; keep values, existence, descriptors, and enumeration as prospective closure requirements with separate fixtures. Clarify whether the captured baseline isolates namespace bindings only or also mutations of shared mutable objects such as `console`.

11. **Material — Module identity contradicts LLP 0023.**  
    Evidence: §7.9 and AC15 require one instance “however spelled” and “across spellings.” [LLP 0024 §7.9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1556) [LLP 0024 AC15](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1990) LLP 0023 deliberately gives case/normalization aliases two `SourceId`s and therefore two instances. [LLP 0023 §2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:710) AC15 also pluralizes synthetic modules although only `ibex:stdin` is one; prompt, `.load`, and `ibex:eval` are scripts.  
    Resolution criterion: scope “same instance” to equal `SourceId`, make the case-alias split explicit, and restrict the synthetic-module cache criterion to `ibex:stdin`.

4. **Cross-document findings**

- **LLP 0022:** `OBL-SUBMIT-CREDENTIAL` is false/outdated: it still specifies one linear permit, while LLP 0024 correctly requires separate read and evaluation permits. [LLP 0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:967) Its body also falsely says LLP 0024 still uses “decision evidence.” [LLP 0022 §7](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:726)

- **LLP 0022:** `OBL-CANCEL-TARGETS` is only partial: it asks for kind plus id, while LLP 0024 carries an id and still has inconsistent terminal edges. `OBL-UTF8` is misowned/partial because LLP 0024 defines strict decoding but not transcript resynchronization. `OBL-MODULE-IDENTITY` has the right cache distinction but uses “source identity” where the normative noun is `SourceLabel`.

- **LLP 0022:** `OBL-BOUNDS` is stale in the favorable direction. LLP 0025 now pins inline renderer and maximum-input values, although the promised annex file remains absent. [LLP 0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990) Its OQ1 also points to LLP 0024 OQ2 for inspection; inspection is currently OQ1. [LLP 0022 OQ1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1184)

- **LLP 0025:** its target-facing ledger is accurate. `OBL-UNIT-PUBLICATION`, `OBL-CANCEL-EDGES`, `OBL-SUSPENDED-UNIT`, `OBL-LIFECYCLE-UNITGENERIC`, and `OBL-0024-EPOCH-VOCAB` correctly identify outstanding LLP 0024 gaps. `OBL-SEQUENCE-ALLOCATOR` is discharged: both documents now assign sequence at session-layer receipt. [LLP 0025 ledger](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1125)

- **LLP 0025 / LLP 0024:** LLP 0024 OQ8 falsely says `session-constants.json` exists and maximum input size is unpinned. [LLP 0024 OQ8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2129) LLP 0025 says the file does not exist and pins maximum input at 1 MiB inline. [LLP 0025 §12](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1151)

- **LLP 0023:** `OBL-TYPED-READ` correctly recognizes LLP 0024’s two-permit form; `OBL-MODULE-IDENTITY` correctly reports the outstanding case-alias and synthetic-module defects; `OBL-ERROR-ORDER` correctly records LLP 0024’s half as discharged. [LLP 0023 ledger](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2032)

- **LLP 0013:** it still normatively says a package global contains exactly policy endowments, [LLP 0013 §Mechanism 2](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:237) while LLP 0024 and the code correctly show live-global value/existence forwarding. LLP 0013 must be revised or mark that claim unmet.

- Cancellation semantics are duplicated between LLP 0024 and LLP 0025 and have already drifted. Module identity is nominally delegated to LLP 0023 but then restated contradictorily. `.load` behavior is also duplicated across LLP 0022 and LLP 0024. Each should have one normative owner and consumer-side acceptance criteria only.

5. **Suggestions**

- Make the checked-in reference model the source of truth before further prose repair. Generate the matrix, rollback fixtures, restricted-global fixtures, and terminology inventory from it.

- Model cancellation as an explicit input to every §7 phase, especially every phase-5 mutation boundary. “No user code” and “uninterruptible” are different properties.

- Separate semantic module kind, lowered execution format, and source role in `ResolvedModule`; the current code overwrites ESM with CommonJS when lowering is needed. [module_loader/mod.rs](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:751)

- Define worker-local and supervisor-wire event schemas separately. This will naturally resolve handle lifetime, inspection, sequencing, and queue ownership.

- Sequence implementation work as: parser/source-goal prototype → executable model and gates → LLP 0002 ABI amendment → native cancellation/work-publication/introspection slices → session lowering → worker protocol. The current REPL and inspector should not be adapted incrementally into the normative display path.

- Correct the revision note: it still says workers draw sequence ranges even though normative §9 retires that design. [LLP 0024 metadata](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:24)

6. **Open questions**

1. Can Hermes defer an async break across the complete phase-5 recheck/commit without compromising the response guarantee, or must interruption there poison and dispose the worker?

2. Which provenance states should permit later lexical shadowing after `function` overwrites an existing configurable or non-configurable property?

3. What exact causal rule assigns promise reactions, timers, and native completions to a TLA settlement unit while keeping each callback a separately cancellable work unit?

4. Can the Script-plus-import-plus-TLA grammar be implemented without losing sloppy Script forms on every advertised target?

5. Is every evaluated `require()` call-time checked, or is a justified literal-require preflight subset intended?

6. Does the LLP 0013 baseline isolate only global namespace bindings, or also mutations reachable through shared baseline/endowment objects?

7. Where is the first bounded queue in the worker-to-supervisor path, and how are pre-receipt drops represented when no sequence number exists yet?

8. Is a background lifecycle request a new control-event variant or a unit-generic extension of the evaluation outcome union?

7. **Readiness verdict**

The central architecture is promising, but the phase-5 cancellation hole, restricted-global function laundering, contradictory rollback criteria, unproven parser goal, and unresolved cross-document state machines are material correctness and feasibility blockers.

VERDICT: NOT READY

### Orchestrator verification notes — TERMINAL round 7

Both round-7 families reviewed `6416ccb8c3c2` and returned NOT READY. This is the last round;
the human authorized a **minimal closing pass**, so the document finishes at **Status: Draft**
(matching all three siblings, none of which reached both-families-READY). Final revision after
this pass: `a51b000bb81e`.

**The convergence signal:** Fable — instructed to attack §7 as an algorithm and re-measure the
adversarial forms — reported it **could not construct the next §7 defect** of the class that
broke rounds 3–6. That is the first round the core session-semantics algorithm survived an
adversarial pass. Codex, reading the same revision, did find two more of that class (below),
which is exactly why the loop runs two independent families.

**Applied this pass (single-valued fixes / factual corrections — each verified, assert+grep):**

- **Codex B2 — `function` laundering (security, ENG-24463-adjacent) — confirmed by
  measurement and fixed.** `function p(){}` over a pre-existing non-configurable property is
  legal and leaves it non-configurable, and marking it "created" would admit a later `let p`
  — but Node **rejects** that `let` (measured: `let q after function q → SyntaxError`). The
  §7.1 provenance rule now reads "created *at a name that had no own property*", and the two
  matrix rows that marked a `function` *overwrite* as "created" are corrected to **not
  created**. Same rule closes the `var Object`/`function Object` asymmetry cleanly.
- **Codex B1 — phase 5 not atomic against concurrent cancellation — confirmed and fixed.**
  §6 permits cancellation concurrently with evaluation, so an async break could land between
  phase-5 mutations after a non-configurable property was created. "No user code" ≠
  "uninterruptible". Phase 5 is now a **cancellation critical section** (request deferred to
  its bounded boundary; undeferrable interruption → `failed` + worker disposal).
- **Codex B3 — commit-if-initialized contradictions — fixed.** Rollback now commits
  **per-cell at `InitializeBinding`** (destructuring `let [a,b]=iter()` commits `a`,
  removes `b`), and the **stale round-5 `$_` acceptance bullet** that contradicted §7.8
  was removed.
- **Codex M6/M8/M9/M10/M11 + Fable C2/C3/C4/C5/C9 — the factual corrections**, all verified:
  require() is call-time transitive (not a "static edge"); §9's async-failure envelope splits
  worker-local (handle) from wire (tree), and a pre-receipt drop carries no sequence number;
  the noun sweep completed (§1 handle→**token**, identity→**label**, snapshot→**capture/
  copied**, TLA control token→**settlement sentinel** — the sixth casualty, "token" reuse);
  deviation (d)'s leak narrowed to **values+existence** (verified `makeCompartment` defines
  only get/has/set over a bare target, so descriptors/enumeration do **not** leak today);
  module identity scoped to **equal SourceId** (0023 splits case-aliases); the stale round-6
  **revision note** crediting worker-draws-ranges corrected; **OQ8**'s false "constants file
  exists" corrected (0025 pins values inline, file owed).
- **Credential** — retracted the "circular for `.load`" claim (my own error): 0022's
  four-stage `SubmissionCredential` lifecycle already orders the read before the digest
  binding, so my two-permit form is *equivalent*, not a fix. Adopted 0022's vocabulary.
- **Coordinator-requested:** the **process lesson** is now in §7 prose (a claim about a change
  is worthless until the change is verified — three silent-replace misses this session proved
  it, and gate 2b would have caught the first without a human); and a **delegated-obligations
  ledger** was added, whose top row is **`OBL-COMPARTMENT-BASELINE` (LLP 0013, = ENG-24463)**.

**Ledgered, not hand-written (needs a generated/executed artifact — the terminal-round
discipline):** the §7 tables are an **interim projection of `OBL-EXEC-MODEL`** (the checked-in
executable reference model); the **Script+import+TLA parser goal** (`OBL-PARSER-GOAL`, OQ5)
must be prototyped; the **result ABI** amendment is LLP 0002's (`OBL-ABI-AMEND`); gate 2b now
distinguishes quirk entries from **expected-deviation** entries but the entries themselves are
model data. These are implementation tickets, not prose to be perfected.

**Not fixed here (reported to the coordinator for the sibling loops):** 0022 §7's false "0024
still uses 'decision evidence'"; 0022 `OBL-SUBMIT-CREDENTIAL` one-vs-two-permit reconciliation;
0025 `OBL-SUSPENDED-UNIT` now apparently discharged; 0022 §5's unqualified `$_` promise;
0013 Mechanism 2's endowments-only claim (the reconciliation is `OBL-COMPARTMENT-BASELINE`).
