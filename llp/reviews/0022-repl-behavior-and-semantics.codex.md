# Review: LLP 0022 — REPL Behavior and Semantics

This file records independent OpenAI-family (Codex) reviews per LLP 0005.
Verbatim review bodies are preserved; orchestrator notes sit outside them.

## Round 1 — 2026-07-11

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f54f9-8c13-7593-a82d-7aff3dbff18b`
**Date:** 2026-07-11
**Revision under review:** `b3332765d1c1` (sha256/12 of the document)
**Redacted:** No — the document and repository were read by the Codex CLI under the user's OpenAI account, as explicitly authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, the concurrent Claude review, or any prior LLP 0022 review artifact (none existed).
**Method:** cli-runner (`codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="ultra"' -s read-only --output-last-message …`), shared round-1 brief (LLP 0005 standard questions + required structure + readiness bar).

### Verbatim review

## 1. **Overall assessment**

LLP 0022 identifies the right product problem and proposes several strong foundational choices. A stable virtual `/project` namespace, one resolver across filesystem and module operations, an armed root-principal session, no implicit startup files, withdrawal of `.env`, and REPL-affordance parity are all good ideas. The supplied on-disk document matches the revision prefix `b3332765d1c1`, and its factual diagnosis of the current cwd fallback, raw `.load`, legacy import rewriting, and unsafe reflective completion is substantially accurate.

The document is not yet ready as a normative Spec. Five issues are blocking rather than ordinary implementation backlog:

- Prompt-time authority attributes contradict immutable, build-generated policy.
- A runtime-wide cwd mutable by package code creates a cross-principal confused-deputy channel.
- `process.exit()` and `process.exitCode` contradict closed CapSec lifecycle surfaces.
- `/home` currently maps to a shared executable cache, creating disclosure and poisoning risks.
- The required persistent lexical semantics across statement-containing top-level `await` have no demonstrated Hermes mechanism.

The major defaults are otherwise directionally sound. Sloppy prompt semantics are a reasonable compatibility choice, especially because the document correctly forbids security from depending on strictness. Withdrawing `.env` is unequivocally correct. A POSIX-shaped virtual namespace is preferable to exposing host spelling. Second-`Ctrl+C` session termination is a sensible last-resort policy for an uninterruptible evaluator, but the state machine and architecture needed to make it reliable are missing.

The main improvement needed is to distinguish three kinds of requirement: semantics already implementable above `Engine`, semantics requiring a new structured engine/session contract, and changes to the normative CapSec vocabulary and registry. The current draft sometimes states the latter two as settled behavior while leaving their core mechanism as an open question.

## 2. **Strengths**

- The security priority is correct and clearly stated. Root prompt code remains subject to every earlier closure and ceiling, while package code retains its principal across asynchronous work. LLP 0022 §10 (`llp/0022-repl-behavior-and-semantics.spec.md:397-413`) aligns with LLP 0021’s decision order, where ambient root is considered only after lifecycle, target, protected-object, and ceiling denials (`llp/0021-capsec-effect-model-migration.plan.md:324-351`).

- The distinction among shell cwd, authenticated project binding, and JavaScript-visible cwd is excellent. The one-resolver mandate and host-path non-disclosure rules in §§1, 3, and 4 (`:98-114`, `:157-231`) are the right response to the current split behavior: armed native cwd returns `undefined` (`src/engine/hermes_runtime.cc:1645-1668`), `process.js` falls back to `/` (`src/builtins/process.js:8-81`), and `fs.js` resolves relative paths against that value (`src/builtins/fs.js:542-602`).

- The affordance-parity rule is an important security principle. The document correctly identifies three real bypass-shaped implementations:

  - `.env` enumerates the raw Rust process environment (`src/bin/ibex/repl/mod.rs:966-970`).
  - `.load` reaches a raw `tokio::fs::read` and bare engine evaluation (`src/bin/ibex/repl/mod.rs:930-941`; `src/bin/ibex/engine/hermes.rs:1140-1159`).
  - Completion constructs and evaluates a base expression and walks its object graph (`src/bin/ibex/repl/mod.rs:283-348`).

- No implicit rc/init file is the right armed-runtime default (§1, `:116-120`). It avoids turning ambient file presence into root-principal code execution.

- The interactive/program/plain-mode taxonomy is useful (§2, `:132-155`). In particular, separating piped program execution from a scriptable projection of persistent REPL semantics is worth preserving, even though the plain protocol needs more definition.

- The non-quiescent interactive event-loop rule is good (§7, `:296-310`). Current architecture already has a credible basis for it: prompt evaluation uses `eval_immediate`, background work uses `drive_ready_tasks`, and EOF has a bounded ready-only drain (`src/bin/ibex/repl/mod.rs:706-777`, `876-884`; `src/bin/ibex/engine/hermes.rs:1554-1590`).

- The document recognizes terminal injection, history privacy, reflective completion, asynchronous error attribution, and terminal restoration as security or correctness properties rather than cosmetics. That is exactly the right level for a REPL Spec.

- The acceptance criteria are unusually concrete and correctly require PTY, protocol, engine, source-builtin, and vendored-generated coverage (§Acceptance criteria, `:562-642`). Requiring source and generated builtin parity is especially valuable because both copies currently retain the old cwd behavior.

- The compatibility ordering (§Compatibility priorities, `:548-560`) is strong: integrity and typed decisions precede path coherence, language compatibility, and cosmetics.

## 3. **Concerns**

1. **Prompt-time authority attributes conflict with immutable armed policy — Blocking**

   **Evidence:** Section 8 says a prompt `with { … }` attribute follows “exactly” the rules of a file import site and may select or attenuate authority within the ceiling (`llp/0022-repl-behavior-and-semantics.spec.md:340-347`; AC17 at `:615-617`). LLP 0014 instead defines import authorities as declarative build inputs resolved before execution and stripped before the engine sees them (`llp/0014-import-site-grants-and-generated-policy.spec.md:97-108`, `228-236`). Runtime grants are explicitly a separate layer (`:281-301`). LLP 0021 makes the armed snapshot immutable (`llp/0021-capsec-effect-model-migration.plan.md:193-206`) and permits only typed dynamic grants for dynamically authorizable definitions within the static ceiling (`:392-396`).

   The live typed bridge also requires a dynamic grant to name the authenticated executing principal (`llp/0021-capsec-effect-model-migration.plan.md:827-848`), so root prompt code cannot silently use it to amplify an imported package. Current REPL behavior is the legacy mechanism the new model rejects: it rewrites imports, prints a “granted” message, and calls `Exact.setModuleCapabilities(0, …)` (`src/bin/ibex/repl/mod.rs:814-836`); armed Host refuses legacy capability checks (`src/host/mod.rs:1285-1290`).

   **Resolution criterion:** Either reject authority-bearing attributes at the prompt, or define them only as assertions/attenuations against an already-armed package row. If actual runtime delegation is required, specify a distinct typed protocol covering canonical `authorities` grammar, target principal, eligible lifecycle classes, grantor attribution, ceiling evidence, cache/re-import conflicts, revocation, and truthful acknowledgement; update LLPs 0013, 0014, and 0021 accordingly.

2. **The shared virtual cwd is a cross-principal confused-deputy channel — Blocking**

   **Evidence:** Section 4 defines one cwd for the runtime and does not restrict mutation to the root principal (`llp/0022-repl-behavior-and-semantics.spec.md:210-231`), while §10 preserves package attribution (`:404-408`). As written, package code that can call `process.chdir()` can redirect a later root-principal relative read, write, import, or `.load`, including asynchronously after its own frame has returned. An `fs:list` or metadata decision on the target directory does not authorize mutation of another principal’s future resolution context. The bullet order at `:220-223` also risks performing an existence check before authorization.

   The registry deliberately classifies `process:cwd` as deny-only shared-process mutation (`capsec/registry/capability-definitions.json:279-291`) and says it remains closed unless virtualization is scoped without changing other principals’ resolution (`capsec/registry/legacy-capability-reconciliation.json:106-112`). `__exactSetCwd` and `process.chdir` are correspondingly closed (`capsec/registry/coverage-edges.json:181624-181631`, `214535-214542`).

   There is also no current runtime-local ownership seam. The Host ABI is a process singleton (`src/host/abi.rs:1-5`, `130`, `214-228`), and relative typed paths join `std::env::current_dir()` (`src/host/mod.rs:278-301`).

   **Resolution criterion:** Choose one of:

   - root-only mutable cwd;
   - per-principal/per-compartment cwd; or
   - a separately specified shared-control action with a convincing non-confused-deputy model.

   Define where cwd lives, how runtime identity reaches every resolver, and how normalization, requested-stage authorization, retained-object verification, and atomic commit are ordered. Add an adversarial package test proving package code cannot redirect a later root-relative effect and a concurrent two-runtime test proving isolation. Regenerate the CapSec registry and target proofs for any reclassification.

3. **`process.exit()` and `process.exitCode` contradict the closed lifecycle model — Blocking**

   **Evidence:** Section 15 requires `.exit` and EOF to honor `process.exitCode`, and requires `process.exit(n)` to terminate the REPL (`llp/0022-repl-behavior-and-semantics.spec.md:534-539`; AC22 at `:634-636`). The armed registry classifies `__exactExit` as closed under `process:signal` (`capsec/registry/coverage-edges.json:174033-174040`), likewise closes `process.exit` (`:215893-215910`), and classifies `process.exitCode` as closed shared mutable runtime state (`:215913-215920`). These closures precede ambient-root authority.

   The current implementation cannot serve as the compliant mechanism: native exit calls `std::exit`/`ExitProcess` directly (`src/engine/hermes_runtime.cc:588-636`, `1704-1727`), bypassing Rust-owned history saving, terminal restoration, principal checks, and orderly runtime release. The Spec also does not say whether an imported package may terminate the root REPL or set its eventual exit status.

   **Resolution criterion:** Replace hard exit with a cooperative, authenticated lifecycle request delivered to the terminal-owning Rust layer. Define whether it is root-only and non-delegable, prove package/background code cannot control session termination or status, and update the registry classification. Otherwise remove JavaScript `process.exit`/`exitCode` from the armed REPL contract and retain only Rust-owned `.exit`/EOF.

4. **Exposing current `home` as `/home` exposes a shared executable cache — Blocking**

   **Evidence:** Section 3 mounts logical root `home` at `/home` for runtime-owned cache state (`llp/0022-repl-behavior-and-semantics.spec.md:159-169`). Default arming maps `home` to the per-user Ibex cache (`src/bin/ibex/runtime.rs:1918-1945`, `3444-3470`). That cache contains generated JavaScript and bytecode selected for execution (`src/bin/ibex/runtime.rs:2319-2332`, `2939-2952`). Cache freshness checks existence, mtimes, and a dependency manifest, but not output integrity (`:2433-2476`). Dependency manifests contain absolute host paths; an existing example starts with such paths at `vendored-generated/embedded_runtime_bundle.js.deps.json:1`.

   Making this binding an ordinary root-visible mount permits cross-project disclosure and, if writable under ambient root, cache poisoning of code consumed by another run. The Spec gives `/home` neither read-only semantics nor a protected-object rule. It also uses a misleading POSIX name: this is a cache directory, not a user home.

   **Resolution criterion:** Do not mount build, transpile, bytecode, or runtime caches into JavaScript’s virtual namespace. Omit `/home` initially, or replace it with per-project/per-snapshot non-executable state whose isolation, lifecycle, and write policy are explicit. Add two-project disclosure and poisoning tests, including mount alias/overlap checks.

5. **Persistent lexical semantics across top-level `await` lack a demonstrated Hermes mechanism — Blocking**

   **Evidence:** Sections 6 and 7 require true persistent `let`, `const`, class, function, import, TDZ, and redeclaration semantics, including `const x = await f()` (`llp/0022-repl-behavior-and-semantics.spec.md:267-305`). Yet §6 permits unspecified “engine-specific compromise” (`:275-281`), Open Question 4 asks whether Hermes can support the behavior (`:706-707`), and Consequences concedes deeper engine work may be required (`:731-732`).

   Hermes file execution uses script evaluation rather than native ESM (`src/bin/ibex/runtime.rs:1054-1060`), and `Engine` exposes only whole-string evaluation, not a persistent lexical-session environment (`src/bin/ibex/engine/mod.rs:22-79`). The current REPL wraps statement-containing TLA in an async IIFE, necessarily losing lexical declarations after the IIFE returns (`src/bin/ibex/repl/mod.rs:1174-1184`). Windows additionally disables native promise unwrapping in this path (`src/engine/hermes_runtime.cc:3033-3038`).

   **Resolution criterion:** Prototype and document a concrete `ReplSession` mechanism before making this mandatory. It must pass TDZ, lexical redeclaration, const immutability, closures across suspension, declarations before and after `await`, destructuring, class/function semantics, rejected-await publication, and imported-binding tests. Otherwise specify a precise bounded deviation or defer statement-containing TLA; remove “where practical” from normative language.

6. **The virtual namespace lacks a complete path grammar and runtime ABI — Material**

   **Evidence:** Sections 3 and 4 require one POSIX-shaped resolver across all platforms and all path-taking surfaces (`llp/0022-repl-behavior-and-semantics.spec.md:181-208`, `216-231`). The current typed Host API accepts host `Path` values and treats absolute paths as host absolute paths; relative paths are joined to the Rust process cwd (`src/host/mod.rs:278-301`). Module resolution also falls back to the host cwd (`src/module_loader/mod.rs:691-725`). Therefore `/project/a` cannot become safe merely by changing `process.js`; the ABI needs a typed logical path and runtime identity.

   The normative edge cases are also absent: `stat("/")`, `readdir("/")`, absent mounts, `/project/../home`, cross-mount symlinks, `realpath`, `readlink`, watch event paths, `require.resolve`, error `.path` fields, `file://localhost`, encoded separators/dot segments/NUL, Buffer and non-UTF-8 paths, and `path.win32`. Current URL code switches file-URL behavior using the host platform (`src/builtins/url.js:2886-2934`, `4175-4221`), conflicting with a universally POSIX effect namespace unless explicitly overridden.

   **Resolution criterion:** Define a canonical `VirtualPath` grammar and a per-surface input/output matrix. The resolver API should carry runtime identity, logical root, normalized components, and original virtual spelling rather than infer meaning from string shape. Specify synthetic-root behavior, mount transitions, path-returning APIs, symlinks, file URLs, non-UTF-8 handling, Windows pure lexical APIs, and explicit-snapshot/project-root mismatch behavior.

7. **Trap-free inspection and completion are not implementable through ordinary JavaScript reflection — Material**

   **Evidence:** Sections 9 and 13 forbid arbitrary getters, Proxy traps, coercions, or promise continuations (`llp/0022-repl-behavior-and-semantics.spec.md:351-361`, `472-493`). JavaScript cannot safely detect a Proxy before invoking `ownKeys`, `getOwnPropertyDescriptor`, or `getPrototypeOf` traps.

   Current completion evaluates a base expression and uses `Object.getOwnPropertyNames` and `Object.getPrototypeOf` (`src/bin/ibex/repl/mod.rs:283-348`). Its five-second receiver timeout does not cancel a wedged Hermes operation (`:27-32`, `247-258`). Current `Exact.inspect` deliberately performs property reads, duck-typed method calls, key enumeration, and descriptor operations that can trigger user code or Proxy traps (`packages/ibex-runtime-js/src/inspect/inspect.ts:85-96`, `182-225`, `279-449`). The current REPL also dynamically looks up `Exact.inspect` and falls back to `String`, which invokes coercion (`src/bin/ibex/repl/mod.rs:63-79`).

   The factual statement in Motivation that completion currently invokes getters should be qualified: the code is structurally unsafe, but armed lockdown tames `Function` (`src/engine/hermes_runtime.cc:2424-2454`), so the current completion query commonly fails closed before evaluating its base. That is inert completion, not safe working completion.

   **Resolution criterion:** Add a native Hermes value-snapshot/introspection primitive capable of recognizing Proxies and reading safe internal metadata without traps, with preemptive work/output budgets. Until then, restrict completion to parser-tracked lexical names and static builtin manifests, and display unknown objects opaquely. Tests must cover throwing and infinite Proxy traps, custom coercion, overwritten inspector state, cycles, huge objects, and continued evaluation after timeout.

8. **The evaluator has no coherent outcome or Promise contract — Material**

   **Evidence:** Section 7 says the prompt waits for the submitted promise to settle (`llp/0022-repl-behavior-and-semantics.spec.md:302-305`), while §9 distinguishes a value of `undefined` from an empty completion and forbids Promise continuation solely for display (`:351-361`).

   Native evaluation instead assimilates every object with a callable `.then`, attaches continuations, and uses a default ten-second wait before returning a still-pending Promise (`src/engine/hermes_runtime.cc:3033-3156`). That timeout is read from `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` after arming (`:3088-3100`), contrary to LLP 0021’s prohibition on post-arming environment consultation. The ABI then maps JavaScript `undefined` to no output (`:3161-3174`), while `Engine::eval` exposes only `Option<String>` (`src/bin/ibex/engine/mod.rs:32-39`). Current REPL therefore prints `undefined` for every `None`, including declarations (`src/bin/ibex/repl/mod.rs:884-890`).

   **Resolution criterion:** Introduce a structured evaluation request/outcome such as `EmptyCompletion | ValueSnapshot | Throw | Cancelled`, with source identity and in-memory source map. Specify bare Promise and arbitrary thenable behavior separately from explicit TLA, including never-settling promises and cancellation. All budgets must be fixed/versioned or captured before arming, and arbitrary thenables must not execute merely because the REPL formats a result.

9. **TypeScript selection and source positions are underspecified — Material**

   **Evidence:** Section 5 says JS versus TS is decided “by content” and uses the same pipeline as a file with the same text (`llp/0022-repl-behavior-and-semantics.spec.md:233-265`). A file’s behavior is not determined by text alone: the loader chooses transpilation from its extension (`src/module_loader/mod.rs:242-256`), and the SWC path chooses JSX/TSX from the extension (`src/module_loader/transpile.rs:109-124`). Prompt source `repl:<n>` and program stdin have no extension. The transform also performs CommonJS lowering (`:166-178`), potentially affecting script/module semantics, and its emitter returns code without a source map (`:183-196`). Engine eval hardcodes `<eval>` (`src/bin/ibex/engine/hermes.rs:1515-1524`).

   **Resolution criterion:** Define an exact grammar selection rule: explicit `--input-type`/session mode, TS-first, JS-first fallback, or another deterministic algorithm. Pin JSX/TSX, decorators, ambiguous JS/TS forms, and program-mode stdin. Make the transform return code plus a source map and pass `repl:<n>` through a structured engine API. Add ambiguity and transformed-diagnostic fixtures.

10. **Failure publication, import bindings, and `$_` are not ECMAScript-precise — Material**

   **Evidence:** Section 6 says runtime exceptions preserve bindings “completed before the throw” (`llp/0022-repl-behavior-and-semantics.spec.md:283-289`). In ordinary Script evaluation, GlobalDeclarationInstantiation occurs before statement execution: a declaration textually after a throw may already reserve a binding, while a lexical binding may remain uninitialized in TDZ. Rejected TLA introduces another boundary.

   The document also does not say whether persistent import bindings are immutable live bindings or snapshots. Current rewriting creates mutable `globalThis` snapshots (`src/bin/ibex/repl/mod.rs:1080-1167`). “Assigns to `$_` explicitly” is similarly ambiguous for lexical declarations, destructuring, update/compound assignment, `globalThis.$_`, `defineProperty`, and indirect eval.

   **Resolution criterion:** Add a state-publication table for parse/early error, synchronous throw before and after declarations, rejected await, wrapper failure, and redeclaration afterward. Specify import liveness and immutability and fully define `$_` ownership, shadowing, opt-out detection, and update rules.

11. **Program, prompt, import, and `.load` module identities are incomplete — Material**

   **Evidence:** Program mode provides only an example synthetic name and says relative imports resolve from cwd (`llp/0022-repl-behavior-and-semantics.spec.md:138-143`). Section 8 defines supported import forms but not their exact binding/cache semantics (`:312-347`). `.load` is described as “the same pipeline as importing” and “not a bare global eval” (`:441-444`), but it does not say whether it:

   - executes in module or REPL-global scope;
   - publishes declarations or exports;
   - displays a result;
   - participates in the module cache;
   - re-executes on repeated load; or
   - shares a cache key with an import of the same file.

   Values for `process.argv`, `__filename`, `__dirname`, `import.meta.url/main`, `require.main`, source-map base, and cache keys after `chdir` are unspecified and can become host-path disclosure channels. Current `.load` bypasses the Runtime/module loader entirely (`src/bin/ibex/repl/mod.rs:930-941`; `src/bin/ibex/engine/hermes.rs:1140-1159`).

   **Resolution criterion:** Add a per-mode metadata table and exact `.load` semantics. Reserve the `repl:` source scheme in the resolver, define canonical stdin identity, virtual module URLs, main-module state, argv, import binding behavior, and cache identity across cwd changes. Build a session evaluator above the bare `Engine` interface.

12. **“Plain protocol mode” is neither framed nor deterministic as written — Material**

   **Evidence:** Section 2 promises deterministic output for the same input/runtime version (`llp/0022-repl-behavior-and-semantics.spec.md:144-151`). `.time` is available in that mode and emits wall-clock elapsed time (`:445-446`). User code can also observe randomness, clocks, network, files, or scheduling, so only REPL-owned framing—not arbitrary transcript bytes—can be deterministic.

   The document does not define submission framing, EOF during incomplete input, record boundaries, separation of value echo from program stdout, asynchronous-event ordering, or status after recoverable errors. Current scheduling is biased toward already-buffered input over idle pumping (`src/bin/ibex/repl/mod.rs:706-777`), so a timer can interleave differently in a pipe than between human-paced inputs. AC18 also says `ibex` and `ibex repl` share transcript fixtures (`llp/0022-repl-behavior-and-semantics.spec.md:621-623`) despite intentionally different non-TTY modes.

   **Resolution criterion:** Either rename this “plain transcript mode” and scope determinism to REPL-owned decoration for deterministic programs, or define a real JSONL/length-framed protocol with input ordinals and typed result/error/async/output records. Pin scheduling checkpoints, `.time`, `.clear`, multiline/EOF behavior, stream handling, and exit status; qualify AC18 by mode.

13. **Ownership of stdin is unspecified and currently races JavaScript — Material**

   **Evidence:** The interactive line editor owns fd 0 (`src/bin/ibex/repl/mod.rs:659-699`), while the runtime exposes the same fd as `process.stdin` (`src/engine/hermes_runtime_process_setup.cc:305-319`) and its stream layer can poll/read it (`src/engine/bootstrap/stream-enhance.js:443-485`). Prompt or imported code can therefore consume future REPL commands or contend with the editor. Program mode also consumes stdin to EOF as source, leaving unclear what `process.stdin` should expose during execution.

   **Resolution criterion:** Specify stdin ownership per mode. In REPL modes, reserve/close it to JavaScript, provide a multiplexed virtual stream, or expose terminal input only through a separate explicit API. In program mode, define that source consumption leaves EOF or provide a separate source descriptor. Add tests in which prompt/package code attempts to read or pause stdin.

14. **Asynchronous error reporting requires a structured engine contract — Material**

   **Evidence:** Section 9 requires one nonfatal report, owning-principal attribution, prompt-safe ordering, and continued input (`llp/0022-repl-behavior-and-semantics.spec.md:388-395`; AC23 at `:637-639`). Native async errors currently log directly, set fatal state, and cause polling to return `-1` (`src/engine/hermes_runtime.cc:3684-3718`); Rust then prints a separate generic pump error (`src/bin/ibex/repl/mod.rs:769-775`). The Rust layer receives neither the original error nor authenticated principal metadata.

   The Spec also omits unhandled-rejection timing, late handlers, `uncaughtException`/`unhandledRejection` listener precedence, evaluation errors versus process handlers, and storm suppression.

   **Resolution criterion:** Define an engine-to-REPL event envelope carrying sequence, kind, original error/value, source, stack, and authenticated principal. Specify handler precedence and the exact point at which a rejection becomes unhandled. Enable nonfatal behavior only for REPL mode and define bounded coalescing/rate limiting and protocol ordering.

15. **Interruption and terminal lifecycle are not an implementable state machine — Material**

   **Evidence:** Section 15 covers nonempty buffers and active evaluation but omits `Ctrl+C` at an empty prompt (`llp/0022-repl-behavior-and-semantics.spec.md:521-546`). It does not define the second-press window, reset rules, external SIGINT, or precedence when JavaScript has installed a SIGINT listener.

   Current readline stops reading while evaluation is handled (`src/bin/ibex/repl/mod.rs:681-697`), `Engine` has no cancellation method (`src/bin/ibex/engine/mod.rs:22-99`), and Hermes evaluation holds serialized runtime access during the native call. Thus the ordinary async control path cannot enter a runtime stuck in synchronous JavaScript. The promise to restore the terminal after every “crash” also needs scoping: catchable panics and controlled exits can be handled, but SIGKILL and some native crashes cannot.

   **Resolution criterion:** Specify an explicit idle/editing/continuation/evaluating/shutdown state machine, including empty-prompt behavior, second-press timing, exit code—normally 130 for SIGINT termination—JS listener precedence, and external signal handling. Validate a Hermes asynchronous-break API or use a supervisor/worker architecture. Limit restoration guarantees to process-controlled/catchable paths and test every such path under a PTY.

16. **Startup configuration and history contradict the absolute affordance-parity rule — Material**

   **Evidence:** Section 1 permits presentation environment to be captured before arming (`llp/0022-repl-behavior-and-semantics.spec.md:127-130`), but §10 says no affordance—including history or banner—may read host state closed to JavaScript (`:415-423`). Section 12 then deliberately reads and writes a persistent host history file outside JavaScript authority (`:456-470`). This can be legitimate terminal-user state, but it is an exception to the stated absolute rule.

   Current order also violates the intended pre-arming capture: `start_repl` constructs and loads the armed runtime first (`src/bin/ibex/main.rs:1333-1366`), then reads prompt environment and derives/migrates/loads history (`src/bin/ibex/repl/mod.rs:582-600`, `646-699`). LLP 0021 says mutable environment is not consulted after arming (`llp/0021-capsec-effect-model-migration.plan.md:625-630`).

   The history contract covers 0600 creation but not parent-directory mode, no-follow open, file type/owner validation, Windows ACLs, hardlinks, concurrent sessions, atomic merge, byte bounds, or cross-project leakage. A single global history can disclose project A’s secrets while working in project B.

   **Resolution criterion:** Define a narrow terminal-operator-state exception and capture all prompt/color/TTY/history handles into a `ReplStartupConfig` before arming. Provide `--no-history` or private mode in the initial design, preferably with a secure default for armed sessions. Specify secure open, owner/type checks, parent protection, atomic locking/merge, byte and entry limits, Windows equivalents, and project scoping via a non-reversible authenticated-project digest.

17. **Terminal safety is too narrowly specified and has contradictory color rules — Material**

   **Evidence:** Section 9 explicitly escapes inspected string values (`llp/0022-repl-behavior-and-semantics.spec.md:363-369`), but error names/messages, stacks, function names, property keys, source excerpts, async labels, hints, completion candidates, and prompt overrides are equally attacker-controlled. Current error rendering interpolates raw error text and submitted source (`src/bin/ibex/repl/mod.rs:107-163`); `Exact.inspect` emits raw function names and error fields (`packages/ibex-runtime-js/src/inspect/inspect.ts:134-143`, `307-312`).

   The output rules also conflict:

   - Program-authored `console.*` output is deliberately unmodified (`llp/0022-repl-behavior-and-semantics.spec.md:366-369`).
   - The next paragraph says color-disabled/non-TTY output contains no ANSI “anywhere” (`:371-374`).
   - §14 honors force-color (`:497-503`), while AC19 unconditionally forbids ANSI when `NO_COLOR` is set or output is non-TTY (`:624-625`).

   **Resolution criterion:** Use a structured renderer with trusted style spans and escape every untrusted fragment on REPL-owned stdout/stderr paths. Keep deliberate program writes explicitly outside that guarantee. Supply a per-stream color-precedence truth table and test OSC terminated by BEL/ST, CSI, C0/C1 controls, bidi controls, property/function/error/source payloads, and hostile prompt configuration.

18. **The dot-command grammar rejects valid JavaScript and leaves continuation controls undefined — Material**

   **Evidence:** Section 11 claims a leading-dot command namespace cannot be produced by JavaScript grammar and reserves any first-nonspace `.` line (`llp/0022-repl-behavior-and-semantics.spec.md:427-447`). `.5 + .5` is valid JavaScript. Current dispatch demonstrates the consequence by treating every trimmed leading dot as a command (`src/bin/ibex/repl/mod.rs:796-809`).

   `.break` must work while input is still incomplete, but command recognition is defined only at a fresh input; a normal validator will append `.break` to the buffered JavaScript. `.time` does not define multiline parsing, `.load` does not define quoted paths, and `.clear` must not emit ANSI in plain mode.

   **Resolution criterion:** Reserve only identifier-shaped control lines, for example `^\.[A-Za-z][A-Za-z0-9_-]*(?:\s|$)`, so numeric literals remain JavaScript. Specify `.break` as a pre-parser continuation-state control and define command argument quoting, aliases, multiline `.time`, and mode-specific `.clear`. Add PTY and protocol fixtures for all of them.

19. **The acceptance suite cannot yet determine conformance — Material**

   **Evidence:** The acceptance section is a strong start (`llp/0022-repl-behavior-and-semantics.spec.md:562-642`) but leaves load-bearing behavior untested or unbounded:

   - AC12 tests getters but not Proxy traps or post-timeout session usability.
   - AC15 tests only string value display, not errors, keys, source, prompt, or async output.
   - AC17 assumes the unresolved prompt-authority model.
   - AC18 conflicts with the distinct non-TTY modes.
   - AC21 omits empty-prompt Ctrl+C, JS signal listeners, and process-controlled hard-exit cleanup.
   - The suite omits malicious package cwd/lifecycle mutation, cross-project `/home` poisoning, stdin contention, TS ambiguity, `.break`, `.5`, and module metadata.
   - Completion timeout, exit drain, async-storm limit, inspector budget, history byte limit, and double-Ctrl+C timing are not fixed.
   - §14 promises Windows behavior while LLP 0021 currently advertises only `aarch64-apple-darwin` and refuses other production targets (`llp/0021-capsec-effect-model-migration.plan.md:930-943`).

   The REPL should also exercise inherited closures end to end—spawn, inspector, VM, workers, WASI, native addons/FFI, and self-grant—to prove no new affordance bypasses LLP 0021.

   **Resolution criterion:** Publish a conformance matrix by mode, target, principal, and output stream; give observable bounds versioned constants or normative ranges; add the omitted adversarial cases; include `-e`, `-p`, and `ibex eval` in shared path-semantic tests; and scope mandatory platform conformance to advertised targets until additional target-cell proofs exist.

## 4. **Suggestions**

- Split the work into dependent normative layers: a virtual-path/runtime-state specification, a structured evaluator/session specification, and the terminal REPL UX. LLP 0022 can remain the product contract while explicitly depending on those mechanisms.

- Make a typed event protocol the canonical seam between evaluation and presentation: `Submit`, `Result`, `Error`, `AsyncError`, `ProgramOutput`, `StateChange`, and `ExitRequested`. Interactive mode can render those events; plain mode can serialize them. This would solve protocol framing, async ordering, result discrimination, and much of terminal safety together.

- Consider a terminal supervisor plus Hermes worker process. The supervisor would own the PTY, history, startup configuration, signals, and final exit. The worker would own JS state. A second Ctrl+C could reliably terminate an uninterruptible worker without leaving the terminal raw or letting native `process.exit` bypass cleanup.

- Ship lexical/static completion first. Parser-tracked session names and the static builtin manifest provide useful completion without reflective execution. Dynamic member completion can wait for a native inert-introspection primitive.

- Omit a general state mount in the first version. Internal executable caches should remain inaccessible. If user-visible temporary/state storage is later needed, prefer an isolated `/state` or `/tmp` with explicit lifetime and authority semantics.

- Reserve synthetic source identities as URIs rather than filesystem-looking paths: `repl:<ordinal>`, `ibex-stdin:main`, and a package/source identity scheme. This keeps virtual files, generated cells, and authenticated package sources distinguishable without host disclosure.

- If strict prompt semantics are desired later, prefer a startup `--strict` mode that fixes the session grammar and declaration behavior. A mutable dot-command toggle would complicate persistent bindings and source interpretation.

- Add small Node/Bun comparison fixtures for intentionally familiar behavior—sloppy globals, `$_`, empty completion, Promise display, Ctrl+C, and dot commands—while documenting every deliberate Ibex divergence.

## 5. **Open questions**

- Is cwd root-only, per-principal, or genuinely shared? If shared, what authority permits one principal to alter another principal’s later resolution context?

- Does prompt import syntax merely assert/attenuate existing armed authority, or can it dynamically delegate to an imported package? How are differing attributes on a cached module handled?

- What concrete Hermes mechanism preserves global lexical records across statement-containing top-level `await` without converting bindings into mutable global properties?

- Are bare Promise expressions displayed as Promise objects, automatically awaited, or treated differently from explicit TLA? What happens to a never-settling await?

- What is the canonical virtual-path grammar for synthetic `/`, mount traversal, symlinks, non-UTF-8 components, Buffer paths, file URLs, and path-returning APIs?

- Should `/home` exist at all? If user-visible state is needed, what is its isolation, lifecycle, mutability, and relationship to internal caches?

- What are the exact per-mode values of `process.argv`, `__filename`, `__dirname`, `import.meta`, `require.main`, stdin, and source identity?

- Is plain mode a human-readable transcript mode or a machine protocol? What framing and scheduling boundary separates one submission from the next?

- Who owns fd 0 during an interactive session, and can prompt/package code ever receive terminal input outside the editor?

- How do JavaScript `SIGINT`, `uncaughtException`, and `unhandledRejection` listeners interact with REPL-owned cancellation and reporting?

- Is persistent history trusted terminal-user state outside the JavaScript parity rule? Should armed sessions default to private or project-scoped history?

- What is the minimum safe value-display contract before native inert inspection exists: primitives only, opaque object tags, or a limited set of engine-proven builtins?

- Is v1 conformance limited to `aarch64-apple-darwin`, or is Windows support a prerequisite for accepting this Spec?

## 6. **Readiness verdict**

The core direction should be retained, but the blocking policy, lifecycle, cache-isolation, cwd-ownership, and Hermes-session questions must be resolved before this can serve as an implementable normative contract.

VERDICT: NOT READY
### Orchestrator verification notes (round 1, outside verbatim body)

Spot-checked decisive claims against the repository; all confirmed:
- `process:cwd` registry row is `lifecycle: deny-only`, `globality: shared-process-mutation`, closed-surface (`capsec/registry/capability-definitions.json`), and `capsec/registry/legacy-capability-reconciliation.json` says "Keep closed unless cwd is virtualized or scoped without changing other principals' resolution" — supporting concern 2 and pre-authorizing the scoped-virtualization fix.
- `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` is read via `std::getenv` post-arming (`src/engine/hermes_runtime.cc:3088-3100`).
- Native result unwrapping assimilates any thenable (`if(!p||typeof p.then!=='function')return null;` then `p.then(...)`, `hermes_runtime.cc:3033-3060`) — user `.then` runs for display.
- `fileURLToPath` behavior is platform-switched in `src/builtins/url.js:2886+`.
- The swc emitter is constructed without a source map (`src/module_loader/transpile.rs:183-196`).
- `/home` ← machine-global cache and the LLP 0014 build-time/strip grant channel were independently verified during the concurrent Claude review's checks (`src/bin/ibex/runtime.rs:1918-1945, 3445-3461`; LLP 0014 lines 107/234/329).

Disposition: concerns 1–4 accepted as written. Concern 5 resolved via the
reviewer's stated alternative ("specify a precise bounded deviation"): the
round-2 revision pins an interim declaration-hoisting baseline with documented
deviations and keeps true lexical session semantics as the target. Concern 12
resolved via the reviewer's rename/scope option (plain transcript mode;
machine protocol deferred). Concern 16 partially adopted: the narrow
terminal-operator-state exception, pre-arming capture, and file hardening are
specified; per-project history scoping remains an open question with a
strengthened private-mode note. Concern 19's Windows item resolved by scoping
conformance to advertised production targets. All other material concerns
accepted; addressed in the round-2 revision.

---

## Round 2 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f5527-7a8c-7012-9d33-533573967a60`
**Date:** 2026-07-12 (attempts on 2026-07-11 PT hit an OpenAI usage limit and produced no review; per LLP 0005 they are not counted and no artifact was fabricated for them — this is the first completed round-2 Codex review)
**Revision under review:** `b2a9580177e0` (sha256/12; the reviewer independently verified the hash)
**Redacted:** No — document and repository read by the Codex CLI under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, the concurrent Claude review, or any prior LLP 0022 review artifact (round-1 artifacts were relocated outside the repository for the duration of the round; the reviewer also states it consulted none).
**Method:** cli-runner (`codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="ultra"' -s read-only --output-last-message …`), shared round-2 brief.

### Verbatim review

## 1. **Overall assessment**

LLP 0022 is an ambitious, directionally correct proposal. The core design—an armed root-principal session, a POSIX-shaped `/project` namespace, runtime-local virtual cwd, capability-preserving imports, REPL-affordance parity, structured evaluation outcomes, and cooperative lifecycle control—is the right architecture. The POSIX namespace is preferable to exposing host spellings; sloppy mode is a defensible interactive default; withdrawing `.env` and rc-file execution is correct; and second-`Ctrl+C` termination is a sensible liveness escape hatch.

The document also diagnoses the current implementation accurately. Armed cwd disclosure returns `undefined` (`src/engine/hermes_runtime.cc:1645-1666`), `process.cwd()` falls back to `/` (`src/builtins/process.js:69-81`), and `fs` resolves relative paths through that value (`src/builtins/fs.js:542-600`). `.env` reads the raw Rust environment (`src/bin/ibex/repl/mod.rs:966-970`), `.load` performs a host-path read (`src/bin/ibex/repl/mod.rs:930-940`; `src/bin/ibex/engine/hermes.rs:1140-1159`), completion evaluates user objects (`src/bin/ibex/repl/mod.rs:283-348`), and native evaluation assimilates arbitrary thenables while consulting a post-arm environment variable (`src/engine/hermes_runtime.cc:3033-3100`).

Nevertheless, this is not yet a coherent normative Spec. Several unresolved points affect security identity, not merely implementation detail: principal-sensitive path identity, the authenticated package graph for an entryless session, symlink staging, raw native bridge reachability, fd 0 ownership, and root-only deputy semantics. Language behavior is also insufficiently pinned for sloppy TypeScript inputs containing imports or top-level await, persistent lexical bindings, safe inspection, and lifecycle interruption.

The implementation plan understates the necessary engine and ABI work. The current engine seam accepts strings or host-path files and returns `Option<String>` (`src/bin/ibex/engine/mod.rs:22-79`), assigns `<eval>` as source identity (`src/bin/ibex/engine/hermes.rs:1515-1525`), and has no native ESM or top-level-await support (`src/bin/ibex/engine/hermes.rs:1653-1660`). Full conformance requires the new structured seams described by the Spec, plus additional path-, stdin-, inspection-, environment-, and raw-bridge seams not yet listed.

I independently verified that the reviewed file has SHA-256 prefix `b2a9580177e0` and did not consult any LLP 0022 review artifact.

## 2. **Strengths**

- The separation of shell cwd, authenticated logical bindings, and JavaScript-visible cwd in §Motivation (`llp/0022-repl-behavior-and-semantics.spec.md:58-70`) is excellent and matches LLP 0021’s typed-root and retained-object model (`llp/0021-capsec-effect-model-migration.plan.md:260-275`, `634-691`).

- Making `/project` the sole initial JS mount while withholding the machine-global runtime-cache `home` binding (§3, lines 193-217) is a strong security decision. Arming currently installs both `project` and `home` bindings (`src/bin/ibex/runtime.rs:1913-1947`), so the distinction is load-bearing.

- The universal POSIX-shaped virtual namespace (§3, lines 243-279) is simpler, more portable, and less disclosure-prone than platform-specific host paths. It also gives file URLs, module metadata, cwd, and filesystem errors a common vocabulary.

- Affordance parity (§10, lines 580-593) is one of the best parts of the proposal. It correctly treats dot commands, completion, banners, and error rendering as part of the security surface rather than privileged CLI conveniences.

- The TTY-driven mode split (§2, lines 145-191) correctly distinguishes an interactive editor, a program read from stdin, and a deterministic transcript projection. Program stdin as an in-memory main module is a useful product boundary.

- The TypeScript non-JSX choice (§5, lines 331-342) is explicit and avoids unreliable content sniffing. The document also correctly requires parser-grade completeness rather than the current delimiter scanner (`src/bin/ibex/repl/mod.rs:486-563`).

- Serialized evaluation without waiting for global quiescence (§7, lines 426-449) is the right interactive event-loop model. The current runtime already approximates this by pumping ready work rather than waiting for every handle (`src/bin/ibex/repl/mod.rs:706-731`; `src/bin/ibex/engine/hermes.rs:1100-1138`).

- The distinction between empty completion and a genuine `undefined` value (§9, lines 498-505) is correct and exposes a real defect in the current string-shaped result API.

- The completion rules (§13, lines 657-682) correctly recognize that pure-JavaScript reflection is not trap-free. Refusing member completion when a native safe primitive is unavailable is the appropriate fail-closed behavior.

- The lifecycle direction (§15, lines 726-774) is sound: the session layer, not JavaScript or native `std::exit`, should own terminal restoration, history, and process termination.

- The compatibility priority ordering (§Compatibility priorities, lines 776-788) is excellent. Security attribution and pre-effect authorization correctly outrank Node familiarity and cosmetic compatibility.

- The acceptance plan is unusually broad, including PTY behavior, source/generated builtin parity, principal propagation through async work, terminal injection, rc-file inertness, and WP7 closures (§Acceptance criteria, lines 820-948).

## 3. **Concerns**

1. **Severity: Blocking — Path traversal and symlink staging are internally inconsistent.**

   **Evidence:** §3 says `..` normalizes lexically and may traverse from `/project` to the readable synthetic `/` (`llp/0022-repl-behavior-and-semantics.spec.md:251-266`). Acceptance criterion 3 nevertheless says bare `../` must fail as an escape (`836-839`). From the initial cwd, `..` and `/project/..` both normalize to `/`.

   More seriously, §3 and AC3 require a symlink escape to fail “before any host access” (`229-235`, `836-839`). The target cannot be discovered without at least retained metadata/readlink/open operations. LLP 0021 explicitly treats such discovery as staged effects that must be authorized before each disclosure (`llp/0021-capsec-effect-model-migration.plan.md:353-363`, `634-691`).

   **Resolution criterion:** Choose whether traversal is normalized-path-equivalent or provenance-sensitive, and pin `stat`, `readdir`, `realpath`, and `chdir` for `".."`, `"/project/.."`, and `"/"`. Replace the impossible symlink rule with an explicit staged algorithm: authorize traversal/discovery, retain the link or parent identity, resolve, re-authorize the discovered target, and authorize content or mutation before that next effect.

2. **Severity: Blocking — Root and package virtual path identities are not defined coherently.**

   **Evidence:** §3 says `/project` is root-visible and package bindings never match it (`213-217`), while §4 says one session cwd drives relative resolution for all code (`298-305`). §6 then keys the module cache by resolved virtual absolute path (`415-421`). LLP 0021 makes package-root identity owner-sensitive (`llp/0021-capsec-effect-model-migration.plan.md:260-275`, `365-370`), and the actual mapper selects owner-matching package bindings for package principals (`crates/capsec-semantics/src/arming.rs:175-218`, `550-580`).

   It is therefore unspecified what package code sees for `process.cwd()`, relative filesystem paths, `/project/...`, `__filename`, `__dirname`, `import.meta.url`, error paths, or a path string passed by root. A display string alone is not a safe cache key when binding owner is part of authorization identity.

   **Resolution criterion:** Define an internal identity such as `(runtime, logical root, binding owner, normalized components)` separately from its display spelling. Specify root and package views for every path-bearing surface, and key module/cache decisions by authenticated identity. Add cross-principal aliasing, workspace/symlinked-package, passed-path, and cache-collision fixtures.

3. **Severity: Blocking — The authenticated graph and policy for an entryless REPL are unspecified.**

   **Evidence:** §8 promises ordinary graph, import-gate, and package-principal behavior (`453-477`). LLP 0014 policy generation is entry-scoped (`llp/0014-import-site-grants-and-generated-policy.spec.md:105-117`), while LLP 0021 requires every package node and edge to exist in the immutable armed snapshot (`llp/0021-capsec-effect-model-migration.plan.md:365-370`). An interactive prompt has no build-time entry; program stdin is not known until read.

   Current startup loads project policy and makes its package nodes available to root (`src/bin/ibex/runtime.rs:1713-1776`), but LLP 0022 neither adopts nor rejects that behavior.

   **Resolution criterion:** Specify the canonical policy artifact and graph for interactive, transcript, and program modes; no-policy behavior; whether program stdin is parsed before arming; which graph nodes root may import; and the error for an out-of-snapshot package. A digest-bound REPL session manifest would be a clean design.

4. **Severity: Blocking — Root-reachable raw native globals bypass the public-facade guarantees.**

   **Evidence:** The root REPL executes on the real root global; only package compartments withhold `__exact*` bridges (`src/engine/hermes_runtime.cc:2569-2645`). Today:

   - `__exactExit` directly reaches native hard termination (`src/engine/hermes_runtime.cc:588-603`, `1704-1727`);
   - `__exactModuleResolve`/`__exactModuleResolveMeta` are global (`src/engine/hermes_runtime.cc:1836-1907`) and serialize host `path` and `pkgRoot` (`src/host/abi.rs:2165-2187`);
   - `__exactRealpath` returns a backing host spelling (`src/engine/hermes_runtime_fs.cc:2551-2578`).

   These violate cooperative exit and the no-host-path rule even if `process`, `fs`, and the module facade are corrected. The registry classifies raw exit as closed (`capsec/registry/coverage-edges.json:174033-174040`), but the implementation is not gated accordingly.

   **Resolution criterion:** Generate an inventory of every root-reachable raw loader, path, environment, stdio, and lifecycle bridge. Seal each after private bootstrap capture or convert it to typed logical inputs/outputs and cooperative requests. Add direct `globalThis.__exact*` red-team fixtures, not only public-builtin tests.

5. **Severity: Blocking — Exclusive session ownership of fd 0 is not enforced across all read routes.**

   **Evidence:** §2 promises that the session layer exclusively owns fd 0 (`180-187`), but AC22 tests only `process.stdin` (`911-912`). Current `__exactStdinRead` directly reads fd 0 (`src/engine/hermes_runtime_crypto.cc:5027-5073`), and `fs.readSync(0, ...)` reaches native descriptor reads (`src/builtins/fs.js:3614-3644`; `src/engine/hermes_runtime_fs.cc:2797-2848`). Close, readv, asynchronous read, `FileHandle`, tty, and retained aliases present the same class of problem.

   **Resolution criterion:** Make execution mode a native session fact. In interactive and transcript modes, every JS-originated operation on fd 0 must return the specified EOF view or one typed session-owned denial before touching the real descriptor; close, poll, and metadata calls must not damage the editor. Test every descriptor API and raw bridge for root and package callers.

6. **Severity: Material — Root-only operations and session commands lack precise principal-source rules.**

   **Evidence:** §4 and §15 authorize based on “the calling frame” being root-attributed (`298-305`, `758-768`). LLP 0021 instead intersects live frames, schedule-time owners, and deputy identities; missing, ambiguous, and `NoUser` attribution deny (`llp/0021-capsec-effect-model-migration.plan.md:326-363`). Package→root deputy calls and root functions scheduled by packages are therefore unsettled.

   Conversely, `.load` performs a typed read (§11, lines 611-618) but originates in the Rust session layer, where there is no Hermes frame. The current implementation simply executes a host-path file read (`src/bin/ibex/repl/mod.rs:930-940`).

   **Resolution criterion:** Define root-only mutation over the complete authenticated constrained-principal set. Separately define an unforgeable operator-submission principal for dot-command effects, normally the armed session root but still subject to ceilings, protected objects, and denial strata. Test direct, deputy, promise, timer, native-completion, and no-user cases.

7. **Severity: Material — The claimed cwd integrity depends on mutable JS facades and an underspecified retained identity.**

   **Evidence:** §4 claims package code cannot redirect a later root-relative operation (`298-305`). Current `process.cwd`/`chdir` exports are writable (`src/builtins/process.js:474-476`), while `fs` and `node:path` dynamically consult the public cwd facade (`src/builtins/fs.js:542-600`; `src/builtins/path.js:8`, `59-70`). A package that can mutate a shared facade can redirect JS-side resolution without invoking native `chdir`.

   The Spec also does not pin behavior if the cwd directory is renamed, removed, replaced, or swapped for a symlink after successful `chdir`.

   **Resolution criterion:** Make canonical cwd a sealed native session identity with a retained directory object or verified identity, rechecked on every relative effect. Specify whether public facade monkeypatching is forbidden or merely ignored by native resolution. Add rename/replacement and `defineProperty`/getter/Proxy attack fixtures.

8. **Severity: Material — The mode matrix is misclassified as implementable above the current engine seam.**

   **Evidence:** Staging stratum 1 assigns “mode detection and the §2 matrix” above the engine seam (`795-800`). TTY dispatch is above-seam, but program mode requires an in-memory main module with identity `ibex:stdin`, a `/project` referrer, static imports, top-level await, module metadata, and file-execution exit semantics. Interactive/transcript modes require a mode-aware native stdin policy.

   The engine currently accepts `<eval>` strings or host-path files (`src/bin/ibex/engine/mod.rs:22-79`; `src/bin/ibex/engine/hermes.rs:1140-1159`, `1515-1525`) and reports that native ESM/TLA are unavailable (`src/bin/ibex/engine/hermes.rs:1653-1660`).

   **Resolution criterion:** Add a staged in-memory source API carrying source text, synthetic identity, virtual referrer, input language/source goal, main-module flag, principal, await policy, and execution mode. Leave only TTY selection and transcript grouping in stratum 1.

9. **Severity: Material — Sloppy scripts, TypeScript, imports, and top-level await lack one coherent source-goal model.**

   **Evidence:** §5 requires classic-script sloppy semantics (`331-349`), while §§7–8 admit top-level await and static-looking imports (`424-490`), normally module-goal constructs with strict semantics. The current file transform lowers TS/ESM to CommonJS (`src/module_loader/transpile.rs:84-124`, `166-196`) and emits no source maps. The Spec does not define how imports are lowered without changing the enclosing input’s strictness, directive prologues, top-level `this`, completion value, or declaration behavior.

   It also says imports are supported “at least” in certain forms (`459-472`), leaving combined/default/type-only imports, `export`, import attributes, CJS globals, `import.meta`, and `.load` referrers unspecified.

   **Resolution criterion:** Provide an exhaustive v1 source-goal matrix for interactive, transcript, `.load`, program stdin, and imported files. Define the exact import grammar, TLA extension, strictness, directive-prologue behavior, referrer, module globals, and completion result. Require a dedicated TS-script transform that preserves those semantics and source locations.

10. **Severity: Material — The v1 persistent-binding model is neither complete nor stable.**

   **Evidence:** §6 permits redeclaration and loses cross-input `const`/TDZ (`378-405`) while requiring full within-input semantics. It also says implementations may narrow these deviations at any time (`393-395`), despite AC7 pinning them (`855-858`).

   The operational behavior of closures, destructuring, multiple declarations, imported snapshots, direct/indirect `eval`, `globalThis`, deletion, `var`/lexical collisions, class self-reference, failed initialization, and cancellation is absent. Hoisting declarations into properties can introduce additional within-input differences—for example whether an earlier closure observes a later replacement of a nominally `const` binding.

   The `$_` takeover rule (`407-413`) is also not implementable without saying whether takeover is syntactic or includes aliases, `Reflect.set`, indirect eval, descriptor replacement, deletion, and failed writes.

   **Resolution criterion:** Freeze one versioned v1 session-record algorithm and publish a declaration/publication conformance table. Define `$_` takeover as either an exhaustive AST rule or a native binding/property mutation observation rule. Narrowing should require a versioned contract change, not silently alter fixtures.

11. **Severity: Material — Trap-free display is not implementable through the seams currently specified.**

   **Evidence:** §9 prohibits getters, Proxy traps, coercions, and promise continuations (`496-519`), but §Staging asks for native trap-free introspection only for completion (`801-811`). Current native formatting reads properties and can call `JSON.stringify`/`toString` (`src/engine/hermes_runtime.cc:493-586`); the REPL then invokes mutable `Exact.inspect` (`src/bin/ibex/repl/mod.rs:63-79`). That inspector performs normal property reads, duck typing, iteration, method calls, `Object.keys`, and descriptor operations (`packages/ibex-runtime-js/src/inspect/inspect.ts:85-95`, `182-380`, `393-449`).

   Native eval also assimilates arbitrary thenables (`src/engine/hermes_runtime.cc:3033-3100`). §7 protects a bare thenable only when the input contains no TLA, leaving `await 0; ({then(){...}})` ambiguous.

   **Resolution criterion:** Add a native trap-free value snapshot/rendering seam, or render unsafe objects opaquely. Specify canonical bounded formatting, key order, cycles, promise/proxy states, Errors, symbols, functions, and Completion-to-display mapping. State that a final value is never assimilated merely because another part of the input used TLA.

12. **Severity: Material — Terminal-safety and styling boundaries are incomplete.**

   **Evidence:** §9 covers C0, ESC, CSI, and OSC (`514-523`) but omits other C1 introducers such as DCS, SOS, ST, PM, and APC. It does not clearly cover error excerpts, editor echo, pasted input, or malicious history recall. Current error formatting embeds submitted source directly (`src/bin/ibex/repl/mod.rs:107-164`).

   Rust cannot safely distinguish trusted inspection styling from user-controlled bytes once `Exact.inspect` returns one mixed string. Additionally, §14 renders prompt overrides verbatim (`686-690`) while §9 and §14 say one color predicate controls every REPL-authored ANSI sequence (`525-528`, `692-703`).

   **Resolution criterion:** Use structured style tokens with separately escaped payloads; escape the full C0/C1 ranges on every REPL-authored path; and explicitly classify trusted prompt ANSI as either exempt or subject to the color predicate. Expand PTY tests to DCS/APC/ST, hostile history, paste, stacks, and error excerpts.

13. **Severity: Material — Plain transcript mode contradicts the global color rule and lacks a complete protocol contract.**

   **Evidence:** §2 says transcript output contains no ANSI (`161-165`), while §14 enables ANSI on non-TTY output when `CLICOLOR_FORCE` is set (`695-703`), and AC25 explicitly requires it (`926-928`).

   The mode is described as deterministic and scriptable, but incomplete EOF does not change the orderly exit code (`166-169`), and ordinary evaluation-error effects on final status are unspecified. The exact ordering/framing between program stdout, displayed values, errors, and asynchronous reports is also not fully pinned.

   **Resolution criterion:** Set an explicit precedence rule—preferably transcript mode is always ANSI-free—and align AC25. Specify the exact record/text grammar, stream assignment, serialization checkpoint, and sticky exit-status policy, or explicitly characterize this as human-readable rather than automation-safe.

14. **Severity: Material — TTY disclosure is normatively contradictory.**

   **Evidence:** §§1 and 10 say captured TTY state is never exposed to JavaScript (`137-143`, `588-591`). §2 requires `process.stdout` and `process.stderr` to report genuine TTY status (`180-187`). Current native process setup exposes `isTTY`, rows, and columns (`src/engine/hermes_runtime_process_setup.cc:280-319`).

   **Resolution criterion:** Separate private CLI presentation state from the typed JS `stdio:query` surface. Specify exact root/package behavior for `isTTY`, dimensions, and fd metadata, then align §§1, 2, 10, registry rows, and tests.

15. **Severity: Material — Host-environment and `process.env` semantics are incomplete.**

   **Evidence:** §1 prohibits mutable host-environment consultation after arming (`137-143`), but §Staging and AC20 single out only `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` (`817-818`, `904-906`). Current post-arm reads include transform configuration (`src/module_loader/transpile.rs:64-94`), engine tracing/fallback controls (`src/bin/ibex/engine/hermes.rs:1026-1031`, `1433-1467`), runtime executable/config lookup (`src/bin/ibex/runtime.rs:975-1026`, `1107-1138`), and native await timeout.

   §10 withdraws `.env` (`585-587`), but AC15 permits it to be “absent or typed-surface-backed” (`887-889`), and the Spec never defines `process.env` reads, enumeration, mutation, deletion, or principal overlays. LLP 0021 distinguishes broker-base and per-principal overlay environment resources (`llp/0021-capsec-effect-model-migration.plan.md:285-287`).

   **Resolution criterion:** Inventory every environment read from startup through shutdown and capture all permitted values into immutable pre-arm configuration. Pin v1 `process.env` semantics by principal, exclude REPL presentation variables, and decide unambiguously whether `.env` is absent in v1.

16. **Severity: Material — The error taxonomy and registry obligations are not implementable through the current ABI.**

   **Evidence:** §9 requires distinct `ENOENT`, outside-mount, policy-denial, and malformed-input results (`530-540`). The current host ABI collapses decision refusal and adapter failure into coarse return values (`src/host/abi.rs:975-997`, `1157-1190`), and native fs commonly maps them to generic permission errors (`src/engine/hermes_runtime_fs.cc:541-565`).

   The synthetic `/` branch is declared a no-effect operation (§3, lines 263-265), but generated `readdir` and `stat` edges currently unconditionally require `fs:list` (`capsec/registry/coverage-edges.json:35302-35348`, `36824-36870`). Staging does not name this registry branch. AC1–6 also sample only a fraction of the promised “all path-taking runtime surfaces.”

   **Resolution criterion:** Define a structured worker-safe resolver result with a stable reason enum, virtual `path`/`dest`, operation, and safe decision ID. Generate exact synthetic-root/no-effect and mounted-resource branches. Tie conformance to a generated inventory covering every sync/callback/promise fs API, multi-path operation, fd route, file URL, module loader, `Exact.file`, watch, source-map, raw bridge, and both source/generated builtins.

17. **Severity: Material — Cancellation, exit, and shutdown lack a complete state-transition contract.**

   **Evidence:** §15 says the first interrupt requests cancellation but also announces that evaluation continues (`737-744`). It does not define accepted versus unavailable cancellation, partial binding publication, `$_`, pending native work, runtime reuse, exit status, or interrupt-latch reset.

   Current Tokio execution is single-threaded (`src/bin/ibex/main.rs:296-297`), native eval blocks synchronously (`src/bin/ibex/engine/hermes.rs:869-917`), and the reader waits for completion (`src/bin/ibex/repl/mod.rs:691-731`). `process.exit` currently hard-exits, while the JS wrapper catches native errors (`packages/ibex-runtime-js/src/node/process.ts:1936-1973`). A cooperative callback that merely records an exit request would allow code after `process.exit(7)` to run; a thrown sentinel could be caught.

   **Resolution criterion:** Specify a transition table for accepted, pending, unavailable, and failed cancellation; state publication; latch reset; and bounded shutdown. Define an uncatchable structured lifecycle completion, `finally` behavior, `beforeExit`/`exit` listener behavior, multiple requests, and `process.exit(7); sideEffect()` ordering. Either prove Hermes’s any-thread timeout interrupt leaves a reusable runtime or make a supervisor/worker boundary normative.

18. **Severity: Material — Asynchronous-failure reporting is not deterministic enough for a Spec.**

   **Evidence:** §9 requires report-once behavior, listener precedence, principal attribution, and storm coalescing (`542-556`) but leaves the determination checkpoint and storm threshold/window undefined. The current fallback rejection tracker wraps Promise methods and can set `process.exitCode` (`packages/ibex-runtime-js/src/promise-rejection-tracking.ts:172-288`); native async callback failures follow a different raw/fatal path (`src/engine/hermes_runtime.cc:653-692`).

   **Resolution criterion:** Require an engine event carrying the original value, safe stack, promise/event identity, owning constrained principals, evaluation association, and handled-late transition. Pin the determination turn, listener precedence, exit-code effect, coalescing threshold/window, and ordering relative to prompt redraw.

19. **Severity: Material — Ignoring an authority attribute and continuing is fail-open with respect to user intent.**

   **Evidence:** §8 says authority-bearing attributes are acknowledged as inert and the import proceeds with existing authority (`479-494`). LLP 0014 defines the canonical `authorities` attribute and rejects legacy forms (`llp/0014-import-site-grants-and-generated-policy.spec.md:228-236`).

   A user attempting attenuation could therefore execute code under broader pre-armed authority than intended. A warning after or alongside execution does not restore that intent.

   **Resolution criterion:** Make recognized authority attributes a pre-evaluation hard error in the REPL. At minimum enumerate every authority-bearing key and require explicit user opt-in before ignoring one; distinguish ordinary import attributes such as JSON type.

20. **Severity: Material — Single per-user history is the wrong secure default.**

   **Evidence:** §12 deliberately shares history across projects and acknowledges that secrets entered in project A become visible in project B (`652-655`). A leading-space convention is easy to forget and does not protect multiline input, accidental paste, or values that only later prove sensitive.

   **Resolution criterion:** Default armed sessions to no persistent history or a file keyed by authenticated-project digest. Cross-project history should require explicit operator opt-in, with a defined migration and retention policy.

21. **Severity: Material — Host-path-bearing observables are not fully specified, and `readlink` can contradict the no-host-path guarantee.**

   **Evidence:** §3 gives only qualitative behavior for `execPath`, argv, homedir, tmpdir, runtime stacks, and similar surfaces (`281-290`). It omits exact values for `__filename`, `__dirname`, `require.resolve`, `require.cache`, `module.paths`, and prompt/loaded `import.meta`.

   It also says `readlink` returns stored target bytes (`260-268`). An absolute symlink created outside Ibex may contain `/Users/alice/...`, directly exposing a backing path. Open question 5 then reopens whether host absolute paths should be accepted (`1041-1043`), despite the normative sections categorically rejecting them.

   **Resolution criterion:** Add a generated table of exact synthetic values, errors, and translation rules for every path-bearing observable. Virtualize or deny host-absolute `readlink` payloads unless a separately typed disclosure authority exists. Resolve open question 5 as “no” for v1.

22. **Severity: Minor/Non-blocking — Several edge cases need exact observable rules.**

   **Evidence:** The Spec does not pin hard-link behavior, synthetic `/` stat fields, file-URL query/fragment cache identity, malformed UTF-8 output, lone surrogates, or whether `.load` consumes a `repl:<n>` ordinal. It reserves `repl:` but not `ibex:`/`ibex:stdin`. Rejecting non-UTF-8 JS paths (§3, lines 251-259) is a legitimate compatibility reduction, but LLP 0021’s underlying typed vocabulary can represent non-UTF-8 Unix components (`llp/0021-capsec-effect-model-migration.plan.md:262-271`).

   **Resolution criterion:** Pin these cases in a compact edge-semantics table, reserve all synthetic schemes, and document where the JS adapter intentionally narrows the underlying typed vocabulary.

## 4. **Suggestions**

- Split the document into a frozen “v1 conformance profile” and a target-semantics appendix. True lexical sessions, future mounts, optional strict mode, framed protocols, and richer cancellation should not make v1 behavior elastic.

- Introduce a digest-bound REPL session manifest containing the authenticated project root, package graph, import edges, registry/profile identities, and permitted root entry surface.

- Treat `/project/...` strictly as presentation. Internally, carry authenticated logical-path objects containing runtime, root, owner, components, and retained platform identity.

- Build one semantic event stream for empty completion, value, evaluation error, asynchronous failure, program output, cancellation, and lifecycle requests. Render that stream to terminal text, plain transcript, or a future JSONL protocol.

- Prototype Hermes’s any-thread interruption primitive early. If catchability or runtime reuse cannot be proven, adopt the terminal-supervisor/engine-worker design before freezing the first-interrupt guarantee.

- Add read-only `.session`, `.policy`, or `.mounts` diagnostics exposing only already-authorized logical identities, graph/profile digests, and virtual cwd. These would materially improve debugging without violating affordance parity.

- Generate the REPL conformance matrix from the CapSec surface registry and builtin manifest so source/generated aliases and new APIs cannot escape path, stdin, lifecycle, or disclosure tests.

- Keep sloppy mode as the default, but consider a startup-only strict profile after the v1 source-goal model is stable. A mid-session toggle would make binding and cache semantics unnecessarily difficult.

## 5. **Open questions**

1. What exact policy artifact and authenticated graph arm an interactive or transcript session with no entry module?
2. What canonical virtual spelling and logical identity does package code receive for its own files, dependencies, and `/project` strings passed by root?
3. Does `..` normalize into the synthetic root, or is mount-boundary traversal provenance-sensitive?
4. Which raw native globals remain reachable from root after bootstrap, and which are sealed versus converted to typed APIs?
5. How will every fd 0 route be brokered without changing program-mode stdin semantics?
6. Is root-only session mutation defined over the complete LLP 0021 constrained-principal set, including deputies and schedule owners?
7. What exact source goal applies to each mode, especially sloppy inputs containing imports or TLA?
8. What operational session-record model freezes v1 closure, declaration, `eval`, and `globalThis` behavior?
9. Can Hermes provide genuinely trap-free value snapshots, including promise and proxy states, on every advertised target?
10. What state survives a successful cancellation, and under what conditions is the runtime reusable?
11. How do `process.exit`, `exitCode`, `beforeExit`, `exit`, `finally`, pending work, and multiple lifecycle requests interact?
12. Is plain transcript mode always ANSI-free, and which recoverable evaluation errors make it exit nonzero?
13. What exact filtered or per-principal `process.env` view exists in v1?
14. Should JS see genuine typed TTY information, synthetic values, or a closed surface?
15. Should persistent history be disabled or project-scoped by default?
16. Is any host-path disclosure admitted in v1? If not, should open question 5 be removed and deferred to a separate typed-debugging proposal?

## 6. **Readiness verdict**

The proposal has the right product and security direction, but unresolved blocking questions remain in path identity, graph construction, raw-native reachability, symlink staging, and stdin ownership. Numerous material language, lifecycle, rendering, environment, and protocol contracts also need to be made normative before independent implementations could conform safely.

VERDICT: NOT READY
### Orchestrator verification notes (round 2, outside verbatim body)

Spot-checked new decisive claims; all confirmed:
- `__exactRealpath` is a root-reachable raw native (`src/engine/hermes_runtime_fs.cc:2551+`); `__exactModuleResolve` metadata serializes host `path`/`pkgRoot` via `to_string_lossy` (`src/host/abi.rs:2177,2182`); `__exactStdinRead` reads fd 0 directly (`src/engine/hermes_runtime_crypto.cc:5027+`).
- `proc.chdir = chdir; proc.cwd = cwd;` are plain writable assignments (`src/builtins/process.js:474-476`).
- Post-arming environment consultation beyond the await knob exists (`src/module_loader/transpile.rs:64-71` reads `RUNTIME_TRANSFORM_ENV`).
- The generated `export:node_fs:readdir` edge requires `fs:list` unconditionally (`capsec/registry/coverage-edges.json:~35302`), confirming the synthetic-root no-effect branch needs a registry change.
- The `..`-traversal/AC3 contradiction and the "symlink escape before any host access" impossibility are accepted as internal defects of revision b2a9580177e0.

Disposition: blocking concerns 1–5 accepted; round-3 revision pins
normalized-path-equivalent traversal with a staged symlink-discovery algorithm,
an authenticated internal path identity (root/owner/components) distinct from
display spelling, the entryless arming contract (project policy artifact,
digest-bound session manifest named as mechanism), a raw-bridge sealing rule
with red-team fixtures, and full-route fd-0 brokering. Material concerns
accepted with these author resolutions of note: authority attributes become a
pre-evaluation hard error (adopting this round's stricter position over
round 1's inert-with-report, which this reviewer had proposed and the author
had adopted); history becomes project-scoped-by-default keyed by the
authenticated-project digest (superseding the v1 single-file choice); `.env` is
absent in v1 outright; `readlink` refuses host-shaped absolute targets as a
documented v1 narrowing; trap-free display is staged (descriptor-only walk
without Gets at stratum 1, native snapshot with proxy opacity at stratum 2)
with the residual stated. Suggestion adopted: conformance fixtures generated
from the surface registry; supervisor/worker named presumptive. Old open
question 5 resolved as "no host absolute paths in v1."

---

## Round 3 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f5549-d01e-7412-b189-2e6965d950c0`
**Date:** 2026-07-12
**Revision under review:** `62a91fa64a73` (sha256/12; reviewer independently verified the full hash)
**Redacted:** No — read by the Codex CLI under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, the concurrent Claude review, or any prior LLP 0022 review artifact (round-1/2 artifacts were relocated outside the repository for the duration of the round).
**Method:** cli-runner, shared round-3 brief.

### Verbatim review

## 1. **Overall assessment**

LLP 0022 is an excellent product and security direction, but it is not yet an executable normative specification. The review target’s SHA-256 is `62a91fa64a73b5600af770b307ba6a7f4bf2095687b60ccfb6298077d9b4fa2d`, matching the requested revision.

The core choices are mostly sound: an authenticated POSIX-shaped virtual namespace, root-attributed prompt code without package-authority laundering, distinct program and transcript modes, no ambient `.env`, no display-driven thenable assimilation, safe terminal rendering, and a supervisor-oriented lifecycle. Sloppy prompt semantics are defensible for compatibility provided strictness never carries security meaning and a strict opt-in is easy to use. Withdrawing `.env` is unequivocally correct. The second-`Ctrl+C` exit convention is reasonable, although its current state machine is contradictory.

The plan is incomplete at several load-bearing seams. Most seriously, the advertised capability registry currently classifies REPL entry and the native evaluator as closed, deny-only `vm:evaluate` surfaces, while the Spec simultaneously says all target-cell closures remain in force and never schedules the necessary evaluation-ingress reclassification. Entryless policy arming, imported dependency TLA, and session lexical persistence also lack implementable, testable contracts. Several security-sensitive surfaces—cwd, environment overlays, inspection, module cache visibility, lifecycle, terminal routing—would require implementers to invent semantics not fixed by the document.

The proposal should proceed, but revision 3 is closer to a strong architectural blueprint plus acceptance wishlist than a complete Spec. The four Blocking concerns below must be resolved, followed by the Material issues, before Ibex can make an honest conformance claim.

## 2. **Strengths**

- The separation of shell cwd, authenticated project identity, and JavaScript-visible cwd is conceptually correct. [§1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:138) fails closed on project authentication, rejects fallback to the host root, and correctly excludes ambient startup files.

- The input-mode split in [§2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:202) is unusually good. Piped `ibex` is a program, while piped `ibex repl` is a human-readable projection of interactive semantics. This avoids accidentally making prompts, ANSI control, and editor behavior part of the program interface.

- Exclusive native ownership of fd 0 in REPL modes is the right invariant. Covering descriptors, retained aliases, raw bridges, polling, and close—not just `process.stdin`—shows appropriate adversarial depth.

- [§3’s identity-versus-spelling model](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:279) is sound. Authorizing and caching on logical-root, owner, normalized components, and retained object identity is consistent with LLP 0021’s exact-root and owner-sensitive model.

- The POSIX-shaped virtual namespace is a good default. It gives programs one portable path language, avoids leaking drive letters and UNC roots, and keeps host layout separate from authority. The staged symlink analysis also correctly acknowledges that link targets cannot be authorized before discovery.

- [§5](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:432) explicitly separates prompt strictness from security. That is essential: sloppy mode may be an ergonomic default, but it must never weaken attribution, policy, or host enforcement.

- [§7’s no-assimilation rule](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:555) is excellent. A displayed thenable is a value, not an instruction to invoke `then`, and unrelated timers or servers must not delay the next prompt.

- Refusing authority-bearing prompt imports in [§8](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:611) is the correct fail-closed default. Silently discarding an attenuation request would give the user broader authority than requested.

- [§9](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:630) properly distinguishes empty completion from the value `undefined`, calls for structured outcomes rather than string conventions, and covers the full C0/DEL/C1 terminal-control space rather than only CSI and OSC.

- The affordance-parity principle in [§10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:742) is exactly right. Rust’s ambient ability to operate the terminal does not authorize it to disclose state denied to session JavaScript. Removing `.env` follows directly.

- Project-scoped, hardened history and no-code-execution completion are strong defaults. The document correctly treats both as security surfaces, not cosmetic conveniences.

- The Spec accurately identifies important current defects:

  - `.env` directly enumerates the host environment at [repl/mod.rs:966](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:966).

  - Completion evaluates a synthesized `Function` and performs Proxy-sensitive reflection at [repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283).

  - The prompt still announces legacy capability grants at [repl/mod.rs:812](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:812).

  - Native evaluation reads `then`, attaches continuations, and consults `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` after startup at [hermes_runtime.cc:3033](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3033).

  - Armed `realpath` currently returns a backing path at [hermes_runtime_fs.cc:2551](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551), while resolver records serialize raw `path` and `pkgRoot` at [abi.rs:2165](/Users/ccheever/projects/ibex/src/host/abi.rs:2165).

  - Native cwd and hard-exit surfaces remain global bridges at [hermes_runtime.cc:1645](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1645) and [hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704).

## 3. **Concerns**

1. **Blocking — The Spec cannot currently coexist with the advertised capability registry.**

   **Evidence.** [§10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:708) says prompt evaluation remains subject to every target-cell closure and explicitly includes VM closure at lines 761–764. The registry classifies `command:ibex repl` as closed `vm:evaluate` at [coverage-edges.json:128477](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128477), `cli:repl` likewise at [coverage-edges.json:132827](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:132827), and `ex_hermes_eval` at [coverage-edges.json:133067](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:133067). `vm:evaluate` is terminal and deny-only until principal and endowment inheritance are proven at [capability-definitions.json:529](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:529). Both REPL target cells remain unsupported with no fixtures at [target-cells.json:49561](/Users/ccheever/projects/ibex/capsec/registry/target-cells.json:49561) and [target-cells.json:56956](/Users/ccheever/projects/ibex/capsec/registry/target-cells.json:56956).

   Inspection-related promises have the same problem. `Exact.inspect`, `require.cache`, `require.main`, and `process.mainModule` are closed `runtime:inspect` surfaces at [coverage-edges.json:196853](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:196853), [coverage-edges.json:222919](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222919), and [coverage-edges.json:216802](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:216802). Yet [§Staging](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1011) schedules only cwd, lifecycle, system-information, synthetic-root, and environment registry changes.

   **Resolution criterion.** Specify a registry/profile split between authenticated session execution ingress and JS-reachable VM evaluation. The former should be an internal control-plane/non-capability route carrying the armed snapshot, root identity, source identity, goal, and endowments; public VM/inspector routes must remain closed. Define the native renderer as non-JavaScript-reachable rather than reopening `Exact.inspect`. Either keep loader cache state closed or expose a principal-filtered immutable facade. Regenerate the edge classifications and target cells and provide executed attribution/endowment fixtures before claiming REPL support.

2. **Blocking — Entryless and stdin arming have no coherent policy-artifact contract.**

   **Evidence.** [§1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:151) introduces a digest-bound “session manifest,” but does not define its schema, generator, provenance, selection algorithm, or relationship to canonical policy and the armed snapshot. LLP 0014 makes generated policy entry-scoped at [0014:113](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:113), while LLP 0021 requires one exact authority row per graph node and exact import edges at [0021:365](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:365).

   The current generator requires `--entry` at [cli.rs:367](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:367). Runtime arming simply selects `<project>/ibex-policy.json` at [runtime.rs:1713](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1713), gives root an import entry for every policy principal at [runtime.rs:1755](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1755), and creates root-to-every-package graph edges at [runtime.rs:1807](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1807). That is not yet the specified entryless artifact.

   Program mode is more problematic: “derive exactly as a file entry would” requires dependency analysis before arming, but stdin cannot safely mint an unreviewed authority graph merely by containing import-site declarations.

   **Resolution criterion.** Define a versioned session-manifest schema, generation workflow, independent digest domain, source-policy provenance, and deterministic selection among zero, one, or multiple entry artifacts. State exactly how the root import surface is derived. Program stdin must use a pre-reviewed graph/ceiling or be restricted to an empty/builtin-only graph; stdin declarations must not create new grants. Add wrong-entry, stale, tampered, multiple-policy, graph-mismatch, and unreviewed-authority fixtures.

3. **Blocking — Dependency-level top-level `await` has no feasible module-graph design.**

   **Evidence.** The [§5 matrix](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:444) promises TLA in every imported file. Hermes reports no native TLA or ESM support at [hermes.rs:1653](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1653). The loader lowers modules into a synchronous CommonJS chain, and its implementation explicitly says TLA is permitted only for the entry shim at [transpile.rs:97](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:97). LLP 0004 confirms the synchronous `require()` architecture at [0004:60](/Users/ccheever/projects/ibex/llp/0004-module-loading-and-builtins.explainer.md:60).

   Correct dependency TLA requires asynchronous linking and evaluation, dependency ordering, live bindings, async-cycle handling, failure propagation and caching, and defined CJS interoperation. “Import/TLA lowering” in Staging does not supply those semantics.

   **Resolution criterion.** Either specify and prototype an asynchronous module-graph linker/evaluator, including cyclic TLA and mixed CJS/ESM fixtures, or narrow v1 to prompt/program-entry TLA and make imported dependency TLA a stable, loud unsupported error.

4. **Blocking — The “frozen v1 session-record algorithm” is not an algorithm and freezes harmful deviations.**

   **Evidence.** [§6](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:493) gives a publication table but does not define binding cells, name lookup, closure capture, cross-kind collisions, destructuring, global property descriptors, direct/indirect eval, Annex B behavior, or cancellation commit points.

   For example:

   ```js
   let x = 1
   const f = () => x
   x = 2
   f()
   ```

   Copy-out publication produces `1`; shared-cell publication produces `2`. Both can be read into the current table. Failed-input closures and `var`/`let` collisions are similarly ambiguous. The current TLA statement wrapper at [repl/mod.rs:851](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:851) demonstrates why publication and closure semantics cannot be inferred from ordinary evaluation.

   The table also deliberately makes prior `const` and imported bindings writable and then declares any correction a versioned contract change. That creates a novel language dialect before compatibility has been demonstrated.

   **Resolution criterion.** Publish an operational environment-record algorithm covering declaration, lookup, assignment, replacement, closure capture, imports, publication, failure, rejection, and cancellation. Preserve ordinary assignment immutability and read-only imports; if explicit cross-input redeclaration is desired, model it as replacement of a session cell rather than ordinary assignment to a `const`. Add exhaustive cross-kind, closure, eval, descriptor, and partial-failure fixtures.

5. **Material — Source goals, file dialects, CommonJS, and `.load` are conflated.**

   **Evidence.** [§5](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:434) first places `.load` under non-JSX TypeScript grammar, then makes it extension-selected. It subsequently classifies all `.load` inputs as sloppy scripts and all imported files as strict modules. The actual loader supports `.js`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.jsx`, `.mts`, `.cts`, and `.json` at [LLP 0004:52](/Users/ccheever/projects/ibex/llp/0004-module-loading-and-builtins.explainer.md:52). A `.cjs` file is not an ESM module with top-level `this === undefined`, and JSON has no JavaScript source goal. The Spec also leaves `.load`’s relative-import referrer and the display result of each static import form undefined.

   **Resolution criterion.** Add two separate normative tables: extension/content → parser dialect, and resolved module kind → evaluation semantics. Cover CJS wrappers, ESM, JSON, JSX/TSX, `.d.ts`, extensionless files, `this`, globals, strictness, TLA, cache behavior, relative referrers, and display results.

6. **Material — The virtual namespace lacks the authenticated prefix data needed to implement principal-relative mapping.**

   **Evidence.** [§3](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:288) allows the same `/project/...` spelling to resolve against different owners, but does not define each package binding’s authenticated virtual prefix or conflict rules. `ArmedRootBinding` contains a logical root, owner, optional logical path, host path, and object identity—but no display prefix—at [arming.rs:58](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:58). Current binding generation assumes `<project>/node_modules/<name>` at [runtime.rs:1823](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1823), which cannot represent workspaces, aliases, scoped/nested duplicates, pnpm layouts, or multiple versions of the same name.

   **Resolution criterion.** Define a total digest-bound mapping `(principal, virtual path) → logical identity` and its inverse display mapping. Add authenticated virtual prefixes, locator/version ownership, longest-prefix and tie rules, and fixtures for duplicate versions, nested dependencies, workspaces, aliases, symlinked packages, and cross-principal string transfer.

7. **Material — Synthetic-root cwd and operation semantics are underdefined.**

   **Evidence.** [§3](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:311) makes `/`, `..`, and `/project/..` a synthetic directory with no backing host effect. [§4](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:416) requires every successful `chdir` target to retain a verified platform directory object. The result of `process.chdir("/")` or `process.chdir("..")` is therefore unspecified. `opendir`, directory descriptors, `access`, `realpath`, watches, and mutation attempts against `/` are also not fixed.

   **Resolution criterion.** Define a sealed synthetic-directory identity and a complete operation matrix, or explicitly deny cwd transition to synthetic nodes with a stable error. Test entry into `/`, re-entry into `/project`, enumeration, stat, descriptors, realpath, watch, and mutation.

8. **Material — Symlink creation, following, and `readlink` do not round-trip coherently.**

   **Evidence.** [§3’s symlink rules](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:343) do not define how virtual absolute targets are stored. Storing `/project/x` makes the host kernel interpret the wrong path; storing the backing host path makes the proposed `readlink` rule refuse an Ibex-created link. Relative targets also need resolution against the link’s parent before containment and authorization. Current armed `realpath` returns the host spelling from a descriptor at [hermes_runtime_fs.cc:2573](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2573).

   **Resolution criterion.** Specify creation-time target encoding, relative-target resolution, object-identity remapping, chain limits, and `readlink` virtualization. Mappable targets should return virtual spellings; unmappable targets should be refused without disclosure. Add create/readlink/follow/realpath round-trip and escape fixtures.

9. **Material — The supposedly exact host-path-observable table is incomplete.**

   **Evidence.** [§3](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:359) calls its listed rows the v1 content. Current loader syntax also exposes `import.meta.path`, `.filename`, `.file`, `.dirname`, and `.dir` at [module-loader.js:3551](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3551). Resolver records carry raw `path` and `pkgRoot` at [abi.rs:2165](/Users/ccheever/projects/ibex/src/host/abi.rs:2165). `os.userInfo()` exposes `homedir` and `shell` at [os.js:190](/Users/ccheever/projects/ibex/src/builtins/os.js:190), backed by passwd data at [hermes_runtime_osinfo.cc:177](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_osinfo.cc:177). `process.execArgv` is another `sys:read` surface at [coverage-edges.json:215369](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215369).

   **Resolution criterion.** Make a generated field-level registry projection the normative artifact. It must join exactly to every path-bearing field and alias and assign each a virtual value, synthetic value, closed behavior, or absence. Include module records, all `import.meta` aliases, argv/execArgv, user information, errors, source maps, watchers, raw resolver payloads, and generated builtin copies.

10. **Material — Shared, universally readable cwd creates a cross-principal metadata and integrity channel.**

    **Evidence.** [§4](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:387) asserts that every package may learn root’s cwd because co-resident packages are already considered able to learn project names. That is not implied by LLP 0021: a package without `fs:list` need not otherwise learn that root entered `/project/secrets/customer-A`. The current registry treats `process.cwd` as a typed `sys:read` effect at [coverage-edges.json:214801](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:214801).

    The claim that replacing shared `process.cwd` “fools nothing that matters” is also too strong. Even after native filesystem resolution is repaired, it can fool root application JavaScript. Today it additionally influences filesystem path resolution directly at [fs.js:542](/Users/ccheever/projects/ibex/src/builtins/fs.js:542) and in the generated copy at [vendored fs.js:366](/Users/ccheever/projects/ibex/vendored-generated/builtins/fs.js:366).

    **Resolution criterion.** Use compartment-local or sealed process facades and decide cwd visibility per principal. If global disclosure is retained, record it as an explicit profile-level information grant with adversarial fixtures rather than treating it as consequence-free.

11. **Material — Per-principal `process.env` overlays have no safe object semantics.**

    **Evidence.** [§10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:749) promises an empty base plus admitted per-principal overlays, but does not define lookup, enumeration, mutation, deletion, captured references, or cross-compartment transfer. Current code creates one mutable Proxy at [process.js:558](/Users/ccheever/projects/ibex/src/builtins/process.js:558), mirrored in the generated copy at [vendored process.js:462](/Users/ccheever/projects/ibex/vendored-generated/builtins/process.js:462). The top-level `process.env` object is presently closed because it mutates shared process state at [coverage-edges.json:215013](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:215013).

    A plain shared object cannot provide per-principal overlays: once root materializes a value or passes a reference, package reads no longer cross an attribution gate.

    **Resolution criterion.** Define a native principal-aware facade or per-compartment objects. Pin `get`, `ownKeys`, descriptors, set/delete/defineProperty, string coercion, captured-reference behavior, case rules, and mutation visibility. Prove that passing root’s `process.env` reference cannot expose root-only overlay entries.

12. **Material — Authority-bearing loader forms and existing dynamic authority APIs are not reconciled.**

    **Evidence.** [§8](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:611) discusses static import attributes, but LLP 0014 also defines `require("pkg", {"authorities":[...]})` at [0014:228](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:228). Current prompt parsing recognizes legacy `with { needs: ... }` at [repl/mod.rs:1033](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1033), and the loader still calls capability-grant logic from `require` and dynamic `import()` at [module-loader.js:5757](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5757) and [module-loader.js:6050](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:6050).

    LLP 0021 also exposes authenticated typed grant and handle APIs through `Ibex.permissions` and `Ibex.authority` at [0021:827](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:827), while LLP 0022 says prompt delegation is future work and adds no self-grant.

    **Resolution criterion.** Provide a mode-by-mode matrix for canonical and legacy authority syntax across static import, dynamic import, `require`, prompt, transcript, `.load`, and program stdin. Define the rejection stage as before authority mutation, resolution, or module execution. Explicitly state whether existing typed grant/handle APIs remain reachable from root prompt code or are closed in the REPL profile.

13. **Material — “Operator-submission principal” is not represented in the principal model.**

    **Evidence.** [§10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:721) attributes `.load` reads to an “operator-submission principal.” The principal enum contains only package, root, runtime, module-loader, and quarantine at [model.rs:302](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:302), matching the schema at [common.schema.json:94](/Users/ccheever/projects/ibex/capsec/schema/common.schema.json:94). Current `.load` delegates to a direct file read at [repl/mod.rs:930](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930) and [hermes.rs:1140](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1140).

    Root-only cwd and lifecycle operations likewise need exact registry predicates; `process:cwd` is currently deny-only shared-process mutation at [capability-definitions.json:279](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:279).

    **Resolution criterion.** Define operator submission as existing authenticated Root plus unforgeable event provenance, or version the principal schema. Pin the effect owner, constrained-principal set, static floor, protected-object checks, and evidence fields for `.load`, cwd, and lifecycle. Add over-granted-package and deputy tests proving root-only operations still deny package participation.

14. **Material — Safe inspection is not feasible under the stated fallback.**

    **Evidence.** [§9](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:639) allows descriptor walking and says a Proxy becomes opaque “once detectable.” JavaScript cannot safely determine that an ordinary-looking object is a Proxy without risking traps; descriptor and prototype reflection themselves invoke Proxy traps. Current completion does exactly that at [repl/mod.rs:311](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:311). Current native formatting reads `.message` and `.stack`, invokes `JSON.stringify`, and falls back to `toString` at [hermes_runtime.cc:493](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:493).

    The Spec’s native snapshot primitive could solve this, but open question 5 still treats its feasibility as unsettled, while rich safe display is already normative.

    **Resolution criterion.** Make the native trap-free snapshot a shipping prerequisite, implemented as a private non-JavaScript seam, or specify that every object/function/thrown object is opaque in v1. Test Proxy traps, hostile Error getters, `Symbol.toStringTag`, `toJSON`, coercions, promise state, and then-getters.

15. **Material — The current result ABI cannot represent the required semantics or terminal safety.**

    **Evidence.** The Spec requires `empty | value | throw | cancelled` and distinguishes empty completion from `undefined` in [§7–§9](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:567). Current C++ returns a null pointer for `undefined` and otherwise a NUL-terminated string at [hermes_runtime.cc:3161](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3161); Rust decodes it with `CStr` at [hermes.rs:898](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:898). Embedded NUL is therefore truncated before the renderer can escape it, and empty completion cannot be distinguished from the value `undefined`.

    The promised byte-deterministic framing also lacks an exact renderer grammar, key-order definition, stack grammar, and truncation marker.

    **Resolution criterion.** Require a length-bearing typed ABI with explicit outcome tags and encoding. Publish a versioned renderer grammar and exhaustively test empty versus undefined, embedded NUL, every C0/DEL/C1 value, invalid-encoding policy, deterministic key order, truncation, cycles, and payload/framing separation.

16. **Material — TTY topology, live-editor safety, and output ordering are unspecified.**

    **Evidence.** [§2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:204) selects interactive mode solely from stdin, while [§9](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:667) splits results and errors between stdout and stderr and [§14](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:869) applies color per stream. The behavior of stdin-TTY/stdout-pipe/stderr-TTY combinations, the destination for prompts/editor control, and broken output pipes is undefined.

    Bracketed paste does not by itself make pasted ESC/C1 bytes terminal-inert if the line editor redraws them verbatim. §9 covers recalled history but does not explicitly cover the live edit buffer or reverse-search display.

    Finally, raw program writes, structured result events, and asynchronous failures travel through different paths. Separate stdout, stderr, and IPC channels cannot inherently provide the ordering promised around prompt redraw.

    **Resolution criterion.** Add a complete fd-topology matrix and specify the controlling terminal/editor descriptor. Require escaping for live buffers and search results. Define one sequenced output broker with backpressure and ordering rules for console output, raw fd writes, results, errors, asynchronous reports, and redraws.

17. **Material — The interrupt state machine is internally contradictory and the supervisor remains only presumptive.**

    **Evidence.** [§15](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:913) says the first idle interrupt leaves the session idle and the second exits. Lines 919–920 say the latch resets whenever the prompt returns to idle, which happens immediately after the first idle interrupt; taken literally, a second interrupt can never be consecutive.

    The five-state model also has no representation for an idle-session background callback currently running synchronous JavaScript. Current `Engine` has no cancellation operation at [engine/mod.rs:22](/Users/ccheever/projects/ibex/src/bin/ibex/engine/mod.rs:22), and current readline waits for engine acknowledgement before drawing another prompt at [repl/mod.rs:681](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:681). Root `process.exit` currently performs an immediate process exit at [hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704); implementing an uncatchable completion that skips `finally` requires an engine abort or worker termination protocol.

    **Resolution criterion.** Define transitions over `(editor phase, engine-busy origin, interrupt latch)` with exact reset events and any timeout. Commit to either a proven reusable Hermes cancellation primitive or a separate worker process—not merely a thread—whose supervisor owns the terminal, history, output broker, and lifecycle. Test prompt evaluation, background infinite loops, accepted/unavailable/failed cancellation, native worker failure, `SIGTSTP`/`SIGCONT`, and repeated interrupts.

18. **Material — History identity, configuration, migration, and pre-arm startup ordering are incomplete.**

    **Evidence.** [§12](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:815) promises a “non-reversible digest” and three modes but gives no construction or user-facing switch. An ordinary hash of a host path or device/inode tuple is dictionary-guessable. Rename, replacement, worktrees, symlinks, and inode reuse also have undefined identity behavior. `Commands::Repl` currently has no options at [cli.rs:227](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:227), while LLP 0010 requires command/option changes to update the CLI manifest and documentation together at [0010:98](/Users/ccheever/projects/ibex/llp/0010-ibex-binary-ownership.decision.md:98).

    Current history migrates one global legacy file into another global location at [repl/mod.rs:582](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:582), potentially importing cross-project history into the first project-scoped session.

    [§1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:191) also requires prompt, color, and history configuration before arming. Current dispatch constructs and loads the runtime first at [main.rs:1332](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1332), then `repl::start` reads prompt and history at [repl/mod.rs:646](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:646).

    **Resolution criterion.** Define a keyed per-user HMAC construction and project-identity persistence rules; pin formats, migration behavior, and exact limits. Add an interface such as `--history=project|global|off` with coordinated manifest updates. Construct an immutable `ReplStartupConfig` in CLI dispatch before `Runtime::from_cli`, and pass it through without later environment consultation.

19. **Material — Normative limits, error shapes, input bounds, and exit normalization are missing.**

    **Evidence.** The document repeatedly says “bounded” or “documented” without supplying normative values: symlink depth, renderer depth/breadth/string length, history entries/bytes, completion time, asynchronous-storm window, shutdown drain, and exit-listener budget. The current implementation already has arbitrary choices—five seconds for completion at [repl/mod.rs:27](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:27) and 200 ms for EOF drain at [hermes.rs:204](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:204)—but the Spec does not adopt or replace them.

    Program stdin is read to EOF before arming without a stated size limit. Malformed UTF-8 “must not crash” but is not specified as rejected, replaced, or losslessly framed. `.load` does not restrict FIFOs, devices, directories, or oversized files. The error taxonomy names reason classes but not JavaScript class/code/property shapes. `process.exit(n)` and `process.exitCode` lack type, range, NaN, descriptor, and platform-normalization rules; current native coercion is ad hoc at [hermes_runtime.cc:1713](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1713).

    **Resolution criterion.** Publish versioned limits, encoding, completion-value, error-shape, and lifecycle tables. Define maximum input sizes and `.load` file types; malformed-UTF-8 behavior; symlink, renderer, storm, and shutdown budgets; JavaScript error fields; and exact exit-code normalization. Acceptance tests should assert boundary values, not merely that some undocumented bound exists.

20. **Minor/Non-blocking — Command and alias extensibility is not fully pinned.**

    **Evidence.** [§11](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:767) requires aliases to appear in `.help` but does not enumerate them. Current aliases include `.h`, `.quit`, `.q`, and `.cls` at [repl/mod.rs:920](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:920), while current help omits them at [repl/mod.rs:608](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:608).

    Allowing new “presentation-level” commands without a Spec revision is also risky: `.session` or `.mounts` can expose profile, graph, or runtime-inspection metadata merely described as “already-authorized,” which is not itself proof that prompt JavaScript may inspect it.

    **Resolution criterion.** Add an exact command/alias and Ibex-owned keybinding table, ideally generated from one manifest. Require an affordance-parity classification for every added command and a contract revision whenever a command introduces new observable state.

## 4. **Suggestions**

- Split the three mechanism layers into child LLPs: virtual path/runtime-state ABI, structured evaluator/session record, and terminal supervisor. LLP 0022 can remain the behavior contract that cites them.

- Put the Hermes worker in a separate process with sealed/EOF fd 0. Native fd checks should remain defense in depth, but OS-level separation makes consuming operator input structurally impossible.

- Use a single length-framed worker-to-supervisor event stream for results, errors, program output, asynchronous failures, cancellation, and lifecycle. Preserve stdout/stderr destinations as event metadata.

- Consider an append-only “cell module” linker for session persistence: each input gets a synthetic module, while an explicit session environment supplies live binding cells and commits publication only at specified points. This may avoid repeatedly reconstructing growing source while preserving closure identity.

- Add a machine protocol in v1 rather than postponing it. A dedicated length-framed descriptor or JSON text sequence can keep evaluator records separate from program stdout/stderr and make automation reliable.

- Keep sloppy mode as the interactive default if compatibility evidence supports it, but ship a startup-only strict profile. Root-principal typo globals are costly even when they are not a security boundary.

- Escape Unicode bidi controls and line/paragraph separators in REPL-authored diagnostics and history display, in addition to terminal control characters, to reduce visual spoofing.

- Specify completion insertion separately from display. Non-identifier property names should be omitted or inserted with correctly escaped bracket notation.

- Add property/state-machine tests for normalization, session cells, principal-relative mounts, lifecycle transitions, and output sequencing, plus fuzzing for TS completeness detection, import transformations, malformed encodings, and terminal payloads.

## 5. **Open questions**

1. What exact registry classification distinguishes authenticated root-session evaluation from closed JS-accessible VM evaluation?

2. Which reviewed entry-scoped artifact governs an entryless session, and how is it selected when several artifacts exist?

3. Can program stdin influence graph shape at all, and what pre-reviewed ceiling constrains it?

4. Is dependency-level TLA genuinely required for v1, or should TLA initially be prompt/program-entry only?

5. What operational cell model implements session lookup, closures, redeclaration, immutability, imports, failures, and cancellation?

6. Should v1 preserve `const` and import assignment immutability while separately permitting explicit cross-input redeclaration?

7. How do `.cjs`, `.mjs`, JSON, JSX/TSX, `.cts`/`.mts`, and `.load` map to dialect, source goal, referrer, and result display?

8. What authenticated virtual prefix represents each package binding, including workspaces, aliases, and duplicate versions?

9. Can cwd be principal-local, and should packages learn root’s cwd at all?

10. How are virtual absolute symlinks stored so that create, `readlink`, follow, and `realpath` round-trip?

11. What exact semantics protect per-principal environment overlays when objects or references cross compartments?

12. Which static, CommonJS, dynamic-import, and typed dynamic-authority forms remain available in each input mode?

13. Can Hermes expose trap-free object, Proxy, promise, and Error state on every advertised target, or must v1 render all objects opaquely?

14. What process-level supervisor protocol provides cancellation, output ordering, backpressure, cooperative exit, and terminal restoration?

15. What are the exact renderer, history, completion, symlink, input, storm, and shutdown limits?

16. What project identity should history survive—or intentionally not survive—across rename, symlink, worktree, clone, and replacement?

17. How do `Ctrl+D` with non-empty input, `SIGHUP`, `SIGQUIT`, `SIGTERM`, output `EPIPE`, and background synchronous loops map to lifecycle states and exit codes?

18. Is plain transcript only a human-readable fixture format, or is it intended to be a dependable automation interface?

## 6. **Readiness verdict**

The behavioral direction is worth pursuing, but the current revision has unresolved material correctness, coherence, feasibility, safety, and decision-quality issues. In particular, registry compatibility, session arming, imported TLA, and session-record semantics are Blocking.

VERDICT: NOT READY
### Orchestrator verification notes (round 3, outside verbatim body)

Spot-checked the decisive new claims; all three confirmed, and two are severe:
- **Blocking 1 confirmed.** `capsec/registry/coverage-edges.json` classifies
  `surface.cli.command.ibex.20repl` as `"classification": "closed"` under
  `"cap": "vm:evaluate"`, rationale "Ad-hoc CLI evaluation and REPL entry are
  closed"; `vm:evaluate` is `lifecycle: deny-only`, `globality: terminal`, risk
  tier 4 (`terminal.unattributed-code`) in `capability-definitions.json`. The
  spec's claim that every WP7 closure remains in force is therefore in direct
  contradiction with the surface it specifies.
- **Blocking 3 confirmed.** `EngineFeature::TopLevelAwait => false` and
  `EsmModules => false` (`src/bin/ibex/engine/hermes.rs:1657-1659`), and
  `src/module_loader/transpile.rs:97-99` states "Top-level `await` is passed
  through untouched — only the entry module may use it, and the entry path wraps
  it in the async shim." Dependency-level TLA, which the §5 matrix promised, has
  no implementation path without an async module linker.
- **Material 13 confirmed.** `Principal` (`crates/capsec-semantics/src/model.rs:304+`)
  has variants Package / Root / Runtime / ModuleLoader / Quarantine — there is no
  operator-submission principal, so §10's `.load` attribution must be defined as
  authenticated Root plus unforgeable provenance, or the schema versioned.

Disposition: this is the final round against the monolithic document. The author
(with the human's authorization) is splitting the mechanism layers into child
LLPs — precisely this review's Suggestion 1 and the same recommendation made by
both families in rounds 1–3. Blocking 1 and 2 are carried into the rewritten
LLP 0022; Blocking 3 and 4 into LLP 0024; the path/identity materials into
LLP 0023; the terminal/lifecycle materials into LLP 0025. Each child document
enters its own review loop, so the concerns are neither dropped nor deemed
resolved by relocation.

## Round 4 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1` (`OpenAI Codex v0.144.1`), model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f5575-0227-7162-beaf-00da3950a10a`
**Date:** 2026-07-12
**Revision under review:** `48607c295a66` (sha256/12 of the document)
**Document under review:** the **post-split behavior contract** — LLP 0022 rewritten after its mechanism layers were extracted into LLP 0023 (virtual namespace), LLP 0024 (structured evaluation), and LLP 0025 (terminal ownership). Rounds 1–3 above reviewed the *earlier monolithic* document and are not comparable revisions.
**Redacted:** No — the document, the sibling corpus, and the repository were read by the Codex CLI under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, to the concurrent Claude review of the same revision, or to any prior LLP 0022 review artifact — the existing `llp/reviews/0022-*.md` files were moved out of the working tree for the duration of the round and restored afterwards.
**Method:** cli-runner (`codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="ultra"' -s read-only --output-last-message …`), shared round-4 brief (LLP 0005 standard questions + required structure + readiness bar + the sibling corpus as normative context, with an explicit instruction to flag contradictions and dangling dependencies across the new 0022↔0023/0024/0025 seam).

### Verbatim review

1. **Overall assessment**

This is a strong proposal with mostly sound defaults, but it is not ready for acceptance. The behavior/mechanism decomposition is appropriate, the security posture is unusually disciplined, and the current-implementation critique is accurate. In particular, the ingress/VM distinction, refusal of runtime authority authoring, `.env` removal, Root-plus-provenance model, bridge sealing, and generated command table are all good decisions.

The remaining problems are substantive seams, not implementation detail. The authenticated ingress has no defined ABI; the synthetic-entry manifest and root import projection do not exist in the current policy/arming schema; operator-submission provenance has no typed carrier; and the siblings contradict 0022 on `eval`, `require.main`, cooperative exit, interrupts, mode topology, and transcript output.

The scope is mostly right for observable REPL behavior. One part should move outward: authenticated execution ingress is shared by REPL cells, `.load`, program stdin, `-e`, `-p`, and `ibex eval`, so its generic contract belongs in LLP 0024 or LLP 0021, with 0022 specializing the REPL behavior.

2. **Strengths**

- The behavior contract is grounded in real defects. Current completion evaluates its base through `Function` and reflective traversal ([repl/mod.rs:283–348](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)); prompt attributes print a false grant and invoke `Exact.setModuleCapabilities` ([repl/mod.rs:812–836](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:812)); `.load` uses `run_file_immediate` ([repl/mod.rs:930–940](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930)), whose implementation performs a raw host-path read and uses that path as source identity ([hermes.rs:1140–1158](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1140)); and `.env` directly enumerates `std::env::vars()` ([repl/mod.rs:966–970](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:966)). The motivation in §Motivation is therefore accurate ([0022:50–83](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:50)).

- The proposed ingress/VM distinction is conceptually correct. The current classifications really are:

| Surface | Current classification |
| --- | --- |
| CLI `command:ibex%20repl` | `closed` → `vm:evaluate` ([coverage-edges.json:128477–128484](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128477)) |
| CLI `repl` | `closed` → `vm:evaluate` ([coverage-edges.json:132827–132834](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:132827)) |
| `ex_hermes_eval` | `closed` → `vm:evaluate`, pending authenticated entry binding ([coverage-edges.json:133067–133074](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:133067)) |
| `vm:evaluate` | deny-only, terminal, risk `terminal.unattributed-code` ([capability-definitions.json:529–541](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:529)) |
| `global:Exact.inspect` | `closed` → `runtime:inspect` ([coverage-edges.json:196853–196860](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:196853)) |
| `global:require.cache` | `closed` → `runtime:inspect` ([coverage-edges.json:222919–222926](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222919)) |
| `runtime:inspect` | deny-only, terminal ([capability-definitions.json:383–395](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:383)) |

  Treating an authenticated operator entry route like `command:ibex run`—a trusted bootstrap non-capability—while retaining JavaScript evaluation as deny-only is coherent ([coverage-edges.json:128487–128494](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128487)).

- The immutable graph rule for piped source is correct. Authority authoring is build-time, entry-scoped, and stripped before execution ([0014:99–123](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:99)); the armed snapshot is the engine’s only policy form ([0021:193–206](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:193)). Piped bytes therefore must not mint graph edges or grants ([0022:148–177](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:148)).

- The authority-attribute HARD ERROR is the right default. Silently ignoring an attempted attenuation can run code with broader pre-armed authority, exactly as §6 argues ([0022:301–321](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:301)). This is safer than attempting runtime interpretation of build-only syntax.

- Root plus separate operator-submission provenance is a better model than inventing another authority principal. `Principal` should answer “whose authority?” while provenance answers “which trusted route asserted that Root?” The existing enum’s Package/Root/Runtime/ModuleLoader/Quarantine set is appropriate ([model.rs:302–322](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:302)).

- Private display, raw-bridge sealing, and `.env` removal are strong choices. Current `__exactExit` immediately terminates the process ([hermes_runtime.cc:1704–1727](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)); `__exactGetEnv` can read the process environment after a gate ([hermes_runtime.cc:1159–1184](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1159)); armed `__exactRealpath` returns a descriptor-derived host spelling ([hermes_runtime_fs.cc:2551–2591](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551)); and resolver records serialize host `path` and `pkgRoot` ([abi.rs:2165–2187](/Users/ccheever/projects/ibex/src/host/abi.rs:2165)). Public-facade security cannot survive those aliases.

- The generated command/alias/help table is an excellent drift-control idea ([0022:388–419](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:388)), consistent with the existing exact CLI manifest/dispatcher join in LLP 0010 ([0010:43–101](/Users/ccheever/projects/ibex/llp/0010-ibex-binary-ownership.decision.md:43)).

3. **Concerns**

1. **Authenticated ingress is not yet an authenticated seam — Blocking.**

   **Evidence:** §1 says ingress supplies the armed snapshot, authenticated Root, source identity, goal, and endowments ([0022:102–126](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:102)). The actual `ex_hermes_eval` ABI accepts only bytes, a caller-chosen source URL, bytecode flag, and output pointer ([hermes_runtime.cc:2924–2930](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2924)), then directly calls `evaluateJavaScript` ([hermes_runtime.cc:3004–3010](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:3004)). Stray embedder-evaluated scripts default to Root attribution ([hermes_runtime.cc:2875–2881](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2875)). LLP 0024’s proposed request has a `principal` field but no opaque armed-session binding ([0024:82–99](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:82)).

   **Resolution criterion:** Define a distinct structured session-submit ABI taking an opaque armed-session handle and deriving—not trusting caller-provided—Root, source goal, source identity, endowments, snapshot digest, and run nonce. Keep generic `ex_hermes_eval` closed in armed production. Add separate registry rows and negative fixtures for CLI dispatch, structured ingress, raw ABI evaluation, and JavaScript `eval`/`Function`. Move the generic ingress contract outward so `-e`, `-p`, and `ibex eval` receive the same treatment.

2. **The synthetic-entry manifest, policy selection, and root-edge projection are not defined — Blocking.**

   **Evidence:** §2 permits deterministic automatic selection among several policy artifacts ([0022:164–169](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:164)), but LLP 0014 makes artifacts entry-scoped specifically to prevent test-only grants from leaking into production ([0014:113–117](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:113)). The canonical generator discards root edges ([generate-policy.mjs:375–379](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:375)) and records only per-package import lists ([generate-policy.mjs:417–445](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:417)). Current arming compensates by making every policy principal directly importable by Root and adding Root→package edges for all of them ([runtime.rs:1763–1811](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1763)), which promotes transitive-only packages.

   The armed schema has no entry/session/main field and rejects extra properties ([armed-snapshot.schema.json:6–30](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:6), [armed-snapshot.schema.json:169–180](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:169)); `ExpectedArmingIdentity` contains no session kind or synthetic identity ([arming.rs:28–41](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:28)). The current policy selector is simply explicit `--policy` or `<project>/ibex-policy.json` ([runtime.rs:1710–1737](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1710)).

   **Resolution criterion:** Specify one canonical session-manifest representation and projection algorithm. It must bind mode, synthetic entry, selected policy digest, exact Root import edges, Root builtin/alias allowlist, and project binding into an independently expected digest component. Ambiguous policy selection must fail unless the operator explicitly selects a digest/artifact or the project commits a dedicated session policy. Add Root→A→B fixtures proving direct prompt import of B fails unless B has its own Root edge, plus conflicting app/test policy fixtures. AC3 must say exactly which bytes are tampered and must fail even after internal checksums are recomputed.

3. **Operator-submission provenance has no typed carrier — Blocking.**

   **Evidence:** `.load` depends on authenticated Root plus unforgeable submission provenance ([0022:347–355](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:347)). The principal enum correctly has no operator variant, but `EffectOccurrence` contains only actor, owner, constrained principals, and resource ([model.rs:1421–1464](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1421)); `DecisionContext` adds only handle IDs ([model.rs:1476–1484](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1476)). LLP 0024 and LLP 0023 define no opaque submission token.

   **Resolution criterion:** Add a non-policy-bearing evidence type such as `OperatorSubmission { snapshotDigest, runNonce, rootIdentity, sourceIdentity, ingressKind }`, backed by an opaque native token minted only by the armed session. Define how it establishes Root as actor/owner/constrained principal for `.load`, how it is validated and audited, and how replay, wrong-session, forged, JavaScript-originated, and arbitrary native-callsite submissions fail.

4. **§7 misstates Root authority, and piped-source trust is ambiguous — Material.**

   **Evidence:** §7 says operator submission is “subject to root’s static floor” ([0022:347–355](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:347)). Under LLP 0021 the static floor is a positive authority source, while authenticated ambient Root is a later independent positive source ([0021:324–351](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:324); [policy-rules.json:364–396](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:364)). A floor does not constrain ambient Root.

   The document calls piped bytes “unreviewed source” when explaining why they cannot author policy ([0022:170–174](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:170)), but apparently executes them as the session’s Root main module. Graph immutability does not contain direct Root effects or use of already-authorized deputies.

   **Resolution criterion:** Correct the floor language: Root is allowed by its floor or ambient-root source after every earlier ceiling, guard, and denial. If `.load` must require explicit floor coverage, define a new session ceiling or precedence rule. Explicitly state whether piping is the operator’s trust act and therefore grants full Root authority; otherwise specify a Quarantine/restricted-stdin profile. Do not imply that “cannot shape the graph” makes hostile piped code safe.

5. **The prompt-specific closure of dynamic authority APIs lacks a reachability profile — Material.**

   **Evidence:** 0022 makes `Ibex.permissions` and `Ibex.authority` unreachable from prompt Root ([0022:323–327](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:323)). LLP 0021 says the live Hermes surface exposes typed grant, revocation, handle-mint, and handle-revocation methods authenticated from the executing principal—including Root ([0021:827–848](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:827)). LLP 0024’s source request has no session endowment/reachability profile ([0024:84–95](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:84)), while §2 says the synthetic entry changes “only” the Root import surface ([0022:158–177](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:158)).

   **Resolution criterion:** Either close these APIs profile-wide or define and digest-bind a session-specific Root reachability/endowment profile that removes them before lockdown. Add direct, alias, prototype-walk, imported-root-code, and `.load` recovery fixtures. Amend the “and only this” statement if session arming also changes Root endowments.

6. **The authority-form HARD ERROR inventory and timing are incomplete — Blocking.**

   **Evidence:** §6 lists `authorities` and `needs`, but the build-time parser recognizes `authorities`, `grants`, `endow`, `builtins`, and `also` ([import-grants.mjs:17–21](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/import-grants.mjs:17)); LLP 0014 also discusses runtime `permissions` forms ([0014:281–296](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:281)). Accepting any historical authority/reachability spelling as an ordinary ignored attribute repeats the fail-open user-intent problem.

   “Before evaluation” is also impossible for an arbitrary computed dynamic-import or `require` option object: argument expressions and possibly Proxy getters must run before its contents are known. The current REPL implementation is only an ad hoc search for `needs:` ([repl/mod.rs:1033–1077](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1033)) and textually rewrites `import(` ([repl/mod.rs:860–862](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:860)).

   **Resolution criterion:** Generate one reserved-authority-form inventory shared with LLP 0014’s parser and reject every canonical or historical spelling across static import, dynamic import, and `require`. Split the timing rule into parse-time rejection of statically recognizable forms before any cell code runs and call-boundary rejection of dynamic bags before resolution, mutation, or module execution. Alternatively reject all nonliteral second arguments in v1. Pin comments, strings, whitespace, nesting, computed objects, aliases, Proxies, and ordinary `type: "json"` in fixtures.

7. **0022 closes `eval`, while LLP 0024 requires it — Blocking.**

   **Evidence:** §1 and AC1 require that prompt code cannot reach `eval`, `new Function`, or the engine evaluator ([0022:121–126](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:121), [0022:482–486](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:482)). LLP 0024 requires direct `eval` to see the session record, indirect `eval` to run as a global script, and indirect-eval writes to participate in `$_` mutation detection ([0024:362–365](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:362), [0024:382–392](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:382)). The registry closes `global:eval` and `global:Function` under `vm:evaluate` ([coverage-edges.json:195084–195091](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:195084), [coverage-edges.json:200533–200540](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:200533)).

   **Resolution criterion:** Remove LLP 0024’s direct/indirect-eval requirements from the initial profile and define their stable absent/tamed behavior. If another profile opens compartment-bound eval, make those cell-model clauses explicitly profile-conditional and revise the registry/security argument accordingly.

8. **Program stdin cannot simultaneously be module-goal, expose `require.main`, and keep it closed — Material.**

   **Evidence:** Program stdin is a module but promises `require.main` naming `ibex:stdin` ([0022:203–210](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:203)). §1 says `require.main` remains a closed `runtime:inspect` surface ([0022:128–134](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:128)); the registry agrees ([coverage-edges.json:222929–222936](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222929)). LLP 0024 gives program stdin module semantics and reserves `require` for script inputs ([0024:124–143](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:124), [0024:169–172](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:169)).

   **Resolution criterion:** Prefer module semantics: retain `import.meta.url`/`import.meta.main` and remove `require.main`. If CommonJS parity is required, define a separately classified immutable synthetic-main descriptor that exposes neither `require.cache` nor live module state. Give `process.mainModule` an explicit disposition too.

9. **Cooperative uncatchable exit has no evaluator representation — Blocking.**

   **Evidence:** LLP 0024’s exhaustive outcome set is empty/value/throw/cancelled ([0024:249–259](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:249)). LLP 0025 requires `process.exit` to create an uncatchable structured completion that skips subsequent code and even `finally`, while reaching the session layer for cleanup ([0025:341–360](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:341)). Current `__exactExit` instead invokes hard process termination directly ([hermes_runtime.cc:1704–1727](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)).

   **Resolution criterion:** Add a typed lifecycle-request outcome, or specify an equally explicit out-of-band engine control channel. Define state publication before the request, non-catchability, repeated requests, listener behavior, terminal restoration, history saving, and worker/supervisor propagation. The evaluator and session acceptance suites must exercise it end to end.

10. **Interrupt semantics conflict, and the architecture needed to guarantee them remains open — Blocking.**

   **Evidence:** 0022 says Ctrl+C cancels evaluation and a second consecutive interrupt always exits 130 ([0022:447–456](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:447)). LLP 0024 permits cancellation to be unavailable or failed ([0024:289–299](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:289)). LLP 0025 also permits a defeated request never to resolve, clears the latch after editing/continuation, and makes a second idle interrupt an orderly exit rather than exit 130 ([0025:258–298](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:258), [0025:328–333](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:328)). The required supervisor is only “presumptive”; process versus thread remains open ([0025:300–324](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:300), [0025:481–492](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:481)).

   **Resolution criterion:** Say that the first interrupt “requests cancellation,” reproduce one authoritative latch/state table, and pin exit status by state. Choose a process supervisor for v1, or provide target-wide proof that an in-process design can terminate hostile synchronous code and leave the runtime/terminal consistent. Also provide a normative program-stdin lifecycle/exit-status table for syntax failure, throw, async failure, `exitCode`, explicit exit, signal, and quiescence.

11. **Input-mode and descriptor topology are internally inconsistent — Material.**

   **Evidence:** 0022 makes TTY stdin sufficient for interactive banner, editor, history, and completion ([0022:196–214](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:196)). LLP 0025 degrades TTY stdin to transcript behavior if neither output is a TTY ([0025:118–130](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:118)); its table sends the ordinary TTY prompt/editor to stdout, but its controller priority selects stderr before stdout ([0025:121–128](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:121)). AC4 ambiguously says both `ibex` and `ibex repl` share transcript suites even though non-TTY `ibex` is program mode ([0022:496–500](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:496)).

   Malformed input is also dangling: LLP 0024 requires UTF-8 text ([0024:84–99](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:84)), while LLP 0025 only says malformed bytes must not crash ([0025:224–230](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:224)). Current code has no TTY split: both routes unconditionally start the same REPL ([main.rs:379–380](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:379), [main.rs:438–465](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:438)), which always prints the banner and starts history/readline ([repl/mod.rs:646–700](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:646)).

   **Resolution criterion:** Define semantic input mode and presentation transport as separate axes, choose one controlling-descriptor priority, and pin the full stdin/stdout/stderr matrix. Correct AC4. Define strict rejection versus replacement for invalid UTF-8 in program and transcript modes, including diagnostic, source position, and exit status.

12. **Safe display and byte-deterministic transcript output are under-specified — Material.**

   **Evidence:** Before its native primitive, LLP 0024 claims no property read while proposing `[Function: name]` and `[Array(3)]` ([0024:405–437](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:405)). Function name and Proxy-wrapped array length cannot safely be obtained through ordinary JavaScript reflection under that promise.

   0022 says transcript output has no ANSI under any setting and is byte-deterministic ([0022:211–224](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:211)), while LLP 0025 deliberately leaves program-authored output unmodified ([0025:184–199](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:184)). LLP 0025 identifies characters to escape but not their exact byte representation ([0025:150–182](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:150)), and both siblings leave renderer, completion, input, shutdown, and history bounds open ([0024:572–575](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:572), [0025:497–501](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:497)).

   **Resolution criterion:** Before native support, use only demonstrably safe coarse tags such as `[Object]` and `[Function]`. Pin a versioned rendering grammar: escape spelling, tags, key order, truncation marker, depth/breadth/string/input limits, newlines, and stdout/stderr determinism. Qualify “ANSI-free” to session-authored framing/styling unless program output is intentionally sanitized. Test callable, array, ordinary, and revoked Proxies.

13. **Path-error and `.load` semantics remain incomplete — Material.**

   **Evidence:** 0022 broadly says host-shaped spellings produce outside-mount errors ([0022:243–249](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:243)), while LLP 0023 explicitly preserves pure lexical `node:path` operations without capability decisions ([0023:388–392](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:388)). Thus `path.resolve("/etc/passwd")` should return a string; only an effectful resolver/adapter should error.

   `.load` is “grammar by extension” in 0022 ([0022:402–410](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:402)), but LLP 0024 does not define extensionless/unknown `.load`, says JSON has no source goal, and then describes `.load` generally as script input ([0024:174–215](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:174)). Its source table says `repl:<n>` annotated with a virtual path, while its acceptance criterion says loaded content reports the file path ([0024:101–122](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:101), [0024:473–476](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:473)).

   **Resolution criterion:** Qualify outside-mount errors to named effectful APIs. Define an exhaustive `.load` matrix for extensionless/unknown, JSON, `.d.ts`, JS/JSX/TS/TSX, CJS, and ESM extensions, including globals, completion value, TLA, imports, and error. Choose one exact diagnostic identity format such as `repl:3 (/project/foo.ts)` and pin its stack/source-map representation.

14. **The generated bridge and command inventories must join existing authorities — Material.**

   **Evidence:** §7 proposes a generated bridge inventory ([0022:357–365](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:357)), but LLP 0021 already defines a source-derived capsec registry and implementation manifest covering globals, ABI, loaders, startup, and CLI surfaces ([0021:530–553](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:530)). LLP 0013 explicitly requires the real-global inventory to include all globals and lazy installers, not merely `__exact*` names ([0013:573–608](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:573)). Resolver installation alone has canonical and “native” aliases plus metadata variants ([hermes_runtime.cc:1838–1907](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1838)).

   The command manifest specifies names and aliases but not arity, extra-argument behavior, allowed modes, output stream, effect/parity class, or `.break` outside continuation. `.help` promises every keybinding even though LLP 0025 only specifies “Emacs-style” plus Ctrl+R ([0022:399–419](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:399), [0025:224–236](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:224)).

   **Resolution criterion:** Make bridge sealing a one-to-one projection of the existing capsec registry, not a second inventory. Cover every Root-reachable native callable/value regardless of name, aliases, symbols, non-enumerable properties, and late installers; add an on-engine post-bootstrap reachability fixture. Join the dot-command schema to dispatcher, help, completion, runtime-surface metadata, and capsec classification, including arity, modes, effect class, stream, and help text. Pin a separate public keybinding manifest.

15. **The behavior/mechanism precedence rule reverses the stated hierarchy — Material.**

   **Evidence:** 0022 calls itself the behavior contract, then says a conflicting mechanism document governs its layer and 0022 is amended afterward ([0022:33–48](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:33)). That makes observable semantics unstable and legitimizes drift.

   **Resolution criterion:** State that 0022 governs observable REPL behavior and security, while siblings govern internal mechanism only when consistent. A contradiction is an invalid corpus state requiring an explicit coordinated revision; neither document silently wins. Give each behavior requirement a stable ID mapped to one sibling mechanism criterion and one end-to-end fixture.

16. **Cross-references and deviation counts have drifted — Minor/Non-blocking.**

   **Evidence:** LLP 0024 lists three session deviations but later calls them four ([0024:367–380](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:367), [0024:542–543](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:542)). It points asynchronous-failure behavior to 0022 §9 rather than §5 ([0024:460–465](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:460)); LLP 0025 points mode selection and transcript checkpoint to 0022 §2 rather than §3 ([0025:118–119](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:118), [0025:197–199](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:197)).

   **Resolution criterion:** Correct the count and references, then run a deterministic cross-LLP anchor check before the next review round.

4. **Cross-document findings**

| Type | Finding |
| --- | --- |
| **CONTRADICTION** | 0022 closes prompt `eval`/`Function`; 0024 requires direct and indirect eval as part of the cell model. |
| **CONTRADICTION** | Program stdin is module-goal, yet 0022 promises `require.main`; 0024 does not give module inputs `require`, and 0022/registry classify `require.main` closed. |
| **DANGLING DEPENDENCY** | 0025 requires an uncatchable cooperative-exit completion, but 0024’s exhaustive evaluator outcomes contain no lifecycle request. |
| **CONTRADICTION** | 0022 says a second interrupt always exits 130; 0025 clears the latch after editing/continuation and makes a second idle interrupt an orderly exit. |
| **DANGLING DEPENDENCY** | The infinite-loop escape guarantee depends on a killable worker, but 0025 leaves supervisor-process versus in-process interruption unresolved. |
| **CONTRADICTION** | 0022 selects interactive behavior solely from TTY stdin; 0025 can degrade that case to transcript behavior based on stdout/stderr. |
| **CONTRADICTION** | 0022’s absolute ANSI-free transcript promise conflicts with 0025’s rule that program output is unmodified. |
| **CONTRADICTION** | 0022’s broad outside-mount wording conflicts with 0023’s pure lexical `node:path` behavior. |
| **INCONSISTENT CONTRACT** | `.load` has competing `repl:<n>` versus virtual-file diagnostic identities and no exhaustive dialect/kind matrix in 0024. |
| **DANGLING DEPENDENCY** | 0022 relies on a session manifest, authenticated root-edge projection, and operator-submission proof that no sibling schema or request type delivers. |
| **DANGLING DEPENDENCY** | Byte-deterministic transcript fixtures depend on exact renderer grammar and numeric limits that 0024 and 0025 explicitly leave open. |
| **DANGLING DEPENDENCY** | Program-mode “file-execution exit codes,” malformed-stdin behavior, and quiescence/fatal-async rules have no cited normative contract in the sibling corpus. |
| **AMBIGUITY** | 0022 closes `require.cache`; 0023 lists its keys as path-bearing observables; 0024 only requires an internal persistent cache. Reachability versus internal representation is not distinguished. |
| **GOVERNANCE CONFLICT** | 0022 says it is the behavior contract but allows mechanism siblings to override it automatically. |

LLP 0023 otherwise validly delivers `/project`, logical path identity, virtual cwd, typed path errors, and no-host-path observables. LLP 0024 validly owns source goals, entry-only TLA, structured values, session cells, and asynchronous envelopes once the conflicts above are removed. LLP 0025 validly owns fd 0 brokerage, safe rendering, sequencing, lifecycle, and history once the unresolved process architecture and state-table discrepancies are settled.

5. **Suggestions**

- Introduce one `ExecutionIngress` record for file entry, stdin program, REPL cell, `.load`, and one-shot eval, authenticated by an opaque armed-session handle. Keep it policy-neutral and non-JavaScript-reachable.

- Require explicit policy selection on ambiguity. A committed `sessionPolicyDigest` or dedicated generated session policy is safer than heuristically selecting among app, test, and tool entries.

- Generate reserved authority syntax, bridge dispositions, and dot-command classifications as projections of existing parser/capsec/runtime authorities rather than creating parallel manifests.

- Make a process supervisor the v1 architecture. Use one private framed event protocol between worker and supervisor, then derive TTY rendering and plain transcript rendering from that same event stream. This would also solve cross-stream ordering, cooperative exit, forced termination, and future machine-protocol drift.

- Ship coarse `[Object]`/`[Function]` display and no member completion until native trap-free inspection is proven. This is a good place to choose safety over apparent richness.

- Consider an explicit `--stdin-quarantine` mode—or, more radically, make restricted stdin the default with `--stdin-root` as the trust assertion. At minimum, document clearly that ordinary piped source is full-trust Root.

- Assign stable behavior IDs such as `REPL-INGRESS-001`, `REPL-EXIT-003`, and `REPL-DISPLAY-004`; generate a matrix joining each to its sibling mechanism, registry edge, and end-to-end fixture.

6. **Open questions**

1. What exact object is the “session manifest,” who creates it, and which independently observed facts authenticate it?

2. Which policy artifact is eligible when a project has app, test, migration, and tool entry policies? Should ambiguity always fail?

3. Does raw `ex_hermes_eval` remain closed permanently in armed production, with only a new structured ingress admitted?

4. Is operator-submission provenance authorization-relevant, audit-only evidence establishing the legitimacy of Root, or both? How is replay prevented?

5. Is program stdin intentionally full ambient Root despite being called “unreviewed”? Would a quarantine profile be useful?

6. What exact builtin and alias set is available to a no-policy session, and how do terminal builtin denials override it?

7. Is `eval` absent in the initial REPL profile, or is compartment-bound direct eval intended to be reopened?

8. Should program stdin expose only `import.meta.main`, or is an immutable `require.main` compatibility facade worth a new registry classification?

9. Is a supervisor process now the v1 decision, or what evidence would permit an in-process implementation?

10. What are the exact rendering, completion, input-size, shutdown, and history bounds?

11. Which complete set of canonical and historical authority keys is reserved, and what is the rule for computed or Proxy-backed options?

12. What are the exact `.load` semantics for JSON, `.d.ts`, extensionless/unknown files, CJS, and ESM?

13. What are the numeric exit statuses and precedence rules for program stdin and transcript mode?

14. What are the initial value and mutation state of `$_`, and exactly which inputs increment the `repl:<n>` ordinal?

7. **Readiness verdict**

The proposal’s direction and major defaults are good, but unresolved authenticated-ingress, manifest/provenance, authority-preflight, evaluator, lifecycle, and sibling-coherence issues prevent acceptance.

VERDICT: NOT READY
### Orchestrator verification notes (round 4, outside verbatim body)

Spot-checked every decisive factual claim against the tree at revision `48607c295a66`. Findings:

**Confirmed — implementation:**
- `.env` enumerates `std::env::vars()` (`src/bin/ibex/repl/mod.rs:967`); `.load` routes through `run_file_immediate` (`:937`); completion evaluates its base expression via `Function('return (' + __expr + ')')()` behind only the syntactic `is_side_effect_free_path` guard (`:283-300`).
- The `[capability granted: …]` message (`:822`) is printed and then `Exact.setModuleCapabilities(0, …)` is called (`:830-831`) — and armed enforce **deletes** `Exact.setModuleCapabilities` at the end-of-bootstrap seal (`src/engine/hermes_runtime.cc:2376-2378`, carrying a `@ref LLP 0013#phase-1` comment stating that under enforce/lockdown grants come from the generated policy artifact, not runtime self-declaration). The prompt therefore reports a grant that provably did not occur. This is the sharpest confirmation of §6's "retired outright", and it is now cited in the revised §6.
- Raw bridges sit on the root global: `__exactExit` (`hermes_runtime.cc:1704-1727`), `__exactGetEnv` (`:1159-1184`), `__exactRealpath` (`hermes_runtime_fs.cc:2551-2591`), `__exactStdinRead` (`hermes_runtime_crypto.cc:5028`). **Beyond both reviews:** `__exactStdinRead` has a *second* install site at `hermes_runtime_crypto_windows.cc:428`. A per-platform duplicate install is exactly the case a hand-maintained bridge list misses, which independently strengthens the "generated inventory / one-to-one projection of the registry" requirement (§7) over any enumerated `__exact*` list.
- `Principal` is Package / Root / Runtime / ModuleLoader / Quarantine with no operator variant (`crates/capsec-semantics/src/model.rs:304-322`) — §7's Root-plus-provenance model is the right call.
- `<eval>` is the hardcoded source name (`src/bin/ibex/engine/hermes.rs:1517`).

**Confirmed — registry (the §1 argument is stronger than the document claimed):**
- `command:ibex%20repl` → `closed`/`vm:evaluate`; `cli:repl` → `closed`/`vm:evaluate`; `ex_hermes_eval` → `closed`/`vm:evaluate`; `command:ibex%20eval` → `closed`/`vm:evaluate`; `global:eval` and `global:Function` → `closed`/`vm:evaluate`. `vm:evaluate` is deny-only, terminal, `staticOnly`, risk tier 4 `terminal.unattributed-code` (`capability-definitions.json:529-541`).
- **But** `command:ibex` → `non-capability` / `runtime-bootstrap-state`, and `command:ibex run` likewise — while `main.rs:462-465` starts the REPL for `ibex` with no command and no file, and `main.rs:380` starts the same REPL for `ibex repl`. **The registry classifies one product surface two contradictory ways today.** Both reviewers found this independently; it is now the load-bearing evidence in §1.
- `command:ibex%20policy` → `non-capability` with `rationaleId: authority-control-plane` — the vocabulary hook the ingress rows need already exists, which answers Fable's OQ 2 in favor of a data change rather than a schema change.
- `global:require.main`, `global:process.mainModule`, `global:require.cache` → all `closed`/`runtime:inspect`. §3's `require.main` promise contradicted §1, the registry, and 0024 (which gives `require` to script inputs only, not to module-goal stdin). **Accepted and fixed** by removing `require.main` from program mode.

**Confirmed — the two artifact-shaped defects (both reviewers, independently):**
- `GRANT_ATTRIBUTE_KEYS` is **five** keys — `authorities`, `grants`, `endow`, `builtins`, `also` (`packages/ibex-devtools/src/scripts/import-grants.mjs:16-22`) — not the two §6 tabulated. A hand-listed refusal table would have silently accepted `grants`/`endow`/`builtins`/`also` as ordinary attributes, reproducing exactly the fail-open-with-respect-to-intent bug §6 exists to prevent. **Accepted**: the reserved-key set is now *generated from that constant* rather than tabulated.
- `generate-policy.mjs:375-379` drops root edges (`.filter(([from]) => from !== '')`, commented "root edges carry grants via import sites, not delegates") and emits only per-package `imports.packages` (`:417-445`) — so **the artifact carries no root-import row at all**. Meanwhile `runtime.rs:1763-1767` projects *every* policy principal as a root import and `:1808-1811` synthesizes a root→principal edge for each, including transitive-only packages. §2's rule ("the set of packages the project's generated policy already authorizes for root") was therefore *underivable from the artifact*, and the shipping behavior is precisely the widening §2 forbids. **Accepted**: §2 now names the artifact obligation and fails closed (empty root import surface, diagnostic naming policy regeneration) rather than defaulting to all-principals.

**Confirmed — schema:** the armed-snapshot schema has 21 required properties, `additionalProperties: false`, and no `entry`/`session`/`main` field; `ExpectedArmingIdentity` (`crates/capsec-semantics/src/arming.rs:30-41`) has no session kind; "entry" appears zero times in `arming.rs` and `capsec/examples/armed-snapshot.canonical.json`. The "synthetic entry" is an LLP 0021 schema change that the document did not state as an obligation. **Accepted**: §2 now carries an explicit obligations paragraph.

**Confirmed — LLP 0021 semantics:** the decision order (`0021:324-351`) makes the static floor stratum **10**, a *positive* authority source ("Every deny stratum precedes every positive authority source"), with ambient root at 14. §7's "subject to root's static floor" was a category error — a floor grants, it does not constrain. **Accepted and rewritten.** WP8 (`0021:827-848`) authenticates `Ibex.permissions.requestTyped` / `Ibex.authority.mintHandle` from the *executing* principal, so a package can self-request within its own floor — meaning a session-wide closure would change package behavior versus file execution. **Accepted**: the closure is now explicitly root-endowment-scoped, with package code unaffected.

**Confirmed — policy selection:** exactly one candidate exists today (`--policy` or `<project>/ibex-policy.json`; env-selected policy paths are explicitly forbidden — `runtime.rs:1710-1716`). §2's "if several candidate artifacts exist, selection is deterministic" described a hypothetical. **Accepted**: replaced with the actual rule, and ambiguity now fails rather than heuristically selecting.

**Rejected / not adopted:**
- Codex's framing of the ingress ABI, manifest, provenance, eval, lifecycle, and interrupt items as **Blocking** for *this document* is not accepted as such. Every one of them is a real defect and every one is fixed, but several are obligations on the *mechanism* siblings (0024's evaluator ABI and lifecycle outcome; 0021's snapshot schema; 0014's artifact). A behavior contract cannot be blocked on prose it does not own; what it *can* be blocked on is failing to **name** the obligation. The revision therefore adds an explicit **§11 dependency ledger** enumerating every guarantee 0022 relies on, the sibling that owns it, and whether that sibling delivers it today — which converts each dangling dependency from an invisible assumption into an auditable, assigned row. That is the correct instrument, and it is stronger than either reviewer proposed.
- Codex's "make a process supervisor the v1 architecture" is a 0025 decision (its §7/OQ1-2), not 0022's to take. 0022 now states its interruption guarantees as behavior and points at the open architectural question rather than pre-empting it.
- Fable's `.graph` command suggestion is deferred to OQ 2 with its parity argument recorded, rather than adopted: §8 requires a parity classification in the manifest for any new command, and this contract should not grow surface area in the same revision that tightens it.

**Sibling defects found and reported, not fixed here** (0023/0024/0025 are under concurrent refinement by other orchestrators; editing them from this loop would race): 0024 §7's direct/indirect-`eval` sentence (contradicts 0022 §1/AC1 and the registry's closure of `global:eval`/`global:Function`); 0024's deviation count (three in §7, "four" in Consequences); 0024 §9's stale `LLP 0022 §9` anchor (should be §5); 0024 §8's pre-primitive display examples `[Function: name]`/`[Array(3)]`, which require property reads (`.name`, `.length`) that trap on a Proxy and so violate that section's own "no property is read" promise; 0024's missing lifecycle-request evaluation outcome (0025 §8 requires an uncatchable cooperative exit that 0024's empty/value/throw/cancelled set cannot represent); 0024's silent Node divergence on program-stdin goal; 0023 §6's `require.cache` row (lists virtual spellings for a surface the registry closes); and 0025 §1's internal contradiction (the TTY/TTY row routes prompt/banner/editor to *stdout* while the controlling-descriptor rule selects "the first of stderr, stdout that is a TTY" = *stderr*).

## Round 5 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f5595-023d-75c2-b64b-4f7c72c2eb44`
**Date:** 2026-07-12
**Revision under review:** `515a2ff19f07` (sha256/12 of the document)
**Sibling corpus seen:** ⚠️ **The sibling corpus was revised by concurrent orchestrators while this round was running.** At launch: LLP 0023 `0d55849a9f5e` (545 lines), LLP 0024 `9561404fa4e8` (575 lines), LLP 0025 `5c86bb7897e4` (506 lines). At completion: 0023 unchanged, LLP 0024 `33b29b0e83d4` (1014 lines), LLP 0025 `184a46b3ebb2` (858 lines). This reviewer's citations show it read the **pre-revision LLP 0024** (its eval-sentence citation `0024:362-365` matches the 575-line file) together with the **post-revision LLP 0025** (its citations at `0025:768-778` and `0025:837-853` exist only in the 858-line file). Two of its Blocking findings are consequently stale against the corpus as it now stands; see the verification notes. This is disclosed rather than smoothed over, and it is itself a finding about running concurrent refinement loops.
**Redacted:** No — the document, the sibling corpus, and the repository were read by the Codex CLI under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, to the concurrent Claude review of the same revision, or to any prior LLP 0022 review artifact — the existing `llp/reviews/0022-*.md` files were moved out of the working tree for the duration of the round and restored afterwards.
**Method:** cli-runner (`codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="ultra"' -s read-only --output-last-message …`), shared round-5 brief (LLP 0005 standard questions + required structure + readiness bar + the sibling corpus as normative context + an explicit instruction to judge §11's new dependency ledger).

### Verbatim review

1. **Overall assessment**

This review covers the exact requested revision: SHA-256 `515a2ff19f07…`.

The proposal is directionally strong and worth pursuing. Treating the REPL as authenticated Root ingress into the same armed runtime—rather than as a privileged evaluator—is the right architecture. The defaults around build-time authority, immutable package graphs, inert display, `.env` removal, and raw-bridge sealing are security-conscious and generally well chosen.

It is not ready, however. Several load-bearing mechanisms are either contradicted by sibling specs, assigned to the wrong owner, or absent from §11. Most seriously, empty Root endowments do not hide `Ibex.permissions` or `Ibex.authority`; the proposed registry rationale does not describe code ingress; the interrupt machine violates its own escape invariant; and the evaluation/result protocol is incompatible with the supervisor boundary. The behavior-contract scope is appropriate, but its delegated interfaces must be normative and internally coherent before implementation can proceed safely.

2. **Strengths**

- The precedence rule is excellent: contradictions are explicitly invalid corpus states rather than silently resolved by document order (`llp/0022-repl-behavior-and-semantics.spec.md:45-51`).

- The current-state diagnosis is accurate. `.env` enumerates the host environment (`src/bin/ibex/repl/mod.rs:966-970`); `.load` performs a direct host-path read (`src/bin/ibex/repl/mod.rs:930-940`, `src/bin/ibex/engine/hermes.rs:1145-1158`); completion evaluates `Function(...)` and reflects over the result (`src/bin/ibex/repl/mod.rs:283-347`); and the prompt prints a false capability-granted message before calling a function removed under enforcement (`src/bin/ibex/repl/mod.rs:819-836`, `src/engine/hermes_runtime.cc:2310-2319`).

- The conceptual split between authenticated ingress and JavaScript-reachable VM evaluation is sound. Keeping `vm:evaluate` deny-only, terminal, and static-only is consistent with the registry (`capsec/registry/capability-definitions.json:529-541`), as is keeping `ex_hermes_eval` closed (`capsec/registry/coverage-edges.json:133067-133074`).

- Keeping inspection and loader state private is coherent with current classifications: `Exact.inspect`, `require.cache`, `require.main`, and `process.mainModule` are closed under `runtime:inspect` (`capsec/registry/coverage-edges.json:196853-196860`, `216802-216809`, `222919-222936`).

- The synthetic-entry direction is reasonable, and refusing to let piped source shape its own authority graph correctly preserves LLP 0014’s build-time grant boundary (`llp/0022-repl-behavior-and-semantics.spec.md:185-249`; `llp/0014-import-site-grants-and-generated-policy.spec.md:99-117`).

- Hard failure on apparent authority attributes is the correct safe default. Silently ignoring an attenuation request would execute with broader pre-armed authority than the author expressed (`llp/0022-repl-behavior-and-semantics.spec.md:405-436`).

- Root plus unforgeable submission provenance is preferable to inventing another principal. The actual principal set is Package, Root, Runtime, ModuleLoader, and Quarantine (`crates/capsec-semantics/src/model.rs:302-322`); submission route is evidence about Root attribution, not a new authority-bearing subject.

- The path behavior aligns well with LLP 0023: `/project`, virtual cwd, normalized outside-mount errors, and no host-path observables agree across the documents (`llp/0022-repl-behavior-and-semantics.spec.md:321-345`; `llp/0023-virtual-filesystem-namespace.spec.md:87-113`, `183-218`).

- Prompt versus program source goals and the entry-only top-level-`await` limit agree with LLP 0024 (`llp/0022-repl-behavior-and-semantics.spec.md:278-286`, `349-363`; `llp/0024-structured-evaluation-and-session.spec.md:124-160`).

- §11 is a valuable instrument. It honestly records real missing work such as the synthetic entry, root-import artifact row, submission provenance, lifecycle outcome, and `$_` display acknowledgement (`llp/0022-repl-behavior-and-semantics.spec.md:620-642`).

3. **Concerns**

1. **Blocking — Empty Root endowments do not close dynamic authority.**  
   Evidence: §2 and §6 say an empty Root endowment set makes `Ibex.permissions` and `Ibex.authority` absent (`llp/0022-repl-behavior-and-semantics.spec.md:212-215`, `444-452`). The snapshot does give Root empty endowments (`src/bin/ibex/runtime.rs:1768-1778`), but C++ unconditionally installs both facades on the real Root global (`src/engine/hermes_runtime.cc:2139-2156`, `2180-2233`).  
   Resolution criterion: specify an owned session-Root sealing or global-construction mechanism that hides both facades from prompt Root while preserving explicitly endowed package behavior. Add a §11 row and tests proving direct prompt absence plus package parity.

2. **Blocking — The proposed ingress registry rationale is semantically false.**  
   Evidence: §1 chooses `authority-control-plane` for REPL and one-shot ingress (`llp/0022-repl-behavior-and-semantics.spec.md:131-159`), but that rationale is limited to authority checking, delegation, revocation, or evidence bookkeeping (`capsec/registry/policy-rules.json:719-724`). Its generated fixtures test only non-capability, no widening, and post-lockdown invariants (`packages/ibex-devtools/src/scripts/capsec-fixture-obligations.mjs:67-72`), not authenticated source submission. Moreover, `command:ibex` is the generic root Clap node, not the implicit no-file dispatch branch (`capsec/registry/coverage-edges.json:128357-128364`).  
   Resolution criterion: introduce an `authenticated-code-ingress` rationale with obligations for snapshot binding, Root attribution, source identity/goal, endowments, wrong-session/replay rejection, and mediation of downstream effects. Inventory actual dispatch branches for implicit REPL, explicit REPL, `eval`, `-e`, and `-p`; leave generic parser markers classified according to their real role.

3. **Blocking — LLP 0024 reopens evaluators that LLP 0022 and the registry close.**  
   Evidence: LLP 0022 says prompt and package code gain no `eval`, `Function`, or evaluator route (`llp/0022-repl-behavior-and-semantics.spec.md:144-155`, `666-671`). LLP 0024 nonetheless defines direct and indirect `eval` over the session record (`llp/0024-structured-evaluation-and-session.spec.md:362-365`). The registry closes both globals (`capsec/registry/coverage-edges.json:195083-195091`, `200533-200540`).  
   Resolution criterion: remove or explicitly condition LLP 0024’s eval semantics on a future profile, and share a fixture proving that no JavaScript-reachable evaluator exists in the initial profile.

4. **Blocking — The evaluation/result contract is incompatible with the supervisor boundary.**  
   Evidence: LLP 0024 returns live value handles and async-failure envelopes containing original JS values (`llp/0024-structured-evaluation-and-session.spec.md:249-278`, `444-451`). LLP 0025 says a value handle cannot cross the supervisor boundary and that the worker must emit serializable display IR (`llp/0025-terminal-session-ownership.spec.md:237-260`). Current `ex_hermes_eval` also assimilates thenables and invokes user-controlled formatting (`src/engine/hermes_runtime.cc:493-537`, `3033-3058`, `3161-3174`). Armed construction merely returns an ordinary runtime handle, so generic eval cannot distinguish armed post-bootstrap use (`src/engine/hermes_runtime.cc:2768-2779`).  
   Resolution criterion: specify two distinct seams: an engine-local structured outcome carrying handles, and a worker-to-supervisor serial protocol carrying display IR, safe errors, async events, cancellation, and lifecycle requests. Define the `$_` display-success acknowledgement. Separate bootstrap-only evaluation from authenticated session submission, and reject generic `ex_hermes_eval` after armed bootstrap.

5. **Blocking — The interrupt contract contradicts LLP 0025 and fails LLP 0025’s own escape invariant.**  
   Evidence: LLP 0022 says a second consecutive interrupt always ends the session (`llp/0022-repl-behavior-and-semantics.spec.md:599-610`). LLP 0025 clears every latch when interrupting an edit or continuation (`llp/0025-terminal-session-ownership.spec.md:389-418`). In the “editing plus stuck background callback” state, the first interrupt clears the buffer and latch, the second only latches the background target, and a third is required—contradicting its two-interrupt invariant and AC7 (`llp/0025-terminal-session-ownership.spec.md:432-445`, `768-778`).  
   Resolution criterion: choose one target/latch model, repair the transition table, state precisely whether “two interrupts” means consecutive globally or against the same work target, and drive both documents from one model-checked/property-tested state machine.

6. **Material — `.load` provenance does not reach the filesystem effect it is meant to authenticate.**  
   Evidence: §7 assigns `.load` authenticated Root submission provenance (`llp/0022-repl-behavior-and-semantics.spec.md:478-492`), but the actual read occurs before evaluation through ambient Rust `tokio::fs::read` (`src/bin/ibex/repl/mod.rs:930-940`; `src/bin/ibex/engine/hermes.rs:1145-1158`). LLP 0024’s source request has neither a session credential nor a filesystem-effect route (`llp/0024-structured-evaluation-and-session.spec.md:82-99`).  
   Resolution criterion: define a typed session-effect API accepting virtual path plus an opaque authenticated submission credential, performing the constrained-Root read decision before reading, and returning authenticated bytes and logical referrer. Direct engine file reads must be unreachable from session commands.

7. **Blocking — The claimed generated raw-bridge inventory is not derivable from the current registry.**  
   Evidence: §7 promises a one-to-one projection covering aliases, symbols, lazy installers, and platform branches (`llp/0022-repl-behavior-and-semantics.spec.md:494-509`). The registry still contains an opaque dynamic native-global sentinel because it cannot identify every installed property (`capsec/registry/coverage-edges.json:194744-194751`). Existing seals are hand-authored arrays (`src/engine/hermes_runtime.cc:2323-2329`, `2360-2368`) and omit live bridges such as exit, environment, resolver aliases, and realpath.  
   Resolution criterion: add a generated root-global disposition manifest recording every install branch, platform, property key or symbol, alias, phase, private consumer, and sealed/converted disposition. Ban unresolved dynamic sentinels for conformant targets, join the manifest exactly to registry rows, and prove set equality with a trap-free live reachability sweep. Add this dependency to §11.

8. **Material — The session manifest needs exact entry, root-import, and package-binding schemas.**  
   Evidence: the armed schema has no entry field and rejects unknown properties (`capsec/schema/armed-snapshot.schema.json:6-28`, `180`). The canonical policy has no root-import surface (`capsec/schema/canonical-policy.schema.json:6-24`); the generator records then drops root edges (`packages/ibex-devtools/src/scripts/generate-policy.mjs:123-130`, `375-379`). Runtime consequently makes every policy principal Root-importable (`src/bin/ibex/runtime.rs:1763-1776`, `1807-1811`) and binds packages as `node_modules/<name>` instead of by authenticated locator (`src/bin/ibex/runtime.rs:1823-1853`).  
   Resolution criterion: define a mandatory discriminated entry union for file and session entries within the existing armed digest domain; define the canonical root-import set and its projection into the snapshot; and authenticate exact locator-to-package-object bindings. Fixtures must cover transitive-only imports, duplicate versions, nested/symlinked packages, and locator mismatch.

9. **Material — The authority-attribute default is good, but its mechanism has no owner.**  
   Evidence: LLP 0022 requires generated-key, pre-effect rejection in every form and mode (`llp/0022-repl-behavior-and-semantics.spec.md:405-436`). LLP 0024 does not assign this to its parser/transform seam. LLP 0014 says grant forms are stripped before execution and source remains runnable “in every mode” (`llp/0014-import-site-grants-and-generated-policy.spec.md:228-236`, `329-331`), which conflicts with hard rejection of raw prompt/stdin source. The authoritative key set is JavaScript (`packages/ibex-devtools/src/scripts/import-grants.mjs:15-22`), while the current Rust REPL parser recognizes only handwritten `needs` syntax (`src/bin/ibex/repl/mod.rs:1033-1077`).  
   Resolution criterion: amend LLP 0014 and LLP 0024 to distinguish build-processed files from raw runtime source; generate one hermetic cross-language reserved-key artifact; define parser/transform ordering; and add a §11 owner with all-form, all-mode pre-effect tests.

10. **Material — §11 is sound in concept but inaccurate and non-exhaustive.**  
    Evidence: its broad “yes” rows (`llp/0022-repl-behavior-and-semantics.spec.md:629-633`) mix contract presence with implementation status. The out-of-snapshot row assigns resolver errors to LLP 0024 §2, which is actually source identity (`llp/0024-structured-evaluation-and-session.spec.md:101-122`). The interrupt row cites “AC4,” while the interrupt criterion is LLP 0025 AC7. The renderer row cites LLP 0025 OQ5, but numeric bounds are OQ6 (`llp/0025-terminal-session-ownership.spec.md:847-853`).  
    Resolution criterion: use one row per interface guarantee with columns for normative owner, owner contract present, implementation present, conformance evidence, and blocking acceptance criterion. Add the missing dependencies enumerated in section 4 below.

11. **Material — The exhaustive command table does not yet have the manifest it claims to reuse.**  
    Evidence: §8 says REPL commands come from LLP 0010’s runtime-surface manifest (`llp/0022-repl-behavior-and-semantics.spec.md:543-549`). LLP 0010 version 4 specifies only the Clap command/parser inventory (`llp/0010-ibex-binary-ownership.decision.md:43-74`), and `runtime-surface.json` has no REPL-command schema (`runtime-surface.json:31-32`). Current help is handwritten and omits `.h`, `.quit`, `.q`, and `.cls` even though dispatch accepts them (`src/bin/ibex/repl/mod.rs:608-630`, `920-979`).  
    Resolution criterion: extend LLP 0010 and the manifest with a validated `replSurface.commands` schema containing name, aliases, arity, modes, stream, help, and parity classification; generate help, dispatch, and completion from it; add the obligation to §11.

12. **Material — `.env` removal does not deliver the stronger environment guarantee.**  
    Evidence: removing `.env` is correct, but §7 also promises that `process.env` exposes only the armed base and admitted overlays (`llp/0022-repl-behavior-and-semantics.spec.md:511-521`). `__exactGetEnv` still returns actual host values, while `__exactGetAllEnv` enumerates the process environment (`src/engine/hermes_runtime.cc:1159-1255`). Both remain reachable from Root, whose ambient authority is positive.  
    Resolution criterion: assign a logical session environment provider, captured before arming and keyed by principal/session; privately capture or seal the raw bridges; and prove an otherwise ambient Root cannot recover a host-only marker through either public or raw names.

13. **Material — Several behavior-contract essentials remain unowned or untestable.**  
    Evidence: program-mode quiescence, fatal async failures, and exit mapping are required by LLP 0022 (`llp/0022-repl-behavior-and-semantics.spec.md:278-311`), but LLP 0024 only emits events and leaves fatality to the consumer (`llp/0024-structured-evaluation-and-session.spec.md:444-465`), while LLP 0025 does not define normal program quiescence. Strict invalid-UTF-8 refusal (`llp/0022-repl-behavior-and-semantics.spec.md:313-315`) has no decoding owner: LLP 0025 merely says malformed bytes must not crash (`llp/0025-terminal-session-ownership.spec.md:339-345`). Renderer, completion, storm, input-size, history, and shutdown bounds remain open (`llp/0024-structured-evaluation-and-session.spec.md:572-575`; `llp/0025-terminal-session-ownership.spec.md:849-853`).  
    Resolution criterion: assign program lifecycle and byte decoding to named interfaces; pin fatality/order/status semantics; and version all bounds needed by deterministic transcripts and liveness fixtures.

4. **Cross-document findings**

**Contradictions**

- **Evaluator exposure:** LLP 0022 closes JavaScript evaluation; LLP 0024 defines direct/indirect eval semantics (`0022:144-155`; `0024:362-365`).

- **Interrupt behavior:** LLP 0022’s “second consecutive interrupt always ends” conflicts with LLP 0025’s target-specific latch clearing (`0022:599-610`; `0025:389-418`).

- **Result transport:** LLP 0024 exposes live value handles and original async-error values; LLP 0025 prohibits a supervisor session layer from receiving them (`0024:249-278`, `444-451`; `0025:237-260`).

- **Supervisor architecture:** LLP 0025 normatively specifies a supervisor process (`llp/0025-terminal-session-ownership.spec.md:504-540`) while OQ2 still asks whether it is a process or thread (`llp/0025-terminal-session-ownership.spec.md:837-840`).

- **Possible `require.cache` contradiction:** LLP 0022 keeps it closed (`llp/0022-repl-behavior-and-semantics.spec.md:161-168`), while LLP 0023 assigns virtual spellings to its keys and requires every observable-table row to be tested (`llp/0023-virtual-filesystem-namespace.spec.md:363-386`, `489-493`). LLP 0023 must say this is internal representation or conditional on future admission.

- **Presentation topology:** LLP 0022 unconditionally promises editing/history/completion for interactive mode (`llp/0022-repl-behavior-and-semantics.spec.md:276-277`), while LLP 0025 disables them when neither output is a TTY (`llp/0025-terminal-session-ownership.spec.md:161-175`).

- **“Independently implementable” is false:** LLP 0025 needs LLP 0024’s renderer, fifth lifecycle outcome, and expanded cancellation vocabulary (`llp/0022-repl-behavior-and-semantics.spec.md:33-43`; `llp/0025-terminal-session-ownership.spec.md:237-260`, `490-494`, `565-572`). “Independently scoped and reviewable” would be accurate.

**DANGLING DEPENDENCIES**

| Dependency relied on by 0022 | Actual gap |
| --- | --- |
| Authenticated `.load` | Provenance is attached to evaluation, not the preceding filesystem decision. |
| Session-Root authority closure | No owner hides `Ibex.permissions`/`Ibex.authority` from the real Root global. |
| Raw-bridge sealing | No generated reachability/disposition manifest exists; the registry has unresolved dynamic globals. |
| Out-of-snapshot error | LLP 0024 §2 is not a resolver taxonomy, and LLP 0023’s reason enum lacks this class. |
| Cancellation protocol | LLP 0024 has accepted/unavailable/failed; LLP 0025 additionally needs unresolved/defeated and background targets (`0024:289-299`; `0025:456-494`). |
| Worker/supervisor protocol | No exact serialized schema joins outcomes, display IR, async reports, lifecycle, cancellation, sequencing, and display acknowledgement. |
| Authority-attribute refusal | No sibling owns generated-key validation and parser ordering. |
| Invalid UTF-8 | No component owns strict byte decoding and named refusal. |
| Program lifecycle | No sibling owns quiescence, fatal background events, listeners, and exit-status mapping. |
| REPL command manifest | LLP 0010/runtime-surface has no REPL table schema. |
| Root-import projection | LLP 0014 alone cannot deliver it; canonical schema, snapshot validation, arming, and package binding also require LLP 0021/0023 ownership. |
| Transcript determinism | Exact IR grammar, escaping serialization, limits, and truncation markers remain unspecified. |

5. **Suggestions**

- Keep the behavior-contract scope, but make every cross-layer interface a small normative schema rather than prose passed between siblings.

- Introduce a non-serializable `AuthenticatedSubmission` capability minted only by trusted ingress and bound to snapshot digest, run nonce, Root identity, source identity, mode, and ingress kind. Use it both for source submission and `.load`’s typed read.

- Generate a separate `root-global-dispositions.json`: registry classification answers “what effect is this?” while the disposition manifest answers “is this property sealed, converted, private, or exposed?” Joining those axes is clearer than asking coverage edges to encode reachability implicitly.

- Model-check the interrupt automaton before coding it. A small state-transition model plus generated property tests would likely be cheaper than debugging PTY edge cases after implementation.

- Consider an explicitly authored build-time `replImports`/session-profile projection. That would let operators import useful installed packages without promoting every transitive dependency or allowing prompt text to shape policy.

- Ship v1 with type-tag-only display and no member completion if necessary. Both are honest degraded behavior and materially reduce the amount of engine work needed before the safe core can ship.

- Treat full-Root piped stdin as a deliberate v1 decision, not an undecided one. A future `--stdin-quarantine` or safer-by-default restricted profile can be evaluated independently.

6. **Open questions**

1. Which exact trusted component may mint an authenticated submission, especially for embedders, and how is replay across runtimes prevented?

2. Should the canonical policy’s session import surface be the union of existing Root import sites, an explicit `replImports` set, or a separate build-generated session profile?

3. How are package dynamic-authority facades withheld from session Root while remaining available to packages whose file-execution profile admits them?

4. Is the supervisor process now the decision, or is process-versus-thread genuinely still open? The corpus currently says both.

5. What exact wire schema joins evaluation outcomes, display IR, async failures, lifecycle requests, cancellation, and `$_` acknowledgement?

6. Should piped program source remain full Root by default, or should restricted/quarantined stdin be the safer product default?

7. Which renderer, input, completion, shutdown, history, and async-storm bounds are normative for v1?

8. Must all runtime authority attributes hard-fail, or should a build-authenticated marker distinguish already stripped source from raw prompt/stdin source?

9. Can the generated native-global inventory eliminate every dynamic-table sentinel on all advertised platforms, including symbols and lazy installers?

10. What owns program-mode event-loop quiescence and fatal async-failure semantics, and are they exactly identical to file execution?

7. **Readiness verdict**

The proposal has a strong core and several excellent security defaults, but unresolved contradictions and dangling dependencies affect attribution, evaluator closure, Root authority, interruption, raw bridges, and testability. Those are material correctness and safety issues, not polish.

VERDICT: NOT READY
### Orchestrator verification notes (round 5, outside verbatim body)

**Process finding first, because it conditions every disposition below.** The three sibling specs are being refined by *concurrent* orchestrators, and LLP 0024 (575→1014 lines) and LLP 0025 (506→858 lines) were both revised **while this round's reviewers were reading**. The two reviewers therefore did not see the same corpus: Codex read the **pre-revision** LLP 0024 with the **post-revision** LLP 0025; Fable read both post-revision. Line-number citations confirm this in each direction. Consequences:

- Codex's Blocking **3** ("LLP 0024 reopens evaluators that 0022 closes") is **stale**: the revised LLP 0024 now states "**`eval` and `Function` are closed** in the v1 profile (LLP 0022 §1, LLP 0021) … This document therefore specifies **no** session semantics for direct or indirect `eval`." The contradiction that three rounds chased is *fixed in the sibling*. Recorded as resolved, not as a defect to fix here.
- Codex's Blocking **4** ("value handles cannot cross the supervisor boundary") is **substantially stale**: revised LLP 0024 §6 now defines value handles as "rooted in, and scoped to, the runtime that produced them … **not** a serializable" object, and revised LLP 0025 §3 pins the display IR as the trust boundary with the renderer running in the worker. The two now compose. The residue — 0024 §9's async envelope carrying "the original thrown/rejected value **as a handle**" — is coherent under the same rule.
- Everything else from both reviews was verified against the current tree and, where accepted, fixed.

**Confirmed — three claims that refute what *this document* asserted in round 4.** These are the round's real yield, and all three were things the orchestrator had introduced:

1. **`authority-control-plane` does not fit the ingress.** Its registry predicate is literally `authenticated-authority-check-delegation-revocation-or-evidence-bookkeeping-**without-an-external-effect**` (`capsec/registry/policy-rules.json`, `nonCapabilityRationales`). Submitting operator source runs arbitrary code at root's full authority — the most external effect there is — and the same rationaleId is carried today by JavaScript-reachable rows (`global:Exact.setModuleCapabilities`). Round 4's claim that the split was "a registry data change rather than a vocabulary change" was **wrong**. §1 now mints a new `authenticated-code-ingress` rationale with its own obligations, and additionally requires the registry to **inventory dispatch branches** — because `command:ibex` is the root *parser node*, and the implicit no-file REPL branch (`main.rs:462-465`) has no row at all, which is worse than being classified wrongly.
2. **Empty endowments cannot close `Ibex.permissions`/`Ibex.authority`.** Bootstrap installs both facades on the real root global unconditionally (`src/engine/hermes_runtime.cc:2139` `var Ibex = g.Ibex || (g.Ibex = {})`, through `:2233`), and the shipping armed snapshot *already* gives root `"endowments": []` (`runtime.rs:1768-1778`) without the APIs being absent. Presence is a fact about **global construction**, not about policy. Round 4's "which is the mechanism and not merely the intent" was **false**. §2/§6 now name the **root-global seal** — the same end-of-bootstrap step that already deletes `Exact.setModuleCapabilities` under enforce — as the mechanism that delivers absence, with the empty escalation ceiling retained as defense in depth. AC 7 now asserts `typeof Ibex.permissions === "undefined"` against the sealed global, with a fixture that would fail if the facades were merely present-but-denying.
3. **The bridge inventory cannot be a one-to-one projection of the capsec registry.** The registry admits unresolved `[[dynamic-table:…]]` sentinel surfaces precisely because it cannot always enumerate what is installed, and today's seals are hand-authored arrays. Reachability is a different axis from effect classification. §7 now requires a **generated root-global disposition manifest** (install branch, platform, key/symbol, aliases, phase, private consumer, disposition), joined to the registry and proven set-equal by the live post-bootstrap sweep, and bans unresolved dynamic sentinels for root-reachable globals. Codex also surfaced `__exactGetAllEnv` (`hermes_runtime.cc:1188,1255`), a whole-process-environment enumerator neither the document nor round 4's notes had named; it is now in AC 9.

**Confirmed — sibling contradictions created by the concurrent revisions** (both found by Fable, which read the current corpus):
- Revised **LLP 0024 §4 now asserts `require.main`** ("names the session's main module — which for program stdin is `ibex:stdin` (LLP 0022 §3)") while the registry closes `global:require.main` under `runtime:inspect` and this document keeps it closed. **Not accepted.** The registry governs a security classification, and `require.main` is not an identity string but the main module's live loader-graph node (`parent`, `children`, `exports`, `loaded`, mutable) — which is exactly why the registry closes it alongside `require.cache`. §1 now argues this explicitly and §11 row 12 records the invalid corpus state. **Reported as a sibling defect.**
- Revised **LLP 0024 §4 hard-errors `.load` of `.json`/`.d.ts`/`.mjs`/`.cjs`**, while §8 said `.json` displays the parsed value. **Accepted** — 0024 owns dialect and module kind, and its argument (neither is a program; `.mjs`/`.cjs` are module-kind assertions and `.load` is not a module load) is sound. §8 and AC 11 now match it exactly.
- The `repl:<n>` ordinal: 0024 advances it for a **failed parse** too. **Accepted**; §5 now says "submitted evaluation", including one that fails to parse.

**Confirmed — remaining accepted fixes:** `runtime-surface.json` has only `clapSurface` and no REPL-command section (so §8's manifest is an *obligation*, now rowed, not a fact); LLP 0025 publishes **no keybinding manifest**, so `.help` no longer claims to generate keybindings from one; LLP 0025 §9 **appends history at submission**, so §10's "saves history" at exit was wrong and is removed; 0025's bounds question is **OQ 6**, not OQ 5, and its interrupt criterion is **AC 7** — both ledger citations fixed; LLP 0014's "runnable in every mode" describes the **bundler-strip** path, so §6 now states why raw prompt/stdin source is different (and rows the undefined unbundled-file-execution case); `.load`'s read happens in ambient Rust *before* evaluation, so §7 now routes it through a typed session-effect decision taken **before** the bytes are read, with AC 11 asserting an instrumented ambient read observes no access; program-mode fatal exit is pinned to **1**.

**Accepted — Fable's sound lower bound, which is the best single idea of the round.** Round 5 made an artifact with no root-import row arm with an *empty* root package-import surface. Fable observed that a package with **no incoming package→package edge** in the artifact is *provably* root-imported, because every package in the artifact is entry-reachable and root edges are the only ones the generator drops. That subset can be admitted without ever being wrong, is strictly narrower than the recorded truth, and eliminates the round's largest usability cost. §2 and AC 3 now specify it.

**Accepted — the ledger must be checked, not asserted.** Both reviewers independently observed that §11 drifted within a day of being written. That is the failure it exists to catch, so §11 now carries stable obligation IDs and requires `./ref-check` to verify each row against the owning document — the same generated-table discipline the repo already applies to builtins, paths, and the CLI surface. The ledger was also rebuilt with honest columns (owner / owner states it / implemented / gating criterion), because the old "delivered today" column conflated *contract presence* with *implementation status*, and grew from 12 rows to 23.

**Rejected:** Codex's proposal to "make a process supervisor the v1 architecture" — that is LLP 0025's decision (its §7 now specifies the supervisor and leaves process-vs-thread to its OQ 2), and this contract states the escape invariant as behavior rather than pre-empting its sibling's architecture. Fable's `.graph` command remains deferred to OQ 2 with its parity argument recorded.

**Sibling defects found and reported, not fixed here** (0023/0024/0025 are under concurrent refinement; editing them from this loop would race): LLP 0024 §4's `require.main` assertion (above); LLP 0025 §6's **escape invariant is violated by its own table** — from *editing* + a stuck *background callback*, interrupt 1 falls in the editing row (clears every latch), interrupt 2 latches the callback, and a **third** is required, contradicting "two interrupts end the session" (Codex found this; it is a defect in the sibling's new state machine, not in 0022); LLP 0025 §1's TTY/TTY row routes prompt/banner/editor to *stdout* while its controlling-descriptor rule selects "the first of stderr, stdout that is a TTY" = *stderr*; LLP 0024 §8's "inspection tree" and LLP 0025 §3's "display IR" are two names for what should be one schema (0025 OQ 7 already leans that way); LLP 0014 defines no reserved-key disposition for **unbundled direct file execution**; and LLP 0023 §6 still lists `require.cache` keys as path-bearing observables for a surface the registry closes.

## Round 6 (Run A) — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f55b1-9ffd-73d1-aafe-b456adc5691d` (started 02:38:52; rollout `~/.codex/sessions/2026/07/12/rollout-2026-07-12T02-38-52-019f55b1-….jsonl`)
**Date:** 2026-07-12
**Revision under review:** `7ba464df70a3` (sha256/12 of the document)
**Provenance correction:** this section initially cited session `019f55c2-…`. **That was wrong**, and the error is recorded rather than silently repaired — see the verification notes below. The body reproduced here (236 lines) was produced by session `019f55b1-…`; `019f55c2-…` is a *second, independent* Codex run of the same revision, recorded separately as Run B.
**Sibling corpus seen:** the siblings continued to be revised concurrently during this round. At launch: LLP 0023 `0d55849a9f5e` (545 lines), LLP 0024 `ec485db8d1ef` (1147 lines), LLP 0025 `184a46b3ebb2` (858 lines). This reviewer's citations reach beyond those line counts for LLP 0023 and LLP 0025, so it read still-later revisions of both. Disclosed rather than smoothed over.
**Redacted:** No — the document, the sibling corpus, and the repository were read by the Codex CLI under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, to the concurrent Claude review of the same revision, or to any prior LLP 0022 review artifact — the existing `llp/reviews/0022-*.md` files were moved out of the working tree for the duration of the round and restored afterwards.
**Method:** cli-runner (`codex exec -m gpt-5.6-sol -c 'model_reasoning_effort="ultra"' -s read-only --output-last-message …`), shared round-6 brief (LLP 0005 standard questions + required structure + readiness bar + the sibling corpus as normative context + an explicit instruction to judge §11's ledger rows for accuracy against current sibling text).

### Verbatim review

1. **Overall assessment**

This is a strong security proposal with the right architectural center: authenticated operator ingress should be distinct from JavaScript-reachable evaluation, and REPL behavior deserves a cross-system contract. The synthetic-entry model, immutable authority graph, build-time-only grant channel, Root-plus-provenance attribution, removal of `.env`, generated surface tables, and adversarial acceptance criteria are all good decisions.

The proposal is not ready, however. Several promised guarantees are currently impossible under the described implementation, contradicted by sibling specs, or delegated to owners that do not deliver them. Most importantly, §11’s new dependency ledger is a sound instrument in principle but is neither mechanically checked nor accurate today.

The scope itself is broadly right, but its description is too narrow. This is not merely a behavior contract whose mechanism lives in three siblings: it normatively constrains the capability registry, armed-snapshot schema, LLP 0014’s generator, LLP 0021’s attribution model, LLP 0013’s bootstrap membrane, and LLP 0010’s runtime-surface manifest. It should call itself the REPL behavior-and-security integration contract, or move those mechanisms into their true owners and retain atomic obligation references here.

2. **Strengths**

- The session-ingress/`vm:evaluate` distinction is the correct architecture. Keeping `eval`, `Function`, raw `ex_hermes_eval`, and package-accessible evaluator paths closed while adding a structured authenticated source request addresses the registry’s real contradiction without reopening generic evaluation (§1, `llp/0022-repl-behavior-and-semantics.spec.md:113-179`; `capsec/registry/capability-definitions.json:529-541`).

- The synthetic entry preserves the armed-snapshot trust domain instead of inventing a REPL-only authority system. Piped input cannot add graph nodes, root import edges, or grants (§2, `llp/0022-repl-behavior-and-semantics.spec.md:213-283`). That is consistent with LLP 0014’s build-time grant channel (`llp/0014-import-site-grants-and-generated-policy.spec.md:99-123`).

- The interim “no incoming package→package edge” rule is a sound under-approximation if its stated generator premises hold: every artifact package is entry-reachable and only Root edges are omitted (§2, `llp/0022-repl-behavior-and-semantics.spec.md:240-249`). It is much better than the current widening to every policy principal (`src/bin/ibex/runtime.rs:1763-1776,1807-1811`).

- Hard-erroring authority-bearing attributes is the right default. Silently ignoring an attempted attenuation would run with broader authority than the author expressed (§6, `llp/0022-repl-behavior-and-semantics.spec.md:458-507`). Generating the refusal key set from LLP 0014’s parser is also the right anti-drift design; current Rust recognizes only `needs` and still prints a false grant message (`src/bin/ibex/repl/mod.rs:817-836,1033-1078`).

- Representing operator submission as authenticated Root plus unforgeable provenance, rather than adding an operator principal, is conceptually correct (§7, `llp/0022-repl-behavior-and-semantics.spec.md:551-579`). The current `Principal` algebra has no such principal and does not need one (`crates/capsec-semantics/src/model.rs:302-322`).

- The authorization-before-read requirement for `.load` is exactly the right security property. The document correctly notices that authenticating only the later evaluation is too late (§7, `llp/0022-repl-behavior-and-semantics.spec.md:555-579`).

- A separately generated native-disposition inventory is a good idea. Reachability and capability classification are different dimensions, especially while the registry admits dynamic sentinels (§7, `llp/0022-repl-behavior-and-semantics.spec.md:581-608`).

- Removing `.env` is the right v1 decision. The current command enumerates `std::env::vars()` directly (`src/bin/ibex/repl/mod.rs:966-970`), violating affordance parity.

- The exhaustive `replSurface` proposal and safe-completion policy are strong (§§8–9, `llp/0022-repl-behavior-and-semantics.spec.md:631-704`). Current completion actually evaluates its base expression and invokes reflection that can trap (`src/bin/ibex/repl/mod.rs:283-349`), so the proposed native, trap-free design closes a real problem.

- The acceptance criteria are unusually concrete and adversarial, particularly the negative tests for graph widening, pre-read authorization, bridge reachability, completion traps, and terminal restoration (`llp/0022-repl-behavior-and-semantics.spec.md:796-899`).

3. **Concerns**

1. **Blocking — §11’s dependency ledger is not mechanically checked and is materially inaccurate.**

   **Evidence:** §11 claims every row has a stable obligation ID and that `./ref-check` verifies the join (`llp/0022-repl-behavior-and-semantics.spec.md:746-754`), but the table contains only mutable ordinal numbers (`:756-780`). `ref-check` checks metadata and reference shape and explicitly declines to gate semantic drift (`ref-check:8-17,145-235`).

   Rows 5, 6, 7, 10, 12, 15, 16, 17, 19, and 22 are inaccurate or too compound:

   - LLP 0024 now states submission provenance, out-of-snapshot errors, and the lifecycle outcome (`llp/0024-structured-evaluation-and-session.spec.md:159-161,218-229,496-506`).
   - LLP 0025 defines display acknowledgement at barrier completion (`llp/0025-terminal-session-ownership.spec.md:326-335`).
   - Row 12 says implementation is “n/a,” but `require.cache` and `require.main` remain live globally, on local `require`, and through `__exactRequire` (`src/engine/bootstrap/module-loader.js:5413-5420,5767-5798,5808-5816`).
   - Row 22 points to LLP 0024 OQ6 and LLP 0025 OQ6; the relevant questions are LLP 0024 OQ8 and LLP 0025 OQ7 (`llp/0024-structured-evaluation-and-session.spec.md:1405-1409`; `llp/0025-terminal-session-ownership.spec.md:999-1003`).

   Missing rows include module identity, the environment base, Root builtin admission, broker-event sequence membership, non-evaluation cancellation targets, async-failure lifecycle policy, and invalid-UTF-8 decoding.

   **Resolution criterion:** Replace ordinal rows with atomic, owner-authored IDs. Each fact needs separate `specified`, `implemented`, `verified`, and `blocked-by` states plus owning section and acceptance-test IDs. Generate §11 from those facts and make `ref-check` fail on missing owners, duplicate IDs, stale acceptance joins, and false delivery status.

2. **Blocking — Root-only removal of dynamic-authority APIs is incompatible with the current compartment design.**

   **Evidence:** The contract requires `Ibex.permissions` and `Ibex.authority` to be absent from Root while imported packages retain their file-execution behavior (§§2, 6, `llp/0022-repl-behavior-and-semantics.spec.md:250-262,509-529`). Both APIs live on the single shared `g.Ibex` object (`src/engine/hermes_runtime.cc:2139-2268`). When admitted to a package compartment, the proxy returns the same `g[prop]` object (`src/engine/hermes_runtime.cc:2612-2639`). Deleting properties from `g.Ibex` therefore deletes them for packages too.

   **Resolution criterion:** Either make dynamic authority unavailable session-wide, or specify and implement principal-specific `Ibex` projections: a sanitized Root facade and authenticated package facades with their normal floors and ceilings. Test reachability and behavior separately from Root and from multiple packages.

3. **Blocking — authenticated Root submission has no complete attribution or anti-replay construction.**

   **Evidence:** The contract correctly avoids adding a principal, but a frame-less `.load` still needs a principal-source rule compatible with LLP 0021’s fail-closed attribution (`llp/0022-repl-behavior-and-semantics.spec.md:551-579`; `llp/0021-capsec-effect-model-migration.plan.md:326-363`). `DecisionContext` currently has actor, constrained principals, stage, and presented handles, but no authenticated ingress assertion (`crates/capsec-semantics/src/model.rs:1476-1484`).

   The promised provenance binds a run nonce but defines no per-submission freshness or atomic consumption. Worse, production arming copies the canonical example snapshot without replacing its fixed `runNonce` (`src/bin/ibex/runtime.rs:1889-1892`; `capsec/examples/armed-snapshot.canonical.json:20-21`); the schema validates only its encoding (`capsec/schema/armed-snapshot.schema.json:68-71`).

   **Resolution criterion:** Define an `authenticated-session-root` principal-source adapter in LLP 0021. It should consume a one-shot opaque submission permit bound to a freshly generated per-runtime nonce, snapshot digest, Root identity, ingress kind, source identity, submission ordinal, and preferably source-byte digest. Validate and atomically consume it before any effect. Test duplicate, cross-session, wrong-source, post-rearm, JavaScript-originated, and forged submissions.

4. **Blocking — `.load`’s authorization-before-read guarantee is a dangling dependency.**

   **Evidence:** The target explicitly admits that neither sibling delivers the typed read (`llp/0022-repl-behavior-and-semantics.spec.md:566-579`). LLP 0024 accepts source text and describes how `.load` evaluates already-obtained bytes, but defines no authorized path-to-bytes operation (`llp/0024-structured-evaluation-and-session.spec.md:144-169,419-430`). Current `.load` passes a path directly to `run_file_immediate` (`src/bin/ibex/repl/mod.rs:930-940`).

   **Resolution criterion:** Split this into atomic obligations: LLP 0021 owns authenticated session attribution; LLP 0023 owns the typed virtual-path read and pre-read decision; LLP 0024 accepts only authenticated bytes plus their logical referrer. An instrumented test must prove that denial occurs before any host lookup or byte read.

5. **Blocking — LLP 0023 and LLP 0024 define incompatible module identities.**

   **Evidence:** LLP 0023 keys file modules by `(runtime, defining principal, retained file object)` so hard-linked files owned by different packages cannot collapse compartments (`llp/0023-virtual-filesystem-namespace.spec.md:290-337`). LLP 0024 still says `(runtime, retained object identity)` and explicitly omits the defining principal (`llp/0024-structured-evaluation-and-session.spec.md:980-990`).

   Object-only identity makes first-load order choose the compartment when two package roots contain hard links to the same inode, violating LLP 0013’s compartment boundary.

   **Resolution criterion:** Adopt the tagged LLP 0023 algebra verbatim in LLP 0024, including synthetic, builtin, generated, and file-backed variants. Add cross-package hard-link, Root/package shared-instance, and bundled/raw/bytecode identity fixtures. Add the identity obligation to §11.

6. **Material — the ingress/VM split is directionally right but not yet coherent with registry semantics or coverage.**

   **Evidence:** The registry facts cited in §1 are correct: explicit REPL/eval routes and `ex_hermes_eval` are closed under terminal `vm:evaluate`, while the root parser and `run` use bootstrap-state classifications (`capsec/registry/coverage-edges.json:128356-128494,132827-132834,133067-133074`; `capsec/registry/capability-definitions.json:529-541`).

   However, §1 calls ingress a non-capability while also calling arbitrary Root execution “the most external effect there is” (`llp/0022-repl-behavior-and-semantics.spec.md:143-163`). Existing non-capability predicates describe routes without independent external authority (`capsec/registry/policy-rules.json:719-774`). The migration table also omits numerous separately generated eval parser, option, spelling, and positional rows (`capsec/registry/coverage-edges.json:128247-128314,130937-130964,131557-131584,132207-132224,132337-132354,132627-132664`).

   Current runtime bootstrap and product evaluation also share bare `ex_hermes_eval`; closing it requires the separate trusted Runtime ingress that LLP 0024 now mentions (`llp/0024-structured-evaluation-and-session.spec.md:178-182`; `src/engine/hermes_runtime.cc:2924-2964`).

   **Resolution criterion:** Define whether `authenticated-code-ingress` merely authenticates in-memory submission while all resulting effects are independently mediated, or is itself a host-only capability. Publish a total projection over every CLI eval facet. Add a separately classified, phase-limited Runtime bootstrap ingress that is sealed before project source begins. Keep JS `eval`, `Function`, raw `ex_hermes_eval`, and package evaluator access closed.

7. **Material — the session-manifest and source-request vocabularies are incomplete.**

   **Evidence:** §1 includes `-e`, `-p`, and `ibex eval`, but §2’s closed entry enum contains only `file`, `stdin`, and `repl` and gives no transcript entry identity (`llp/0022-repl-behavior-and-semantics.spec.md:176-179,213-225`). LLP 0024 gives one-shot input the distinct identity `ibex:eval` (`llp/0024-structured-evaluation-and-session.spec.md:193-199`).

   §1 also says the source request carries or derives endowments (`llp/0022-repl-behavior-and-semantics.spec.md:143-175`), while LLP 0024 has no endowment field or normative projection rule (`llp/0024-structured-evaluation-and-session.spec.md:146-169`). Finally, no exact Root builtin set is named for an empty-policy session; current arming admits every `RUNTIME_GATED_NODE_BUILTINS` entry (`src/bin/ibex/runtime.rs:1758-1776`).

   **Resolution criterion:** Define one exhaustive, schema-checked mapping across file execution, prompt, transcript, program stdin, eval, and print. Bind entry kind, source identity, main flag, goal, mode, endowment projection, graph, and Root builtin set with schema conditionals and digest fixtures.

8. **Material — the synthetic-entry proof assumes an authenticated package graph that current arming does not provide.**

   **Evidence:** The lower-bound proof depends on every package node being entry-reachable and on Root edges being the only omitted edges (§2, `llp/0022-repl-behavior-and-semantics.spec.md:240-249`). Current arming promotes every policy principal to Root, emits Root→every-package edges, guesses package roots as `project_root/node_modules/<name>`, silently skips missing roots, and does not verify installed content against the principal integrity (`src/bin/ibex/runtime.rs:1763-1776,1807-1811,1823-1852`). LLP 0023 now requires exact locator/integrity bindings and errors on missing roots (`llp/0023-virtual-filesystem-namespace.spec.md:181-202`).

   **Resolution criterion:** Add atomic LLP 0014 obligations for entry reachability and dropped-edge semantics, tied to the artifact version. Resolve exact locators through an authenticated lockfile graph, verify integrity, bind actual nested/aliased/pnpm roots, and fail on missing or ambiguous packages. Acceptance must cover duplicate package names, nested versions, and extraneous indegree-zero nodes.

9. **Material — the path and source-observable contract is contradictory across 0022 and 0023.**

   **Evidence:**

   - 0022 calls lexical `node:path` operations non-capability operations and includes `path.resolve` in that discussion (`llp/0022-repl-behavior-and-semantics.spec.md:390-395`); 0023 correctly says `path.resolve` and `path.relative` are session-state reads (`llp/0023-virtual-filesystem-namespace.spec.md:736-742`).
   - 0022/0024 set program-stdin `import.meta.url` to `ibex:stdin` (`llp/0022-repl-behavior-and-semantics.spec.md:326-333`; `llp/0024-structured-evaluation-and-session.spec.md:399-405`), while 0023’s generated table unconditionally describes it as a virtual file URL (`llp/0023-virtual-filesystem-namespace.spec.md:694-712`).
   - 0023’s marker-ascent project-root rule is more specific than 0022’s shell-cwd “project candidate” language (`llp/0023-virtual-filesystem-namespace.spec.md:145-179`).
   - 0023 requires an out-of-project-package diagnostic to name the actual out-of-project root (`llp/0023-virtual-filesystem-namespace.spec.md:193-202`), conflicting with 0022’s no-host-path error rule (`llp/0022-repl-behavior-and-semantics.spec.md:390-396`).

   **Resolution criterion:** Make 0022 use 0023’s exact “discovery origin then marker ascent” terminology; classify `resolve`/`relative` as session-state reads without making them containment gates; make the observables table conditional on source kind; and require symbolic out-of-project diagnostics that name the package locator and authenticated boundary, never the host root.

10. **Material — interrupt behavior differs by both bound and topology.**

   **Evidence:** 0022 says two interrupts escape engine work “from any state,” then qualifies this by target and edit-buffer behavior (`llp/0022-repl-behavior-and-semantics.spec.md:720-731`). LLP 0025 says two interrupts against the same running target escape, but the global bound is three when the first interrupt is spent on a non-empty edit buffer (`llp/0025-terminal-session-ownership.spec.md:453-509`). It also gives interactive-without-editor, transcript, program, one-shot, and file modes single-interrupt termination rather than the editor latch machine (`llp/0025-terminal-session-ownership.spec.md:190-205`).

   **Resolution criterion:** State one generated per-mode interrupt table. The invariant should be: two interrupts against the same running work terminate; from any editor state at most three terminate; non-editor modes terminate on one interrupt. Use the same target IDs, latch rules, statuses, and terminal-restoration assertions in both documents.

11. **Material — lifecycle and event-loop consumption remain partly unowned.**

   **Evidence:** 0022 still says LLP 0024 lacks the lifecycle outcome (`llp/0022-repl-behavior-and-semantics.spec.md:733-735`), but LLP 0024 now defines it (`llp/0024-structured-evaluation-and-session.spec.md:496-506`). Conversely, 0022 requires background failures to be fatal in program/file execution and nonfatal interactively (`llp/0022-repl-behavior-and-semantics.spec.md:354-362,434-437`). LLP 0024 delegates fatality to LLP 0025 (`llp/0024-structured-evaluation-and-session.spec.md:1151-1164`), but LLP 0025’s lifecycle section does not provide a mode×async-event policy or exact event-to-exit-code consumption rule (`llp/0025-terminal-session-ownership.spec.md:640-705`).

   Row 6 similarly treats “quiescence” and “ready-work-only” as delivered merely because LLP 0024 names those labels; it does not define the drain algorithm or readiness boundary.

   **Resolution criterion:** Add a normative matrix covering mode × evaluation outcome × async event × drain boundary × exit status. Define quiescence, ready work, background-handle treatment, fatal-event consumption, and lifecycle acknowledgement precisely.

12. **Material — the display wire and sequence domain contradict each other.**

   **Evidence:** LLP 0024 says it owns a semantic tree, LLP 0025 owns a styled display IR, and only that IR crosses the worker boundary (`llp/0024-structured-evaluation-and-session.spec.md:1077-1095`). LLP 0025 says the unstyled tree itself is the versioned serializable cross-worker value and that the session layer derives styling (`llp/0025-terminal-session-ownership.spec.md:251-279`).

   LLP 0024’s sequence allocator covers evaluation outcomes and async failures (`llp/0024-structured-evaluation-and-session.spec.md:1129-1135`); LLP 0025 says broker events share it too (`llp/0025-terminal-session-ownership.spec.md:295-304`). Display acknowledgement is now specified in 0025, but both ledgers still describe it as missing or incomplete.

   **Resolution criterion:** Choose one versioned wire object and one owner. Specify exactly where inspection, truncation, styling, escaping, and serialization occur. Extend the sequence-domain definition to broker events, then generate both ledgers from the same owner facts.

13. **Material — byte-deterministic acceptance criteria depend on unspecified bounds.**

   **Evidence:** Transcript fixtures require pinned renderer grammar and numeric bounds, while completion requires a documented budget (§§3, 9, `llp/0022-repl-behavior-and-semantics.spec.md:335-352,698-704`). AC4 and AC13 already require deterministic bytes and budget-miss behavior (`:829-838,894-897`), yet §11 row 22 admits that the constants remain open. LLP 0024 OQ8 and LLP 0025 OQ7 leave renderer, completion, queue, input, and shutdown bounds undecided (`llp/0024-structured-evaluation-and-session.spec.md:1405-1409`; `llp/0025-terminal-session-ownership.spec.md:999-1003`).

   **Resolution criterion:** Land one versioned constants annex defining renderer grammar, depth, breadth, payload limits, truncation tokens, completion work units, queue bounds, maximum input, and drain budgets. Prefer deterministic work-unit budgets over wall-clock budgets.

14. **Material — the authority-attribute hard-error rule needs a safe grammar and a decision for direct files.**

   **Evidence:** The default is good, but “object literal” is not a sufficiently closed grammar: object literals can contain getters, setters, methods, computed keys, spreads, and executable nested expressions (§6, `llp/0022-repl-behavior-and-semantics.spec.md:492-501`). The section also says “every mode” while explicitly leaving unbundled direct file execution unresolved (`:458-483`).

   **Resolution criterion:** Specify a recursive data-only AST grammar: static keys and plain data properties only, including a similarly constrained nested `with` object; reject getters, methods, spreads, computed keys, and non-data expressions without executing them. Either make unbundled direct files obey the same refusal or explicitly narrow “every mode” to source passing through the shared runtime ingress.

15. **Material — piped-stdin authority is not actually settled.**

   **Evidence:** §2 normatively makes piped source full Root and calls quarantine an open option (`llp/0022-repl-behavior-and-semantics.spec.md:285-293`). OQ6 then says the “honest v1” ships `--stdin-quarantine`, but no flag semantics, principal mapping, manifest row, or acceptance criterion exists (`:952-960`); the current CLI has no such option (`src/bin/ibex/cli.rs:24-173`).

   **Resolution criterion:** Make one explicit v1 decision. If full Root remains the default, either specify the restricted flag completely or remove the claim that it ships. If restriction is the default, require an explicit `--stdin-root` trust act. I recommend shipping a restricted route in v1 even if compatibility keeps Root as the default.

16. **Material — the native-disposition proof and environment guarantee are underspecified.**

   **Evidence:** The manifest is the right idea, but “manifest equals live sweep equals registry” compares different sets: sealed rows belong in the source-derived manifest but must be absent from the post-bootstrap reachable set (§7 and AC9, `llp/0022-repl-behavior-and-semantics.spec.md:587-608,867-875`). The registry also includes dynamic and nested surfaces rather than only direct global installations.

   The statement that reachable `__exactGetEnv` immediately defeats armed `process.env` is also too strong. Those bridges read the host environment only after a legacy capability check (`src/engine/hermes_runtime.cc:1159-1255`), and armed hosts currently fail that check closed (`src/host/mod.rs:1285-1291`). They still must be sealed or converted, but they are not presently an armed bypass. Conversely, the promised empty environment base has no owner or ledger row (`llp/0022-repl-behavior-and-semantics.spec.md:610-620`).

   **Resolution criterion:** Define three explicit projections: native installation sites, permitted post-bootstrap reachable natives, and registry rows joined by stable IDs. Specify finite descriptor-only traversal, symbols, aliases, prototypes, nested namespaces, lazy installers, and native identification without invoking getters. Bind an explicitly empty session environment base plus admitted overlays in the armed snapshot and test that presentation variables never enter it.

17. **Material — the generated command table is sound, but its conformance story is incomplete.**

   **Evidence:** §8 promises manifest ownership of aliases, arity, modes, stream, help, and affordance classification (`llp/0022-repl-behavior-and-semantics.spec.md:642-651`), while AC12 checks mainly recognition, aliases, and help (`:888-893`). `runtime-surface.json` currently has only `clapSurface`, not `replSurface`. The target also says keybindings are omitted until a table exists (`:653-655`), while LLP 0025 says editing bindings come from one manifest (`llp/0025-terminal-session-ownership.spec.md:386-390`).

   **Resolution criterion:** Require a one-to-one manifest-to-handler join and generated positive and negative tests for every alias, arity, mode, stream, and classification. Decide whether keybindings are in v1 help; then make both documents cite the same manifest.

18. **Minor/Non-blocking — several observable command and input edges are not pinned.**

   **Evidence:** Invalid UTF-8 has a program-mode nonzero requirement but no transcript recovery/termination rule (`llp/0022-repl-behavior-and-semantics.spec.md:364-366`). `.load` refusal and JSON behavior, `.time` parse failures, and timing output do not completely specify ordinal advancement, `$_`, clock, units, precision, or TLA duration (`:420-424,658-671`).

   **Resolution criterion:** Add a compact command/outcome matrix covering whether source is submitted, ordinal advancement, `$_`, output stream, recovery, and exit status. Specify `.time`’s clock and stable presentation separately from byte-stable transcript fixtures.

4. **Cross-document findings**

| Kind | Seam | Finding |
| --- | --- | --- |
| **CONTRADICTION** | 0023 ↔ 0024 module cache | 0023 requires defining-principal-tagged identity; 0024 still uses object-only identity (`0023:290-337`; `0024:980-990`). |
| **DANGLING DEPENDENCY** | 0022 → 0021/0023/0024 `.load` | No sibling delivers authenticated frame-less Root attribution plus authorization-before-read (`0022:555-579`; `0024:144-169,419-430`). |
| **CONTRADICTION** | 0022 ↔ 0023 `node:path` | 0022 treats `path.resolve` as pure/no-decision; 0023 classifies it as a session-state read (`0022:390-395`; `0023:736-742`). |
| **CONTRADICTION** | 0022/0024 ↔ 0023 stdin identity | 0022/0024 require `ibex:stdin`; 0023’s `import.meta.url` row is unconditionally file-shaped (`0022:326-333`; `0024:399-405`; `0023:694-712`). |
| **CONTRADICTION** | 0022 ↔ 0023 diagnostic secrecy | 0023 asks to print an out-of-project host root; 0022 forbids host paths in errors (`0023:193-202`; `0022:390-396`). |
| **DANGLING DEPENDENCY** | 0022 → 0024 source context | LLP 0024 carries provenance and principal but does not deliver the promised endowment derivation or validation table (`0022:143-175`; `0024:146-169`). |
| **CONTRADICTION** | 0024 ↔ 0025 display wire | 0024 says styled IR crosses the worker boundary; 0025 says the unstyled tree crosses (`0024:1077-1095`; `0025:251-279`). |
| **DANGLING DEPENDENCY** | 0024 ↔ 0025 sequencing | Broker events and non-evaluation cancellation targets are not incorporated into 0024’s sequence/cancellation vocabulary (`0024:1129-1135`; `0025:295-304,431-470`). |
| **CONTRADICTION** | 0022 ↔ 0025 interrupts | Two-versus-three global bound and editor-versus-no-editor mode topology disagree (`0022:720-731`; `0025:190-205,453-509`). |
| **DANGLING DEPENDENCY** | 0022 → 0024 → 0025 async fatality | 0024 delegates consumer fatality to 0025, but 0025 has no mode×event consumption rule (`0022:354-362`; `0024:1151-1164`; `0025:640-705`). |
| **CONTRADICTION** | 0022 ledger ↔ current siblings | Out-of-snapshot, lifecycle, and display acknowledgement are marked absent after siblings added them (`0022:772-774`; `0024:218-229,496-506`; `0025:326-335`). |
| **DANGLING DEPENDENCY** | 0022 → 0024/0025 bounds | Byte-stable rendering and bounded completion are acceptance gates, but their numeric contract remains open (`0022:779,829-838,894-897`; `0024:1405-1409`; `0025:999-1003`). |
| **DANGLING DEPENDENCY** | 0022 → input/session layer | No owner defines invalid-UTF-8 decoding, transcript recovery, diagnostic form, and exit behavior (`0022:364-366`; `0024:151`; `0025:376-381`). |

5. **Suggestions**

- Turn delegated obligations into owner-authored structured data, then generate every human ledger. Pin the exact claim text or a claim-schema digest so marker presence cannot masquerade as semantic agreement.

- Treat LLPs 0022–0025 as a versioned contract bundle. CI should reject a mixed bundle in which one document changes an exported obligation without updating dependents.

- Model submission as a one-shot `SessionSubmitPermit`, not a reusable evidence bag. It should authenticate Root attribution without becoming a principal or entering any positive-authority stratum.

- Give native host functions stable installation IDs at creation time. Generate a capability “negative-space census” from those tags: source install sites, permitted live reachability, and registry classifications can then be compared without guessing from JavaScript property names.

- Generate one mode algebra rather than maintaining parallel prose tables: input transport × editor ownership × source identity × goal × principal × drain policy × interrupt policy × lifecycle policy. Project the CLI, source request, terminal table, and acceptance fixtures from it.

- Put Root package imports, Root builtins, package graph closure, exact package bindings, and integrity witnesses into a proof-carrying session-manifest section. Do not reconstruct these facts heuristically during arming.

- Stage implementation vertically. A useful first proof slice is transcript mode with an empty package graph, inert display tags, no dynamic Root authority, structured outcomes, and typed stdin. Prove the ingress, attribution, display, and lifecycle seams before adding the interactive editor and rich inspection.

- Add differential fixtures that execute the same source through file, program stdin, transcript, prompt, and one-shot modes and compare every invariant that should be equal: principal, endowments, import graph, builtin set, resolver errors, and closed surfaces.

6. **Open questions**

- Does the registry define a capability only as external-resource authority, allowing authenticated in-memory source submission to be a non-capability, or is possession of the submit seam itself authority?

- What trusted component mints and consumes `SessionSubmitPermit`, and can embedders obtain it without becoming equivalent to the CLI operator?

- Should full-Root piped stdin remain the compatibility default, or should non-TTY source require an explicit `--stdin-root` trust assertion?

- Can dynamic authority be closed only for Root with the existing global/compartment architecture, or should v1 close it session-wide?

- What is the exact Root builtin set for an empty-policy or synthetic-entry session, and where is that set authored?

- Is LLP 0023’s defining-principal-tagged module identity now the canonical answer for raw, bundled, cached, bytecode, builtin, and synthetic modules?

- Which object crosses the worker boundary: semantic inspection tree or styled display IR? Which document owns its version and bounds?

- Which document owns async-event fatality, drain-to-quiescence, and event-to-exit-status mapping?

- What is the intended direct-file behavior when unbundled source still contains authority-bearing attributes?

- Can Hermes implement Script-plus-import-plus-entry-TLA, trap-free inspection, reusable cancellation, and lifecycle unwind on every advertised target, or should the initial advertised target/profile be narrowed?

- Should the native-disposition manifest cover only direct globals, or the entire descriptor-reachable object graph including nested facades and prototypes?

- Is the contract willing to expose a restricted stdin profile in v1, or should every reference to `--stdin-quarantine` be removed until its semantics are specified?

7. **Readiness verdict**

The core architecture is promising, but the false dependency ledger, impossible Root-only facade seal, incomplete authenticated-submission construction, missing `.load` read route, and module-identity contradiction are blocking. Numerous additional cross-spec seams remain materially unresolved.

VERDICT: NOT READY

## Round 6 (Run B) — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f55c2-3a75-75c3-b944-95dc06d4072d` (started 02:57:00; rollout `~/.codex/sessions/2026/07/12/rollout-2026-07-12T02-57-00-019f55c2-….jsonl`)
**Date:** 2026-07-12
**Revision under review:** `7ba464df70a3` (sha256/12 of the document) — the **same revision as Run A**
**Why there are two:** the coordinating (main) session launched a second Codex run on this revision, not knowing the orchestrator had already launched one. Both are genuine, independent, non-interactive `gpt-5.6-sol`/`ultra` reviews of the same text by the same family, and both are recorded in full rather than merged, interleaved, or discarded. Two independent same-family reviews is unusual and is real additional signal; nothing here is a re-run to obtain a different answer.
**Redacted:** No — read under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, to Run A, to the concurrent Claude round-6 review, or to any prior LLP 0022 review artifact (`llp/reviews/` held no 0022 files while it ran — the stash of the five prior rounds held).
**Method:** cli-runner, the orchestrator's shared round-6 brief verbatim, launched from the main session. Provenance (model, effort, session id, rollout) independently verified on disk by the coordinating session against the rollout JSONL and its md5.

### Verbatim review

## 1. **Overall assessment**

This is a strong proposal with the right overall architecture: 0022 fixes observable REPL behavior while delegating filesystem, evaluation, and terminal mechanisms to 0023–0025. The ingress/`vm:evaluate` distinction, synthetic session entry, fail-closed authority syntax, Root-plus-provenance model, `.env` removal, generated bridge inventory, and generated command table are all good decisions.

Round 6 is nevertheless not ready. It contains three blocking security/coherence problems: the authenticated-submission credential is not sufficiently specified and relies on a non-fresh nonce; the promised Root-only dynamic-authority seal is impossible with the current shared `Ibex` object; and 0023/0024 contradict each other about module identity in a way that can collapse package compartments. The `.load` pre-read authorization route is also a blocking dangling dependency.

The behavior-contract scope is appropriate, but the shared ingress rules for `-e`, `-p`, `ibex eval`, file execution, stdin, and the REPL should live normatively in one shared ingress section/spec. Round 6’s “one-shots are out of scope but some REPL rules bind them” formulation leaves security requirements ambiguous.

This assessment is pinned to the requested `7ba464df70a3` round-6 text; 0022 line references below refer to that revision.

## 2. **Strengths**

- **The ingress/VM split is conceptually correct (§1, lines 115–179).** The registry really does classify `command:ibex` as bootstrap state while classifying `command:ibex repl`, `cli:repl`, and `ex_hermes_eval` under `vm:evaluate` ([coverage-edges.json:128357](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128357), [coverage-edges.json:128477](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128477), [coverage-edges.json:132827](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:132827), [coverage-edges.json:133067](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:133067)). Keeping raw or JavaScript-reachable evaluation closed while admitting authenticated operator source is the right distinction.

- **The synthetic-entry session manifest and immutable graph rule are good defaults (§2, lines 213–293).** In particular, piped stdin must not author its own authority graph. The proposed root-import rows fix a real widening: current arming makes every policy principal root-importable and inserts a Root edge to each one ([runtime.rs:1763](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1763), [runtime.rs:1807](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1807)). The interim lower bound is honestly described as conservative.

- **Hard-erroring authority-bearing forms in every unprocessed mode is correct (§6, lines 458–501).** LLP 0014 makes grants build-time declarations and strips them before execution ([0014:97](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:97), [0014:228](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:228)). Ignoring such syntax at runtime would silently provide broader authority than the author requested. Generating the reserved-key set is also the right anti-drift mechanism.

- **Authenticated Root plus provenance is preferable to a new principal (§7, lines 555–564).** The actual principal enum has only Package, Root, Runtime, ModuleLoader, and Quarantine ([model.rs:302](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:302)). Submission provenance is an authentication dimension, not another authority dimension.

- **The proposal correctly identifies unsafe existing behavior.** `.env` enumerates the host environment ([repl/mod.rs:966](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:966)); completion evaluates `Function(...)` and traverses objects/prototypes ([repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)); `.load` performs an ambient filesystem read ([hermes.rs:1145](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1145)); and the REPL prints a capability-granted message before calling a function production arming deletes ([repl/mod.rs:812](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:812), [hermes_runtime.cc:2291](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2291)). The proposed defaults—no `.env`, inert completion, typed `.load`, and no false grant message—are sound.

- **A separate generated root-global disposition inventory is a good idea (§7, lines 581–608).** Reachability and capability classification are different questions. Aliases such as `__exactModuleResolve`/`__exactNativeModuleResolve` demonstrate why source install sites and live reachability must both be checked ([hermes_runtime.cc:1836](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1836)).

- **The exhaustive command/alias table is well chosen (§8, lines 631–680).** Extending LLP 0010’s existing surface manifest is better than inventing an unrelated authority. The current hand-written help already omits accepted aliases ([repl/mod.rs:608](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:608), [repl/mod.rs:920](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:920)).

- **The delegated-obligations ledger is the right instrument in principle (§11).** A behavior contract should expose rather than conceal missing sibling guarantees. Its failure in round 6 is in execution and accuracy, not in the underlying idea.

## 3. **Concerns**

1. **Severity: Blocking — 0023 and 0024 define incompatible module-cache identities.**

   **Evidence:** 0022 assumes one coherent module cache in §6 (`0022:443`). LLP 0023 keys file modules by `(runtime, defining principal, retained file object)` so two packages sharing a hard-linked inode remain separate ([0023:311](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:311), [0023:325](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:325)). LLP 0024 instead says identity is `(runtime, retained object identity)` and that one file is one instance regardless of principal (`0024:980–990`). Its citation to “0023 AC11” is also wrong; the relevant tests are AC16/17 ([0023:998](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:998)). The 0024 rule can collapse two package compartments through a shared inode, violating LLP 0013.

   **Resolution criterion:** Make 0024 import 0023’s complete tagged identity algebra without restating a reduced tuple. Preserve one instance only when the defining principal also matches, correct the AC references, add a §11 obligation, and test both root/package access to one package file and cross-package hard links.

2. **Severity: Blocking — the submission credential and replay defense do not yet support the security claims.**

   **Evidence:** Sections 1 and 7 require derived attribution, endowments, session binding, nonce binding, and replay rejection (`0022:143–175`, `0022:555–579`). LLP 0024’s request lists a session handle and provenance, but provenance binds only snapshot digest, run nonce, root identity, source identity, and ingress kind; it does not bind source bytes, goal, role, referrer, dialect, execution mode, or endowment projection, and the request has no authenticated endowment field ([0024:146](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:146)). Neither `EffectOccurrence` nor `DecisionContext` can carry a submission credential ([model.rs:1421](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1421), [model.rs:1476](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1476)); `DecisionEvidence` is output, not authenticated input ([decision.rs:300](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:300)).

   Production arming copies a canonical example snapshot and never replaces its `runNonce` ([runtime.rs:1889](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1889)); that fixture contains a fixed nonce ([armed-snapshot.canonical.json:20](/Users/ccheever/projects/ibex/capsec/examples/armed-snapshot.canonical.json:20)). Recomputing the digest afterward does not make the nonce fresh ([runtime.rs:1953](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1953)).

   **Resolution criterion:** Define an authenticated, non-JavaScript-reachable submission envelope whose security-relevant fields are derived or cryptographically bound, including a source digest, snapshot and per-runtime nonce, submission ordinal, principal, endowment-set digest, identity, goal, role, referrer, dialect/kind, and execution mode. Generate a cryptographically fresh nonce before snapshot digesting, validate and atomically consume each credential once, record its identifier in output evidence, and test within-session and cross-session replay.

3. **Severity: Blocking — the Root-only dynamic-authority seal promised in round 6 is not implementable with the current compartment membrane.**

   **Evidence:** Round 6 requires `Ibex.permissions` and `Ibex.authority` to be absent from Root while packages imported at the prompt retain file-execution parity (`0022 §6:509–529`). Both facades are installed on the single real-global `g.Ibex` object ([hermes_runtime.cc:2139](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2139), [hermes_runtime.cc:2214](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2214)). Package compartments classify `Ibex` as endowment-controlled but, when admitted, return the same `g[prop]` object ([hermes_runtime.cc:2581](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2581), [hermes_runtime.cc:2612](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2612)). Deleting members from Root therefore deletes them for every package.

   **Resolution criterion:** Either specify per-principal `Ibex` projections—a sanitized Root facade and authenticated package facades—or seal the facades session-wide and explicitly accept the package-parity divergence. Add a paired fixture proving the selected behavior for Root and an ordinarily endowed imported package.

4. **Severity: Material — the proposed registry classification has no typed carrier for its security obligations.**

   **Evidence:** The ingress/VM distinction in §1 is coherent, and `vm:evaluate` is correctly deny-only, terminal, `staticOnly`, and tier 4 for unattributed code ([capability-definitions.json:529](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:529)). But a non-capability edge can carry only an ID, surface, rationale ID, and rationale text ([coverage-edge.schema.json:313](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:313)). Target cells contain opaque fixture IDs ([target-cell.schema.json:17](/Users/ccheever/projects/ibex/capsec/schema/target-cell.schema.json:17)), and a new rationale receives only a generic `.non-capability` fixture unless special-cased ([capsec-fixture-obligations.mjs:57](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/capsec-fixture-obligations.mjs:57)). None of §1’s session-binding, derived-Root, wrong-session, replay, JavaScript-origin, goal, or endowment obligations would be generated.

   The relevant current target cells are merely `unsupported`, including REPL, raw eval, and `Exact.inspect` ([target-cells.json:49561](/Users/ccheever/projects/ibex/capsec/registry/target-cells.json:49561), [target-cells.json:57356](/Users/ccheever/projects/ibex/capsec/registry/target-cells.json:57356), [target-cells.json:83771](/Users/ccheever/projects/ibex/capsec/registry/target-cells.json:83771)).

   **Resolution criterion:** Add either a first-class typed `authenticated-ingress` edge/classification or a checked obligations dataset keyed to ingress edges. Generate exact fixtures for every authentication property and inventory actual dispatch branches—not just Clap parser nodes—for implicit TTY REPL, non-TTY stdin, transcript REPL, file execution, `ibex eval`, `-e`, and `-p`.

5. **Severity: Material — one-shot execution is internally inconsistent with the closed session-entry vocabulary and incompletely scoped.**

   **Evidence:** The Scope binds one-shots to the same ingress (`0022:100–105`), but §2’s closed entry vocabulary contains only `file`, `stdin`, and `repl` (`0022:221–225`), even though 0024 assigns one-shots the identity `ibex:eval`. The current armed-snapshot schema has no entry field and forbids extra properties ([armed-snapshot.schema.json:6](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:6), [armed-snapshot.schema.json:180](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:180)). One-shots currently arm through `eval_code` but receive generic `"<eval>"` identity ([main.rs:337](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:337), [hermes.rs:1515](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1515)).

   “Every mode” in §6 (`0022:458`) refers naturally to §3’s three REPL modes, while one-shots are declared outside scope. LLP 0024 does separately bind the authority-syntax refusal to one-shots ([0024:184](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:184)), but 0022’s scope and acceptance criteria should not make that security inheritance implicit.

   **Resolution criterion:** Add an `eval`/`oneshot` synthetic-entry kind and canonical identity; explicitly state which shared-ingress requirements bind file, stdin, REPL, and one-shot execution; and add fixtures for `-e`, `-p`, and `ibex eval`, including reserved authority keys. Authenticate or validate the reachability premise before using “no incoming package edge” as the interim root-import proof, with an orphan-principal negative fixture.

6. **Severity: Blocking — `.load`’s pre-read authorization route is a dangling dependency assigned to the wrong owner.**

   **Evidence:** Section 7 correctly requires the typed decision before bytes are disclosed (`0022:566–579`) and row 10 assigns the route to 0024 §1 plus 0021 evidence (`0022:767`). LLP 0024 §1 defines an evaluation request, not a filesystem-effect route ([0024:144](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:144)). LLP 0023 defines typed VFS behavior generally but no credential-verifying operator-submission read that returns authenticated bytes and a logical referrer. Current `.load` calls `run_file_immediate` ([repl/mod.rs:930](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930)), which performs `tokio::fs::read` before any typed decision and uses the host path as the source name ([hermes.rs:1145](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:1145)).

   **Resolution criterion:** Assign the effect route to 0023 plus the 0021 decision/evidence model, or to an explicit ingress-effect owner. Specify credential validation, virtual-path resolution, pre-read decision ordering, TOCTOU/object-identity handling, atomic credential consumption, authenticated-byte and logical-referrer output, and how 0024 consumes that result without reopening the file.

7. **Severity: Material — §11’s ledger is sound in concept but neither mechanically checked nor accurate.**

   **Evidence:** Section 11 claims stable obligation IDs and a `./ref-check` owner join (`0022:746–754`), but the table uses ordinal rows 1–23 and no owner-authored markers. `ref-check` documents only reference, metadata, numbering, and `[inferred]` checks and explicitly declines drift checking ([ref-check:8](/Users/ccheever/projects/ibex/ref-check:8), [ref-check:145](/Users/ccheever/projects/ibex/ref-check:145), [ref-check:187](/Users/ccheever/projects/ibex/ref-check:187)).

   The rows are already materially stale or inaccurate:

   - Row 5 overstates authenticated endowment delivery by 0024.
   - Row 7 marks a broad 0024 dependency delivered despite unresolved broker-sequence and target-ID seams.
   - Row 10 says provenance is absent, although 0024 now states it; the `.load` read half remains genuinely absent.
   - Row 12 marks implementation `n/a`, although live `require.cache` and `require.main` are exposed ([module-loader.js:5757](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5757)).
   - Row 15 says the out-of-snapshot taxonomy is missing, but 0024 and 0023 define it ([0024:218](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:218), [0023:845](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:845)).
   - Row 16 says the lifecycle outcome is missing, but 0024 defines it ([0024:496](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:496)).
   - Row 17 says display acknowledgement is absent, but 0024 requires it and 0025 defines barrier-completion acknowledgement ([0025:330](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:330)).
   - Row 19 should be “partly delivered”: 0025 requires a generated keybinding manifest, but its exhaustive content is not yet published.
   - Row 22 cites the wrong open-question numbers; the renderer-bounds questions are 0024 OQ8 and 0025 OQ7.

   Rows 1–4 and 6 appear substantively accurate. The problem is not that every row is wrong; it is that the claimed instrument cannot detect the wrong ones.

   **Resolution criterion:** Give every obligation a semantic ID authored in the owning LLP, generate the ledger from those markers, distinguish “owner acknowledges,” “fully specified,” and “implemented/tested,” and extend `ref-check` to reject duplicate IDs, missing owners, stale anchors, inconsistent statuses, and missing acceptance criteria. Add a regression fixture proving a sibling-status change breaks the join.

8. **Severity: Material — the safe-display and renderer boundary is contradictory and under-specified.**

   **Evidence:** LLP 0024 says it emits a semantic inspection tree and that 0025 owns a separate versioned display IR with trusted style/layout tokens ([0024:1077](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1077)). LLP 0025 says the renderer directly consumes the versioned tree, that the tree carries no styling, and explicitly rejects a second style-bearing display IR ([0025:262](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:262)). The exact renderer grammar, limits, escaping spelling, and truncation constants remain open, while 0022 AC4 requires byte-exact transcripts (`0022:829–838`).

   There is also a smaller dangling dependency: 0022 requires a named invalid-UTF-8 refusal (`0022:364–366`); 0024 merely requires UTF-8 source, and 0025 only says malformed bytes must not crash ([0025:388](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:388)). Finally, current display updates `$_` before calling JavaScript-visible `Exact.inspect`/`String`, so a failed display can still replace it ([repl/mod.rs:63](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63)).

   **Resolution criterion:** Choose one wire boundary. Prefer a versioned, style-free semantic tree produced beside the value and rendered by 0025, with styling derived solely from trusted node kinds. Pin serialization, hostile-input behavior, invalid-UTF-8 refusal, escaping, bounds, and truncation in one constants annex. Add a fixture proving display failure does not update `$_`.

9. **Severity: Material — interrupt, sequencing, and cancellation contracts do not join.**

   **Evidence:** Section 10 says two interrupts end a session from any state containing non-returning engine work (`0022:720–724`), then partially narrows that to the same target (`0022:725–731`). LLP 0025 says two interrupts suffice only against the same running-work target; an editing-plus-background-work state may require three ([0025:440](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:440), [0025:500](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:500)).

   LLP 0024’s allocator covers evaluation outcomes and async failures ([0024:1129](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1129)); 0025 adds broker events to the same sequence domain ([0025:303](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:303)). LLP 0025 also requires monotonic target IDs and completion-query cancellation, while 0024’s cancellation ABI has no target ID or completion-query outcome ([0025:428](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:428), [0024:592](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:592)).

   **Resolution criterion:** State the exact invariant as “two interrupts against the same running-work class; at most three from any reachable state.” Define the sequence allocator’s owner across worker outcomes, raw program bytes, broker events, barriers, and async reports. Extend 0024’s cancellation request with target kind/id, native begin/end publication, completion-query support, and stale-ID rejection.

10. **Severity: Material — raw-bridge and closed-inspection conformance is not yet executable as specified.**

   **Evidence:** The inventory idea in §7 is good, but round 6 does not define canonical installation IDs, join cardinality for aliases, lazy/platform installs, or precisely which nested native values the live sweep must traverse (`0022:581–608`). The current surface includes direct termination through `__exactExit` ([hermes_runtime.cc:1704](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1704)), host-path disclosure from `__exactRealpath` ([hermes_runtime_fs.cc:2551](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551)), and resolver payloads containing host `path`, `pkgRoot`, and source bytes ([abi.rs:2165](/Users/ccheever/projects/ibex/src/host/abi.rs:2165)).

   Round 6 also overstates the current environment bridge as a live armed bypass: `__exactGetEnv` and `__exactGetAllEnv` consult the legacy capability check before reading/enumerating the host environment ([hermes_runtime.cc:1159](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1159)). That remains a fragile dependency worth sealing, but the factual description should distinguish “currently fails closed through legacy machinery” from “live bypass.”

   `Exact.inspect`, `require.cache`, and `require.main` are registry-closed under `runtime:inspect` ([coverage-edges.json:196853](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:196853), [coverage-edges.json:222919](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222919)), yet the current REPL calls `Exact.inspect` and the loader exposes the live cache/main node. Section 11 row 12 therefore cannot say implementation is `n/a`.

   **Resolution criterion:** Define canonical install-site IDs, alias and many-to-one projection rules, phase/platform handling, traversal roots and boundaries, and two-way assertions among install sites, permitted post-bootstrap reachability, and registry survivors. Generate the inventory from a common native-registration primitive where possible. Add explicit closure rows and live fixtures for `Exact.inspect`, `require.cache`, `require.main`, `process.mainModule`, `__exactExit`, resolver aliases, environment bridges, and host-path-bearing filesystem bridges.

11. **Severity: Minor/Non-blocking — the generated command surface needs a closed schema before its exhaustiveness claim is testable.**

   **Evidence:** Reusing `runtime-surface.json` is sound (§8, lines 642–651), but that artifact currently defines only `clapSurface`; LLP 0010’s exact join covers Clap commands/options, not REPL commands ([0010:43](/Users/ccheever/projects/ibex/llp/0010-ibex-binary-ownership.decision.md:43)). The current help/dispatcher alias drift proves the need.

   **Resolution criterion:** Define `replSurface` with a closed affordance-class vocabulary and exact fields for aliases, arity, modes, streams, effects, help, and completion. Require manifest↔dispatcher↔help↔completion equality and a typed-effect/registry join for effectful commands.

## 4. **Cross-document findings**

| Seam | Finding | Assessment |
| --- | --- | --- |
| Module cache | **CONTRADICTION:** 0023 keys file identity by defining principal plus retained object; 0024 drops the principal. | Blocking; can collapse package compartments. |
| Display boundary | **CONTRADICTION:** 0024 delegates a separate style-bearing display IR to 0025; 0025 rejects that IR and renders the style-free tree directly. | Material security/trust-boundary conflict. |
| Interrupt bound | **CONTRADICTION:** 0022 says two interrupts from any state with running work; 0025 requires up to three from editing plus background work. | Material observable-behavior conflict. |
| Authenticated source request | **DANGLING DEPENDENCY:** 0024 has a session handle and partial provenance, but no authenticated endowment projection or binding of all security-relevant request fields. | Blocking as part of the replay/forgery claim. |
| `.load` read | **DANGLING DEPENDENCY:** no sibling owns the credential-verifying, pre-disclosure typed filesystem read. | Blocking. |
| Sequence and cancellation | **DANGLING DEPENDENCY:** broker events, allocator ownership, target IDs, native work boundaries, and completion-query cancellation are not jointly specified. | Material. |
| Renderer constants | **DANGLING DEPENDENCY:** neither 0024 nor 0025 pins the grammar and bounds needed by 0022’s byte fixtures. | Material testability gap. |
| Invalid UTF-8 | **DANGLING DEPENDENCY:** 0022 requires a named refusal; siblings require only UTF-8 input/no crash. | Material completeness gap. |
| Keybindings | **PARTIAL DEPENDENCY:** 0025 requires a generated manifest, but no exhaustive binding content exists yet. | Non-blocking design gap; blocks conformance. |
| Out-of-snapshot, lifecycle, display ack | **LEDGER FALSE NEGATIVES:** the siblings now state these guarantees, contrary to 0022 rows 15–17. | Demonstrates that §11 is not mechanically joined. |

## 5. **Suggestions**

- Move the shared source-ingress contract into 0024 §1 or a dedicated shared ingress spec. Let 0022 specify only REPL-specific identities, modes, and behavior while importing the same authenticated ingress for file, stdin, eval, and REPL.

- Represent operator submission as an **affine authentication ticket**: unforgeable, session-bound, monotonically numbered, and consumable exactly once. It remains neither a principal nor authority, but the type system makes accidental reuse difficult.

- Generate conformance as a differential matrix: submit equivalent source through file execution, program stdin, transcript, interactive REPL, `-e`, `-p`, and `ibex eval`; assert identical attribution, resolver, module-cache, and effect decisions, with only documented source-goal and presentation differences.

- Route all native global installation through one registration helper that emits the disposition record and installs the value. That is more reliable than trying to rediscover dynamically assembled install sites with a source parser.

- Generate the §11 ledger from owner-authored obligation records and display three independent states: acknowledged, normatively complete, and implemented with passing evidence.

- Consider shipping piped stdin under an explicit quarantine profile, or at least offering `--stdin-quarantine` in v1. Full Root is compatible, but stdin is commonly supplied by less-trusted automation; a first-class constrained mode could be valuable without changing the default immediately.

- Add property/model tests for the interrupt state machine, graph lower-bound proof, renderer escaping, source-request field binding, and ledger joins. These are better suited to exhaustive generation than example-only tests.

## 6. **Open questions**

1. Should `authenticated-code-ingress` remain a specialized non-capability rationale, or should the registry gain a first-class authenticated-ingress classification with its own schema and fixture derivation?

2. Which component mints, stores, validates, and consumes the submission ticket, and exactly which source-request fields must it authenticate?

3. Is the v1 dynamic-authority choice Root-only absence with new per-principal facades, or session-wide absence with an explicit package-parity exception?

4. Does 0023 own `.load`’s authenticated read completely, including TOCTOU/object identity, or is a separate session-effect owner needed?

5. Which module-identity algebra is authoritative, and how will raw, bundled, cached, bytecode, hard-linked, and synthetic modules prove they use it consistently?

6. What component owns the cross-process sequence allocator, and how do raw stdout/stderr byte cutoffs join evaluation outcomes, broker events, and display acknowledgements?

7. What exact renderer grammar, bounds, replacement policy, and truncation marker define byte-stable transcript output?

8. How is a project’s committed session policy chosen when LLP 0014 artifacts are entry-scoped but a REPL has no build-time entry? When can the conservative root-import fallback be retired?

9. What is the precise traversal universe for the root-global disposition sweep—prototypes, symbols, nested facades, lazy installs, platform branches, and mutable objects—and how are canonical install IDs assigned?

10. Should program-mode stdin remain ambient Root by default, or should quarantine be the eventual secure default once compatibility evidence exists?

## 7. **Readiness verdict**

The proposal is directionally excellent, but round 6 has unresolved blocking security and cross-spec coherence failures, plus material gaps in the dependency ledger and acceptance machinery.

VERDICT: NOT READY

### Orchestrator verification notes (round 6, outside verbatim body)

**Provenance incident and correction — recorded, not repaired quietly.** Round 6 was reviewed **twice** by the GPT family, and this section originally attributed Run A's body to Run B's session id. The record now shows both the error and its correction, because a review artifact that hides its own defects is worth nothing.

What happened: the orchestrator launched a Codex run (session `019f55b1-…`, 02:38:52) and, separately and unaware of it, the coordinating main session launched a second one (session `019f55c2-…`, 02:57:00). Both runners wrote their logs to the *same path* (`doc-0022/codex-r6.log`); the second clobbered the first. The orchestrator then lifted the session id from what it reasonably believed was its own log and recorded `019f55c2-…` against the 236-line body that `019f55b1-…` had actually produced.

How it was caught: the coordinating session extracted the true final assistant message from each rollout JSONL and hashed it — Run A's body is 236 lines (md5 `d29294be…`), Run B's is 182 lines (md5 `3392d791…`), and the two do not contain one another (different opening paragraphs, different concern ordering). The mis-attribution was therefore provable, not arguable. **No review was fabricated, and no body was altered** — but a real body was attributed to a session that did not generate it, which is exactly the class of error LLP 0005's honesty rules exist to prevent.

Disposition: **both runs are recorded in full**, each against its own verified session id and rollout, rather than one being discarded or the two merged. They are genuinely independent same-family reviews of the same revision at the same model and effort, which is unusual and is real additional signal — and neither is a re-run to obtain a friendlier answer. Run A's id is corrected in place with the error noted. Going forward the orchestrator writes its Codex logs to a `self-*` prefixed path so a concurrent launch cannot collide again.

Run B's substantive findings are dispositioned alongside Run A's below; where they overlap (the impossible root-only seal, the fixed `runNonce`, the overstated env-bridge claim, the stale ledger rows) they were reached **independently**, which strengthens rather than duplicates the evidence. Run B additionally contributed four findings Run A did not, all verified and all carried into the round-8 revision: the registry cannot actually *express* §1's ingress obligations (a non-capability edge carries only `{id, surface, rationaleId, rationale}`, and a new rationale yields only a generic `.non-capability` fixture), so the obligations must live in target-cell fixtures or a checked dataset; `DecisionEvidence` is an **output** type and therefore cannot carry an authenticated submission credential, which needs an input-side carrier; the interim lower bound needs an **orphan-principal negative fixture**, since a non-entry-reachable orphan in the artifact would otherwise be admitted as "provably root-imported"; and the shipping REPL assigns `globalThis.$_ = _val` **before** calling `Exact.inspect` (`src/bin/ibex/repl/mod.rs:63-79`), so a failed display *does* replace `$_` today — a live contradiction of this document's "last **successfully displayed** value" rule, now gated by a fixture.

Both families returned NOT READY on `7ba464df70a3`. The round's yield was unusually sharp: **three code-verified findings that refuted mechanisms this document asserted**, one of which is a live security defect in the shipping code. Every decisive claim below was checked against the tree.

**Confirmed — the root-only seal is not implementable, so v1 closes dynamic authority session-wide.** Both families found this independently (Fable C3: "no owner"; Codex Blocking 2: "impossible"). Codex identified the mechanism: a package compartment's global is a `Proxy` whose `get` trap ends in `return g[prop]` (`src/engine/hermes_runtime.cc:2628-2639`) — it hands back the *same* object from the shared real global. `Ibex.permissions` and `Ibex.authority` hang off one shared `g.Ibex` (`:2139`, `:2153`, `:2214`). Deleting them at the seal therefore deletes them for **every** principal; a root-only seal cannot be expressed over this membrane. Round 6's §6 promised exactly that, so it promised something impossible. **Accepted, and the design changed rather than the prose:** §6 now seals them **session-wide** in v1, states plainly that this is the one place package code at the prompt does *not* behave as it does under `ibex run`, and records per-principal `Ibex` projections (`OBL-IBEX-PROJECTION`, owner LLP 0013) as the path back to parity. Failing closed and saying so beats a parity promise the membrane cannot keep.

**Confirmed — the `runNonce` is a hardcoded constant: replay protection is currently vacuous.** `build_default_armed_host` loads `capsec/examples/armed-snapshot.canonical.json` and overrides `workflow`, `effectiveMode`, `policyDigest`, and `engine` — but never `runNonce` (`src/bin/ibex/runtime.rs:1889-1900`), and the example's value is the fixed test vector `"AQIDBAUGBwgJCgsMDQ4PEA"` (base64 of `01 02 … 10`). **Every armed production session therefore shares one run nonce**, so a submission permit bound to it would replay across sessions by construction. §7 now requires a freshly generated per-runtime nonce and a schema that demands freshness rather than validating the encoding, and `OBL-FRESH-NONCE` is the only ledger row marked a **live defect**. This is a code bug worth fixing independently of this document, and it is reported to the human.

**Confirmed — and this document was overstating a hazard.** Round 6's §7 said `__exactGetEnv`/`__exactGetAllEnv` "return and enumerate the host environment, so `process.env`'s armed classification means nothing while they are reachable." Codex refuted it: both bridges consult the legacy oracle first (`hermes_runtime.cc:1171-1172`), and `Host::check_capability` returns `false` unconditionally whenever a typed decision context exists (`src/host/mod.rs:1286-1290`) — i.e. under an armed host they already fail closed. They are **not** a live bypass today. **Accepted and walked back.** §7 now says exactly that, and keeps the sealing requirement on the honest ground: a guarantee that holds only while a *legacy oracle* keeps refusing is a coincidence with a shelf life, not a guarantee. Overstating a hazard is its own kind of dishonesty, and the disposition notes should say so as plainly as the document now does.

**Confirmed — "object literal" is not a closed grammar (Codex Material 14).** An object literal may carry getters, setters, methods, computed keys, spreads, and nested executable expressions, so `import(spec, { with: { get authorities() { … } } })` satisfies round 6's rule while still running user code *inside the security check*. **Accepted:** §6 now admits only a **recursively data-only** literal — static keys; literal or nested data-only values; no getters, setters, methods, computed keys, spreads, or non-literal expressions at any depth — which is close to what the language already demands of static import attributes, and AC 7 gains a fixture per rejected form.

**Confirmed — the ingress rhetoric contradicted the classification (Codex Material 6).** Round 6 argued the ingress is a non-capability while simultaneously calling it "the most external effect there is." Both cannot hold. **Accepted:** §1 now states *why* it is a non-capability — the ingress performs no external effect of its own; it submits **attributed** source, and every effect that source attempts is independently mediated at its own decision site — which is precisely the property `eval` lacks, and gives the new `authenticated-code-ingress` rationale a predicate. Also accepted: the projection must be **total**, because the registry classifies the same `-e` flag two ways (`option:ibex:eval_code` is `non-capability`; `argument-parser:ibex:eval_code:utf8-string` is `closed`/`vm:evaluate` — Fable found this), and the rationale must **partition** with `runtime-bootstrap-state` or the §1 critique recurs one door down at `ibex run`. File execution is the same act with a file identity, so it takes the same rationale.

**Confirmed — the sound lower bound was oversold (Fable C4).** Round 6 claimed it "keeps the common case working." It does not: a package that root imports **and** another package also imports — every shared `lodash`-class dependency — has an incoming edge and is refused despite being genuinely root-imported. Worse, the prescribed remedy ("regenerate policy") is a **no-op** until LLP 0014 emits the root-import row, so the diagnostic named a remedy that cannot work — the exact false-reassurance failure §6 condemns, committed by §2. **Accepted:** §2 now states the incompleteness plainly, states the two premises the proof rests on as LLP 0014 obligations, and splits the refusal into two distinct diagnostics — out-of-snapshot (remedy: regenerate + restart) versus the **interim** class (remedy: the generator upgrade). AC 3 tests both.

**Confirmed — ledger rows stale again, in the *favorable* direction.** The siblings have converged on this contract's asks: LLP 0024 now carries the out-of-snapshot taxonomy (§2), the fifth **lifecycle** outcome (§6), and the **submission provenance** field (§1, verbatim to §7's binding list); LLP 0025 now carries the display-acknowledgement lane (§3) and a **keybinding manifest** (§5). Five rows and two normative sentences said otherwise. **Accepted:** the rows are refreshed, §10's stale "0024 does not carry it today" is gone, `.help` now generates keybindings, and the old OQ 7 (which enum owns out-of-snapshot) is answered and retired. Citations corrected to LLP 0024 OQ 8 / LLP 0025 OQ 7. `OBL-LOADER-CLOSED`'s implementation cell is corrected to **no** — Codex is right that `require.cache`/`require.main` remain live on the global and through `__exactRequire`.

**Accepted — the ledger becomes owner-authored data.** Both families independently concluded that a hand-maintained ledger cannot do this job; it has now gone stale twice in a day. §11 is rebuilt on **stable IDs** (`OBL-…`, not ordinals, which renumber on insertion), specified as one machine-readable file that owning documents mark and `./ref-check` verifies, from which this table and LLP 0025's equivalent are generated. `OBL-LEDGER-CHECK` rows the tooling obligation itself — the ledger of dangling dependencies had been quietly omitting its own.

**Rejected / not adopted:**
- Codex's framing of the ledger, the `.load` read, and the module-identity contradiction as **Blocking on this document**. Each is real and each is rowed, but two are obligations on *siblings* (`OBL-TYPED-READ`, `OBL-MODULE-IDENTITY`) and one is tooling (`OBL-LEDGER-CHECK`). A behavior contract is blocked by failing to *name* an obligation, not by its owner not yet having discharged it — that is what the ledger is for, and pretending otherwise would make every contract in a four-document corpus permanently unready.
- Codex's proposal to rename the document a "behavior-and-security integration contract." The scope note already says it constrains the registry and the siblings; a longer title adds nothing.
- Codex's recommendation to *ship* a restricted stdin route in v1: §2 now **decides** full Root (with the Node-parity argument), and OQ 6 records both families' recommendation to add a Quarantine-principal route. This document will not claim a flag it has not designed — which is precisely the criticism Codex made of round 6's `--stdin-quarantine` parenthetical, applied consistently.

**Sibling defects found and reported, not fixed here:** LLP 0023 ↔ LLP 0024 **module identity** disagree — 0023 now keys on `(runtime, defining principal, retained object)` while 0024 still keys on `(runtime, retained object)`, so two package roots hard-linking one inode would let first-load order pick the compartment, violating LLP 0013's boundary (`OBL-MODULE-IDENTITY`). LLP 0024 ↔ LLP 0025 **display wire** disagree — 0024 says the styled IR crosses the worker boundary; 0025 says the unstyled tree does (`OBL-DISPLAY-WIRE`). LLP 0024's **AC 5 contradicts its own §4 table** on `.load` of `.json` (§4 says parse-and-display; AC 5 says hard error). LLP 0025 §6's **escape invariant is violated by its own table** (editing + stuck background callback needs three interrupts, not two) — 0025 has since restated the bound as "at most three," which this document now tracks. LLP 0023's observables table describes `import.meta.url` unconditionally as a virtual file URL, contradicting `ibex:stdin`. LLP 0025 owns no **mode × async-event fatality** rule though LLP 0024 delegates fatality to it (`OBL-ASYNC-FATALITY`). LLP 0014 defines no reserved-key disposition for **unbundled direct file execution** (`OBL-FILE-GRANTS`).

## Round 7 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f55ce-e1e6-76e2-b3e8-9b74b94084f1`
**Date:** 2026-07-12
**Revision under review:** `71cc16796e2f` (sha256/12 of the document)
**Sibling corpus seen:** LLP 0023 `18741ecdbd7f`→later, LLP 0024 `3071f3c6d074`→`b0ff4ea3247e`, LLP 0025 `43ff879a257a` — all three remained under concurrent revision during the round.
**Redacted:** No — read under the user's OpenAI account, as authorized by the human invocation of /llp-super-refine.
**Independence:** Fresh non-interactive session; no access to the orchestrating session, to the concurrent Claude round-7 review, or to any prior LLP 0022 review artifact (the six prior rounds were stashed out of `llp/reviews/` for the duration and restored afterwards).
**Method:** cli-runner, shared round-7 brief. Log written to a self-prefixed path after a round-6 filename collision with a concurrently-launched run (see the round-6 notes).

### Verbatim review

1. **Overall assessment**

This is a strong proposal with the right scope: a REPL needs an explicit behavior and security contract, not an accumulation of convenient exceptions. The precedence rule—behavior here, mechanisms in the siblings, contradictions invalidating the corpus—is exactly right ([0022:37](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:37)).

The defaults are generally sound: keep raw VM evaluation closed, authenticate operator ingress, do not let piped source author policy, reject runtime authority attributes, use Root plus provenance rather than inventing a principal, remove `.env`, and generate the command and native-disposition inventories.

It is not ready. Three security/lifecycle issues are blocking: the one-shot submission credential has no coherent read-to-evaluation lifecycle, cooperative exit has two incompatible sibling mechanisms, and nonce freshness is assigned to a schema that cannot enforce it. There are also material registry, arming, module-identity, terminal, and feasibility gaps.

The scope itself is not wrong. Some mechanism-level text—“decision evidence,” schema-enforced freshness, and the interim root-import algorithm—should move into or be resolved by the owning specs, while 0022 retains the observable invariant.

2. **Strengths**

- The proposal correctly treats contradictions as invalid corpus state and introduces explicit delegated obligations rather than silently assuming mechanisms exist ([0022 §Summary:51](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:51), [§11:848](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:848)).

- Its diagnosis of the current REPL is unusually accurate. `.load` calls the immediate file evaluator ([repl/mod.rs:930](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930)); `.env` directly enumerates `std::env::vars()` ([repl/mod.rs:966](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:966)); completion evaluates the base expression and reflects over it ([repl/mod.rs:283](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:283)); and the capability-granted message is printed before an ignored optional call ([repl/mod.rs:814](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:814)).

- The conceptual split between authenticated CLI ingress and JavaScript-reachable evaluation is good ([0022 §1:145](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:145)). The registry confirms the problem: `command:ibex` is presently non-capability ([coverage-edges.json:128357](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128357)), while `command:ibex repl`, `cli:repl`, and `ex_hermes_eval` are closed under `vm:evaluate` ([coverage-edges.json:128477](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128477), [132827](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:132827), [133067](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:133067)). Keeping the raw evaluator closed is correct.

- The proposal also correctly leaves inspection and loader state closed. `runtime:inspect` is deny-only and terminal ([capability-definitions.json:383](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:383)); `Exact.inspect`, `process.mainModule`, `require.main`, and `require.cache` are closed under it ([coverage-edges.json:196853](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:196853), [216802](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:216802), [222919](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222919)). A private safe-display seam is the right replacement.

- The synthetic-entry model and prohibition on stdin shaping the authority graph are good decisions ([0022 §2:243](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:243), [315](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:315)). They agree with LLP 0014’s rule that grants are authored and stripped at build time ([0014:104](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:104), [230](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:230)). Full Root for explicitly piped code is a defensible and candid v1 default; it does not imply that those bytes may author policy.

- Hard errors for authority-bearing import forms are the right default. Silently ignoring an attenuation request would be fail-open with respect to operator intent ([0022 §6:522](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:522)).

- Root plus unforgeable submission provenance is preferable to a new operator principal. The actual enum contains only Package, Root, Runtime, ModuleLoader, and Quarantine ([model.rs:302](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:302)).

- The generated three-way native disposition join is a substantial improvement over handwritten name lists ([0022 §7:688](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:688)). Removing `.env` in v1 is also the right security/usability tradeoff ([0022:718](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:718)).

- The generated exhaustive command/alias table and trap-free completion rule are sound ([0022 §8:750](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:750), [§9:790](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:790)). They directly address the current handwritten help/dispatcher drift ([repl/mod.rs:608](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:608), [920](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:920)).

- The end-to-end acceptance criteria are substantially better than the current test posture. They generally name observable outcomes and adversarial fixtures rather than merely implementation steps ([0022:924](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:924)).

3. **Concerns**

1. **Blocking — the submission permit has no coherent read/evaluate lifecycle.**

   **Evidence:** Section 7 requires a one-shot permit, including a submission ordinal, consumed atomically before the first effect ([0022:636](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:636)). Current 0024 places an atomically consumed permit on the later source request while also requiring the preceding `.load` read to use that provenance ([0024:173](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173), [197](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:197)). If the read consumes it, evaluation cannot; if evaluation consumes it, the read occurred first. The request also omits the ordinal and does not bind endowments. Moreover, `DecisionContext` has no submission credential field ([model.rs:1476](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1476)), while `DecisionEvidence` is output generated after a decision ([decision.rs:300](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:300)). Calling the permit “decision evidence” is therefore a category error.

   **Resolution criterion:** Specify an opaque, non-JavaScript-reachable `SubmissionCredential` and a linear state machine, for example `minted → read-authorized → immutable byte capsule → evaluated`. The capsule must bind the bytes’ digest, virtual source identity, referrer, goal, role, mode, endowment projection, entry kind, and ordinal. Define mint authority, verifier boundary, atomic transitions, races, replay rejection, and teardown. Test every ingress, not only `.load`.

2. **Blocking — cooperative exit has incompatible mechanisms.**

   **Evidence:** 0022 says the fifth outcome unwinds evaluation ([0022:844](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:844)); 0024 likewise says the native frame unwinds and the transaction rolls back ([0024:564](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:564)). 0025 says the call parks forever, does not unwind, and the supervisor terminates the worker after receiving an authenticated control record ([0025:654](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:654)); its own ledger explicitly calls 0024’s mechanism wrong ([0025:870](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:870)).

   **Resolution criterion:** Select one mechanism in coordinated revisions. If park/control-record is retained, define the lifecycle outcome as supervisor-synthesized, specify whether and how the cell transaction is rolled back, authenticate the record, and test spoofing, worker death, `try/finally`, broker flushing, and terminal restoration.

3. **Blocking — nonce freshness is assigned to an unenforceable mechanism.**

   **Evidence:** Section 7 says the schema must require freshness and describes the fixed nonce as a live replay defect ([0022:650](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:650)). Production copies the canonical example without replacing `runNonce` ([runtime.rs:1889](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1889)); the example is fixed ([armed-snapshot.canonical.json:20](/Users/ccheever/projects/ibex/capsec/examples/armed-snapshot.canonical.json:20)); and the schema validates only representation ([armed-snapshot.schema.json:68](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:68)). A stateless schema cannot establish entropy, uniqueness, or freshness. There is also no shipping permit consumer, so this is currently a latent prerequisite defect rather than an exploitable replay channel.

   **Resolution criterion:** Require production runtime construction to generate the nonce with a CSPRNG, specify entropy and lifecycle, disallow artifact/caller-supplied production values, and test cross-runtime rejection. Prefer binding permits to an unexported runtime-local handle or secret; deterministic nonce injection should be test-only.

4. **Material — the ingress/`vm:evaluate` split is correct in concept but wrong in granularity.**

   **Evidence:** The target requires `authenticated-code-ingress` on every parser node, spelling, option, positional, and branch ([0022:181](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:181)). But arity, value-name, and spelling rows are syntax metadata; they do not themselves authenticate or submit source. The present `-e` rows demonstrate the inconsistency ([coverage-edges.json:128247](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128247), [130927](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:130927)). The non-capability edge schema can carry only a rationale ID and prose, not the required session-binding fixtures ([coverage-edge.schema.json:313](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:313)). Finally, the 0024 source request derives principal but still lacks an authenticated endowment field ([0024:173](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173)).

   **Resolution criterion:** Classify the canonical CLI dispatch route as `authenticated-code-ingress`; relate structural parser rows to that route rather than pretending each satisfies its predicate. Keep the structured engine-submit operation private and separately classified, with raw `ex_hermes_eval` closed. Add machine-readable ingress obligations and prove that every security-relevant request field is derived from authenticated session state.

5. **Material — the synthetic-entry policy and root-import transition are not artifact-sound.**

   **Evidence:** LLP 0014 makes policy entry-scoped ([0014:113](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:113)), yet neither the canonical policy nor armed-snapshot schema currently records the proposed entry applicability or exact root-import surface ([canonical-policy.schema.json:6](/Users/ccheever/projects/ibex/capsec/schema/canonical-policy.schema.json:6), [armed-snapshot.schema.json:6](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:6)). The generator records and then drops root edges ([generate-policy.mjs:123](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:123), [375](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:375)); runtime compensates by making every principal root-importable ([runtime.rs:1763](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1763), [1807](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1807)). The proposed no-incoming-edge fallback is sound only if two unrepresented completeness premises are true. Latest 0023 also records graph-location and integrity-binding prerequisites as unlanded ([0023:1239](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1239)).

   **Resolution criterion:** Prefer direct cutover to a versioned artifact carrying synthetic-entry applicability, exact root-import locators, authenticated graph locations, integrity, root builtin set, and environment base. Reject old artifacts with an upgrade diagnostic. If the lower bound remains, add an authenticated edge-completeness bit and split root-row emission, entry reachability, and “only root edges dropped” into separate obligations.

6. **Material — module identity remains contradictory, though §11 describes the obsolete contradiction.**

   **Evidence:** Current 0023 keys modules on `(runtime, defining principal, SourceId)` and says `repl:<n>`, `ibex:eval`, and `.load` are script inputs with source identity only—no module identity or cache entry ([0023:423](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:423), [455](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:455)). Current 0024 defers the tuple mechanism but still says module identity must cover `ibex:eval` and `repl:<n>` and says synthetic sources are keyed ([0024:1134](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1134), [1147](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1147), [1482](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1482)).

   **Resolution criterion:** State in both siblings that `ibex:stdin` is the sole synthetic module. `repl:<n>`, `ibex:eval`, and `.load` have source identities but never module identities or cache keys. Update the sibling acceptance criteria and 0022’s OBL row accordingly.

7. **Material — hard-error enforcement lacks alias and binding semantics.**

   **Evidence:** The default is correct, and the authoritative keys are `authorities`, `grants`, `endow`, `builtins`, and `also` ([import-grants.mjs:15](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/import-grants.mjs:15)); the current Rust parser knows only historical `needs` ([repl/mod.rs:1033](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:1033)). But a syntactic scan can falsely reject a locally shadowed `require`, and miss `const r = require; r("pkg", proxy)`. Rejecting an arbitrary options object at the loader boundary must not inspect a getter or Proxy. Unbundled direct file execution is also explicitly unresolved ([0022:546](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:546)).

   **Resolution criterion:** Define loader-binding identity across persistent cells. Compiler-validate recognized literal calls, and make any aliased loader callable reject a second argument at its native/internal boundary without reading it. Add alias, shadowing, cross-cell, getter, Proxy, spread, and computed-key fixtures. Resolve direct-file behavior before claiming “every mode.”

8. **Material — sealing `Ibex.authority` is a broader parity break than the proposal states.**

   **Evidence:** Section 6 describes the break mainly as loss of dynamic grants ([0022:582](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:582)). LLP 0021 distinguishes dynamic grants from bearer-handle delegation; `Ibex.authority` includes minting and revocation, not merely self-grant requests ([0021:374](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:374), [827](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:827)). Current bootstrap installs one shared `g.Ibex` ([hermes_runtime.cc:2139](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2139)), and compartments return that same object ([hermes_runtime.cc:2627](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2627)). The registry also models these facades as live authority-control-plane surfaces ([coverage-edges.json:200783](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:200783), [200963](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:200963)).

   **Resolution criterion:** Explicitly decide whether losing handle mint/revoke/delegation is acceptable in v1. Make session entry kind part of bootstrap disposition and target-cell applicability, and add file-versus-session conformance tests. Otherwise make per-principal `Ibex` projections a release requirement.

9. **Material — the raw-bridge inventory is a good design without a complete discovery mechanism.**

   **Evidence:** The proposed descriptor-only live sweep does not define traversal roots, cycles, budget, accessors, Proxies, or install identity ([0022:688](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:688), [706](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:706)). Current seals are handwritten arrays ([hermes_runtime.cc:2323](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2323), [2360](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2360)). More importantly, `__exactModuleResolve` directly invokes the host resolver ([hermes_runtime.cc:1836](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1836)); the ordinary loader’s import gate lives only in JavaScript ([module-loader.js:5757](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5757)); and the raw ABI returns source plus host `path`/`pkgRoot` fields ([abi.rs:2168](/Users/ccheever/projects/ibex/src/host/abi.rs:2168), [2198](/Users/ccheever/projects/ibex/src/host/abi.rs:2198)). `__exactRealpath` likewise returns a backing host path ([hermes_runtime_fs.cc:2551](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551)).

   **Resolution criterion:** Centralize native installation through one registrar with stable install IDs and owner-authored dispositions. Keep native handles in a private table rather than installing and deleting them where possible. Pin sweep roots, cycles, budgets, descriptors, symbols, aliases, prototypes, and platform branches. Enforce the typed import decision inside the native resolver as defense in depth and return only virtual identities.

10. **Material — §11’s ledger is sound traceability infrastructure but currently inaccurate and overclaims verification.**

    **Evidence:** Stable OBL IDs and owner-authored data are good ideas ([0022:857](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:857)). But the current table already misreports the revised siblings:

    - typed read and drain are now specified ([0024:188](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:188), [197](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:197));
    - 0024 and 0025 now agree on one unstyled display tree ([0024:1239](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1239), [0025:262](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:262)), contrary to `OBL-DISPLAY-WIRE`;
    - UTF-8 decoding is specified but stream recovery is not, so the status is partial ([0024:173](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173));
    - `OBL-INGRESS-CTX` lacks endowment binding;
    - `OBL-OUT-OF-SNAPSHOT` lacks the interim class;
    - the module-identity row describes an obsolete tuple conflict;
    - 0023 itself has numerous unlanded transitive prerequisites ([0023:1253](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1253)).

    `ref-check` can validate IDs, anchors, syntax, and declared evidence. It cannot prove that prose semantically delivers an obligation.

    **Resolution criterion:** Make each OBL one semantic assertion, with states such as `specified`, `partial`, `open`, `contradicted`, `implemented`, and `conformant`. Store per-owner attestations, anchors and revision hashes, `blockedBy` edges, implementation evidence, conformance-test IDs, and conflicts separately. Treat the generated table as traceability, not semantic proof.

11. **Material — the mode, interrupt, and transport matrices remain incomplete.**

    **Evidence:** Transcript invalid-UTF-8 recovery is stated per input ([0022:411](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:411)), but an unframed malformed byte stream has no defined next-input boundary. 0024 now supplies strict decoding only. Async fatality remains delegated by 0024 ([0024:1315](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1315)), while 0025 has no mode × event × status table; one-shot fatality is unstated. Cancellation is internally inconsistent: 0025 first says defeated requests never resolve, then says later normal completion resolves them defeated ([0025:551](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:551), [563](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:563)). Referrer capture covers prompt, modules, and `.load`, but not program stdin or one-shots ([0023:1151](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1151)). Finally, 0022’s no-editor interrupt list omits interactive-without-editor, which 0025 makes a reachable topology ([0022:828](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:828), [0025:191](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:191)).

    **Resolution criterion:** Add complete mode × input/event × outcome/status matrices, including one-shot and interactive-without-editor. Define byte-level transcript resynchronization or make malformed UTF-8 fatal until a framed protocol exists. Use 0024’s cancellation model—permanently stuck remains `Pending`; later completion terminates as `defeated`. Pin referrer origin, capture time, and stale-identity behavior for every source kind.

12. **Material — feasibility and implementation sequencing are still open.**

    **Evidence:** The required Script-plus-import-plus-TLA parser goal does not exist in the pinned parser and the implementation strategy remains an open question requiring a prototype ([0024:1596](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1596)). Numeric bounds remain open, preventing transcript-byte fixtures from being pinned ([0024:1611](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1611)). The target itself admits that a companion Plan is still needed to sequence the new ABI, engine patches, supervisor, schemas, and harness ([0022:1102](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1102)). Current CLI code does not implement the mode split: both spellings reach the same function ([main.rs:379](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:379), [462](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:462)), which always starts the interactive implementation ([main.rs:1332](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1332)).

    **Resolution criterion:** Land a companion Plan with dependency ordering and a minimal conformant profile. Before design acceptance, prototype the parser goal and lifecycle/interrupt mechanism on every candidate target, pin the constants annex, and demonstrate the proposed first slice end to end.

13. **Material — `replSurface` needs a security-registry join, not only an affordance label.**

    **Evidence:** The generated exhaustive table is good, but the current runtime manifest contains only `clapSurface` ([runtime-surface.json:31](/Users/ccheever/projects/ibex/runtime-surface.json:31)). An `affordance-parity` label does not satisfy LLP 0021’s no-unclassified-surface invariant. Commands such as `.load` and `.time` submit code or perform effects and require actual registry relationships.

    **Resolution criterion:** Give every command and alias a stable surface ID with a one-to-one join to a coverage edge, target cells, and—where relevant—typed effect routes. Generate help, dispatch, completion, parity classification, and security coverage from the same records.

4. **Cross-document findings**

- **Contradiction — lifecycle:** 0022/0024 require unwind-and-rollback; 0025 requires park-and-supervisor-disposal. Blocking.

- **Contradiction — module versus script identity:** 0023 excludes `repl:<n>` and `ibex:eval` from module identity; 0024 still requires them to be keyed. Material.

- **Contradiction — startup-diagnostic confidentiality:** 0022 permits host paths in pre-evaluation startup diagnostics ([0022:452](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:452)); 0023 requires symbolic package-locator output ([0023:267](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:267)); 0025 treats startup diagnostics as session output and forbids host paths ([0025:809](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:809)). The safer coherent rule is symbolic output.

- **Contradiction — cancellation:** 0025 describes `defeated` as both never resolving and as a terminal resolution. 0024’s distinction between permanently `Pending` and terminal `defeated` is clearer and should win.

- **Dangling dependency — `.load` credential handoff:** neither sibling defines how a consumed read credential becomes an authenticated, exactly-once evaluation of the returned bytes.

- **Dangling dependency — ingress context:** no sibling authenticates endowments as part of the source request, and goal/referrer/role/mode/main are not uniformly shown to be derived rather than caller-selectable.

- **Dangling dependency — referrers:** program stdin and one-shot referrer origin, capture time, and stale-identity behavior are missing.

- **Dangling dependency — interim import refusal:** neither 0023’s closed error union nor 0024’s taxonomy contains the distinct old-artifact refusal required by 0022.

- **Dangling dependency — UTF-8 recovery:** strict decoding now exists, but transcript resynchronization after malformed bytes has no owner.

- **Dangling dependency — async fatality:** program/file versus prompt behavior is stated, but one-shot behavior and the complete mode/event/status matrix are absent from 0025.

- **Dangling dependency — cross-process sequence allocation:** 0024 and 0025 agree that outcomes, async failures, and broker events share one sequence, but neither pins allocator ownership, crash epochs, or high-watermark behavior across the worker/supervisor boundary ([0024:1292](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1292), [0025:303](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:303)).

- **Dangling dependency — canonical source spelling:** 0023 unifies identity but leaves canonical display spelling open, while 0024 needs it for source maps and stacks ([0023:1521](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1521), [0024:1621](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1621)).

- **Resolved seam, stale ledger — display wire:** current 0024 and 0025 now agree that one versioned, unstyled semantic tree crosses the boundary. `OBL-DISPLAY-WIRE` should no longer say contradicted.

- **Hidden dependency closure — paths:** `OBL-PATHS` is normatively specified, but 0023’s own ledger marks its ABI handle, graph location, object state, occurrence owner, integrity binding, alias canonicalization, and disposition dataset unlanded. A flat “yes” hides these transitive blockers.

The §11 status corrections are therefore:

- Sound as written or substantially accurate: `OBL-SAFE-DISPLAY`, `OBL-NO-EVAL`, `OBL-ENTRY`, `OBL-ROOT-IMPORTS` as undelivered, `OBL-INGRESS-ROWS`, `OBL-IBEX-SEAL`, `OBL-IBEX-PROJECTION`, `OBL-DISPOSITION`, `OBL-ENV-BASE`, `OBL-ROOT-BUILTINS`, `OBL-REPL-SURFACE`, `OBL-RESERVED-KEYS`, `OBL-FILE-GRANTS`, `OBL-ASYNC-FATALITY`, `OBL-BOUNDS`, `OBL-ESCAPE`, and `OBL-LEDGER-CHECK`.

- Correct only with qualification: `OBL-PATHS` is specified but transitively blocked; `OBL-EVAL-OUTCOMES` has the five-way type but conflicts on lifecycle mechanism; `OBL-TERMINAL` specifies most listed components but not all cross-process protocols; `OBL-LOADER-CLOSED` is delivered collectively but must cite 0023 for `require.cache`; `OBL-FRESH-NONCE` is correctly “no,” but its schema/live-defect explanation is wrong.

- Incorrect or stale: `OBL-INGRESS-CTX` is partial; `OBL-SUBMIT-PERMIT` states a permit but not its protocol; `OBL-TYPED-READ` is now specified; `OBL-DRAIN` is now specified; `OBL-OUT-OF-SNAPSHOT` is partial; `OBL-MODULE-IDENTITY` describes an obsolete contradiction while missing the remaining script/module conflict; `OBL-DISPLAY-WIRE` is now aligned; `OBL-KEYBINDINGS` names a requirement but no exhaustive manifest; and `OBL-UTF8` is partial rather than wholly absent.

5. **Suggestions**

- Replace “decision evidence” with an explicitly authenticated `SubmissionCredential` or runtime-local bearer handle, while retaining the rule that it is not a new positive CapSec authority source.

- Eliminate the interim root-import inference and make policy regeneration a direct artifact-version cutover. Compatibility logic here costs more semantic surface than it saves.

- Add a digest-bound session-profile record inside the armed snapshot containing entry kind, policy applicability, root imports, root builtins, environment base, presentation-capture digest, and mode-dependent facade disposition.

- Build one native-binding registrar that produces both the install inventory and stable IDs consumed by the owner-authored disposition dataset.

- Make OBL data a dependency graph with atomic assertions and independent specification, implementation, and conformance states. Generate the prose tables from it, but retain human semantic review.

- Model-check the terminal/cancellation/lifecycle state machines. Their finite states and interrupt transitions are unusually well suited to exhaustive checking.

- Until transcript framing is specified, make malformed UTF-8 fatal in transcript mode. A future framed machine protocol can safely support per-frame recovery.

- Ship an explicit `--stdin-quarantine` route if there is demand, but keep full Root as the documented default unless usage evidence justifies changing it.

6. **Open questions**

1. Who may mint a submission credential—only the CLI process, trusted embedders, or other native consumers—and what authenticates that caller?

2. Is cooperative exit implemented by engine unwind or worker park/disposal, and what happens to the session-record transaction in the chosen model?

3. Which committed policy artifact is applicable to a synthetic REPL entry when policy is entry-scoped, especially in projects with several file entries?

4. Is loss of `Ibex.authority` handle delegation for imported packages an acceptable v1 compatibility break, or must per-principal facades land first?

5. Is the Script-plus-import-plus-TLA goal actually feasible on every candidate Hermes target without silently imposing Module early errors?

6. What is the exact one-shot async-failure rule and exit status, and should it match program/file execution?

7. What byte-level framing or recovery boundary makes invalid UTF-8 recoverable in a transcript?

8. Where does the session-wide sequence allocator live across worker and supervisor, and how are worker death and restart represented?

9. Should old policy artifacts be rejected outright, or is the complexity of an authenticated edge-completeness fallback genuinely justified?

10. What canonical display spelling identifies a module with multiple authenticated aliases, independently of import order?

11. What exact renderer, completion, queue, input-size, and shutdown bounds make the acceptance fixtures deterministic?

12. Is type-tag-only display an acceptable first release, or is stage-1.5 safe error capture the minimum usable profile?

7. **Readiness verdict**

The proposal is directionally excellent, but the permit protocol, lifecycle mechanism, nonce construction, sibling contradictions, and ledger inaccuracies are unresolved correctness and safety issues.

VERDICT: NOT READY
### Orchestrator verification notes (round 7, outside verbatim body)

Both families returned NOT READY on `71cc16796e2f`. Fable judged the substance sound — "every verified empirical claim held" — with three material concerns, each a one-paragraph fix. Codex raised three Blocking. Between them, plus the un-dispositioned findings of round 6's second Codex run, round 8 makes one structural change and several corrections.

**The structural change: §11's status column is removed, and the ledger now fails closed.** This is the round's real result. Both families, plus the coordinating session, converged independently on the same diagnosis, and Codex stated the decisive part outright: *"`ref-check` can validate IDs, anchors, syntax, and declared evidence. It cannot prove that prose semantically delivers an obligation."* A status column that no mechanism can verify is not a control — and this one had gone stale three times in one day, in **both** directions, while the section asserted it was the instrument that prevents exactly that. The asymmetry is what matters and is now stated: a stale "not delivered" is a false alarm, which is safe and self-correcting; a stale "delivered" is a **false assurance**, which is the failure mode this entire document exists to prevent. So the ledger asserts no status, treats every obligation as undischarged until an owner attestation and a gating fixture both pass, and pins any verified discharge to the sibling revision it was checked against (`verified at 0024 b0ff4ea3247e` is permanently true; a bare "yes" can become false). Rows are split so that one row is one semantic assertion. Until `OBL-LEDGER-CHECK` exists, §11 says in those words that it is *documentation of an intent, not a control*.

The coordinating session put the underlying lesson better than either review: **an honest "not delivered" is a control; a "yes" you cannot mechanically check is a liability.** `OBL-ASYNC-FATALITY` is the proof — it has sat honestly undischarged for four rounds, stayed true the whole time, and is the only row that never misled anyone. It is retained, and its placement on the lifecycle owner is affirmed rather than left to age.

**Named the rule the document turns on.** Three defects that looked unrelated are one disease: the prompt printing `[capability granted]` for a grant that provably did not occur (§6); §2 telling an operator to regenerate policy when regeneration provably could not help; and an interrupt notice promising "press again" that a dirty edit buffer would silently swallow (§10). The Motivation now states it once — *never tell the operator something that is not true, least of all something reassuring* — and §10 adopts LLP 0025's framing that the property worth guaranteeing is not the keypress bound but that **every notice becomes true**, because the failure being guarded against is an operator reaching for `kill -9` after the session lied to them.

**Accepted — the root-import lower bound is retired for a version cutover.** Round 7 admitted every package with no incoming package→package edge, on the argument that such a package is provably root-imported. Both Codex runs pressed on the premises, and they are right: the inference is sound *against today's generator* but rests on two facts the artifact does not attest (every package entry-reachable; only root edges dropped), so an **orphan principal would be admitted as "provably root-imported"** when it is nothing of the kind. This document argues in §7 that a guarantee holding only while another component keeps behaving is *a coincidence with a shelf life* — accepting one in §2 would have been incoherent. It was also incomplete exactly where operators would feel it (every shared `lodash`-class dependency has an incoming edge and was refused anyway). A version cutover rests on nothing and fails closed. AC 3 gains the orphan-principal fixture.

**Accepted — the submission credential was a category error.** Calling it "decision evidence" was wrong in kind: `DecisionEvidence` is an *output* the decision model emits after deciding and structurally cannot authenticate an *input* (Codex r6 Run B and r7, independently). §7 now specifies an input-side `SubmissionCredential` with a linear lifecycle — minted → read-authorized → immutable byte capsule → evaluated — consumed exactly once and binding the **source bytes' digest**, without which it would authorize *a* read rather than *these bytes*.

**Accepted — nonce freshness is a construction obligation, not a schema one.** Round 7 said "the schema must require freshness." A stateless schema can check an encoding; it cannot establish entropy, uniqueness, or freshness. The nonce must come from a **CSPRNG during runtime construction, before snapshot digesting**. (Codex is also right that with no permit consumer shipping today this is a latent prerequisite defect rather than a live replay channel — the earlier "live defect" framing overstated it in the alarming direction, which this document has now done twice and should stop doing.)

**Accepted — the reserved-key refusal must sit where it cannot be aliased around.** `const r = require; r("pkg", bag)` defeats any check keyed to the spelling `require`, and a locally shadowed `require` would be falsely accused by one. The refusal is now enforced at the **loader's native boundary, rejecting a second argument without reading it**. AC 7 gains alias, shadowing, cross-input rebinding, getter, Proxy, spread, and computed-key fixtures.

**Accepted — the ingress classification attaches to the dispatch route, not to syntax metadata** (an arity or value-name row authenticates nothing), the obligations cannot live in the rationale (a non-capability edge carries only `{id, surface, rationaleId, rationale}` and a new rationale otherwise inherits a generic fixture, so they must be target-cell fixtures or a checked dataset), and the route inventory was missing `ibex capsec audit <file>`, which executes an operator-named file — verified. Naming it is the difference between a partition and a slogan.

**Accepted — `$_` is corrupted by a failed display today.** The shipping REPL assigns `globalThis.$_ = _val` *before* calling `Exact.inspect` (`src/bin/ibex/repl/mod.rs:63-79`), so a value whose display throws already replaces `$_`, contradicting this document's "last **successfully displayed** value" rule. AC 6 gates it.

**Accepted — §10 cites rather than paraphrases.** A previous revision inherited the word "unwind" for the cooperative exit from LLP 0024; LLP 0025 shows the call **parks** and does not unwind past `finally`, a mechanism no vendored Hermes interface offers. Paraphrase is precisely how every cross-document claim in this corpus has gone stale, so §10 now cites LLP 0025 §6/§8 for the machine and the mechanism.

**Verified discharged, and recorded pinned to a revision:** `OBL-DISPLAY-TREE`. LLP 0024 amended its §8 in LLP 0025's favor — one versioned, **unstyled** semantic tree crosses the worker boundary and the session layer derives styling. The deciding argument is a security argument and is worth preserving: under the worker split the producer may be hostile, so *a producer that can name a style can emit terminal control*; a tree that cannot express styling makes injection **structurally impossible rather than merely forbidden** — the same reasoning that seals a bridge instead of gating it.

**Rejected:** Codex's proposal to rename this a "behavior-and-security integration contract" (the Scope already says it constrains the registry and the siblings). Codex's recommendation to *ship* `--stdin-quarantine` in v1 — §2 decides full Root with the Node-parity argument, and this document will not claim a flag it has not designed; OQ 6 records both families' recommendation. And the framing of sibling-owned gaps as Blocking *on this document*: a behavior contract is blocked by failing to **name** an obligation, not by its owner not yet having discharged it — which is what the ledger is for, and treating it otherwise would make every document in a four-document corpus permanently unready.

**Sibling defects found and reported, not fixed here:** LLP 0025's own ledger row `O-2` still marks the display-IR retraction "not yet" although LLP 0024 has now done it — stale in the opposite direction, in a fourth document, which is further evidence for the fail-closed redesign above. LLP 0025 describes `defeated` cancellation both as never resolving and as a terminal resolution (LLP 0024's permanently-`Pending`-vs-terminal-`defeated` distinction is the clearer one and should win). LLP 0023's observables table still describes `import.meta.url` unconditionally as a virtual file URL, contradicting `ibex:stdin`. Neither sibling owns transcript resynchronization after malformed UTF-8, so this document makes it fatal in transcript mode until a framed protocol exists. And no sibling pins the cross-process sequence allocator's owner, crash epochs, or worker-restart behavior (`OBL-SEQUENCE`).

## Round 8 — 2026-07-12

**Reviewer family:** GPT (OpenAI)
**Provider / runtime:** Codex CLI `codex-cli 0.144.1`, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, non-interactive (`codex exec`), workdir `/Users/ccheever/projects/ibex`, session id `019f55f3-f264-76a0-90d7-ae47e9347f25`
**Method:** cli-runner, shared round-8 brief. Log written to a `self-`-prefixed path, adopting the discipline that prevents the round-6 filename collision recurring.
**Date:** 2026-07-12
**Revision under review:** `826d4120247f` (sha256/12 of the document)
**Sibling corpus seen:** LLP 0023 `a1ba44b33dd1`, LLP 0024 `b0ff4ea3247e`, LLP 0025 `7b89315f8ad7` at launch; all three remained under concurrent revision.
**Redacted:** No.
**Independence:** Fresh session; no access to the orchestrating session, to the concurrent review of the same revision by the other family, or to any prior LLP 0022 review artifact (the seven prior rounds were stashed out of `llp/reviews/` for the duration and restored afterwards).

### Verbatim review

## 1. Overall assessment

Reviewed the complete round-8 document at SHA-256 `826d4120247f…`, all three sibling specs, the governing LLPs, registry data, and the named implementation surfaces.

The proposal has the right security instincts and a compelling product model. In particular, separating authenticated CLI ingress from JavaScript-reachable evaluation, refusing runtime authority authoring, retaining Root while authenticating the submission route, removing `.env`, and inventorying raw bridges are all good decisions.

It is not ready. The corpus currently contains invalid normative states around submission credentials, exit, interruption, module identity, cancellation, sequencing, and startup diagnostics. The synthetic-entry authority artifact is not yet defined well enough to determine what graph or builtin surface a session receives. Section 11 honestly exposes many of these gaps, but its rows are not atomic, several owners and gates are wrong, and one row embeds exactly the unpinned status claim the section rejects.

The stated scope is also too narrow for the document’s actual role. Sections 1, 2, 6, and 7 define cross-runtime security architecture for file execution, one-shots, audit, loader ABI, arming schemas, and native reachability—not merely observable REPL behavior. Those requirements should remain, but their canonical mechanism should move into a session-security/ingress spec and a companion Plan. Otherwise 0022 will continue duplicating sibling mechanism and drifting from it.

## 2. Strengths

- The “never tell the operator something untrue” principle is unusually strong and usefully concrete ([0022 §Motivation](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:97)). It directly addresses the current false capability acknowledgement: the REPL prints before checking success ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:818)), while enforce startup removes `Exact.setModuleCapabilities` ([hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2291)).

- The conceptual split between authenticated execution ingress and JavaScript-reachable `vm:evaluate` is correct ([0022 §1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:155)). The registry genuinely contradicts itself: root `command:ibex` is non-capability, explicit `repl` is closed, and raw `ex_hermes_eval` is closed ([coverage-edges.json](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128357), [coverage-edges.json](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:128477), [coverage-edges.json](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:133067)). `vm:evaluate` is specifically tier-4, deny-only, terminal, and concerned with unattributed code ([capability-definitions.json](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:529)).

- The intended version-cutover rule for root package imports is the right fail-closed answer ([0022 §2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:290)). Current code makes every policy principal root-importable and synthesizes root edges to all of them ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1763)); fixing that widening is important.

- Full Root for piped stdin is defensible as an explicit compatibility decision, and the document correctly distinguishes “cannot author policy” from “is untrusted code” ([0022 §2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:347)). The language should say “operator-selected ingress” rather than “operator-authored,” but the trust-boundary reasoning is sound.

- Hard refusal of runtime authority attributes is the correct default ([0022 §6](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:546)). LLP 0014 makes grants build-time inputs stripped before execution ([0014 §Grant syntax](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:99)), and the actual key constant confirms the proposed generated set ([import-grants.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/import-grants.mjs:15)).

- Root plus an unforgeable submission credential is preferable to inventing an operator principal. The current principal algebra has only Package, Root, Runtime, ModuleLoader, and Quarantine ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:302)); provenance answers which trusted route asserted Root, not who the principal is.

- Keeping `Exact.inspect`, `require.cache`, `require.main`, and `process.mainModule` closed while providing a private display seam is coherent with the registry ([coverage-edges.json](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:196853), [coverage-edges.json](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:222919)). This directly repairs the current REPL’s JavaScript-reachable `Exact.inspect` path ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:63)).

- Removing `.env` in v1 is the right decision. The current command enumerates the ambient host environment directly from Rust ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:966)).

- The generated command/alias and native-disposition approaches are strong drift controls. Current help already omits `.h`, `.quit`, `.q`, and `.cls` despite dispatch accepting them ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:609), [repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:920)).

- Section 11’s use of stable IDs, revision-pinned verification, and fail-closed treatment is a good traceability design ([0022 §11](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:913)). Its admission that the checker does not yet exist is honest.

## 3. Concerns

1. **Blocking — The root-import fallback directly contradicts itself.**

   **Evidence:** Section 2 retires the no-incoming-package-edge inference and says old artifacts admit no root package-import surface ([0022:290–318](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:290)). Consequences resurrects that exact inference ([0022:1124–1128](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1124)). The generator currently drops root edges ([generate-policy.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:375)).

   **Resolution criterion:** Delete the stale Consequences statement, name the exact new policy schema/version or feature marker, and fixture only the refuse-all cutover behavior.

2. **Blocking — `SubmissionCredential` is internally contradictory and not delivered by 0024.**

   **Evidence:** Section 7 first calls provenance “decision evidence” ([0022:673](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:673)), then correctly calls that a category error and requires a linear input credential ([0022:687](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:687)). Line 720 still assigns it to an “evidence schema.” LLP 0024 retains the obsolete terminology, omits the endowment projection and several required bindings, and returns bytes “with decision evidence” ([0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173), [0024 typed read](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:197)). Current `DecisionContext` has no such input ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1476)).

   The byte binding is also incomplete for `.ts`, JSX, and hashbang-normalized input: bytes read are not bytes Hermes executes.

   **Resolution criterion:** Define one canonical linear type—`PendingSubmission → ReadAuthorized → ImmutableSourceCapsule → EvaluationRequest`—with atomic state consumption. Bind the original-byte digest, transform identity/version, executed-byte digest, referrer, goal, role, mode, entry kind, endowment projection, and ordinal. Reserve “decision evidence” for output.

3. **Blocking — The ingress partition is conceptually right but not exhaustive or classification-safe.**

   **Evidence:** Section 1 says every source-submission route gets `authenticated-code-ingress` and specifically names file execution and `capsec audit` ([0022:187–207](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:187)). Yet `ibex run <name>` may dispatch to a package script, ambient-read `package.json` and `PATH`, and spawn `/bin/sh` ([main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:344), [main.rs package scripts](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:523)). That route does exercise external authority itself. `capsec audit` currently constructs an unarmed audit host ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1073)). AC1 omits file, run, audit, and package-script branches ([0022 AC1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1004)).

   The proposed non-capability representation is also undecided between “target-cell fixtures or a checked obligations dataset” ([0022:208](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:208)).

   **Resolution criterion:** Generate one canonical `executionRoutes` dataset that separately identifies REPL, program stdin, eval, print, file, run-file, package-script, audit, and implicit spellings. Join every branch exactly once. Apply `authenticated-code-ingress` only where its no-independent-effect predicate and armed-session fixtures hold; classify package-script effects explicitly. Revise `vm:evaluate` so it clearly means caller-selectable/unattributed or JavaScript-reachable evaluation.

4. **Blocking — The synthetic-entry authority artifact is not sufficiently defined.**

   **Evidence:** LLP 0014 policy is entry-scoped ([0014:113](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:113)), but a REPL has no analyzed entry. Section 2 selects a project’s singular committed artifact without defining which entry it represents. The armed schema has no entry field and rejects unknown fields ([armed-snapshot.schema.json](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:6), [armed-snapshot.schema.json](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:180)).

   Root builtins are also unresolved: no-policy sessions promise allowed builtins, `OBL-ROOT-BUILTINS` requires an authored exact set, while current construction simply admits every gated builtin ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1758)). Package bindings are guessed by bare name and silently skipped ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1823)).

   Nonce construction covers neither arming path completely: default construction retains the example’s fixed nonce ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1889), [example snapshot](/Users/ccheever/projects/ibex/capsec/examples/armed-snapshot.canonical.json:20)), while explicit startup accepts a caller-supplied, already-digested snapshot unchanged ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1605)).

   **Resolution criterion:** Define a versioned session-policy/profile artifact bound to permitted entry kinds, exact root imports, exact root builtins, project identity, and one-to-one locator/integrity package bindings. Specify which trusted component injects the per-run nonce and computes the final armed digest for both default and external-launcher paths. Add an explicit package-binding obligation.

5. **Blocking — Cooperative exit and interrupt escalation contradict their owning sibling.**

   **Evidence:** 0022 says exit parks and does not unwind ([0022 §10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:902)); 0024 says it unwinds as a lifecycle completion ([0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:564)); 0025 specifies park/no-unwind and two realizations ([0025 §8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:537)).

   Likewise, 0022 promises two interrupts against the same running target ([0022:877](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:877)), while 0025 explains that target IDs are for cancellation delivery and escalation must latch onto a running-work class and work epoch ([0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:391)). Its ledger explicitly calls 0022’s wording false under turnover ([0025:737](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:737)).

   **Resolution criterion:** Make 0024’s lifecycle outcome an out-of-band committed record synthesized without JavaScript/native-frame unwinding, including a precise record-publication rule. Replace 0022’s target wording with 0025’s generated class-and-work-epoch invariant.

6. **Material — Shared identity, cancellation, and sequencing algebras remain inconsistent.**

   **Evidence:** 0023 says `repl:<n>`, `ibex:eval`, and `.load` are script source identities with no module/cache identity; only `ibex:stdin` is a synthetic module ([0023 §2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:455)). 0024 says module identity must cover `repl:<n>` and `ibex:eval` ([0024 §7.9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1147)).

   0024 defines `defeated` as terminal and permanently stuck work as `Pending` ([0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:676)); 0025 says “defeated—never resolves” and then says it resolves defeated ([0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:464)).

   Both siblings name one sequence domain, but neither defines allocator ownership, collision avoidance across worker/supervisor, crash epochs, or restart behavior required by `OBL-SEQUENCE` ([0024 §9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1292), [0025 §3](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:260)).

   **Resolution criterion:** Publish one shared algebra for source versus module identity, cancellation states, and sequence identifiers. Reserve `Pending` for unresolved work, make `defeated` terminal, and define supervisor ownership or epoch-tagged range leasing for sequence numbers.

7. **Material — Typed `.load` and authority-attribute enforcement have unresolved ownership and semantics.**

   **Evidence:** 0022 prose assigns `.load` credential/read work to 0024 and 0021 ([0022:708](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:708)), while `OBL-TYPED-READ` assigns 0023 and 0021 ([0022:956](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:956)). No owner combines credential verification, byte capsule, referrer, TOCTOU, and retained-object identity. Current `.load` routes to an ambient file-read path ([repl/mod.rs](/Users/ccheever/projects/ibex/src/bin/ibex/repl/mod.rs:930)).

   Section 6 supports ordinary attributes but later requires the native loader boundary to reject any second argument without reading it ([0022:573](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:573), [0022:600](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:600)). Those rules conflict for aliased calls unless validated requests acquire a separate sanitized internal representation. LLP 0014’s “runnable in every mode” wording also still conflicts with 0022’s bundler-only interpretation and unresolved direct-file case ([0014:329](/Users/ccheever/projects/ibex/llp/0014-import-site-grants-and-generated-policy.spec.md:329)).

   **Resolution criterion:** Split path/object/TOCTOU ownership to 0023+0021 and credential/capsule ownership to 0024+0021, then add a composition fixture. Lower validated data-only ordinary attributes to a sanitized internal request; refuse unvalidated raw two-argument loader calls. Revise LLP 0014 concurrently and settle direct-file grants.

8. **Material — The raw-native disposition equality is not type-correct.**

   **Evidence:** Section 7 defines sets over native install sites, then says a traversal of everything reachable from the root global must equal the surviving native set ([0022:737–765](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:737)). The live graph also contains ordinary JS/ECMAScript objects; conversely, descriptor traversal cannot see a native captured privately in a JS closure. Current dual aliases demonstrate the install-identity problem ([hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1836)). `__exactRealpath` also remains root-reachable and returns a backing host path ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551)).

   **Resolution criterion:** Give every native callable a stable registrar-issued install ID. Define the live sweep as a native, trap-free projection over reachable tagged natives and aliases—not the entire object graph. Separately attest private captures, JS wrappers, platform branches, and closure consumers.

9. **Material — Startup diagnostics and resolver error ownership conflict.**

   **Evidence:** 0022 permits startup diagnostics to name an out-of-project host path ([0022 §4](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:473)); 0023 requires that exact package-containment diagnostic to be symbolic and never name the host path ([0023 §1.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:267)).

   Separately, 0023 claims a closed total resolver union but omits unknown-builtin, unsupported dependency TLA, and a general module-resolution-failure member ([0023 §7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1096)); 0024 supplies those classes without a composed total order ([0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:261)).

   **Resolution criterion:** Publish one diagnostic-disclosure matrix by phase and error class. Either scope 0023’s union strictly to path adapters and define composition in 0024, or create one closed resolver/import/path union with pairwise precedence fixtures.

10. **Material — Transcript determinism and the generated surface contract remain incomplete.**

   **Evidence:** `OBL-UTF8` demands a transcript resynchronization boundary, but 0024 only specifies strict decoding and 0025 only says malformed input must not crash ([0022:976](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:976), [0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:173), [0025 §5](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:327)). Renderer and transcript bounds remain open; 0025 claims a constants annex but supplies no values ([0024 OQ8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1611), [0025 §12](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:744)).

   The command table says its manifest contains modes, streams, arity, and affordance classifications but does not state their values. `OBL-KEYBINDINGS` requires exhaustiveness while 0025 lists only four control keys despite promising Emacs editing ([0025 §5](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:343)). `.time` is excluded from byte fixtures without a complete statement of how that affects transcript determinism.

   **Resolution criterion:** Choose fatal malformed UTF-8 or a precise discard-through-newline/reset rule. Publish actual versioned bounds and truncation grammar. Materialize `replSurface` and the documented-keybinding manifest with stable values and fixture IDs; define `.time` as an explicit nondeterministic exception.

11. **Material — Section 11 is a useful ledger but not yet an accurate instrument.**

   **Evidence:** It claims every row is one assertion ([0022:940](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:940)), but `OBL-PATHS`, `OBL-SUBMIT-CREDENTIAL`, `OBL-TERMINAL`, `OBL-DISPOSITION`, `OBL-MODULE-IDENTITY`, and `OBL-UTF8` are compound. `OBL-ASYNC-FATALITY` embeds an unpinned “undischarged for four rounds” status despite the section rejecting mutable status ([0022:961](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:961)).

   Owner/gate errors include:

   - `OBL-DISPLAY-TREE` names 0025 although 0024 owns the schema ([0024 §8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1239)).
   - `OBL-TYPED-READ` omits 0024.
   - `OBL-LOADER-CLOSED` omits 0023’s `require.cache` rule.
   - `OBL-KEYBINDINGS` omits LLP 0010, where 0025 says the manifest lives.
   - AC4 does not gate the display tree, terminal history, full interrupt machine, or sequence allocator; AC12 does not gate editor bindings.
   - 0025’s own status table is already stale about completion cancellation, sequence membership, and 0022’s parking language ([0025 §11](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:727)).

   **Resolution criterion:** Store obligations as machine-readable atomic rows with stable sub-IDs, owner anchors and revisions, dependency direction, stable fixture IDs, and report digests. Remove status prose from obligation text. Let the checker prove freshness and fixture linkage; retain human review for semantic adequacy.

12. **Material — This is not yet an implementable plan, and its current scope causes duplication.**

   **Evidence:** `OBL-PLAN` explicitly records that no companion Plan exists ([0022:979](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:979)), while OQ8 admits that “v1” currently spans roughly thirty obligations, a new ABI, engine patches, supervisor, schemas, generators, and PTY harness ([0022:1183](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1183)). The core Script-plus-import-plus-TLA parser mechanism remains unprototyped ([0024 OQ5](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1596)). Raw `ex_hermes_eval` is still a bare evaluator that directly calls Hermes ([hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2924)), and many trusted startup operations still depend on arbitrary evaluation.

   **Resolution criterion:** Create the companion Plan before review acceptance. Define a bootstrap/session phase latch, structured ABI migration, parser prototype gate, schema/generator order, supervisor milestone, conformance target, and minimal v1. Move the canonical credential/entry/bridge mechanisms into a cross-runtime security spec; leave 0022 as the observable behavior consumer.

## 4. Cross-document findings

| Type | Finding |
|---|---|
| **CONTRADICTION** | 0022 calls submission provenance decision evidence and then rejects that category; 0024 retains the rejected model. |
| **CONTRADICTION** | 0022/0025 specify park/no-unwind; 0024 specifies unwind. |
| **CONTRADICTION** | 0022 promises escalation against one running target; 0025 requires running-work class plus work epoch. |
| **CONTRADICTION** | 0023 gives script inputs no module identity; 0024 requires `repl:<n>` and `ibex:eval` to be keyed. |
| **CONTRADICTION** | 0024 makes `defeated` terminal and stuck work `Pending`; 0025 calls defeated unresolved. |
| **CONTRADICTION** | 0022 allows a package host path in startup diagnostics; 0023 forbids it for the same arming failure. |
| **DANGLING DEPENDENCY** | `OBL-INGRESS-CTX`: 0024 does not derive every required field and has no endowment projection. |
| **DANGLING DEPENDENCY** | `OBL-SUBMIT-CREDENTIAL`: no sibling defines the complete linear, byte-bound type. |
| **DANGLING DEPENDENCY** | `OBL-TYPED-READ`: its path, credential, byte capsule, referrer, and TOCTOU pieces have inconsistent owners and no composition contract. |
| **DANGLING DEPENDENCY** | `OBL-SEQUENCE`: no allocator owner, crash epoch, stale-event, or worker-restart protocol exists. |
| **DANGLING DEPENDENCY** | `OBL-UTF8` and `OBL-BOUNDS`: strict decode exists, but transcript recovery and numeric bounds do not. |
| **DANGLING DEPENDENCY** | `OBL-ENTRY`, `OBL-ROOT-IMPORTS`, `OBL-ROOT-BUILTINS`, `OBL-ENV-BASE`, `OBL-INGRESS-ROWS`, `OBL-IBEX-SEAL`, `OBL-DISPOSITION`, `OBL-REPL-SURFACE`, and `OBL-RESERVED-KEYS` name real required work not delivered by their current owners. |
| **DANGLING DEPENDENCY** | `OBL-KEYBINDINGS`: 0025 names four special keys but does not provide the exhaustive published manifest 0022 requires. |
| **DANGLING DEPENDENCY** | `OBL-PLAN` and `OBL-LEDGER-CHECK` do not exist; therefore §11 is traceability prose, not a release control. |

## 5. Suggestions

- Extract a fourth normative seam—“Authenticated Session Ingress and Security Envelope”—owning `EntryKind`, `SubmissionCredential`, source capsules, phase sealing, execution-route classification, and native disposition. Let 0022 consume it behaviorally.

- Generate an `executionRoutes` manifest mapping parser spellings and implicit branches to canonical routes. This is a cleaner answer than attaching security semantics to every Clap metadata row.

- Split canonical build policy from the run-specific armed snapshot. The former records reviewed root imports/builtins and permitted entry kinds; the latter injects the CSPRNG nonce, authenticated project bindings, and engine/session identity.

- Model-check the credential state machine and arming cutover, as 0025 already proposes for interrupts. Linear-state bugs and replay are especially suitable for exhaustive checking.

- Require registrar-issued native install IDs and generate all aliases and private captures through that registrar. Then the live sweep can compare identities rather than names or arbitrary objects.

- Adopt the proposed transcript-first minimal v1: empty package graph, inert display, structured outcomes, strict stdin ownership, no dynamic authority, and no editor. Use it to prove ingress, attribution, sequencing, and lifecycle before adding PTY complexity.

- Give every refusal a stable code plus a machine-readable remedy identifier. This operationalizes the document’s “never lie” principle and makes diagnostics independently testable.

- Keep `.env` absent and keep the session-wide `Ibex.permissions`/`Ibex.authority` seal for v1. The parity break is narrow, explicit, and safer than promising a root-only projection the current membrane cannot express.

## 6. Open questions

1. Which exact build artifact authorizes a REPL or stdin session when policy is entry-scoped: a dedicated session profile, one selected file entry, or a new project-level artifact?

2. Which component is trusted to mint `runNonce` and finalize the armed digest when an external launcher supplies arming material?

3. Should the restricted `Quarantine` stdin route ship in v1, and should the default ever change from full Root? In either case, the trust boundary should be described as operator-selected bytes, not authenticated human authorship.

4. Is the dynamic-authority parity break acceptable for v1, or must per-principal `Ibex` projections become a release gate?

5. How is a lifecycle outcome and session-record rollback established when the JavaScript frame parks forever and the worker is disposed or the process `_exit`s?

6. Where does the cross-process sequence allocator live, and how are worker death, late messages, and replacement epochs ordered?

7. Are malformed transcript bytes fatal, or what exact byte boundary permits safe resynchronization?

8. What is the disposition of authority attributes in unbundled direct file execution, and how are ordinary sanitized attributes represented after alias-safe validation?

9. Can the Script-plus-static-import-plus-TLA parser goal be implemented without unacceptable divergence, and is that prototype a prerequisite to accepting the spec?

10. Does “exhaustive keybinding manifest” mean every editor binding or only documented product bindings? The latter is likely the maintainable contract.

11. Is type-tag-only display a shippable minimal v1, or must the trap-free inspection patch land first?

12. What exact subset of the thirty-plus obligations constitutes a conformant advertised target, and which target will execute the first end-to-end report?

## 7. Readiness verdict

The design direction is good, but the current corpus has unresolved material correctness, security, ownership, and feasibility defects. The sibling seam is not coherent enough to implement or fixture as one contract.

VERDICT: NOT READY
### Orchestrator verification notes (round 8, outside verbatim body)

Both families returned NOT READY on `826d4120247f`. Fable's verdict names the shape of what remained: "All are small, bounded edits plus one coordinated sibling pass; none requires rethinking a decision." Codex raised five Blocking — and **two of them were this document contradicting itself**, which is the most useful thing either review found.

**Confirmed — round 8's own corrections were half-applied, and the document was doing the exact thing it forbids.** §7 said the provenance is "carried as **decision evidence, not as authority**" and then, ten lines later, "It is **not** 'decision evidence' … a category error." The Consequences section still described the root-import lower bound that §2 had just retired, and AC 3 tests against. Both families found both. A contract whose organizing rule is *never tell the operator something untrue* cannot ship telling the implementer two contradictory things — the failure is the same one, pointed inward. Fixed, and the lesson is recorded rather than quietly swept: **a correction is not applied until every statement it falsifies is removed.** Adding the right sentence next to the wrong one is not an edit; it is an accretion.

**Accepted — the ingress predicate was too broad, one door further down than I had looked.** §1 claimed the partition covered every route that submits operator-authored source. But `ibex run <name>` may dispatch a package script, ambiently read `package.json` and `PATH`, and **spawn a shell** — it *does* exercise external authority and therefore cannot be a non-capability. The predicate is now applied exactly: a route is `authenticated-code-ingress` only when submitting attributed source is **all** it does; a route that also performs effects keeps its own classification for those. This is precisely the "recurs one door down" failure §1 warned about, committed by §1.

**Accepted — §11 violated its own rule in the row it praised.** `OBL-ASYNC-FATALITY` carried unpinned prose asserting it had "stood honestly undischarged for four rounds" — a delivery-status claim, in the section whose entire round-8 change was that unpinned status claims are the disease. It was **false within a day**: LLP 0025 §8 now carries the mode × failure-class × exit-status matrix both siblings delegated to it. The row is corrected, the discharge pinned to `0025 7b89315f8ad7`, and the irony left in the text, because a ledger that hides its own violation is the thing it was built to prevent.

**Accepted — the escape guarantee was stated in language LLP 0025 has shown to be false.** §10 said "two interrupts against the same running **target**." Under a `setInterval` turnover storm the callback is a *different object* each press, so a guarantee phrased over target identity is **vacuous in exactly the case a stuck operator needs it**. LLP 0025 rebuilt its machine over work **class and epoch** for that reason and placed `OBL-INTERRUPT-CLASS` on *this* document. §10 now states the guarantee in those terms, and the obligation is discharged and pinned. This is the fourth time in this loop that paraphrasing a sibling produced a false claim; §10 now cites.

**Accepted — §10 had no acceptance criterion at all**, while four ledger rows gated on AC 4, which tests none of them. A gating fixture that passes without exercising its obligation is a false-discharge channel built into the control. AC 15 now exercises §10 through the product surface, including the turnover-storm case that a target-identity rule would pass while the operator reaches for `kill -9`.

**Accepted — the nonce tripwire.** Arming now refuses any `runNonce` equal to a `capsec/examples/` vector. It costs nothing and would have caught the shipped defect mechanically, without waiting for the CSPRNG work.

**Rejected:** Codex's framing of the sibling-owned gaps (`OBL-ENTRY`, `OBL-ROOT-IMPORTS`, `OBL-SUBMIT-CREDENTIAL`) as Blocking *on this document*. They are named, owned, and gated; a behavior contract is blocked by failing to *name* an obligation, not by its owner not yet having discharged it. Treating it otherwise makes every document in a four-document corpus permanently unready — which is a description of the corpus, not a defect in one member of it.

**Sibling defects reported, not fixed here:** LLP 0024 §1 still calls the submission credential "decision evidence" and says "the LLP 0021 evidence schema carries the field" — the position this document now identifies as a category error, and per the precedence rule an invalid corpus state (`OBL-SUBMIT-CREDENTIAL`). LLP 0024 §6 still says the cooperative exit "unwinds" while LLP 0025 §8 says it **parks** and that an unwind past `finally` is a mechanism no vendored Hermes interface offers (`OBL-EXIT-MECHANISM`). Three documents hold three positions on whether a startup diagnostic may name a host path — §4 exempts it, LLP 0023 §1.2 mandates a symbolic locator *and attributes that rule to LLP 0025*, and LLP 0025 §9 disclaims having imposed it; now rowed as `OBL-STARTUP-DIAG`. And the `OBL-*` namespace collides across documents (0022 and 0023 both mint `OBL-MODULE-IDENTITY` for different assertions; three documents mint `OBL-LEDGER-CHECK`), which will need document-qualified IDs before the mechanical join exists.

**Convergence status: not reached.** Five rounds (4–8) of dual-model review, ten reviews in total (round 6 was reviewed twice by the GPT family), and both families returned NOT READY on every revision. Substance converged steadily — round 8's reviews found no wrongheaded *decision*, and Fable verified nearly every empirical claim against the code — but the corpus did not hold still: LLP 0023, 0024, and 0025 were each revised repeatedly *during* the rounds, and roughly three-quarters of §11's obligations have no sibling text behind them yet. `Status` therefore remains **Draft**, which is the correct and required outcome: this loop may only advance Draft → Review on convergence, and convergence was not reached.
