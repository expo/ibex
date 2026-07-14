# LLP 0024 review — Claude Fable

Reviews of `llp/0024-structured-evaluation-and-session.spec.md`, recorded per
LLP 0005. One `## Round N` section per round; earlier rounds are never
overwritten.

## Round 1 — 2026-07-12

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose`
subagent launched in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `9561404fa4e8`
**Redaction:** none — the reviewer received the unredacted brief and full
read access to the repository.
**Independence:** launched concurrently with the Codex reviewer on the same
revision, in a separate agent session with no shared context. No
`llp/reviews/0024-*` artifact existed at launch (this is round 1), and the brief
forbade reading `llp/reviews/`, so neither reviewer could see the other's
findings.
**Method:** read the full target document, the sibling corpus (LLP 0022, 0023,
0025) and the governing LLPs (0003, 0004, 0019, 0021), then verified
load-bearing claims against `src/bin/ibex/engine/{mod,hermes}.rs`,
`src/engine/hermes_runtime.cc`, `src/module_loader/{mod,transpile}.rs`,
`src/bin/ibex/repl/mod.rs`, and `packages/ibex-runtime-js/src/inspect/inspect.ts`
— and additionally probed the shipping engine directly (`tools/hermes/hermes`)
and the live `ibex repl` for TDZ, `const`, `with`, direct-`eval` scope,
`globalThis` var configurability, and cross-input lexical persistence.
**Transport note:** captured verbatim from the subagent's final message; the
agent transport HTML-escaped `<` and `>` inside code spans, and those escapes are
decoded here. No other alteration.

### Verbatim review

# Review: LLP 0024 — Structured Evaluation and Session Semantics (rev 9561404fa4e8, round 1)

## 1. Overall assessment

This is a strong, honest, well-motivated spec whose factual indictment of the current seam is essentially **100% verified against the code**: `Engine::eval` returns `Option<String>` (src/bin/ibex/engine/mod.rs:33), the source name is hardcoded `<eval>` (src/bin/ibex/engine/hermes.rs:1517,1524; src/engine/hermes_runtime.cc:2960), `undefined` collapses into a null pointer (hermes_runtime.cc:3162-3163) behind a NUL-terminated C string read via `CStr::from_ptr` (hermes.rs:902,914), the native unwrap assimilates any callable-`then` thenable (hermes_runtime.cc:3044-3057), `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` is `getenv`'d after arming with a hidden 10 s default (hermes_runtime.cc:3089-3100), the transform emits no source map (src/module_loader/transpile.rs:189), the REPL subtracts a wrapper prefix length to fake positions (src/bin/ibex/repl/mod.rs:107-164,874), the async-IIFE TLA wrap discards declarations (repl/mod.rs:1174-1186), a declaration prints `undefined` (repl/mod.rs:888-890), and native async errors log and set `fatal_async_error` (hermes_runtime.cc:681-692). The four headline decisions — shared cells with cell replacement, entry-only TLA, staged inert-not-unsafe inspection, and script-goal-preserving lowering — are all the right calls, each matching an honest reading of the engine's limits.

However, judged as a **normative Spec** by its own stated standard — "an operational cell model, not a table of adjectives" — §7 does not yet fully clear the bar: two independent implementers would diverge on closure binding time and on the failure path of a redeclaring input, the "exhaustive" deviation list is internally miscounted (three listed, "four" claimed) and demonstrably incomplete (globalThis configurability), and one normative sentence (direct-eval scoping) both contradicts LLP 0022 §1 and is unimplementable on the shipping engine, which I confirmed rejects `with` outright, gives `eval` no lexical scope, enforces no TDZ, and reports `const` violations as compile errors. These are all fixable within the document's existing architecture — this reads like a spec one hard revision away from READY, not one that needs rethinking.

## 2. Strengths

- **Motivation is evidence, not vibes (§Motivation, §6).** Every claimed defect of the current seam checks out at a specific line of code (citations above). This is the best-grounded motivation section of the four-document split.
- **The cell model asks the right question and answers the flagship case (§7).** Pinning `let x=1; const f=()=>x; x=2; f()` → `2` (shared cells, not copy-out), distinguishing redeclaration-as-cell-replacement from assignment, and refusing to make prior `const`s writable ("a new language") is exactly V8's REPL-mode design and the correct decision set. The "deviations are fixture-pinned; narrowing is a versioned contract change" discipline (§7) is excellent and matches the repo's LLP 0019 corpus culture.
- **Entry-only TLA is honest engineering (§3).** Verified premise: the loader lowers everything to a synchronous `require()` chain (LLP 0004; transpile.rs:97-101, with TLA passed through only for the entry shim at src/bin/ibex/runtime.rs:2616). Today an imported TLA module dies with an incidental syntax error; the spec's loud named error is strictly better, and refusing a plausible-but-wrong-under-cycles async lowering (§3, OQ5) is the right call.
- **Staged inspection refuses to pretend (§8).** The claim that pure-JS reflection cannot be trap-free is verifiably true of the current inspector: `safeGet` duck-typing probes and `Object.keys`/`getOwnPropertyDescriptor` run Proxy traps (packages/ibex-runtime-js/src/inspect/inspect.ts:90-96, 293-354, 394-431), and Hermes promise state is read via undocumented `_x`/`_z` slots (inspect.ts:359-360). "Inert is acceptable; unsafe is not" is the right priority order.
- **Outcome discipline (§6).** Discriminated outcomes, no assimilation, no hidden timeout, no post-arming env — each retires a verified concrete defect. The length-bearing-ABI prerequisite framing ("not a refinement") is correct: an embedded NUL truncates today at the `CStr` boundary.
- **Dialect ≠ module kind (§4).** The two-table split, the `.cjs`/JSON corrections it records, and the no-content-sniffing TS-grammar decision with documented `a<b>(c)` consequences are decision-quality work with matching acceptance criteria (AC5, AC6).
- **Acceptance criteria are mostly adversarial and behavioral** (instrumented thenables, embedded NULs, descriptor-identity `$_` aliases, per-stratum inspection instrumentation) rather than shape-based — the lesson LLP 0019 records.

## 3. Concerns

**C1. Free-identifier/closure binding time is unspecified — the model is not yet an algorithm. (Blocking)**
Evidence: §7 says "Name lookup for a free identifier resolves to the session cell; closures capture the cell" and "closures captured over the *old* cell keep seeing the old value" — but never says *when* a reference binds to a cell. Two divergent, defensible implementations: (i) bind at the referencing input's declaration-instantiation (V8 REPL-mode-like static slots); (ii) late-bind at each evaluation. They disagree observably on: I1 `let x=1`; I2 `const f=()=>x`; I3 `let x=2` (replacement); I4 `f()` → `1` under (i), `2` under (ii). Also undefined: a closure over a name *not yet declared* at capture (`const f=()=>x` before any `x` exists), then declared, then replaced. AC10 only pins the same-input capture case.
Resolution criterion: a normative binding-time rule covering (a) name bound at the referencing input's instantiation, (b) name unbound at instantiation and declared later, (c) both followed by replacement — with AC fixtures for each, such that the (i)/(ii) implementations above cannot both pass.

**C2. Redeclaration-then-throw is ambiguous between "prior cell restored" and "name destroyed". (Blocking)**
Evidence: §7 binds declarations "at the input's declaration-instantiation, before the input's statements run" (so replacement happens early), but publishes "at input completion", and on a throw "leaves the input's lexical cells unpublished — the name is free again and redeclarable." For I1 `const x=1`; I2 `let x = oops()` where `oops` throws: is `x` afterwards the old cell (`1`, replacement unpublished) or *free* ("free again" read literally — destroying a prior binding on a failed input)? A closure or `globalThis`-escaped function created inside the failing input adds a third observable (which cell did it capture?). AC11 covers only the fresh-name case.
Resolution criterion: a worked example pinning that a failed input's replacement leaves the previous cell published (or the deliberate alternative), plus what an escaped closure from the failed input observes; AC11 extended accordingly.

**C3. The globalThis-reflection sentence is factually wrong, and the deviation list fails its own exhaustiveness claim (three vs "four"). (Material)**
Evidence: §7 — "globalThis reflects var/function cells as **configurable**, writable properties, **as in ordinary script semantics**." Ordinary script semantics create *non-configurable* global var/function bindings (CreateGlobalVarBinding, deletable=false), and shipping Hermes agrees: my probe printed `configurable=false` for a top-level `var`. Configurable reflection is the right *choice* (cross-kind cell replacement needs to remove the property), but it is then a **deviation (d)** missing from the "complete list", whose §Consequences already says "four pinned deviations" while §7 lists exactly three — the exhaustiveness machinery is broken at round 1. Also unspecified: the property lifecycle on `var→let` replacement (delete? stale-but-shadowed? — observably different via `globalThis.x`), `let→var`, `delete globalThis.x`, and `defineProperty` over a var cell (real script semantics would throw on non-configurable; the cell model presumably permits it).
Resolution criterion: corrected sentence; deviation list updated and count reconciled; cross-kind property-transition and `delete`/`defineProperty` behavior pinned in AC10.

**C4. The direct/indirect `eval` clause contradicts LLP 0022 §1 and is unimplementable as written on Hermes. (Material)**
Evidence: §7 — "Direct eval sees the session record as its enclosing scope; indirect eval is a global script, as ECMAScript requires." LLP 0022 §1: `vm:evaluate` stays closed; "no prompt code gains `eval`, `new Function`, `vm`". So the clause is either dead text or a violation. And even where a profile admitted eval, the engine cannot deliver it: Hermes emits "Direct call to eval(), but lexical scope is not supported" and the eval'd code cannot see enclosing locals (verified with the bundled `tools/hermes/hermes` binary); `with` is a compile error, so no scope-object trick exists. Additionally, indirect-eval-created global *lexicals* live in the real global environment, not the session record — whether later inputs see them differs between the two OQ1 mechanisms, falsifying OQ1's "observable semantics are fixed either way."
Resolution criterion: delete the clause or scope it explicitly to profiles where eval is admitted, specify what is actually deliverable there (e.g., eval sees var-kind cells via globalThis only), and reconcile with 0022 §1 in the same change.

**C5. The engine premises of §7 are unstated, and the "TDZ/const hold exactly" claims exceed what the doc obligates anyone to build. (Material)**
Evidence: shipping Hermes has **no TDZ** (read-before-`let` yields `undefined`), reports `const` assignment as a *compile-time* error rather than ECMA's runtime `TypeError`, has no block scoping (`3,3,3` for-of capture — LLP 0019's founding premise), no `with`, no lexical eval, and — verified through the live `ibex repl` — no persistence of top-level `let` across evaluations (`let q = 7` then `q` → ReferenceError) and no cross-input `const` protection (`const cc = 9` then `cc = 10` → `10`). So §7's "TDZ within an input… hold[s]", "exactly ECMAScript's", and AC10's cross-input `const TypeError` are only achievable via whole-input identifier rewriting into kind/initialized-checked cell operations — a substantial mechanism the document never names, while OQ1 implies an engine-record alternative might exist. AC10 also never tests TDZ, so a non-conforming implementation would pass the suite.
Resolution criterion: state the engine premises (cite LLP 0019/0003) and their consequence — that v1's viable mechanism is an evaluator-owned record with checked cell access, or name the required engine work; add TDZ and late-const-assignment (`sideEffect(); c = 2` runs the side effect then throws) fixtures to AC10.

**C6. Stage-1 inspection's own examples violate its no-read rule. (Material)**
Evidence: §8 — "every non-primitive value renders opaquely by type tag (`[Object]`, `[Function: name]`, `[Array(3)]`) … No property is read, so no trap and no getter can fire." `[Function: name]` requires reading `name` (redefinable as a getter; a Proxy whose target is callable has `typeof === "function"` and traps the read); `[Array(3)]` requires reading `length` (`Array.isArray` is trap-transparent for proxies over arrays, so the follow-up `length` read fires the trap). The examples and the rule cannot both hold pre-primitive.
Resolution criterion: enumerate the trap-free stage-1 toolkit (`typeof`, `Array.isArray`, identity) and degrade tags to what it supports (`[Function]`, `[Array]`), or explicitly carve a documented residual-trap exception; AC14 updated to instrument `name`/`length`.

**C7. Throw-outcome payloads have no trap-free extraction story. (Material)**
Evidence: §6 promises a throw outcome carrying "the thrown value, a safe stack, and source positions", while §8 forbids running user code to format; extracting `.message`/`.stack` from a hostile thrown object is a property read (the current path does exactly that via `JSError::getMessage` and handler calls, hermes_runtime.cc:3178-3199). Pre-primitive, does a thrown hostile object display as a bare type tag (severe usability cost for *all* errors), or does the engine capture message/stack at throw time natively?
Resolution criterion: specify the pre-primitive throw-rendering rule and the source of "safe stack" (engine-captured at throw), with an instrumented hostile-error fixture.

**C8. The new result ABI obligates LLP 0002, which is neither Related nor amended. (Material)**
Evidence: §6 mandates a typed, length-bearing outcome ABI replacing the null-pointer/NUL-string contract of `ex_hermes_eval` — a public embedding surface owned by LLP 0002 (LLP 0003 §Boundaries; include/exact_runtime.h) with external embedder consequences. LLP 0002 is absent from the Related list; no amendment obligation is stated, unlike the careful LLP 0019 amendment clause in §4.
Resolution criterion: add LLP 0002 to Related with an "amended in the same change" clause mirroring §4's.

**C9. The transform-tier mapping to LLP 0019 misdescribes the tiers, so the shared corpus does not actually gate the new obligations. (Material)**
Evidence: §4 — "LLP 0019 fixes that the Hermes-compat rewrite exists in exactly two tiers… The evaluation seam does not add a third: prompt … sources are lowered by the **in-process runtime transform tier** — the same tier that handles on-the-fly file transpilation." LLP 0019's two tiers are the *for-of/Hermes-compat* rewrite specifically: the build-time AST authority (`hermes-compat.mjs`) and the embedded loader string scanner (`module-loader.js`). The in-process SWC transpile (src/module_loader/transpile.rs) is neither, and the 0019 corpus pins for-of/async-generator *behavior*, not source-goal preservation, source maps, or completion values — so "join the corpus over the same fixtures" gates none of this document's new obligations. Also §4's "pinned to a named parser/toolchain version" never names one (the implementation pins engines only via cache tags, transpile.rs:48-52).
Resolution criterion: name the SWC in-process stage as what it is, enumerate the new fixture families (goal preservation, source maps, completion values), state where they live, and amend LLP 0019 (or record that a new corpus section is created) in the same change; name the parser and version.

**C10. §5 (completeness) is normative but has zero acceptance criteria. (Minor/Non-blocking)**
Evidence: the current scanner is confirmed inadequate (no template-interpolation, regex, or TS awareness — repl/mod.rs:486-563), and LLP 0022 §3 leans on "LLP 0024 §5 completeness exactly," yet none of AC1-16 exercises continuation judgment or the fail-safe rule.
Resolution criterion: an AC with template-literal/regex/TS fixtures plus one ambiguity fixture asserting submit-and-recoverable-error.

**C11. Synthetic-identity details underspecified. (Minor/Non-blocking)**
Evidence: §2's `repl:<n>` "1-based session ordinal" doesn't say what increments `n` (commands? failed parses? `.load`?), and `.load`'s identity is "`repl:<n>`, annotated with the loaded file's virtual path" while AC2 says errors "report the file's virtual path" — the actual sourceURL string is ambiguous between the two.
Resolution criterion: pin the ordinal rules and the exact frame-identity string for `.load`ed content.

**C12. `$_` mechanics wobble between cell and property. (Minor/Non-blocking)**
Evidence: §7 says the evaluator "owns `$_` as a cell whose descriptor it records" — cells don't have descriptors; properties do. Whether `$_` is a var-kind cell (reflected, hence descriptor-bearing) or lexical (invisible to `globalThis.$_ =`, which would then create a *shadowed* property rather than "mutate the binding") changes which of the listed aliases are even observable; and the self-write discrimination (evaluator's own updates vs a user `$_ = $_`) is unstated.
Resolution criterion: state `$_`'s cell kind and the exact observation algorithm (descriptor + value + cell identity).

## 4. Cross-document findings

1. **Contradiction with 0022 §1 (eval)** — see C4. 0024 §7 specifies direct/indirect eval semantics for a surface 0022 §1 closes outright ("no prompt code gains `eval`"). One of them must yield; today neither cites the other on this point.
2. **Contradiction with 0025 §6 (cancellation arity)** — 0024 §6 states cancellation "resolves explicitly… yields one of" three outcomes; 0025 §6 normatively adds "**or not at all**" (defeated: the async break is a catchable throw user code can swallow) and defines *accepted* by actual return. 0024 acknowledges this only in OQ3; its normative §6 must carry the defeated/non-resolution state, since 0025's second-interrupt design depends on it.
3. **Tension with 0022 §3 (exit codes)** — 0024 §9: "An asynchronous failure never sets the session's exit code," but 0022 §3 gives program mode file-execution exit codes, and file execution treats these as fatal (ENG-23130 per LLP 0003; Node parity). Since 0024's execution modes include "program," scope the sentence: the *engine* never sets it; the consumer's lifecycle policy (fatal in file/program mode) may.
4. **Dangling: the structured render-piece schema.** 0025 §3 requires "structured style tokens with separately escaped payloads" and says LLP 0024 §8 produces them; 0024 §8 never defines an output format (only what may be read, bounds, tags) — its Consequences mention "structured pieces" in passing. Neither document owns the schema both depend on.
5. **Dangling: display-seam reachability.** 0022 §1 asserts the renderer uses a "private, non-JavaScript-reachable display seam (LLP 0024 §8)"; 0024 §8 never states that the descriptor walk / native primitive is closed to JavaScript. Since `runtime:inspect` surfaces are registry-closed, 0024 should say so explicitly or the primitive becomes an unclassified surface (LLP 0021's no-unclassified-surface invariant).
6. **Dangling: the env-variable inventory.** 0024 AC9 and 0025 AC3 both test "any inventoried variable," and 0024 AC9 adds `IBEX_LOCKDOWN`/`IBEX_ENDOW` classification — but no document defines where the inventory lives or how it's generated (contrast 0023's generated observables table, which names its generator).
7. **Dangling: supervisor/worker seam.** 0025 §7 makes a supervisor process with an engine *worker* presumptive; 0024's language is in-process ("delivered as a value handle", "the caller awaits that unit's settlement", evaluator-owned `$_` cell). Value handles don't cross a process boundary; which side runs inspection, holds handles, and owns the session record is unaddressed in either document.
8. **Duplication (consistent today, drift-prone):** module identity/cache is specified nearly verbatim in 0023 §2 + AC11 and 0024 §7 + AC13; the post-arming-env rule in 0025 §2 + AC3 and 0024 §6 + AC9; the TLA-unsupported error in 0022 §5/§6 and 0024 §3/AC7; `$_` in 0022 §5 and 0024 §7; the strict-profile open question in 0022 OQ3 and 0024 OQ4. Recommend each pair name a single owner and the other cite (the split's own rule — "the mechanism document governs its own layer" — implies 0023 owns module identity and 0025 owns env capture; 0024 currently restates both normatively).
9. **LLP 0019 tier mismatch** — see C9. **LLP 0002 omission** — see C8.

## 5. Suggestions

- **Make the deviation list mechanically checkable.** Build a differential fixture family: concatenate a session's inputs into one growing script, run both forms, and require any observable divergence to map to a pinned deviation (a)-(d). This turns "exhaustive" from a claim into a gate, in exactly the LLP 0019 corpus style, and would have caught C1-C3 automatically.
- **Name V8's REPL mode as the precedent and adopt its answered edge cases** (binding at compile-of-referencing-input; replacement appends; old slots persist) as the tie-breaker for C1, unless you deliberately diverge — then pin the divergence.
- **Specify the rewrite as the normative mechanism shape** (each input compiled with top-level declarations and free session-name accesses lowered to kind/initialized-checked cell operations against a hidden session object), since the engine facts (no `with`, no lexical eval, no TDZ, no persistent lexicals — all verified) leave no other v1 path. Keep observable behavior as the contract, but stop implying an engine-record option that stock Hermes doesn't offer.
- **Enumerate the trap-free toolkit for stage-1 display** (`typeof`, `Array.isArray`, `Object.is`, reference identity) and derive the tag vocabulary from it, resolving C6 by construction.
- **Define the §9 determination checkpoint concretely** as the `ex_hermes_poll` iteration boundary (LLP 0003 §event loop) and fold it, the async-storm window, and the session-ordinal rules into OQ6's versioned-constants question — ideally one constants annex shared with 0025 OQ5 rather than two parallel "bounded adjectives" lists.
- **Add a `.load`-vs-import worked example** (same `.ts` file: script-input with TLA and persisting declarations via `.load`; module with TLA refused via `import`) — it is the most user-visible consequence of the goal split and currently only derivable.
- **Extend sequence numbering from failure envelopes to all outcomes** (a session epoch on outcomes and async events) so transcript-mode flush ordering (0022 §3) and `$_` observations are provable rather than hoped.

## 6. Open questions

1. What is the binding-time rule for free identifiers across inputs (C1), and does it match or deliberately diverge from V8 REPL mode?
2. On a failed redeclaring input, is the prior cell restored (C2)?
3. Is the trap-free introspection primitive JavaScript-reachable-never (registry row), and which document owns the structured render-piece schema it feeds (cross-findings 4-5)?
4. Where does the session record live under 0025's presumptive supervisor/worker split, and what do "value handle" and "the caller awaits" mean across that boundary?
5. Does v1 ship TDZ emulation for session names only (checked cell access), and is local block-level TDZ inside an input explicitly out of scope on the current engine profile?
6. What increments the `repl:<n>` ordinal, and what is the exact sourceURL for `.load`ed frames?
7. Should restricted global names (`undefined`, `NaN`, `Infinity`, `globalThis`) be declarable/replaceable as session cells, where a growing script would raise the restricted-global-property SyntaxError?
8. Is the stage-1 (type-tag-only) REPL genuinely shippable given C7 makes *error* display opaque too — or does the throw path get engine-captured message/stack ahead of the general primitive?

## 7. Readiness verdict

The decision set is right and the evidence discipline is exemplary, but a Spec whose central section stakes its identity on being "an operational cell model, not a table of adjectives" cannot be READY while two implementers would diverge on closure binding time and failure-path redeclaration (C1, C2), while its "exhaustive" deviation list miscounts itself and omits a real deviation grounded in a factually wrong sentence (C3), and while one normative clause contradicts a sibling contract and the shipping engine at once (C4). All are repairable in one revision without disturbing the architecture.

VERDICT: NOT READY

### Orchestrator verification notes

Every decisive claim was independently re-checked against the repository, the
bundled shipping engine (`tools/hermes/hermes`), and the Node/Deno/Bun REPLs.

**Confirmed (code).** The whole indictment in §1 of the review checks out at the
cited lines: `Engine::eval` → `Result<Option<String>>`
(`src/bin/ibex/engine/mod.rs:34`); `<eval>` hardcoded (`hermes.rs:1517,1524`);
`undefined` → null pointer (`hermes_runtime.cc:3161-3164`) → `Ok(None)`
(`hermes.rs:911-917`); thenable assimilation (`hermes_runtime.cc:3044-3057`);
`IBEX_AWAIT_UNWRAP_TIMEOUT_MS` `getenv`'d inside the eval call with a hidden
10 000 ms default (`hermes_runtime.cc:3089-3100`); no source map from the SWC
emitter (`transpile.rs:189`, the trailing `None`); wrapper-prefix position
arithmetic (`repl/mod.rs:874`); the async-IIFE TLA wrap that discards declarations
(`repl/mod.rs:1174-1186`); a declaration printing `undefined`
(`repl/mod.rs:888-890`); and `fatal_async_error` poisoning the pump
(`hermes_runtime.cc:673-692`).

**Confirmed (engine probes).** Every engine premise in C4/C5 reproduced on
`tools/hermes/hermes`:

| Probe | Result |
| --- | --- |
| `var vv = 1` descriptor on `globalThis` | `configurable=false` — **C3 confirmed**; §7's "configurable … as in ordinary script semantics" was wrong on both halves |
| read a `let` before its declaration | `undefined` — **no TDZ** |
| `const c = 1; c = 2` | **compile-time** "invalid assignment left-hand side", not a runtime `TypeError` |
| `with (o) {}` | compile error, "with statement is not supported" |
| direct `eval` reading an enclosing local | "Direct call to eval(), but lexical scope is not supported"; the local is not visible |
| `for (let i…)` closure capture | `3,3,3` — no per-iteration binding, no block TDZ |

**C9 (LLP 0019) and C8 (LLP 0002) — confirmed, and both were load-bearing.**
LLP 0019's tiers are the Hermes-compat for-of/async-generator rewrite (AST
authority `hermes-compat.mjs`; bootstrap scanner in
`src/engine/bootstrap/module-loader.js`), not the SWC/Oxc TypeScript/ESM lowering
in `src/module_loader/transpile.rs` that this document actually extends. And
`llp/0002-host-embedding-abi.spec.md` §"The narrow consumer contract
(semver-major)" explicitly owns `ex_hermes_eval(…, out_value)` — "on success
`out_value` points to a malloc'd result string (or NULL for `undefined`)" — the
exact ABI §6 retires. Both are fixed in this revision; LLP 0002 is added to
Related with an amendment obligation.

**C10, C11, C12, C1–C7 — accepted** and addressed in the revision (completeness
ACs; ordinal and `.load` identity rules; `$_` respecified as a native accessor
pair so that same-value writes and `defineProperty` ABA are detectable without an
engine hook; binding-time rule; rollback rule; corrected deviation list and count;
stage-1 tag vocabulary derived from a trap-free toolkit; engine-captured
message/stack for the throw outcome).

**Refuted / not adopted.**

- The review's characterization of the current pin as "exactly V8's REPL-mode
  design", and its suggested tie-breaker for C1 — "binding at
  compile-of-referencing-input; replacement appends; **old slots persist**" — are
  backwards. I probed the precedent: **Deno 2.9.1 and Bun 1.3.12 both yield `2`**
  for `let x=1` / `const f=()=>x` / `let x=2` / `f()`, i.e. V8/JSC REPL mode makes a
  redeclaration visible to closures created earlier; old slots do **not** persist.
  (Node 25 sidesteps the question by refusing cross-input `let` redeclaration as a
  `SyntaxError`.) Adopting the suggested tie-breaker would have hard-coded the
  divergence C1 was raised to remove — and would have broken plain `var` semantics,
  since `var v=1; const g=()=>v; var v=2; g()` must yield `2` (Deno confirms). The
  revision therefore adopts **late binding by name through the session record**:
  the flagship shared-cell result still holds, `const` stays immutable against
  assignment (Deno confirms `TypeError`), `var` is correct, and rollback becomes
  coherent. I verified on the shipping Hermes binary that a checked-cell record
  delivers all of it — shared cells, late-bound redeclaration, a runtime `const`
  `TypeError`, and a real TDZ `ReferenceError` — none of which Hermes provides
  natively, which also settles C5's mechanism question and retires OQ1's false
  "observably interchangeable" claim.
- C7's premise that an opaque throw payload would be a "severe usability cost for
  *all* errors" is accepted as a concern but not as a constraint: the throw outcome
  now carries an **engine-captured** message, stack, and positions taken at throw
  time (which is where Hermes already has them, `JSError`), so ordinary errors
  render fully in stage 1. Only a *hostile non-Error thrown value* renders by type
  tag. That is the right trade and it is now stated.

## Round 2 — 2026-07-12

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose`
subagent launched in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `33b29b0e83d4` — the first 12 hex digits of
`shasum -a 256` over the target file, not a Git object.
**Redaction:** none.
**Independence:** launched concurrently with the Codex reviewer on the same
revision. **Both round-1 artifacts were moved out of `llp/reviews/` before launch
and restored only after both round-2 reviews were in**, so neither reviewer could
see the previous round or each other.
**Sibling drift (material to this round):** between round 1 and round 2 the sibling
corpus was revised concurrently by other work — LLP 0022 grew from 580 to 866 lines
and LLP 0025 from 507 to 858. This reviewer read the revised siblings, which is why
its cross-document findings (X1–X9) are new: LLP 0022 had newly closed
`require.main`, newly pinned `.load` of JSON, and newly obliged a fifth outcome.
**Method:** read the full target, the sibling corpus, and the governing LLPs; then
independently re-verified the target's **empirical claims** — the eight engine
premises against `tools/hermes/hermes`, the code claims against source, and the
Deno/Bun precedent claims against those runtimes. The brief explicitly instructed
it not to take the Engine-premises table on trust.
**Transport note:** captured verbatim from the subagent's final message; the agent
transport HTML-escaped `<`/`>` inside code spans and those escapes are decoded
here. No other alteration.

### Verbatim review

# Review: LLP 0024 — Structured Evaluation and Session Semantics (rev 33b29b0e83d4, round 2)

## 1. Overall assessment

This is a strong, unusually honest spec, and the right document to exist: it correctly identifies that every defect in the current seam (verified below, all real) is a convenience overriding a language or security rule, and it replaces them with a seam where the rule is structural. The round-1 revision visibly improved it — the checked-cell record with late binding is the right model (I verified its flagship semantics against Deno and Bun, and both agree, including for the subtle same-input-closure variant), entry-only TLA is the only honest answer on a synchronous `require()` runtime, the staged inspection contract refuses to pretend, and §6's structural non-assimilation (private control token + out-of-band result slot) is genuinely good design rather than a rule the implementation is asked to remember.

Three things keep it from READY. First, the **0022/0024 seam has drifted**: 0022's round-5 revision (same day) fixed things 0024 still asserts — `require.main` most seriously — and the two documents now contradict each other on `.load` of `.json` and on the ordinal, which 0022's own precedence rule calls an invalid corpus state. Second, **§7 is about 85% of an algorithm**: I found specific corners — `globalThis` property/cell coexistence, instantiation-phase failure vs. rollback exception (i), the undefined value of a new `var` cell after a failed input, a cross-kind hoisting divergence unmapped to any deviation — where two independent implementers would diverge, and where the growing-script oracle as defined cannot adjudicate. Third, **one empirical claim is false**: Bun does *not* throw `TypeError` on assignment to a prior-input `const` (verified on Bun 1.3.12: `c = 10` succeeds and `c` becomes `10`), so the precedent argument for the model's most user-visible property is overstated. All of this is fixable by editing plus a small amount of verification work; none of it requires rethinking the architecture.

Every load-bearing engine premise checked out against the bundled binary, and every claim about the shipping code checked out against the source — the document's empirical discipline is real, with the one exception noted.

## 2. Strengths

- **Engine-premises section (§Engine premises) is exemplary and accurate.** I independently verified all eight premises against `tools/hermes/hermes`: `let` read before declaration yields `undefined` (no TDZ); `const c=1; c=2` is a compile-time error ("invalid assignment left-hand side") that pre-empts *all* execution; `with` is a compile error; direct `eval` cannot see enclosing locals ("lexical scope is not supported", `typeof local` → `undefined`); `for (let i…)` closures capture `3,3,3`; global `var` is non-configurable (`configurable: false`); top-level `let` is not a `globalThis` property; and cross-evaluation lexical persistence is absent (verified via the ibex REPL: `let zz = 41` then `zz` → `ReferenceError`). Deriving the three consequences (evaluator-owned record is the *only* option; no `with` trick; no `eval` semantics) from measured facts is exactly how a spec on this engine should argue.
- **The motivation's code claims are all true.** `Option<String>` with NULL-means-undefined (`src/bin/ibex/engine/hermes.rs:911-917`, `src/engine/hermes_runtime.cc:3161-3174`); hardcoded `<eval>` (`hermes.rs:1517`); thenable assimilation on any callable `then` (`hermes_runtime.cc:3048-3051`), compiled out on Windows (`hermes_runtime.cc:3038`); post-arming `getenv("IBEX_AWAIT_UNWRAP_TIMEOUT_MS")` (`hermes_runtime.cc:3090`); the async-IIFE lowering that discards `const x = await f()` (`src/bin/ibex/repl/mod.rs:1174-1186`); wrapper-prefix position arithmetic (`repl/mod.rs:107-127, 874`); no source maps from the transform (`src/module_loader/transpile.rs:189`, `JsWriter::new(…, None)`); the three inconsistent dependency-TLA behaviors (SWC pass-through `transpile.rs:100-107`; Oxc ad-hoc bail `transpile.rs:212-217`; scanner blind to plain TLA `src/module_loader/mod.rs:284-295`); per-call env-var transform selection (`transpile.rs:64-78, 89`); JS throw and engine fault both `return 1` + string (`hermes_runtime.cc:3178-3238`); the uncaught-handler path converting a throw into success (`hermes_runtime.cc:3182-3193`); the runtime lock held across the whole native eval so cancellation cannot be delivered (`hermes.rs:877-896`); `EngineFeature` conflating native and evaluator capability (`hermes.rs:1658-1660`).
- **§7's late-binding decision is correct and now precedent-verified.** Deno and Bun both yield `2` for the flagship across inputs, *and* both yield `2` when the closure is created in the same input as the original declaration — so uniform late binding by name matches the permissive-redeclaration precedent even in its subtlest corner. The `var`-coherence and rollback-coherence arguments (§7.2) are sound.
- **Entry-only TLA (§3) is the right default, stated honestly.** The role field on the source request, detection on resolved kind rather than text scan, one named error, and graph preflight are all well-chosen; refusing to ship "a plausible-looking lowering that is wrong under cycles" is the correct posture for a loader that is a synchronous `require()` chain (LLP 0004, `transpile.rs:97-107`).
- **§6's settlement/delivery split is the standout design decision.** Recognizing that resolving the driving promise *with* the user's value would re-introduce assimilation via ordinary promise resolution — and therefore requiring a non-thenable control token and a rooted result slot — makes non-assimilation structural. The completion-record treatment (naming `UpdateEmpty`, declaring the last-expression heuristic non-conforming with the exact counterexamples) is precise and testable.
- **§8's staging is honest where most specs hand-wave.** The stage-1 toolkit derivation (why `[Function: name]` and `[Array(3)]` violate the rule the earlier draft broke) is airtight, and the current `inspect.ts` confirms the problem is real: `safeGet` does raw property reads for duck-typing (`packages/ibex-runtime-js/src/inspect/inspect.ts:90-96`) and emits pre-colored ANSI (`inspect.ts:60-79`) — exactly what §8 and LLP 0025 §3 retire.
- **§7.7's deviations-as-gate** (replay against a growing-script oracle; unexplained divergence fails the build) is the LLP 0019 discipline correctly transplanted — the right way to make "exhaustive" a property rather than a claim, modulo the oracle-domain gap in Concern 5.
- **§4's transform-authority correction** is accurate: this seam extends `src/module_loader/transpile.rs`, not LLP 0019's for-of tiers, and the LLP 0019 amendment tripwire is good hygiene.

## 3. Concerns

**C1. The Bun `const` claim is false — a load-bearing precedent claim in normative rationale.** *Severity: Material.* Evidence: §7.2 ("Deno and Bun both … still throw `TypeError` on assignment to a prior `const`"). Verified: Deno 2.x throws `Uncaught TypeError: Assignment to constant variable`; **Bun 1.3.12 accepts `c = 10` after `const c = 9` and `c` becomes `10`**. The design choice (preserve `const` immutability) remains right — it matches Deno, the language, and the document's own "not a compatibility concession but a new language" argument — but the evidence as stated is wrong, and the model's most user-visible strictness now *diverges* from one of the two cited precedents. Resolution: correct the sentence, cite Deno + ECMAScript as the authority, record the Bun divergence explicitly (with the measured version, per the LLP 0004 oracle-pinning house style), and note it under a compatibility-priority argument.

**C2. The cell storage model is incoherent at the `globalThis` boundary — §7.1/§7.2's value-cells vs. §7.5/§7.8's object-environment semantics.** *Severity: Material.* Evidence: §7.1 defines a cell as `{kind, initialized, value}` and §7.2/Engine-premises consequence 1 specify *lowering free session names into cell operations*; but §7.5 requires `globalThis.x = 1` on an undeclared name to create a cell (unobservable to an evaluator-owned map without object-environment backing), requires `Object.defineProperty(globalThis, 'x', …)` over a `var` cell to *succeed* (an accessor is unrepresentable as a `value`), and §7.8 *requires* a bare-identifier write `$_ = v` to invoke the runtime's setter installed on the `globalThis` property — which only happens if `var`-kind names resolve through an object environment record, not through a lowered cell-get/cell-set. Worse, the map-from-name-to-cell cannot represent the ordinary Script state `let x = 1; globalThis.x = 2` (lexical binding *coexisting* with a plain global property; oracle: `x === 1`, `globalThis.x === 2`) — the document is silent, and a naive implementation (create/replace a `var` cell) diverges from the oracle with no deviation to map to, making a conforming-looking implementation fail AC13 by construction. Resolution: state the hybrid model explicitly — `var`/`function` cells are *stored as* `globalThis` properties (the record row is bookkeeping for kind/replacement; the property is the storage, so accessors and reflection behave per object-environment semantics), lexical cells are evaluator-owned — and define the lexical-cell/global-property coexistence case; add fixtures for `let x` + `globalThis.x = 2`, defineProperty-accessor-then-identifier-read, and `$_ = v` via bare identifier.

**C3. Instantiation-phase failure contradicts rollback exception (i).** *Severity: Material.* Evidence: §3 "an import that throws means the input publishes nothing and none of its statements run" (also AC4) vs. §7.4 "(i) `var` and `function` cells for names that had no prior cell remain … exactly as a throw in a script does not un-hoist." Both imports and `var` hoisting occur at declaration-instantiation (§3, §7.3), whose internal order is unspecified — so for `import bad from 'boom'; var w = 1`, §7.4(i) says `w` remains and AC4 says nothing publishes. Two implementers, two answers. Resolution: define instantiation order (e.g., restricted-global check → lexical/var/function binding → import execution, or imports first) and state the precedence rule: *instantiation-phase* abrupt completion publishes nothing; *execution-phase* abrupt completion follows §7.4. One paragraph plus a fixture.

**C4. "Surviving cell" is undefined, so the rollback rule's exceptions (i) and (ii) conflict on the most common failure case.** *Severity: Material.* Evidence: §7.4. For `var w = 1; boom()` with no prior `w`: exception (i) says the cell remains "initialized as hoisting left them" — hoisting leaves `w` as `undefined` — while the oracle (and exception (ii), *if* a newly created cell counts as "surviving") gives `w === 1`, since a throw in a script does not undo the executed assignment. AC12 pins that the cell *remains* but not its *value*. The same ambiguity governs §7.3's destructuring hand-off ("the abrupt-completion path of §7.4 … is what actually determines what survives") for `var [a, b] = failingIter()`. Resolution: define *surviving* = any cell present after rollback (restored or retained), and state that every write through a surviving cell stands including writes made during the failed input; pin `var w = 1; boom()` → `w === 1` and a partial `var`-destructuring case in AC12.

**C5. The growing-script oracle is undefined over exactly the sessions §7.4 exists for.** *Severity: Material.* Evidence: §7.7 "replays each session's inputs as one growing script, runs both forms" and AC13. A session containing a failing input cannot be replayed as one growing script — the script aborts at the throw and never runs the later inputs, so post-failure state (the entire subject of §7.4 and deviation (c)) has no oracle; sessions using TLA or imports are not legal Scripts at all; and the compared observables (final record? `globalThis` state? per-input completion values? stdout?) are unstated. As written, the headline "mechanically checkable, not merely asserted" is not yet an executable definition. Resolution: define the oracle's domain and transformation per session class (e.g., failure-free prefixes replay as one script; failing and TLA sessions are pinned by direct AC12/AC8-style fixtures instead), and enumerate the compared observables in the corpus schema.

**C6. A real cross-kind divergence is unmapped by the deviation list: later-input `function` over committed `var`.** *Severity: Material.* Evidence: §7.3 matrix ("`var`/`function` → `var`/`function`: reuse … a function redeclaration overwrites the value") + §7.7. Session: input 1 `var x = 1`; input 2 `function x(){}` → `x` is the function. Growing script `var x = 1; function x(){}`: whole-text hoisting initializes `x` to the function at instantiation, then the statement `x = 1` executes — `x === 1`. Observable divergence; deviation (e) as worded covers only "a call in one input cannot reach a function declared in a later one," not initialization-order overwrites, so AC13's gate has a divergence with no pinned deviation to map to. Resolution: reword (e) to cover *all* whole-text-hoisting divergences (forward reference *and* instantiation-order effects), or add deviation (f); add the fixture.

**C7. The "Script early-error rules extended with imports/TLA" parse goal may be unimplementable on the pinned parser as configured — and the spec both pins the parser and forbids the workaround.** *Severity: Material.* Evidence: §3 ("parsed under Script early-error rules extended with `ImportDeclaration` and top-level `AwaitExpression` — not parsed as a Module and patched afterwards"), §4 (pin to `swc_ecma_parser`). swc offers Script and Module goals (`transpile.rs:120-136` uses `parse_program`, which promotes to Module on seeing `import`); it has no Script-plus-import mode, and Module parsing rejects sloppy-only *parse-level* forms (legacy octal literals, `delete identifier`, duplicate parameters) that the stated goal must accept. The fixture family ("Source-goal preservation") tests runtime strictness effects (undeclared assignment, `this`) but no sloppy-only parse form, so the gate as listed would not catch a Module-goal-based implementation for those. Resolution: demonstrate a concrete mechanism on the pinned parser (custom goal/fork, or pre-extraction with proof it preserves early errors), or narrow §3 to the achievable early-error set as a documented narrowing; add sloppy-only parse forms (octal, `delete x`) to the fixture family.

**C8. `await` as an identifier in entry script inputs is an unresolved grammar ambiguity.** *Severity: Material.* Evidence: §3 admits top-level `AwaitExpression` into a *sloppy Script*, where `await` is otherwise a legal identifier — so `var await = 1`, `await(x)`, and `function await(){}` at the prompt are ambiguous between the base grammar and the extension. AC8 pins only the *dependency* side ("a CommonJS module using `await` as an identifier is not misclassified"); nothing pins the entry side. Resolution: state the rule (recommend: `await` is reserved at the top level of script inputs, a documented narrowing mirroring the module goal — Node's REPL does the same) and add it to the source-goal fixture family.

**C9. Stage-1's error carve-out quietly requires engine machinery the document doesn't enumerate.** *Severity: Material.* Evidence: §8 "Errors are the exception … engine-captured message, stack, and positions, taken at throw time from the engine's own error state rather than by reading `.message`/`.stack` off the thrown object," and "only a *hostile non-`Error`* thrown value renders by type tag." Two gaps: (a) on stock JSI the only capture path *is* property reads — `jsi::JSError` populates message/stack via Gets, and the current seam uses `err.getMessage()/getStack()` (`hermes_runtime.cc:3199-3208`) — so `throw {get message(){…}}` runs user code during capture unless Hermes is patched to expose VM-level thrown-value state; (b) *classifying* a thrown value as ordinary-`Error`-vs-hostile is a brand/Proxy check the stage-1 toolkit (`typeof`, `Array.isArray`, identity) cannot perform. The error carve-out is therefore not toolkit-only; it needs a narrow native slice (`IsNativeError` brand + own-data-property read, or VM throw-state capture) that is effectively a piece of the stage-2 primitive. Resolution: either enumerate throw-time error capture as its own engine obligation (alongside OQ 1 and OQ 3, plausibly one patch), or stage error rendering explicitly and let stage 1 render even ordinary errors from whatever the engine can capture trap-free today.

**C10. AC11's "executable table" does not mark input boundaries, and some fixtures are meaningless or illegal as single inputs.** *Severity: Material (testability).* Evidence: AC11 writes the flagship as `let x = 1; const f = () => x; let x = 2; f()` on one line — as *one* input that is a redeclaration `SyntaxError`; split differently, the shared-cells fixture `…; x = 2; f()` passes under *any* publication model (including copy-out) unless the write crosses an input boundary. §7's code block implies line = input; the ACs imply nothing. Resolution: adopt an explicit input-boundary notation in every AC-11/12/13 fixture (and in the corpus schema), so each fixture is a list of inputs with per-input expected outcomes.

**C11. Restricted-globals rule is overbroad.** *Severity: Minor/Non-blocking.* Evidence: §7.3 "A **declaration** that would shadow a non-configurable global property … is a `SyntaxError`, as in a Script." In a Script only *lexical* declarations are restricted; `var undefined` is legal and inert — so a literal implementation of §7.3 diverges from the oracle with no deviation to map to. (AC11's own example, `let undefined`, is correctly lexical; Hermes agrees, rejecting it at compile time.) Resolution: say "a lexical declaration."

**C12. The lowering's sloppy-read edges are unstated: `typeof x` on a missing cell must not throw.** *Severity: Minor/Non-blocking.* Evidence: §7.2 "A free identifier whose name has no cell throws `ReferenceError` when evaluated" — a naive lowering of every free identifier to a throwing cell-get breaks `typeof x` (and sloppy `delete x`). The oracle would catch it only if a fixture exists; the §4 session-lowering family doesn't name one. Resolution: one sentence (`typeof`'s operand resolves to `undefined` for a missing cell, per Script semantics) plus a fixture.

**C13. §4's evaluation-by-kind table contradicts §3's goal table on TLA unless the reader applies the role rule.** *Severity: Minor/Non-blocking.* Evidence: kind table row "ESM … TLA: no (v1)" while §3 gives program-mode stdin (a module, ESM-shaped) TLA *yes*; the tables disagree on their face because admission is by *role*, not kind. Resolution: change the kind-table cell to "entry role only (§3)".

**C14. AC8 is unsatisfiable as worded for computed dynamic imports.** *Severity: Minor/Non-blocking.* Evidence: AC8 requires the dependency-TLA error "raised by graph preflight **before** the entry runs" for "static, dynamic, and transitive imports" — a computed `import(expr)` target is not statically discoverable, so its refusal necessarily happens at call time (§3's own text says preflight covers the "statically discoverable" graph). Resolution: split the criterion — preflight for the static graph; the *same named error* at call time for dynamic.

**C15. `$_`'s accessor pair contradicts §7.5's stated reflection shape.** *Severity: Minor/Non-blocking.* Evidence: §7.5 pins `var` cells as "writable, enumerable, configurable" data properties; §7.8 installs `$_` (a `var`-kind cell) as an accessor pair. Resolution: note `$_` as a runtime-owned exception to the descriptor shape (it already is one semantically), so the generated observables/descriptor fixtures don't trip on it.

**C16. "Poisons the pump" slightly overstates the current behavior.** *Severity: Minor/Non-blocking.* Evidence: §9 "the current behavior, in which a native async error logs directly and poisons the pump" — the shipping flag is deliberately one-shot so the next poll succeeds (`hermes_runtime.cc:690, 715, 976-983`; LLP 0003 §Event loop: "one-shot so a REPL survives it"). The real (and sufficient) complaint is that the *engine layer* decides fatality by returning `-1` from poll at all. Resolution: adjust the characterization; the normative direction is unchanged.

**C17. Engine premises are verified on one binary; at least one premise is known to vary by target.** *Severity: Minor/Non-blocking.* Evidence: §Engine premises ("verified against the bundled Hermes"); meanwhile `hermes_runtime.cc:3035-3037` records that the Windows Hermes eval path "does not support async function syntax", which — if still true — breaks the async-wrapper TLA lowering on an advertised target (LLP 0001). Resolution: make the premise table per-advertised-target (or state that conformance is claimed only where the premises are re-verified), and verify/retire the Windows comment.

## 4. Cross-document findings

**X1. `require.main` — direct contradiction with 0022, on a security-classified surface.** LLP 0024 §4 (line 326-328): "`require.main` names the session's main module — which for program stdin is `ibex:stdin` (LLP 0022 §3)". LLP 0022 round-5 *explicitly fixed this*: §1 "This contract does **not** reopen `require.main` or `process.mainModule`" (0022:162-172), §3 "**no `require.main`** — that surface stays closed" (0022:284), §11 ledger "`require.main`/`require.cache` kept closed" (0022:637), and the revision header names "the `require.main` … errors" as fixed. 0024 cites 0022 §3 *for support of the sentence 0022 §3 now negates*. Under 0022's precedence rule this is an invalid corpus state. Fix: delete/replace the 0024 sentence (entry identity is `import.meta`, per 0022 §1/§3) in a coordinated revision.

**X2. `.load` of `.json` — direct contradiction.** 0024 §4: "`.load` of `.json` or `.d.ts` is a **hard error** (neither is a program — `import` the JSON instead)" (also AC5). 0022 §8: "a `.json` file displays the parsed value and declares nothing" (0022:562-564), enforced by 0022 AC11. Same-day revisions, opposite pins. Also lesser drift: 0024 refuses `.load` of `.mjs`/`.cjs`; 0022's pinned refusal list (`.d.ts`, unknown, extensionless) omits them while claiming to accept "exactly the dialects LLP 0024 §4 defines." Fix both in one pass; I'd keep 0024's hard error (a `.load` that displays but declares nothing is a false affordance) and amend 0022 §8/AC11.

**X3. The `repl:<n>` ordinal — contradiction on `.time`.** 0024 §2: the ordinal "does not advance for a REPL command (LLP 0022 §8)" (with `.load` carved out). 0022 §5: it "advances once per **evaluated source**: each submitted prompt or transcript input, each **`.time` argument**, and each `.load` body." Under 0024 alone, `.time`'s evaluated argument has no identity at all. Fix: 0024 should adopt 0022's evaluated-source rule (commands advance it iff they evaluate source).

**X4. The fifth (lifecycle) outcome — dangling dependency, unacknowledged.** 0025 §8 and 0022 §10/§11 both require the uncatchable cooperative exit to surface as "a fifth outcome alongside empty / value / throw / cancelled (LLP 0024 §6 is amended in the same change)"; 0022's ledger row marks it *not yet* against 0024 §6. Round-2 0024 neither adds it nor forward-references it — an implementer of §6's ABI as written mints a four-tag outcome enum that needs another semver-major bump. Fix: add the outcome (or at minimum a normative forward note naming the pending amendment) in §6.

**X5. Background-callback cancellation target — half-delivered amendment.** 0025 §6: "LLP 0024 §6's enumeration is amended in the same change to admit both the unresolved case **and the non-evaluation target**." 0024 round-2 added *defeated* (the unresolved case) but §6 still defines all four resolutions over "the evaluation"; what a cancellation request means against a *background callback* (no input, no record transaction — presumably: effects stand, no publication question) is unstated. Fix: one paragraph in §6.

**X6. Submission provenance on the source request — obligation not yet carried.** 0022 §7/§11 oblige LLP 0024 §1 (with the LLP 0021 evidence schema) to carry unforgeable operator-submission provenance binding "the snapshot digest, the run nonce, the root identity, the source identity, and the ingress kind." §1's *authenticated context* field (snapshot, principal, endowments) covers part; no provenance/nonce field is named ("execution mode" is a drain-policy selector, not evidence). Fix: name the field in §1's table or explicitly defer to the 0021 schema row with a *pending* marker mirroring 0022's ledger.

**X7. Out-of-snapshot import error — assigned to 0024 §2, absent.** 0022 §2/§11 require a distinct out-of-snapshot error, "distinct from a resolution failure and from a policy denial," owned by "LLP 0024 §2 (resolver errors)". §2 defines only the reserved-scheme errors; no import-gate error taxonomy exists. Fix: add the taxonomy row (or re-home the obligation deliberately).

**X8. Display-acknowledgement seam — 0024's half now exists; 0025's half doesn't.** §7.8 states the evaluator side ("updates it on the consumer's display acknowledgement"), addressing 0022's ledger row; LLP 0025 §3's broker never mentions emitting an acknowledgement. Residual gap is on 0025, but 0024 should cite where the ack comes from (0025 §3) so the seam is named on both sides.

**X9. Stale cross-references.** 0024 OQ 6 cites "LLP 0025 OQ5" for the shared constants annex — 0025's bounded-adjectives question is **OQ 6** (OQ 5 is supervisor scope; 0025:847-853). 0024 §6 calls 0025 §7's split "presumptive"; 0025 round-1 upgraded it to "the specified realization" with a conformance-gated in-process alternative. Also §6 amends LLP 0002 but not LLP 0000, which 0002 says must move together (0002 §Notes). All trivial fixes.

**No contradictions found with LLP 0023**: §1's virtual referrer, §2's identities and reserved schemes, §7.9's deference on module identity (0023 §2, AC11), and the `__filename`/`__dirname` absence rule (0023 §6) all line up cleanly.

## 5. Suggestions

- **Specify §7 as ECMAScript's own global environment, modified.** The model you have converged on *is* a GlobalEnvironmentRecord — an object record on `globalThis` for `var`/`function`, a declarative checked record for lexicals — with exactly three modifications: per-input redeclaration as cell replacement, configurable `var` properties, and per-input instantiation. Saying so (and writing §7.3/§7.4 as deltas against `GlobalDeclarationInstantiation` and script evaluation) imports two decades of specified edge cases and resolves C2, C3, C11, and the `let x`/`globalThis.x` coexistence by construction, at the cost of half a page.
- **Pin runtime precedents the way LLP 0004 pins Node oracles.** The Bun finding shows precedent claims drift; a tiny differential harness that pipes the AC11 input lists through Deno/Bun/Node at recorded versions would keep §7.2's rationale measured rather than remembered.
- **One Hermes patch, three consumers.** OQ 1 (trap-free introspection), OQ 3 (completion-record discriminator), and C9 (throw-time error capture) are plausibly one VM-surface patch. Also investigate whether the debugger build's variable/property inspection path (`HERMES_ENABLE_DEBUGGER`, LLP 0003 §map) already reads own properties and internal state without invoking traps — the stage-2 primitive may be mostly extant behind an API you already vendor, which would materially change OQ 1's cost estimate.
- **Give the corpus an input-boundary schema now** (C10/C5): each fixture = ordered inputs, each with expected outcome kind, published record delta, and display; the growing-script oracle then becomes a *derivation* over failure-free fixtures rather than a separate mechanism, and AC13's gate is fully defined in one place.
- **Consider naming a stage-1.5**: with only the `IsNativeError`-and-data-read slice (C9), ordinary `Error` display and `Array.isArray`+`[Array]` are safe; that slice is much cheaper than the full primitive and removes stage 1's worst UX cliff while keeping the staging honest.
- Fold the §7.2 "only rule that keeps `var` correct" bullet down to what it proves: under the matrix's own `var`-reuse row, capture semantics would also yield 2 for the `var` case; the decisive arguments are the lexical-replacement flagship and rollback coherence.

## 6. Open questions

1. Can the pinned swc parser be configured or minimally forked to implement Script-goal-plus-`ImportDeclaration`/TLA with the correct sloppy early-error set (C7), and if not, which parse-level narrowings does v1 accept and document?
2. Is `await` a reserved word at the top level of entry script inputs (C8)?
3. Where does trap-free throw-time error capture live — a Hermes VM patch, a JSI extension, or an accepted stage-1 narrowing (C9)? Should it join OQ 1/OQ 3 as one patch program?
4. What is the growing-script oracle's exact domain and observable set, and how are failing, TLA-bearing, and import-bearing sessions adjudicated (C5)?
5. Do the engine premises hold per advertised target — specifically, is the Windows eval-path async-function limitation (`hermes_runtime.cc:3035-3037`) real, and if so what does entry TLA ship on Windows (C17)?
6. Which document owns the single post-arming environment inventory? §6 says 0025 §2 owns it; 0025 §2 says it contributes only presentation rows — name one owner and one annex (ties into the OQ 6 constants annex and X9).

## 7. Readiness verdict

The architecture, the defaults, and the empirical discipline are right, and round 2 fixed what round 1 was told to fix. What remains is: two direct sibling contradictions and several half-delivered sibling obligations on a seam whose whole purpose is coherence (X1-X7); a §7 that is nearly-but-not-yet an algorithm at the `globalThis`, instantiation-failure, and rollback edges (C2-C6, C10); one false empirical claim in the model's rationale (C1); and two understated feasibility items (C7, C9). Every fix is editorial or small-scope verification; none threatens the design.

VERDICT: NOT READY

### Orchestrator verification notes

**C1 — confirmed, and it was my own error.** I re-ran the probe: on **Bun 1.3.12**,
`const c = 9` then `c = 10` leaves `c` as **10** — no `TypeError`. On **Deno 2.9.1**
the same sequence throws `Uncaught TypeError: Assignment to constant variable`. The
round-1 revision asserted that *both* enforce it, which was false, and it was
asserted in support of the model's most user-visible property. §7.2 now cites Deno
and ECMAScript as the authority and **records the Bun divergence explicitly** as a
deliberate decision, with the measured version. This is exactly the failure mode
LLP 0005's honesty rules exist to catch, and it is worth noting that the reviewer
caught it only because the brief instructed it to re-verify the empirical claims
rather than trust them.

**C2 — confirmed, and it drove the round's largest change.** The reviewer's
suggestion (§5, first bullet) is right and I took it: §7 is now specified as a
**modified ECMAScript `GlobalEnvironmentRecord`** — an object record on `globalThis`
where the *property is the storage* for `var`/`function`, plus an evaluator-owned
declarative record for lexicals. That resolves C2, C11, C12, C15, and the
`let x = 1` / `globalThis.x = 2` coexistence case **by construction**, and it fixed a
defect neither reviewer's numbered concerns named outright but Codex's did: the
previous draft made a free identifier with no cell a `ReferenceError`, which would
have made `Object` unreachable.

**C3, C4, C6 — confirmed as genuine self-contradictions and fixed.** §7.3 now
enumerates six evaluation phases; abrupt completion in phases 1–5 publishes
**nothing** (so `import "./boom"; var w` leaves no `w`), while phase 6 follows the
rollback rule. *Surviving* is defined, and `var w = 1; boom()` is pinned to leave
`w === 1` — the reviewer's oracle reading is correct. Deviation (e) is reworded to
cover initialization-order divergences, with the reviewer's own
`var x = 1 ⏎ function x(){}` case as its fixture.

**C5 — confirmed.** The oracle was unusable over exactly the sessions the deviations
exist for. §7.7 now scopes it: redeclaration-free, failure-free, import-free,
TLA-free sessions replay as one growing script and **any** divergence fails the
build; everything else is pinned by direct per-input fixtures. The corpus schema
(ordered inputs; per-input outcome, record delta, `globalThis` delta, display) is
stated, which also closes C10 — and C10 was right that AC11's flagship, written on
one line, was a `SyntaxError` as a single input. The ACs now use an explicit `⏎`
boundary marker.

**C7, C8 — confirmed against the code.** `parse_program` promotes to Module on
seeing `import`, and the Module goal rejects sloppy-only parse forms. §3 now names
the gap rather than assuming it away, requires one of three concrete mechanisms,
adds the sloppy-only *parse* forms (legacy octal, `delete identifier`, duplicate
parameters) to the fixture family so a Module-goal implementation fails the corpus,
and makes the mechanism open question 5. `await` is reserved at the top level of
script inputs, as recommended.

**C9 — confirmed, and it is the most consequential concern of the round.**
`jsi::JSError` populates message and stack by *reading* `.message`/`.stack`, so the
round-1 claim of "engine-captured" error payloads was not achievable on stock JSI.
§8 now says so plainly: **stage 1 renders every thrown value by type tag, including
ordinary errors**, which is a severe usability cliff and is labeled as one. The
reviewer's **stage 1.5** suggestion is adopted by name — the `IsNativeError` brand
check plus own-data-property read is much cheaper than the full primitive and
restores ordinary error display on its own — and the three engine slices
(introspection, completion-record discriminator, throw capture) are now framed as
**one patch program**.

**C16, C17 — confirmed by probe and by source.** `fatal_async_error` *is* one-shot
(set at `hermes_runtime.cc:690`, read-and-cleared at `:3716-3717`; LLP 0003 §Event
loop calls it one-shot deliberately), so "poisons the pump" was overstated. §9 now
makes the narrower, correct complaint: the **engine layer decides fatality at all**,
returning `-1` from poll where the consumer should receive a structured event. The
Windows async-function comment is real (`hermes_runtime.cc:3035-3037`); the premise
table is now scoped per advertised target and the Windows entry-TLA question is
open question 7.

**C13, C14 — accepted**; the kind table now reads "entry role only (§3)", and AC8
splits preflight (static and literal-dynamic edges) from call-time refusal (computed
imports) with the same named error.

**X1–X9 — all confirmed against the live sibling text and all fixed on this side.**
The sibling corpus was revised concurrently during this run (0022: 580→866 lines;
0025: 507→858), which is why these findings are new. `require.main` is retired;
`.load` of JSON now displays the parsed value; the ordinal follows 0022 §5's
evaluated-source rule (so a `.time` argument advances it); the **lifecycle** outcome
is added as the fifth; background callbacks are a cancellation target; submission
provenance and the armed-session binding are fields of §1's source request; the
out-of-snapshot error joins §2's new taxonomy; the display IR is deferred to
LLP 0025 §3 (this document keeps the *semantic* inspection tree); and the stale
references are corrected (LLP 0025 OQ 6, not OQ 5; LLP 0000 moves with LLP 0002).

**Not adopted.**

- **X2's recommendation** to keep `.load` of JSON as a hard error and amend LLP 0022
  instead. The reviewer calls a display-only `.load` "a false affordance"; I disagree
  — displaying a parsed JSON value is a real, useful affordance, and JSON genuinely
  has no declarations to publish, so there is nothing false about it. LLP 0022 is the
  product contract and pinned this edge deliberately; 0024 aligns. The
  module-kind-asserting extensions (`.mjs`, `.cjs`, `.mts`, `.cts`) *are* refused —
  symmetrically, which is the part LLP 0022's enumeration misses and which is
  reported back as a sibling nit.
- The §7.2 rationale bullet the reviewer suggested folding down is **kept, but
  corrected**: it is right that under the matrix's `var`-reuse row a capture model
  would also yield `2` for the plain `var` case, so that framing was imprecise. The
  bullet now makes the argument that actually holds — a reference compiled while `x`
  was `var`-kind must still see the lexical cell a later input puts in its place,
  which capture (or a raw global lookup) cannot do.


## Round 3 — 2026-07-12

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose`
subagent launched in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `3071f3c6d074` (first 12 hex of `shasum -a 256` over the
target file — a content hash, not a Git object)
**Redaction:** none.
**Independence:** launched concurrently with the Codex reviewer on the same
revision. Both earlier rounds' artifacts were moved out of `llp/reviews/` before
launch and restored only after both round-3 reviews were in, so neither reviewer
could see a prior round or each other.
**Sibling drift:** the sibling corpus was under concurrent revision throughout.
LLP 0022 gained a machine-checked obligations ledger with stable `OBL-*` ids;
LLP 0023 replaced object-only module identity with a tagged algebra (§2.3);
LLP 0025 reached `5001c0098469`. This reviewer read them as they stood.
**Method:** the brief explicitly instructed the reviewer **not to trust the
document's empirical claims** but to re-measure them — the eight engine premises
against `tools/hermes/hermes`, the revoked-Proxy behavior, and the Deno/Bun/Node
precedent — after a false empirical claim survived round 1 by being taken on trust.
It re-measured all of them and reported them all as holding, including the
corrected Bun-`const` divergence.
**Transport note:** captured verbatim from the subagent's final message; the agent
transport HTML-escaped `<`/`>` inside code spans and those escapes are decoded here.
The reviewer's own preamble line ("All verification is complete…") is omitted; the
review body is otherwise unaltered.

### Verbatim review

# Review: LLP 0024 — Structured Evaluation and Session Semantics (rev 3071f3c6d074, round 3)

## 1. Overall assessment

This is an unusually strong specification, and — rare for a round-3 document — its empirical spine held up under independent re-measurement. I re-ran every measured claim: all eight engine premises against the bundled `tools/hermes/hermes`, the revoked-Proxy behavior, the Deno 2.9.1 and Bun 1.3.12 REPL measurements (including the corrected Bun-`const` claim, which is exactly as now stated: Bun silently accepts the write), the Node 25 redeclaration refusal, and the live defects in the shipping seam (thenable assimilation, post-arming env timeout, `Option<String>` collapse, `<eval>` identity, async-IIFE binding loss, wrapper-prefix arithmetic). Every one verified. The document's diagnosis of the current seam is accurate at the file:line level, its engine premises are true, and its central architectural conclusion — that the session record must be an evaluator-owned checked-cell environment because the engine supplies no TDZ, no runtime `const`, and no cross-evaluation lexical persistence — is genuinely forced, not merely preferred.

Judged as a normative Spec, §§1–6 and §8–9 are close to done: complete, honest about staging and about what Hermes cannot do, and testable. §7 — the section the round-2 revision rebuilt as an algorithm — is much better than a table of adjectives, and its fixture schema (explicit input boundaries, record delta, `globalThis` delta, display) is exactly right. But attacking §7 as an algorithm, as this review was asked to, finds real cracks: the kind-table rule combined with the cross-kind matrix specifies deleting a realm builtin's `globalThis` property when a session input lexically shadows it (`let Object = 1` destroys `Object` for every imported module), in direct contradiction with §7.1's coexistence rule and §7.7's own oracle; the oracle's stated domain is wrong on three separate routes; and rollback is underdetermined under third-party interference (import side effects, callbacks during suspension, explicit property writes). There is also one material contradiction with LLP 0025 at the display-IR seam, and a misquote of LLP 0023's module-identity rule. These are localized and fixable, but they are precisely the "two independent implementers diverge" defects §7 exists to preclude.

Not ready yet; one more focused revision away.

## 2. Strengths

1. **Empirical claims are true — all of them.** Verified against the shipping binary and installed runtimes: no TDZ; `const c = 1; c = 2` → compile-time "invalid assignment left-hand side"; `with` → compile error; direct eval cannot see enclosing locals; `for (let i…)` closures capture `3,3,3`; global `var` non-configurable; no native ESM and no native TLA; cross-evaluation lexical non-persistence (confirmed live through `target/debug/ibex repl`); `Array.isArray` on a revoked Proxy throws `TypeError: Proxy has been revoked` while `typeof` is safe; Deno 2.9.1 and Bun 1.3.12 both late-bind (`f()` → `2`); Deno throws `TypeError` on prior-input `const` assignment while **Bun 1.3.12 silently accepts it**; Node 25.9.0 refuses redeclaration with `SyntaxError`. So §7.2's corrected claim and the recorded divergence are accurate.
2. **The current-seam diagnosis is verified at every citation.** `Option<String>` and `<eval>` (engine/mod.rs:33; hermes.rs:1517,1524); thenable assimilation (hermes_runtime.cc:3044-3053); the unwrap compiled out on Windows with the async-syntax comment (hermes_runtime.cc:3035-3038 — also validating open question 7); `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` read after arming (hermes_runtime.cc:3089-3100); NULL-for-`undefined` plus NUL-terminated malloc'd string (hermes_runtime.cc:3161-3174) truncated by `CStr::from_ptr` (hermes.rs:914); the runtime lock held across the whole native call (hermes.rs:877); `EngineFeature` reporting TLA/ESM/CJS `false` (hermes.rs:1658-1660); the uncaughtException handler converting a throw into a *successful* `undefined` outcome (hermes_runtime.cc:3182-3193); the async-IIFE lowering discarding declarations (repl/mod.rs:1174-1186, confirmed live); wrapper-prefix arithmetic (repl/mod.rs:107-127, 874); the delimiter-counting completeness scanner (repl/mod.rs:486-563); the adjacent-`.map`-file source-map machinery (hermes.rs:1173,1197,1207); error capture reading `.message`/`.stack` off the thrown value (hermes_runtime.cc:511-512; jsi.h:2162-2181); and the three-behaviors-for-one-condition dependency-TLA mess (transpile.rs:100-101; transpile.rs:212-217; module_loader/mod.rs:278-284).
3. **§7's architecture is right.** The modified `GlobalEnvironmentRecord` framing (§7.1) imports the coexistence, `typeof`, and sloppy-creation edge cases instead of re-deriving them; late binding by name (§7.2) is argued from `var`-correctness and rollback coherence and backed by measured precedent; the six phases (§7.3) give a throwing import and a throwing statement different, stated consequences; the deviation list (§7.7) is closed, versioned, and fixture-pinned; and the corpus schema's explicit input boundaries (`⏎`) are exactly what makes AC11–AC13 testable.
4. **§6 is decision-grade.** Empty-vs-`undefined` grounded in completion-record semantics with the "last expression statement" heuristic explicitly non-conforming; non-assimilation made *structural* via the private control token; the fault/throw split; the four-way cancellation resolution with races enumerated and no assertion about break catchability; the lifecycle outcome matching LLP 0025 §8. Routing the byte-level schema to a semver-major LLP 0002 amendment is the right altitude.
5. **§8's staging is honest.** Stage 1 is "useless-but-safe" and says so; the withdrawn `[Function: name]`/`[Array(3)]` tags are a rare self-audit; the revoked-Proxy fallback is pinned; stage 1.5 is correctly identified as the cheap high-value slice; and the three engine slices are scoped as one patch program. The current `inspect.ts` confirms the necessity (inspect.ts:293-384, 396-431; repl/mod.rs:64).
6. **§3's parser-goal honesty.** Naming that the Script-plus-extensions goal does not exist in the pinned parser (transpile.rs:134 `parse_program` auto-promotes), forbidding "parse as Module and patch," and designing the sloppy-parse-form fixtures specifically to catch that cheat is the difference between a spec and a wish.

## 3. Concerns

**C1 — Blocking. The kind-table rule plus the cross-kind matrix destroys realm builtins on lexical shadowing, contradicting §7.1's coexistence rule and §7.7's oracle.**
Evidence: §7.1 says a name with no kind entry "(a realm builtin, an endowment) behaves as `var`-kind **for every rule below**"; §7.3's matrix says existing `var` + new lexical → "**replace**; the `globalThis` property is **deleted**"; §7.5 reinforces it. Composed, `let Object = 1` deletes `globalThis.Object` — and since imported modules are not rewritten (§7.1's mechanism) and resolve only through the object record, every subsequent import breaks. This contradicts (a) §7.1's own coexistence requirement, and (b) §7.7's oracle: `let Object = 1 ⏎ Object` is oracle-checkable under the stated domain, and the growing script leaves `globalThis.Object` intact, so the fixture's `globalThis` delta fails the build for the matrix-conforming implementation. The same defect is reachable via §7.1's sloppy-creation rule: `globalThis.x = 2 ⏎ let x = 1` (matrix: delete; ordinary Script and the oracle: coexist). §7.1's coexistence example covers only the cell-first order; the property-first order is handled only by the wrong route. Two implementers will diverge, one of them catastrophically.
Resolution criterion: the matrix distinguishes a **session-declared** `var`/`function` binding (replace ⇒ delete, as now) from a **kindless global property** (builtin, endowment, explicit `globalThis` write) — the latter gets a shadowing lexical cell with the property untouched; the "behaves as `var`-kind" sentence is scoped to access/assignment/redeclaration-legality rules, excluding the matrix's delete action; AC11 gains `let Object = 1 ⏎ Object` and `globalThis.x = 2 ⏎ let x = 1` fixtures.

**C2 — Material. The oracle's domain claim is false on at least three routes.**
Evidence: §7.7 defines oracle-checkable sessions as "no cross-input **lexical** redeclaration, no failing input, no import, and no top-level `await`," and asserts "**Any** observable divergence fails the build." All three clauses fail: (i) deviation (d) arises without any exclusion — `var x = 1 ⏎ delete globalThis.x ⏎ typeof x` diverges; (ii) deviation (e) arises via **var/function** redeclaration, which is not *lexical* redeclaration — `var x = 1 ⏎ function x(){} ⏎ x` is oracle-checkable yet is AC13's own pinned divergence; (iii) `x = 1 ⏎ let x = 2` concatenates to a *legal* Script that throws (TDZ write) while the session succeeds.
Resolution criterion: redefine the domain by exclusion of **all** cross-input same-name declaration pairs, any `delete`/`defineProperty` observation of a session binding, failures, imports, and TLA — and drop or correct the "none of (a)–(e) can arise" sentence.

**C3 — Material. Rollback (§7.4) is underdetermined under third-party interference.**
Evidence, three cases two implementers will decide differently: (a) `import "./boom"; var w` where boom writes `globalThis.w = 5` before throwing — is `w` absent (restore) or `5` (module effect stands)? And does "fully restored" scope to declared names or the whole object record? (b) A callback firing during suspension deletes `globalThis.w` for a phase-4-created `var w`; the input then throws — exception (i) says `w` is "retained, holding the value it held at the moment of the abrupt completion", undefined for a deleted property. (c) During phase 6 of an input whose phase 4 deleted a prior `var x`, code executes `globalThis.x = 99`; the input throws — does 99 survive or does restoration overwrite it?
Resolution criterion: specify rollback operationally — journal the *declaration-structure* operations of phases 4–5 per declared name, rollback applies their structural inverse only, with a stated rule for a name concurrently mutated by non-declaration code — and add the three fixtures to AC12.

**C4 — Material. §8's display-IR description contradicts LLP 0025 §3.**
Evidence: §8 says "LLP 0025 §3 pins the **display IR** — the versioned, serializable form carrying **trusted style and layout tokens from a closed enum**… only the IR crosses". LLP 0025 §3 defines no such IR: its renderer's input is the *tree*, whose nodes carry "kind, untrusted payload, children — *and never styling*"; "the **session layer** derives trusted styling from node **kinds**"; and the *tree* is the versioned, serializable artifact that crosses. Worse than a naming mismatch: producing style tokens worker-side violates LLP 0025 §7's trust posture (guarantees must hold against a *hostile* worker; "a producer cannot name a style").
Resolution criterion: §8 states that the semantic tree is the serializable boundary object and that style derivation is wholly the session layer's, deleting the style-token IR language — or LLP 0025 is amended; one of the two, in a coordinated revision.

**C5 — Material. §7.9 misquotes LLP 0023's module-identity rule it claims to defer to.**
Evidence: §7.9 says "Module **identity** is LLP 0023 §2's — the retained platform object, `(runtime, retained object identity)`." LLP 0023 §2.3 specifies a **tagged algebra** whose file-backed case is `(runtime, defining principal, retained file object)`, and explicitly argues that keying on the retained object *alone* is wrong because it collapses compartments across hard-linked inodes (§2.3, AC17). §7.9's parenthetical is the rejected rule.
Resolution criterion: name the tagged algebra and the defining-principal key, or delete the parenthetical, leaving the deferral clean.

**C6 — Material. §6's cancellation machine lacks the target-id and completion-query vocabulary LLP 0025 §6 requires.**
Evidence: LLP 0025 §6 gives work units **monotonic target ids**; "a cancellation request **carries the id it was raised against**, and the engine must discard a request whose id is not that of the work it is currently executing" (hazard: one poll runs several callbacks; Hermes's queued interrupt runs exactly once); its ledger rows this on LLP 0024 §6 as *not yet*. §6 here added the background-callback target but carries no id concept and no completion-query target, and its race rules are id-blind.
Resolution criterion: §6's request carries the target id with the discard rule, and either admits the completion query as a third target or states where completion-query cancellation lives.

**C7 — Minor/Non-blocking. §9's sequence domain omits broker events.** LLP 0025 §3 requires broker events to draw from "the same session-wide sequence LLP 0024 §9 defines… one domain, not two." §9 names only evaluation outcomes and async events.

**C8 — Minor/Non-blocking. §7.8's `$_` declaration rule cites a matrix behavior the matrix doesn't deliver.** "A *declaration* of `$_` in an input **replaces** the binding (§7.3)" — but `$_` is var-kind and the matrix says var→var **reuses**; a bare `var $_` neither replaces nor triggers the setter.
Resolution criterion: pin that any top-level declaration of `$_` disables auto-update at phase 4 regardless of matrix row; add `var $_` to AC14.

**C9 — Minor/Non-blocking. `typeof` on an in-TDZ lexical cell is unpinned.** ECMAScript throws `ReferenceError` for `typeof x` inside x's TDZ; §7.6/AC11 never say it.
Resolution criterion: AC11 adds `typeof x; let x = 1` (one input) → `ReferenceError`.

**C10 — Minor/Non-blocking. Source-map composition through LLP 0019 tier 2 has no named mechanism.** Tier 2 is a line-based string scanner running inside the bootstrap with no parser and no map machinery.
Resolution criterion: state which mechanism satisfies AC2 for tier 2 — a line/column-stable rewrite guarantee, map emission from the scanner, or a documented narrowing.

**C11 — Minor/Non-blocking. `using` disposition is pinned for script inputs only.** Program-mode stdin is a module-goal **entry** where top-level `using` has coherent scope-exit semantics (and `await using` intersects the entry-TLA lowering). Unstated.

**C12 — Minor/Non-blocking. §6's "defeated" is defined two ways.** The outcome table says the request "never resolves at all"; the race bullet says an evaluation completing normally after delivery makes the request "resolve **defeated**".

**C13 — Minor/Non-blocking. Two corpus-coverage gaps.** (a) Declaration collection "after TypeScript lowering" will collect transform-introduced temporaries (the enum-lowering IIFE variable) as session names unless hygiene is required. (b) The fixture family omits *assignment-form* fidelity the free-identifier rewrite must preserve: compound assignment, update expressions, destructuring assignment targets, `for (x of …)` heads, PutValue ordering. Also: phase 2's "a duplicate destructuring target" is a SyntaxError only for lexical binding — `var [a, a]` is legal in a Script, so "exactly as in a Script" and the list disagree.

## 4. Cross-document findings

1. **Contradiction (ties C4):** §8's display IR vs LLP 0025 §3's styleless tree and session-layer styling — including which artifact crosses the process boundary.
2. **Contradiction (stale sibling ledgers):** LLP 0022 §11 and LLP 0025 §11 both assert LLP 0024's outcomes "are empty/value/throw/cancelled"; §6 here now carries the fifth **lifecycle** outcome. The rows are false against this revision and must flip.
3. **Contradiction:** LLP 0022 claims the **out-of-snapshot** error class is one "no sibling owns"; §2 here now owns a six-class resolver/import-gate taxonomy including it.
4. **Half-stale ledger / dangling dependency:** the **typed session-effect read** for `.load`, which LLP 0022 §7 places as an obligation "on LLP 0024 §1," is still absent from §1 here — that half genuinely dangles.
5. **Dangling (ties C6, C7):** LLP 0025's rows on target-id cancellation, the completion-query target, and broker membership in the §9 sequence domain remain unreflected here.
6. **Stale the other way:** LLP 0022 says "0025 has no ack lane"; LLP 0025 §3 now defines display acknowledgement at barrier completion, matching §7.8 here. The three documents agree; the ledger doesn't.
7. **Citation drift:** LLP 0022 cites "LLP 0024 OQ 6, LLP 0025 OQ 6" for the shared constants annex; in the revised documents those are **0024 OQ 8** and **0025 OQ 7**. For a ledger that must be mechanically checked, the pointers must be stable IDs, not section numbers.
8. **Contradiction (ties C5):** §7.9's module-identity parenthetical vs LLP 0023 §2.3.
9. **Confirmed consistent** (no action): entry-only TLA and the stable dependency-TLA error; drain policy by execution mode; `require.main`/`process.mainModule` retirement; `.load` edge tables; `$_` semantics; reserved-scheme placement; synthetic identities; fatality as a consumer decision.

## 5. Suggestions

1. Fix C1 with a two-row split in the matrix ("existing *session* `var`/`function`" vs "kindless global property") plus one scoping sentence. Small edit, large defect.
2. Recast §7.4 as journal semantics (structural declaration ops journaled; rollback = structural inverse only; concurrent non-declaration mutations governed by one pinned rule).
3. Run the growing-script oracle **differentially**: replay oracle-checkable sessions both on the standards engine *and* through the real lowering on shipping Hermes. The standards engine alone validates the semantics but never exercises the §7 lowering, which is where implementations will actually diverge.
4. Consider stamping each record operation with an **input epoch**. It gives rollback its journal for free and gives §9's association-to-evaluation field a mechanism.
5. Non-standard idea: implement the session record as a **generated JS module compiled at bootstrap from the same table the fixtures are generated from** (the LLP 0019 corpus discipline applied to §7) — the corpus could then run on the bare `tools/hermes/hermes` binary with no Rust harness. Also: check whether the vendored debugger's *pause-state* capture already records thrown values without property reads — that would make stage 1.5 nearly free.
6. Add to AC11: `let Object = 1 ⏎ Object`; `typeof x; let x` (TDZ); declare-after-`delete globalThis.x`; an endowment-name redeclaration round-trip asserting what descriptor the recreated property carries.
7. Add a fixture where a command argument (`.time {`) is incomplete, pinning "commands never enter continuation" from this side too.
8. In §6, note that the lifecycle outcome's §7.4 rollback is unobservable in v1 (no JavaScript runs afterwards) and exists to keep the record's invariants unconditional.

## 6. Open questions

1. (C1 follow-on) When an *earlier input's* sloppy-created global is lexically redeclared, is that the session-binding row (delete) or the kindless-property row (shadow)?
2. (C3) Is rollback's unit the declared-name set or a journal of record operations — and does restore-wins or last-writer-wins govern a name concurrently mutated by non-declaration code?
3. (C4) Which side of the worker boundary derives style tokens, and is the serialized artifact the semantic tree or a distinct IR?
4. (C6) Does the evaluator validate cancellation target ids itself, or does the session layer pre-filter?
5. Does the §7.7 oracle compare `globalThis` deltas via the trap-free primitive (stage 2) or JS reflection — i.e., can the oracle itself run before the engine patch program lands?
6. What is `using`/`await using` at the top level of the module-goal entries, and does `await using` compose with the entry-TLA lowering on Windows (OQ 7)?
7. For phase-2 collection "after TypeScript lowering": which hygiene rule keeps transform-introduced names out of the session record and out of tab completion?

## 7. Readiness verdict

The document's empirical foundation is fully verified and its design judgment is consistently sound, but §7 as written contains one self-contradiction with catastrophic observable consequences (C1), an oracle whose stated domain misclassifies three reachable session shapes (C2), a rollback rule that is underdetermined exactly where the phase model exists to determine it (C3), and two material seam defects with concurrently-revised siblings (C4, C5) plus one with LLP 0025's cancellation contract (C6). Each is narrowly fixable, and nothing found undermines the architecture.

VERDICT: NOT READY

### Orchestrator verification notes

Both round-3 reviewers converged independently on the same core defects, which is
strong evidence they are real. I re-measured every decisive claim.

**C1 — confirmed, and it is the round's most serious finding.** My §7.1 said a
kindless global property "behaves as `var`-kind **for every rule below**", and my
§7.3 matrix said `var` + new lexical → "replace; the `globalThis` property is
**deleted**". Composed, **`let Object = 1` deletes `globalThis.Object`** — and since
imported modules are not rewritten and resolve only through the object record, every
later import breaks. Node confirms ECMAScript **shadows** rather than deletes
(`globalThis.q = 2; let q = 1` leaves `q === 1`, `globalThis.q === 2`), and a bare
`var Object` is a **no-op** with `Object` intact.

The fix taken is better than the two-row split the reviewer proposes: §7 adopts the
**shadow model** outright — a lexical declaration *never* removes a property. That
single rule was generating four separate defects, and removing it also removes the
*reason* deviation (d) (configurable globals) existed, so global `var` returns to
ECMAScript's **non-configurable**, which in turn kills C2(i) (the `delete
globalThis.x` oracle divergence) and both of C3's property-deletion cases. The
document got smaller and more correct at once — the signal that this is real
semantics rather than accumulated patches.

**C2 — confirmed, and Codex's version of it is sharper**: `for (let i…)` in *one*
input is oracle-eligible under my stated domain and returns `3,3,3` on Hermes versus
`0,1,2` on a standards engine — an **engine** defect, not a **session** defect, with
no deviation to map it to. The fix is a factorization neither reviewer named: the
oracle is now **engine-relative** — a growing script on Hermes versus the session on
Hermes — which cancels engine quirks and isolates exactly the session deviations.
Engine-local semantics (block TDZ, per-iteration bindings) are LLP 0019's subject
and are explicitly outside this document's deviation list. The domain is also
widened to exclude *all* cross-input same-name declaration pairs, not only lexical
ones, which closes C2(ii) and C2(iii).

**C3 — confirmed and adopted, via the reviewer's own suggestion 2.** §7.4 is recast
as **journal semantics**: the evaluator journals the declaration-structure operations
of phases 4–5 per declared name; rollback applies their structural inverse and is
**scoped to the names the input declared** (so a module's write to
`globalThis.fresh` is untouched); values written by any code are not restored; and a
name whose property was concurrently deleted is not resurrected. The shadow model
independently removes cases (a) and (c) by construction, since phase 4 no longer
deletes properties at all.

**C4 — confirmed, and decided in LLP 0025's favor.** 0025 §3 says *this* document
owns the tree schema, that the tree carries **no** styling, and that the session
layer derives styling from node kinds. §8 is amended to own the unstyled tree and
the styled-IR language is deleted. The deciding argument is the reviewer's own: under
the worker split the producer may be hostile, so a producer that can *name a style*
can emit terminal control; a tree that cannot express styling makes that structurally
impossible. Both statements are not left standing.

**C5 — confirmed** (and independently raised by the coordinator). §7.9 now cites
LLP 0023 **§2.3** — the tagged algebra keyed on the caller-independent *defining*
principal — with **no inline restatement of the mechanism and no AC number**, since
restating a sibling's mechanism inline is exactly what let it go stale, and 0023's
module-identity criteria have already renumbered once.

**C6, C7, C8, C9, C11, C12, C13 — all confirmed and fixed.** Target ids with the
stale-id discard rule and the completion-query target (LLP 0025 §6); broker events
join the §9 sequence domain; any top-level declaration of `$_` disables auto-update
at phase 4 regardless of matrix row; `typeof x` inside x's TDZ throws
`ReferenceError` (measured); `using` at a module-goal entry is dispositioned;
`defeated` is given a `Pending` state so it is no longer defined two ways; hygiene
for transform-introduced names is required; assignment-form fidelity is fixtured.

**C13's destructuring point is confirmed as a definite language error of mine**:
`var [a, a] = [1, 2]` is **legal** Script yielding `2`, while `let [a, a]` is a
`SyntaxError`. The collision rule is now keyed by kind rather than blanket.

**C10 — confirmed and narrowed.** LLP 0019's tier-2 scanner is a line-based string
rewriter inside the bootstrap with no map machinery, so §4 now states the mechanism
that satisfies AC2 for it rather than assuming composition is free.

**Not adopted.**

- Suggestion 3's framing that the oracle should also run against a standards engine.
  It should not, as the *deviation* gate: that is what produced C2's false positives.
  A standards-engine comparison measures **engine** conformance, which is LLP 0019's
  charter, not this document's. The reviewer's underlying point — that the oracle must
  exercise the real lowering, not just the idea — is taken: the engine-relative oracle
  runs both arms *through the real lowering on shipping Hermes*, which is strictly
  more demanding than a standards replay.
- The reviewer reports all eight engine premises and the Deno/Bun precedent as
  holding. Codex agrees but adds a sharper epistemic point I have adopted: Deno and
  Bun both yielding `2` rules out *retaining the old value*, but does **not**
  distinguish name-lookup-into-a-replaced-cell from mutating one reused cell. The
  precedent supports late binding without proving the mechanism, and §7.2 now claims
  only what the measurement supports.

## Round 4 — 2026-07-12

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose`
subagent in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `b0ff4ea3247e` (content hash, not a Git object)
**Redaction:** none.
**Independence:** launched concurrently with the Codex reviewer on the same revision.
Both earlier artifacts were stashed out of `llp/reviews/` for the duration and
restored only after both round-4 reviews were in.
**Method:** the brief instructed the reviewer **not to trust the document's empirical
claims** but to re-measure them — the engine premises, the revoked-Proxy behavior, the
ECMAScript assertions, and the Deno/Bun/Node precedent — and told it plainly that an
earlier round had shipped a false empirical claim on trust and a later round a
catastrophic rule that two reviewers had *praised*. It re-measured all of them against
`tools/hermes/hermes`, Node 25.9.0, Deno 2.9.1, and Bun 1.3.12, and reports them all as
holding.
**Transport note:** captured verbatim from the subagent's final message; the agent
transport HTML-escaped `<`/`>` inside code spans and those escapes are decoded here.
The reviewer's preamble line ("All verification complete…") is omitted; the body is
otherwise unaltered.

### Verbatim review

# Review: LLP 0024 "Structured Evaluation and Session Semantics" (rev b0ff4ea3247e, round 4)

## 1. Overall assessment

This is a strong, unusually honest spec that has visibly improved under review pressure: the shadow model is the correct ECMAScript semantics (I re-measured every claim — all true), the engine-relative oracle is a genuinely good idea that fixes a real category error, and the empirical hygiene is now excellent — every engine premise, every ECMAScript assertion, and every runtime-precedent claim I re-measured (bundled Hermes, Node 25.9.0, Deno 2.9.1, Bun 1.3.12 — the exact pinned versions) came back exactly as documented, including the previously-false Bun/`const` claim, now correctly stated. The code-facing claims are likewise accurate: I verified every load-bearing one against source, cited below.

But the document is not internally settled. The round-3 revision moved §3's dynamic-import rule to call-time-only and left AC8 and the §4 fixture table mandating the opposite (a flat design/AC contradiction on normative behavior). §7's algorithm has two genuine holes of the `let Object = 1` class: the journal cannot honor "phases 1–5 publish nothing" for a function-value overwrite, and the adopted-property case (measured on V8) falsifies §7.5's unconditional "session `var` is non-configurable / `delete` returns false" and leaves a matrix row undefined. And the concurrent revision of the siblings has left real cross-document contradictions standing — the lifecycle park-vs-unwind conflict 0025 explicitly flags as a wrong sentence in this document, a two-meanings `defeated`, and a module-identity coverage claim 0023 rules a category error — plus at least five ledger rows now false. All are fixable with local edits; none invalidates the design.

## 2. Strengths

- **Empirical claims all verified true.** Engine premises: on `tools/hermes/hermes` I measured no TDZ, `const` reassignment → compile-time "invalid assignment left-hand side", `with` → compile error, direct `eval` → "lexical scope is not supported", `for (let i…)` → `3,3,3`, global `var` `configurable:false` with `delete` → `false`. `Array.isArray` on a revoked Proxy throws on both Hermes and V8. `throw {get stack(){…}}` runs the getter during Hermes's own uncaught-error capture — confirming §8's stage-1.5 premise from the live engine (`src/engine/hermes_runtime.cc:3199-3208`).
- **The shadow model is right, in both orders.** Measured under V8 Script goal: property-then-`let` and `let`-then-property both coexist; `let Object = 1` leaves `globalThis.Object` intact; bare `var Object` is a no-op; `var [a,a]` yields 2 while `let [a,a]` is a `SyntaxError`; `typeof` in TDZ throws while `typeof neverDeclared` is `"undefined"`; `var` on a non-extensible `globalThis` throws; a global `let` in one script is visible to a later script (deviation (d)'s measurement); `let undefined` is a `SyntaxError` while `var undefined` is inert; delete-then-reveal and accessor-controls-reads both hold; deviation (e)'s paired example is exact.
- **Precedents measured at the pinned versions.** Deno 2.9.1 late-binds and enforces prior-input `const`. Bun 1.3.12 late-binds and silently accepts the `const` write. Node 25.9.0 refuses redeclaration. §7.2's care about what the measurement does and does not distinguish (late lookup vs shared cell) is exemplary review-resistant writing.
- **Code claims all check out**: bare-string `Option<String>` seam (`engine/mod.rs:33`), `<eval>` hardcoded (`hermes.rs:1517,1524`), zero-length source rejected (`hermes_runtime.cc:2950-2952`), NULL-for-`undefined` (`:3161-3174`), throw vs engine fault conflated (`:3178-3231`), the uncaught handler converting a throw into a *successful* outcome (`:3182-3193`), thenable assimilation and its Windows compile-out (`:3033-3057`), `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` post-arming (`:3088-3090`), `EngineFeature` conflation (`hermes.rs:1653-1661`), ffi-lock-across-eval with deliberate debugger bypass, interrupt "exactly once" (`AsyncDebuggerAPI.h:134`), the three inconsistent TLA behaviors, no source map emitted (`transpile.rs:189`), async-IIFE binding loss (`repl/mod.rs:1178-1183`), `.load` passing the host path (`repl/mod.rs:930-941`), and the inspector reading `.name`/`.length` (`inspect.ts:18-39,139-152`).
- **The engine-relative oracle (§7.7)** is the document's best decision: it cleanly separates session conformance from engine conformance.
- **Honest staging** (§6/§8): the capability strata resolve the earlier §6/§8 contradiction; the tree-not-string trust boundary now agrees exactly with LLP 0025 §3.
- **Decision quality elsewhere**: entry-only TLA; the `SourceRequest` sum type; the drain-boundary table; strict UTF-8 and valid-empty-source; the structural non-assimilation argument; the LLP 0019 tier-2 line-stability claim is actually true in code (`module-loader.js:3512-3515`).

## 3. Concerns

1. **[Blocking] AC8 and the §4 fixture table contradict §3 on literal dynamic imports.** §3 says preflight covers the static graph *only* and every `import()` is checked at call time — with the argument that `if (false) import("./tla.js")` must never fail. AC8 and the §4 fixture row say preflight covers "static and literal-dynamic edges." Two implementers produce *opposite* behavior. **Resolution:** one rule, stated identically in §3, §4, and AC8 (call-time for every `import()`), plus a fixture asserting an unevaluated literal dynamic import of a TLA module does not fail.

2. **[Material] The journal cannot deliver "phases 1–5 publish nothing" for a function-value overwrite.** The matrix says a function redeclaration overwrites the value per `CreateGlobalFunctionBinding`. The journal records only structure and rollback explicitly does not restore values. So `function f(){1}` then the input `import "./boom"; function f(){2}` overwrites `f` in phase 4, throws in phase 5, and the journal has nothing to invert. **Resolution:** journal instantiation-time property writes with the displaced value and descriptor; scope "values are not restored" to phase-6/user writes.

3. **[Material] §7.5/AC11's unconditional "session `var` is non-configurable; `delete` returns false" is false for adopted properties.** Measured on V8: `globalThis.adopt = 7` then `var adopt` leaves the property **configurable**, `delete` returns **true**, and the name stays in `[[VarDeclaredNames]]` with no property (reads throw `ReferenceError`, `typeof` is `"undefined"`). **Resolution:** qualify §7.5/AC11 to properties the record *created*; add matrix rows for adoption and for a `[[VarDeclaredNames]]` name with no own property.

4. **[Material] The oracle-checkable class is unsound under dynamic `globalThis` mutation.** `globalThis["ad"+"opt"] = 7 ⏎ var adopt ⏎ delete globalThis.adopt` declares no name twice and forward-references nothing, yet diverges from the growing script. **Resolution:** exclude inputs that dynamically mutate `globalThis` properties, and soften the "none can arise" claim.

5. **[Material] The position-stability inventory omits the bootstrap's other mapless string rewrites.** `aliasNodePathGlobals` regex-replaces `__dirname`/`__filename` with `globalThis.`-prefixed forms (`module-loader.js:3546-3551`), shifting columns; the `import.meta.url` replacement substitutes a long expression. AC2's "correct column" cannot survive them. **Resolution:** enumerate every rewrite stage between submitted text and Hermes bytes.

6. **[Material] The lexical-feasibility predicate is underspecified against the standard it invokes.** ECMAScript's `HasRestrictedGlobalProperty` is descriptor-based (any non-configurable own property) — and session `var`s *are* non-configurable, so an implementer importing the standard predicate refuses `var x ⏎ let x`, which the matrix requires to shadow. **Resolution:** state the modified predicate exactly (restricted iff own non-configurable global property *and* name ∉ `[[VarDeclaredNames]]`) and record the modification in §7.7.

7. **[Minor] Deviation (a)'s wording undercounts.** It must also cover the cross-kind rows — `var`→`let`, `let`→`var`, `function`→lexical — all `SyntaxError` in one growing script.

8. **[Minor] `$_` disable vs rollback is unspecified.** Two implementers differ on `var $_; boom()`.

9. **[Minor] The session lowering's own hooks need the private-seam treatment.** Nothing states that the environment operations' backing intrinsics are unreachable/unforgeable from user source.

10. **[Minor] The oracle's observation set is undefined.** "Any observable divergence" never says what is compared.

11. **[Minor] Program-arm modeling nit.** §1's `Program` field "resolved module kind: ESM / CommonJS / JSON" contradicts the sum type's point that JSON takes the `JsonData` arm.

## 4. Cross-document findings

1. **Lifecycle mechanism contradiction (0024 §6 vs 0025 §8).** 0024 says the evaluation "**unwinds**"; 0025 §8 specifies the call **parks**, never unwinds ("an unwind past `finally` is a mechanism no vendored Hermes interface offers"), and the outcome is delivered out of band. 0025 row **O-7** names 0024's wording as wrong. Material.
2. **`defeated` means two things across the seam.** 0024 makes `defeated` terminal and `Pending` the possibly-forever state; 0025 says a request "is defeated — never resolves." 0024's vocabulary is the better one; the siblings must converge in the same change.
3. **Module identity of `repl:<n>`/`ibex:eval` contradicts LLP 0023 §2.3.** 0023 rules that script inputs "are not modules and have no module identity"; only `ibex:stdin` is a synthetic module. 0024 should name `ibex:stdin` alone. 0023's own ledger row is stale in the other direction.
4. **`OBL-ASYNC-FATALITY` is still dangling.** 0024 delegates fatality to 0025 §8; 0025 §8 has no mode×async-event rule; 0022 §3 states the rule itself while its ledger records that no mechanism owner does.
5. **Ledger rows now false after this revision.** In 0022 §11: `OBL-TYPED-READ`, `OBL-UTF8`, `OBL-DRAIN`, `OBL-DISPLAY-WIRE`, `OBL-MODULE-IDENTITY`. In 0025 §11: O-2, O-5, O-8, O-9. This is exactly the drift the ledger-check rows exist to catch.
6. **The interim refusal class has no mechanism home.** 0022 §2 requires a refusal distinct from out-of-snapshot; 0024 §2's taxonomy has no such class.
7. **Permit field drift.** 0022 binds six fields including a submission ordinal; 0024 binds five.
8. **`import.meta` in script inputs.** 0022 pins it as a syntax error at the prompt; 0024, which owns the source goal, never says.
9. **No total order over the import-gate taxonomy.** 0023 §7.2 records that "LLP 0024 tables an import-gate taxonomy without a total order."

## 5. Suggestions

- Fix concern 2 by making the journal's unit "declaration-structure operation *with displaced state*" uniformly — displaced cell for cells, displaced value+descriptor for instantiation-time property writes.
- Prototype **OQ 9 before building the full Reference-fidelity lowering.** An engine-level checked global record would delete most of §7.1's table, deviation (d), and the hook-unforgeability question in one move.
- Add a **grammar-restricted differential fuzzer** to the oracle gate: generate sessions inside the (repaired) oracle-checkable class and diff automatically.
- Consider *normalizing adoption* as an alternative to concern 3: redefine an adopted configurable property to ECMAScript's `var` descriptor at phase 4. Either answer is defensible; the document must pick one and pin it.
- Give AC fixtures stable IDs per deviation and per matrix row, so the corpus provably covers the matrix.
- State the `.load` identity parse rule (`repl:<digits>:` prefix, remainder verbatim) so a colon-bearing filename cannot make the identity ambiguous.
- 0025 O-6 wants native begin/end publication of every work unit from the engine seam this document owns; §6 implies it but should state it as a seam obligation.

## 6. Open questions

The document's ten are the right ones (OQ 5 and OQ 7 gate the most). Add:

1. What is the oracle's observation channel, and how are per-input displays reconciled with a single-script replay?
2. Who owns the *total* precedence order across the import-gate classes?
3. Adoption policy: descriptor-preserving `CreateGlobalVarBinding`, or redefine at phase 4 and add the deviation?
4. Does the `$_` auto-update disable participate in the journal?
5. Are the bootstrap's non-0019 string rewrites retired, mapped, or stability-bound?
6. Should `hermesc` gain the async-break-check flag as part of this program, since §6's cancellation quality depends on it?

## 7. Readiness verdict

One blocking internal contradiction (design vs acceptance criterion on literal dynamic-import preflight), two material algorithm holes in §7 of exactly the class this round was asked to hunt, an unsound oracle-class definition, and standing cross-document contradictions that the concurrently-revised siblings explicitly track. All have crisp, local fixes and none threatens the architecture; a round-5 revision that lands them should be READY.

VERDICT: NOT READY

### Orchestrator verification notes

I re-measured every decisive claim; all held. Codex's round-4 review found the same
class of defects independently.

**C1 — confirmed, and it was sloppiness.** Round 3 moved §3's rule to call-time-only
and left the §4 fixture table and AC8 mandating literal-dynamic preflight. A design/AC
contradiction on normative behavior is the worst kind. Deleted everywhere.

**C2 and C3 — confirmed, and together they exposed a defect my own round-3 fix
created.** Making session `var`s non-configurable was right, but it made phase-5
rollback **impossible**: you cannot delete a non-configurable property (`delete
globalThis.v` → `false`, measured). The resolution is neither reviewer's — it is a
**phase reorder**. Import evaluation moves *before* instantiation, so a failing import
throws before anything is instantiated: "publishes nothing" becomes trivially true, no
property ever needs deleting, and rollback touches **only the evaluator's own
declarative record**. That also disposes of C2's function-overwrite case for free (with
import-first, `f` is never overwritten), with no VM transaction API and no journaling of
property values.

C3's adoption measurement is confirmed and adopted as stated: a `var` adopting a
pre-existing configurable property leaves it **configurable** and deletable. I took the
reviewer's *first* option (follow ECMAScript's descriptor-preserving
`CreateGlobalVarBinding`) rather than the "normalize adoption" alternative, because it
adds no deviation. §7.5 is now qualified to properties the record *created*, and the
`[[VarDeclaredNames]]`-name-with-no-property case is pinned.

**C4 — confirmed** (and Codex found a second, sharper falsifier: a directive prologue.
`0 ⏎ "use strict"; function f(){return this} ⏎ f()` is `undefined` as a session and
`globalThis` concatenated — measured). Both reviewers independently proposed the same
remedy, which 0025 has already proven by making its interrupt machine generated data
after prose falsified it three rounds running: **split the gates and make §7 an
executable reference model**. Adopted.

**C5 — confirmed.** `aliasNodePathGlobals` regex-rewrites `__dirname` → `globalThis.__dirname`,
shifting columns with no map, and the `import.meta` substitution does likewise. §4 now
enumerates every rewrite stage between submitted text and Hermes bytes.

**C6 — confirmed and important.** `HasRestrictedGlobalProperty` is descriptor-based, and
since session `var`s are non-configurable, importing the standard predicate verbatim
would refuse `var x ⏎ let x` — which the matrix requires to *shadow*. The modified
predicate is now stated exactly and recorded as the mechanism of deviation (a), since
§7.1 promises "the modifications enumerated in §7.7 and no others."

**C7–C11, and every cross-document finding — confirmed and fixed.** Lifecycle adopts
LLP 0025's **park** (the call never unwinds; state is *discarded*, not rolled back).
The credential adopts LLP 0022's full linear `SubmissionCredential` — including the
submission ordinal — and drops "decision evidence", a phrase 0022 explicitly names a
**category error**. Module identity drops script sources: LLP 0023 rules they are not
modules at all, and my demand that identity "cover the sources this document mints" was
exactly the **noun-reuse conflation** the coordinator warned about. And the failing
module's cache entry does **not** stand — the loader deletes it (`delete cache[cacheKey]`),
so my "of course stands" was false.

**Not adopted.** The "normalize adoption" alternative (C3's second option) — it buys a
tidier §7.5 at the price of a new deviation from Script semantics, and this document has
been trying to *shed* deviations, not collect them.

## Round 5 — 2026-07-12

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose` subagent
in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `c264085e7ebf` (content hash). *The reviewer's own header
records a working revision of `e3eace63fe78`; that is the hash it computed mid-run while
the file was momentarily being written by the orchestrator's residue-fix edits. Its
citations resolve against `c264085e7ebf`, which is the revision it was briefed on and the
one Codex reviewed concurrently. Noted rather than quietly normalized.*
**Redaction:** none.
**Independence:** launched concurrently with the Codex reviewer on the same revision;
both prior artifacts were stashed out of `llp/reviews/` for the duration.
**Method:** the brief instructed the reviewer to **re-measure** every empirical claim
rather than trust it, and additionally to hunt for **noun reuse** — a shared word
silently covering two concepts — after that failure mode had bitten the corpus twice. It
re-measured all seven engine premises, ~15 ECMAScript claims, and the Deno/Bun/Node
precedent, and reports every one as reproducing.
**Transport note:** captured verbatim; the agent transport HTML-escaped `<`, `>`, and `&`
inside code spans and those escapes are decoded here. The reviewer's preamble line is
omitted; the body is otherwise unaltered.

### Verbatim review

# Review: LLP 0024 — Structured Evaluation and Session Semantics (round 5, working revision `e3eace63fe78`)

## 1. Overall assessment

This is the strongest revision of this document yet, and most of round 4's structural surgery is correct: moving import evaluation before instantiation genuinely dissolves the unimplementable rollback (a fresh session `var` is non-configurable — re-verified), the descriptor-keyed matrix now matches real ECMAScript behavior in every row I could execute, and the three-gate structure over an executable reference model is the right answer to three consecutive rounds of falsified hand-written tables. Unusually for this corpus's history, **every empirical claim I re-measured held**: all seven Hermes engine premises reproduce byte-for-byte on `tools/hermes/hermes`; the fifteen-odd ECMAScript claims (shadow-not-delete in both orders, `var`/`function` asymmetry on builtins, adopted-vs-created descriptors including the delete-then-`ReferenceError` sequence, `var [a,a]` legality, TDZ `typeof`, non-extensible-global `var` `TypeError`, realm-visible global `let`, directive-prologue displacement) all reproduce under real Script semantics; and Deno 2.9.1, Bun 1.3.12, and Node 25.9 behave exactly as pinned — Bun really does silently accept a write to a prior-input `const`.

It is nonetheless not ready. The §2 error taxonomy's total order **contradicts the same document's §1**, contradicts LLP 0023 §7.2's confidentiality ordering (in the direction that creates an existence oracle), and contains a class (`interim`) whose defining citation no longer exists in LLP 0022. And the predicted "next defect" in §7-as-algorithm is there: the import-before-instantiation reordering moved, rather than removed, the interference window — feasibility (phase 3) is checked *before* arbitrary user code runs in phase 4, phase-5 failure semantics are unspecified, and an acceptance criterion still carries vocabulary from the retired property-rollback model. Two implementers would demonstrably diverge on phase-5 failure, on `[[VarDeclaredNames]]` survival, and on the `$_` disable's rollback.

## 2. Strengths

- **Imports-before-instantiation (§7.3, §7.4).** The core round-4 move is correct and elegantly argued: "publishes nothing" becomes trivially true instead of unimplementable, and I verified the impossibility premise it rests on (fresh Script global `var` is writable/enumerable/**non-configurable**; `delete` returns `false` — measured in Node via `vm.runInThisContext`, and on Hermes directly where `delete globalThis.v` → `false`).
- **The cross-kind matrix (§7.3, §7.5) is now empirically right.** Bare `var Array` is a no-op; `function JSON(){}` clobbers; an adopted configurable property stays deletable and a post-delete read throws `ReferenceError` with `typeof` `"undefined"`; `var` over an inherited-only name creates a fresh own non-configurable property initialized to `undefined`. Every row I executed matched. The modified restricted-global predicate (§7.3 phase 3) is the minimal correct modification — `let undefined` still refused (measured `SyntaxError`), `var x ⏎ let x` admitted.
- **The shadow model (§7.1) and its collateral simplifications.** `let Object = 1` leaving `globalThis.Object` intact is confirmed Script behavior; pleasingly, my own test harness broke *because* a real global `let Object` is realm-visible — direct proof of deviation (d)'s measured claim and of why it must be a listed deviation.
- **Honesty of the engine premises.** All re-verified on the shipping binary: no TDZ, compile-time-only `const`, `with` refused, direct-`eval` lexical-scope gap, `3,3,3` loop capture, non-configurable global `var`, and `Array.isArray` throwing `TypeError` on a revoked Proxy.
- **The gates (§7.7).** Engine-relative gate 2 with a genuinely restricted class — the directive-prologue exclusion is real (measured) — and a stated observation channel replaces "any observable divergence."
- **Every seam-indictment claim against the code verified.** `Engine::eval` → `Result<Option<String>>` (`engine/mod.rs:33`); hardcoded `<eval>` (`hermes.rs:1517,1524`); thenable assimilation (`hermes_runtime.cc:3048`), compiled out on Windows (`cc:3038`) with the exact "async function syntax" comment OQ 7 cites; `getenv("IBEX_AWAIT_UNWRAP_TIMEOUT_MS")` inside the eval call (`cc:3089-3100`); zero-length source rejected (`cc:2950`); error capture by reading `.message`/`.stack` off arbitrary thrown values (`cc:511-512`); one-shot `fatal_async_error` producing `-1` from poll (`cc:3688-3717`, matching LLP 0003:118-123); `EngineFeature::SourceMaps => true` beside three honest `false`s (`hermes.rs:1657-1660`); SWC passing TLA through while Oxc bails ad hoc (`transpile.rs:100,212-214`); no map emission (`transpile.rs:185-193`); `$_` assigned before render inside `Exact.inspect(_val, {colors: true, …})` (`repl/mod.rs:64-80`); completion via `Function('return (' + expr + ')')()` (`repl/mod.rs:297`); the loader deleting a failing module's cache entry (`module-loader.js:5326,5691`) — §7.9's corrected claim is true against the loader.
- **§6's cancellation vocabulary** now agrees with LLP 0025 §6 exactly, and §6's lifecycle outcome carries 0025 §8's park-and-discard mechanism verbatim.
- **§8's staging** — including the stage-1.5 carve-out and the one-patch-program framing — is honest engineering.

## 3. Concerns

**C1. Blocking — §2's error-class total order contradicts §1, LLP 0023 §7.2, and itself; and its unsafe direction is an existence oracle.**
Evidence: §2 states "reserved-scheme → **resolution failure** → outside-mount / path class → unknown-builtin → out-of-snapshot → interim → **policy denial** → TLA". §1's `.load` paragraph states the opposite: "an outside-mount refusal precedes a policy denial, which precedes a resolution failure". LLP 0023 §7.2 — which §2 says it defers to — orders `ERR_IBEX_OUTSIDE_MOUNT` (#4) and policy denial (#7) *before* `ENOENT`-class absence (#8), with the normative rule "absence is never disclosed before authorization". Deciding "no such module" second — before containment and policy — requires probing the host for a path outside every mount or for an out-of-graph package, i.e. exactly the existence oracle 0023 §7.2 prohibits. Two implementations following §1 versus §2 report different classes for `import "/etc/passwd"`; the taxonomy's own rationale ("what a specifier *is* precedes where it *resolves*…") bakes the error in.
Resolution criterion: re-derive §2's order from 0023 §7.2's no-lookup-before-authorization principle — specifier-shape classes first, then the deferred path classes, then session-visibility, then policy denial, then resolution failure, then TLA — and make §1's sentence and the rationale agree. One order, stated once.

**C2. Blocking — phase-5 failure is unspecified, and phase 4 (imports) invalidates phase 3's feasibility answers; AC 12 carries a vestigial rule that contradicts §7.4's own invariant.**
Evidence: §7.3 phase 3 evaluates `CanDeclareGlobal*` "for every name before any mutation… fails atomically"; phase 4 then runs arbitrary user code (imported module bodies); phase 5 instantiates. `import "./m"; var x = 1` where `m` calls `Object.preventExtensions(globalThis)` — or defines a non-configurable accessor for a name the input declares as `function` — makes `CreateGlobalVarBinding`/`CreateGlobalFunctionBinding` throw *during phase 5*, after some properties were already created (created `var`s are non-configurable and cannot be removed — measured). §7.4 enumerates consequences only for "before phase 5" and "in phase 6"; a phase-5 abrupt completion is in neither bucket. AC 12's interference bullet — "a name made non-configurable mid-input so that its inverse is impossible yields a **failed** transaction reported as an **engine fault**" — is triply wrong under the current model: the journal touches only the evaluator-owned declarative record, whose inverses user code cannot make impossible (a leftover from the retired property-rollback model); "engine fault" contradicts §6's definition; and "failed" is cancellation vocabulary that per §6 ends the session.
Resolution criterion: specify phase-5 semantics in the reference model. The clean fix is cheap: **re-validate all `CanDeclareGlobal*` predicates at the top of phase 5, after imports** — instantiation itself runs no user code (ordinary `DefineOwnProperty` on `globalThis` fires nothing), so recheck-then-mutate is atomic, a recheck failure is an ordinary throw publishing nothing, and §7.4's two buckets become exhaustive. Delete or rewrite AC 12's interference bullet, and add the `import "./preventExtensions"; var x` fixture.

**C3. Material — the journal's scope is stated inconsistently, and whether `[[VarDeclaredNames]]` survives a phase-6 failure is observable and unpinned.**
Evidence: §7.3 phase 5: "Every operation is journaled" — including property creation and VDN updates. §7.4: "the journal covers exactly one record: the **declarative** one." If an implementer journals and rolls back VDN on a phase-6 failure, then after `var w = 1; boom()` the property survives (non-configurable) but `w ∉ [[VarDeclaredNames]]` — so a later `let w` hits the modified restricted-global predicate and is **refused**, where the other reading shadows. No AC pins this.
Resolution criterion: state that VDN additions for bindings that survive are not rolled back, and add the fixture `var w = 1; boom() ⏎ let w` → shadow succeeds.

**C4. Material — the `$_` disable's journaling contradicts both §7.4's vars-survive rule and §7.8's own "permanently".**
Evidence: §7.8: auto-update "disables **permanently**"; also "any top-level declaration of the name `$_` … disables auto-update at instantiation"; §7.4: "The `$_` auto-update disable **is journaled** and rolls back with the input." For `var $_ = 5; boom()`: the `var` binding survives (§7.4 phase-6 rule), but the journaled disable rolls back — leaving auto-update armed over a name the user has declared, verbatim the hazard the declaration rule exists to prevent. Separately, it is undefined whether a *mutation*-triggered ("permanent") disable inside a failing input is journaled.
Resolution criterion: tie the disable's rollback to the fate of what triggered it — a disable from a `var`/`function` declaration survives phase-6 failure exactly as the binding does; one from a lexical declaration rolls back with its cell; mutation-triggered disables are never journaled. Add the `var $_ = 5; boom()` fixture.

**C5. Material — the `interim` class dangles: LLP 0022 §2 no longer defines it, and AC 3 omits it.**
Evidence: §2's taxonomy row "interim — … (LLP 0022 §2)". "Interim" appears in 0022 exactly once, as the unrelated phrase "in the interim"; 0022 §2 *retired* the "provably root-importable" inference. AC 3 lists six classes and omits `interim`, so the taxonomy and its own acceptance criterion disagree.
Resolution criterion: delete the class, or have LLP 0022 §2 define the state it names; make AC 3 enumerate exactly the taxonomy.

**C6. Material — the cross-process sequence allocator has no named owner, no crash-epoch or worker-restart behavior; 0022's ledger explicitly demands them of this document.**
Resolution criterion: name the allocator's home (the natural answer: the session layer assigns the number at receipt, since it is already the single writer) and state what a worker restart does to the domain.

**C7. Material — 0025's `OBL-UNIT-PUBLICATION` obligation on this document's engine seam is not carried anywhere in §6.**
Evidence: 0025 §6/§11: "publishing unit boundaries natively is an obligation on the engine seam… a Rust id wrapped around the FFI call cannot name a unit: one native poll drains a whole callback queue and several timers". §6 assigns target ids and even repeats the one-poll-many-callbacks fact, but the ABI-replacement list contains a cancellation operation and no unit begin/end publication.
Resolution criterion: add native unit begin/end publication to §6's ABI obligations, enumerate the unit kinds, and state whether §7.4's unit-membership line also defines the target-id boundary (answering 0025 OQ 9).

**C8. Material — the noun hunt finds the next candidate: "handle" is silently covering four concepts, one of which must cross the process boundary that another is forbidden to cross.**
Evidence: §6: "A handle is **not** a serializable value and **never crosses a process boundary**" — said of *value handles*. §1: "armed-session binding | the opaque **handle** to the armed snapshot" — an object that must accompany a source request into the worker; LLP 0023 names that kind "opaque, authenticated session **tokens** [which] cross a process boundary". §2 also defines retained platform identity as "a live **handle** to a file object", and §4 calls `require.main` a "live loader-state handle". Four senses, one noun, with a crossing rule stated over the noun — precisely the shape that bit "identity" and "defeated".
Resolution criterion: rename the armed-session binding to a *token* (adopting 0023's vocabulary), and scope §6's never-crosses sentence explicitly to engine value handles.

**C9. Minor — the call-time `import()` check does not say "transitively."** If the selected module M is TLA-free but statically imports a TLA module T, one implementer checks M's bit and another preflights M's static graph. Resolution: add "the same transitive static-graph preflight, applied to the dynamically selected root" to §3 and AC 8.

**C10. Minor — §4's tier-2 disposition overclaims "line- **and column**-stable."** A one-for-one line replacement is line-stable but not column-stable *on the rewritten lines themselves*; AC 2 promises "a correct column" through this stage.

**C11. Minor — "accepted" is defined more loosely here than in 0025.** Add "with the `cancelled` outcome" to §6's accepted row.

**C12. Minor — "entry" covers two concepts in this document's own §1.** "Source role: **entry** or dependency" versus the credential's "**entry kind**" (0022 §2's arming enum). One sentence closes it.

**C13. Minor — two engine premises are not re-measurable by the stated method.** "Lexical declarations do not persist across evaluations" and "a *prior-input* `const` is not enforced" require two `ex_hermes_eval` calls on one runtime; the standalone binary cannot exercise that. State the harness (a two-eval C-API probe) so the verification claim is reproducible.

## 4. Cross-document findings

- **Contradiction (Blocking, = C1):** §2's class order vs LLP 0023 §7.2 and vs this document's own §1.
- **Dangling dependency (= C5):** `interim` cites LLP 0022 §2 for a state 0022 retired.
- **Ledger rows now false in the safe direction (0025 §11):** `OBL-CANCEL-COMPLETION`, `OBL-LIFECYCLE-OUTCOME`, `OBL-SEQUENCE-DOMAIN`, `OBL-DISPLAY-ACK` — all now delivered by the target. Also 0025's `OBL-EXIT-PARK` on 0022 is stale.
- **0022 §7 prose now false:** "LLP 0024 still uses the retired 'decision evidence' terminology" — the target adopted the linear `SubmissionCredential` and explicitly disavows the phrase.
- **0023 `OBL-MODULE-IDENTITY`:** still true at this revision — §7.9 defers with no inline tuple; script inputs have no module identity in both documents.
- **Duplication:** the four-row `.load` edge table appears verbatim in both 0022 §8 and 0024 §4. §7.9's own doctrine argues for 0022 citing 0024's table.
- **Other cross-corpus shared nouns worth a glossary line:** "epoch", "generation", "snapshot". None is currently causing a wrong rule; all have the pre-bite shape.
- **Healthy, verified agreements:** five-way outcome type; park-and-discard lifecycle; drain boundary; entry-only TLA and `$_` semantics; `import.meta`/`export` syntax errors; reserved-key refusal; credential field lists; the `repl:`/`ibex:` reservation mirroring LLP 0004's unknown-builtin guard; §4's transform-authority paragraph correctly *declining* to claim LLP 0019's tiers.

## 5. Suggestions

1. Adopt the phase-5 recheck (C2) as the reference model's rule — it restores true atomicity with zero engine support, because instantiation runs no user code between recheck and mutation.
2. Add an advisory **gate 2b**: run the descriptor-matrix and adopted/created fixtures against a standards engine's real Script semantics (`vm.runInThisContext` on V8), quirk-filtered. That is exactly the harness this review used, and it would have caught every one of rounds 2-4's matrix defects without waiting for a human; **the Hermes-relative gate 2 cannot see a wrong *model* of ECMAScript in rows the engine itself lacks.**
3. Pin the microtask question for phase 4: a module body that calls `queueMicrotask` during import evaluation — do those jobs drain before phase 5, before phase 6, or at settlement?
4. Consider whether rolling back an *initialized* lexical (`let x = 1; boom()` → `x` gone) is worth the divergence from Node/Deno (both keep `x = 1`), given the neighboring `var w = 1; boom()` keeps `w`. If kept, say so under deviation (c) explicitly and pin it in a compatibility note.
5. Add a small vocabulary table for "handle/token" (C8) and one line for "entry role vs entry kind" (C12), following §2's identity-table pattern.
6. In §9, consider making the drop marker carry the *highest dropped sequence number*, not only a count.
7. When fixing C1, state explicitly that ordering between shape-disjoint classes is vacuous and the normative content is the *decision staging* — that framing is what makes the order derivable rather than memorized.

## 6. Open questions

1. Phase-4 microtask timing: when do jobs queued by imported modules run relative to phases 5-6?
2. Is the initialized-lexical rollback divergence from Node/Deno a deliberate cost, and where is it recorded?
3. Who allocates the shared sequence domain under the worker split, and what is a worker restart's epoch story?
4. Does §7.4's TLA-unit membership line also define the target-id unit boundary 0025 OQ 9 asks about?
5. Is there a stated budget or fixture for large `.load` bodies, where every free identifier in a big file becomes a checked environment operation?
6. When the reference model lands, is its state tuple `(declarative record, object record, [[VarDeclaredNames]], journal)` actually sufficient, or does it need `$_` accessor-identity and disable state as a fifth component?

## 7. Readiness verdict

Two blocking findings (C1's self-contradictory, unsafe error order; C2's unspecified phase-5/interference semantics with a vestigial AC) plus the material cluster around journal scope, `$_`, the sequence allocator, and the un-carried unit-publication obligation mean this revision does not yet meet the bar, although every empirical claim now verifies and the architecture is sound.

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

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose` subagent
in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `88ebc6349bab` (content hash). *The reviewer computed a working
blob id of `afc4ad94ef90` mid-run; its citations resolve against `88ebc6349bab`, the
revision it was briefed on and the one Codex reviewed concurrently. Noted, not normalized.*
**Redaction:** none.
**Independence:** launched concurrently with the Codex reviewer on the same revision; both
prior artifacts were stashed out of `llp/reviews/` for the duration.
**Method:** the brief instructed the reviewer to **re-measure** every empirical claim, to
hunt the **fifth noun-reuse casualty**, and to **independently probe the compartment leak**.
It re-measured all engine premises (including the two-eval-probe rows through the live
`target/debug/ibex repl`), the ECMAScript claims on V8, the Deno/Bun/Node precedent, and all
18 code claims, and reproduced the session-`var` leak through a real package compartment.
**Transport note:** captured verbatim; the agent transport HTML-escaped `<`, `>`, and `&`
inside code spans and those escapes are decoded here. The reviewer's preamble line and its
italic revision-caveat line (recorded above) are omitted from the body; otherwise unaltered.

### Verbatim review

# Review: LLP 0024 — Structured Evaluation and Session Semantics (round 6)

## 1. Overall assessment

This is a strong, honest, unusually well-evidenced spec, and round 6's new content is right: the phase-5 recheck-then-mutate genuinely makes instantiation atomic with zero engine support; gate 2b is justified by a real, measured engine defect; the two-permit credential fixes a real circularity; deviation (d) now states a leak I verified in shipping code rather than asserting an isolation that does not exist. **Every empirical claim I re-measured is true** — engine premises (including the two-eval-probe rows via the live REPL), revoked-Proxy `Array.isArray`, adopted-vs-created descriptors, `var Object` vs `function Object(){}`, non-configurable undeletability, `var [a,a]` / `let [a,a]`, TDZ `typeof`, `var` on a non-extensible global, realm-visible global `let`, directive-prologue displacement, the realm-global/`globalThis` split, Deno/Bun late binding, Deno-enforces/Bun-does-not `const`, and the forwarding-Proxy compartment leak. Every code claim checked out (details in §3/§4).

What blocks it is the document's own diagnosed disease: **a repair that removes a premise was not chased through every place the premise was assumed.** Round 5 narrowed deviation (c) to *uninitialized* lexicals and re-keyed the restricted-global predicate on provenance — but §7.3's normative predicate text, §7.1's bookkeeping, the matrix, the reference-model state tuple, §7.4's `$_` bullet, and two AC12 fixtures still carry the round-4 semantics. The result is a reopened laundering path the header claims closed, and an acceptance-criteria section that demands two opposite behaviors for the same program. There is also real cross-document drift (sequence-allocator mechanism, credential shape) and a fifth noun-reuse casualty in the making: **epoch**.

## 2. Strengths

- **Empirical discipline (Engine premises, §7.2, §7.7, §8).** Every measured claim reproduced exactly, including the ones earlier rounds got wrong: Bun 1.3.12 silently accepts a write to a prior-input `const` (`c` reads `10`) while Deno 2.9.1 throws `TypeError`; Deno and Bun both yield `2` for the late-binding probe while Node 25 refuses the redeclaration. The §7.2 precedent paragraph is claimed *only as far as the measurement goes* (it correctly concedes the probe cannot distinguish late lookup from cell reuse) — exemplary epistemics.
- **Gate 2b (§7.7) is grounded in a real engine defect I reproduced**: Hermes rewrites an adopted `{writable:false,enumerable:false,configurable:true}` property to writable/enumerable/non-configurable and destroys a configurable accessor (turns it into a data property whose value is `undefined`), while V8 Script semantics leave the adopted descriptor untouched. An engine-relative oracle is provably blind in exactly those rows; the conclusion that the lowering must define its own descriptors is forced, not stylistic.
- **Import-before-instantiation plus the phase-5 re-check (§3, §7.3–§7.4)** dissolves a genuinely unimplementable rollback: a fresh session `var` is non-configurable (`delete` returns `false` — measured), so "remove the bindings a failing import created" was impossible, and the atomicity argument (ordinary `DefineOwnProperty` on the realm global runs no user code) is sound on this engine.
- **Deviation (d) tells the truth (§7.7(d))**, and the truth verifies: `makeCompartment` builds a forwarding Proxy (`src/engine/hermes_runtime.cc:2627-2659`) whose `get` forwards every non-withheld name to the real global; the withheld set is only the `__exact*`/`__ibex*` prefixes plus a finite powerful-name list (`:2581-2582`, `:2620-2626`), so a session `var apiKey` *is* readable from package code today. The requirement placed on LLP 0013 correctly names an existing seam (`isWithheld`).
- **§7.1's shadow-not-delete respecification** is exactly ECMAScript (verified both orders on V8), and the resolution order imports the right edge cases (`typeof` on unresolvable vs in-TDZ; inherited globals; accessor control of identifier reads).
- **§8's staged inspection** is honest about the Proxy-detection limit, and its one stated toolkit gap is real (`Array.isArray` throws `TypeError: Proxy has been revoked` — measured); the current `inspect.ts` demonstrably runs user code (raw gets, `toISOString()`, `String(obj)`, `entries()` iteration — `packages/ibex-runtime-js/src/inspect/inspect.ts:90-96,296-304,319,340`), and the REPL calls `Exact.inspect(v, {colors:true, ...})` (`src/bin/ibex/repl/mod.rs:64`), so retiring the pre-colored string is correct.
- **§4's generated source-map inventory** matches code precisely: `aliasNodePathGlobals` is dead (defined `module-loader.js:3545-3550`, never called), while the dirname-binding rewrite (`:3130-3138`, live at `:5559,5566`), the eval-shim preamble (`:5523-5557`), and the `import.meta` replacement (`:3553-3568`) are live and mapless; the tier-2 scanner's own comment claims line alignment only (`:3512-3515`). `EngineFeature::SourceMaps => true` is indeed a lie today (`src/bin/ibex/engine/hermes.rs:1653-1661`) against a disk-`.map`-only mechanism (`hermes.rs:1163-1214`).
- **§6/§9 against the current seam**: `Option<String>` and hardcoded `<eval>` (`engine/mod.rs:33`, `hermes.rs:1515-1524`), NULL-for-undefined NUL-terminated result (`hermes_runtime.cc:3161-3174`; LLP 0002:38-42 confirms it is the semver-major narrow contract), thenable assimilation compiled out on Windows (`:3038-3159`), `IBEX_AWAIT_UNWRAP_TIMEOUT_MS` read per-eval after arming (`:3089-3100`), the one-shot fatal flag and `-1` from poll (`:3689-3718`, matching LLP 0003:118-123), no cancellation on the `Engine` trait with the FFI lock held across the call and the debugger bypass (`hermes.rs:544-575`). I also reproduced the motivating TLA defect live: `const x = await Promise.resolve(41)` then `x` → `ReferenceError` on the shipping REPL.
- **The §2 vocabulary table** and the ledger-friendly cross-referencing style (contributing classes into 0023 §7.2's staging rather than restating the within-tier order) are the right corpus hygiene — where followed (see Concern 8).

## 3. Concerns

**1. BLOCKING — `[[SessionCreatedVars]]` is never defined or populated, and §7.3's predicate text contradicts the round-5 fix, reopening the laundering path.** The header (lines 12–14) says the restricted-global predicate is "re-keyed on **provenance** (`[[SessionCreatedVars]]`)"; §7.7(d) (line 1314) cites "(`[[SessionCreatedVars]]`, §7.3)" as its definition site; §7.4 (line 1204) and AC12 (line 1800) journal it. But §7.3 phase 3 states the predicate as: "restricted iff the name has a non-configurable own global property *and* is not in **`[[VarDeclaredNames]]`**" (lines 1069–1070); §7.1's bookkeeping defines only `[[VarDeclaredNames]]` (lines 926–931); no matrix row populates `[[SessionCreatedVars]]` (the adopt row adds only to `[[VarDeclaredNames]]`, line 1135); and the reference-model state tuple omits it (line 1331). As the body reads, `var undefined ⏎ let undefined` is *admitted*: `var undefined` adopts and enters `[[VarDeclaredNames]]`, so `let undefined` is no longer restricted and shadows `undefined` — the exact laundering the revision claims closed, and §7.3's own sentence "That still refuses `let undefined`" (line 1070) becomes false after adoption. Measured anchor: V8 refuses `let undefined` after a prior-script `var undefined` (my S11 probe), so the session as written diverges from every real engine. *Resolution criterion:* define `[[SessionCreatedVars]]` in §7.1's bookkeeping; add a populate/not-populate column to the matrix (fresh-create and recreate-as-fresh rows add; adopt does not); restate §7.3's predicate over it; add it to §7.7's model tuple; pin `var undefined ⏎ let undefined` (refused) and `var x ⏎ let x` (shadows) as fixtures.

**2. BLOCKING — AC12 demands two opposite behaviors for the same program shape; the `$_` disable bullets contradict §7.8's own fate table.** AC12 contains both "`let x = 1; throw new Error()` **publishes the effect but not `x`**, and `x` is redeclarable" (line 1788 — round-4 semantics, when deviation (c) rolled back every lexical) and "`let x = 1; boom()` leaves `x` as **1** (an *initialized* lexical survives)" (line 1801 — round-5 narrowed (c)). These are the same program (declaration statement completes, then throw) with opposite expected outcomes in one acceptance criterion; no implementation can pass AC12. Same lineage: `let $_;` *initializes* its cell when the declaration statement evaluates, so in `let $_; boom()` the cell survives under narrowed (c), and §7.8's fate table ("rolls back with the cell, **if** that cell was uninitialized and is removed", lines 1407–1414) therefore leaves auto-update *disabled* — contradicting §7.4's bullet ("does not permanently disable a binding it never published" — it *did* publish, line 1222) and AC12's bullet (line 1785). *Resolution criterion:* delete/correct line 1788 to the surviving-lexical semantics; change both `$_` examples to `let $_ = boom()` (uninitialized → removed → disable rolls back), which is the case the rule actually covers; regenerate AC12 from the model — which is the document's own remedy for exactly this defect class.

**3. Material — the journal is contradictory for a lexical cell displaced by a `var`/`function` that then survives a phase-6 failure.** §7.4: the journal "records each lexical cell the input created **or replaced**, together with the displaced cell …, and rollback **restores them**"; also "Structure is restored … which record a name lives in." Apply to `let x = 1 ⏎ var x = 2; boom()`: phase 5 removes the cell and creates the var property; phase 6 assigns `2`, then throws. The var binding survives ("a throw does not un-hoist a `var`"), rollback never touches the object record — but "restores the displaced cell" would resurrect `let x = 1` *on top of* the surviving var, making `x` read `1` while `globalThis.x` is `2`, i.e., the surviving binding §7.4 promises is "left in place" is left in place *and invisible*. The clause "a displaced cell is restored underneath either way" (line 1203) is defined only for lexical-over-lexical replacement; for cross-record replacement "underneath" does not exist, and two implementers will disagree. The adjacent sentence "`[[VarDeclaredNames]]` and `[[SessionCreatedVars]]` are journaled **only so that a phase-5 re-check failure … has defined semantics**" is also vestigial: the re-check precedes *all* mutation, so a re-check failure leaves nothing to journal. *Resolution criterion:* a matrix/journal rule stating that a displaced cell is restored only when the replacing binding itself did not survive (or the deliberate opposite), pinned by fixtures `let x = 1 ⏎ var x = 2; boom() ⏎ x` and the `function`/adopted variants; delete or correct the vestigial journaling sentence.

**4. Material — the gates are four, but the document says three, and AC13 omits gate 2b entirely.** §7.7's intro reads "Three gates, with disjoint jobs" above a table with four rows (1, 2, 2b, 3); AC13 (line 1809) reads "gated by **three gates**" and enumerates only model conformance, model validation, and lowering fidelity — the acceptance criteria never require the model-vs-standards-engine gate that round 6 was substantially about, and whose justification I verified empirically (Concern-free: H10 vs S3). *Resolution criterion:* "four gates" in §7.7 and AC13, with a 2b bullet naming the comparison (`vm.runInThisContext`, descriptor matrix + created/adopted rows) and the quirk-filter's owner.

**5. Material — the phase-4 microtask question is unanswered.** Nothing states when jobs queued by an imported module run: between imports, after phase 5, at the input's first phase-6 suspension, or at settlement — all observably different (`import "./m"` where `m` queues a microtask writing a global the input's first statement reads). §7.4's settlement boundary classifies phase-6-queued jobs (the `queueMicrotask` example) but not import-queued ones ("jobs belonging to the input's own TLA unit" does not obviously include or exclude them), so whether an import-queued throw is the input's outcome or a background event is also open. The phase-5 atomicity argument implicitly assumes no microtask checkpoint between re-check and mutation but never says so. *Resolution criterion:* pin (a) where import-queued jobs drain, (b) their §7.4/§9 classification, (c) an explicit no-checkpoint rule inside phase 5 — each with a fixture.

**6. Material — gate 2's observation channel fails inside its own restricted class.** The channel compares "the completion value … of the whole script (gate 2)" against an undefined session-side fold: for the in-class session `1+1 ⏎ let a = 2`, the concatenated script's completion is `2` (measured: V8 `UpdateEmpty`) while the session's last input completes empty — a correct implementation fails the gate. Separately, `1+1 ⏎ $_` is inside the stated class (`$_` is never *declared*), yet under display acknowledgements the session reads `2` where the one-script arm reads `undefined`. *Resolution criterion:* define the fold (UpdateEmpty across per-input completions) or compare per-input against per-statement-group; exclude inputs referencing runtime-owned bindings (`$_`) from the class, or pin the harness's ack behavior.

**7. Material — deviation (d)'s requirement on LLP 0013 does not close the disclosure channel as narrated.** The requirement withholds names the record **created** (`[[SessionCreatedVars]]`). But §7.1 says a sloppy undeclared assignment (`apiKey = "…"`) creates an ordinary configurable property in *no* session set, and `x = secret ⏎ var x` *adopts* (also outside `[[SessionCreatedVars]]`) — so both spellings still forward through the compartment Proxy (`hermes_runtime.cc:2637-2639`; withheld set at `:2581-2582,2620-2626` covers neither). An operator cannot be expected to know that `var apiKey = s` is package-invisible while `apiKey = s` is package-readable. *Resolution criterion:* either widen the withholding key (and say how sloppy-created names are tracked) or state the residual leak explicitly with the same honesty the sub-case now applies to `var`s, plus a fixture for the sloppy spelling.

**8. Material — the fifth noun-reuse casualty is "epoch," and §2's table does not carry it.** Three distinct counters now share the bare noun: 0024 §9's *worker-restart sequence epoch* ("a worker restart opens a new epoch … the epoch is carried on every event", lines 1611–1612, unqualified); 0025 §6's *work epoch* (opens at in-flight-from-quiescence, closes at quiescence — the latch/escape unit, also used by 0022 §10); 0025 §7's *channel epoch* (control-record authentication). Their reset rules are incompatible (many per session vs once per worker restart), and "the epoch is carried on every event" against 0025's "class and epoch" is exactly the one-noun-two-rules shape that produced *identity/defeated/private global/handle*. *Resolution criterion:* name it ("sequence epoch"/"worker epoch"), add a §2 vocabulary row, and reconcile with 0025 whether the channel epoch and the sequence epoch are one counter or two.

**9. Minor/Non-blocking — phase-5 re-check scope.** "Re-evaluates every `CanDeclareGlobal*` predicate" covers var/function feasibility but not phase 3's restricted-global check for lexicals — an import can install a non-configurable own property at a name the input `let`s. Shadowing is mechanically safe and there is no growing-script analogue, but §7.1 promises no unstated modifications; the model must pick throw-vs-shadow and pin it.

**10. Minor/Non-blocking — secondary noun candidates.** "Snapshot" carries three senses (armed snapshot / deviation (b)'s "snapshots at import" / OQ1's "trap-free value snapshot") — rename (b) to "copied-at-import values" and OQ1 to "introspection capture." "Unit" carries two (work unit with a target id vs the input's TLA settlement unit), and 0025 OQ9 shows the boundary between them is live and unresolved — §6 should either identify them (one id across suspensions) or name both.

**11. Minor/Non-blocking — incomplete adoption of "source label."** §2's table adopts LLP 0023's noun, but "source identity" still appears 7× (vs 3× "label"), including in AC2 and §7.9 — the term containing the corpus's first casualty. Sweep or declare synonymy explicitly.

**12. Minor/Non-blocking — AC20 under-asserts §9.** §9 requires the drop marker carry the count **and the highest dropped sequence number** (with a stated reason a count alone fails LLP 0022 §3); AC20 asserts only "a count."

**13. Minor/Non-blocking — two factual nuances.** (a) §7.3 says the taming "lives in an environment-gated lockdown branch": true of the engine (`hermes_runtime.cc:2404`, `withEnableEval(true)` at `:2792`), but the CLI now force-sets `IBEX_LOCKDOWN=1` unconditionally (`src/bin/ibex/main.rs:319-326`) — the fixture requirement stands; the framing should note the gate is vestigial on the CLI path. (b) The matrix's "function → overwrite the **value**" glosses `CreateGlobalFunctionBinding`'s descriptor reset (measured: clobbering configurable `Object` flips it to enumerable:true/configurable:false); the executable model needs the full semantics — gate 2b would catch this, which is an argument *for* Concern 4's fix.

## 4. Cross-document findings

1. **Sequence-allocator mechanism contradiction (Material).** 0024 §9: "the **session layer owns the allocator**, and assigns the number **at receipt** … a worker that minted its own numbers could lie about them." 0025 §3: "The **supervisor owns the sequence allocator**; **the worker draws ranges from it**." Range-drawing *is* worker-minted numbering — the very thing 0024's threat-model rationale forbids. Owners agree; mechanisms are incompatible; ordering authority differs observably. Per 0022's precedence rule this is an invalid corpus state needing a coordinated revision (0025's `OBL-SEQUENCE-ALLOCATOR` row anticipated exactly this reconciliation).
2. **Credential shape (Material).** 0022 §7 and `OBL-SUBMIT-CREDENTIAL` specify **one** SubmissionCredential, "a one-shot permit, validated and atomically consumed **before any effect**," binding the byte digest; 0024 §1 names precisely that formulation *circular for `.load`* and replaces it with **two affine capabilities**. Additionally, 0022 §7's claim that "LLP 0024 still uses the retired 'decision evidence' terminology" is now false — this revision uses the phrase only to disclaim it. 0022 needs the two-permit revision and the stale sentence removed.
3. **0025 ledger rows now discharged by this revision (safe-direction staleness — repin).** `OBL-UNIT-PUBLICATION` ("verified outstanding at LLP 0024") — 0024 §6 now specifies native begin/end publication for exactly 0025's five unit kinds. `OBL-LIFECYCLE-MECHANISM` — 0024 §6's lifecycle outcome now parks, never unwinds, delivered out of band, matching 0025 §8 verbatim.
4. **0022 `OBL-UTF8` half-dangling.** The "defined transcript resynchronization boundary" is assigned to **LLP 0024 §1**; 0024 specifies the strict refusal but neither defines the boundary nor acknowledges the obligation. Carry it, or explicitly decline it so 0022's fatal-in-transcript stopgap is a decision rather than a gap.
5. **0023 `OBL-MODULE-IDENTITY` re-check (0023's own stamp flags it).** 0023 §2.3 now keys `(runtime, SourceId)` with a defined **project arm** (authenticated root identity + binding-relative lexical-canonical path). 0024 §7.9's fourth bullet still reads as if the root arm may be undefined ("If that component can only express a package identity…"); the conditional is now moot and should acknowledge the landed arm. (Code today is neither: the runtime cache is path-keyed, `module-loader.js:5253-5258`, and the `name@version` identity keys principals only — consistent with both documents' "not yet delivered" posture. 0024's failing-entry-deleted claim verified at `module-loader.js:5690-5691`.)
6. **0024 OQ8 is stale against 0025 §12.** The "one versioned constants annex" OQ8 calls for now exists — `session-constants.json` v1, owned by 0025, pinning renderer depth/breadth/payload/truncation. OQ8 should shrink to what genuinely remains open (completion budget and async-storm window per 0025 OQ8; "maximum input size," which neither document pins).
7. **Minor.** 0024 §2's four-tier table mirrors 0023 §7.2's exactly (consistent today) — given `OBL-ERROR-ORDER`'s history, mark it explicitly as a non-normative projection or reduce it to the class-contribution list. Ledger rows verified consistent in both directions otherwise: five-way outcome, park semantics, cell model, `$_` ack at barrier completion, drain boundary, cancellation algebra/targets/races, module-identity category split, `.load` tables, ordinal rules, reserved schemes. (Also noticed in passing, for 0023's author: §7.2 contains a duplicated existence-oracle paragraph at lines 1435–1451.)

## 5. Suggestions

- Fix Concern 1 as one mechanical change: a matrix column ("enters `[[SessionCreatedVars]]`? yes for create/recreate-as-fresh, no for adopt"), the §7.1 bookkeeping row, the §7.3 predicate, the §7.7 model tuple — then regenerate AC11/AC12 from the model, which also discharges Concern 2 structurally rather than editorially.
- Answer the phase-4 microtask question with the simplest defensible rule: phases 1–5 execute within one job (no checkpoint anywhere, stated); import-queued jobs drain with the input's first phase-6 checkpoint (suspension or settlement) and are classified *background* for §7.4/§9, matching the `queueMicrotask` precedent — then pin it with an import-queues-a-throwing-microtask fixture.
- Put `$_`'s state (disable bit + accessor-identity check) inside the reference model's tuple, or state that §7.8 is pinned only by direct fixtures; today the model cannot generate the `$_` rows AC12/AC14 rely on.
- For gate 2b, name the quirk-filter as owner-authored data (like `loaderExpectations` in LLP 0019) so a V8 quirk cannot silently exempt a wrong model row.
- Novel but cheap: run gate 2b in CI against *two* standards engines (node `vm` + one of Deno/Bun via a script harness) — a quirk-filter entry needed by both is evidence of a wrong model, needed by one is evidence of a quirk; this converts the "quirk-filtered" adjective into a mechanism.
- Consider having the compartment requirement in (d) key on "session-*originated* globals" (created vars ∪ names first defined on the realm global while a session input or its background work was the running principal) if trackable; otherwise add the residual-leak sentence (Concern 7) now, so the security posture is stated exactly.
- Adopt qualified nouns corpus-wide in one sweep: *sequence epoch / work epoch / channel epoch*; *armed snapshot / copied-at-import values / introspection capture*; *work unit / settlement unit*; finish the *source label* rename. Add all to §2's table — it is the right instrument; it just needs the rows.
- Record in §7.3's eval-closure paragraph that the CLI force-sets `IBEX_LOCKDOWN=1` today (`main.rs:319-326`) — it strengthens the case that the fixture, not the env var, is the guarantee.

## 6. Open questions

1. Should the phase-5 re-check cover the full phase-3 feasibility (including the modified restricted-global predicate for lexicals), or only `CanDeclareGlobal*`? Either is defensible; the model must pick (Concern 9).
2. Is a lexical cell displaced by a surviving `var`/`function` restored on failure (shadowing the survivor) or not (Concern 3)? The document's principles pull both ways.
3. Are 0025 §7's *channel epoch* and 0024 §9's worker-restart *sequence epoch* one counter or two?
4. Is an input's TLA unit one work unit (one target id) across suspensions, or does each resumption open a new unit? This is 0025 OQ9, whose owner is this document's engine seam.
5. Do gate-2 fixture arms run with display acknowledgements enabled (deciding whether `$_` can diverge inside the restricted class)?
6. Who owns gate 2b's quirk-filter list, and is a filtered row required to carry the measured engine/standards outputs the way LLP 0019 pins divergences?
7. Where is "maximum input size" pinned, now that 0025 §12 owns the constants annex but does not list it?

## 7. Readiness verdict

The document's empirical and code-level foundations are fully verified and sound, and round 6's mechanisms are the right ones. But two blocking internal contradictions (the unpopulated `[[SessionCreatedVars]]` predicate that reopens the laundering path the revision claims to close; AC12 demanding opposite behaviors for the same program), plus material algorithm gaps (§7.4's cross-record displaced-cell rule, the phase-4 microtask question), a material under-coverage in a security requirement (deviation (d)'s sloppy-assignment residual), gate-definition defects (missing 2b in AC13; gate-2's channel), and cross-document contradictions (allocator mechanism, credential shape) remain unresolved.

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

## Round 7 — 2026-07-12 — HELD ROUND, Fable half only

**Reviewer family:** Claude (Fable)
**Provider / runtime:** Anthropic, Claude Code `Agent` tool, `general-purpose` subagent
in a fresh session whose only context was the review brief.
**Model:** Claude Fable 5 (`fable`)
**Reasoning effort:** max (inherited orchestrator runtime)
**Revision under review:** `6416ccb8c3c2` (content hash of the target, not a Git object)
**Redaction:** none.
**Round status — TERMINAL two-family round, revision `6416ccb8c3c2`.** *(This block was
first written while the round was held single-family — the coordinator had paused new Codex
launches pending the human's decision. It is updated here, honestly, now that the Codex pair
ran against the same revision under the human's bounded endgame authorization: round 7 is
complete and two-family.)* Both families reviewed `6416ccb8c3c2` and returned **NOT READY**;
the Codex half is recorded in its own file. This is the **last** review round of the effort:
the human authorized a terminal minimal-close pass, not a further loop, so the document
finishes at **Status: Draft** — the honest outcome, matching all three siblings, none of
which reached both-families-READY.
**Independence:** launched as a fresh subagent with no access to the orchestrating session,
to any prior LLP 0024 artifact (rounds 1–6 were moved out of `llp/reviews/` to a scratch
stash for the duration — verified absent during the run), or to a Codex half (none exists
for this revision yet).
**Method:** `brief-round7.md` verbatim, which directed the reviewer to **re-measure every
empirical claim including the laundered/adversarial form, not the happy path**, and to hunt
a sixth noun-reuse casualty. It re-ran the engine premises, ~20 ECMAScript claims (both
spellings of the `var undefined ⏎ let undefined` laundering, the commit-iff-initialized
rollback cases, adopted-vs-created descriptors, the `$_` exact-descriptor ABA, the
`vm.createContext`-vs-`runInThisContext` descriptor difference), the Deno/Bun/Node
precedent, and the code claims; it also re-executed the shipping compartment proxy logic to
test the deviation-(d) leak per channel.
**Notable outcome:** the reviewer states plainly it **could not construct the next §7
algorithm defect** of the class that broke rounds 3–6 — the first round in which the core
algorithm survived an adversarial pass. Its verdict is NOT READY on **coherence** grounds
(a dead journal clause, a stale revision-note claim, a false artifact-existence claim, an
incomplete noun sweep, an untracked cross-document obligation), all cheap, none undermining
the design.
**Transport note:** captured verbatim; the agent transport HTML-escaped `<`, `>`, and `&`
inside code spans and those escapes are decoded here. One long strengths bullet that only
enumerated already-cited file:line confirmations was elided to a bracketed summary; no
concern, finding, or verdict text was altered.

### Verbatim review

1. **Overall assessment**

This is a strong, unusually honest normative spec at round 7, and the empirical hygiene the earlier rounds demanded has clearly taken: **every measured claim I re-ran — including the laundered and adversarial forms — reproduced exactly**, on the bundled Hermes, node 25.9.0, deno 2.9.1, and bun 1.3.12. The §7 session algorithm survived a deliberate adversarial pass: I could not construct a defect of the class that broke rounds 3–6 (would-delete-`Object`, impossible rollback, import-invalidated feasibility, unlanded predicate edit). The provenance-keyed restricted predicate closes the laundering path (`var undefined ⏎ let undefined` refused because adoption ≠ creation; verified against real Script semantics on V8, where both spellings are refused), and the commit-iff-initialized rule resolves every displacement/rollback scenario I could invent without contradiction.

What keeps it from READY is a cluster of coherence defects of exactly the kind this corpus polices hardest: a §7.4 journal clause left over from the retired rollback design that records displacements the one rule can never consume; a revision-note claim (§9 adopts sequence *ranges*) that the body explicitly retires; an Open-Questions assertion that `session-constants.json` "now exists" while its owner (0025 §12) states it does not; an incomplete "handle"→token sweep whose fix is described in §2 but never landed in the §1 row it describes; and a security-relevant obligation placed on LLP 0013 (the compartment baseline) that no ledger anywhere tracks — 0024 is the only sibling without a delegated-obligations ledger. All are cheap fixes; none undermines the design.

2. **Strengths**

- **Engine premises are load-bearing and true** (§Engine premises). Re-measured on `tools/hermes/hermes`: no TDZ (`read-before-let → "undefined"`), `const` reassignment a compile error ("invalid assignment left-hand side"), `with` a compile error, direct-eval lexical scope unsupported (warning + ReferenceError), `for(let i…)` closures `3,3,3`, global `var` non-configurable with `delete → false`. The harness note distinguishing one-eval from two-eval probes is exactly the reproducibility discipline a premise table needs.
- **The §7.3 phase structure is genuinely atomic with zero engine support** (§7.3 phase 5). The full-vector re-check-then-mutate argument holds: `CanDeclareGlobalVar/Function` and the modified restricted predicate consume only descriptor state; instantiation is `DefineOwnProperty`-on-data from captured values, so no getter/setter/trap can fire between re-check and mutation. `CanDeclareGlobalFunction`'s writable+enumerable gate even guarantees the "reset descriptor" define never throws on a surviving non-configurable target — the matrix is self-consistent under ECMAScript's own operations.
- **The provenance predicate is the right key and is validated the right way** (§7.1 `[[SessionCreatedVars]]`, §7.3, gate 2b). Measured: `var undefined ⏎ let undefined` → SyntaxError on V8 (`vm.runInThisContext`), `var x ⏎ let x` → SyntaxError on V8 (so shadowing is honestly deviation (a), not a claimed equivalence); created vars non-configurable, adopted vars keep their configurable descriptor and are deletable, deletion-then-redeclaration recreates fresh non-configurable — every matrix row I probed matches. And non-configurable builtins cannot be deleted, so nothing launderable can ever enter `[[SessionCreatedVars]]`.
- **Gate 2b is a real discovery, and its fresh-realm requirement is empirically justified** (§7.7). Measured: `vm.createContext` gives a *configurable* `var` (unsound oracle); `vm.runInThisContext` in a Worker realm gives the standard non-configurable one; Hermes rewrites an adopted `{writable:false,enumerable:false,configurable:true}` to writable/enumerable/non-configurable and turns a configurable accessor into a data property (both reproduced via indirect eval) — precisely the rows where an engine-relative gate is blind.
- **Deviation (d) states a leak instead of asserting an isolation** (§7.7(d)). Verified in shipping code and by faithful re-execution of the shipping proxy logic on both node and Hermes: `makeCompartment`'s `get` trap forwards every non-withheld name to the real global (`src/engine/hermes_runtime.cc:2627-2660`), so a package reads a session `var`, a sloppy assignment, and an adopted-and-assigned builtin (all three leaked in my simulation). Naming the withhold-list patch a *partial* mitigation — and the residual sloppy/adopted spellings — is exactly right.
- **`$_`'s ABA bound is honest and correct** (§7.8). Measured on both V8 and Hermes: after save-descriptor → delete → redefine, the restored descriptor's `.get` is `===` the original — undetectable in pure JS, as stated. The fate-table (disable lives and dies with its trigger's binding, `let $_;` initializes and commits) is the only rule consistent with §7.4.
- **The current-seam indictment is accurate to the line.** [Extensive file:line citations verified — see verbatim record; every claim in §6/§8/§9's diagnosis of the current implementation reproduced at the cited lines.]
- **The error-staging invariant and its deference to 0023 §7.2** (§2) is the correct division: the tiering matches 0023's tiers 1–4 exactly, and 0023's `OBL-ERROR-ORDER` row records 0024's half as landed — which it is.
- **Precedent is measured and claimed only as far as it goes** (§7.2). All reproduced: Deno/Bun yield `2` for the redeclared-closure quartet; Node 25 refuses; Bun 1.3.12 silently accepts a prior-input `const` write (`c` → 10); Deno throws TypeError; `let x = 1; throw` leaves `x = 1` on Node and Deno; the directive-prologue session/concatenation divergence (`undefined` vs `globalThis`) reproduced.

3. **Concerns**

1. **Material — §7.4's journal records displacements the one rule can never consume.** Under commit-iff-initialized, a `var`/`function` *always* commits (initialized in phase 5), so a displaced binding attached to a `var`/`function` — the removed lexical cell *and* the taken-over property — is always "gone" and never restored; only a lexical-declaration's displaced *cell* is ever restored. The property arm is residual text from the retired restore-on-failure design, and it is precisely the pattern §3 warns about ("a repair that removes a premise must be chased through every place that premise was assumed"). Resolution: restate the journal's contents as exactly what the rule consumes (lexical-declaration entries: new cell + displaced cell), or mark var/function displacement entries diagnostics-only; add an AC12 fixture `globalThis.G = 1 ⏎ function G(){2}; boom() ⏎ G` → the function (property not restored).
2. **Material — the revision note contradicts the body it describes.** Header: "the §9 allocator adopts LLP 0025's supervisor-owns-worker-draws-ranges mechanism"; §9 body: "the worker never mints them, **not even in reserved ranges** … the range idea is retired on both sides"; 0025 §3 agrees with the body. The topmost revision entry asserts a mechanism the same revision explicitly retires — a reader of the header alone adopts the wrong (security-relevant: forgeable-ordering) mechanism. Resolution: correct the round-6 note so the revision log describes the landed state.
3. **Material — OQ8 asserts an artifact exists that its owner says does not.** 0024 OQ8: "The one versioned constants annex **now exists** — `session-constants.json` v1…"; 0025 §12: the file "**does not exist yet**, and this document does not claim it does"; verified: no `session-constants.json` in the repo. Resolution: reword OQ8 to "0025 §12 now pins the v1 values normatively; the digest-bound file is owed (0025 `OBL-CONSTANTS-ANNEX`)".
4. **Material — the "handle" sweep is described as done but not landed at its origin, and "snapshot" is re-used against its own reservation.** §1's field table still reads "the opaque **handle** to the armed snapshot" while §2 renames exactly that object "session **token**" and narrates §1's usage in the past tense; §6 refers to "the armed-snapshot **token** of §1" that §1 does not contain. Meanwhile §7.7(b) reserves "snapshot" for the armed snapshot, yet §3 says import bindings are "snapshots rather than live bindings", OQ4 says "snapshot imports", and OQ1 introduces a third sense "trap-free value snapshot". Also sweep §2's residual "identity" for what its own table calls a *label*. Resolution: change §1's row to "session token"; replace §3/OQ4's "snapshot(s)"; rename OQ1's ask.
5. **Minor — deviation (d) overstates which channels the shipping proxy leaks.** Measured by re-executing the shipping trap logic on node and Hermes: `get` leaks values and `has` leaks existence, but `getOwnPropertyDescriptor` returns `undefined` and `ownKeys` is empty (the proxy target is a bare `Object.create(null)`; no forwarding traps for those). The *requirement* (close all four channels) is right; the *factual claim* is half wrong. Resolution: narrow the parenthetical to get/has; keep the requirement over values, existence, descriptors, and enumeration.
6. **Minor — gate 2b's treatment of deliberate deviations is unstated.** Several matrix rows deliberately diverge from real Script semantics (deviation (a) replacement rows — `var x ⏎ let x` is a SyntaxError on V8 and a shadow in the model), and the quirk-filter is defined only for engine quirks, not for model-vs-standards deviations. As written, a correct model fails 2b on every deviation-(a) row. Resolution: state that 2b's fixture set excludes rows where deviations (a)–(e) fire, or carries owner-authored *expected-deviation* entries distinct in kind from quirk entries.
7. **Minor — two legal same-input combinations are unpinned.** The legal `var f; function f(){}` in one input (ECMAScript GDI: the function binding wins) matches no matrix row and no AC11 collision fixture; Annex B block-level functions have no fixture. Resolution: one sentence stating GDI's precedence is imported unchanged, plus generated fixtures.
8. **Minor — `[[SessionCreatedVars]]`' exit clause is unreachable.** "A name … leaves it only if the property is later deleted" — every created property is non-configurable, hence undeletable, so the exit path can never execute. Resolution: mark it defensive or delete it.
9. **Minor — two small §2/§9 wording defects.** (a) §2's sequence-epoch row says "Reset once per worker restart" while §9 says a restart "advances" it — "reset" invites the rewind reading. (b) §9 distinguishes a TLA rejection from a background failure "by the unit's identity", but §2 defines the settlement unit as "not a cancellation target on its own" with no stated identity. Resolution: s/Reset/Advanced/; one sentence on the discriminator.

4. **Cross-document findings**

- **Dangling security obligation on LLP 0013, tracked nowhere.** 0024 §7.7(d) places the complete fix (compartment baseline captured at arming) on LLP 0013. LLP 0013 (last revised before 0024 existed) contains no mention of it; no ledger row in 0022 §11 or 0025 §11 covers it. 0024 is the only sibling without a delegated-obligations ledger, so its outbound requirements — the 0013 baseline (gating a live disclosure channel), the LLP 0002/0000 ABI amendment, the LLP 0021 registry rows for the private seams, the LLP 0019 amend-if-changed trigger — are all untracked. (Also: 0013's "its properties are exactly the policy's endowments" is contradicted by its own shipping forwarding-proxy mechanism, which 0024 documents and 0013 has not absorbed.)
- **0022 §7 is now false about 0024 (safe direction).** "LLP 0024 still uses the retired 'decision evidence' terminology" — verified: 0024 uses the phrase only in explicit negation. The stale claim should be re-verified and the row's parenthetical updated. (0022's one-credential-linear-lifecycle vs 0024's two-permit decomposition: the two documents should say whose decomposition is normative — 0022's four-stage lifecycle already encodes 0024's ordering.)
- **0025 `OBL-SUSPENDED-UNIT` ("open") looks discharged by this revision.** 0024 §2's work-unit/settlement-unit split answers 0025 OQ9's boundary question. 0025 should re-verify at `0024@6416ccb8c3c2`.
- **Rows verified at `88ebc6349bab` remain true at `6416ccb8c3c2`**: `OBL-UNIT-PUBLICATION`, `OBL-CANCEL-EDGES`, `OBL-SEQUENCE-ALLOCATOR` (at-receipt; ranges retired), 0022's `OBL-DISPLAY-TREE`, `OBL-EVAL-OUTCOMES`, `OBL-EXIT-MECHANISM`, `OBL-DRAIN`, `OBL-MODULE-IDENTITY`, `OBL-LOADER-CLOSED`.
- **0022's `OBL-BOUNDS` "(open in both)"** is now half-stale: 0025 §12 pins values (file owed); 0024 OQ8 correctly routes remaining constants there — once Concern 3's overclaim is fixed.
- **Deliberate duplication that currently agrees**: the `.load` edge table and ordinal rules (0022/0024) are verbatim-equivalent; drift-prone; consider 0022 citing rather than restating.
- **0022 §5's unqualified `$_` promise** ("Any user mutation permanently disables auto-update") is falsifiable by the ABA case 0024 §7.8 honestly bounds. 0022 should adopt or cite the bound.

5. **Suggestions**

- Add a §-numbered **delegated-obligations ledger to 0024** (stable ids, sibling content digests, per 0022 §11 / 0025 §11 discipline): `OBL-COMPARTMENT-BASELINE` (LLP 0013 — the deviation-(d) fix, with the three failing spellings as gating fixtures), the LLP 0002/0000 ABI amendment, the LLP 0021 registry rows, the LLP 0019 trigger, the max-input-size constant owed to 0025 §12.
- Pin the §7 fixtures named in Concerns 1 and 7, plus a lexical destructuring partial-commit case (`let [a,b] = failingIterator()` → `a` committed, `b` removed).
- Gate 2's restricted class excludes inputs that *reference* `$_`; an input that *declares* `$_` also diverges — add "or declares".
- Consider adding "keep-alive handle" and 0025 §9's history *journal* vs §7.4's rollback *journal* to §2's watch-list.
- OQ1's debugger-inspection-path suggestion is good and cheap; promote it to the first step of the §8 patch program.

6. **Open questions**

- Gate 2b's oracle composition: table names `vm.runInThisContext`, prose names "subprocess or Worker, not `vm.createContext`" — presumably `runInThisContext` inside a fresh realm. Worth one clarifying clause.
- Cost envelope of rewriting every free identifier in a large `.load` body (OQ8's max-input-size), and interaction with LLP 0013 per-package frame attribution on the hot path.
- Does the reference model get its own digest-bound row, so "generated from the model" is verifiable — the move 0025 made for its interrupt data?
- OQ7 (Windows async-function lowering): confirmed real in code — should AC8 state it is unclaimable on Windows until settled?

7. **Readiness verdict**

The design is sound and the algorithm withstood adversarial attack — I state plainly that I could not find the next §7 defect of the prior rounds' class. But Material coherence defects remain: the dead journal clause (C1), a revision note asserting a retired mechanism (C2), a false artifact-existence claim its owner disclaims (C3), an incompletely-landed noun sweep in the hazard machinery itself (C4), and an untracked security obligation on LLP 0013 (cross-document). Each is cheap; together they fail the document's own standard.

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
