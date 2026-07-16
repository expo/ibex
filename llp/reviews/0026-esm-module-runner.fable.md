# Reviews of LLP 0026 — ESM Module Runner and Runtime Module Graph (Fable family)

Review artifacts for `llp/0026-esm-module-runner.rfc.md`, recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `48920030446b`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex review of the same revision, and no access to
  any prior LLP 0026 review artifact (none existed — this is round 1). Instructed
  not to read `llp/reviews/`.
- **Method:** subagent, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round1.md`). Brief supplied the
  target, the governing/related LLPs (0007/0009/0004/0019/0013/0014/0021/0023/
  0024/0022/0025 and supporting docs), a required code-verification list, the
  LLP 0005 standard questions, and a fixed output structure ending in an
  explicit verdict line.

### Verbatim review

I have completed all required verification. Now I'll write the review.

## 1. Overall assessment

LLP 0026 is a well-motivated, unusually honest RFC that correctly diagnoses the current architecture, verifies as accurate on every load-bearing `[observed]` claim I checked against the code, and lands in the right place: the bootstrap string transformer (`transformEsmToCjs`) is doing a parser and linker's job, file-at-a-time CommonJS lowering cannot deliver ESM graph semantics, and the LLP corpus (0007's deferred ModuleRunner fork, 0009's "SWC is compatibility, not destiny," 0024's "an asynchronous module graph is a separate design") has been pointing at exactly this document for a month. The layering (ModuleArtifact as the stable contract, native graph owner vs. Hermes-side object identity, oracle-gated conformance corpus, measured migration gates) is sound and matches the repo's established discipline (LLP 0018 fail-loud, LLP 0019 corpus-enforced seams).

Two gaps keep it short of ready. First, the Hermes-compat seam is underspecified to the point of internal tension: §3 requires the transform to apply Hermes compatibility "through the LLP 0019 AST authority," but that authority is a build-time Node/Bun JavaScript script that the hermetic in-process path cannot run, while Phase 5 simultaneously says bootstrap Hermes workarounds are retained — and LLP 0019 is an Accepted decision that there are *exactly two* implementations. Second, the RFC's identity backbone (`SourceId`) is spec-only — none of LLP 0023's `OBL-SOURCE-ID`/`OBL-SOURCE-PROVENANCE` obligations have landed, they are ledgered to LLP 0021 + bundler, and the migration plan neither sequences against them nor reconciles ownership. Both are fixable with targeted revisions, not redesign.

## 2. Strengths

1. **The motivating diagnosis is accurate, and the `[observed]` claims verify.**
   - Ordinary ESM-heavy JS really is served verbatim: `needs_transpile` matches only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`); `needs_js_downlevel` matches `js|mjs|cjs` only when string scans find async generators / `for await` / `using` / loop-scope hazards (`mod.rs:371-422`); a plain ESM module is classified `ModuleKind::Esm` and shipped with its source prefetched, explicitly commented as the "hot path (modern ESM-heavy node_modules)" (`mod.rs:928-946`).
   - `transformEsmToCjs` is exactly the string/delimiter/regex scanner the RFC describes (§Motivation): a character-level scanner tracking single/double quotes, comments, regex-vs-division via prior-token index, and template interpolations (`src/engine/bootstrap/module-loader.js:4224-4325`), a shared multi-line delimiter state machine (`moduleScanState`, `:4651-4755`), line-regex statement classification (`:4706-4715`), and minified-statement splitting (`:4326-4343`, `:4716-4737`). The scanner region and its helpers (`transformImportMeta` `:3605`, `transformDynamicImport` `:4090`, `createDelimiterScanState` `:3967`) span well over a thousand lines and are studded with ticket-numbered repairs (ENG-22514, ENG-22528, ENG-22536, ENG-22811) — strong evidence for the "unbounded JavaScript knowledge is not sustainable here" claim.
   - The "cannot preserve" list (§Motivation) holds. Exports are snapshot assignments, not live bindings (`module.exports.<name> = <name>;`, `module-loader.js:4689`). There is no linking phase — ESM is compiled as a CJS function body and invoked (`:5500-5507`, `:5710-5711`). Top-level await is handled by wrapping the whole body in a fire-and-forget async IIFE (`wrapAsyncModule`, `:5415-5417`), so importers receive exports before the body finishes, with a documented deliberate double-execution of the prefix before the failing `await` (`:5680-5694`, ENG-22811). Interop is heuristic `__esModule`/default-merging (`:5455-5476`).

2. **It correctly resolves the fork its parents left open, with clean authority boundaries.** LLP 0007 explicitly routed a ModuleRunner redesign to a separate Decision/RFC (`0007:45-48`, `:425`, `:428-431`), and LLP 0009 blocked the default switch on "a later ModuleRunner-style loader redesign" (`0009:63-73`). 0026's Summary states the ownership split with 0007 precisely and does not re-litigate the transform-engine choice. The claim that SWC is kept for contract reasons, not architectural preference, matches 0009 verbatim (`0009:13-23,32-37`) and matches the code: SWC is the default engine doing ESM→CJS lowering (`src/module_loader/transpile.rs:33,109`; `Cargo.toml:98-106`), while the pinned Oxc 0.121 candidate exists behind `IBEX_RUNTIME_TRANSFORM=oxc` and deliberately fails on general ESM→CJS and TLA (`transpile.rs:42-80,199,402,414`; Oxc pins at `Cargo.toml:45-53`).

3. **The identity model matches LLP 0023.** ModuleKey `(runtime identity, SourceId)` is exactly 0023 §2.3's key (`0023:676-710`, AC at `:2330`), including the subtleties: chunk pathname is not module identity (RFC §9 vs `0023:749-756`), SourceLabel is display-only (RFC Terminology vs `0023:758-764`), and "aliases mapped to one SourceId share a record; physically coincident sources with distinct SourceIds do not" (RFC security invariant 8) is 0023's hard-link/compartment-collapse analysis restated correctly (`0023:666-674,834-836`).

4. **The TLA design is honest where the current corpus is honest.** LLP 0024 makes TLA entry-only in v1 precisely because "a dependency that suspends has nowhere to suspend to" and names the asynchronous graph as separate work (`0024:464-519`). 0026 §6 builds that graph, keeps `import()` call-time-checked dead-branch semantics consistent with 0024's hard-won rule (`0024:508-515` vs RFC §1 "a dead dynamic branch does not resolve, probe, or fail"), and adopts Node's `ERR_REQUIRE_ASYNC_MODULE` fail-closed shape for sync `require()` of async graphs.

5. **Security invariants are the right ones and match the shipped enforcement architecture.** Import gating at every edge, no caller-selected principal, frame/continuation attribution, and fail-closed deputy handling all correspond to mechanisms that exist today (`checkImportGate` on every `require` edge, `module-loader.js:5441-5446`; schedule-time principal capture and `kNoUserPrincipal` fail-closed sentinel per LLP 0013's revision log, `0013:8`). "No authority by chunk co-residence" and staged authorize-before-read (§1) track 0023's staged-authorization and no-probe rules.

6. **Decision-quality discipline.** Deferring numerical budgets to a measured Phase 0 baseline rather than inventing numbers (§Performance gates), naming the alternatives honestly (each rejected alternative is credited as a useful bridge, §Alternatives), fail-loud non-zero-case-count corpus gating (LLP 0018), and the explicit note that the RFC does not self-accept are all the corpus's process working as intended.

## 3. Concerns

**1. The Hermes-compat seam for the in-process path is underspecified and in tension with Accepted LLP 0019.**
**Severity:** Material.
**Evidence:** RFC §3 requires the transform to "apply Hermes compatibility through the LLP 0019 AST authority or its consolidated successor," and `transform_fingerprint` includes a "Hermes-compat-pass version" (§2), implying transform-time application inside the hermetic Rust pipeline. But the LLP 0019 AST authority is `packages/ibex-devtools/src/scripts/hermes-compat.mjs`, a build-time Node/Bun script; 0019 states the in-process bootstrap has "no JS parser available (no Oxc, no acorn — `parseModuleOrScript` is a build-time Node/Bun tool)" (`0019:40-48`) and decides the rewrite "exists in exactly **two tiers**, by design" (`0019:12-14`) after a documented history of three-implementation drift (`0019:50-62`). Meanwhile RFC Phase 5 says bootstrap scanners are removed *except* "narrowly documented Hermes workarounds still owned by LLP 0019" — i.e., evaluation-time application survives. These cannot all be true at once: either (a) a new Rust/Oxc implementation of the Hermes-compat passes is written (a third implementation, contradicting 0019 as written and requiring the conformance corpus to gain a third runner), or (b) the bootstrap Tier-2 scanner keeps rewriting runner-emitted factory source at evaluation time — which breaks §10's requirement that no stage "silently shift locations" (the bootstrap scanner composes no source maps today) and leaves §3's transform requirement unmet for the in-process path. The RFC's Risks section names the Hermes-quirk gap but not this implementation-language/authority problem, and no migration phase contains the work.
**Resolution criterion:** Add a subsection (or revise §3/Phase 5) that states, for the in-process path: which implementation applies the LLP 0019 passes, in what language, at which stage; how it is gated by the existing two-runner corpus (including whether a third system-under-test is added); how its source maps compose; and that LLP 0019's "exactly two tiers" decision will be revised in the same change, listed as an explicit migration deliverable.

**2. The plan builds on `SourceId` without sequencing against the fact that it does not exist, and without reconciling obligation ownership with LLP 0023's ledger.**
**Severity:** Material.
**Evidence:** The architecture "link[s] ModuleRecords by SourceId" (Summary) and Phase 1 emits artifacts carrying `source_id` and verifies them "against the existing resolver and CapSec graph." But `SourceId` is spec-only: LLP 0023's ledger marks `OBL-SOURCE-ID` and `OBL-SOURCE-PROVENANCE` as **not landed** and owned by **LLP 0021 (+ bundler)** (`0023:2057-2058`); the only `source_id` in the tree is an unrelated capsec grant-authority field (`src/host/mod.rs:1344`), and the module cache today keys on path+target+source hash (`src/module_loader/mod.rs:1717,802`). If Phases 1–2 proceed before the SourceId constructor exists, the runner will key records on paths — entrenching exactly the identity drift 0023 §2.3 was written to prevent — or will implement SourceId ad hoc inside the runner, duplicating an obligation ledgered to another document. Relatedly, RFC §9's provenance manifest *is* `OBL-SOURCE-PROVENANCE`, yet the RFC never names the obligation rows it consumes or co-implements, and AC 12's reconciliation list (0004, 0007, 0009, 0019, 0024) omits LLP 0023 and 0021 entirely.
**Resolution criterion:** State the dependency explicitly: either gate Phase 1's artifact identity on `OBL-SOURCE-ID` landing (naming who implements it), or define a documented interim record key with a mandatory upgrade step; name the 0023 ledger rows (`OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE`, `OBL-MODULE-IDENTITY`) this RFC touches and reconcile ownership; add 0023 (and 0021 if ownership shifts) to AC 12.

**3. "Retires the current general restriction on dependency-level TLA" mischaracterizes the current state.**
**Severity:** Minor/Non-blocking.
**Evidence:** RFC §6 frames dependency-level TLA as currently restricted, and Summary/§Motivation imply the current path simply cannot run it. In the shipped code there is no restriction and no stable error: a dependency whose body trips the await-syntax detection is silently async-wrapped and evaluated fire-and-forget, publishing incomplete exports to importers, with deliberate double-execution of the pre-await prefix (`module-loader.js:5415-5417,5657-5694`; ENG-22811). LLP 0024's entry-only rule, single named error, and manifest preflight are Draft-spec obligations with no implementation (`grep` finds no `unsupported-dependency-TLA`/`ERR_REQUIRE_ASYNC` in `src/` or `crates/`). The design consequence is small, but Phase 0's "record current intentional extensions and divergences" and the migration's compatibility story should start from the true baseline: today dependency TLA is *unsoundly permitted*, not refused — meaning migration can *tighten* observable behavior for packages that accidentally rely on fire-and-forget semantics.
**Resolution criterion:** One honest paragraph in Motivation or §6 describing the current fire-and-forget lowering and its hazards, and a Phase 0 fixture family pinning that behavior as a named divergence, so the switch's behavior delta is deliberate rather than discovered.

**4. The ModuleArtifact/record algebra omits module kinds the loader already has.**
**Severity:** Minor/Non-blocking.
**Evidence:** `source_kind` is "ESM or CommonJS" (§2), but the current loader classifies `builtin`/`cjs`/`json`/`esm` (`src/module_loader/mod.rs:907-927`; LLP 0004:461), JSON is forced to a distinct kind precisely so it is never compiled (`mod.rs:923-927`), and LLP 0023 gives builtins and synthetic modules their own SourceId arms (`0023:704-710`). Import attributes (`with { type: "json" }`) — which the Node oracle requires for ESM JSON imports — appear nowhere, including in the conformance corpus list.
**Resolution criterion:** Extend the artifact/record kind algebra (or explicitly scope it) to cover JSON, builtin, and synthetic module kinds, and add JSON-module/import-attribute rows to the corpus and interop rules.

**5. HMR generations vs. the one-instance identity invariant.**
**Severity:** Minor/Non-blocking.
**Evidence:** §8 creates new graph generations whose records coexist with old ones ("importers either remain on the old coherent generation or relink"), but security invariant 8 and LLP 0023 key one logical instance on `(runtime, SourceId)` with no generation component (`0023:676-710`), and LLP 0024 promises "one file is one module instance." Two live records for one ModuleKey is a real (dev-only) exception to the algebra that neither document currently admits.
**Resolution criterion:** State explicitly how generation composes with ModuleKey (e.g., dev-mode cache key is `(runtime, SourceId, generation)` and the invariant is scoped to a generation), and flag the corresponding 0023/0024 reconciliation.

**6. "Fully linked, synchronous ESM graph" leaves sync `require(ESM)`'s driving obligation ambiguous.**
**Severity:** Minor/Non-blocking.
**Evidence:** §7 says `require()` of "a fully linked, synchronous ESM graph" evaluates synchronously. Read literally, an ESM target that has not yet been loaded/linked (the common case for the first `require`) is outside the rule; the record lifecycle (§5) puts loading before linking with the native owner doing "asynchronous dependency scheduling" (§4). Node's `require(esm)` drives resolution, loading, and linking synchronously. Whether Ibex's sync path may perform synchronous file I/O and parsing through the native owner is load-bearing for the whole interop story and is not stated.
**Resolution criterion:** One sentence: sync `require()` may synchronously drive load→link→evaluate for a graph proven synchronous, including its I/O and transform, or the rule's actual precondition if not.

## 4. Cross-document findings

- **Clean seam with LLP 0007/0009 (verified).** 0007 keeps transform-toolchain authority; 0026 takes graph/link/evaluate/interop. This is exactly the completion state 0007 predicted ("a documented Decision choosing a ModuleRunner-style redesign," `0007:45-48,421-426`) and 0009 deferred (`0009:63-73`). No duplication found; 0026's Summary states the boundary explicitly.
- **Clean consumption of LLP 0023's identity algebra (verified),** with the two gaps in Concern 2: the obligations ledger (`0023:2053-2079`) assigns SourceId and provenance-manifest work to 0021/bundler, and 0026 neither cites nor reconciles those rows; AC 12 omits 0023. One stylistic note: 0023 deliberately removed the defining principal as a component *outside* SourceId ("the outer copy is removed, deliberately," `0023:691-696`); 0026's ModuleArtifact reintroduces a separate `defining_principal` field with a must-agree invariant. As a denormalized carrier field this is defensible, but given 0023's recorded history of "a noun quietly covering two things," the RFC should say explicitly that this field is derived/verification-only, never an independent input.
- **Tension with Accepted LLP 0019** (Concern 1): 0019's "exactly two tiers, by design" cannot survive an in-process AST transform pipeline unrevised; 0026 names 0019 in Phase 5's doc-update list but plans no work item and specifies no implementation seam.
- **LLP 0024 is characterized accurately at the spec level** — entry-only TLA, single named error, static-graph preflight, call-time `import()` checks (`0024:464-519`) — and 0026's §6 retirement note correctly leaves 0024 authoritative for unmigrated modes. The drift risk is temporal: 0024's preflight machinery (dependency manifests) is itself unbuilt, and building it per 0024 and then the runner per 0026 means two metadata emitters unless coordinated (see Suggestion 3).
- **LLP 0013/0014/0021 enforcement points are preserved, not restated** — correct altitude. One unstated interaction: today's enforcement achieves bundled attribution by *per-package chunking* (`0013:8`, enforce/audit auto-enable per-package chunks; sibling resolution via `__exactChunkDir`), whereas 0026 §9 permits multi-module (implicitly multi-principal) chunks attributed via manifest. That is a mechanism change for frame attribution that 0013's text doesn't contemplate; it deserves a sentence and 0013 doesn't appear in AC 12's reconciliation list either.
- **LLP 0025** is invoked in Phase 3 ("LLP 0024/0025 contracts") but absent from the `Related` header — trivial metadata drift.

## 5. Suggestions

1. **Adopt (or explicitly benchmark against) the `System.register` factory contract as the ModuleArtifact factory ABI.** It is a battle-tested lowering target that already expresses live bindings (setter callbacks), hoisted-function cycles, TDZ, star exports, and TLA (`execute` returning a promise) on ES5-era engines, with a decade of ecosystem conformance behind it. Even if Ibex emits its own shape, differential-testing the emitted factories against SystemJS's semantics would buy an independent oracle for the hardest part (binding cells and cycle ordering) — and would sharpen open question 2 (native vs. JS-side cells) with an existing all-JS data point.
2. **Use test262's `language/module-code` and top-level-await suites as a corpus backbone** rather than only hand-written fixtures. The RFC's corpus list is good but bespoke; test262 gives thousands of implementation-neutral cases with known-correct outcomes, and the expected-divergence mechanism the RFC already specifies (named, exact, fail-when-stale) is precisely how to run test262 against a non-native ESM implementation.
3. **Make LLP 0024's dependency manifest an early ModuleArtifact projection.** 0024 needs per-module static edges + TLA bit for its interim preflight; 0026 Phase 1 emits exactly that metadata. If the interim entry-only-TLA enforcement consumes a projection of the Phase 1 artifact, the corpus gets exercised early, 0024's "one stable error" lands from one metadata source, and there is no second emitter to retire.
4. **Reuse the hardened transpile-cache machinery for the artifact cache.** The current cache already has tamper rejection, quota eviction, and publication races handled and tested (`src/module_loader/mod.rs:801-822,2894,2918`); §8's content-addressed artifact cache should name it as the starting point rather than implying new machinery.
5. **Shadow-mode comparison via the CapSec audit/effect log.** The migration risk "shadowing must never execute side effects twice" limits naive dual execution. Comparing the *effect trace* (which the CapSec layer already observes) of corpus runs under old and new loaders gives behavioral equivalence evidence without dual-executing application code in production.
6. **Consider Hermes's native CommonJS-module bundling support when choosing the bytecode carrier** (open question 6): Hermes has engine-level support for statically resolved module bundles; if per-factory HBC proves too heavy, that facility may provide multi-module bytecode with per-module boundaries the provenance manifest can map onto.
7. **State the dev cold-path budget intention now, qualitatively.** Today plain ESM is served verbatim with zero parse (the deliberate hot path, `mod.rs:928-946`); the new design parses everything at least once. The gates cover warm loads; adding "cold first-load of an ESM-heavy graph" as a named Phase 0 metric (it is implied but not listed as a gate) would prevent the one regression users will actually feel in dev.

## 6. Open questions

Beyond the RFC's own list (which is good), these must be answered to refine it:

1. Where does the LLP 0019 Hermes-compat lowering execute in the in-process pipeline, implemented in what language, gated by which corpus runner — and what happens to 0019's two-tier decision? (Concern 1.)
2. What is the sequencing between this RFC's Phase 1 and LLP 0023/0021's unlanded `OBL-SOURCE-ID` / `OBL-SOURCE-PROVENANCE`, and who owns the constructor? (Concern 2.)
3. How does the dev-mode generation compose with `(runtime, SourceId)` identity, and which documents record the exception? (Concern 5.)
4. What are the artifact kinds beyond ESM/CommonJS (JSON, builtin, synthetic), and are import attributes in scope for v1? (Concern 4.)
5. May synchronous `require()` drive load/parse/link synchronously through the native owner (including file I/O and transform), and on which threads? (Concern 6.)
6. What is the observable-behavior delta for packages currently relying on the fire-and-forget dependency-TLA lowering, and is a compatibility flag needed during the default switch? (Concern 3.)
7. For multi-principal chunks (§9), how does frame attribution map a Hermes frame to a principal — per-factory compiled units, manifest-driven ranges, or retention of per-package chunking as the default?

## 7. Readiness verdict

This is a strong RFC: the diagnosis is verified accurate against the code, the architecture is the right one, the corpus/gate discipline is exemplary, and the document is honest about what it does not know. But two material gaps remain. The Hermes-compat seam — the one part of the transform story that cannot be delegated to Oxc — is internally inconsistent and collides with an Accepted decision (LLP 0019) without a planned work item. And the identity backbone the whole security story hangs on (`SourceId`) is an unlanded obligation owned by other documents, with no sequencing, interim key, or ledger reconciliation in the plan. Both are resolvable with focused revisions rather than redesign; with those landed (and the minor accuracy/scope fixes at the author's discretion), I would expect this to be ready in one more round.

VERDICT: NOT READY

---

## Round 2 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `8e12e2b92ab0`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-2 review of the same revision, and no
  access to any prior LLP 0026 review artifact — the round-1 artifacts were
  moved out of `llp/reviews/` into a scratch stash for the duration of the
  round. Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0026/brief-round2.md`) — the round-1 brief
  updated to the new revision hash.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes replacing Ibex's file-at-a-time ESM→CJS compatibility path (Rust SWC lowering for TS/JSX extensions plus a bootstrap string-scanner rewriter for everything else) with a real module runner: Oxc-parsed, provenance-bound `ModuleArtifact`s, `(runtime, SourceId)`-keyed `ModuleRecord`s, System.register-shaped factories with live binding cells, honest async evaluation for top-level await, and explicit CJS interop rules — gated by a Node/V8-oracle conformance corpus and staged behind the existing loader until measured gates pass.

This is a strong, correct diagnosis and a well-constructed plan. I verified every load-bearing `[observed]` claim against the code and found all of them accurate — including the unflattering ones (the deliberate double-execution of pre-`await` prefixes is documented in a code comment exactly as the RFC describes). The RFC's integration with the LLP corpus is unusually precise: it names each document it will amend (0019's two-tier decision, 0024's entry-only TLA rule and §7.9 wording, 0023's one-instance invariant under HMR generations) rather than silently contradicting them, and it correctly routes around the specific crate-level gap LLP 0009 recorded. My concerns are minor: a re-entrancy corner in §5/§7 that should be named, the drift-surface implications of a third Hermes-compat implementation, and small editorial tensions. Nothing I found is materially wrong, incoherent, infeasible, or unsafe.

## 2. Strengths

**Every verified factual claim holds.** The RFC's evidence discipline is real, not decorative:

- *Extension-gated transform with verbatim ESM fast path* (Motivation): `needs_transpile` matches only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`); `needs_js_downlevel` fires on `js|mjs|cjs` only when string scanners detect async generators, `for await`, `using`, or block-scoped loop-closure patterns (`src/module_loader/mod.rs:371-422`). Ordinary ESM-heavy JavaScript really is served verbatim (`src/module_loader/mod.rs:342-361`) and lands in the bootstrap scanner.
- *The bootstrap transformer is a string/regex scanner doing a parser's job* (Motivation): `transformEsmToCjs` (`src/engine/bootstrap/module-loader.js:4224` onward), the shared character-walking lexical helpers with regex-vs-division prior-token heuristics (`module-loader.js:3743-3760`), `transformImportMeta` (`:3605`), and `transformDynamicImport` (`:4090`) total roughly 1,400 lines of a 6,207-line bootstrap, studded with regression-ticket references (ENG-22514, ENG-22520, ENG-22528) that confirm the fragility claim empirically.
- *The current path mishandles dependency TLA rather than refusing it* (Motivation): `wrapAsyncModule` is a fire-and-forget async IIFE (`module-loader.js:5415-5417`), and the invocation-site comment states verbatim that "The prefix before the failing await runs twice; that double execution is a deliberate trade" (`module-loader.js:5680-5686`, ENG-22811). The RFC's decision to pin this as a named Phase 0 divergence before tightening it is exactly right.
- *Current execution is a synchronous CJS function-body chain*: `moduleBody(localRequire, module, module.exports, filename, dir, moduleDynamicImport)` (`module-loader.js:5500-5507`), matching LLP 0004:75-87.
- *SWC and Oxc status*: SWC crates at `Cargo.toml:98-106` do the default lowering (`src/module_loader/transpile.rs:50-58,109`); Oxc is already in-tree — `oxc_resolver` for resolution plus `oxc_parser/semantic/transformer/codegen` pinned `=0.121.0` (`Cargo.toml:45-53`) backing the opt-in `IBEX_RUNTIME_TRANSFORM=oxc` candidate (`transpile.rs:199-265`), exactly as LLP 0009 records.

**The design routes around the actual blocker rather than wishing it away** (§3, Risks). LLP 0009:44-51 records that newer Oxc/Rolldown needs Rust ≥1.94 while the repo pins 1.93.1 (`rust-toolchain.toml`), and that in-tree Oxc 0.121 lacks general ESM→CJS lowering. The runner makes that missing lowering unnecessary — it needs parse, semantics, TS/JSX stripping, and factory codegen, all of which the in-tree 0.121 crates already provide — and still treats pinned-toolchain feasibility as a Phase 1 exit criterion rather than an assumption. That is good decision hygiene.

**Identity handling matches LLP 0023 exactly** (Terminology, §2). The `(runtime, SourceId)` key, the defining-principal-appears-exactly-once rule, and the provenance-manifest treatment of chunks reproduce LLP 0023 §2.3 (`0023:676-710`) faithfully, and the RFC's `defining_principal` denormalization is explicitly framed as a verification field whose mismatch rejects the artifact — respecting 0023's "one noun, one concept" repair history. Phase 1's "no interim path-keyed identity" rule is well-aimed: today's principal attribution map is literally keyed on path strings (`typed_module_principals: HashMap<String, Principal>`, `src/host/mod.rs:191`), which is precisely the debt the RFC refuses to extend. `SourceId` has no Rust implementation yet (no hits in `src/` or `crates/`), and the RFC correctly sequences landing it (with 0023's ledger rows `OBL-SOURCE-ID`/`OBL-SOURCE-PROVENANCE`, `0023:2057-2058`, both still open) before any artifact publication.

**The §9 per-principal carrier constraint takes Hermes attribution granularity seriously.** LLP 0013:328-334 states that one bundled HBC file is one `RuntimeModule`, so `RuntimeModule → package` attribution requires per-package module units or a function-range table. The RFC's v1 rule (per-principal executable carriers; multi-principal carriers only after a prototyped native attribution mechanism passes frame-attribution tests; "a provenance manifest alone never grants attribution") is the correct fail-closed reading, and matches how production enforcement already chunks (`src/bin/ibex/runtime.rs:2816,3018-3045`).

**Honest amendment of LLP 0019 instead of a silent third copy** (§3). The RFC correctly identifies that 0019's AST authority is a build-time Node/Bun script the hermetic in-process path cannot run (`0019:40-48`), names the required third tier as a revision of an Accepted decision, and subordinates it to 0019's real-Hermes behavior corpus.

**The interop section is precise where precision matters** (§7). Scoping the no-partial-execution guarantee to the newly selected target graph — with the mixed re-entry fixture where a running CJS body computes a `require()` of an async graph — closes a hole most designs discover in production. The SWC removal logic correctly tracks *two* independent gates (module-transform role via 0007/0026 gates; parser role via 0024's parse-equivalence pin, `0024:666-674`), so "parser-only SWC" is a recorded state, not an oversight.

**Migration discipline**: shadowing compares CapSec effect traces rather than dual-executing side effects (Phase 2); Phase 0 measures the cold-first-load regression the runner necessarily introduces (today's verbatim path does zero parsing); Phase 4 upgrades the existing bundle-cache/chunk pipeline in place (`runtime.rs:3091-3149,4341`) rather than green-fielding.

## 3. Concerns

1. **Sync/async re-entrancy on in-flight records is not specified.** — **Severity: Minor/Non-blocking.** **Evidence:** §5 gives a monotonic lifecycle and §7 gives rules for TLA-containing graphs and mixed re-entry, but neither states what happens when a synchronous `require()` reaches a record currently in `loading`/`linking`/`evaluating` under an in-flight asynchronous operation (e.g., a TLA-free graph mid-`import()` whose load stage is suspended in async I/O), or when `import()` targets a record currently being synchronously evaluated inside `require(ESM)`. The design principle "never blocks a runtime thread" (Design principles) and the adopted Node oracle (§5: "observable results must match the adopted Node/V8 oracle corpus") constrain the answer — Node has the `ERR_REQUIRE_CYCLE_MODULE`/`ERR_REQUIRE_ASYNC_MODULE` family for these states — but the RFC neither names the rule nor lists the fixture, while it does name the (rarer) mixed re-entry fixture. **Resolution criterion:** add the in-flight-record rule to §7 (fail deterministically; never block; never re-enter evaluation) and add sync-require-meets-async-in-flight and cycle-through-`require` fixture families to the conformance-corpus list.

2. **The third Hermes-compat implementation reopens the drift surface LLP 0019 existed to close, and the end-state tier inventory is unstated.** — **Severity: Minor/Non-blocking.** **Evidence:** LLP 0019's history section documents that three implementations "demonstrably drifted" and the decision deliberately pinned exactly two tiers (`0019:10-15,50-62`). §3 and Phase 1 add a third (Oxc-in-Rust) tier, corpus-gated — the right mechanism — but Phase 5 retains "narrowly documented Hermes workarounds still owned by LLP 0019" in the bootstrap without saying whether the tier-2 string scanner (`fixForOfScoping` in `module-loader.js`) still has consumers once the runner is default, i.e., whether the steady state is two tiers again or three indefinitely. **Resolution criterion:** the planned 0019 revision (or Phase 5) states the intended end-state tier count and the retirement condition for the bootstrap scanner tier.

3. **`role` in the serialized `ModuleArtifact` is in tension with content-addressing.** — **Severity: Minor/Non-blocking.** **Evidence:** §2 lists `role` as an artifact field, then immediately says it is "contextual evaluation metadata … and must not fragment content-addressed artifacts." A field that is present in the serialized artifact but excluded from its identity/cache key is a standing invitation to a cache-key bug. **Resolution criterion:** either move `role` out of the artifact into the evaluation-request context, or state explicitly that it is excluded from `transform_fingerprint`/content addressing and add a fingerprint-coverage test to Phase 1's cache-fingerprint work.

4. **The "Synchronous ESM graph" definition includes a clause the static proof cannot see.** — **Severity: Minor/Non-blocking.** **Evidence:** Terminology defines it as a graph "whose reachable static ESM records contain no top-level `await` and whose required CommonJS evaluation does not suspend." CJS bodies are synchronous by construction and their `require()` edges are dynamic, so "does not suspend" is either vacuous or refers to call-time refusal of a nested `require(async ESM)` — which §7's mixed re-entry rule already handles. As written, the definition implies the static proof covers CJS behavior it cannot inspect. **Resolution criterion:** redefine as TLA-freeness of the statically reachable ESM closure, with CJS-initiated edges governed by §7's call-time rule, and cross-reference §7 from the definition.

5. **The Related-header gloss for LLP 0018 is wrong.** — **Severity: Minor/Non-blocking.** **Evidence:** the header calls it "LLP 0018 (hermetic regression testing)"; the document is "Agent Tooling Should Fail Loud, Not Silent-Green" (`llp/0018-agent-tooling-fail-loud.plan.md:1`). The body usages (fail-loud, non-zero case counts) are correct; only the gloss misnames it. **Resolution criterion:** fix the parenthetical.

## 4. Cross-document findings

- **LLP 0007 (Draft): clean seam, correctly claimed.** 0007:45-48 explicitly routes the case where Oxc cannot satisfy the sync loader contract to "a separate RFC for an async ModuleRunner-style loader"; 0026 is that document, and it leaves 0007 the transform-toolchain authority. Note 0007's own acceptance criteria (`0007:412-426`) complete via "a Decision LLP, or this RFC is revised to Accepted" — when 0026 advances, 0007 needs its completion state recorded (0026's Phase 5/AC 12 covers this).
- **LLP 0009 (Accepted): consistent.** The Rust-pin blocker (`0009:44-51`), the 0.121.0 candidate pin, and "the default switch is blocked on … a ModuleRunner-style loader redesign" (`0009:63-65`) are all reproduced accurately; 0026 is the redesign 0009 anticipated.
- **LLP 0019 (Accepted): deliberate amendment, honestly flagged** (see Concern 2). The RFC also correctly does *not* assign `OBL-SOURCE-PROVENANCE` to 0019 — matching 0023's ledger correction (`0023:2058`).
- **LLP 0023: exact agreement** on `(runtime, SourceId)`, defining-principal-once, lexical path component, provenance manifests, and staged authorization (`0023:655-756`). The HMR-generation extension of the one-instance invariant (§8) is declared as a reconciliation item rather than a silent exception — the right move, since 0023 §2.3 assumes a single generation.
- **LLP 0024: two declared supersessions, both handled.** The entry-only TLA rule and single stable refusal error (`0024:472-519`) are correctly described as specified-but-unbuilt (the code still fire-and-forget wraps, `module-loader.js:5657-5694`); §7.9's delete-on-failure is reconciled to generations in the Acceptance criteria; and the `swc_ecma_parser` dialect pin with Oxc parse-equivalence gate (`0024:666-674`) is preserved as an independent SWC-removal gate. `OBL-MODULE-IDENTITY` (`0023:2078`) is correctly cited as consumed.
- **LLP 0013/0021: enforcement contracts preserved, not paraphrased loosely.** The full evaluation context (constrained-principal set, effect owner, schedule-time identity — `0021:1038-1108`), frame attribution via `CodeBlock → RuntimeModule` (`0013:319-334`), and the per-package chunking prerequisite already live in production code (`runtime.rs:2816,3018`).
- **LLP 0022/0014: clean.** `require.cache` closure (`0022:243-255,980`) and the unbundled direct-file grant-attribute open question (`0022:577,617,988` — `OBL-FILE-GRANTS`) are both cited accurately, with 0026 §7 committing to settle the latter in Phase 2 rather than absorbing it.
- **LLP 0002/0003/0005: consistent** — sync embedding entry points unchanged, async completion via the host-pumped loop, and the bytecode source-fallback rule ("pre-execution load failure only") matches 0005's run-time entry-bytecode fallback (ENG-23484, `0005:103-111`).
- **Duplication to watch:** 0007's Phase 0 fixture suite and 0026's Phase 0 corpus overlap substantially (transform-contract fixtures vs. module-semantics corpus). Not a conflict — 0026's is implementation-neutral and behavior-oracle-based — but the two documents should eventually name one corpus or an explicit containment relationship, or the suites will drift.

## 5. Suggestions

- **State the corpus relationship with LLP 0007's fixture suite** (one corpus, or 0026's corpus subsumes 0007's transform-contract fixtures) so Phase 0 does not build two overlapping harnesses.
- **Name the cold-first-load mitigation options in §8, not just the measurement.** The RFC is honest that the runner parses everything today's verbatim path skips; it could pre-commit the obvious levers (parallel parse of the discovered static frontier, cache pre-warm on install, artifact emission during `ibex`'s existing bundle step) so Phase 0's numbers have somewhere to go if they miss the envelope.
- **Consider making the generation concept a first-class shared noun with LLP 0024 now** rather than at reconciliation time — §5's error-caching, §8's HMR keying, and 0024's recover-by-retry all lean on it, and it currently exists only inside this RFC's prose.
- **Novel/non-standard idea worth a paragraph:** since Rust owns the graph and factories are `System.register`-shaped, the runner could emit a *deterministic linearized evaluation plan* (topological order + SCC groups) into the prepared-mode provenance manifest and have the runtime verify — not compute — it at startup. That turns spec-corner-heavy evaluation ordering into a checkable artifact, shrinks prepared-mode startup work, and gives CapSec an auditable record of what will run in what compartment order before anything executes. It fits the corpus discipline (source mode computes; prepared mode verifies equivalence).
- **Consider a "scanner tombstone" fixture family in Phase 5**: when a bootstrap scanner path is removed, keep one fixture per retired ENG regression (22514/22520/22528/22811) running through the runner, so the new path provably covers every bug the old path accumulated.

## 6. Open questions

The RFC's own eleven open questions are the right ones; the ones that most need answers before implementation hardens, plus two of mine:

1. Which Oxc integration shape (raw AST + Ibex codegen vs. ModuleRunner-style transform) emits the factory contract on Rust 1.93.1 — the Phase 1 exit criterion that everything downstream depends on.
2. Which Node release is the interop oracle, since synthetic named CJS exports and `require(ESM)` behavior differ across releases and must match Rolldown's interop in prepared mode.
3. What exactly happens when synchronous `require()` meets a record in an async in-flight state, and what error class it carries (Concern 1).
4. Whether the bootstrap tier-2 scanner retires at Phase 5 or persists, and what the 0019 end-state tier inventory is (Concern 2).
5. Where binding-cell state lives (native vs. Hermes-owned cells behind opaque handles) — this decides ABI chattiness and the memory-retention profile.
6. What the generation/transaction contract with Vite HMR is, and how stale async completions are fenced at the ABI rather than by convention.

## 7. Readiness verdict

This is a round-2 document and it shows: every load-bearing `[observed]` claim I checked is accurate against the code, the corpus cross-references are precise down to ledger-row names, prior-decision amendments (0019, 0024, 0023) are declared and scheduled rather than smuggled, and the known feasibility risk is correctly demoted to a Phase 1 exit criterion with the in-tree Oxc 0.121 evidence supporting plausibility. The five concerns in §3 are all minor: one specification corner to name (in-flight re-entrancy), one drift-surface end-state to state (compat tiers), two editorial tensions, and one mislabeled gloss. None undermines the design's correctness, coherence, feasibility, safety, or the quality of the decision it proposes; all are resolvable with small text changes and fixture-list additions that do not alter the architecture.

VERDICT: READY

---

## Round 3 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `6fd42d559714`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-3 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–2 artifacts were
  moved out of `llp/reviews/` into a scratch stash for the duration of the
  round. Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-3 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round3.md`) — the round-2 brief
  updated to the new revision hash; same brief as the Codex round-3 reviewer.
- **Orchestrator verification note (outside the verbatim body):** Concern 1's
  dormant-branch finding was independently verified true against
  `src/module_loader/mod.rs` (`ResolveOptions` default leaves `module_type`
  detection disabled; ENG-22950 dormancy note), and was independently reported
  by the concurrent Codex round-3 review of the same revision.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes replacing Ibex's file-at-a-time ESM→CJS compatibility path (Rust-side SWC lowering plus the bootstrap string scanner) with an authenticated module graph: Oxc/Rolldown parse/lower, a provenance-bound `ModuleArtifact`, `ModuleRecord` linking keyed on `(runtime, SourceId)`, a `System.register`-shaped factory ABI with evaluator-owned binding cells, honest asynchronous evaluation including dependency-level top-level `await`, and explicit CommonJS interop.

This is a strong document. The diagnosis is correct and verified against the code: the bootstrap transformer really is a ~1,000-line character/line scanner doing a parser's job, the current dependency-TLA handling really is fire-and-forget with deliberate double execution of the pre-`await` prefix, and live bindings really are lowered to snapshot assignments. The proposed architecture is the standard, ecosystem-proven answer (System.register-class factories with host-owned linking), and the document's distinctive contribution is the security integration: staged authorization at every edge kind, `SourceId`-keyed identity that survives chunking and bytecode, per-principal executable carriers pinned to Hermes's actual attribution granularity, and an adoption gate that reconciles the governing decisions (0007/0009/0019) *before* implementation rather than after. Cross-document seams that in most corpora would be silent contradictions (0024's entry-only TLA rule, 0024 §7.9's delete-on-failure, 0023 §2.3's single-generation identity, 0019's two-tier pin) are each named and given an explicit reconciliation path.

I verified the load-bearing `[observed]` claims against the code. All but one hold exactly; one (the §1 claim that metadata resolution currently performs an unauthorized ESM body read) describes a dormant code path as live behavior, inherited from a stale LLP 0023 ledger entry. That is an accuracy defect worth fixing, but it does not change any decision the RFC makes — the Phase 1 requirement it motivates (body-read-free typed resolution with `.js`/`.mjs` fixtures) is correct either way.

## 2. Strengths

**Code claims are real, and the motivation is honest.** I verified:

- *Transform selection:* `needs_transpile` transforms only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`); `needs_js_downlevel` flags `js|mjs|cjs` only for specific constructs (async generators, `for await`, `using`, loop-scope hazards — `mod.rs:371-422,772-791`). Ordinary ESM-heavy JavaScript is served verbatim, exactly as the Motivation states (`mod.rs:342-347,354-362`; test `serves_plain_module_source_verbatim`, `mod.rs:3855-3865`).
- *The scanner:* `transformEsmToCjs` (`src/engine/bootstrap/module-loader.js:4224` onward, with delimiter/regex machinery at `:3373,3744,3967` and `moduleScanState` balance tracking at `:4651-5038`) is a character-and-line scanner tracking strings, comments, regex-vs-division (`:4235-4304`), template interpolation (`:4319-4325`), minified `}}export{...}` statement splitting (`:4326-4343`), and multiline export baselines — precisely the "rediscovering JavaScript facts" list in the Motivation. Its accreted bug-fix references (ENG-22514, ENG-22528, ENG-22811 in comments) corroborate the fragility claim.
- *Execution model:* modules run through `new Function("require","module","exports","__filename","__dirname","__exactDynamicImport", source)` (`module-loader.js:240-273`) — a synchronous CJS function-body loader. Exports are emitted as snapshot assignments (`module.exports.<name> = <name>;`, `module-loader.js:~4689`), so live bindings, TDZ, and ESM cycle semantics are genuinely not preserved; the "cannot preserve" list holds.
- *Fire-and-forget TLA:* `wrapAsyncModule` wraps the body in an unawaited `(async function(){...})();` (`module-loader.js:5415-5417`), and the invocation-retry path's own comment confirms "The prefix before the failing await runs twice; that double execution is a deliberate trade… (ENG-22811)" (`module-loader.js:5679-5694`). The RFC's claim that migration *tightens* behavior, with Phase 0 pinning separate divergence baselines, is exactly the right honesty discipline (Motivation; Phase 0).
- *Entry-TLA machinery:* separate awaited CLI shim exists (`run_entry_with_tla_shim`, `src/bin/ibex/runtime.rs:1616,1652,1664`; bytecode fallback re-selecting `.mjs`, `runtime.rs:1607-1620`).
- *SWC and Oxc roles:* SWC is the default engine, Oxc an opt-in candidate pinned to `=0.121.0` (`Cargo.toml:45-53,98-106`; `src/module_loader/transpile.rs:42-95`), matching LLP 0009. Oxc already resolves (`oxc_resolver`, `mod.rs:824-946`) and the candidate already does AST-based TLA detection (`transpile.rs:286-315`) — useful feasibility evidence for §3.
- *Identity:* `(runtime, SourceId)` with the defining principal exactly once inside `SourceId` matches LLP 0023 §2.3 verbatim (`0023:676-696,704-710`), and the generation/ABA characterization matches 0023's handle table (`0023:1663`).
- *Carrier constraint:* "one HBC file is one `RuntimeModule`" is exactly LLP 0013's recorded constraint (`0013:329-330`), and per-package chunks already exist in production (`__ibexpkg__` machinery, `module-loader.js:137-166,5136-5152`). §9's refusal to let a provenance manifest grant attribution is the single most important security judgment in the document, and it is correct.

**Design quality.** The declare/execute factory ABI with checked cells (§4) is the proven shape for ESM-on-engines-without-ESM; making the ABI reviewable as checked-in canonical artifacts rather than prose (Phase 1) is unusually good practice. §7's mixed re-entry rule — scoping no-partial-execution to the newly selected target graph and owning the caller's prior effects — closes the exact loophole most designs leave undefined. The dual independent SWC-removal gates (module transform vs 0024's parser pin, §3 and Phase 5) show real cross-corpus care; 0024:666-674 confirms the parser pin exists. The adoption gate (decisions amended before implementation, Phase 5 edits merely descriptive) is the correct LLP-process shape.

## 3. Concerns

**1. §1's "current resolver" claim describes a dormant code path as live behavior.**
**Severity:** Minor/Non-blocking.
**Evidence:** RFC §1: "The current resolver does not yet meet this order: metadata resolution reads an ordinary `.js`/`.mjs` body during ESM classification before target authentication." The classification read exists (`src/module_loader/mod.rs:936-946`) but is dormant: the resolver is constructed with `..ResolveOptions::default()` (`mod.rs:105-135`), and `module_type` defaults to `false` (`oxc_resolver-11.18.0/src/options.rs:182,537`; `esm_file_format` returns `None` when disabled, `lib.rs:1909-1910`), so `resolution.module_type()` is `None` and `kind` never becomes `Esm` on this path (`mod.rs:907-922`). The loader's own test note records this: "the resolver runs with `module_type` detection disabled… the resolve-time single-read + prefetch branch (`kind == Esm`) is dormant in this configuration" (`mod.rs:3848-3854`, ENG-22950). No other resolver construction exists in the tree. The same was true at LLP 0023's ledger-stamp commit `3060574776a3` (that revision's `mod.rs` shows the identical dormancy note and default options), so the ledger entry `OBL-RESOLVE-GATE` (`0023:2068`) itself overstates, and 0026 inherits it. Meanwhile LLP 0002:326-327 and LLP 0004:465-466 document metadata resolution as body-read-free — which is currently *accurate* for the shipped default (ENG-23007 tests, `mod.rs:2606-2660`), though the `.ts`-only fixture criticism stands.
**Resolution criterion:** Reword §1 (and note for the 0023 ledger owners) to say the classification body-read is a *latent* path, disabled under the shipped resolver configuration, one configuration flip from live — and that Phase 1 must make the typed resolver body-read-free *by construction* with `.js`/`.mjs` fixtures pinning it. No design change needed; the Phase 1 work item is already right.

**2. Performance gates omit steady-state evaluation overhead of the cell/setter ABI.**
**Severity:** Minor/Non-blocking.
**Evidence:** "Performance and platform gates" covers warm load, prepared startup, cache size/eviction, cold load, compile time, and binary size — all load-time. §4's ABI adds per-update setter fan-out and sentinel-checked reads for live bindings; today's lowered code pays none of that (plain property assignments, `module-loader.js:~4689`). A hot loop reading a mutated imported binding is a realistic ecosystem pattern.
**Resolution criterion:** Add a steady-state execution benchmark (import-access in hot code; export-mutation fan-out; namespace property access) to the Phase 0 baseline and the default-switch gates.

**3. Nothing requires executing the Phase 1 checked-in factories on real Hermes before Phase 2.**
**Severity:** Minor/Non-blocking.
**Evidence:** Phase 1 "check[s] in canonical serialized `ModuleArtifact`s and their generated factories" for review as artifacts; the first real-Hermes execution appears in Phase 2's graph work. The ABI's riskiest assumptions (TDZ sentinel semantics, namespace property ordering/immutability on Hermes, setter dispatch cost, compileability of the factory shape to HBC) are cheap to disprove early and expensive to discover in Phase 2, and LLP 0019's history (its "shape-based tests prove nothing" lesson, `0019:58-62`) argues for engine-honest checks from the first artifact.
**Resolution criterion:** Add to Phase 1: run the checked-in generated factories on real Hermes (fixture-level, no graph needed) — or state explicitly why deferral to Phase 2 is acceptable.

**4. §7 interop rules never explicitly state `import()` called from CommonJS.**
**Severity:** Minor/Non-blocking.
**Evidence:** §7 enumerates ESM-imports-CJS, CJS-requires-CJS, and CJS-requires-ESM (sync-proof and async-refusal), and §6 defines `import()` generally; the conformance corpus lists "literal and computed dynamic imports." But the one interop cell that lets CJS reach *asynchronous* ESM legally — promise-returning `import()` from a CommonJS body (which today exists as `__exactDynamicImport`, `module-loader.js:5497-5499`) — is not named as a rule, and Node has real semantics here that the corpus should pin.
**Resolution criterion:** Add the explicit rule (CJS `import()` of any ESM graph returns a promise, no sync proof required) and a corpus line for it.

**5. §8 promises a reconciliation the Acceptance criteria don't name.**
**Severity:** Minor/Non-blocking.
**Evidence:** §8: "LLP 0023 §2.3 and LLP 0024's one-file-one-instance wording assume production's single generation; both are reconciled explicitly (see Acceptance criteria)." AC 12 names LLP 0024's one-file-one-instance wording and 0023's *obligations ledger*, but not 0023 §2.3's single-generation assumption / the generation-scoping of security invariant 8.
**Resolution criterion:** Add "LLP 0023 §2.3's generation scoping of module identity" to AC 12's enumerated reconciliations.

## 4. Cross-document findings

- **LLP 0007 (fork resolution): clean.** 0007 explicitly routes the failure case into "a documented Decision choosing a ModuleRunner-style redesign" (`0007:45-48`) and lists that redesign as an acceptance outcome (`0007:420-426`). 0026's claim to resolve that fork while leaving 0007 the transform-toolchain authority is the correct division; the Adoption gate requires 0007 to record the resolution, closing the loop.
- **LLP 0009 (Accepted decision): consistent, correctly gated.** 0026's toolchain facts match 0009 exactly: Rust pinned at 1.93.1 (`rust-toolchain.toml`), Oxc pinned `=0.121.0` which compiles on that pin (`Cargo.toml:46-53`, used in `transpile.rs`), newer Rolldown/Oxc requiring newer Rust (`0009:44-51`). 0026 makes amending 0009 an adoption-gate precondition rather than overriding an Accepted decision by RFC — the right process shape. Note in 0026's favor: 0009's blocker was Oxc 0.121's missing *ESM-to-CJS lowering*, which the module runner does not need — the runner needs metadata + factory codegen, which the in-tree `oxc_semantic`/`oxc_codegen` already suggest is feasible on the pin.
- **LLP 0019 (two-tier pin): clean amendment.** 0019 pins "exactly two tiers, by design" (`0019:12-14`) with the scanner tier existing precisely because no parser is available in the bootstrap (`0019:40-48`). 0026 names its third Rust/Oxc tier as a 0019 revision with the tier added as a system-under-test of 0019's corpus, and an end state of two tiers again (Adoption gate). No silent exception.
- **LLP 0023 (identity): matches, one inherited defect, one deliberate tension.** `(runtime, SourceId)`, principal-once-inside-SourceId, and the generated-modules provenance row all match (`0023:676-710`). Ledger obligations and owners match 0026's claims (`OBL-SOURCE-ID`/`OBL-SOURCE-PROVENANCE` owner LLP 0021 + 0023, `OBL-MODULE-IDENTITY`, `0023:2057-2078`). The inherited defect is Concern 1 (stale `OBL-RESOLVE-GATE` characterization). The tension: 0026's `ModuleArtifact.defining_principal` reinstates, as a denormalized field, the outer principal copy 0023 §2.3 removed on redundancy grounds (`0023:691-696`); 0026 addresses this head-on (verification-only, mismatch rejects), which is defensible, but see Suggestions.
- **LLP 0024 (structured evaluation): every seam named.** Entry-only TLA v1 with the async graph as a separate design (`0024:464-519`); the single refusal error specified but unimplemented ("Today it is not… three behaviors for one condition," `0024:487-495`); §7.9 delete-on-failure (`0024:1657-1661`) vs 0026's generations; the `swc_ecma_parser` session-dialect pin with a parse-equivalence gate (`0024:666-674`) vs 0026's dual SWC-removal gates; one-file-one-instance (`0024:1639-1644`) vs generations. 0026 reconciles each explicitly rather than overriding. Minor residue is Concern 5.
- **LLP 0022 / 0014:** `require.cache` closure (`OBL-LOADER-CLOSED`, `0022:980`), generated reserved-key refusal (`0022:560-591,987`), and `OBL-FILE-GRANTS` (tracked in 0022's ledger, owner LLP 0014, `0022:988`) all match 0026 §7's statements.
- **LLP 0013 / 0021:** the frame-attribution granularity constraint matches (`0013:329-330`); the `GraphEvaluationContext` requirements (effect owner, schedule-time identity, complete constrained-principal set) track 0021's vocabulary (`0021:371,1038-1039`).
- **LLP 0012:** Node 24.13.1 pin verified (`runtime-identity.json:10`); 0026 correctly routes oracle changes through a 0012 revision.
- **LLP 0002/0004:** their body-read-free metadata-resolution documentation (`0002:326-327`, `0004:465-466`) currently matches shipped behavior — part of Concern 1's correction, since 0026 (via 0023) implies they are wrong.

No unreconciled conflict or silent duplication found.

## 5. Suggestions

1. **Cite SES/Compartment prior art.** Agoric's SES `StaticModuleRecord`/`Compartment` model is the closest existing *security-reviewed* implementation of "authenticated module records with host-mediated linking on an engine without native ESM" — closer to 0026's threat model than SystemJS is. Borrowing its ambient-authority test cases would strengthen the security corpus.
2. **Consider Hermes's native CommonJS-module machinery as a factory carrier.** Hermes ships metro-style module-ID/`require` support in HBC. Mapping per-principal factory sets onto that machinery (rather than plain function values) might buy cheaper dispatch and, potentially, better `RuntimeModule` alignment for §9's attribution question (open question 11). Worth a note in Alternatives or open questions.
3. **Memoize the synchronous-closure proof per `(record, generation)`.** §7's `require(ESM)` sync proof is a transitive property; without memoization, hot computed `require()` paths re-prove it. A cached graph-level "async-tainted" bit invalidated by generation would keep the call-time rule cheap.
4. **Reconsider serializing `defining_principal` at all.** Since it must byte-agree with `SourceId` provenance and is rejected on mismatch, an equivalent design binds it only into the digest chain (no independent field to disagree). That removes the redundancy hazard 0023 §2.3 removed once already, at the cost of needing the `SourceId` decoder wherever the principal is displayed.
5. **State how the corpus obtains its Node/V8 oracle hermetically.** The runtime is hermetic; the test oracle is not. A pinned-Node acquisition rule (and what CI does when the pinned Node is unavailable) belongs with the compatibility-contract section, following LLP 0018's fail-loud discipline.
6. **Name the source-goal detection rule for ambiguous `.js`.** Today goal detection for plain `.js` without a `package.json` `type` is the bootstrap's `looksLikeModuleSyntax` sniff plus compile-failure retry (`module-loader.js:5710-5722`). The RFC says the parse decides "source goal," but parse-both/detect-module semantics (Node's unambiguous-syntax detection) vs manifest-only classification is a real interop decision the pinned Node oracle has opinions about. Make it explicit (also feeds Concern 1's resolver redesign).

## 6. Open questions

Beyond the RFC's own §Open questions (which are good), the review surfaced these as the key ones to answer next:

1. What is the exact ESM/CJS **source-goal classification rule** for extension-ambiguous `.js` in the new typed resolver — manifest `type` only, Node-style unambiguous-syntax detection, or parse-both — and does it match the pinned Node 24.13.1 oracle? (Suggestion 6; determines what replaces both the dormant resolver classification branch and the bootstrap sniff.)
2. Can the `System.register`-shaped factory + checked-cell TDZ semantics be demonstrated on real Hermes (including HBC compilation of the factory shape) in Phase 1, and what does the setter fan-out cost on Hermes? (Concerns 2–3.)
3. Does Oxc 0.121.0's AST/codegen surface suffice on the pinned Rust 1.93.1 to emit the full `ModuleArtifact` (typed edges, export descriptors, live-binding rewrites, `import.meta` capability rewrites, composed source maps), or does the Phase 1 exit criterion force the toolchain-upgrade decision immediately?
4. On which thread/context does the synchronous `require(ESM)` load-link-evaluate drive run when an asynchronous evaluation of an *overlapping* subgraph is already in flight in the same generation — and is the stable cycle/async error family (§6) the answer for every overlap case, not just direct record re-entry?
5. When 0023's ledger entry `OBL-RESOLVE-GATE` is corrected (Concern 1), does the obligation stay "close before Phase 1" or become "keep body-read-free by construction, pinned by `.js`/`.mjs` fixtures" — and who lands the LLP 0002/0004 reconciliation notes?

## 7. Readiness verdict

The RFC is architecturally sound, unusually well-verified against the code it describes, and exemplary in how it handles cross-document authority: every governing decision it touches (0007, 0009, 0019, 0023, 0024) is amended through an explicit gate rather than overridden. Of the code claims I checked, all hold except one — the present-tense unauthorized-body-read characterization in §1, which describes a dormant branch inherited from a stale ledger entry. That and the other four concerns are accuracy and completeness polish: none changes a decision the document makes, each has a cheap, local fix, and the Phase 1 work items remain correct as written even before the fixes land. There is no unresolved material correctness, coherence, feasibility, safety, or decision-quality concern.

VERDICT: READY

---

## Round 4 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `19962358a06f`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-4 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–3 artifacts were kept
  out of `llp/reviews/` in a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-4 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round4.md`) — the round-3 brief
  updated to the new revision hash; same brief as the Codex round-4 reviewer.
- **Orchestrator verification note (outside the verbatim body):** the §4
  finding that `require.cache` is exposed today was verified
  (`localRequire.cache = cache`, `src/engine/bootstrap/module-loader.js:5485`)
  and `OBL-LOADER-CLOSED` is indeed an open obligation (`0022:980`).

### Verbatim review

# Review: LLP 0026 — ESM Module Runner and Runtime Module Graph (round 4)

Target: `llp/0026-esm-module-runner.rfc.md` at revision `19962358a06f` (verified by `shasum -a 256`). All code citations are from `/Users/ccheever/projects/ibex` at this working tree. Nothing under `llp/reviews/` was read.

## 1. Overall assessment

This is a strong RFC and the right architectural call. The core diagnosis — that the bootstrap string transformer is doing a parser and linker's job, and that file-at-a-time CommonJS lowering structurally cannot deliver linked-ESM semantics — is correct and is backed by code that says exactly what the RFC claims it says. I verified every load-bearing `[observed]` claim listed in the brief and found each one accurate, including two that could easily have been fudged: the "ordinary ESM served verbatim" fast path and the subtle "OBL-RESOLVE-GATE describes a latent branch as live" ledger correction, both of which the code confirms precisely.

The proposal is unusually disciplined about its relationship to the rest of the corpus: it takes module identity from LLP 0023 verbatim rather than reinventing it, names its two deliberate normative extensions (the LLP 0019 third tier and the §8 generation dimension) as amendments requiring reconciliation before the phases that need them, and stages implementation behind an adoption gate with a mandatory producer spike so the biggest feasibility risk (Oxc/Rolldown Rust integration on the pinned toolchain) cannot be assumed away. The choice of a `System.register`-shaped factory ABI with evaluator-owned checked cells is well-precedented (SystemJS, SES/Compartment) and correctly identified as the only known way to get TDZ, live bindings, and async SCCs on an engine without native ESM.

My concerns are all minor: a wording contradiction in the artifact digest rule, an unstated module-request-keying question around import attributes, a missing `import.meta.resolve` line, and an unspoken asymmetry in what HMR can actually reload under an immutable armed snapshot. None undermines the design's correctness, coherence, feasibility framing, or safety story.

## 2. Strengths

**Every load-bearing `[observed]` claim I checked is true, with the code in the state described.**

- *Verbatim ESM fast path* (Motivation): `needs_transpile` matches only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`); `needs_js_downlevel` fires only on `js|mjs|cjs` **and** a string-scan hit for async generators / `for await` / `using` / loop-scope hazards (`mod.rs:371-419`); everything else is served verbatim (`mod.rs:342-361`). Ordinary ESM-heavy JS really does bypass transform, so the runner's parse-everything cost is a genuine regression risk — which the RFC itself calls out in Phase 0 and the performance gates.
- *Scanner machinery* (Motivation): `transformEsmToCjs` (`src/engine/bootstrap/module-loader.js:4224` onward) is a hand-rolled character/line state machine tracking strings, comments, regex-vs-division (`lastCodeIndex`, ENG-22528 comments at 4235, 4294-4305), template interpolations (4316-4323), and delimiter balance (`moduleScanState`, 4651-5038), spanning on the order of a thousand lines inside a 6,207-line bootstrap file. The RFC's list of "JavaScript facts it must rediscover" is a fair description, not rhetoric.
- *Fire-and-forget dependency TLA* (Motivation): `wrapAsyncModule` is literally `"(async function() {\n" + text + "\n})();"` with the promise discarded (`module-loader.js:5415-5417`); the retry path re-runs the pre-`await` prefix with a fresh exports object, with an in-code comment calling the double execution "a deliberate trade" (ENG-22811, `module-loader.js:5680-5694`). The RFC's framing — the current path *mishandles* rather than *refuses* dependency TLA, and LLP 0024's entry-only refusal is specified-but-unbuilt (LLP 0024:472-499 confirms both the rule and that "the loader's downlevel trigger does not detect plain top-level `await` at all") — is exactly right, and the Phase 0 requirement to pin the current behavior as named divergence baselines is the correct migration discipline.
- *No live bindings today*: the scanner emits snapshot assignments (`module.exports.name = name;`, `module-loader.js:4633-4646, 4689`), not getters — so the "cannot preserve live bindings" claim holds for the shipping path, while the Alternatives section honestly credits SWC's getter-backed lowering with covering many live-binding cases. That honesty about the middle option strengthens rather than weakens the argument.
- *Latent classification branch* (§1): `ResolveOptions` never enables `module_type` detection (`mod.rs:105-135`), so `resolution.module_type()` yields `None` → CommonJS (`mod.rs:907-922`) and the ESM-classification body read at `mod.rs:936-946` is dead code; the in-tree test note says exactly this ("the resolve-time single-read + prefetch branch (`kind == Esm`) is dormant in this configuration", `mod.rs:3848-3854`), and `resolve_meta_does_not_read_or_transpile_body` (ENG-23007, `mod.rs:2606-2622`) pins body-read-free resolution. Meanwhile LLP 0023's `OBL-RESOLVE-GATE` row (0023:2068) still describes the read as live. The RFC's correction — re-audit the ledger row to say "latent," while noting LLP 0002/0004's body-read-free documentation is currently accurate (LLP 0002:327 cites ENG-23007) — is a genuinely verified cross-corpus fix, not a drive-by claim.
- *CJS-shaped resolver* (§1): merged `require`+`import` condition set (`mod.rs:117-122`), private `#imports` prioritizing `require` (`mod.rs:1630`), unclassified→CommonJS (`mod.rs:921`). The typed `ResolutionKind` contract with cache-key isolation is the right fix and correctly makes source-goal selection a pre-parse input.
- *Principal-before-compile ordering* (§4): `compileModuleBody` sets the pending package id before `new __privFunction(...)` and clears it in `finally` (`module-loader.js:240-262`), exactly the ordering the RFC says the compile-or-load-factory operation must preserve.
- *Entry-TLA machinery exists separately*: `run_entry_with_tla_shim` (`src/bin/ibex/runtime.rs:1616`) and `contains_top_level_await` (`src/bin/ibex/main.rs:1253`) confirm the Motivation's claim that entry TLA has its own awaited CLI path.
- *Dependency posture* (§3, Risks): Oxc is already present in two roles — `oxc_resolver 11.17.0` plus the pinned `=0.121.0` parser/transformer/codegen family (`Cargo.toml:45-53`) — and SWC provides the actual ESM→CJS lowering (`common_js` transform, `src/module_loader/transpile.rs:33-36`), with the Oxc candidate behind `IBEX_RUNTIME_TRANSFORM=oxc` and separated cache tags (`transpile.rs:38-62`). This matches LLP 0009's decision text word for word, including the Rust-pin constraint the RFC elevates to a Phase 1 exit criterion.

**Design-quality strengths:**

- *Identity discipline* (Terminology, §2): `(runtime, SourceId)` is adopted exactly as LLP 0023 §2.3 defines it (0023:676-696), including the hard-won "defining principal appears exactly once, inside SourceId" rule; the RFC even recounts removing a denormalized principal field for the same reason 0023 did. The runtime-identity gloss (pointer-plus-nonce, not LLP 0012 product identity) matches real machinery (`ex_hermes_runtime_nonce`, `src/engine/mod.rs:545,1758-1793`).
- *Attribution granularity honesty* (§9): the per-principal executable-carrier constraint is grounded in LLP 0013's own finding that one HBC file is one `RuntimeModule` and attribution needs per-package units or a function-range table (0013:329-334). "A provenance manifest alone never grants attribution" is exactly the right invariant.
- *Fail-closed sync/async seam* (Design principles, §6, §7): the `require(ESM)` rule (static proof of TLA-freedom, one stable `ERR_REQUIRE_ASYNC_MODULE`-class error, mixed re-entry scoping) mirrors the pinned Node target's semantics, and the explicit refusal to invent a v1 cancellation primitive — deferring to LLP 0024/0025's target-id-exact model (0025:226) — avoids a classic scope trap.
- *Process integrity* (Adoption gate): requiring the 0007/0009/0019 reconciliations *before* implementation beyond spike scope, and requiring an engine-honest producer spike before acceptance, directly encodes LLP 0019's "shape tests prove nothing" lesson (0019:58-62).

## 3. Concerns

**1. The artifact digest rule contradicts its own `source_label` carve-out as written.**
**Severity:** Minor/Non-blocking.
**Evidence:** §2 states "A field is either digest-covered or explicitly derived and recomputed from covered data; there is no third category," but three paragraphs later `source_label` is "excluded from portable artifact identity and the digest's semantic coverage" and is remapped by the consuming runtime — i.e., it is neither digest-covered nor derived from covered data. The intent (labels are non-semantic, machine-local per LLP 0023:758-764, replaced on ingest) is clear, but the schema-listed field `source_label` (§2's `ModuleArtifact` block) sits in a textual third category the rule says doesn't exist. A verifier author reading the rule literally will either cover the label (breaking machine portability) or wonder which sentence wins.
**Resolution criterion:** Reword the no-third-category rule to scope itself to semantic fields and state explicitly that `source_label` is the one non-semantic field, discarded/remapped at ingest and never verified — or move the label out of the canonical wire schema into carrier-local metadata.

**2. Module-request keying under import attributes is not squared with `(runtime, SourceId)`.**
**Severity:** Minor/Non-blocking.
**Evidence:** §1 puts attributes "in link identity exactly like static-edge attributes," and §2 makes `with { type: "json" }` part of the static-edge shape — but the record key (Terminology; Acceptance criterion 5) is `(runtime, SourceId)` with no attribute dimension. Per the import-attributes proposal, hosts key module requests on (specifier, attributes); two requests for one target with conflicting attributes must not silently share an instance. In practice Ibex can refuse kind-mismatched requests at resolution (a JSON `SourceId` arm is only reachable via the attribute, per §2's record algebra), which makes collisions unrepresentable — but the RFC never says this, and "part of link identity" is doing unexplained work.
**Resolution criterion:** One paragraph in §1 or §2 stating the rule: attribute-bearing requests resolve to kind-specific records, kind-mismatched requests for the same `SourceId` fail at resolution (with a corpus fixture), so the record key needs no attribute component.

**3. The most likely §3 implementation is a bespoke Oxc→factory codegen pass, and the RFC under-names that burden.**
**Severity:** Minor/Non-blocking (gated by the adoption-gate spike, which is why this is not Material).
**Evidence:** §3 offers "an Oxc ModuleRunner-style transform, a small Ibex code-generation layer over Oxc's AST, or a Rolldown runtime API," but neither Oxc nor Rolldown emits `System.register`-shaped output today, and LLP 0009:44-51 records that the crate generation compatible with the pinned Rust (`0.121.0`, `Cargo.toml:46-53`) lacks even general ESM→CJS lowering. The realistic v1 producer is therefore Ibex-authored lowering over Oxc's AST — a hand-built transform whose correctness burden is the very thing the Motivation criticizes about hand-built transforms. The mitigations are real (AST base, checked-in canonical artifacts, oracle corpus, engine-honest spike), but the document reads as if an off-the-shelf integration might exist.
**Resolution criterion:** Name the custom codegen layer as the expected default implementation in §3 (with the other two options as upside), so the adoption-gate spike is explicitly scoped to proving *Ibex's own* factory emitter, not a crate selection.

**4. HMR's re-verify-against-existing-snapshot rule implies a package-edit restart requirement that is never stated.**
**Severity:** Minor/Non-blocking.
**Evidence:** §8: "An HMR transaction may only replace module records whose sources re-verify against the *existing* snapshot's integrity and policy." Under LLP 0021, package principals are integrity-bound (locator+digest; 0021:37,205-214), while the Root principal carries identity only (LLP 0023:712-721, `crates/capsec-semantics/src/model.rs` per 0023's citation). So first-party project files can HMR freely, but any edit to a file under an integrity-bound package digest cannot re-verify and requires regenerate-and-restart. That is a defensible and probably intended asymmetry — but a Vite-HMR consumer (§8's last paragraph, open question 5) will hit it immediately, and the RFC never says which sources are actually hot-reloadable.
**Resolution criterion:** One sentence in §8 stating the asymmetry explicitly (root-owned sources re-verify and may HMR; integrity-pinned package bytes cannot change without re-arming), plus a corpus fixture for the package-edit refusal.

**5. `import.meta.resolve` is absent from the contract and corpus.**
**Severity:** Minor/Non-blocking.
**Evidence:** §7 and the conformance corpus cover `import.meta.url`/`filename`/`dirname`/`main`, but not `import.meta.resolve` — which the pinned Node 24 target ships, and which is precisely a resolve-only bridge of the kind LLP 0023's `OBL-RESOLVE-GATE` (0023:2068) exists to gate (today's `require.resolve` still bypasses `checkImportGate`: `module-loader.js:5479-5481` calls `__exactResolvePath` with no gate). If the runner rewrites `import.meta` "through typed runner capabilities" (§3), the resolve capability's authorization and non-disclosure behavior must be specified or explicitly refused.
**Resolution criterion:** Add `import.meta.resolve` to §7's interop rules (supported-and-gated, or refused in v1 with the stable-error family) and to the corpus list.

## 4. Cross-document findings

**Clean seams (verified):**
- **LLP 0007**: the fork is real — 0007 explicitly routes a ModuleRunner-style redesign to "a separate RFC" (0007:279-282) and lists it as one acceptance branch (0007:425). 0026 claims that branch, leaves 0007 the transform-toolchain authority, and Phase 0 requires the two fixture suites to share cases. No overlap of ownership.
- **LLP 0009**: 0026's toolchain-feasibility exit criterion quotes 0009's actual findings (Rust 1.93.1 pin vs 1.94.0 requirement, Oxc 0.121.0 as the compilable pin; 0009:44-51), and 0009's own follow-up (0009:71-73) invites exactly this decision. The SWC-removal double gate correctly imports LLP 0024's separate `swc_ecma_parser` pin (0024:669-673) rather than assuming module-transform retirement frees the crates.
- **LLP 0019**: the two-tier decision and its "build-time Node/Bun tool, no parser in the bootstrap" rationale (0019:12-14, 40-48) are represented accurately; 0026's third tier is framed as an amendment landed with the pass, and the intended end state (retire the scanner tier) matches 0019's direction.
- **LLP 0023**: module identity, SourceId algebra, defining-principal-inside-SourceId, SourceLabel separation, and the provenance-manifest carrier story are adopted without restatement drift (0023:655-764). The obligations-ledger co-implementation claims (`OBL-SOURCE-ID` at 0023:2057, `OBL-SOURCE-PROVENANCE` at 2058, `OBL-MODULE-IDENTITY` at 2078) reference real rows.
- **LLP 0013**: §9's per-principal carrier constraint matches 0013's RuntimeModule-granularity finding (0013:329-334) and per-package chunking already being production enforcement (0013 revision log).
- **LLP 0021/0022**: generation-never-touches-authority (§8) is consistent with the immutable armed snapshot (0021:37,421-424) and regenerate-and-restart (0022:323,351); the reserved-grant-key refusal for direct-file execution matches 0022:560-591 and `OBL-RESERVED-KEYS` (0022:987).
- **LLP 0024/0025**: the TLA entry-only rule, `unsupported-dependency-TLA` error, and dependency-manifest preflight (0024:472-499) are correctly described as the still-correct old-path spec; the no-new-cancellation-primitive stance matches 0025's id-exact model (0025:226,244-245).

**Drift the RFC corrects (verified accurate):** the `OBL-RESOLVE-GATE` row (0023:2068) describes `resolve_meta`'s ESM body read as live; the shipped code has the classification branch dormant (`mod.rs:3848-3854`) and body-read-free resolution pinned by test (`mod.rs:2606-2622`, ENG-23007), with LLP 0002:327 already documenting it. The RFC's "re-audit to say latent" instruction is right.

**Named conflicts with a reconciliation plan (acceptable):** LLP 0024 §7.9's delete-on-failure ("the loader deletes it," 0024:1657-1661) vs §5's standards error-retention-within-generation — 0026 preserves 0024's motivating retry-after-fix experience via generations and schedules the wording change with the first session consumer; and 0024's one-file-one-instance / 0023 §2.3's generation-less identity vs §8's generation dimension — explicitly gated ("exactly one generation until amended").

**One latent gap worth noting (not a 0026 defect):** 0026 §7 says `require.cache` "stay[s] closed per LLP 0022," but the current bootstrap exposes it (`localRequire.cache = cache`, `module-loader.js:5485`); LLP 0022's `OBL-LOADER-CLOSED` (0022:980) is an open obligation, not shipped state. §7's phrasing could mislead a reader into thinking it describes today; a "(target state; OBL-LOADER-CLOSED is open)" parenthetical would prevent that.

## 5. Suggestions

1. **Generative differential testing of the linker.** The corpus is fixture-based; the factory ABI (§4) is exactly the kind of machinery that property-based graph generation catches best. A small generator producing random module graphs (cycle topology, star re-exports, TLA placement, export mutation schedules) executed on both the Node oracle and Hermes would find linker ordering and cell bugs no hand-written fixture anticipates, cheaply.
2. **Precompute the sync-`require` proof into prepared artifacts.** `has_top_level_await` and typed `static_edges` are already digest-covered (§2); Rolldown can compute the transitive async-tainted bit per module at build time and bind it into the manifest, so production `require(ESM)` needs no runtime closure walk at all — the memoized bit (§7) becomes a verification of a shipped fact rather than a computation.
3. **Name the cross-heap retention problem in Risks.** "Memory retention" (Risks) covers size but not shape: native-owned records holding handles to Hermes namespace/cell objects while those objects close over native handles is a classic cross-heap cycle surface. One sentence assigning ownership direction (native records own JS handles; JS never strongly owns a record) plus a teardown fixture (the existing two-runtime / destroy-recreate corpus entries are close) would close it.
4. **State the entry-role plumbing once.** §2 correctly moves entry-versus-dependency role onto the evaluation request (per LLP 0024), but §1 also has `ResolutionKind::entry` selecting conditions. A sentence relating the two (resolution kind is about condition sets; evaluation role is about TLA admission) would prevent readers from conflating them.
5. **Non-standard idea — treat the bootstrap scanner as a migration oracle, not just dead weight.** During Phases 2–3 shadowing, diff the runner's parsed static-edge set against `transformEsmToCjs`'s discovered rewrites per module and fail loudly on disagreement. The scanner's decade of accreted edge-case knowledge (semicolonless multiline imports, regex/template traps) becomes free test coverage for the new parser integration before it is deleted.
6. Fold the §7 `require.cache` parenthetical (see §4 findings) and the Concern 4 HMR asymmetry sentence into the next revision even if the concerns section items are deferred.

## 6. Open questions

The RFC's own thirteen are well-chosen; questions 1 (integration selection), 5 (HMR transaction contract), 11 (per-factory attribution), and 13 (overlapping-subgraph sync drive) are the ones the spike and Phase 3 must actually answer before the design hardens. To them I would add:

1. How are import-attribute-bearing requests keyed against `(runtime, SourceId)` — refusal-at-resolution for kind mismatch, or an attribute component in the record key? (Concern 2.)
2. Is `import.meta.resolve` supported, and under what authorization/non-disclosure rule? (Concern 5.)
3. Which source classes can an HMR transaction actually replace under an immutable armed snapshot — root-owned only, or is there a dev-mode arming posture where package integrity is deliberately unpinned? (Concern 4; interacts with open question 5.)
4. Who owns whom across the native/Hermes heap boundary for records, cells, and namespaces, and what does generation teardown guarantee about reclamation? (Suggestion 3.)
5. For the shadowing phases: what is the exact disagreement policy when the runner and the legacy path produce different module graphs for the same fixture — fail the run, or record a named divergence? (Phase 2 says "comparing CapSec effect traces"; the graph-shape comparison rule is unstated.)

## 7. Readiness verdict

The RFC's factual foundation is solid: every load-bearing `[observed]` claim I verified against the code is accurate, including the two most falsifiable ones (the verbatim-ESM fast path and the latent-vs-live resolver-read ledger correction). Its relationship to the corpus is carefully managed — authority boundaries with LLP 0007/0019/0023/0024 are explicit, its two normative extensions are flagged as amendments with phase-specific reconciliation, and its riskiest assumptions (toolchain feasibility, factory-ABI expressibility on real Hermes, attribution granularity) are converted into gates rather than asserted. The five concerns in §3 are all wording-precision or completeness items with narrow, mechanical resolutions; none is a correctness, coherence, feasibility, safety, or decision-quality defect in the design itself, and none blocks acceptance of a Draft whose own adoption gate already requires a producer spike before implementation proceeds.

VERDICT: READY

---

## Round 5 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `00abb645d5a7`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-5 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–4 artifacts were kept
  out of `llp/reviews/` in a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-5 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round5.md`) — the round-4 brief
  updated to the new revision hash; same brief as the Codex round-5 reviewer.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes replacing Ibex's file-at-a-time ESM→CJS lowering (Rust SWC transpile for TS/JSX plus the bootstrap string-scanner `transformEsmToCjs` for ordinary ESM) with a host-owned, authenticated module graph: Oxc/Rolldown parsing and lowering into a digest-covered `ModuleArtifact`, native `ModuleRecord` linking keyed by `(runtime identity, SourceId)`, a `System.register`-shaped factory ABI for live bindings/TDZ/cycles, honest asynchronous evaluation for dependency-level top-level `await`, and explicit CommonJS interop pinned to the Node 24.13.1 oracle.

This is the right architecture, and the document is unusually well-grounded. I verified every load-bearing `[observed]` claim against the code and found them accurate — in several cases more precisely worded than the sibling LLPs they cite (the RFC correctly identifies that LLP 0023's `OBL-RESOLVE-GATE` ledger row is stale about the resolve-time body read). The cross-document conflicts a proposal of this scope inevitably creates (LLP 0019's two-tier pin, LLP 0024's entry-only TLA rule and delete-on-failure cache wording, LLP 0023/0024's generation-free module identity) are each named, scoped, and given an explicit amendment plan and phase gate rather than papered over. The migration plan is behavior-gated with an honest adoption gate that requires a real producer spike on real Hermes before implementation proceeds.

I found no material correctness, coherence, feasibility, safety, or decision-quality flaw. Remaining concerns are minor and non-blocking, mostly about sequencing risk and a few contract details deferred to the checked-in canonical artifacts.

## 2. Strengths

- **The motivation is factually correct against the code.** Ordinary ESM really is served verbatim by the Rust loader: `needs_transpile` covers only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`), `needs_js_downlevel` fires only on scanner-detected downlevel triggers in `js|mjs|cjs` (`src/module_loader/mod.rs:371-388`), and everything else round-trips untransformed (`src/module_loader/mod.rs:342-347`, pinned by the ENG-22950 test at `src/module_loader/mod.rs:3848-3865`). The bootstrap then rediscovers module grammar with exactly the string/delimiter/regex machinery the RFC describes (`transformEsmToCjs` at `src/engine/bootstrap/module-loader.js:4224` onward, with regex-vs-division and comment-state special cases at 4235-4305 carrying ticket scars ENG-22514/ENG-22528). Its exports are plain snapshot assignments (`module.exports.x = x;`, e.g. `module-loader.js:4633-4646`, 4899-5040), so the "cannot preserve live bindings/TDZ" claim holds for the shipped path.
- **The fire-and-forget TLA indictment (Motivation) is exact.** `wrapAsyncModule` wraps the body in an unawaited async IIFE (`module-loader.js:5415-5417`, invoked at 5658/5672/5690), the module is published with whatever exports exist at first suspension, and the deliberate double execution of the pre-`await` prefix is documented in-code with ENG-22811 (`module-loader.js:5679-5694`). The claim that entry TLA has separate CLI machinery is verified (`run_entry_with_tla_shim`, `src/bin/ibex/runtime.rs:1616,1652`). Pinning this as a named Phase 0 divergence baseline before tightening it is exactly right.
- **The resolver characterization (§1) is verified.** One merged condition set containing both `require` and `import` (`src/module_loader/mod.rs:117-122`); private `#` imports prioritize `require` (`pick_package_import_path` at `src/module_loader/mod.rs:1617-1640`); unclassified modules default to CommonJS (`mod.rs:921`); and the resolve-time ESM classification read is genuinely *latent* — the `kind == Esm` prefetch branch at `mod.rs:936-946` is dormant because `module_type` detection is disabled (test note at `mod.rs:3848-3854`). The RFC's correction request against LLP 0023's `OBL-RESOLVE-GATE` row (which cites a now-stale `mod.rs:775` body read) is accurate and appropriately scoped.
- **Dependency-state honesty.** SWC is in-tree and in-process as the default engine (`Cargo.toml:98-106`; `src/module_loader/transpile.rs:33-36,78,152-176` — TS strip, JSX, `common_js` lowering), and Oxc is already present in both roles the RFC assumes: `oxc_resolver` in production and the pinned `=0.121.0` AST/transformer stack as an explicit opt-in candidate engine (`Cargo.toml:45-53`; `transpile.rs:42-96`, selected via `IBEX_RUNTIME_TRANSFORM=oxc`). The RFC's two-gate SWC retirement (module-transform gate here, parser-equivalence gate in LLP 0024 §~669's `swc_ecma_parser` pin) matches the corpus. The toolchain-pin risk is real and correctly sourced: LLP 0009 records Rolldown 1.1.1 → Oxc 0.135.0 → Rust 1.94.0 vs the repo's 1.93.1 pin (`0009:44-49`), and the RFC makes pinned-toolchain feasibility a Phase 1 exit criterion rather than an assumption (§3).
- **Attribution design builds on verified mechanisms.** Compile-time principal stamping before `new Function` is exactly what the loader does today (`compileModuleBody`, `module-loader.js:240-262`); the single-scheduler-principal-per-job limitation motivating the Phase 3 context token is exactly what patch 0008 implements (`patches/hermes/0008-schedule-time-principal-capture.patch:18-30,100-105`); and the per-principal executable-carrier constraint in §9 correctly tracks Hermes's `RuntimeModule` granularity as LLP 0013 documents it (`0013:328-332`).
- **Corpus and gate discipline.** Behavior-gated migration against a hermetically acquired Node oracle (pinned at 24.13.1, verified in `runtime-identity.json:10`), fail-loud per LLP 0018, named expected divergences (including LLP 0023's query/fragment strip), CapSec-effect-trace shadowing instead of double side effects (Phase 2), and using the scanner's accreted edge-case knowledge as a free migration oracle before deletion — this is a high-quality migration plan.
- **Self-corrections show design maturity**: removing the denormalized defining-principal field and `SourceLabel` from the portable artifact (§2) both eliminate the "must always byte-agree" redundancy class, correctly citing LLP 0023's own §2.3 precedent.

## 3. Concerns

1. **Phase 1 critical-path breadth.** — **Severity:** Minor/Non-blocking. **Evidence:** Phase 1 co-implements three unimplemented LLP 0023 obligations (`OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE`, `OBL-GRAPH-LOCATION` — all "implemented: no" in 0023's ledger, rows at `0023:2057-2067`; no `SourceId` type exists anywhere in the Rust tree today), plus a typed-resolver rewrite, the canonical artifact wire schema, Hermes-executed canonical factories, and an LLP 0019 revision. That is a very large "first phase," and its obligations have external owners (LLP 0021). The risk is a long-lived half-migrated state where the graph work stalls on capsec-side landings. **Resolution criterion:** Add an explicit intra-Phase-1 ordering (what is the minimal slice that unblocks Phase 2, and which obligations can land behind the experimental flag in parallel), or state which co-implemented obligation is the schedule-critical dependency and who owns it.

2. **Live-binding/TDZ lowering locus is under-specified relative to how load-bearing it is.** — **Severity:** Minor/Non-blocking. **Evidence:** §4 prescribes both setter-per-dependency propagation (System.register shape) and checked-cell TDZ ("reading the sentinel throws"). These compose only if import-site *reads* in the importer are lowered to checked reads (or setter-updated locals initialized to a checked sentinel) — i.e., every hot-path import read may carry a guard. The performance gate section correctly demands measurement of exactly this, but the ABI text never says where the check lives, and the answer determines both the perf envelope and the factory codegen the spike must produce. **Resolution criterion:** One or two sentences in §4 fixing the read-lowering strategy (checked read at import use vs. setter-maintained local with sentinel), or an explicit statement that the checked-in canonical factories (Phase 1) are the normative answer and the prose intentionally defers to them.

3. **Shipped resolver extensions that are not Node-oracle behavior are only generically covered.** — **Severity:** Minor/Non-blocking. **Evidence:** §1 keeps "extension aliases" as retained resolver authority, but the shipped resolver also carries the retry-bare-as-relative heuristic with an ambient `exists()` probe *before* any authorization (`src/module_loader/mod.rs:879-891`) and TS `extension_alias` probing (`mod.rs:126-133`). The typed `ResolutionKind` contract pins condition vectors and `.js` classification to the pinned Node oracle, yet these two deliberate divergences interact with the no-probe rule (§1's staged authorization, security invariant 2) and with cache keying, and are only covered by Phase 0's generic "record current intentional extensions." **Resolution criterion:** Name these two extensions explicitly (in §1 or Phase 0) with their intended disposition in the typed contract — in particular whether the bare-as-relative existence probe survives, and if so where it sits in the authorize-before-probe order.

4. **`require.resolve` gating is left implicit while `import.meta.resolve` is handled.** — **Severity:** Minor/Non-blocking. **Evidence:** §7 routes `import.meta.resolve` through the typed edge gate per LLP 0023's resolve-gate rules, but the shipped CJS `require.resolve` bypasses `checkImportGate` entirely (`module-loader.js:5479-5481`), which is the still-live half of LLP 0023's `OBL-RESOLVE-GATE` row (`0023:2068`). Since the runner will own the require surface after Phase 2's loader-state closure, the RFC is the natural place to say the same typed resolution-only gate covers `require.resolve`. **Resolution criterion:** One sentence in §7 (or the §1 contract) stating that CJS `require.resolve` uses the same resolution-only typed gate and non-disclosing denials as `import.meta.resolve`.

## 4. Cross-document findings

- **LLP 0007:** The fork exists as described — 0007 explicitly routes an async ModuleRunner-style loader to a separate RFC (`0007:281-282`) and lists the decision as open (`0007:364,425`). 0026's authority split (0007 keeps transform-toolchain convergence; 0026 owns graph/linking/evaluation/interop) is a clean seam, and the adoption gate requires 0007 to record the fork's resolution rather than assuming it.
- **LLP 0009:** Accurately characterized — SWC retained as the current reliable implementation, Oxc 0.121.0 pinned as candidate (`0009:19-20`), Rust-pin conflict recorded (`0009:44-49`). 0026 requires amending 0009's scope decision at the adoption gate; no silent override.
- **LLP 0019:** Real conflict, correctly declared. 0019 pins "exactly two tiers" (`0019:12-18`) with a build-time Node/Bun AST authority (`0019:42-43`); 0026 needs a third Rust/Oxc in-process tier and treats that as a planned 0019 revision plus system-under-test of 0019's behavior corpus, with an intended two-tier end state after scanner retirement. This is the right way to amend a sibling Decision.
- **LLP 0024:** Two named conflicts, both handled. (a) The entry-only TLA rule (`0024:472-475`) is superseded for runner consumers with 0024 revised at adoption time; the RFC also correctly notes 0024's refusal is specified-but-unbuilt (the code shows fire-and-forget instead). (b) §7.9's delete-on-failure cache wording ("A failing module's cache entry does not stand. The loader deletes it") is reconciled to errored-record-plus-generation semantics, with the amendment scheduled at first consumer adoption. The RFC also respects 0024's `swc_ecma_parser` session pin (`0024:669`) via the two-gate SWC retirement, and its role-vs-ResolutionKind distinction (§1) preserves 0024's role field cleanly.
- **LLP 0023:** ModuleKey `(runtime, SourceId)` matches 0023's decided key (`0023:679`, `0023:2330`). The generation extension of module identity is flagged as a normative amendment gated before Phase 4, with a one-generation runner until then — the correct fail-closed posture. The `OBL-RESOLVE-GATE` correction the RFC requests is justified: the row's cited body read (`mod.rs:775` at stamp time) is now the dormant classification branch at `mod.rs:936-946`, while the row's `require.resolve` half is still live (see Concern 4).
- **LLP 0022:** The RFC's statement that `OBL-LOADER-CLOSED` (`0022:980`) is open and that 0022's current-state prose overstates closure is verified: the shipped bootstrap exposes `require.cache`/`require.main` (`module-loader.js:5485-5486`) while 0022:243-244 calls them closed surfaces. Good catch; the RFC assigns the correction alongside itself.
- **LLP 0013/0021/0014/0025:** Consistent. Per-package carrier constraint matches 0013's RuntimeModule granularity analysis; generation-never-touches-authority matches 0021's immutable armed snapshot; `authorities` attribute stripping matches `0014:233-234`; the no-new-cancellation-primitive stance matches 0025's id-exact cancellation model (`0025:226`). `OBL-FILE-GRANTS` is recorded in 0022's ledger with LLP 0014 as owner (`0022:988`) — the RFC's attribution "LLP 0014's obligation" is fair but could cite 0022's ledger as its location.
- **Duplication risk:** low. The RFC consistently defers mechanism ownership (cancellation to 0024/0025, source identity to 0023, policy to 0014/0021) and restates only contracts it consumes.

## 5. Suggestions

- **Add a short normative "interfaces" appendix or checked-in schema pointer.** §2's artifact field list is prose plus a pseudo-struct; since Phase 1 checks in canonical serialized artifacts anyway, name the file path where the versioned wire schema will live so reviewers of later phases diff artifacts, not prose.
- **State the single-JS-thread assumption explicitly as an invariant.** §6's overlap-detection argument ("in-flight asynchronous records are quiescent between jobs") silently depends on one JS thread per runtime pumping the loop (LLP 0003). One sentence naming that as a load-bearing assumption — and what breaks if a future embedder pumps from multiple threads — would make the quiescence argument auditable.
- **Consider an explicit "bridge mode" decision point.** The Alternatives section correctly rejects SWC-everywhere and Oxc file-at-a-time as end states, but Phase 2's shadowing period could cheaply adopt Oxc file-at-a-time lowering as the *fallback* (replacing scanner fixes during migration) if scanner defects keep surfacing. Naming the trigger condition for that interim move would prevent ad-hoc scanner growth during a long migration.
- **Novel/non-standard idea:** the RFC already plans to use the scanner as a "free migration oracle." Go one step further and *generate* corpus fixtures from the scanner's ticket history — each ENG-referenced scanner repair (ENG-22514, ENG-22528, ENG-22811, etc.) becomes a named fixture family, so the corpus provably covers every bug the old path ever hit before the scanner is deleted.
- **Consider content-addressed sharing of binding-cell layouts across generations.** HMR generations relink fresh records; for large graphs, most modules are unchanged between generations, and artifact digests already identify them. A note that unchanged-artifact records *may* be structurally shared across generations (without weakening the one-instance-per-generation invariant) would pre-empt the memory-retention risk the Risks section names.

## 6. Open questions

The RFC's own twelve open questions are the right set; the ones that most need answers before implementation, plus two of mine:

1. Which concrete Oxc integration produces the §4 factory shape with the least Ibex-authored codegen on Rust 1.93.1 (RFC OQ 1) — the adoption-gate spike's central question, since neither Oxc nor Rolldown emits it today.
2. Where does the TDZ check live in lowered import reads, and what is its measured hot-path cost (Concern 2; RFC OQ 2 and the perf gate)?
3. What is the minimal Phase 1 slice, and which co-implemented LLP 0023/0021 obligation is schedule-critical (Concern 1)?
4. Does the Node 24.13.1 pin survive through Phase 5, given the interop table (`'module.exports'` marker, `require(ESM)` selection) is pinned to it (RFC OQ 3)?
5. Can Hermes provide per-factory attribution cheaply enough to relax the per-principal carrier constraint, or does per-package chunking remain the permanent production shape (RFC OQs 6/11)?
6. What is the exact HMR transaction contract with Exact/Vite, and does the 0023/0024 generation amendment land in time for Phase 4 (RFC OQ 5)?

## 7. Readiness verdict

This is a strong, verifiable, well-governed RFC. Its factual `[observed]` claims about the current loader, scanner, TLA handling, resolver shape, and dependency state all check out against the code; its conflicts with LLPs 0019, 0023, and 0024 are declared and gated rather than latent; its migration plan is behavior-gated with an honest producer spike before commitment; and its security invariants are consistent with the CapSec corpus and grounded in mechanisms that already exist (compile-time principal stamping, per-package chunking, schedule-time capture). The four concerns above are minor, each with a small, concrete resolution, and none undermines the design's correctness, coherence, feasibility, or safety. As a Draft RFC entering its acceptance decision, it is ready.

VERDICT: READY

---

## Round 6 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `d6120aba94c3`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-6 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–5 artifacts were kept
  out of `llp/reviews/` in a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-6 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round6.md`) — the round-5 brief
  updated to the new revision hash; same brief as the Codex round-6 reviewer.
- **Note:** one line of the verbatim review contains a stray non-English word
  ("SWC/Oxc状态") — preserved verbatim as received.

### Verbatim review

# Review: LLP 0026 — ESM Module Runner and Runtime Module Graph (round 6)

Reviewed at revision `d6120aba94c3` of `/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md` (verified by hash). Read-only review; nothing under `llp/reviews/` was consulted.

## 1. Overall assessment

This is a strong, unusually honest RFC. It proposes the right architecture — replacing a file-at-a-time string-scanner ESM→CJS path with a linked, authenticated module graph — and the motivation survives adversarial code verification: the bootstrap scanner really is a ~900-line character-state machine reimplementing lexer facts, the Rust loader really does serve ordinary ESM verbatim into it, and the current dependency-TLA behavior really is a fire-and-forget async IIFE whose prefix deliberately executes twice. Every load-bearing `[observed]` claim I checked was accurate, including several subtle ones (the *latent* resolve-time body read, the invented condition precedence for `#` imports, the ungated `require.resolve`, the single-scheduler-principal promise-job patch) where a less careful document would have overclaimed in one direction or the other.

The design's decision quality is high: authority boundaries with LLPs 0007/0019/0023/0024 are stated as explicit amendments rather than silent exceptions; the riskiest feasibility assumption (no off-the-shelf producer emits the factory shape, so v1 is a hand-built Oxc lowering) is named and gated behind a producer spike plus a pinned-toolchain exit criterion; and normative weight is placed on checked-in canonical artifacts rather than prose. My concerns are refinements, not blockers.

## 2. Strengths

- **Motivation is code-verified, not rhetorical.** The RFC's claim that ordinary ESM bypasses Rust transforms holds: `needs_transpile` matches only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-368`) and `needs_js_downlevel` fires only for specific constructs (`async function*`, `for await`, `using`, loop-closure captures; `mod.rs:371-422`), so plain ESM `.js` is served verbatim (`mod.rs:928-946`) into the bootstrap. `transformEsmToCjs` (`src/engine/bootstrap/module-loader.js:4224` onward) is exactly the string/delimiter/regex scanner described — hand-tracking single/double quotes, comments, regex-vs-division (`indexAfterRegexLiteral`, `module-loader.js:4294-4305`), template interpolations (`4319-4323`), and multiline statement balance via `moduleScanState` (`4651-5038`) — with ENG-22514/22528 repair commentary embedded in it.
- **The fire-and-forget TLA claim (Motivation) is precisely right.** `wrapAsyncModule` is `"(async function() {...})();"` (`module-loader.js:5415-5417`), and the ENG-22811 comment at `module-loader.js:5679-5694` states verbatim that "The prefix before the failing await runs twice; that double execution is a deliberate trade." The RFC's framing that migration *tightens* behavior, with Phase 0 pinning separate baselines, is the correct treatment.
- **Resolver critique (§1) is accurate in every checked particular.** Merged condition set `["node","require","import","default"]` (`mod.rs:117-122`); private `#` imports iterate a fixed precedence with `require` before `import` (`mod.rs:1630`, test `package_import_condition_prefers_require_over_import` at `mod.rs:2663`); unclassified modules default to CommonJS (`mod.rs:921`); the bare-specifier-as-relative retry does an ambient `exists()` probe (`mod.rs:879-886`). The RFC's "conditions are membership tests, not a precedence order" correction is exactly what the shipped `#`-imports code gets wrong.
- **The "latent branch" nuance (§1) is correct and better than either simple story.** The resolve-time ESM classification read exists (`mod.rs:936-945`) but is dormant because `module_type` detection is disabled (`ResolveOptions` at `mod.rs:105-135`; explicit note at `mod.rs:3848-3850`; test `resolve_meta_does_not_read_or_transpile_body` at `mod.rs:2606-2615`). The RFC correctly says LLP 0023's `OBL-RESOLVE-GATE` row (0023:2068, which still cites a stale live body read) needs re-auditing to "latent," while the `require.resolve` half really is still live-ungated (`module-loader.js:5479-5481` calls `__exactResolvePath` with no `checkImportGate`).
- **Factory-attribution ordering claim (§4) verified.** `compileModuleBody` sets the pending package id before `new __privFunction` and binds the compartment Domain after (`module-loader.js:240-272`), matching "the ordering today's loader already follows."
- **The promise-job attribution gap (§4) verified.** The patched engine arms a single job-scheduler capture (`ex_hermes_vm_set_job_scheduler_capture`, `src/engine/hermes_runtime.cc:3832-3839`), consistent with "stores a single scheduler principal per promise job"; requiring a real context token before dependency TLA ships is the right gate.
- **SWC/Oxc状态 accurately reported.** SWC is the default in-process engine doing `common_js` lowering (`src/module_loader/transpile.rs:1-6, 33-34, 169-173`; crates at `Cargo.toml:98-106`); Oxc is present as pinned `=0.121.0` candidate transform plus the live `oxc_resolver 11.17.0` (`Cargo.toml:45-53`; `TransformEngine::Oxc` behind `IBEX_RUNTIME_TRANSFORM`, `transpile.rs:42-60`) — matching LLP 0009's decision and the RFC's three-gate SWC-removal rule (§3), which correctly leaves LLP 0024's `swc_ecma_parser` session pin (0024:669) out of this RFC's authority.
- **Decision-quality machinery.** The adoption gate (Migration plan) requires document reconciliation *before* implementation, plus a producer spike on real Hermes; performance budgets are deferred to measured Phase 0 baselines instead of invented; the empty-target-matrix vacuity trap is explicitly closed (Performance gates). The `System.register`-shaped ABI with checked-in canonical factories as the normative lowering statement (§4) is the right way to review semantics.
- **Security invariants are the right eight**, and §2's two-digest-domain artifact design (semantic digest vs. payload binding, no third category) shows real hard-won discipline — the removed denormalized-principal field note (§2) matches LLP 0023 §2.3's `SourceId`-carries-principal design (0023:679, 0023:2330).

## 3. Concerns

1. **Synchronous `require(ESM)` cold-drive latency is unbudgeted.** — **Severity: Minor/Non-blocking.** **Evidence:** §7 permits `require()` to "synchronously drive the full load → link → evaluate pipeline… including file I/O and transform," and §6 requires computing "the statically reachable closure and its async-taint proof" before creating any record. On the JS thread, a cold computed `require()` of a large ESM subtree stalls the event loop for the full fetch+parse+transform of the closure. The memoized taint bit (§7) covers warm paths only, and the Performance gates section measures warm loading, prepared startup, and cell overhead — but not this. **Resolution criterion:** add cold sync-drive latency of a representative graph to Phase 0 measurements / the pre-switch gate list (or state explicitly why the existing cold-first-load measurement subsumes it).

2. **The entry-TLA text detector is another scanner with no named retirement.** — **Severity: Minor/Non-blocking.** **Evidence:** the RFC leans on "entry top-level `await` already has separate awaited CLI machinery" (Motivation) and Phase 0 baselines "the entry-TLA shim," but that machinery is itself a textual brace-depth scanner (`contains_top_level_await`, `src/bin/ibex/runtime.rs:3972-3977`, with regex-skipping tests at `runtime.rs:7168-7176`) — precisely the class of grammar-by-string-scan the Design principles prohibit. Phase 5 retires the *bootstrap* scanners, but the CLI entry detector's replacement by the artifact's AST-derived `has_top_level_await` bit is never explicitly assigned. **Resolution criterion:** one sentence in §6 or Phase 5 stating that entry-TLA detection migrates to the artifact's `has_top_level_await` and the CLI text scan retires with the scanner tier.

3. **Normative Node-24 interop prose can drift from the oracle it defers to.** — **Severity: Minor/Non-blocking.** **Evidence:** §7 states exact behaviors ("always contains a named `'module.exports'` entry," conditional `__esModule`, `require(ESM)` return selection) in normative prose while also making the pinned oracle (`runtime-identity.json:10`, Node 24.13.1, per LLP 0012) authoritative and re-pinnable. If a re-pin changes any listed behavior, the prose silently becomes wrong even though the corpus stays right — the RFC already treats staleness as a failure for divergence fixtures, but not for its own prose table. **Resolution criterion:** mark §7's behavior list as descriptive of the current pin with the corpus authoritative, or fold it into the "pinned Node interop table" fixture family it already names, so re-pinning has one owner.

4. **Phase 1 is a wide co-implementation front.** — **Severity: Minor/Non-blocking.** **Evidence:** Phase 1 requires `OBL-SOURCE-ID` (unlanded — no `SourceId` exists anywhere in the Rust tree today), the typed resolver, the wire schema, canonical factories on real Hermes, plus parallel `OBL-GRAPH-LOCATION` and the LLP 0019 third-tier revision (Migration plan; 0023 ledger rows at 0023:2057-2078). The RFC does name the minimal unblocking slice, which is the right mitigation, but the slice still couples this RFC's schedule to two other documents' unbuilt obligations. **Resolution criterion:** none strictly required — already acknowledged as schedule-critical; a fallback statement (what Phase 1 does if `OBL-SOURCE-ID` stalls, e.g. flag-gated hashing of the eventual encoding) would de-risk it further.

## 4. Cross-document findings

- **LLP 0007 seam is clean.** 0007 explicitly routes "a separate RFC for an async ModuleRunner-style loader" (0007:281-282) and lists "A ModuleRunner-style loader redesign before replacing SWC" as an open item (0007:425). 0026's authority split (0007 keeps transform-toolchain convergence; 0026 owns graph/linking/evaluation/interop) matches, and 0026 correctly does not self-accept the fork resolution (Summary).
- **LLP 0009 facts confirmed.** The Rust-pin blockage (Rolldown 1.1.1 → Oxc 0.135.0 → Rust 1.94.0 vs. pinned 1.93.1; Oxc 0.121.0 compiles) is at 0009:43-49, and 0009:69-73 anticipates exactly this redesign. 0026's Phase 1 toolchain exit criterion is the correct treatment.
- **LLP 0019 amendment discipline is correct.** 0019 pins "exactly two tiers" (0019:12-18); 0026 treats the in-process Rust/Oxc tier as a planned 0019 revision with a canonical-mirror-then-flip authority relationship (§3, Adoption gate) rather than a silent exception. No conflict.
- **LLP 0024 seams are clean and honestly described.** The entry-only TLA rule and stable refusal error are specified at 0024:472-496 but unimplemented — the shipped path fire-and-forgets (`module-loader.js:5657-5694`), exactly as 0026 says; 0024:477-478 itself says dependency TLA "needs an asynchronous linker/evaluator… None of that exists." 0026's phase-specific reconciliation (TLA/failure-caching amendments land with first consumer; generation amendments before Phase 4) avoids retroactive authorization.
- **LLP 0023 identity claims match.** Module identity `(runtime, SourceId)` at 0023:679 and 0023:2330; the obligations 0026 co-implements (`OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE`, `OBL-GRAPH-LOCATION`, `OBL-MODULE-IDENTITY`) exist as ledger rows (0023:2057-2078). One genuine drift 0026 correctly flags: `OBL-RESOLVE-GATE` (0023:2068) describes the resolve-path ESM body read as live with now-stale line citations, while the shipped branch is latent (`mod.rs:3848-3850`, `mod.rs:2606-2615`) and the `require.resolve` gate bypass remains live (`module-loader.js:5479-5481`).
- **LLP 0022 drift confirmed.** 0022:243-244 describes `require.cache`/`require.main` as "closed `runtime:inspect` surfaces" and `OBL-LOADER-CLOSED` (0022:980) as unreachable-in-every-mode, but the shipped bootstrap sets `localRequire.cache = cache; localRequire.main = mainModule` (`module-loader.js:5485-5486`). 0026 §7's statement that 0022's current-state prose must be corrected is accurate and appropriately scoped to Phase 2.
- **Duplication risk, managed.** 0026 restates substantial 0021/0023 material (staged authorization, snapshot immutability, no-probe rules). It consistently phrases these as "remain those of LLPs 0014/0021/0023" rather than re-specifying, which is the right altitude, but the sheer volume of restated rules is a standing drift surface (see Suggestions).

## 5. Suggestions

- **Use the Phase 2 scanner-vs-parser edge diff as a fixture generator, not just a gate.** The RFC already treats the scanner's accreted knowledge as "a free migration oracle" (§Phase 2); go one step further and auto-promote every real-world graph-shape disagreement into a named corpus fixture, so the scanner's decade of edge cases is captured mechanically before deletion.
- **Differential fuzzing against the oracle.** Beyond fixed fixtures and test262, a small generator of random module graphs (cycles, star re-exports, TDZ orderings, mixed CJS/ESM, TLA placement) executed on both the pinned Node and Ibex/Hermes would find linker-ordering bugs no hand-written corpus anticipates. This is cheap once the hermetic oracle acquisition (Compatibility contract) exists.
- **Reserve schema space for upcoming TC39 phases.** `static_edges[]` typed variants (§2) should reserve encoding room for `import defer` and source-phase imports so a future addition is a schema version bump, not a redesign of the digest domain.
- **State the ambiguous-`.js` ordering as one line.** §1 and Design principles together imply resolve → authenticate edge → read → detection parse → authoritative parse, but the reader assembles it from three places. A single ordered list would prevent an implementer from doing the detection read pre-gate.
- **Add a drift-check hook for restated rules.** Where 0026 paraphrases 0021/0023 invariants, consider tagging each paraphrase with the owning LLP section (several already are) and letting `./ref-check`-style tooling flag when the owner's section changes — the corpus's own maintain-skill pattern, applied to this document's largest risk.
- **Non-standard idea: ship the sync-proof as a build-time certificate.** §7 already allows prepared manifests to carry the async-taint bit. Extending that to a signed per-entry "synchronous closure certificate" for popular `require()` roots in dev caches (not just prepared builds) would erase most cold-drive proof cost (Concern 1) without weakening the fail-closed rule, since the runtime verifies rather than trusts it — the same verify-don't-compute pattern the RFC already endorses.

## 6. Open questions

The RFC's own twelve open questions are good; these should be added or answered during refinement:

1. What is the acceptable cold-latency budget for a synchronous `require()` that must prove and then evaluate a large ESM closure on the JS thread, and does any real dependency in the Phase 0 corpus exceed it? (Concern 1.)
2. How does exact-edge authorization behave for genuinely dynamic development-mode edges that cannot appear in the armed `OBL-GRAPH-LOCATION` map — is the fallback ordinary 0014 policy evaluation, and is that difference observable to non-disclosure fixtures?
3. When `OBL-SOURCE-ID` slips, what interim identity (if any) may the flag-gated experimental runner use without creating the path-keyed migration debt Phase 1 forbids? (Concern 4.)
4. Does the CLI entry-TLA text detector retire with the scanner tier, and which phase owns that? (Concern 2.)
5. For the detection parse's cached verdict: does it live in the resolution cache, the artifact, or both — and which one is authoritative when they disagree after a source change?

## 7. Readiness verdict

The RFC is architecturally sound, exceptionally well-grounded in the actual code (every load-bearing `[observed]` claim I verified held, several with nuance a superficial audit would have missed), and disciplined about authority boundaries, amendment sequencing, and feasibility gating. The four concerns in §3 are all Minor/Non-blocking refinements — a missing latency measurement, an unassigned scanner retirement, a prose-vs-oracle drift guard, and an acknowledged schedule dependency — none of which undermines the correctness, coherence, safety, or decision quality of the proposal as a Draft ready to proceed through its own adoption gate.

VERDICT: READY

---

## Round 7 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `6f3be27b997e`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-7 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–6 artifacts were kept
  out of `llp/reviews/` in a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-7 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round7.md`) — same brief as the
  Codex round-7 reviewer.

### Verbatim review

# Independent design review — LLP 0026: ESM Module Runner and Runtime Module Graph (round 7)

Target: `llp/0026-esm-module-runner.rfc.md` at revision `6f3be27b997e` (verified by `shasum -a 256`). Reviewed read-only, without consulting anything under `llp/reviews/`.

## 1. Overall assessment

This is a strong, unusually well-grounded RFC. It proposes the right architecture — an authenticated module graph with real module records, `System.register`-shaped factories, host-owned linking, and honest asynchronous evaluation — to replace a bootstrap string/regex transformer that is demonstrably doing a parser's and linker's job today. Every load-bearing `[observed]` claim I verified against the code held up, including several subtle ones (the latent resolve-time body read, the `require.resolve` gate nuance, the deliberate double-execution of pre-`await` prefixes, the single-principal-per-promise-job limitation of the Hermes scheduling patch). The document's cross-corpus discipline is exceptional: it identifies real conflicts and stale claims in LLPs 0021, 0022, and 0023 and routes every semantic change through named, gated amendments rather than silent divergence. The migration plan is phased, spike-gated, and honest about the largest risk — that no off-the-shelf Oxc/Rolldown component emits the required factory shape, so v1 is an Ibex-authored lowering.

The concerns I found are all minor: a missing adversarial paragraph on the initialization-authority amendment, a soft quantitative bar on the adoption-gate spike, no stated contingency if the cold synchronous `require(ESM)` budget fails, and the document's sheer size. None is a material correctness, coherence, feasibility, safety, or decision-quality defect.

## 2. Strengths

**The diagnosis is accurate and verified.** The Motivation's picture of the current path is exactly what the code shows:

- Ordinary ESM-heavy JavaScript really is served verbatim by the Rust loader: `needs_transpile` covers only `ts|tsx|jsx|mts|cts` (`src/module_loader/mod.rs:364-369`), and `needs_js_downlevel` triggers only on scanner-detected async generators, `for await`, `using`, and loop-scoping patterns (`src/module_loader/mod.rs:371-394`) — plain `import`/`export` syntax passes through untransformed (`src/module_loader/mod.rs:354-362`).
- `transformEsmToCjs` is a character-by-character string/comment/regex/template state machine (`src/engine/bootstrap/module-loader.js:4224-4325`) feeding a line-based rewriter driven by `createDelimiterScanState`/`moduleScanState` (`module-loader.js:3969, 4651-4700`), carrying accreted ENG-referenced repairs (ENG-22514, ENG-22528 comments in situ). The RFC's list of "JavaScript facts it must rediscover" is a fair description of this machinery.
- Execution is a synchronous function-body loader: `compileModuleBody` builds `new __privFunction("require","module","exports","__filename","__dirname","__exactDynamicImport", source)` (`module-loader.js:240-262`) — and it does set the pending package principal before compilation, exactly as §4 claims the new compile-or-load-factory operation will preserve.
- The dependency-TLA characterization (Motivation) is precise, not rhetorical: `wrapAsyncModule` wraps the body in a fire-and-forget async IIFE (`module-loader.js:5415-5417`), invoked at `module-loader.js:5657-5694`, and the code comment at `5680-5686` explicitly states "The prefix before the failing await runs twice; that double execution is a deliberate trade" (ENG-22811). The RFC's claim that migration *tightens* behavior, and its Phase 0 requirement to pin the current fire-and-forget baseline first, follow directly.
- The resolver critique is grounded: one merged condition set containing both `require` and `import` (`src/module_loader/mod.rs:117-122`); private package imports resolved with an invented fixed precedence `["node", "require", "import", "default"]` (`mod.rs:1630`) — the exact key-order-versus-precedence hazard §1 warns about; the bare-specifier-as-relative retry with an ambient `exists()` probe (`mod.rs:879-885`); `extension_alias` (`mod.rs:126-133`); unclassified modules defaulting to CommonJS (`mod.rs:921`).

**The nuanced security-state claims are correct, including where the RFC corrects other documents.**

- The "latent branch" claim (§1) is right: the resolve-time ESM classification read at `mod.rs:936-945` is gated on `kind == ModuleKind::Esm`, which never fires because module-type detection is disabled — confirmed by the ENG-22950 test note at `mod.rs:3848-3854`. LLP 0023's `OBL-RESOLVE-GATE` row (0023:2068) describes that read as live; the RFC's correction is accurate.
- The `require.resolve` claim (§7) is precisely calibrated: it does bypass the JavaScript `checkImportGate` (`module-loader.js:5848-5864` calls the meta bridge directly), but the native bridge (`src/host/abi.rs:3203-3232`) routes through `resolve_module_meta_for_principal`, which resolves the authenticated requester and runs `preflight_armed_module_resolution` against the armed snapshot (`src/host/mod.rs:2182-2231`). The RFC saying the ledger row "overstates the bypass" is correct.
- The trusted-loader-versus-`fs:read` corpus conflict (§4) is real, and the RFC is the first document to name it: LLP 0013 records shipped module reads under the trusted `module-loader` principal (0013:163), while the generated coverage edges classify loader surfaces as `fs:list`/`fs:read` with `principalSources: ["loader-referrer"]` and `effectOwnerSource: "loader-referrer"` (`capsec/registry/coverage-edges.json`, `surface.loader.commonjs.module.13o3pbt`). Resolving this by explicit LLP 0021 amendment with a narrowly defined non-delegable operation is the right call.
- The `OBL-LOADER-CLOSED` correction (§7) is right: LLP 0022 asserts `require.cache`/`require.main` "are closed `runtime:inspect` surfaces **today**" (0022:243-245), but the shipped bootstrap exposes `require.cache` on local and global require (`module-loader.js:5485, 5841`), a `require.main` getter (`module-loader.js:5868-5872`), and mirrors both onto `__exactRequire` (`module-loader.js:5882-5883`).

**Identity and artifact hygiene are excellent (§2, Terminology).** The `(runtime, SourceId)` key with the defining principal exactly once inside `SourceId` matches LLP 0023 §2.3 verbatim (0023:679, 691-696), including 0023's own hard-won lesson about denormalized copies — which the RFC applies again by deleting its earlier denormalized principal field. The two-digest-domain artifact model (semantic digest vs payload binding), the "digest-covered or derived, no third category" rule, and the exclusion of `SourceLabel` from the portable artifact are coherent and well-motivated.

**The per-principal executable-carrier constraint (§9) is grounded in engine reality**, not caution theater: LLP 0013 records that one bundled HBC file is one `RuntimeModule` and `RuntimeModule → package` attribution only works with per-package emission (0013:329-330), and the Hermes patch stack (`patches/hermes/0001-domain-package-principal.patch`, `0002-frame-attribution-helper.patch`) is the mechanism. Likewise the §4 requirement for a real async context carrier is grounded: patch `0008-schedule-time-principal-capture.patch` stores exactly one POD `uint32_t` scheduler principal per promise job (`jobSchedulerQueue_`, one entry per job), so the RFC's "loses the originating chain after one hop" is literal fact.

**Toolchain honesty.** SWC is really in the tree as the default compatibility engine (`Cargo.toml:98-106`, `src/module_loader/transpile.rs`), Oxc is really pinned at `=0.121.0` as the flagged candidate plus `oxc_resolver` (`Cargo.toml:45-53`), and the RFC treats LLP 0009's Rust-pin blocker (0009:44-51) as a Phase 1 exit criterion rather than assuming it away. The three-gate SWC-removal rule (§3) correctly preserves LLP 0024's independent `swc_ecma_parser` session pin (0024:669).

**Decision-process integrity.** The RFC explicitly refuses self-acceptance (Summary), and the Adoption gate front-loads every governing-document amendment (0007 fork closure — verified open at 0007:281-282, 425; 0009 amendment; 0019 third tier against its verified two-tier decision at 0019:12) before implementation proceeds beyond a mandatory spike.

## 3. Concerns

**1. The initialization-authority amendment lacks an explicit adversarial analysis of attacker-chosen initialization timing.**
**Severity:** Minor/Non-blocking.
**Evidence:** §4 ("Factory evaluation is autonomous record-owned execution") amends LLP 0021's deputy-constraint intersection so importer frames above the initialization boundary do not join the constrained set. The determinism argument is strong — and in fact stronger than the RFC states: under full intersection plus §5's sticky ESM failure caching, a low-authority importer could deliberately first-import a powerful module, have its init effect denied, and poison the record into `errored` for every subsequent legitimate importer — a denial-of-service laundering the amendment forecloses. But the residual hazard in the other direction is not discussed: an importer that is *allowed* the edge can choose *when* a module's initialization-time effects run at the module's full autonomous authority, which under the old rule would have been constrained. The corpus fixtures listed (cold/warm, `await 0`, concurrent importers) test invariance, not adversarial triggering.
**Resolution criterion:** Add one paragraph to §4 naming the attacker-chooses-init-timing hazard and why it is accepted (the same effects run on any first import; the module's own grants bound them), plus a red-team fixture where a minimal-authority importer triggers initialization of an effectful module, and the sticky-error DoS scenario as supporting rationale for the amendment.

**2. The adoption-gate spike's exit bar is qualitative.**
**Severity:** Minor/Non-blocking.
**Evidence:** Adoption gate: "emitting and executing representative canonical artifacts on real Hermes — live mutation, cycles, TDZ, re-exports, top-level `await`, dynamic import, TypeScript/JSX, Hermes compatibility, and composed source maps." Given §3 concedes the v1 producer is a hand-built lowering — and the whole Motivation is a cautionary tale about hand-built module machinery accreting defects — "representative" is a soft word for the single largest correctness risk in the proposal.
**Resolution criterion:** State a quantitative spike/Phase-1 bar, e.g. a minimum pass rate on test262 `language/module-code` + top-level-await under the expected-divergence mechanism, or an enumerated checked-in canonical-artifact list the spike must execute, so "the spike passed" is a falsifiable claim.

**3. No stated contingency if the cold synchronous `require(ESM)` drive misses its budget.**
**Severity:** Minor/Non-blocking.
**Evidence:** §7 permits `require()` of ESM to "synchronously drive the full load → link → evaluate pipeline… including file I/O and transform"; the Performance gates require the cold drive latency to be "measured in Phase 0 and budgeted," but unlike other gates there is no named fallback if the number is bad (candidates exist: restrict sync `require(ESM)` to warm-cache/prepared graphs where the async-taint bit is a manifest fact, or accept a documented regression).
**Resolution criterion:** One sentence in §7 or the Performance gates naming the fallback posture if the cold-drive budget fails, or an entry in Open questions.

**4. Document scope: one RFC is carrying an RFC, a partial spec, a migration plan, and the amendment vehicle for six other documents.**
**Severity:** Minor/Non-blocking.
**Evidence:** 1334 lines; §§1-2 and 7 contain spec-grade normative detail (wire-schema digest domains, the pinned interop table) inside a `Draft` RFC whose fixtures are declared authoritative over its own prose (§7's "stale prose is a corpus failure" rule — a good rule that also concedes the prose will go stale).
**Resolution criterion:** Non-blocking now; at acceptance, split the artifact wire schema and interop contract into a Spec-type LLP (the RFC already anticipates this shape by making the corpus authoritative), leaving 0026 as architecture + migration.

## 4. Cross-document findings

**Verified clean seams:**
- **LLP 0007:** the fork is genuinely open there ("move to a separate RFC for an async ModuleRunner-style loader", 0007:281-282; completion state "a documented Decision choosing a ModuleRunner-style redesign", 0007:425). 0026 resolves exactly that fork while leaving 0007 the transform-toolchain authority. Clean.
- **LLP 0009:** its Consequences block the default switch on "a ModuleRunner-style loader redesign" (0009:63-65), which 0026 is; the Adoption gate correctly requires amending 0009 rather than treating it as already permissive. The Rust-pin facts (0009:44-51) are carried into 0026's risks verbatim. Clean.
- **LLP 0019:** verified two-tier decision (0019:12-18). The third (Rust/Oxc) tier is a real amendment, and 0026's authority-flip choreography (build-time tier canonical during migration, roles flip at Phase 5) is the right way to amend a Decision rather than erode it.
- **LLP 0023:** `(runtime, SourceId)` with the principal inside `SourceId` matches §2.3 exactly (0023:679-696); the query/fragment strip divergence 0026 imports as a named expected divergence is 0023's own recorded decision (0023:796-803). The `OBL-SOURCE-ID`/`OBL-SOURCE-PROVENANCE`/`OBL-GRAPH-LOCATION`/`OBL-MODULE-IDENTITY` ledger rows (0023:2057-2078) exist and are open, matching Phase 1's co-implementation plan.
- **LLP 0024:** the entry-only TLA rule and its rationale are exactly as 0026 describes (0024:472-495 — "None of that exists, and this document will not pretend otherwise"); 0026 is the document 0024 was waiting for. The delete-on-failure behavior 0026 preserves until generations land matches 0024's recorded position (failing module's cache entry "is *deleted*, not kept", 0024:83-84). The SWC session-parser pin (0024:669) is correctly treated as an independent gate.
- **LLP 0012:** the pinned oracle is real (`runtime-identity.json:10`, Node `24.13.1`), and 0026 correctly routes re-pins through 0012.
- **LLP 0013:** frame-attribution granularity claims verified (0013:286-287, 329-330); §9's per-principal carrier rule matches what production enforcement already does per 0013's revision history (per-package chunking under enforce/audit).

**Conflicts 0026 correctly surfaces (and must land):**
- LLP 0021's generated coverage edges vs LLP 0013/shipped code on loader source-acquisition classification — verified real on both sides (0013:163; `capsec/registry/coverage-edges.json` `surface.loader.commonjs.module.13o3pbt`: `loader-referrer` principal/effect-owner). 0026's amendment plan is the only place this conflict is reconciled.
- LLP 0023 `OBL-RESOLVE-GATE` row describes the resolve-time body read as live; it is latent (`mod.rs:936-945` gated on never-taken ESM classification; `mod.rs:3848-3854`). The row also cites stale line numbers (`mod.rs:775`).
- LLP 0022's "closed today" loader-state prose (0022:243-245) contradicts shipped code (`module-loader.js:5485, 5841, 5868-5872`). 0026's Phase 2 correction plan is right.
- LLP 0004's "down-leveled" description (0004:82) vs the SWC pipeline's admission that the ES5 target is not honored (`src/module_loader/transpile.rs:269-271`) — 0026's Phase 0 correction is justified.

**Drift risk managed:** 0026 restates interop behavior descriptively but declares the pinned-oracle fixtures authoritative (§7), and extends the single-owner fixture rule to the 0019 and 0024 sibling corpora. That is the correct anti-drift posture; the residual risk is only the document-size concern above.

## 5. Suggestions

- **Name the sticky-error DoS argument in §4.** As noted in Concern 1, §5's sticky ESM failures under a full-chain intersection would let a low-authority importer poison a shared module for everyone. This is the strongest single argument for the initialization-boundary amendment and it is currently implicit.
- **Consider a "graph lint" byproduct.** The runner's parsed static-edge set vs the scanner's discovered rewrites is already used as a migration oracle (Phase 2). The same diff against LLP 0014's *declared* import-site grants would give a free "policy says X, graph says Y" report — useful both for migration confidence and for the `OBL-FILE-GRANTS` pre-runtime analysis phase §7 sketches.
- **Non-standard idea — property-based cycle/liveness fuzzing against the oracle.** The corpus enumerates known-hard fixtures, but linking/evaluation-order bugs live in unenumerated graph shapes. A small generator producing random DAGs+cycles with live-binding mutations and TLA placement, executed on the pinned Node oracle and Hermes with output-trace comparison, would find lowering bugs no curated fixture list will. It composes naturally with the existing expected-divergence mechanism.
- **State the detection-parse cache-coherence rule explicitly.** Design principles say the goal-detection verdict "is cached in the artifact so no source is re-classified on a warm path"; since the verdict is presumably inside the semantic-digest-covered fields keyed by source integrity, an edited file naturally re-classifies — but one sentence saying so would close an obvious reviewer question.
- **Consider naming the private-imports precedence bug as a Phase 0/1 fixture family.** `pick_package_import_path`'s fixed `["node","require","import","default"]` array (`mod.rs:1617-1641`) is a concrete, currently-shipping instance of the invented-precedence hazard §1 describes for `#`-imports; pinning its divergence from key-order semantics before the typed contract replaces it would make §1's claim a fixture, not just an argument.

## 6. Open questions

The RFC's own twelve open questions are the right set. To refine it further, these should be answered (mostly refinements of the concerns above):

1. What is the quantitative exit bar for the adoption-gate spike and Phase 1 canonical artifacts (test262 module-code pass-rate target or an enumerated artifact list)?
2. What is the fallback posture if the cold synchronous `require(ESM)` drive misses its Phase 0 budget — restrict to prepared/warm graphs, or accept a recorded regression?
3. What is the adversarial story for attacker-chosen initialization timing under the §4 autonomy amendment, and which red-team fixture pins it?
4. When the LLP 0023/0024 generation amendments land, which document owns the generation counter's semantics — this RFC's runner, or LLP 0024's session model — so the two consumers cannot fork it?
5. Does the checked-read-everywhere v1 lowering meet the steady-state gate on real ESM-heavy workloads, and if not, what is the shape of the reviewable per-site elision proof the RFC reserves?

## 7. Readiness verdict

The RFC is architecturally sound, factually accurate everywhere I could check it against the code and corpus, honest about its costs and its largest risk, and disciplined about how it changes the governing documents around it. The four concerns in §3 are all minor: each is a paragraph, a sentence, or a post-acceptance structural split, and none undermines the design's correctness, feasibility, safety, or the quality of the decision it asks the author to make. The document's own adoption gate already prevents any of the flagged amendments from landing silently. For a Draft RFC whose stated next step is acceptance-with-spike, this document is ready.

VERDICT: READY

---

## Round 8 — 2026-07-15

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-fable-5`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-15
- **Revision under review:** `1b523e2d9fc1`
  (`shasum -a 256 llp/0026-esm-module-runner.rfc.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex round-8 review of the same revision, and no
  access to any prior LLP 0026 review artifact — rounds 1–7 artifacts were kept
  out of `llp/reviews/` in a scratch stash for the duration of the round.
  Instructed not to read `llp/reviews/`.
- **Method:** subagent, round-8 brief by reference
  (`scratchpad/llp-super-refine/doc-0026/brief-round8.md`) — same brief as the
  Codex round-8 reviewer.
- **Orchestrator note (outside the verbatim body):** the four minor concerns
  were addressed in the post-round-8 revision; Concern 3's missing citation
  is the engine-side bounded thenable pump (`src/engine/hermes_runtime.cc`,
  ~4026-4135, verified in earlier rounds), now cited in the document.

### Verbatim review

## 1. Overall assessment

LLP 0026 proposes replacing Ibex's file-at-a-time ESM→CJS compatibility path (a bootstrap string/regex transformer feeding a synchronous `new Function` loader) with an authenticated module graph: Oxc/Rolldown parse-and-lower, a digest-bound `ModuleArtifact`, native-owned `ModuleRecord` linking keyed on `(runtime identity, SourceId)`, a `System.register`-shaped factory ABI with checked binding cells, honest asynchronous evaluation including dependency-level top-level `await`, and explicit CommonJS interop pinned to the Node 24.13.1 oracle.

This is the right architecture, and the document is unusually well-grounded. I verified every load-bearing `[observed]` claim the brief lists against the code at this revision, and all of them hold — including two claims that would have been easy to get wrong (the *latent* resolve-time body read, and the real LLP 0013-vs-0021 registry conflict over loader source-acquisition authority). The RFC's most dangerous moves — the initialization task-boundary amendment to LLP 0021's intersection rule, the trusted-loader reclassification, the generation extension of LLP 0023 module identity, and the third LLP 0019 tier — are all named as explicit amendments in an adoption gate that must be reconciled before implementation proceeds beyond spike scope, rather than smuggled in as side effects. The migration plan is phased, oracle-gated, fail-loud per LLP 0018, and honest that the realistic v1 producer is an Ibex-authored lowering whose correctness burden is carried by a falsifiable spike and checked-in canonical artifacts.

The concerns I found are minor: one internal framing inconsistency about how many policy amendments the non-goals admit, a couple of under-pinned interop edge cases, and some claims I could only partially verify (the "bounded wait" characterization of the entry-TLA shim path). None is material.

## 2. Strengths

**The motivation is factually accurate against the shipped code.** The RFC's core empirical claims all verify:

- Only `ts|tsx|jsx|mts|cts` are unconditionally transpiled (`needs_transpile`, `src/module_loader/mod.rs:364-369`); `js|mjs|cjs` are transformed only when string scanners detect async/`using`/loop-closure patterns (`needs_js_downlevel`, `mod.rs:371-394`); ordinary ESM-heavy JS is served verbatim with a prefetched-source fast path (`mod.rs:928-946`). (Motivation §"The current fallback…")
- `transformEsmToCjs` (`src/engine/bootstrap/module-loader.js:4224` onward, in a 6,207-line bootstrap) is exactly the string/delimiter/regex scanner the RFC describes — `moduleScanState`/`createDelimiterScanState` balance tracking (`module-loader.js:4651-5038`), pending-export baseline heuristics, and per-line `import.meta` checks — rediscovering statement boundaries and content contexts by hand, with named bug repairs (ENG-22514 at `module-loader.js:4142`).
- The dependency-TLA claim is precisely right: `wrapAsyncModule` is a fire-and-forget async IIFE (`module-loader.js:5415-5417`), invoked from the fallback path (`module-loader.js:5658, 5672, 5690`), and the code itself documents the deliberate double execution of the pre-`await` prefix under ENG-22811 (`module-loader.js:5680-5686`). LLP 0024's entry-only refusal (`0024:472-475`) is indeed specified but not what the bootstrap does. (Motivation)
- The entry-TLA machinery is separate and text-detected as claimed: `contains_top_level_await` is a depth-0 scanner (`src/bin/ibex/runtime.rs:3972-3974`) that treats template literals as opaque ("Template interpolation is not inspected", `runtime.rs:4019-4021`) and misses block-nested TLA at the routing sites (`runtime.rs:1635`, `main.rs:1253`); the `-e` async wrap is `!cfg!(windows)`-gated (`main.rs:1251-1253`); Rolldown CJS-mode TLA retry-as-ESM exists (`runtime.rs:3110-3146`).

**The typed resolution contract targets real, verified divergences** (§1, Phase 0): the shipped merged condition set `["node","require","import","default"]` (`mod.rs:117-122`); the invented fixed condition precedence for `#`-imports (`pick_package_import_path`, `mod.rs:1630` — a literal ordered array where Node uses key-ordered membership); the bare-specifier-as-relative retry with its ambient `exists()` probe (`mod.rs:879-882`); `extension_alias` probing (`mod.rs:126-133`); and unclassified-defaults-to-CommonJS (`mod.rs:921`). The RFC's normative point that conditions are membership tests, not a precedence order, is exactly the correction the shipped code needs.

**The latent-branch claim is correct and the RFC catches stale corpus prose.** The resolve-time ESM classification read (`mod.rs:936-946`) is gated on `kind == ModuleKind::Esm`, which never fires because `module_type` detection is disabled (`ResolveOptions` default, confirmed by the test note at `mod.rs:3848-3850`); LLP 0023's `OBL-RESOLVE-GATE` row (`0023:2068`) still describes it as a live body read at a stale line number. The RFC both credits the current body-read-free state and demands the ledger correction plus a by-construction guarantee (§1) — this is exactly the kind of drift-catching the corpus process wants.

**The claimed LLP 0013/0021 conflict is real, and resolving it explicitly is good decision hygiene** (§4). LLP 0013 defines a trusted `module-loader` principal (`0013:163`, `0013:1130`), while the generated registry classifies module resolution/loading as `fs:list`/`fs:read` with `principalSources: ["loader-referrer"]` and `effectOwnerSource: "loader-referrer"` (e.g. `surface.host.abi.ex.host.module.resolve.0xdfuf4` in `capsec/registry/coverage-edges.json:143729-143731`; 254 such edges). The RFC's narrow trusted-loader definition — non-delegable, bound to an already-authorized exact edge — matches the shipped model (module source reads past the import gate) and is pinned by fixtures.

**Identity discipline matches LLP 0023 exactly.** `ModuleKey = (runtime identity, SourceId)` with the defining principal appearing exactly once inside `SourceId` reproduces `0023:676-696` faithfully, including the removed-denormalized-field lesson (§2). The "armed root identity is a literal constant" caveat is verified: `{"kind": "root", "identity": "project-root"}` is hardcoded (`src/bin/ibex/runtime.rs:2033`, `src/host/mod.rs:4428`), so the RFC's prohibition on cross-project portable cache reuse until `OBL-SOURCE-ID` lands is necessary, not decorative.

**Factory-attribution ordering builds on the shipped mechanism rather than inventing one.** Compile/load-time principal stamping generalizes what `compileModuleBody` already does — pending package id set before `new __privFunction`, cleared in `finally`, compartment bound after (`module-loader.js:240-272`). The `GraphEvaluationContext` → `DecisionContext` mapping requirement is grounded: the semantic core's `DecisionContext` really carries stage/actor/effect-owners/constrained-principals/presented-handle-ids (`crates/capsec-semantics/src/decision.rs:405-420, 499-504`).

**The initialization-authority rule (§4) is a genuinely reasoned decision, not an oversight.** The determinism argument (one-instance initialization cannot soundly depend on which importer arrives first; `await 0` must not shed constraints) and the sticky-error poisoning attack under the alternative (a low-authority importer deliberately poisoning a privileged module's record into `errored`) are both correct and the adversarial residue is accepted explicitly with a red-team fixture.

**SWC's status is handled honestly.** SWC is the default engine today (`Cargo.toml:98-106`; `selected_transform_engine` defaults to `Swc`, `src/module_loader/transpile.rs:77`) doing TS-strip/JSX/`common_js` lowering with no target-compat pass (`transpile.rs:109-197` — confirming Phase 0's planned correction of LLP 0004:82's "down-leveled" wording), and Oxc is already present both as resolver (`Cargo.toml:45`) and as an opt-in transpile spike (`transpile.rs:88-94`, pinned `=0.121.0`). The three independent SWC-removal gates (§3) correctly respect LLP 0024's parser pin (`0024:669-673`).

**Cross-document seams are unusually clean**: LLP 0007 really does route the ModuleRunner redesign to a separate RFC (`0007:281-282, 425`); LLP 0009 really records the Rust-toolchain-pin blocker (`0009:64-72`); LLP 0019 really pins exactly two tiers (`0019:12-18`), and the RFC treats the third tier as a planned amendment with a defined authority relationship (canonical-vs-mirror, roles flipping at Phase 5) rather than a silent exception. The `OBL-LOADER-CLOSED` correction (§7) is verified — `require.cache`/`require.main` are exposed today (`module-loader.js:5485-5486`) against `0022:980`'s "unreachable in every mode" — and `require.resolve` does bypass the JS `checkImportGate` (`module-loader.js:5479-5481`) while the native bridge preflights the armed requester (`src/host/mod.rs:2191-2260`), exactly as the RFC's carefully hedged sentence says.

## 3. Concerns

**1. The "three flagged exceptions" framing undercounts the policy amendments.**
**Severity:** Minor/Non-blocking.
**Evidence:** Non-goals lists exactly three exceptions to "not changing capability policy defined by LLPs 0013, 0014, 0021, and 0023": the §8 generation extension, the §4 initialization task boundary, and the §4 trusted-loader classification. But §4 also amends LLP 0014's "an import grant is not a host-capability grant" rule ("is amended to name this one bounded exception explicitly"), and the Adoption gate calls that same change a "clarification." Either initialization-triggering is a semantics change to LLP 0014 policy (then the non-goals list has four exceptions), or it is a clarification (then §4 should not say "amended … exception"). The two words currently disagree.
**Resolution criterion:** Pick one framing: add the LLP 0014 initialization-triggering amendment as a fourth named exception in Non-goals, or consistently downgrade the §4 wording to a clarification of already-true semantics and say why it changes no decision.

**2. The mixed ESM/CJS failure-caching interaction is not explicitly in the corpus list.**
**Severity:** Minor/Non-blocking.
**Evidence:** §5 gives ESM records sticky errors and keeps CommonJS/JSON delete-on-throw eviction. §7 makes ESM `import` of CommonJS evaluate the CJS record and wrap it in a namespace adapter. The cross-product — CJS module throws when reached via ESM `import`, then is `require()`d again after eviction, then `import`ed again — is a divergence-prone edge (does the ESM view stick to the first error while the CJS cache re-evaluates?) that the pinned oracle answers precisely, but neither §5, §7, nor the conformance-corpus bullet list names it.
**Resolution criterion:** One sentence in §5 or §7 stating which cache algebra governs the ESM view of an evicted CJS record, plus a named fixture in the corpus list.

**3. "Bounded non-Windows wait path" for entry TLA is stated more precisely than I could verify.**
**Severity:** Minor/Non-blocking.
**Evidence:** Motivation describes the entry-TLA shim as running "on the bounded non-Windows wait path" with "wait-timeout" baseline cases in Phase 0. I verified the non-Windows gating (`main.rs:1251-1253`), the detector misses, and the shim wrap (`runtime.rs:1685-1736`, `3865-3939`), but could not locate a distinct bounded-wait/timeout mechanism specific to entry-TLA settlement in `src/bin/ibex/main.rs`/`runtime.rs` (the 50 ms keep-alive driver and HTTP shutdown deadline at `main.rs:1129-1184` are not TLA-specific). If the bounded wait lives in the engine crate, fine; if the characterization is stale, Phase 0's "wait-timeout" baseline family is aimed at a case that does not exist as described.
**Resolution criterion:** A file/function citation for the bounded wait in the RFC's Motivation (or in the Phase 0 bullet), or corrected wording.

**4. The synchronous `require(ESM)` cold drive concentrates a lot of machinery on the hot JS thread, and the recorded fallback changes observable semantics.**
**Severity:** Minor/Non-blocking (explicitly gated and the fallback is named).
**Evidence:** §7 permits `require()` of ESM to synchronously perform file I/O, transform, closure computation, and the async-taint proof on the JS thread; the performance gate ("cold synchronous `require(ESM)` drive latency") admits a fallback that refuses *cold* drives entirely. That fallback makes `require(esm)` success dependent on cache warmth — a behavioral mode split the interop corpus would need to pin as its own named divergence, which the RFC does not currently say.
**Resolution criterion:** If the fallback is exercised, the RFC (or the Phase 0 baseline) must state that cold-refusal is a corpus-visible divergence with its own fixture family, not just a perf-gate footnote.

## 4. Cross-document findings

**Conflicts found and correctly handled by the RFC:**
- LLP 0013 trusted `module-loader` principal (`0013:163, 1130`) vs LLP 0021 generated registry `loader-referrer` classification (`capsec/registry/coverage-edges.json:143729-143731` and 253 sibling edges) — real; the RFC resolves it as a named LLP 0021 amendment (§4).
- LLP 0023 `OBL-RESOLVE-GATE` row (`0023:2068`) describes the classification body read as live; code shows it latent (`mod.rs:936-946` gated by disabled `module_type` detection, `mod.rs:3848-3850`) — real drift; the RFC demands the correction (§1, Phase 1).
- LLP 0022 `OBL-LOADER-CLOSED` (`0022:980`) states `require.cache`/`require.main` "unreachable"; they are exposed (`module-loader.js:5485-5486`) — real; the RFC scopes it to Phase 2 with the prose correction (§7).
- LLP 0024's entry-only TLA rule (`0024:472-475`) vs this RFC's dependency TLA — handled by the one normative admission matrix (§1/§6) with revision at the migration point, not silently.
- LLP 0019's two-tier pin (`0019:12-18`) vs the required in-process pass — handled as a planned amendment with a defined canonical/mirror authority relationship (§3).

**Duplication/drift risk:** The RFC restates substantial LLP 0021/0023 semantics inline (staged authorization, digest discipline, SourceId arms). The planned Spec split at acceptance (Adoption gate) is the right mitigation; until then, drift risk is bounded by the corpus-as-authority rule (§7's "stale prose is a corpus failure").

**Clean seams verified:** LLP 0007 retains transform-toolchain authority and routed the runner out (`0007:281-282`); LLP 0009's toolchain-pin blocker is imported as a Phase 1 exit criterion (`0009:64-72`); LLP 0012's pin (`runtime-identity.json:10`, Node 24.13.1) is cited exactly; LLP 0025's supervisor/worker topology (`0025:92-96`) is respected by §4's worker-locality rule; the `#`-imports fixed-precedence divergence Phase 0 must pin is real code (`mod.rs:1630`).

## 5. Suggestions

1. **Consider shipping the "run every ESM file through SWC" bridge as an explicit interim mitigation.** The RFC correctly rejects it as the end state, but the migration is long and the scanner is the live defect source (ENG-22514/22520/22528/22811). A one-paragraph disposition — do it, or explicitly decline because it churns baselines twice — would close an obvious "why not both" question.
2. **Name the artifact cache poisoning surface in the security invariants.** Invariant 6 covers integrity-before-execution and §8 inherits the hardened transpile cache, but a short invariant stating that a cache entry is only ever admitted under the same semantic-digest verification as a fresh transform (i.e., the cache can never *widen* what a producer could emit) would make the §2 producer-trust rule and §8's cache text visibly the same rule.
3. **Consider a `ModuleArtifact` schema fuzzer as a standing corpus member**, not just malformed-field fixtures — the versioned wire schema with two digest domains is exactly the kind of parser that benefits from structure-aware fuzzing, and the fail-closed claims (§2) become measurable.
4. **Novel/non-standard idea:** since the checked-cell ABI is evaluator-owned, the runner could emit a per-artifact *cell-access trace* in development mode (which importer read which binding before initialization) and turn TDZ violations into attributed diagnostics naming the offending cycle path. The graph owner already has all the data; this would make the hardest-to-debug class of ESM cycle failures self-explaining and would exercise the source-map registry's sum key.
5. **Pin the `module-sync` condition's interaction with the async-taint bit explicitly.** §1 mentions `module-sync` dispositions following the pinned release and §7 memoizes the taint bit; a fixture where `module-sync` selects a different file than `import` would catch a cache-key aliasing bug between condition membership and taint memoization.

## 6. Open questions

The RFC's own twelve open questions are good. Three to add:

1. When a cold synchronous `require(ESM)` drive is refused mid-proof (Concern 4), what — if anything — of the transform/parse work (not records) is retained for the subsequent `import()` retry, and does that retention have a principal-attribution story?
2. Which cache algebra governs the ESM namespace view of a CommonJS record that threw and was evicted (Concern 2) — sticky ESM error, or re-evaluation tracking the CJS cache?
3. Does the Phase 2 shadow-comparison (CapSec effect traces, not dual side effects) have a defined story for effect *ordering* differences that are semantically benign (e.g., prefetch order changes under the new resolver), or will the trace comparator need its own expected-divergence mechanism?

## 7. Readiness verdict

This RFC is exceptionally well-verified against the code it describes: every load-bearing `[observed]` claim the brief required me to check holds at file:line, including the two subtlest ones (the latent resolve-time body read and the LLP 0013/0021 loader-authority conflict), and the claims it makes about sibling documents are accurate at the cited obligations. Its riskiest design moves are named amendments behind an adoption gate with falsifiable exit criteria, its migration plan starts by pinning today's misbehavior as baselines, and its performance and security gates have teeth (non-empty target matrices, fail-loud corpora). The four concerns above are wording precision, one missing fixture family, one citation to supply, and one divergence-labeling obligation on a named fallback — all clearly non-blocking polish, none touching correctness, coherence, feasibility, safety, or decision quality.

VERDICT: READY
