# Reviews: LLP 0028 — Oxc-Only Transform Authority and SWC Retirement (OpenAI Codex family)

## Round 1 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f51-1824-71a0-9ace-e0ad7e749091`
**Date:** 2026-07-17
**Redacted:** no (repository content only; no secrets present)
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewer read LLP 0028 at git-blob `6eea0bcccdd7e65795b946ea5a0d7556e76037c5`, governing LLPs, and repo code; barred from reading `llp/reviews/`
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The architectural direction is good. Converging runtime module transformation on Oxc, deleting SWC, closing the bounded compatibility window, and rotating every cache and artifact identity affected by the change are all consistent with the accepted direction in LLPs 0007, 0009, and 0026. The proposal’s basic repository facts are accurate: Rust is pinned to 1.93.1, the core Oxc crates to 0.121.0, nine direct SWC crates remain, SWC is still the default in-process engine, and the legacy-loader fence expires after 0.1.x.

The current plan, however, is not yet a safe retirement plan. It understates where SWC and parser-less compatibility transforms remain reachable, treats the LLP 0019 runners as evidence for a native Oxc path they do not exercise, and collapses LLP 0024’s three independent parser/lowering obligations into one underspecified parser comparison. It also leaves the security mechanism for computed imports undefined and makes an undeclared platform-support decision at the 0.2 fence.

I would keep the proposal but redraft it around a complete transform-reachability inventory and a retirement matrix: every current parser, transform, scanner, subprocess override, cache domain, platform path, and conformance runner should have an explicit post-retirement disposition and executable gate. With that change, this could become a strong implementation RFC; at this revision, deletion would outrun the evidence.

2. **Strengths**

- The end-state is clear and appropriately ambitious: one hermetic in-process runtime transform authority, no SWC crates, and continued runtime TypeScript rather than a build-time-only retreat. This follows the accepted direction in `LLP 0028 §Summary/Goals`, `LLP 0009 §Decision/TypeScript runtime direction`, and `LLP 0026 §3`.

- The proposal recognizes that engine retirement is also an identity migration. Its treatment of cache tags, prepared-artifact revalidation, `transform_fingerprint`, and CapSec inventory changes is directionally correct and consistent with `LLP 0028 §4` and `LLP 0027 §Digest domains`.

- Giving each unsupported interop shape an explicit native-support-or-refusal outcome is better than leaving an indefinite fallback. The closed-set and fail-closed instincts in `LLP 0028 §2` are sound even though the mechanisms need more specification.

- The staged rollout and requirement that LLP updates land with the corresponding implementation are good operational discipline (`LLP 0028 §5`). Separating toolchain rotation, interop work, parser work, window closure, and dependency deletion should make regression attribution tractable.

- Reconsidering whether SWC should remain the parser oracle is reasonable. The eventual contract should be expressed in terms of Ibex’s accepted source semantics and the actual Oxc-to-Hermes pipeline, not permanent deference to a retired implementation (`LLP 0028 §3`; `LLP 0024 §3–4`).

3. **Concerns**

- **The stated LLP 0019 gate does not exercise Tier 3.** **Severity: Material.**  
  **Evidence:** `LLP 0028 §5` says the existing two runners remain the gate. Those runners are explicitly Tier 1 AST and Tier 2 SWC plus the bootstrap scanner (`tests/hermes_compat_conformance.rs:8-17,117-132`). The real-binary runner invokes `ibex capsec audit` with `EXACT_COMPAT_TEST=1`, deliberately forcing the unarmed compatibility path (`packages/ibex-devtools/src/scripts/run-hermes-compat-loader.mjs:11-18,158-181`). Meanwhile, Tier 3 rewrites only a simple identifier-bound `let`/`const` `for...of` loop by moving its body into an ordinary function (`src/module_loader/producer_spike.rs:428-469`), while the shared corpus includes destructuring, lexical `this` and `arguments`, control-flow and hoisting hazards, and other cases (`hermes-compat-corpus.mjs:40-309`). The Cargo runners also do not cover LLP 0019’s async-generator corpus.  
  **Resolution criterion:** Add a real-binary native Tier 3 runner over every applicable LLP 0019 for-of and async-generator fixture, assert that the native Oxc fingerprint/path actually executed, run it on real Hermes for every advertised target and both source/prepared carriers, and make it green before removing Tier 2.

- **SWC and compatibility-transform reachability is broader than the three named shapes.** **Severity: Material.**  
  **Evidence:** Unarmed audit/diagnostic runtimes bypass native graph production unconditionally (`src/bin/ibex/runtime.rs:1445-1450`). The entry-TLA shim directly calls the SWC-only `transpile_to_cjs` rather than the engine selector (`src/bin/ibex/runtime.rs:1892-1918`). The Oxc candidate explicitly rejects top-level await and remaining general ESM syntax (`src/module_loader/transpile.rs:212-217,258-262`). Beyond LLP 0019’s scanner, the compatibility loader contains dynamic-import, `import.meta`, and ESM-to-CJS string rewrites (`src/engine/bootstrap/module-loader.js:4090-4224,5691-5704`), while the CLI retains text-based TLA/module rewriting. This contradicts `LLP 0028 §Motivation`, §2, and §4’s implication that closing three shape gaps plus deleting the enum is sufficient.  
  **Resolution criterion:** Add a complete reachability inventory for every runtime parser, transform, syntax scanner, and lowering entrypoint—including audit/diagnostic execution and the entry-TLA shim—and assign each an implemented Oxc/native replacement or explicit supported-surface refusal before SWC or Tier 2 is removed.

- **Closing the 0.1 window silently removes runtime source support from most platform tuples.** **Severity: Material.**  
  **Evidence:** Native admission currently covers only macOS/aarch64 and Linux/x86_64 (`src/bin/ibex/runtime.rs:40-49`). Once the 0.1 fence closes, an armed runtime on Windows x64, macOS x64, iOS, Android, or another tuple refuses every script entry before graph production (`src/bin/ibex/runtime.rs:1451-1465`). LLP 0026 explicitly records Windows as compatibility-only and says it will refuse after the window closes (`LLP 0026 §Performance and platform gates`, lines 1395-1403), while LLP 0001 carries a broader product/platform matrix. This is incompatible with `LLP 0028 §Summary` saying runtime TypeScript remains first-class “throughout” unless the support matrix is intentionally narrowed.  
  **Resolution criterion:** Before closing the window, either provide and advertise matching native-runner artifacts for every retained supported tuple or explicitly narrow the supported platform matrix and reconcile LLP 0001, LLP 0026, and LLP 0028’s runtime-TypeScript guarantee.

- **The proposal mischaracterizes LLP 0024’s removal gates.** **Severity: Material.**  
  **Evidence:** `LLP 0028 §3` calls parser equivalence “the last named blocker.” LLP 0026 instead names three independent gates: module transformation, LLP 0024 parsing, and LLP 0024 session lowering (`LLP 0026 §3`, lines 527-538). LLP 0024 requires a hybrid Script-plus-`import`-plus-TLA goal that neither ordinary Script nor Module parsing supplies (`LLP 0024 §3`, lines 438-456), plus TypeScript lowering, session-binding hygiene, TLA lowering, and composed source maps (`LLP 0024 §4`, lines 636-717). It explicitly says the LLP 0019 corpus gates none of those obligations. Hermes alone is not a TypeScript or hybrid-source-goal oracle.  
  **Resolution criterion:** Specify and prototype the exact parser mechanism for every LLP 0024 goal and dialect, implement or deliberately revise the session-lowering, hygiene, and source-map contracts, and amend LLPs 0024 and 0026 accordingly. SWC removal must remain gated on all three obligations, not merely an Oxc-versus-Hermes parse comparison.

- **The proposed TypeScript/JSX preservation evidence is the wrong corpus and is far too narrow.** **Severity: Material.**  
  **Evidence:** `LLP 0028 §Goals` promises TypeScript/JSX preservation “bit-for-bit against the LLP 0019 conformance corpus,” but LLP 0019 governs Hermes-compat passes, not the complete runtime transform contract. LLP 0007 requires fixtures for TS/TSX, decorators, type-only imports, ESM/CJS, dynamic import, `import.meta`, TLA, aliases, helpers, diagnostics, and real-Hermes behavior (`LLP 0007 §2`, lines 236-269). LLP 0026 requires an even broader source/prepared semantics corpus (`LLP 0026 §Compatibility contract and conformance corpus`). The current canonical manifest has one basic TSX fixture (`tests/fixtures/module-runner-spike/manifest.json:61-65`), while the production fingerprint explicitly says `decorators=off` (`src/module_loader/producer_spike.rs:72-85`).  
  **Resolution criterion:** Define a separate behavioral transform corpus covering every advertised extension and runtime-bearing TS construct—enums, namespaces, `import =`, JSX configuration, decorator policy, type-only edges, CJS/ESM, TLA, dynamic import/meta, diagnostics, and composed source maps—on real Hermes in source and prepared modes. Use semantic parity rather than “bit-for-bit” except where exact bytes or codes are contractual.

- **Section 2 does not yet resolve the three legacy shapes at the authority and timing level.** **Severity: Material.**  
  **Evidence:** The current graph builder rejects computed dynamic imports precisely because no authenticated finite candidate table exists (`src/module_loader/runner_pipeline.rs:358-366`); LLP 0027 requires that table and denial without probing (`LLP 0027 §Artifact envelope`, lines 63-66). LLP 0014 currently says computed specifiers contribute no policy and are denied (`LLP 0014`, lines 99-103,137-148). For computed `require`, LLPs 0026 and 0027 already describe a call-time, finite-candidate model (`LLP 0026:210-217,354-356`; `LLP 0027:182-187`), whereas the implementation currently refuses the graph at build time using a transformed byte offset (`src/module_loader/producer_spike.rs:931-947`). That violates LLP 0024’s dead-branch/call-time rule (`LLP 0024:506-524`) and cannot provide a stable original-source site. Dynamic-import options are likewise underspecified: the producer rejects all of them (`producer_spike.rs:815-832,944-947`), while the runtime attribute type currently admits only `type=json` (`identity.rs:226-257`).  
  **Resolution criterion:** Specify how each site obtains a digest-bound finite candidate set, how expressions and option bags are evaluated, how attributes participate in identity and authorization, how denial avoids probing, and how stable original-source sites and errors are produced. If computed `require` is intentionally being removed instead, explicitly supersede the contrary LLP 0024/0026/0027 commitments and pin invocation-time/dead-branch behavior with fixtures.

- **“Oxc is the only parse/transform engine in Ibex” is not the end-state actually described.** **Severity: Material.**  
  **Evidence:** The default generated-runtime build still passes `--lower-classes` (`package.json:10`) and invokes Babel (`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:437-477`), a known exception in `LLP 0007 §Current state`. The runtime also retains `EXACT_TRANSPILE_SCRIPT`, which selects an arbitrary subprocess transform and separate cache domain (`src/module_loader/mod.rs:2099-2121,2366-2377`). Both conflict with the unqualified title/summary and the “one engine, one cache-tag domain, no subprocess” language in `LLP 0028 §Summary/Goals`.  
  **Resolution criterion:** Either retire these paths too, or narrow the normative claim to the production in-process runtime module transform authority and explicitly classify the Babel build stage and developer override. If the override remains, specify that it is unavailable in production claims and retain its separate authenticated cache identity.

- **The rollout changes Oxc before rotating the identities that name its output.** **Severity: Material.**  
  **Evidence:** `LLP 0028 §5` puts the toolchain/Oxc re-pin in step 1, but fingerprint rotation appears under the later engine-surgery step. The Oxc cache tag is hard-coded as 0.121.0 (`src/module_loader/transpile.rs:47-53`), and both spike and production artifact fingerprints hard-code 0.121.0 (`src/module_loader/producer_spike.rs:43-44,66-87`). LLP 0027 requires the fingerprint to cover parser and transform versions. Landing a new Oxc implementation under the old identity risks cache or prepared-artifact aliasing.  
  **Resolution criterion:** Make every pin change atomic with all cache tags, transform fingerprints, fixture artifacts, and prepared-carrier admission expectations. Add golden tests proving the pin/options change alters cache and semantic identities and that pre-rotation artifacts reject or rebuild.

- **CapSec regeneration will fail after deleting `TransformEngine` unless its discovery model is changed first.** **Severity: Material.**  
  **Evidence:** The live SWC surface IDs are present at `src/capsec_registry_generated.rs:4067,4124,4198,4244,4251`, but inventory discovery finds transform engines only through `TransformEngine::Variant` references and errors if it finds none (`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:12417-12445`). The authored coverage model also names four `transpile_with_swc` routes and `transform-engine:swc` (`capsec-coverage-model.mjs:6178-6362`). Registry generation updates a coordinated catalog of Rust, C++, JavaScript, TypeScript, registry, schema, and documentation outputs (`generate-capsec-registry.mjs:52-150`), not just the Rust file named in §4.  
  **Resolution criterion:** Update Oxc-only engine discovery and the authored route/classifier/environment inventories before deleting the enum, regenerate the complete catalog, and require `bun run check:capsec-registry` to pass as a retirement gate.

- **The toolchain/pin step is not yet reproducible enough.** **Severity: Minor.**  
  **Evidence:** “≥1.94.0” and “a current release” in `LLP 0028 §1` are moving targets. The implementation directly uses the allocator, AST, visitor, codegen, parser, semantic, span, transformer, and sourcemap crates (`Cargo.toml:53-62`), not merely parser plus transformer as §Alternatives suggests. Rust 1.93.1 is also repeated in CI workflows and performance evidence, including `.github/workflows/ci.yml:20-21,96-97`, `module-loader-baselines.yml:67-68,168-169`, and the performance fixtures.  
  **Resolution criterion:** Name an exact Rust version and coherent exact Oxc crate set, enumerate all workflow/baseline updates, and record the Rolldown compatibility, MSRV, compile-size, and performance evidence for that precise lockfile.

4. **Suggestions**

- Add a checked-in “retirement manifest” listing forbidden SWC crates, engine selectors, old cache tags, CapSec surfaces, subprocess paths, and runtime scanner/rewriter symbols. A CI negative gate can then prove the removal rather than relying on a review-time search.

- Derive cache tags and artifact parser-version fields mechanically from one generated transform-identity manifest or build-time Oxc version constant. The current duplicated string literals make future pin rotations unnecessarily fragile.

- During the Oxc re-pin, dual-produce old/new artifacts without executing both in production, then compare semantic metadata, source maps, and real-Hermes behavior in CI. This provides useful migration evidence without duplicating side effects.

- Prefer an explicit finite-candidate construct—such as a manifest declaration or `import.meta.glob`-style expansion—over arbitrary runtime graph expansion for computed imports. It matches existing no-probe and prepared-graph invariants and gives tooling a reviewable policy surface.

- Add selector-retirement tests covering unset, `oxc`, `swc`, the legacy alias, and precedence, plus cache-key goldens and prepared-artifact rejection tests.

- Expand the required LLP reconciliation list to include at least LLP 0001, 0014, and 0027; the proposal changes platform support, computed-edge policy generation, and the normative interop contract.

5. **Open questions**

- Does “Oxc-only” mean all Ibex build and runtime transforms, or only the production in-process runtime module producer? What is the intended status of Babel and `EXACT_TRANSPILE_SCRIPT`?

- What executes runtime-loaded source in unarmed audit/diagnostic runtimes after Tier 2 retires?

- Which platform tuples will advertise runtime TypeScript at 0.2, and is dropping source execution on the others an intentional product decision?

- How is the authenticated finite candidate set for a computed import authored or generated, bound to a site, represented in artifacts, and carried into prepared graphs?

- Is rejecting every computed `require` an intentional reversal of the accepted finite-candidate design? If so, what exact compatibility and dead-branch semantics replace it?

- Which dynamic-import options and attributes are accepted, and what are their expression-evaluation order, side-effect, identity, authorization, and error-timing rules?

- Which concrete parser mechanism implements LLP 0024’s Script-plus-`import`-plus-TLA goal, and what replaces SWC’s separate session-lowering role?

- What exact runtime TypeScript and decorator dialect is promised, including enums, namespaces, `import =`, JSX runtime, and future syntax drift?

- Which CI jobs prove native Tier 3 behavior on real Hermes for every advertised target and for both source and prepared carriers?

- What exact Rust/Oxc/Rolldown pins will be adopted, and what evidence determines whether the pin rotation is accepted?

6. **Readiness verdict**

VERDICT: NOT READY — The Oxc-only direction is sound, but the current plan leaves unresolved material gaps in native conformance, transform reachability, LLP 0024 migration, computed-edge authority, platform support, cache identity, and CapSec feasibility.
### Orchestrator verification notes (round 1, outside verbatim body)

Spot-checked against the working tree (2026-07-17): Babel `--lower-classes` in `package.json:10` + `rolldown-bundle.mjs:437-477`; `EXACT_TRANSPILE_SCRIPT` subprocess override; hard-coded `0.121.0` in cache tag and both fingerprints; LLP 0026 §3 three-gate text verbatim; LLP 0014 computed-specifier denial (lines 99-103, 147, 232); computed-dynamic-import legacy routing in `runner_pipeline.rs:358-366`; dynamic-import-options and computed-require producer rejections (`producer_spike.rs:815-832, 938-947`); capsec surface IDs present. Conformance-runner tier coverage and capsec inventory-discovery claims (`capsec-surface-inventory.mjs`, `capsec-coverage-model.mjs`) taken on cited line evidence consistent with repo structure. All decisive claims confirmed; no material defect found in the review's factual basis.

## Round 2 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f64-72a1-77a3-b6c2-16c3aa9db4ab`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed LLP 0028 at git-blob `efad9164d4cba38cc8a495c4dec3e95523c8f65a`; barred from reading `llp/reviews/` (round-1 artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The direction is good: Oxc should become Ibex’s sole production in-process runtime transform authority, and the bounded SWC compatibility stack should retire. The RFC correctly identifies the current Rust/Oxc and SWC pins, default-SWC selector, cache tags, 0.1 legacy fence, advertised target tuples, three independent SWC gates, current conformance-runner coverage, and CapSec regeneration hazards.

The proposal is also stronger than a typical dependency-removal plan. It treats cache and artifact identity atomically, requires behavior on real Hermes, inventories host consumers, distinguishes build-time Babel from runtime transforms, and makes the platform consequence explicit.

It is not ready, however. The computed-import design relies on an authority set LLP 0014 does not provide and loses site identity before execution. It contradicts the no-wire-change non-goal. Dynamic-import error timing conflicts with governing LLPs. The LLP 0024 parser/session work is described as a migration even though its defining frontend and lowering do not exist. Audit, the supported no-default profile, and a separate handwritten Rust transformer lack executable dispositions. Finally, native Tier 3 is already broader and less safe than the RFC acknowledges, while the rollout adds a runner but no explicit parity implementation or quarantine step.

2. **Strengths**

- The scope is precise about “one engine” meaning production in-process runtime transforms, while retaining build-time Babel and retiring `EXACT_TRANSPILE_SCRIPT` explicitly (LLP 0028 §Summary, §Non-goals, §4b).

- The Oxc pin change is correctly coupled to cache-tag and `transform_fingerprint` rotation, with stale-cache and prepared-carrier goldens (LLP 0028 §1). This directly addresses the duplicated identities in `src/module_loader/transpile.rs:47-52` and `src/module_loader/producer_spike.rs:43-81`.

- The RFC correctly treats module transformation, LLP 0024 parser selection, and LLP 0024 session lowering as three independent SWC gates. It also correctly rejects Hermes as an oracle for TypeScript grammar (LLP 0028 §3; LLP 0026 §3).

- The host-path and platform inventories are valuable. The 0.1 fence and macOS/aarch64 plus Linux/x86_64 advertisement are accurately reflected in `src/bin/ibex/runtime.rs:25-49`, and §4d appropriately prevents platform de-support from occurring accidentally.

- The proposal correctly recognizes that the existing two conformance runners cover the Tier 1 AST authority and forced Tier 2 compatibility loader, not native Tier 3 (`tests/hermes_compat_conformance.rs:117-132`). Requiring a real-binary runner, native fingerprint evidence, and source/prepared execution is the right discipline (LLP 0028 §5).

- The CapSec sequencing is factually sound: engine discovery depends on `TransformEngine::Variant` and fails when no engine is found, while the authored model and generated registry contain SWC routes and IDs (`capsec-surface-inventory.mjs:12417-12446`; `src/capsec_registry_generated.rs:4066-4068,4243-4251`). Updating the generator before deleting the enum is correct (LLP 0028 §4c).

3. **Concerns**

1. **Material — The candidate-set authority premise is incorrect, and per-site subsets are not enforceable.** Evidence: LLP 0028 §2 claims LLP 0014 already grants exact package-local specifiers. LLP 0014 instead says computed specifiers contribute nothing and are denied (`llp/0014-import-site-grants-and-generated-policy.spec.md:99-103,137-148`); its artifact records package and builtin import fences, not package-local module spellings (`:246-288`). Initialization itself is authority (`:150-158`), so admitting every package file would be a new expansion. Current plumbing also unions candidates module-wide: `src/module_loader/graph.rs:352-403` reduces computed sites to `has_computed`, while `producer_spike.rs:393-414` emits `context.dynamicImport(expr)` without the site. Resolution criterion: define a reviewable authenticated artifact keyed by at least `(requester SourceId, site, exact authored spelling, attributes, target SourceId/integrity)`, carry the site through factory and native ABIs, specify deterministic glob/package-boundary/symlink rules, and add a two-site disjoint-set non-escalation test. Alternatively, state honestly that the module—not the site—is the authority unit.

2. **Material — The proposal changes ModuleArtifact v1 while declaring that it does not.** Evidence: the Non-goals say this work only rotates fingerprint inputs, but §2 adds a candidate-set digest to `DynamicEdgeV1::Computed`. The Rust variant is closed and contains only `site` (`src/module_loader/artifact.rs:152-162`); the strict schema permits only `kind` and `site` (`schemas/module-artifact-v1.schema.json:145-166`). LLP 0027 deliberately places deployment-specific candidates outside the artifact (§Artifact envelope). Resolution criterion: either introduce and migrate ModuleArtifact/prepared-graph v2, including compatibility rules, or leave v1 unchanged and bind a site-indexed candidate table into a versioned authenticated deployment-graph envelope.

3. **Material — Dynamic-import option timing is contradictory.** Evidence: LLP 0028 §2 makes invalid literal options fail at graph build, while its rollout and acceptance criteria require invocation-time failure. LLP 0024 requires every `import()`—literal or computed—to be checked at call time so dead branches never fail (`llp/0024-structured-evaluation-and-session.spec.md:506-524`); LLP 0026 likewise requires call-time validation (`llp/0026-esm-module-runner.rfc.md:331-356`). Resolution criterion: make all dynamic-import option errors rejected promises at invocation, preserving specifier/options evaluation order and side effects, and add literal/computed dead-branch, getter, and malformed-bag fixtures. Otherwise the governing LLPs must be explicitly revised.

4. **Material — The LLP 0024 migration plan is circular and misstates implementation state.** Evidence: §3 proposes comparing SWC and Oxc over Script-plus-`import`-plus-TLA even though LLP 0024 says neither parser supplies that goal (`llp/0024-structured-evaluation-and-session.spec.md:438-455`) and leaves its parser mechanism/prototype open (`:1893-1898,2256-2262`). LLP 0024 also says none of its owed artifacts are discharged; repository SWC implementation is confined to `src/module_loader/transpile.rs`, with no existing session lowering to “reimplement.” Finally, session inputs do not currently have ModuleArtifact prepared carriers, so applying the §Acceptance criteria’s source/prepared matrix to all three corpora is inaccurate. Resolution criterion: recast §3 as first implementation directly on Oxc; first choose and prototype a versioned hybrid frontend, define a normalized parse-equivalence projection, build LLP 0024’s executable model and corpus, and give LLP 0024 its own oracle/carrier matrix. SWC-versus-Oxc differential evidence should cover only goals both implementations can actually parse.

5. **Material — Native Tier 3 needs an implementation/quarantine phase, not only a new runner.** Evidence: `producer_spike.rs:428-471` wraps every qualifying loop body in an ordinary nested function without the canonical transform’s checks for `this`, `arguments`, `return`, `break`, `continue`, `yield`, `await`, `var` hoisting, or nested loops. `:1386-1398` leaves async-generator syntax at ES2022. The only native fixture is the trivial capture case (`tests/fixtures/module-runner-spike/manifest.json:68-72`). LLP 0019 nevertheless declares Tier 3 zero-divergence and canonical for ordinary ESM (§Tier 3). LLP 0028 §5 adds a runner, but rollout steps 1–5 contain no explicit pass implementation or interim quarantine. Resolution criterion: add a pre-step that either classifies all unproven Tier 3 shapes as typed `LegacyRequired` or lands the complete Oxc passes; then require every shared for-of and async-generator fixture, including mapped error locations, through production source and prepared paths on both advertised tuples before Tier 2 retirement.

6. **Material — Snapshotless audit migration has no security mechanism.** Evidence: runtime deliberately bypasses native graphs without an armed snapshot (`src/bin/ibex/runtime.rs:1443-1450`); graph construction immediately requires one (`src/module_loader/runner_pipeline.rs:264-270`), and the host ABI fails otherwise (`src/host/abi.rs:547-557`). The existing loader conformance runner itself invokes `ibex capsec audit`, so repointing it also depends on this design. The phrase “weaker (non-authority-manufacturing) admission” in §4b does not specify identities, resolution, receipts, caching, or denial behavior. Resolution criterion: define a normative audit-graph admission contract with principal/SourceId derivation, hard fences, would-deny evidence, prepared-cache rules, target availability, and denied/missing/cross-principal fixtures—or explicitly retire audit source execution and revise the compatibility claim.

7. **Material — The supported no-default profile is absent, making §4a’s parity work ambiguous.** Evidence: `module-runner` remains optional (`Cargo.toml:120-130`); the runner dispatch and 0.1 fence are feature-gated, while `--no-default-features` takes compatibility evaluation (`src/bin/ibex/runtime.rs:25-37,1435-1599`). CI both checks and executes that profile (`.github/workflows/module-loader-baselines.yml:101-110,223-230`). The RFC neither retires nor migrates it. This also leaves no named consumer requiring the file-at-a-time Oxc candidate to gain TLA/general ESM-to-CJS parity; all listed consumers otherwise migrate to the native producer or retire. Resolution criterion: make the native runner unconditional, define a fail-loud non-runner profile, or specify an Oxc-only evaluator with its own contract. Then either name its need for file-at-a-time parity or delete that candidate and remove the unnecessary parity work from rollout step 2.

8. **Material — The “complete” transform retirement inventory is incomplete.** Evidence: `src/bin/ibex/runtime.rs:4094-4133,4865-4915` contains a live handwritten ESM-to-script transformer plus raw `import.meta` and `import(` replacements, used by Windows and Rolldown-output paths. Additional Rust compatibility scanners remain in `src/module_loader/mod.rs`. These are production runtime source transforms but are not explicit rows or forbidden needles in §4. `IBEX_LEGACY_MODULE_LOADER` also lacks a post-window disposition. Resolution criterion: give every scanner, rewrite, forcing environment variable, and affected test/profile a delete/replace/retain row and retirement-manifest needle, or narrow and justify the “one engine” claim.

9. **Material — Computed-`require` retirement lacks decision-grade telemetry.** Evidence: §2 relies on “observed usage … nil” and future aggregation, but `LegacyModuleRunnerRequirement` contains only a free-form `reason` (`src/module_loader/runner_pipeline.rs:35-43`) and runtime writes it to stderr (`src/bin/ibex/runtime.rs:1570-1581`). No stable category, collection path, population, denominator, observation window, or reopening threshold is specified. Resolution criterion: define a typed event schema and collection plan covering CI and named downstream versions, state the observation window and decision threshold, and archive the reviewed report before closing the window.

10. **Minor — The pin inventory is not exact.** Evidence: §1 says “all nine” Oxc crates but `Cargo.toml:53-62` has ten direct `oxc_*` dependencies: eight core crates, `oxc_sourcemap`, and `oxc_resolver`. Rust 1.93.1 also appears in `compartment-conformance.yml`, `hermes-patch-canary.yml`, and two performance fixtures in addition to the named primary workflows. Resolution criterion: correct the count, enumerate all pin sites, and preferably make workflows consume `rust-toolchain.toml` with a drift check.

11. **Minor — Selector deprecation needs release sequencing.** Evidence: the current variables are read only through `selected_transform_engine` and transform-cache calls (`src/module_loader/transpile.rs:38-81`; `src/module_loader/mod.rs:2099-2121`). Once step 4 removes the consumers and step 5 deletes the selector, `IBEX_RUNTIME_TRANSFORM=swc` cannot fail loudly for a minor release. Resolution criterion: either remove the variables immediately at 0.2 or retain a dedicated startup validator through 0.2 and remove it in 0.3.

4. **Suggestions**

- Add a Phase 0 that freezes the behavioral corpus, Tier 3 quarantine, retirement manifest, old-identity goldens, telemetry schema, and target CI matrix before changing the Oxc pin.

- Prefer architectural deletion over parity work: if audit and no-default both move to the authenticated graph producer, delete the file-at-a-time Oxc CommonJS candidate instead of teaching it a second TLA/ESM lowering model.

- Generate one checked version-set constant from the locked Oxc dependency graph and derive cache tags, fingerprints, reports, and spike fixture identities from its digest. Make this part of step 1, not a follow-up.

- Add a test-only execution receipt containing `SourceId`, semantic digest, transform-fingerprint digest, carrier kind, producer digest, and loaded Hermes digest. This makes “the intended native artifact executed” independently auditable.

- Require zero resolved `swc_*` packages in `Cargo.lock` across retained feature/target profiles, not merely zero direct entries in `Cargo.toml`.

- Extend the existing single-owner module-semantics corpus rather than creating a jointly owned parallel corpus; archive the input manifest and normalized output of the one-shot dependency sweep.

5. **Open questions**

- What exact reviewed artifact grants computed-import candidates, and is authority scoped per site or per module?

- Will candidate binding live in ModuleArtifact v2 or a versioned deployment-graph envelope, and how will site and attributes cross the native ABI?

- Which mechanism implements LLP 0024’s hybrid source goal, and what parser-independent oracle defines correctness?

- Is structured session evaluation required to ship before SWC deletion, or should LLP 0024 be revised now to target a future Oxc implementation without retaining SWC?

- Will snapshotless audit continue executing source, and if so, what prevents its weaker admission from manufacturing executable authority?

- Is `--no-default-features` a supported runtime, a compile-only profile, or retired? Which target tuples apply to it and to audit?

- Is any retained consumer actually supposed to use file-at-a-time Oxc ESM-to-CJS lowering?

- What telemetry population and threshold justify dropping computed `require`, and must the argument expression still be evaluated before the stable error?

- Which required macOS-arm64 and Linux-x86_64 jobs will run each corpus and carrier unconditionally on the exact linked Hermes build?

- Which consumers depend on SWC diagnostic text, environment selectors, or current compatibility-path baselines?

6. **Readiness verdict**

VERDICT: NOT READY — The direction is sound, but unresolved authority, wire-contract, parser feasibility, profile coverage, audit safety, and native Tier 3 correctness issues prevent safe approval.
### Orchestrator verification notes (round 2, outside verbatim body)

Spot-checked: handwritten `transpile_esm_to_script` transformer exists (`src/bin/ibex/runtime.rs:4865+`) with raw `import.meta`/`import(` rewrites surviving for Rolldown ESM bundle outputs (comment at 4094-4098) — the "inventory incomplete" finding is confirmed; `DynamicEdgeV1::Computed` is a closed `deny_unknown_fields` variant carrying only `site` and the strict schema matches (`schemas/module-artifact-v1.schema.json:145-166`) — the wire-contract contradiction is confirmed; `module-runner` is an optional Cargo feature (round-1 checks). No material defect found in the review's factual basis.

## Round 3 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f7a-215b-7721-980b-787165faaac4`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed LLP 0028 at git-blob `73be98e1c96836071ce7f04add9757e1f3175ad1`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The strategic direction is sound. Oxc is already the canonical producer for ordinary ESM, SWC now primarily supports bounded compatibility paths, and retaining two runtime transform engines creates real conformance, cache-identity, diagnostic, and dependency costs. Deleting the file-at-a-time pipeline once every consumer has migrated is the right architectural endpoint.

The proposal also contains strong migration mechanics: evidence precedes the pin rotation, conformance runs through the real binary and real Hermes, prepared and source modes are both covered, and generated retirement gates replace informal source searches. Most factual inventory claims checked against the repository are accurate, including the toolchain pin, dependency counts, legacy fence, advertised tuples, current conformance gap, cache tags, and generated CapSec surface IDs.

It is not yet a decision-complete plan. Several load-bearing contracts remain unspecified or conflict with existing closed schemas: the candidate declaration and carrier, requester identity for scripts, invocation-time versus admission-time failures, transform fingerprint composition, audit admission, and target-platform disposition. The native Hermes transform surface also has an immediate safety defect that must be contained independently of the future re-pin. The RFC is a strong program outline, but accepting it now would approve important security, compatibility, and wire-format decisions before their designs are known.

2. **Strengths**

- The scope is disciplined. “One engine” is explicitly limited to production in-process runtime transforms, while Babel, subprocess overrides, and handwritten compatibility transforms are separately classified (LLP 0028 §Summary, §Goals, §Non-goals).

- The repository inventory is generally accurate. Rust is pinned to 1.93.1; `Cargo.toml:53-62` has ten direct Oxc dependencies and `Cargo.toml:110-118` has nine direct SWC dependencies; `Cargo.lock` contains twenty resolved `swc_*` packages. The default selector and tags are correctly identified in `src/module_loader/transpile.rs:38-77`, and the 0.1.x fence and kill switch are correctly described from `src/bin/ibex/runtime.rs:25-36` (LLP 0028 §1, §4).

- Phase 0 is the right ordering principle. The current Rust tests exercise the Tier 1 and compatibility-loader paths, not native Tier 3: `tests/hermes_compat_conformance.rs:117-132`, the loader runner at `packages/ibex-devtools/src/scripts/run-hermes-compat-loader.mjs:158-181`, and the audit bypass at `src/bin/ibex/runtime.rs:1443-1450` confirm the gap. Requiring the real Ibex binary, execution receipts, loaded-Hermes identity, source/prepared modes, and every advertised tuple is excellent evidence design (LLP 0028 §5).

- The candidate-set security model has good foundations: finite authenticated sets, no call-time filesystem probing, per-site separation, explicit declaration by default, and policy-closure expansion treated as a reviewable authority change (LLP 0028 §2).

- Deleting the file-at-a-time transform rather than growing a second lowering architecture is coherent with the module-runner endpoint. The sequenced CapSec generator/model update also correctly reflects how the current registry discovers `TransformEngine` variants (LLP 0028 §4a–§4c).

- The RFC surfaces audit admission and platform support as explicit blockers instead of allowing their behavior to change accidentally (LLP 0028 §4b, §4d). Those blockers need resolution, but naming them is a substantial strength.

3. **Concerns**

- **Material — The candidate-table mechanism is not yet a specified public or wire contract.**  
  **Evidence:** LLP 0028 §2 offers “an `import.meta.glob`-style or manifest-declared enumeration” (`llp/0028-oxc-only-transform-and-swc-retirement.rfc.md:210-218`), which are two materially different authoring models. Grammar, site association, zero-match behavior, package roots, symlinks, source-mode generation, and runtime value semantics are undefined. The proposed carrier is also unspecified: LLP 0027 defines a strict canonical `ibex/prepared-module-graph/1` at `llp/0027-module-artifact-and-interop.spec.md:129-137`, so a table cannot simply be added without a schema transition or an authenticated sidecar reference. Finally, `(requester SourceId, site)` is insufficient for edited artifacts and cannot address LLP 0024 scripts, which deliberately have no `SourceId` or module identity (`llp/0024-structured-evaluation-and-session.spec.md:359-361,1638-1643`).  
  **Resolution criterion:** Select one v1 authoring mechanism and specify its complete syntax, trust boundary, deterministic enumeration, diagnostics, and source/prepared behavior. Define `prepared-module-graph/2` or a separately versioned digest-bound sidecar, including v1 rebuild behavior. Bind module rows to requester semantic identity, transform fingerprint, site, and generation; either define a distinct authenticated script-requester identity or explicitly exclude and disposition every script surface.

- **Material — The claimed complete reachability inventory has demonstrable omissions.**  
  **Evidence:** LLP 0028 §4b retires `contains_top_level_await` through the entry-shim row, but it is also a live semantic dependency of `ibex -e` at `src/bin/ibex/main.rs:1251-1260` and bundle-format selection at `src/bin/ibex/runtime.rs:3326-3338`. `EXACT_COMPAT_TEST`, which selects loader behavior for conformance, module-semantics, performance, and eleven bootstrap-loader tests, has no disposition. The file-at-a-time path also owns additional cache namespaces beyond the two engine tags, including `loader-transpile-v14-content-addressed`, `transpile-tool-directory-v1`, `subprocess-transpile-toolchain-v2`, `subprocess-transpile-script`, and `in-process-transpile-engine` in `src/module_loader/mod.rs:1910-2121`.  
  **Resolution criterion:** Expand the generated retirement manifest and prose matrix to cover every caller, test selector, environment variable, and cache namespace. Provide an explicit post-retirement path for file entries, `-e`, `-p`, stdin, REPL, `.load`, audit, `.hbc`, bundling, and all conformance/performance runners, with behavior tests for TLA and non-TLA cases.

- **Material — LLP 0024 requires an architectural reconciliation, not merely an engine re-pin.**  
  **Evidence:** LLP 0028 §3 proposes changing `swc_ecma_parser` to Oxc while deferring the session implementation. But LLP 0024’s future transform authority is explicitly the soon-to-be-deleted `src/module_loader/transpile.rs` synchronous-`require` pipeline (`llp/0024-structured-evaluation-and-session.spec.md:675-699`), and its source-map model composes through the Tier 2 compatibility transform being retired. Its hybrid Script-plus-import-plus-TLA goal remains unprototyped (`llp/0024-structured-evaluation-and-session.spec.md:1893-1901,2256-2262`).  
  **Resolution criterion:** Make the LLP 0024 revision describe the complete post-retirement seam: parser entry point, hybrid-goal feasibility, module-runner handoff, static/dynamic/require behavior, non-file requester handling, and source-map composition after Tier 2 deletion. Reconcile every reference and acceptance criterion that currently depends on deleted machinery.

- **Material — Error timing and reserved-attribute handling are internally inconsistent.**  
  **Evidence:** LLP 0028 §2 says every dynamic-import failure occurs at invocation and dead branches remain admissible (`:184-194`), but also requires reserved policy attributes to be rejected on the wire (`:249-256`). LLP 0027 requires malformed or reserved wire attributes to fail artifact admission, before execution (`llp/0027-module-artifact-and-interop.spec.md:70-86`). Current production code rejects options during graph construction at `src/module_loader/producer_spike.rs:819-823,944-947`. The RFC’s reserved-key list is also stale: it omits the current canonical `authorities` attribute defined by LLP 0014 at `llp/0014-import-site-grants-and-generated-policy.spec.md:246-254`.  
  **Resolution criterion:** Normatively separate source-generation failures, authenticated-artifact admission failures, and invocation failures. Runtime option errors that must preserve dead-branch behavior need a guarded factory/runtime representation that leaves the artifact admissible; hostile or malformed wire artifacts must still fail admission. Derive all reserved keys and legacy aliases from one canonical schema and test every ingress.

- **Material — “One fingerprint domain derived from one Oxc constant” is not sufficient transform identity.**  
  **Evidence:** Production already uses a structured fingerprint with independent parser, transform, ABI, Hermes-compat, detector, and option fields (`src/module_loader/artifact.rs:69-82`; `src/module_loader/producer_spike.rs:66-98`). The actual Oxc target is separately hard-coded to `es2022` at `src/module_loader/producer_spike.rs:1386-1398`, while `hermes_target` receives the loaded engine bytecode-cache identity at `src/bin/ibex/runtime.rs:1537-1541`; the target is not present in the option digest. Moreover, rollout step 2 changes the factory/native ABI from `dynamicImport(expr)` to a site-bearing call after step 1’s Oxc-driven rotation. LLP 0027 §Digest domains requires the ABI and every output-affecting option to participate.  
  **Resolution criterion:** Treat the locked Oxc dependency-set digest as one fingerprint component, not the whole identity. Define one canonical transform configuration used both to construct Oxc and populate a domain-separated fingerprint containing the ECMAScript target, Oxc versions/sources/features, handwritten pass version, ABI, detector, and options. Rotate and stale-test identity at every output-changing phase, including the candidate-site ABI change.

- **Material — Native Tier 3 is unsafe today, and the planned corpus does not yet define the complete Hermes target.**  
  **Evidence:** The production producer reuses the spike at `src/module_loader/producer_spike.rs:795-809`. Its for-of visitor rewrites every matching identifier-bound `const`/`let` block into a regular-function IIFE without checking `this`, `arguments`, `break`, `continue`, `return`, `yield`, `await`, hoisting, or redeclaration (`:428-471`). Thus some hazards described as “untouched” in LLP 0028 §5 are actively rewritten and may change semantics or produce invalid syntax. This contradicts LLP 0019’s zero-divergence requirement while the native runner is already the default. The proposed corpus also omits known Hermes gaps: `for await`, `using`, and `await using` are detected at `src/module_loader/mod.rs:548-574`, while canonical BigInt lowering exists because Hermes rejects literal syntax (`packages/ibex-devtools/src/scripts/hermes-compat.mjs:15-21,598-648,987-990`). SWC currently enables decorators, whereas the Oxc fingerprint says `decorators=off`, without a normative compatibility decision.  
  **Resolution criterion:** Make typed quarantine an immediate 0.1 release blocker, not merely a precondition to the re-pin. Define an exhaustive Hermes syntax/pass/unsupported matrix, including for-of, async generators, for-await, resource-management syntax, BigInt, decorators, and source-map expectations. Every row must have real-binary source/prepared fixtures and a final window-close disposition; no quarantine may disappear merely because the fallback is deleted.

- **Material — The computed-`require` decision rests on a false rationale and non-representative evidence.**  
  **Evidence:** LLP 0028 §2 says CommonJS has no declaration channel without inventing syntax (`:241-244`), but LLP 0014 already defines a JSON-only second argument, `require("pkg", {"authorities":[...]})`, at `llp/0014-import-site-grants-and-generated-policy.spec.md:250-254`. The synchronous graph-drive cost remains valid, but absence of an authoring channel does not. The proposed telemetry observes only Ibex CI and Snapback test populations, and treats four weeks of zero events as decision-grade (`llp/0028-...:459-471`); zero test executions provide no denominator or evidence about untested downstream source.  
  **Resolution criterion:** Correct the rationale and explicitly evaluate reuse of the existing CJS JSON channel or manifest rows. Either gather representative, versioned evidence with a denominator—such as downstream static scans plus deployment reporting—or label telemetry advisory and make unsupported computed `require` an explicit 0.2 compatibility decision.

- **Material — Audit migration is a security architecture prerequisite, not a loader repoint.**  
  **Evidence:** Native graph construction calls the armed-snapshot-dependent path at `src/module_loader/runner_pipeline.rs:264-278`, while audit deliberately constructs an unarmed host and currently bypasses native graphs (`src/bin/ibex/runtime.rs:1278-1301,1443-1450`). LLP 0028 names a future audit-admission workstream in §4b but does not specify how an unarmed diagnostic principal can construct authenticated graphs without manufacturing executable authority.  
  **Resolution criterion:** Before this RFC advances, land an accepted contract or executable prototype defining principal and `SourceId` derivation, hard fences, cache admission, would-deny receipts, and denied/missing/cross-principal behavior. The real audit-based conformance runner must prove the contract rather than merely select a different loader.

- **Material — The target-platform outcome remains an unresolved product decision.**  
  **Evidence:** LLP 0028 §4d leaves step 4 to a later author choice between new native artifacts and platform de-support (`:395-408,583`). Compatibility currently also provides audit and script execution on unadvertised tuples, so the effect is broader than armed production runtimes. The acceptance wording alternates between “every advertised tuple” and “both tuples” (`:514-516`), which would become wrong if support expands.  
  **Resolution criterion:** Choose the supported 0.2 matrix in this RFC, or make an already-accepted platform Decision a prerequisite to accepting LLP 0028. Cover production, audit, diagnostics, and TypeScript runtime behavior on every retained tuple, and derive CI requirements from the matrix rather than hard-coding two jobs.

- **Minor — The governing LLP reconciliation list omits LLP 0007.**  
  **Evidence:** LLP 0028 calls LLP 0007 the transform-toolchain authority, but §5’s reconciliation list (`:501-505`) does not update it. LLP 0007 remains Draft and retains obsolete SWC-default, Windows-switch, fallback-window, and decorator questions; LLP 0026 explicitly requires its update during retirement.  
  **Resolution criterion:** Add LLP 0007 to rollout and acceptance, reconcile its fixture/platform/Babel/decorator language, and then accept, close, or explicitly supersede it.

4. **Suggestions**

- Split the work into three linked decisions: the Oxc/SWC retirement RFC, a candidate-table Spec, and an audit-admission Spec. Retirement can then depend on two accepted, testable contracts instead of embedding placeholders.

- Merkleize large candidate tables: bind a root into the deployment graph and authenticate the invoked site’s canonical row and target proof. This preserves per-site non-escalation without eagerly copying large route closures into every carrier.

- Generate an executable transform manifest from the canonical transform configuration. Use it to configure Oxc, construct the fingerprint, populate execution receipts, and enumerate conformance rows.

- Add a non-gating latest-Oxc canary and make lock-resolved package version/source/checksum authoritative. Consider exact-pinning `oxc_resolver`, whose current Cargo requirement is not exact even though the lockfile resolves one version.

- Supplement computed-`require` runtime telemetry with static scans of authenticated dependency graphs; this provides a denominator without requiring production code execution.

- Replace “both tuples” with “every advertised tuple” throughout, and assign stable diagnostic codes for syntax deliberately unsupported after SWC retirement.

5. **Open questions**

- What exact v1 candidate-declaration syntax is supported, and who is authorized to author it?

- What versioned object carries candidate rows, and how are source edits, site reordering, HMR generations, and stale prepared graphs handled?

- What authenticated requester identity applies to `ibex:eval`, REPL, and `.load` scripts that have no `SourceId`?

- What exact ECMAScript/Hermes target does the native producer promise, and what is the exhaustive pass-versus-typed-unsupported matrix?

- Are decorators a supported runtime TypeScript feature after retirement, or an intentional 0.2 incompatibility?

- What audit-admission construction proves that an unarmed host cannot manufacture executable authority?

- Which target tuples remain supported at 0.2 for production, audit, diagnostics, and runtime TypeScript?

- Is computed `require` removal an evidence-driven compatibility claim or an explicit product break, and what population can actually answer that question?

- Which parts of the transform fingerprint rotate for an Oxc re-pin, an Ibex pass change, an ABI change, or an output-target change?

6. **Readiness verdict**

VERDICT: NOT READY — Material candidate-contract, runtime-safety, identity, audit-admission, and platform decisions remain unresolved.
### Orchestrator verification notes (round 3, outside verbatim body)

Spot-checked: LLP 0014 does define a CJS JSON attribute channel (`require("pkg", {"authorities":[...]})`) — the review's correction of the RFC's "no CJS authoring channel" rationale is confirmed; the reserved-attribute list in LLP 0014 names `authorities` (RFC's list was stale); `contains_top_level_await` is also read by `ibex -e` and bundle-format selection; the additional transpile cache namespaces exist in `src/module_loader/mod.rs`. One review claim inverts the RFC's §5 wording ("untouched" — the RFC says hazards are left raw where the reviewer shows they are actively rewritten); the underlying safety defect is confirmed either way and the RFC text is corrected in the round-3 revision. No material defect found in the review's factual basis.

## Round 4 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f8e-b7c7-7fb0-9da6-9acc95b8b671`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed at git-blob `d4dc72fe44c7998b26c54e1f420833989b695af5`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round). Round-4 brief added the calibration that registered author decisions do not by themselves make a document unready.
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The proposal’s central direction is sound: Oxc should become Ibex’s sole production in-process module-transform authority, and the bounded SWC compatibility path should be removed rather than taught permanent parity. The RFC is unusually strong at inventorying the migration, acknowledging platform limits, and placing conformance gates before the version rotation. Its factual foundation is mostly accurate.

The plan is not yet ready for acceptance, however. Several load-bearing contracts are internally inconsistent or incomplete: script surfaces are assigned to an LLP 0024 frontend whose implementation is simultaneously declared unnecessary; computed-candidate identity and admission are not securely defined across source, prepared, and HMR modes; the replacement meaning of `hermes_target` is absent; `EXACT_COMPAT_TEST` is incorrectly treated as loader-only; and the proposed `cargo deny` prefix gate cannot implement the stated invariant.

This should remain an umbrella Draft while those contracts are made decision-complete. The right end state is clear, but accepting the present text would bless multiple incompatible implementation paths and at least one unsafe retirement action.

2. **Strengths**

- The scope is honest and well chosen. “One engine” is explicitly limited to production in-process runtime transforms, while Babel and developer subprocess behavior are classified separately (LLP 0028 Summary, Goals, and Non-goals). This aligns with LLP 0009’s accepted Oxc direction and LLP 0026’s bounded 0.1 fallback.

- The repository supports the RFC’s main inventory claims. There are ten direct Oxc dependencies and nine direct SWC dependencies ([Cargo.toml:53](/Users/ccheever/projects/ibex/Cargo.toml:53), [Cargo.toml:110](/Users/ccheever/projects/ibex/Cargo.toml:110)), twenty resolved `swc_*` packages, Rust is pinned to 1.93.1 ([rust-toolchain.toml:1](/Users/ccheever/projects/ibex/rust-toolchain.toml:1)), and SWC remains the file-at-a-time default while Oxc is opt-in ([transpile.rs:47](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:47), [transpile.rs:64](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:64)).

- The transform-identity diagnosis is excellent (LLP 0028 §1). `TransformFingerprintV1` is already structured, but `es2022` is hard-coded outside its option digest and `hermes_target` is supplied externally ([artifact.rs:69](/Users/ccheever/projects/ibex/src/module_loader/artifact.rs:69), [producer_spike.rs:66](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:66), [producer_spike.rs:1386](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:1386)). Moving construction, fingerprints, cache tags, and receipts under one configuration authority is the right design.

- The immediate Tier 3 quarantine is necessary and correctly prioritized (LLP 0028 §5). The production Oxc visitor currently wraps matching `for…of` bodies in ordinary-function IIFEs without semantic hazard checks ([producer_spike.rs:428](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:428)); Tier 2, by contrast, checks control flow and hoisting hazards and uses an arrow-based iterator-protocol rewrite ([module-loader.js:3463](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3463), [module-loader.js:3526](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3526)). That is a live violation of LLP 0019’s zero-divergence discipline, not speculative cleanup.

- Phase 0 correctly requires a new native, real-binary Hermes runner. The enforced conformance seam currently covers only the canonical AST and compatibility-loader paths ([hermes_compat_conformance.rs:1](/Users/ccheever/projects/ibex/tests/hermes_compat_conformance.rs:1), [hermes_compat_conformance.rs:117](/Users/ccheever/projects/ibex/tests/hermes_compat_conformance.rs:117)).

- The exact retirement-manifest idea, platform Decision gate, audit-admission gate, and explicit author-decision register are good governance mechanisms (LLP 0028 §§4–7). Surfacing those choices is substantially better than hiding them in implementation issues.

3. **Concerns**

- **Material — The script-surface successor contradicts the rollout prerequisites.** Evidence: LLP 0028 §3 says the structured-session implementation is not required for SWC deletion, but §4b requires `-e`/`-p`, REPL, and `.load` to execute through that frontend after retirement and moves TLA detection to it. LLP 0024 still says its hybrid Script-plus-`import`-plus-TLA goal does not exist and must be prototyped ([LLP 0024, OBL-PARSER-GOAL](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1897)). Current `-e` routing still uses the text scanner ([main.rs:1251](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1251)), and the entry shim still invokes SWC directly ([runtime.rs:1892](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1892)).  
  **Resolution criterion:** define a minimal Oxc-backed script frontend distinct from the deferred full session stack, enumerate every required reader/surface, and make its implementation plus real-Hermes fixtures an explicit step-4 and acceptance gate; alternatively, make the relevant LLP 0024 implementation itself a prerequisite.

- **Material — The computed-candidate contract lacks a secure, stable site and carrier identity.** Evidence: LLP 0028 §2 refers to a “named computed site” but never defines the author-facing name or join behavior after edits. Ordinals and spans are edit-sensitive. `SourceId` contains principal/path identity but not source integrity ([identity.rs:18](/Users/ccheever/projects/ibex/src/module_loader/identity.rs:18)); source integrity is a separate artifact field ([artifact.rs:215](/Users/ccheever/projects/ibex/src/module_loader/artifact.rs:215)), yet the proposed sidecar key omits it. Current site semantics are already inconsistent: `DynamicEdgeV1.site` promises stable producer order ([artifact.rs:152](/Users/ccheever/projects/ibex/src/module_loader/artifact.rs:152)), ESM writes a transformed byte offset ([producer_spike.rs:393](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:393), [producer_spike.rs:824](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:824)), and CommonJS uses an ordinal ([producer_spike.rs:963](/Users/ccheever/projects/ibex/src/module_loader/producer_spike.rs:963)). The RFC describes only a prepared-graph-v2 carrier, not equivalent authenticated source-mode admission, and mixes immutable sidecar identity with LLP 0026’s runtime execution generation. It also does not define who may authorize package-closure candidates under LLP 0014’s root-only grant channel.  
  **Resolution criterion:** land a normative candidate-table contract defining declaration authority, a stable site key, requester source-integrity or semantic-digest binding, missing/moved/duplicate-site behavior, one bijection across artifact/site-table/ABI/sidecar, and atomic policy/graph/sidecar admission for source, prepared JS, prepared HBC, HMR, and audit. Include cross-source, cross-policy, cross-generation, substitution, and two-site non-escalation fixtures.

- **Material — The canonical manifest does not define the new meaning of `hermes_target`.** Evidence: LLP 0028 §1 correctly notes that the field is currently runtime-derived, but its proposed manifest field list never says what replaces it. The field remains mandatory in the unchanged v1 fingerprint ([artifact.rs:69](/Users/ccheever/projects/ibex/src/module_loader/artifact.rs:69)). Production currently passes `bytecode_cache_identity()` ([runtime.rs:1537](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1537)), which hashes both the loaded Hermes binary and discovered `hermesc` ([hermes.rs:2571](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:2571)). That is evaluator/HBC-toolchain identity, not simply producer configuration.  
  **Resolution criterion:** define a stable producer-declared Hermes syntax/ABI target in the manifest, separate it from actual evaluator and HBC-carrier admission identity, and test same-target reuse, incompatible-evaluator refusal, and rotations of each independent identity component.

- **Material — `EXACT_COMPAT_TEST` is not a loader selector and cannot retire as proposed.** Evidence: LLP 0028 §4b says it retires with the compatibility loader. In reality, the general compatibility runner sets it for every fixture ([compat/runner.rs:481](/Users/ccheever/projects/ibex/src/bin/ibex/compat/runner.rs:481)); it installs fixture globals and Bun test globals ([compat-polyfills.js:2661](/Users/ccheever/projects/ibex/src/engine/bootstrap/compat-polyfills.js:2661), [compat-polyfills.js:4152](/Users/ccheever/projects/ibex/src/engine/bootstrap/compat-polyfills.js:4152)); it changes process identity ([process.ts:803](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/node/process.ts:803)); and retained fetch/stream code reads it ([Headers.ts:31](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/fetch/Headers.ts:31)). Runtime uses it for both polyfill reapplication and preparation bypass ([runtime.rs:1646](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1646), [runtime.rs:3291](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:3291)).  
  **Resolution criterion:** retain or rename a fixture-fidelity contract, split out the legacy-loader/preparation-bypass meaning, and give every producer and reader an explicit retain/migrate/remove disposition with native-path execution receipts.

- **Material — The normative failure taxonomy is internally inconsistent.** Evidence: LLP 0028 §2 says source-generation failures never block dead-branch sites and that source-authored malformed bags fail only when invoked. The same section later says reserved policy keys are source-diagnosed as class-1 generation failures, which necessarily can block a dead branch. The “same malformed bag” fixture therefore cannot satisfy both rules as written.  
  **Resolution criterion:** define a complete key/value/timing matrix. State explicitly which statically forbidden constructs are unconditional generation errors, which are guarded invocation errors, and which malformed wire forms fail admission; then revise the blanket dead-branch statement and fixtures to match.

- **Material — The proposed `cargo deny` wildcard gate cannot enforce the stated prefix invariant.** Evidence: LLP 0028 §§4 and 6 rely on a `swc_*` wildcard ban to reject every present or future SWC crate. Cargo-deny package specifications identify crate names and optional version requirements; its `wildcards` setting concerns wildcard dependency versions, not name-prefix globs, as shown in the official [cargo-deny package-spec documentation](https://embarkstudios.github.io/cargo-deny/checks/cfg.html).  
  **Resolution criterion:** enumerate known SWC crates in cargo-deny if useful, and add a separately tested CI check over `cargo metadata` or `Cargo.lock` that rejects every package whose name starts with `swc_` across each retained profile.

- **Material — The RFC is not decision-complete.** Evidence: LLP 0028 §7 leaves five blocking author choices unresolved: platform support, whether computed dynamic import ships in step 2, computed `require`, decorators, and contract ownership. The accepted audit-admission contract also does not yet exist. These choices materially change compatibility, security authority, scope, and the advertised Snapback promise; telemetry can inform them but cannot make them.  
  **Resolution criterion:** record the author’s decisions before advancing the RFC, or split the contingent designs into accepted Decision/Spec LLPs with precise prerequisite relationships and make this document explicitly an umbrella Plan rather than the final retirement RFC.

- **Minor — The claimed complete retirement inventory contains localized factual omissions.** Evidence: §4a’s “full cache-namespace estate” omits `in-process-oxc-0.121.0-v1` ([transpile.rs:47](/Users/ccheever/projects/ibex/src/module_loader/transpile.rs:47)), `IBEX_TRANSPILE_CACHE_MAX_BYTES` ([mod.rs:2357](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:2357)), and the test barrier `IBEX_TEST_TRANSPILE_INPUT_BARRIER` ([mod.rs:2499](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:2499)). The entry-shim row also says every source-extension entry is SWC-lowered, but `.cjs` is excluded from its lowering set ([runtime.rs:1902](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1902)).  
  **Resolution criterion:** add exact dispositions and manifest needles for the omitted tag/env contracts, and correct the `.cjs` statement and fixture matrix.

4. **Suggestions**

- Generate a reviewed `computed-sites.lock` from the producer’s single AST pass. Key each entry by requester source integrity plus a structural site digest, and have `--check` propose replacements when edits invalidate a site. Humans would review stable candidate diffs without hand-authoring fragile ordinals.

- Make the transform configuration an authored canonical input that generates Rust constants, cache tags, receipts, and CI pin assertions. “Checked-in generated manifest” currently leaves its upstream source of truth unclear.

- Define the “Oxc locked-set digest” over the complete output-affecting resolved dependency closure, including source/version/checksum, rather than only the ten direct packages.

- Add one checked-in mapping from every LLP 0019 corpus case to either native `Pass` or typed quarantine. Both outcomes should emit receipts for source and prepared paths, preventing silent gaps between the shared corpus and Tier 3.

- Name and digest the dependency-tree populations used for advisory telemetry. A zero count from an unspecified or mostly synthetic corpus is weak evidence even when telemetry is correctly labeled non-authoritative.

- Replace “revised and closed” with precise LLP lifecycle outcomes for LLPs 0007 and 0009: Implemented, Superseded, or tombstoned with preserved historical rationale.

- A non-standard future extension could give script submissions an ephemeral `EvaluationSourceKey` derived from session identity, submission ordinal, and source digest. That could authenticate script-local candidate tables without falsely assigning an LLP 0023 module `SourceId`.

5. **Open questions**

- What is the minimum Oxc-backed frontend that must exist for `-e`/`-p`, REPL, `.load`, stdin, and hybrid Script-plus-import-plus-TLA before SWC deletion?

- What stable identifier does an author use to declare a computed site, and what happens when source edits move, remove, duplicate, or reorder it?

- Who may declare package-closure candidates, and how is root approval distinguished from a package request under LLP 0014?

- How is the sidecar admitted and bound atomically in source, prepared-JS, prepared-HBC, HMR, and audit execution?

- What exactly does `hermes_target` mean after rotation, and which evaluator/compiler properties belong in transform identity versus carrier admission?

- Which semantics of `EXACT_COMPAT_TEST` remain part of the compatibility harness, and what new selector—if any—owns loader-only behavior?

- Which platform tuples are supported at 0.2, and what are the explicit runtime-TypeScript, audit, and diagnostic behaviors on every other retained tuple?

- Does Snapback require computed dynamic import at window close? Are computed `require` and decorators supported or deliberately diagnosed as incompatible?

- Which source-authored option errors are generation-time versus reached-site failures, especially reserved policy keys in dead branches?

- What precommitted semantic projection and allowed-difference set govern the old-pin/new-pin differential report?

6. **Readiness verdict**

VERDICT: NOT READY — The Oxc-only direction is strong, but the script replacement, candidate-sidecar security contract, transform identity, compatibility-flag migration, and enforcement gates retain unresolved material correctness issues.
### Orchestrator verification notes (round 4, outside verbatim body)

Spot-checked: `EXACT_COMPAT_TEST` has fixture-fidelity readers beyond the loader (`compat/runner.rs:486`, `Headers.ts:36`, `process.ts:804,870`, `runtime.rs:1646,3292`) — confirmed; `.cjs` is absent from the entry shim's lowering extension set — confirmed; the cargo-deny wildcard-ban limitation is accepted on the cited documentation (bans are name+version specs, not name-prefix globs) and the gate was respecified over `cargo metadata` in the round-4 revision. The script-frontend contradiction, taxonomy inconsistency, and `hermes_target` gap are internal-consistency findings verified against the reviewed revision's own text. No material defect found in the review's factual basis.
