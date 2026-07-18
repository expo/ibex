# Reviews: LLP 0029 — Single-File Executable Packaging (OpenAI Codex family)

## Round 1 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f51-1e5a-7881-9cb5-64c2cf2384d8`
**Date:** 2026-07-17
**Redacted:** no (repository content only; no secrets present)
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewer read LLP 0029 at git-blob `683fc6ebe3008f3de8c1a512731b6d5a3681d77f`, governing LLPs, and repo code; barred from reading `llp/reviews/`
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The product idea is strong. A hermetic, single-file Ibex executable with frozen code, policy, runtime identity, and deterministic packaging would materially improve deployment and auditability. Reusing LLP 0027 carriers and target-specific runtime stubs is directionally right.

The current proposal, however, treats several unfinished or incompatible mechanisms as if they already compose. Today’s prepared module graph is multi-carrier, path-bearing, and disk-revalidated; HBC carriers are not wired into production preparation; carrier engine binding is not stub binding; an LLP 0014 policy is not itself the execution-bound authority object; and neither proposed target is currently CapSec-eligible. Cross-target compilation, static runtime artifacts, code signing, and application boot semantics also need substantially more design.

I would keep the proposal but revise it around a new authenticated package envelope, a dedicated minimal stub, target artifact descriptors, and a disk-free CapSec arming procedure. The result can preserve LLP 0027 carrier bytes, but it is not merely concatenation and it does require a new outer artifact contract.

2. **Strengths**

- The user-facing goal is clear and valuable: one command producing a relocatable executable with no source tree or package installation dependency (LLP 0029 §Summary, §Motivation, §Goals).

- The proposal correctly favors canonical prepared artifacts over embedding loose source and recreating resolution at startup (LLP 0029 §Goals; §Alternatives, “Embed source and interpret at startup”).

- Reusing LLP 0027’s carrier manifests, semantic digests, per-principal isolation, and pre-execution bytecode checks is the right foundation (LLP 0029 §2–§3; LLP 0027 §Carrier manifest and integrity, §Prepared deployment graph).

- The fail-loud, offline packaging rule is excellent. Missing target artifacts should not trigger hidden downloads or host-dependent fallback (LLP 0029 §5).

- The draft recognizes that runtime configuration and application-visible environment authority are different concerns (LLP 0029 §4). That separation is essential even though the mechanism is not yet complete.

- Initial platform restraint and explicit deferral of Windows, FFI closure, and automatic publisher signing are sensible scoping choices (LLP 0029 §Non-goals).

- The open questions identify several real decision points—environment handling, cwd/stdio authority, stub distribution, and detached provenance—rather than presenting them as settled (LLP 0029 §Open questions).

3. **Concerns**

1. **Material — The proposed payload is not the artifact the current module runner actually needs.**

   **Evidence:** LLP 0029 §2 depicts one carrier plus policy, identity, and entry designation, while LLP 0027 permits one defining principal per carrier and separately requires a prepared-graph index. Production preparation emits one carrier per principal and an `ibex/prepared-module-graph/1` index (`src/module_loader/runner_pipeline.rs:45–83,419–564`). That index serializes source paths, and loading requires absolute paths, rereads source files for authentication, and re-resolves authored edges through the host (`runner_pipeline.rs:521–560,650–689`). This contradicts LLP 0029 §Goals and §5 claims that execution performs no disk resolution and output contains no build-host paths.

   **Resolution criterion:** Define a canonical, versioned, path-independent executable envelope containing the prepared graph, canonical entry `SourceId`, every per-principal carrier manifest and byte section, module-to-carrier bindings, and all relevant digests. Specify an embedded admission path that never reads or resolves original files, and require relocation tests that delete the source tree and reproduce identical output from different checkout paths. Withdraw the §Non-goals claim that no new outer artifact format is required.

2. **Material — Stub, engine, producer, and package identities are conflated.**

   **Evidence:** LLP 0029 §3 says the HBC carrier binds the exact runtime stub. LLP 0027’s carrier encoding instead contains `engine_binary_digest` and `bytecode_version` (`src/module_loader/carrier.rs:23–31,147–165`). The runtime hashes the loaded artifact containing Hermes (`src/engine/mod.rs:38–110`): currently that is a dynamic framework or `.so` on macOS and default Linux builds (`build.rs:1223–1233,1443–1458`), not the stub. With static Hermes it can become the final executable, making a digest embedded inside that same executable self-referential. Prepared graphs also identify their producer by hashing the current `ibex` executable (`src/bin/ibex/runtime.rs:52–57`), which will differ from the packaged stub. Finally, `runtime-identity.json` contains product/version identity, not stub, engine, policy, graph, or artifact provenance (`runtime-identity.json:1–16`; LLP 0012 §Decision).

   **Resolution criterion:** Define separate digest domains for the builder/producer, HBC-compatible Hermes build and ABI, projected immutable stub core, canonical package envelope, and final signed file. Explicitly exclude payload and signature regions from the projected stub digest. Add a separate package provenance/boot manifest; do not overload `runtime-identity.json` or place a full final-executable digest inside the executable itself.

3. **Material — Embedding an LLP 0014 policy does not establish the claimed authority boundary.**

   **Evidence:** LLP 0021 §Policy forms distinguishes the canonical review policy from the execution-bound `ArmedSnapshot`; only the latter is consumed by the engine. Current arming binds the target, engine, registry, graph, authenticated roots, protected objects, generations, and fresh run/channel nonces (`src/bin/ibex/runtime.rs:2129–2529`). LLP 0029 does not define how those values arise without an installed tree. More seriously, canonical policy rows cover package principals, while the current evaluator can grant unresolved root effects through `AmbientRoot` (`crates/capsec-semantics/src/policy.rs:121–129`; `crates/capsec-semantics/src/decision.rs:924–948`). Therefore “total authority is exactly the embedded policy” and “no ambient filesystem/network” do not follow for the compiled application’s root code. There are also presently zero verified CapSec target advertisements (`capsec/generated/target-matrix.md:5–9`; `target-advertisements.json:1–5`), and production arming refuses unadvertised targets (`src/host/mod.rs:3014–3084`).

   **Resolution criterion:** Make LLP 0021 governing context and specify a complete disk-free arming algorithm that creates a fresh per-run snapshot while binding the embedded graph, policy, engine, registry, virtual roots, and protected artifacts. Define authored compiled-root authority or an explicit bounded process-wide ceiling that prevents `AmbientRoot` from widening it. Require verified CapSec advertisements for each exact stub target and feature profile before claiming production readiness.

4. **Material — The build and policy-generation description is factually wrong and risks bypassing policy review.**

   **Evidence:** LLP 0029 §1 says the default policy uses the same generation “ordinary build performs.” Current `ibex build` accepts a file and `--outdir`, bundles CommonJS, compiles HBC, and copies sibling chunks (`src/bin/ibex/cli.rs:229–238`; `src/bin/ibex/main.rs:1384–1430`). It neither creates LLP 0027 carriers nor generates/checks policy. Policy generation is a separate external-script-backed command (`src/bin/ibex/runtime.rs:5396–5443`). LLP 0014 requires the canonical policy to be committed and drift-checked as a review tripwire (LLP 0014 §Canonical policy artifact, §Tool integration).

   **Resolution criterion:** Define a real executable producer pipeline. By default it should consume a strict-valid, committed policy, run the equivalent of `ibex policy check`, and fail if the policy is missing or stale. Any auto-generation mode should be explicit and unsuitable for release output unless its widening is reviewed. One authenticated graph snapshot must drive both policy validation and carrier production.

5. **Material — The environment hardening rule is incomplete and does not separate runtime and application channels.**

   **Evidence:** LLP 0029 §4 proposes ignoring `IBEX_*` and `EXACT_*` except an allowlist. The actual runtime also has `EX_*` and unprefixed startup controls, including security- and transport-affecting names. Live readers include legacy loader and bytecode switches, cache and repository-root overrides, transform configuration, Hermes tool paths/timeouts, DNS configuration, and Node-compatible TLS/channel controls (`src/bin/ibex/runtime.rs:33–36,3315–3417,5207–5495`; `src/module_loader/transpile.rs:65–70`; `src/bin/ibex/engine/hermes.rs:1612–1700`; `src/capsec_registry_generated.rs:28904–28926`). Some reads occur before the armed Host exists. Application `process.env` currently derives from the same OS environment, so globally removing variables can also remove values the application is authorized to read.

   **Resolution criterion:** Generate a versioned compiled-startup environment profile from the complete CapSec inventory, independent of name prefix, and require every new runtime reader to be classified. Compiled boot must be selected before any such read. Define ignore-versus-reject behavior, capture a distinct immutable application-visible environment snapshot, and test every inventoried variable plus child-process inheritance.

6. **Material — The target-stub, cross-target, dependency, and signing plan is not currently feasible as described.**

   **Evidence:** LLP 0029 §2 characterizes cross-packaging as essentially selecting a prebuilt stub and appending bytes. Current HBC production discovers a host compiler and checks it against the loaded host engine; it has no target parameter (`src/bin/ibex/engine/hermes.rs:2775–2937`). Module semantic fingerprints also contain the Hermes target, so a host-prepared graph is not automatically valid for another target (`src/module_loader/artifact.rs:69–90`). Current macOS and default Linux builds dynamically link Hermes, and the Linux target is not dependency-free in the literal sense (`build.rs:1223–1233,1443–1474`). No checked-in target-stub catalog supplies static stubs, compiler compatibility, minimum OS/glibc/CPU requirements, or HBC metadata. Separately, §Non-goals says macOS re-signing is documented but not implicit, while §2 says `ibex build` performs ad-hoc `codesign`. Signing mutates Mach-O layout and places signature data near EOF, which interacts directly with the proposed trailer and deterministic digest projection.

   **Resolution criterion:** Either limit v1 to host-target packaging or define authenticated target descriptors containing the target tuple, stub-core digest, Hermes build/features/HBC version, compatible host-runnable compiler, and minimum platform baseline. Define whether “no dependencies” means fully static or only no Ibex sidecars, and enforce it with `otool`/`ldd` CI. Resolve the signing contradiction and normatively specify packaging/signing order, trailer discovery, digest exclusions, cross-host signing support, and reproducibility expectations.

7. **Material — In-file digests provide consistency, not authenticity against tampering.**

   **Evidence:** LLP 0029 §2–§3 says the footer verifies the payload and tampering breaks the runtime/carrier pair. An attacker who can replace carrier code or policy can also recompute the manifest and footer digests. Carrier admission likewise compares fields with caller-supplied expectations (`src/module_loader/carrier.rs:230–281`). Ad-hoc macOS signing is not publisher authentication, and no Linux trust anchor is proposed.

   **Resolution criterion:** State the threat model explicitly. If the intended guarantee is corruption detection, narrow the wording accordingly. If malicious replacement is in scope, require a publisher signature or externally trusted digest over the canonical package manifest and every routing field and section. The parser must authenticate and strictly validate section types, offsets, lengths, ordering, overlap, duplication, entry designation, and allocation limits before evaluating code.

8. **Material — Compiled boot and application process semantics are undefined.**

   **Evidence:** Current `main` performs namespace interception and Clap parsing before runtime boot (`src/bin/ibex/main.rs:244–317`). A packaged application invoked as `mytool test`, `mytool new`, or `mytool --foo` would therefore be intercepted or rejected unless compiled-payload detection occurs earlier. Existing file execution also constructs `process.argv` with a source-path slot (`src/bin/ibex/runtime.rs:1608–1619`), which has no obvious compiled equivalent. A subtractive `compiled-mode` feature is also awkward because the repository has one unconditional CLI/repl/compat binary graph, and the exact CLI audit rejects target-conditional production surfaces (`Cargo.toml:17–145`; `src/bin/ibex/cli.rs:1393–1409`).

   **Resolution criterion:** Prefer a dedicated minimal compiled-stub binary/crate, or specify a trailer-detection branch before all namespace and Clap handling. Normatively define forwarding and runtime values for `argv`, `argv0`, `execPath`, `execArgv`, `--`, `--version`, non-UTF-8 arguments, exit status, signals, cwd, and stdio. Tests must prove that arbitrary application flags and reserved Ibex command words reach the application unchanged.

9. **Material — The RFC lacks an implementation and acceptance plan proportionate to the new machinery.**

   **Evidence:** LLP 0029 moves directly from architecture to alternatives and open questions. It has no staged producer/loader migration, conformance matrix, failure-injection plan, or acceptance criteria. Its performance premise is also unsupported: current HBC paths copy carrier bytes into aligned storage rather than evaluating an mmap-backed buffer (`src/engine/hermes_module_runner.cc:53–81,1173–1214`; `src/engine/hermes_runtime.cc:554–574,4064–4107`), and no checked-in measurements establish 10–20 MB output or single-digit-millisecond startup.

   **Resolution criterion:** Add phased work packages and acceptance gates covering format golden vectors and parser fuzzing, wrong-engine and wrong-version rejection, source-tree deletion, target/CapSec eligibility, environment isolation, authority-denial tests, two-clean-builder reproducibility, signing verification, dependency inspection, application process semantics, and measured size/startup budgets. Recast the mmap, size, and startup statements as hypotheses until a representative prototype confirms them.

10. **Minor — The exact CLI and `.env` wording need correction.**

   **Evidence:** The proposed `ibex build --compile <entry> --output …` does not explain how the existing positional `build <FILE>` and `--outdir` behave, and `--policy` is currently a root option rather than a build-local option (`runtime-surface.json:834–853,1018–1063`). LLP 0010 requires the Clap tree and exact `runtime-surface.json` inventory to change together. LLP 0029 §4 also implies `.env` is an ordinary LLP 0022 loader surface, whereas LLP 0022’s v1 contract removes `.env` and the production REPL remains closed.

   **Resolution criterion:** Specify the complete command grammar, option placement, conflicts, compatibility behavior, and parser kinds, then update LLP 0010 and `runtime-surface.json` together. Say simply that compiled mode has no REPL and performs no `.env` loading.

4. **Suggestions**

- Prefer a distinct `ibex compile <ENTRY> -o <FILE>` or `ibex package` command over overloading the existing bytecode-oriented `build` command.

- Use a dedicated `ibex-compiled-stub` crate sharing only the host, engine, embedded-loader, and CapSec boot libraries. This should make the attack surface and size budget easier to audit than a subtractive Cargo feature.

- Introduce an `ibex/single-file-executable/1` canonical envelope with a Merkle-style section directory. Keep LLP 0027 carrier manifests and bytes verbatim inside it, but bind the graph, policy, target descriptor, provenance, and all sections at the outer layer.

- Produce a deterministic unsigned package first, then optionally produce a signed artifact and detached provenance/SBOM record. Record both digests instead of forcing signing variability into the reproducible-core claim.

- Add `ibex inspect-executable <FILE>` for metadata and integrity inspection. Avoid stealing an application’s `--version` flag; expose runtime/package provenance through a namespaced application API if needed.

- Store stubs and target descriptors in a content-addressed offline catalog with an explicit fetch/update command. Packaging should never download implicitly.

- Defer the interpreter-only variant until benchmark data shows whether it materially improves size or portability; keep factory-table carriers an explicit diagnostic fallback rather than a silent HBC fallback.

5. **Open questions**

- Is the integrity threat model accidental corruption, malicious file replacement, or publisher authenticity? What trusted key or external digest anchors the latter two?

- What is the exact canonical outer-envelope schema, and how are the graph index, multiple per-principal carriers, entry identity, policy, and logical roots cross-bound?

- Which digest identifies the Hermes compatibility domain, which identifies the immutable stub core, and which identifies the final signed file?

- How is a fresh LLP 0021 `ArmedSnapshot` derived without filesystem discovery, and what exact authority does compiled root/application code receive?

- Must policy be committed and drift-checked, or may release compilation generate it? How are authority expansions surfaced for review?

- Which exact target-and-feature tuples must become CapSec-eligible before v1 ships?

- Is v1 host-target-only? If cross-target compilation is required, where do compatible host-runnable Hermes compilers and authenticated target metadata come from?

- Does “no external dependencies” mean fully static, no non-system sidecars, or merely no Ibex/Hermes sidecars? What macOS, glibc, kernel, and CPU baselines are supported?

- What is the complete runtime-internal environment profile, and how is it separated from capability-authorized application `process.env` and child-process inheritance?

- What are the normative cwd, filesystem-root, stdio, argv, signal, exit, locale, terminal, and diagnostic semantics?

- In what order are payload append, footer construction, digesting, macOS signing, and optional publisher signing performed, and how does boot locate the footer after signing?

- Is HBC mandatory for release packages, or is factory-table execution a supported format with separately stated performance and exposure tradeoffs?

6. **Readiness verdict**

VERDICT: NOT READY — The product direction is compelling, but material gaps remain in artifact composition, authority arming, target feasibility, identity and signing, environment isolation, and executable boot semantics.
### Orchestrator verification notes (round 1, outside verbatim body)

Spot-checked against the working tree (2026-07-17): prepared-module-graph index serializes per-record `path` strings (`runner_pipeline.rs:521-540`); `pre_clap_namespace_dispatch` intercepts argv before Clap (`src/bin/ibex/main.rs:244+`); `ibex build` grammar is positional `FILE` + `--outdir` (`cli.rs:229-238`); HBC carrier bytes are copied into vector/aligned storage, not mmap-evaluated (`src/engine/hermes_module_runner.cc:53-70`); producer identity digests `std::env::current_exe()` (`runtime.rs:52-57`); zero verified CapSec target advertisements (`capsec/generated/target-matrix.md`, `target-advertisements.json` `advertisements: []`); `AmbientRoot` stratum in `crates/capsec-semantics/src/decision.rs:382,944-945`. All decisive claims confirmed.

## Round 2 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f64-79eb-7021-ac43-af460b03c591`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed LLP 0029 at git-blob `ca7f7200395488e982b17428219660619e2c3983`; barred from reading `llp/reviews/` (round-1 artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

This is a good product idea and the right architectural direction for Ibex. A dedicated compiled stub, embedded prepared graph, frozen capability policy, and explicit provenance fit the repository’s existing security model much better than wrapping the full CLI or extending the legacy bytecode `build` command. The proposal is especially strong where it admits that packaging is a new composition contract rather than simple concatenation.

The plan is not yet internally complete, however. Several load-bearing claims do not match the current artifacts: the embedded graph cannot be the LLP 0027 index “verbatim”; production HBC carriers are not currently published; policy checking and carrier production do not share a graph snapshot; the proposed engine digest does not bind a carrier to an exact stub; and compiled root authority, virtual mounts, runtime environment closure, signing order, and process lifecycle are not yet expressible as described.

I would continue with the proposal, but revise it around three explicit contracts: a path-independent embedded-graph schema, a v1 stub compatibility descriptor, and a single immutable build snapshot shared by policy validation and carrier production. Until those contracts and the process/security decisions below are specified, implementation can usefully prototype the format and static stub, but the RFC is not ready for acceptance.

2. **Strengths**

- The separation of `ibex compile` from `ibex build` is correct (LLP 0029 §1). The present `build` surface is exactly positional `FILE` plus `--outdir` (`src/bin/ibex/cli.rs:229-238`, `runtime-surface.json:1018-1063`) and dispatches through a separate Rolldown/Hermes bytecode path (`src/bin/ibex/main.rs:1384-1429`), not through LLP 0027 carrier publication.

- A dedicated stub rather than a feature-reduced full CLI is a sound boundary (LLP 0029 §2a). The current binary combines pre-Clap namespace interception, CLI, runtime, REPL, engine, and host code (`src/bin/ibex/main.rs:6-15,244-304`), while the CLI audit rejects production `cfg` variation (`src/bin/ibex/cli.rs:1393-1409`). A separate crate makes both attack surface and size reviewable.

- The RFC accurately identifies current platform prerequisites (LLP 0029 §2a and §5). macOS presently links a checkout-local Hermes framework dynamically (`build.rs:1223-1233`), Linux alone has the `HERMES_LINK_STATIC` branch (`build.rs:1443-1458`), and the relevant Hermes artifacts are gitignored (`.gitignore:4-7`).

- The policy posture is appropriate (LLP 0029 §1 and §4): production policy ingress already validates vocabulary, registry and policy digests plus `purpose: production, mode: enforce` (`crates/capsec-semantics/src/policy.rs:104-142`), and the drift command fails on missing or stale committed policy while separating expansions from narrowings (`packages/ibex-devtools/src/scripts/generate-policy.mjs:565-615`). Refusing silent policy generation during packaging is the right security choice.

- The proposal is unusually honest about integrity versus authenticity (LLP 0029 §3), about the current zero-target CapSec advertisement (`capsec/generated/target-advertisements.json:1-6`), and about size/startup numbers being hypotheses rather than results (LLP 0029 Motivation and §7).

- Keeping package provenance separate from `runtime-identity.json` is correct (LLP 0029 §3). LLP 0012 and `runtime-identity.json:3-16` define product and compatibility identity, not loader ABI, producer, or artifact provenance.

- The phased gates are useful and mostly measurable (LLP 0029 §7): relocation after deleting sources, two-builder byte comparison, parser fuzzing, wrong-engine rejection, dependency audits, target advertisement, and real-hardware measurements are the right classes of evidence.

3. **Concerns**

1. **Material — The path-independent graph is a new inner contract, contrary to the RFC’s non-goal.**

   **Evidence:** LLP 0029 lines 103-105 says the graph index remains an LLP 0027 artifact “verbatim,” while §2b lines 184 and 202-211 removes host paths and replaces disk admission. The existing schema requires `record.path` and carrier filenames (`schemas/prepared-module-graph-v1.schema.json:83-130`), and the loader requires absolute paths, re-authenticates source files, and re-resolves every authored edge (`src/module_loader/runner_pipeline.rs:584-711`). Those paths also determine source labels, `import.meta.url`, `__filename`, and `__dirname` (`runner_pipeline.rs:191-222`; `src/engine/module_runner.rs:1451-1459`). The checked-in schema additionally permits only file `SourceId`s, although Rust supports builtin and synthetic variants and publication places builtins in the root carrier (`schemas/prepared-module-graph-v1.schema.json:69-81`; `src/module_loader/identity.rs:22-37`; `runner_pipeline.rs:464-470`).

   **Resolution criterion:** Define and check in a separately named/versioned contract such as `ibex/embedded-module-graph/1`, including canonical section references, entry designation, every `SourceId` variant, typed edges and candidate sets, virtual `SourceLabel`/URL construction, source-map behavior, and admission rules. Validate complete real graphs including builtins against the schema, and remove the “verbatim/no new inner format” claim.

2. **Material — The proposed identities do not bind a payload to the exact compatible stub.**

   **Evidence:** LLP 0029 §3 says the static archive digest is “exactly as LLP 0027 prescribes” and that replay against a different stub fails. LLP 0027 instead specifies the loaded engine binary digest (`llp/0027-module-artifact-and-interop.spec.md:118-127`), matching the current whole-mapped-artifact hash (`src/engine/mod.rs:38-110`). A carrier contains engine digest and HBC version, but no stub identity (`src/module_loader/carrier.rs:20-52,147-165`); two different stubs using the same archive would accept the same carrier. The stub-core digest is merely recorded, and boot does not compare it (`LLP 0029 §3 and §6`). Replacing the current independent producer self-hash with a producer value read from the same envelope also removes the existing same-binary ABI guard (`src/bin/ibex/runtime.rs:52-57`; `src/module_loader/runner_pipeline.rs:584-603`). The proposed future descriptor omits accepted envelope/artifact/carrier schemas, module-runner ABI, transform profile, CapSec/arming ABI, and runtime identity.

   **Resolution criterion:** Make a content-addressed `StubContractV1` a v1 requirement, compile its digest into the stub, and require the envelope to pin the same digest. It should cover target/baseline, stub and loader ABI, accepted schemas, runtime-identity digest, transform/module-runner profile, Hermes compatibility identity, exact compiler identity, structural features, and CapSec registry/arming ABI. Add same-Hermes/different-stub swap rejection and producer-newer/stub-older rejection tests. Separate HBC compatibility identity from archive and executable provenance hashes rather than silently changing LLP 0027’s existing field meaning.

3. **Material — The claimed complete HBC producer path does not exist yet, and complete graphs depend on unfinished LLP 0028 work.**

   **Evidence:** LLP 0029 §1 describes the LLP 0026 production path as producing HBC carriers. The actual publisher emits only JavaScript factory tables and `.js` carriers (`src/module_loader/runner_pipeline.rs:419-423,497-507`), while reload supplies no expected engine digest/version and therefore rejects HBC manifests (`runner_pipeline.rs:632-645`; `src/module_loader/carrier.rs:271-279`). Current compiler preparation compares `hermesc` only with the packaging process’s loaded-engine HBC version; `bind_hermes_bytecode` accepts the caller-supplied target digest (`src/bin/ibex/engine/hermes.rs:2871-2874,2927-2938`; `carrier.rs:147-165`). Computed dynamic imports still return `LegacyRequired`, computed `require` lacks candidate tables, and import options remain unsupported (`runner_pipeline.rs:352-366`; `producer_spike.rs:829-841,941-973`). LLP 0028’s candidate-map implementation is still Draft and future work (`llp/0028-oxc-only-transform-and-swc-retirement.rfc.md:162-225,390-410`).

   **Resolution criterion:** Add explicit production-HBC and LLP 0028 dependency workstreams. Require an authenticated compiler paired with the selected stub contract, real HBC publication/admission, and source-deleted end-to-end executions on both tuples. Either block v1 on candidate-map implementation and the remaining legacy-shape dispositions, or explicitly narrow v1 and fail compilation on unsupported shapes. `factory-table` must not be presented as solving graph incompleteness.

4. **Material — Policy validation and carrier production do not currently use the same authenticated graph snapshot.**

   **Evidence:** LLP 0029 §1 lines 135-139 requires one snapshot. Today `ibex policy check` spawns an independent JavaScript generator (`src/bin/ibex/runtime.rs:5396-5439`), which performs its own Rolldown traversal (`packages/ibex-devtools/src/scripts/generate-policy.mjs:299-312`). The canonical policy has no graph-digest field (`capsec/schema/canonical-policy.schema.json:6-27`). Carrier production uses the Rust module-runner graph and different unsupported-shape rules. Even absent a race, those two graph interpretations can differ; a source mutation between steps adds a direct TOCTOU failure.

   **Resolution criterion:** Produce policy validation and carriers from one captured byte graph, or give both artifacts one authenticated graph digest whose node, package, integrity, typed-edge, candidate-set, and entry inventories must match exactly. Add an inter-step mutation fixture and a semantically divergent Rolldown-versus-module-runner graph fixture that both refuse packaging.

5. **Material — “Authority exactly equals the embedded policy” is not yet expressible, and compiled path semantics are undefined.**

   **Evidence:** Canonical policy ingress rejects non-package principals (`crates/capsec-semantics/src/policy.rs:121-129`), the generator emits package principals, and unresolved root effects are currently authorized through `AmbientRoot` (`crates/capsec-semantics/src/decision.rs:936-947`). LLP 0029 correctly identifies this in §4, but leaves it open. Separately, LLP 0023 requires `/project` to be backed by an authenticated project-root object and makes virtual cwd a retained directory identity (`llp/0023-virtual-filesystem-namespace.spec.md:242-271,1310-1422`). A redistributed executable has no build project tree: binding `/project` to launch cwd grants a mutable deployment tree, leaving it unbound breaks relative filesystem APIs, and retaining the build path defeats relocation. Stdio and cwd authority are also explicitly unresolved in LLP 0029 lines 452-456.

   **Resolution criterion:** Revise LLP 0021/0014 and the canonical schema to encode root/entry ceilings, generate them, and prove `AmbientRoot` cannot exceed them. Define a compiled mount contract covering initial cwd, backing-object authentication, logical spelling, policy selectors, relative-path behavior, and `chdir`. Then decide and encode the complete stdio/cwd/process authority profile with over-ceiling denial fixtures. This must be settled before “exactly the policy” is claimed.

6. **Material — The proposed environment profile cannot provide the stated closure from the current inventory.**

   **Evidence:** The scanner deliberately excludes generated code, build scripts, tests, devtools, and compatibility sources (`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:14286-14325,15563-15603`) and emits dynamic-access sentinels rather than an exhaustive per-name list (`capsec/generated/surface-inventory.md:6845-6858`). LLP 0025’s stronger post-arming environment inventory is explicitly “not started” (`llp/0025-terminal-session-ownership.spec.md:1149`). Application and runtime access currently share the OS environment: `process.env` calls native getters, which read `std::env`/`environ` directly (`packages/ibex-runtime-js/src/node/process.ts:1225-1299`; `src/engine/hermes_runtime.cc:1983-2082`; `src/host/abi.rs:4758-4769`). Native dependencies such as libcurl can also consult proxy/TLS environment outside the authored-source scanner. Finally, an “immutable process.env” would break existing writes, deletes, and child inheritance (`process.ts:1236-1245,1286-1299`; `src/builtins/child-process.js:1225-1227,2176-2184`).

   **Resolution criterion:** Specify an earliest-instruction sequence that captures the application base environment, sanitizes the real process environment before Ibex and dependency reads, and serves application reads from a separate capability-gated broker with a mutable process-local overlay and exact child inheritance. Generate a stub-specific reader inventory with its own schema/version/digest and cover dynamic access and dependency behavior. Explicitly scope the claim to Ibex-controlled post-entry behavior: dynamic-loader variables can act before `main` and cannot honestly be neutralized by an in-process profile.

7. **Material — The macOS signing/trailer state machine and detached authenticity story are incomplete.**

   **Evidence:** LLP 0029 §2c specifies append-then-sign and bounded reverse magic scanning, but not original-signature removal, footer candidate selection, a maximum publisher-signature span, or a check that the code signature covers the appended payload. The current `target/debug/ibex` is already ad-hoc linker-signed and its `LC_CODE_SIGNATURE` range ends exactly at EOF. A signed-then-appended file can still contain a perfectly valid internal footer and envelope, so internal digest checks alone cannot establish the RFC’s claimed signing-order refusal. Stub-core bytes also change during signing unless a normalization is defined. In §3, an unsigned colocated provenance JSON provides consistency, not authenticity; subsequent publisher signing changes the signed-file digest and immediately stales the record emitted by `compile`.

   **Resolution criterion:** Specify a byte-exact state machine: strip or normalize the linker signature, define stub-core bytes, append the envelope/footer, sign, parse `LC_CODE_SIGNATURE`, require its range to end at EOF and the footer to occupy the defined pre-signature position, and reject multiple candidates. Test ad-hoc and real identity/entitlement signing on the minimum macOS target. Split provenance into an immutable build statement and an authenticated publisher-signing statement; `inspect-executable` must distinguish internal consistency, platform-signature validity, and externally authenticated provenance.

8. **Material — Compiled lifecycle, signal, and output semantics are delegated too vaguely.**

   **Evidence:** LLP 0029 §6 says exit, signals, cwd, and stdio behave as policy surfaces define. LLP 0025 instead makes rendering, brokering, lifecycle, and interruption concrete obligations for file execution (`llp/0025-terminal-session-ownership.spec.md:133-140,214-237`) and says external interruption is not a JavaScript capability (`:1102`). The target implementation is not present: `process.exit` still drains briefly and invokes `std::exit` (`src/engine/hermes_runtime.cc:689-705`), while the only ordinary Tokio signal loop is the debugger keepalive path (`src/bin/ibex/main.rs:1091-1138`). LLP 0025 itself remains Draft with relevant outstanding obligations.

   **Resolution criterion:** Add normative compiled-file rows for event-loop drain, pending async work, uncaught exceptions/rejections, `process.exit`/`exitCode`, output brokering and loss, SIGINT/SIGTERM/SIGHUP, cancellation, and signal-derived status. State whether the stub is in-process or supervised, and make completion depend on the corresponding LLP 0025 obligations and end-to-end fixtures.

9. **Material — Arbitrary non-UTF-8 argv cannot reach JavaScript “unchanged” under the stated API.**

   **Evidence:** LLP 0029 §6 lines 377-384 promises unchanged non-UTF-8 arguments. Current argument and runtime APIs use `String`/`Vec<String>` and JSON serialization (`src/bin/ibex/cli.rs:162-168,177-216`; `src/bin/ibex/runtime.rs:1608-1611,1653-1662`). POSIX argv is arbitrary bytes; JavaScript strings are Unicode. There is no implicit lossless mapping.

   **Resolution criterion:** Either narrow the contract to Unicode arguments with a stable rejection or replacement rule, or define a reversible surrogate-escape/WTF-8 mapping plus a raw-byte argv API and byte-roundtrip tests. Specify `argv0`, `process.argv[0]`, `execPath`, and the embedded designation separately.

10. **Minor — CLI/CapSec registry integration is missing from phase 4.**

    **Evidence:** `runtime-surface.json` feeds the CapSec CLI inventory (`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:10573-10615,10828-10845`), so adding commands rotates registry and policy digests. Every CLI name requires reviewed admission, and the current classifier maps any name containing `inspect` to `inspector:activate` (`packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:5358-5375,9617-9635`), which would misclassify `inspect-executable`.

    **Resolution criterion:** Extend phase 4 to include explicit CLI classification, generated CapSec registry/binding regeneration, policy-digest migration, and drift gates. Add a dedicated non-inspector classification for executable inspection.

11. **Minor — Several current-state descriptions should be tightened.**

    **Evidence:** The existing build usually uses Rolldown but can fall back to raw source before `hermesc` (`src/bin/ibex/runtime.rs:3359-3406`); the global `--policy` option is syntactically present although build does not consume or bind the canonical artifact (`src/bin/ibex/cli.rs:84-86`); and LLP 0028 places build-pipeline retirement outside its own transform-engine scope rather than directly owning the command’s fate (`llp/0028-oxc-only-transform-and-swc-retirement.rfc.md:111-116`). Also, lean/full size comparisons should use equivalently pinned, patched, static, CapSec-conformant Hermes builds before influencing selection.

    **Resolution criterion:** Correct the factual wording and compare only eligible engine variants. These changes do not alter the architecture.

4. **Suggestions**

These are non-blocking once the material contracts above are resolved.

- Embed the exact host stub and `StubContractV1` bytes inside the distributing `ibex`, or install them as one content-addressed release bundle. Then host-target `compile` only performs deterministic envelope assembly and never discovers an arbitrary warm-checkout artifact.

- Make the embedded graph a compact content-addressed table: sorted `SourceId → semantic digest, carrier digest/entry, typed edges, virtual label` records. Full `ModuleArtifact` semantics already live in carrier manifests and need not be duplicated unnecessarily.

- Give the environment profile its own version and digest rather than coupling every configuration-surface change to the outer envelope version.

- Publish compile output transactionally: define collision and symlink behavior, stage the executable and build statement together, fsync as appropriate, and ensure failure never leaves a seemingly valid binary paired with stale provenance.

- Have `inspect-executable` report three independent states: envelope consistency, executable/platform-signature validity, and authenticated external attestation. Avoid presenting an internally self-consistent policy as publisher-authenticated.

- Consider `/app` for immutable embedded resources and an optional `/work` mount for an explicitly authorized launch directory, rather than pretending a distributed program retains a build-time `/project`.

- Record explicit size and cold-start budgets before phase 7, including factory-table versus HBC, copy versus mmap, startup with large graphs, and signature-envelope scanning costs.

5. **Open questions**

- What exact schema replaces the path-bearing prepared index, and how are virtual labels, CommonJS filename/dirname, source maps, builtins, and computed candidate sets represented?

- What is the v1 stub compatibility identity, and which loader, transform, Hermes, policy, registry, and runtime ABI facts does it cover?

- How is the exact host stub acquired and authenticated by an installed `ibex compile` without relying on gitignored checkout artifacts?

- Is HBC mandatory for release output, and what exact compiler-to-stub compatibility proof is required? If factory tables ship, what security and performance posture do they advertise?

- Must v1 wait for LLP 0028 candidate maps and legacy-shape closure, or does compilation reject those programs with a documented support subset?

- What single immutable graph representation drives both policy validation and carrier production?

- How are root/entry authority, `/project` or replacement mounts, launch cwd, stdio, and child-process inheritance represented in the canonical policy and armed snapshot?

- What is the precise pre-main environment threat boundary, and how are application environment, runtime configuration, native dependencies, and spawned children isolated?

- What exact signed Mach-O layout is accepted, how is the original linker signature handled, and what authenticated object survives later publisher signing?

- What are the compiled program’s lifecycle and signal semantics, and which LLP 0025 obligations must land before advertisement?

- What is the cross-platform argv encoding contract, especially for arbitrary POSIX bytes?

- Are the two target names referring to module-runner advertisement, CapSec target advertisement, or a new compiled-stub advertisement? These should be separate, explicit predicates.

6. **Readiness verdict**

VERDICT: NOT READY — The proposal has a strong architecture, but unresolved material graph-format, stub-binding, producer, authority, environment, signing, lifecycle, and argv-contract gaps remain.
### Orchestrator verification notes (round 2, outside verbatim body)

Spot-checked: prepared-module-graph schema requires `record.path` and permits only file `SourceId`s while Rust supports builtin/synthetic variants — consistent with `runner_pipeline.rs` publication placing builtins in the root carrier (round-1/2 checks); `ibex policy check` spawns the external JS generator (`runtime.rs:5396+`) with its own Rolldown traversal — the two-graph TOCTOU finding is structurally confirmed; argv plumbing is `String`-typed (`cli.rs:162-168`) so the non-UTF-8 finding is correct; `LC_CODE_SIGNATURE`-at-EOF observation taken on the review's own evidence (consistent with linker-signed macOS binaries). No material defect found in the review's factual basis.

## Round 3 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f7a-2827-7680-9aed-f1743b651077`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed LLP 0029 at git-blob `0a15ed9ba18118830510aa26ee0c4ead44d3270f`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

The proposal is strategically sound. A dedicated compiled stub, explicit executable envelope, path-independent embedded graph, committed capability policy, and detached provenance are the right architecture for a distributable Ibex executable. Separating `ibex compile` from the legacy `build` pipeline is especially well judged.

The repository supports many of the RFC’s factual premises: `build` is still the Rolldown/`hermesc` path; prepared publication is factory-table-only; HBC metadata currently binds a loaded-file engine digest; macOS Hermes is dynamically linked; and CapSec advertises no verified exact targets. The RFC also does an unusually good job of naming prerequisite work instead of pretending it already exists.

It is not ready, however. Several load-bearing contracts are circular, mapped to the wrong existing mechanism, or inconsistent with governing LLPs. Most seriously, the stub identity cannot be constructed as written; the proposed root ceiling does not identify the evaluator stratum that actually constrains `AmbientRoot`; the environment broker preserves controls it claims to neutralize; LLP 0028 requires invocation-time failures that this RFC moves to compile time; and the macOS notarization state machine assumes an operation Apple does not support for standalone binaries. These are repairable design problems, not reasons to reject the feature.

2. **Strengths**

- The new command boundary is correct and factually grounded. [LLP 0029 §1](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:124) accurately distinguishes the proposal from the existing positional `build` grammar in [cli.rs](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:229) and its legacy dispatch in [main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1384). Updating the Clap tree and `runtime-surface.json` together is consistent with LLP 0010.

- The RFC correctly stops pretending that the on-disk prepared graph is suitable for embedding. [LLP 0029 §2b](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:252) accounts for builtins, virtual source labels, disk-free admission, and path independence; the current schema really does contain path-bearing, file-only records in [prepared-module-graph-v1.schema.json](/Users/ccheever/projects/ibex/schemas/prepared-module-graph-v1.schema.json:69).

- The single-snapshot rule in [§1](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:150) is an excellent organizing invariant. It directly addresses the current independent Rolldown traversal in [generate-policy.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:299) and gives policy, carriers, and the entry designation one common authority boundary.

- The identity and threat-model separation in [§3](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:332) is directionally strong. It distinguishes compatibility, corruption detection, reproducibility, and publisher authenticity, and correctly leaves product/version lineage in `runtime-identity.json` as governed by LLP 0012.

- The RFC accurately identifies current implementation gaps. Production publication emits only factory-table carriers in [runner_pipeline.rs](/Users/ccheever/projects/ibex/src/module_loader/runner_pipeline.rs:497); macOS links the checkout Hermes framework dynamically while the static switch is Linux-only in [build.rs](/Users/ccheever/projects/ibex/build.rs:1223); and the verified CapSec target list is empty in [target-advertisements.json](/Users/ccheever/projects/ibex/capsec/generated/target-advertisements.json:1).

- The phased acceptance plan in [§7](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:543) is appropriately evidence-driven: relocation, wrong-engine rejection, parser fuzzing, clean-builder reproduction, target advertisement, and measured size/startup are meaningful release gates.

3. **Concerns**

- **Circular stub identity — Material.**

  **Evidence:** The contract digest is compiled into the stub, while that contract contains the stub-core digest ([LLP 0029 §2a](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:224)). The stub-core digest is itself defined over the signature-stripped stub and is also compiled into the stub ([§3](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:351)). This creates `stub bytes → stub digest → contract bytes → contract digest → stub bytes`. The RFC recognizes the analogous engine cycle but recreates it for the stub.

  **Resolution criterion:** Define an acyclic identity construction. Either split a compile-time compatibility identifier from a post-build instance descriptor, or specify an exact masked/zeroed hash projection with fixed slot offsets and signing normalization. Cross-language golden vectors must prove construction and boot verification on both target formats.

- **The root ceiling is not connected to the evaluator mechanism that constrains `AmbientRoot` — Material.**

  **Evidence:** The RFC says an entry declaration becomes a generated “ceiling row” that `AmbientRoot` cannot exceed ([LLP 0029 §4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:402)). In the actual evaluator, `AmbientRoot` is constrained by the distinct process ceiling at decision stratum 5 ([decision.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:658), [AmbientRoot](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:936)). A principal row’s `escalationCeiling` only bounds dynamic grants ([decision.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:1248)); the armed schema calls the relevant field `processAuthorityCeiling` ([armed-snapshot.schema.json](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:105)). Additionally, runtime-internal frames are transparent under LLP 0021, so folding bootstrap-only effects into the application root floor/ceiling risks granting those effects to ordinary root code.

  **Resolution criterion:** Specify whether the generated artifact populates `processAuthorityCeiling` or introduces a new earlier root-specific stratum, including exact containment semantics. Define the entry-manifest schema and binding to the captured entry. Give bootstrap authority a distinct stage or principal that becomes unavailable before application evaluation, with fixtures proving both successful bootstrap and denial of the same effect to application root code.

- **The environment sequence preserves controls it claims to close — Material.**

  **Evidence:** The RFC captures the full launch environment, scrubs only the real process environment, and then serves `process.env` from the unsanitized captured snapshot ([LLP 0029 §4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:446)). Runtime JavaScript itself reads security-sensitive controls from `process.env`: `EXACT_ALLOW_INSECURE_CRYPTO` enables an insecure randomness fallback in [Crypto.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/crypto/Crypto.ts:1815), and `NODE_TLS_REJECT_UNAUTHORIZED=0` disables TLS verification in [fetch.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/fetch/fetch.ts:494). Current production startup rejects closed controls before boot in [host/mod.rs](/Users/ccheever/projects/ibex/src/host/mod.rs:38). Post-boot proxy writes are presently ungated in [process.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/node/process.ts:1330).

  The proposed source inventory also cannot prove closure over libcurl, the resolver, libc, OpenSSL, or other linked dependencies. Environment enumeration and child inheritance are separate unresolved authority surfaces: armed enumeration currently returns no wildcard snapshot, while child spawning flattens `process.env`.

  **Resolution criterion:** Separate application environment data from runtime configuration. Runtime code must not interpret the application snapshot or overlay as configuration; profiled control names must be inert even when app-written. After capture, clear the real environment and restore only a minimal contract-pinned allowlist, or provide an equally strong dependency-level audit. Specify exact-name read, enumeration, write/delete, and child-environment authorization, including POSIX invalid bytes, duplicates, Windows case folding, and the precise pre-`main`/static-constructor boundary.

- **Unsupported-module error timing contradicts LLP 0028 — Material.**

  **Evidence:** LLP 0029 makes computed dynamic imports, computed `require`, and unsupported import options compile-time failures ([LLP 0029 §1 step 4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:188)). LLP 0028 explicitly requires all such errors to occur at invocation and says dead sites must not fail graph construction ([LLP 0028 §2](/Users/ccheever/projects/ibex/llp/0028-oxc-only-transform-and-swc-retirement.rfc.md:176)). LLP 0028 also permanently disposes computed `require` as an invocation-time refusal, so LLP 0029’s claim that the subset will “widen automatically” is false for that shape.

  **Resolution criterion:** Either preserve LLP 0028 timing inside compiled binaries—including dead-branch behavior—or explicitly revise LLP 0028 and narrow LLP 0029’s “identical to `ibex run`” goal. Cross-mode fixtures must compare evaluation order, side effects, promise rejection/throw timing, and dead branches.

- **The macOS notarization state machine assumes unsupported standalone-binary stapling — Material.**

  **Evidence:** The RFC says notarization stapling mutates the executable after signing ([LLP 0029 §2c](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:322). Apple’s current documentation states that tickets are created for standalone binaries but cannot be stapled to them; stapling requires an app, bundle, disk image, or installer package. [Apple’s notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

  **Resolution criterion:** Choose and specify one supported distribution state: a raw signed binary relying on the online ticket, or a staplable ZIP payload/container such as a package or disk image. Rewrite publisher-statement digests around that state. Before acceptance, record byte-level ad-hoc and Developer ID signing vectors on the minimum macOS, including footer padding, `LC_CODE_SIGNATURE` coverage, signature replacement, and notarization verification.

- **Disk-free protected-artifact identity and self-file acquisition are unspecified — Material.**

  **Evidence:** Current arming requires protected artifacts to carry a host path, filesystem object identity, and content digest ([arming.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:41)). LLP 0029 instead proposes embedded policy, graph, and registry sections without defining a replacement protected-artifact type ([LLP 0029 §4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:389)). Reopening `current_exe` by pathname can race replacement and cause signed mapped code to admit an envelope from a different file. The existing engine identity code already defends against this class by comparing the opened object with the mapped image ([engine/mod.rs](/Users/ccheever/projects/ibex/src/engine/mod.rs:47), [macOS mapping check](/Users/ccheever/projects/ibex/src/engine/mod.rs:204)).

  **Resolution criterion:** Add an embedded protected-artifact identity such as `(mapped executable object, authenticated byte range, section role, digest)`. Acquire one pinned fd/handle, prove it is the object supplying a mapped stub symbol, and perform footer parsing, hashing, and section admission from that same handle on both targets.

- **The common graph identity and reproducibility projection are not wire-grade yet — Material.**

  **Evidence:** LLP 0029 relies on one graph digest joining policy, carriers, and envelope ([§1](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:152), but current code has several incompatible identities. The Rolldown digest includes absolute source paths ([rolldown-bundle.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:370)); runtime wraps it as a deployment digest ([runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1492)); the module-generation digest has a different projection ([generation.rs](/Users/ccheever/projects/ibex/src/module_loader/generation.rs:148)); and the canonical policy schema has no graph or entry identity ([canonical-policy.schema.json](/Users/ccheever/projects/ibex/capsec/schema/canonical-policy.schema.json:6)). Current `hermesc` invocation also receives an absolute staged input path ([hermes.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:2919)).

  **Resolution criterion:** Define a named digest domain, canonical schema, set ordering, and exact projection for nodes, package identities, source integrity, typed edges, candidates, and entry. State its relationship to existing cache/package graph digests. Reproduce carrier manifests under that new identity and pin a deterministic `hermesc` recipe using logical filenames, controlled working directory, flags, and environment. Require cross-language golden vectors and clean-root HBC byte comparison.

- **The compiled HBC engine binding needs a typed wire revision and verified producer path — Material.**

  **Evidence:** Carrier v1 specifically encodes `engineBinaryDigest` plus `bytecodeVersion` ([module-carrier-v1.schema.json](/Users/ccheever/projects/ibex/schemas/module-carrier-v1.schema.json:37)), whereas LLP 0029 introduces a different static compatibility-identity domain. `bind_hermes_bytecode` accepts caller-supplied metadata without inspecting the bytecode ([carrier.rs](/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:147)). The real-Hermes test compiles actual HBC but labels it with a dummy engine digest and version `1`, then admits the same assertions ([module_runner.rs](/Users/ccheever/projects/ibex/src/engine/module_runner.rs:2336)).

  **Resolution criterion:** Version or tag the carrier engine binding so loaded-file and static-compatibility identities cannot be confused. Production publication must accept a verified `hermesc`/stub-contract capability, inspect the emitted HBC version, derive metadata rather than receive arbitrary values, and test real compiler/stub mismatches end to end.

- **The `/app` and `/work` namespace is an undeclared amendment of LLP 0023 — Material.**

  **Evidence:** LLP 0023 says `/project` is the sole initial mount for every armed execution mode and that any additional mount requires an update specifying isolation, lifecycle, and policy ([LLP 0023 §1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:240)). LLP 0029 replaces it with `/app` and optional `/work` ([LLP 0029 §4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:417)) but does not explicitly revise LLP 0023. It also leaves important semantics unclear: whether `/app` is a readable filesystem mount or only a display namespace, what bytes a source read returns when only HBC is embedded, and what `cwd` is when `/work` is absent.

  **Resolution criterion:** Revise LLP 0023 in the same change. Define the logical-root vocabulary, backing identity, initial cwd, relative-path behavior, `chdir`, path observables, source reads, symlinks, and `/work` authentication. If `/app` is metadata-only, say so and refuse filesystem operations against it distinctly.

- **Content addressing is not a catalog trust root — Material.**

  **Evidence:** The packager always consumes prebuilt stub, contract, and compatible `hermesc` catalog artifacts ([LLP 0029 §2a](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:224), [§5](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:483)), but the RFC specifies no authenticated catalog index, pinned signing key, rollback rule, or trusted mapping from target to expected digest. An attacker-selected stub and matching contract remain internally content-consistent and may subsequently be publisher-signed.

  **Resolution criterion:** Define an authenticated, rollback-resistant catalog manifest pinned by the packager release or another explicit trust root. Verify fetch/update against it and bind the catalog entry and verification evidence into provenance.

- **Two-file transactional publication is overstated — Minor.**

  **Evidence:** The RFC promises that a staged executable and detached build statement are atomically renamed so stale provenance cannot remain ([LLP 0029 §1 step 5](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:196)). Two independent sibling-file renames are not one atomic filesystem transaction.

  **Resolution criterion:** Use an atomic directory/version-pointer protocol, embed the immutable build statement and keep only authentication detached, or weaken the guarantee to independently atomic files whose mutual digests make every torn pair detectably invalid.

4. **Suggestions**

- Represent each LLP 0027 carrier as separate typed manifest and payload sections with a required bijection. Bulk-preflight every graph-record/manifest-entry relationship and every engine binding before evaluating the first carrier; the current loader checks exact entry equality incrementally in [module_runner.rs](/Users/ccheever/projects/ibex/src/engine/module_runner.rs:442).

- Introduce a canonical `CompilePlanV1` as the single immutable producer input: graph root, policy digest, stub contract, compiler identity, carrier encoding, target, and environment-profile digest. Make final assembly a pure function of that plan.

- Keep one policy option. If both a global and subcommand-local spelling are retained, `ibex --policy A compile … --policy B` should be an explicit conflict, never precedence-dependent.

- Choose the carrier default before exposing the command. HBC is the natural release default; factory-table could remain diagnostic-only until its runtime-parser exposure and performance are measured.

- Clarify the product claim as “one runtime artifact plus optional detached attestation metadata.” Embedding the immutable build statement while signing or transparency-logging a detached publisher statement would make that distinction cleaner.

- Consider TUF-style catalog metadata and Sigstore/in-toto-style publisher attestations. This would give the catalog, build plan, and final executable one coherent supply-chain story without asking the executable’s internal digests to prove authenticity.

- Add explicit size, startup, and dependency budgets rather than only recording measurements. A report without a pass/fail threshold cannot decide whether the motivating advantage over Deno/Bun was achieved.

5. **Open questions**

- What exact acyclic digest projection identifies a stub, and how is it reconstructed after platform signing changes Mach-O bytes?

- Which canonical-policy field authors the root process ceiling, and how is bootstrap-only authority kept unavailable to application root code?

- Is the launch environment application data, runtime configuration, or both? What are the exact read, enumeration, mutation, child-inheritance, dependency, and pre-entry rules?

- Must compiled binaries preserve LLP 0028’s invocation-time failure semantics, or is compiled mode intentionally a stricter language/runtime subset?

- Is `/app` a filesystem, a metadata namespace, or both? What is the initial cwd without `/work`, and what source bytes, if any, are readable?

- Is the macOS distributable a raw executable with online notarization, or a staplable container around that executable?

- What authenticates and rolls back the stub/compiler catalog, and how is that catalog identity represented in provenance?

- What is the default release carrier, and is factory-table a supported deployment format or only a diagnostic escape hatch?

- Are stdio and tty implicit host facilities or policy-authorized capabilities? The answer must compose with LLP 0022/0025 before the stub process contract can be considered closed.

- What failure/crash-consistency guarantee is required for the executable, build statement, publisher statement, and any later signing transformation?

6. **Readiness verdict**

VERDICT: NOT READY — The proposal has a strong architecture, but circular identity, broken environment closure, governing-LLP conflicts, and unresolved policy, self-file, HBC, catalog, and macOS distribution contracts leave material correctness and security concerns.
### Orchestrator verification notes (round 3, outside verbatim body)

Spot-checked: `EXACT_ALLOW_INSECURE_CRYPTO` read from `process.env` in `Crypto.ts:1818` and `NODE_TLS_REJECT_UNAUTHORIZED` in `fetch.ts:497,1441` — the "environment broker preserves controls it claims to neutralize" finding is confirmed; `processAuthorityCeiling` exists in the armed-snapshot schema with a distinct `ProcessCeiling` decision stratum (`decision.rs:372,676-679`) — the root-ceiling mechanism correction is confirmed; the stub-identity circularity is real in the reviewed revision's §2a/§3 text. The Apple notarization-stapling claim (standalone binaries cannot be stapled) is consistent with Apple's documented workflow and accepted. No material defect found in the review's factual basis.

## Round 4 — 2026-07-17

**Reviewer family:** GPT (OpenAI Codex)
**Provider / runtime:** OpenAI Codex CLI v0.144.5, model `gpt-5.6-sol`, reasoning effort `ultra`, sandbox `read-only`, session `019f6f8e-c089-7731-839c-43c0a0e8bb50`
**Date:** 2026-07-17
**Redacted:** no
**Method:** cli-runner — `codex exec` non-interactive, orchestrated by `/llp-super-refine`; reviewed at git-blob `e838e3afd0effc30f2005226d8ab29540dfdd4e2`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round). Round-4 brief added the calibration that registered author decisions do not by themselves make a document unready.
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

This is a good product idea and, at the architectural level, the right way to approach it. Ibex already has most of the difficult ingredients: authenticated module artifacts, per-principal carriers, typed policy, prepared graphs, Hermes bytecode, and runtime identity. LLP 0029 correctly recognizes that a distributable executable requires new composition contracts rather than simply concatenating an existing binary and HBC file.

The proposal is unusually strong about identity separation, provenance, invocation-time compatibility, fail-closed admission, reproducibility, and the limits of self-integrity. Its account of the current repository is generally accurate: `ibex build` is the legacy Rolldown-to-`hermesc` path; production carrier publication is factory-table-only; current HBC metadata is caller-asserted; macOS Hermes is dynamically linked; Linux alone supports `HERMES_LINK_STATIC`; and CapSec currently advertises no verified target.

It is not ready, however. Several load-bearing contracts remain undefined or contradict the mechanisms they propose to reuse. Most seriously: the macOS trailer is contrary to Apple’s supported Mach-O layout; `processAuthorityCeiling` is process-wide rather than root-only; the committed compiled-policy form and graph projection are unspecified; bootstrap authority has no defined lifecycle; the environment design conflicts with exact-name CapSec; and the catalog and detached-attestation trust models are descriptions rather than protocols. These are design questions that need resolution before the phase plan can safely drive implementation.

2. **Strengths**

- The separate `ibex compile` command is well justified and grounded in the actual CLI. Today’s `build` has a required positional file and `--outdir`, dispatches through the legacy bundle/bytecode path, and does not produce LLP 0027 carriers ([LLP 0029 §1](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:127), [cli.rs](/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:229), [main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:1384)). Requiring synchronized Clap and `runtime-surface.json` changes follows LLP 0010 correctly.

- Preserving LLP 0028’s invocation-time failure behavior is the right compatibility decision. The diagnostic plus opt-in `--deny-unsupported` design avoids changing dead-branch behavior merely because a program is packaged ([LLP 0029 §1 step 4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:200)).

- The split between `StubContractV1`, the post-build instance descriptor, producer identity, envelope identity, and signed-file identity is thoughtful and acyclic ([LLP 0029 §§2a, 3](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:237)). It correctly avoids reusing today’s loaded-file Hermes identity for statically linked compiled mode.

- The proposal accurately identifies the current HBC weakness. `bind_hermes_bytecode` accepts caller-supplied engine and bytecode-version fields without inspecting the payload ([carrier.rs](/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:147)), while the real-Hermes test supplies dummy identity metadata ([module_runner.rs](/Users/ccheever/projects/ibex/src/engine/module_runner.rs:2336)). Requiring payload-derived metadata and a versioned compatibility identity is necessary.

- The threat-model language is honest. Internal digests are correctly framed as corruption and mix-and-match defenses, not authenticity against an attacker who can rewrite the entire artifact ([LLP 0029 §3](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:409)).

- The proposal does not conceal its platform and conformance dependencies. Static macOS Hermes, Linux libcurl disposition, host-only compiler selection, and the zero-advertised-target CapSec matrix are all real prerequisites ([LLP 0029 §§2a, 4, 5](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:278), [build.rs](/Users/ccheever/projects/ibex/build.rs:1223), [target-matrix.md](/Users/ccheever/projects/ibex/capsec/generated/target-matrix.md:5)).

- The phase plan includes meaningful refusal, mutation, fuzzing, relocation, and two-builder gates rather than treating successful execution as sufficient evidence ([LLP 0029 §7](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:560)).

3. **Concerns**

1. **Material — The normative macOS trailer is not a supported signed Mach-O design.**

   **Evidence:** LLP 0029 specifies stripping the linker signature, appending an envelope and footer, and then invoking `codesign` ([§§2b–2c](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:335)). Apple’s code-signing guidance says appending data to a Mach-O executable is prohibited and recommends placing embedded data in a proper section instead. Merely signing after the append does not make otherwise out-of-layout bytes a valid Mach-O segment. [Apple TN2206](https://developer.apple.com/library/archive/technotes/tn2206/)

   **Resolution criterion:** Make a dedicated Mach-O segment/section the normative macOS v1 layout, retaining the trailer for ELF; alternatively, fully specify a deterministic load-command/`__LINKEDIT` rewrite and demonstrate a Developer-ID-signed, hardened-runtime, notarized, Gatekeeper-accepted executable on the minimum supported macOS before accepting trailer embedding.

2. **Material — `processAuthorityCeiling` is not a root ceiling.**

   **Evidence:** LLP 0029 calls it the “root ceiling” and derives it from an entry declaration ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:428)). The evaluator applies the process ceiling to every effect for every constrained principal before package floors or AmbientRoot ([decision.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:658)); AmbientRoot is applied later only to otherwise-unauthorized root effects ([decision.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:936)). A root-only declaration can therefore deny package floors. Conversely, unioning package-global needs into the process envelope can make those authorities available to AmbientRoot.

   **Resolution criterion:** Explicitly choose one of two semantics: define the entry declaration as the total process envelope, prove every package floor and implicit effect is contained, and acknowledge its effect on root authority; or introduce a distinct root-specific ceiling while retaining `processAuthorityCeiling` as a true whole-process bound. Specify omission defaults and provenance, and add root/package containment and over-ceiling fixtures.

3. **Material — The compiled authority source is not yet one committed, auditable artifact.**

   **Evidence:** Compile is said to consume the committed canonical policy and never generate it ([§1 step 2](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:179)), but the process ceiling comes from a separate entry manifest flowing through the generator ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:433)), and compiled-target generation is expected to rewrite the resource vocabulary to `/app` and `/work` ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:465)). The current generator has only entry/out/mode/check inputs, defaults to one project-level `ibex-policy.json`, and emits current package-principal rows ([generate-policy.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:45), [generate-policy.mjs](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:523)). The strict canonical schema has no entry, graph, target profile, mount profile, or process-ceiling fields ([policy.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/policy.rs:27), [canonical-policy.schema.json](/Users/ccheever/projects/ibex/capsec/schema/canonical-policy.schema.json:6)).

   The claim that authority is “exactly the embedded policy” is also too narrow: LLP 0021 makes the armed snapshot—not the review policy—the evaluator input, and that snapshot adds the graph, root bindings, process ceiling, protected guards, implicit package-self authority, and execution identity ([LLP 0021 §Policy forms and digests](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:203)).

   **Resolution criterion:** Define canonical policy v2 so the normalized ceiling, bound entry, graph identity, target/mount profile, and provenance are covered by `policyDigest`. Specify deterministic authoring and drift-check CLI behavior, artifact naming keyed by entry and target/profile, and forbid compile from rereading a mutable authority manifest. `inspect-executable` should reconstruct and report the complete effective armed authority bundle, not only dump the review policy.

4. **Material — The authenticated graph to armed `packageGraph` relationship is undefined.**

   **Evidence:** The new snapshot lists six inventories but says only that its digest and the armed `packageGraph` digest are “cross-checked” ([§1 step 1](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:158)); the concrete projection remains an open question ([Open questions](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:642)). The armed graph is authority-bearing: nodes include principals, root objects, aliases, and platform disposition; edges include request spelling, resolution kind, conditions, and attributes ([arming.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:590)). Arming requires exact equality between policy rows and graph nodes, and between import allowlists and graph edges ([arming.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:688)).

   **Resolution criterion:** Define a total normative projection from `AuthenticatedGraphSnapshotV1` to the compiled armed package graph, covering every module-to-principal assignment, exact package set, root/package/builtin and candidate edges, conditions, attributes, entry identity, aliases, embedded object identities, and platform disposition. Prefer embedding one graph source and deriving the domain-separated `packageGraph` during arming, with mutation vectors for every projected field.

5. **Material — Bootstrap authority is a label, not yet a security mechanism.**

   **Evidence:** LLP 0029 introduces a bootstrap principal/stage that becomes unavailable before application evaluation ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:437)). Existing `Stage` values describe effect progression, not a sealed runtime lifecycle ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:377)); canonical review policy accepts only package principal rows ([policy.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/policy.rs:121)). LLP 0027 currently groups builtins into the root carrier and attributes their initialization to root ([runner_pipeline.rs](/Users/ccheever/projects/ibex/src/module_loader/runner_pipeline.rs:456), [LLP 0027](/Users/ccheever/projects/ibex/llp/0027-module-artifact-and-interop.spec.md:223)). A shared root HBC carrier cannot distinguish bootstrap and application-root frames by Hermes `RuntimeModule` alone.

   **Resolution criterion:** Specify the exact bootstrap identity, authority source, process-ceiling interaction, sealing transition, serialization and digest coverage, and behavior of retained callbacks/functions after sealing. Either create a dedicated runtime/bootstrap carrier and revise LLP 0027, or define an unforgeable evaluator phase token orthogonal to frame principal. Test successful initialization, denial to application root, and denial through retained bootstrap-created functions after closure.

6. **Material — The pre-library environment capture guarantee has no feasible entry mechanism.**

   **Evidence:** LLP 0029 promises capture “at the stub’s first instruction, before any library or runtime initialization” ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:483)). An ordinary Rust `main` runs after loader and language/runtime startup; the current binary uses `#[tokio::main]` ([main.rs](/Users/ccheever/projects/ibex/src/bin/ibex/main.rs:296)). Static constructors and system-library initialization may also precede application entry. The threat model excludes loader variables but does not reconcile this broader pre-main window.

   **Resolution criterion:** Specify and prototype a platform entry/pre-init shim that captures and sanitizes before every linked constructor under Ibex’s control, with constructor probes on both target tuples. If that cannot be guaranteed, narrow the contract to the earliest executable-controlled hook and explicitly classify all earlier readers as outside the in-process boundary.

7. **Material — The environment broker conflicts with exact-name CapSec and has an incomplete security-control taxonomy.**

   **Evidence:** The proposal promises full snapshot enumeration, mutable overlays, and exact child inheritance ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:498)). Current armed enumeration deliberately returns empty because wildcard disclosure cannot be represented ([hermes_runtime.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2007)); the current broker authorizes only exact `broker-base` reads ([host/mod.rs](/Users/ccheever/projects/ibex/src/host/mod.rs:749)). `EnvironmentName` admits only uppercase ASCII-style names, so it cannot represent lowercase or non-UTF-8 POSIX names ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:847)). The JS proxy has one runtime-global override/tombstone map rather than principal-keyed overlays ([process.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/node/process.ts:1228)).

   The sentence that runtime code never interprets application environment as configuration is also too broad for Node compatibility, while its security-sensitive inventory is incomplete. Crypto treats both `NODE_ENV=test` and `EXACT_ALLOW_INSECURE_CRYPTO=true` as enabling an insecure fallback ([Crypto.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/crypto/Crypto.ts:1815)); fetch interprets `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, and a separate `__exactHostEnv` channel ([fetch.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/fetch/fetch.ts:407), [fetch.ts](/Users/ccheever/projects/ibex/packages/ibex-runtime-js/src/fetch/fetch.ts:435)). Other builtins intentionally use app environment for debug and terminal behavior.

   **Resolution criterion:** Define a byte-preserving or explicitly rejecting name/value algebra; implement principal-keyed typed read/write/delete, per-name-filtered enumeration and descriptors, and conjunctively authorized child projection. Generate a complete consumer-to-disposition inventory distinguishing privileged bootstrap/security controls from intentional application behavior. Test direct reads, spreads, descriptors, deletes, cross-principal isolation, child inheritance, and inertness through both `process.env` and `__exactHostEnv`.

8. **Material — Transform identity and HBC admission are not yet closed over `StubContractV1`.**

   **Evidence:** `TransformFingerprintV1.hermes_target` is a free-form semantic field ([artifact.rs](/Users/ccheever/projects/ibex/src/module_loader/artifact.rs:69)). Graph production accepts a caller string, and the current CLI supplies `bytecode_cache_identity()` ([runner_pipeline.rs](/Users/ccheever/projects/ibex/src/module_loader/runner_pipeline.rs:264), [runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1537)). That identity incorporates compiler path and filesystem metadata, including device and inode ([hermes.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:768), [hermes.rs](/Users/ccheever/projects/ibex/src/bin/ibex/engine/hermes.rs:2571)), defeating clean-checkout semantic reproducibility. Rebinding an HBC manifest leaves its entry semantics unchanged ([carrier.rs](/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:147)).

   Current manifest admission can also label arbitrary bytes as HBC; actual sanity checking occurs only when the carrier is lazily evaluated ([carrier.rs](/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:445), [hermes_module_runner.cc](/Users/ccheever/projects/ibex/src/engine/hermes_module_runner.cc:1173)).

   **Resolution criterion:** Derive a canonical path-independent transform and engine target exclusively from `StubContractV1`, and cross-check every entry fingerprint against it. During bulk boot preflight, parse and sanity-check every HBC payload and compare its observed version with both manifest and stub contract before any carrier evaluates. Compare complete semantic manifests and unsigned executables across two checkout paths, not only HBC bytes.

9. **Material — Per-module diagnostics and source maps do not survive grouped HBC carriers as specified.**

   **Evidence:** The carrier builder concatenates factories into one table without factory offsets or a composed carrier map ([carrier.rs](/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:94)). Native loading caches the table by carrier and evaluates it under the first entry’s source label; later entries cannot acquire distinct Hermes labels ([hermes_module_runner.cc](/Users/ccheever/projects/ibex/src/engine/hermes_module_runner.cc:1166), [hermes_module_runner.cc](/Users/ccheever/projects/ibex/src/engine/hermes_module_runner.cc:1213)). LLP 0029 promises per-module `/app` labels and source-map spellings ([§2b](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:319)), while LLP 0026 requires every transform stage to compose maps ([LLP 0026 §10](/Users/ccheever/projects/ibex/llp/0026-esm-module-runner.rfc.md:1035)).

   **Resolution criterion:** Add a digest-bound path-neutral carrier/HBC map that composes HBC positions through table-wrapper positions to each artifact map and `/app` label, or use one HBC carrier per module in v1. Gate thrown-error and stack traces across multiple entries, principals, TypeScript sources, and relocated builds.

10. **Material — The catalog and detached-attestation trust models are not implementable protocols yet.**

   **Evidence:** A monotonic catalog version does not prevent replay without either an exact release pin or durable trusted state. LLP 0029 does not choose between those models or define keys, rotation, expiry, freeze behavior, atomic state, or recovery ([§2a](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:267)). Current Hermes download tooling fetches an artifact and checksum from the same origin, which is integrity checking rather than an independent trust root ([download-hermes.sh](/Users/ccheever/projects/ibex/scripts/download-hermes.sh:83)).

   Similarly, `inspect-executable` promises an “externally authenticated” adjacent attestation, but “Sigstore/in-toto-style” does not define a signed envelope, publisher identity policy, trust root, transparency evidence, replay policy, or offline semantics ([§§1, 2c, 3](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:228)). This is load-bearing on Linux, where there is no general platform-enforced ELF signature.

   **Resolution criterion:** For v1, either pin one exact immutable catalog-manifest digest per Ibex release or specify a real TUF-like update state machine. Separately choose a versioned DSSE/in-toto or equivalent publisher envelope and verification policy. Inspection must distinguish statement presence, digest consistency, cryptographic validity, and trusted publisher identity, with replay, freeze, substitution, key-rotation, and offline fixtures.

11. **Material — `/app` assets and acceptance-blocking process semantics are unfinished.**

   **Evidence:** `/app` is described as a filesystem mount for embedded resource sections ([§4](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:450)), but the envelope layout contains no asset inventory, and the producer surface has no asset discovery or inclusion contract. It is therefore undefined what `fs.readFile(new URL("./asset", import.meta.url))` packages, how it is digested, or how policy grants join it. The RFC also explicitly leaves stdio/cwd semantics and the initial environment allowlist undecided and says they block `Accepted` ([§§6–7](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:548)).

   **Resolution criterion:** Either remove filesystem-visible embedded assets from v1 and make `/app` a module/diagnostic namespace only, or specify explicit asset authoring/discovery, canonical labels, digest coverage, size limits, policy joins, and relocation behavior. Resolve the stdio, cwd, `/work`, and initial allowlist decisions normatively before acceptance.

12. **Minor — The runtime-identity digest is undefined.**

   **Evidence:** `StubContractV1` includes a runtime-identity digest ([§2a](/Users/ccheever/projects/ibex/llp/0029-single-file-executable-packaging.rfc.md:248)), but `runtime-identity.json` contains comments and LLP metadata, while generated bindings emit semantic values without a digest ([runtime-identity.json](/Users/ccheever/projects/ibex/runtime-identity.json:1), [generate-runtime-identity.ts](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-runtime-identity.ts:23)).

   **Resolution criterion:** Define a named strict-JCS semantic projection and digest domain, generate its constant into Rust and TypeScript, and decide whether compiled artifacts forbid Bun compatibility or make it an explicit contract input.

13. **Minor — The macOS distribution details contain two definite errors or omissions.**

   **Evidence:** ZIP is listed with staplable containers, but Apple says ZIP archives and standalone binaries cannot be stapled directly. The publisher-signing contract also omits hardened runtime and secure timestamp requirements. [Apple notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow), [Apple notarization troubleshooting](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)

   **Resolution criterion:** Remove ZIP from the staplable-container list; describe it only as transport for already-stapled supported contents. Specify Developer ID identity, `--options=runtime`, secure timestamp, identifier and entitlement policy, and real notarization/Gatekeeper tests.

4. **Suggestions**

- Use one HBC carrier per module for v1. It costs some container overhead but makes source labels, maps, attribution, corruption isolation, and bootstrap separation substantially simpler. Grouping can follow measurement.

- Embed one authenticated graph source and derive both the embedded module index and armed package graph from it. Keeping two digest domains is useful; keeping two independently authored fact sets is not.

- Split the LLP 0027 carrier into an immutable content manifest and an envelope-specific admission binding. Packaging could then preserve content identity while rotating graph, engine, and envelope bindings without describing the operation as rewriting the carrier itself.

- Start with an internal standalone “capsule” payload format consumed by a development stub before binding it into ELF or Mach-O. The same parser corpus and golden vectors could test disk-free arming independently of platform signing.

- For v1, prefer an exact catalog-manifest digest compiled into each Ibex release. A genuinely updateable TUF workflow can be added later when there is a demonstrated need for catalog updates independent of Ibex releases.

- Make `inspect-executable` produce a canonical effective-authority report: policy, total process ceiling, bootstrap authority, graph projection, mounts, environment profile, implicit authority, and target advertisement. A diff between two executables would be particularly valuable.

5. **Open questions**

- Is the entry declaration intended to bound only root authority, or the total process including every package and implicit effect?

- What exact committed artifact contains the entry identity, graph binding, compiled mount vocabulary, process/root ceiling, and their provenance? How are multiple compiled entries and target profiles named and drift-checked?

- What is the normative projection from the authenticated module graph to the authority-bearing armed package graph?

- Will macOS use a dedicated segment/section, and what minimum-OS Developer ID/notarization evidence is required before that layout is accepted?

- What mechanism executes and then irreversibly seals bootstrap authority, including callbacks retained past initialization?

- Which environment variables are application data, privileged runtime configuration, safe real-environment allowlist entries, or prohibited? How are non-UTF-8 names and values represented?

- Will v1 use per-module HBC or define a composed carrier source map?

- Are filesystem-visible embedded assets in v1? If so, how are they selected, authenticated, and authorized?

- Is the catalog immutable per Ibex release or independently updateable? What identities make an adjacent publisher statement trusted, especially on Linux?

- What are the final stdio, cwd, `/work`, child-environment, and unset-cwd semantics?

- Does v1 wait for at least one verified CapSec advertisement, or is the first release explicitly blocked until that external program completes?

6. **Readiness verdict**

VERDICT: NOT READY. The proposal has a strong core architecture, but unresolved material issues in Mach-O packaging, authority semantics, policy/graph derivation, bootstrap and environment isolation, carrier diagnostics, and supply-chain trust prevent acceptance.
### Orchestrator verification notes (round 4, outside verbatim body)

Spot-checked: `ProcessCeiling` applies to every constrained principal (stratum 5) rather than root only — the "root ceiling" naming correction is confirmed (`decision.rs:658-682`); armed enumeration returning empty and exact-name broker reads are as cited; `#[tokio::main]` on the full binary confirms the pre-main capture-feasibility point for that binary shape. The Apple TN2206 append-prohibition and ZIP-stapling claims are accepted on the cited documentation and adopted in the round-4 revision. No material defect found in the review's factual basis.
