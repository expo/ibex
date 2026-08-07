# Reviews: LLP 0029 — Single-File Executable Packaging (Claude Fable family)

## Round 1 — 2026-07-17

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session)
**Date:** 2026-07-17
**Redacted:** no (repository content only; no secrets present)
**Method:** sub-agent — orchestrated by `/llp-super-refine`; reviewer read LLP 0029 at git-blob `683fc6ebe3008f3de8c1a512731b6d5a3681d77f`, governing LLPs, and repo code; barred from reading `llp/reviews/`
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

This is a well-motivated RFC pointed in the right direction. The core thesis — that single-file packaging for Ibex is "composition, not invention," because LLP 0027 already defines a digest-bound prepared carrier, LLP 0014 already defines the resolved policy artifact, and LLP 0026 §9 already defines bytecode production — is genuinely true, and I verified the load-bearing pieces: `ibex build` exists in the clap inventory (`runtime-surface.json`, currently with only `--outdir`), the `ibex/module-carrier/1` HBC encoding really does bind `engine_binary_digest` and `bytecode_version` (`src/module_loader/carrier.rs:27-29, 152-161, 265-277`), the policy artifact and its drift gate exist as described in LLP 0014, `runtime-identity.json` is the identity authority per LLP 0012, and the advertised-target framing (macOS arm64 + Linux x64 native, Windows compatibility-only) matches LLP 0001's revision history. The trailer-over-linker choice, the fail-loud absent-stub behavior (consistent with LLP 0005's hermetic-default invariant), and the compiled-mode env-var lockdown are all sound instincts. As a direction, this is a good idea and a plausible differentiator for the Snapback use case.

However, the document is thinner than its subject at exactly the points where the composition stops being trivial. Three of these are load-bearing. First, §3's "self-binding identity" story has an unexamined circularity: the runtime today computes the engine digest by hashing the loaded Hermes artifact file at runtime (`src/engine/mod.rs:38-100`), and in a single-file world that file is the executable itself — including the appended payload and the post-append ad-hoc signature — so "bound to the digest of the exact stub it ships inside, computed at packaging time" is not currently a well-defined quantity. Second, the RFC silently assumes a statically linked stub, but on macOS the host links `hermesvm.framework` dynamically via an rpath into the checkout (`build.rs:1223-1235`; confirmed with `otool -L` on `target/debug/ibex`), and the `HERMES_LINK_STATIC` path exists only in the non-framework branch; a static macOS Hermes is real unbuilt work the RFC doesn't name. Third, the payload description ("a prepared module carrier," singular) contradicts LLP 0026 §9's hard constraint that carriers are per-principal, and omits the `ibex/prepared-module-graph/1` index the loader needs to link anything. None of these is fatal — each has a clear fix — but together they mean the design section describes a system adjacent to, not identical with, the one the governing specs permit.

There is also a decision-quality issue in how the embedded policy is sourced, and an honesty issue in the integrity framing that LLP 0013 explicitly obligates this corpus to avoid. With those addressed, this would be a strong RFC.

2. **Strengths**

- **Reuse over invention (§Summary, §Non-goals).** "The payload is LLP 0027 carriers, verbatim" is the right constraint, and the carrier machinery it leans on is real and tested — HBC and source carriers execute to the same namespace on real Hermes (`src/engine/module_runner.rs:2312`).
- **Command-surface discipline (§1).** The RFC correctly treats LLP 0010's manifest as the authority and commits to the clap-tree/manifest/LLP triple update; the proposed `--target` values match the actually-advertised tuples (LLP 0001), and Windows is correctly excluded until the patched-Hermes question resolves.
- **Hermeticity and fail-loud (§5, §6).** "Fails loudly when a stub for the requested target is absent... rather than falling back to a network download mid-build" is exactly LLP 0005's invariant extended to a new surface, with stable error families per the repo's diagnostics discipline.
- **Compiled-mode env lockdown (§4).** The runtime has ~107 distinct `IBEX_*`/`EXACT_*` variables across `src/`, several of which are security-posture-relevant (`IBEX_ENDOW`, `IBEX_LEGACY_MODULE_LOADER`, `IBEX_POLICY`, `EXACT_HAVE_FRAME_ATTRIBUTION`). Defaulting that entire surface to off with a non-widening allowlist is the correct posture and the most valuable single sentence in the design.
- **Correct scoping of authority (§4).** The distinction between the runtime's configuration surface (closed) and the program's granted surface (policy-governed) is precise and matches LLP 0013/0014's model.
- **Alternatives are genuinely considered (§Alternatives),** with revisit conditions (trailer-vs-signature friction) rather than strawmen.

3. **Concerns**

- **Material — Payload composition contradicts LLP 0026 §9 and omits the graph index.** Evidence: LLP 0026:1004-1016 mandates per-principal executable carriers ("v1 therefore emits executable chunks and bytecode per authenticated principal (per-package)"; a multi-principal carrier is prohibited until a native attribution mechanism passes frame-attribution tests). LLP 0027 additionally defines `ibex/prepared-module-graph/1` as the index binding entry, resolved-specifier maps, and carrier inventory — without it the stub cannot link. The RFC's §2 layout lists "module carrier" (singular) and no index. Resolution: revise §2/§Summary to embed a carrier *set* (one per principal) plus the prepared-module-graph index, and state explicitly that packaging does not collapse principals into one carrier.
- **Material — §3's self-binding digest is circular/underspecified.** Evidence: `loaded_engine_binary_digest` is computed by hashing the file at `ex_hermes_engine_binary_path` at runtime (`src/engine/mod.rs:38-100`). In a statically linked single file, that path is the executable itself, whose bytes include the appended payload (which contains the carrier that carries the digest — a fixpoint that cannot exist) and the ad-hoc signature applied *after* appending (codesign rewrites `__LINKEDIT` inside the stub extent, so even "hash the stub extent recorded in the footer" fails if the digest was computed pre-signing). Resolution: specify the digest domain and order of operations — e.g., the stub embeds a link-time engine-identity constant (digest of the static Hermes archive) that `loaded_engine_binary_digest` returns in compiled mode, and carriers bind to that; or define a stub-extent hash that provably excludes signature-mutable ranges, with the packaging/signing sequence written down.
- **Material — Static Hermes on macOS is unacknowledged prerequisite work.** Evidence: `build.rs:1223-1235` links `framework=hermesvm` with an rpath; `target/debug/ibex` depends on `@rpath/hermesvm.framework` (otool); `HERMES_LINK_STATIC` exists only in the non-macOS branch (`build.rs:~1447-1458`). A "single self-contained platform executable" on the primary development target requires a static macOS Hermes build (and a decision about the lean vs full engine variant) that exists nowhere today. Resolution: add a design/plan item naming the per-target static-link work, its Hermes-build implications (LLP 0001/0005), and its effect on the stub size estimate.
- **Material — No admission/trust-anchor story for a source-less environment.** Evidence: LLP 0027's prepared-graph reload "re-authenticates each source identity and integrity, re-resolves each authored edge against the current armed snapshot" (llp/0027:129-137), and admission matches the prepared producer binary digest — all of which presume a project on disk and an arming step. A compiled binary on a stranger's machine has no sources, no committed policy file, and no `ibex` producer. Resolution: specify the compiled-mode admission chain (footer digest → graph index → carrier admission → policy ingress), what substitutes for source re-authentication and snapshot arming at boot, and how the producer-binary-digest expectation is satisfied (embedded as verified data, presumably).
- **Material — Policy sourcing can bypass LLP 0014's review discipline.** Evidence: §1's default is "policy resolved from the entry's module graph per LLP 0014 (the same generation the ordinary build performs)" — but LLP 0014's model is a *committed, drift-checked* artifact where `--check` gates expansions (llp/0014:293-301); the ordinary build *consumes* the committed artifact, it does not regenerate. Silent regeneration at compile time would embed unreviewed expansions, defeating the tripwire; and `--policy <path>` accepts an arbitrary artifact with no stated mode/purpose constraint, while production ingress accepts only `purpose: production, mode: enforce` (llp/0014:11-17). Resolution: state that `--compile` consumes the committed canonical artifact (failing on drift, like the run path's `validate_production_inputs`), and that any embedded policy must pass canonical registry-bound ingress with enforce/production posture — or explicitly justify a compiled permissive mode.
- **Material — Integrity framing overclaims against LLP 0013's honesty rule.** Evidence: §3 "tampering with either half breaks the pair" and §Motivation's "cleanest authority story." An attacker with write access to the file can modify the carrier, recompute the binding and footer digest, and repack — self-verification defends against corruption, skew, and accidental mix-and-match, not against an adversary who controls the artifact; only external signing/attestation does that. LLP 0013:220-221 requires public descriptions to state this class of boundary honestly. Resolution: add one paragraph scoping the footer/binding checks to integrity-against-accident-and-skew, and point real tamper resistance at platform code signing plus the detached provenance record.
- **Minor — LLP 0022 citation error (§4).** LLP 0022's `.env` is a REPL dot-command that is already "absent in v1" (llp/0022:69, 781-783), not a runtime env-file or loader-override surface; the sentence cites 0022 for something it doesn't say (the env-var configuration surface lives in `runtime.rs` and friends). Resolution: fix the citation; if dotenv-file behavior is meant, cite what actually implements it.
- **Minor — Unsubstantiated quantitative claims (§Motivation, §4).** "Lands around 10–20 MB," "cold starts in single-digit milliseconds," and "most of the size savings" from removing repl/eval have no in-repo measurement (debug `ibex` is 126 MB; `hermesvm.framework` is 9.4 MB; the lean macOS `hermes.framework` is 1.8 MB — plausible, but nothing is measured, and the REPL is unlikely to dominate binary size versus the compat harness, CDP, and engine). Resolution: label these as estimates and add a measured size/startup gate to acceptance criteria (the LLP 0026 performance-gate report pattern fits).
- **Minor — Determinism claim vs codesign (§5 vs §2).** `codesign -s -` output bytes depend on the host's codesign/toolchain version, so "same digests → same bytes" will not hold across build hosts on macOS unless the signer is pinned in-tree (e.g., an apple-codesign-style implementation) or the determinism claim is scoped to exclude/normalize the signature blob. Resolution: pick one and say so.
- **Minor — Relationship to today's `ibex build` and the legacy pipeline.** `build_bytecode` (`src/bin/ibex/main.rs:1385-1425`) is the legacy Rolldown-bundle → `hermesc` path with per-package chunk siblings (ENG-22760), while `--compile` consumes the LLP 0026 §9 carrier path — two divergent pipelines under one command, with the legacy window closing at 0.2 per LLP 0028. Resolution: one paragraph on whether plain `ibex build` migrates to carrier production and in what order relative to `--compile`.
- **Minor — Stub distribution analogy is factually off.** "Prebuilt and committed/downloaded like other platform Hermes artifacts" — the platform Hermes artifacts are *git-ignored*, not committed (`.gitignore:4,7`; `tools/hermes/`, `ios/Frameworks/` are local artifacts, a known worktree-setup friction). Resolution: correct the analogy; the open question on distribution already exists, so just don't presuppose a committed precedent.
- **Minor — No phasing, gates, or acceptance criteria.** Peer RFCs at this stakes level (LLP 0026, 0028) carry phased rollout with named gates. Resolution: add a minimal plan (stub build → packaging format → compiled-mode boot → env lockdown → determinism/size gates) with per-phase evidence requirements.

4. **Suggestions**

- Add an introspection contract: a reserved `--ibex-policy` (or `mytool --version --json`) that dumps the embedded policy artifact and digests from the binary itself. It makes the "auditable frozen authority" story operational — anyone can read a shipped tool's total capability surface without tooling — and it falls out of the payload for free.
- Make the detached provenance record default-on rather than an open question; it also resolves the tamper-framing concern cheaply (the provenance record is what a distributor signs).
- Add `ibex build --verify <binary>` (or fold into `--compile --check`): re-derive the payload from inputs and byte-compare — turns the determinism goal into a checkable property instead of a promise.
- Consider a hybrid embedding: trailer on Linux, Mach-O section/segment on macOS. The RFC's own §Alternatives flags trailer-vs-signature friction as the revisit trigger; specifying the fallback now (rather than "revisit") would de-risk the platform where the friction is known to exist.
- The interpreter-only lean stub question (§Open questions) has evidence in-repo already: the macOS lean `hermes.framework` is 1.8 MB vs 9.4 MB for `hermesvm.framework`. Worth citing to convert the open question into a near-decision.
- State explicitly that dynamic `import()` in compiled mode (including LLP 0028's native computed dynamic import) is bounded to the embedded graph — resolution outside the payload fails closed with a stable error. This is implied by "nothing is resolved from disk or network" but deserves normative text since it changes observable behavior versus `ibex run`.
- The stdio open question should reference LLP 0022/0025's existing typed `stdio:query` surface and terminal-ownership model so the compiled-mode answer composes with, rather than forks, that spec.

5. **Open questions**

- What exact bytes does the compiled-mode engine/stub digest cover, computed when, relative to appending and signing? (This must be answered before any code, since it defines the carrier binding.)
- How is a static Hermes produced for macOS (and which variant — full vs lean), and does the Linux `HERMES_LINK_STATIC` path produce a fully self-contained binary today (libcurl, ssl, c++ runtime)?
- What is the compiled-mode boot admission chain end-to-end — what replaces source re-authentication, snapshot arming, and the producer-binary-digest match on a machine with no project and no `ibex`?
- Must the embedded policy be the committed drift-checked artifact, and is enforce/production posture mandatory for compiled output?
- Is `ibex/module-carrier/1` + `ibex/prepared-module-graph/1` embedded as-is, or does packaging define a new footer-level manifest that references them — and is that footer format versioned independently of the carrier schema?
- The RFC's own listed questions (env allowlist freezing, stdio implicitness, stub distribution, provenance record) — of these, the env allowlist and stdio answers gate the security review and should be resolved before Accepted status.

6. **Readiness verdict**

VERDICT: NOT READY — the direction and reuse thesis are right, but the design as written contradicts LLP 0026 §9's per-principal carrier constraint, leaves the §3 digest binding circular, omits the macOS static-link prerequisite and the source-less admission model, and under-specifies policy provenance — each fixable, none yet fixed.

### Orchestrator verification notes (round 1, outside verbatim body)

Spot-checked against the working tree (2026-07-17): runtime engine digest hashes the loaded Hermes artifact file (`src/engine/mod.rs:38+`); macOS links `hermesvm` framework dynamically with rpath (`build.rs:1224-1234`), `HERMES_LINK_STATIC` only in the non-framework branch (`build.rs:1447`); LLP 0026 per-principal carrier mandate (lines 1004-1016); LLP 0027 reload re-authenticates source identity/integrity (lines 129-137); LLP 0014 committed drift-checked artifact + production `purpose: production, mode: enforce` ingress (lines 11-17, 293-301); LLP 0022 `.env` is a REPL dot-command absent in v1 (lines 69, 781-783); `tools/hermes`/`ios/Frameworks` git-ignored (`.gitignore:4,7`); `ibex build` takes positional file + `--outdir`. All decisive claims confirmed.

## Round 2 — 2026-07-17

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session and of round 1)
**Date:** 2026-07-17
**Redacted:** no
**Method:** sub-agent — orchestrated by `/llp-super-refine`; reviewed LLP 0029 at git-blob `ca7f7200395488e982b17428219660619e2c3983`; barred from reading `llp/reviews/` (round-1 artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

This is a good proposal, and an unusually well-grounded one. I verified its load-bearing repo claims directly, and nearly all of them check out exactly as stated: the prepared-graph index does serialize absolute source labels and its reload does re-authenticate every source from disk and re-resolve edges against the armed snapshot (`src/module_loader/runner_pipeline.rs:657-690`); the producer-identity check does hash the executing binary (`src/bin/ibex/runtime.rs:52-54`, `std::env::current_exe()`); the engine-identity check does hash the loaded Hermes artifact file at boot (`src/engine/mod.rs:38-112`), which in a static single-file world would be the executable itself; macOS does link `hermesvm`/`hermes.framework` dynamically with an rpath into the checkout and `HERMES_LINK_STATIC` exists only on the non-framework branch (`build.rs:1223-1233`, `build.rs:1447-1459`); the capsec target matrix advertises zero targets (`capsec/generated/target-advertisements.json`, `"advertisements": []`) and production arming refuses unadvertised targets (`crates/capsec-semantics/src/decision.rs:199`); `AmbientRoot` really does authorize any otherwise-unauthorized root-principal effect after denials (`decision.rs:936-948`); the runtime really does read configuration beyond `IBEX_*`/`EXACT_*` (`EX_DISABLE_BYTECODE_SANITY_CHECK` via raw C++ `getenv` in `src/engine/hermes_runtime.cc:4070`, `IBEX_DNS_SERVER`, `RES_OPTIONS`, `EXACT_WPT_TRUST_LOOPBACK_TLS`, unprefixed `HOST`/`HOSTNAME`); the lean/full framework sizes are 1.8 MB / 9.4 MB as stated; and the HBC path does copy into aligned storage rather than mmap (`src/engine/hermes_module_runner.cc:70-71`). The round-1 revision visibly did its job: the withdrawn "no new format" claim, the resolved digest circularity, the dedicated stub crate, and the inventory-derived env profile are all correct responses to real properties of this codebase.

The direction is right and the composition argument is sound: LLP 0027 carriers, the LLP 0014 policy artifact, and LLP 0021 arming are genuinely the hard parts, and a versioned outer envelope plus a disk-free admission path is the correct one-new-contract framing. The plan is phased sensibly with real gates.

The remaining gaps concentrate in two places the document has not yet thought all the way through. First, the *producer side* of the identity story: the RFC treats "bind carriers to the stub's link-time engine constant" as settled by LLP 0027, but today's production pipeline can only bind carriers to the *packaging process's loaded engine* — a different artifact from the stub's static archive by construction — and production HBC carrier emission does not actually exist yet (`publish_prepared_source_graph_v1` emits only factory-table carriers). Second, compiled-mode *policy semantics*: what a project-rooted `fs:` grant means on a machine with no project tree is never defined, and the root-authority ceiling's authoring surface contradicts LLP 0014's generated-not-hand-authored doctrine as currently phrased. These are addressable with specific revisions, not rethinks.

2. **Strengths**

- **Honest self-correction against verified code.** The Summary and §2b withdraw the earlier "no new format" claim and give the two precise reasons the envelope must exist (path-bearing index; disk re-authentication on reload) — both verified true (`runner_pipeline.rs:657-666`, `:677-690`). This is the LLP process working as intended.
- **§3's digest-domain separation** resolves a genuine circularity. The engine-identity provider really does hash the loaded engine file (`src/engine/mod.rs:41-102`), and the producer check really is a self-hash (`runtime.rs:52-54`); splitting engine/stub-core/producer/envelope/file digests, with the file digests detached, is the correct topology. The plainly stated threat model ("an adversary who can rewrite the file can recompute every internal digest") honors LLP 0013's honesty rule (§Threat model, "the honest name is supply-chain integrity, not sandbox").
- **§4's two prerequisite gates are real findings, not padding.** `AmbientRoot` (`decision.rs:936-948`) would silently widen the "authority is exactly the embedded policy" claim, and the empty target-advertisement matrix genuinely blocks production arming today. Naming these as program gates rather than discovering them at ship time is exactly what an RFC is for.
- **The env profile keyed on the capsec inventory rather than name prefixes (§4)** is the right mechanism: the verified read surface includes `EX_*` and unprefixed names and raw C++ `getenv`, so a prefix rule would be a fiction. The "ignore, not reject" choice and the app-env-snapshot/runtime-profile channel separation are both well judged.
- **§1's two rejections are correct on the evidence.** `ibex build` really is the legacy positional-`FILE`/`--outdir` grammar (`src/bin/ibex/cli.rs:230-238`) whose fate LLP 0028 §4b owns, and the full binary really has pre-clap namespace interception (`src/bin/ibex/main.rs:247`) that a subtractive feature would have to boot around; the dedicated stub crate is the smaller, more auditable shape.
- **Measured-claims discipline (Motivation, §7 phase 7).** Size/startup numbers are labeled estimates with a named acceptance gate, matching LLP 0026's performance-gate pattern (`ibex/module-runner-performance-gate/1`, verified).
- **§2c's signing/determinism order of operations** (unsigned-core reproducibility, recorded signed digest, bounded EOF magic scan) is unusually concrete for a Draft and correctly scoped ("host `codesign` output is not bit-stable").

3. **Concerns**

- **Material — engine-digest binding at packaging time is unresolved even for host-target v1.** Carrier admission binds `engine_binary_digest` to the *loaded* engine (`src/module_loader/carrier.rs:265-277`; `src/engine/mod.rs:249-253`), and the packaging `ibex`'s loaded engine (dynamic `hermesvm.framework`) is a different artifact — different digest — from the stub's static Hermes archive by construction. §3 defines the compiled-mode constant and §5 defers "there is no target parameter today" to *cross-target*, but the packaging-binary-vs-stub engine mismatch exists on the host tuple too: v1 packaging must bind HBC carriers to the stub descriptor's engine digest rather than its own loaded engine, and must verify that the hermesc it runs produces bytecode compatible with the stub's static Hermes (bytecode version and feature profile). The RFC never states this producer-side rule. *Resolution:* add to §3/§7 an explicit rule that packaging binds carriers to the target descriptor's compiled-in engine digest and bytecode version, verified against the compiler used, with a wrong-engine fixture; reframe §5 so this is named as v1 work.
- **Material — production HBC carrier emission does not exist, and "targets that advertise bytecode production" is undefined.** `publish_prepared_source_graph_v1` builds carriers only via `from_inline_artifacts`, which is hardwired to `JavascriptFactoryTable` (`runner_pipeline.rs:497-503`; `carrier.rs:135`); `bind_hermes_bytecode` is exercised only in tests that shell out to per-host checked-in `hermesc` binaries (`src/engine/module_runner.rs:2336-2368`). The Summary's "reuses … LLP 0026 §9's bytecode production" is true for admission/execution but not for production, and §1 step 1's "targets that advertise bytecode production" names an advertisement concept that exists nowhere (the capsec advertisement is conformance evidence, and it is empty). *Resolution:* name HBC-carrier production wiring as an explicit phase/gate in §7 and define concretely what advertises bytecode production (and where that fact lives — target descriptor seems the natural home).
- **Material — compiled-mode resource semantics are undefined.** LLP 0014 grants carry path-tree resources rooted at the project (e.g. `"root": "project"` in the artifact example, LLP 0014 §The generated artifact), and LLP 0021 arming derives package-tree write guards from the authenticated project tree. §4's disk-free arming lists "virtual roots" as an input but never says what a project-rooted `fs:` grant *means* on a customer machine with no project tree, arbitrary cwd, and a relocated executable. Until resource anchoring is specified, the Goals' "authority is exactly the embedded policy" is not a checkable claim. *Resolution:* add a §4 subsection defining compiled-mode interpretation of each resource-root kind (project-rooted, absolute, cwd-relative), including whether project-rooted grants are rejected at compile time, with denial fixtures.
- **Material (narrow) — the root-authority ceiling's authoring surface contradicts LLP 0014 as phrased.** §4 says the ceiling is "authored in the policy artifact like any principal's grants," but LLP 0014's artifact is *generated, not hand-authored*, and every principal's grants originate at import sites — there is no import site for root code, so no existing channel produces the ceiling row. The ceiling must also leave room for runtime-internal root effects (builtins are charged to the root initialization owner, LLP 0027 §Builtins), or compiled boot dies under its own ceiling. The open question flags vocabulary, not authoring. *Resolution:* specify the authoring channel (e.g., an entry-file self-attribute or manifest field flowing through the LLP 0014 generator with provenance) and state the bootstrap/builtin floor the ceiling must include.
- **Minor — enforcement mechanism for the env profile is unspecified where it is hardest.** Several inventoried reads are raw C++ `getenv` (`hermes_runtime.cc:4070`) and some names (`RES_OPTIONS`) are also read by system resolvers the runtime cannot instrument; "compiled-boot selection happens before any inventoried read" needs a stated mechanism, and the inventory's `startup:env:<dynamic>:cpp:getenv` rows classify *call sites*, not variable *names* (`capsec/generated/surface-inventory.md:6845-6848`), so "inventory-derived profile" needs name-level enumeration the inventory does not yet carry. *Resolution:* specify the mechanism — snapshot-then-scrub of `environ` at stub entry before any library init is the natural one, with the app snapshot used for child spawns — and state the name-enumeration requirement on the registry gate.
- **Minor — unsigned-core determinism silently depends on stub build reproducibility.** If `ibex compile` builds the stub "from the hermetic checkout" per invocation, two-clean-builder byte-identity requires reproducible Rust builds (path remapping, pinned toolchain) — an unnamed workstream. *Resolution:* either state that packaging always consumes the stub as a content-addressed prebuilt artifact (the §5 descriptor model, applied to the host tuple too), or name build reproducibility as a phase-1 gate.

4. **Suggestions**

- Decide envelope section *alignment* now: page-align carrier sections and record alignment in the section directory, so phase 7's mmap-vs-copy evaluation can be answered without a format revision. This is cheap in v1 and expensive to retrofit.
- Treat the host target as just another target-descriptor entry from day one — v1 becomes "cross-target packaging where the catalog happens to contain only the host," which unifies the code paths, fixes the determinism question above, and makes §5 a catalog-population problem rather than a second design.
- Consider a phase-0 spike: factory-table-only payload appended to a dynamically-linked dev stub, to de-risk envelope parsing, embedded admission, and disk-free arming before the static-Hermes workstream (the plan's largest unknown) completes.
- Note macOS notarization stapling in §2c: `stapler` mutates the file after signing, which interacts with both the signed-file digest and the bounded EOF scan window.
- Let `ibex inspect-executable` also verify an adjacent `<file>.provenance.json` when present, making the detached-record story a one-command audit.
- Consider optional per-section compression (digests recorded over uncompressed bytes) — the size delta versus Deno is part of the pitch, and carriers of factory-table JS compress well.
- The diagnostics-verbosity allowlist entry deserves care: pin where diagnostics *go* (stderr only), so the one allowed variable cannot become an exfiltration or filesystem-write channel.

5. **Open questions**

The RFC's own list (stdio implicit-vs-policy, initial allowlist, lean-vs-full engine, ceiling vocabulary, signed reproducibility, factory-table release status) is the right list. Add:

- How are policy resource roots interpreted after relocation (concern 3) — and is a project-rooted grant a compile-time error or a re-anchored grant?
- What channel authors the root-authority ceiling, given LLP 0014's generated-artifact doctrine, and what bootstrap/builtin floor must it contain (concern 4)?
- How does packaging bind and verify the stub's engine identity when it differs from the packaging binary's loaded engine (concern 1)?
- Is the stub rebuilt per compile or consumed content-addressed, even on the host tuple (concern 6)?
- Does the compiled application's `process.env` mutation surface (writes, deletes) operate on the boot snapshot, and exactly which environment do spawned children inherit?
- Does `ibex-compiled-stub` appear in `runtime-surface.json` accounting at all, or does LLP 0010 need a sentence stating that compiled binaries are explicitly outside the clap-surface contract (they own argv per §6)?

6. **Readiness verdict**

VERDICT: NOT READY — the direction, envelope design, and honesty discipline are strong, but the producer-side engine-binding gap, the nonexistent production HBC emission path it presumes, undefined compiled-mode resource semantics, and the root-ceiling authoring contradiction are unresolved material correctness/feasibility concerns, each with a concrete resolution named above.

### Orchestrator verification notes (round 2, outside verbatim body)

Spot-checked: `publish_prepared_source_graph_v1` emits carriers via `from_inline_artifacts` (factory-table only; `runner_pipeline.rs:497-507`, `carrier.rs:135`) — the "production HBC emission does not exist" finding is confirmed; LLP 0014's artifact example carries `"root": "project"` path-tree resources; raw C++ `getenv` read in `hermes_runtime.cc:4070` confirmed. No material defect found in the review's factual basis.

## Round 3 — 2026-07-17

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session and of prior rounds)
**Date:** 2026-07-17
**Redacted:** no
**Method:** sub-agent — orchestrated by `/llp-super-refine`; reviewed LLP 0029 at git-blob `0a15ed9ba18118830510aa26ee0c4ead44d3270f`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round)
**Verdict:** NOT READY

### Review (verbatim)

1. **Overall assessment**

This is a strong, unusually well-grounded RFC. Its central architectural judgment — that single-file packaging is composition over existing verified contracts (LLP 0027 carriers, LLP 0014 policy, LLP 0026 §9 production) plus exactly two new contracts (outer envelope, inner path-independent graph index) — is correct, and I verified the load-bearing repo facts behind it: `ibex build` really is the legacy positional-`FILE`/`--outdir` Rolldown→`hermesc` path with a raw-source fallback that neither produces carriers nor binds the root `--policy` option (`/Users/ccheever/projects/ibex/src/bin/ibex/cli.rs:230-238`, `src/bin/ibex/main.rs:1385-1431`, `src/bin/ibex/runtime.rs:3359-3408`); the prepared-module-graph index is genuinely path-bearing and disk-re-authenticating with a builtin-vs-file-only-schema mismatch (`src/module_loader/runner_pipeline.rs:538,658-667`, `src/host/mod.rs:2191-2227`, `schemas/prepared-module-graph-v1.schema.json` lines 69-95); engine identity really is a hash of the loaded Hermes artifact *file* (`src/engine/mod.rs:38-112`), making the §3 circularity analysis and the new compiled-mode identity domain necessary rather than decorative; the same-binary self-hash producer guard exists and genuinely cannot survive into a compiled binary (`src/bin/ibex/runtime.rs:52-57`, `runner_pipeline.rs:600-603`); macOS Hermes is dynamically linked via an rpath into the checkout with `HERMES_LINK_STATIC` Linux-only (`build.rs:1224-1234,1447-1458`); the production publisher emits only factory-table carriers with HBC binding test-only (`runner_pipeline.rs:423-582`, `carrier.rs:315+`); the `AmbientRoot` stratum authorizes any unauthorized root effect (`crates/capsec-semantics/src/decision.rs:936-948`), so the root-ceiling requirement is well-founded; and the capsec CLI heuristic really would misfile `inspect-executable` (`capsec-coverage-model.mjs:9627-9636`, `name.includes("inspect")` → `inspector:activate`). The document's habit of naming what does not exist yet (production HBC wiring, static macOS Hermes, CapSec advertisement, the policy generator's missing graph binding) is exactly the honesty discipline the corpus demands, and most of its "named workstreams" check out as real gaps.

The plan is good: the phase ordering (format spike before static-Hermes work; formats before admission; measured claims last) de-risks in the right order, and the acceptance gates are concrete and falsifiable. The dedicated stub crate over a subtractive feature is right given the verified pre-clap namespace interception in the full binary (`main.rs:247-268`); the dedicated `ibex compile` subcommand over a `build` overload is right given what `build` actually is.

Three things keep it from ready. First, a genuine internal contradiction: carriers "embedded verbatim" carry a `deployment_graph_digest` that today derives from a digest over *absolute module paths*, which is irreconcilable with the phase-3 "two checkout paths → identical unsigned bytes" gate. Second, §1 step 1 describes a six-inventory graph digest as though the production path already produces it, when the actual digest covers three of the six and at least three distinct graph-digest domains coexist unreconciled in the repo. Third, the §4 environment scrub is specified default-open (scrub known names) while the claim it supports ("closed configuration") requires default-closed. All three are fixable with targeted revisions, not redesign.

2. **Strengths**

- **The "composition plus two new contracts" framing (Summary, §2b) is verified-correct, including its self-correction.** The checked-in prepared-graph schema really does admit only file `SourceId`s while publication places builtins in the root carrier (`runner_pipeline.rs:302-305,468-469,525-528` vs schema lines 69-82) — the RFC caught a latent repo inconsistency that earlier revisions of itself had papered over.
- **§3's digest-domain separation is the right fix to a real circularity.** The loaded-file engine hash (`src/engine/mod.rs:85-106`, with `O_NOFOLLOW` and post-hash identity re-check) cannot govern a static single-file world; naming the compiled-mode identity as a new LLP 0027 domain rather than reinterpreting the existing field is the honest move, and the `StubContractV1` replacement for the producer-equals-executor guard is correctly reasoned.
- **The threat model (§3) obeys LLP 0013's honesty rule** ("the honest name is supply-chain integrity, not sandbox", LLP 0013 line 220-221): internal digests detect corruption/skew, not malice; pre-main `DYLD_*`/`LD_PRELOAD` is explicitly outside the boundary. The immutable-build-statement / publisher-statement split (§2c) is a clean answer to notarization mutating bytes.
- **§4's root-ceiling requirement is grounded in verified code**: `AmbientRoot` fires "still after every denial" for any unauthorized root effect (`decision.rs:936-948`), so without a ceiling "authority is exactly the embedded policy" would be false. The generated authoring channel (entry-manifest → generator → ceiling row with bootstrap floor) respects LLP 0014's generated-never-hand-edited invariant rather than fighting it.
- **The mount contract's refusal to fake `/project` (§4)** is the right call — every candidate reinterpretation it lists really is wrong — and `/app`/`/work` compose cleanly with LLP 0023 §5's session-cwd resolution model.
- **§1's rejection rationales are all factually verified**: `build`'s grammar conflict and unbound `--policy` (`runtime.rs:3040-3051,3105-3119`), the capsec CLI classification consequence, and the LLP 0010 manifest/clap sync test (`cli.rs:1931-1985`) that makes "update together" enforceable.
- **§2c's Mach-O layout check** (signature range must cover the envelope; footer immediately before the signature blob) is a genuinely clever structural answer to the signed-then-appended attack that internal digests cannot distinguish.
- **§5's "catalog-population, not a second design"** correctly matches the advertisement gate in code (`runtime.rs:42-44`: exactly `macos/aarch64` and `linux/x86_64`) and the git-ignored-artifact model it formalizes.

3. **Concerns**

- **Material — "carriers embedded verbatim" contradicts the path-independence/determinism gates.** Carrier manifests bind a `deployment_graph_digest` and admission rejects drift (`src/module_loader/carrier.rs:250-255`; LLP 0027 "binds … deployment-graph digest"). Today that digest comes from the Rolldown bundle manifest's `graphDigest` (`src/bin/ibex/runtime.rs:1494-1497`), which is SHA-256 over `JSON.stringify(deps)` where each dep is `{ path: <absolute module path>, sha256 }` (`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:380-419`). Two checkout paths therefore yield different carrier manifest bytes, so §2b's "carriers, embedded verbatim" and phase 3's "two checkout paths → identical unsigned bytes" gate cannot both hold. Either carriers are re-bound at packaging to the new path-independent snapshot digest (in which case they are not verbatim copies of production-cache artifacts and the RFC should say so), or the graph-digest domain itself must become path-independent first. *Resolution:* §2b/§3 specify what the embedded carriers' graph binding points at in compiled mode, reconcile the "verbatim" wording, and add a carrier-bytes checkout-path-independence fixture to the phase-3 gate.
- **Material — §1 step 1 presents a graph-digest domain that does not exist and leaves three real domains unreconciled.** The text reads as though the LLP 0026 §9 path already yields "its authenticated graph digest — over the node, package, integrity, typed-edge, candidate-set, and entry inventories." Today's generation digest (`src/module_loader/generation.rs:148-165`, domain `ibex/module-generation-graph/1`) covers sourceId + semanticDigest + bindings only — three of the six; candidate-set and entry inventories are not covered anywhere; and the digest actually bound into publication is the separate path-bearing Rolldown `graphDigest`, while the armed snapshot carries yet another `packageGraph` digest (`runtime.rs:2378-2386`). Meanwhile the canonical policy artifact has no graph-identity field at all and its Rust ingest is `deny_unknown_fields` (`crates/capsec-semantics/src/policy.rs:27-38`), so the cross-check needs a schema revision, not just a generator flag. The RFC names the generator work but not the digest-domain work. *Resolution:* rewrite §1 step 1 to define the snapshot digest as a new/widened domain, enumerate the existing three domains it subsumes or binds, and note the policy-schema revision the `deny_unknown_fields` ingest forces.
- **Material — the env sanitize step is default-open as written, undercutting the "closed configuration" claim (§4).** Step 2 scrubs "every name in the stub's runtime-configuration profile"; any name *not* in the profile survives in the real environ, where raw `getenv` readers can still see the launch environment — and the set of such readers is not fully enumerable from this repo's source: Ibex's own C++ adapter has ~115 raw `getenv` sites, but the static Hermes archive and statically linked libcurl/resolver read names (proxy variables, `SSL_CERT_FILE`, glibc internals) that no scan of this tree can inventory, which is precisely why the profile gate ("fails when a new runtime reader is unclassified") cannot be sufficient. Since application `process.env` is served from the base snapshot anyway, nothing needs the real environ except the allowlist. *Resolution:* specify the scrub as default-deny — clear the entire real environ, restore only the allowlist — or state explicitly why enumerated scrubbing meets the closed-configuration claim including readers invisible to source scanning.
- **Minor — the LLP 0023 machinery §4 builds on is largely spec-side today.** There is no literal `/project` virtual mount in code: relative resolution goes through `process.cwd()` defaulting to `/` (`src/builtins/path.js:8,59-71`, `src/builtins/fs.js:544-562`); what exists is the armed snapshot's logical project-root binding backed by an object identity (`src/host/embedder_artifacts.rs:591-595`, `arming.rs:912-930`); and `LogicalRoot` has only `Project, Package, Home, Tmp, Absolute` (`crates/capsec-semantics/src/model.rs:626-633`) — no App/Work vocabulary. *Resolution:* one sentence in §4 acknowledging the LLP 0023 implementation dependency, and the `LogicalRoot::App`/`Work` vocabulary addition named explicitly in the phase-3 schema-revision list.
- **Minor — the Linux "static" branch is static-Hermes-only, and libcurl is linked dynamically.** `HERMES_LINK_STATIC` yields `static=hermesvm` but then links `stdc++`, `z`, `resolv`, `pthread`, `dl`, optional `static=ssl/crypto`, and `curl` as a dylib only when present (`build.rs:1447-1474`). §2a's audit workstream is correctly named, but "no non-system dynamic libraries" needs an explicit libcurl disposition (vendor/static vs. classify into the system baseline recorded in the contract). *Resolution:* name libcurl's disposition as a required output of the phase-1 audit gate.
- **Minor — the phase-6 CapSec-advertisement gate silently inherits the entire LLP 0021 conformance program.** `capsec/generated/target-advertisements.json` is `"advertisements": []` and the matrix shows 0 enforced / 7108 unsupported cells for `aarch64-apple-darwin`. The RFC treats verified advertisement as one gate among several; in fact it is the completion condition of another whole program, and this RFC's schedule is hostage to it. That coupling is arguably *correct* (compiled binaries are production posture; LLP 0021 principle 7), but the magnitude should be stated. *Resolution:* §7 phase 6 cites the current matrix state and names LLP 0021 as the owning program whose completion the gate inherits, so the dependency is a visible scheduling fact.
- **Minor — compiled-mode `process.env` must be reconciled with LLP 0022's armed classification.** LLP 0022 (lines 781-785) pins `process.env` under arming to "an empty base with per-principal overlays … never the host environment." §4 step 3 serves application reads from the captured host snapshot "through the existing capability gate," which is presumably root-view-only with package principals still seeing the armed classification — but the RFC never says so. *Resolution:* one sentence stating how the base snapshot composes with per-principal classification, plus a package-principal env-read fixture in phase 5.

4. **Suggestions** (non-blocking)

- **Zero-copy HBC from the already-mapped image.** The executable is mapped by the OS loader at exec; with the page-aligned, alignment-recorded sections of §2b, phase 7's mmap-vs-copy question can include a third option — evaluating HBC directly from the loaded image with a non-owning buffer (today's path is an explicit `memcpy` into aligned heap storage, `src/engine/hermes_module_runner.cc:64-81,1174-1177`). Worth naming since it may make the cold-start pitch decisively better.
- **Argv: consider a reversible surrogate-escape** (Python `surrogateescape` / Rust `OsString`-style) as the middle path between strict Unicode rejection and a raw-byte API — a compiled file tool that hard-fails on a legal non-UTF-8 filename argument is a real-world sharp edge; if rejection ships, the boot error should name the offending argument index.
- **Expose the env allowlist and profile via `ibex inspect-executable`**, and consider having the stderr diagnostics toggle report (count-only) how many launch variables were scrubbed — it turns "my tool ignores HTTP_PROXY" from a mystery into a one-line diagnosis without opening an exfiltration channel.
- **File the schema/publication builtin mismatch now.** The prepared-module-graph schema admitting only file `SourceId`s while publication emits builtin records is a latent LLP 0027 defect independent of this RFC; it deserves its own ticket rather than being fixed only as a side effect of §2b.
- **Publisher statement: name sigstore/transparency-log integration** as the concrete realization of "or logs in a transparency service" — the detached-provenance design is already shaped for it.
- **Busybox-style multi-entry envelopes** (one stub + shared carriers, entry selected by argv0 or a designation table) could serve Snapback's per-app CLI *family* at near-zero marginal size per tool. Non-standard, out of v1 scope, but the section directory and entry-designation design should merely avoid foreclosing it (e.g., don't make "exactly one entry designation" a format invariant if a designation *table* costs nothing now).

5. **Open questions**

- Which digest is *the* snapshot identity, and how do the three existing domains (generation graph digest, Rolldown `graphDigest`, armed-snapshot `packageGraph` digest) bind to or retire into it? (Concern 2 — must be answered to make §1 step 1 executable.)
- What do embedded carrier manifests' `deployment_graph_digest` fields bind to in compiled mode, and are carriers verbatim or re-bound at packaging? (Concern 1.)
- Is the environment scrub default-deny or enumerated, and if enumerated, what covers engine/third-party readers invisible to source scanning? (Concern 3.)
- Does the motivating consumer actually fit v1's tuples? Snapback's per-app CLIs target other people's machines, which includes Windows and x86_64 macOS; v1 ships `aarch64-apple-darwin` + `x86_64-unknown-linux-gnu` and Windows is deferred behind LLP 0026's patched-Hermes question. The RFC should state whether v1 satisfies the motivating consumer or only prototypes for it.
- What is the realistic path and timeline for the first verified CapSec target advertisement (currently zero, 7108 unsupported cells on the host tuple), and does LLP 0029 block on it or contribute conformance evidence to it?
- The RFC's own open questions stand (implicit vs. policy-explicit stdio/cwd; allowlist contents; lean-vs-full Hermes; root-ceiling vocabulary; signed-artifact reproducibility; factory-table release status; per-section compression) — of these, stdio/cwd implicitness and the root-ceiling vocabulary are the two that gate `Accepted`.

6. **Readiness verdict**

VERDICT: NOT READY — the direction, decomposition, and phasing are sound and the document's factual grounding is exceptional, but three material issues (the verbatim-carriers vs. path-independent-determinism contradiction, the overstated/unreconciled graph-digest domain in §1 step 1, and the default-open environment scrub) must be resolved by targeted revision before the design's central claims are internally coherent.

### Orchestrator verification notes (round 3, outside verbatim body)

Spot-checked: the Rolldown `graphDigest` is SHA-256 over deps records containing absolute `path` fields (`rolldown-bundle.mjs`) and is what runtime wraps into `deployment_graph_digest` — the verbatim-carriers/path-independence contradiction is confirmed; `ibex/module-generation-graph/1` covers three of the six claimed inventories; canonical policy ingest is `deny_unknown_fields`. No material defect found in the review's factual basis.

## Round 4 — 2026-07-17

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session and of prior rounds)
**Date:** 2026-07-17
**Redacted:** no
**Method:** sub-agent — orchestrated by `/llp-super-refine`; reviewed at git-blob `e838e3afd0effc30f2005226d8ab29540dfdd4e2`; barred from reading `llp/reviews/` (artifacts stashed outside the tree during the round). Round-4 brief added the calibration that registered author decisions do not by themselves make a document unready.
**Verdict:** NOT READY

### Review (verbatim)

(Note: the reviewer's returned message opened with one sentence of run coordination before the review proper; it is preserved verbatim below as received.)

All five verification agents have now reported. Every load-bearing repo claim in the RFC checked out; I have one independent feasibility finding of my own on the macOS signing sequence. Writing the review now.

1. **Overall assessment**

This is a strong, unusually well-grounded RFC, and the feature itself is a good idea: single-file executables are the natural distribution endpoint for the artifact stack Ibex has already built (LLP 0027 carriers, LLP 0014 generated policy, LLP 0026 §9 prepared graphs), and the "compiled artifact as a frozen, auditable authority object" framing (§Motivation) is a genuine differentiator over `deno compile`/`bun build --compile`, not just parity. The document's most striking property is that its repo-facts are *true*. I verified every load-bearing claim against the code and found no factual errors: `ibex build`'s legacy grammar and the unbound root `--policy` (`src/bin/ibex/cli.rs:229-238`, `src/bin/ibex/runtime.rs:3040-3052` passes `None`); `bind_hermes_bytecode` trusting caller-supplied engine metadata and the real-HBC tests labeling genuine bytecode with placeholder digests (`src/module_loader/carrier.rs:149-166`, `src/engine/module_runner.rs:2371-2373`); the three fragmented graph digests exactly as described (generation digest covering three of the six inventories, `src/module_loader/generation.rs:148-165`; Rolldown `graphDigest` over `realpath`-absolute deps, `rolldown-bundle.mjs:417-419`; armed `packageGraph` digest, `arming.rs:40`); the file-only `sourceId` schema vs. builtin-emitting publication (`schemas/prepared-module-graph-v1.schema.json:69-82` vs `runner_pipeline.rs:469-537`); production emitting factory tables only; `ProcessCeiling` at stratum 5 denying before `AmbientRoot` at stratum 14 while escalation ceilings bound only dynamic grants (`decision.rs:658-682, 936-948, 1248-1256`); zero advertised targets (`target-advertisements.json`: empty array; `target-matrix.md`: 0 enforced / 7108 unsupported); `HERMES_LINK_STATIC` Linux-only with macOS dynamic `hermesvm` framework (`build.rs:1447-1458, 1224-1233`); the env-control reads and the existing closed-startup-controls gate (`fetch.ts:494-500`, `Crypto.ts:1818-1826`, `src/host/mod.rs:42-58`); even the capsec coverage model's literal `name.includes("inspect")` → `inspector:activate` heuristic (`capsec-coverage-model.mjs:9627-9636`) that §1 defends against. Three rounds of review have plainly done their work: the acyclic stub identity, the payload-verbatim/manifest-re-bound distinction, the unstaplable-binary correction, and the invocation-time error preservation are all fixes to real defects in earlier revisions, and each is now consistent with the governing documents.

The plan is credible: phases are ordered to de-risk (format spike on a dynamic dev stub before static-Hermes work; disk-free arming before producer wiring), gates are fixture-named, the author-decision register is explicit, and the two giant external dependencies (LLP 0021's zero-advertisement state and LLP 0028's window-closure program) are stated as scheduling facts rather than hidden.

I have one material concern. The normative macOS signing sequence in §2c ("append envelope + footer; ad-hoc sign") is written as a plain trailer append followed by `codesign -s -`, but Mach-O code signing requires the signature blob to terminate `__LINKEDIT` with no unsealed bytes after it — appended trailer data is precisely why tools like postject (Node SEA) and Deno's `sui` exist as *section/segment injectors* on macOS rather than trailer appenders. The RFC's own boot-side layout check ("footer immediately before the signature blob; signature range covers the envelope") actually describes the file you'd get from `__LINKEDIT`-extension surgery, not from a naive append — so the design is one specified step away from coherent, but that step is load-bearing and currently missing from a section labeled normative. Beyond that, my concerns are minor: a mischaracterization of LLP 0028's computed-`require` register, un-precommitted phase-7 budgets (a trap this corpus elsewhere explicitly avoids), unstated sequencing against the concurrent LLP 0028 program (including two concurrent revisions to the same `deny_unknown_fields` LLP 0014 schema), stub-contract churn from the repo-global registry digest, and an unspecified catalog key story.

2. **Strengths**

- **Verified factual grounding throughout.** Every checked claim about the repo is accurate (see above). Notably, §1 step 3's identification of the `bind_hermes_bytecode` trust gap and the dummy-digest real-Hermes tests is a real latent defect (`carrier.rs:149-166`; `module_runner.rs:2371-2388`), and requiring production wiring to derive the HBC version by inspection is exactly the right fix.
- **The digest-domain reconciliation (§1, §3) addresses real fragmentation, not invented tidiness.** The three partial graph identities exist exactly as described, the Rolldown digest genuinely embeds absolute paths into publication bindings (`rolldown-bundle.mjs:391, 417-419` → `runtime.rs:1544-1560`), and a path-independent authenticated snapshot domain is the correct unifying move. Saying plainly that the domain "does not exist today" is the honesty discipline working.
- **Acyclic stub identity and cryptographic humility (§2a, §3).** Splitting the compatibility identifier from the instance descriptor resolves a genuine cycle, and "boot does not self-hash — a file cannot prove its own bytes" is correct. The pinned-fd self-file acquisition (§3) is modeled on a mechanism that verifiably exists and works (`src/engine/mod.rs:83-102, 155-237`: dev/inode mapped-image identity check before hashing), so the design is grounded in proven practice, not aspiration.
- **Authority story wired to the evaluator's real strata (§4).** `processAuthorityCeiling` as the constraint on `AmbientRoot` — not a principal escalation ceiling — matches the implemented decision order precisely (`decision.rs`: ProcessCeiling step 5, AmbientRoot step 14; escalation ceilings only at `decision.rs:1248-1256`), and the distinct bootstrap stage correctly avoids granting builtin-initialization effects to application root code. The mount contract follows LLP 0023's own rule for new mounts to the letter (LLP 0023 §1: "Any future mount … requires an update to this document").
- **Default-deny environment with app-env-as-data (§4).** The justification — native readers invisible to source scanning — is verified real (dynamic libcurl on Linux, `build.rs:1467-1474`; `NODE_TLS_REJECT_UNAUTHORIZED`/`EXACT_ALLOW_INSECURE_CRYPTO` reads in runtime JS), and it correctly extends an existing production posture (`reject_closed_startup_environment`, `src/host/mod.rs:42-58`) rather than inventing one. Making profiled controls inert even when app-written closes the obvious loophole.
- **Language non-forking (§1 step 4).** Preserving LLP 0028's invocation-time error semantics in compiled binaries — and withdrawing the earlier compile-time refusal as contradicting it — is the right call; `--deny-unsupported` as opt-in keeps the clean-graph guarantee available.
- **Honest threat model (§3) and honest motivation (§Summary, Motivation).** No tamper-proofness claims beyond platform signing; the `DYLD_*`/`LD_PRELOAD` concession; size/startup as budgeted hypotheses rather than claims; the Snapback v1-coverage gap stated up front. This is LLP 0013's honesty rule applied consistently.
- **Process quality (§7).** Phase 0 spike before the static-Hermes long pole; fixtures named per gate; an author-decision register that correctly separates product choices from design.

3. **Concerns**

- **[Material] §2c's normative macOS sequence assumes `codesign` accepts a trailer-appended Mach-O; it almost certainly does not.** Evidence: §2c step 2-3 ("Append envelope + footer … Ad-hoc sign (`codesign -s -`)") with §2b choosing "trailer over linker-section embedding." Mach-O signing requires `LC_CODE_SIGNATURE` data to be the terminal content of `__LINKEDIT` with no bytes after it; unsealed trailing data prevents signing — this constraint is why Node SEA uses postject and Deno built `libsui` to inject into sections/segments on macOS instead of appending. The RFC's own boot check ("footer … immediately before the signature blob; the signature range covers the envelope") describes a file where the envelope sits *inside* the signed region — achievable only via `__LINKEDIT`/segment extension surgery that §2c never specifies. The section fallback is named but §2c is written as settled. On the v1 arm64 tuple, signing is kernel-mandatory, so this cannot be deferred as polish. **Resolution:** either (a) specify the Mach-O surgery (extend `__LINKEDIT` or inject a dedicated segment, postject/libsui-style) as the normative macOS mechanism and rewrite the §2c steps and boot layout check around it, or (b) demote the macOS embedding mechanism to an explicit phase-0/phase-2 spike decision (trailer-with-surgery vs. section) with both variants' boot checks sketched, or (c) cite concrete evidence that `codesign` signs the proposed trailer layout.
- **[Minor] §1 step 4 overstates LLP 0028 on computed `require`.** The RFC says computed `require` "is permanently invocation-refused there"; LLP 0028 actually registers it as a live 0.2 author decision with a named reopening design ("deferred, with a design that already fits" — LLP 0028 §2; register item 3). **Resolution:** reword to track LLP 0028's register, and add one sentence saying what compiled mode does if reopening lands (computed-`require` candidate rows ride the same embedded candidate tables).
- **[Minor] Phase-7 budgets are promised but not precommitted (§Motivation, §7 phase 7).** The RFC correctly argues "a report without thresholds cannot decide," but the thresholds are set at phase-7 time — thresholds set at measurement time can be fitted to results, the exact trap LLP 0028 §3 closes with its precommitted parse-equivalence projection. **Resolution:** register budget-setting as an author decision that blocks phase-7 *entry* (numbers fixed before measurement), or precommit provisional numbers now (even coarse ones, e.g., a fraction of Deno's ~65 MB hello-world).
- **[Minor] Sequencing against the concurrent LLP 0028 program is unstated, including a schema-ownership collision.** §1 step 4 consumes LLP 0028's guarded representation and candidate tables (0028 rollout step 2), yet neither document says which lands first; worse, both RFCs command a revision of the LLP 0014 canonical-policy schema (0028: manifest-declared candidates; 0029: graph-identity field and entry-manifest ceiling declaration), and that schema is `deny_unknown_fields` (`crates/capsec-semantics/src/policy.rs:28-78`), so two uncoordinated revisions cannot both be "the versioned change." Both are Drafts dated the same day. **Resolution:** one paragraph in §7 mapping 0029 phases onto 0028 rollout steps (e.g., phase 4 requires 0028 step 2 landed or explicitly tolerates its absence via invocation-refusal) and naming a single owner/order for the LLP 0014 schema revision.
- **[Minor] `StubContractV1` pins the repo-global capsec registry digest, which rotates on CLI-surface-only changes.** Verified: the registry digest derives from the surface inventory, which includes every `runtime-surface.json` CLI row (`generate-capsec-registry.mjs:758, 928, 1015`; `capsec/generated/surface-inventory.md` cli rows) — adding `ibex compile` itself rotates it. Every such rotation would churn the stub contract and force catalog re-issue even when nothing the stub enforces changed, coupling stub releases to unrelated CLI edits. **Resolution:** pin a runtime-relevant registry *projection* in the contract (with its own digest), or explicitly state and accept the churn with a catalog re-issue policy.
- **[Minor] The catalog trust root has no key story (§2a).** "Authenticated, rollback-resistant catalog manifest … pinned by the distributing `ibex` release, TUF-style in spirit" names the shape but not who signs it, how the pinned root rotates across ibex releases, or what "authenticated" means for the fetch step (signature? pin-in-binary of the manifest digest? both?). Content addressing was correctly rejected as a trust root; the replacement needs at least its custody named. **Resolution:** add key custody/rotation/pinning to §2a or the open-questions/register list with a phase-1 owner.
- **[Minor] Root-principal classification of the captured env base is ambiguous (§4 step 3).** LLP 0022's armed classification is "an empty base with per-principal overlays as the registry admits, never the host environment" (LLP 0022 §7); compiled mode instead captures the full launch `environ` as the root view "served … through the capability gate." Whether root reads of arbitrary captured names require policy rows (broker-base env-name selectors exist: `model.rs:841-849`, `authority-selector.schema.json`) or are ambient for root is not stated, and it determines how much of the launcher's environment a compiled program can see by default. **Resolution:** one sentence specifying the default classification of the base snapshot for the root principal, plus a fixture in phase 5.

4. **Suggestions** (non-blocking)

- Name **rcodesign (the `apple-codesign` crate)** as the candidate answer to the signed-reproducibility open question: it is deterministic where Apple's `codesign` is not, runs on Linux (unblocking future cross-target macOS packaging from the Linux builder), and could collapse the "determinism scoped to unsigned core" caveat.
- Give `ibex inspect-executable` a **stable machine-readable output contract** (versioned JSON) so fleets of shipped tools can be policy-audited and release-to-release authority diffs automated — this operationalizes the "legible authority story" and is cheap to specify now.
- Link the independently-filed prepared-module-graph schema defect (file-only `sourceId` vs. builtin publication — verified at `schemas/prepared-module-graph-v1.schema.json:69-82` / `runner_pipeline.rs:527-537`) to phase 2, since the embedded-graph schema work will touch the same variant space; note the on-disk loader never enforces the JSON schema (serde-only), so the fix should add a conformance test.
- §2b's "Trailer over linker-section embedding for the same reasons as before" cites reasoning that no longer appears in the document; restate the reasons in one clause so the RFC stays self-contained (and revisit them if the Material concern flips macOS to section embedding).
- Define operationally what "cross-checked, not conflated" means for the armed `packageGraph` digest vs. the new snapshot domain (§1 step 1): what projection is compared, and is mismatch a packaging refusal or a boot refusal?
- Add one distributor-docs line about macOS quarantine reality: curl-fetched binaries carry no quarantine attribute (no Gatekeeper check at all), browser-fetched ones need the online ticket — it sharpens who actually needs the container-packaging path.
- Consider stating whether `ibex inspect-executable` must work cross-platform on foreign-target executables (envelope/attestation checks are portable; platform-signature validity is not) — one sentence prevents a v2 surprise.

5. **Open questions**

- The macOS embedding mechanism under codesign (the Material concern): trailer-with-`__LINKEDIT`-surgery, dedicated segment/section injection, or evidence the naive trailer signs — this reshapes §2c and the boot layout check.
- Catalog trust-root custody: who signs the catalog manifest, where it is hosted, and how the pinned root rotates across `ibex` releases.
- Ordering against LLP 0028's rollout steps, and single ownership of the LLP 0014 schema revision both programs claim.
- Whether the stub contract pins the full registry digest or a runtime-relevant projection.
- The concrete `ibex/authenticated-graph-snapshot/1` projection (already registered; the golden-vector precommitment is the right control).
- Default root-view classification of the captured env base (policy-gated per name vs. ambient for root), and the initial allowlist contents (registered).
- Whether the unset-cwd sentinel survives contact with real Node-compat libraries (already registered; phase-3 evidence).
- The phase-7 budget numbers themselves, precommitted before measurement.
- The §7 register items, especially ship-before-first-advertisement sequencing (register 4) and Snapback's Windows/x64-macOS pull (register 5), which together determine whether v1 as scoped serves the motivating consumer or only prototypes for it.

6. **Readiness verdict**

VERDICT: NOT READY — the RFC is factually rigorous and near-ready, but §2c's normative macOS signing sequence rests on a trailer-append-then-codesign step that known Mach-O signing constraints (the reason postject/libsui exist) likely make infeasible as written, and that load-bearing mechanism must be respecified or evidence-backed before the document goes to Review; the remaining concerns are minor and clearly resolvable.

### Orchestrator verification notes (round 4, outside verbatim body)

The macOS finding (codesign requires `LC_CODE_SIGNATURE` to terminate `__LINKEDIT` with no unsealed trailing bytes; postject/libsui exist precisely because naive trailer appends cannot be signed) is consistent with Codex's independent round-4 finding citing Apple TN2206 and was adopted: the round-4 revision makes a dedicated Mach-O segment the normative macOS layout. The LLP 0028 register mischaracterization and the LLP 0014 schema-ownership collision are confirmed against the two documents' texts. No material defect found in the review's factual basis.

## Round 5 — 2026-08-01 (cluster loop: LLP 0029 + 0039 + 0047, round 1)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session)
**Date:** 2026-08-01
**Redacted:** no (repository content only; no secrets present)
**Topology:** lockstep cluster review. LLP 0047 is a scoped amendment to LLP 0029's release sequencing (§7 register item 4) and LLP 0039's product defaults; the three were reviewed together because cross-document coherence is the primary axis. This is the single verbatim cluster review, preserved once in the primary target's artifact; LLP 0039 and LLP 0047 carry pointer artifacts with the same per-target verdict sections.
**Method:** sub-agent — orchestrated by `/llp-super-refine`; reviewer read the three targets at git-blobs 0029 `e082559b9c53a83b6fc5fc314dde367d752bffb0`, 0039 `b8a6e07c79ad6931a52d10734895a40b9ad0e53f`, 0047 `9890e6bb6587ec906ef09049ba84c03b77ceaec6` (repo HEAD `54761987`), plus governing LLPs and repo source. Blindness was structural: both prior 0029 review artifacts were moved out of the working tree for the round's duration, and each family's response was held in an out-of-repo scratchpad until both landed.
**Brief:** `brief-r1.md`, hash `2d2438a011e9e43161263d6b58c45222bfa84552`
**Verdicts:** LLP 0029 NOT READY · LLP 0039 NOT READY · LLP 0047 NOT READY · **CLUSTER NOT READY**

### Review (verbatim)

I have completed my verification pass. I checked every load-bearing implementation claim against source, read the referenced LLPs (0021, 0022, 0023, 0025, 0026, 0027, 0028, 0031, 0034, 0036, 0038), compiled the stub crate, and inspected the CapSec registry artifacts. Writing the review now.

## Per-target findings

### LLP 0029

Verified true before findings: the Mach-O layout claims are exact (`crates/sfe-format/src/macho.rs:15-18` — 72+80=152-byte `LC_SEGMENT_64`+`section_64`, `__IBEX,__payload`, 16 KiB alignment, all §2c refusal conditions at macho.rs:111-151; headerpad `0x1000` at `crates/compiled-stub/build.rs:32`); the ELF audit matches §2a's exact DT_NEEDED set, RPATH/GLIBC/ISA/libcurl rules (`scripts/audit-sfe-linux-deps.sh:90-158`, CI-wired at `.github/workflows/hermes-artifacts.yml:466-473`); the Linux network-disable is real (`build.rs:2639-2672`, `EXACT_DISABLE_LINUX_NETWORK`); the pre-init env capture/sanitize/first-wins/constructor-probe claims are implemented (`crates/compiled-stub/src/environment.rs`, `build.rs:58-107`); the argv projection and index-named Unicode refusal exist (`crates/compiled-stub/src/process.rs:46-61`); zero advertised targets is true (`capsec/generated/target-advertisements.json` → `advertisements: []`); the phase-0 relocation smoke matches §2b (`scripts/test-sfe-phase0.sh`); producer preflight/two-atomic-file output exist (`src/bin/ibex/sfe.rs:232,405-425`).

- [MATERIAL] Correctness/Coherence: §1 step 3 still normatively pins the `hermesc` recipe as "the exact `-emit-binary -out {output} {input}` vector", and the digest-bound implementation enforces exactly that (`crates/sfe-format/src/lib.rs:317-336`, which refuses any other recipe). This contradicts LLP 0034's requirement that "every Ibex-owned `hermesc` invocation that emits executable HBC passes the flag" (0034 line 76), is empirically a miscompile hazard (issues/20260731-hermesc-recipe-missing-es6-block-scoping.md: flagless AOT gives capture-last `for-of` `let` semantics), and contradicts LLP 0047 M0.2, which this document's own 2026-08-01 revision incorporates by reference. A same-day revision that adopts 0047 must not leave the flagless vector as the stated normative recipe; the recipe digest is load-bearing (`ibex:hermesc-compatibility:1`, carrier admission), so the doc should state the coordinated bump.
- [MATERIAL] Correctness: multiple present-tense repo-state claims are now false, some contradicted by the document's own implementation-update paragraphs in the same section: (a) §1 step 1 "This domain does not exist today" — `ibex/authenticated-graph-snapshot/1` is implemented at `crates/capsec-semantics/src/graph_snapshot.rs:16-17` and consumed by the producer; (b) §1 step 3 "today `bind_hermes_bytecode` trusts its caller" — the current code derives `bytecode_version` by inspecting the emitted HBC (`src/module_loader/carrier.rs:204-218`, `HermesBytecodeMetadataV1::inspect`), which is exactly what the sentence demands as future work; (c) §3 "today's protected artifacts require a host path plus filesystem object identity" — `ExpectedEmbeddedProtectedArtifact` exists (`crates/capsec-semantics/src/arming.rs:100,277`, "These have no host path"), and LLP 0021's revision history records arming ABI v2 landing embedded protected ranges (0021 line 159); (d) §4 "host tuple: 0 enforced / 7108 unsupported cells" — the registry now has 7,528 cells per tuple (15,056 total, all `unsupported`; `capsec/registry/target-cells.json`). "Zero verified targets" remains true. In a Status: Review document revised 2026-08-01, these misstate what work remains and must be swept.
- [MINOR] Coherence: §6's implementation-status sentence "reserved Ibex spellings are passed through unchanged" (and the stub's own contract comment, `process.rs:4-5`: "Ibex option and subcommand spellings have no special meaning here") describes the pre-0047 contract; under the amended contract `--ibex-capsec` at argv[1] must not pass through. Date-scope the status so it cannot be read as the amended contract's implementation state.
- [MINOR] Coherence: §1 step 4's parenthetical asserts "computed `require` is permanently invocation-refused there" and the next sentence corrects itself ("registers computed `require` as a live 0.2 author decision ... rather than refusing it permanently" — the latter matches LLP 0028 §7). Delete the first claim rather than stacking a correction on it.
- [MINOR] Coherence: §6 keeps "SIGINT/SIGTERM/SIGHUP" as normative LLP 0025 rows while LLP 0047 M4 (which amends this RFC's sequencing) lists only SIGINT/SIGTERM. Say whether SIGHUP is in the v1 contract.

**LLP 0029 verdict: NOT READY**

### LLP 0039

Verified true before findings: `default = ["standard"]`, `insecure` non-default and implying `unadvertised-dev-arming` (`Cargo.toml:173-200`, with the doc's exact secure-dev build line at 166-168); `check-secure-mode.sh` exists with the behavioral probe and `BAD(permitted)` (`scripts/check-secure-mode.sh:33,61`), wired into the CapSec macOS job (`.github/workflows/compartment-conformance.yml:109-111`); `ex_host_is_armed` insecure gating and the ~46-gate description match `src/host/abi.rs:7723-7735`; the armed-observer `#[cfg(not(feature = "insecure"))]` story matches the referenced closed ticket.

- [MATERIAL] Coherence/Safety (blast radius understated): the 2026-08-01 revision carves the LLP 0047 exception into the Decision paragraph and trip-wire 3, but the rest of the document's acceptability apparatus was not reconciled with it. (a) Trip-wires 1, 2, and 4 key exclusively on the `insecure` feature, yet everything they warn about — running third-party/generated code with full ambient authority, including by agents in this repo — is now reachable through a supported zero-feature-flag path (`ibex compile` + run, ambient default). Item 4's rationale applies verbatim and no wire covers it. (b) "Preventing an accidental ship" is entirely about keeping no-sandbox builds out of release pipelines, while the amended Decision makes shipping enforcement-off artifacts the standalone default; the section does not say how its build-time-refusal ambition coexists with a product whose release stub deliberately contains the enforcement-off path selected at runtime (today enforcement-off absence is compile-time: `src/host/abi.rs:7731`, `src/host/mod.rs:4617`; the dual-mode artifact necessarily gives that property up, and no document in the cluster states this shift). (c) The closing trigger — "revisited the first time Ibex executes code it did not author — that event, not a date, is the trigger" — now describes designed, routine behavior of the sanctioned product (an ambient compiled app embedding npm dependencies), and the document does not say whether the trigger excludes LLP 0047's contract or has effectively fired. Each fix is a paragraph, but this document's entire job is recording when the posture stops being acceptable, so the unreconciled register is material.
- [MINOR] Coherence: trip-wire 3 conditions the exception on the standalone application's "help ... mak[ing] the lack of sandboxing explicit", but under the cluster's argv contract the application owns its help surface entirely (the stub reserves only argv[1] `--ibex-capsec`); Ibex controls `ibex compile`'s help/notice, inspection, and release metadata, not the app's help. Restate the condition over surfaces Ibex actually controls (0047 M5 gets this right).
- [MINOR] Correctness: the Context still cites LLP 0036 as "~22k unresolved rows" — 0036's own header now reports 17,179 (Apple) / 17,193 (Windows) unresolved as of 2026-07-27, and LLP 0021's 2026-07-28 lines report 16,628. The qualitative claim (months, no bulk win) survives; the figure is stale in a doc revised 2026-08-01.
- [MINOR] Coherence: "It uses the enforcement-off mechanics" points (via "Mechanically the modes are described in LLP 0038") at mechanics LLP 0038 defines as the compile-time `insecure` feature — the very thing LLP 0047 forbids reusing. The runtime-selectable substrate actually exists (`SecurityMode::Permissive`/`is_allow_all` at `src/host/mod.rs:4600-4605`; unarmed native-gate diagnostic branches), but neither document names it, leaving a reader one plausible step from concluding the release stub compiles with `insecure`.

**LLP 0039 verdict: NOT READY**

### LLP 0047

Verified true before findings: every §2 current-state claim checks out — `IBEX_RELEASE_SFE_CATALOG_DIGEST` is set by nothing in the repo (`src/bin/ibex/sfe.rs:50`, `option_env!` only); release compiled boot deliberately refuses after full admission (`crates/compiled-stub/src/main.rs:277-284`); the compiled-stub crate has genuinely drifted from the carrier admission API — I reproduced the failure: `cargo check -p ibex-compiled-stub` fails with two E0308 errors (main.rs:180, main.rs:424; `BTreeSet<Digest>` vs the new `Arc<BTreeSet<Digest>>` at `src/module_loader/carrier.rs:115` / `src/module_loader/artifact.rs:306`), and the only CI that builds it is the conditionally-run artifact workflow, not ci.yml, so M0.1's "normal workspace/CI check" is the right fix; grammar, envelope, catalog, admission types, and both target contracts exist where claimed. The "admission identical in both modes" claim is achievable with the stub as written: admission (self-file pin, layout validation, envelope, provenance, graph, policy, carriers, candidate tables) all precede the current release-refusal point that M2 replaces with mode dispatch.

- [MATERIAL] Coherence: LLP 0031 — listed in Related as "v1 platform matrix" — still says "If either selected tuple lacks a verified CapSec advertisement at release time, 0.2 waits" (0031:44-46), "Release scheduling is coupled to verified CapSec advertisements for both selected tuples. Missing evidence holds the release" (0031:68-69), and "Single-file executable catalog population follows the same two tuples" with per-tuple required evidence including "complete verified CapSec target advertisement" (0031:40-41,55). §9 here says "CapSec advertisement completion is explicitly not a v1 release criterion." The plan amends 0029 and 0039 explicitly but neither amends 0031 nor acknowledges the conflict; 0031 carries no 2026-08-01 revision. The corpus now contains a Decision that flatly forbids what this Plan schedules. (0031's unadvertised-tuple refusal language — "do not select ... an ambient Hermes build, or an unverified prepared carrier", 0031:48-51 — also needs an explicit scoping statement relative to ambient compiled boot.)
- [MATERIAL] Decision quality/Coherence: the plan never addresses that every compile — including the flagship ambient-default flow — requires an authored, committed, registry-bound `purpose: production, mode: enforce` CapSec policy. LLP 0029 §1 step 2 mandates it and the implementation enforces it (`src/bin/ibex/sfe.rs:145-158` refuses with "run `ibex policy generate --entry ... --target-triple ...` and commit the result"; the envelope structurally requires a singular `ResolvedPolicy` section, `crates/sfe-format/src/lib.rs:1056-1061`; the stub validates it in the shared admission path, main.rs:137-140). So v1's "short, authored scripts" default requires authoring a full CapSec policy artifact that the default mode never enforces. M5's exit ("install one release ibex, compile a short program, copy, run") and M1's exit ("using only the pinned catalog") are written as if this step doesn't exist. Either the plan owns the friction explicitly, or it amends the producer contract (auto-generated minimal policy would contradict 0029's "compiling never generates policy silently") — right now the cluster leaves the flagship flow's biggest product wart undecided and unmentioned.
- [MINOR] Safety: the one-artifact-two-modes decision means every distributed standalone binary contains the complete enforcement-off machinery, and `--ibex-capsec`'s fail-closed guarantee rests on pre-runtime dispatch integrity rather than compile-time absence (the property LLP 0039's secure builds and promotion-evidence rules treat as security-relevant, e.g. feature closures rejecting `insecure`). The design is defensible (enforcement is in-process either way; the selector is one-way, captured pre-runtime, fixture-proven monotonic), but §1's "CapSec remains real when selected" should state the changed trust model in one sentence rather than leaving it implicit.
- [MINOR] Feasibility (implementation-phase, no defective decision): M2's ambient item 3 ("inherited environment ... with ordinary non-sandboxed semantics") interacts with the stub's unconditional pre-init environment scrub (`environment_preinit.c` via `crates/compiled-stub/build.rs:58-107`): the C shim scrubs the real environment before `main`, but the mode is determined by argv[1]. A sound implementation exists (init-array/constructor receives argc/argv on both v1 tuples, so the shim can branch on the selector; or capture-and-restore), but neither M2 nor 0029 §4 names the interaction, and 0029 §4's "sanitize before every constructor under Ibex's control" guarantee for CapSec must survive the dual-mode shim. Worth one sentence.
- [MINOR] Coherence: the Summary's identical-in-both-modes list ("Envelope integrity, graph/carrier admission, HBC compatibility, provenance, and platform layout") omits policy, while M2 ambient item 1 says "policy bytes" and the current shared admission path validates policy content against the compiled-in registry and graph identity (main.rs:527-563). Say explicitly whether ambient boot semantically validates the embedded policy (as today's code does) or only digest-admits it; §9's "envelope/integrity admission is identical across modes" is ambiguous on exactly this point.
- [MINOR] Correctness (wording): §2 lists "compile-plan ... sections"; there is no CompilePlan section kind (`SectionKindV1`, sfe-format/src/lib.rs:597-605) — the plan is a field of the provenance section.

**LLP 0047 verdict: NOT READY**

## Cross-document findings

- [MATERIAL] Linux ambient network is left in a contradictory state. Revised 0029 §2a still keys the omission of fetch/WebSocket to CapSec state ("The current compiled CapSec projection advertises no network authority, so the Linux release-stub profile compiles fetch/WebSocket as unavailable and libcurl is absent"), with the trigger for adding a backend being "a future compiled target that advertises network authority." 0047 makes CapSec advertisement non-binding for the shipped artifact and M4 says v1 "should aim to match the ordinary `standard` runtime feature closure" — which on Linux includes a working libcurl-backed fetch (build.rs:2604-2661 panics without it in the source runtime), while the release-stub profile compiles it out (`EXACT_DISABLE_LINUX_NETWORK`, build.rs:2639-2640) and the audit forbids dynamic libcurl (audit-sfe-linux-deps.sh:120-123). Net effect if nothing changes: the flagship "ambient compatibility" v1 has working fetch on macOS (NSURLSession, `src/engine/native_fetch_macos.mm`) and no network at all on Linux — a cross-tuple asymmetry in the default mode that no document decides, and whose 0029 rationale (advertisement-triggered) is dangling under the ambient default. Either 0047 explicitly ships v1 Linux ambient without network (naming it in M4/M5 and release notes), or it schedules the vendored/static backend 0029 §2a requires — neither is currently written.
- [MATERIAL] LLP 0022's "Compiled-program exception" (0022 ~lines 848-857) categorically describes LLP 0029 executables: earliest-hook capture, sanitized real environment, broker-gated exact reads, and "The exception never exposes the sanitized real environment." Under 0047's default, the majority behavior of compiled executables is precisely to expose the inherited environment with no broker. 0029 §4 re-scoped itself to the CapSec path and cites "the LLP 0022 revision" as carrying the enumeration exception, but 0022 received no corresponding scoping revision and does not mention ambient/0047. A governing Spec the cluster cites now misdescribes the default behavior of the artifacts it governs; the fix is a scoping sentence in 0022 (or an explicit 0047 milestone item to revise it — M0/M2 currently name no 0022 change).
- [MATERIAL] (recorded under LLP 0047 above, restated as the set-level structural issue) The cluster's amendment discipline is incomplete: 0047 amends exactly the two documents it names, but the posture change's blast radius includes LLP 0031 (release coupling) and LLP 0022 (compiled env contract). Given this repo's own rule ("Don't leave stale docs unmarked"), the cluster is not coherent until those two are revised or their supersession is recorded.
- [MINOR] issues/20260717-sfe-program.md still records register item 4 in its 2026-07-18 form ("0.2 waits for verified CapSec advertisements on both selected tuples") — two re-resolutions stale. 0047 M0.4 already owns reconciling the SFE tickets, so this is corroboration for M0.4, not a new gap; noting it so M0.4's sweep includes the umbrella ticket.
- [MINOR] `scripts/run-tests.sh:24-25,174-175` comments claim "LLP 0039 puts `insecure` in the default set" — describing the briefly-inverted 2026-07-24 convention that 0039 and Cargo.toml (line 161-173, `default = ["standard"]`) both say was reverted. The script's behavior matches 0039; its comments contradict it. Code-comment fix, but it is the exact confusion 0039's history warns about.

## Set-level verdict
**CLUSTER: NOT READY**

## Round 6 — 2026-08-01 (cluster loop round 2, DELTA ROUND)

**Date:** 2026-08-01
**Round type:** delta round (LLP 0010 §2 addendum). Instructions enumerated the
revision and required every concern classified IN-DELTA vs PRE-EXISTING.
**Revision reviewed:** 0029 `38f724c799948380d0be5c344e64bb2b06e39e70`, 0039
`975c98a4fa77e262e8c4b53bd5a7dd25b8333606`, 0047
`893ea5732c7283816f2f90869c0e7349537ed001`; collateral (non-target, coherence
scope only) 0031 `9261864bb5a9097a7bc3f26e1026a46b05d31207`, 0022
`7a5be6b9398746f278fb0003ce5786ac8f48bd8b`. Revision uncommitted, so `git diff
llp/` was the delta.
**Brief:** `brief-r2.md`
**Redacted:** no (repository content only; no secrets present)
**Blindness:** structural — all six cluster review artifacts moved out of the
working tree for the round's duration; each family's response held in an
out-of-repo scratchpad until both landed.
**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context
**Verdicts:** LLP 0029 **READY** · LLP 0039 **READY** · LLP 0047 NOT READY · **CLUSTER NOT READY**

### Review (verbatim)

## Per-target findings

### LLP 0029

- [MINOR] [IN-DELTA] correctness: The rewritten computed-`require` sentence now mischaracterizes LLP 0028's register state. llp/0029-single-file-executable-packaging.rfc.md:322-324 says LLP 0028 "*registers* computed `require` as a live 0.2 author decision with a named reopening design rather than refusing it permanently," but LLP 0028 marks that decision closed: "**Resolved 2026-07-18:** 0.2 keeps this fail-closed disposition; it does not add computed-`require` candidate rows" (llp/0028-oxc-only-transform-and-swc-retirement.rfc.md:362-363, and its header at lines 11-13 lists it among made author decisions). The revision correctly deleted the "permanently invocation-refused" half of the old self-contradiction but kept the wrong other half: the accurate state is "resolved for 0.2, with a named reopening path," not "live." The downstream consequence stated (candidate rows carried with no format change if reopening lands) is unaffected.
- [MINOR] [PRE-EXISTING] coherence: §4's ambient-admission enumeration omits the policy section that LLP 0047's delta now emphasizes ambient boot must semantically admit. llp/0029:702-704 ("it skips policy enforcement but still admits the self-file layout, envelope, graph, HBC carriers, compile plan, and provenance") and the Goals restatement at llp/0029:179-181 both enumerate ambient admission without the policy section, while llp/0047:44-51 and llp/0047:305-314 make embedded-policy semantic admission an explicit both-modes requirement (and the code already does it: crates/compiled-stub/src/main.rs:137-140, 527-563). Not a contradiction — "skips policy enforcement" ≠ skips policy admission — but the enumeration now lags the requirement the revision added next door.

Everything else I checked in this document's delta verified against source: the graph-snapshot domain exists and is producer-consumed (crates/capsec-semantics/src/graph_snapshot.rs:16-22; src/module_loader/embedded_graph.rs:10; src/bin/ibex/sfe.rs:166); `HermesBytecodeMetadataV1::inspect` derives version/length from emitted bytes (src/module_loader/carrier.rs:49-66); `ExpectedEmbeddedProtectedArtifact` exists (crates/capsec-semantics/src/arming.rs:277) and LLP 0021 records arming ABI v2 with embedded protected ranges (llp/0021:159); the 0-enforced/7528-unsupported host-tuple count is exact (capsec/generated/target-matrix.md:5,9); the third `inspect-executable` state is stated at exactly its implemented strength — presence-only, "unverified", no publisher trust policy, no stub-core rehash (src/bin/ibex/sfe.rs:501-513, and no rehash anywhere in `inspect`); the argv status is date-scoped correctly — every argument passes through, no reserved selector (crates/compiled-stub/src/process.rs:1-61, including the `reserved_ibex_spellings_remain_application_arguments` test); the "Proposed amendment (not implemented)" relabel matches the code (unconditional post-admission release refusal at crates/compiled-stub/src/main.rs:277-284); the flagless `hermesc` recipe is real (crates/sfe-format/src/lib.rs:318-328), LLP 0034:76 requires the flag, the recipe digest is inside `ibex:hermesc-compatibility:1` (lib.rs:22, 300-301, 405) so the coordinated-bump claim is right, and the issue file exists.

**LLP 0029 verdict: READY**

### LLP 0039

- [MINOR] [IN-DELTA] correctness: "**As of LLP 0047 the trigger has fired, deliberately**" (llp/0039:308-312) asserts a past event that has not occurred. The trigger is defined as an execution event ("the first time Ibex executes code it did not author"), and no ambient standalone executable can exist today: `ibex compile` refuses without a compiled-in catalog digest (no repository build sets `IBEX_RELEASE_SFE_CATALOG_DIGEST` — only src/bin/ibex/sfe.rs references it) and the stub refuses every release envelope (crates/compiled-stub/src/main.rs:277-284). What has actually happened is that a reviewed design commits to firing it. The substantive move — converting the trigger to cover only undeliberate instances — is sound and is itself the re-evaluation the trigger demands, but a document whose round-1 theme was sweeping false present-tense claims should not assert one.
- [MINOR] [IN-DELTA] correctness: The new preamble claims "each wire is stated over *enforcement-off execution* generally" (llp/0039:127-128), but wire 5 remains keyed on the Cargo feature only (llp/0039:160-162). The deviation is reasoned inside wire 5 itself (deliberate ambient shipping is item 3's product), so no reader is endangered, but the "each wire" generalization is literally false for one of the five.
- [MINOR] [IN-DELTA] coherence: Trip-wire 3's cross-reference "LLP 0047 §8 item 4" (llp/0039:151) resolves correctly only through markdown renumbering, because LLP 0047 §8 contains two items literally numbered "4." (see LLP 0047 findings). Fix belongs in 0047.

The load-bearing corrections all verified: `insecure` is genuinely not a default feature (`default = ["standard"]`, Cargo.toml; scripts/check-secure-mode.sh:4 agrees), the armed observer batches carry both `#[cfg(not(feature = "insecure"))]` and the `capsec-conformance-observer` feature gate (e.g., src/bin/ibex/engine/hermes.rs:9422-9424), so the inverted-`cfg` correction is right and the old text was indeed backwards; the row figures match their sources exactly (LLP 0036:8 — 17,179/17,193 unresolved ≈ "~17.2k per tuple"; LLP 0021:8 — 16,628 Apple); the mechanical distinction holds — a runtime-permissive host posture exists ungated (`Host::default_legacy()` / `SecurityMode::Permissive`, src/host/mod.rs:4563-4568); and the accidental-vs-deliberate guard section's claim that a feature-keyed guard permits the ambient product without a carve-out is logically consistent with "a release stub must never be built with `insecure`."

**LLP 0039 verdict: READY**

### LLP 0047

- [MATERIAL] [IN-DELTA] decision quality / coherence: The new §12 register mis-scopes the blocking effect of its most consequential item. The preamble says "Items 1 and 2 block the §9 release criteria; items 3 and 4 block claiming the disclosure posture is adequate" (llp/0047:552-553), but item 3 is the ambient-eligibility question — "Whether ambient-by-default should be the v1 default at all… This is the decision the whole plan rests on; it is registered rather than assumed" (llp/0047:565-569; also llp/0047:133-134). An item that decides whether the default posture ships at all cannot coherently gate only a disclosure-adequacy claim, and §9 (llp/0047:473-497) contains no item-3 criterion — so as written, v1 can satisfy every release criterion while the plan's foundational decision is recorded as open. Either item 3 blocks §9 (say so), or the plan's §1 stands as the provisional resolution that item 3 ratifies before release (say that, and drop "registered rather than assumed"). The current text supports both readings and therefore neither.
- [MINOR] [IN-DELTA] correctness: §8 has two items literally numbered "4." — "Close the recipient's disclosure gap" (llp/0047:443) and "Produce a signed macOS artifact" (llp/0047:463), with the following item still numbered "5." (llp/0047:465). Rendered markdown renumbers so the "§8 item 4" cross-references (llp/0047:460-461, 539-540; llp/0039:151) happen to resolve to the disclosure item, but the raw source is mislabeled from item 5 onward.
- [MINOR] [IN-DELTA] correctness: The Related header points the collateral amendments at the wrong section: "compiled-program exception scoped by §1" and "SFE release coupling amended by §1" (llp/0047:16-18). The amendments are owned and described by the Summary's "What this plan amends" subsection (llp/0047:53-78) and milestone 0 item 5 (llp/0047:210-214), not §1.
- [MINOR] [IN-DELTA] coherence: §12 says item 1 "block[s] the §9 release criteria" (llp/0047:552), but §9's list carries no criterion for the mandatory-policy friction — unlike item 2, which got an explicit §9 row ("the Linux ambient network disposition is resolved…", llp/0047:492-493). The register and the criteria list should agree about what gates release.
- [MINOR] [IN-DELTA] coherence: New §4 item 6 chooses "milestone 2's dispatch lands before the first catalog is cut" (llp/0047:237-243), which inverts the milestone 1 → 2 ordering, while milestone 1's exit text still reads as completing first on "the pinned catalog" (llp/0047:267-270) and milestone 2's own exit needs a built executable, which packaging can only produce from catalog artifacts (LLP 0029 §2a) — i.e., via the developer-only escape hatch milestone 1 exists to remove. The sequencing decision is sound; the milestone structure and exits were not adjusted to match it.
- [MINOR] [IN-DELTA] feasibility: The pre-init selector design (llp/0047:317-330) is verified feasible — the shim really does capture-then-unconditionally-scrub before Rust `main` (crates/compiled-stub/src/environment_preinit.c:48-125), and glibc/dyld do pass `argc`/`argv` to preinit/constructor entries on both v1 tuples (the current entry just declares a void signature, c:122-124, 117-118). But the design now implies two argv-derived mode determinations — the pre-init C read that decides whether to scrub, and the boot-time dispatch — and the plan requires constructor-ordering probes without requiring that the pre-init determination be the single authoritative mode source. A divergence (e.g., differing byte-comparison vs Unicode-decode rules on argv[1]) would reproduce exactly the constructor-observes-wrong-environment bug the section analyzes. Implementation-phase material; no defective decision.

All new factual claims verified against source: `StubContractV1`'s fields are exactly as stated with no boot-mode/selector/CapSec-evidence field (crates/sfe-format/src/lib.rs:136-149); the compile plan is a provenance field, not a section kind (lib.rs:100-103, 597-606); the shared admission path performs semantic policy validation against the compiled-in registry and graph identity before the refusal point (crates/compiled-stub/src/main.rs:137-140, 277-284, 527-563); every compile requires a committed `purpose: production, mode: enforce` policy with the exact `ibex policy generate` refusal (capsec-semantics/src/policy.rs:198-199; src/bin/ibex/sfe.rs:149-151) and the envelope requires a singular resolved-policy section (sfe-format/src/lib.rs:1053-1064); the Linux release-stub profile compiles fetch/WebSocket out (`EXACT_DISABLE_LINUX_NETWORK`, build.rs:2640-2641) with libcurl absence ELF-audited (scripts/audit-sfe-linux-deps.sh:120-121) while macOS fetch is NSURLSession-backed (build.rs:2371); the compiled-stub drift is real — I reproduced the compile failure (two E0308s: `authorized_semantic_digests` now `Arc<BTreeSet<Digest>>`, crates/compiled-stub/src/main.rs:180, 424); the umbrella ticket really is two re-resolutions stale (issues/20260717-sfe-program.md:51); SIGHUP really is in LLP 0029 §6's rows (llp/0029:929-930); and catalog entries bind the stub-core digest while the release binary pins the catalog digest, so the §4-item-6 rotation chain is correct.

**LLP 0047 verdict: NOT READY**

## Cross-document findings

- [MATERIAL] [IN-DELTA] coherence (same root cause as the §12 item-3 finding): the cluster is now ambiguous about whether ambient-by-default is decided. LLP 0029 §7 item 4 records it "**re-resolved 2026-08-01 by LLP 0047**" (llp/0029:1009-1011, pre-existing); LLP 0031's new scoping note enacts it in the indicative ("They no longer gate the standalone executable", llp/0031:63-70); LLP 0039 calls it "the reviewed product contract" (llp/0039:284-287) and says the foreign-code trigger "has fired" on its strength; yet LLP 0047 §12 item 3 says the same decision is "registered rather than assumed." Four documents treat it as made; the plan's own register says it is open. Resolving the §12 finding one way or the other resolves this too — but until then the corpus states as settled what the plan's register calls its most open question.
- [MINOR] [IN-DELTA] coherence: LLP 0022's scoping note asserts the ambient path has "no capture, no sanitization, and no broker" (llp/0022:855-858), which is stronger than LLP 0047's actual requirement — that "the shim scrubs only on the CapSec path" (llp/0047:324-326), leaving capture unspecified for ambient. If the implementation keeps unconditional capture and makes only the scrub conditional (the simplest reading of §5), the Spec's "no capture" is false as written. The two documents should specify the same strength.
- [MINOR] [IN-DELTA] coherence: LLP 0031's scoped sentence — "'complete verified CapSec target advertisement' is not among the evidence required to populate a cell for the ambient path" (llp/0031:71-73) — implies path-scoped catalog cells, but under LLP 0047 §5 there is one catalog entry per target serving one dual-mode artifact; advertisement gates claiming the CapSec mode works, not a separate ambient cell. Meaning is recoverable; wording invents a structure the format doesn't have. (Collateral doc — coherence scope only, per the brief.)
- [MINOR] [IN-DELTA] coherence: LLP 0047's eligibility boundary declares itself "narrower than LLP 0029's framing of the feature as suiting 'any Ibex program' and agent-facing tools generally" (llp/0047:127-129) — accurately quoting llp/0029:109-119 — but LLP 0029 was not edited to point at the boundary, even though this revision otherwise swept 0029 and the plan owns 0029's amendments. If the boundary survives register item 3, 0029's Summary framing needs the same scoping note; today only 0047 carries the narrowing.

The claimed collateral edits do land what the plan says: LLP 0031's quoted coupling text is verbatim-accurate ("If either selected tuple lacks a verified CapSec advertisement at release time, 0.2 waits", llp/0031:47-49; "do not select … an ambient Hermes build, or an unverified prepared carrier", llp/0031:53-54), the scoping preserves source-execution coupling as promised, and no other LLP still asserts the superseded SFE advertisement-first gate (llp/0028's "0.2 waits" is the distinct window-close gate). `./ref-check` passes on the revised tree (0 errors).

## Delta assessment

The revision introduced one new MATERIAL defect: the §12 register's blocking classification for item 3 contradicts the item's own content and §9, with a cluster-wide echo (0029 "re-resolved" / 0031 enacted / 0039 "reviewed product contract" vs. 0047 "registered rather than assumed") that leaves the plan's foundational decision simultaneously recorded as made and as open. It is a one-to-two-sentence fix, but it sits on the load-bearing decision.

No MATERIAL concern remains in PRE-EXISTING text that I could find. Every pre-existing repository claim I probed held up, and — notably — the revision's new factual claims are uniformly accurate: I verified the StubContractV1 field inventory, the compile-plan/provenance correction, the unconditional pre-init scrub, the pre-refusal semantic policy admission, the mandatory production-policy refusal, the singular-policy envelope requirement, the Linux network compile-out and ELF audit, the NSURLSession macOS fetch, the compiled-stub API drift (reproduced the build failure), the 7528/17.2k/16,628 figures, the flagless hermesc recipe and its digest-rotation chain, the observer-test double-gating behind the corrected `cfg` explanation, and the ticket-staleness claims. The round-1 symptoms this revision claims to have fixed are genuinely fixed; the residual defects are the register-scope incoherence above plus a handful of minor precision/numbering items ("live 0.2 author decision", "the trigger has fired", duplicate §8 item numbers, "§1" pointers, the 0022 "no capture" overstatement).

## Set-level verdict
**CLUSTER: NOT READY**

## Round 7 — 2026-08-01 (cluster loop round 3, SECOND DELTA ROUND — final round of budget)

**Date:** 2026-08-01
**Round type:** delta round. Narrowly scoped to verifying the two round-2
in-delta MATERIAL fixes; every concern classified IN-DELTA vs PRE-EXISTING.
**Revision reviewed:** 0029 `42f8f3681e224a4b621491f1c492c3bab5fd90f9`, 0039
`5d81b99b66efa42f8a75d094fed669d12ae377a0`, 0047
`a2d26a3d6b76fcec59395ef3de06f57684af3530`; collateral (non-target) 0031
`c2cd43f1845de50945d716fa30cd49a4f4351778`, 0022
`89994ffa74f012517bee379ce9f5c07b671f0a9c`.
**Brief:** `brief-r3.md`
**Redacted:** no (repository content only; no secrets present)
**Blindness:** structural — all six cluster review artifacts moved out of the
working tree for the round's duration; each family's response held in an
out-of-repo scratchpad until both landed.
**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context
**Verdicts:** LLP 0029 **READY** · LLP 0039 **READY** · LLP 0047 **READY** · **CLUSTER READY**

### Review (verbatim)

## Per-target findings

### LLP 0029

No findings. Every round-3 delta claim verified against source: the computed-`require` restatement matches LLP 0028's register verbatim (llp/0028-oxc-only-transform-and-swc-retirement.rfc.md, "Resolved 2026-07-18: 0.2 keeps this fail-closed disposition; it does not add computed-`require` candidate rows", with the sidecar/JSON-channel reopening path named); recipe-identity enforcement correctly re-attributed — carrier admission checks only engine binding and inspected HBC version (/Users/ccheever/projects/ibex/src/module_loader/carrier.rs:106-118) while the recipe digest lives in `HermescRecipeV1`/`HermescCompatibilityV1` on the catalog/compiler side (/Users/ccheever/projects/ibex/crates/sfe-format/src/lib.rs:300-345), and the current fixed recipe is still flagless (lib.rs:316-329), consistent with scheduling the `-Xes6-block-scoping` bump as LLP 0047 milestone-0 work rather than claiming it landed; the ambient admission enumeration including embedded-policy semantic validation matches the stub (`admit_policy` binds the compiled-in registry digests and refuses a policy bound to a different graph identity, /Users/ccheever/projects/ibex/crates/compiled-stub/src/main.rs:137-140, 527-560); the graph-snapshot open question is correctly closed (/Users/ccheever/projects/ibex/crates/capsec-semantics/src/graph_snapshot.rs exists); the cell count is exact (0 enforced / 7528 unsupported for `aarch64-apple-darwin`, /Users/ccheever/projects/ibex/capsec/generated/target-matrix.md:5,9); the inspector third-state description is accurate (present → `"unverified"`, absent → `"absent"`, no stub-core rehash, /Users/ccheever/projects/ibex/src/bin/ibex/sfe.rs:501-513); and the argv-current-state paragraph matches the stub, which passes every argument through including Ibex spellings with index-named Unicode refusal (/Users/ccheever/projects/ibex/crates/compiled-stub/src/process.rs:1-61, test at :68-81) while the release refusal remains unconditional after admission (main.rs:277-284).

**LLP 0029 verdict: READY**

### LLP 0039

- [MINOR] [IN-DELTA] coherence: the new preamble says the wires generalize to enforcement-off execution "except wire 5, which stays feature-specific for the reason given there" (llp/0039-secure-and-insecure-modes.decision.md:138-140), but wire 5 (:170-172) states only the distinction ("Distinct from, and not excused by, deliberately shipping ambient standalone artifacts under item 3"), leaving the actual reason — a posture-general wire 5 would fire on every deliberate item-3 product ship — to inference. One clause would discharge the preamble's promise explicitly.

The load-bearing delta claims are confirmed against source: `Host::new_armed` compiles unconditionally (/Users/ccheever/projects/ibex/src/host/mod.rs:723, no cfg attribute) while `new_armed_insecure` is `#[cfg(feature = "insecure")]` (:693-695) and is what an insecure build selects (/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:3700, 5588 vs :3706, 5593-5596), with the permissive gates written as `cfg!`-folded branches present in every compilation (host/mod.rs:4617-4623 et seq.) — so "no runtime-selectable enforcement-off route, not literal absence of enforcement-off code" is the accurate strength. The corrected `cfg` explanation is definitionally right (`not(insecure)` includes the batches in a default build; the observer feature is the exclusion mechanism, and the batch files spell `standard,capsec-conformance-observer,openssl-crypto`). The foreign-code-trigger restatement's two supporting facts hold: no build sets the catalog digest (`option_env!("IBEX_RELEASE_SFE_CATALOG_DIGEST")`, sfe.rs:50; nothing in scripts/.github sets it) and the stub refuses every release envelope (main.rs:277-284), so "committed to by a reviewed design, not yet fired" is the honest state. The Context figures match their sources (LLP 0036 rev 2026-07-27: 17,179/17,193 unresolved ≈ "~17.2k per tuple"; LLP 0021 rev 2026-07-28: 16,628).

**LLP 0039 verdict: READY**

### LLP 0047

- [MINOR] [IN-DELTA] coherence: §5's `StubContractV2` bullet ends "it must happen in lockstep before the first catalog is cut" (llp/0047-standalone-executable-finish-line.plan.md:317-318), but §4 item 6 (:252-254) and the §5 exit (:393-395) establish that the first catalog *is* cut on `StubContractV1` (provisional, §4 item 1 at :238-239) and re-cut on V2 at milestone-2 exit — the ordering "first catalog" naively reads as forbidding is the one §4.6 explicitly adopts, and §4's own title calls the provisional cut "a real release catalog." The decision itself is unambiguous (stated three times); qualify the phrase ("before the first non-provisional catalog is cut" or "before any catalog ships to users") so the two sections cannot be read against each other.
- [MINOR] [IN-DELTA] coherence: the embedded-contract change is described as "an envelope schema revision (a new `SectionKindV1` variant)" (:327-329) without saying whether `ibex/single-file-executable/1` rotates. The same strict-schema rule the plan invokes to force `StubContractV2` arguably reaches the envelope's section-kind vocabulary (old parsers reject unknown kinds); "no catalog has shipped" makes in-place V1 extension as defensible as V1 replacement, but the plan applies the naming rigor to one contract and not the other. State which it is.

The two round-2 fixes themselves verify. Fix 1: `SectionKindV1` has exactly seven variants with no contract (and no compile-plan) section (/Users/ccheever/projects/ibex/crates/sfe-format/src/lib.rs:597-605), matching §2's corrected current-state list (`CompilePlanV1` is a field of `PackageProvenanceV1`, lib.rs:100-108); `StubContractV1` is strict `deny_unknown_fields` with fixed `ibex/stub-contract/1` / `ibex:stub-contract:1` (lib.rs:17-18, 134-149) and carries no boot-mode, selector, or advertisement-identity field, so the V2 requirement and the none-carries-the-mode premise are both true; the pinned digest the new section admits against exists (`envelope.directory.stub_contract_digest`, sfe.rs:522); and the digest-reveals-nothing reasoning is sound — the only contract bytes in today's file are an unaddressable `include_bytes!` blob in stub rodata (main.rs:385), exactly the "undocumented stub behavior" §5 rules out trusting. Fix 2's feasibility premise also verifies: the pre-init shim captures then unconditionally scrubs before Rust `main` (/Users/ccheever/projects/ibex/crates/compiled-stub/src/environment_preinit.c:48-125), and the constructor entry can receive argv on both v1 tuples — glibc's `_dl_init` invokes `.preinit_array`/`.init_array` entries with `(argc, argv, env)` (the shim already sits in `.preinit_array`, :122-125), and macOS dyld invokes Mach-O initializers with `(argc, argv, envp, apple, vars)`, with `crt_externs.h` (`_NSGetArgc`/`_NSGetArgv`) — a public header the shim already includes (:9) — available as an equivalent route. §4's mandatory-policy claims verify (`ResolvedPolicy` is a preflight singleton, lib.rs:1018-1060; the producer's diagnostic names `ibex policy generate ... and commit the result`, sfe.rs:151), as does §3 item 4's ticket-staleness claim (issues/20260717-sfe-program.md:51 still carries the 2026-07-18 form) and §2's drift claim (the stub builds a plain `BTreeSet` where current admission takes `Arc<BTreeSet<Digest>>`, carrier.rs:115 vs main.rs:142-148, 180).

**LLP 0047 verdict: READY**

## Cross-document findings

- None material. The four-document amendment web is closed and mutually consistent: LLP 0031's scoping note quotes its own coupling text accurately (llp/0031:47-48) and its ambient-Hermes/unverified-carrier argument is correct (compiled boot uses the catalog-pinned static engine and envelope-admitted digest-bound carriers); LLP 0022's splice reads coherently and its "capture left open, scrub CapSec-conditional" parenthetical matches what LLP 0047 §5 actually requires; LLP 0029 §7 item 4, LLP 0039's trip-wire 3 / accidental-ship section, and LLP 0047 §12 item 3 now agree the ambient-by-default decision is made, with one pre-release ratification checkpoint and a named narrow-scope fallback. Observation, not a defect: milestone-0 item 5's "Done (2026-08-01)" is true only of this uncommitted revision — the five files must land in one commit or the claim briefly outruns the corpus.

## Delta assessment

Both round-2 MATERIAL defects are correctly fixed. The boot-mode mechanism is now implementable: naming `StubContractV2` follows from the verified strict `deny_unknown_fields` V1 with a fixed schema string, and embedding the canonical contract bytes as a new digest-checked envelope section — genuinely a new `SectionKindV1` variant, since none of the seven existing variants covers it — is what lets inspection read *and* authenticate the mode from the file alone, with the pin already present in the envelope directory. The register mis-scope is resolved: §12's preamble makes items 1-3 blocking with matching §9 criteria (all three present), and item 3 is restated as pre-release ratification of a decision §1 explicitly makes, which the other four documents' treatment now matches rather than contradicts. The revision's four flagged source claims all confirm: `SectionKindV1`'s variants, `StubContractV1`'s strictness, the unconditional armed constructor with `insecure` selecting a different one, and pre-init argv availability on both v1 tuples. No new MATERIAL defect was introduced — the three findings above are wording-level (two in LLP 0047's new catalog-sequencing/schema-revision text, one in LLP 0039's new wire preamble), none identifying a defective decision. No MATERIAL concern was found in PRE-EXISTING text; every pre-existing factual claim spot-checked en route (matrix counts, unresolved-row figures, drift, refusal point, argv passthrough, inspector states) verified accurate.

## Set-level verdict
**CLUSTER: READY**

---

## Loop close-out — 2026-08-01 (cluster 0029 + 0039 + 0047)

**Terminal state: round budget exhausted (3/3), escalated to the author.**
Not convergence-by-dual-READY, and not a detail-horizon stop.

### What the final verdicts bind to

Round-3 verdicts bind to these revision hashes:

| doc | reviewed revision | Fable | Codex |
|---|---|---|---|
| LLP 0029 | `42f8f3681e224a4b621491f1c492c3bab5fd90f9` | READY | NOT READY |
| LLP 0039 | `5d81b99b66efa42f8a75d094fed669d12ae377a0` | READY | READY |
| LLP 0047 | `a2d26a3d6b76fcec59395ef3de06f57684af3530` | READY | NOT READY |
| cluster | — | **READY** | **NOT READY** |

**A later, UNREVIEWED revision exists.** After round 3 closed, the orchestrator
applied one more revision addressing every round-3 finding from both families.
No round was run against it and none was fabricated. Its hashes:

- LLP 0029 `f2e1a69db85cf068852ecd6f60e6e0028577b5b9`
- LLP 0039 `398fe7fab4dac708615aaf18e4048174f6afbb51`
- LLP 0047 `c08cb90e90726ef470c0af404404b6fb20931c3f`
- collateral, unchanged since round 3: LLP 0031
  `c2cd43f1845de50945d716fa30cd49a4f4351778`, LLP 0022
  `89994ffa74f012517bee379ce9f5c07b671f0a9c`

### Verdict history

| round | type | Fable | Codex |
|---|---|---|---|
| 1 (r5 of 0029's history) | full | NOT READY ×3 | NOT READY ×3 |
| 2 (r6) | delta | 0029 READY · 0039 READY · 0047 NOT READY | 0029 READY · 0039 READY · 0047 NOT READY |
| 3 (r7) | delta | **all three READY** | 0029 NOT READY · 0039 READY · 0047 NOT READY |

### Delta-convergence status

The LLP 0010 §2 addendum criterion — *no family reports a MATERIAL concern in
pre-existing text* — was **met in both round 2 and round 3**. Every MATERIAL
concern raised after round 1 was IN-DELTA: defects the loop's own revisions
introduced, which is the documented hazard delta rounds exist to catch. The
documents' pre-existing substance was not found materially defective by either
family in two consecutive rounds.

The loop did not close on dual-READY because each revision introduced fresh
in-delta defects — round 1→2 introduced two (an unimplementable boot-mode
authentication mechanism; a register that mis-scoped its own load-bearing
item), and round 2→3 introduced version-propagation gaps. Both sets were
corrected; the second correction is the unreviewed revision above.

### Round-3 disposition ledger (nothing summarized away)

Codex MATERIAL (all IN-DELTA), and their disposition in the unreviewed revision:

1. *LLP 0029 still normative on `StubContractV1` and an envelope without the
   contract section.* **Fixed** — §2 gains a wire-identity rotation note naming
   `StubContractV2` and `ibex/single-file-executable/2`.
2. *§5's "before the first catalog is cut" contradicts §4 item 6's provisional
   catalog.* **Fixed** — qualified to the first *non-provisional* catalog, with
   the provisional V1 cut explicitly permitted. (Fable raised the same point as
   MINOR.)
3. *Refusing to extend strict `StubContractV1` in place while proposing a new
   `SectionKindV1` variant applies the rule inconsistently.* **Fixed** — the
   envelope rotates to V2 on the same reasoning, stated as replacement rather
   than migration since nothing has shipped. (Fable raised the same point as
   MINOR: "state which it is.")
4. *LLP 0047's amendment inventory omits that it changes 0029's contract and
   envelope architecture.* **Fixed** — the inventory records both rotations.

Fable MINOR, and disposition:

5. *Trip-wire 5's preamble exception is asserted without its reason.* **Fixed**
   — wire 5 now states why it stays keyed to the Cargo feature.
6. *Milestone 0 item 5's "Done (2026-08-01)" is true only of the uncommitted
   revision.* **Fixed** — restated as landing with this plan's own commit, with
   an explicit all-five-files-together requirement.

Fable's two LLP 0047 MINORs are items 2 and 3 above, fixed identically.

### Divergence note

Round 3's split is a **severity disagreement, not a factual contradiction**.
Both families identified the same catalog-sequencing and envelope-versioning
gaps from the same source evidence; Fable classified them as wording-level with
the underlying decision unambiguous, Codex as material wire-identity
incoherence. Codex additionally caught the LLP 0029 propagation gap that Fable
missed. Neither family's factual claims were contradicted by the other, and the
orchestrator independently verified the load-bearing ones against source.

### Bounds

- **Round budget:** 3/3 consumed. This is the terminal trigger.
- **Launch cap:** 3 launches per family per target of an available 6. Not
  reached. No voided rounds; no failed or malformed responses.
- **Growth budget:** entering 1584 lines, ~20% ceiling 1901, final **2102
  (+32.7%)** — **over budget**, concentrated in LLP 0047 (313 → 656). Two
  compression passes were applied. The overage is reported rather than resolved
  by cutting findings-driven content; it is the author's call whether the
  additions earn their length.

### Author decision required

Both terminal bounds (round budget; growth budget with MATERIAL concerns open
at round 3's close) require escalation. The documents remain `Status: Review` —
the loop applied that transition at start and never sets `Accepted`. Options
put to the author: keep `Review`, revert to `Draft`, or authorize one
out-of-budget delta round against the unreviewed revision.

### Concurrent-session note (disclosed)

While this loop ran, LLP 0047 milestone-0 implementation work appeared in the
working tree: the compiled-stub `Arc<BTreeSet<Digest>>` drift repair (M0.1),
`-Xes6-block-scoping` added to `HermescRecipeV1::production()` plus a
closure-capturing `for-of` execution fixture (M0.2), a
`scripts/check-sfe-foundation.sh` gate wired into
`.github/workflows/module-loader-baselines.yml` (M0.3), and subsequently
catalog/contract/generated-artifact and issue-ticket changes (M0.4).

The orchestrator initially misattributed these to a reviewer subagent and
reverted them. That was wrong: a **separate, concurrent `codex` session of the
author's** was running in this same checkout with write access (started
2026-08-01 19:58, unsandboxed, cwd `/Users/ccheever/projects/ibex`), and the
work is that session's. **The revert was undone and every change restored** from
a preserved patch, verified to re-apply cleanly. No implementation work was lost.

None of it is part of this loop's output, and none of it was committed by this
loop — the acceptance commit contains only the five LLP documents and the six
review artifacts.

**Findings integrity: unaffected.** All three rounds' findings describe the
unmodified tree. Rounds 1 and 2 both reproduced the compiled-stub build failure
as still present; round 3's Fable review states "the current fixed recipe is
still flagless," so its reading preceded its own edits. Codex ran under a
read-only sandbox in every round and could not modify anything; none of its
round-3 findings depend on the touched files' contents. No verdict in this
artifact was formed against a mutated repository.

### Author decision — applied 2026-08-01

The author (Charlie Cheever) reviewed this close-out and set **all three
targets to `Status: Accepted`**. Recorded here for provenance:

- Acceptance was applied by the author, not by the loop. This skill never sets
  `Accepted`; it escalated with the ledger above and the author decided.
- Acceptance binds to the **unreviewed** post-round-3 revision — LLP 0029
  `f2e1a69db85cf068852ecd6f60e6e0028577b5b9`, LLP 0039
  `398fe7fab4dac708615aaf18e4048174f6afbb51`, LLP 0047
  `c08cb90e90726ef470c0af404404b6fb20931c3f` — not to the round-3 revision the
  final verdicts bind to. The delta between them is the six round-3 findings'
  fixes, enumerated in the disposition ledger above.
- The collateral documents LLP 0031 and LLP 0022 were **not** targets of this
  loop and remain `Status: Draft`; only their scoping edits landed.
- The open author-decision registers stay open: LLP 0029 §7 items 1, 2, 3, 6,
  7, 8 and LLP 0047 §12 items 1–4. Acceptance of the documents is not
  resolution of the decisions they register — LLP 0047 §12 items 1–3 still
  block its own §9 release criteria.

## 2026-08-03 external-script correction cluster

The app-bound amendment at git-blob
`ad717b9578a650577be4b6177243126f56edb167` was reviewed in the LLP 0048
cluster. The complete Fable-family bodies and provenance are recorded once in
`0048-external-script-admission-and-broker.fable.md`, Rounds 1–4. The final
full-cluster and delta verdicts were **READY** with no remaining MATERIAL or
MINOR findings. The amendment preserves the one trusted embedded entry while
placing caller-selected source in the separate restricted-worker lane and
mirrors the complete app-bound format/evidence rotations.
