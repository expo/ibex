# Reviews of LLP 0023 — Virtual Filesystem Namespace and Path Identity (Codex family)

Review artifacts for `llp/0023-virtual-filesystem-namespace.spec.md`, recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, invoked as
  `codex exec` (non-interactive), sandbox `read-only`, workdir
  `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`
- **Reasoning effort:** `ultra` (`-c model_reasoning_effort="ultra"`)
- **Session id:** `019f5595-6e6c-7c02-8b54-f57996c74b10`
- **Date:** 2026-07-12
- **Revision under review:** `0d55849a9f5e`
  (`shasum -a 256 llp/0023-virtual-filesystem-namespace.spec.md | cut -c1-12`)
- **Redacted:** No. The repository and document were read under the user's own
  OpenAI account, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session with no access to the
  orchestrating session, no access to the concurrent Fable review of the same
  revision, and no access to any prior LLP 0023 review artifact (none existed —
  this is round 1). Instructed not to read `llp/reviews/`.
- **Method:** cli-runner, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round1.md`) — the same brief given
  to the Fable reviewer. Brief supplied the target, the sibling corpus
  (0022/0024/0025) as normative context, the governing LLPs (0021/0013/0014/0004),
  a required code-verification list, the LLP 0005 standard questions, and a fixed
  output structure ending in an explicit verdict line.
- **Run note (recorded for honesty):** the first Codex attempt for this round was
  terminated by **orchestrator error** — a broad `pkill` issued from the
  supervising session on a mistaken diagnosis that the process had died. It was
  not a reviewer failure, not a timeout, and not a usage limit. The review below
  is from a re-launch with the **identical brief** against the **identical
  revision** (`0d55849a9f5e`), and is a first-attempt, complete, independent
  review of that revision. No partial output from the killed attempt was read,
  retained, or incorporated.

### Verbatim review

</content>
1. **Overall assessment**

LLP 0023 has the right architectural objective. A native virtual namespace, caller-relative authorization, retained-object validation, and a surface-wide prohibition on host-path disclosure are necessary for armed Ibex. The current implementation strongly confirms the motivating failures.

As a normative Spec, however, revision `0d55849a9f5e` is not ready. Several load-bearing requirements are internally contradictory, unsafe, or not implementable through the stated ABI:

- A single root-owned cwd necessarily changes package resolution, contrary to §5.
- The universal authorization tuple requires a target object before that object can exist or be discovered.
- Object-only module identity can collapse distinct package compartments and does not cover bundled, builtin, or synthetic modules.
- The process-global Host ABI cannot provide the promised per-runtime isolation.
- Encoded-dot refusal cannot work for ordinary normalized `URL` objects.
- Symlink creation and “link or parent” retention leave security and race holes.
- Registry rows, error enums, platform aliases, synthetic-node behavior, and generated observable metadata are not specified precisely enough to implement or test.

I read the complete target and required LLP corpus, checked the requested source and generated artifacts, and did not read `llp/reviews/` or modify files.

2. **Strengths** (with section citations)

- The motivation is accurate and concrete. Armed cwd currently disappears, `process.cwd()` falls back to `/`, and `fs` resolves relative paths against it ([LLP 0023 Motivation](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:34); [hermes_runtime.cc:1653](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1653); [process.js:69](/Users/ccheever/projects/ibex/src/builtins/process.js:69); [fs.js:542](/Users/ccheever/projects/ibex/src/builtins/fs.js:542)). The vendored builtin reproduces the same behavior ([vendored fs.js:366](/Users/ccheever/projects/ibex/vendored-generated/builtins/fs.js:366)).

- The `/project`-only mount is a strong initial security default (§1). Current arming already distinguishes the authenticated project binding from the machine-global `home` cache ([runtime.rs:1913](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1913), [runtime.rs:1941](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1941)). Refusing to expose executable caches to JavaScript is clearly correct.

- Separating display spelling, authorization identity, and module identity is the right conceptual decomposition (§2). Re-resolving a transferred string under the receiving principal correctly prevents path strings from becoming bearer capabilities ([LLP 0023 §2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114)).

- Lexical normalization before mount containment is a defensible capability-system default (§3). The Spec clearly documents its divergence from physical `open()` semantics rather than leaving `..` behavior accidental ([LLP 0023 §3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:183)).

- Staged symlink discovery correctly recognizes that link-target discovery is itself an effect (§4). Existing native code already retains descriptors, uses `O_NOFOLLOW`, and can retain symlink objects using `O_SYMLINK` or `O_PATH|O_NOFOLLOW`, so the architecture is feasible after its race rules are tightened ([hermes_runtime_fs.cc:533](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:533), [hermes_runtime_fs.cc:570](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:570)).

- The whole-surface no-host-path invariant (§6) is essential. Current `realpath` and module resolver bridges directly return host paths, confirming that virtualizing only `process.cwd()` would be inadequate ([hermes_runtime_fs.cc:2551](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2551), [abi.rs:2168](/Users/ccheever/projects/ibex/src/host/abi.rs:2168)).

- Refusing `%2F`, non-UTF-8 adapter inputs, host-shaped `readlink` results, and unsupported out-of-project roots are all defensible fail-closed v1 decisions when their compatibility boundaries are explicit. `%2F` refusal is already present in both source and vendored URL adapters ([url.js:2935](/Users/ccheever/projects/ibex/src/builtins/url.js:2935), [vendored url.js:1601](/Users/ccheever/projects/ibex/vendored-generated/builtins/url.js:1601)).

- The acceptance criteria are unusually adversarial and correctly demand callback/sync/promise parity, source/vendored parity, cross-principal tests, bridge sealing, and distinguishable error classes ([LLP 0023 Acceptance criteria](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:438)).

3. **Concerns**

1. **Blocking — The cwd ownership model contradicts itself.**

   **Evidence:** §5 defines one per-runtime cwd, owned and mutated by root, then says root mutation “changes no other principal’s resolution context” ([LLP 0023 §5:282–313](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:282)). Yet the same section says `fs`, module resolution, and `node:path` all use that cwd ([LLP 0023 §5:347](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:347)). A root `chdir` therefore changes every package’s relative-resolution base. Current `fs` and `path.resolve` demonstrate exactly this shared behavior ([fs.js:542](/Users/ccheever/projects/ibex/src/builtins/fs.js:542), [fs.js:570](/Users/ccheever/projects/ibex/src/builtins/fs.js:570), [path.js:59](/Users/ccheever/projects/ibex/src/builtins/path.js:59)).

   **Resolution criterion:** Choose one normative model:

   - a session-global cwd whose root-authorized mutation is explicitly acknowledged and classified as cross-principal influence; or
   - principal-specific resolution contexts, with root mutable and package contexts fixed or independently scoped.

   Add tests for package `fs`, `path.resolve`, `path.relative`, `require`, and dynamic import before and after root `chdir`.

2. **Blocking — Universal cwd visibility is not “one registry row,” and the proposed stricter profile leaks through aliases.**

   **Evidence:** §5 says a stricter profile can mask non-root `process.cwd()` without changing anything else, while §6 calls `node:path` pure ([LLP 0023 §5:288](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:288), [LLP 0023 §6:388](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:388)). But `path.resolve` and `path.relative` consult cwd ([path.js:8](/Users/ccheever/projects/ibex/src/builtins/path.js:8), [path.js:97](/Users/ccheever/projects/ibex/src/builtins/path.js:97)), while the registry classifies `path.resolve` as pure computation ([coverage-edges.json:89434](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:89434)). Relative file URLs, errors, watches, and module referrers create further channels.

   Registry mechanics also disagree with §8: `process:cwd` is deny-only ([capability-definitions.json:279](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:279)); non-authorable actions are rejected before ambient-root authority ([decision.rs:439](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:439)); and the current cwd read edge only admits ambient-root/static-floor sources ([coverage-edges.json:2881](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:2881)). There is no universal package authority source.

   **Resolution criterion:** Specify the exact action, resource, lifecycle, positive authority source, and target cells for both cwd observation and mutation. Every implicit-cwd channel must use the same projected resolution context. If a stricter profile merely masks `process.cwd()` while relative resolution still exposes the real cwd, remove that profile claim.

3. **Blocking — The authorization-identity tuple is impossible at requested and absent-create stages.**

   **Evidence:** The Summary and §2 require every authorization decision to include a retained target object ([LLP 0023:22](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:22), [LLP 0023 §2:116](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:116)). Before discovery, or when creating a nonexistent file, no such target exists. CapSec therefore models `parent_object`, `final_object`, and `retained_handle` as optional ([model.rs:1273](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1273)); the ABI represents absent-create with a retained parent and no final object ([abi.rs:1058](/Users/ccheever/projects/ibex/src/host/abi.rs:1058)).

   **Resolution criterion:** Define stage-specific types:

   - `NamespacePath`: runtime/snapshot, authenticated binding, owner, normalized components;
   - `DiscoveredPath`: namespace path plus retained parent, basename, and existing/absent witness;
   - `CommittedPath`: discovered path plus retained final object or handle.

   State which form keys each decision and cache stage.

4. **Blocking — Object-only module identity can collapse package compartments and does not cover Ibex’s actual module kinds.**

   **Evidence:** §2 keys modules solely by `(runtime, retained object)` ([LLP 0023 §2:149](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:149)). The loader assigns each module a package-specific principal and compartment, then stores those fields on the one cached module record ([module-loader.js:47](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:47), [module-loader.js:5296](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5296)). If two package bindings or locators reach one inode through hard links or aliases, first load determines the execution compartment for both.

   Object-only identity also fails for generated execution: ordinary JS/TS is bundled before execution, and one generated chunk can contain multiple original modules ([runtime.rs:1216](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1216), [runtime.rs:2939](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:2939)). Builtins, stdin, eval, and synthetic entries have no source-file object. Current user-module caching is path-ID based, not object based ([module-loader.js:5253](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5253), [module_loader/mod.rs:805](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:805)).

   **Resolution criterion:** Define module identity as a tagged algebra containing a defining principal independent of the caller:

   - disk module: runtime + defining principal + retained file identity;
   - bundled module: runtime + defining principal + authenticated source-provenance ID;
   - builtin: runtime + builtin source key;
   - synthetic/eval/stdin: runtime/session + source identity.

   Alternatively, arming must prove that one retained object can belong to at most one package owner. Caller-relative import/path authorization must run before every cache hit. Add same-object/two-owner, bundled/cache/bytecode, builtin, and synthetic tests. Remove “exactly as in Node” unless hard-link, query, CJS/ESM, and replacement semantics are explicitly matched.

5. **Blocking — The typed ABI lacks the runtime locality and trust boundary needed to implement the Spec.**

   **Evidence:** §7 says the ABI carries runtime and binding-owner identities but does not say who derives or authenticates them ([LLP 0023 §7](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:401)). JavaScript must not be allowed to assert either.

   Today the ABI is backed by one process-global `HOST`; installing another Host replaces it ([abi.rs:128](/Users/ccheever/projects/ibex/src/host/abi.rs:128), [abi.rs:214](/Users/ccheever/projects/ibex/src/host/abi.rs:214)). The typed filesystem ABI carries no runtime handle ([abi.rs:975](/Users/ccheever/projects/ibex/src/host/abi.rs:975)). Module resolution accepts only specifier/referrer strings, carries no runtime or attributed caller, authenticates armed resolution using the root principal, and returns host `path`/`pkgRoot` strings ([abi.rs:2197](/Users/ccheever/projects/ibex/src/host/abi.rs:2197), [host/mod.rs:1435](/Users/ccheever/projects/ibex/src/host/mod.rs:1435), [abi.rs:2177](/Users/ccheever/projects/ibex/src/host/abi.rs:2177)). AC6’s concurrent-runtime isolation is therefore impossible through the current ABI.

   **Resolution criterion:** Define an opaque native `RuntimeId`/session handle with allocation, affinity, teardown, and stale-handle rules. Replace singleton state with engine-owned or handle-indexed Host/VFS state. Native code must derive caller ownership from Hermes provenance and mint opaque resolved-path tokens; JavaScript supplies only untrusted path syntax. Thread runtime identity through fs, cwd, module resolution, caching, and errors.

6. **Blocking — Encoded-dot refusal is not implementable for ordinary `URL` objects and does not match the cited behavior.**

   **Evidence:** §3 and AC4 require `%2E%2E` to be refused “matching Node” ([LLP 0023 §3:220](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:220)). Ibex’s WHATWG parser recognizes encoded dot segments and removes them during URL construction ([url.js:1348](/Users/ccheever/projects/ibex/src/builtins/url.js:1348), [url.js:1660](/Users/ccheever/projects/ibex/src/builtins/url.js:1660)). `fileURLToPath` subsequently rejects encoded `/`, but no longer has provenance showing whether an already-removed `..` was encoded ([url.js:2928](/Users/ccheever/projects/ibex/src/builtins/url.js:2928), [url.js:2935](/Users/ccheever/projects/ibex/src/builtins/url.js:2935)). The vendored implementation behaves the same.

   **Resolution criterion:** Follow WHATWG/Node behavior: normalize encoded dot segments, then apply virtual containment, while retaining `%2F` refusal. If raw encoded-dot rejection is required, define a provenance-preserving raw URL representation and explicitly specify that ordinary constructed `URL` objects cannot satisfy it.

7. **Blocking — The symlink contract permits a persistent escape and an object-swap race.**

   **Evidence:** §4 allows relative targets to be stored verbatim and checks containment only when followed ([LLP 0023 §4:260](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:260)). A package could create `../../host-secret`; Ibex might refuse to follow it, but an external tool or later trusted process could. Current code deliberately gates both the link location and resolved target for this reason ([hermes_runtime_fs.cc:3278](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3278), [hermes_runtime_fs.cc:3297](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3297)).

   Step 2 also permits retaining “the link’s (or its parent’s)” identity ([LLP 0023 §4:246](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:246)). Retaining only the parent does not bind the child name; the link can be replaced between authorization, `readlinkat`, and follow. Existing code has the stronger link-object primitive ([hermes_runtime_fs.cc:570](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:570)).

   Relative `readlink` output, dangling links, non-UTF-8 targets, `{encoding:"buffer"}`, and the numeric chain-depth limit are also undefined. Current sync and async adapters already differ in applying output encoding ([fs.js:5731](/Users/ccheever/projects/ibex/src/builtins/fs.js:5731), [fs.js:5746](/Users/ccheever/projects/ibex/src/builtins/fs.js:5746)).

   **Resolution criterion:** Require target-side authorization and containment during symlink creation. Require retained link identity, or a specified pre/post `fstatat` verification and bounded-retry protocol. Define the exact depth, error reason, relative/dangling behavior, and all string/Buffer output forms.

8. **Material — Project-root and package-binding discovery are dangling prerequisites for the single-mount default.**

   **Evidence:** The Spec applies to every armed mode but never defines how the authenticated project root is selected. Current arming uses `canonical(entry).parent()` or host cwd ([runtime.rs:1669](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1669)); an entry at `/repo/src/app.js` therefore mounts `/repo/src`, potentially placing `/repo/node_modules` outside `/project`.

   Package bindings are guessed as `project_root/node_modules/<name>`, canonicalized, and accepted without project-containment validation ([runtime.rs:1823](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1823), [runtime.rs:1847](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1847)). That is insufficient for nested duplicates, multiple locators with one name, workspaces, and pnpm. Bindings also lack an authenticated canonical virtual display prefix, so an object reachable through multiple in-project aliases has no deterministic `__filename`.

   **Resolution criterion:** Define project-root discovery for file, REPL, stdin, `-e`/`-p`, eval, and embedders. Require one exact binding per locator-and-integrity graph principal, an authenticated canonical virtual prefix, overlap/alias rules, and native containment validation. Treat pnpm/workspace refusal as an explicit product compatibility boundary with fixtures and diagnostics, not merely an open question.

9. **Material — The path grammar is incomplete at the host-adapter boundary.**

   **Evidence:** §3 defines UTF-8 components but not component equality, case folding, Unicode normalization, lone-surrogate handling, empty input, trailing slash intent, or host-unrepresentable Windows names ([LLP 0023 §3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:183)). The registry already requires Apple alias keys and stricter Windows component rules ([policy-rules.json:576](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:576)). These are security properties because two distinct policy selectors can alias the same host object.

   Strict UTF-8 refusal is also not implemented end to end: Buffer paths are replacement-decoded in JavaScript, while several native paths use lossy conversion. The typed model itself can preserve binary components ([model.rs:480](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:480)). Armed execution is currently advertised only on macOS/aarch64, making the Spec’s Windows assertions presently untestable ([runtime.rs:1663](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1663)).

   Synthetic `/` is similarly underspecified: `Stats` fields, `Dirent` values, ordering, encoding, `withFileTypes`, and overload behavior are absent.

   **Resolution criterion:** Publish an input/output matrix covering string, Buffer, URL, empty/trailing forms, Unicode aliases, case aliases, Windows representability, and non-UTF-8 directory entries. Define exact synthetic `stat`/`readdir` records. Either gate non-macOS behavior as future work or supply target fixtures.

10. **Material — The error result and precedence are not normative enough to satisfy AC16.**

    **Evidence:** §7 gives prose classes but no enum literals or wire schema; it omits the synthetic-node reason later required by AC16 ([LLP 0023 §7:411](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:411), [LLP 0023 AC16](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:497)). Symlink-depth and unmappable-`readlink` reasons are also absent.

    The current C ABI returns only `1/0/-1` ([abi.rs:967](/Users/ccheever/projects/ibex/src/host/abi.rs:967)); C++ collapses denial to `"Permission denied"` ([hermes_runtime_fs.cc:541](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:541)); and `fs.js` reconstructs errors by parsing messages ([fs.js:764](/Users/ccheever/projects/ibex/src/builtins/fs.js:764)). Some paths open parent and target before their first typed decision, making `ENOENT` versus denial precedence observable ([hermes_runtime_fs.cc:2007](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2007), [hermes_runtime_fs.cc:2027](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2027)).

    **Resolution criterion:** Define a versioned result union with exact reason literals and mappings to `code`, `errno`, `syscall`, `path`, `dest`, and safe decision ID. Specify precedence: adapter/namespace validation, requested-stage authorization, authorized discovery/existence, discovered-target authorization, then commit/repeat. Require no host lookup before the requested-stage gate except the explicitly authorized symlink-discovery steps.

11. **Material — The generated path-observable table cannot currently be generated from the registry and conflicts with existing dispositions.**

    **Evidence:** §6 says the table is a projection of registry surfaces joined to every path-bearing field and alias ([LLP 0023 §6:363](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:363)). Current coverage edges describe surfaces and effects but contain no output-field, path-disposition, alias-shape, or synthetic-value schema. Resolver edges, for example, record effects but not the disposition of returned `path` or `pkgRoot` ([coverage-edges.json:136017](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:136017)).

    Existing classifications also disagree with the table’s apparent contract: `require.cache` is closed, `os.homedir`/`tmpdir`/`userInfo` are currently `sys:read` effects, and `import.meta.file` is a basename rather than equivalent to `.path`. Thus “every alias returns virtual spellings” is not precise enough.

    **Resolution criterion:** Add a separate generated output-disposition dataset with exact values such as `virtual-absolute`, `virtual-relative`, `virtual-basename`, `synthetic-source-id`, `absent`, `closed`, and `refused`. Make the audit table and fixtures projections of that dataset. Virtualizing a value must not implicitly reopen a closed inspection surface.

4. **Cross-document findings** (contradictions/dangling deps with 0022/0024/0025)

1. **Blocking contradiction — `require.cache` is closed in LLP 0022 but exposed in LLP 0023.** LLP 0023 assigns virtual keys and requires the row to be asserted ([0023 §6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:368)); LLP 0022 says `require.cache` stays closed as `runtime:inspect` ([0022 §1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:161)). Change 0023 to “closed; if later admitted, keys are virtual,” or deliberately reopen a filtered facade and revise both documents and the registry.

2. **Material contradiction — Source-map identities have incompatible domains.** LLP 0023 says source-map sources are virtual spellings ([0023 §6:380](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:380)); LLP 0024 requires reserved `repl:` and `ibex:` synthetic identities, including `.load` identities containing a virtual path ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:169), [0024 AC2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:863)). Define a tagged source identity: canonical virtual file URL or an LLP 0024 synthetic identity, never a host path.

3. **Material dangling dependency — Relative-module referrer capture time is undefined.** LLP 0023 says native resolution uses sealed cwd state ([0023 §5](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:347)); LLP 0024 puts a typed virtual referrer in each source request ([0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:135)); LLP 0022 says prompt imports use cwd, module imports use the module directory, and `.load` uses the loaded file’s directory ([0022 §4](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:334), [0022 `.load`](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:551)). None decides whether the prompt referrer is captured at submission or consulted later by a closure/dynamic import after `chdir`.

4. **Material dangling dependency — Retained path identities have no supervisor/worker locality contract.** LLP 0023’s cwd and path identities contain retained platform objects ([0023 §2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114), [0023 §5](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:282)); LLP 0025 places the engine in a worker and the session in a supervisor ([0025 §7](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:504)). Specify that VFS identities live and are derived in the worker, with only opaque authenticated session tokens crossing the process boundary.

5. **Material dangling dependency — `process.argv[1]` has no per-mode rule.** LLP 0023 says it is the entry’s synthetic identity “where one exists” ([0023 §6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:368)); LLP 0022 gives every REPL an arming entry ([0022 §2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:185)); LLP 0024 defines individual prompt identities but no stable session entry ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:169)). Distinguish arming entry, source identity, and argv identity in an exhaustive mode table.

6. **Material dangling dependency — Resolver errors have no composed union.** LLP 0023 defines namespace/path failures ([0023 §7](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:401)); LLP 0022 additionally requires an out-of-snapshot error ([0022 §2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:235)); LLP 0024 adds reserved-scheme errors ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:189)). Define one resolver error union and precedence.

7. **Material dangling dependency — Out-of-project refusal is absent from LLP 0022’s arming contract.** LLP 0023 refuses the entire graph ([0023 §2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:167)); LLP 0022 describes the recorded root-import surface as importable without stating this containment precondition ([0022 §2](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:199)). Add successful namespace arming as a precondition.

8. **Minor/Non-blocking duplication — Raw-bridge inventories have two apparent owners.** LLP 0023 owns path-bearing bridge disposition and fixtures ([0023 §6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:394)); LLP 0022 owns the general generated raw-bridge inventory ([0022 Affordance parity](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:494)). State that LLP 0023 is a generated projection of one inventory.

9. **Minor/Non-blocking wording drift — “root-only cwd” is misleading.** LLP 0022 uses that phrase ([0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:631)); LLP 0023 makes only mutation root-only while read access is universal ([0023 §5](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:282)). Use “root-owned/root-mutable, universally readable in v1.”

10. **Blocking sibling contradiction — Program-stdin `require.main`.** LLP 0022 says program stdin has no `require.main` and keeps the surface closed ([0022 §1](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:161), [0022 program stdin](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:282)); LLP 0024 says it names `ibex:stdin` ([0024 program stdin](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:325)).

11. **Blocking sibling contradiction — `.load` of JSON.** LLP 0022 says it displays parsed JSON ([0022 `.load`](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:551)); LLP 0024 makes `.json` a hard error ([0024 source kinds](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:331), [0024 AC5](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:875)).

12. **Blocking sibling dangling dependency — Lifecycle completion.** LLP 0024’s exhaustive result set has four outcomes ([0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:395)); LLP 0025 requires a fifth uncatchable lifecycle outcome ([0025 §8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:565)); LLP 0022 already records the gap ([0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:616)).

13. **Material sibling contradiction — Display IR styling.** LLP 0024 says inspection nodes carry kind, payload, children, and “never styling” ([0024 §8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:797)); LLP 0025 says the serialized IR itself includes trusted style/layout tokens ([0025 §3](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:237)). One document must own one exact versioned schema.

5. **Suggestions**

- Replace the single identity tuple with three native types: `NamespacePath`, `ResolvedPathOccurrence`, and `ModuleSourceId`. This mirrors CapSec’s actual stages and avoids pretending every path already has a target object.

- Use a native, dirfd-relative VFS resolver: untrusted virtual syntax in, opaque runtime-scoped path occurrence out. Host backing paths should never be materialized in JavaScript or accepted back from it.

- Generate an authenticated module-provenance manifest during bundling. Each original source module would receive a stable `(defining principal, logical source ID, digest)` independent of bundle/chunk inode, allowing raw, bundled, cached, and bytecode execution to share correct identity.

- Consider authenticated virtual prefixes on every package binding instead of requiring host ancestry under the project root. That could retain one visible `/project` namespace while admitting pnpm stores and workspace siblings through explicitly armed bindings.

- When creating an in-mount symlink, store a relative host target where possible. Storing an absolute backing host path makes links machine-specific and undermines the stated worktree/container portability.

- Create a registry-adjacent output-disposition schema rather than overloading capability edges. Generate the §6 table, bridge sealing assertions, aliases, and tests from that schema.

- Add model/property tests for normalization and aliasing, plus adversarial fixtures for hard links, two owners of one object, case-insensitive aliases, Unicode normalization, concurrent runtimes, stale cwd, symlink replacement, and cache hits under a different caller.

- Add an implementation dependency order: runtime/session handle and native resolver first; module resolver/cache conversion second; cwd and all fs families third; observable-output generation and bridge sealing fourth; mode-wide conformance last.

6. **Open questions**

1. Is cwd session-global, or does each principal have a resolution context? If global, is root’s ability to change package-relative resolution an accepted authority?

2. Which exact CapSec actions, resources, and authority sources represent cwd observation and virtual cwd mutation?

3. Can one retained object belong to two package-graph principals? If so, which principal owns its execution compartment?

4. What are module identities for bundled source modules, bytecode, builtins, eval, stdin, and synthetic session entries?

5. What selects the project root for nested file entries, REPL, stdin, `-e`/`-p`, eval, and embedders?

6. What canonical virtual spelling is chosen when one object has multiple aliases, and can that spelling depend on first load?

7. Should authenticated out-of-project package bindings be admitted at their logical `/project/node_modules/...` prefix without making their host parent part of the project mount?

8. Are file URL query and fragment values part of module identity even though they are excluded from path identity?

9. What exact symlink-depth limit, creation authority, race protocol, and relative-`readlink` representation are required?

10. Where do VFS state and retained objects live in the LLP 0025 supervisor/worker architecture, and how are runtime handles invalidated after worker replacement?

11. What happens when `readdir` encounters a non-UTF-8 host entry under the v1 UTF-8-only JavaScript contract?

12. Which currently closed observables remain closed after virtualization, especially `require.cache`, module search paths, `createRequire`, and raw resolver bridges?

13. What is the complete error precedence among malformed syntax, outside-mount, policy denial, absence, out-of-snapshot, symlink escape, stale identity, and unsupported synthetic operations?

7. **Readiness verdict**

The proposal is directionally strong and worth pursuing, but it has unresolved material correctness, safety, coherence, registry, and ABI-feasibility issues. The cwd model, stage-aware identity, module ownership, runtime locality, URL rule, and symlink protocol must be revised before this can govern an implementation.

VERDICT: NOT READY
### Orchestrator verification notes

I independently re-checked every decisive factual claim against the repository at
revision `0d55849a9f5e`. This review is unusually code-accurate; several findings
are more serious than the reviewer states.

**Confirmed (spot-checked directly):**

- **Blocking 2 — cwd registry mechanics. Confirmed, and it is the sharpest
  finding in either review.** `capsec/registry/capability-definitions.json`
  `definitions[19]` gives `process:cwd` as `"lifecycle": "deny-only"`,
  `"globality": "shared-process-mutation"`. `crates/capsec-semantics/src/decision.rs:439-448`
  hard-denies any action whose `lifecycle != Lifecycle::Authorable` at the
  `LifecycleAndTargetClosure` stratum — i.e. **before** any positive authority,
  including ambient root. And `capsec/registry/coverage-edges.json` shows the
  cwd **read** edge (`export:exact_process:cwd`, `__exactGetCwd`) is
  `cap: "sys:read"` with `positiveSources: ["ambient-root", "static-floor"]`
  only, while the **mutation** edges (`export:exact_process:chdir`,
  `__exactSetCwd`) are `"classification": "closed"` on `process:cwd`.
  Therefore §8's "the rows are regenerated" is **not achievable**: root-only
  virtual `chdir` cannot be expressed on a deny-only action, and there is no
  authority source that admits a *package* principal to the cwd read. The doc
  must specify **new authorable typed actions** with typed resources and named
  authority sources, and say what becomes of the deny-only `process:cwd` row.
- **Blocking 3 — staged identity. Confirmed.**
  `crates/capsec-semantics/src/model.rs:1273-1280` —
  `OccurrenceResource::PathOccurrence { requested: LogicalPath, follow_mode,
  object_state, parent_object: Option<ObjectIdentity>, final_object: Option<…> }`.
  Parent and final objects are already **optional**, and `src/host/mod.rs:318-320`
  threads them as `Option`. The doc's universal five-tuple with a mandatory
  "retained platform object" is therefore wrong for the requested stage and for
  absent-create. The reviewer's staged decomposition matches CapSec's actual model.
- **Blocking 5 — runtime locality. Confirmed.** `src/host/abi.rs:130` —
  `static HOST: OnceLock<RwLock<Host>>`, a **process-global singleton**;
  `install_host` (`abi.rs:214`) *replaces* it. AC6 ("a second runtime … does not
  change") is not implementable through this ABI without a runtime/session handle.
- **Blocking 6 — encoded dot segments. Confirmed** (independently found by Fable
  as its Concern 2). `src/builtins/url.js:1348-1355` treats `%2e`, `.%2e`,
  `%2e.`, `%2e%2e` as dot segments; `url.js:1666-1672` collapses them during URL
  path normalization; `fileURLToPath` (`url.js:218-230`) refuses only `%2F`/`%5C`.
  The information needed to refuse an encoded `..` is gone by the time a `URL`
  object exists.
- **Blocking 7 — symlink creation. Confirmed, and worse than stated.**
  `src/engine/hermes_runtime_fs.cc:3281-3300` shows the **current**
  `__exactSymlink` already authorizes *both* the link location (`fs:write:<path>`)
  **and** the resolved target (`fs:write:<absTarget>`, resolving relative targets
  against the link's directory), with the comment (ENG-22682): "a path-scoped
  principal must not plant a link that points outside its write grant for other
  principals (or external tools) to traverse." The doc's §4 — which authorizes the
  target only at *follow* time — would therefore be a **regression against
  shipped behavior**. The stronger link-object primitive the reviewer points to
  also exists (`hermes_runtime_fs.cc:570`, `openArmedLinkTarget`).
  Separately confirmed: `src/builtins/fs.js:5731-5740` `readlinkSync` **ignores**
  its `options` argument entirely, while async `readlink` (`fs.js:5741-5755`)
  applies `_encodeFsPathResult(value, options)` — a live sync/async encoding
  divergence, which is why the output forms must be pinned.
- **Material 8 — project-root discovery. Confirmed, and I rate it Blocking.**
  `src/bin/ibex/runtime.rs:1674-1677` —
  `project_candidate = entry.canonicalize().parent()`, falling back to
  `std::env::current_dir()`. `runtime.rs:1824` — package roots are guessed as
  `project_root.join("node_modules").join(name)` and skipped entirely if that path
  does not exist. So `ibex src/app.js` mounts `<repo>/src` as `/project`, and a
  repo whose `node_modules` sits at `<repo>/node_modules` has **no package
  bindings at all**. Layered on the doc's new arming refusal, this would refuse or
  mis-bind essentially every real project whose entry is not at the repo root.
  The doc cannot state a containment invariant without also specifying
  project-root discovery. (Also noted: `runtime.rs:1843` calls
  `.expect("advertised target paths must be UTF-8")` — a **panic**, not a clean
  refusal, on a non-UTF-8 project path.)
- **Material 9 / Material 11 — grammar and generated-table gaps. Confirmed.**
  No `alias_key`/`aliasKey` implementation exists anywhere in `crates/`, `src/`,
  or `capsec/` (LLP 0021:270-273 specifies the Apple alias key at arming only).
  `coverage-edges.json` carries no output-field/alias/path-disposition schema.
  And `import.meta.file` is a **basename** (`module-loader.js:3563` —
  `__filename.split('/').pop()`), so the §6 row lumping `.file` with the other
  aliases under "virtual spellings" is affirmatively wrong.
  `src/module_loader/mod.rs:805` — `id: full_path.to_string_lossy().to_string()`
  confirms both the path-string module key and a **lossy** non-UTF-8 conversion
  that silently aliases distinct host paths.
- **Material 10 — error precedence. Confirmed.** `src/host/abi.rs:967` returns
  `1/0/-1`; `hermes_runtime_fs.cc:541` collapses denial to `"Permission denied"`;
  `src/builtins/fs.js:764` reconstructs errors by parsing messages.
- **Cross-doc 1 — `require.cache`. Confirmed**, and independently found by Fable
  (its Concern 7). LLP 0022 §1 closes `require.cache`; LLP 0023 §6 assigns it a
  value. 0023 yields.

**Refuted / corrected:**

- **Blocking 4's bundling sub-claim is partially refuted.** The reviewer cites
  `runtime.rs:1216` and `runtime.rs:2939` for "ordinary JS/TS is bundled before
  execution." `run_file_with_args` (`runtime.rs:1216-1222`) in fact carries the
  comment *"Use runtime module loader instead of bundling"* and does **not**
  bundle; `runtime.rs:2939` is about bundle **cache layout**, not the file-execution
  path. However, a per-package-chunked bundler does exist (`__ibexpkg__*` chunks,
  shared `rolldown-runtime.js`), so the underlying concern is sound **for the
  bundled and bytecode modes**, and the rest of Blocking 4 stands on its own
  without the bundling claim: builtins are already keyed by a non-path key
  (`module-loader.js:5253-5256`, `builtinCacheKeyFor`), and `repl:<n>`,
  `ibex:stdin`, and `ibex:eval` have no file object at all. I accept Blocking 4
  on the strength of those, plus the hard-link/compartment-collapse argument,
  and I record the bundling citation as inaccurate.
- **Cross-doc 9's "wording drift" is accepted but I disagree it is Minor.** The
  phrase "root-only cwd" is not merely misleading; §5's *justification* for
  regenerating the registry rows ("it changes no other principal's resolution
  context") is **false within a runtime**: `fs` and `path.resolve` resolve
  relative paths against the session cwd (`fs.js:542-568`, `path.js:59-71`), so a
  root `chdir` does move every package's relative base. Only the *cross-runtime,
  cross-embedder, process-global* claim survives. This is Codex Blocking 1, and I
  treat it as Blocking.

**Sibling defects reported, not fixed** (cross-doc findings 10-13 concern
0022/0024/0025 and are outside this document's authority; they are relayed to the
author in the orchestrator's final report): program-stdin `require.main`
(0022 vs 0024), `.load` of JSON (0022 vs 0024), the fifth uncatchable lifecycle
outcome (0024 vs 0025), and display-IR styling ownership (0024 §8 vs 0025 §3).

**Disposition:** Accepted on Blocking 1, 2, 3, 4, 5, 6, 7; Material 8 (upgraded to
Blocking), 9, 10, 11; and cross-doc 1, 2, 3, 4, 5, 6, 7, 8, 9. The two reviews
converge independently on the `%2E%2E` defect, the `require.cache` conflict, the
cwd-profile leak through `node:path`, the missing error-code table, the
generated-table feasibility gap, and the symlink-storage problem — I weight those
most heavily. Round-1 revision `dd8e3d70f5c9` addresses all of them; see the
`**Revised:**` line and §Design of the target document.

Rejections and partial acceptances:

- I **reject** Codex's suggested resolution to Blocking 1 that would give packages
  a *fixed* resolution base independent of root's cwd. That silently changes what
  `fs.readFileSync("./x")` means inside a package relative to Node, for a threat
  that does not exist: root is strictly more authoritative than any package, and
  root moving the shared base cannot grant a package authority it lacks (every
  resulting path is still authorized against the package's own binding). The
  actual defect is the doc's **false justification**, not the shared base. I fixed
  the justification, stated the within-runtime influence plainly as a deliberate
  Node-compatible property, and added the fixture Codex asked for.
- I **partially accept** Codex's module-identity algebra. I adopt the tagged
  union, but I key file-backed modules on
  `(runtime, defining principal, retained object)` where the **defining
  principal** is the owner of the most specific binding *containing* the file and
  is computed **caller-independently**. This preserves the doc's original
  requirement (root's `import "foo/util.js"` and `foo`'s `require("./util")` are
  one instance, because both have defining principal `foo`) while closing the
  compartment-collapse hole (two packages hard-linked to one inode have different
  defining principals, so they stay two modules in two compartments). Codex's
  alternative — "arming must prove one retained object belongs to at most one
  package owner" — is not provable under pnpm's content-addressed hard-linking.

---

## Round 2 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, invoked as
  `codex exec` (non-interactive), sandbox `read-only`, workdir
  `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`
- **Reasoning effort:** `ultra` (`-c model_reasoning_effort="ultra"`)
- **Session id:** `019f55b9-b67b-7420-977c-4d520a549a50` (rollout on disk at
  `~/.codex/sessions/2026/07/12/rollout-2026-07-12T02-47-42-019f55b9-….jsonl`)
- **Date:** 2026-07-12
- **Revision under review:** `832eb25f0327`
- **Redacted:** No. Read under the user's own OpenAI account, authorized by the
  human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session. No access to the
  orchestrating session, to the concurrent Fable round-2 review of the same
  revision, or to any prior LLP 0023 review artifact — the round-1 artifacts were
  moved out of `llp/reviews/` into a scratch stash for the duration of the round
  and `llp/reviews/` was verified to contain no 0023 files while it ran.
  Instructed not to read `llp/reviews/`.
- **Method:** cli-runner, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round2.md`) — the same brief given
  to the Fable reviewer. The brief told the reviewer the document had been revised
  after a prior round, named the new/rewritten sections, and instructed it to
  judge the current revision on its own merits and to check the document's own
  file:line citations.

### Verbatim review

1. **Overall assessment**

The proposal has the right architectural direction: one virtual namespace, authenticated path identities, runtime-local cwd state, caller-relative authorization, caller-independent module identity, and generated coverage of path-bearing observables. Those are good ideas and substantially better than the current string-shaped, process-global behavior.

It is not yet a coherent normative Spec. Several central types contradict the armed CapSec model, the package graph cannot supply the bindings the design requires, the module algebra is not total, the symlink round-trip is incorrect for admitted package aliases, and the runtime-handle contract is explicitly required but left unspecified. The sibling corpus also contains direct contradictions and stale references. These are design defects, not merely implementation work.

2. **Strengths**

- The motivation accurately identifies the current cwd/path failure: armed cwd returns `undefined`, `process.cwd()` falls back to `/`, and `fs` resolves relative paths from that value ([§Motivation, 0023:47](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:47); [hermes_runtime.cc:1654](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:1654); [process.js:69](/Users/ccheever/projects/ibex/src/builtins/process.js:69); [fs.js:542](/Users/ccheever/projects/ibex/src/builtins/fs.js:542)).

- A synthetic `/` with a single `/project` mount is a clean, understandable v1 model. Keeping the machine-global `home` cache unmounted is the correct security default ([§1, 0023:114](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:114); [runtime.rs:1918](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1918)).

- The distinction between caller-relative authorization identity and caller-independent module identity is conceptually sound and necessary for LLP 0013’s package compartments ([§2.2–2.3, 0023:257](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:257)).

- Refusing an unrepresentable package layout during arming is preferable to silently omitting a binding or assigning code to the wrong principal ([§1.2, 0023:181](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:181)).

- The document is unusually honest about deliberate divergences: lexical `..`, shared cwd influence, synthetic-root `chdir`, host-shaped `readlink` refusal, and non-UTF-8 narrowing are stated rather than hidden ([§3–§5, 0023:353](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:353)).

- Retaining the link itself and authorizing symlink targets at creation are strong security requirements. The current engine does have a link-object primitive and a legacy creation-time target check, so the proposal starts from real implementation knowledge ([§4, 0023:458](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:458); [hermes_runtime_fs.cc:570](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:570); [hermes_runtime_fs.cc:3281](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3281)).

- §7 correctly recognizes that per-runtime semantics cannot be built over the process-global Host singleton and runtime-less filesystem ABI ([§7.1, 0023:763](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:763); [abi.rs:130](/Users/ccheever/projects/ibex/src/host/abi.rs:130); [abi.rs:214](/Users/ccheever/projects/ibex/src/host/abi.rs:214); [abi.rs:975](/Users/ccheever/projects/ibex/src/host/abi.rs:975)).

- The generated output-disposition and structured-error directions are excellent. The problem is completeness, not the underlying idea ([§6–§8, 0023:678](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:678)).

3. **Concerns**

1. **Blocking — the staged identity contradicts the current CapSec stage model.**

   **Evidence:** §2.1 makes `DiscoveredPath` parent + basename + existence witness and delays the final object until `CommittedPath` ([0023:228](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:228)). Current CapSec requires `finalObject` during discovery for an existing path and a retained handle at commit ([containment.rs:594](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/containment.rs:594)). More fundamentally, `PathOccurrence.object_state` is mandatory even at requested stage ([model.rs:1273](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1273)), so the ABI speculates `Existing` before lookup ([abi.rs:1058](/Users/ccheever/projects/ibex/src/host/abi.rs:1058)). That violates the governing prohibition on speculative stage facts.

   **Resolution criterion:** Make requested existence genuinely unknown; define discovery as carrying a discovered final/link identity for an existing target and a retained parent for absent-create; define commit as adding the retained operation handle and verification result. Update LLP 0021, schemas, ABI, digest vectors, cache vectors, and requested/discovery/commit fixtures together.

2. **Blocking — the arming containment invariant is not representable under current effect-owner semantics.**

   **Evidence:** §2.2 requires one occurrence derived from the effect owner’s binding, against which every constrained principal is evaluated ([0023:257](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:257)). `LogicalPath` and `PathOccurrence` contain no binding owner ([model.rs:583](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:583); [model.rs:1273](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1273)). The evaluator instead prefers each constrained package principal as `expected_owner` ([decision.rs:1124](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:1124)). LLP 0021 and the machine rule explicitly say package-root ceilings evaluate against each constrained principal’s own binding ([0021:349](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:349); [policy-rules.json:578](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:578)).

   **Resolution criterion:** Add an authenticated occurrence-level binding owner, compare every constrained authority against that owner, revise LLP 0021’s conflicting rule, and add an A-owner/B-deputy fixture proving B’s own-root grant cannot authorize A’s occurrence.

3. **Blocking — project-root discovery is not pinned tightly enough for an authority boundary.**

   **Evidence:** §1.1 refers to “a workspace root declaration, a lockfile, then `package.json`” but names neither concrete files nor field predicates, and does not say whether marker precedence applies across directory levels ([0023:145](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:145)). As written, a nested `package.json` wins before an ancestor workspace marker. An unrelated marker in a broad ancestor such as a home directory can also enlarge `/project`, even though object authentication does not establish that the ancestor was intended as the authority boundary. Current code simply takes the entry parent or cwd ([runtime.rs:1669](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1669)).

   **Resolution criterion:** Enumerate exact marker names and field predicates, define cross-level precedence, ownership/device/ascent stopping rules, the explicit flag name, safe diagnostic content, and how the discovery-version constant enters the armed digest. Add nested workspace, unrelated ancestor marker, symlinked entry, markerless, and explicit-override fixtures.

4. **Blocking — the package graph cannot derive authenticated package bindings.**

   **Evidence:** §1.2 requires one binding per exact graph principal at its actual root ([0023:181](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:181)). The armed graph contains only principals and importer/imported edges, with no root or resolving specifier ([armed-snapshot.schema.json:211](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:211)). The binding shape contains no authenticated virtual prefix or alias ([armed-snapshot.schema.json:263](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:263); [arming.rs:60](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:60)). Current runtime code consequently guesses `project/node_modules/<name>` ([runtime.rs:1823](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1823)).

   A canonical root alone also cannot associate `/project/node_modules/foo/x` with a symlinked physical package root before discovery, despite §2.2 promising that behavior. Equal canonical roots owned by two principals have no tie rule.

   **Resolution criterion:** Define a trusted graph-location artifact or deterministic arming algorithm carrying each edge’s resolving specifier, exact principal, canonical root, and authenticated virtual alias set. Reject or define equal-root/equal-specificity cases, and make every alias part of the armed digest.

5. **Blocking — package integrity is not bound to the installed content.**

   **Evidence:** The generator hashes package manifests and module content ([generate-policy.mjs:259](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/generate-policy.mjs:259)), but arming copies the supplied principal and records only directory object metadata. The current resolver explicitly says its `name@version` identity is not an integrity boundary ([module_loader/mod.rs:28](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:28)). §1.2 nevertheless assumes integrity-bound graph principals.

   **Resolution criterion:** Specify the exact verification algorithm and point at which installed content is matched to the principal digest; bind every loaded source or generated provenance record to that result; define post-arming mutation and stale-content behavior; refuse mismatches before package code executes.

6. **Blocking — the module identity algebra is internally incomplete.**

   **Evidence:** The file-backed key is `(runtime, defining principal, retained object)`, while the generated key is `(runtime, defining principal, source-provenance id)` ([§2.3, 0023:311](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:311)). As distinct algebra variants, they cannot literally “agree on identity” across raw, bundled, cached, and bytecode execution as §2.3 and AC18 require. Current `ResolvedModule` has no provenance field ([module_loader/mod.rs:28](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:28)), generated chunks are attributed through filename heuristics ([module-loader.js:104](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:104)), and one resolver record becomes one string-keyed cache entry ([module-loader.js:5253](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5253)).

   **Resolution criterion:** Introduce one canonical authenticated `SourceId` shared by raw, generated, and bytecode forms, with object identity as verification evidence rather than an incompatible variant; specify the provenance manifest, ABI transport, per-original-module chunk records, and cache equality algorithm.

7. **Blocking — defining principal, canonical display spelling, and stale identity are not total functions.**

   **Evidence:** The defining principal is described as “where the file lives,” but the document admits one object under several package bindings ([0023:301](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:301)). OQ7 leaves `__filename`/`import.meta.url` alias choice unresolved, and OQ8 leaves query/fragment identity unresolved ([0023:1113](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1113)). Yet `realpath`, source maps, and imported-source identity are already required to be canonical.

   “Verification generation” is also undefined. Current `ObjectIdentity` is only platform/volume/file ([model.rs:614](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:614)), and the Unix adapter records only device/inode ([abi.rs:1393](/Users/ccheever/projects/ibex/src/host/abi.rs:1393)). Detecting delete/recreate on a module-cache hit would require an otherwise unspecified filesystem lookup.

   **Resolution criterion:** Define the principal from authenticated occurrence/binding provenance, reject ambiguous equal-root ties, choose canonical display spelling and query/fragment semantics, name the platform generation primitive or retained-handle fallback, and specify revalidation cadence, authorizing effect, cost, and precedence.

8. **Blocking — alias canonicalization only addresses occurrences, not authored authority.**

   **Evidence:** §3 says resolver components become volume-canonical before the typed decision ([0023:384](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:384)). Current arming copies authority selectors unchanged ([arming.rs:391](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:391)), and containment compares component bytes ([containment.rs:393](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/containment.rs:393)). Canonicalizing only `/project/Secrets` at occurrence time can make an authored `/project/secrets` selector fail to match rather than safely alias. The current machine-readable LLP 0021 rule is decoded-byte identity plus adapter rejection, not the proposed equivalence ([policy-rules.json:578](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:578)).

   **Resolution criterion:** Specify a versioned per-volume canonicalization function applied to both armed selectors and occurrences, bind its identity into the snapshot/digests, update LLP 0021 and containment vectors, and test case, normalization-form, absent-create, and cross-binding collisions.

9. **Blocking — the symlink storage/readback scheme fails for admitted virtual aliases.**

   **Evidence:** §4 requires host-relative stored bytes and says `readlink` returns them verbatim as a virtual-relative spelling ([0023:500](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:500)). For a pnpm/workspace alias, the kernel resolves relative bytes from the physical package directory, whose depth differs from `/project/node_modules/foo`. A host-correct target such as `../../../../../a` can therefore escape or name a different object when interpreted verbatim from the virtual parent; a virtual-correct `../a` may point to the wrong physical object. Current resolver records already allow canonical package roots distinct from record spelling ([module_loader/mod.rs:28](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:28)).

   Separately, §4 says a dangling target’s containment is lexically decidable without lookup. That is false when its deepest existing ancestor is a symlink to outside the mount. Current creation stores supplied bytes directly after a legacy string check ([hermes_runtime_fs.cc:3270](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3270)).

   **Resolution criterion:** Either translate physical relative bytes back into a virtual-relative spelling on `readlink`, restrict creation to topology-preserving same-binding cases, or redesign the encoding. Creation must resolve and authenticate the deepest existing ancestor before appending a missing suffix. Test pnpm/scoped/workspace aliases, foreign relative escapes, dangling targets below symlinked ancestors, moves, and swap races.

10. **Material — cwd projection, mutability, and registry semantics contradict one another.**

   **Evidence:** §5.3 says whatever a principal observes as cwd is its resolution base, while §5.4 and AC15 say monkeypatching writable `process.cwd` changes the observed value but not resolution ([0023:639](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:639); [0023:667](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:667)). A profile that “closes” cwd observation is also specified to return `/project`, which is masking/projection rather than denial.

   §8’s claim that no authority source can admit package cwd reads is false: `sys:read` is authorable, `cwd` is a valid `system-info` selector, and the edge admits static-floor authority ([capability-definitions.json:515](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:515); [authority-selector.schema.json:291](/Users/ccheever/projects/ibex/capsec/schema/authority-selector.schema.json:291); [coverage-edges.json:2881](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:2881)).

   The new actions are unnamed and lack wire resources, globality, channels, and a root-only positive predicate. Merely making mutation `Authorable` permits a package static floor to authorize it.

   **Resolution criterion:** Define an authenticated native cwd view distinct from a user-overridden facade, select the v1 per-principal projection explicitly, correct the registry rationale, and pin exact action IDs/resources/predicates. Either seal `process.cwd` or limit “view equals base” to the authenticated native view. Decide OQ6 before acceptance; my preference is `/project` view/base for non-root principals because the shared variant leaks navigation and can redirect already-authorized package effects.

11. **Blocking — the runtime/session ABI contract is demanded but not specified.**

   **Evidence:** §7.1 explicitly requires allocation, affinity, teardown, and stale behavior but provides no API or state machine ([0023:763](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:763)). Today `ex_host_install_armed` replaces a global host, `ex_hermes_create_armed` accepts only a digest, and filesystem gates have no runtime parameter ([abi.rs:877](/Users/ccheever/projects/ibex/src/host/abi.rs:877); [exact_runtime.h:40](/Users/ccheever/projects/ibex/include/exact_runtime.h:40); [abi.rs:975](/Users/ccheever/projects/ibex/src/host/abi.rs:975)). ABI version remains 1 ([abi.rs:128](/Users/ccheever/projects/ibex/src/host/abi.rs:128)). OQ9 leaves worker invalidation open.

   **Resolution criterion:** Pin session creation, engine attachment, per-call token transport, thread affinity, worker transfer, cancellation/draining, destruction, generation/ABA defense, and stale/cross-session errors, including the ABI version transition. Require caches to be session-local or key them by session identity. Add cross-runtime, stale-after-destroy, in-flight teardown, and worker-replacement tests.

12. **Material — the error contract is neither a complete union nor a versioned ABI schema.**

   **Evidence:** §7.2 promises a stable versioned reason enum but provides only a prose table ([0023:799](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:799)). It omits stale/unknown/wrong-session handle reasons, ordinary filesystem errors, alias-collision/verification failures, and their precedence. Reserved-scheme and out-of-snapshot are merely said to precede namespace validation without an order relative to each other or other loader classes. Current ABI still returns `1/0/-1`, and JS parses strings ([abi.rs:967](/Users/ccheever/projects/ibex/src/host/abi.rs:967); [fs.js:764](/Users/ccheever/projects/ibex/src/builtins/fs.js:764)).

   **Resolution criterion:** Define one closed wire union with explicit discriminant values, version, ownership/freeing rules, every namespace/loader/session/OS-error member, and a complete precedence order. Add ambiguous cross-product fixtures, not merely one fixture per code.

13. **Blocking — the output-disposition table is not exhaustive and already assigns incorrect shapes.**

   **Evidence:** §6 claims to cover every path-bearing observable ([0023:678](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:678)). Current Rust module IDs are lossy host paths ([module_loader/mod.rs:805](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:805)); JS exposes them through `module.id`, `filename`, `path`, `paths`, parent/children, and error prefixes ([module-loader.js:5296](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5296); [module-loader.js:5691](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5691)). Closing `require.cache` does not close the per-module `module` object.

   The table also omits normal `readlink`, `realpath`, `process.cwd`, cwd-derived `node:path` results, `ExactFile.name`, `Dirent.parentPath/path`, stream `.path`, `FileHandle.path`, URL-converter returns, and several aliases. “Closed” rows do not pin whether the observable is absent, throws, or returns a neutral value.

   **Resolution criterion:** Land a normative machine-readable dataset or exhaustive annex before acceptance, keyed by surface, variant, field, alias, mode, and source kind. Prove equality with the generated surface inventory and live root-reachability manifest, and make an unclassified field fail the build.

14. **Material — `%5C` and file-URL serialization are internally contradictory.**

   **Evidence:** §3 permits backslash as an ordinary POSIX component but calls `%5C` a separator and requires refusal ([0023:353](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:353); [0023:429](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:429)). The cited `url.js:218-230` branch is inside a hard-disabled block ([url.js:163](/Users/ccheever/projects/ibex/src/builtins/url.js:163)). Active source and generated code reject `%5C` only in Windows mode ([url.js:2928](/Users/ccheever/projects/ibex/src/builtins/url.js:2928); [vendored url.js:1597](/Users/ccheever/projects/ibex/vendored-generated/builtins/url.js:1597)). Active `pathToFileURL` encodes a literal POSIX backslash as `%5C`, so the proposed inverse would reject its own output ([url.js:2958](/Users/ccheever/projects/ibex/src/builtins/url.js:2958)).

   Canonical file-URL serialization is also unpinned for `%`, `?`, `#`, controls, and line terminators; current `import.meta.url` and `sourceURL` concatenate raw filenames ([module-loader.js:3553](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:3553); [module-loader.js:5572](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5572)).

   **Resolution criterion:** Under POSIX-everywhere semantics, refuse `%2F` but decode `%5C` as a backslash, or explicitly outlaw backslash everywhere and document the divergence. Pin one URL serializer/parser shared by `node:url`, `Exact`/`Bun`, `import.meta`, source maps, and source URLs, with round-trip fixtures.

15. **Material — non-UTF-8 and byte-preserving `readlink` semantics do not compose.**

   **Evidence:** §3 refuses non-UTF-8 path input, while §4 permits non-UTF-8 `readlink` output under `{encoding:"buffer"}` if it resolves in-namespace ([0023:402](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:402); [0023:514](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:514)). The document does not say how bytes excluded from namespace identity are tested for namespace containment. Current Buffer paths are decoded lossily ([fs.js:242](/Users/ccheever/projects/ibex/src/builtins/fs.js:242)), while native `readlink` returns a JSI string ([hermes_runtime_fs.cc:3341](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3341)).

   **Resolution criterion:** Add a byte-preserving tagged native result and define native containment over binary `PathComponent`s, or refuse non-UTF-8 link targets even in buffer mode. Pin lone-surrogate conversion, malformed URL decoding, and sync/async/promise behavior.

16. **Material — the mount, synthetic-root, and operation contracts are incomplete.**

   **Evidence:** §1 says mounts have write, symlink, lifecycle, and metadata attributes but gives no `/project` values ([0023:116](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:116)). The synthetic stat record is called pinned without specifying mode, uid/gid, nlink, device/inode numbers, bigint fields, or which of `stat`, `lstat`, `access`, `realpath`, and `exists` succeed. The document also lacks an operation matrix for rename, copy, hardlink, recursive operations, descriptors, directory handles, and watches. Two-path operations need source/destination actions, binding transitions, atomicity, and defining-principal consequences. Current hardlink code already demonstrates that read/write authority on both sides matters ([hermes_runtime_fs.cc:3308](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3308)).

   “The empty path is malformed” is likewise not scoped: current `node:path.resolve("")` intentionally treats it as no component and consults cwd ([path.js:59](/Users/ccheever/projects/ibex/src/builtins/path.js:59)).

   **Resolution criterion:** Add a complete operation/adapter matrix, actual mount attributes, exact synthetic records, per-surface empty/trailing-slash rules, and two-path staging/atomicity rules.

17. **Material — registry integration and target-advertisement claims are incomplete.**

   **Evidence:** §8 introduces actions, branches, and a dataset without naming their files, schemas, stable IDs, digest projections, or target cells ([0023:863](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:863)). Alias semantics also change the governing machine rule but §8 only calls out package containment as an LLP 0021 update.

   §3 says armed execution is “advertised” on macOS/aarch64, but the machine-readable authority has `advertisedTargets: []`; macOS is only a candidate ([policy-rules.json:786](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:786)). A CLI hardcode refusing other targets does not constitute a CapSec advertisement.

   **Resolution criterion:** Add every new file to `contract-files`, schemas, vocabulary/registry digest projections, generated bindings, target cells, and conformance obligations. Correct the advertisement wording and require demotion/re-promotion after the new obligations execute.

18. **Minor/Non-blocking — multiple citations do not directly say what the document claims.**

   **Evidence:** The armed cwd return is at `hermes_runtime.cc:1654-1655`, while line 1653 is only a comment. `model.rs:1273-1280` omits `final_object`, which is line 1281. `model.rs:578` is `Home`; `Tmp` is line 579. The raw realpath return is at `hermes_runtime_fs.cc:2573-2577`, not line 2551. The denial string is at `:543-545`, not `:541`. Message parsing is at `fs.js:766-770`, not merely line 764. The preauthorization host opens are at `hermes_runtime_fs.cc:2010` and `:2015`; line 2007 only splits the path. `runtime.rs:1918-1945` proves a cache binding, not by itself the stronger claim that it holds generated code for every project.

   **Resolution criterion:** Replace point citations with ranges or anchors that directly establish each factual assertion, and distinguish “current precedent” from evidence that the proposed typed behavior already exists.

4. **Cross-document findings**

1. **Blocking contradiction: LLP 0024 still specifies the old module identity.** It says `(runtime, retained object identity)` and “one file is one module instance no matter which principal” ([0024:980](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:980)). That contradicts 0023’s defining-principal key and required cross-package hardlink split. Its references to “0023 AC11” are stale; current AC11 concerns package-attributed `chdir`, while module identity is AC16–18 ([0024:1292](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1292); [0023:981](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:981)).

2. **Material contradiction: LLP 0022’s project startup rule is stale.** It says the shell cwd is selected and installed as the project candidate ([0022:201](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:201)); 0023 makes cwd only a discovery origin and ascends to a marker ancestor.

3. **Material contradiction: source identities and module identities are conflated.** 0023 puts `repl:<n>` and `ibex:eval` in the module algebra, while 0022/0024 define prompt and one-shot sources as scripts with no module record ([0023:315](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:315); [0022:402](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:402); [0024:237](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:237)). `.load` has composite identity `repl:<n>:<virtual path>` in 0024 but is absent from 0023’s exhaustive source-identity rows ([0024:189](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:189)).

4. **Material contradiction: `import.meta` dispositions are wrong for program stdin.** 0023 says `import.meta.url` is always a virtual file URL and its path aliases are virtual paths ([0023:699](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:699)). 0022 and 0024 require `import.meta.url === "ibex:stdin"` and no backing file ([0022:326](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:326); [0024:193](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:193)).

5. **Material dangling dependency: resolver error ownership remains unsettled.** 0023 claims one composed union and order; 0024 lists classes without a total order; 0022 says out-of-snapshot has no owner and OQ7 still asks which enum owns it ([0023:845](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:845); [0024:218](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:218); [0022:961](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:961)).

6. **Material dangling dependency: session handle and referrer stage are not shared types.** 0023 introduces a runtime/session handle and staged path identities; 0024 separately names an armed-session binding and a generic “typed logical path identity” referrer ([0023:763](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:763); [0024:146](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:146)). Neither 0024 nor 0022 selects `NamespacePath`, `DiscoveredPath`, or a retained directory `CommittedPath`, or repeats 0023’s submit-time capture rule.

7. **Material contradiction: the worker/display wire boundary differs between 0024 and 0025.** LLP 0024 says the worker produces display IR and only that IR crosses ([0024:1077](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1077)); LLP 0025 says a style-free tree crosses and the session layer derives style and bytes ([0025:251](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:251)).

8. **Material dangling entry case:** 0022 calls the armed-entry enum closed with only `file`/`stdin`/`repl`, while 0023/0024 require armed one-shot identity `ibex:eval` ([0022:213](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:213); [0024:193](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:193)).

9. **Material diagnostic conflict:** 0023 requires an arming diagnostic that names the out-of-project host root ([0023:193](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:193)), while 0022 and 0025 apply the no-host-path rule to session and startup diagnostics ([0022:390](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:390); [0025:799](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:799)). Use a package locator plus symbolic classification or explicitly coordinate an exception.

10. **The sibling obligation ledgers contain extensive stale state:**

   - 0022 and 0025 say the lifecycle outcome is absent, but 0024 now defines it ([0022:733](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:733); [0025:871](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:871); [0024:496](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:496)).
   - 0022/0025 say display acknowledgement is missing, but 0025 now defines barrier-completion acknowledgement ([0022:774](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:774); [0025:332](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:332)).
   - 0022 says no keybinding manifest exists, while 0025 requires one ([0022:655](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:655); [0025:386](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:386)).
   - 0022 says submission provenance has not landed, while 0024 includes it ([0022:767](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:767); [0024:159](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:159)).
   - Bounds references point to 0024/0025 OQ6, but they are now 0024 OQ8 and 0025 OQ7 ([0022:779](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:779); [0024:1405](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1405); [0025:999](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:999)).
   - 0022 cites the trap-free primitive as 0024 OQ2; it is now OQ1 ([0022:936](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:936); [0024:1372](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1372)).
   - 0025 calls 0023 identity a live retained object, contradicting 0023’s identity-record rule ([0025:751](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:751); [0023:339](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:339)).
   - 0025’s “closed cwd surfaces” language is stale after 0023’s proposed authorable virtual cwd ([0025:709](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:709)).
   - 0024’s summary still lists only four outcomes after adding lifecycle ([0024:49](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:49)).

11. **The claimed ledger validator does not exist.** LLP 0022 says every obligation has a stable ID and `ref-check` verifies the join ([0022:746](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:746)). The checker explicitly excludes drift and stale-gloss validation and contains no obligation logic ([ref-check:8](/Users/ccheever/projects/ibex/ref-check:8)).

12. **Minor wording contradiction:** 0023 says “Only opaque, authenticated session tokens cross a process boundary” ([0023:791](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:791)), while 0024/0025 necessarily send outcomes, display data, and broker events across it. Qualify this as applying only to VFS/authority-bearing identities.

5. **Suggestions**

- Define a single native `VfsSession` service with a generational session handle, mount table, principal bindings, cwd projection, alias adapter, path cache, and error mapper. Every filesystem, module, cwd, and URL adapter should call it.

- Introduce an authenticated `BindingLocator` record containing principal, integrity, canonical root object, virtual aliases, volume-normalizer identity, and graph-edge provenance. This would resolve package binding, defining principal, display spelling, and arming containment through one type.

- Make module identity source-based: `(runtime, defining principal, SourceId, URL discriminator)`. Treat platform object identity as verification evidence for the source, not as the only file-backed cache key.

- For symlinks, store the kernel-correct physical-relative target but translate it back through the binding table for `readlink`; refuse when no unique virtual-relative spelling exists. This preserves external-tool behavior without leaking physical topology.

- Specify cwd through a private, principal-aware native getter captured by `process`, `node:path`, and URL code. The public writable property should not be the trusted resolution source.

- Build the output-disposition dataset and operation matrix before implementing adapters. Generating a red-team test for every discovered path field will likely find more leaks than hand review.

- Add a small executable reference model of normalization, mount selection, aliasing, symlink traversal, defining-principal selection, and error precedence. Property-test the native resolver against it over case aliases, Unicode normalization, hardlinks, symlink cycles, missing leaves, and rename races.

6. **Open questions**

1. What exact, security-bounded marker algorithm discovers the project root, and how is its version bound into arming?

2. What authenticated artifact maps graph principals and edges to installed roots and virtual aliases?

3. Can two principals share one canonical package root? If so, how is defining principal selected without caller or load-order dependence?

4. What single `SourceId` unifies raw, bundled, cached, and bytecode execution?

5. What platform primitive supplies “verification generation,” and what happens where none is reliable?

6. Is module-cache revalidation intentionally an authorized filesystem lookup on every cache hit?

7. How are kernel-relative symlink bytes translated back through virtual aliases without exposing physical topology?

8. Should non-root principals ship with the shared cwd view/base or a fixed `/project` projection?

9. Are the proposed cwd actions path actions, system-information actions, or a new session-state resource kind?

10. What is the complete runtime/session handle lifecycle across creation, async work, destruction, and worker replacement?

11. Which module URL spellings are canonical, and do query/fragment distinguish module instances?

12. What exact Apple/APFS alias function canonicalizes both policy selectors and runtime occurrences?

13. Will v1 genuinely support non-UTF-8 `readlink` buffers, or should all non-UTF-8 path material be refused consistently?

14. What are the source/destination authorization and identity rules for hardlink, rename, copy, recursive operations, descriptors, and watches?

7. **Readiness verdict**

VERDICT: NOT READY
### Orchestrator verification notes

I re-checked every decisive claim against the repository at revision
`832eb25f0327`. This review is materially correct on its central findings, and
three of them invalidate design choices I made in the round-1 reconciliation.

**Confirmed — and these change the design:**

- **Blocking 2 (occurrence owner). Confirmed; my §2.2 was simply wrong.**
  `crates/capsec-semantics/src/model.rs:585-590` — `LogicalPath` is
  `{root, components, host_bound}` and carries **no binding owner**.
  `crates/capsec-semantics/src/decision.rs:1129-1133` computes
  `expected_owner = if principal.is_package() { Some(principal) } else if
  occurrence.effect_owner.is_package() { … }` — i.e. it prefers **each
  constrained principal**, not the effect owner. LLP 0021:349-350 states
  "Package-root ceiling selectors evaluate separately against each constrained
  package principal's own binding," and `capsec/registry/policy-rules.json`
  carries the machine-readable rule
  `"evaluate-separately-against-each-constrained-package-principals-own-binding"`.
  My round-1 §2.2 asserted the opposite ("derived from the effect owner's
  mapping, **not** from each member of the constrained-principal set"). Round 1's
  Fable review asked me to pin this fork and I pinned it backwards. Retracted.
- **Blocking 1 (staged identity). Confirmed.** `model.rs:1277` makes
  `object_state: ObjectState` a **mandatory** field with no `Option` and no
  `skip_serializing_if`, and `src/host/abi.rs:1058-1062` hardcodes
  `ObjectState::Existing` when `stage == 0` (Requested) — the ABI **speculates
  existence before any lookup**, which is exactly the speculative-stage-fact
  prohibition LLP 0021 states. My §2.1's NamespacePath is therefore not
  expressible today; the `object_state` change is a real LLP 0021 / schema /
  digest-vector obligation and must be named as one rather than assumed.
- **Blocking 8 (alias canonicalization). Confirmed, and my round-1 fix was
  unsafe.** `crates/capsec-semantics/src/containment.rs:393-396` (`path_equal`)
  compares roots and component vectors bytewise, and `arming.rs`'s
  `bind_authorities` binds authored selectors without canonicalization.
  Canonicalizing **only the occurrence**, as my §3 said, would make an authored
  `/project/secrets` selector *fail to match* a canonicalized `/project/Secrets`
  occurrence — breaking matching rather than safely aliasing. Both authored
  selectors and occurrences must be canonicalized by one versioned function whose
  identity enters the digest.
- **Material 14 (`%5C`). Confirmed, and my citation was to dead code.**
  `src/builtins/url.js:163` reads `if ( false && …`, so the `%2F`/`%5C` refusal
  block at `url.js:218-230` that I cited as "which Ibex already implements" is
  **hard-disabled**. The active path rejects `%5C` only in Windows mode, and
  active `pathToFileURL` percent-encodes a literal POSIX backslash — so the `%5C`
  refusal I specified would reject its own serializer's output. Under
  POSIX-everywhere, backslash is an ordinary component character: refuse `%2F`,
  **decode** `%5C`.
- **Material 17 (advertisement). Confirmed.**
  `capsec/registry/policy-rules.json` has `initialProfile.advertisedTargets = []`
  and `candidateTargets = [aarch64-apple-darwin]`. macOS/aarch64 is a
  **candidate**, not an advertised target; the CLI hardcode at
  `src/bin/ibex/runtime.rs:1663` is not a CapSec advertisement. My §3 wording was
  wrong.
- **Blocking 6 / Cross-doc 3 (module algebra). Confirmed.** The file-backed and
  generated variants have different key shapes, so AC18's "raw, bundled, and
  bytecode execution of the same source agree on identity" is unsatisfiable as
  written — a genuine internal inconsistency I introduced. Separately, `repl:<n>`
  and `ibex:eval` are **script inputs** under LLP 0024 §3, not modules, so listing
  them as rows of a *module*-identity algebra is a category error. Only
  `ibex:stdin` is a synthetic module.
- **Cross-doc 9 (diagnostic). Confirmed.** LLP 0025:812 requires startup
  diagnostics to name things **symbolically, not by host path**. My §1.2's
  "diagnostic naming the offending package and its out-of-project root" would
  print a host path and violates it.
- **Cross-doc 11 (ledger validator). Confirmed.** `grep -c 'obligation\|ledger'
  ref-check` is **0** — the checker has no obligation logic. LLP 0022 already
  discloses this honestly in its own ledger row `OBL-LEDGER-CHECK` ("**no** —
  `ref-check` validates `@ref` targets and metadata only"). Any ledger I add must
  follow that pattern and must not claim validation it does not have.
- **Minor 18 (citations). Confirmed.** Several of my citations are off by a few
  lines (`hermes_runtime.cc:1653` is a comment; the return is `:1654-1655`;
  `model.rs:578` is `Home`, `Tmp` is `:579`; the denial string is `:543-545`, not
  `:541`; the pre-authorization opens are `:2010`/`:2015`, not `:2007`). Fixed.

**Refuted / corrected:**

- **Cross-doc 2 (0022 project startup) is stale, not a contradiction.** Codex
  cites 0022 as still selecting the shell cwd as the project candidate. In the
  current file, 0022 **already adopted this document's rule**: "The project
  candidate is chosen by LLP 0023's rule — **discovery origin, then marker
  ascent** — not by taking the shell's cwd as the root." What remains is an
  *intra*-0022 inconsistency (an earlier sentence still says "from the shell's
  current directory") — a sibling wart to report, not a 0023↔0022 contradiction.
  The Fable round-2 review made the same claim and it is refuted the same way.
- **Cross-doc 10's sibling-ledger staleness is real but out of scope.** Those rows
  concern 0022/0024/0025 among themselves; I report them and do not edit siblings.
- Codex's line numbers for the siblings do not resolve against the current files
  (the siblings were revised again mid-round), so I verified those findings by
  content rather than by line.

**Disposition:** Accepted on Blocking 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13 and
Material 10, 12, 14, 15, 16, 17, 18, and on cross-doc 1, 3, 4, 5, 6, 9, 11, 12.
The two round-2 reviews converge independently on the symlink virtual-vs-physical
relative-target defect (Codex B9 / Fable C1), the project-root marker ambiguity
(Codex B3 / Fable C2), the disposition-set incompleteness (Codex B13 / Fable C3),
the `sys:read` misstatement (Codex M10 / Fable C5), and the missing LLP 0002
citation and obligations ledger (Fable C4, which Codex reaches via CD11) — I
weight those most heavily.

Rejections and partial acceptances:

- I **reject** Codex's Material 10 preference that v1 ship the `/project`
  view/base for non-root principals. It is a coherent position and I have
  strengthened OQ6 to carry it, but shipping it in v1 silently changes the meaning
  of `fs.readFileSync("./config.json")` inside ordinary packages relative to every
  other runtime, and the disclosure it prevents is bounded to *names within the
  project namespace*. I keep the shared base for v1, recorded as an information
  grant, and I have made it a fixture-pinned decision rather than a default nobody
  chose. Codex is right, however, that §5.3/§5.4 contradicted each other, and that
  is fixed: "view equals base" now scopes to the **authenticated native view**,
  not to whatever the monkeypatchable `process.cwd` facade returns.
- I **partially accept** Blocking 5 (integrity binding). Verifying installed
  content against the principal digest is right, but the *algorithm* belongs to
  LLP 0021/0014, not here. I state the dependency and row it in the new ledger
  rather than inventing a verification scheme in a path document.
- I **decline to inline** the full operation matrix, the complete wire union with
  discriminant values, and the exhaustive observables annex (Codex M12, M16, B13).
  These are exactly the artifacts this document says must be **generated**;
  inlining a 200-row table into a spec is how such tables go stale. Instead §6/§8
  now pin the closed vocabulary, the totality rule, and the build-failure
  condition, and the ledger names the datasets and their owners. The obligation is
  stated and assigned; the rows are generated.

---

## Round 3 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
  (non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol` — confirmed in the run log; no substitution
- **Reasoning effort:** `ultra` — confirmed in the run log
- **Session id:** `019f55e2-ae8f-7633-89c9-6a0e75c36cf4`
- **Integrity:** the session rollout's final-message md5 is `7d1507764929`, and the
  captured review body's md5 is `7d1507764929` — a byte-for-byte match, which I
  reproduced independently rather than taking on report. This check is stronger
  than citing a session id alone: an id proves a session ran, a hash match proves
  *this body* is what *that session* produced.
- **Date:** 2026-07-12
- **Revision under review:** `a1ba44b33dd1`
- **Redacted:** No. Read under the user's own OpenAI account, authorized by the
  human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session. No access to the
  orchestrating session, to the concurrent Fable round-3 review of the same
  revision, or to any prior LLP 0023 review artifact — the round-1 and round-2
  artifacts were stashed out of `llp/reviews/` for the duration and the directory
  was verified to contain no 0023 files while it ran.
- **Method:** cli-runner, round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round3.md`) — the same brief given
  to the Fable reviewer. The brief named the three round-2 retractions as the
  least-tested material, told the reviewer to judge the current revision on its own
  merits, and warned that a prior round had found a citation pointing at code
  disabled by a literal `false &&`.

### Verbatim review

## 1. **Overall assessment**

The proposal’s architectural direction is strong: one virtual namespace, graph-derived package bindings, staged authorization, a shared native resolution base, structured errors, physical symlink storage, and a generated observable-disposition contract are all good ideas.

It is not yet ready to govern implementation. The most serious defect is in revised §2.2: the occurrence is expressed in the effect owner’s coordinate system, while the evaluator merely changes the expected authority owner for each constrained principal. It does not re-project the target into that principal’s binding. The two statements the document calls compatible are therefore neither coherent in the current model nor implemented by the cited code.

The revised `SourceId`, project-discovery, alias, symlink, lifecycle, error, and delegated-obligation designs also leave security- or identity-critical choices unresolved. Several sibling specifications still contradict the target. These are substantive blockers, not polish.

## 2. **Strengths**

- **§1.1 correctly identifies the shipped project-root bug.** The runtime currently selects the canonical entry parent, or host cwd when there is no entry, rather than a workspace root (`src/bin/ibex/runtime.rs:1669-1679`). Cross-ancestor marker discovery is the right problem to solve.

- **§1.2 correctly rejects guessed package bindings.** The current runtime constructs `project_root/node_modules/<name>` and silently omits the binding when it is absent (`src/bin/ibex/runtime.rs:1823-1854`). Deriving bindings from authenticated graph records is a material improvement.

- **§2.1 correctly identifies speculative requested-stage state.** `ObjectState` has only `Existing` and `AbsentCreate` (`crates/capsec-semantics/src/model.rs:1248-1253`), the occurrence requires it (`model.rs:1273-1284`), and the ABI hardcodes `Existing` at the requested stage (`src/host/abi.rs:1058-1067`). Adding a requested-stage unknown state is necessary.

- **§2.3 correctly separates authorization identity from module identity.** Including the defining principal is necessary to prevent a hard-linked inode shared between package roots from collapsing their compartments. Demoting a platform object from the logical cache key is directionally correct, even though the replacement `SourceId` is not yet defined.

- **§3’s two-sided alias rule and `%5C` correction are correct.** Current containment compares path bytes directly (`crates/capsec-semantics/src/containment.rs:393-414`). The live URL implementation decodes `%5C` on POSIX and re-encodes literal backslashes (`src/builtins/url.js:2886-2963`; `vendored-generated/builtins/url.js:1565-1641`). The old unconditional refusal really is disabled behind literal `false &&` (`src/builtins/url.js:163-168,218-229`).

- **§4 correctly retracts virtual-relative symlink storage.** Current creation derives bytes from the requested spelling and sends them directly to `symlink` (`src/engine/hermes_runtime_fs.cc:3289-3303`), while current `readlink` exposes stored bytes (`hermes_runtime_fs.cc:3342-3361`). Storing physical-relative bytes against the retained parent avoids the aliased-parent unsoundness identified by the document.

- **§5’s shared native base is a sound invariant.** Today `fs` and `node:path` dynamically consult writable JS `process.cwd` state (`src/builtins/fs.js:542-568`; `src/builtins/path.js:59-70`; `src/builtins/process.js:475-476`). Sealed native session state is the right owner.

- **§6’s explicit `non-path` disposition is an excellent design choice.** It distinguishes a reviewed negative classification from an unreviewed omission, which is essential for a total generated contract.

- **§7.1 and §7.2 diagnose real ABI problems.** The host is currently process-global (`src/host/abi.rs:128-130,214-228`), typed filesystem calls carry no runtime identity (`src/host/abi.rs:975-987`), the engine performs lookup before its first typed decision (`src/engine/hermes_runtime_fs.cc:2010-2029`), native errors collapse to “Permission denied” (`hermes_runtime_fs.cc:541-545`), and JS reconstructs codes from messages (`src/builtins/fs.js:764-770`).

- **§8 correctly identifies the cwd registry gap.** `process:cwd` is deny-only (`capsec/registry/capability-definitions.json:279-294`), and `node:path.resolve`/`relative` are currently classified as non-capability surfaces despite their conditional cwd dependency.

- **§9’s delegated-obligation ledger is the right governance mechanism.** Explicit ownership and landed-state tracking are valuable; the problem is that the current ledger is incomplete and already stale.

## 3. **Concerns**

1. **§2.2 does not implement per-principal binding evaluation.**

   - **Severity:** Blocking
   - **Evidence:** The host computes one `requested` path using the actor/effect owner (`src/host/mod.rs:329-334`) and puts that unchanged resource on every effect (`src/host/mod.rs:399-415`). For each constrained principal, `authority_matches` changes only `expected_owner` (`crates/capsec-semantics/src/decision.rs:1124-1147`); containment still compares the same root and component bytes (`crates/capsec-semantics/src/containment.rs:393-414,1009-1017`). `LogicalPath` carries no owner or projection identity (`crates/capsec-semantics/src/model.rs:583-590`).

     Consequently, an occurrence expressed as `package(A)/x` can structurally match B’s `package(B)/**` authority: the owner check compares B’s authority with B, but nothing says the occurrence’s `package` root came from A’s binding. Conversely, a root-owned occurrence for a file in B appears as `project/node_modules/B/x`, so B’s legitimate package-root self-authority does not match. This directly refutes the compatibility claim in §2.2 (`llp/0023-virtual-filesystem-namespace.spec.md:345-401`).

     Bounded process-ceiling package selectors are also not currently viable: they are bound with `package_owner = None` (`crates/capsec-semantics/src/arming.rs:299-315`), while package-root authorities require a package owner (`crates/capsec-semantics/src/decision.rs:1008-1013`).
   - **Resolution criterion:** Represent one objective authenticated target plus a deterministic logical projection for every constrained principal, or an equivalent binding-indexed occurrence algebra. Include those projections or their authenticated derivation in decision-cache identity. Add adversarial fixtures proving both that B’s self-grant cannot authorize A’s file and that B’s self-grant does authorize a deputy operation genuinely targeting B. Merely adding `OBL-OCCURRENCE-OWNER` is insufficient.

2. **§2.3’s `SourceId` is not a normative identity definition, and retained object evidence does not authenticate bytes.**

   - **Severity:** Blocking
   - **Evidence:** §2.3 calls `SourceId` “the authenticated source identity” but does not define a tagged representation, construction algorithm, collision domain, equality rules, defining principal for non-file kinds, alias handling, query/fragment semantics, or generated-provenance authentication (`llp/0023-virtual-filesystem-namespace.spec.md:402-496`).

     Current modules have an arbitrary string ID (`src/module_loader/mod.rs:28-40`), file-backed IDs are lossy host paths (`src/module_loader/mod.rs:805-812`), and the JS cache keys modules by that value (`src/engine/bootstrap/module-loader.js:5253-5261`). The bundler’s provenance is only `{version, entry, deps:[host paths]}` (`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:122-140`), and HBC reuse is mtime-based (`src/bin/ibex/runtime.rs:2479-2497`). A sidecar listing original IDs does not itself cause modules internal to a bundled chunk to participate in the runtime module cache.

     Current `ObjectIdentity` is platform/volume/file only (`crates/capsec-semantics/src/model.rs:616-620`; populated in `src/host/abi.rs:1394-1460`). Device/inode identity—and even inode generation—does not prove that file contents were not mutated in place. `OBL-OBJECT-GENERATION` is named in §2.3 but absent from §9.
   - **Resolution criterion:** Define a versioned tagged `SourceId` algebra and canonical wire encoding for files, builtins, stdin, and generated modules. Separate it from a deterministic human-facing `SourceLabel`. Bind source content, defining principal, armed graph, chunk content, toolchain, and per-original-module factory metadata into authenticated provenance. Specify how raw, bundled, and HBC execution register the same original modules in one cache, or narrow the cross-form singleton claim. Execution must verify the actual bytes, not only the inode.

3. **§1.1 claims to pin project-root discovery exactly, but does not.**

   - **Severity:** Blocking
   - **Evidence:** The algorithm does not define exact marker filenames and parsers, npm/pnpm workspace glob and exclusion semantics, malformed or unreadable marker behavior, what qualifies as a “Cargo-style manifest” or “polyglot,” symlinked membership, or the trusted source of the invoking user’s home (`llp/0023-virtual-filesystem-namespace.spec.md:152-215`). An explicit `--project` override is not required to contain the entry, leaving no `/project` spelling for that entry.

     The current armed-snapshot schema has no project-discovery record or marker-set version and rejects unknown fields (`capsec/schema/armed-snapshot.schema.json:6-28,170-180`). §9 has no owner row for this schema transition or the CLI surface.
   - **Resolution criterion:** Pin a versioned marker set, parser versions, workspace-membership/glob semantics, malformed-marker behavior, nested-marker ordering, symlink and boundary rules, trusted home lookup, and the containment requirement for explicit overrides. Digest-bind the discovery origin, selected marker kind/path, marker-set version, and selected root. Add fixtures for nested workspaces, exclusions, malformed markers, stop boundaries, symlinked entries, and overrides outside the entry tree.

4. **§1.2 lacks a coherent graph-to-binding and integrity representation.**

   - **Severity:** Blocking
   - **Evidence:** The snapshot currently stores `packageGraph` and `rootBindings` separately (`capsec/schema/armed-snapshot.schema.json:73-78,211-245,263-301`), and runtime construction independently emits graph nodes and guessed bindings (`src/bin/ibex/runtime.rs:1799-1811,1823-1854,1900-1947`). The proposal does not say whether package root bindings disappear, are derived, or must be byte-identical to graph location records. Its proposed record also omits the native location needed to populate the existing required `hostPath`.

     §1.2 permits an optional graph principal without a binding (`llp/0023-virtual-filesystem-namespace.spec.md:276-282`), while LLP 0021 requires every graph node to have one (`llp/0021-capsec-effect-model-migration.plan.md:365-369`). The current graph schema has no optional/platform-absent disposition.

     Installed-content integrity is still undefined. The actual disclaimer is at `src/module_loader/mod.rs:41-48`, not the target’s cited line 28. The “symbolic” diagnostic can also leak a host path because locator grammar accepts arbitrary non-whitespace text such as `file:/Users/...` (`capsec/schema/common.schema.json:22-24`; `crates/capsec-semantics/src/model.rs:244-284`).
   - **Resolution criterion:** Define realized installation records explicitly: resolving specifier, physical location, canonical object, alias set, optional/platform disposition, and the exact one-to-one or one-to-many relationship with runtime bindings. Reconcile LLP 0021. Define the integrity-covered byte/tree encoding, symlink treatment, generated and ignored files, postinstall mutation policy, verification time, and invalidation. Use a separately constrained safe diagnostic ID rather than an unrestricted locator.

5. **§2.1’s staged table disagrees with the governing validator.**

   - **Severity:** Blocking
   - **Evidence:** The target gives `DiscoveredPath` an existing witness but not an unambiguous final-object requirement, and gives `CommittedPath` a final object “or handle” (`llp/0023-virtual-filesystem-namespace.spec.md:305-337`). Current governing validation requires a final object at discovery for an existing target and a retained handle at commit or later (`crates/capsec-semantics/src/containment.rs:574-617`). The document also alternates between “no object state asserted” and an explicit `Unknown` state, including AC19 (`llp/0023-virtual-filesystem-namespace.spec.md:1387-1390`).
   - **Resolution criterion:** Define one wire model: `Unknown` valid only at requested stage; exact existing/absent facts required at discovery; and whether commit requires identity and retained handle together or permits named platform-specific alternatives. Version the model, schema, ABI, digest, and cache vectors together, with invalid-stage fixtures.

6. **§3 does not yet define a sound alias canonicalizer or test both-sided application.**

   - **Severity:** Blocking
   - **Evidence:** Current matching is bytewise (`crates/capsec-semantics/src/containment.rs:393-414`). A pre-discovery `LogicalPath` has no volume (`crates/capsec-semantics/src/model.rs:583-590`), while a root binding supplies only the root object’s volume (`crates/capsec-semantics/src/arming.rs:60-68`). The Spec neither prohibits nested filesystem transitions nor explains how canonicalization changes when lookup crosses onto a volume with different case or Unicode behavior.

     AC5 can pass when only occurrences are canonicalized; AC27’s lowercase-authored/lowercase-occurrence grant also fails to prove selector-side conversion. The tests therefore do not detect the exact one-sided implementation that the retraction is meant to forbid.
   - **Resolution criterion:** Define a locale-independent alias-key function with explicit soundness and completeness relative to kernel lookup. Either impose a single-volume binding invariant or require staged reauthorization on volume transition. Test all authored/occurrence permutations for case and NFC/NFD, and inspect the canonical selector bytes in the armed snapshot.

7. **§4’s storage correction still leaves a race and an undefined dangling-link observable.**

   - **Severity:** Blocking
   - **Evidence:** The target computes stored bytes relative to a retained parent but does not require the mutation itself to use that retained parent. Current sync and async implementations still call pathname-based `::symlink` (`src/engine/hermes_runtime_fs.cc:3301-3303,1754-1758`). A swapped parent can therefore redirect the irreversible write before any late check.

     Creation explicitly permits dangling in-mount targets (`llp/0023-virtual-filesystem-namespace.spec.md:701-706`), while `readlink` refuses when stored bytes do not resolve to an in-namespace object (`llp/0023-virtual-filesystem-namespace.spec.md:733-739`). The permitted dangling case consequently has no defined readback. Canonical display spelling needed by `readlink` and `realpath` remains open question 7 (`llp/0023-virtual-filesystem-namespace.spec.md:1518-1526`).
   - **Resolution criterion:** Require `symlinkat(retained_parent, basename)`/descriptor-relative readback, immediate parent and ancestor revalidation, and post-create commit verification. Define dangling translation using an authenticated deepest existing ancestor plus lexical suffix, or explicitly refuse creation of that class. Pin the virtual-relative base and a caller-independent canonical display spelling.

8. **§7.1’s session-handle lifecycle conflicts with async execution and misstates the public ABI boundary.**

   - **Severity:** Blocking
   - **Evidence:** The table says the handle is usable only on the runtime-owning thread and that teardown makes every in-flight call fail (`llp/0023-virtual-filesystem-namespace.spec.md:1033-1079`). Armed async commit and repeated authorization currently execute on filesystem workers (`src/engine/hermes_runtime_fs.cc:1918-1936,3903-3910,1259-1283,3998-4004`), consistent with LLP 0021 (`llp/0021-capsec-effect-model-migration.plan.md:648-663`). A teardown cannot retroactively fail an irreversible write already performed.

     The target also calls both `ex_host_*` and `ex_hermes_*` the narrow semver-major consumer contract. LLP 0002 instead defines five public lifecycle/evaluation/host-call functions as that contract and treats the broader host callbacks as implementation detail (`llp/0002-host-embedding-abi.spec.md:18-21,26-54`). `ExactHermesRuntime*` is already an opaque public runtime handle (`include/exact_runtime.h:27-66`).
   - **Resolution criterion:** Choose and specify a thread-safe session reference, runtime-thread-minted operation lease, or runtime-thread authorization round trip. Define begin-close, drain, cancel, irreversible-commit, create-cleanup, and final-free ordering. Test ABA reuse, wrong thread/process, queued and running work at destruction, and two runtimes over one snapshot. Enumerate actual public versus internal symbol changes before declaring a semver-major consumer transition.

9. **§7.2’s closed error union and global precedence are neither closed nor safe.**

   - **Severity:** Blocking
   - **Evidence:** The current implementation proves the need: native code opens and `fstat`s before the first typed decision (`src/engine/hermes_runtime_fs.cc:2010-2029`), emits generic permission errors (`hermes_runtime_fs.cc:541-545`), and JS parses messages (`src/builtins/fs.js:764-770`).

     But the proposed total order puts `ELOOP` before a discovered-target policy denial (`llp/0023-virtual-filesystem-namespace.spec.md:1084-1126`). Discovering that a chain beyond a denied target exceeds the hop limit requires traversing a resource that policy has already refused, creating an existence/topology oracle. Sibling-required import/resolution classes are also absent, as detailed below.
   - **Resolution criterion:** Define stage-local precedence with the invariant that later-stage facts are never probed solely to outrank an earlier refusal. Split a closed `VfsAdapterError` from a composed `ModuleResolutionError`, or include every module-level class with an explicit owner and order. Add tests proving that denial at a link step prevents probing later links.

10. **§8’s cwd actions cannot be represented or securely enforced by the current registry model.**

   - **Severity:** Blocking
   - **Evidence:** `session-state` is not a permitted resource kind and `session-scoped` is not a permitted globality (`capsec/schema/capability-definitions.schema.json:41-67`). Capability definitions have no root-only-positive-predicate field (`capsec/schema/capability-definitions.schema.json:35-138`). `EffectGate` receives one adapter-supplied predicate Boolean (`crates/capsec-semantics/src/decision.rs:259-265`), while static floors and ambient-root authority are evaluated as separate strata (`decision.rs:683-692,768-779`). Merely adding registry rows cannot prove that the complete constrained set is root-only.

     §8 also reclassifies `path.resolve` and `path.relative` wholesale, although `resolve` stops before consulting cwd once an absolute argument determines the result (`src/builtins/path.js:59-70`), and `relative` delegates through it (`src/builtins/path.js:97-102`).
   - **Resolution criterion:** Version the definitions, selectors, occurrences, and evaluator; define session-state containment; make permitted positive sources core-enforced; and derive the mutation predicate from the complete authenticated constrained-principal set. Add a no-effect branch for fully determined `node:path` calls and adversarial package-to-root deputy tests.

11. **The path-surface and operation contracts are not yet total.**

   - **Severity:** Blocking
   - **Evidence:** The registry often inventories only exports, not returned fields. It has one `node_os:userInfo` export row (`capsec/registry/coverage-edges.json:89212-89250`), while `homedir`, `shell`, and other fields exist only in code (`src/builtins/os.js:190-206`). A new return field could therefore evade the proposed join.

     §6 requires totality over `(surface, field-or-return-shape, alias, mode)` and failure for every undispositioned field (`llp/0023-virtual-filesystem-namespace.spec.md:916-946`), but §8 drops `mode` and says only missing path-bearing fields fail (`llp/0023-virtual-filesystem-namespace.spec.md:1228-1231`). Several rows remain structurally ambiguous: `module.parent`/`children` are objects rather than paths, synthetic-root `Stats` fields are not fully pinned, and non-UTF-8 directory-entry markers have no concrete JS shape.

     Most importantly, two-path operations remain open question 11 (`llp/0023-virtual-filesystem-namespace.spec.md:1534-1540`) even though the document says every path-taking surface uses this resolver. LLP 0021 currently keeps rename, copy, symlink, and hard-link paths closed pending staged adapters (`llp/0021-capsec-effect-model-migration.plan.md:683-691`).
   - **Resolution criterion:** Create an independent generated output-shape inventory with nested, array, and dynamic-shape sentinels; require exact missing-and-stale joins including mode; and mutation-test new fields. For every two-path operation, either normatively keep it closed in v1 or specify source and destination actions, per-side projections, binding transitions, race protocol, atomicity, and module-identity consequences.

12. **§9’s delegated-obligation ledger is incomplete and partly stale.**

   - **Severity:** Material
   - **Evidence:** `OBL-OBJECT-GENERATION` is named in §2.3 but has no row in §9 (`llp/0023-virtual-filesystem-namespace.spec.md:485-495,1239-1268`). There are no rows for project-discovery snapshot fields, marker-versioning, `--project`, optional graph dispositions, the staged-fact schema transition, or the core `SourceId` algebra. `OBL-MODULE-IDENTITY` describes an obsolete version of LLP 0024.

     Target state is also inconsistent across governing artifacts: the registry has no advertised target (`capsec/registry/policy-rules.json:787-790`), the runtime admits macOS/aarch64 (`src/bin/ibex/runtime.rs:1663-1667`), and arming treats the resulting state as `CompleteAdvertised` (`crates/capsec-semantics/src/arming.rs:353-365`), while LLP 0021 calls macOS/aarch64 the sole advertised target (`llp/0021-capsec-effect-model-migration.plan.md:930-943`).
   - **Resolution criterion:** Give every referenced obligation exactly one ledger row, owner-side marker, version transition, target-cell consequence, and acceptance test. Reconcile the target-state artifacts and implement the stable-ID ledger checker before treating “landed” as normative.

13. **Several citations and acceptance checks need correction.**

   - **Severity:** Minor/Non-blocking
   - **Evidence:** The integrity disclaimer cited as `src/module_loader/mod.rs:28` is actually at `:41-48`. `ObjectIdentity` fields are at `crates/capsec-semantics/src/model.rs:616-620`, not line 614. Sync `readlink` validates options but ignores the requested result encoding (`src/builtins/fs.js:5731-5739`); async applies it (`src/builtins/fs.js:5750-5752`), so “ignores options entirely” is too broad.

     AC6’s literal `pathToFileURL(fileURLToPath(u)) === u` cannot succeed because `pathToFileURL` returns a new URL object. The §4 consequence saying Ibex stores relative targets also overstates the normative algorithm, which permits a host-absolute fallback.
   - **Resolution criterion:** Correct the cited ranges and wording; compare canonical `.href` strings or round-trip path strings in AC6; and state the symlink consequence as “physical-relative where representable, otherwise the specified contained fallback.”

## 4. **Cross-document findings**

1. **Blocking — LLP 0024 still assigns module identity to scripts.** LLP 0023 excludes `repl:<n>`, `ibex:eval`, and `.load` scripts from module identity/cache (`llp/0023-virtual-filesystem-namespace.spec.md:455-462,1378-1386`). LLP 0024 requires module identity for `ibex:eval` and `repl:<n>` and its AC15 covers the complete synthetic-source set (`llp/0024-structured-evaluation-and-session.spec.md:234-243,1147-1153,1482-1487`). Revise LLP 0024 so scripts retain source identities only; imported modules, builtins, and any agreed stdin module enter the module cache.

2. **Blocking — the supposedly closed error union omits sibling-required errors.** LLP 0024 requires `unknown-builtin`, generic resolution failure, and `unsupported-dependency-TLA` (`llp/0024-structured-evaluation-and-session.spec.md:261-273`). LLP 0022 defines an additional in-artifact root-import-unprovable refusal (`llp/0022-repl-behavior-and-semantics.spec.md:291-298`). LLP 0023’s claim that a current LLP 0022 open question asks which enum should carry this is stale; no such question exists at `llp/0022-repl-behavior-and-semantics.spec.md:1073-1108`.

3. **Blocking — lifecycle completion is still contradictory.** LLP 0024 says `process.exit` unwinds the native evaluation frame (`llp/0024-structured-evaluation-and-session.spec.md:564-570`), and LLP 0022 repeats the unwind model (`llp/0022-repl-behavior-and-semantics.spec.md:844-846`). LLP 0025 says the call parks forever, explicitly does not unwind, and emits an out-of-band lifecycle record (`llp/0025-terminal-session-ownership.spec.md:654-671`). The corpus must select one mechanism and define rollback/disposal accordingly.

4. **Material — LLP 0025 misuses §2.3’s retained object as a cross-session history identity.** LLP 0023’s record is runtime-local, invalidated at teardown, and not serialized (`llp/0023-virtual-filesystem-namespace.spec.md:485-496,1061-1079`). LLP 0025 instead uses creation time with canonical-path fallback across sessions and calls it the same record (`llp/0025-terminal-session-ownership.spec.md:748-774,965-967`). Define a separate `ProjectHistoryScopeId`.

5. **Material — startup diagnostic disclosure conflicts.** LLP 0023 permits only a safe package identifier plus symbolic `outside-project-mount` (`llp/0023-virtual-filesystem-namespace.spec.md:267-271`), while LLP 0022 permits the host package-root path (`llp/0022-repl-behavior-and-semantics.spec.md:452-459`). LLP 0025’s symbolic rule applies specifically to history diagnostics (`llp/0025-terminal-session-ownership.spec.md:809-813`), so LLP 0023 overstates it as a general sibling rule.

6. **Material — cancellation disagrees on `defeated`.** LLP 0024 makes `Pending` unresolved and `defeated` terminal (`llp/0024-structured-evaluation-and-session.spec.md:676-709`). LLP 0025 says `defeated` never resolves, then says the request resolves defeated (`llp/0025-terminal-session-ownership.spec.md:551-566,866`). Reserve non-resolution for `Pending`.

7. **Material — `SourceId` and source-map/display identity are conflated.** LLP 0024 calls an imported file’s source identity its virtual URL and keys source maps by it (`llp/0024-structured-evaluation-and-session.spec.md:234-243,527-534`), while LLP 0023 requires an opaque authenticated identity but leaves canonical display and query/fragment rules open (`llp/0023-virtual-filesystem-namespace.spec.md:438-453,1521-1533`). Define separate `SourceId` and `SourceLabel` contracts.

8. **Material — sibling ledgers are stale.** LLP 0023’s `OBL-MODULE-IDENTITY` row falsely describes current LLP 0024 (`llp/0023-virtual-filesystem-namespace.spec.md:1265`). LLP 0022 says typed `.load` and the drain boundary are unstated although LLP 0024 now specifies them, and it claims a display-wire contradiction that current LLPs 0024/0025 have resolved (`llp/0022-repl-behavior-and-semantics.spec.md:885-900`; `llp/0024-structured-evaluation-and-session.spec.md:188-205,1239-1258`; `llp/0025-terminal-session-ownership.spec.md:262-276`). LLP 0025’s O-2, O-5, and O-8 are likewise stale (`llp/0025-terminal-session-ownership.spec.md:865-871`).

9. **Material — async fatality remains dangling.** LLP 0022 makes program/file async failures fatal and prompt failures nonfatal (`llp/0022-repl-behavior-and-semantics.spec.md:401-409`). LLP 0024 delegates process outcome to the consumer/LLP 0025 (`llp/0024-structured-evaluation-and-session.spec.md:1315-1328`), but LLP 0025’s status table contains no async-failure row (`llp/0025-terminal-session-ownership.spec.md:697-710`).

10. **Minor/Non-blocking — LLP 0022 states two project-root rules.** It first says startup installs shell cwd as the binding, then correctly says cwd is only the marker-discovery origin (`llp/0022-repl-behavior-and-semantics.spec.md:237-240,259-260`). The first statement should be narrowed.

The siblings otherwise align well on typed `.load` reads, captured logical referrers, cwd/path behavior, the unstyled semantic display tree, and worker-local runtime ownership. Those seams do not need redesign.

## 5. **Suggestions**

- Replace the caller-relative occurrence path with an authenticated structure such as:

  `TargetObject + { BindingId -> LogicalProjection }`

  The host discovers one objective target; the semantic core selects the projection belonging to each constrained principal. This makes §2.2 explicit, makes cache keys auditable, and avoids overloading one `LogicalPath` with incompatible coordinate systems.

- Split identity into three named layers:

  - `SourceId`: opaque authenticated module-cache identity.
  - `SourceLabel`: deterministic virtual URL or synthetic diagnostic/source-map label.
  - `ObjectEvidence`: retained descriptor, generation, and verified content digest supporting a file-backed `SourceId`.

- Use a digest-bound provenance DAG rather than a flat bundle sidecar. Each original source node can bind its `SourceId`, defining principal, content digest, dependencies, transformed factory, source map, and containing chunk. This gives raw, bundled, and bytecode forms a concrete equivalence proof.

- Replace one global error precedence list with a staged error lattice: input validation, namespace projection, authorized discovery, commit, and module-resolution wrapping. A later stage must never be evaluated solely to outrank an earlier result.

- Model async operations with session operation leases. A lease captures the session generation, authenticated principal stack, requested facts, and allowed worker behavior. Teardown stops new leases, cancels queued work, drains or records already-committed work, then frees session state.

- Consider making v1 explicitly single-volume and refusing nested mount transitions. That is a defensible narrow profile until per-volume lookup semantics and volume-crossing reauthorization are fully specified.

- Generate output-shape metadata from builtin schemas or annotated return constructors, then mutation-test it by adding fields and aliases. A registry containing only export names cannot prove return-field totality.

- Use property-based/model-checked tests for the cross-product of principals, bindings, aliases, symlink swaps, stages, and error precedence. These rules are compositional enough that example fixtures alone are unlikely to cover the dangerous interactions.

## 6. **Open questions**

1. What exact authenticated representation lets one target be evaluated in every constrained principal’s binding without trusting caller-supplied projections?

2. What bytes and metadata construct a file-backed `SourceId`, and what prevents content mutation after verification?

3. Is canonical display spelling part of authenticated graph data, and how are hard links, aliases, query strings, and fragments ordered?

4. Should outermost-workspace selection remain the default authority boundary, or should broader-than-nearest selection require an explicit workspace or CLI declaration?

5. Are optional/platform dependencies absent graph nodes, present nodes with absent installation records, or edge-specific dispositions? How are multiple installations of one locator represented?

6. Does v1 prohibit cross-volume project trees, or must discovery switch canonicalizers and reauthorize at every volume boundary?

7. What should `readlink` return for a permitted dangling target, and may any contained target require host-absolute stored bytes in the single-mount profile?

8. Do async workers hold thread-safe session references, immutable operation leases, or perform owner-thread authorization round trips? What exactly happens after an irreversible operation during teardown?

9. Is the closed error owner the VFS adapter or the complete module resolver? Which facts may be probed at each precedence stage?

10. Will `rename`, `copyFile`, `link`, and symlink creation remain closed in v1, or what is the complete two-sided authorization and atomicity matrix?

11. Is universal cwd observation the intended information grant, or should v1 use the stricter `/project`-masked profile for non-root principals?

12. What separate, stable cross-session identity should LLP 0025 use for history scope?

## 7. **Readiness verdict**

The proposal has a good architectural center, but unresolved issues in §2.2, `SourceId`, project and package binding construction, staged identity, symlink mutation, session teardown, error precedence, cwd authorization, operation totality, and sibling coherence prevent it from safely governing an implementation.

VERDICT: NOT READY
### Orchestrator verification notes

I re-checked every decisive claim against the repository at revision
`a1ba44b33dd1`. The two central findings are correct, and the concurrent Fable
round-3 review found both independently — which I weight as decisive.

**Confirmed — and Blocking 1 is the most serious defect any round has produced:**

- **Blocking 1 (§2.2 does not implement per-principal binding evaluation).
  Confirmed by construction.** `LogicalRoot` is a **payload-free enum**
  (`crates/capsec-semantics/src/model.rs:575-581`), and
  `logical_path_for_host_components` builds
  `LogicalPath { root: binding.logical_root, components: <tail after the binding> }`
  (`arming.rs:214-218`). Therefore `/proj/node_modules/A/x` mapped under **A's**
  binding and `/proj/node_modules/B/x` mapped under **B's** binding are the *same
  value*: `{root: Package, components: ["x"]}`. The occurrence does not say which
  package. Meanwhile `decision.rs:1136-1139` sets
  `same_package_root_owner: !has_package_root || authority.package_root_owner == expected_owner`
  — comparing the **authority's** declared owner to the **principal under test**,
  never to the binding the *resource* was mapped under. So for an occurrence on
  A's file, constrained principal B's own package-root grant passes the owner gate
  (B == B) *and* bytewise containment, and authorizes B's dimension for A's file.
  That is precisely what my AC 20a asserts cannot happen.

  My round-2 §2.2 therefore stated a **false safety property in the present
  tense**. The retraction fixed the *rule* but asserted a *consequence* the shipped
  model cannot deliver, and called the two statements "compatible." They are not
  compatible without a per-principal projection of the resource. This is the second
  time this section has been wrong in three rounds, and both times the error was
  reasoning from code rather than from what the code *computes*.
- **Blocking 2 (`SourceId` undefined). Confirmed**, and Fable's sharper form is
  accepted: my §2.3 defined the file-backed case as "the authenticated source
  identity of that file within its binding," which is a **circularity, not a
  constructor**, and the three properties I demanded of it — unify same-principal
  hard links; retained object is evidence not key; build-time computable and
  portable in a provenance manifest — are **jointly unsatisfiable**. Notably the
  hard-link-unification property was my own invention, is not Node's behavior
  (Node splits hard links), and is not needed by anything: the compartment-collapse
  fix requires that two *different* packages sharing an inode be two modules, which
  splitting delivers for free. Dropping it makes the key definable and *reduces*
  divergence from Node.
- **Blocking 8 (LLP 0002 boundary). Confirmed, and it cuts the other way too.**
  LLP 0002 says the semver-major contract is **five `ex_hermes_*` functions plus
  the host-call installer**, and that "the full `ex_host_*` callback surface …
  is an implementation detail." My §7.1 called `ex_host_*` the narrow contract —
  wrong. And `ExactHermesRuntime*` is **already an opaque public runtime handle**
  (`include/exact_runtime.h:27-28`), so part of what I demanded already exists;
  the real gap is the process-global `Host` and the runtime-less typed fs ABI.
  `OBL-ABI-HANDLE` was mis-scoped in both directions.
- **Blocking 9 (`ELOOP` before discovered-target denial). Confirmed** — and it is
  an oracle, not a cosmetic ordering wart. Establishing that a chain *beyond* a
  denied link exceeds the hop bound requires traversing links the policy already
  refused. Discovered-target denial must outrank `ELOOP`.
- **Blocking 10 (registry model). Confirmed.**
  `capsec/schema/capability-definitions.schema.json` contains **no**
  `session-state` resource kind, **no** `session-scoped` globality, and **no**
  predicate field at all. My two new actions are unrepresentable as written; this
  is a schema version change, not "adding rows."
- **Blocking 7 (symlink race). Confirmed.** Creation still calls pathname-based
  `::symlink` (`src/engine/hermes_runtime_fs.cc:3301-3303`), so computing bytes
  against a retained parent while writing through a pathname leaves the swap window
  open. `symlinkat(retained_parent, basename)` is required.
- **Blocking 3 / Fable C4 (marker membership). Confirmed.** "A workspace of which
  the discovery origin is a member" requires evaluating workspace globs, whose
  dialects differ across npm/yarn/pnpm/bun; and "Cargo-style manifest where the
  project is polyglot" is circular — polyglot relative to a root not yet selected.
  Two conforming implementations can select different roots.
- **Concern 13 / Fable C8 (citations). Confirmed.** The integrity disclaimer is at
  `src/module_loader/mod.rs:46-48`, not `:28`; `ObjectIdentity` is at
  `model.rs:616-620`, not `:614`; AC6's `pathToFileURL(fileURLToPath(u)) === u`
  cannot hold because `pathToFileURL` returns a fresh `URL` object.

**Refuted / corrected:**

- **Cross-doc 1 and 8 read a stale LLP 0024.** The current LLP 0024
  (`b0ff4ea3247e`) has **landed** the module-identity realignment: §7.9 now reads
  "Module **identity** is LLP 0023 §2.3's, and this document does not restate the
  mechanism," with no inline tuple and no AC number. Codex's claim that 0024 "still
  assigns module identity to scripts" does not hold against the file; 0024 states
  the *requirement* that identity cover `ibex:stdin`/`ibex:eval`/`repl:<n>` as
  **sources**, which is compatible with §2.3 keeping scripts out of the *module*
  cache. What *is* true — and what Codex's CD8 catches in the mirror — is that **my
  own `OBL-MODULE-IDENTITY` ledger row is now the stale one**, describing a sibling
  that no longer exists. Fixed, and every ledger row now carries the sibling
  revision it was verified against, so staleness is detectable by inspection.
- **Cross-doc 5 (startup diagnostic) is right that I mis-cited, but wrong about the
  disposition.** I cited LLP 0025 for a general "startup diagnostics are symbolic"
  rule. There is no such general rule: 0025's symbolic-naming sentence is a
  parenthetical about the *legacy history file*. Meanwhile current LLP 0022 §4 says
  the no-host-path rule "does not bind the CLI's own startup diagnostics" and that
  an arming failure naming an out-of-project package root **may name it there** —
  the opposite of what my §1.2 mandated, and it mis-attributes the must-name
  requirement to *me*. I have aligned with 0022 (a pre-arming, operator-facing
  diagnostic is not a JavaScript disclosure) and removed my mis-citation of 0025.
- I **decline** Codex's framing that the whole document is blocked on the two-path
  operation matrix. I adopt Fable's narrower fix instead: a conservative v1 rule
  now (both endpoints take the full pipeline independently; a cross-binding-owner
  `rename`/`link` is refused in v1), with the general matrix left to the generated
  dataset. Inlining a full two-path matrix into a spec is how such matrices go
  stale.

**Disposition:** Accepted on Blocking 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 and
Material 12 and Minor 13; and on cross-doc 2, 3, 4, 6, 7, 9, 10. Where this review
and the concurrent Fable review converge — §2.2's false safety claim, `SourceId`'s
undefinedness, the marker-membership gap, the two-path gap, the stale ledger row,
and the LLP 0002 mischaracterization — the finding is treated as decisive.

---

## Round 4 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
  (non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`; **reasoning effort:** `ultra` — both confirmed in the
  run log; no substitution
- **Session id:** `019f5600-58f2-7ea2-9d2f-a64302c2d800`
- **Integrity:** rollout final-message md5 `d1fda436b544` == captured body md5,
  byte-for-byte. I reproduced the body hash independently rather than taking it on
  report.
- **Date:** 2026-07-12
- **Revision under review:** `b60400977333` (`shasum -a 256`, first 12). Note: the
  concurrent Fable reviewer reported this document as `7f71f6986b7d`, which is the
  **`git hash-object` blob SHA-1 of the identical bytes** — not drift. I verified
  both hashes against the same file; the content was stable across the round and
  both reviewers saw the same document.
- **Redacted:** No. Read under the user's own OpenAI account, authorized by the
  human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session; no access to the
  orchestrating session, to the concurrent Fable round-4 review of the same
  revision, or to any prior LLP 0023 review artifact — rounds 1–3 were stashed out
  of `llp/reviews/` for the duration and the directory was verified empty of 0023
  files while it ran.
- **Method:** cli-runner, round-4 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round4.md`) — the same brief given
  to the Fable reviewer. The brief carried an explicit methodological warning to
  **prefer running artifacts to reading them**, which this review acted on to
  decisive effect (see the verification notes).

### Verbatim review

1. **Overall assessment**

The proposal’s core direction is good: one synthetic namespace, staged authorization, per-principal authority coordinates, and separate authorization, module, retained-object, and display identities. Several round-3 repairs are notably honest about what the shipped model cannot yet guarantee.

However, revision `b60400977333` is not ready to govern an implementation. The blockers are concrete:

- the workspace-membership algorithm fails its own canonical monorepo case;
- per-principal projection is neither representable nor defined at the pre-lookup alias stage;
- `SourceId` is not total for project files, builtins, or `ibex:stdin`;
- hard-link authorization is unsafe, and `renameat`/`linkat` remain name-racy;
- the symlink-creation guarantee lacks an atomic realizable protocol; and
- error precedence still admits target-existence disclosure.

The host-path arming diagnostic is the right default for a privileged, pre-evaluation CLI error. Embedders should receive separate privileged detail and guest-safe projections rather than an undifferentiated string.

Cross-document findings below were checked against sibling snapshots `0022@88decefdc683`, `0024@c264085e7ebf`, and `0025@cfe6e1a65761`.

2. **Strengths**

- §2.1’s staged `NamespacePath → DiscoveredPath → CommittedPath` model is materially better than pretending every request already names an object. It correctly identifies that requested-stage `object_state` is mandatory today and is incorrectly hardcoded as existing ([0023:351](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:351), [model.rs:1273](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1273)).

- §2.2 correctly retracts the prior present-tense containment claim and makes it conditional on `OBL-OCCURRENCE-PROJECTION` ([0023:419](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:419), [0023:463](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:463)). The governing machine artifact really does say `evaluate-separately-against-each-constrained-package-principals-own-binding` ([policy-rules.json:580](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:580)), and the mapper’s exact-owner filter computes the intended ordinary root, package, nested-binding, and non-package cases ([arming.rs:179](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:179), [arming.rs:191](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:191)).

- §2.3’s separation of authorization identity, `SourceId`, `SourceLabel`, and retained verification evidence is conceptually sound ([0023:480](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:480), [0023:516](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:516), [0023:537](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:537)). Withdrawing same-principal hard-link unification was the right decision.

- §1.1’s outer-workspace/nearest-lockfile/nearest-manifest priority, explicit ascent stops, and fail-closed handling of malformed markers are good security-boundary decisions ([0023:210](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:210), [0023:215](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:215), [0023:228](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:228)).

- §4 now recognizes the difference between a retained parent and a retained link object, requires descriptor-relative creation, and defines dangling-link readback rather than hand-waving it away ([0023:774](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:774), [0023:833](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:833), [0023:855](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:855)). The cited current gaps are real: the engine retains the link object but still creates through pathname `symlink(2)` ([hermes_runtime_fs.cc:570](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:570), [hermes_runtime_fs.cc:3301](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3301)).

- The reachability check around `%5C` was methodologically correct: the older refusal is indeed behind literal `false &&` ([url.js:163](/Users/ccheever/projects/ibex/src/builtins/url.js:163)), while the active implementation rejects `%2F` and decodes `%5C` on POSIX ([url.js:2935](/Users/ccheever/projects/ibex/src/builtins/url.js:2935), [url.js:2942](/Users/ccheever/projects/ibex/src/builtins/url.js:2942)). The external Node comparison is wrong, but the code-reachability analysis is right.

- §7.2’s correction making discovered-target denial outrank `ELOOP` is sound: walking beyond an already denied link would disclose topology outside the caller’s authority ([0023:1294](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1294)).

- §8 is commendably explicit that the cwd actions cannot be represented by the current schema ([0023:1391](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1391)). Machine inspection confirms the missing globality, resource kind, and predicate vocabulary ([capability-definitions.schema.json:41](/Users/ccheever/projects/ibex/capsec/schema/capability-definitions.schema.json:41), [capability-definitions.schema.json:48](/Users/ccheever/projects/ibex/capsec/schema/capability-definitions.schema.json:48), [capability-definitions.schema.json:204](/Users/ccheever/projects/ibex/capsec/schema/capability-definitions.schema.json:204)).

3. **Concerns**

1. **Blocking — §1.1’s workspace-membership rule cannot satisfy AC 3a.**

   **Evidence:** Membership matches the discovery origin itself relative to the declaring directory, with `*` not crossing `/` ([0023:180](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:180), [0023:194](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:194), [0023:197](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:197)). Therefore `packages/*` matches `packages/foo` but not origin `packages/foo/src`. AC 3a nevertheless requires `packages/foo/src/app.js` to select the workspace root ([0023:1499](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1499)). Ibex itself uses exactly `workspaces: ["packages/*"]` ([package.json:5](/Users/ccheever/projects/ibex/package.json:5)). Executing the specified `* → [^/]*` rule confirmed the mismatch.

   The glob dialect is also not fully pinned: `?`, character classes, braces, escaping, trailing slashes, dot components, and unsupported constructs have no defined meaning or refusal.

   **Resolution criterion:** Define membership as “the discovery origin lies at or below a directory matched as a workspace member,” identify that member-root ancestor explicitly, and either completely specify or fail closed on unsupported glob syntax. Add exact fixtures for nested origins, exclusions, last-match behavior, malformed markers, and unsupported patterns.

2. **Blocking — Per-constrained-principal projection has no valid transport or requested-stage derivation.**

   **Evidence:** §2.2 says no new wire field is needed while also requiring a projection set to be carried ([0023:456](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:456)). The actual model has one resource per effect and one `requested` path for the whole constrained set ([effect.schema.json:49](/Users/ccheever/projects/ibex/capsec/schema/effect.schema.json:49), [model.rs:1421](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1421), [model.rs:1509](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1509)). The host computes that resource once for the acting principal ([host/mod.rs:329](/Users/ccheever/projects/ibex/src/host/mod.rs:329), [host/mod.rs:397](/Users/ccheever/projects/ibex/src/host/mod.rs:397)), and the cache stores one resource separately from the principal set ([cache.rs:49](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/cache.rs:49)). Payload-free `LogicalRoot::Package` cannot recover which projection belonged to which principal ([model.rs:573](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:573)).

   The staging is also backwards for aliases. Requested authorization must precede lookup ([0023:365](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:365)), but §2.2 describes discovering one object and then projecting it ([0023:439](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:439)). Current bindings have no authenticated virtual-alias prefix ([arming.rs:58](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:58)), so `/project/node_modules/B/x` cannot be projected to B’s physical workspace binding before lookup. §4 and §4.1 further regress to “effect owner’s binding/authority” wording ([0023:774](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:774), [0023:891](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:891)).

   **Resolution criterion:** Version the occurrence model to carry a canonical exact map of `{principal, projectedResource}` whose key set equals `constrainedPrincipals`, or carry one owner-independent authenticated namespace input from which the semantic core derives the map. Cache principal-resource pairs, not an unpaired resource and set. Define requested projection from digest-bound virtual aliases without I/O, and discovery/commit projection from retained canonical location. Apply it at every symlink step and both endpoints, with root, nested-package, Runtime, ModuleLoader, Quarantine, absent-create, and alias fixtures.

3. **Blocking — The §2.3 module-key/`SourceId` algebra is not total or fully defined.**

   **Evidence:** The universal key is `(runtime, defining principal, SourceId)` ([0023:501](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:501)), while a file `SourceId` requires a defining-principal locator and integrity digest ([0023:521](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:521)). Yet project bindings are ownerless by schema ([armed-snapshot.schema.json:263](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:263), [armed-snapshot.schema.json:287](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:287)), and Root has only `identity`, not locator/integrity ([model.rs:304](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:304)). Therefore “owner of the most specific binding” does not yield a defining principal for ordinary project files ([0023:554](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:554)). Builtins and `ibex:stdin` likewise have no containing binding, leaving the outer principal slot undefined.

   The outer key also duplicates the principal embedded in file `SourceId` without requiring equality. Query/fragment equality remains open even though the identity is described as defined ([0023:1745](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1745)).

   **Resolution criterion:** Define a tagged, total algebra and canonical encoding for every variant: project file keyed by authenticated root identity; package file by complete package principal; builtin by a named runtime/module-loader domain plus source key; `ibex:stdin` by authenticated session/root identity. Remove the duplicated principal or normatively require equality. Pin collision scope, query/fragment treatment or refusal, and canonical equality vectors.

4. **Material — The raw/bundle/bytecode unification claim lacks the build and runtime mechanism needed to make it true.**

   **Evidence:** §2.3 says raw, bundled, cached, and bytecode forms share one live instance through a per-original-module provenance manifest and calls the result build-computable and portable ([0023:528](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:528)). Current bundling emits only absolute dependency paths ([rolldown-bundle.mjs:122](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:122)); package attribution is self-reported `name@version` and expressly not an integrity boundary ([transforms.mjs:791](/Users/ccheever/projects/ibex/packages/ibex-devtools/src/scripts/transforms.mjs:791)); the bundler receives no armed graph or bindings ([runtime.rs:3221](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:3221)); and the loader caches the generated record’s path-based id ([module-loader.js:5253](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5253)). Merely carrying IDs does not register each original module’s initialized exports under that ID.

   The only specified path canonicalizer is volume-dependent ([0023:660](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:660)), which cannot also serve as a portable build identity without another rule. The obligation is assigned to LLP 0019, whose subject is the Hermes compatibility transform, not artifact provenance ([0023:1461](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1461)).

   **Resolution criterion:** Define a digest-bound provenance schema produced from authenticated graph/binding data; reject duplicate, unknown, out-of-snapshot, and principal/path-mismatched rows; bind it to artifact bytes; and specify the runtime original-module registry that makes later raw loads return the already-instantiated bundled/HBC module. Use a separate portable source-path normalizer. Test mixed execution forms in one runtime.

5. **Blocking — §4.1’s two-path rule is unsafe and not representable by the current effect data.**

   **Evidence:** `link` is specified as source read plus destination-parent write ([0023:895](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:895)). That lets a path-scoped caller hard-link a read-only source into its writable tree and mutate the source inode through the alias. Both governing LLP 0013 and reachable engine code correctly require source write as well ([0013:1068](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:1068), [hermes_runtime_fs.cc:3318](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3318)).

   Retained parents plus ordinary `renameat`/`linkat` do not bind the source basename. It can be swapped after authorization and before the syscall. LLP 0021 keeps analogous `unlinkat` removal closed for exactly this reason and says rename/link adapters remain pending ([0021:683](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:683), [0021:688](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:688)).

   The coverage schema has no endpoint-role field ([coverage-edge.schema.json:42](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:42)); current rows contain undifferentiated effects, such as one `fs:write` for rename ([coverage-edges.json:36536](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:36536)). The cross-binding refusal has no reason/code in the closed error union, and §4.1 has no acceptance criterion.

   **Resolution criterion:** Require source read and source-object write for hard links. Add source-object, source-parent, destination-object, and destination-parent roles to the data model; apply each across the complete constrained set; add a stable cross-binding reason and precedence; and generate pairwise/race fixtures. Keep portable rename and hard-link creation closed until an object-bound primitive is specified—e.g. source-fd `linkat(..., AT_EMPTY_PATH)` where available. Copying can be designed separately around an opened source descriptor.

6. **Blocking — The symlink-creation safety property has no atomic realizable protocol.**

   **Evidence:** The spec promises that an escaping link is refused before it exists and that Ibex never writes an escape artifact ([0023:797](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:797), [0023:1703](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1703)). It authenticates the target or deepest existing ancestor, computes bytes, calls `symlinkat`, and post-verifies only the retained link parent ([0023:808](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:808), [0023:840](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:840)). Target topology can change between target verification and publication, producing a link that resolves elsewhere. A post-create target check still leaves a publication window, and future ancestor replacement can change any pathname-based symlink’s meaning.

   AC 7 and 7a test static topology, not a target/ancestor swap ([0023:1530](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1530)).

   **Resolution criterion:** Either specify and prove an atomic construction/commit protocol against the chosen concurrency threat model, or narrow the guarantee to an explicitly defined authorization-time snapshot and acknowledge the publication/future-mutation limit. If “never publishes an escape artifact under concurrent external mutation” remains literal, symlink creation must stay closed in v1.

7. **Blocking — Error precedence still permits an existence oracle and conflicts with the sibling resolver order.**

   **Evidence:** The path table puts in-mount `ENOENT` at #8 and discovered-target denial at #9 ([0023:1287](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1287)), while §4 requires authorizing each discovered target before accessing it ([0023:784](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:784)). A symlink to a denied nonexistent target must return denial without probing absence. AC 24 does not include this cross-product ([0023:1641](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1641)).

   The broader composition rule says specifier-level classes precede path classes ([0023:1263](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1263)), while LLP 0024 puts generic resolution failure before outside-mount/path authorization ([0024:309](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:309)). Resolution presently performs host-backed checks ([module_loader/mod.rs:691](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:691), [module_loader/mod.rs:727](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:727)), contradicting §7.2’s no-lookup-before-authorization invariant ([0023:1303](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1303)).

   **Resolution criterion:** Replace the flat table with a shared, phase-aware state machine: session/input validation; purely syntactic specifier refusals; virtual containment and requested authorization; authorized discovery; reauthorization of every discovered path; then absence/resolution and later execution facts. Generate the union and pairwise precedence fixtures, including symlink → denied-and-absent with syscall observation.

8. **Material — Canonical `SourceLabel`, `readlink`, and `realpath` behavior remains unresolved.**

   **Evidence:** `SourceLabel` must deterministically drive `import.meta.url`, source maps, stacks, and errors ([0023:537](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:537)). `readlink` and `realpath` likewise require translated or canonical virtual spellings ([0023:848](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:848)), but OQ7 admits the spelling tie-break is still unpinned ([0023:1739](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1739)). The output table classifies `readlink` as `virtual-relative` without stating its base ([0023:1078](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1078), [0023:1113](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1113)).

   **Resolution criterion:** Define one deterministic display-selector function independent of import order. Explicitly distinguish symlink aliases from distinct hard-link directory entries, state whether `readlink` returns an absolute virtual target or a path relative to the canonical link parent, and pin sync/async/Buffer/dangling/package-alias fixtures.

9. **Material — `OBL-CWD-SCHEMA` does not yet specify a complete implementable resource algebra.**

   **Evidence:** The spec correctly identifies missing `session-state`, `session-scoped`, and predicate vocabulary ([0023:1391](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1391)), but the required change also spans the selector union, occurrence union, Rust model, canonical bytes, containment, cache identity, session generation, and version cutover. Those unions currently omit session state entirely ([authority-selector.schema.json:12](/Users/ccheever/projects/ibex/capsec/schema/authority-selector.schema.json:12), [effect-occurrence.schema.json:29](/Users/ccheever/projects/ibex/capsec/schema/effect-occurrence.schema.json:29), [model.rs:970](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:970)).

   AC 13 says a profile that “closes” cwd observation still makes `process.cwd()` and resolving operations succeed with `/project` ([0023:1570](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1570)). A binary denial cannot produce that sanitized success.

   **Resolution criterion:** Specify exact selector and occurrence shapes, equality/containment, session and generation identity, canonical encoding, digest/cache rules, and schema-version transition. Define the stricter profile as an explicit constant/no-effect projection to `/project`, or define another result branch; do not call it a denial while requiring successful sanitized output.

10. **Material — The public ABI claim is unsubstantiated, and operation-lease semantics risk freezing authority.**

   **Evidence:** §7.1 calls the runtime handle a semver-major public change while acknowledging that `ExactHermesRuntime*` already exists ([0023:1191](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1191), [0023:1208](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1208)). The pointer is already opaque, creation returns it, and evaluation already receives it ([exact_runtime.h:27](/Users/ccheever/projects/ibex/include/exact_runtime.h:27), [exact_runtime.h:60](/Users/ccheever/projects/ibex/include/exact_runtime.h:60)); its private struct can carry session state without changing layout visible to consumers ([hermes_runtime_internal.h:85](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_internal.h:85)). The demonstrated gaps are the process-global `HOST` and internal callback lacking runtime identity ([abi.rs:130](/Users/ccheever/projects/ibex/src/host/abi.rs:130), [abi.rs:975](/Users/ccheever/projects/ibex/src/host/abi.rs:975)).

   “Operation lease … captures … decided facts” is ambiguous about whether an allow survives revocation ([0023:1221](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1221)); LLP 0021 requires current-generation checks at operation time ([0021:398](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:398), [0021:863](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:863)). The teardown promise that undelivered results “fail” also lacks a recipient once the runtime is destroyed; current code deliberately drops/leaks such callbacks because no JS runtime remains ([hermes_runtime.cc:900](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:900), [hermes_runtime.cc:2896](/Users/ccheever/projects/ibex/src/engine/hermes_runtime.cc:2896)).

   **Resolution criterion:** Either reuse the existing opaque pointer plus an internal generation/session map, or state the exact public signature change that requires a major version. Limit leases to immutable attribution and authenticated object facts; require fresh generation-sensitive decisions at discovery, commit, repeat, and delivery. Define an external audit/supervisor destination for post-destroy results.

11. **Material — The §9 revision-stamping repair is absent, and the ledger already contains stale or missing edges.**

   **Evidence:** §9 says every row records the revision it was checked against ([0023:1448](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1448)). The table has no revision column; twenty of twenty-one rows merely say `no`, and only `OBL-MODULE-IDENTITY` contains a hash ([0023:1456](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1456), [0023:1476](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1476)). That one “Delivered” row is stale against current 0024.

   Inbound `OBL-TYPED-READ` is also missing. LLP 0022 assigns `.load`’s credential-verifying pre-read, authenticated bytes/referrer, and TOCTOU handling to 0023 and 0021 ([0022:969](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:969)); 0023 mentions operator provenance but has no corresponding row or AC ([0023:1232](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1232)).

   **Resolution criterion:** Add a verified-against revision/hash to every positive and negative row, or remove `Landed?` and fail closed until the join is automated. Add `OBL-TYPED-READ` with an AC covering credential validation before disclosure, authenticated byte capsule/referrer, retained identity, and TOCTOU behavior. Restamp module identity only after the current sibling text is reconciled.

12. **Material — Drive/UNC-looking JavaScript strings have no consistent v1 meaning.**

   **Evidence:** The grammar allows any UTF-8 component except NUL and `/` ([0023:608](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:608)), and backslash is an ordinary POSIX component character. Yet §3 says virtual paths never contain drive or UNC prefixes and current branches are covered by outside-mount refusal ([0023:757](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:757)), while §7.1 forbids string-shape inference ([0023:1183](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1183)). A JavaScript string carries no host-path intent bit. Current adapters still recognize drive/UNC shapes ([fs.js:523](/Users/ccheever/projects/ibex/src/builtins/fs.js:523), [process.js:41](/Users/ccheever/projects/ibex/src/builtins/process.js:41)).

   **Resolution criterion:** State that every JavaScript path string is virtual and host paths exist only in a separate native type, or explicitly reserve/refuse drive/UNC lexical forms and acknowledge that those otherwise-valid POSIX filenames become unrepresentable. Add cross-platform fixtures.

13. **Minor/Non-blocking — The Node `%5C` compatibility claim is false.**

   **Evidence:** §3 and AC 6 call POSIX `%5C` decoding a deliberate Node divergence ([0023:728](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:728), [0023:1519](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1519)). I executed Node v24.14.0: `fileURLToPath("file:///tmp/a%5Cb")` returned `/tmp/a\b`, while `%2F` threw `ERR_INVALID_FILE_URL_PATH`; `pathToFileURL("/tmp/a\\b")` produced `%5C`. The active Ibex implementation behaves the same ([url.js:2935](/Users/ccheever/projects/ibex/src/builtins/url.js:2935), [url.js:2950](/Users/ccheever/projects/ibex/src/builtins/url.js:2950), [url.js:2963](/Users/ccheever/projects/ibex/src/builtins/url.js:2963)).

   **Resolution criterion:** Keep the desired behavior, remove the divergence claim, and rewrite AC 6’s rationale as POSIX/Node-compatible round-trip behavior.

14. **Minor/Non-blocking — Two promised JavaScript output shapes are not concrete enough to test.**

   **Evidence:** Non-UTF-8 `readdir` entries become a “distinguishable marker,” but no marker type is defined for string, Buffer, or `Dirent` modes ([0023:694](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:694)). Synthetic `stat("/")` uses a reserved device/inode pair that “can never collide” without giving values or a tagged identity domain ([0023:718](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:718)).

   **Resolution criterion:** Define exact return schemas for all `readdir` modes. Either expose a tagged synthetic-stat identity or weaken the raw-number non-collision claim and specify actual values.

4. **Cross-document findings**

1. **0024’s module-cache text contradicts 0023’s repaired hard-link and script rules.** 0023 splits distinct hard-link entries and gives scripts no module identity ([0023:545](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:545), [0023:588](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:588)). Current 0024 says one instance “however it was spelled” and AC 15 says the synthetic sources of §2 are keyed ([0024:1264](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1264), [0024:1640](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1640)), despite its own body saying `repl`, `.load`, and `ibex:eval` are not modules ([0024:1254](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1254)). Narrow AC 15 to `ibex:stdin`, symlink unification, and explicit same-principal hard-link splitting.

2. **Resolver ordering has three incompatible definitions.** 0023 puts all specifier classes before path classes; 0024’s taxonomy puts generic resolution failure before path classes ([0024:309](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:309)); 0024’s `.load` rule instead says outside-mount → policy → resolution ([0024:215](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:215)). Its `interim` class is also dangling: current 0022 refuses old artifacts entirely rather than maintaining an inferred interim set ([0022:296](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:296), [0022:306](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:306)).

3. **0022’s typed-read status is stale in both directions.** Its operative obligation correctly assigns the path-side read to 0023+0021, but nearby prose says neither 0024 nor 0021 carries the credential and that 0024 still uses the retired terminology ([0022:714](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:714), [0022:726](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:726)). Current 0024 does define the linear credential and pre-read route ([0024:202](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:202), [0024:215](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:215)); 0023 is now the missing owner.

4. **0022’s startup-diagnostic ledger row describes a contradiction that no longer exists.** Its operative text permits the privileged CLI diagnostic to name the host root ([0022:480](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:480)), matching current 0023. `OBL-STARTUP-DIAG` still claims 0023 mandates symbolic-only output ([0022:993](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:993)).

5. **0022 and 0025 disagree on interruption epochs and the two-press guarantee.** 0022 says an epoch closes only after quiescence plus prompt republication and that two interrupts within one epoch terminate ([0022:896](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:896), [0022:899](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:899)). Current 0025 says epoch closure is quiescence alone and explicitly rejects prompt coupling ([0025:417](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:417)); two suffice only for the same class and epoch, with three the general bound ([0025:470](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:470), [0025:480](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:480)).

6. **0025 introduces an undefined root identity crossing.** It now requires supervisor and worker to compare an independently computed root fingerprint ([0025:746](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:746)). It does not define construction, domain/key, session binding, collision behavior, linkability, or wire form. That sits uneasily with 0023’s rule that only opaque authenticated session tokens cross and VFS identities remain worker-local ([0023:1241](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1241)). Define a session-keyed, domain-separated attestation that cannot rehydrate or link the root, or incorporate the equality check into the existing opaque token.

7. **0024 contradicts itself on import evaluation.** §3 says imports evaluate during instantiation and a failing import rolls back the input’s bindings ([0024:418](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:418), [0024:424](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:424)). §7.3 says imports evaluate before instantiation, so no bindings exist and rollback is unnecessary ([0024:973](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:973), [0024:980](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:980)). The latter is the implementable repaired rule; the former text must be updated.

8. **Governing LLP 0021 contradicts the machine authority and 0023 on target advertisement.** 0021 says aarch64 macOS is the only advertised complete profile ([0021:930](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:930)). Parsed `policy-rules.json` has `advertisedTargets: []` and lists it only as a candidate ([policy-rules.json:786](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:786)). 0023 accurately reports the machine data ([0023:703](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:703)); 0021 must be corrected or the registry intentionally promoted.

5. **Suggestions**

- Replace the security-relevant prose tables with one versioned executable VFS contract artifact containing marker/glob semantics, projection stages, endpoint roles, the error state machine, canonical display selection, and observable dispositions. Generate prose tables, Rust/JS bindings, cache vectors, and fixtures from it.

- Prefer semantic-core derivation of per-principal projections from one authenticated, owner-independent namespace input. A host-supplied projection map is workable but expands the trusted adapter surface and needs exact key-set validation.

- Ship a smaller v1 mutation surface: reads, metadata, descriptor-based writes/copies, and realpath; keep symlink creation, rename, hard links, removal, and recursive creation closed until each has an object-bound protocol.

- Implement `SourceId` generation as a standalone deterministic tool over authenticated graph data. Run identical vectors at build time and runtime, including cross-volume/case/normalization fixtures.

- Give embedders a structured arming error with separate privileged detail and guest-safe code. The CLI can print the privileged host root; an embedder can choose an appropriate trusted sink.

- Make the obligation ledger fail closed like current 0022: no semantic “landed” assertion without a revision-pinned owner attestation and a named passing fixture.

6. **Open questions**

1. Should per-principal projections cross the ABI explicitly, or should the semantic core derive them from an authenticated virtual-path/object input?

2. What exact tagged principal represents ownerless project files, builtins, and `ibex:stdin` in the module key?

3. Are URL query and fragment rejected for file modules in v1, or included in `SourceId` equality?

4. What concurrency threat model does symlink creation promise against? If external namespace mutation is in scope, can the stated “never publishes an escape” property be delivered at all?

5. Which advertised platforms offer genuinely object-bound hard-link and rename primitives? What is the portable refusal behavior where they do not?

6. What deterministic spelling wins for `SourceLabel`, `realpath`, `readlink`, and source maps when symlink aliases exist?

7. Is the stricter non-root cwd projection to `/project` the desired default? If so, should it be modeled as a no-effect constant branch rather than an authority denial?

8. What public ABI signature actually must change for VFS session identity, beyond the already opaque `ExactHermesRuntime*`?

9. What exactly is 0025’s root fingerprint, and how is it made session-bound and unlinkable?

10. What is the version-cutover rule for old snapshots lacking graph locations, `SourceId` provenance, cwd resources, or projection data?

7. **Readiness verdict**

The proposal is directionally strong, but concerns 1, 2, 3, 5, 6, and 7 still block it from safely and deterministically governing an implementation. The remaining material concerns also prevent `READY` under the requested standard.

VERDICT: NOT READY
### Orchestrator verification notes

Re-checked against the repository at `b60400977333`. Two findings are decisive, and
one of them caught **me** committing exactly the error this document keeps
punishing.

**Confirmed — and Concern 13 is the most instructive finding of the whole loop:**

- **Concern 13 (`%5C` "divergence") — CONFIRMED, my claim was false, and I put it
  in on a reviewer's say-so without running it.** The reviewer executed Node; so did
  I, to settle it myself. Node v25.9.0:
  `fileURLToPath("file:///tmp/a%5Cb")` → `/tmp/a\b` (**decodes**, does not throw);
  `fileURLToPath("file:///tmp/a%2Fb")` → throws `ERR_INVALID_FILE_URL_PATH`;
  `pathToFileURL("/tmp/a\b").href` → `file:///tmp/a%5Cb`. Node on POSIX therefore
  **decodes `%5C`, refuses `%2F`, and round-trips a backslash filename perfectly** —
  which is precisely what this document specifies. It is **Node-compatible, not a
  divergence**. The round-3 Fable review asserted the opposite (its C9), I accepted
  a claim about an *external system* without executing it, and wrote a false
  divergence into a normative spec. Corrected. This is the third time in four rounds
  that running an artifact beat reading one, and the first time it caught me
  trusting a *reviewer* rather than the code.
- **Concern 5 (`link` is unsafe) — CONFIRMED, and I introduced a real privilege
  escalation.** My §4.1 specified `link` as *source read + destination-parent
  write*. The shipped engine explicitly refuses that:
  `src/engine/hermes_runtime_fs.cc:3318-3324` (ENG-22682) — *"It also needs
  `fs:write` on the SOURCE: the new name aliases the inode, so a later (in-grant)
  write through `newp` would mutate a file the caller could only read."* LLP 0013
  requires the same (`0013:1068`). A caller with read on `/project/secrets/x` and
  write on `/project/mine/` could have hard-linked the secret into its own tree and
  then written through the alias, mutating a file it could only read. This is the
  **second** time this document has tried to regress a deliberately-added, shipped
  security control (round 1 did it to symlink target gating).
- **Concern 1 (workspace membership) — CONFIRMED**, and independently by the
  concurrent Fable review (its C2). Ibex's own `package.json` uses
  `workspaces: ["packages/*"]`, and the pinned dialect (`*` does not cross `/`)
  cannot match origin `packages/foo/src`. AC 3a passes today only by falling through
  to the lockfile rule — for the wrong reason.
- **Concern 2 (projection has no transport, and its staging is backwards) —
  CONFIRMED, and the staging half is the part I missed.** The effect model carries
  **one** resource per effect (`capsec/schema/effect.schema.json`, `model.rs:1421`),
  the host computes it once for the actor (`host/mod.rs:329,397`), and the cache
  stores one resource unpaired from the principal set (`cache.rs:49`). More
  importantly: §2.1 requires requested-stage authorization to **precede** any host
  lookup, but my §2.2 described *discovering one object and then projecting it* —
  which is discovery-first. The requested-stage projection must be derivable from
  the virtual path and the bindings **without I/O**, and bindings carry no
  authenticated virtual-alias prefix today (`arming.rs:58`). My §4/§4.1 also
  regressed to "the effect owner's binding" wording, undoing §2.2's own fix.
- **Concern 3 (`SourceId` not total) — CONFIRMED**, and independently by Fable (its
  C4). `Root` carries only `identity`, not a locator or integrity digest
  (`model.rs:304`); LLP 0021's locator+digest identity is the **package** principal
  (`0021:318`). So the constructor is undefined for `/project/src/app.js`, for
  builtins, and for `ibex:stdin`.
- **Concern 7 (error precedence still leaks absence) — CONFIRMED.** My table puts
  in-mount `ENOENT` (#8) *before* discovered-target denial (#9), so a symlink whose
  target is both **denied and absent** would report absence rather than denial. The
  flat total order is simply the wrong shape: containment → authorization → existence
  must hold **per stage**, and there are two stages. A phase machine, not a list.
- **Concern 11 (§9 revision stamps absent) — CONFIRMED, and it is an honesty
  defect.** §9's prose says every row records the revision it was verified against.
  The table has **no such column**; only `OBL-MODULE-IDENTITY` carries a hash inline.
  I claimed a control I did not build.
- **Concern 9 (AC 13), Concern 10 (ABI over-claim), Concern 12 (drive/UNC),
  Concern 14 (marker shapes), Concern 4 (`OBL-SOURCE-PROVENANCE` mis-assigned to
  LLP 0019, whose subject is the Hermes compat transform, not artifact
  provenance) — all confirmed.**

**Refuted / corrected:**

- Nothing material. Concern 6's framing ("symlink creation has no atomic protocol")
  is correct, and I am resolving it by **closing the operation** rather than by
  attempting a third protocol.

**The scope decision this round forces.** LLP 0021 already keeps rename, copy,
symlink, and hard-link **closed** pending typed staged adapters
(`llp/0021-capsec-effect-model-migration.plan.md:688-690`), and removal likewise.
This document twice tried to specify protocols for that surface and got two of them
wrong in a security-relevant direction. The honest response is not a third attempt:
**v1 closes two-resource mutation** — symlink creation, hard-link creation, and
rename — exactly as the governing plan already has them, and specifies completely
the surface it *can* make safe: reads, metadata, traversal and `readlink`/`realpath`
of **existing** links (which `node_modules` depends on), single-path writes, and
descriptor-based `copyFile`. The object-bound protocols become a named obligation
rather than prose I have now failed twice to get right. This is Codex's own
suggestion 3, and it is right.

**Disposition:** Accepted on Blocking 1, 2, 3, 5, 6, 7; Material 4, 8, 9, 10, 11,
12; Minor 13, 14; and cross-doc 1, 2, 3, 4, 6, 8. Cross-doc 5 and 7 are
sibling-sibling (0022↔0025 interrupt epochs; 0024's internal import-evaluation
contradiction) and are reported, not fixed. Where this review and the concurrent
Fable review converge — workspace membership, `SourceId` totality, and the
0024 error-order conflict — the finding is decisive.

---

## Round 5 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
  (non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`; **reasoning effort:** `ultra` — both confirmed in the
  run log; no substitution
- **Session id:** `019f5621-cf86-7522-9d87-ed64fd39364f`
- **Integrity:** rollout final-message md5 `737f771f44d5` == captured body md5,
  reproduced independently.
- **Date:** 2026-07-12
- **Revision under review:** `ab8658a68b57` (`shasum -a 256`, first 12)
- **Redacted:** No. Read under the user's own OpenAI account, authorized by the
  human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session; no access to the
  orchestrating session, to the concurrent Fable round-5 review of the same
  revision, or to any prior LLP 0023 review artifact — rounds 1–4 were stashed out
  of `llp/reviews/` for the duration and the directory was verified empty of 0023
  files while it ran.
- **Method:** cli-runner, round-5 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round5.md`), same brief as Fable,
  carrying the "prefer running artifacts to reading them" warning — which this
  review acted on (it executed Node for every compatibility claim).

### Verbatim review

## 1. **Overall assessment**

I reviewed the complete target at `ab8658a68b57` and pinned the sibling corpus at `0022@88decefdc683`, `0024@88ebc6349bab`, and `0025@19de10797c67`.

This is a strong proposal with the right architecture: virtual spellings are separated from authorization and module identity; authorization is staged; projection is principal-relative; host paths are treated as a whole-surface concern; and closing name-bound mutation in v1 is the correct default.

It is not yet ready to govern implementation. Four defects are blocking:

- `out-of-snapshot` remains a graph-membership oracle, and §7.2 contains several mutually inconsistent precedence rules.
- Existing cross-package hard links plus permitted single-path writes recreate the privilege escalation that closing `link()` was intended to prevent.
- The closed mutation surface omits public composite aliases, while the open creation protocol leaves unsafe rollback behavior unspecified.
- The proposed output-disposition dataset has no independent universe against which “totality” can be checked and already omits live path-bearing outputs.

Several additional material gaps remain in `copyFile`, watch lifetimes, `SourceId`, cwd-dependent aliases, and symlink projection.

## 2. **Strengths**

- **Project discovery is now correctly ancestor-inclusive.** [§1.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:182) fixes the concrete `packages/foo/src` versus `packages/*` failure and provides useful cross-ancestor selection rules. This is a real correction to the current entry-parent inference in [runtime.rs](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1674).

- **§1.2 is appropriately honest about graph provenance and integrity.** It does not pretend the current snapshot carries authenticated package roots or aliases, and it correctly calls out that `name@version` is not an integrity boundary ([LLP 0023](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:302), [module_loader/mod.rs](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:41)). Allowing the pre-JavaScript arming diagnostic to name the offending host root is also a sound operator-facing exception ([§1.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:339)).

- **Staged authorization identity is the right model.** The requested stage cannot honestly claim an existing object before lookup; the current `ObjectState` has only `Existing` and `AbsentCreate` ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1248)). Requiring `Unknown` is correct and closes a real modeling hole ([§2.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:389)).

- **The revised projection design in §2.2 is substantially better.** An exact `{principal → projected resource}` map, principal-resource cache keys, and lexical requested-stage projection are the correct consequences of constrained-principal evaluation ([§2.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:508)). This is necessary because `LogicalRoot::Package` carries no owner ([model.rs](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:573)), while the policy explicitly requires each constrained package’s own binding ([policy-rules.json](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:579)).

- **`SourceId` is much clearer than earlier formulations.** Placing the defining principal exactly once inside a single `(runtime, SourceId)` key and adding the project/root arm remove genuine type and identity holes ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:576), [constructor table](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:604)). Separating `SourceId` from `SourceLabel` is also essential ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:639)).

- **Alias canonicalization is correctly required on both sides.** Canonicalizing occurrences without authored selectors would silently break grants. The requirement to version and digest-bind the canonicalizer is sound ([§3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:752), [AC27](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1806)). The `%5C` correction is also right: Node 24.14 on POSIX decodes it, round-trips it through `pathToFileURL`, and still refuses `%2F`. The contrary-looking constructor block is genuinely unreachable behind `false &&` in [url.js](/Users/ccheever/projects/ibex/src/builtins/url.js:163).

- **Closing name-bound mutation in §4.1 is the right v1 decision.** POSIX name operands do not provide the object-bound guarantees the spec wants, and the shipped hard-link check confirms why source write authority matters ([§4.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:951), [hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3318), [LLP 0013](/Users/ccheever/projects/ibex/llp/0013-per-package-capability-compartments.rfc.md:1068)). Keeping traversal and readback of existing links open is necessary for ordinary `node_modules` layouts.

- **The cwd design is coherent at its core.** One per-runtime native cwd, a shared resolution base, and “authenticated view equals base” avoid the dangerous state where a package resolves relative paths against information it is forbidden to observe ([§5](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1006), [AC13](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1710)). The document correctly acknowledges that the present capability schema cannot express the required state and root-only predicate ([§8](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1525)).

- **The denial-before-absence invariant is excellent.** Its per-stage formulation is the correct confidentiality rule ([§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1364), [per-stage rule](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1419)). The cited current violation is real: native `fs.open` performs target lookup and type inspection before its first typed decision ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2010)).

- **The obligation ledger is more credible now.** Revision stamps and explicit acknowledgement that no validator yet enforces the join are preferable to unverifiable status claims ([§9](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1571)).

## 3. **Concerns**

1. **Severity: Blocking — §7.2 does not define a safe, satisfiable error order.**

   Evidence:

   - `out-of-snapshot` is placed in snapshot tier 2 before policy denial ([§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1377)). But the snapshot separately contains the global package graph ([armed-snapshot.schema.json](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:211)) and each principal’s permitted package imports ([armed-snapshot.schema.json](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:303)). Principal A can therefore distinguish “B absent globally” (`out-of-snapshot`) from “B present but not importable by A” (policy denial). That violates the document’s own no-existence-disclosure invariant. The current host avoids this distinction by consulting the caller-specific import set directly ([host/mod.rs](/Users/ccheever/projects/ibex/src/host/mod.rs:1377)).
   - `ERR_IBEX_STALE_SESSION` is inside tier 3 ([§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1403)), after shape and snapshot processing, while AC24 says it beats everything ([AC24](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1781)). A stale handle cannot safely select the snapshot needed for tier 2.
   - Closed operations are numbered after outside-mount, synthetic-node, and alias processing, while the same row says closure is operation-only and happens before path work ([§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1408)).
   - A foreign `readlink` target is both outside every mount under the generic traversal algorithm ([§4](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:889)) and specifically `ERR_IBEX_UNMAPPABLE_LINK` under readback ([§4](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:916)).
   - `ENOENT` precedes stale retained identity in the table, but AC14 and AC18 require removed/recreated retained objects to produce `ERR_IBEX_STALE_IDENTITY` ([AC14](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1714), [AC18](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1737)).
   - The union attributes an `interim` error to LLP 0022 ([§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1358)), but LLP 0022 defines no such class. Meanwhile the live URL adapter emits omitted classes including `ERR_INVALID_ARG_TYPE`, `ERR_INVALID_URL`, `ERR_INVALID_URL_SCHEME`, and `ERR_INVALID_FILE_URL_HOST` ([url.js](/Users/ccheever/projects/ibex/src/builtins/url.js:2886)).

   **Resolution criterion:** Add a session-envelope tier before all other processing; decide snapshot membership from the caller’s authorized graph view so absent and unauthorized-present are indistinguishable; define operation- and stage-specific precedence for closure, readlink translation, and stale identity; and generate the closed error union and pairwise fixtures from one authoritative dataset containing every live adapter class.

2. **Severity: Blocking — existing hard links plus open writes permit cross-principal content mutation.**

   Section 1.2 explicitly admits two different packages whose files are hard-linked to one inode ([§1.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:378)). Section 2.3 says distinct `SourceId`s contain that coincidence ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:673)), while §4.1 opens `writeFile`, truncation, and descriptor writes ([§4.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:990)).

   That contains compartment identity, but not bytes. If B has an otherwise valid explicit `fs:write` grant to its own package path, it may write the inode through B’s alias and thereby change A’s source. A later import executes those bytes in A’s compartment and with A’s authority. `fs:write` is authorable ([capability-definitions.json](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:179)); the adapter truncates and writes the retained target directly ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:643), [repeat write](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:675)); Unix object identity is only device and inode ([host/abi.rs](/Users/ccheever/projects/ibex/src/host/abi.rs:1444)); and protected objects currently exclude installed package source ([policy-rules.json](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:688)). The unimplemented integrity obligation does not currently rescue this ([§1.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:318)).

   This is the same aliasing fact recognized by the shipped hard-link-creation check: a later write through the alias mutates the source inode ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:3318)). Closing `link()` prevents creating a new alias; it does not neutralize aliases already present in the admitted package layout.

   **Resolution criterion:** Make authenticated package content immutable/protected against `fs:write`, or refuse/COW any writable object with an alias crossing defining principals. Add a red-team fixture in which B writes B’s hard-linked file and prove that A’s bytes neither change nor execute. If integrity is the defense, specify and test content revalidation at module read/commit; an arming-only hash is insufficient.

3. **Severity: Blocking — name-bound closure and open creation are incomplete at the public API boundary.**

   The normative phrase “path removal is closed” is broader than the actual operation table and AC7, which name only `unlink` and `rmdir` ([§4.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:953), [AC7](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1672)).

   Live public composites can perform effects before reaching those leaves:

   - `rm`, `rmSync`, and promises `rm` perform `lstat`, recursive `readdir`, and sometimes permission changes before unlink/rmdir ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:5875), [async rm](/Users/ccheever/projects/ibex/src/builtins/fs.js:5975)).
   - `cp` can create directories and files, remove destinations, or encounter a now-closed symlink operation after earlier entries were already copied ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:2587)).
   - `mkdtempDisposable().remove()` routes through recursive removal, so an otherwise-open API returns a disposer that cannot satisfy its contract ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:3102)).

   The open `mkdir` protocol is also underspecified under the document’s concurrent-mutator threat model. Current sync and async code creates a directory and, after an open or commit failure, rolls it back using name-bound `unlinkat(parentFd, name, AT_REMOVEDIR)` ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:725), [async path](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:1630)). A concurrent replacement can cause that rollback to delete the wrong directory—the precise class of race §4.1 rejects.

   **Resolution criterion:** Apply closure at every public/native entry point before lookup, including `rm`, recursive `rmdir`, `cp` modes that require closed operations, and disposable cleanup. Specify the create commit point and post-create failure behavior; forbid name-based rollback unless the exact created object is provably still bound to the name. Add syscall-observed fixtures proving zero reads and zero mutations for closed calls and swap fixtures for create rollback.

4. **Severity: Material — the allegedly complete open surface does not yet specify `copyFile` or watch sufficiently.**

   `copyFile` receives only a short descriptor sketch ([§4.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:998)), while OQ11 concedes that operand actions, binding transitions, and atomicity remain undecided ([OQ11](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1904)). Missing decisions include:

   - independent source and destination staging and cross-operand error precedence;
   - `COPYFILE_EXCL` and clone-mode behavior;
   - partial writes and destination cleanup;
   - whether a final source symlink is traversed, since literal `O_NOFOLLOW` conflicts with the table’s open existing-link traversal;
   - behavior when destination creation succeeds but source read or repeated authorization later fails.

   Watch is merely marked open and staged ([§4.1](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:994)). The registry treats `fs:watch` as an independent action with repeated delivery checks ([capability-definitions.json](/Users/ccheever/projects/ibex/capsec/registry/capability-definitions.json:164)); current watch instead polls `stat`/`readdir` and emits changes ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:5250)). There is no acceptance criterion proving that `fs:list` alone cannot start or receive a watch, that the constrained set is retained for delivery, or that revocation/stale identity closes it.

   This also conflicts with the governing plan: LLP 0021 keeps recursive mkdir closed ([LLP 0021](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:678)) and copy closed pending a staged adapter ([LLP 0021](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:688)), while its current final-symlink posture is `O_NOFOLLOW` ([LLP 0021](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:648).

   **Resolution criterion:** Define complete two-operand and watch-lifetime state machines with generated fixtures, and revise or explicitly supersede the contradictory LLP 0021 rows. Otherwise close these APIs in v1.

5. **Severity: Material — `SourceId` and canonical display remain underdefined.**

   The constructor table calls `SourceId` total, but OQ8 still leaves URL query and fragment identity undecided ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:598), [OQ8](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1892)). A Node 24.14 execution confirmed that `x.mjs?v=1` and `x.mjs?v=2` are different ESM instances, while repeating the same query reuses the instance. Include, strip, or refuse is a v1 identity decision, not post-spec polish.

   Lexical-canonical paths are appropriate for portable manifests ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:623)), but the spec does not say how a single portable lexical spelling is chosen when one object is reachable through case or normalization aliases. On the current case-insensitive volume, `README.md` and `readme.md` stat to the same device/inode while `realpath` preserves the two spellings. Without a provenance-selected primary spelling, the “one file, however spelled” requirement can split.

   Display is separately unresolved: `realpath` must return a canonical virtual absolute path ([§4](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:931)), but OQ7 says the canonical display alias is unpinned ([OQ7](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1886)). That affects `SourceLabel`, source maps, stack frames, and error paths.

   **Resolution criterion:** Specify query/fragment treatment; specify case/normalization alias behavior as unify, split, or refuse; and define an authenticated deterministic primary display alias independent of first-load order and local filesystem spelling.

6. **Severity: Blocking — output-disposition “totality” is not enforceable or currently total.**

   Section 6 requires a dataset total over `(surface, field/return-shape, alias, mode)` and promises that any undispositioned field fails the build ([§6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1182)). But the current coverage schema knows only a surface’s kind and name, not its fields or return shape ([coverage-edge.schema.json](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:23)). A newly authored dataset cannot prove its own completeness: an omitted field is indistinguishable from a nonexistent field unless an independent output-shape inventory or reflection sweep supplies the universe.

   Concrete omissions and mismatches already demonstrate the problem:

   - `Dir.path` is a live path-bearing property absent from the table and AC inventory ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:2259)).
   - `mkdtemp`, disposable `.path`, recursive `mkdir`’s returned first-created path, glob, and recursive-readdir results need dispositions ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:2948), [disposable object](/Users/ccheever/projects/ibex/src/builtins/fs.js:3119)).
   - The module object exposes enumerable `__exactPackageRoot` ([module-loader.js](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5296)), currently fed by raw host `pkgRoot`, but the output table does not cover it.
   - Watch-event paths are classified `virtual-absolute` ([§6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1218)); the implementation returns a basename for nonrecursive watches and a relative path for recursive ones ([fs.js](/Users/ccheever/projects/ibex/src/builtins/fs.js:5226)).
   - `virtual-absolute` conflates path strings, file-URL strings, and URL objects. `pathToFileURL` returns an object, while AC6 itself compares `.href`.
   - The non-UTF-8 readdir “distinguishable marker” has no exact JavaScript representation ([§3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:796)).
   - `closed` is defined as pinning absent/throw/neutral behavior, but `process.execArgv`, `require.cache`, `os.homedir/tmpdir/devNull`, and `os.userInfo` do not specify their exact closed outcomes ([§6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1177)). Current `os` code still reads HOME/TMP, returns native user paths, and publishes `/dev/null` ([os.js](/Users/ccheever/projects/ibex/src/builtins/os.js:63), [userInfo](/Users/ccheever/projects/ibex/src/builtins/os.js:190), [devNull](/Users/ccheever/projects/ibex/src/builtins/os.js:229)).

   **Resolution criterion:** Establish an independently generated output-shape catalog or exhaustive live descriptor sweep, perform a bidirectional join against dispositions, distinguish semantic disposition from concrete JS shape/encoding, enumerate root/internal fields, and pin exact outcomes for every `closed` row.

7. **Severity: Material — cwd-dependent aliases remain unclassified and can violate view-equals-base.**

   Section 3 calls `path.win32` and `path.posix` pure lexical utilities ([§3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:861)), and §8 reclassifies only top-level `node:path.resolve` and `relative` ([§8](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1537)).

   In fact, the shared implementation reads `process.cwd()` ([path.js](/Users/ccheever/projects/ibex/src/builtins/path.js:8)); `path.win32.resolve` consults it ([path.js](/Users/ccheever/projects/ibex/src/builtins/path.js:206)); `relative` calls that resolver ([path.js](/Users/ccheever/projects/ibex/src/builtins/path.js:298)); and `toNamespacedPath` does likewise ([path.js](/Users/ccheever/projects/ibex/src/builtins/path.js:456)). An executed Node probe confirmed their results change after `chdir`. `node:url.pathToFileURL` also consults cwd for relative inputs ([url.js](/Users/ccheever/projects/ibex/src/builtins/url.js:4212)).

   Under the stricter profile, these aliases can disclose or resolve against root’s actual cwd while `process.cwd()` reports `/project`, directly violating authenticated-view-equals-base.

   **Resolution criterion:** Enumerate every cwd-dependent alias across `node:path`, `node:path/posix`, `node:path/win32`, `path.posix`, `path.win32`, `node:url`, and Exact-global facades; give each the same conditional session-state read/no-effect branches, or pin a documented fixed-base divergence.

8. **Severity: Material — the symlink staging algorithm contradicts the projection model.**

   The numbered algorithm authorizes the link and discovered target under the effect owner’s binding ([§4](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:878)). Its concluding paragraph instead says every stage uses the projection of each principal being tested and explicitly rejects a single effect-owner binding ([§4](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:946)).

   This is not academic: the live, reachable helper uses only `currentPrincipalId()` ([hermes_runtime_fs.cc](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:570)). An implementer following the numbered steps could preserve exactly the one-projection behavior §2.2 is intended to remove.

   **Resolution criterion:** Rewrite every numbered stage in terms of the exact `{principal → projected resource}` map and conjunctive decisions over the captured constrained-principal set. Add an A-owner/B-deputy symlink traversal fixture in both directions.

9. **Severity: Minor/Non-blocking — compatibility and editorial claims need correction.**

   - The claim that default Node ESM preserves symlink spellings and splits instances ([§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:690)) is false under Node 24.14’s default mode: importing the same module through a `node_modules` symlink and its realpath returned the same namespace. The proposed Ibex unification is therefore Node-compatible absent `--preserve-symlinks`.
   - Program-stdin argv is not “as Node” ([§6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1227)). `printf 'console.log(process.argv)' | node - alpha beta` produced `[nodePath, "-", "alpha", "beta"]`; user arguments begin at index 2. Ibex may omit `"-"`, but that is a stated divergence.
   - Rejecting `%5C` “on Windows” conflicts with the later requirement that armed file-URL conversion use POSIX rules on every platform.
   - The `fs.open` existence-oracle paragraph is duplicated at [§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1435).

   **Resolution criterion:** Correct the Node descriptions, state intentional divergences, reconcile future Windows `%5C` semantics, and remove the duplicate paragraph.

## 4. **Cross-document findings**

1. **Error taxonomy remains materially drifted between 0023 and 0024.** LLP 0023 says the siblings delete their restated order and attributes `interim` to 0022 ([0023 §7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1358)). LLP 0024 says it does not restate the order but immediately reproduces the four-tier table, without `interim` ([0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:339)). LLP 0022 defines no `interim` error. One generated taxonomy/order source is needed.

2. **0024’s module-identity AC is stale in two directions.** Its body correctly says only `ibex:stdin` is a synthetic module ([0024 §7.9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1425)), matching [0023 §2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:647). AC15 nevertheless says the plural synthetic sources are cache-keyed ([0024 AC15](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1837)). Its root-key warning also still narrates the project/root arm as unresolved ([0024 §7.9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1444)), although 0023 now defines it.

3. **0022 and 0024 disagree on submission credentials.** LLP 0022 specifies one one-shot permit consumed before any effect, while also describing a multi-stage linear lifecycle ([0022 §7](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:680)). LLP 0024 correctly identifies the `.load` circularity and specifies separate affine read and evaluation permits ([0024 §1](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:222)). 0023’s `OBL-TYPED-READ` should explicitly name the read permit and authenticated capsule, and 0022 should adopt the two-permit algebra.

4. **0022’s interrupt contract is stale against current 0025.** LLP 0022 closes an epoch only after prompt republication and claims any two interrupts within one work epoch terminate ([0022 §10](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:892)). LLP 0025 closes at quiescence alone and permits the editing case to require three presses; its own ledger correctly marks both 0022 claims stale ([0025 ledger](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:947)). 0022 should delegate without paraphrasing.

5. **The current 0025 interrupt machine is itself not executable as written.** Its promise bit requires the next interrupt to terminate irrespective of class changes ([0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:509)), but AC7 still expects three presses for schedules whose first press prints that promise ([0025 AC7](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1016)). Its latch is also described both as `Idle | Running(epoch) | Shutdown` and as `(class, epoch)` including operator input ([0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:431), [later definition](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:455)). These are sibling defects rather than independent 0023 defects, but they block a coherent corpus-level implementation plan.

6. **Cancellation and lifecycle seams remain inconsistent between 0024 and 0025.** LLP 0025 says every accepted cancellation produces `cancelled`; LLP 0024 correctly reserves that outcome for evaluations and treats callback/query acceptance as the unit returning ([0025 §6](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:605), [0024 §6](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:868)). LLP 0025 also says an accepted lifecycle record wins even when its ACK is lost, while its AC says any unacknowledged commit takes the fatal disposition ([0025 §8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:708), [AC9](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1033)).

7. **Shared constants have moved in 0025 but not its consumers.** LLP 0025 now normatively pins the values even though `session-constants.json` is not yet created ([0025 §12](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:959)). LLP 0024 still calls renderer bounds and the truncation marker open ([0024 OQ8](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1971)); LLP 0022 says bounds remain open in both siblings ([0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:990)). LLP 0025’s OQ8 also still calls its now-pinned history-lock bound open and engine-dependent ([0025 OQ8](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1082)).

8. **The startup-diagnostic contradiction recorded by 0022 is stale.** LLP 0022 still claims 0023 mandates symbolic-only output ([0022 ledger](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:993)); current 0023 expressly permits the pre-JavaScript host root ([0023 §1.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:339)). Current 0025’s symbolic legacy-history notice is explicitly its own narrower choice.

9. **0024 contradicts itself on failed module caching.** It first says a throwing imported module’s cache entry stands ([0024 §3](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:499)), then says a failing module’s entry is deleted and later import re-executes it ([0024 §7.9](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1452)). Because 0023 owns module identity while 0024 owns session cache behavior, that must be resolved at the seam.

10. **No new direct 0023↔0025 identity contradiction remains.** Current 0025 explicitly separates `ProjectHistoryScopeId` from every VFS identity and keeps retained VFS identity worker-local ([0025 §9](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:826)). That repair is aligned with 0023.

## 5. **Suggestions**

- Replace the prose operation matrix with one machine-readable VFS contract keyed by public facade, operand role, stage, follow mode, closure status, error class, and output shape. Generate registry rows, ABI discriminants, public-alias coverage, and acceptance fixtures from it.

- Treat authenticated package source as immutable executable content. Give packages a separate writable state/cache mount rather than allowing general writes into package roots.

- Construct a caller-specific projected graph view before resolver classification. `out-of-snapshot` should describe absence from the caller’s authorized snapshot view, not the project-global graph.

- Make `SourceId` consume a provenance-selected canonical component vector, while `SourceLabel` uses an independently selected primary display alias. This preserves build portability without making first lookup order determine identity or display.

- Add a tier-zero session-envelope validation and express subsequent precedence as an operation/stage decision DAG rather than a single flat list.

- Generate the disposition universe from runtime exports, object properties, return-record schemas, and native registrar IDs. The disposition dataset should annotate that universe, not define it.

- Until the multi-operand and repeated-delivery protocols are complete, closing `copyFile`, `cp`, watch, recursive mkdir, and disposable removal would produce a smaller but genuinely safe v1.

## 6. **Open questions**

1. Are authenticated package roots intended to be immutable, or may explicit `fs:write` grants modify installed package code? If writable, what prevents cross-principal hard-link mutation?

2. Is project-global graph membership public to every principal? If not, what exact caller-specific graph view determines `out-of-snapshot`?

3. Are file-URL query and fragment part of `SourceId`, stripped before identity, or refused? How do case and Unicode-normalization aliases behave?

4. What exact concurrent-mutator threat model applies to creation and rollback? Is the adversary allowed to replace a newly created name between `mkdirat`, verification, and cleanup?

5. Should v1 close `copyFile`, watch, recursive mkdir, `cp`, and disposable temp APIs until complete protocols exist, or are these required for a concrete launch workload?

6. What independent artifact defines the universe of JavaScript-visible output fields and return shapes for disposition totality?

7. Should the strict non-root cwd profile—view and base fixed at `/project`—be the default, avoiding the universal cwd information grant?

8. Which authenticated rule selects the primary display alias used by `realpath`, `SourceLabel`, source maps, stack frames, and errors?

## 7. **Readiness verdict**

The architecture is promising, and closing name-bound mutation is the correct direction. However, the error-order oracle, pre-existing hard-link write escalation, incomplete mutation/create boundary, and unenforceable output-totality claim are blocking. The remaining material identity, copy/watch, cwd-alias, and projection gaps also preclude READY status.

VERDICT: NOT READY
### Orchestrator verification notes

Re-checked against the repository at `ab8658a68b57`. The lead finding is a genuine,
verified security defect that survives the round-4 mutation closure, and the
concurrent Fable review's own verdict ("the architecture is done; nothing here needs
redesign") should be read against it: the architecture is sound, but this round found
a real hole in the *authority* model, not just residue.

**Confirmed — Blocking 2 is a live security bug, verified in the decision core:**

- `crates/capsec-semantics/src/decision.rs:946-958` — `protected_object_matches`
  compares by **exact object identity** (`object == &guard.object`), against the
  occurrence's `parent_object`/`final_object`.
- `src/bin/ibex/runtime.rs:1948-1952` — the shipped guard protects **one** object:
  `root_object`, which is the **project-root directory's** `(volume, inode)`
  (`runtime.rs:1681-1689`), with `deniedActions: ["fs:write"]`.
- Therefore a write whose `final_object` is a file **inside** `node_modules` has a
  *different inode* than the project-root directory, the guard does not fire, and
  the write is decided by ordinary `fs:write` authority.
- §1.2 admits an in-project content-addressed store that **hard-links** two
  packages' byte-identical files to one inode; §4.1 opens `writeFile`, truncate, and
  descriptor writes. So package B, writing its own file under a legitimate `fs:write`
  grant, mutates the shared inode — and package A's source with it. A later import
  runs the mutated bytes in **A's** compartment under **A's** authority. Closing
  `link()` (round 4) prevents *creating* a new alias; it does nothing about aliases
  already in the admitted layout.

  This is the same aliasing fact the shipped hard-link *creation* check defends
  against (`hermes_runtime_fs.cc:3318`), reachable through a different door. Accepted
  as blocking. Resolved by making **authenticated package source immutable** —
  extending the existing `protectedObjects` mechanism from the single project-root
  object to every package binding's subtree, an LLP 0021 obligation
  (`OBL-PACKAGE-IMMUTABLE`). Package code is reviewed, integrity-bound, executable
  content; it should not be writable at armed runtime by anyone, which is a
  defensible v1 default in its own right (install-time mutation happens outside armed
  execution). First-party project source stays writable.

- **Blocking 1 (error order — the `out-of-snapshot` oracle). Confirmed and sharp.**
  The armed snapshot carries both the **global** package graph
  (`capsec/schema/armed-snapshot.schema.json:211`) and each principal's **permitted**
  imports (`:303`), so placing `out-of-snapshot` in a snapshot tier *before* policy
  denial lets principal A distinguish "B absent globally" from "B present but A may
  not import it" — an existence oracle over the graph, violating this document's own
  invariant. The current host avoids it by consulting the **caller-specific** import
  set (`src/host/mod.rs:1377`). Fix: `out-of-snapshot` is decided from the *caller's
  authorized graph view*, so absent and unauthorized-present are indistinguishable;
  and the several ordering inconsistencies (stale-session tier, closed-op position,
  foreign-`readlink` dual classification, `ENOENT`-before-stale) are resolved by
  making the order an explicit per-stage machine rather than a flat list with a
  prose caveat. `interim` — attributed to LLP 0022, which defines no such class —
  is deleted.
- **Blocking 3 (closure incomplete at the public boundary). Confirmed.**
  `rm`/`rmSync`/promise `rm` do `lstat` + recursive `readdir` before reaching
  `unlink`/`rmdir` (`src/builtins/fs.js:5875`); `cp` copies entries before hitting a
  now-closed symlink op (`fs.js:2587`); `mkdtempDisposable().remove()` routes through
  recursive removal (`fs.js:3102`); and the open `mkdir` rolls back with **name-bound**
  `unlinkat(parentFd, name, AT_REMOVEDIR)` (`hermes_runtime_fs.cc:725`), which a
  concurrent replacement can turn into deleting the wrong directory — the exact race
  §4.1 rejects. Accepted.
- **Blocking 6 (output-disposition totality). Confirmed.** The coverage schema knows
  only a surface's kind and name (`capsec/schema/coverage-edge.schema.json:23`), not
  its fields or return shapes, so a dataset cannot prove its own completeness — an
  omitted field is indistinguishable from a nonexistent one without an **independent**
  live-descriptor universe. And concrete rows are already missing: `Dir.path`
  (`fs.js:2259`), the enumerable `__exactPackageRoot` on the module object
  (`module-loader.js:5296`), and watch-event paths (basename for nonrecursive,
  relative for recursive — `fs.js:5226`), which §6 wrongly dispositions
  `virtual-absolute`. Accepted.
- **Material 7 (cwd-dependent aliases). Confirmed by execution.** `path.win32.resolve`
  (`path.js:206`), `relative` (`:298`), and `toNamespacedPath` (`:456`) all read the
  session cwd, as does `url.pathToFileURL` for relative inputs — so §8's reclassifying
  only top-level `resolve`/`relative` leaves cwd-reading aliases that, under the strict
  profile, would resolve against root's real cwd while `process.cwd()` reports
  `/project`. Accepted.
- **Material 8 (symlink staging contradicts projection). Confirmed.** §4's numbered
  steps say "under the effect owner's binding" while §4's own closing paragraph says
  per-principal projection; the reachable helper uses only `currentPrincipalId()`
  (`hermes_runtime_fs.cc:570`). Rewritten in projection terms.
- **Minor 9 (Node-ESM, stdin argv, duplicated paragraph). All confirmed**, the
  Node-ESM one by executing Node (see the round-5 Fable notes) — my §2.3 claim that
  default ESM splits symlinked specifiers is **false**; Node resolves them, the split
  needs `--preserve-symlinks`. This is the **fourth** false Node claim in five rounds,
  and — as the coordinator observed — every one entered as a *reviewer's assertion I
  adopted without running Node*. A borrowed empirical claim is a rumor with a
  citation. Corrected, and the pattern is now named once in §3.

**The ledger-stamp defect (Fable's finding, confirmed here too):** my round-4
revision-stamp column used `b60400977333` — the **document's own shasum** — for the
code/schema/registry rows. `git cat-file -t b60400977333` fails; the stamp resolves
to nothing, so the staleness detector I built was itself unverifiable, and behind it
two rows had gone stale favorably (0021 now says the macOS candidate "remains
unadvertised"; 0024 has landed the error-order deferral). Restamped with a resolvable
`git rev-parse` object (`3060574776a3`), and `OBL-LEDGER-CHECK`'s first assertion is
now "every stamp resolves."

**The scope decision this round forces — a further, deliberate narrowing.** Four of
the five blockers (2, 3, 4-copy, and the copyFile/watch material) are all the same
shape: a *complex or multi-step or aliased* filesystem operation that cannot be made
safe by prose in a security spec, and that this document has now repeatedly gotten
wrong when it tried. The disciplined response, which both reviewers explicitly
endorse (Codex suggestion 7; Fable C3), is to **close the whole hard-to-specify
surface in v1** and specify completely only what is genuinely simple:

- **Closed in v1:** symlink/hard-link creation, rename, `unlink`/`rmdir`/`rm`
  (including recursive), `cp`/`copyFile`, `fs.watch`/`watchFile`, recursive `mkdir`,
  and the disposable-temp APIs whose cleanup routes through recursive removal.
  Closure is applied at the **public entry point**, before any lookup, so a composite
  cannot do partial effects before reaching a closed leaf.
- **Open, and specified completely:** reads, `stat`/`lstat`, `readdir`, `realpath`,
  `readlink` and traversal of **existing** links, single-path `writeFile`/truncate/
  descriptor writes to **non-package** objects, and **non-recursive** `mkdir` with an
  **object-bound** create/rollback (rollback only if the created object is provably
  still bound to the name).

This is a smaller v1 than round 4 claimed, and it is the honest one: it is exactly
the surface whose safety this document can state and a fixture can prove, and every
operation beyond it becomes a named obligation rather than prose that has now failed
twice.

**Disposition:** Accepted on Blocking 1, 2, 3, 6; Material 4, 5, 7, 8; Minor 9.
Cross-doc 1 (interim/taxonomy), 2 (0024 AC15 stale), 8 (0022 startup-diag stale) are
seam items I fix on my side or report; 3, 4, 5, 6, 7, 9, 10 are sibling-sibling and
reported, not fixed.

---

## Round 6 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`
  (non-interactive), sandbox `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`; **reasoning effort:** `ultra` — both confirmed in the
  run log; no substitution
- **Session id:** `019f5789-9a7f-7c32-825f-0f088c7650de`
- **Integrity:** rollout final-message md5 `43860050d387` == captured body md5,
  reproduced independently.
- **Date:** 2026-07-12
- **Revision under review:** `a77e5a385f6a` (`shasum -a 256`, first 12) — the
  **same** revision the round-6 Fable half reviewed.
- **Redacted:** No. Read under the user's own OpenAI account, authorized by the
  human invocation of `/llp-super-refine`.
- **Independence:** Fresh non-interactive Codex session; no access to the
  orchestrating session, to the round-6 Fable review of the same revision, or to
  any prior LLP 0023 review artifact — rounds 1–5 were stashed out of `llp/reviews/`
  for the duration and the directory was verified empty of 0023 files while it ran.
  This is the **Codex half** of round 6, run after the Fable half had already
  returned READY; the two halves reviewed the identical revision `a77e5a385f6a`.
- **Method:** cli-runner, round-6 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round6.md`), which carried the
  "prefer running artifacts to reading them" rule. This review executed Node
  v24.14.0, parsed the registry/schema JSON, ran `git cat-file`, and ran the
  repository's CapSec checks.

### Verbatim review

1. **Overall assessment**

The proposal’s core architecture is sound: a session-local virtual namespace, authenticated graph-derived bindings, staged path identities, per-principal projections, and typed host boundaries are the right design.

I parsed the registry/schema JSON, ran the repository’s CapSec checks, inspected cited code for reachability, ran `git cat-file`, and executed Node v24.14.0 for the compatibility claims. The corrected symlink, case-alias, hard-link, `%5C`, `%2F`, encoded-dot-segment, argv, and query/fragment claims were confirmed.

However, the current revision is not finished. Six localized but genuine blockers remain: unsafe `mkdir` rollback, incomplete package immutability, an incompletely closed graph oracle, two unresolved identity/display decisions, and an undefined `/dev/null` node. These require targeted specification work, not architectural redesign.

2. **Strengths**

- §1.1 gives project discovery a deterministic, ancestor-inclusive workspace rule and records the result in the armed snapshot. That is substantially better than inferring the boundary from the entry file’s parent ([0023:203](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:203), [0023:222](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:222), [0023:300](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:300)).

- §1.2 correctly derives package bindings from authenticated graph locations, rejects ambiguous/shared roots, binds integrity as a named dependency, and honestly refuses out-of-project layouts in v1 ([0023:314](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:314), [0023:330](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:330), [0023:336](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:336), [0023:346](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:346)).

- §§2.1–2.2 separate requested, discovered, and committed identity, and correctly require one projection per constrained principal. The document accurately identifies the present speculative `Existing` state and payload-free `Package` root rather than claiming the current model already works ([0023:407](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:407), [0023:430](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:430), [0023:497](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:497), [model.rs:1273](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/model.rs:1273), [abi.rs:1058](/Users/ccheever/projects/ibex/src/host/abi.rs:1058)).

- §2.3’s defining-principal approach avoids both caller-relative duplicate instantiation and cross-package compartment collapse. I ran Node: default ESM and CommonJS unified symlink spellings; `--preserve-symlinks` split them; hard-link spellings split; and case aliases on this case-insensitive volume produced distinct ESM instances. The revised claims at [0023:719](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:719) are accurate.

- §3’s authorization-side alias canonicalization is applied symmetrically to selectors and occurrences and digest-binds the canonicalizer ([0023:775](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:775)). I also ran Node and confirmed `%5C` decodes and round-trips on POSIX, `%2F` throws `ERR_INVALID_FILE_URL_PATH`, and encoded dot segments collapse. The cited old `%5C` refusal is indeed dead under `false &&` at [url.js:163](/Users/ccheever/projects/ibex/src/builtins/url.js:163); the live implementation is [url.js:2886](/Users/ccheever/projects/ibex/src/builtins/url.js:2886).

- §4.1 correctly closes composite operations at the public entry point before lookup or partial work ([0023:996](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:996)). §4.2 also identifies a real package-source aliasing vulnerability and chooses the correct security default: authenticated dependency source must not be runtime-writable ([0023:1055](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1055)).

- §§5 and 7.1 make cwd, bindings, leases, and module state session-local and explicitly distinguish public semver-major ABI work from internal `ex_host_*` threading ([0023:1198](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1198), [0023:1380](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1380), [0023:1414](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1414)). This matches the actual process-global `HOST` limitation at [abi.rs:128](/Users/ccheever/projects/ibex/src/host/abi.rs:128).

- §7.2’s governing rule—authorization before any existence-disclosing class—is correct, and deciding `out-of-snapshot` from the caller’s view is the right repair ([0023:1468](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1468), [0023:1493](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1493)).

- §6 correctly recognizes that coverage edges cannot prove output completeness because their surface schema contains only `kind` and `name`; an independent output-shape universe is necessary ([0023:1277](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1277), [coverage-edge.schema.json:23](/Users/ccheever/projects/ibex/capsec/schema/coverage-edge.schema.json:23)).

3. **Concerns**

1. **Blocking — non-recursive `mkdir` rollback repeats the name-swap race the spec closes.**

   **Evidence:** §4.1 closes removal because `unlinkat` is name-bound ([0023:1013](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1013)), but then permits rollback after separately verifying that the created object remains bound to the name ([0023:1027](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1027)). An external mutator can replace the directory between verification and `unlinkat`. LLP 0021 already identifies exactly this race ([0021:683](/Users/ccheever/projects/ibex/llp/0021-capsec-effect-model-migration.plan.md:683)), and the reachable implementation performs the unsafe name-based rollback at [hermes_runtime_fs.cc:725](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:725).

   **Resolution criterion:** Either abandon rollback after publication, prove no post-publication failure is possible, close `mkdir`, or specify an atomic identity-conditional removal primitive available on every target. A pre-`unlinkat` identity check is insufficient.

2. **Blocking — package immutability does not specify a mechanism covering both package paths and hard-link aliases.**

   **Evidence:** The policy in §4.2 is right, but “every package binding’s subtree is a protected object” is not representable by the current exact-object guard ([0023:1074](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1074), [0023:1734](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1734)). `ProtectedObjectGuard` contains only `{action, object}` ([decision.rs:114](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:114)), matches exact parent/final object identities ([decision.rs:946](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/decision.rs:946)), and the schema admits one object per row ([armed-snapshot.schema.json:120](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:120)). The runtime installs only the project-root object ([runtime.rs:1948](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1948)).

   A lexical path-tree guard is needed to deny package creates before lookup; an authenticated exact-object/generation set is separately needed to catch writes through hard links outside package spellings. The present “first-party source outside any package binding stays writable” statement is ambiguous when that name shares an inode with package source ([0023:1078](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1078)).

   **Resolution criterion:** Specify both digest-bound guards, including files, directories, symlink objects, generations, and writable-descriptor/metadata mutation. State that package-source immutability wins through every alias. Add fixtures for an outside-package hard-link alias and for an absent package path proving denial precedes lookup.

3. **Blocking — the caller-view graph oracle is neither exactly computable nor acceptance-complete.**

   **Evidence:** The snapshot graph contains only `{importer, imported}` edges ([armed-snapshot.schema.json:211](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:211)); per-principal imports contain locators but no importer-relative request/alias mapping ([armed-snapshot.schema.json:328](/Users/ccheever/projects/ibex/capsec/schema/armed-snapshot.schema.json:328)). `OBL-GRAPH-LOCATION` supplies only a resolving specifier per principal ([0023:1739](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1739)), while the live predicate reduces allowed locators and requests to bare package names ([mod.rs:1526](/Users/ccheever/projects/ibex/src/host/mod.rs:1526)).

   Separately, local and global `require.resolve` bypass `checkImportGate` ([module-loader.js:5052](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5052), [module-loader.js:5413](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5413), [module-loader.js:5774](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5774)) and enter a resolver that probes and canonicalizes paths first ([mod.rs:1430](/Users/ccheever/projects/ibex/src/host/mod.rs:1430)). AC24 tests “importing” but not these opened resolve-only routes ([0023:1926](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1926)).

   **Resolution criterion:** Add a digest-bound `(importer, request specifier/alias, exact imported principal, platform disposition)` map, define tier-2 membership from it, and apply the gate before every local/global/internal resolve-only bridge. Fixtures must compare globally absent with present-but-unauthorized packages and assert that no resolver probe occurs.

4. **Blocking — `SourceId` is declared total while query/fragment identity remains undecided.**

   **Evidence:** §2.3 calls `SourceId` defined and total ([0023:616](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:616)), and the obligation promises a query/fragment disposition ([0023:1730](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1730)). OQ8 nevertheless says v1 must choose include, strip, or refuse and has not done so ([0023:2053](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2053)). I ran Node v24.14.0: repeated `?v=1` reused an ESM instance, differing queries split instances, and differing fragments also split them.

   **Resolution criterion:** Choose include/strip/refuse normatively and define canonical encoding, cache/provenance behavior, and repeated/differing query and fragment fixtures across raw, bundled, and cached forms.

5. **Blocking — canonical `SourceLabel` spelling is explicitly unpinned.**

   **Evidence:** `SourceLabel` is required to be deterministic ([0023:668](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:668)); `realpath`, stack frames, source maps, errors, and `import.meta.url` require canonical outputs ([0023:976](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:976), [0023:1323](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1323)). OQ7 concedes that the spelling for aliased objects is still unpinned and must not depend on load order ([0023:2047](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2047)).

   **Resolution criterion:** Define a caller- and load-order-independent primary spelling for symlink, hard-link, case, and normalization aliases. Test `realpath`, `__filename`, `import.meta.url`, source maps, and errors with reversed load order.

6. **Blocking — `/dev/null` contradicts the namespace contract and lacks node semantics.**

   **Evidence:** V1 has only the `/project` mount ([0023:161](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:161)); any other child of `/` is outside-mount ([0023:749](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:749)); and synthetic `/` supports only `stat` and `readdir` ([0023:1175](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1175)). §6 nevertheless creates `/dev/null` as a synthetic no-effect sink without defining lookup, identity, open/read/stat/truncate/descriptor, listing, or error-order behavior ([0023:1316](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1316)). Current code merely exports the host-shaped string ([os.js:229](/Users/ccheever/projects/ibex/src/builtins/os.js:229)), and the registry classifies it as pure computation ([coverage-edges.json:88498](/Users/ccheever/projects/ibex/capsec/registry/coverage-edges.json:88498)).

   **Resolution criterion:** Either close `os.devNull`, or specify a reserved mount/node with complete operation semantics, dispositions, mount-table behavior, error precedence, and acceptance tests.

7. **Material — §4.1 does not classify the complete live mutation surface.**

   **Evidence:** The table claims completeness at [0023:996](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:996), but reachable `chmod`, `chown`, `utimes`, `lchmod`, `lchown`, `lutimes`, descriptor/FileHandle variants, and `mkdtemp` are neither open nor closed. They are exported at [fs.js:7123](/Users/ccheever/projects/ibex/src/builtins/fs.js:7123), have live promise routes such as [fs.js:6424](/Users/ccheever/projects/ibex/src/builtins/fs.js:6424) and [fs.js:6548](/Users/ccheever/projects/ibex/src/builtins/fs.js:6548), and have corresponding coverage edges. Some link-metadata operations are themselves name-bound.

   **Resolution criterion:** Produce an exhaustive operation matrix covering sync, callback, promise, FileHandle, descriptor, and stream aliases; classify metadata mutation and `mkdtemp`; and make every absent row default-closed.

8. **Material — the output-disposition table is not yet a valid projection of its claimed closed dataset.**

   **Evidence:** The closed vocabulary has no `typed` member, but the resolver-record row uses `refused / typed` ([0023:1257](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1257), [0023:1306](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1306)). `module.parent` and `module.children` are object/array shapes grouped ambiguously under `virtual-absolute / closed` ([0023:1304](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1304)); `__exactPackageRoot` is given alternatives rather than one result ([0023:1322](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1322)); and `os.userInfo()` does not pin how closure appears.

   `Exact` and `Bun` are the same live object ([exact-global.js:2824](/Users/ccheever/projects/ibex/src/engine/bootstrap/exact-global.js:2824)), but Bun URL aliases are omitted. `Exact.resolve`/`resolveSync` are additional cwd readers ([exact-global.js:849](/Users/ccheever/projects/ibex/src/engine/bootstrap/exact-global.js:849)). I also executed the repository’s `path.js` under Node with `/project` as cwd: `path.win32.resolve("x")` returned `\project\x`, not a canonical virtual absolute path, contradicting the generic disposition at [0023:1310](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1310).

   **Resolution criterion:** Give each field/alias/mode one exact disposition and outcome; introduce a typed-logical or lexical-Windows disposition if needed; include Bun and Exact aliases; and define nested record/object shapes explicitly.

9. **Material — the ledger’s resolvable-stamp claim is false and already hides sibling drift.**

   **Evidence:** §9 says every stamp resolves and makes that the checker’s first assertion ([0023:1714](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1714)). I ran `git cat-file -t`: `3060574776a3` resolves as a commit, while `88decefdc683` and `88ebc6349bab` do not resolve. The current 0024 SHA-256 prefix is `6416ccb8c3c2`, not the table’s `88ebc6349bab`; its current module-identity text is no longer aligned. Several rows also use line numbers or `current` instead of revisions ([0023:1733](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1733), [0023:1743](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1743)).

   **Resolution criterion:** Separate section locator from revision, use committed blob or commit IDs for every row, verify each with `git cat-file`, re-audit current siblings, and make the checker reject unresolved or stale stamps.

10. **Minor/Non-blocking — several repaired references remain stale.**

   **Evidence:** §7.2 says LLP 0022 mints `interim` and later says it does not ([0023:1462](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1462), [0023:1516](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1516)); “four tiers” lists tiers 0–4; denial/absence are rows 7/8, not 8/9; and `ELOOP` is row 9, not 10 ([0023:1481](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1481), [0023:1549](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1549)). The case-alias discussion points to OQ3 instead of OQ10, while `os.devNull` incorrectly calls OQ10 resolved.

   **Resolution criterion:** Correct the labels and cross-references without changing the substantive ordering.

4. **Cross-document findings**

- **Blocking seam — `.load` credential cardinality:** LLP 0022 requires one permit consumed before any effect while also binding the eventual byte digest ([0022:680](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:680)). LLP 0024 correctly identifies that as circular and requires separate read and evaluation capabilities ([0024:239](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:239)). LLP 0022 also falsely says current 0024 still uses “decision evidence” ([0022:726](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:726)). Because 0023 delegates `OBL-TYPED-READ` through this seam, the corpus must adopt 0024’s two-capability capsule protocol consistently.

- **Material — module identity:** LLP 0023 deliberately gives case/normalization aliases distinct `SourceId`s ([0023:641](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:641)), while LLP 0024 still promises one instance “however it was spelled” and “across spellings” ([0024:1556](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1556), [0024:1990](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:1990)). Its AC also pluralizes synthetic modules, while 0023 says only `ibex:stdin` is a module ([0023:676](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:676)). LLP 0024 should state sameness only for equal `SourceId` and narrow the synthetic case to `ibex:stdin`.

- **Material — interrupts:** LLP 0022 closes an epoch only after quiescence plus prompt republication and promises two interrupts per epoch ([0022:896](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:896)). LLP 0025 closes at quiescence alone and requires three presses from the editing row ([0025:456](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:456), [0025:614](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:614)). LLP 0022 must defer to the current 0025 machine.

- **Material — graph discoverability:** LLP 0022 OQ2 claims prompt code can discover every in-graph package through import probing ([0022:1189](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:1189)). That is incompatible with 0023’s caller-authorized graph view when the global graph contains packages outside the caller’s permitted set.

- **Minor/Non-blocking — builtin terminology:** LLP 0024 defines `unknown-builtin` as outside an “allowlist” but also makes it decidable from static manifests without a snapshot ([0024:352](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:352), [0024:374](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:374)). It should say “absent from the static builtin manifest”; a known-but-disallowed builtin is a later snapshot/policy result.

- **Minor/Non-blocking — worker-locality carve-out:** 0023 permits only opaque authenticated session tokens across the worker boundary ([0023:1440](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1440)); 0025 requires a nonce-bound, non-rehydratable root-equality proof and records the missing carve-out ([0025:913](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:913), [0025:1016](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1016)). One sentence in 0023 can permit comparison proofs while continuing to forbid serialized VFS identities.

- **Minor/Non-blocking — stale citations:** 0022’s `OBL-PATHS` cites 0023 AC5 for the entire namespace/cwd bundle, but AC5 now covers only alias canonicalization ([0022:958](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:958), [0023:1792](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1792)). Its startup-diagnostic row says 0023 mandates symbolic output, while current 0023 explicitly permits the host path ([0022:993](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:993), [0023:357](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:357)). Its trap-free-inspection reference names 0024 OQ2, but that is current OQ1.

- **Minor/Non-blocking — other sibling drift:** 0024 says the constants annex exists while 0025 still says it does not; 0024 also has one stale AC sentence about `let $_; boom()` that contradicts its own normative fate table. These do not alter 0023’s architecture but should be reconciled before treating the sibling corpus as revision-locked.

5. **Suggestions**

- Check in the Node probes used during review—symlink/default versus `--preserve-symlinks`, hard links, case aliases, query/fragment identity, `%5C`/`%2F`, encoded dots, and argv—as executable compatibility fixtures with the tested Node version recorded.

- Generate both a public-operation matrix and an output-shape catalog, with unlisted operations and fields failing closed. A descriptor sweep alone is unlikely to discover every argument-dependent return shape safely; combine static export/type information with controlled runtime probes.

- Make error-order fixtures observe resolver calls and syscalls, not merely returned error codes. “Same error” is weaker than “no unauthorized probe happened.”

- Publish the intended v1 workload envelope. Reads, direct writes, descriptor writes, and non-recursive `mkdir` can support many evaluation workloads, but not package managers, atomic-save workflows, temp-heavy tools, or cleanup-heavy build systems. That compatibility boundary should be explicit.

- Represent ledger revisions automatically as `blob:<oid>` or `commit:<oid>` values generated by tooling, rather than manually entered prefixes.

6. **Open questions**

- Which canonical alias becomes the `SourceLabel`, and is that choice stored in authenticated provenance or derived from a deterministic binding order?

- Are query and fragment included in `SourceId`, stripped, or refused?

- Is `/dev/null` important enough for a fully specified synthetic node, or should `os.devNull` be closed in v1?

- Which concrete generation primitive is used on macOS, and is the retained-descriptor fallback affordable for graphs with many modules ([0023:2057](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2057))?

- Is the intentionally narrow mutation profile the advertised product scope, or must a writable state mount and atomic-save/cleanup support precede target promotion?

- Should captured referrers undergo the same stale-identity verification as cwd before later dynamic imports ([0023:2073](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2073))?

7. **Readiness verdict**

The proposal is a good idea and does not need redesign, but the current revision still has unresolved safety and semantic defects. The blocking items are concrete and localized; once they and the material corpus/dataset inconsistencies are resolved, the architecture appears capable of reaching READY.

VERDICT: NOT READY
### Orchestrator verification notes

Re-checked against the repository at `a77e5a385f6a`. Round 6 is a **split**: the
Fable half returned READY, this Codex half returned NOT READY. That is **not
convergence** — the loop requires both reviewers READY on the same revision — so the
round is recorded honestly as a split and the document is revised toward round 7.
The split is itself informative: it is the two reviewers disagreeing on the *depth*
of one finding (§4.2), and Codex is right.

**Confirmed — Blocking 2 is the finding that justified the round, and it is a real
feasibility defect Fable under-rated as Minor:**

- `ProtectedObjectGuard` is `{action, object}` (`crates/capsec-semantics/src/decision.rs:114-117`),
  matched by **exact** object identity (`decision.rs:946`), and the armed-snapshot
  schema admits **one object per protected row**. So §4.2's "every package binding's
  subtree is a protected object" is **not representable by one guard**. Path
  containment and inode aliasing are *different matching problems*: a **lexical
  path-tree guard** is needed to deny writes/creates to package *paths* before lookup
  (and to cover creating a *new* file inside a package root, where no object yet
  exists), while a separate **authenticated exact-object/generation set** is needed
  to catch writes through a hard link whose *spelling* is outside any package but
  whose *inode* is package source. Fable rated §4.2 Minor ("intent unambiguous");
  Codex correctly found it is a two-mechanism problem, which is exactly the "can the
  containment machinery host a tree-shaped guard" question the orchestrator's
  readiness note flagged as worth catching before freeze. Answered: not with one
  mechanism. Accepted; §4.2 and `OBL-PACKAGE-IMMUTABLE` now name **both** guards.

- **Blocking 9 is worse than the Fable half caught, and it is a humbling correction
  of my own round-5 work.** I ran `git cat-file -t` on the stamps: `3060574776a3`
  (the HEAD **commit**) resolves; `88decefdc683` and `88ebc6349bab` — the sibling
  **document shasums** — **fail** ("Not a valid object name"). A document's
  `shasum -a 256` is **not a git object id**; the git *blob* oid of 0024 is
  `42560218ce56` while its content sha256 is `6416ccb8c3c2` — different hashes
  entirely. So my "every stamp resolves" claim, the round-5 fix for the round-4
  stamp bug, is **itself false** for every sibling row. The convention conflated two
  distinct hashes. Fixed by labeling the method explicitly: `commit:<oid>` for
  this repo's tracked state (git-resolvable), `sha256:<prefix>` for sibling docs
  (shasum-verifiable, *not* git), and the claim reworded from "every stamp resolves
  [via git]" to "every stamp is verifiable by its stated method."

- **Blocking 1 (mkdir rollback race). Confirmed.** The shipped mkdir does `mkdirat`
  then a verification `openat` (`hermes_runtime_fs.cc:725`); a name-based rollback
  after a post-create failure is a TOCTOU the spec elsewhere closes (LLP 0021:683).
  Fixed: non-recursive `mkdir` is the atomic `mkdirat` under the retained parent with
  **no** name-based rollback — a post-`mkdirat` verification failure leaves the
  (benign) empty directory rather than racing an `unlinkat`.

- **Blocking 3 (resolve-only oracle). Confirmed.** `resolve_module_meta`
  (`src/host/mod.rs:1430`) stats and reads `package.json` during resolution, and the
  JS `require.resolve` path uses that metadata-only route
  (`module-loader.js:5768-5770`) — so a resolve-only call can probe a path before the
  out-of-snapshot / caller-view check, an existence oracle AC 24 did not cover.
  Fixed: the gate and the no-probe-before-authorization rule apply to **every**
  resolve-only bridge; AC 24 tests them.

- **Blocking 4, 5 (`SourceId` query/fragment; `SourceLabel` spelling). Confirmed** —
  both were "declared total/deterministic" while an OQ left the actual value open, an
  internal contradiction. Decided this round: query/fragment are **stripped** from a
  file-backed `SourceId` (a stated divergence from Node ESM, which splits on them),
  and `SourceLabel` is pinned to the **load-order-independent** volume-canonical
  spelling of the canonical physical location. OQ 7/OQ 8 close.

- **Blocking 6 (`/dev/null`). Confirmed**, and Fable flagged it too (its concern 3).
  §6 invented a synthetic sink that §3's "child of `/` that is not a mount" rule
  refuses, with no node semantics. Fixed by the honest v1 answer: `os.devNull`
  returns the well-known constant string `/dev/null` (which names no host and
  discloses nothing), it is **not** a mount, so an `fs` operation on it fails
  outside-mount in v1, and a reserved sink node is a named future item — no invented
  half-specified machinery.

- **Material 7, 8 (unclassified mutation surface; table not a valid projection).
  Confirmed.** 165 chmod/chown/utimes/mkdtemp hits in `fs.js` are neither open nor
  closed; the `refused / typed` disposition uses a `typed` member absent from §6's
  closed vocabulary; `path.win32.resolve("x")` returns `\project\x` (I did not
  re-run this, accepting the reviewer's execution) which is not `virtual-absolute`.
  Fixed: a **default-closed** rule for any unlisted mutation op (metadata mutation
  and `mkdtemp` explicitly closed in v1), a `typed-logical` disposition member, Bun
  URL aliases added, and the platform-string `path.win32`/`path.posix` variants
  dispositioned `non-path` (they embed only the projected virtual cwd).

- **Material 10 / Minor drift. Confirmed.** The `interim` leftover (line 1462, which
  the Fable half also caught), "four tiers" now spanning tiers 0–4, and the row-number
  drift (denial/absence at 7/8 not 8/9; `ELOOP` at 9 not 10) are all real consequences
  of my round-5 renumbering. Fixed.

**Refuted / corrected:** nothing material. Where the two round-6 halves disagree
(§4.2 severity), the Codex depth-finding governs — a security control that cannot be
expressed by the shipped mechanism is Blocking, not Minor, regardless of whether its
*intent* is clear.

**Cross-doc handled per the coordinator's routing:** the `.load` credential
cardinality tension is a genuine 0022 §7 defect (one permit vs binding the byte
digest, which needs the read); I do not fix 0022, but this document's
`OBL-TYPED-READ` now cites **LLP 0024's two-capability capsule protocol** (separate
read and evaluation permits), not 0022's un-nuanced "one permit," so the seam this
document depends on names the correct side. The remaining cross-doc items (0024
module-identity "across spellings" vs the case-alias split; 0022↔0025 interrupts;
0022 OQ2 graph-probing vs the caller-view; stale 0022 citations) are sibling-side and
reported, not fixed.

**Disposition:** Accepted on Blocking 1–6 and Material 7, 8, 9, 10. Round 7 is
warranted — six blockers is not a convergence residue — and every one is localized
specification work, not architecture, consistent with both reviewers' read that the
design is sound.

---

## Round 7 — 2026-07-12

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`, sandbox
  `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`; **reasoning effort:** `ultra` — both confirmed in the log
- **Session id:** `019f57b8-615b-7540-8b06-08581adda8ee`
- **Integrity:** rollout final-message md5 `2f15f494ef8c` == captured body md5,
  reproduced independently.
- **Date:** 2026-07-12
- **Revision under review:** `ed6599c16ea9` — the **same** revision the round-7 Fable
  half reviewed.
- **Redacted:** No.
- **Independence:** Fresh non-interactive Codex session; no access to the
  orchestrating session, the round-7 Fable half, or any prior LLP 0023 artifact —
  rounds 1–6 stashed out of `llp/reviews/` for the duration, directory verified empty
  of 0023 files while it ran. This is the **Codex half** of round 7.
- **Method:** cli-runner, round-7 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round7.md`). This review parsed all 22
  registry/schema JSON artifacts, checked every ledger stamp by its named method, and
  executed Node/Bun and the source/vendored JS artifacts.

### Verbatim review

1. **Overall assessment**

This is a strong design direction, but the current revision is not ready as a normative Spec. The round-6 repairs materially improved the document—especially the mutation narrowing, two-guard decomposition, resolve-before-probe rule, `SourceId` query/fragment decision, and ledger stamp convention—but several genuine correctness and coherence defects remain.

I read all 2,214 lines of LLP 0023 and the complete governing/sibling documents. I verified the target hash as `ed6599c16ea9…`, parsed all 22 registry/schema JSON artifacts with Python, checked every ledger stamp by its named method, traced cited identifiers to reachable code, and executed Node/Bun and the relevant source/vendored JavaScript artifacts. The important failures below come from those executions, not conjecture.

2. **Strengths**

- **Project discovery is unusually well specified.** §1.1 defines origin selection, ancestor-inclusive workspace matching, marker precedence, stop boundaries, malformed-marker behavior, and fallback diagnostics (`llp/0023-virtual-filesystem-namespace.spec.md:203-330`). This directly replaces the live `project_root/node_modules/<name>` guess at `src/bin/ibex/runtime.rs:1823-1853`.

- **§1.2 is honest about binding and integrity prerequisites.** It correctly observes that the armed graph lacks resolved roots, aliases, and virtual prefixes (`0023:334-369`), matching `capsec/schema/armed-snapshot.schema.json:211-235,328-345` and `crates/capsec-semantics/src/arming.rs:58-68`.

- **The staged identity model and per-principal projection are sound.** §2.1 distinguishes `NamespacePath`, `DiscoveredPath`, and `CommittedPath`, while explicitly acknowledging that current `ObjectState` cannot represent requested-stage unknown (`0023:432-464`; `crates/capsec-semantics/src/model.rs:1250-1284`). §2.2 also correctly identifies the missing principal-resource wire pairing (`0023:522-568`; `capsec/schema/effect.schema.json:49-64`; `crates/capsec-semantics/src/cache.rs:49-60`).

- **The empirical Node corrections are now accurate.** I ran Node 24.14.0 and confirmed:

  - query and fragment variants instantiate distinct ESM modules;
  - default ESM and CommonJS unify real and symlink spellings;
  - case-variant spellings on this case-insensitive volume instantiate distinct ESM modules;
  - `%5C` decodes and round-trips, while `%2F` throws `ERR_INVALID_FILE_URL_PATH`;
  - stdin places `"-"` at `argv[1]`, while `-e` begins user arguments at index 1.

  These support §2.3, §3, and the argv table (`0023:717-795,914-944,1424-1428`). The `%5C` citation now correctly identifies the earlier refusal as dead code under `false &&` at `src/builtins/url.js:163-229`.

- **The §4.1 narrowing is a good safety decision.** Default-closing name-bound, multi-operand, recursive, metadata, and temporary-directory mutations is coherent (`0023:1049-1080`). Removing mkdir rollback is also correct: the current rollback calls are name-bound `unlinkat`s at `src/engine/hermes_runtime_fs.cc:732,740,1638,1645`, and can delete a concurrent replacement. A preauthorized atomic `mkdirat` may honestly leave an empty directory when later verification fails.

- **The two-guard package split is conceptually correct.** A lexical guard is needed for absent creates, while exact object/generation matching is needed for pre-existing hard-link aliases (`0023:1117-1167`). The current guard really is only one exact object (`crates/capsec-semantics/src/decision.rs:114-117,946-958`), and the runtime currently protects only the project-root object (`src/bin/ibex/runtime.rs:1948-1952`).

- **§7.1’s session handle and worker-lease model is realistic.** The current host is process-global and replaceable (`src/host/abi.rs:130,214-224`), while the typed filesystem ABI carries no session identity (`src/host/abi.rs:975-987`). Reusing the existing opaque `ExactHermesRuntime` handle (`include/exact_runtime.h:27-38`) and distinguishing the semver-major and implementation-detail halves is good design.

- **The ledger stamp repair is mechanically correct.** `git cat-file -t 3060574776a3` returned `commit`. `shasum -a 256` matched `020f3455209e` for LLP 0002, `daa9a6823b00` for LLP 0021, `88decefdc683` for LLP 0022, and `6416ccb8c3c2` for LLP 0024. The remaining ledger problems are semantic, not stamp-method failures.

3. **Concerns**

1. **Severity: Blocking — `Exact.resolve`/`Bun.resolve` has two incompatible normative meanings.**

   **Evidence:** §6 classifies these as cwd-reading path resolvers (`0023:1403`), matching reachable code: `src/engine/bootstrap/exact-global.js:849-857` delegates directly to `path.resolve`. I executed it and `Exact.resolve("pkg")` returned `/Users/ccheever/projects/ibex/pkg`.

   But §7.2, `OBL-RESOLVE-GATE`, and AC 19r treat the same functions as module-resolution routes subject to import-graph membership (`0023:1605-1612,1859,2017-2021`). The registry also classifies them as module-resolution `fs:list` effects (`capsec/registry/coverage-edges.json:190971-191015,197568-197613`). Bun 1.3.12’s actual `Bun.resolveSync("./package.json", cwd)` performed module resolution, confirming that the compatibility name itself does not settle the intended behavior.

   **Resolution criterion:** Choose one API contract. If it remains lexical path arithmetic, remove it from `OBL-RESOLVE-GATE`/AC 19r and classify its cwd observation correctly. If Bun-compatible module resolution is intended, rewrite §6, §8, the implementation, and fixtures, pinning referrer, sync/async, error, and return semantics.

2. **Severity: Blocking — the supposedly total §6 disposition universe is neither total nor single-valued.**

   **Evidence:**

   - `Exact.which`/`Bun.which` is absent from §6. It is reachable at `src/engine/bootstrap/exact-global.js:1239-1247`; native `__exactWhich` searches host `PATH`, calls `realpath`, and returns the host spelling at `src/engine/hermes_runtime_process.cc:2647-2697`. All three aliases are already inventoried as effectful registry surfaces (`coverage-edges.json:186838-186875,192505-192550,199192-199240`). V1 admits no subprocess authority, so it needs an explicit closed/null/refused disposition.
   - §6 gives cwd-consulting `node:path` results virtual-path dispositions at `0023:1398`, then calls all `path.posix.*` and `path.win32.*` results `non-path` at `0023:1404`. I ran the artifact with cwd `/project`: the default export was exactly `p.posix`, `p.posix.resolve("x")` returned `/project/x`, and `p.win32.resolve("x")` returned `\project\x` (`src/builtins/path.js:56-70,203-212,473-477`).
   - `module.parent`/`children` are both “closed” in one row and `non-path` in another (`0023:1392,1414`). The live objects directly link the loader graph (`src/engine/bootstrap/module-loader.js:5296-5315`), allowing upward traversal to the same mutable state that LLP 0022 closes through `require.main` and `require.cache` (`llp/0022-repl-behavior-and-semantics.spec.md:243-260`).
   - `require.resolve` is not always `virtual-absolute` as `0023:1391` says. The live return is `record.path || record.id || specifier` (`module-loader.js:5774-5786`); builtins therefore return identifiers. Running Node confirmed `require.resolve("fs") === "fs"` and `require.resolve("node:fs") === "node:fs"`.
   - `require.resolve.paths` is currently hardcoded to `null` (`module-loader.js:5416-5418,5791-5793`), yet AC 19r treats it as a probing resolver without first deciding whether v1 keeps the null behavior.
   - Existing output families including `Exact.argv`/`main`, `Bun.argv`/`main`, `fs.glob`/`globSync`, `require.main`, and `process.mainModule` are not dispositioned, despite the bidirectional-totality claim at `0023:1333-1377`.

   **Resolution criterion:** Produce the actual independent catalog and disposition dataset now, keyed at least by alias, mode, module kind, builtin/file/synthetic kind, and return variant. Give every surface one unambiguous disposition. Close `module.parent`/`children` or specify a principal-filtered immutable facade; explicitly disposition `Exact.which`; split builtin and file-backed resolver/module fields; and decide `.paths`.

3. **Severity: Blocking — hard-link `SourceLabel` is incompatible with split `SourceId`, referrer, and source-map semantics.**

   **Evidence:** §2.3 deliberately gives same-principal hard-link entries distinct `SourceId`s/modules (`0023:647-653,788-795`), but assigns every such entry the one lexically least hard-link spelling as `SourceLabel` (`0023:693-715`; AC 18a at `2010-2016`).

   That creates two unresolved collisions:

   - §7.3 says relative imports use “that module’s virtual directory” (`0023:1701-1707`). For hard-linked `/a/main.js` and `/z/main.js`, resolving the `/z` instance from `/z` makes its `import.meta.url` disagree with its base; resolving from the shared `/a` label makes its distinct lexical `SourceId` disagree with its base.
   - LLP 0024 keys the in-memory source-map registry by source label (`llp/0024-structured-evaluation-and-session.spec.md:676-683`). Distinct hard-link modules therefore collide. Different hard-link filenames can have different extensions and transformations; extension-based transpilation already exists at `src/module_loader/mod.rs:252-256`.

   The implementation also has no reverse object-to-all-directory-entries index; its retained identity is only platform/volume/file (`crates/capsec-semantics/src/model.rs:614-620`). Finding the lexically least hard link otherwise requires a complete binding scan that the Spec does not assign.

   **Resolution criterion:** Make a hard-linked module’s label/referrer derive from its own lexical `SourceId` path while retaining symlink realpath unification; or define a digest-bound reverse-object index and change LLP 0024’s source-map key to `SourceId` plus evaluation identity. Add different-directory and different-extension hard-link fixtures.

4. **Severity: Material — the two package-immutability guards lack a complete construction and create-path contract.**

   **Evidence:** “Either fires denies” is correct only if the object set is complete and the lexical guard is applied to every effective create location. §4.2 never states when the complete package-source `(object,generation)` set is populated, whether it follows package/source symlinks, how it is tied to integrity verification, or how races during enumeration are handled (`0023:1152-1169,1853`). A lazy loaded-object set loses on the first write through a never-loaded hard-link alias.

   §4 does require reauthorization after following a symlink (`0023:967-985`), but §4.2 pins its lexical guard to the requested stage, and AC 7a tests only a direct create (`0023:1943-1951`). It never explicitly states that the caller-independent package guard is rerun against the canonical retained parent plus absent tail for an outside spelling such as `scratch/link/new.js` where `link` points into a package. Ordinary package-root authority matching is principal-relative (`crates/capsec-semantics/src/decision.rs:1124-1140`), so it cannot silently stand in for this global immutability guard.

   **Resolution criterion:** Define a digest-bound, arming-time complete package-object index produced by the integrity walk; specify symlink handling and race behavior; and require the lexical guard after each symlink expansion against canonical parent plus tail. Add never-loaded hard-link and symlink-to-package create fixtures for `writeFile`, writable `open`, and `mkdir`.

5. **Severity: Material — the “metadata-only” resolver reads ESM bodies under a metadata-only registry classification.**

   **Evidence:** §7.2 says `resolve_module_meta` stats and reads `package.json`, citing `src/host/mod.rs:1430` (`0023:1605-1609`). That cited line is only the function signature. The reachable call at `src/host/mod.rs:1435` enters `ModuleLoader::resolve_meta`; for ordinary ESM, `src/module_loader/mod.rs:764-810` executes `std::fs::read_to_string` and retains the source.

   Native comments claim the route does not read the body (`src/engine/hermes_runtime.cc:1871-1877`), but they are false for `.mjs`/plain ESM. Existing tests use `.ts`, whose extension bypasses that read (`src/module_loader/mod.rs:1352-1405`). Meanwhile `__exactModuleResolveMeta` carries only `fs:list` in the registry (`coverage-edges.json:180527-180572`).

   The proposed graph gate closes the unauthorized-package existence oracle, but it does not authorize this separate body read.

   **Resolution criterion:** Make `resolve_meta` genuinely body-read-free and add an `.mjs` syscall/permission fixture; or add a distinct pre-read `fs:read` decision and update the registry, compatibility contract, and documentation. The body-free design is preferable for `require.resolve`.

6. **Severity: Material — the default-closed mutation and error matrices cannot generate deterministic fixtures as written.**

   **Evidence:** §4.1 says every mutation not explicitly listed open is closed (`0023:1075-1080`). The open table names `writeFile`, truncate, descriptor writes, and mkdir, but not the writable/create/truncate forms of `open`, `appendFile`, or `createWriteStream` (`0023:1082-1090`). Yet §4.2 assumes writable descriptor opens exist (`0023:1136-1139`).

   Separately, `watch` is closed before path work and must return first-tier `EPERM` (`0023:1059-1070,1635-1643`), while §5.2 and AC 10 require a watch on `/` to return the later synthetic-node error (`0023:1261-1268,1969-1971`). Both cannot be true.

   **Resolution criterion:** Name a machine-readable open-family set covering every sync/callback/promise/descriptor/stream alias, with open-flag semantics. Remove closed operations from synthetic-node examples, or change the precedence rule and explicitly reopen the operation.

7. **Severity: Material — `ERR_IBEX_ALIAS_COLLISION` has no defined predicate.**

   **Evidence:** The canonicalization rule correctly specifies comparison domains and application to selectors and occurrences (`0023:828-865`), but never defines what facts constitute a collision. Nevertheless, the error is ordered at `0023:1642`, and `OBL-ALIAS-CANON` promises an “occurrence-time collision condition” at `0023:1862`. AC 5 tests alias equivalence only (`0023:1912-1916`).

   **Resolution criterion:** Define the exact collision predicate, stage, compared records, and safe diagnostic, with a fixture; otherwise remove this error class from the v1 order.

8. **Severity: Material — captured-referrer stale identity remains an unresolved safety decision.**

   **Evidence:** §7.3 normatively captures module and submission referrers (`0023:1699-1708`), but OQ 12 still asks whether a renamed/replaced referrer fails stale or resolves from the old spelling (`0023:2212-2214`). Following a retained directory moved outside the mount, rebinding the old spelling, and refusing stale have materially different containment behavior.

   **Resolution criterion:** Pin the retained-object-versus-spelling behavior and add dynamic-import fixtures for in-mount rename, replacement, and relocation outside the project binding.

9. **Severity: Material — the ledger’s methods are fixed, but several semantic attestations are false or stale.**

   **Evidence:** `OBL-TARGET-PROMOTE` claims stamped LLP 0021 is consistent because its header says macOS is unadvertised (`0023:1871`; `llp/0021-capsec-effect-model-migration.plan.md:8`). The same stamped document later calls macOS the only advertised profile (`0021:930-943`), as does LLP 0013 (`llp/0013-per-package-capability-compartments.rfc.md:18-24`). I parsed `policy-rules.json`: `advertisedTargets` is actually `[]`, with macOS only a candidate.

   Likewise, `OBL-ERROR-ORDER` says the LLP 0022 half is outstanding (`0023:1870`), but running `rg` for total/error-order language found no restated total order in current LLP 0022.

   **Resolution criterion:** Re-run the semantic join against the whole stamped document, not one selectively quoted line; update the ledger and sibling attestations together; and extend `OBL-LEDGER-CHECK` beyond stamp syntax to owner-side claims.

10. **Severity: Minor/Non-blocking — the macOS generation identifiers and rollback citation are inaccurate.**

    **Evidence:** §2.3/OQ 9 names `ATTR_CMNGEN`, while the ledger names `ATTR_CMN_GEN` (`0023:765-768,1851,2195-2199`). Neither exists in the installed SDK. The actual public identifiers are `st_gen` at `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/stat.h:125` and `ATTR_CMN_GEN_COUNT` at `sys/attr.h:438`. Also, `0023:1090` cites `hermes_runtime_fs.cc:725` for rollback; that line is `mkdirat`, while rollback is at `:732/:740` and `:1638/:1645`.

    **Resolution criterion:** Correct the identifiers and citations, then separately verify which generation primitive is reliable on supported filesystems.

4. **Cross-document findings**

- **LLP 0022 startup-diagnostic ledger is stale.** `llp/0022-repl-behavior-and-semantics.spec.md:993` says LLP 0023 mandates symbolic-only output. Current LLP 0023 explicitly permits the operator-facing host root (`0023:382-398`), agreeing with LLP 0022’s own rule (`0022:480-487`).

- **LLP 0022 and LLP 0025 still disagree on interruption epochs.** LLP 0022 closes an epoch on quiescence plus prompt republication and promises two interrupts within it (`0022:892-905`). LLP 0025 resets escalation only on live-prompt editor input (`llp/0025-terminal-session-ownership.spec.md:486-506`) and records both LLP 0022 statements as stale (`0025:1077-1078`).

- **The known LLP 0024 module-identity drift is confirmed.** Its “one file … however spelled” and AC 15 language (`0024:1556-1564,1990-1995`) conflicts with LLP 0023’s intentional case-alias and same-principal-hard-link splits. Its OQ 10 still says canonical `SourceLabel` is open (`0024:2139-2142`), while LLP 0023 now pins it. More seriously, its source-map registry key (`0024:676-683`) conflicts with LLP 0023’s shared hard-link label.

- **LLP 0025’s target pin is stale.** `0025:1076` calls `0023@2b4c28230caf` current; the reviewed revision is `ed6599c16ea9`. The nonce-bound equality proof is plausibly compatible with §7.1 because it is non-rehydratable, but the explicit carve-out remains a dangling dependency.

- **LLP 0025 contradicts itself about history-token possession.** §9 says the worker receives no history-scope token (`0025:957-961`), while AC 11 says it holds an opaque token (`0025:1181-1183`). The acceptance criterion should assert absence.

- **Governing LLP 0021 remains stale against §4.1.** It still requires name-bound mkdir rollback (`0021:678-687`) and says descriptor ownership/mode/time mutations remain open (`0021:664-666`), whereas LLP 0023 removes rollback and closes the metadata-mutation family.

- **The known `.load` credential disagreement need not be reopened here.** LLP 0023 now correctly cites LLP 0024’s two-capability read/evaluation capsule at `0023:1857`; that side of the seam is coherent.

5. **Suggestions**

- Materialize the output-disposition catalog and dataset as checked JSON before further prose review. Most remaining §6 defects would become ordinary duplicate/missing-key failures.

- Add a `platform-lexical` disposition for `path.win32` results instead of calling path-shaped values `non-path`.

- Build the package immutable-object set as a by-product of the same complete integrity walk that authenticates package bytes. One traversal should produce both the digest proof and the object/generation index.

- Key source maps internally by `SourceId` plus evaluation identity; retain `SourceLabel` strictly as display data.

- Put import/resolve membership in one native admission function shared by `import`, local/global `require.resolve`, `createRequire`, and raw bridges. JavaScript call-site discipline is too easy to bypass.

- Scope “JavaScript never sees a host path” precisely. Authorized `process.env.HOME`/`PATH` currently return native values (`src/engine/hermes_runtime.cc:1159-1183,1186-1245`), and argv/user strings can themselves contain host paths. The useful invariant is likely “the runtime never originates or derives a backing host path except through an explicitly authorized external-data channel.”

6. **Open questions**

- Is `Exact.resolve` intentionally lexical, or is Bun-compatible module resolution the desired API?
- Are first-party workspace package roots deliberately immutable, or should authenticated application/workspace source differ from third-party package source? §4.2 preserves writes only outside package bindings.
- Does `require.resolve.paths` remain a constant `null`, or become a gated virtual search-path API?
- What concurrent external-mutator threat model applies to retained parents and captured referrers moved outside their original binding?
- Which environment/operator-supplied string channels are explicitly exempt from the no-runtime-originated-host-path invariant?

7. **Readiness verdict**

The current revision retains genuine blocking defects in resolver semantics, output-disposition totality/safety, and hard-link source labeling, plus several unresolved material contracts. These are not round-seven polish.

VERDICT: NOT READY
### Orchestrator verification notes

Re-checked against `ed6599c16ea9`. Round 7 is complete (Fable NOT READY, Codex NOT
READY). Per the orchestration's read — a reconciliation churn whose exit both
reviewers named (materialize the disposition dataset as checked JSON) — the round-8
reconciliation is a **minimal closing pass**: close blockers with the smallest edits
that make them total/single-valued, ledger what needs a generated dataset rather than
hand-writing a table the next reviewer falsifies, introduce nothing new.

**Confirmed (decisive claims, verified before accepting):**

- **Blocking 1 (`Exact.resolve` two meanings). Confirmed.**
  `src/engine/bootstrap/exact-global.js:851-854` — `E.resolve = function() { var path
  = require('path'); return path.resolve.apply(path, arguments); }`. Pure lexical
  `path.resolve` delegate, not module resolution. Removed from `OBL-RESOLVE-GATE` /
  AC 19r; classified `non-path` (cwd-read); the registry-vs-code mismatch and the
  Bun-module-resolution question become OQ 13.
- **Blocking 2 (§6 not total / not single-valued). Confirmed**, and this is the churn
  the coordinator flagged as the exit. `require.resolve` returns `record.path ||
  record.id || specifier` (`module-loader.js:5786`), so builtins return their id
  (`require.resolve("fs") === "fs"`); `.paths` is hardcoded `null` (`:5791`);
  `Exact.which`/`fs.glob`/`require.main`/`process.mainModule` were undispositioned;
  `module.parent`/`children` were double-valued. Rather than re-architect the table in
  prose (which spawned this defect three rounds running), the §6 table is demoted to
  an **illustrative interim projection** and the generated `OBL-DISPOSITION-DATASET`
  is the normative totality — the move LLP 0025 made for its interrupt model. Visible
  flat contradictions fixed; the churn surfaces closed or dispositioned.
- **Blocking 3 (hard-link `SourceLabel` collides split `SourceId`). Confirmed** by
  reading §2.3/§7.3 against LLP 0024's source-map-by-label. Fixed by the *simpler*
  rule: a hard link's `SourceLabel` is its **own** entry's spelling (matching its own
  `SourceId`), not a shared lexically-least one — so per-instance identity, label,
  referrer, and source-map key all agree, and the reverse object→entries index the
  model lacks is not needed. Collation pinned byte-wise-UTF-8.
- **Material 5 (`resolve_meta` reads ESM bodies). Confirmed.**
  `src/module_loader/mod.rs:775` — `std::fs::read_to_string(&full_path)` for ESM
  classification, under an `fs:list`-only classification. §7.2 now requires the
  resolve route to be **body-read-free**; `OBL-RESOLVE-GATE` names it.
- **Material 4, 6, 7, 8, 9, 10 and the two Fable-half carry-forwards. All confirmed**
  and reconciled minimally: the two immutability guards gain an arming-time
  integrity-walk object set + rerun-after-symlink; the open-write family is
  enumerated and the `watch`-on-`/` contradiction resolved (watch is closed-`EPERM`,
  earlier than synthetic-node); `ERR_IBEX_ALIAS_COLLISION` (no defined predicate)
  removed from the v1 order; the referrer stale-identity pinned (OQ 12 closed); the
  two false ledger attestations corrected and `OBL-LEDGER-CHECK` extended to verify
  owner-side *claims* not just stamp syntax; `OBL-MKDIR-ROLLBACK` files the untracked
  mkdir/0021 contradiction; the `OBL-HISTORY-LOCALITY` §7.1 line LLP 0025 drafted is
  added; `st_gen`/`ATTR_CMN_GEN_COUNT` and the rollback citation corrected.

**The ledger-attestation finding cuts deepest, and it is recorded as doctrine.**
`OBL-TARGET-PROMOTE` and `OBL-ERROR-ORDER` each carried a *resolvable* stamp whose
*owner-side claim* was false or stale (0021 is internally inconsistent on target
advertisement; 0022 has no restated order to retract). So a resolvable stamp is
necessary but not sufficient — the tool built to catch unverified completion claims
was, a third time, an unverified completion claim of a subtler kind. §9 now states
that `OBL-LEDGER-CHECK` must verify the owner-side semantic claim against the whole
stamped document.

**Disposition:** Accepted on Blocking 1–3 and Material 4–10, plus the Fable-half M1/M2.
Reconciled at `601cb5213dca` as a minimal closing pass. Round 8 reviews that revision.
If it converges (both families READY), Status advances Draft→Review; if not, the
residual owed artifacts (the disposition catalog; the model-checkable pieces) become
implementation tickets, not round 9.

---

## Round 8 — 2026-07-12  (terminal round)

**Provenance**

- **Reviewer family:** GPT (OpenAI), Codex
- **Provider / runtime:** OpenAI Codex CLI `codex-cli 0.144.1`, `codex exec`, sandbox
  `read-only`, workdir `/Users/ccheever/projects/ibex`
- **Model:** `gpt-5.6-sol`; **reasoning effort:** `ultra` — confirmed in the log
- **Session id:** `019f57de-5fe7-7c33-b564-9f1e318878a4`
- **Integrity:** rollout final-message md5 `d846996263f8` == captured body md5,
  reproduced independently.
- **Date:** 2026-07-12
- **Revision under review:** `601cb5213dca` — the same revision the round-8 Fable half
  reviewed.
- **Redacted:** No.
- **Independence:** Fresh non-interactive Codex session; no access to the orchestrating
  session, the round-8 Fable half, or any prior LLP 0023 artifact (rounds 1–7 stashed,
  directory verified empty of 0023 while it ran). The **terminal** round, run with
  human authorization to finish.
- **Method:** cli-runner, round-8 brief verbatim. Recomputed the target SHA-256,
  verified stamps by their methods, loaded registry/schema JSON with Python, ran
  `./ref-check`, executed Node probes and the shipped binary, traced Rust/C++ entry
  points.

### Verbatim review

## 1. **Overall assessment**

The architecture and overall plan remain sound, but round 8 is not ready to close. The remaining defects are bounded reconciliation issues—not reasons to redesign the namespace—but several are genuine normative contradictions, incorrect executable values, or incomplete safety gates.

I read the complete target and required sibling/governing corpus, without reading `llp/reviews/`. I recomputed the target SHA-256 (`601cb5213dca`), verified the `commit:` and `sha256:` stamps by their stated methods, loaded the registry/schema JSON with Python, ran `./ref-check`, and executed Node probes against source and vendored artifacts for `Exact`/`Bun`, `node:path`, glob, module metadata, URL handling, query-bearing imports, and argv behavior. I also traced the relevant Rust/C++ entry points. `./ref-check` passed, but it does not validate obligation semantics.

The generated disposition dataset is a good and appropriate solution to prose-table incompleteness. I am not treating its not-yet-landed totality as a blocker. The problems are that its delegated contract is not yet defined consistently and several rows that the interim table does name contain demonstrably wrong values.

## 2. **Strengths**

- The staged `NamespacePath → DiscoveredPath → CommittedObject` model and per-principal projections are a strong foundation for avoiding existence oracles and confused-deputy authority. The per-stage `containment → authorization → existence` rule is particularly clear in [§7.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1768).

- The repaired hard-link rule in [§2.3](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:749)—each entry gets its own `SourceId`, `SourceLabel`, referrer, and source-map key—does remove the prior collision with LLP 0024’s source-map registry keyed by `SourceLabel` at [LLP 0024 §2](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:676). It is feasible and requires no reverse inode-to-entry index.

- Moving disposition totality to an independently generated catalog and bidirectional join is the right response to repeated prose drift. [§6](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1440) correctly explains why the current registry cannot prove output-field completeness by itself.

- The two-guard package-immutability design is conceptually correct: a requested-stage lexical guard covers nonexistent creates, while an exact object/generation set covers hard-link aliases at commit. Current `ProtectedObjectGuard` really is only one exact object, confirming the need for the extension described in [§4.2](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1191).

- The round-7 resolve corrections are substantially right. I executed the artifacts and confirmed that `Exact.resolve`/`Bun.resolve` are `path.resolve` delegates at [exact-global.js:849](/Users/ccheever/projects/ibex/src/engine/bootstrap/exact-global.js:849), while `require.resolve("fs")` returns `"fs"` via [module-loader.js:5774](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5774). Removing `Exact.resolve` from the module-resolution gate was correct.

- The body-read-free resolve obligation identifies a real defect: `resolve_meta` reads ESM source at [mod.rs:775](/Users/ccheever/projects/ibex/src/module_loader/mod.rs:775).

- `OBL-MKDIR-ROLLBACK` accurately captures both the sibling contradiction and shipped TOCTOU-prone rollback: `mkdirat` occurs at [hermes_runtime_fs.cc:725](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:725), followed by name-bound `unlinkat` cleanup.

- The stamp convention is now technically sound. All cited prefixes resolved through their named method. The history-locality acknowledgement is also present and semantically closes LLP 0025’s requested seam.

## 3. **Concerns**

1. **Blocking — AC18a directly contradicts the repaired hard-link `SourceLabel` rule.**

   **Evidence:** Section 2.3 requires each hard-link entry’s own spelling at [0023:749](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:749), but AC18a still requires both entries to use the lexically least spelling at [0023:2145](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2145). That recreates the referrer/source-map-key collision the revision says it removed.

   **Resolution criterion:** Change AC18a to assert distinct per-entry labels, referrers, and source-map keys in both load orders; retain shared labeling only for symlink aliases.

2. **Blocking — stale retained-base identity is ordered after an operation that must not occur first.**

   **Evidence:** Section 5.2 requires revalidating retained cwd identity before later relative resolution at [0023:1347](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1347), with the same requirement for retained module referrers in §7.3. Yet the error table puts target `ENOENT` at row 7 and all stale identity at row 10, while the prose says stale identity necessarily follows requested-stage `ENOENT` at [0023:1760](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1760). With a replaced cwd followed by `readFile("missing")`, inspecting the replacement or child before rejecting the stale base violates the retained-base guarantee.

   **Resolution criterion:** Distinguish stale base/referrer validation from stale final-object-at-commit, or define phase-relative precedence. Add a fixture where the base is replaced and the requested child is absent, asserting stale identity before any child lookup.

3. **Blocking — `OBL-ERROR-ORDER` makes a false whole-document attestation.**

   **Evidence:** The row says stamped LLP 0022 contains only class statements consistent with §7.2 at [0023:2003](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2003). LLP 0022 says habitual host paths produce outside-mount errors from watches and every effectful filesystem operation at [0022:471](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:471). LLP 0023 instead closes every watch before path work with `EPERM` at [0023:1741](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1741).

   The related statement that “a watch or mutation on `/`” always gets closed-operation `EPERM` at [0023:1339](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1339) is also too broad: §4.1 explicitly opens writes and non-recursive `mkdir`.

   **Resolution criterion:** Qualify LLP 0022 to cover only adapters that reach namespace classification, then repin and re-attest the entire document. In 0023, say “watch or closed mutation” and separately pin the synthetic-root result for open writes and non-recursive `mkdir`.

4. **Material — several named §6 values are wrong when the artifacts are executed.**

   **Evidence:**

   - `Exact.resolve` is classified `non-path` at [0023:1493](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1493), although it returns the same virtual absolute path as `path.resolve`, classified correctly at line 1488. I executed both and obtained identical cwd-derived absolute values.
   - `path.posix.*` is grouped with `win32` as `non-path` at line 1494, but `path.posix` is the runtime’s default path implementation at [path.js:473](/Users/ccheever/projects/ibex/src/builtins/path.js:473).
   - `fs.glob`/`globSync` is called `virtual-absolute` at line 1507. Both source and vendored artifacts return relative candidates for relative patterns, as implemented at [fs.js:2848](/Users/ccheever/projects/ibex/src/builtins/fs.js:2848) and [fs.js:2919](/Users/ccheever/projects/ibex/src/builtins/fs.js:2919).
   - Module fields are blanket-classified as virtual absolute at lines 1481–1482. Executing the real loader with builtin metadata produced `id="fs"`, `filename="fs"`, `path="fs"`, and `paths=["fs/node_modules"]`, following [module-loader.js:5253](/Users/ccheever/projects/ibex/src/engine/bootstrap/module-loader.js:5253).
   - `Exact.main`/`Bun.main` is called a synthetic source ID at line 1506, but it is exactly `process.argv[1] || ""` at [exact-global.js:1435](/Users/ccheever/projects/ibex/src/engine/bootstrap/exact-global.js:1435).
   - `process.execArgv` is asserted never to carry paths at line 1473, but arbitrary compatibility strings are appended without validation at [runtime.rs:942](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:942), including potentially path-valued flags.

   **Resolution criterion:** Correct the interim named rows and executable fixtures by mode, module kind, and return variant. Default/posix/Exact/Bun `resolve` should agree; glob strings should be relative to `cwd` where appropriate; builtin and synthetic module variants must be separate; `main` must either retain argv semantics or deliberately become source identity.

5. **Material — the owed disposition artifact does not have one consistent contract.**

   **Evidence:** Totality is first defined over `(surface, field-or-return-shape, alias, mode)` at [0023:1435](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1435), then the normative dataset uses module kind and return variant at [0023:1458](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1458). Section 8 drops mode, kind, and variant at [0023:1921](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1921); the ledger row restores mode but still omits kind, variant, the independent catalog, bidirectional validation, and duplicate-key failure at [0023:2000](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2000).

   **Resolution criterion:** State one canonical schema everywhere, including stable surface ID, field/shape, alias, mode, source kind, and return variant. Carry the independent catalog, reverse join, and duplicate-key gate explicitly into `OBL-DISPOSITION-DATASET`.

6. **Material — the package integrity walk is underspecified around symlinks and mixed ownership.**

   **Evidence:** Section 4.2 says the walk follows package-internal symlinks to their targets at [0023:1215](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1215), without defining whether the target must remain in the same authenticated binding. A package link to `/project/src/x` would otherwise place root-owned source in the global immutable set, contradicting first-party writability at [0023:1183](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1183). Links back toward `/project` also need visited-object and cycle rules. Mixed first-party/package hard links present the same ownership conflict.

   The ledger row at [0023:1986](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1986) also omits both round-8 completeness requirements: eager population from the integrity walk and rerunning the lexical guard after every symlink expansion.

   **Resolution criterion:** Define membership by authenticated defining principal or same package binding; pin outward-link and mixed-hard-link behavior, visited identities, cycles, and depth; carry the eager-walk and post-expansion invariants into the delegated obligation.

7. **Material — the open-write family is incomplete around durability and registry closure.**

   **Evidence:** The open list at [0023:1129](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1129) omits `fsync`, `fdatasync`, `FileHandle.sync()`/`.datasync()`, and `flush:true`. Open write routes perform those effects after writing bytes at [fs.js:1850](/Users/ccheever/projects/ibex/src/builtins/fs.js:1850), [fs.js:5041](/Users/ccheever/projects/ibex/src/builtins/fs.js:5041), and [fs.js:6162](/Users/ccheever/projects/ibex/src/builtins/fs.js:6162). Default-closing the durability leaf can therefore report denial after a partial mutation—the composite behavior §4.1 prohibits.

   Additionally, `OBL-OBJECT-BOUND-MUTATION` at [0023:1984](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1984) governs future reopening, but no obligation assigns the v1 registry migration that marks all currently effect-classified mutation aliases closed.

   **Resolution criterion:** Admit durability operations as exact-object writes with repeat checks, or reject `flush:true` before writing and pin standalone sync outcomes. Add a branch-sensitive mutation-closure registry obligation covering every alias while preserving the explicitly open family.

8. **Blocking — current source can manufacture an advertised target state instead of deriving it from authoritative machine data.**

   **Evidence:** The registry has no advertised target and only a macOS candidate at [policy-rules.json:787](/Users/ccheever/projects/ibex/capsec/registry/policy-rules.json:787). The production path reaches `build_default_armed_host` through [runtime.rs:1040](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1040) and [runtime.rs:1559](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1559), checks only the platform cfg at line 1663, then hardcodes `target_complete_and_advertised: true` at [runtime.rs:1981](/Users/ccheever/projects/ibex/src/bin/ibex/runtime.rs:1981). `ArmedSnapshot::load` trusts that boolean at [arming.rs:107](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:107), and `decision_context` hardcodes `CompleteAdvertised` again at [arming.rs:353](/Users/ccheever/projects/ibex/crates/capsec-semantics/src/arming.rs:353).

   I also ran the existing prebuilt binary; it refused for lack of a verified advertisement, but that refusal is not represented by the current source path, so the binary appears out of sync and does not discharge the source defect.

   **Resolution criterion:** Extend `OBL-TARGET-PROMOTE` beyond sibling prose reconciliation: remove the hardcoded states, derive the gate from authenticated machine data plus the completed target report, and require a clean-build test proving the candidate refuses.

9. **Material — the existence-oracle claim and AC name the wrong native surface.**

   **Evidence:** Section 7.2 and AC24a call the cited code `fs.open` at [0023:1784](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1784) and [0023:2220](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2220). The cited branch is actually `__exactReadFile`, beginning at [hermes_runtime_fs.cc:1984](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:1984), and it does open/stat before authorization. Actual `__exactFsOpen` begins at line 2675 and performs its requested-stage authorization at [hermes_runtime_fs.cc:2703](/Users/ccheever/projects/ibex/src/engine/hermes_runtime_fs.cc:2703), before its first lookup at line 2725.

   **Resolution criterion:** Rename the defect and acceptance test to the whole-file-read routes, then enumerate all adapters sharing that route. Do not claim the actual open route has this particular ordering defect unless another executable path demonstrates it.

10. **Material — `OBL-LEDGER-CHECK` conflates mechanically verifiable joins with semantic review.**

    **Evidence:** The prose requires a checker to verify an owner-side semantic claim against an entire document at [0023:1966](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1966), while its ledger row promises only IDs, markers, landed state, and stamps at [0023:2005](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:2005). LLP 0022 correctly observes that a mechanical tool can validate markers and fixtures but cannot establish arbitrary prose truth at [0022:933](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:933). The false `OBL-ERROR-ORDER` attestation demonstrates the distinction.

    **Resolution criterion:** Split this into a deterministic ledger/stamp/fixture checker and a provenance-tracked whole-document semantic attestation performed by a reviewer or formalized executable assertion.

11. **Minor/Non-blocking — editorial residue remains.**

    **Evidence:** Error-row references were not renumbered after removing alias collision: [0023:1760](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1760) calls rows 9 and 10 rows 10 and 11, while line 1798 calls policy denial row 7 instead of 6. The interim table visibly duplicates `module.paths`, module identity fields, and `Dirent` fields at lines 1481–1503. Line 1524 says argv’s only Node divergence is `argv[0]`, contradicting the explicitly stated stdin divergence at line 1520.

    **Resolution criterion:** Renumber the references, remove duplicate rows, and qualify the argv sentence. These do not independently block readiness.

## 4. **Cross-document findings**

- **LLP 0022 — Blocking:** Its watch/outside-mount statement contradicts LLP 0023’s closed-operation precedence, invalidating `OBL-ERROR-ORDER` as described above.

- **LLP 0022 ↔ LLP 0024 — Material:** LLP 0022 still normatively specifies one submission permit at [0022:680](/Users/ccheever/projects/ibex/llp/0022-repl-behavior-and-semantics.spec.md:680), while LLP 0024 specifies two affine capabilities at [0024:240](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:240). `OBL-TYPED-READ` correctly chooses the latter at [0023:1990](/Users/ccheever/projects/ibex/llp/0023-virtual-filesystem-namespace.spec.md:1990), but does not assign or stamp the required LLP 0022 edit.

- **LLP 0024 — Material:** OQ10 still says LLP 0023 leaves canonical display labeling open at [0024:2139](/Users/ccheever/projects/ibex/llp/0024-structured-evaluation-and-session.spec.md:2139). Consequently, `OBL-MODULE-IDENTITY`’s assertion that exactly two 0024-side edits remain is incomplete.

- **LLP 0025 — Minor/Non-blocking:** Its `OBL-HISTORY-LOCALITY` row still points to an older target digest at [0025:1106](/Users/ccheever/projects/ibex/llp/0025-terminal-session-ownership.spec.md:1106). The stamp convention correctly makes that attestation stale, while the actual requested acknowledgement is now present in LLP 0023. Refreshing the row is cleanup, not a substantive blocker.

- **LLP 0002 and LLP 0004 — Material:** Both still call metadata resolution body-read-free at [0002:175](/Users/ccheever/projects/ibex/llp/0002-host-embedding-abi.spec.md:175) and [0004:296](/Users/ccheever/projects/ibex/llp/0004-module-loading-and-builtins.explainer.md:296), contrary to the executed `read_to_string` route. `OBL-RESOLVE-GATE` should include these documentation owners.

- **Properly ledgered, therefore not independent blockers:** LLP 0021’s mkdir rollback contradiction, LLP 0013/0021’s stale “advertised macOS” prose, and LLP 0025’s history-locality seam are all explicitly identified with resolvable stamps. Their owed state is acceptable; the separate unledgered runtime hardcode in Concern 8 is not.

## 5. **Suggestions**

- Keep the architecture and make a focused reconciliation pass: correct the named §6 values, AC18a, error phases, and owner lists without reopening namespace design.

- Generate the output-shape catalog and disposition dataset together, then derive both fixtures and any human-readable table from that one artifact. Include negative tests for duplicate keys and missing aliases.

- Represent error precedence as a phase graph—adapter, base validation, requested path, each discovered target, final commit—rather than forcing base-staleness and commit-staleness into one flat row.

- Generate the open/closed mutation matrix from registry surface IDs and JS aliases, including composite options such as `flush:true`. That would make “closed at public entry” executable rather than prose-dependent.

- Bind built binaries to the source/registry revision used to construct their target-advertisement decision, so a stale binary cannot provide misleading evidence during review.

## 6. **Open questions**

1. When one physical object is both authenticated package source and first-party source through hard links, must arming refuse the graph, or does package immutability deliberately freeze every alias?

2. May an integrity walk follow a package symlink outside its defining binding, and if so, which principal owns the target object?

3. Should `Exact.main` remain a Bun-shaped argv alias, or become a stable source identity distinct from `process.argv[1]`?

4. Are `path.win32` results foreign-dialect paths requiring their own disposition, or intentionally opaque platform strings? Grouping them with `path.posix` is not tenable.

5. Are durability operations part of the v1 open-write authority, or should all `flush:true` and standalone synchronization surfaces close before any write?

6. What form of provenance will count as the whole-document semantic attestation that `OBL-LEDGER-CHECK` itself cannot compute?

## 7. **Readiness verdict**

The design is good and the remaining work is bounded, but direct normative contradictions, wrong executable surface values, an incomplete retained-identity order, and a source-level advertisement bypass remain unresolved.

VERDICT: NOT READY
### Orchestrator verification notes

Terminal round, both halves recorded (Fable NOT READY / 3 Material + 6 Minor; Codex
NOT READY / 4 Blocking + 6 Material + 1 Minor). This is a **ledger-and-stop**, not a
chase: the reviewers converge on substance, and the pattern is exactly the one the
loop has been driving toward — the remaining defects are prose failing to be a
machine-checked artifact, which is a *finding* (the disposition dataset must be
generated), not another design round.

**The two halves converge**, differing only in how they label the same items:
- Both flag the **identical fixable trio**: AC 18a still mandating the withdrawn
  shared hard-link `SourceLabel` (Codex B1 / Fable C1); §7.2 row-number references
  stale after the `ERR_IBEX_ALIAS_COLLISION` removal (Codex Minor 11 / Fable C2);
  the `Exact.resolve` disposition wrong/self-contradictory (Codex M4 / Fable C3).
- Both accept the **owed obligations as non-blockers**: Fable — "the owed obligations
  are properly stamped, owned, and accurate, and none is a blocker"; Codex — "Properly
  ledgered, therefore not independent blockers: LLP 0021's mkdir rollback, LLP 0013/
  0021's stale advertised-macOS prose, LLP 0025's history-locality seam."

**Confirmed (decisive claims, verified before accepting):**

- **Codex Blocking 3 — my own `OBL-ERROR-ORDER` "discharged-by-absence" was itself a
  false whole-document attestation.** LLP 0022:471 says habitual host paths produce
  outside-mount errors "from watches and every effectful filesystem operation," which
  IS order-relevant and is inconsistent with §4.1/§7.2 closing `watch` with `EPERM`
  *before* path work. So 0022 is not silent on the order; my round-7 claim that it
  "restates no total order" was wrong. This is the **third** instance of the
  completion-detector-can't-detect-its-own-incompleteness bug — and it landed in the
  row I wrote to *fix* the previous false attestation, which is precisely why Codex
  Material 10 (split `OBL-LEDGER-CHECK` into a mechanical checker + a reviewer-
  performed semantic attestation) is correct: a mechanical tool cannot establish
  arbitrary prose truth, and pretending it can is how the false attestation recurred.
- **Codex Blocking 8 — the source *manufactures* the advertised-target state.**
  `src/bin/ibex/runtime.rs:1981` hardcodes `target_complete_and_advertised: true` and
  `crates/capsec-semantics/src/arming.rs:361` hardcodes `TargetArmState::CompleteAdvertised`,
  while `policy-rules.json` has `advertisedTargets: []`. Real code defect; per the
  orchestration's routing it is ledgered as owed on `OBL-TARGET-PROMOTE` (remove the
  hardcode, derive the gate from authenticated machine data, clean-build refuse test)
  — a code/0021 obligation, not a 0023 mechanism defect. (The shipped binary in fact
  *refuses* for lack of a verified advertisement, so the binary is ahead of the source
  path — which is itself the argument for binding a binary to the revision it was
  built from, a suggestion I record.)
- **Codex Material 9 — my existence-oracle citation named the wrong surface.**
  `__exactFsOpen` (`hermes_runtime_fs.cc:2676`) authorizes at `~:2705` *before* its
  first `::open` at `~:2725`; the open-before-auth oracle is in `__exactReadFile`
  (`:1984`), the whole-file-read route. My §7.2/AC 24a cited `fs.open`. The "run the
  artifact" lesson biting my own citation. Fixed to name the read routes.
- **Codex Blocking 2 (retained-base staleness ordering). Confirmed.** A replaced cwd
  followed by `readFile("missing")` must reject the stale *base* before inspecting the
  child; base/referrer staleness is a **requested-stage precondition**, distinct from
  the commit-stage final-object staleness at table row 10. Fixed as a stated phase
  rule, not a table rewrite.
- **Codex Material 4 (§6 named values wrong on execution). Confirmed — and this is
  THE finding.** `path.posix.*` is the runtime default (`path.js:473`), not a foreign
  dialect; `Exact.resolve` returns a virtual-absolute path (so `non-path` is wrong);
  `fs.glob` returns relative candidates for relative patterns; builtin `module.*`
  fields return the id (`"fs"`); `Exact.main` is `process.argv[1]` (argv semantics,
  not synthetic-source-id). Per the orchestration: the clearly-wrong single-valued
  rows are corrected, and the mode/kind/variant-dependent split is **demoted to the
  generated `OBL-DISPOSITION-DATASET`** as normative — not hand-written into a table
  the next reviewer would falsify (the move already made for the table's totality).
- **Codex Material 5, 6, 7, 10 and Fable C4–C9. All confirmed** and reconciled with
  single-valued fixes or ledger carries (one canonical dataset key schema; integrity-
  walk membership by defining-principal so a package symlink out to root source does
  not freeze it; durability ops added to the open family; the ledger-check split;
  dedupe; glob dual-disposition; crossref/wording nits).

**Refuted / corrected:** nothing material. Where Codex labels an item Blocking that
the orchestration routes to the ledger (the source hardcode) or to the generated
dataset (the §6 values), the resolution is ledger-and-demote per the terminal-round
instruction, which Codex's own "properly ledgered → not a blocker" standard accepts.

**Disposition:** Terminal reconciliation applied at the revision below. **Status
remains `Draft`** — the round did not reach both-families-READY, which is the honest
outcome; the residual owed artifacts (the generated disposition catalog/dataset; the
source-derived target-advertisement gate; the model-checkable guard/projection pieces;
the two-capability `.load` credential edit on 0022) become implementation tickets,
which is the actual path to READY. No round 9.
