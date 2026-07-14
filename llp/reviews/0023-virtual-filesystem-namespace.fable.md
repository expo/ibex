# Reviews of LLP 0023 — Virtual Filesystem Namespace and Path Identity (Fable family)

Review artifacts for `llp/0023-virtual-filesystem-namespace.spec.md`, recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-12

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-12
- **Revision under review:** `0d55849a9f5e`
  (`shasum -a 256 llp/0023-virtual-filesystem-namespace.spec.md | cut -c1-12`)
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex review of the same revision, and no access to
  any prior LLP 0023 review artifact (none existed — this is round 1). Instructed
  not to read `llp/reviews/`.
- **Method:** subagent, round-1 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round1.md`). Brief supplied the
  target, the sibling corpus (0022/0024/0025) as normative context, the governing
  LLPs (0021/0013/0014/0004), a required code-verification list, the LLP 0005
  standard questions, and a fixed output structure ending in an explicit verdict
  line.

### Verbatim review

# Independent Design Review — LLP 0023: Virtual Filesystem Namespace and Path Identity (rev 0d55849a9f5e, round 1)

## 1. Overall assessment

This is a strong, unusually well-grounded spec that solves a real and verified problem with the right architecture. Every load-bearing claim in the Motivation checks out in code, end to end: armed `__exactGetCwd` returns `undefined` (`src/engine/hermes_runtime.cc:1653-1656`), the `process` facade falls back to `/` (`src/builtins/process.js:69-82`), `fs` eagerly joins relative paths against that facade producing `/README.md` (`src/builtins/fs.js:513-521, 570-602`), and the armed host infers meaning from string shape — `path.is_absolute()` plus a `std::env::current_dir()` join (`src/host/mod.rs:288-298`) — before prefix-matching host components against bindings (`crates/capsec-semantics/src/arming.rs:184-207`), yielding exactly the generic "Permission denied" the doc describes (`src/host/mod.rs:1449`). The three-way conflation diagnosis is correct, and the WASI-preopen-style fix is the standard, defensible move.

The two central intellectual contributions — (a) splitting caller-relative *authorization* identity from retained-object *module* identity, and (b) carrying identity instead of inferring it from text — are both correct and both anchored in existing mechanism rather than invented: the dual package/root mapping the spec describes is literally what `logical_path_for_host_components` already does (`arming.rs:532-585` proves the same host path maps to `LogicalRoot::Package` for the owner and `LogicalRoot::Project` for root), and the string-keyed module cache it retires is real (`src/engine/bootstrap/module-loader.js:5253-5262`). The headline defaults are mostly right (see §Strengths). What keeps this from READY is a set of material round-1 gaps, all fixable without redesign: a missing treatment of case/normalization aliasing on the only advertised target, one acceptance criterion that is unimplementable as written (`%2E%2E`), unpinned JS-visible error codes for the new error classes, unspecified retention semantics for object-keyed identity, an occurrence-mapping ambiguity under deputy intersection, a portability defect in the symlink-creation rule, and one genuine cross-document conflict with LLP 0022.

## 2. Strengths

- **Verified motivation.** Every mechanism claim in §Motivation is observable at a specific line (citations above, plus `process.js:41-54` for the eager join). A spec whose problem statement survives adversarial code-checking this cleanly is rare.
- **§2's authorization/module identity split** preempts a real double-instantiation bug (broken singletons and `instanceof` across the root/package boundary) and is faithful to LLP 0013's one-principal-one-compartment, shared-intrinsics model (0013:219-221, 448). The insistence that "passing a string is not delegation" matches LLP 0021's handle model precisely.
- **§1's refusal to mount `home`** is the correct security call, and the characterization is accurate: the `home` binding is the machine-global cache `~/Library/Caches/Ibex` (`src/bin/ibex/runtime.rs:1918-1945, 3445-3460`), and mounting it would be a cross-project cache-poisoning channel. The "adding a mount is a security decision" framing is exactly right.
- **§2's arming-time refusal of out-of-project package roots** is honest fail-loud scoping: better a named diagnostic than an undefined `__dirname`. The deferral (OQ5) correctly identifies the real constraint — `LogicalPath` has no display prefix today (`crates/capsec-semantics/src/model.rs:575-590`).
- **§4's staged symlink discovery** honestly corrects the unimplementable "before any host access" to "before disclosure or mutation of the target," and matches the staging discipline WP5 already implements (LLP 0021 WP5 status: retained parents, `O_NOFOLLOW` finals, commit-stage identity checks).
- **§6's alias obsession is vindicated by the code**: the `import.meta` aliases exist exactly as listed (`module-loader.js:3553-3568` — `.path`, `.filename`, `.file`, `.dirname`, `.dir`), `__exactModuleResolve` really does serialize host `path`/`pkgRoot` (`src/host/abi.rs:2168-2187`), `__exactRealpath` is one identifier away on the global (`hermes_runtime_fs.cc:2551-2591`, used at `fs.js:3084`), and I found a *second*, laxer `fileURLToPath` on the Exact global (`exact-global.js:923-926`, no `%2F` refusal) — precisely the class of drift a hand-written list would miss.
- **§5's facade analysis is verified**: `fs` and `node:path` consult the mutable `process.cwd` at call time today (`fs.js:542-568`; `path.js:8, 62`), and `process.cwd`/`chdir` are plain writable assignments (`process.js:475-476`). Sealed-native-identity resolution is the right fix, and the registry quote gating the reopening is verbatim accurate (`capsec/registry/legacy-capability-reconciliation.json:112`).
- **The universal `process.cwd()` read as a recorded information grant** (§5) is good decision hygiene: named, bounded (names within the namespace, never host paths), fixture-backed, and closeable.
- **Acceptance criteria are concrete and adversarial** (AC8's deputy/timer/promise chdir matrix; AC15's red-team-by-name; AC17's vendored-parity gate — the vendored copies exist and are the hermetic source of truth).
- **§3's POSIX-everywhere decision** formalizes what the code already does (`path.js:477` exports posix unconditionally), and `%2F` refusal matches the existing implementation (`url.js:218-230`).

## 3. Concerns

1. **Case-insensitivity and Unicode-normalization aliasing is unaddressed for runtime path identity.** Severity: **Material** (safety, on the only advertised target). Evidence: §2/§3 define identity over byte-lexical "normalized components"; host mapping is byte prefix-matching (`arming.rs:190`, `host/mod.rs:299`). macOS default volumes alias case and NFC/NFD forms, so `/project/Secrets` and `/project/secrets` are two authorization identities naming one platform object. A path-keyed *denial* (LLP 0021 precedence stratum 6) or path-tree ceiling can be sidestepped by a case-variant spelling that fails the lexical match while the host opens the denied object; retained-object commit checks verify the object matches the *requested* resolution, which it does. LLP 0021 WP0 has the machinery ("an Apple bound-volume adapter supplies its actual case/normalization alias key") but only at arming. Resolution criterion: §3 gains a normative per-volume alias-canonicalization step for authorization identity (reusing the WP0 adapter), or an explicit rule that negative rows are object-keyed on aliasing volumes; AC fixture probing a case-variant spelling against a path-keyed denial.

2. **The `%2E%2E` refusal is unimplementable as specified and mis-cites Node.** Severity: **Material** (correctness of a normative rule and its AC). Evidence: §3 and AC4 say dot segments in file URLs are "refused, not decoded — matching Node's `ERR_INVALID_FILE_URL_PATH`." WHATWG URL parsing collapses `%2e`/`%2e%2e` as dot segments *during parse*, before any pathname exists — Ibex's own parser does this (`url.js:1348-1355, 1666-1672`) — and Node refuses only `%2F`/`%5C` (matched by `url.js:218-230`). For a `URL`-object input the information needed to refuse is already gone. The collapse is also harmless: it coincides with §3's own lexical normalization. Resolution criterion: narrow the rule and AC4 to encoded separators, and document that percent-encoded dot segments are collapsed at URL parse, equivalently to §3 normalization.

3. **JS-visible `code`/`errno` values for the new error classes are unpinned.** Severity: **Material** (completeness — this is exactly what a path spec must pin). Evidence: §7 defines a host-side reason enum; §5 pins only the synthetic-node case ("`EINVAL`-class"). Outside-mount, stale-cwd, and malformed-input reach JavaScript as errors whose `code` (the thing real Node programs branch on: `ENOENT` vs `EACCES` vs a new code) is nowhere stated; AC3/AC16 demand distinguishability without saying at which surface. Resolution criterion: a normative table mapping each reason to its Node-visible `code`/`errno`/`syscall`/message shape (novel codes allowed but named), referenced by AC16.

4. **Module-identity retention semantics and cost are unspecified, and "exactly as in Node" overclaims.** Severity: **Material**. Evidence: §2 keys module identity on "(runtime, retained object identity)". Unstated: whether a cache entry holds a live descriptor for the session (fd exhaustion at real graph scale; macOS default `RLIMIT_NOFILE` is small) or a verified `(volume, file)` record (inode-reuse aliasing after delete+recreate). Also, Node's behavior is not one thing: CJS realpath-keys (unifying symlinks, splitting hard links) while ESM preserves symlinked specifiers (splitting them); object keying unifies hard links and symlinked ESM paths — a defensible improvement, but a divergence, not "exactly as in Node." Resolution criterion: specify the retention mechanism, lifecycle, and resource bound; replace the Node claim with the precise divergence list; add a hard-link case to AC11.

5. **Which principal's binding keys the occurrence under a multi-principal constrained set is ambiguous.** Severity: **Material** (coherence with LLP 0021). Evidence: §2 says the host maps a path to "the most specific binding owned by the *calling* principal," but LLP 0021 decisions intersect a deduplicated constrained set (deputy, schedule-time owner), the occurrence's logical path is computed once for the actor today (`host/mod.rs:329-334`), and LLP 0021's containment rule ("authority containing a package logical root also requires the same package-root binding owner") means a package-root-keyed occurrence can never be contained by root's project-tree floor — only ambient root (stratum 14) saves the root dimension. Whether deputy intersection passes therefore *depends* on whose mapping the occurrence carries, and the spec never says. Resolution criterion: §2 states the occurrence resource is derived from the effect owner/acting principal's mapping and how each other constrained dimension evaluates, with a deputy fixture added to AC12.

6. **Storing host-absolute bytes in Ibex-created symlinks breaks the portability story and leaks host-prefix length.** Severity: **Material** (decision quality). Evidence: §4 creation rule stores "the host path that the mount translation yields"; §Consequences promises "stable paths across machines, worktrees, containers." Moving or cloning the project dangles every Ibex-created absolute link and makes it *foreign to its own runtime* (its `readlink` then refuses it); committing one records the developer's host path in the repository; and `lstat` on the link (a permitted metadata operation) discloses the host-root byte length via `st_size`. A link-parent-relative encoding is equally kernel-resolvable, move-stable, and host-byte-free. Resolution criterion: either switch in-namespace absolute targets to relative storage (documenting the readlink absolute/relative fidelity note), or document the staleness/disclosure consequences explicitly and add a moved-project fixture.

7. **The `require.cache` observables row conflicts with LLP 0022.** Severity: **Material** (cross-document; also listed in §4 below). Evidence: §6 table gives "`require.resolve`, `require.cache` keys, `module.paths` — virtual spellings," presented as an armed value; LLP 0022 §1 closes `require.cache` outright ("loader cache state stays closed — if it is ever exposed, it is as a principal-filtered immutable facade"). Resolution criterion: mark the row conditional ("closed per LLP 0022 §1; keys are virtual spellings in any facade ever exposed"), or amend 0022.

8. **The generated-observables-table premise assumes registry facets that do not exist.** Severity: **Material** (feasibility of the central enforcement claim). Evidence: §6 says the table is "a projection of the surface registry joined to every path-bearing field **and alias**." The WP1 inventory enumerates surfaces and export/prototype shapes (LLP 0021 WP1), not return-value fields (`os.userInfo().homedir`) and not a mandatory path-bearing disposition per field — so the join's left side is a semantic judgment someone must author, and an unmarked new field escapes silently, the exact failure §6 claims to prevent. The second `fileURLToPath` on the Exact global (`exact-global.js:923-926`) shows how real this is. Resolution criterion: §8 names the registry-schema obligation (mandatory path-bearing yes/no on every surface, field, and return shape, with validation failing on absence), and AC14 cites it.

9. **"One registry row" for the stricter cwd profile is overconfident.** Severity: **Minor/Non-blocking** (it concerns a recorded escape hatch, not v1 behavior). Evidence: §5 claims a profile can close the universal cwd read "without changing anything else"; but `path.resolve("")`/`path.resolve("x")` return the session cwd spelling by §5's own sealed-identity rule, so a closure that touches only `process.cwd()` leaks through `node:path`, `error.path`, and relative-resolution observables — or else splits a principal's view from its resolution base. Resolution criterion: reword §5/OQ6 to "view = resolution base, per principal" under any closing profile.

10. **Renamed-cwd divergence from POSIX/Node is undocumented, and stale-cwd recovery is unspecified.** Severity: **Minor/Non-blocking**. Evidence: §5's stale rule means an in-project rename of the cwd breaks all later relative I/O (POSIX processes keep working via the object; Node's `getcwd` reports the new path). Spelling-anchored cwd is the right containment call (an object-anchored cwd could be `mv`-ed outside the binding and `openat` would silently escape), but the divergence belongs in §Consequences, and whether a later successful `chdir` clears staleness is unstated. Resolution criterion: add both sentences.

11. **Several observables rows name their value by reference rather than pinning it.** Severity: **Minor/Non-blocking**. Evidence: "synthetic runtime identity" (`execPath`/`argv0`), "the entry's synthetic identity" for `argv[1]` (which does not obviously cover ordinary file execution — is it the virtual spelling?), and `os.tmpdir()`/`homedir()` "the registry's closed-surface behavior" (returning `undefined`? throwing?). AC14 asserts "every row," so the values must exist somewhere normative. Resolution criterion: pin the runtime-identity string and the closed-surface value shape, or cite the artifact that pins them; fix the `__filename` row to "absent where there is no *file-backed* module" (see §4, 0022's `ibex:stdin`).

12. **Windows-reserved component names.** Severity: **Minor/Non-blocking** (Windows is unadvertised). §3's grammar admits `CON`, trailing dots/spaces; WP0 rejects these for *authored* rows at arming but runtime-requested paths on a future Windows host would reach device semantics. Resolution criterion: one sentence deferring component restrictions to Windows target advertisement, mirroring WP0.

13. **The pnpm example is inaccurate.** Severity: **Minor/Non-blocking**. Default pnpm hard-links store content into in-project `node_modules/.pnpm` with in-project symlinks — v1 *admits* it; the refused layouts are out-of-project stores, hoisted workspaces, and siblings. Hard-linked store content also shares platform-object identity with the global store (harmless per-runtime, but worth a line given object-keyed identity). Resolution criterion: correct the example in §2/AC13.

14. **"Decision caches key on the authorization identity" reads as replacing LLP 0021's frozen cache key.** Severity: **Minor/Non-blocking**. LLP 0021 enumerates the cache key (action, canonical resource bytes, constrained principal set, effect owner, stage, digests, generations); §2's tuple is the resource/owner component, not the whole key. Resolution criterion: one aligning sentence.

## 4. Cross-document findings

- **Conflict (Material, = Concern 7):** 0023 §6's `require.cache` row vs 0022 §1's closure of `require.cache` as `runtime:inspect`. One of them must yield; per 0022's own governance rule ("the mechanism document governs its own layer"), 0023 should carry the conditional wording.
- **Duplication with drift risk:** the module-identity rule is normative in both 0023 §2 and 0024 §7, and 0023 AC11 ≈ 0024 AC13 nearly verbatim (same fixture: root `import "foo/util.js"` + package `require("./util")` → one instance; chdir-between-imports; instanceof). 0024 cites 0023 §2 as the source, which is correct, but 0024 §7 restates enough normative text to drift; recommend shrinking 0024's restatement to the citation plus the `.load`-no-cache-entry rule it owns.
- **Wording seam (Minor, = Concern 11):** 0022 §3 pins `ibex:stdin` as a *module* with no `__filename`/`__dirname`; 0023 §6's row says `__filename` is "absent where there is no module," which doesn't cover module-with-no-file. Harmless today, but the generated table will need the precise predicate.
- **Clean seams verified:** 0022 §2's project-binding installation → 0023 §1; 0022 §4's cwd/chdir/outside-mount consequences → 0023 §3/§5 (identical attribution language: complete constrained-principal set, `NoUser` denies — matches 0025 §8's exit rule); 0024 §1's "virtual referrer" and §2's `file:///project/…` identities → 0023 §3; 0024's reserved `repl:`/`ibex:` schemes do not collide with 0023's namespace; 0025 §9's history keying on "authenticated root's object identity" uses 0023's retained-identity concept consistently; 0023 §6's citation of "LLP 0022 §Affordance parity" resolves (0022 §7). No dangling dependency found in either direction beyond the items above.
- **Governing-doc consistency:** §5's registry quote is verbatim (`legacy-capability-reconciliation.json:106-112`); the no-effect-branch concept exists in LLP 0021 WP1 ("explicit no-effect branches"); "LLP 0021 permits a package binding to sit anywhere on the host" is accurate (WP0 host-bound absolute bindings; no containment invariant) — which means 0023's arming refusal is a *new* armed-snapshot invariant that LLP 0021's invariant list should eventually absorb (worth a Related-note, not a conflict). The typed-ABI demand of §7 is feasible: precedent exists in the typed staged ingress (`ex_host_authorize_typed_fs_stack`, `abi.rs:975`) alongside the C-string legacy fs ABI it will replace (`abi.rs:2283-2859`).

## 5. Suggestions

- Adopt link-parent-relative storage for in-namespace absolute symlink targets (Concern 6) — it strictly dominates on portability, artifact hygiene, and disclosure, at the cost of one documented readlink fidelity note.
- Reuse 0024's reserved `ibex:` scheme for the synthetic runtime identity (`process.execPath`/`argv0`, e.g. `ibex:runtime`), so the resolver's reserved-scheme guard automatically protects the observables table's synthetic values from ever being importable or file-resolvable.
- Give the mount table schema per-mount flags now (read-only, metadata-only, symlink-follow policy, lifecycle) even with one mount, so `/tmp`/`/state` (OQ2 — note `LogicalRoot::Tmp` already exists in the model, `model.rs:579`) become additive rows rather than new design.
- Make the outside-mount error's message enumerate the mount table — parity-safe by construction (§3 makes the table publicly listable) and it converts the most common confusion (habitual host spellings) into self-explaining diagnostics; 0022 §4's UX goal gets this for free.
- For OQ1, commit now to the *shape* of any future host-path debugging authority: a typed, root-only, terminal-classified API taking a handle (never a string, never `process.cwd()`), so nobody designs it as a string surface later.
- Add two fixtures beyond the ACs: a case-variant denial probe on an APFS case-insensitive volume (Concern 1) and a moved-project symlink round-trip (Concern 6).
- State explicitly that the `fs.js`/`process.js` Windows-drive branches (`fs.js:574-599`, `process.js:43-45`) are dead in armed mode and covered by the outside-mount rule, so nobody "fixes" them into the virtual namespace.

## 6. Open questions

1. What is retained, and for how long, behind "retained platform object" in the module cache and cwd — a held descriptor (fd budget?) or a verified identity record (inode-reuse window?) — and what is the per-session resource bound? (Concern 4.)
2. How does per-volume alias canonicalization (case, Unicode form) enter authorization identity on Apple targets — request-time adapter canonicalization, object-keyed negative rows, or both? (Concern 1.)
3. What are the exact JS-visible `code` values for outside-mount, stale-cwd, synthetic-node, and malformed-input — Node codes reused or new codes — and do probes like `fs.existsSync("/etc/passwd")` return `false` or throw? (Concern 3.)
4. Under deputy intersection, whose binding keys the occurrence, and is ambient root the intended reason root-dimension containment passes for package-root-keyed occurrences? (Concern 5.)
5. Under a stricter profile closing the cwd read, does the closed view also become the resolution base for that principal (view = base), and which other spelling-returning routes (path.resolve, error.path, module.paths) does the closure cover? (Concern 9 / OQ6.)
6. Should LLP 0021's armed-snapshot invariant list absorb the new "package bindings contained within the project binding" arming invariant, so the two documents cannot drift on what arming refuses?
7. For registry generation: what schema change makes "path-bearing" a mandatory, validated disposition at field/return-shape granularity, and who owns it? (Concern 8.)

## 7. Readiness verdict

The architecture is right, the defaults are well-argued (single mount: right; identity split: right; lexical `..`: right and honestly scoped; staged discovery: right; arming refusal: right; `%2F` refusal: right; universal cwd read as recorded grant: right; non-UTF-8 refusal: acceptable v1 narrowing), and the code-facing claims are accurate to a degree that materially de-risks implementation. But there are unresolved material concerns: one safety-relevant identity gap on the advertised target (case/normalization aliasing), one normative rule and AC that cannot be implemented as written (`%2E%2E`), unpinned error-class surfaces, unspecified retention semantics, an occurrence-mapping ambiguity against LLP 0021, a portability defect in symlink creation, one genuine cross-document conflict with 0022, and a feasibility gap in the generated-table premise.

VERDICT: NOT READY

### Orchestrator verification notes

I independently re-checked every decisive factual claim against the repository at
revision `0d55849a9f5e`. Findings:

**Confirmed (spot-checked directly):**

- `src/engine/hermes_runtime.cc:1653-1656` — `__exactGetCwd` returns
  `Value::undefined()` when `ex_host_is_armed() == 1`. Confirmed.
- `src/builtins/process.js:69-82` — `cwd()` falls back to `"/"`. Confirmed.
- `src/host/mod.rs:288-298` — `typed_logical_path` branches on
  `path.is_absolute()` and otherwise joins `std::env::current_dir()`. Confirmed;
  this is the string-shape inference the doc retires.
- `crates/capsec-semantics/src/arming.rs:184-207` — binding selection by
  `host_components.starts_with(&binding.host_path.components)`, package bindings
  filtered to `binding.owner.as_ref() == Some(principal)`. Confirmed, including
  the reviewer's point that the same host path maps to `Package` for the owner
  and `Project` for root.
- `src/host/mod.rs:1449` — `anyhow!("Permission denied for {}", path.display())`.
  Confirmed: the generic error the Motivation describes.
- `src/engine/bootstrap/module-loader.js:3553-3568` — the `import.meta` alias
  table exists with exactly `.url`, `.path`, `.filename`, `.file`, `.dirname`,
  `.dir`, `.main`, `.require`. Confirmed.
- `src/host/abi.rs:2168-2187` — `module_meta_json` serializes host `path` and
  `pkgRoot` via `to_string_lossy()`. Confirmed.
- `src/engine/bootstrap/exact-global.js:922-926` — a **second** `fileURLToPath`
  on the `Exact` global doing bare `decodeURIComponent(u.pathname)` with **no**
  `%2F` refusal. Confirmed. This is the strongest single piece of evidence for
  §6's generated-table premise, and simultaneously for Concern 8's point that the
  premise is not satisfiable from today's registry.
- `src/engine/bootstrap/module-loader.js:5253-5262` — user modules cached on
  `record.id` (a path string); builtins special-cased via `builtinCacheKeyFor`.
  Confirmed. (Note this *also* shows the current cache already needs a
  non-path key for builtins — see Codex Blocking 4.)
- `src/builtins/url.js:1348-1355, 1666-1672` — `_isSingleDotPathSegment` /
  `_isDoubleDotPathSegment` treat `%2e`, `.%2e`, `%2e.`, `%2e%2e` as dot segments
  and collapse them during URL path normalization; `url.js:218-230`
  (`fileURLToPath`) refuses only `%2F`/`%5C` with `ERR_INVALID_FILE_URL_PATH`.
  **Concern 2 confirmed** — and independently confirmed by Codex Blocking 6.
  The doc's `%2E%2E` rule is not implementable for a `URL` object and mis-cites
  Node.
- `crates/capsec-semantics/src/model.rs:575-581` — `LogicalRoot` is
  `{Project, Package, Home, Tmp, Absolute}`; `LogicalPath` is
  `{root, components, host_bound}` with **no display prefix**. Confirmed, both
  for OQ5's constraint and for the reviewer's `LogicalRoot::Tmp` observation.
- `crates/capsec-semantics/src/cache.rs:49-61` — `DecisionCacheKey` enumerates
  action, resource canonical bytes, principal-set bytes, effect-owner bytes,
  stage, four digests, generations, positive-authority context. **Concern 14
  confirmed**: §2's tuple is the resource/owner component, not the whole key.
- `capsec/registry/legacy-capability-reconciliation.json:106-112` — the quoted
  reconciliation condition is verbatim accurate. Confirmed.
- `src/builtins/path.js:59-71` — `resolve()` falls back to `_cwd()`, which reads
  `process.cwd()` dynamically. **Concern 9 confirmed**, and I found the sharper
  form: `capsec/registry/coverage-edges.json` classifies
  `export:node_path:resolve` and `export:node_path:relative` as
  `"classification": "non-capability"` with `rationaleId: "pure-in-memory-compute"`
  — a registry **misclassification** that the doc's own §6 sentence ("Pure lexical
  functions in `node:path` … take no capability decision") endorses. This upgrades
  Concern 9 in my judgment from Minor to Material.
- No `alias_key`/`aliasKey` implementation exists anywhere under `crates/`,
  `src/`, or `capsec/`. LLP 0021:270-273 specifies the Apple alias key only at
  arming. **Concern 1 confirmed** as a genuine runtime gap.
- `crates/capsec-semantics/src/model.rs:481-484` — `PathComponent` is
  `{Utf8(String), Base64Url(Vec<u8>)}`, so the typed vocabulary can indeed
  represent non-UTF-8 components while the JS adapter declines to. The doc's
  framing is accurate.

**Refuted / corrected:**

- Nothing in this review was refuted. The one imprecision I would note is
  Concern 11's characterization of `import.meta.file`: it is not merely
  "unpinned," it is a **basename** (`module-loader.js:3563` —
  `__filename.split('/').pop()`), so the §6 row that lumps `.file` with the other
  aliases under "virtual spellings" is affirmatively *wrong*, not just vague.
  Codex Material 11 makes the same point. I have treated this as a factual
  correction to the doc rather than a reviewer error.

**Disposition:** Accepted, in whole or in part, on every Material concern
(1, 2, 3, 4, 5, 6, 7, 8) and on Minor concerns 9 (upgraded to Material on the
`non-capability` finding above), 10, 11, 12, 13, 14. Concern 9's resolution
("view = resolution base") is adopted as a normative rule rather than a wording
change. See the round-1 reconciliation summary in the Codex artifact's
disposition notes for the full list of edits, which address both reviews jointly.
</content>
</invoke>

---

## Round 2 — 2026-07-12

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden by the orchestrator. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-12
- **Revision under review:** `832eb25f0327`
- **Redacted:** No. The reviewer read the repository and document directly under
  the user's own environment, authorized by the human invocation of
  `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex review of the same revision, and no access to any
  prior LLP 0023 review artifact — the round-1 artifacts were moved out of
  `llp/reviews/` into a scratch stash for the duration of the round. Instructed not
  to read `llp/reviews/`.
- **Method:** subagent, round-2 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round2.md`) — the same brief given
  to the Codex reviewer. The brief told the reviewer the document had been revised
  after a prior round, named the new/rewritten sections, and instructed it to judge
  the current revision on its own merits and to check the document's own file:line
  citations.

### Verbatim review

# Review: LLP 0023 — Virtual Filesystem Namespace and Path Identity (rev. 832eb25f0327, round 2)

## 1. Overall assessment

This is a strong, unusually honest revision of a genuinely hard spec. The three-way conflation it names (host cwd / armed project binding / JS-visible cwd) is real and verified end-to-end in the code: `src/engine/hermes_runtime.cc:1654-1656` returns `undefined` for armed `__exactGetCwd`, `src/builtins/process.js:69-79` falls back to `/`, `src/builtins/fs.js:568-570` resolves `README.md` to host `/README.md`, `crates/capsec-semantics/src/arming.rs:206` refuses it as unbindable, and `src/host/mod.rs:1449` reports the generic "Permission denied". The staged identity (§2.1) matches the shipped CapSec model exactly (`model.rs:1273-1290`, `cache.rs:48-61`), the module-identity algebra (§2.3) solves two real problems (cross-boundary double instantiation; hard-link compartment collapse) with a stated Node divergence, and §5.1's reversal of the previous draft's false "changes no other principal's resolution" claim is argued rather than buried. The citation record is remarkably accurate: of the ~35 file:line citations I checked, none was false; one is off by a few lines (`hermes_runtime_fs.cc:541` vs. ~545 for the "Permission denied" collapse), which is within tolerance.

It is not yet ready. Four material problems remain: (1) the symlink relative-target rule is stated in a form that is unsound when the link's parent path traverses a symlink — the very invariant §4 exists to protect; (2) the project-root discovery rule's marker precedence is ambiguous, and its natural (nearest-first) reading forces §1.2's arming refusal on ordinary monorepos, recreating the failure mode §1.1 was written to fix; (3) the output-disposition dataset's closed set has no "not-path-bearing" member, so the build check the whole §6 mechanism rests on is undecidable as specified; and (4) the runtime/session handle is a semver-major change to LLP 0002's ABI contract that the document never assigns — and, unlike both siblings, 0023 has no delegated-obligations ledger at all despite placing obligations on 0021, 0014, 0002, and 0022. There is also a live contradiction with LLP 0024 over module identity that the corpus's own precedence rule declares an invalid state.

## 2. Strengths

- **Staged identity is the shipped model, not an invention (§2.1).** `OccurrenceResource::PathOccurrence` carries `requested: LogicalPath` with optional `parent_object`/`final_object` (`crates/capsec-semantics/src/model.rs:1273-1290`), and the decision-cache key is left untouched and correctly described (`cache.rs:48-61`: action, resource bytes, principal set, effect owner, stage, four digests, generations, positive-authority context). Adopting the existing staging instead of a universal tuple is the right correction, and the create-path argument (the target does not exist at authorization) is airtight.
- **Module identity keyed on the defining principal (§2.3)** is the best design decision in the document. It preserves LLP 0024 §7's cross-boundary instance sharing while containing the pnpm hard-link coincidence that would otherwise violate LLP 0013's one-compartment-per-package invariant (`0013 line 448: "A package is one principal with one compartment"`). The Node divergence table (unify symlinks and same-principal hard links; split cross-principal hard links) is stated rather than glossed. The motivating defect is real: the cache keys on `full_path.to_string_lossy()` today (`src/module_loader/mod.rs:806`).
- **§5.1's self-correction** — "This must be said plainly, because the previous draft said the opposite" — and its precise re-reading of the reconciliation condition. The quote is verbatim (`capsec/registry/legacy-capability-reconciliation.json:112`), `process:cwd` is indeed `deny-only` / `shared-process-mutation` (`capability-definitions.json` definitions[19]), and `decision.rs:440-448` does hard-deny non-authorable lifecycle at `LifecycleAndTargetClosure` before any positive stratum, so §8's "a deny-only action cannot be opened by adding a grant" is correct against the code.
- **§2.2's occurrence-keying decision** ("derived from the effect owner's mapping, not from each member of the constrained set") explicitly names a fork that is decidable either way and would silently change which grants apply — exactly the kind of thing a spec must pin. It is consistent with `arming.rs:184-197`, where binding lookup filters package roots by owner.
- **Creation-time symlink containment restored (§4).** The engine precedent is exactly as cited: `hermes_runtime_fs.cc:3281-3300` gates the target, resolving relative targets against the link's directory (ENG-22682). The argument that follow-time-only checking regresses a persistent artifact an external tool will traverse is correct, and `openArmedLinkTarget` exists at `hermes_runtime_fs.cc:570` for the retained-link-object primitive.
- **The %2E%2E correction (§3)** is verified: `src/builtins/url.js:1348-1355` and `1662-1672` collapse encoded dot segments at parse, so post-parse refusal is unimplementable; `%2F`/`%5C` refusal exists at `url.js:218-230`; and the second, refusal-free `fileURLToPath` on the Exact global is exactly where cited (`exact-global.js:922-926`) — a genuinely good catch that justifies the generated-table approach.
- **The error table and staged-precedence idea (§7.2)** replace a demonstrably broken pipeline: `abi.rs:967-975` returns 1/0/-1, the engine collapses to `"Permission denied"` (`hermes_runtime_fs.cc:545`), and `fs.js:764-769` re-derives codes by parsing message strings. The `readFile` path really does open parent and target before its first typed decision (`hermes_runtime_fs.cc:2010-2030`), making the nonconformance example concrete.
- **§7.1's singleton finding is correct and load-bearing**: `static HOST: OnceLock<RwLock<Host>>` (`abi.rs:130`), `install_host` replaces it (`abi.rs:214-218`), and `ex_host_authorize_typed_fs_stack` (`abi.rs:975`) carries no runtime identity — per-runtime cwd is genuinely unimplementable through the current ABI, so AC9's "fails against a process-global Host" is honest.
- **§1.1/§1.2 name the right defect**: `runtime.rs:1674-1677` really does mount `canonicalize(entry).parent()`, and `runtime.rs:1824-1830` really does guess `node_modules/<name>` and silently skip. `import.meta.file` really is the basename (`module-loader.js:3563`); builtins really are specially cache-keyed (`module-loader.js:5254-5258`); sync/async `readlink` really disagree on encoding (`fs.js:5731` ignores options; the async path applies `_encodeFsPathResult` at `fs.js:5750-5751`).

## 3. Concerns

**C1. (Material — security soundness) §4's relative-target rule is unsound as stated when the link's parent path traverses a symlink.** Evidence: §4 says "Stored bytes are always relative to the link's parent" and concludes "Because creation refuses out-of-mount targets, stored relative bytes can never climb above the project root." If "the link's parent" means the caller's *virtual spelling* of the parent, the inference fails: create `l` at `/project/sub/l` targeting `/project/a`, where `sub` is itself an in-project symlink to `/project` (or any directory at a different depth). The virtual parent `/project/sub` yields stored bytes `../a`; the kernel resolves those against the *physical* parent, which in the degenerate case is `/project` itself — so `../a` resolves to a sibling *of the project root*, outside every mount, despite creation-time containment having passed. The engine precedent (`hermes_runtime_fs.cc:3287-3295`) explicitly resolves "exactly as the kernel will," but §3's lexical discipline is not kernel resolution, so the document's own normalization can diverge from what the created artifact means. Resolution criterion: pin that the relative encoding and its containment check are computed against the canonical namespace path of the *retained, post-discovery parent object* (the DiscoveredPath's parent), not the requested spelling; state that a mismatch between the requested parent spelling and the discovered parent identity re-derives depth from the latter; add an AC7/AC8 fixture with a symlinked parent directory.

**C2. (Material — decision quality/ambiguity) §1.1's marker precedence is ambiguous, and the nearest-first reading recreates the refusal §1.1 exists to fix, for monorepos.** Evidence: step 2 says "nearest ancestor containing a project marker, checking each directory before its parent," and separately gives a precedence order "workspace root declaration, a lockfile, then package.json." Under nearest-first, precedence only breaks ties within one directory — where a workspace declaration virtually always coexists with `package.json`, making the precedence list nearly vacuous. Consequence: `ibex packages/foo/src/app.js` in a workspace selects `packages/foo` (its `package.json` is the nearest marker), the hoisted root `node_modules` (or pnpm's root `.pnpm` store that per-package symlinks point into) lies outside `/project`, and §1.2 refuses arming — i.e., "essentially every real" monorepo fails, the same class of failure §1.1's motivation paragraph condemns for `src/`-entry projects. If instead precedence is meant to operate *across* ancestors (ascend to the outermost workspace-root declaration containing the origin), standard monorepos arm under a repo-root `/project` with no OQ5 machinery — but then §1.2's "workspace root hoisted above the project" refusal case largely evaporates and the text should say so. AC3 tests neither workspace case. Resolution criterion: state unambiguously whether precedence is within-directory tie-breaking or cross-ancestor override; state the intended outcome for an in-repo workspace (arming refusal vs. workspace-root mount) with rationale; add an acceptance criterion for it.

**C3. (Material — mechanism completeness) The output-disposition dataset cannot deliver its own build check because the closed set has no "not path-bearing" member.** Evidence: §6 fixes the closed set as `virtual-absolute, virtual-relative, virtual-basename, synthetic-source-id, absent, closed, refused`; §8 says validation "fails the build when any path-bearing surface, field, or alias lacks a disposition." A checker cannot know that an *unmarked* field (`process.pid`, `os.cpus()[0].model`) is or is not path-bearing — that judgment is exactly what the dataset must record. Without a `non-path` disposition and a totality rule over `(surface, field, alias)`, "an unmarked new field would escape silently" remains true *of the dataset itself*, which is the failure §6 says it exists to prevent. Resolution criterion: add an explicit non-path member to the closed set, require totality over every output field/alias of every surface in the registry join, and restate AC22's build-failure condition as "any un-dispositioned field," not "any path-bearing field lacking one."

**C4. (Material — dangling dependency / corpus discipline) The runtime/session handle is a semver-major LLP 0002 change that this document never assigns, and 0023 has no delegated-obligations ledger.** Evidence: §7.1 requires a new opaque handle, handle-indexed host state, and runtime identity "threaded through `fs`, cwd, module resolution, module caching, and errors" — a change to the `ex_host_*` embedding surface that LLP 0002 owns; LLP 0024 §6 handles the *same situation* correctly ("part of LLP 0002's narrow consumer contract, which is explicitly semver-major... LLP 0002 is amended in the same change"), and LLP 0002 appears nowhere in 0023's Related list or text. More broadly, 0023 places obligations on LLP 0021 (absorb the arming-containment invariant, §8; new authorable actions and dataset), on the LLP 0014 generator (whoever synthesizes the universal static-floor row for the observation action, §8 — unassigned, see C5), and consumes LLP 0022 §7's bridge inventory — yet both siblings carry checked ledgers (LLP 0022 §11, whose preamble notes rows "drifted within a day"; LLP 0025 §11) and 0023 carries none. Resolution criterion: add LLP 0002 to Related and state the amendment obligation; add a §-level delegated-obligations table with the same `ref-check`-verifiable IDs the siblings use.

**C5. (Minor — registry reasoning) §8 overstates the read-edge argument: "no authority source admits a package principal to it at all" is not a valid inference from `positiveSources: ["ambient-root", "static-floor"]`.** Evidence: the cwd read edges are as cited (`coverage-edges.json`: `export:exact_process:cwd`, `__exactGetCwd`, `global:process.cwd` → `sys:read`, positiveSources ambient-root + static-floor), but `sys:read` is `lifecycle: "authorable"` with `staticOnly: false` (`capability-definitions.json`, index 34) — a static floor is precisely a package-admitting source if generated policy emits a row, and §8's own proposal uses that mechanism ("open to all principals in v1 through the static floor"). What is true is that no shipped artifact emits such floors. Resolution criterion: reword to "no artifact today authors it and the dynamic channel is closed," and assign the synthesis of the universal floor row (generator vs. arming-time snapshot row) to a named owner.

**C6. (Minor — normative precision) §7.2's precedence text contradicts §2.1 by one step, and two table rows are missing from the ordering.** Evidence: "No host lookup occurs before step 3" (step 3 = requested-stage authorization) permits a lookup *during* step 3, while §2.1 says the requested-stage gate "must precede any host lookup"; the intended statement is "before step 4." Also `synthetic-node` and `unmappable-readlink-target` appear in the reason table but not in the precedence order, and the union composition sentence pins reserved-scheme/out-of-snapshot "before path-namespace validation" without locating them relative to step 1 (adapter input validation). Because §7.2 declares precedence observable and normative, these gaps are testable ambiguities. Resolution criterion: fix the step number, slot all reason classes (including the sibling-union members) into one explicit total order.

**C7. (Minor — coherence) §5.2's four-step `chdir` protocol never takes §8's new virtual-cwd *mutation* decision.** Evidence: step 2 names only "the typed directory-metadata decision (the stat/enumeration edge of LLP 0021 WP5)"; §8 defines a mutation action "whose resource is the target logical path, authorable, root-only." An implementer following §5.2 alone would gate `chdir` on `fs:list`-class authority plus root attribution and never consult the new action. Resolution criterion: make §5.2's decision set explicitly conjunctive over the mutation action and the metadata edge.

**C8. (Minor — completeness/compat) The `process.argv` contract pins `argv[1]` but not the argv tail, and the mode values diverge from Node without being flagged.** Evidence: §6's mode table sets `argv[1]` to `ibex:eval`/`ibex:stdin` where Node leaves `argv[1]` to the *first user argument* for `-e` (user args start at index 1 in Node's `-e` mode) and absent for piped stdin — so Ibex's choice silently shifts user arguments unless the tail is also specified. The document elsewhere prides itself on stating divergences (§2.3, §5.2). Resolution criterion: pin the full argv shape per mode (where user arguments begin) and record the Node divergence.

**C9. (Minor — completeness) Non-UTF-8 `readdir` reporting is ambiguous, and buffer-encoded *output* surfaces are half-specified.** Evidence: §3 says a `readdir` encountering a non-UTF-8 entry "reports that entry as malformed" — it does not say whether the whole call throws (losing the listing) or the entry is reported per-item; §4 grants `readlink` an `{encoding: "buffer"}` escape hatch but §3/§6 are silent on `readdir`/`realpath` buffer output. AC25 inherits the ambiguity. Resolution criterion: pin throw-vs-marker semantics and the buffer-output disposition per surface.

**C10. (Minor — completeness) The v1 mount row's attributes are never valued.** Evidence: §1 introduces per-mount attributes (write policy, symlink-follow policy, lifecycle, metadata-only) "even though v1 has one row," and then never states `/project`'s values. Resolution criterion: one row of values in §1.

**C11. (Minor — feasibility disposition) "A principal with no resolvable root is an arming error" (§1.2) needs a stated disposition for platform-conditional/optional dependencies.** Evidence: a committed artifact generated on macOS can name `fsevents` while a Linux install legitimately omits it; §1.2 converts today's silent skip (`runtime.rs:1824-1830`) into an arming refusal with no carve-out, which is the right default but a real-world breakage class the document should name (artifact records platform conditionality, or refusal-plus-regenerate is the accepted answer). Resolution criterion: one paragraph or an open question assigning it.

**C12. (Minor — clarity) The defining-principal computation (§2.3) is not pinned to a path stage.** Evidence: "the owner of the most specific binding *containing* the file" — containment is a property of a path, not of an inode; for the symlinked-package case the answer only comes out right if the computation runs on the post-discovery (physical, in-namespace) location, which §1.2's resolved-root bindings imply but §2.3 never states; nested-binding tie-breaking ("most specific") should also be stated against nested `node_modules`. Resolution criterion: one sentence pinning the stage (DiscoveredPath/retained-object canonical location) and the nesting rule, plus its interaction with OQ7's display-spelling question.

## 4. Cross-document findings

- **Contradiction with LLP 0024 on module identity (coordinated fix required).** LLP 0024 §7.9 restates 0023 §2's rule as "the retained platform object, `(runtime, retained object identity)`" and says "one file is one module instance no matter which principal reached it." Under the current 0023 §2.3 that tuple is exactly the design §2.3 rejects — it "collapses compartments" for cross-principal hard links (0023 AC17 mandates *two* instances) and cannot express builtins/synthetic modules. LLP 0022's precedence rule calls this "an invalid corpus state... resolved by a coordinated revision of both"; 0023 should not merge while its first consumer's restatement asserts the superseded rule.
- **Stale acceptance-criterion number in LLP 0024.** 0024 §7.9 and AC15 cite "LLP 0023 AC11" for "one instance per file across principals and spellings; a `chdir` between imports creates no second entry." In the current 0023, AC11 is package-attributed `chdir` denial; the cited content lives at AC16. Exactly the numbering drift the checked-ledger discipline exists to catch — and 0023 has no ledger (C4).
- **Contradiction with LLP 0022 §2 on project selection.** 0022 says the CLI "selects the project candidate from the shell's current directory, canonicalizes and authenticates it"; 0023 §1.1 makes the cwd only the *discovery origin*, with marker ascent selecting the root (0023 AC3 asserts a REPL in `<repo>/src` mounts the repo root, not `src/`). One of the two must be revised; as written they specify different mounts for the same session.
- **Out-of-snapshot error ownership is circular.** 0022 §11 row 15 says "no import-gate error taxonomy exists in any sibling" and OQ7 asks whether 0023 §7's reason enum should carry it; 0024 §2 *does* table an import-gate taxonomy including out-of-snapshot (citing 0022); 0023 §7.2 composes "one resolver error union" with "one precedence order" without naming the union's owner or giving that order. Three documents each point elsewhere; 0023, as the owner of the adapter result, is the natural place to close it.
- **Stale characterization in LLP 0025 §9.** 0025 says "LLP 0023 §2's identity is a *live retained platform object*, which cannot key a file that outlives the process"; 0023 §2.3 now says explicitly that retention is "an identity record, not a held descriptor." 0025's conclusion survives, but the description quotes a superseded rule.
- **Stale architecture wording in the target.** 0023 §7.1 says "LLP 0025 §7 names a supervisor/worker architecture as presumptive"; 0025's round-2 header explicitly replaced presumption with "the specified realization" plus a conformance-gated in-process alternative. (LLP 0024 §6 carries the same stale word — sibling-sibling.) 0023's normative content here (identities live with the engine; only tokens cross) is compatible with both, so this is wording, not substance.
- Adjacent (sibling-sibling, noted in passing): 0022 §11 row 22 cites "LLP 0024 OQ 6" for the bounds annex; that question is now 0024 OQ 8.

## 5. Suggestions

- **Adopt the cross-ancestor reading of the workspace marker** (C2): ascend to the outermost workspace-root declaration containing the origin, else nearest lockfile, else nearest `package.json`. It arms standard monorepos under one `/project` today, shrinks OQ5 to the genuinely hard cases (out-of-project stores, true siblings), and costs one sentence of rationale about the wider mount.
- **Record the discovery decision in the armed snapshot** — which marker selected the root, at which path — so the §1.1 fallback diagnostic, AC3, and future debugging can name *why* `/project` is what it is rather than only what it is.
- **Add the ledger** (C4) with `ref-check`-verified obligation IDs; candidate rows: LLP 0002 ABI amendment (runtime handle, structured result); LLP 0021 schema (arming-containment invariant; the two new actions and the dataset); LLP 0014 generator (universal observation-action floor rows); LLP 0022 §7 inventory (bridge projection); LLP 0024 §7.9 (module-identity restatement realignment).
- **Give the disposition dataset a `non-path` member and a totality rule** (C3); then AC22's build check becomes mechanically decidable, and the same dataset can absorb the env-shaped path channels (`PWD`, `HOME`, `TMPDIR` values) with a one-line cross-reference to the env classification so no path-bearing channel lives outside the table.
- **Address `os.devNull`.** The observables table closes `os.tmpdir()`/`os.homedir()` but says nothing about `/dev/null`, which working CLIs write to constantly; under this namespace it is outside-mount. A reserved synthetic sink (a namespace node with a no-effect write branch, like the synthetic root's no-effect stat) would be cheap, novel, and squarely in this document's jurisdiction — or state the refusal as deliberate.
- **Pin the ELOOP bound's provenance** (32 matches macOS `SYMLOOP_MAX`; Linux resolves to 40) as a deliberate cross-platform constant, one clause.
- **Consider testing AC13 against a test-only profile now** so the view-equals-base rule is exercised before any strict profile ships; otherwise AC13 is unfalsifiable in v1 and OQ6's decision later inherits an untested mechanism.

## 6. Open questions

1. Marker precedence semantics and the intended monorepo outcome (C2) — the highest-leverage open decision in the document.
2. Which document owns the unified resolver error union and its total precedence order (0022 OQ7 currently points here)?
3. How are platform-conditional/optional graph principals represented so §1.2's arming error doesn't refuse legitimately absent packages (C11)?
4. Does alias canonicalization need per-component volume identity for a foreign volume mounted *inside* the project (case-sensitive volume under a case-insensitive project root), or is a single per-binding alias key an accepted v1 approximation?
5. Do captured referrers (§7.3) carry the same stale-identity re-verification as the session cwd — i.e., does a renamed referrer directory fail a later dynamic `import()` with `ERR_IBEX_STALE_IDENTITY` or resolve against the old spelling?
6. Where do user arguments begin in `argv` per mode, and is the `-e`/stdin `argv[1]` divergence from Node acceptable (C8)?
7. Does the no-host-path property need a package-compartment analogue of LLP 0022 §7's *root*-global sweep, or do LLP 0013's compartment endowments structurally exclude every native bridge from package reach?

## 7. Readiness verdict

The document's direction, mechanism choices, and evidence discipline are excellent, and most of what round 1 demanded has landed well. But C1 (an unsound justification inside a stated security invariant), C2 (an ambiguous rule whose plain reading refuses ordinary monorepos), C3 (the enforcement dataset cannot enforce as specified), C4 (an unassigned semver-major ABI dependency and no obligations ledger), and the live 0024 contradiction are each material and unresolved.

VERDICT: NOT READY

### Orchestrator verification notes

I re-checked every decisive claim against the repository at revision
`832eb25f0327`.

**Confirmed:**

- **C1 (symlink relative-target unsoundness). Confirmed, and the concurrent Codex
  review found the same defect independently and more generally (its Blocking 9):
  for a symlinked/aliased package root the kernel resolves stored relative bytes
  from the *physical* parent, whose depth differs from the virtual spelling, so a
  virtual-relative encoding can name a different object or escape.** Two
  independent reviewers converging on this is decisive. Accepted.
- **C2 (marker precedence → monorepo refusal). Confirmed by reasoning and matched
  by Codex Blocking 3.** Under nearest-first, `ibex packages/foo/src/app.js`
  selects `packages/foo`, leaving the hoisted root `node_modules` outside
  `/project` and tripping §1.2's refusal — exactly the failure class §1.1 exists
  to prevent. Accepted; cross-ancestor workspace-root override adopted.
- **C3 (no `non-path` disposition). Confirmed.** The closed set as written cannot
  decide whether an unmarked field is path-bearing, so the build check is
  undecidable. Matched by Codex Blocking 13. Accepted.
- **C4 (LLP 0002 + missing ledger). Confirmed.**
  `llp/0002-host-embedding-abi.spec.md` exists and carries the heading
  "## The narrow consumer contract (semver-major)", which is precisely the surface
  §7.1's runtime handle changes; 0023 cited neither the document nor the
  obligation. Both siblings carry `### 11. Delegated obligations` ledgers
  (`0022:848`, `0025:857`); 0023 had none. Accepted — with the caveat below.
- **C5 (`sys:read`). Confirmed and my §8 text was wrong.**
  `capsec/registry/capability-definitions.json` gives `sys:read` as
  `lifecycle: "authorable"`, `staticOnly: false` — so a static floor *is* a
  package-admitting source, which is exactly the mechanism my own §8 proposal
  relies on. The true statement is that no shipped artifact authors such a row.
  Corrected.
- **C6, C7, C8, C9, C10, C11, C12.** All confirmed by reading the document against
  itself; each is a real gap. Accepted.
- **Cross-doc: 0025's "live retained platform object" gloss and 0023's own stale
  "presumptive" wording for 0025 §7.** Both confirmed. The latter is mine and is
  fixed; the former is a sibling defect I report rather than edit.

**Refuted / corrected:**

- **The claimed 0022↔0023 contradiction on project selection is refuted.** The
  current LLP 0022 already adopted this document's rule verbatim: "The project
  candidate is chosen by LLP 0023's rule — **discovery origin, then marker
  ascent** — not by taking the shell's cwd as the root." What remains is an
  *intra*-0022 inconsistency (an earlier sentence still says the candidate comes
  "from the shell's current directory"), which I report as a sibling wart. A
  reviewer's cross-document claim is not privileged over the file; both round-2
  reviewers made this claim and both are wrong on it.
- **C4's suggestion that the ledger carry "`ref-check`-verified obligation IDs" is
  not achievable today and I have not claimed it.** `grep -c 'obligation\|ledger'
  ref-check` returns **0** — the checker has no obligation logic at all, and
  LLP 0022 already discloses this honestly in its own row `OBL-LEDGER-CHECK`
  ("**no** — `ref-check` validates `@ref` targets and metadata only"). My new
  ledger follows that pattern: it states the obligations and explicitly records
  that no validator enforces the join yet. Adding a ledger that claims a
  verification which does not exist would be worse than having no ledger.
- **C12's premise is right but its framing understates the problem.** Pinning the
  defining principal to a path *stage* is necessary but not sufficient: the
  concurrent Codex review shows the function is not *total* (two principals can
  share a canonical root; equal-specificity ties have no rule). I have adopted the
  stronger fix — the defining principal is derived from authenticated binding
  provenance, and ambiguous ties are refused at arming rather than resolved by
  load order.

**Disposition:** Accepted on C1–C12, with C5 and C12 corrected as above and C4
accepted in substance but not in its proposed `ref-check` framing. Where this
review and the concurrent Codex review converge (C1/B9, C2/B3, C3/B13, C5/M10,
C4/CD11), I weight the finding decisively.

---

## Round 3 — 2026-07-12

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable` — a fresh subagent session spawned by the orchestrating
  `/llp-super-refine` run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden. (Recorded as-is rather than asserted.)
- **Date:** 2026-07-12
- **Revision under review:** `a1ba44b33dd1`
- **Redacted:** No. Read the repository and document directly under the user's own
  environment, authorized by the human invocation of `/llp-super-refine`.
- **Independence:** Fresh subagent with no orchestrator conversation context, no
  access to the concurrent Codex review of the same revision, and no access to any
  prior LLP 0023 review artifact — rounds 1 and 2 were stashed out of
  `llp/reviews/` for the duration.
- **Method:** subagent, round-3 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round3.md`) — the same brief given to
  the Codex reviewer.

### Verbatim review

# Review: LLP 0023 — Virtual Filesystem Namespace and Path Identity (rev. a1ba44b33dd1, round 3)

## 1. Overall assessment

This is a strong, unusually honest revision of a genuinely hard spec, and most of the round-2 replacements survive hostile inspection. I verified essentially every load-bearing code citation (≈45 of them) and the registry claims; with four small exceptions noted below, they are accurate — including the delicate ones (`ObjectState::Existing` hardcoded at the requested stage at `src/host/abi.rs:1058-1062`; the `%5C` refusal sitting inside the `if (false && …)` block spanning `src/builtins/url.js:163-315` while the *live* `fileURLToPath` at `url.js:2942-2956` already decodes `%5C` on POSIX; the verbatim ceiling string at `capsec/registry/policy-rules.json:580`; the deny-only hard stop at `crates/capsec-semantics/src/decision.rs:439-448`; the fs.open existence oracle at `src/engine/hermes_runtime_fs.cc:2010-2027`). The motivation is real and reproducible from the cited code, the §3/§4/§5 retractions are correct and well argued, and the obligations ledger is honest about what does not exist.

Two material problems remain, both in the least-tested round-2 material: §2.2's safety claim about per-principal evaluation is stronger than what the shipped evaluator actually delivers (the resource carries no binding owner and the evaluator never consults it for a package dimension, so AC 20a cannot pass against the code the section blesses), and §2.3's `SourceId` — the entire replacement for the retracted module algebra — is never defined for file-backed modules, and its stated property set appears jointly unsatisfiable by any obvious candidate definition. There is also one live three-document contradiction (the arming-refusal diagnostic) that the corpus's own precedence rule declares an invalid state. These are fixable with targeted revisions, not redesigns, but they block the document from governing the module-identity and cross-principal-authorization subsystems as written.

A process note: the sibling corpus changed *during this review* — LLP 0022's obligations ledger was revised mid-session (its `OBL-MODULE-IDENTITY` row moved from "contradicted" to aligned). I judged everything against the current files on disk; this live drift is itself the best evidence that `OBL-LEDGER-CHECK` should be sequenced early.

## 2. Strengths

- **Motivation grounded in verified failures** (§Motivation): every citation checks out — `hermes_runtime.cc:1654-1655`, `process.js:69/78-80`, `fs.js:542/570`, `arming.rs:190/206`, `host/mod.rs:288-298/1449`, `module_loader/mod.rs:805-806`. The "conflation of three concepts" framing is exactly right.
- **§1.1 cross-ancestor marker selection**: the nearest-first failure is real (confirmed `runtime.rs:1674-1677` mounts `<repo>/src` today), the stop rules are the right shape, and recording the marker kind/path in the snapshot with the marker-set version in the digest is excellent — discovery changes cannot silently re-root a project.
- **§1.2**: refusing ambiguity instead of load-order resolution; the optional-dependency carve-out (`fsevents`); and the honest integrity caveat — the "not an integrity boundary" comment really exists (`module_loader/mod.rs:46-48`) and rowing `OBL-INTEGRITY-BIND` rather than pretending is the right move. The schema claim is verified: `armed-snapshot.schema.json` has no resolved-root/specifier/alias fields.
- **§2.1** adopts the model's real staging (`model.rs:1273-1284`) and catches the genuine speculative-existence defect with a precise citation; `OBL-OBJECT-STATE` correctly scopes model+schema+ABI+digest/cache vectors together.
- **§3 both-sides canonicalization**: the "canonicalizing one side alone is a new bug" argument is verified against bytewise containment (`containment.rs:393-401`), and binding the canonicalizer version into the snapshot digest is the correct discipline. The `%5C` retraction is correct — I confirmed the earlier draft's citation was dead code, and that the active `pathToFileURL` percent-encodes backslash (`url.js:3310`), so the refusal would have rejected its own serializer.
- **§4 physical storage + translated `readlink`**: the aliased-parent counterexample is sound (kernel resolves from the physical parent), creation-time target containment is confirmed as existing engine behavior (`hermes_runtime_fs.cc:3281-3300`, ENG-22682), and the doc even catches the real sync/async divergence (`fs.js:5731` raw vs `:5751` encoded).
- **§5**: the plain reversal ("the previous draft said the opposite"), the precise reading of the reconciliation condition against `legacy-capability-reconciliation.json` and `capability-definitions.json` `definitions[19]` (both verified verbatim), and the **view-equals-base** rule — a genuinely good invariant that makes the §5.3 grant closeable.
- **§6 the `non-path` totality rule** and the generated table: the registry really has no output-disposition schema (checked `coverage-edges.json`, 6861 edges), the second `fileURLToPath` really exists and is laxer (`exact-global.js:922-926`), and `import.meta.file` really is a basename (`module-loader.js:3563`). The argv-by-mode table fixes a real earlier conflation.
- **§7.2**: encoding the confidentiality rule *in the precedence order* (host-untouched reasons 1–8 before lookup-dependent 9–15) is elegant and testable; AC 24/24a's pairwise and syscall-observation fixtures are the right way to pin it.
- **§8**: the registry analysis is verified exactly — deny-only lifecycle hard stop, `sys:read` static-floor admissibility (correcting the earlier draft's own error), and the `node:path` misclassification (`pure-in-memory-compute` rows confirmed).
- **§9**: an obligations ledger that states "no validator enforces this table" and makes building the checker its own last row is the honest construction.

## 3. Concerns

**C1 — `SourceId` is undefined for file-backed modules, and the stated property set looks unsatisfiable. Severity: Blocking.**
Evidence: §2.3 defines the file-backed row as "the authenticated source identity of that file within its binding" — a circularity, not a constructor. The section simultaneously requires: (a) "unifies both symlinks and **same-principal hard links**"; (b) "the retained platform object is therefore **evidence, not a key**"; (c) the same SourceId is "carried in the provenance manifest" across bundling/caching/bytecode (AC 18), i.e. computable at build time and portable across machines. No candidate satisfies all three: a binding-relative canonical path splits same-principal hard links (violates a); an object identity (`volume`,`file` — `model.rs:614-620`) makes the retained object the key after all (violates b) and is not machine-portable in a provenance manifest (violates c); a content digest collapses byte-identical distinct files within one package, breaking per-module URL/relative-import semantics (unaddressed). This is the same class of defect the section itself diagnoses in the round-1 algebra ("two distinct key shapes cannot agree"): the new single shape has no stated value, so AC 16–18 are not implementable without inventing the key.
Resolution criterion: pin the SourceId constructor per module kind (exact fields, normalization, canonical-location rule, build-time computability), demonstrate it satisfies the §2.3 divergence table — or amend the table (dropping same-principal hard-link unification, which Node also splits, is the cheapest consistent choice) — and reconcile with the evidence-not-key demotion. Settle OQ 8 (query/fragment) at least for v1.

**C2 — §2.2's containment claim overstates the shipped evaluator; AC 20a cannot pass against the code the section cites. Severity: Material.**
Evidence: the pair as stated matches the code's surface — `requested` is computed under the effect owner (`host/mod.rs:329-334`, and `effect_owner: principal.clone()` at `mod.rs:417`), and `expected_owner` prefers the constrained principal (`decision.rs:1129-1133`) — but the claimed property ("B's package-root grant **can only ever authorize paths inside B's own root**") does not follow. `LogicalPath` carries no owner (`model.rs:585-590`), `requested_selector_resource` projects the owner-less path (`model.rs:1356-1360`), and `authority_matches` compares the authority's `package_root_owner` to the *principal under test*, never to the binding the resource was mapped under (`decision.rs:1136-1139`). So for an occurrence on A's files (resource `package/[x]` mapped under A), constrained package B's *own* package-root authority passes both the owner gate (B==B) and byte containment — B's dimension is satisfied by B's grant for A's file, the exact behavior AC 20a asserts "not to occur". §2.2's statement that the owner "reaches the decision out-of-band through the decision context" is wrong for package dimensions: nothing carries the resource's owner at all. The document does row `OBL-OCCURRENCE-OWNER`, but frames it as identity hygiene rather than as *necessary* for the property §2.2 asserts in the present tense.
Resolution criterion: correct the mechanism description; state that the cross-package-deputy containment property holds only once `OBL-OCCURRENCE-OWNER` (or per-dimension resource projection — pick one and say which) lands; gate AC 20a on that obligation explicitly.

**C3 — The arming-refusal diagnostic is in live three-way contradiction with the siblings. Severity: Material** (also §4 of this review).
Evidence: §1.2 mandates a symbolic diagnostic (`outside-project-mount`, "*not* the out-of-project host path") citing "LLP 0025 requires startup diagnostics to name things symbolically". Current LLP 0022 §4 (`0022:472-479`) states the opposite for this exact diagnostic: the no-host-path rule "does not bind the CLI's own startup diagnostics … an arming failure that must name an out-of-project package root (LLP 0023) **may name it there**" — and mis-attributes the must-name requirement to 0023. LLP 0025's only symbolic-naming statement (`0025:812`) is a parenthetical about the legacy history file, justified by "LLP 0022 §4's no-host-path rule binds session output, and a startup diagnostic is session output" — citing 0022 §4 for the opposite of what it says. Per 0022's own precedence rule this is "an invalid corpus state".
Resolution criterion: a coordinated revision of all three; whichever disposition wins, 0023 §1.2 must either cite a real general rule in 0025 or own the rule itself. (Substantively: symbolic-only may be genuinely hard to act on for a store the operator must find; consider naming the path relative to a named boundary, or pointing at `--project`.)

**C4 — §1.1's deciding predicate — workspace *membership* — is not pinned. Severity: Material.**
Evidence: step 3 turns on "declares a workspace **of which the discovery origin is a member**", but membership requires evaluating workspace globs, and npm/yarn/pnpm/bun glob dialects (negations, `*` vs `**`, exclusions) differ. The marker table pins names and field presence only. Step 2's "Cargo-style manifest **where the project is polyglot**" is an undefined, circular predicate (polyglot relative to a root not yet selected). Since "the selected directory *is* the authority boundary" and the algorithm claims to be "pinned exactly, not described", two conforming implementations can currently select different roots for one tree.
Resolution criterion: pin the membership evaluation per marker kind (dialect, matching semantics, exclusion handling) inside the versioned marker-set constant; define or delete "polyglot". Consider adding `bun.lock` (text form) to the lockfile row.

**C5 — The "closed, total" error union omits resolver classes its siblings define. Severity: Material.**
Evidence: §7.2 claims "the union lives here, and its precedence is stated once, here", but LLP 0024 §2's import-gate taxonomy includes `unknown-builtin` and `unsupported-dependency-TLA`, and its `resolution failure` has no stated mapping into the union (is it #9 `ENOENT`? for bare specifiers?). 0024:263 scopes 0023's ownership to "the path classes", which is narrower than 0023's claim. Today the extra classes are pairwise disjoint on specifier shape, so no observable ambiguity exists — but a union advertised as closed and totally ordered, with AC 24 asserting pairwise precedence, cannot silently exclude members of the same resolver's error space.
Resolution criterion: either absorb 0024's classes with explicit ranks, or narrow the ownership claim to path/adapter classes and state the composition rule (including where `resolution failure` lands) in one place.

**C6 — Two-path operations (`rename`, `copyFile`, `link`) have no normative v1 rule. Severity: Material.**
Evidence: OQ 11 defers the whole matrix (source and destination actions, the binding-transition rule — which §2.3 makes identity-relevant — and atomicity), yet these surfaces exist in the shipped builtin today (e.g. `link` at `fs.js:5725-5729`) and §6 asserts "every path-taking runtime surface uses the same resolver". A spec governing the fs adapter cannot leave its only multi-resource operations entirely open.
Resolution criterion: state a conservative v1 rule now (both endpoints take the full pipeline independently; a cross-binding-owner rename/link is refused in v1), leaving the general matrix to the dataset OQ 11 contemplates.

**C7 — §7.1 mischaracterizes LLP 0002's narrow contract. Severity: Minor/Non-blocking.**
Evidence: "The `ex_host_*` and `ex_hermes_*` entry points are LLP 0002's **narrow consumer contract**" — LLP 0002 (Summary; §The narrow consumer contract) says the semver-major subset is the five `ex_hermes_*` functions plus the host-call installer, and that "the full `ex_host_*` callback surface … is an implementation detail". The semver-major conclusion for the handle stands (it changes `ex_hermes_create/eval`); the sentence and `OBL-ABI-HANDLE`'s framing should be corrected.
Resolution criterion: restate which half of the amendment is semver-major.

**C8 — Stale citations and one stale ledger row. Severity: Minor/Non-blocking.**
Evidence: (a) §9 `OBL-MODULE-IDENTITY` says LLP 0024 "restates module identity as `(runtime, retained object identity)` and cites a stale acceptance-criterion number" — current 0024 §7.9 (`0024:1134-1146`) explicitly does *not* restate the key, defers to 0023 §2.3, and cites no AC number; AC 15 (`0024:1482`) cites "§2.3" generically. The obligation is effectively landed and the row describes a sibling that no longer exists. (b) §7.2's "LLP 0022's OQ asks which enum carries the out-of-snapshot error" — current 0022 has no such open question. (c) §7.1's worker-transfer row cites "(LLP 0025 §7)" for successor handle minting, but worker *replacement* is 0025 OQ 4, undecided. (d) `src/module_loader/mod.rs:28` should be `:46-48`.
Resolution criterion: refresh all four; mark OBL-MODULE-IDENTITY landed or reword it as a keep-aligned obligation.

**C9 — The `%5C`-decode divergence from Node is not stated as a divergence. Severity: Minor/Non-blocking.**
Evidence: Node's POSIX `fileURLToPath` refuses `%5C` (same `ERR_INVALID_FILE_URL_PATH` as `%2F`), so Node's own round-trip fails for a backslash filename; Ibex deliberately decodes (and the live `url.js:2942-2956` already does). The decision is right, but §2.3's own standard is divergences "stated rather than glossed", and §3 states Node-compat for `%2F` while staying silent on the `%5C` divergence.
Resolution criterion: one sentence naming it, and pin it in AC 6.

## 4. Cross-document findings

1. **Contradiction (live): arming-refusal disclosure** — 0023 §1.2 vs 0022 §4 (`0022:472-479`) vs 0025 §9 (`0025:812`), detailed as C3. Each document cites another for its position, and two of the three citations are inaccurate.
2. **Stale in 0023 → 0024**: `OBL-MODULE-IDENTITY` (C8a). Conversely, 0024's current text (§7.9, AC 15, OQ 10) is fully consistent with 0023 §2.3, including mutual acknowledgment that the canonical display spelling is open (0023 OQ 7 ↔ 0024 OQ 10).
3. **Divergent definition under one name**: 0025 §9 (`0025:756-762`) calls its history key "the retained-object record of LLP 0023 §2.3 — `(volume, file, verification generation)`" but defines the generation as *birth time* (`st_birthtime`/`STATX_BTIME`) with a *canonical-path* fallback, while 0023 §2.3 names `st_gen`/`ATTR_CMNGEN` with a *retained-descriptor* fallback and leaves the primitive open (OQ 9). Two documents now answer 0023's open question differently under a shared term; when OQ 9 is resolved, 0025 either inherits or must stop claiming the same record.
4. **Stale in 0023 → 0022**: the "LLP 0022's OQ" claim in §7.2 (C8b); and the union-ownership scoping wobble with 0024:263 ("LLP 0023 §7 owns **the path classes**") vs 0023's whole-union claim (C5).
5. **Weak citation**: §7.1's "(LLP 0025 §7)" for successor handle minting; replacement is 0025 OQ 4 (C8c).
6. **Consistent and verified** (worth saying): the synthetic identities and script/module split (0023 §2.3/§6 ↔ 0024 §2/§3 ↔ 0022 §3); referrer capture (0023 §7.3 ↔ 0024 §1's typed-logical-path referrer field ↔ 0022 §8); `path.resolve` returning strings uncontained (0023 §6 ↔ 0022 §4/AC 5); `.load`'s typed pre-read (0022 §7 ↔ 0024 §1; 0023 supplies path+decision, though it never mentions how a *session-layer* caller with no engine frame presents its principal to the §7.1 ABI — "native derivation from engine provenance" doesn't cover operator submission; a sentence in §7.1 would close this dangling edge); and 0024 §1's error precedence (outside-mount ≺ policy denial ≺ resolution failure) agrees with 0023's order.
7. **Process observation**: 0022's ledger changed during this review (its module-identity row was realigned mid-session). The four-document seam is drifting in real time; `OBL-LEDGER-CHECK` (and 0022's `OBL-LEDGER-CHECK` twin) should be sequenced before further concurrent revision rounds, and until then each ledger row could carry the sibling revision it was last checked against.

## 5. Suggestions

- **Pin SourceId** as: the defining principal's locator+digest plus the *binding-relative canonical path* of the module's canonical (physical) in-namespace location. This unifies symlink spellings, splits hard links (amend the §2.3 divergence sentence — Node splits them too, so this *reduces* divergence), keeps the retained object as pure evidence, and is build-computable and machine-portable for provenance manifests. If hard-link unification is genuinely wanted, say why and accept the object-derived key openly.
- For C2, consider **per-dimension resource projection** (map the host path under each constrained principal's own binding; a non-owner maps A's file to `project/node_modules/A/x`, and B's Package-rooted grant fails on root mismatch) as an alternative to the occurrence-owner field — it delivers AC 20a without widening the wire model, at the cost of N mappings per decision. Whichever is chosen, name it in §2.2.
- Answer OQ 10 (`os.devNull`) before v1 rather than after: working CLIs hit `/dev/null` immediately, the no-effect-write sink is cheap, and it exercises the mount-table machinery §1 claims is additive.
- On OQ 6, lean toward shipping the strict profile as a *profile* but keeping the universal read as the v1 default: §5.3's adversarial-fixture framing plus view-equals-base already makes the flip cheap later, and the Node-compat cost of default-strict is real.
- Add the mid-review-observed mitigation to §9: each ledger row records the owner document's revision at last verification, so a stale row is detectable by inspection even before `OBL-LEDGER-CHECK` exists.
- State in §3 how alias canonicalization composes with the decision cache: `resource_canonical_bytes` (`cache.rs:51`) must be post-canonicalization bytes, or two spellings split the cache while agreeing on the decision.

## 6. Open questions

1. What exactly is a file-backed `SourceId` (C1)? This is the question the rest of §2.3 hangs on.
2. Owner-field or per-dimension projection for C2 — and does the chosen mechanism change the decision-cache key shape?
3. Who wins the startup-diagnostic disagreement (C3), and is a boundary-relative path an acceptable middle ground?
4. What is the v1 rule for two-path operations, and does a cross-binding rename change module identity mid-session (interacts with §2.3 and the module cache)?
5. Which glob dialect(s) define workspace membership, and how is a mismatch between the declaring tool and the marker (e.g. `pnpm-workspace.yaml` present but origin excluded) diagnosed?
6. How does per-volume canonicalization behave for a path that crosses an in-project device boundary (a mount point inside `/project`), and does §1.1's device-stop rule interact with it?
7. Does the operator-submission (`.load`) route present a principal to the §7.1 ABI through the session handle, given "native derivation from engine provenance" cannot apply to a caller with no engine frame?

## 7. Readiness verdict

The document is close: the namespace, cwd, observables, error-precedence, and registry sections could govern implementation today, and the honesty of the ledger is exemplary. But C1 (the module-identity key is undefined and its property set likely unsatisfiable as stated), C2 (the §2.2 safety claim does not hold of the cited evaluator and AC 20a is ungated), and C3 (a live corpus contradiction on a diagnostic this document specifies) are unresolved material correctness/coherence concerns.

VERDICT: NOT READY

### Orchestrator verification notes

I re-checked every decisive claim against the repository at revision `a1ba44b33dd1`.
This review and the concurrent Codex round-3 review converge independently on the
two central defects, which I treat as decisive.

**Confirmed:**

- **C2 (§2.2's safety claim is false of the shipped evaluator). Confirmed by
  construction**, and matched by Codex Blocking 1. `LogicalRoot` is a payload-free
  enum (`model.rs:575-581`); `arming.rs:214-218` builds
  `LogicalPath { root: Package, components: <tail> }`, so A's file and B's file
  produce the *identical* value `{Package, ["x"]}`; and `decision.rs:1136-1139`
  compares the **authority's** `package_root_owner` to the **principal under
  test**, never to the binding the resource was mapped under. B's own grant
  therefore satisfies B's dimension for A's file — exactly what AC 20a says cannot
  happen. My §2.2 asserted the opposite **in the present tense**. Accepted; the
  property is now stated as conditional on the obligation, and I adopt the
  **per-dimension projection** mechanism this review proposes.
- **C1 (`SourceId` undefined and its properties unsatisfiable). Confirmed**, and
  this review's analysis is sharper than Codex's. The decisive point is that my
  "unifies same-principal hard links" property was **my own invention**, is **not**
  Node's behavior (Node splits hard links), and is required by nothing — the
  compartment-collapse fix needs *different* packages sharing an inode to be *two*
  modules, which splitting delivers. Dropping it makes the key definable and
  *reduces* divergence. Accepted, with the proposed constructor.
- **C3 (arming diagnostic). Confirmed, and I had it backwards.** There is no
  general "startup diagnostics are symbolic" rule in LLP 0025 — its symbolic
  sentence is a parenthetical about the legacy history file. Current LLP 0022 §4
  says the opposite of my §1.2: the no-host-path rule "does not bind the CLI's own
  startup diagnostics," and an arming failure naming an out-of-project package root
  **may name it there**. I mis-cited a sibling to justify a rule that sibling does
  not contain. Aligned with 0022.
- **C4 (workspace membership / "polyglot"). Confirmed.** Matched by Codex
  Blocking 3.
- **C5 (error union not closed), C6 (two-path operations), C7 (LLP 0002 boundary),
  C8 (stale citations and the stale `OBL-MODULE-IDENTITY` row), C9 (`%5C`
  divergence unstated). All confirmed.** C7 is understated: `ExactHermesRuntime*`
  is **already** an opaque public runtime handle (`include/exact_runtime.h:27-28`),
  so part of what §7.1 demands already exists.
- **The process observation is correct and I have acted on it.** The sibling corpus
  moved *during* this review. Every §9 ledger row now records the sibling revision
  it was last verified against, so a stale row is detectable by inspection — the
  mitigation this review proposes.

**Refuted / corrected:**

- Nothing material. This review's four self-declared citation exceptions are
  themselves accurate.

**Disposition:** Accepted on C1–C9. Where this review and the concurrent Codex
review converge — §2.2, `SourceId`, marker membership, two-path operations, the
LLP 0002 mischaracterization, and the stale ledger row — the finding is decisive
and I did not weigh my own prior judgment against it.

---

## Round 4 — 2026-07-12

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable`; fresh subagent spawned by the orchestrating `/llp-super-refine`
  run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden.
- **Date:** 2026-07-12
- **Revision under review:** `b60400977333` (`shasum -a 256`). The reviewer reported
  it as `7f71f6986b7d`, which is the **`git hash-object` blob SHA-1 of the identical
  bytes**. I verified both against the same file: no drift, and both round-4
  reviewers saw the same document.
- **Redacted:** No.
- **Independence:** Fresh subagent; no orchestrator context, no access to the
  concurrent Codex round-4 review, and no access to any prior LLP 0023 artifact —
  rounds 1–3 were stashed out of `llp/reviews/` for the duration.
- **Method:** subagent, round-4 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round4.md`) — same brief as Codex,
  carrying the explicit "prefer running artifacts to reading them" warning.

### Verbatim review

*(Reviewer's note on revision, preserved: the prompt named `b60400977333`; the
working tree hashed to `7f71f6986b7d` under the reviewer's method. The target did
not change during the review; LLP 0024 changed twice and LLP 0025 once while it was
being read.)*

## 1. Overall assessment

This is a strong, unusually honest spec whose round-3 repairs are — with two exceptions — genuine repairs. I verified essentially every load-bearing code citation by reading or executing the artifact rather than trusting the doc, and the hit rate is remarkable: `LogicalRoot` is payload-free exactly as claimed (model.rs:575-581), the arming mapper really does strip the binding prefix and emit an ownerless resource (arming.rs:214-218), the owner gate really compares against the principal under test (decision.rs:1129-1139), the policy identifier is verbatim in the shipped dataset (policy-rules.json:580), the schema really cannot represent the cwd actions (I ran the enums: no `session-state`, no `session-scoped`, no predicate field anywhere), the `false &&` dead block is where the doc says it is (url.js:163), the live `fileURLToPath` does decode `%5C` on POSIX and the live `pathToFileURL` does emit `%5C` (url.js:2936-2951, 2958-2963), and the fs.open existence oracle is real (fs.cc:2010-2030, authorization at 2028). The conditional-property-plus-gated-AC pattern (§2.2/AC 20a) is exactly how a spec should handle a safety property the shipped code cannot yet deliver.

What still blocks it is narrow but real: (1) the error-class composition seam with LLP 0024 has drifted into a direct, observable contradiction — and each document independently holds one infeasible element of it; (2) §1.1's pinned workspace-membership predicate is under-inclusive in a way that falsifies AC 3a's own rationale and mis-roots real monorepos. Two further material gaps (nested-binding projection semantics in §2.2; two holes in the §2.3 `SourceId` constructor) need sentences, not redesign. The architecture itself — staged identity, per-dimension projection, `SourceId`/`SourceLabel` separation, the total disposition dataset, the stamped obligations ledger — is sound and I would not change its shape.

## 2. Strengths (with citations)

- **The motivation chain is entirely true.** Every link verified: armed cwd returns `undefined` (hermes_runtime.cc:1654-1656), the facade falls back to `/` (process.js:69-80), `fs` resolves against it (fs.js:570-599), the armed host refuses unbindable host paths (arming.rs:206-208), and the error is a generic "Permission denied" (mod.rs:1449). The relative-path join against the Rust process cwd (mod.rs:288-298) and the lossy string module ids (module_loader/mod.rs:805-806) are as described.
- **§2.2 is the best section in the document.** The self-refutation is precisely correct against the code: the resource `{root: Package, components: tail}` names no owner (arming.rs:214-218), the owner gate compares `authority.package_root_owner` to the *principal under test* (decision.rs:1136-1139), so B's self-grant passes both the owner gate and bytewise containment (containment.rs:393-403) for an occurrence on A's file. The projection fix reuses a mapper that already takes a principal (arming.rs:179) and is called once today (mod.rs:334). Stating the property as conditional on `OBL-OCCURRENCE-PROJECTION` and gating AC 20a on it is exactly right.
- **§8's unrepresentability claim survives execution.** `definitions[19]` is `process:cwd` / `deny-only` / `shared-process-mutation`; the lifecycle hard-deny is at decision.rs:439-448 before any positive source; the read edge is `sys:read` with `["ambient-root", "static-floor"]` and `sys:read` is authorable/`staticOnly: false` — so the doc's correction of its own earlier "no source admits a package" claim is itself correct. The schema enums contain none of the three needed constructs. The `node:path` misclassification is live data (`export:node_path:resolve`/`relative` = `non-capability`/`pure-in-memory-compute`), and the no-effect branch matches the shipped early-exit in path.js:59-71.
- **§3's `%5C` reversal is verified end-to-end**: the cited refusal really is dead code behind `false &&` (url.js:163-168); the live POSIX path decodes `%5C` and refuses it only on Windows (url.js:2936-2951); `_encodeFileURLPathChar` emits `%5C` for a literal backslash (url.js:2958-2963), so the round-trip argument in AC 6 is grounded in the shipped serializer. The `%2E` non-refusal matches the parser (url.js:1348-1355, 1666-1680).
- **§4's physical-vs-virtual symlink encoding analysis** (the round-1 defect) is subtle and correct, and both halves of the current-code claim check out: target gating exists (fs.cc:3281-3300, the ENG-22682 comment verbatim) while the write is pathname-based `::symlink` (fs.cc:3301-3303), which the spec correctly rules non-conforming. The dangling-readback rule (deepest existing ancestor, lexical tail) closes the hole the last draft left.
- **§7.1's LLP 0002 restatement is now exactly right**: the narrow contract is the five `ex_hermes_*` functions plus the installer (0002:26-46), `ex_host_*` is "an implementation detail" (0002:21), `ExactHermesRuntime` exists (exact_runtime.h:27-28), the Host singleton and replacing installer are real (abi.rs:130, 214-220), and fs work runs on worker threads (fs.cc:1918-1940), which makes the operation-lease design necessary rather than decorative.
- **§7.2's ordering rationale is a genuine security argument**: discovered-target denial over `ELOOP` ("a later-stage fact is never probed merely to outrank an earlier refusal") is correct, and the existence-oracle citation is accurate — parent `open`, target `openat`, `fstat`, and a type-based `EACCES` all precede the first typed decision (fs.cc:2010-2030).
- **§1.2's diagnostic decision** is correctly re-grounded: 0022 §4 states the JavaScript-visible scoping *and* explicitly authorizes the arming diagnostic to name an out-of-project package root — the seam agrees verbatim in both directions.
- **The §9 ledger with revision stamps proved its worth during this review**: 0024 moved twice while I read it, and the stamp is what makes `OBL-MODULE-IDENTITY`'s row checkable at all.

## 3. Concerns

**C1. (Blocking) The error-class composition rule contradicts LLP 0024 §2, and each side holds one infeasible element.**
Evidence: 0023 §7.2 places the specifier-level classes — "reserved scheme, out-of-snapshot, unknown-builtin, TLA" — between rows 3 and 4, i.e. *before* `ERR_IBEX_OUTSIDE_MOUNT` and every other path class, on the premise that "the two sets are disjoint on specifier shape." LLP 0024 §2 (current revision `e9ea5276`, ~line 311) pins the opposite as its own normative total order: "reserved-scheme → **resolution failure** → outside-mount / path class (LLP 0023 §7.2 owns these and this document defers) → unknown-builtin → out-of-snapshot → interim → policy denial → unsupported-dependency-TLA," and 0024 §1 reaffirms "Error precedence is §2's taxonomy" for `.load`. These are mutually exclusive observable orders. Worse, each is independently wrong once: 0023's placement of `unsupported-dependency-TLA` (and out-of-snapshot for path-shaped specifiers) before the path classes is unimplementable — a dependency's TLA cannot be known before the path pipeline resolves and reads it, and `import("./node_modules/foo/x.js")` shows the disjointness premise false for out-of-snapshot. Conversely 0024's "resolution failure" (defined there as "no such module") *before* the path classes requires existence probing before containment/authorization — precisely the oracle 0023 §7.2 prohibits ("absence is never disclosed before authorization") and that AC 24 pins (`ERR_IBEX_OUTSIDE_MOUNT`, never `ENOENT`).
Resolution criterion: one jointly-agreed order, stated once and cited by the other document: shape-decidable classes (reserved-scheme; unknown-builtin for builtin-shaped specifiers) → path/containment/authorization classes → resolution- and graph-dependent classes (resolution failure, out-of-snapshot, interim, policy denial, TLA); delete or scope the disjointness sentence; both revisions restamped in both ledgers.

**C2. (Blocking) §1.1's workspace-membership predicate, as pinned, does not fire for real entry points — including the one in its own AC.**
Evidence: §1.1 step 2 pins "patterns are matched against **the origin's path** relative to the declaring directory, `*` does not cross a `/`." The origin is the entry file's *directory* (step 1). For `ibex packages/foo/src/app.js` — AC 3a's own fixture — the origin is `packages/foo/src`, which `packages/*` does not match under the pinned dialect. The outermost-workspace clause therefore never selects; selection silently falls through to "nearest lockfile." In a monorepo with only a root lockfile the fixture still passes — for the wrong reason, masking the defect — and in a workspace where a member carries its own lockfile (mixed-tooling repos) or none exists at the root, nearest-lockfile/nearest-`package.json` selects the *member*, the hoisted `node_modules` falls outside `/project`, and §1.2 refuses arming: the precise failure §1.1 states it exists to prevent. The membership predicate is the sentence "the whole algorithm turns on," and it is under-inclusive.
Resolution criterion: define membership as "the origin, or an ancestor of the origin at or below the declaring directory, is matched by a member glob (last match wins, exclusions included)"; add two AC 3a variants that cannot pass via the lockfile fallback — a workspace whose member carries its own lockfile, and a workspace with no root lockfile.

**C3. (Material) §2.2's projection is stated and fixtured for sibling packages only; nested package bindings silently re-open the headline property.**
Evidence: with `node_modules/a/node_modules/b`, principal `a`'s own binding physically contains `b`'s files, and package bindings filter only on exact owner (arming.rs:191-194) — so `a`'s projection of `b`'s file is `{root: Package, components: ["node_modules","b","x"]}`, inside `a`'s own frame, and `a`'s package-root grant passes the owner gate (a == a, decision.rs:1136-1139) and containment. The revision header's defect statement — "a package's own grant structurally authorizes an occurrence on *another* package's file" — therefore remains true for nested layouts after the fix; §2.2's worked example covers only the case where "B owns no binding containing that file," and AC 20a tests only siblings. This may well be the *intended* physical-tree semantics (Node nests dependencies inside parents deliberately; LLP 0013's compartments are about execution, and §2.3 correctly keeps `b`'s module identity separate) — but a spec that just withdrew an over-claimed containment property should not leave its replacement property with an unstated exception.
Resolution criterion: one paragraph in §2.2 stating the nested-binding rule explicitly (accepted as physical-tree semantics, or projected out), plus a nested-layout arm on AC 20a either way.

**C4. (Material) The `SourceId` file-backed constructor has two undefined points: the root-principal arm and which "canonical components."**
Evidence: §2.3 defines the file-backed key as "(defining principal **locator + integrity digest**, binding-relative canonical path)." Locator-plus-integrity-digest is LLP 0021's *package* principal identity (0021:318); the root principal has neither, so the constructor is not total over `/project/src/app.js` — the most common module in the system. Separately, "in canonical components" is ambiguous between §3's lexical canonical form and §3's *per-volume* canonicalization; the latter is machine-specific (case folding, normalization form "as the volume actually implements them"), which contradicts §2.3's own requirement that a SourceId be "build-computable and machine-portable" so a provenance manifest "generated on one machine must name the same modules on another."
Resolution criterion: define the principal component as LLP 0021's principal identity value for *every* principal kind (naming what that is for root), and pin the path component to the lexical canonical component vector (volume canonicalization confined to authorization identity), with the portability rationale stated.

**C5. (Minor/Non-blocking) Obligation-gated acceptance criteria are labeled inconsistently.** AC 20a is explicitly gated on its obligation; AC 9, 19, 18, 5/27, and 22 are equally unpassable today but carry no gate. Resolution: stamp each obligation-dependent AC the way 20a is stamped.

**C6. (Minor/Non-blocking) `ERR_IBEX_ALIAS_COLLISION` (§7.2) has no occurrence-time semantics anywhere in the document.** Resolution: one sentence defining the occurrence-time collision condition, or an explicit deferral to `OBL-ALIAS-CANON`.

**C7. (Minor/Non-blocking) §2.1's NamespacePath and §7.1's ABI both carry a singular "binding owner," which §2.2's projection set supersedes.** Resolution: a clause stating what the singular field means post-projection.

**C8. (Minor/Non-blocking) §4.1's "cross-binding-owner" rule doesn't say whether package↔project moves are covered, and leaves `copyFile`'s asymmetry implicit.**

**C9. (Minor/Non-blocking) AC 18's "stale-identity error at commit" doesn't name the triggering operation** given the same AC pins that a cache *hit* performs no lookup.

**C10. (Minor/Non-blocking) Two citation nits.** fs.js:5731's `readlinkSync` *validates* its `options` and then fails to apply them — "ignores its `options` entirely" slightly overstates. And the macOS attribute is spelled `ATTR_CMN_GEN`, not `ATTR_CMNGEN`.

## 4. Cross-document findings

- **Contradiction (both directions wrong once): the error-class composition order, 0023 §7.2 ↔ 0024 §2** — detailed as C1. This is the one live seam break in the corpus, and it is of exactly the class the corpus keeps catching: each document cites the other while stating a different observable order.
- **Stale stamp, substance intact:** 0023 §9's `OBL-MODULE-IDENTITY` row is stamped "delivered at `b0ff4ea3247e`"; 0024 is now at `e9ea5276`. The claimed sentence still exists verbatim at the current revision, so the row is true but its stamp is two revisions old. Restamp; and this is the concrete argument for prioritizing `OBL-LEDGER-CHECK`.
- **Seams verified agreeing:** 0022 §4's JavaScript-visible no-host-path rule and its explicit allowance for the arming diagnostic to name an out-of-project package root match §1.2 exactly. 0025's only "symbolic" sentence is indeed the legacy-history parenthetical, and 0025 explicitly marks it as its own choice — §1.2's mis-citation correction is accurate. 0024 §7.9, AC 15, and OQ 10 are aligned with §2.3 and OQ 7. The operator-submission credential §7.1 leans on exists in 0022 §7 and 0024 §1.
- **Dangling-dependency watch:** 0022's own ledger stamps 0024/0025 at hashes that are also now stale — the same restamping sweep should cover all four documents.

## 5. Suggestions

1. Fix C1 jointly with 0024 in one commit, and state the merged order in exactly one of the two documents with the other citing it — the current "each states the whole order" pattern is what allowed the drift.
2. Fix the §1.1 membership predicate (ancestor-inclusive matching) and add the two unmasked fixtures from C2; also consider recording in the armed snapshot the nearer markers that were ascended *past*, so the discovery diagnostic can say "not `packages/foo`, because the workspace at `<root>` claims it."
3. For `SourceId`, define the principal component as "the LLP 0021 principal identity" uniformly (which names the root arm), and pin lexical-canonical components with the portability argument (C4).
4. Answer OQ 10 (`os.devNull`) now in favor of the reserved synthetic sink.
5. Generate the AC 24 pairwise-precedence fixture list from the error-union dataset itself, so a new reason cannot ship without its ordering fixtures.
6. Add differential property-based fixtures against Node for the pure-lexical surfaces — the spec pins several deliberate divergences, and a generated "everything else agrees with Node" harness is the cheapest way to keep the divergence list closed rather than growing by accident.
7. On OQ 6, keep the current choice (universal read + view-equals-base).
8. Nano-fixes: C10's citation nits.

## 6. Open questions

1. Which projection is the *audit/evidence* resource for a multi-principal occurrence, and does the decision-cache key carry N projections or their derivation?
2. What are the nested-binding authorization semantics (C3)?
3. Where exactly does generic resolution failure sit in the merged order, and is the extension/index probing that produces it itself typed-decided per probe?
4. Is a package→project `rename` inside the single mount refused as "cross-binding-owner" (C8)?
5. Does the captured referrer re-verify like the cwd? Recommending yes.

## 7. Readiness verdict

The document's architecture is right, its self-corrections are verified true, and most of what remains is sentence-level. But two defects meet the bar of unresolved material correctness/coherence: the 0023§7.2 ↔ 0024§2 error-order contradiction (with one infeasible element on each side), and the §1.1 membership predicate that fails its own AC's rationale on the security boundary it exists to pin. C3 and C4 are material completeness gaps in the two sections this round rewrote.

VERDICT: NOT READY

### Orchestrator verification notes

Re-checked against the repository at `b60400977333`.

**Confirmed:**

- **C1 (error-order contradiction). Confirmed, and worse than reported: LLP 0024
  contradicts *itself*.** Its line 223 says "an outside-mount refusal precedes a
  policy denial, which precedes a resolution failure," while its line ~313 pins
  "reserved-scheme → **resolution failure** → [path classes] → … → policy denial."
  Those are mutually exclusive. Both reviewers converge on the conflict; the 0024
  author has since conceded it and is adopting the merged order, deleting its
  restated total order, and citing this document instead. Accepted.
- **C2 (workspace membership). Confirmed**, independently by Codex (its Blocking 1),
  and decisively: Ibex's **own** `package.json` uses `workspaces: ["packages/*"]`,
  which under my pinned dialect cannot match origin `packages/foo/src`. My own AC 3a
  passes only by falling through to the lockfile rule. Accepted.
- **C3 (nested bindings). Confirmed by construction.** For
  `node_modules/a/node_modules/b`, `a`'s projection of `b`'s file lands inside `a`'s
  own frame and `a`'s package-root grant matches. This is the *intended* physical-tree
  semantics — a parent package's root genuinely contains its nested dependencies, and
  §2.3 keeps `b`'s *module* identity and compartment separate — but the reviewer is
  right that a document which just withdrew an over-claimed containment property must
  not leave its replacement with an unstated exception. Stated.
- **C4 (`SourceId` root arm). Confirmed**, independently by Codex (its Blocking 3),
  and it is the *busiest* row, not an edge case: a prompt `import "./util.js"` over a
  plain project file has defining principal **Root**, and `Root` carries only
  `identity` (`model.rs:304`), not LLP 0021's package locator+digest (`0021:318`). The
  most common module identity in a REPL session was undefined. Accepted.
- **C5–C10.** All confirmed.

**Refuted / corrected:**

- **This review's own round-3 claim that Node refuses `%5C` on POSIX was FALSE, and I
  propagated it into the spec without executing Node.** The concurrent Codex review
  ran Node; so did I: v25.9.0 **decodes** `%5C` (`/tmp/a\b`), refuses `%2F`
  (`ERR_INVALID_FILE_URL_PATH`), and `pathToFileURL` re-emits `%5C` — so Ibex's
  behavior is **Node-compatible, not a divergence**. I accepted a reviewer's assertion
  about an *external system* without running it, and it became a false normative claim.
  Removed. This is the single most instructive error of the loop.

**Disposition:** Accepted on C1–C10, with the `%5C` correction reversing a claim this
reviewer itself introduced in round 3.

---

## Round 5 — 2026-07-12

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable`; fresh subagent spawned by the orchestrating `/llp-super-refine`
  run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden.
- **Date:** 2026-07-12
- **Revision under review:** `ab8658a68b57` (`shasum -a 256`).
- **Redacted:** No.
- **Independence:** Fresh subagent; no orchestrator context, no access to the
  concurrent Codex round-5 review, and no access to any prior LLP 0023 artifact —
  rounds 1–4 were stashed out of `llp/reviews/` for the duration.
- **Method:** subagent, round-5 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round5.md`), same brief as Codex,
  carrying the "prefer running artifacts to reading them" warning — which this
  review acted on (it executed Node for every compatibility claim).

### Verbatim review

# Review: LLP 0023 — Virtual Filesystem Namespace and Path Identity (revision `ab8658a68b57`, round 5)

## 1. Overall assessment

This is now a genuinely strong spec, and the round-4 repairs are each correct in substance. I verified essentially every load-bearing citation against the artifact it names — registry strings verbatim (`capsec/registry/policy-rules.json:580`, `legacy-capability-reconciliation.json:112`, `capability-definitions.json` `definitions[19]`), model and evaluator structure (`crates/capsec-semantics/src/model.rs:575-581, 1273-1284`, `decision.rs:1129-1139, 439-448`, `cache.rs:49-61`), the shipped engine's hard-link and symlink-creation gates (`src/engine/hermes_runtime_fs.cc:3281-3300, 3318-3331`), the existence oracle in today's `fs.open` branch (`hermes_runtime_fs.cc:2005-2028`), and every Node claim in §3 by executing Node v25.9.0 — `%2F` refusal, `%5C` decode, backslash round-trip, dot-segment collapse all confirmed, in both Node and Ibex's live `fileURLToPath` (`src/builtins/url.js:2935-2951`). The four-tier error order is mirrored exactly in the current 0024. The architecture is done; nothing here needs redesign.

What still blocks is narrow and shallow: one undefined member (`interim`) sitting inside the very error-order table this document now owns; a ledger whose new revision-stamp column — the round-4 repair itself — uses an unresolvable stamp for 12 of 23 rows, behind which two rows are demonstrably stale in the favorable direction; a `copyFile`-vs-LLP 0021 seam that escaped the ledger; and one more unexecuted-Node claim of exactly the class this document has twice recorded being burned by (§2.3's Node-ESM contrast — refuted by one `node` run). These are a one-day revision pass, not another design round.

## 2. Strengths

- **§2.2 is now exactly right about the shipped evaluator, and honest about it.** Each link in the chain confirmed: `LogicalRoot` payload-free (`model.rs:575-581`), the mapping strips the binding prefix (`arming.rs:213-217`), the owner gate compares against the principal under test (`decision.rs:1129-1139`), the effect schema carries one resource and the cache stores it unpaired (`cache.rs:49-61`), and the host calls the projection once (`src/host/mod.rs:334`). Gating AC 20a on `OBL-OCCURRENCE-PROJECTION` instead of asserting the property is the rare spec that models its own gap.
- **§4.1's closure is the right call, verified against the artifacts that prove it.** The engine's own comment refuses exactly the escalation the second draft would have permitted (`hermes_runtime_fs.cc:3322-3326`), LLP 0013:1068 requires it, and 0021:688-690 already holds the surface closed. Closure preserves the shipped posture; it breaks nothing that works today.
- **§7.2's invariant-first tiering is correct and the per-stage rule is the real fix.** The denied-and-absent discovered-target cross-product genuinely defeats a flat list; `ELOOP`-below-denial is right; the existence oracle it condemns is real and cited accurately (`hermes_runtime_fs.cc:2010-2028`). 0024 defers to this order with an identical tier table.
- **§1.1's ancestor-inclusive predicate is load-bearing and self-tested.** This repository's own `package.json` declares `workspaces: ["packages/*"]`, so the failure the earlier draft reintroduced is an in-corpus fact; AC 3a's two lockfile variants make the membership clause unfakeable.
- **§2.3's totality repair was necessary and is sufficient.** `Principal::Root` really carries only an `identity` (`model.rs:304`), so the previous locator+digest key genuinely left first-party files identityless.
- **§3 is fully verified**, including every Node claim by execution.
- **§5's reversal is argued, not asserted**, and §5.3's view-equals-base is the piece that makes the profile closeable.
- **§8's registry claims all check**, including the schema genuinely lacking `session-state`/`session-scoped`/any predicate field.
- **Ledger honesty where it works:** `OBL-MODULE-IDENTITY` self-flags its own stale stamp; `OBL-LEDGER-CHECK` admits no validator exists.

## 3. Concerns

1. **Material — `interim` is an undefined class inside the error order this document owns.** §7.2 states "LLP 0022 mints `out-of-snapshot` and `interim`" and lists `interim` as a tier-2 member. No document defines any such class: 0022 at `88decefdc683` — the exact revision this document stamps — contains the word only as ordinary prose ("in the interim", 0022:1187), and 0024's mirrored tier table lists tier 2 as `out-of-snapshot` alone, so owner and citer already disagree on tier-2 membership. A conformance suite generated from the error-union dataset (AC 24) cannot emit fixtures for a member with no definition. *Resolution:* define, rename, or delete `interim` in both occurrences.

2. **Material — the revision-stamp column fails its own stated purpose for 12 of 23 rows, and two rows behind it are demonstrably stale.** §9 says "the revision stamp is what makes a stale row detectable by inspection," but `code @ b60400977333` resolves to nothing — `git cat-file -t b60400977333` fails; it is the doc's own shasum, not a code revision. Behind the unresolvable stamps: (a) `OBL-TARGET-PROMOTE` reports "LLP 0021 claims macOS/aarch64 is already the sole advertised target" — current 0021 says the opposite ("the macOS candidate remains unadvertised", 0021:8); (b) `OBL-ERROR-ORDER` reports "no" while current 0024 has landed its half. *Resolution:* pin a resolvable stamp convention (`git rev-parse HEAD`), restamp, refresh the two stale rows, make "stamps resolve" the first assertion of `OBL-LEDGER-CHECK`.

3. **Material — `copyFile`'s opening diverges from LLP 0021's current text with no ledger row.** §4.1 quotes 0021:688-690, whose closed list includes "copy," then opens `copyFile` in the same table. Legitimate (0023 is discharging the pendency), but no obligation tells 0021 to move copy out of its closed-fixture set. *Resolution:* a sentence acknowledging the copy divergence plus a ledger row.

4. **Minor/Non-blocking (but of the burned class) — the Node-ESM contrast in §2.3 is false of current Node, verified by execution.** §2.3 states Node ESM "preserves symlinked specifiers, splitting them." Executed on Node v25.9.0: default ESM **resolves** symlinks — `import` of `self.mjs` and a symlink `selflink.mjs` yields one instance; the split appears only under `--preserve-symlinks`. The design is unaffected (divergence shrinks), but this is an unexecuted claim about an external system, in the section whose text says "Fixtures pin each of these," in the document that has twice recorded exactly this failure mode. *Resolution:* correct to "like Node CJS and like default Node ESM; unlike ESM under `--preserve-symlinks`."

5. **Minor — duplicated paragraph in §7.2.** The "native `fs.open` branch today…" paragraph appears twice, nearly verbatim. *Resolution:* delete one.

6. **Minor — row 7's note reads against its own position in the pinned order.** The table orders outside-mount (4), synthetic-node (5), alias-collision (6) ahead of closed-operation (7), yet row 7's note says closure happens "before any path work." *Resolution:* state row index is total precedence and reword the note.

7. **Minor — stale-session's tier placement vs "beats everything."** AC 24 says stale-session beats everything, but the class is tier-3 row 1. *Resolution:* a note that session liveness precedes all tiers, or a tier-0.

8. **Minor — `process.execArgv` row is internally incoherent.** §6 dispositions it `closed` while its value cell cites "the registry's `sys:read` classification" — and the registry classifies it as an authorizable effects edge, not closed. Its value is flags, not paths, so the honest disposition is likely `non-path`. *Resolution:* pick one consistent with the registry.

9. **Minor — stdin-mode argv "as Node" is imprecise, verified by execution.** Node's stdin-with-arguments form is `node - args…`, which puts `-` at `argv[1]` with user arguments from index 2. *Resolution:* mirror Node's `-` convention or drop "as Node" for that row.

10. **Minor — `SourceId`'s path component is named but never constructed, and one consequence is unstated.** "Binding-relative lexical-canonical path" must mean the retained object's canonical physical location spelled without volume canonicalization, but the text never says so. Consequence: on a case-aliasing volume, two case spellings of one file are one authorization identity but could be two `SourceId`s — Node-ESM-style double instantiation. *Resolution:* a one-line constructor plus a sentence on case aliases.

11. **Minor — the §1.1 fallback can select a stop boundary as the project root.** If the discovery origin *is* the home directory, step 5 mounts all of `$HOME` as `/project`. *Resolution:* when origin == a stop boundary, require `--project` or emit a distinct wide-mount diagnostic.

12. **Minor — `readlink`'s return form is under-pinned.** §6 dispositions it `virtual-relative`/`refused`, but a link storing an absolute in-namespace target presumably reads back virtual-absolute. *Resolution:* pin stored-relative → virtual-relative and stored-absolute → virtual-absolute.

## 4. Cross-document findings

- **0024 → 0023, landed and consistent (positive):** current 0024 deletes its restated order, defers to §7.2 by name, mirrors the four tiers exactly — except `interim` (Concern 1). Its source-identity table, `ibex:stdin`-as-sole-synthetic-module, and §7.9 defer-without-inline-tuple posture all match 0023. 0023's ledger has not caught up (Concern 2).
- **0022 → 0023, one stale row:** 0022's `OBL-STARTUP-DIAG` still reports "LLP 0023 §1.2 mandates a symbolic package locator" — current 0023 mandates the opposite (name the host root), and correctly identifies 0025's symbolic sentence as that document's own choice, which 0025:786-787 confirms verbatim.
- **0023 → 0022, `interim`:** Concern 1 — 0023 attributes a class to 0022 that 0022 does not define.
- **0023 → 0021, copy:** Concern 3.
- **0025 seams verified clean:** worker replacement genuinely open there, and 0025's `ProjectHistoryScopeId` deliberately avoids 0023's retained-object locality rule — both documents describe each other accurately.

## 5. Suggestions

- **Make the ledger self-verifying now, cheaply:** a script that stamps rows with `git rev-parse HEAD` + doc shasums and a CI check that every stamp resolves. That single assertion would have caught Concern 2 mechanically.
- **Name the concrete cost of §4.1 in Consequences:** the temp-file-plus-`rename` atomic-write idiom and `unlink` cleanup — pervasive in real Node code — fail with `EPERM` in armed v1. Consumers should meet the breakage in Consequences, not in production.
- **Row 5's `EINVAL` sits oddly against "novel conditions get novel codes"** — consider `ERR_IBEX_SYNTHETIC_NODE`.
- **Pin denial semantics for every boolean probe**, not just `existsSync`-on-outside-mount.
- **OQ 10 deserves a fast answer:** `os.devNull` is `/dev/null` today; the reserved-synthetic-sink looks strictly better than a refusal and needs no second mount.
- **Record `--project` overrides as their own marker kind** in the discovery record.

## 6. Open questions

1. Is the resolver's admissible specifier universe pinned anywhere such that `SourceId` totality is checkable — e.g., are `data:` URLs refused, by which tier?
2. When a second mount exists, does tier 2 survive for specifiers whose snapshot membership depends on which mount a referrer sits in?
3. Case-aliased spellings of one file: one instance or two — and if two, recorded as an accepted wart?
4. Does the per-stage rule apply verbatim to recursive `watch` and `readdir`-driven traversal, where "each path the resolver touches" is a stream?
5. For `OBL-OBJECT-GENERATION`: is the retained-descriptor fallback's cost measurable enough that it should be settled before AC 18's fixture is written?

## 7. Readiness verdict

Three material items stand: the undefined `interim` member in the owned error order, the unresolvable ledger stamps with two stale-favorable rows behind them, and the un-ledgered `copyFile`/0021 divergence — plus one refuted Node claim that is cheap and, given this document's history, obligatory to fix. All are shallow edits; none touches the architecture, which I verified against the code and registries and believe is sound and implementable as specified.

VERDICT: NOT READY

### Orchestrator verification notes

Re-checked against the repository at `ab8658a68b57`.

**Confirmed:**

- **C2 (ledger stamps unresolvable). Confirmed by running `git cat-file`.**
  `b60400977333` is the document's own shasum; `git cat-file -t b60400977333`
  fails. The staleness detector I built in round 4 was itself unverifiable — the
  exact "attestation without a resolvable content hash is not an attestation" failure
  the corpus converged on. Both stale rows confirmed: 0021 now says the macOS
  candidate "remains unadvertised" (`0021:8`), and 0024 (`88ebc6349bab`) has landed
  "LLP 0023 §7.2 owns the total order … this document does not restate it". Restamped
  with `git rev-parse` (`3060574776a3`); "stamps resolve" is now `OBL-LEDGER-CHECK`'s
  first assertion.
- **C1 (`interim` undefined). Confirmed** — `grep -in interim` on 0022 returns one
  hit, ordinary prose. I imported a nonexistent class into a table I own. Deleted.
- **C4 (Node-ESM false claim). Confirmed by execution**, independently of Codex's
  identical run: default ESM evaluates a symlinked specifier once (`a === b` true),
  the split needs `--preserve-symlinks`. **Fourth false Node claim in five rounds**,
  every one adopted from a reviewer without running Node — including, this round, one
  I *myself* introduced (the round-3 `%5C` claim). A borrowed empirical claim is a
  rumor with a citation. Corrected; the pattern is named once in §3.
- **C3, C5–C12.** All confirmed and fixed, or folded into the round-5 scope decision.

**Refuted / corrected:**

- Nothing material. This review's verdict framing ("shallow edits, architecture
  sound") is correct **as far as it goes** — but the concurrent Codex review found a
  genuine *blocking* authority defect this review did not (a pre-existing
  cross-package hard link plus open writes lets B mutate A's source), verified in the
  decision core. "The architecture is done" is true of the *namespace/identity*
  architecture; the *write-authority* model still had a hole. I weight the security
  finding decisively and did not let this review's milder verdict lower the bar.

**Disposition:** Accepted on C1–C12. Where this review is milder than the concurrent
Codex review, the security finding governs.

---

## Round 6 — 2026-07-12  (Fable half; Codex half held pending human cost decision)

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable`; fresh subagent spawned by the orchestrating `/llp-super-refine`
  run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly
  overridden.
- **Date:** 2026-07-12
- **Revision under review:** `a77e5a385f6a` (`shasum -a 256`, first 12).
- **Redacted:** No.
- **Independence:** Fresh subagent; no orchestrator context, no access to any prior
  LLP 0023 review artifact (rounds 1–5 stashed out of `llp/reviews/` for the
  duration), and no access to the Codex round-6 review — **which has not run.**
  This is the **Fable half** of round 6: the round-6 Codex review was *held* by the
  orchestration before launch, pending a human decision on continued spend. This
  half is recorded because the review genuinely happened; the round is **not
  reconciled** on one reviewer, and the target document is held unchanged at
  `a77e5a385f6a` so the eventual Codex half pairs against the identical revision.
- **Method:** subagent, round-6 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round6.md`), carrying the "prefer
  running artifacts to reading them" rule — which this review acted on (it executed
  Node for every compatibility claim and read the decision core for the security
  findings). **First READY verdict in six rounds.**

### Verbatim review

# Review: LLP 0023 — Virtual Filesystem Namespace and Path Identity (rev `a77e5a385f6a`, round 6)

## 1. Overall assessment

This revision is ready. I verified the document the way its own history demands — by running artifacts rather than reading prose — and the load-bearing claims all held. Every Node-compatibility claim I tested is true on Node v25.9.0 (I executed Node for each: `%5C` decode / `%2F` refusal / backslash round-trip / dot-segment collapse; CJS realpath-keying that unifies symlinks and splits hard links; default-ESM symlink unification with `--preserve-symlinks` splitting; ESM query-string instance splitting with repeat reuse; `node - args` placing `-` at `argv[1]`; `-e` args at index 1; `path.resolve("") === cwd()`; and — new this round — the case-alias ESM double-instantiation on a case-insensitive volume, which is real: two instances, and `realpathSync` does not case-canonicalize). Every security-critical code citation resolves to code that says what the document claims, including the two round-5 findings: the `protectedObjects` guard matches by exact object identity (`crates/capsec-semantics/src/decision.rs:946-958`) over a one-element list containing only the project-root object (`src/bin/ibex/runtime.rs:1948-1952`), so the §4.2 hard-link write-through hole was live; and the shipped host already answers imports from the caller's own import set (`src/host/mod.rs:1377`), so §7.2's caller-view rule for `out-of-snapshot` is implementable and the existence oracle is genuinely closed at the spec level. The ledger's code stamp `3060574776a3` resolves (`git cat-file -t` → `commit`; it is HEAD), and the 0022 stamp `88decefdc683` equals 0022's current shasum.

The round-5 scope narrowing is the right move and the argument for it is honest: two consecutive drafts specified multi-operand mutation unsafely, and closing the whole surface at the public entry point converts an unprovable protocol into a provable denial. What remains is a set of small, clearly bounded editorial and precision defects — a leftover sentence the round-5 fix missed, an unreconciled reserved-sink carve-out, stamp-convention gaps on same-repo sibling rows — each of which is already covered by a control the document itself specifies (dataset totality, AC 22, `OBL-LEDGER-CHECK`). None is a material correctness, coherence, feasibility, safety, or decision-quality defect.

## 2. Strengths

- **§4.2 closes a verified, live authority defect with the right shape of rule.** I confirmed the premise end-to-end: exact-inode matching (`decision.rs:946-958`), project-root-only protection (`runtime.rs:1948-1952`), open single-path writes (§4.1), and the admitted hard-linking store (§1.2). The immutability rule (all package subtrees, all principals, package's own included) closes the escalation for every in-model actor, because the only runtime route to a *new* alias is already closed by §4.1, and a pre-armed adversarial alias implies pre-armed project write access, which defeats the model regardless. The rule's cost accounting (scratch space → OQ 2's state mount; first-party source stays writable) is honest, and `node_modules/.cache`-style directories, being no package's root, stay writable — so real-world breakage is narrower than it first appears.
- **§2.2 is the best section in the corpus.** The demonstration that `LogicalRoot` is payload-free (`model.rs:575-581`), that the mapping strips the prefix and discards the owner (`arming.rs:214-218`), and that the owner gate compares the authority's declared owner against the principal under test rather than against the binding the resource was mapped under (`decision.rs:1129-1139`) is exactly right — I read all three and the sibling-grant confusion is real. The document neither claims the fix is shipped nor hides the wire change (single resource per effect, `model.rs:1421`; unpaired cache key, `cache.rs:49-61`), gates AC 20a on the obligation, and states the nested-binding exception instead of leaving it implicit.
- **§7.2's invariant-first error order.** Deriving the tiering from one sentence ("no class that discloses existence may precede an authorization decision that would have denied the caller"), demoting resolution failure and dependency-TLA to tier 4, deciding `out-of-snapshot` from the caller's authorized view (verified implementable at `host/mod.rs:1377`; the snapshot carries both the global graph and per-principal authority, `armed-snapshot.schema.json:211`/`:303`), and making rows 8/9 a per-stage phase rather than fixed slots — this is the correct structure, and the shipped `fs.open` counterexample (`hermes_runtime_fs.cc:2010-2027`, authorization only after open/fstat) is accurately cited as non-conforming.
- **§2.3's identity algebra is now total and Node-anchored.** The single `(runtime, SourceId)` key shape, the project arm (fixing the previously undefined most-common case — `Root` carries no locator/digest, `model.rs:304`), the lexical-canonical path component with its stated case-alias consequence (which I verified matches Node ESM by running it), and the script-input/module distinction aligned with 0024 §7.9 — all coherent.
- **§1.1's discovery algorithm is pinned to the point of being executable**, with the ancestor-inclusive membership predicate self-tested against this very repository (`package.json` `workspaces: ["packages/*"]` — verified), fail-closed glob handling, stop boundaries, and the digest-bound marker-set version.
- **§6's totality mechanism** — the `non-path` member plus the independently generated output-shape catalog — correctly diagnoses that the coverage schema knows only `{kind, name}` (verified: `coverage-edge.schema.json` has no field/return-shape/alias vocabulary), so a registry-joined dataset cannot prove its own completeness. The registry corrections are all real as claimed: `export:node_path:resolve`/`relative` are `non-capability`/`pure-in-memory-compute`; `process:cwd` is `deny-only`/`shared-process-mutation` (`definitions[19]`); the cwd read edge carries `positiveSources: ["ambient-root","static-floor"]` with `sys:read` authorable/`staticOnly: false`; `capability-definitions.schema.json` has no `session-state`, `session-scoped`, or predicate vocabulary; `advertisedTargets: []` with the macOS candidate.
- **The ledger is now mostly a real detector.** Code stamps resolve; the 0022 stamp is current; the two rows refreshed in the favorable direction (`OBL-TARGET-PROMOTE` vs `0021:8` "remains unadvertised" — verified consistent; `OBL-ERROR-ORDER` 0024-half landed — verified at 0024's *current* revision, line 343: "LLP 0023 §7.2 owns the total order … this document does not restate it").

## 3. Concerns

1. **Residual `interim` attribution — the round-5 deletion was applied incompletely.** Severity: **Minor/Non-blocking.** Evidence: line 1464 still reads "LLP 0022 mints `out-of-snapshot` and `interim`," while lines 1516-1519 correctly state that LLP 0022 defines no such class (verified: `interim` appears in 0022 only as ordinary prose, its line 1187) and the revision header (line 36) claims the class "is deleted." The tiering itself is clean; the intro sentence is the leftover. Resolution: delete "and `interim`" from line 1464.
2. **§6 table carries duplicated rows with ambiguous per-field dispositions.** Severity: **Minor/Non-blocking.** Evidence: `module.id/.filename/.path/.parent/.children` appears at line 1304 as `virtual-absolute / closed` and again at line 1322 (with `.paths` and `__exactPackageRoot`) as `virtual-absolute / refused`; `Dirent.parentPath`/`Dirent.path` appears at lines 1311 and 1321. The `x / y` alternatives notation never says which field takes which disposition — in the one table whose entire argument is per-field totality. The generated dataset would fail on a duplicate key, which is the designed control, but the normative illustration should not need it. Resolution: merge the duplicates and give each field exactly one disposition.
3. **The `os.devNull` reserved sink is not reconciled with §3's containment rule.** Severity: **Minor/Non-blocking.** Evidence: §3 (lines 760-765) refuses "any child of `/` that is not a mount name" as outside-mount; §6's row (line 1316) makes `/dev/null` a synthetic sink with a no-effect write branch. `/dev` is not a mount, so a §3-literal implementation refuses what §6 requires. Reads, `stat`, `open` modes, and `readdir("/")` visibility of the sink are unpinned, and no AC exercises it (AC 22 asserts the row generically; AC 4 pins `readdir("/")` as "exactly the mount table"). Both readings are safe, so this is coherence polish, not a hole. Resolution: add the reserved-sink exception to §3 beside the synthetic-root branch, pin its non-write operations, and state whether `readdir("/")` lists it.
4. **The ledger's own stamp convention is not applied to the same-repo sibling rows.** Severity: **Minor/Non-blocking.** Evidence: §9's preamble mandates resolvable stamps ("code-side rows … with a `git rev-parse` commit … sibling-side rows with the sibling's shasum"), yet `OBL-OBJECT-BOUND-MUTATION` stamps `0021 @ 688-690`, `OBL-ABI-HANDLE` `0002 @ 26-46`, `OBL-HOST-SESSION` `0002 @ 21`, `OBL-ARMING-CONTAINMENT`/`OBL-TARGET-PROMOTE` `0021 @ current`, `OBL-LEDGER-CHECK` `ref-check @ current`. Line numbers and "current" are not content hashes; "every stamp resolves" — the row's own first assertion — fails on them today (0021's shasum is `daa9a6823b00`, 0002's `020f3455209e`; both were one command away). Resolution: stamp the 0021/0002/ref-check rows with shasums like the 0022/0024 rows.
5. **The argv table's summary sentence undercounts its own divergences.** Severity: **Minor/Non-blocking.** Evidence: line 1339 says "The only divergence from Node is `argv[0]`," but the program-stdin row (line 1334) itself records a second, correctly labeled divergence — Ibex omits the `"-"` Node places at `argv[1]` (verified by running `echo … | node - foo bar` → `[node, "-", "foo", "bar"]`). Resolution: reword to "the only divergence *common to every mode*…" or enumerate both.
6. **§4.2/`OBL-PACKAGE-IMMUTABLE` should pin the protection's matching semantics.** Severity: **Minor/Non-blocking** (the intent is unambiguous; the letter should match). Evidence: the shipped mechanism matches parent/final *object identity* (`decision.rs:951-958`), which cannot express a subtree — a deep write's parent object is an interior directory, not the binding root — so the extension necessarily changes the matcher's kind, not just its list length. The obligation row (line 1734) names the target ("every package binding's subtree") but not the decision basis: requested-stage lexical containment of the projected path within the binding's authenticated virtual subtree (which covers *creates* of new files inside a package root — the planted-module case — since the object does not exist yet), plus commit-stage verification. AC 7a covers only the hard-link write and the first-party-writable converse. Also worth one sentence each: workspace-member packages are package principals, so their source becomes runtime-immutable to the developer's own tooling; and the pre-existing outside-alias residual is out of the armed threat model (pre-arm project write access already defeats root's code). Resolution: one paragraph pinning the matching basis and the create case, one AC 7a clause for a create inside a package subtree, and the two consequence sentences.
7. **The 0024-side stamps are stale (honestly, per the convention).** Severity: **Minor/Non-blocking.** Evidence: `OBL-MODULE-IDENTITY` and `OBL-ERROR-ORDER` are verified at `0024 @ 88ebc6349bab`; 0024's current shasum is `5a355080fbfd`. I re-verified both claims at the current revision: §7.9 still defers ("Module identity is LLP 0023 §2.3's… does not restate the mechanism", 0024:1524), the §2 order deferral stands (0024:343), and AC 15's plural "synthetic sources of §2" imprecision persists exactly as the ledger notes (0024:1973). This is the "outdated, honest, detectable" state the convention anticipates. Resolution: refresh the stamps at next touch.

## 4. Cross-document findings

- **0022 §4 contradicts 0023 §4.1/§7.2 on `fs.watch` (0022-side staleness).** 0022 line 473 lists "watches" among effectful operations that yield the outside-mount error for habitual host spellings; under 0023, `watch` is a closed operation refused `EPERM` "before any path work" (row 1 precedes row 4), so `fs.watch("/etc/passwd")` cannot produce outside-mount. 0023 owns the order (`OBL-ERROR-ORDER`); 0022 predates the round-5 watch closure. Needs a one-word 0022 edit (drop "watches") or a coordinated note.
- **0022 §11 `OBL-STARTUP-DIAG` describes a conflict that no longer exists.** The row (0022:993) says "LLP 0023 §1.2 mandates a **symbolic** package locator and attributes that rule to LLP 0025" — that was the pre-round-5 0023. Current 0023 §1.2 reverses it (names the host path), 0022 §4 already exempts pre-evaluation CLI diagnostics, and 0025 §9 (line 891-893) explicitly disclaims imposing the rule, applying its symbolic choice only to its own legacy-history notice "on its own grounds." The three positions have collapsed into agreement; the row is stale in the favorable direction and should be re-verified/retired on the 0022 side.
- **0023 line 1464 mis-attributes `interim` to 0022** (concern 1 — the only 0023-side sibling-claim defect I found, and the document's own later paragraph already refutes it).
- **0023's `OBL-ERROR-ORDER` marks 0022's half outstanding, but current 0022 contains no restated total order** that I could find — only class-distinctness statements (§2) and one pairwise claim ("outside-mount — not `ENOENT`," §4) consistent with 0023's rows. Stale in the safe direction; possibly already dischargeable.
- **Confirmed-consistent seams (both directions):** 0024 §2/§3/§7.9/AC 3/AC 15/OQ 10 against 0023 §2.3/§7.2 (including the "unifies to one identity" phrasing, which is correct for symlink aliases, with the case-alias split and open display-spelling question matching 0023 OQ 7/OQ 10); 0024's token-vs-handle vocabulary against 0023 §7.1's "session tokens cross a process boundary"; 0022 §1's `require.cache`/`runtime:inspect` closure, §7's bridge-inventory ownership, and §8's `.load` referrer against 0023 §6/§7.3; 0025 §9's refusal to borrow 0023's retained-object record and its nonce-bound equality proof honoring §7.1's locality rule; 0023's worker-transfer row correctly citing 0025's open worker-replacement question (0025 OQ 5). LLP 0021:8, 0021:318, 0021:678/688-690, 0013:1068, and 0002:19-46 all say what 0023 cites them for (read directly). The governing LLPs contain no references back to 0023, so no reverse staleness exists there.

## 5. Suggestions

- Fold the concern-6 sentences into §4.2 now; they are cheap and they close the last interpretive freedom in the one rule added this round.
- §1.1's fail-closed glob rule will refuse arming for real repos using brace patterns (`packages/{a,b}` is common in yarn/pnpm configs). The `--project` remedy is stated, but consider naming braces in the malformed-marker diagnostic so the operator learns the *why* in one line.
- Pin the macOS generation attribute's real name once (`ATTR_CMN_GEN_COUNT`); the document currently spells it two ways (`ATTR_CMNGEN` §2.3, `ATTR_CMN_GEN` §9), neither the actual constant.
- `readlink`'s deepest-existing-ancestor walk for dangling links performs existence probes over host ancestors; a sentence noting those probes are internal to the staged translation and disclose only the one refused/translated bit (safe in v1 because link *creation* is closed, so stored bytes are not runtime-attacker-chosen) would make §4 airtight.
- OQ 6 (ship the strict cwd profile as v1 default?) deserves resolution before implementation of `OBL-CWD-FLOOR`, since the floor's very existence is what OQ 6 would delete.
- When AC 22's fixture generation lands, have it also assert the *absence* of duplicate `(surface, field, alias, mode)` keys in the dataset — that converts concern 2's class of error into a build failure permanently.

## 6. Open questions

- Does the future `/state` mount (OQ 2) need to land in the same release as `OBL-PACKAGE-IMMUTABLE`, given §4.2 removes the only writable location some shipped packages assume? The document treats them as independent; real-workload evidence might not.
- Should `SourceId`'s case-alias split (two instances on an aliasing volume) be surfaced as a diagnostic when it actually occurs, rather than waiting for OQ 3/OQ 10's resolution? Node's silence here causes rare, deeply confusing state-duplication bugs; Ibex is positioned to do better cheaply.
- The operation lease (§7.1) captures "the decided facts" — when a stage's decision is taken on the runtime thread but the effect executes on a worker after teardown began, which of lease generation and session generation wins is stated (teardown records committed work), but the boundary between "queued" and "committed" for a multi-stage §4 traversal could use one sentence when `OBL-HOST-SESSION` is designed.
- Should `OBL-LEDGER-CHECK`'s "every stamp resolves" assertion also require stamps to be *current* for rows marked landed/aligned (as 0025 §11 now does with digest-mismatch-invalidates), not merely resolvable? The 0024 rows this round show why the distinction matters.

## 7. Readiness verdict

Every serious claim I could execute, I executed, and all held; the defects that remain are enumerated above, are individually one-sentence-to-one-paragraph fixes, and each is already backstopped by a control this document itself specifies. A spec is allowed to be finished.

VERDICT: READY

### Orchestrator verification notes

I spot-checked the review's decisive claims against the repository at `a77e5a385f6a`.
This is the **Fable half of round 6**; the Codex half is held, so the round is
**not reconciled** and the target is unchanged. The verdict is recorded, not acted on.

**Confirmed:**

- **Concern 1 (`interim` leftover). Confirmed, and it is a genuine incomplete fix of
  mine.** Line 1464 still reads "LLP 0022 mints `out-of-snapshot` and `interim`,"
  while my round-5 addition at line 1516 says 0022 defines no such class and the
  revision header (line 36) claims the class "is deleted." The document contradicts
  itself and the header overclaims. `grep -n interim` on 0022 returns a single
  ordinary-prose hit. Real, Minor, mine to fix in the reconciliation.
- **Concern 4 (sibling stamps not shasums). Confirmed.** Lines 1733/1735/1736/1743/
  1751/1752 stamp `0021 @ 688-690`, `0002 @ 26-46`, `0002 @ 21`, `0021 @ current`,
  `ref-check @ current` — line numbers and "current," not content hashes, so "every
  stamp resolves" fails on the rows I wrote it for. The real shasums (0021
  `daa9a6823b00`, 0002 `020f3455209e`) were one command away, which I have now run.
- **Concern 7 (0024 stamps stale). Confirmed, and drifting fast** — the reviewer saw
  0024 at `5a355080fbfd`; it is already `6416ccb8c3c2` as I write this. The claims
  still hold at the current revision; the stamps are honestly-outdated, which is the
  convention working as designed.
- The verdict's **decisive security spot-checks** (exact-inode guard at
  `decision.rs:946`, project-root-only protection at `runtime.rs:1948`, caller-view
  imports at `host/mod.rs:1377`) match what I independently verified in round 5.
- The reviewer **executed Node** for every compatibility claim, including the
  case-alias double-instantiation new this round; consistent with my own runs.

**Refuted / corrected:** nothing. Every concern is real; none rises above Minor.

**Disposition:** The Fable verdict is **READY** — the first in six rounds — with seven
Minor/Non-blocking residuals, all of which match the orchestrator's own pre-review
readiness-note prediction (no new Blocking; a handful of completeness/precision
items). Because convergence requires **both** reviewers READY on the **same**
revision, the round is held open for the Codex half against `a77e5a385f6a`. If that
half runs and also returns READY, the seven residuals here plus any Codex residuals
are reconciled in one pass and Status advances Draft → Review; if the effort is
halted first, this half stands as an honest record and Status remains Draft.

---

## Round 7 — 2026-07-12  (Fable half; Codex half held pending human continue/stop decision)

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable`; fresh subagent spawned by the orchestrating `/llp-super-refine`
  run. Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool; not explicitly overridden.
- **Date:** 2026-07-12
- **Revision under review:** `ed6599c16ea9` (`shasum -a 256`, first 12).
- **Redacted:** No.
- **Independence:** Fresh subagent; no orchestrator context, no access to any prior
  LLP 0023 review artifact (rounds 1–6 stashed out of `llp/reviews/` for the
  duration), and no access to the Codex round-7 review — **which has not run.** This
  is the **Fable half** of round 7: the Codex half is *held* pending a human decision
  on continued spend. Recorded because the review genuinely happened; the round is
  **not reconciled** on one reviewer, and the document is held unchanged at
  `ed6599c16ea9` so the eventual Codex half pairs against the identical revision.
- **Method:** subagent, round-7 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round7.md`), carrying the
  "prefer running artifacts to reading them" rule — which this review acted on: it
  verified the ledger stamps by their named methods, ran Node v25.9.0 for every
  compatibility claim, read every cited code line, and evaluated the registry/schema
  JSON with `python3`. **Notably: "for the first time in this document's history,
  every empirical claim I could test survived execution."**

### Verbatim review

# Review: LLP 0023 — Virtual Filesystem Namespace and Path Identity (revision `ed6599c16ea9`, round 7)

## 1. Overall assessment

This revision is the strongest state the document has been in, and — unusually for this document's history — **every empirical claim I tested held**. I verified the ledger's five revision stamps by their stated methods (`git cat-file -t 3060574776a3` → `commit`; all four `sha256:` prefixes recomputed with `shasum -a 256` match the sibling files exactly, and both `git cat-file -t 88decefdc683` / `6416ccb8c3c2` fail exactly as §9 predicts). I ran Node v25.9.0 against all six load-bearing Node claims (default-ESM symlink unification, `--preserve-symlinks` split, CJS hard-link split + realpath keying, ESM query/fragment instance split, `%5C` decode / `%2F` refusal / backslash round-trip, `node -` argv layout, `%2e%2e` collapse-at-parse) — all correct. I read every cited code line: the §4.2 premise (`ProtectedObjectGuard` is a single exact object, `decision.rs:114-117`, matched by identity at `:946-958`; the armed snapshot installs exactly one project-root guard, `runtime.rs:1948-1952`), the §2.2 evaluator account (payload-free `LogicalRoot` at `model.rs:575-581`, prefix-strip at `arming.rs:214-218`, owner gate at `decision.rs:1136-1139`, single-projection call at `mod.rs:334`, unpaired cache resource at `cache.rs:49-61`), the §2.1 claim (`object_state` mandatory at `model.rs:1277`, `ObjectState::Existing` hardcoded at `abi.rs:1058-1062`), the §7.2 oracle claims (`require.resolve` bypasses `checkImportGate` — gate at `module-loader.js:5762` for `require`, absent from `require.resolve` at `:5788`; `resolve_module_meta`'s own doc-comment says it stats and reads `package.json`, `mod.rs:1425-1435`; the native `fs.open` branch opens parent, opens target, `fstat`s and checks `S_ISREG` before its first typed decision), the §4.1 evidence (both name-bound `unlinkat` rollback sites live in the shipped mkdir at `hermes_runtime_fs.cc:~731/~741`; the hard-link `fs:write`-on-SOURCE comment at `:3318` verbatim), and the registry/schema claims via `python3` (deny-only `process:cwd` at `definitions[19]`, `sys:read` authorable/`staticOnly:false`, `node_path` resolve/relative misclassified `pure-in-memory-compute`, `advertisedTargets: []`, no `session-state`/`session-scoped`/predicate vocabulary in the capability schema, no field/shape vocabulary in the coverage-edge schema). The `false &&` dead block in `url.js` spans lines 164–315 and contains the `%5C`-refusing `fileURLToPath` variant, exactly as the round-2 history records; the live export decodes `%5C` on POSIX.

All six round-6 reconciliations are, in my judgment, genuinely repaired: the two-guard §4.2 mechanism is grounded in what the shipped guard can and cannot represent; the mkdir no-rollback rule correctly deletes a real verify-then-`unlinkat` TOCTOU; the resolve-only-bridge gate closes a verified existence oracle; `SourceId`/`SourceLabel` are now total and pinned (with one precision gap noted below); `os.devNull` is honest; the stamp convention finally passes its own test.

What remains is two **material cross-corpus coherence items** — one untracked contradiction with LLP 0021's mkdir text, and the locality carve-out LLP 0025 has formally requested of this document — plus a set of genuinely minor precision and cross-reference issues. Nothing structural, nothing mechanism-level; but under this corpus's own standard ("an obligation that lives only in prose is an obligation that escapes"), the two material items are real and unresolved.

## 2. Strengths

- **§4.2's two-guard split is the correct decomposition, and it is derived from the artifact, not asserted.** The lexical-subtree and exact-object matching problems genuinely cannot share the shipped guard (`decision.rs:114-117` is `{action, object}`; `:946` matches by identity), and the split assigns each threat to the stage where its facts exist: creates (no object yet) to the pre-lookup path guard, hard-link aliases (path outside every package) to the commit-stage object/generation set. Either-fires-denies is the right combining rule. AC 7a tests both guards separately, including deny-before-lookup by syscall observation.
- **§7.2's round-6 catch is real and I confirmed it end-to-end**: `require.resolve` reaches `resolve_module_meta` with no import gate (`module-loader.js:5788` vs the gated `require` at `:5762`), and `resolve_module_meta`'s own comment admits it stats and reads `package.json` during resolution (`mod.rs:1425-1435`). Extending the tier-2 gate and no-probe rule to every resolve-only route (`OBL-RESOLVE-GATE`, AC 19r asserted by syscall observation) closes a genuine oracle.
- **§2.3 is now empirically clean.** After four false Node claims in prior rounds, every Node statement in this revision survives execution — including the two hardest (default ESM unifies symlinks; query/fragment splits instances, making the strip a correctly-labeled divergence). The section also names the failure pattern once, which is the right amount.
- **§2.2 is the most precise account of the shipped projection defect I have seen in this corpus** — every clause (payload-free root, prefix-strip, owner-gate-against-principal-under-test, one projection call, unpaired cache resource) matches the code exactly, and the document refuses to claim the containment property until `OBL-OCCURRENCE-PROJECTION` lands, gating AC 20a explicitly on it. That honesty discipline (also `OBL-OBJECT-STATE`, the `SourceId` obligations, "AC cannot pass against the code today") is exemplary spec practice.
- **§4.1's default-closed mutation surface with the mkdir no-rollback rule** is the right trade, and the shipped rollback it deletes is verifiably the TOCTOU described (two name-bound `unlinkat` sites in `hermes_runtime_fs.cc`). The Consequences section names the real consumer cost (write-temp-then-`rename` returns `EPERM`) rather than hiding it.
- **§1.1's discovery algorithm** is pinned to the level a boundary decision needs — one glob dialect, ancestor-inclusive membership with this very repository as the would-have-failed case, malformed markers as arming errors, home/device stop boundaries.
- **§9's ledger stamps finally pass their own test.** The `commit:`/`sha256:` split is the correct model, and I verified all five stamps resolve by their named method — a fitting close for a convention this document itself fixed twice.

## 3. Concerns

**Concern 1 — LLP 0021's mkdir text still promises the rollback §4.1 deletes; no obligation tracks the contradiction. [Material]**
Evidence: §4.1 (`0023:1090`) makes non-recursive mkdir "one atomic `mkdirat` … and nothing more … no rollback." But LLP 0021 (`0021:678-686`, which I read) currently specifies mkdir as: "authorize the requested path, retain and verify the parent, preauthorize absent creation, create with `mkdirat`, and commit the opened directory identity, **rolling the new directory back if commit fails.**" The shipped code (`hermes_runtime_fs.cc` mkdir, two `::unlinkat(..., AT_REMOVEDIR)` sites) implements 0021's version, not 0023's. So 0023 now contradicts its governing plan on a shipped behavior, and — unlike the `copyFile`/`copy` case, which §9's `OBL-OBJECT-BOUND-MUTATION` explicitly flags ("LLP 0021 currently lists `copy` in its closed set … a reopening must move it there in the same change") — **no ledger row records this mkdir divergence.** The document's own doctrine is that an untracked cross-document contradiction is exactly what the ledger exists to surface.
Resolution criterion: either add the mkdir-rollback retirement to an obligation row targeting LLP 0021 (parallel to how `copy` is handled), or cite 0021's mkdir line in §4.1 and state that 0021 is amended in the same change. One sentence and one stamped row.

**Concern 2 — `OBL-HISTORY-LOCALITY` is a live inbound dependency from LLP 0025 that §7.1 does not yet discharge. [Material]**
Evidence: LLP 0025 §9 (`0025:1033`, `OBL-HISTORY-LOCALITY`) states that its `ProjectHistoryScopeId` nonce-bound equality proof "relies on LLP 0023's worker-locality rule permitting a *derived, non-rehydratable* comparison value to cross the boundary," and records: "**0023's parenthetical enumerating by-design crossings does not yet name it**; one line there (or an explicit acknowledgement) closes the seam." I checked §7.1's "Worker locality" paragraph (`0023:1533-1541`): its by-design-crossings parenthetical names "evaluation outcomes, display trees, and broker events … per LLP 0024 and LLP 0025" — and does **not** name a derived history-scope equality-proof digest. So the seam LLP 0025 explicitly asked 0023 to close is still open on 0023's side, and 0023 carries no obligation row pointing back at it (the ledger has `OBL-BRIDGE-PROJECTION` toward 0022 but nothing toward 0025). This is a dangling dependency in the direction the task asks me to check.
Resolution criterion: add the history-scope equality-proof digest to §7.1's list of authorized boundary crossings (it is a derived, non-rehydratable comparison value, so it fits the rule) — or add a ledger row acknowledging and scoping it. LLP 0025 has told you the exact remedy.

**Concern 3 — `SourceLabel`'s hard-link tie-break says "lexically least" but does not pin the collation, leaving a determinism gap the section elsewhere closes. [Minor/Non-blocking]**
Evidence: §2.3 (`0023:715`) resolves a hard link's canonical spelling to "the entry within the defining principal's binding, and if several qualify, the **lexically least** — a total, load-order-independent choice." But "lexically least" over component vectors is only total once the comparison unit and ordering are fixed (byte-wise over UTF-8? Unicode scalar? per-component then length?). The very same section is meticulous that `SourceId` uses the *lexical* vector precisely because volume canonicalization is "machine-specific" and unportable — yet a locale- or encoding-sensitive "lexically least" reintroduces exactly that portability hazard for `SourceLabel`. Since `SourceLabel` is display-only this is not a safety defect, but the section's own standard is not quite met.
Resolution criterion: pin the collation — e.g. "byte-wise lexicographic over the UTF-8 encoding of the component vector" — in the hard-link bullet.

**Concern 4 — The `SourceId` project arm keys on "authenticated root identity," but the `Root` principal carries only an opaque `identity` string; the arm's stability across re-arming is unstated. [Minor/Non-blocking]**
Evidence: §2.3 (`0023:650, 664`) defines the project arm's principal component as "the authenticated root identity," and correctly notes (verified: `model.rs:310-312`) that `Root { identity: NonEmptyString }` has neither locator nor digest. `SourceId` is also asserted "build-computable and machine-portable" (`0023:690`) so a provenance manifest "must name the same modules on another" machine. Whether the root `identity` string is stable across machines/re-arming is not stated — if it embeds anything host- or session-specific, the first-party arm silently loses the portability the package arm has.
Resolution criterion: state what the root `identity` is derived from and assert its cross-machine stability, or scope the portability claim to the package arm.

**Concern 5 — §6 dispositions `path.win32.resolve` as `non-path` while §8 reclassifies it as a cwd-reading session-state read; the two rows describe the same surface with different effect status. [Minor/Non-blocking]**
Evidence: §6's observables table (`0023:1404`) gives `path.win32.*`/`path.posix.*` string results the disposition `non-path`. §8 (`0023:1776-1789`), correctly and with code backing (`path.js:206` `win32.resolve` reads `_cwd()`; `:298` relative; `:456` toNamespacedPath — confirmed all three), reclassifies them as cwd-reading session-state reads needing the no-effect branch. `non-path` is about *output shape*; the §8 reclassification is about *effect*. Not strictly contradictory, but a reader reconciling the `non-path` label against §8 will find the seam under-explained.
Resolution criterion: note in the §6 `path.win32` row that the surface is `non-path` in *output* but carries the §8 cwd-read effect (the disposition dataset must record both axes).

**Concern 6 — "the reachable helper uses only `currentPrincipalId()` today (`hermes_runtime_fs.cc:570`)" is cited for two different helpers in §4. [Minor/Non-blocking]**
Evidence: §4 step 1 (`0023:969-971`) cites `:570` as "the reachable helper uses only `currentPrincipalId()` today," and step 2 (`0023:977-979`) cites the *same* `:570` as `openArmedLinkTarget`. Both land on the same function — fine for step 2, but makes step 1's general "one projection everywhere" claim over-specific (the single-principal pattern is pervasive: `:128, :182, :221, :539, :575, :621, :704, …`).
Resolution criterion: for step 1, cite the pattern generally rather than pointing at `openArmedLinkTarget` specifically.

## 4. Cross-document findings

- **LLP 0025 → 0023 (Concern 2, Material):** `OBL-HISTORY-LOCALITY` (`0025:1033`) is an inbound obligation whose stated remedy is a line in 0023 §7.1; 0023 has not added it and carries no reciprocal row. Dangling dependency, 0025→0023 direction.
- **LLP 0021 ↔ 0023 (Concern 1, Material):** 0021's mkdir spec (`0021:678-686`) still mandates the rollback 0023 §4.1 deletes; untracked contradiction.
- **0024 ↔ 0023 module-identity phrasing — confirmed still open, correctly ledgered, not re-litigated.** §9's `OBL-MODULE-IDENTITY` row records that 0024's "one instance … across spellings" phrasing contradicts §2.3's case-alias split and that 0024's AC pluralizes synthetic modules. Confirmed 0024 §7.9 (`0024:1556`) still says "however it was spelled" and 0024 AC 15 (`0024:1993`) says "the synthetic sources of §2 are keyed" (plural). 0023 correctly marks these "0024 edits outstanding." **One tightening:** 0024 OQ 10 (`0024:2139`) still says "LLP 0023 leaves the canonical display spelling open" — but §2.3 has now *pinned* `SourceLabel`. So 0024 OQ 10's premise is stale in 0023's favor; worth noting in the `OBL-MODULE-IDENTITY` row as a third outstanding 0024 edit.
- **`.load` credential cardinality — verified consistent.** §9's `OBL-TYPED-READ` cites "LLP 0024's two-capability capsule … *not* LLP 0022's 'one permit.'" Confirmed 0024 §1 (`0024:240`) now specifies "two affine capabilities, not one"; 0022 §7 (`0022:689`) still says "a one-shot permit … consumed exactly once." 0023 cites the correct (0024) side. The 0022/0024 divergence is real but is 0022's to reconcile.
- **Error-order ownership — verified consistent.** §7.2 owns the total order; 0024 §2 (`0024:361-364`) now cites it and 0023's `OBL-ERROR-ORDER` correctly records "0024 half landed, 0022 half outstanding."
- **`OBL-TARGET-PROMOTE` — verified.** 0021:8 "the macOS candidate remains unadvertised"; `policy-rules.json` `advertisedTargets: []`. Consistent.

## 5. Suggestions

- Discharge Concern 2 with the single acknowledgement line in §7.1 that LLP 0025 has literally drafted for you; it is the cheapest possible close of a formally-requested seam.
- Fold Concern 1's mkdir divergence into `OBL-OBJECT-BOUND-MUTATION` or a sibling row, using the exact pattern the `copy`/`copyFile` note already models.
- Pin the `SourceLabel` hard-link collation (Concern 3) — byte-wise over UTF-8 is the obvious choice.
- OQ 2 (writable `/state` mount) and OQ 10 (`/dev/null` sink node) are both now load-bearing for real workloads; consider promoting at least `/state` from "open" to "planned for v2," since §4.2 *creates* the need by closing package-root writes.
- Consider a one-line forward-reference in §6's `path.win32` row to §8 (Concern 5).

## 6. Open questions

- **Is the root `identity` string cross-machine stable?** (Concern 4.) Determines whether the `SourceId` project arm delivers the build-portable-manifest property the package arm does.
- **Does the captured referrer carry stale-identity re-verification?** The document's own OQ 12 — a renamed referrer directory failing a later dynamic `import()` — interacts with §5.2's stale-cwd rule; worth resolving before the referrer-capture fixtures.
- **Does closing all package-root writes (§4.2) plus no writable mount (OQ 2) break real first-party build tooling** that writes into `node_modules/.cache`? The document scopes immutability to "authenticated package source," which may or may not include a package's own `.cache` — worth stating explicitly which side of the line an in-package cache dir falls on.

## 7. Readiness verdict

The mechanism design is sound and, for the first time in this document's history, every empirical claim I could test survived execution. The two material items are both **cross-document coherence gaps, not mechanism defects**: an untracked contradiction with LLP 0021's mkdir text (Concern 1) and an inbound locality carve-out that LLP 0025 has formally requested and 0023 has not yet named (Concern 2). Neither is a correctness, feasibility, or safety error in what 0023 *specifies* — but both are exactly the "obligation that lives only in prose escapes" / "a sibling cites a section that no longer says what it is cited for" failure class this review is charged to catch, and this corpus's own doctrine treats an untracked cross-document contradiction as an invalid state rather than polish. They are each a one-to-two-line fix (a ledger row; an acknowledgement sentence), but until made, the ledger does not reflect the corpus.

VERDICT: NOT READY

### Orchestrator verification notes

I spot-checked the two Material claims against the repository at `ed6599c16ea9`.
This is the **Fable half of round 7**; the Codex half is held, so the round is **not
reconciled** and the target is unchanged. The verdict is recorded, not acted on.

**Confirmed:**

- **Concern 1 (LLP 0021 mkdir rollback contradiction). Confirmed.**
  `llp/0021-capsec-effect-model-migration.plan.md:679-681` still specifies mkdir to
  "commit the opened directory identity, rolling the [new directory back if commit
  fails]" — the rollback §4.1 now deletes as a TOCTOU. `OBL-OBJECT-BOUND-MUTATION`
  handles the parallel `copy` case explicitly but carries no mkdir row. Real,
  Material, cross-doc. A ledger row (or a §4.1 amends-0021 sentence) closes it.
- **Concern 2 (`OBL-HISTORY-LOCALITY` dangling). Confirmed, and LLP 0025 has drafted
  my remedy.** `llp/0025-terminal-session-ownership.spec.md:1076` carries the
  obligation, states that "LLP 0023's by-design-crossings parenthetical does not yet
  name it; one acknowledging line there closes the seam," and (notably) has already
  re-stamped itself against a later 0023 revision confirming the parenthetical is
  still unchanged. 0023 §7.1's crossing list (line 1537 onward) names evaluation
  outcomes, display trees, and broker events — not the history-scope equality proof.
  Real, Material. A single §7.1 acknowledgement line — a derived, non-rehydratable
  comparison value fits the worker-locality rule — closes it.
- **The §4.2-freezes-workspace-code concern the reviewer *nearly filed* correctly
  dissolved under verification** (LLP 0013 Resolved Questions §1: workspace members
  default to the **root** principal, so their source is not under a package binding
  and §4.2 leaves it writable). This is the run-the-artifact rule working in the
  reviewer's favor. Worth a clarifying sentence in §4.2 during reconciliation, plus a
  statement of which side of the immutability line an in-package `.cache` dir falls
  on (the reviewer's OQ).
- The **empirical claims** the reviewer re-ran (ledger stamps by named method; six
  Node claims; the §4.2/§2.2/§7.2 code citations) match my own verification. Notably
  this is the reviewer's own finding that, for the first time, nothing empirical
  failed — consistent with the loop having exhausted the mechanism-level defects.

**Refuted / corrected:** nothing. All four Minor concerns are also real and cheap.

**Disposition:** The Fable verdict is **NOT READY** with two Material cross-doc
coherence items (both one-to-two-line fixes, neither a mechanism defect) and four
Minor. Because convergence requires **both** reviewers READY on the same revision, the
round is held open for the Codex half against `ed6599c16ea9`. These items are recorded
as round-7 reconciliation carry-forwards, to be applied jointly with whatever the
Codex half raises — not on one reviewer, and not while the round is held.

---

## Round 8 — 2026-07-12  (terminal round)

**Provenance**

- **Reviewer family:** Claude (Anthropic), Fable
- **Provider / runtime:** Claude Code Agent tool, `subagent_type: general-purpose`,
  `model: fable`; fresh subagent spawned by the orchestrating `/llp-super-refine` run.
  Orchestrator model: `claude-opus-4-8`.
- **Reasoning effort:** harness default for the Agent tool.
- **Date:** 2026-07-12
- **Revision under review:** `601cb5213dca` (`shasum -a 256`, first 12) — the same
  revision the round-8 Codex half reviewed.
- **Redacted:** No.
- **Independence:** Fresh subagent; no orchestrator context, no access to the round-8
  Codex half, and no access to any prior LLP 0023 artifact (rounds 1–7 stashed out of
  `llp/reviews/` for the duration). This is the **terminal** round, run with human
  authorization to finish.
- **Method:** subagent, round-8 brief verbatim
  (`scratchpad/llp-super-refine/doc-0023/brief-round8.md`). Executed Node for every
  Node claim, `shasum`/`git cat-file` for every ledger stamp, `python3` over the
  registry/schemas, attempted the shipped `ibex` binary, and read every cited code
  line.

### Verbatim review

# Review — LLP 0023: Virtual Filesystem Namespace and Path Identity (round 8, revision `601cb5213dca`)

## 1. Overall assessment

This is a strong, honest, and now substantively correct spec, and the round-8 reconciliation did what it claimed on every point of substance. I verified the round-7 repairs against the artifacts rather than the prose — ran Node for every Node claim, ran `shasum`/`git cat-file` for every ledger stamp, ran `python3` over the registry and schemas, attempted to run the shipped `ibex` binary, and read every cited line of shipped code — and the substance holds throughout: `Exact.resolve` really is a `path.resolve` delegate, `resolve_meta` really does read ESM bodies under an `fs:list`-only classification, the two corrected ledger attestations now verify against the *whole* stamped siblings, and the per-entry hard-link `SourceLabel` genuinely removes the §7.3/source-map collision in the body text.

What keeps this from READY is not architecture, safety, feasibility, or any owed obligation — it is three pieces of textual residue the round-7 edits left behind, each a flat internal contradiction in normative text: an acceptance criterion (AC 18a) that still mandates the exact shared-lexically-least hard-link label §2.3's headline repair withdrew; four stale row indices in §7.2's prose after the `ERR_IBEX_ALIAS_COLLISION` row was removed and the table renumbered (in a section that declares "the row index is the total precedence"); and a §6 row (`Exact.resolve`) whose disposition contradicts the table's own `node:path` resolve row. All three are mechanical one-edit fixes with unambiguous direction. Nothing here needs another design round.

## 3. Concerns (abridged in this artifact; full text in the review record)

1. **Material — AC 18a still mandates the withdrawn shared hard-link `SourceLabel`** (line 2151 "lexically least" vs §2.3's per-entry rule). A fixture from AC 18a would fail a correct implementation.
2. **Material — §7.2's cross-reference prose is half-renumbered** after the ALIAS_COLLISION removal: "row 10/11" should be "9/10", "row 11 not 8" should be "10 not 7", "row-7 denial" should be "row-6 denial" (row 7 is ENOENT, the opposite of a denial).
3. **Material — §6's `Exact.resolve` row contradicts the table's own `node:path` row** for the same computation (`non-path` vs `virtual-absolute`); POSIX `path.resolve` output IS a virtual-path spelling.
4. **Minor — §6 interim table has duplicate keys** (Dirent, module fields) — violates its own duplicate-key discipline.
5. **Minor — `fs.glob`/`globSync` dispositioned `virtual-absolute`** where Node returns pattern-shaped (relative for relative patterns).
6. **Minor — the dataset key tuple is spelled four ways** (lines 1435/1459/1921/2000); pick one.
7. **Minor — stale OQ pointer in the `os.devNull` row** (sink question now inside OQ 7's resolved block; OQ 10 is case-alias).
8. **Minor — §2.3 hard-link bullet wording**: "own lexical spelling" collides with the section's lexical-vs-volume-canonical distinction.
9. **Minor — `process.execArgv` `non-path` rests on an unstated premise** (armed execArgv contains no path-valued flags; `EXACT_COMPAT_EXEC_ARGV` splices operator strings); and the "165 sites" count is not reproducible (≈142/196).

## 7. Readiness verdict

Everything architectural, safety-relevant, and ledger-relevant verifies — the owed obligations are properly stamped, owned, and accurate, and none is a blocker. What remains is three flat internal contradictions in normative text, each unlabeled/unledgered, each a one-line mechanical fix. Under this round's own bar I cannot call that READY, and equally I see nothing that needs another design pass: fix those three edits (and optionally the minors), and this document is done.

VERDICT: NOT READY
