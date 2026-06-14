# Review: LLP 0007 — Converging Runtime Transforms on Vite, Rolldown, and Oxc

**Reviewer family:** Claude (Anthropic)
**Provider / runtime:** Claude Code · model `claude-opus-4-8[1m]`
**Date:** 2026-06-13
**Redacted:** No — the review was performed entirely against local repo sources; no
document content was transmitted to any external provider.
**Method:** Direct provenance verification. Every `[observed]` citation was read
against its cited file and line range. External `[official docs]` URLs were **not**
re-fetched this pass (see C-ext). This Claude session did **not** author the draft
(Author: *Charlie Cheever / Codex*), so it stands as one independent family
reviewer per [LLP 0005 review process](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).

## Overall assessment

**Revise and stay `Draft`.** The RFC is well-scoped, correctly identifies the core
architectural tension (synchronous `require()` chain vs. an async ModuleRunner ABI),
and stages the migration sensibly. Its provenance discipline is mostly good: the
load-bearing `transpile.rs` citations — the heart of the argument — are precise, and
`[observed]` / `[official docs]` / `[inferred]` tags are used correctly.

Two classes of problem keep it from being accept-ready: (1) one **High**-severity
accuracy error in the description of current runtime behavior (the in-process engine
does *not* honor the down-level target the way the prose implies), and (2) several
**imprecise line-range citations**, most notably for `transforms.mjs`. Both are
fixable in place and, once fixed, the RFC's own argument for a fixture suite gets
*stronger*, not weaker.

## Strengths

- **§Proposal / §Migration plan** — the staged path (treat SWC as fallback → define
  the contract via fixtures → prefer in-process Rust → align generated artifacts
  first → flag-gated runtime path → default switch only after parity) is the right
  shape and explicitly refuses to "swap crates until a spike proves" parity.
- **§Current state → Runtime module loading** — the `transpile.rs` citations
  (`:8-15` engine-choice rationale, `:36-41,88-124` the pass pipeline, `:142-176`
  the contract tests) are all accurate to the source. The "good historical reason,
  not a permanent decision" framing matches the in-code comment.
- **§Goals / §Non-goals** — crisp and correctly scoped; "preserve the hermetic
  default" and "not an app framework / Vite dev server" are the right guardrails and
  line up with LLP 0005's hermetic-default invariant.
- **§Acceptance criteria** — forces a concrete terminal decision (one of four named
  outcomes) rather than letting the RFC drift.

## Concerns

### C1 (High) — The in-process engine ignores the down-level target; prose implies it doesn't

§Risks says *"Ibex currently sometimes asks SWC for `es5` when loop-scoping
downleveling is required `[observed]` (`src/module_loader/mod.rs:594-605`)"* and
§Current state says some `.js/.mjs/.cjs` files *"are down-leveled when scanners detect
unsupported Hermes syntax."* Verified against source, this is misleading for the
**default** path:

- `transpile_target_for_source` (`mod.rs:599-605`) computes `"es5"` / `"es2015"`.
- That target is threaded into the **cache key** (`mod.rs:828`) and into the
  **`EXACT_TRANSPILE_SCRIPT` subprocess** (`mod.rs:966-967`) — but the default
  in-process branch calls `transpile::transpile_to_cjs(&source, entry)` **with no
  target** (`mod.rs:942`).
- `transpile_to_cjs` hardcodes `EsVersion::Es2022` (`transpile.rs:68`) and runs only
  resolver → typescript → react → common_js → inject_helpers → hygiene → fixer
  (`transpile.rs:88-120`). There is **no compat / es-downlevel pass**, and
  `Cargo.toml:56-64` confirms no `swc_ecma_transforms_compat` crate is even a
  dependency.

Consequence: the scanners *detect* `for await` / async generators / `using` /
block-scoped loop closures and route the file to transpile, but the default
in-process engine **applies none of those Hermes lowerings** — it strips types,
compiles JSX, and lowers modules, then emits at ~es2022. The actual for-of/async-gen
rewrites live exclusively in build-time `transforms.mjs` (applied to *generated*
builtins and the runtime bundle via `createHermesCompatPlugin`,
`transforms.mjs:796-814`), not in the runtime loader. The es5/es2015 target only has
real effect through the opt-in subprocess.

**Why it matters for this RFC:** the migration's promise is to "preserve existing
loader semantics." If the *current* in-process default already skips these
down-levelings, then "preserve current behavior" and "apply the Hermes lowerings the
scanners imply" are two different goals, and the RFC should say which it means. A
faithful fixture suite (§Proposal 2) would surface this immediately — so this finding
*reinforces* the RFC's central recommendation, but the current-state description must
stop implying the in-process path honors the target.

**Resolution:** correct §Current state and §Risks to distinguish *scanner detection*
(picks a target, separates the cache) from *engine application* (the in-process
engine currently does not down-level). State plainly that closing this gap is part of
the Oxc work (Oxc's syntax-lowering/target would need to be wired in), not just
"preserved."

### C2 (Medium) — `transforms.mjs` line citations are wrong

The file is **877 lines** and is cited three times with ranges that don't cover the
referenced content:

- §Motivation cites `transforms.mjs:1-24` for *"Rolldown plus shared JS transforms."*
  Lines 1-24 are the header, imports, and the `rolldownConditionNames` /
  `hermesRolldownTarget` constants. The actual `createRolldownConfig` is at
  **`:848-877`**; the shared Hermes transforms are `fixForOfScoping` (**`:62-251`**)
  and `transformAsyncGenerators` (**`:392-597`**).
- §Motivation and §Proposal 2 cite `transforms.mjs:1-220` for *"Acorn-based JS source
  rewrites."* `:1-220` captures only part of `fixForOfScoping` and misses
  `transformAsyncGenerators` (`:392-597`), `replaceModuleDirnameBindings`
  (`:672-777`), and the exponentiation guards (`:322-386`). The Acorn import itself is
  `:10`.

**Resolution:** replace `:1-24` and `:1-220` with the specific function ranges above.

### C3 (Medium) — "scanners or shared transforms" conflates two code paths

§Proposal 2 lists Hermes lowerings *"currently handled by scanners or shared
transforms (`mod.rs:195-607`; `transforms.mjs:1-220`)."* The `mod.rs` scanners only
**detect** (`source_needs_async_downlevel` `:217-228`,
`source_needs_loop_scope_downlevel` `:585-597`); the **rewrites** live in
`transforms.mjs` and run at **build time** over generated artifacts, not over
runtime-loaded files. Same root cause as C1.

**Resolution:** separate "detected by runtime scanners" from "applied by build-time
`transforms.mjs`," and note the runtime in-process engine applies neither rewrite
today.

### C4 (Low) — Minor citation drift

- §Current state, `--lower-classes` Babel block: cited `rolldown-bundle.mjs:84-120`.
  The Babel block is **`:90-131`** (line 84 is inside the deps-manifest write).
- §Proposal 5, `EXACT_TRANSPILE_SCRIPT`: cited `mod.rs:922-970`. The override branch
  is `:936-938` (+ tooling-hash branch `:852-857`); `:922-929` is the unrelated
  `should_rebuild_output`. Tighten to **`:932-979`**.
- §Motivation, `package.json:22-25` for "Vite 8 and Rolldown": accurate, but worth
  noting these are **devDependencies** (build-time, consistent with the hermetic
  story) and that `rolldown` is `^1.0.0-rc.4` — a **pre-1.0 release candidate**. That
  pre-1.0 status is directly relevant to the "Rust API maturity" risk and slightly
  tempers "the repo already depends on Rolldown."

### C5 (Low) — The existing `es2020` Hermes target is unmentioned

§Risks says *"Rolldown's transform target defaults to `esnext` unless configured."*
True in the abstract, but the generated-artifact path already configures
`hermesRolldownTarget = 'es2020'` (`transforms.mjs:23`, used in `createRolldownConfig`
`:867`). The RFC should treat es2020 as the **existing baseline** the open question
"which exact Hermes target?" is refining, rather than implying the target is
unconfigured.

### C6 (Low) — `import.meta` is already a transform-time rewrite on the bundle side

§Open questions asks whether `import.meta.main` / TLA *"should become transform-time
rewrites."* For the bundle path this is already done: `runtimeImportMetaDefine`
(`transforms.mjs:25-34`) maps `import.meta.*` via Rolldown `define`. Worth citing as
precedent so the open question is framed as "extend the existing approach to the
runtime loader," not "invent one."

### C-ext (Flagged, not a defect) — External `[official docs]` claims not re-verified

The seven `[official docs]` citations (Vite 8 migration, Rolldown/Oxc docs) are
properly tagged and URL-cited, but were **not** re-fetched in this pass. They are
plausible and consistent with the toolchain direction, but a reviewer with web access
should confirm the two most decision-relevant ones before accept: the Rolldown
transform **target floor (`es2015`) / default (`esnext`)** and the Vite 8 **"consistent
CommonJS interop"** change, since both feed named risks.

## Open questions surfaced (beyond those the RFC already lists)

- Is the cache-key inclusion of `target` (`mod.rs:828`) now partly vestigial for the
  in-process path? Two targets key to two cache entries that the target-ignoring
  engine would fill with identical output. `[inferred]` this looks like migration
  residue from when the subprocess was the default; worth a line in the RFC.
- Should the Oxc migration be framed as *also closing the C1 gap* (actually applying
  Hermes lowerings in-process), making it a behavior **fix**, not a pure swap? If so,
  that should be an explicit, tested goal with its own fixtures.

## Recommended next step

Apply the C1–C6 corrections in place and keep `Status: Draft`. The RFC is not yet
accept-ready (it is explicitly pending a spike), and per LLP 0005 the status
transition is the author's call. If the author wants a second independent family
before any accept, route the corrected draft to a non-Claude reviewer; this single
session cannot stand in for the multi-family loop.
