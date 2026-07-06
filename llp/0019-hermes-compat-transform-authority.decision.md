# LLP 0019: Hermes-Compat for-of Transform Authority — One AST Authority, One Constrained Scanner

**Type:** Decision
**Status:** Accepted
**Systems:** Module Loader, Build, Runtime
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-06
**Related:** LLP 0004 (module loading); LLP 0005 (build pipeline); LLP 0007 (transform convergence RFC); LLP 0009 (runtime transform scope); LLP 0018 (fail-loud tooling)

## Decision

The Hermes-compat `for...of` scoping rewrite exists in exactly **two tiers**,
by design, and the split is enforced by a shared conformance corpus rather
than by trying to make one implementation serve both environments.

Anything that changes what either tier emits must keep the shared corpus
green through **both** conformance runners; expected differences between the
tiers are encoded explicitly, never left implicit.

### Tier 1: the canonical AST authority

`packages/ibex-devtools/src/scripts/hermes-compat.mjs` (`fixForOfScoping` and
the other Hermes-compat passes). Every build-time consumer uses it:
`transforms.mjs` imports and re-exports it (no second copy),
`rolldown-bundle.mjs`/`build-builtins.mjs` apply it through
`createHermesCompatPlugin`, and the `ibex` binary's pre-bundle path shells
out to that same script (ENG-22987).

### Tier 2: the embedded loader string scanner

`fixForOfScoping` in `src/engine/bootstrap/module-loader.js`. It rewrites
modules loaded through the in-process pipeline (the path taken when the
bundler is unavailable or bypassed, e.g. `EXACT_COMPAT_TEST=1`). Since
ENG-22990 it emits the same ENG-22569 iterator-protocol output shape as the
authority; its *rewrite set* is a converged-but-coarser approximation of the
authority's (see "Accepted divergences").

## Why two implementations at all

The loader scanner runs *inside the Hermes bootstrap*: it executes on the
engine it is compensating for, before any package code loads, with no
JS parser available (no Oxc, no acorn — `parseModuleOrScript` is a build-time
Node/Bun tool). A full unification would mean either embedding a parser in
the bootstrap (startup cost, and the parser itself would need Hermes-compat
lowering) or generating the scanner from the AST authority (a code generator
with its own drift surface). Neither buys more correctness than the chosen
seam: one authoritative transform, one constrained mirror, and a differential
test that fails when they disagree on observable behavior.

## History: the drift this decision ends

There were three implementations, and they demonstrably drifted:

- the ibex loader scanner (nested-loop gap fixed in ENG-22558),
- exact-devtools' AST `fixForOfScoping` (same gap fixed independently a
  second time in ENG-22559),
- an ibex-devtools byte-identical clone of the exact AST version.

The pre-ENG-22569 AST shape also passed textual-shape assertions while
closures captured `undefined` on shipping Hermes (ES6BlockScoping=false) —
proof that shape-based tests prove nothing and only engine-honest behavioral
fixtures gate this transform. The consolidation sequence:

- **ENG-22987** extracted the canonical transforms into `hermes-compat.mjs`,
  made `transforms.mjs` a re-export, and promoted the inline fixtures into the
  implementation-neutral corpus `hermes-compat-corpus.mjs`.
- **ENG-22989** added the two conformance runners over that corpus (see next
  section).
- **ENG-22990** converged the loader scanner's emitted shape onto the
  authority's iterator-protocol shape and aligned its bails, retiring the
  `Array.from(...).forEach(...)` materialization (which snapshotted lazy
  iterators, broke mutation-during-iteration and IteratorClose ordering, and
  rebound `arguments`/`super`/`new.target`).

The exact-devtools site is the remaining third copy; consolidating it onto
this repo's authority (via the vendored ibex pin) is exact-side work tracked
in ENG-22567.

## The enforced conformance seam

One corpus, one oracle, two systems under test:

- `hermes-compat-corpus.mjs` — implementation-neutral fixtures recording
  observable behavior facts (`rewrites`, `hermesMatchesOracle`,
  `rawHermesCaptureLast`). It imports no transform and no engine.
- `run-hermes-compat-corpus.mjs` — the AST path: transform output must
  preserve V8/Node oracle semantics and reproduce them on the standalone
  Hermes binary when present.
- `run-hermes-compat-loader.mjs` — the loader path: every fixture is driven
  through the **real built `ibex` binary**'s in-process module pipeline (not
  a unit-test copy of the scanner), compared against the same oracle, with
  per-fixture expectations (`loaderExpectations`) that pin documented
  divergences to their exact output. Stale entries, missing entries, and an
  engine-premise canary (raw for-of must still capture-last) all fail loudly.
- `tests/hermes_compat_conformance.rs` — wires both runners into
  `cargo test` / `scripts/run-tests.sh`, parsing non-empty pass counts so the
  gate cannot silently run nothing (LLP 0018).

`bun run test:hermes-compat` is the standalone entrypoint;
`bun test packages` covers the AST path plus the async-generator corpus.

The async-generator corpus (`asyncGeneratorCorpus`, ENG-23036 / ENG-23124)
applies the same divergence discipline to `transformAsyncGenerators`: each
fixture's oracle is the untransformed source run as a native async generator,
and a deliberate divergence of the desugared iterator must be pinned by an
explicit `divergence` entry recording the exact oracle and transformed
outputs (the pin fails when either side drifts, including when a fix makes
them converge). The one pinned divergence: `return()` resumes the desugared
body via a rejection sentinel, so a bare `catch` around a `yield` observes
the cancellation that native RETURN completions skip — full fidelity would
require a state-machine rewrite of the body.

## Accepted divergences between the tiers

The tiers agree on emitted shape and on oracle-observable behavior except
where the scanner's line-based analysis is inherently coarser. Divergences
are acceptable only in the **safe direction** — the scanner may *bail* (leave
a loop raw, costing the known capture-last pitfall on non-block-scoping
Hermes) where the AST authority rewrites, never the reverse:

- the scanner only rewrites single-line `for (const|let ... of ...) {`
  headers whose loop closes on a bare `}` line; the authority rewrites any
  parseable loop (including `for (var ...)`/bare-assignment headers, which it
  lowers to the plain iterator shape without a per-iteration wrapper);
- the scanner's bail regexes (`return`/`break`/`continue`/`yield`/`await`,
  `var`-in-body and line-leading function declarations as hoisting hazards,
  simple-binding `let`/`const` redeclaration) test raw body lines, so a
  keyword inside a nested closure bails the whole loop; the authority walks
  the AST and stops at function/class boundaries;
- both tiers share one documented behavioral hole, pinned by the corpus: a
  hazard-bailed loop's escaping closures keep raw capture-last behavior on
  shipping Hermes (`hazard-bailed-var-in-body`).

Every behavioral divergence visible through the corpus MUST appear as an
explicit `loaderExpectations` entry with its exact output and reason; the
runner fails when a documented divergence stops reproducing (including when a
fix makes the loader match the oracle — the entry must be flipped in the same
change).

## Consequences

- Behavior changes to the transform land in `hermes-compat.mjs` first, with
  corpus fixtures pinning the new behavior; the scanner follows only as far
  as its constraints allow, and the delta lands as expectation entries.
- New corpus fixtures must be implementation-neutral (data only) so exact can
  run them against its own transform and Hermes binary unchanged.
- The bundle cache hashes `hermes-compat.mjs` (see
  `bundler_cache_input_paths` in `src/bin/ibex/runtime.rs`) so semantic edits
  invalidate cached bundles.
