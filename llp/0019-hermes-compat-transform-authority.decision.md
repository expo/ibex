# LLP 0019: Hermes-Compat Transform Authority and Runtime Mirrors

**Type:** Decision
**Status:** Accepted
**Systems:** Module Loader, Build, Runtime
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-06
**Revised:** 2026-07-17 (the native source/prepared real-binary gate and
exhaustive Hermes target matrix pin every Tier 3 for-of corpus row to a pass
or stable typed quarantine; unsupported Hermes syntax and BigInt/source-map
expectations join the same executable contract); 2026-07-17 (LLP 0028 Phase 0
quarantines unproven Tier 3 `for...of` shapes behind typed `LegacyRequired`
categories); 2026-07-15 (ENG-25066 made Tier 3 canonical for ordinary ESM;
Tier 2 remains only for the bounded unsupported-shape window); 2026-07-15
(LLP 0026 adoption adds the Rust/Oxc in-process zero-divergence mirror as a
migration tier)
**Related:** LLP 0004 (module loading); LLP 0005 (build pipeline); LLP 0007 (transform convergence RFC); LLP 0009 (runtime transform scope); LLP 0018 (fail-loud tooling); LLP 0026 (module runner)

## Decision

During the LLP 0026 migration, the Hermes-compat `for...of` scoping rewrite
exists in exactly **three tiers**. The additional Rust/Oxc tier is a temporary
migration shape; the intended end state returns to two tiers after the
bootstrap scanner retires. The split is enforced by a shared conformance
corpus rather than by trying to make one implementation serve every
environment.

Anything that changes what a tier emits must keep every applicable shared-
corpus runner green; expected differences between tiers are encoded
explicitly, never left implicit. Tier 3 joins the real-Hermes corpus as its
production pass lands rather than receiving a prose-only exemption.

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

### Tier 3: the Rust/Oxc module-artifact producer

The in-process producer introduced by LLP 0026 expresses the same
Hermes-compat passes over Oxc's AST while emitting module-runner factories.
During migration, Tier 1 remains canonical and Tier 3 is a zero-divergence
mirror: every applicable shared-corpus behavior must match on real Hermes and
its composed source maps must preserve the same locations. The bounded spike
established feasibility and passed the canonical LLP 0019 capture fixture;
the production factory pass now serves ordinary ESM by default. No
bootstrap-scanner workaround may be applied to runner-emitted factory text.

Tier 3 is canonical for ordinary ESM. Tier 2 remains reachable only through
the bounded 0.1 compatibility path for unsupported interop shapes and retires
with that path. Any non-zero divergence requires an explicit revision here
rather than an expected result hidden in the runner.

**Dated compatibility disposition (2026-07-17).** The first Tier 3 `for...of` mirror used
an ordinary-function IIFE without the canonical pass's control-flow, lexical
`this`/`arguments`, hoisting, redeclaration, or nested-loop analysis. Until a
complete Oxc pass lands, every unproven row is classified by an AST-derived
`Tier3ForOfQuarantineReason` and returns typed `LegacyRequired` to the bounded
0.1 compatibility loader. The simple identifier-bound block-capture row stays
native only when none of those hazards is present. Deleting the fallback does
not resolve a row: each quarantine must become a proven pass or a stable,
documented unsupported diagnostic before the window closes.

The Phase-0 gate closes the unclassified part of that exception.
`config/llp0019-native-tier3-corpus.json` covers all 31 shared-corpus rows:
four proven for-of rows execute natively; every other row has an exact typed
code and reason. The broader `config/llp0019-hermes-target-matrix.json` pins
the native contract for for-of, async generators, `for await`, explicit
resource management, BigInt, decorators, and source maps. A quarantine still
uses Tier 2 during the bounded window, but it can no longer disappear by
accident: window close must preserve its stable unsupported diagnostic or
land a proven pass.

## Why multiple implementations exist during migration

The loader scanner runs *inside the Hermes bootstrap*: it executes on the
engine it is compensating for, before any package code loads, with no
JS parser available (no Oxc, no acorn — `parseModuleOrScript` is a build-time
Node/Bun tool). A full unification would mean either embedding a parser in
the bootstrap (startup cost, and the parser itself would need Hermes-compat
lowering) or generating the scanner from the AST authority (a code generator
with its own drift surface). Neither buys more correctness than the chosen
seam: one authoritative transform and environment-specific constrained
mirrors, with differential tests that fail when they disagree on observable
behavior. The Rust/Oxc mirror exists because unlike the bootstrap scanner it
can use a native AST without adding a Node/Bun runtime dependency.

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

One corpus, one oracle, three systems under test:

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
- `run-native-tier3-conformance.mjs` plus
  `tests/native_tier3_conformance.rs` — drives the real CLI binary through
  source and prepared native profiles. Passing rows must match the oracle and
  emit one authenticated execution receipt; quarantined rows must emit their
  stable code/reason and no receipt. The named macOS-arm64 and Linux-x64 CI
  cells run this gate. Its debug-only CapSec conformance constructor skips
  only report promotion while retaining exact-engine, protected-artifact,
  root-binding, and bounded project/stdout authorization checks.

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

- During migration, behavior changes land in `hermes-compat.mjs` first, with
  corpus fixtures pinning the new behavior; the scanner follows only as far
  as its constraints allow, the Rust/Oxc mirror follows with zero divergence,
  and scanner deltas land as expectation entries.
- New corpus fixtures must be implementation-neutral (data only) so exact can
  run them against its own transform and Hermes binary unchanged.
- The bundle cache hashes `hermes-compat.mjs` (see
  `bundler_cache_input_paths` in `src/bin/ibex/runtime.rs`) so semantic edits
  invalidate cached bundles.
