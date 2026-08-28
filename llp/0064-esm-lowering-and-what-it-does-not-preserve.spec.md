# LLP 0064: ESM lowering, and what it does not preserve

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Build, Runtime
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-28 (§4.1: both remaining divergences are now reported by `ibex2 build` rather than left silent. Measurement added — Exact has 3 `export let` against 12,677 immutable exports and 112 barrel files, which is why §3.1 gets a warning and not the §5 fix.) 2026-08-28 (initial draft)
**Related:** LLP 0028 (Oxc-only transform authority — the parser this uses), LLP 0057 (Ibex 2 §5.2 — targeting Exact is why ESM is required), LLP 0026 (ESM module runner — Ibex 1's prior art), LLP 0058.000.001 (greenfield kernel — the loader this sits in), LLP 0062 (measured engine facts, §3.1 — the `for-of` bug found here), LLP 0058 (the engine seam, OQ3 — the conformance floor this argues for)

## Summary

Ibex 2 accepts `import` and `export` by **lowering them to the CommonJS-shaped
module factory the loader already runs**. Oxc parses; the transform rewrites the
byte ranges the parser reports and copies everything else verbatim.

This is not an ES module linker. It is close enough to run ES module code and
far enough from the specification that the gap needs writing down, because
**every remaining divergence is silent** — it produces a plausible value rather
than an error.

The one-line rule that follows: **exports are live, imports are not.** Almost
everything below is a consequence of that asymmetry.

## 1. Why lowering rather than linking

`hermesc` has a module mode, `-commonjs`, which is the mode that accepts
`import` and `export`. On the pinned engine **it segfaults on every input**,
including plain CommonJS, while the same compiler without the flag is fine. The
engine's own module path is unavailable, so the transform is ours.

Oxc is the parser because LLP 0028 makes it the transform authority and because
the project standardizes on the Vite/Oxc ecosystem. Nothing here re-opens that.

**Spans, not an AST rebuild.** The parser reports an exact byte range for each
import and export; those ranges are replaced and every other byte is copied
through. A module's own code therefore reaches the engine exactly as written,
which keeps the transform auditable and leaves source positions recoverable.

## 2. What is preserved

- **Exports are live.** Each is published as a getter over its binding, so a
  module that reassigns an exported `let` after evaluation has that visible to
  importers. `exports.x = x` would snapshot.
- **Imports are hoisted.** Every dependency is evaluated before the importing
  module's own code, and a binding is usable above its `import` statement — as
  ES modules require. This was a divergence until it was measured: a module
  using a binding before importing it silently saw `undefined`.
- **Named, default, namespace, and side-effect imports**; **named exports,
  default exports, re-exports, `export *`, and `export * as`.**
- **CommonJS interop.** A CommonJS module imported by an ES module has its
  `module.exports` treated as the default, which is what every bundler
  converged on. The two module systems mix freely in one graph.
- `export *` excludes `default`, as the specification requires.

## 3. What is not preserved

Three divergences, all silent, and the first two are the same fact.

**3.1 Named imports snapshot.** `import { n } from './c'` lowers to a
destructure, so a later reassignment of `n` in `./c` is invisible to the
importer. Measured:

```js
import { n, bump } from './c.js';
import * as ns from './c.js';
bump();
console.log(n, ns.n);   // 0 1  — the specification says 1 1
```

The namespace form is correct because it reads through the module object, whose
properties are the live getters from §2.

**3.2 Cycles behave as CommonJS cycles.** A module in a cycle observes its
partner's *partial* exports rather than an ES module's temporal dead zone. In
the measured case a cyclic import read `undefined` where the specification
requires a `ReferenceError`. Silent partial data instead of a loud failure.

**3.3 `export { x }` of a name later reassigned by a cycle partner** inherits
3.1's limitation through the same route.

Loud, and therefore safe, on the current engine: **top-level await**,
**`import.meta`**, and **dynamic `import()`** are all compile errors. The last
two are the engine's refusal, not this transform's — Hermes reports
`'import.meta' is currently unsupported`.

## 4. What to do and not do

**Do:**

- **Use a namespace import when a binding is expected to change.**
  `import * as counter from './counter.js'` then `counter.value` is live;
  `import { value }` is not. This is the single most useful rule here.
- **Keep the module graph acyclic.** Cycles do not fail loudly, so a cycle that
  works today can start returning `undefined` after an unrelated reordering.
- **Prefer `export const` and `export function`** — bindings that are never
  reassigned make 3.1 unobservable.

**Do not:**

- **Do not use top-level await.** It does not compile, which at least means it
  cannot be relied on by accident.
- **Do not use `import.meta` or dynamic `import()`** yet. Both are engine
  limitations; `import.meta` in particular is something LLP 0023 §6 expects to
  provide, so it is a gap to close rather than a decision.
- **Do not rely on a cycle's TDZ behaviour** to catch an ordering mistake. It
  will not throw.
- **Do not add a second place that produces the module wrapper.** The artifact
  key is computed over the wrapper text, so a second producer means two keys for
  one module. `loader::lower_and_wrap` is the only one.

## 4.1 Both divergences are reported, not left silent

`ibex2 build` warns on each. The danger in §3 was never the wrong answer; it was
that the wrong answer arrives quietly.

```
ibex2: warning: ./counter.js exports `n` and reassigns it. An importer writing
       `import { n }` will see a stale value; `import * as ns` reads through
       and is live (LLP 0064 §3.1).
ibex2: warning: import cycle: ./a.js -> ./b.js -> ./a.js. Cycles resolve to
       partial exports rather than failing, so this will not error if the order
       changes (LLP 0064 §3.2).
```

Warnings rather than errors, and reporting rather than fixing, because the
measurement says so. Exact has **3** `export let` against **12,677**
`export const`/`function`/`class`, so §3.1 is close to unreachable in practice —
and §5's fix rewrites every usage site in every module to reach three
declarations. It has **112** `export *` barrel files, which is why cycles get a
detector rather than a shrug.

The mutable-export check is deliberately approximate: a shadowed inner binding
counts as an assignment, so it can warn where the export is never actually
reassigned. For a warning that is the right direction to err, and a precise
answer needs the same scope analysis §5 defers.

## 5. Closing the gap

3.1 and 3.2 both close the same way: bind imports through the module object
rather than by value, rewriting each usage site from `n` to `_ns.n`. That needs
scope analysis to know which `n` is the import — `oxc_semantic` is already
pinned in this repository and is the tool for it.

That is the whole fix, and it is bounded. It is not done here because the
transform is currently a span rewrite with no name resolution, and adding
resolution is a different piece of work from adding syntax support.

The alternative — a real ES module linker with `Module` records, instantiation,
and TDZ — is what the engine would give if `-commonjs` worked. Worth revisiting
on a pin bump, since it would make §3 empty rather than smaller.

## 6. What this says about conformance

The `for-of` binding bug in LLP 0062 §3.1 was found by this work, and it has the
same shape as everything in §3: **wrong values rather than errors.**

That is an argument about where LLP 0061's conformance effort should point.
LLP 0058 OQ3 asks for a floor "expressed as a suite over the application tier",
and this document says what belongs in it — closure capture in loops, live
bindings across modules, cycle behaviour. A runtime that gets these wrong
miscomputes silently, which is the failure mode a test suite is worth the most
against.
