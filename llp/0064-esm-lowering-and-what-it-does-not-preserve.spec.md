# LLP 0064: ESM lowering, and what it does not preserve

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Build, Runtime
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-29 (§2: strict mode preserved; `import()` arguments by span — both from the Grok 4.6 review) 2026-08-28 (§8 JSON modules, from running Exact's native entry — its boot graph imports two; and the expression-form nesting fix, since 21 of Exact's modules put `import()` inside an exported function)
**Revised:** 2026-08-28 (§7: `import.meta` and dynamic `import()` are lowered rather than left to the engine, since Oxc parses what Hermes will not and the transform already sits between them — 807 and 759 uses in Exact respectively. §7.1 records why top-level await is deferred rather than joining them.) 2026-08-28 (§4.1: both remaining divergences are now reported by `ibex2 build` rather than left silent. Measurement added — Exact has 3 `export let` against 12,677 immutable exports and 112 barrel files, which is why §3.1 gets a warning and not the §5 fix.) 2026-08-28 (initial draft)
**Related:** LLP 0028 (Oxc-only transform authority — the parser this uses), LLP 0057 (Ibex 2 §5.2 — targeting Exact is why ESM is required), LLP 0026 (ESM module runner — Ibex 1's prior art), LLP 0058.000.001 (greenfield kernel — the loader this sits in), LLP 0062 (measured engine facts, §3.1 — the `for-of` bug found here), LLP 0058 (the engine seam, OQ3 — the conformance floor this argues for), LLP 0065 (package resolution — how a specifier becomes the module this lowers)

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

*(2026-08-29, from the Grok 4.6 review: **strict mode is preserved now.** ES
module code is strict by definition, and the factory it was lowered into was a
plain function — so every module ran sloppy: an undeclared assignment created
a global, `010` was eight, `arguments.callee` worked, and the frozen-global
failure of LLP 0062 §3 surfaced three modules late instead of as the
TypeError strict code throws at the write. The lowering now prepends
`"use strict"` to a module's factory body and leaves CommonJS as written, as
Node does. Also from that review: the argument range of a lowered `import()`
comes from the parser's spans rather than from searching the expression for
`(`, which `import /*(*/('./x')` defeated.)*


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

**3.4 Top-level await is unsupported**, and fails loudly. See §7.

`import.meta` and dynamic `import()` were in this list and are not any more —
§7 says why, and the reason generalizes.

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

## 7. The engine's parser limits are this transform's to route around

Hermes parses neither `import.meta` — it reports `'import.meta' is currently
unsupported` — nor dynamic `import()`, which it rejects as an invalid
expression. Oxc parses both. **The transform already stands between them**, so
those are not application limitations unless we leave them so.

Measured in Exact: **807 uses of `import.meta` across 447 files**, and **759
dynamic imports across 260 files**. Neither is optional.

Both are now lowered.

**`import.meta`** becomes an injected module parameter. The value is per module
while the wrapper text is identical across modules, which is what keeps one
artifact per distinct source — a URL baked into the wrapper would give two
identical modules two artifacts. LLP 0023 §6 specifies what it should carry: the
virtual `file:///project/…` URL for a file-backed module. That namespace does
not exist yet, so this uses the same shape over the resolved specifier and moves
to the VFS when there is one.

**Dynamic `import()`** becomes a call taking the importing module's own
`require`, so a relative specifier resolves against the right file and the
imported module's grants are looked up under its own resolved name. It returns
a promise: the module is local and already compiled, so there is no I/O to wait
for, but the contract is a promise and callers rely on the continuation running
in a microtask. A failure rejects rather than throwing synchronously.

**The build distinction that matters.** A dynamic import with a **literal**
specifier is compiled ahead of time — otherwise it is absent from the manifest
and fails under `--precompiled`. But it is **conditional** where a static import
is not, so a literal target that does not exist is a *warning* rather than a
build failure; guarding an optional import is a correct thing to write. A
**computed** specifier cannot be resolved by any build, so it is not compiled,
and it works at run time only if its target was reached some other way. That is
the same shape as LLP 0028's computed-`require` candidate tables, and the same
answer will serve both.

### 7.1 Top-level await is different in kind

It is not a syntax gap. TLA makes module **evaluation** asynchronous: the
factory becomes `async`, `require` returns a promise, and every importer of a
TLA module must await it. That is ES modules' async module graph, and it is a
change to the loader's model rather than a lowering.

It also fails loudly today, so nothing can come to depend on it by accident.
Deferred until something measurably needs it, and measured properly — a grep for
`await` at column zero counts unindented awaits inside functions and is not
evidence.

## 6. What this says about conformance

The `for-of` binding bug in LLP 0062 §3.1 was found by this work, and it has the
same shape as everything in §3: **wrong values rather than errors.**

That is an argument about where LLP 0061's conformance effort should point.
LLP 0058 OQ3 asks for a floor "expressed as a suite over the application tier",
and this document says what belongs in it — closure capture in loops, live
bindings across modules, cycle behaviour. A runtime that gets these wrong
miscomputes silently, which is the failure mode a test suite is worth the most
against.

## 8. JSON modules

A `.json` module is a CommonJS module whose `module.exports` is the parsed
value: `import data from './x.json'` binds it through the default interop and
`require('./x.json')` returns it. Exact's native boot graph reaches two —
`@exact/core`'s colour policy is the first module `main.tsx` loads that is not
JavaScript — and the repository has eight, three of them written with
`with { type: 'json' }`.

Parsed with `JSON.parse` at load rather than pasted in as an object literal: a
literal `{"__proto__": …}` sets the prototype where JSON gives an own property.
The text is a string constant in the bytecode artifact, so a JSON module
compiles ahead of time like any other and costs one parse at load, as it does
in Node.

Two divergences, both permissive. Import attributes are accepted and not
required, where Node and the browser require them; Exact's imports are split
between the two forms and its bundler never enforced either. Named imports
(`import { a } from './x.json'`) work, because the lowering destructures
`module.exports`, where the specification allows only `default`. Neither can
make a working program fail; both let a program work here that would fail
elsewhere, which is the opposite direction from the divergences in §3.

`.json` is last in the extension probe (LLP 0065), so a `.js` sibling wins for
an extensionless specifier, as in Node.

