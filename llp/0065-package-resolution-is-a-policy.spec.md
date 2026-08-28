# LLP 0065: Package resolution is a policy, not a lookup

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Security, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Related:** LLP 0028 (Oxc-only transform authority — `oxc_resolver` is the same pin), LLP 0057 (Ibex 2 §5.2 — targeting Exact is why bare specifiers are required), LLP 0059 §6 (Node's server surface is deleted — why the `node` condition is absent), LLP 0060 (authority is carried, not inferred — why a package is granted nothing by arriving), LLP 0064 (ESM lowering — what happens to a module once resolution has found it), LLP 0062 (the reachability frame this containment rule belongs to)

## Summary

Until now `resolve()` refused any specifier not beginning with `./`. That was
deliberate: Node resolution is an algorithm with real semantics — `exports`
maps, condition matching, directory walking — and slipping one in by accident
decides policy questions silently.

Exact's graph makes it mandatory: 409 packages, dominated by `@exact/*`
workspace links and `react`. This document records the choices made when
turning it on. **`oxc_resolver` supplies the mechanism; every question below is
one it leaves to us.**

The through-line: resolution decides *what code enters the process*, so it is a
security surface, not a filesystem convenience.

## 1. Conditions, and the one that is missing

Resolution matches `exports` against `["import", "require", "default"]`.

`import` leads because the loader is ESM-first and a package's ESM entry is the
one whose live bindings and static shape the transform understands (LLP 0064).
`require` follows it because most of npm still ships CommonJS and the loader
handles both.

**`node` is deliberately absent.** LLP 0059 §6 deleted Node's server surface —
`http`, `net`, `tls`, `child_process`, `zlib`. A package that offers a Node
build and gets it here would receive one written against modules that do not
exist, and would fail at a confusing distance from the cause. Not selecting it
means such a package falls through to `default`, which is the branch its author
wrote for runtimes like this one.

`main_fields` is `["module", "main"]`, same ordering and same reason, for the
packages that predate `exports`.

## 2. `node_modules` is inside the project, not a hole in it

The loader's containment rule — a resolved path must stay under the project
root — is not suspended for packages. A package that resolves outside the root
is refused.

This matters more here than for relative specifiers, because Node resolution
**walks up** the directory tree looking for `node_modules`. Without the check,
a project could silently bind against a package installed above it, outside
anything the author reviewed.

## 3. Workspace symlinks resolve logically

`oxc_resolver` defaults to resolving symlinks to their real path. Ibex 2 turns
that off (`symlinks: false`).

Workspace packages are symlinks from `node_modules` into the monorepo, and
`@exact/*` — the dominant case in the real graph — are exactly that. Following
the link yields a path outside the project root, which §2 then refuses. The
logical path stays inside.

**The tradeoff, stated plainly:** a symlink inside `node_modules` pointing
somewhere arbitrary becomes reachable as a module. That is a weaker containment
guarantee than resolving first and checking after. It is accepted because the
alternative refuses every monorepo, and because the contents of a project's own
`node_modules` are already code the project chose to install and execute. §2
still governs everything that is not a symlink the project placed there itself.

This is the weakest claim in this document and the one to revisit first if
containment is ever load-bearing against an installed-dependency threat.

## 4. A package is granted nothing by being a dependency

This is the part that resolution must not quietly undo, and the reason it was
not simply switched on.

A package is a module like any other (LLP 0060 D1). It receives the authority
the grant manifest names under its **resolved specifier** —
`./node_modules/needy/index.js` — and nothing by virtue of having been
imported. A third-party package that reaches for `fetch` gets a binding that
carries no origins and is refused at the boundary.

So packages are *addressable* without being *ambient*: a manifest can grant one
exactly what it needs, and silence grants nothing.

Note the shape of the test this requires. Every module is handed a `fetch`
parameter, so `typeof fetch` is `"function"` in every module and proves
nothing. Authority is only observable by *use*.

## 5. What a missing package says

An unresolvable specifier reports the name as written — `cannot resolve
"lodash" from ./index.js` — rather than the deepest `node_modules` path the
algorithm reached. `node:` and `bun:` are refused ahead of resolution by their
scheme, naming the deleted builtin namespace (LLP 0059 §6) instead of reporting
that a package called `node:fs` is not installed.

## 6. Open questions

**OQ1 — Should `browser` be honored?** It is not today. Ibex 2 is not a
browser, but much of npm treats `browser` as "not Node", which is closer to
true here than `default` is. Wants measurement against Exact's actual
dependencies rather than a guess.

**OQ2 — Should the manifest be able to grant a whole package?** Grants key on
resolved file paths, so granting a multi-file package means naming its
internals — which are not the author's to know and change on upgrade. A
package-level grant scope is the obvious answer and is not yet specified. This
is the concrete form LLP 0062 OQ1 takes once packages exist.

**OQ3 — Is `symlinks: false` right, or is a root allowlist better?** §3 accepts
a real weakening. An alternative is to resolve symlinks honestly and let the
project declare additional permitted roots (the workspace directory), which
keeps containment strict at the cost of configuration.
