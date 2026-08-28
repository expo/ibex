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

## 3. Symlinks are resolved, and containment is checked against the real path

Containment (§2) compares the **canonical** path against the canonical root, so
a symlink inside `node_modules` pointing out of the project is refused like any
other escape. A workspace package resolves to its real location — and is
reachable only if that location is itself inside the root.

**This section previously claimed the opposite**, and was wrong. It said
resolution deliberately did not follow symlinks (`oxc_resolver`'s
`symlinks: false`), so workspace links would resolve "logically" and stay
inside `node_modules`, and it recorded that as an accepted weakening of
containment. Two things were wrong with that:

1. The option was **inert**. Setting it to `true` changes no observable
   behaviour, because the canonicalize below it normalizes the path either way.
   Verified by mutation: every test passes identically with the option flipped.
2. The weakening it admitted **did not exist**. A symlink out of the project was
   already refused. The document conceded a security property the code had not
   actually given up.

The option has been removed rather than left with a corrected comment, so the
resolver and the containment check now agree on what a path is instead of one
silently undoing the other. `a_symlink_out_of_the_project_is_refused` pins the
behaviour, and says in its own comment that the protection comes from the
canonicalize — so a future change that relaxes it fails a test that explains
itself.

The lesson worth keeping: this document was written from the code's *comments*
rather than from its *behaviour*, and the comments described an intent that the
implementation had overtaken.

### 3.1 What this costs, which is real

Strict containment plus a root defined as the entry's own directory means
**monorepo layouts do not resolve at all**. With the entry at
`apps/mobile/index.js`, a hoisted `node_modules/` and a `packages/` directory at
the repository root are both *above* the root and therefore refused.

That is Exact's shape, and Exact is what Ibex 2 targets (LLP 0057 §5.2), so
package resolution is not yet usable for its actual target. The mechanism is
correct and the containment is correct; the **root** is the wrong one. OQ4
carries this.

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

**OQ3 — Should a project be able to declare additional permitted roots?**
Containment is a single directory today. A project that legitimately spans two
trees has no way to say so except by widening the root, which widens it for
everything. An explicit allowlist would keep the boundary tight and stated.

**OQ4 — What is the project root?** The blocking question, and §3.1 is why. The
root is the entry file's own directory, which is right for a single-directory
program and wrong for every monorepo. Candidates: the nearest ancestor holding
a `package.json`; the nearest ancestor whose `package.json` declares
`workspaces`; the nearest ancestor holding a `node_modules`; or an explicit
`--root`. The tension is that containment is a security boundary, and every
implicit rule that widens it automatically can be induced to widen it further
than the author expected — a stray `package.json` in a home directory should
not silently make the home directory reachable. An explicit `--root` with a
conservative default is the likely answer, but the default is the decision.
