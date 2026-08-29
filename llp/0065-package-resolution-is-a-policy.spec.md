# LLP 0065: Package resolution is a policy, not a lookup

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Security, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-29, night (§3.3: edges recorded at build, and the `loader` feature) 2026-08-29, evening (§3.2: the resolve cache and what it gives up) 2026-08-29 (§4.2: package identity is the install `bind` resolves, never a path's spelling — a reviewer showed `evil/node_modules/react/` holding `[react]`; sections are canonicalized at bind) 2026-08-28 (§4.2 package-level grants — sections by package name, directory, or file, most specific wins; OQ2 resolved) 2026-08-28 (§8 platform variants removed the same evening — the target moved to Exact 2, which forbids the convention; OQ6 with it)
**Revised:** 2026-08-28 (§5 — the project root is declared with `--root` and never inferred, which unblocks monorepos and so unblocks Exact; §3 rewritten after self-review found it documenting a tradeoff that did not exist; §1 and §4.1 corrected after an adversarial review confirmed two capability bypasses. See `llp/reviews/0065-*.grok.md`.) 2026-08-28 (initial draft)
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
security surface, not a filesystem convenience. Two corollaries run through the
whole document, and both were learned by getting them wrong first — containment
and authority are properties of **files**, not of the strings that name them
(§4.1), and the boundary they are checked against must be **declared**, never
inferred from a file that exists for someone else's purposes (§5).

## 1. Conditions, and the one that is missing

Resolution matches `exports` against `["import", "require", "default"]`.

**It is a set, not a ranking**, and an earlier version of this section got that
wrong. It said `import` "leads" because the loader is ESM-first. Nothing leads:
`oxc_resolver` walks the *package's* `exports` keys in their own order and takes
the first one this set contains. A package that writes `require` before `import`
gets CommonJS, and reordering our list changes nothing. Verified by test — a
require-first package resolves to its CommonJS entry.

The real content of the choice is therefore only **which conditions are in the
set**, and the interesting one is the one that is not.

**`node` is deliberately absent.** LLP 0059 §6 deleted Node's server surface —
`http`, `net`, `tls`, `child_process`, `zlib`. A package that offers a Node
build and got it here would receive one written against modules that do not
exist, failing at a confusing distance from the cause.

That choice has a cost, and the earlier version of this section understated it
by claiming such a package "falls through to `default`, which is the branch its
author wrote for runtimes like this one." That is true only when the package
*has* a `default`. A package exporting **only** a `node` condition does not fall
through to anything — it fails to resolve, with an error naming the conditions
tried. `a_package_exporting_only_node_does_not_resolve` pins that, so the cost
is visible rather than discovered later.

### 1.1 Omitting `node` does not keep Node builds out

Measured against React 19.2.8, and worth recording because it undercuts the
obvious reading of §1. `react-dom` exports `./server` under nine conditions:

```
react-server, workerd, bun, deno, worker, node, edge-light, browser, default
```

Our set matches none of the first eight — and lands on `default`, which **is**
`./server.node.js`. Requiring `react-dom/server` therefore fails on `util`, a
Node builtin LLP 0059 §6 deleted, exactly as if we had selected `node`.

So omitting `node` prevents *selecting* the Node build; it does not prevent
*receiving* one, because a package is free to make the Node build its default.
The working entry is `react-dom/server.browser`, chosen by explicit subpath.

That is the concrete case behind OQ1: `browser` is the condition that would
have selected correctly here, and much of npm uses it to mean "not Node" —
which is closer to true for this runtime than `default` is. Still wants
measurement against Exact's dependencies before being added, since `browser`
also implies a DOM that does not exist.

`main_fields` is `["module", "main"]` for packages predating `exports`. Unlike
conditions this *is* an order, and it is a bundler's policy rather than Node's:
Node reads `main`. Choosing `module` first prefers a package's ESM entry, whose
live bindings and static shape the transform understands (LLP 0064).

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
package resolution was not usable for its actual target. The mechanism was
correct and the containment was correct; the **root** was the wrong one. §5
resolves it.

### 3.2 What the loader remembers

Added 2026-08-29. Resolution asks the filesystem, and a 500-module graph paid
two `realpath(3)` and up to five `stat(2)` calls per module — 26 of its 36 µs
— for answers that do not change while it loads. The loader keeps a
`ResolveCache` for its life: one `readdir` and one `realpath` per directory
answer every extension probe in it and give each file its on-disk spelling; a
full `canonicalize` is kept for a symlink entry and for a spelling that
differs from the listing's on a case-folding filesystem, so §3 and §4.1 decide
exactly what they did; the package resolver is one per loader, so its own
cache of `package.json` reads is kept. Resolution went from 13 ms to under 1
ms for 500 modules.

The one thing it gives up, stated: a file created after its directory was
first listed is not seen until the loader is set again. A module graph does
not grow while it loads; a build that writes modules and then runs them is
two loaders.

### 3.3 Resolution happens at build time

Added 2026-08-29. `ibex2 build` walks the graph and resolves every edge; it
now records each one in the manifest — importer, specifier as written,
resolved specifier — and a run with a manifest takes the edge before it
resolves anything. With the edges and the bundle (LLP 0067 §5), a
`--precompiled` run resolves nothing, lists no directory, and opens one file:
500 modules load in under a millisecond, 1.6 µs each.

That is also what makes a **run-only binary** possible. The `loader` feature
— on by default — is everything that turns source into a wrapper and a
specifier into a file: Oxc's parser, transformer, and resolver. Off, the
binary carries none of it, refuses `build`, refuses `run` without
`--precompiled`, refuses a TypeScript source and an ES module it is handed,
and refuses a bare specifier the manifest does not name rather than searching
for it. It is 5.6 MB against 9.6 MB, and a Rust consumer of the standard
library (LLP 0068) depends on the crate the same way, `default-features =
false`, and compiles none of the loader either.

What still resolves at run time: a dynamic `import()` with a computed
specifier (LLP 0064 §7), and every module in a run that was not built. Both
need the full binary.

## 4. A package is granted nothing by being a dependency

This is the part that resolution must not quietly undo, and the reason it was
not simply switched on.

A package is a module like any other (LLP 0060 D1). It receives the authority
the grant manifest names under its **resolved specifier**, and nothing by virtue
of having been imported. A third-party package that reaches for `fetch` gets a
binding that carries no origins and is refused at the boundary.

The resolved specifier is the **canonical path from the project root**, which is
not always the spelling the author typed. A classic dependency is
`./node_modules/needy/index.js`; a *workspace* package, being a symlink, is
`./packages/ui/index.js`, and a pnpm install is somewhere under
`./node_modules/.pnpm/`. Grant manifests must name what the module resolved to,
and `ibex2 build` prints it.

That single identity is load-bearing, not a convenience. §4.1 is why.

### 4.1 One file, one name

Grants are keyed by specifier, so **if a file has two names it has two grant
sets** — and a module locked down under one name holds the default's authority
under the other:

```
[*]
net.fetch https://api.example.com
[./packages/ui/index.js]          # deliberately empty: this module gets nothing
```

Reached as `@w/ui` that module is denied. Reached as
`./node_modules/@w/ui/index.js` — the same bytes, the same inode — it used to
match no section, inherit `[*]`, and get the network. The same held for
`./LOCKED.js` against `./locked.js` on a case-insensitive filesystem.

Both were confirmed and are fixed: `loader::contain` is the single point where a
path becomes an identity, both resolver arms go through it, and it canonicalizes
— which resolves symlinks and settles case. `contain` also fails closed, refusing
a path it cannot canonicalize rather than falling back to the spelling.

The general statement, because it outlives these two instances: **containment
and authority are properties of files, and a specifier is only a name for one.**
Any future code path that produces a specifier without going through `contain`
reintroduces both bugs at once.



### 4.2 Packages are granted by name; first-party code by path

Added 2026-08-28, discharging OQ2. Keying grants on file paths alone made a
manifest for a real dependency graph unwritable: a package's internals are not
the author's to know and change on upgrade. A manifest section now names one
of four things, and a module gets the **most specific** section naming it —
its own file, then its package, then the longest directory, then `*` — with
nothing combined, so an explicit empty section still means nothing:

```
[*]                          # everything not named below
[./net.js]                   # one module
[./src/telemetry/]           # every module under a directory, longest prefix wins
[react]                      # every file of the package, in every installed copy
[@w/ui]                      # a scoped package, installed or workspace
```

**What names a package is the install, never a spelling.** `ModuleGrants::bind`
resolves each package section to the directory `<root>/node_modules/<name>`
canonicalizes to — the same place for an in-place install, pnpm's store for a
pnpm one, the project's own tree for a workspace package — and the files
under that directory hold the grant. Nothing else does: not a package
declaring `"name": "react"` in its own manifest, and not a directory *named*
`react` that a dependency vendors inside itself. The first version of this
section took identity from the innermost `node_modules/<name>/` segment of the
path, which closed the first door and left the second wide open — a
reviewer's `evil/node_modules/react/` held `[react]`'s authority — and it was
the mistake §4.1 had already fixed for files, one level up. A copy nested
under another package is a different install and is granted by its directory
if it needs anything. `react-dom` is not `react`, and neither is a sibling.

**A workspace package is first-party code under a name.** Its symlink
canonicalizes outside `node_modules` (§4.1: `./packages/ui/index.js`); `bind`
binds `[@w/ui]` to that directory, at package precedence, so it reaches the
package whether imported by name or by relative path and outranks a directory
section covering the same tree — one file, one name, one grant set.

**Every section is canonical after `bind`.** File and directory sections are
re-keyed by their real path, because module identity is canonical and a
section spelt `./LOCKED.js` on a case-insensitive filesystem named
`./locked.js` in every respect but the one that decided its grants.

**A section naming something that does not exist is refused**, at load and
before any module runs: a package not installed under the root's
`node_modules`, a file or directory that is not there, or a section that is
neither a path, a directory, a package name, nor `*`. That is a usability
rule, not a safety one — a section that matches nothing grants nothing — and
it exists because a manifest that silently does nothing is the worst kind of
wrong.

Tests: `a_package_section_covers_its_install_and_nothing_beside_it`,
`the_most_specific_section_names_a_module_and_nothing_is_combined`,
`bind_refuses_the_uninstalled_and_binds_workspace_packages_to_their_directory`
(unit); `a_package_grant_covers_every_file_of_the_package_and_no_other`,
`a_directory_named_after_a_granted_package_inside_another_package_gets_nothing`,
`a_package_section_beats_a_directory_section_for_a_workspace_package`,
`a_section_spelt_in_another_case_still_names_the_file`,
`a_workspace_package_section_binds_to_its_real_directory`,
`a_manifest_naming_an_uninstalled_package_is_refused` (engine).

So packages are *addressable* without being *ambient*: a manifest can grant one
exactly what it needs, and silence grants nothing.

Note the shape of the test this requires. Every module is handed a `fetch`
parameter, so `typeof fetch` is `"function"` in every module and proves
nothing. Authority is only observable by *use*.

## 5. The root must be declared

`--root <dir>` names the project. Package resolution happens **only** when it
is given; without it, a bare specifier is refused with a message saying so.
Relative specifiers are unaffected, so a self-contained program still runs with
no ceremony.

The alternative was to infer the root — the nearest ancestor with a
`package.json`, or with a `node_modules`, or one declaring `workspaces`. All
were rejected, for two reasons.

**The weaker reason:** the obvious rule does not even work. In a monorepo
`apps/mobile/package.json` usually exists, so "nearest `package.json`" stops
there and the hoisted `node_modules` is still above it.

**The reason that decides it:** every inference rule can be induced to widen
the boundary further than the author expected. `package.json` and
`node_modules` exist for npm's purposes and appear in places nobody chose — a
stray `~/node_modules`, common on development machines, would silently make the
home directory the containment boundary. *A file that exists for someone else's
purposes must not be able to move a security boundary.* Refusing is a
resolution error the author can act on; guessing is a boundary nobody sees.

The root is also part of the **grant manifest's semantics**, not merely a
filesystem check: grant keys are paths from the root (§4), so moving the root
silently changes what every section names. That is a second reason it should be
stated rather than discovered.

### 5.1 What the root does and does not buy

For a monorepo, declaring the repository root makes containment a **weak**
boundary — the whole repository becomes reachable. That is correct and worth
saying plainly rather than hiding: containment's job is to stop code escaping
the project, not to partition within it. The control that partitions is the
capability model, which is per-module and unaffected by how wide the root is.
Narrowing within a project is OQ3.

### 5.2 Why not a config file

A project file — `ibex2.toml`, whose *location* defines the root and which
carries the grants — is the better long-run answer, because it puts the root
and the grant keys in one versioned artifact, and because it is an Ibex-owned
file rather than npm's. It is deliberately **not** built yet: `--root` is
strictly less machinery, and it is worth learning whether passing it is
actually annoying before adding a discovery rule and a file format. The
migration is additive — the flag stays as the override.

## 6. What a missing package says

An unresolvable specifier reports the name as written — `cannot resolve
"lodash" from ./index.js` — rather than the deepest `node_modules` path the
algorithm reached. `node:` and `bun:` are refused ahead of resolution by their
scheme, naming the deleted builtin namespace (LLP 0059 §6) instead of reporting
that a package called `node:fs` is not installed.

## 8. Platform variants — removed

Existed for one day (2026-08-28), then LLP 0057 §5.2 moved the target to
Exact 2, whose `rules/NOT-DOING.md` forbids platform-suffixed files: "one
route, one file." A policy serving a convention the target bans was deleted
rather than kept dormant. The rule it implemented was Metro's — `--platform
<name>` selecting `x.<name>.ext`, then `x.native.ext` for any name but `web`,
on both arms — and it lives in history at `60c19f0dc` if a target ever wants
it back. The number that justified it, 22 such pairs on Exact 1's boot graph,
is Exact 1's and was recorded in LLP 0066.

## 7. Open questions

**OQ1 — Should `browser` be honored?** It is not today. Ibex 2 is not a
browser, but much of npm treats `browser` as "not Node", which is closer to
true here than `default` is. Wants measurement against Exact's actual
dependencies rather than a guess.

**OQ2 — Should the manifest be able to grant a whole package?** *Resolved by
§4.2:* yes, by name, with identity taken from the path and never from the
package's own `package.json`; first-party code and workspace packages by
directory. This was the concrete form LLP 0062 OQ1 took once packages existed,
and the second item of `issues/20260828-capsec-made-whole.md`.

**OQ3 — Should a project be able to declare additional permitted roots?**
Containment is a single directory today. A project that legitimately spans two
trees has no way to say so except by widening the root, which widens it for
everything. An explicit allowlist would keep the boundary tight and stated.

**OQ4 — What is the project root?** *Resolved by §5:* declared with `--root`,
never inferred, and bare specifiers refused when it is absent. **OQ5 replaces
it:** is passing `--root` annoying enough in practice to justify the config
file §5.2 describes? That is a usage question and wants a few weeks of use
rather than an argument.
