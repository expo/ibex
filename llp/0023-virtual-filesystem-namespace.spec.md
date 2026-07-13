# LLP 0023: Virtual Filesystem Namespace and Path Identity

**Type:** Spec
**Status:** Draft
**Systems:** Runtime, Filesystem, Security, Module Loader, Host ABI
**Author:** Charlie Cheever / Claude / Codex
**Date:** 2026-07-12
**Revised:** 2026-07-12 (round-8 dual-model review, **terminal** — both NOT READY,
reconciled as a **ledger-and-stop**, the honest end of the loop. Fable and Codex
converged on substance ("everything architectural, safety-relevant, and ledger-relevant
verifies") and on the same fixable trio: **AC 18a** still mandated the shared hard-link
`SourceLabel` §2.3 withdrew (fixed to per-entry, in both load orders); the **§7.2
row-number** references went stale after the `ERR_IBEX_ALIAS_COLLISION` removal (fixed);
and the **`Exact.resolve` disposition** contradicted the `node:path` row for the same
computation (fixed to `virtual-absolute`, along with `path.posix`, `fs.glob`, and
`Exact.main`, all wrong on execution). The remaining Codex items are the loop's final
finding — *prose cannot carry the disposition universe, its values included* — so the
§6 named values are demoted to an **executed, generated `OBL-DISPOSITION-DATASET`**
normative for both membership and value under one canonical key tuple; the wrong
single-valued cells are corrected. Also: **retained-base/referrer staleness** is a
requested-stage precondition, ordered before the child's `ENOENT` (not the commit-stage
row 10); the **integrity-walk object set** is eager and membership is by **defining
principal** (a package symlink out to root source does not freeze it); **durability ops**
join the open family (closing the durability leaf would allow partial-mutation-then-
denial); the **existence-oracle citation** is corrected to the whole-file-**read** routes
(`__exactReadFile`) — the actual `fs.open` route authorizes first, the run-the-artifact
lesson biting the citation; and — sharpest — my round-7 **`OBL-ERROR-ORDER`
"discharged-by-absence" was itself a false whole-document attestation** (0022:471's
watch→outside-mount statement *is* order-relevant), the third instance of the
completion-detector-can't-detect-its-own-incompleteness bug, which is why
**`OBL-LEDGER-CHECK` is now split** into a mechanical stamp/marker checker and a
reviewer-performed whole-document semantic attestation (the review record *is* that
attestation). The **source hardcode** of the advertised-target state
(`runtime.rs:1981`) is ledgered as owed on `OBL-TARGET-PROMOTE`. **Status stays Draft** —
not both-families-READY; the residual owed artifacts become implementation tickets, the
actual path to READY. No round 9. Round-7 body follows.

Round-7 dual-model review — both NOT READY, and a deliberately **minimal closing pass**
after the reviewers converged on the exit: the
remaining defects are the kind a *generated, machine-checked* dataset eliminates and
prose review keeps re-finding in a new spelling each round, so several are ledgered as
owed rather than hand-written into a table the next reviewer falsifies. Blockers:
`Exact.resolve`/`Bun.resolve` are **not** module bridges — they are shipped
`path.resolve` delegates (`exact-global.js:849`), so they leave `OBL-RESOLVE-GATE` and
are classified as cwd-reading `non-path`; the §6 disposition table is demoted to an
**illustrative interim projection** with the generated `OBL-DISPOSITION-DATASET` as the
normative totality (visible flat contradictions — `module.parent`/`children`,
builtin-vs-file `require.resolve` — fixed, and `Exact.which`/`fs.glob`/`require.main`
closed or dispositioned); a hard link's **`SourceLabel` is its own entry's spelling**,
not a shared lexically-least one, so per-instance `SourceId`/label/referrer/source-map
key all agree and no reverse index is needed. Material: the two immutability guards get
an **arming-time integrity-walk object set** and a **rerun-after-symlink** rule; the
resolve route must be **body-read-free** (`resolve_meta` reads ESM bodies today,
`mod.rs:775`); the open-write family is **enumerated** and the `watch`-on-`/` vs
synthetic-node contradiction resolved (watch is closed-`EPERM`, earlier); the undefined
**`ERR_IBEX_ALIAS_COLLISION`** is removed from the v1 order; the **referrer
stale-identity** is pinned (closing OQ 12); and two **false ledger attestations**
(`OBL-TARGET-PROMOTE`, `OBL-ERROR-ORDER`) are corrected, with `OBL-LEDGER-CHECK`
extended to verify owner-side *claims*, not just stamp syntax — because a stamp can
resolve while its attestation is stale. Two cross-doc carry-forwards from the Fable
half land too: the untracked **mkdir/0021 rollback contradiction** (`OBL-MKDIR-ROLLBACK`)
and the **`OBL-HISTORY-LOCALITY`** §7.1 acknowledgement LLP 0025 drafted. Minors: the
real macOS generation identifiers (`st_gen`/`ATTR_CMN_GEN_COUNT`) and citation fixes.
Round-6 body follows.

Round-6 dual-model review — a **split** verdict, Fable READY and Codex NOT READY, so
not convergence; Codex's six blockers are reconciled here. The one that justified the round is **§4.2's package-immutability
mechanism**: the round-5 rule ("every package binding's subtree is a protected
object") is *not representable* by the shipped guard, which is a single exact object
(`decision.rs:114-117,946`). Path containment and inode aliasing are different
matching problems, so §4.2 now names **two** guards — a lexical path-tree guard
(denying in-package writes and creates before lookup) and a set-valued
exact-object/generation guard (catching hard-link aliases at commit) — and
immutability holds if either fires. Also: **non-recursive `mkdir` drops its
name-bound rollback** (a verify-then-`unlinkat` TOCTOU), becoming a bare atomic
`mkdirat`; the **resolve-only bridges** (`require.resolve`, `Exact.resolve`) are
gated like `import`, because `resolve_module_meta` stats before the gate
(`mod.rs:1430`) — an existence oracle; **`SourceId` strips query/fragment** and
**`SourceLabel` is pinned** to the load-order-independent canonical spelling, closing
two OQs that contradicted "total/deterministic"; **`os.devNull`** stops pretending to
be a synthetic sink (it returns the constant string and fails outside-mount on use);
the mutation surface is **default-closed** with the metadata-mutation family and
`mkdtemp` explicitly closed; the observables table gains `typed-logical` and
`reserved-constant` dispositions, Bun aliases, and fixed `path.win32`/`module.parent`
rows; and — humblingly — **the ledger's stamp convention is fixed a second time**: a
document's `shasum` is *not* a git object (`git cat-file` rejects it), so stamps now
name their method explicitly, `commit:<oid>` verified by git and `sha256:<prefix>`
verified by shasum. Round-5 body follows.

Round-5 dual-model review. Two findings of substance, both verified by running
rather than reading. **(1) A live authority defect that survived
the round-4 mutation closure:** §1.2 admits an in-project store that hard-links
byte-identical files across packages to one inode, §4.1 opens single-path writes, and
the shipped `protectedObjects` guard protects only the *project-root directory's*
inode (`runtime.rs:1948`), matched by *exact* inode identity (`decision.rs:946`) — so
a file inside `node_modules` is unprotected, and package B, writing its own file
under a valid grant, mutates package A's hard-linked source, which A then executes
under A's authority. Closing `link` (round 4) stops new aliases; it does nothing about
existing ones. Fixed by **§4.2: authenticated package source is immutable** — every
package binding's subtree is protected against `fs:write`, extending the existing
guard from one object to all package roots (`OBL-PACKAGE-IMMUTABLE`). **(2) `out-of-
snapshot` was a package-graph existence oracle** — decided from the *global* graph, it
let a principal distinguish "package absent" from "present but not importable by me";
§7.2 now decides it from the *caller's authorized graph view*, as the shipped host
already does (`host/mod.rs:1377`).

A **further, deliberate scope narrowing** followed from the pattern: four separate
findings were all *complex or multi-step filesystem operations specified unsafely in
prose*. So v1 now closes the **whole** hard-to-specify surface — symlink/hard-link
creation, rename, removal (incl. recursive `rm`), `cp`/`copyFile`, `watch`, recursive
`mkdir`, and disposable-temp cleanup — at the **public entry point**, and specifies
completely only what is genuinely simple: reads, metadata, existing-link traversal and
readback, single-path writes to non-package objects, and non-recursive object-bound
`mkdir`. `copyFile` is now closed too (an earlier draft opened it against LLP 0021's
own closed list).

Also: the **error order gains a tier-0 (session) and fixes several within-tier
placements**; the duplicated `fs.open` paragraph is removed; the `interim` class —
attributed to LLP 0022, which defines no such class — is deleted; `SourceId`'s path
component is pinned to the **lexical** canonical vector (with the case-alias
consequence stated); every **cwd-reading path/URL alias** (not just top-level
`resolve`/`relative`) gets the no-effect branch; `os.devNull` becomes a reserved
synthetic sink and the closed `os` rows pin their outcomes; and the **ledger's
revision stamps are made resolvable** — a prior draft stamped rows with the document's
own shasum, which `git cat-file` rejects, so the staleness detector was itself
unverifiable; stamps are now `git rev-parse` objects, and two rows stale in the
favorable direction (0021's target advertisement, 0024's landed error-order deferral)
are refreshed. The **fourth false Node claim** in five rounds — "default ESM splits
symlinked specifiers," which Node does not do — is corrected, and the pattern (every
false Node claim entered as a reviewer's assertion adopted without running Node) is
named once in §2.3.

Rounds 1–4, for the record. Round 1: staged identity, project-root discovery, the
runtime handle, the cwd actions. Round 2 retracted the effect-owner occurrence rule,
one-sided alias canonicalization, and a `%5C` refusal justified by a citation to code
behind a literal `false &&`. Round 3 retracted §2.2's safety claim — false of the
shipped evaluator, because `LogicalRoot` is a payload-free enum, so a package's own
grant structurally authorized another package's file; fixed by per-dimension
projection. Round 4 closed name-bound mutation after specifying a hard-link privilege
escalation, made `SourceId` total (the root/project arm had no identity), removed the
doubly-carried principal, and made workspace membership ancestor-inclusive (the prior
predicate could not match this repository's own `packages/*`). **Every defect across
five rounds was found by running or evaluating an artifact, never by re-reading
prose** — and the ones that reached the document were, without exception, claims
adopted from a reviewer without running the artifact.)
**Related:** LLP 0002 (host embedding ABI — the semver-major consumer contract
the runtime/session handle amends); LLP 0021 (capsec effect model — the typed
decisions this namespace feeds); LLP 0013 (per-package compartments); LLP 0014
(import-site grants and generated policy); LLP 0004 (module loading); LLP 0022
(REPL behavior — the first consumer to demand this contract); LLP 0024
(structured evaluation — module cache identity); LLP 0025 (terminal session
ownership — worker locality of retained identities)

## Summary

Armed Ibex gives JavaScript a **virtual absolute path namespace** rooted at
`/`, with `/project` as its only initial mount, backed by the authenticated
project-root binding. JavaScript never sees a host path. Relative paths resolve
from a virtual **resolution base** that is per-runtime session state owned by the
root principal, held natively as a retained platform identity rather than as a
mutable JavaScript value.

Underneath the spelling, every authorization and cache decision keys on an
**authenticated logical path identity**. That identity is **staged**, not a
single tuple: a path acquires an authenticated binding before it acquires a
platform object, and it must, because the target of a create does not exist when
the create is authorized. Two principals can spell the same path and mean
different authorities; a string handed across a principal boundary carries none.

This document is the path-and-runtime-state mechanism that LLP 0022 (REPL),
file execution, the one-shot evaluation surfaces, and embedders all depend on.
It applies to every armed execution mode, not only the interactive one.

## Motivation

Armed Ibex closes native cwd disclosure, as LLP 0021 requires
(`src/engine/hermes_runtime.cc:1654-1655` returns `undefined` when armed). The
JavaScript `process` facade then falls back to `/`
(`src/builtins/process.js:69`), and the `fs` builtin eagerly resolves
`README.md` against it to the host-absolute string `/README.md`
(`src/builtins/fs.js:542`, `fs.js:570`). That path has no authenticated
logical-root binding, so the armed host refuses it as an unbindable host path
(`crates/capsec-semantics/src/arming.rs:206`) — and a session started in a
repository that contains `README.md` reports a generic permission error
(`src/host/mod.rs:1449`) for a file that startup had just authenticated as part
of the project root.

The failure is wrong twice: the read should succeed, and the error names
neither the real problem nor its class. The cause is a conflation of three
concepts that share a spelling but not a meaning:

1. the shell's host working directory, used to choose and authenticate a
   project at startup;
2. the armed snapshot's logical project-root binding; and
3. the JavaScript-visible current working directory used for lexical path
   resolution.

Treating them as one value either leaks a host path or makes ordinary relative
paths unusable. A virtual namespace gives JavaScript a coherent absolute path
model while keeping the authenticated host boundary — the move WASI preopens
and Capsicum's directory-relative discipline make in other capability systems.

A second, quieter failure motivates the identity half of this document. The
armed host today recovers a logical path by prefix-matching *host path
components* against authenticated bindings (`arming.rs:190`), and it maps a
relative path by joining the Rust process cwd (`src/host/mod.rs:288-298`).
Meaning is inferred from string shape (`path.is_absolute()`). That inference
cannot distinguish a virtual path from an explicit host path, cannot tell which
principal's binding a spelling refers to, and makes the module cache key on a
string (`src/module_loader/mod.rs:805-806` — `full_path.to_string_lossy()`) that two
principals can produce for different resources, and that silently aliases two
distinct host paths when either is not valid UTF-8. Carrying identity instead of
inferring it from text is what makes the rest of this contract enforceable rather
than aspirational.

## Scope

This document specifies, for all armed execution modes:

- the virtual namespace, its mount table, and its path grammar;
- **project-root discovery and package-binding containment**, because the mount
  table is meaningless without a specified rule for what backs `/project`;
- staged logical path identity, its relationship to display spelling, and its
  separation from module identity;
- normalization, alias canonicalization, traversal, containment, and staged
  symlink discovery;
- the virtual resolution base (working directory) and its mutation rules;
- the set of path-bearing observables and their armed values;
- the typed logical-path ABI, the runtime/session handle it requires, and the
  structured resolver result and error-code mapping the host adapters owe
  JavaScript; and
- the capsec registry rows and datasets this design obliges.

It does not specify the REPL's interactive behavior (LLP 0022), the evaluation
seam (LLP 0024), or terminal ownership (LLP 0025). It does not admit a
subprocess, a debugger, or a system-information authority; where those need
paths, they must adopt this contract rather than invent a second one.

## Design

### 1. The mount table, the project root, and package bindings

The armed namespace has one initial mount:

| Virtual path | Armed binding | Purpose |
| --- | --- | --- |
| `/project` | logical root `project` | source tree and default resolution base |

The mount table is a **typed table with per-mount attributes** — write policy,
symlink-follow policy, lifecycle, and whether it is metadata-only — even though
v1 has one row. A second mount is then an additive row rather than a new design.

The runtime's other logical bindings are **not** mounted. In particular the
`home` binding — today the machine-global runtime cache holding generated
JavaScript and bytecode for every project on the machine
(`src/bin/ibex/runtime.rs:1918-1945`) — stays runtime-internal: the loader and
cache machinery use it natively, and it is not addressable from JavaScript.
Mounting an internal executable cache would create cross-project disclosure and
cache-poisoning channels (a write to another project's cached bundle is a write
to code that project will later execute), and under the spelling `/home` it would
additionally shadow the most common Linux host-path prefix, turning a habitual
host spelling into an in-mount `ENOENT` instead of a clear namespace error.

Any future mount — `/tmp`, `/state`, or another — requires an update to this
document specifying its isolation, lifecycle, write policy, and relationship to
internal caches. Adding a mount is a security decision, not a configuration
detail.

`/` is the **synthetic namespace root**: not the host filesystem root, and not
an alias for `/project`.

#### 1.1 Project-root discovery

**The project root is discovered, not inferred from the entry's location.** This
is a normative rule, not an implementation detail, because §1.2's containment
invariant is unstatable without it.

Today the project candidate is `canonicalize(entry).parent()`, falling back to
the host cwd (`src/bin/ibex/runtime.rs:1674-1677`). That is wrong: `ibex
src/app.js` mounts `<repo>/src` as `/project`, which places `<repo>/node_modules`
*outside* the mount. Layered on §1.2, it would refuse arming for essentially
every real project whose entry is not at the repository root. The entry's parent
directory is not a project.

Project-root discovery is **one rule shared by every mode** — file execution,
`ibex run`, REPL, program stdin, `-e`/`-p`/`eval`, and embedders. Because the
selected directory *is* the authority boundary, the algorithm is pinned exactly,
not described:

1. Take the **discovery origin**: the canonicalized entry file's directory where
   there is a file entry, and the shell's current directory otherwise (REPL,
   stdin, `-e`/`-p`/`eval`). An embedder supplies it explicitly.
2. Ascend from the discovery origin toward the filesystem root, collecting every
   ancestor that carries a marker. The v1 marker set is a **versioned constant**
   with exact names and field predicates:

   | Marker | Test | Membership predicate |
   | --- | --- | --- |
   | workspace root | `pnpm-workspace.yaml` with a `packages:` list | origin is matched by a `packages:` glob and not excluded by a `!`-prefixed one |
   | workspace root | `package.json` with a non-empty `workspaces` field (array, or `{ packages: [...] }`) | origin is matched by a `workspaces` glob and not excluded by a `!`-prefixed one |
   | lockfile | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`, or `bun.lock` | — |
   | package manifest | `package.json` | — |

   **Membership is evaluated, not assumed — and it is ancestor-inclusive.** "The
   origin is a member of the workspace" is the predicate the whole algorithm turns
   on, so its evaluation is pinned rather than left to whichever glob library an
   implementation reaches for:

   > The origin **is a member** if the origin, **or any ancestor of the origin at or
   > below the declaring directory**, is matched by a member pattern. Patterns are
   > matched against that candidate's path **relative to the declaring directory**;
   > `*` does not cross a `/`, `**` does; a leading `!` excludes; the **last**
   > matching pattern wins. Any other glob construct (`?`, character classes, braces,
   > escapes) is **unsupported and fails closed**: the marker is treated as malformed
   > (below), not silently ignored.

   **Ancestor-inclusive is the load-bearing word, and an earlier draft omitted it.**
   That draft matched only the origin itself — and the origin is the entry file's
   *directory*. So for `ibex packages/foo/src/app.js`, the origin is
   `packages/foo/src`, which `packages/*` does not match, because `*` does not cross
   a `/`. The workspace clause would then never fire, selection would fall silently
   through to "nearest lockfile," and in a repo whose member carries its own lockfile
   — or which has none at the root — it would select `packages/foo`, put the hoisted
   `node_modules` outside `/project`, and refuse to arm. That is precisely the failure
   §1.1 exists to prevent, reintroduced by the predicate meant to prevent it. (Ibex's
   own `package.json` declares `workspaces: ["packages/*"]`, so the repository this
   document lives in is an instance of the case its own acceptance criterion missed.)
   Matching `packages/foo` — an ancestor of the origin, at the declaring directory's
   level — is what makes the rule fire.

   This is one dialect, applied to every marker kind, and it is part of the versioned
   marker-set constant — because npm, yarn, pnpm, and bun do not agree with each
   other, and a security boundary cannot be decided by a coin-flip between their
   dialects. Where a tool's own semantics differ, the operator's remedy is
   `--project`.

   An earlier draft also listed "a `[workspace]` table in a Cargo-style manifest
   where the project is polyglot." That predicate is circular — *polyglot relative to
   a root not yet selected* — and is withdrawn. A non-JavaScript workspace root is
   not a v1 marker.

3. **Selection is cross-ancestor, not nearest-first.** The **outermost ancestor
   that declares a workspace of which the discovery origin is a member** wins. If
   there is none, the **nearest** ancestor with a lockfile wins. If there is none,
   the **nearest** ancestor with a `package.json` wins.

   A marker that is present but **malformed or unreadable** (unparseable YAML, a
   `workspaces` field of the wrong type) is an **arming error naming the file**, not
   a silent skip — a project whose workspace declaration cannot be read is a project
   whose authority boundary cannot be established.

   Nearest-first would be wrong, and the failure is the one §1.1 exists to
   prevent: `ibex packages/foo/src/app.js` would select `packages/foo`, whose
   nearest marker is its own `package.json`, leaving the workspace's hoisted
   `node_modules` outside `/project` — and §1.2 would then refuse to arm every
   ordinary monorepo. Selecting the workspace root instead mounts one `/project`
   that contains both the member package and the hoisted dependencies, and it
   arms.

4. **Ascent stops** at the first of: a device/filesystem boundary; the invoking
   user's home directory (a marker in `$HOME` must never enlarge `/project` to
   the whole home directory); an ancestor the runtime cannot authenticate; or the
   filesystem root. A marker found *at* a stop boundary is not selected.
5. If no marker is found, the discovery origin itself is the candidate and a
   diagnostic names the fallback — a project without a marker is a legitimate
   thing to run, but the operator should know the mount is narrow. **Exception:** if
   the discovery origin *is* a stop boundary — the user's home directory, in
   particular (a REPL launched from `~`) — the fallback does **not** silently mount
   all of `$HOME` as `/project`; it requires an explicit `--project` and emits a
   distinct wide-mount diagnostic. The stop rule prevents ascent *into* home; this
   prevents *starting* there.
6. The candidate is canonicalized and authenticated, and becomes the `project`
   binding. Authentication precedes any JavaScript evaluation. **A `--project`
   override is recorded in the discovery record as its own marker kind** (§1.1's
   snapshot fields, `OBL-DISCOVERY-RECORD`), so a diagnostic can distinguish a
   discovered root from an operator-pinned one.

An explicit operator override (`--project <dir>`) may name the project root
directly; it is subject to the same authentication and to §1.2, and it is the
supported escape hatch for a layout the marker rules do not fit.

**The discovery decision is recorded in the armed snapshot** — which marker kind
selected the root, and at which path — so that a diagnostic can explain *why*
`/project` is what it is, and so that two runs over the same tree cannot
silently disagree. The marker-set version constant is part of the snapshot's
digest input: changing the marker rules changes the armed identity, rather than
silently re-rooting an existing project.

#### 1.2 Package bindings are derived from the graph and contained in the project

Package bindings today are *guessed* at `project_root/node_modules/<name>` and
skipped silently when that path does not exist
(`src/bin/ibex/runtime.rs:1824-1830`). One guess per bare package name cannot
express nested duplicates, two locators with one name, or workspace layouts.

Package bindings are instead **derived from an authenticated graph-location
record**: one binding per graph principal (exact locator plus integrity digest,
per LLP 0021), at that principal's actual resolved root, canonicalized and
authenticated. A principal with no resolvable root is an arming error, not a
silent omission.

**This requires armed-snapshot fields that do not exist.** The armed graph
carries principals and importer/imported edges only — no resolved root, no
resolving specifier, and no virtual alias — and the binding shape carries no
authenticated virtual prefix. The runtime consequently *guesses* the location.
Deriving bindings from the graph is therefore an **LLP 0021 schema obligation**
(ledger `OBL-GRAPH-LOCATION`, §9), not something this document can assume: the
snapshot must carry, per graph principal, its resolving specifier, its canonical
root object, and its authenticated virtual alias set, all inside the armed
digest.

**Ambiguity is refused, not resolved by load order.** If two graph principals
resolve to the *same* canonical root, or two bindings are equally specific for
one path, arming refuses. A defining principal (§2.3) chosen by which import
happened to run first would make a package's compartment depend on execution
order, which is not a property a security boundary may have.

**Integrity is bound to installed content, or it is not an integrity boundary.**
The current resolver states plainly that its `name@version` identity is *not* an
integrity boundary (`src/module_loader/mod.rs:46-48`), while LLP 0021's package
principal is "the exact package locator plus integrity digest." A binding is only
as trustworthy as the check that the bytes on disk are the bytes the digest names.
The verification algorithm and the point at which it runs belong to LLP 0021 and
LLP 0014, not to a path document; this document *depends* on it and rows it
(`OBL-INTEGRITY-BIND`, §9). Until it exists, package bindings authenticate a
*location*, not a *content*, and this document does not pretend otherwise.

**Out-of-project package roots are refused at arming in v1.** LLP 0021 permits a
package binding to sit anywhere on the host, but a package root outside the
project binding — a content-addressed store outside the project, a workspace root
above the project that the marker rules did not select, a monorepo sibling — has
no virtual spelling under a single `/project` mount, so `__dirname`,
`import.meta.url`, `require.resolve`, and error paths for such a package would
have no defined value, and the containment rule of §4 would refuse the
`node_modules/<name>` symlink into the store outright. Rather than leave that
silently broken, **session arming refuses a package graph whose bindings are not
contained within the project binding**.

**The refusal diagnostic names the host path, and that is correct.** An earlier
draft mandated a symbolic-only diagnostic and justified it by citing a general
"startup diagnostics are symbolic" rule in LLP 0025. **No such rule exists** — the
symbolic sentence there is a parenthetical about the legacy history file — and the
mis-citation produced a rule that was both unfounded and unusable: an operator told
only that *some* package is `outside-project-mount` cannot find the store, the
hoist, or the sibling that caused it.

The correct rule, and the one LLP 0022 §4 already states, is that the no-host-path
property binds **JavaScript-visible surfaces**. An arming refusal is emitted by the
CLI, to the operator's terminal, **before any JavaScript exists**; it is not a
disclosure channel because there is no principal to disclose to. So the diagnostic
names the offending **package locator**, the symbolic classification
(`outside-project-mount`), **the out-of-project host root**, and the remedy
(`--project`, or a supported layout). It is the one place in this document where a
host path is printed, and it is printed because the alternative is an operator who
cannot act.

Containment is checked **natively, against the authenticated bindings** — not by
string prefix on an unauthenticated path.

**Platform-conditional dependencies are not a refusal.** A committed artifact
generated on macOS may name an optional, platform-gated package (`fsevents`) that
a Linux install legitimately omits. Such a principal is *absent by declaration*,
which is distinct from *unresolvable*: the graph record marks it optional, arming
omits its binding, and an import of it fails closed with the ordinary
out-of-snapshot error. A principal that is **not** declared optional and cannot be
located is an arming error, per above.

This deliberately scopes v1 to project-contained layouts. It **admits** an
in-project content-addressed store (pnpm's default `node_modules/.pnpm`, whose
package directories sit inside the project even though their file *content* is
hard-linked from a global store) and every `node_modules` layout including
in-project symlinks. It **refuses** an out-of-project store, a workspace root
hoisted above the project, and monorepo siblings. Supporting those requires
either per-package mounts or a containment rule that admits a principal's own
bindings — a design this document defers to open question 5, not an accident of
the mount table.

Note that an in-project content-addressed store means two *different* packages
can contain byte-identical files that the store hard-links to **one inode**.
§2.3's module identity is built to survive that.

### 2. Identity versus spelling

`/project/src/a.ts` is a *display spelling*. It is never an authorization key and
never a cache key. What the runtime authorizes, retains, and caches on is an
authenticated identity — and that identity is **staged**, because a path acquires
an authenticated binding before it acquires a platform object.

#### 2.1 Staged authorization identity

A single tuple containing a "retained platform object" cannot describe the
requested stage of a decision, and cannot describe a create at all: the target of
`writeFile("/project/new.txt")` does not exist when the write is authorized.
CapSec already models this correctly — `OccurrenceResource::PathOccurrence`
carries `requested: LogicalPath` with `parent_object` and `final_object` as
**optional** (`crates/capsec-semantics/src/model.rs:1273-1284`). This document
adopts that staging as its identity model:

| Stage | Identity | Contains |
| --- | --- | --- |
| **NamespacePath** | pre-discovery | runtime/session handle, authenticated logical root, binding owner, normalized components |
| **DiscoveredPath** | post-discovery | a NamespacePath, plus the retained parent object, the basename, and an existence witness (present / absent) |
| **CommittedPath** | post-commit | a DiscoveredPath, plus the retained final object or handle |

The **requested-stage** decision is taken on a NamespacePath: it is exactly the
decision that says "this principal may attempt this operation on this named
resource," and it is the gate that must precede any host lookup. Discovery
authorizes the transition to DiscoveredPath. The **commit-stage** decision is
taken on a CommittedPath and re-verifies that the retained object still matches
what was authorized. This is the staging discipline of LLP 0021, not a new one.

**Requested-stage existence must become genuinely unknown.** Today it is not:
`OccurrenceResource::PathOccurrence` makes `object_state` a **mandatory** field
(`crates/capsec-semantics/src/model.rs:1277`), and the ABI hardcodes
`ObjectState::Existing` at the requested stage (`src/host/abi.rs:1058-1062`) —
so the model *speculates* that the target exists before anything has looked.
That is precisely the speculative-stage-fact the governing model prohibits, and
it is why a NamespacePath cannot be expressed today. Admitting an `Unknown`
object state at the requested stage is an **LLP 0021 obligation**
(`OBL-OBJECT-STATE`, §9), covering the model, the schema, the ABI, and the digest
and cache vectors together. This document does not paper over it.

The **decision-cache** key is unchanged from LLP 0021
(`crates/capsec-semantics/src/cache.rs:49-61`: action, canonical resource bytes,
principal set, effect owner, stage, digests, generations, positive-authority
context). This document supplies the *resource* and *owner* components of that
key; it does not replace it.

#### 2.2 Authorization identity is caller-relative

*Binding owner is part of authorization identity.* There is one namespace and one
mount table for every principal in the runtime: package code resolving `./x` or
`/project/src/a.ts` obtains the same spelling root code would, so the namespace is
not a per-principal illusion. What differs is **authority, not visibility**. The
armed host maps a virtual path to the most specific binding owned by the principal
whose authority is being tested — a package's own root where it owns one, the
project binding otherwise — and takes the typed decision against that binding.

**Each constrained principal is evaluated against its own binding.** An earlier
draft of this document asserted the opposite — that one occurrence is keyed on the
effect owner's mapping and every other constrained dimension is evaluated against
*that* — and it was wrong. The governing rule is that "package-root ceiling
selectors evaluate separately against each constrained package principal's own
binding" (LLP 0021), the machine-readable policy dataset carries it verbatim as
`evaluate-separately-against-each-constrained-package-principals-own-binding`, and
the evaluator implements it: `expected_owner` prefers the constrained principal
under test and falls back to the effect owner
(`crates/capsec-semantics/src/decision.rs:1129-1133`).

That rule is also the *safe* one, which is why it should not have been overridden.
The same host object has a different logical spelling under different bindings —
`/project/node_modules/foo/x` is `package(foo)/x` to `foo` and
`project/node_modules/foo/x` to everyone else. Evaluating principal B's authority
against principal A's coordinate system tests a grant in a frame it was never
written for. Evaluating each principal against its own binding means B's
package-root grant can only ever authorize paths inside B's own root, which is
exactly the containment property the compartment model exists to provide.

**The shipped model cannot express this, and saying otherwise was the last
draft's error.** A previous revision asserted, in the present tense, that "B's
package-root grant can only ever authorize paths inside B's own root." That is
**false of the code today**, and the reason is worth stating precisely because it
is not obvious:

`LogicalRoot` is a **payload-free enum** (`crates/capsec-semantics/src/model.rs:575-581`),
and a logical path is built by stripping the binding's prefix and keeping the tail
(`arming.rs:214-218`). So `/project/node_modules/A/x` mapped under **A's** binding
and `/project/node_modules/B/x` mapped under **B's** binding are the *same value* —
`{root: Package, components: ["x"]}`. **The resource does not say which package.**
Meanwhile the evaluator's owner gate compares the **authority's** declared
`package_root_owner` against the **principal under test**
(`decision.rs:1136-1139`) — never against the binding the *resource* was mapped
under, because the resource carries no such fact. Consequently, for an occurrence
computed under A's binding, constrained principal **B's own package-root grant
passes both the owner gate (B == B) and bytewise containment** — and authorizes
B's dimension for **A's file**. That is exactly the confusion this document exists
to prevent.

**The fix is per-dimension projection.** One host object is discovered; the
resource is then **projected separately into each constrained principal's own
binding**, and each principal's authority is evaluated against *its own*
projection:

- For an occurrence on A's file, **A** projects to `{root: Package, components: ["x"]}`
  — A owns the containing package binding.
- **B**, which owns no binding containing that file, projects the *same object* to
  `{root: Project, components: ["node_modules", "A", "x"]}` — because package
  bindings match only their exact owner (`arming.rs:191-194`), so B's most specific
  covering binding is the project.
- B's package-rooted grant (`{root: Package, …}`) then fails on **root mismatch**
  against B's project-rooted projection. B's self-grant cannot reach A's file — as
  a structural consequence, not an assertion.
- And B's *legitimate* self-authority still works: an occurrence on B's own file
  projects, for B, to `{root: Package, …}` and matches.

The mapping function already exists — `logical_path_for_host_components` **takes a
principal** (`arming.rs:179`) and does exactly this. The host simply calls it once,
for the acting principal (`src/host/mod.rs:334`), where it must call it once per
constrained principal.

**But it does need a wire change, and an earlier draft was wrong to say otherwise.**
The effect model carries **one** resource per effect
(`capsec/schema/effect.schema.json`, `crates/capsec-semantics/src/model.rs:1421`),
and the decision cache stores that resource **unpaired** from the principal set
(`cache.rs:49`) — so there is nowhere to put N projections, and a payload-free
`LogicalRoot` cannot recover which projection belonged to which principal even if
there were. The occurrence must carry an exact map
`{principal → projected resource}` whose key set **equals** the constrained set, and
the cache must key on **principal-resource pairs**, not on a resource beside a set of
principals.

**And the projection must be computable *before* the lookup, which is the harder
half.** §2.1 requires the requested-stage decision to precede any host access. An
earlier draft described "one host object is discovered; the resource is then
projected" — which is discovery-first, and would authorize *after* looking. The
requested-stage projection is therefore **lexical**: it maps the virtual path
through the authenticated bindings, with no I/O at all. That is possible — the
bindings are in the snapshot — but it requires each binding to carry its
**authenticated virtual prefix**, which none does today (`arming.rs:58`). Discovery
and commit stages then re-project from the *retained canonical location*, which is
where physical facts legitimately enter.

Until all three land, the containment property above **does not hold**, and this
document does not claim it does. It is rowed as `OBL-OCCURRENCE-PROJECTION` (§9),
and AC 20a is explicitly gated on it.

**Nested bindings are a deliberate exception, and it must be stated.** With
`node_modules/a/node_modules/b`, package `a`'s binding *physically contains* `b`'s
files, so `a`'s projection of `b`'s file lands inside `a`'s own frame
(`{root: Package, components: ["node_modules", "b", "x"]}`) and `a`'s package-root
grant does reach it. That is **intended**: a package root genuinely contains its
nested dependencies on disk, and a `path-tree` grant over that root means what it
says. It does *not* re-open the defect above, because the defect was about
**siblings** — B reaching A's files while owning no binding over them. And it does
not collapse compartments: `b`'s **module** identity and execution compartment
remain `b`'s (§2.3), because the defining principal is the owner of the *most
specific* containing binding. Filesystem authority follows the physical tree;
execution identity does not. A document that has just withdrawn an over-claimed
containment property should not leave its replacement with an unstated exception, so:
this is the exception, and it is by design.

Consequences that follow, and that an implementation must not violate:

- No virtual path addresses a package binding *as such*. There is no
  `/packages/<name>` spelling. A package's own files are reachable at their
  `/project/node_modules/<name>/…` spelling, resolved against whichever binding
  that principal owns there.
- A `/project/…` string handed from root to package code (or the reverse) is
  **re-resolved under the receiving principal's identity**. It carries no
  authority with it. Passing a string is not delegation; delegation requires a
  handle (LLP 0021).
- A symlinked or workspace-linked package resolves to its owner's binding, not
  to whatever binding its physical location would suggest.

#### 2.3 Module identity is a tagged algebra, keyed on the *defining* principal

**Authorization identity is not module identity.** The staged identity above is
the *authorization* key and is deliberately caller-relative: the same file
authorizes differently for root and for its owning package. Using it as the
*module* key would be a serious error — root's `import "foo/util.js"` resolves
under the project binding while `foo`'s own `require("./util")` resolves under
`foo`'s package binding, so a caller-relative module key would instantiate the
same file twice, breaking module-level state, singletons, and `instanceof`
across the root/package boundary.

But keying module identity on the retained object *alone* is also wrong, in two
ways. It cannot express the modules that have no file object at all — builtins
(already specially keyed today, `src/engine/bootstrap/module-loader.js:5253-5256`),
`repl:<n>`, `ibex:stdin`, `ibex:eval` — and it **collapses compartments** when one
inode is reachable from two package roots, which §1.2 explicitly admits: an
in-project content-addressed store hard-links byte-identical files, so two
different packages can share an inode, and first load would decide the execution
compartment for both. That would violate LLP 0013's one-compartment-per-package
invariant through a filesystem coincidence.

Module identity is therefore

```
(runtime, SourceId)
```

— **one** key shape for every module kind, not a family of rival shapes.

An earlier draft gave file-backed modules `(runtime, defining principal, retained
object)` and generated modules `(runtime, defining principal, provenance id)` as
*different variants*, and then demanded that raw, bundled, and bytecode execution
of the same source "agree on identity." Two distinct key shapes cannot agree; the
requirement was unsatisfiable as written. The fix is to name the thing they are all
identities *of*.

**The defining principal appears exactly once, inside `SourceId`.** A subsequent
draft wrote the key as `(runtime, SourceId)` while *also*
putting the defining principal inside `SourceId` — which is either redundant or a
sign that one noun was covering two concepts. It is redundant: they are the same
principal. The outer copy is removed, deliberately and now, because this corpus has
already lost a round each to a noun quietly covering two things.

**`SourceId` is the authenticated identity of a source module**, stable across every
form that source is executed in. It is **defined**, not merely named — an earlier
draft called the file-backed case "the authenticated source identity of that file
within its binding," which is a circularity rather than a constructor — and it is
**total**: every module kind has a well-formed value.

| Module kind | `SourceId` | Retained object |
| --- | --- | --- |
| file-backed, in a **package** | `(package principal identity, binding-relative lexical-canonical path)` — the package principal identity is LLP 0021's locator + integrity digest | **verification evidence** for the SourceId |
| file-backed, in the **project** (no package) | `(authenticated root identity, binding-relative lexical-canonical path)` | **verification evidence** |
| builtin | `(runtime builtin domain, source key)` | none |
| synthetic module (`ibex:stdin`) | `(authenticated session identity, source identity)` of LLP 0024 §2 | none |
| generated (bundled chunk, bytecode) | **the same SourceId the raw file has**, carried per original module in the provenance manifest | the chunk's object is *not* any module's identity |

**The project arm is the busiest one, and an earlier draft left it undefined.** That
draft made the principal component "locator + integrity digest," which is LLP 0021's
**package** principal identity (`0021:318`) — but the `Root` principal carries only
an `identity` and has neither (`crates/capsec-semantics/src/model.rs:304`). So a
prompt `import "./util.js"` over an ordinary first-party project file — the single
most common module in a session — had **no well-formed identity at all**, and
LLP 0024's "one file is one module instance" guarantee was undefined for first-party
code. The principal component is therefore **the LLP 0021 principal identity for
that principal's kind**, whatever kind it is: locator+digest for a package, the
authenticated root identity for root.

One caveat the machine-portability claim below depends on: the **root `identity` must
be a project-stable, host-independent value** — derived from the authenticated project
identity, not from a host path or a per-launch session nonce — or the *package* arm's
provenance manifest is portable while the *project* arm's is not. Whatever
`OBL-SOURCE-ID` fixes for it must assert that stability; if it cannot, the portability
claim below is scoped to the package arm and the project arm's SourceId is
session-local.

**The path component is the *lexical* canonical component vector** — the retained
object's canonical physical in-namespace location, spelled in lexically-normalized
components (`.`/`..`/empty collapsed) **without** the per-volume canonicalization of
§3. Volume canonicalization (case folding, normalization form "as the volume actually
implements them") is deliberately **machine-specific**, and a machine-specific value
cannot serve as a build-time identity that a provenance manifest generated on one
machine must reproduce on another. So volume canonicalization is confined to
**authorization** identity; `SourceId` uses the lexical form.

One consequence must be stated rather than left implicit: on a case- or
normalization-aliasing volume, two spellings of one file (`README.md`, `readme.md`)
are **one authorization identity** (§3) but, spelled differently, **two `SourceId`s**
— so a program that imports both spellings gets two module instances, exactly as Node
ESM does on such a volume. Authorization safety is unaffected (both spellings
authorize identically). Whether module identity should *also* unify them is open
question 10; v1 accepts the Node-equivalent split rather than inventing a
volume-dependent module key.

The retained platform object is therefore **evidence**, not a key: it proves the
bytes behind a file-backed SourceId are the ones authorized. A bundled chunk
containing forty original modules carries forty SourceIds in its provenance
manifest; the chunk's inode identifies none of them. This is what lets raw,
bundled, cached, and bytecode execution of one source share one module instance —
they share a SourceId. It is also **build-computable and machine-portable**, which
an object-derived key would not be: a provenance manifest generated on one machine
must name the same modules on another.

**`SourceId` is not `SourceLabel`.** Identity and display are different problems
and must not share a value. `SourceId` is opaque, authenticated, and keys the
module cache. **`SourceLabel`** is the deterministic human- and tool-facing
spelling — the virtual `file:///project/…` URL, or an LLP 0024 synthetic identity —
and it is what `import.meta.url`, stack frames, source maps, and error paths carry
(§6). Conflating them is how a cache key ends up in a stack trace, or a display
string ends up deciding instance identity.

**`SourceLabel` is pinned, and it does not depend on load order.** A prior draft
called `SourceLabel` "deterministic" while leaving its *constructor* open (the old
OQ 7), which is not a definition — `realpath`, `import.meta.url`, source maps, and
error paths all demand a canonical output, so the spelling must be fixed. It is: the
**volume-canonical virtual spelling of the retained object's canonical physical
location**. Because `SourceLabel` is a display value shown on *this* machine, it may
use §3's per-volume canonicalization (the operator sees the real spelling on their
disk), unlike `SourceId`, which must be machine-portable and therefore lexical. When
one object is reachable by several in-project aliases:

- a **symlink** alias resolves to its physical target's canonical spelling (the
  realpath), so every symlink to a file yields the same `SourceLabel` — matching the
  symlink *unification* of `SourceId`;
- a **hard link** is a genuinely distinct directory entry with its **own** `SourceId`
  (§2.3 splits hard links), so its `SourceLabel` is that **same entry's own**
  (volume-canonical) spelling — *not* a lexically-least spelling shared across all the
  aliases ("own-entry", not "lexical", is the operative word; `SourceLabel` uses §3's
  volume canonicalization, being a display value, unlike the lexical `SourceId`). This is
  the correction the round-7 review forced: labeling every hard-link entry with one
  shared spelling collided the distinct-`SourceId` modules' referrers (§7.3, "that
  module's virtual directory") and LLP 0024's source-map key, and it demanded a
  reverse object→entries index the model does not have (`ObjectIdentity` is
  platform/volume/file only, `crates/capsec-semantics/src/model.rs:614-620`). Per
  entry, `SourceId`, `SourceLabel`, the §7.3 referrer, and the source-map key all
  agree, and no reverse index is needed.

Component ordering, where "lexical" is used, is **byte-wise lexicographic over the
UTF-8 encoding of the component vector** — a total, locale- and machine-independent
order, matching why `SourceId` uses the lexical (not volume-canonical) vector.

**Query and fragment are stripped from a file-backed `SourceId`.** This closes the old
OQ 8, which left "include / strip / refuse" undecided while §2.3 called `SourceId`
total — a contradiction. A file's identity is its bytes at its canonical location; a
`?v=1` on a file specifier is not a second file. So a file specifier carrying a query
or fragment is accepted, and the query/fragment is **ignored for identity and module
caching**: `import("./x.js?v=1")` and `import("./x.js?v=2")` are **one** module
instance. This is a **stated divergence from Node ESM**, which splits instances on
differing query and fragment (verified by running Node). The divergence is
deliberate — v1 has no query-based cache-busting need, and keeping identity tied to
bytes rather than to a URL decoration is the safer default — and it is pinned by a
fixture rather than left to chance.

**Script inputs are not modules and have no module identity.** `repl:<n>`,
`ibex:eval`, and `.load`'s `repl:<n>:<virtual path>` are *script* sources under
LLP 0024 §3, evaluated into the session record rather than instantiated as
modules; `.load` explicitly creates no cache entry. Listing them as rows of a
module-identity algebra, as an earlier draft did, was a category error. They have
**source** identities (LLP 0024 §2), which §6 disposes of as observables; they do
not key the module cache. Only `ibex:stdin` — a module goal under LLP 0024 §3 — is
a synthetic *module*.

**The defining principal** is the owner of the most specific binding containing
the module's source, computed **caller-independently** and **from authenticated
binding provenance** (§1.2) rather than from a string prefix. It is resolved at
the **DiscoveredPath's canonical location** — the physical, in-namespace location
of the retained object — so a symlinked package directory resolves to its owner's
binding, not to whatever its link's spelling suggests. "Most specific" means the
longest authenticated binding path, so a nested `node_modules/a/node_modules/b`
resolves to `b`. Equal-specificity ties and shared canonical roots are **refused
at arming** (§1.2), never broken by load order.

This is what makes the key work:

- Root's `import "foo/util.js"` and `foo`'s own `require("./util")` have the same
  defining principal (`foo`) and the same SourceId, so they are **one module
  instance**. Module-level state and `instanceof` survive the boundary, as
  LLP 0024 requires; what differs between the callers is the authority under which
  they reached it, not the instance they get.
- Two different packages whose files are hard-linked to one inode have **different
  defining principals**, so they are two modules in two compartments. The
  filesystem coincidence is contained.

**Retention is an identity record, not a held descriptor.** A retained object is
`(volume, file, verification generation)`, re-verified at commit; it is not a live
descriptor held for the session, which would exhaust the descriptor budget on a
real graph. `ObjectIdentity` today is platform/volume/file only
(`crates/capsec-semantics/src/model.rs:616-620`) and the Unix adapter records device
and inode, so **"verification generation" does not exist yet**: it must be a
platform-supplied generation counter where one is reliable
(`st_gen`/`ATTR_CMN_GEN_COUNT`), and a retained descriptor for the object's lifetime
where none is. Naming that primitive and its fallback is an obligation
(`OBL-OBJECT-GENERATION`, §9), and revalidation runs at **commit**, not on every
module-cache hit — a cache hit that performed a filesystem lookup would turn every
`require` into an authorized effect.

**Relationship to Node, verified by running Node** — because this document has a
history here worth naming once. Across five review rounds, **four** separate
Node-compatibility claims proved false, and *every one* entered as a reviewer's
assertion adopted without executing Node (the `%5C` "Node refuses it" claim of §3,
and this paragraph's own earlier "ESM splits symlinks" claim among them). A borrowed
empirical claim about an external system is a rumor with a citation. The statements
below were checked with `node`:

- Node CommonJS keys on the realpath — **unifying symlink spellings, splitting hard
  links** (two hard links to one inode load as two modules).
- Node **default ESM also resolves symlinks** — importing a file and a symlink to it
  yields **one** instance (`a === b` is true); the split appears only under
  `--preserve-symlinks`. An earlier draft here claimed default ESM *splits* symlinked
  specifiers. It does not. That false claim sat in the paragraph that says "fixtures
  pin each of these" — the fixture would have failed.

This design **unifies symlink spellings** (like Node CJS and like default Node ESM)
and **splits hard links** (like Node CJS). A yet-earlier draft additionally claimed to
*unify* same-principal hard links — invented here, not Node's behavior, required by
nothing, and jointly unsatisfiable with the build-portable-manifest requirement; it is
withdrawn. Cross-principal hard links split necessarily, since their defining
principals differ — the compartment-collapse fix, delivered for free. The result is
close to Node, the differences are pinned by fixtures, and **no fixture pins a Node
behavior Node does not have.**

### 3. Path grammar, normalization, aliasing, and containment

A canonical virtual path is `/` followed by `/`-separated, non-empty, UTF-8
components containing neither `NUL` nor `/`.

Resolution is **normalized-path-equivalent**. It normalizes lexically first —
collapsing `.`, empty components, and `..`, which may traverse above a mount
root — and *then* applies mount containment to the normalized result.
Therefore:

- `..`, `/project/..`, and `/` all denote the synthetic root;
- `/project/../etc/passwd` is exactly `/etc/passwd`, and is refused as
  outside-mount rather than treated as an escape attempt with a different
  error;
- a normalized path inside a mount is *in-namespace* and proceeds to the typed
  decision;
- a normalized path outside every mount — `/etc/passwd`, `/home/<user>/x`,
  `/README.md`, any child of `/` that is not a mount name — is refused with the
  **outside-mount error**, a class distinct from `ENOENT`, before any host
  access. The diagnostic enumerates the mount table, which discloses nothing (the
  synthetic root is publicly listable, below) and makes the most common confusion
  self-explaining.

Lexical `..` collapse *before* symlink resolution is a deliberate
capability-system choice: it matches `path.resolve` and WASI-style discipline,
and it makes containment decidable without a filesystem round-trip. It differs
from host `open()` semantics when an intermediate component is a symlink. That
divergence is accepted and documented rather than reconciled; it is not a bug
to be "fixed" by physical resolution, which would reintroduce the round-trip
this design exists to avoid.

**Alias canonicalization.** Byte-lexical component equality is *not* sufficient
for authorization identity on the advertised target. macOS default volumes alias
case and Unicode normalization form, so `/project/Secrets` and `/project/secrets`
are two byte-distinct component sequences naming **one platform object** — and a
path-keyed denial or a `path-tree` ceiling authored with one spelling would be
silently sidestepped by the other, while the host cheerfully opens the denied
object. There is no alias machinery in the runtime today; LLP 0021's Apple
bound-volume alias key exists only at arming.

Therefore: **authorization identity is computed over volume-canonical
components** — and **on both sides of the comparison**.

Canonicalizing only the runtime occurrence would be worse than doing nothing. The
armed snapshot binds authored selectors without canonicalizing them, and
containment compares component vectors bytewise
(`crates/capsec-semantics/src/containment.rs:393-396`). Canonicalize
`/project/Secrets` at occurrence time and an authored `/project/secrets` selector
stops matching it — turning a denial that would have fired into one that does not,
and a grant that would have applied into one that does not. That is a *new* bug,
not a fix.

The rule is therefore:

- one **versioned per-volume canonicalization function**, supplied by the
  bound-volume adapter (case folding and Unicode normalization form as the volume
  actually implements them);
- applied to **authored authority selectors at arming** and to **occurrences at
  decision time**, so both sides live in the same coordinate system;
- its identity is **bound into the snapshot digest**, so a change to the
  canonicalizer changes the armed identity rather than silently re-interpreting
  existing policy;
- alias collisions are compared only within the same bound-root/volume namespace,
  exactly as LLP 0021 requires; two packages' separate bindings never alias.

On a volume with no aliasing, canonicalization is the identity function and costs
nothing. Display spelling is unaffected — the operator sees what they typed. This
changes LLP 0021's decoded-byte-identity rule and its containment vectors, and is
rowed as `OBL-ALIAS-CANON` (§9).

**Component and input rules.** These bind **adapter inputs** — the path arguments
of `fs`, file URLs, module specifiers, and every other surface that takes a path
*to perform an effect on*. They do not bind `node:path`'s string arithmetic, which
is not an adapter (below).

- The **empty path** is malformed adapter input. (`path.resolve("")` is unaffected:
  it treats the empty string as no component and consults the resolution base,
  which is string arithmetic, not an adapter call.)
- A **trailing slash** asserts directory intent and is carried as a flag on the
  NamespacePath, not as a component.
- Path arguments that are **not valid UTF-8** — including Buffer inputs that do not
  decode, and lone surrogates — are refused as malformed adapter input. This is a
  deliberate v1 narrowing: LLP 0021's typed vocabulary can represent non-UTF-8 Unix
  components (`PathComponent::Base64Url`,
  `crates/capsec-semantics/src/model.rs:481-484`), and the JavaScript adapter
  declines to. The current `to_string_lossy()` conversions
  (`src/module_loader/mod.rs:805-806`) alias distinct host paths onto one string and
  are retired.
- A **`readdir` that encounters a non-UTF-8 host entry** reports *that entry* as
  malformed and continues; it does not throw away the listing. A directory
  containing one undecodable name must remain enumerable, or a single hostile
  filename becomes a denial of service against its parent. The malformed entry is
  reported as a distinguishable marker, never as a lossily-decoded name that could
  collide with a real one.
- **Windows-reserved component names** (`CON`, trailing dot or space, DOS device
  names) are refused only under a Windows target, mirroring LLP 0021 WP0.

**On target advertisement.** Armed execution is **not** an advertised target
today: the machine-readable profile carries `advertisedTargets: []` with
`aarch64-apple-darwin` as a *candidate*
(`capsec/registry/policy-rules.json`). The CLI's hardcoded refusal of other
targets (`src/bin/ibex/runtime.rs:1663`) is a guard, not an advertisement. This
document therefore asserts no Windows behavior it cannot test, and the obligations
it adds must execute before macOS/aarch64 is promoted from candidate to advertised
(`OBL-TARGET-PROMOTE`, §9).

**The synthetic root is readable namespace metadata.** Listing `/` enumerates
mount names; stat-ing it reports a synthetic directory. Both are facts about the
namespace, involve no host effect, and take no capability decision — so the
generated registry must carry an explicit no-effect branch for them. Without that
branch, a generated `readdir`/`stat` edge demands `fs:list` for a path that never
reaches a filesystem, and the namespace root becomes spuriously privileged. The
synthetic records are pinned, not left to the implementation: `readdir("/")`
returns exactly the mount names in a fixed order, `withFileTypes` reports each as
a directory, and `stat("/")` reports a directory with zeroed times and sizes and a
reserved synthetic device/inode pair that can never collide with a host object.

**File URLs and percent-encoding.** A percent-encoded **forward slash** (`%2F`) in
a file URL is **refused**, not decoded, so no encoding trick can smuggle a
component boundary past normalization. This matches Node's
`ERR_INVALID_FILE_URL_PATH`.

**`%5C` is decoded, not refused — and this is Node-compatible, not a divergence.**
Under this document's POSIX-everywhere rule a backslash is an **ordinary component
character**, not a separator. Node agrees: on POSIX, `fileURLToPath` **decodes**
`%5C` (`file:///tmp/a%5Cb` → `/tmp/a\b`) while refusing `%2F` with
`ERR_INVALID_FILE_URL_PATH`, and `pathToFileURL` re-emits `%5C` — so a backslash
filename round-trips exactly. Ibex's live implementation already does the same.
Backslash is refused only under a Windows target, where it *is* a separator.

Two earlier drafts got this wrong in opposite directions, and the corrections are
worth recording because they are the same lesson twice. The first **refused** `%5C`,
citing a refusal in `src/builtins/url.js` that turned out to sit inside a block
disabled by a literal `false &&` (`url.js:163`) — a citation to **dead code**. The
second decoded it but called the decode a *deliberate divergence from Node*, on a
reviewer's assertion that Node refuses `%5C`. **Node does not**, as running Node
shows in one line. A claim about an external system was written into a normative spec
without anyone executing that system. Both errors were caught by *running* the
artifact rather than reading about it.

Percent-encoded **dot segments** (`%2E`, `%2E%2E`) are **not** refused. They
cannot be: WHATWG URL parsing recognizes and collapses them during URL
construction (`src/builtins/url.js:1348-1355`, `url.js:1666-1672`), so by the time
a `URL` object exists the evidence is gone, and Node does not refuse them either.
The collapse is also harmless — it is exactly the lexical normalization above, and
the resulting path is then subject to mount containment like any other. An earlier
draft of this document required refusal here; that requirement was unimplementable
and mis-cited Node, and is withdrawn.

Other percent-encoding is decoded before these rules apply. The URL host component
must be empty or `localhost`; query and fragment are not part of path identity;
and Ibex never serializes a backing host path into a file URL.

**POSIX everywhere.** In armed execution the default `node:path` module and
file-URL conversions operate in **POSIX mode on every platform including
Windows** — virtual paths never contain drive letters or UNC prefixes — while
`path.win32` and `path.posix` remain pure lexical utilities with their usual
platform-independent string behavior. Host-specific path forms exist only on the
native side of the mount translation. The drive-letter branches in the current
builtins (`src/builtins/fs.js:574-599`, `src/builtins/process.js:43-45`) are dead
in armed mode and are covered by the outside-mount rule; they must not be "fixed"
into the virtual namespace.

### 4. Symlinks: staged discovery, contained creation

A link's target cannot be known without an effect, so escape is **not** detected
"before any host access" — that requirement is unimplementable. It is detected
before any *disclosure or mutation of the target*. The adapter stages the
operation:

1. authorize traversal/metadata discovery of the link itself — **projected into each
   constrained principal's own binding and decided conjunctively over the captured
   constrained-principal set (§2.2)**, not under a single "effect owner's binding";
   the single-principal `currentPrincipalId()` pattern is pervasive in the shipped fs
   helpers (`src/engine/hermes_runtime_fs.cc` passim), and is the one-projection
   behavior §2.2 removes;
2. **retain the link's own platform identity** — not merely its parent's. A
   retained parent does not bind the child name, so a link retained only by its
   parent can be replaced between authorization, `readlinkat`, and follow. The
   stronger primitive already exists in the engine
   (`src/engine/hermes_runtime_fs.cc:570`, `openArmedLinkTarget`), and this
   document requires it. Where a platform cannot retain a link object, the adapter
   must instead perform a pinned pre/post `fstatat` verification with a bounded
   retry count, and a verification mismatch is a refusal, not an unbounded retry;
3. resolve one link step;
4. re-normalize the discovered target and re-apply mount containment — refusing
   with the outside-mount error if it left every mount — and re-authorize the
   discovered target, again **projected per constrained principal (§2.2)**;
5. only then authorize and perform the content read, write, or other effect.

Every numbered stage above is decided over the `{principal → projected resource}`
map of §2.2, not a single binding. The concluding rule of this section and these
steps therefore agree: there is no "effect owner's binding" shortcut anywhere in
symlink handling.

Link chains repeat the staging to a **bound of 32 steps**, after which the
operation is refused with the symlink-depth error. It is a refusal, not a silent
truncation. The bound is a **fixed, versioned constant**, not the platform's:
macOS resolves `SYMLOOP_MAX` at 32 while Linux allows 40, and a limit that varied
by host would make the same project behave differently on two machines — which is
the class of difference this document exists to remove.

**Reading a link back is a translation, and the two encodings are genuinely
distinct.** A link's stored bytes are *physical*: the kernel resolves a relative
target from the link's **physical** parent, not from its virtual spelling, and the
two differ whenever the link's path traverses a symlink or an aliased package root.
If `/project/sub` is itself a link to `/project`, then a link at `/project/sub/l`
storing `../a` is resolved by the kernel from `/project` — landing on a **sibling of
the project root, outside every mount** — even though `../a` read as a *virtual*
path relative to `/project/sub` names `/project/a`. Physical bytes encode physical
topology, and physical topology is exactly what this namespace exists to hide.

(An earlier draft of this document proposed *creating* links with virtual-relative
bytes and concluded that containment at creation made escape impossible. It does
not, for the reason just given. That draft is withdrawn along with the rest of
creation — §4.1.)

- **`readlink` translates the stored bytes back through the mount and binding
  tables** into a virtual spelling, and returns that. It does not return raw stored
  bytes: physical bytes encode physical topology, and physical topology is exactly
  what this namespace exists to hide. Where the stored target resolves to an object
  with **no unique virtual spelling**, or to no in-namespace object at all — a
  foreign link into `/Users/alice/…`, a link into an unmounted binding — `readlink`
  is **refused** with `ERR_IBEX_UNMAPPABLE_LINK` rather than disclosing a host path.
- **A dangling link still reads back.** A link whose target does not exist is
  ordinary on disk (build tools and package managers leave them), so `readlink` must
  have an answer for one — "resolves to an in-namespace object" is false of a link
  to a file that does not exist yet. The rule: the stored bytes are resolved against
  the link's retained parent to the **deepest existing ancestor**, which is
  authenticated and translated, and the non-existent tail is appended lexically. A
  dangling link whose *existing* ancestor is in-namespace reads back as a virtual
  spelling; one whose existing ancestor is not is refused as unmappable.
- **`realpath`** returns the canonical **virtual absolute** path of the final
  object.

Sync and async `readlink` must agree on encoding and on the refusal; they do not
today (`src/builtins/fs.js:5731` validates its `options` and then fails to apply
them to the result, while the async path applies `_encodeFsPathResult`). Under
`{encoding: "buffer"}` the *virtual* spelling's bytes are returned; a non-UTF-8
stored target is refused as malformed, because §3 excludes non-UTF-8 material from
namespace identity and there is no coherent way to test bytes for containment in a
namespace they cannot be named in.

A foreign link into the host is therefore inert rather than a disclosure. The
refusal of unmappable targets is a documented v1 narrowing of `readlink` fidelity,
taken deliberately in favor of the disclosure rule.

Each stage is a typed decision in the sense of LLP 0021: discovery is itself an
effect that must be authorized before it discloses anything — and every stage
resolves under the **projection of the principal whose authority is being tested**
(§2.2), not under a single "effect owner's binding."

#### 4.1 The v1 mutation surface: small, object-bound, and completely specified

The safe v1 filesystem surface is deliberately **narrow**. Everything that is
multi-operand, recursive, watching, name-bound, or composite is **closed**;
everything that remains is a single object under a retained parent, whose safety a
fixture can prove. This is a further narrowing than an earlier draft claimed, and it
is the honest one: this document has now specified complex filesystem operations in
prose *twice* and introduced a security defect *twice*, and the disciplined response
is to close the surface it cannot prove safe rather than attempt a third protocol.

**Closed in v1** — each returns a typed closed-operation denial (`EPERM`), takes no
filesystem action, and is closed **at its public entry point, before any lookup**, so
a composite cannot perform partial effects before reaching a closed leaf:

| Closed | Why |
| --- | --- |
| `symlink`, `link` (creation) | POSIX offers no object-bound operand; two prior drafts specified these unsafely (below) |
| `rename` | `renameat` binds its operands by **name**; the source can be swapped between authorization and the syscall |
| `unlink`, `rmdir`, `rm` (incl. recursive) | name-bound removal has the same swap window; `rm`/`rmSync` also `lstat` + recursively `readdir` before the leaf (`src/builtins/fs.js:5875`) |
| `cp`, `copyFile` | two-operand; `cp` copies entries before it can hit a now-closed symlink op (`fs.js:2587`); the flag modes (`COPYFILE_EXCL`, clone) and partial-write cleanup are unspecified |
| `fs.watch`, `watchFile` | repeated delivery must re-authorize over time against a retained constrained set; the current impl polls `stat`/`readdir` (`fs.js:5250`), and no fixture proves `fs:list` alone cannot start one |
| recursive `mkdir` | LLP 0021 keeps it closed (`0021:678`); it creates many objects, each needing the object-bound create protocol below |
| disposable-temp cleanup (`mkdtempDisposable().remove()`) | routes through recursive removal (`fs.js:3102`), so its disposer cannot satisfy its own contract under the closed surface |
| metadata mutation — `chmod`/`chown`/`utimes` and their `l`- and `f`-variants (`lchmod`, `lchown`, `lutimes`, `fchmod`, …) | not needed for the v1 workload, some are name-bound (`lchown` on a path), and permission/ownership mutation is its own escalation surface; the many such call sites in `fs.js` (roughly 140–200 lines depending on how variants are counted) were previously unclassified |
| `mkdtemp` | creates a directory in a temp location that a single `/project` mount does not provide; part of the temp-heavy surface closed above |

**Closure is by default, not by enumeration.** The list above is illustrative; the
normative rule is that **every filesystem mutation operation not explicitly listed
*open* below is closed**, across sync, callback, promise, `FileHandle`, descriptor,
and stream aliases. A newly added mutation surface is closed until this document opens
it, so it cannot escape classification by being unlisted — the same default-closed
discipline §6 applies to observables.

**Open in v1, and specified completely** — each is a single object reached under a
retained parent:

| Open | Contract |
| --- | --- |
| read, `stat`/`lstat`, `readdir`, `realpath` | staged per §2.1; each stage projected per §2.2 |
| `readlink` and **traversal** of existing symlinks | staged discovery and translation per §4; `node_modules` depends on this |
| single-path writes — the **open-write family**: `writeFile`/`appendFile`, `truncate`/`ftruncate`, `createWriteStream`, `open`/`openSync`/`FileHandle` in any writable/create/truncate flag mode (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`O_APPEND`), descriptor writes, **and the durability operations on an already-authorized descriptor**: `fsync`/`fdatasync`, `FileHandle.sync()`/`.datasync()`, and the `flush: true` write option | one resource, staged, retained-parent-relative; **subject to the package-immutability rule below**. Durability ops are **open** because they act on a descriptor the caller already holds and was already authorized to write — closing the durability *leaf* would let a write succeed and then its `flush:true` deny, the partial-mutation-then-denial composite §4.1 prohibits (the routes perform them post-write at `src/builtins/fs.js:1850,5041,6162`). Every unlisted write alias is still closed by default; a v1 **registry migration marking all effect-classified mutation aliases closed** is owed (`OBL-OBJECT-BOUND-MUTATION`). |
| **non-recursive** `mkdir` | one atomic `mkdirat(retained_parent_fd, name)` and nothing more. It has **no rollback** — an earlier draft rolled back a post-create verification failure with a name-bound `unlinkat` "after verifying the object is still bound to the name," but that verify-then-unlink is the exact TOCTOU §4.1 closes elsewhere (the name-bound rollback `unlinkat`s are at `hermes_runtime_fs.cc:732,740`; `:725` is the `mkdirat` itself; LLP 0021:683): a concurrent replacement between the check and the `unlinkat` deletes the wrong directory. Since `mkdirat` is itself atomic, there is nothing to roll back; a post-create step that fails (e.g. an unexpected verification result) **leaves the created directory** and returns the error. A leaked empty directory is benign; a wrong-directory deletion is not |

Everything closed here is a named obligation, not a permanent refusal:
`OBL-OBJECT-BOUND-MUTATION` (§9) covers the reopening, and requires a concrete
object-bound primitive (for hard links, `linkat(source_fd, "", dst_fd, name,
AT_EMPTY_PATH)` where the platform provides it) plus a stated concurrency threat
model. A guarantee of the form "Ibex never publishes an escaping link" is **not
deliverable** against a concurrent external mutator with today's name-bound syscalls,
and a spec should not promise it.

**Why the two prior drafts were retracted**, recorded because it is the argument for
the closure rather than an apology for it:

- The first specified symlink creation to authorize its target only at *follow* time
  — which would have regressed a shipped control (`hermes_runtime_fs.cc:3281-3300`,
  ENG-22682) that already gates the target at creation.
- The second specified `link` as **source read + destination write**. That is a
  **privilege escalation**: a hard link is a second name for one inode, so a caller
  holding only *read* on a secret and *write* on its own directory could link the
  secret in and then write through the alias — mutating a file it could only read.
  The shipped engine refuses exactly this (`hermes_runtime_fs.cc:3318`: *"It also
  needs `fs:write` on the SOURCE: the new name aliases the inode"*), and LLP 0013
  requires it (`0013:1068`).

Both were caught only because a reviewer read the *shipped* control rather than the
prose.

#### 4.2 Authenticated package source is immutable

**Closing `link` does not close the aliasing hole; a hard link already present in the
admitted layout does.** §1.2 admits an in-project content-addressed store, which
hard-links byte-identical files across packages to **one inode**. Refusing to *create*
a new alias (§4.1) leaves the existing ones, and §4.1 opens single-path writes — so
package B, writing its own file under a legitimate `fs:write` grant, mutates the
shared inode, and **package A's source with it**. A later import runs the mutated
bytes in **A's** compartment under **A's** authority. This is the same aliasing fact
the shipped hard-link-creation check defends against
(`hermes_runtime_fs.cc:3318`), reached through a different door.

The shipped protection does **not** cover it. The armed snapshot's one
`protectedObjects` guard denies `fs:write` on the **project-root directory object**
alone (`src/bin/ibex/runtime.rs:1948-1952`), and the guard matches by **exact inode
identity** (`crates/capsec-semantics/src/decision.rs:946-958`: `object == &guard.object`).
A file *inside* `node_modules` has a different inode than the project root, so the
guard never fires on it.

Therefore, normatively: **authenticated package source is immutable in armed
execution.** No principal — including the package's own — may `fs:write`, truncate, or
open a writable descriptor onto authenticated package source. Package code is
reviewed, integrity-bound, executable content, and mutating it at runtime is a
supply-chain write however it is spelled. First-party project source outside any
package binding stays writable; a package that needs scratch space uses a future
writable state mount (open question 2), not its own root.

**This is a two-mechanism guard, not one, and saying otherwise was the round-5
error.** An earlier draft said "every package binding's subtree is a protected
object," which the shipped guard *cannot represent*: `ProtectedObjectGuard` is
`{action, object}` (`crates/capsec-semantics/src/decision.rs:114-117`), a **single
exact object**, matched by identity (`decision.rs:946`). Package immutability spans
two matching problems that no single guard solves, because they key on different
things:

- **A lexical path-tree guard**, decided at the **requested stage before any lookup**,
  denies `fs:write`/create/truncate to any path that lexically falls within a package
  binding's authenticated virtual subtree (§2.2's projection supplies the subtree).
  This is the mechanism that covers **creating a new file inside a package root** —
  the planted-module case — where there is *no object yet* to match by identity, and
  it is what makes the denial precede existence disclosure (§7.2).
- **An authenticated exact-object / generation set**, decided at the **commit stage**,
  denies a write whose retained final object is package source *however the path was
  spelled* — the hard-link case, where the write's *path* is outside every package but
  its *inode* is package content. This is the set-valued extension of today's
  single-object guard, keyed on `(object, generation)` so inode reuse cannot alias it.

Immutability holds when a write is refused by **either** guard: the path guard stops
in-package spellings and creates before lookup; the object-set guard stops
out-of-package aliases at commit.

**The object set is built once, at arming, by the integrity walk — not lazily.** A
lazily-populated "objects we happen to have loaded" set loses on the first write
through a never-loaded hard-link alias. So the complete package-source
`(object, generation)` set is a **by-product of the same arming-time integrity walk**
that authenticates package bytes (`OBL-INTEGRITY-BIND`): one traversal produces both
the digest proof and the object/generation index, digest-bound into the snapshot, and
it runs before the first prompt, so there is no enumeration race with running code.

**Membership is by *defining principal*, not by reachability, and that is what keeps
the walk from freezing first-party source.** An object joins the immutable set only if
its **defining principal is a package** (§2.3). So when the walk follows a
package-internal symlink, the *target's* membership is decided by whose binding
contains the target: a symlink from `node_modules/foo/x` to another package file adds
that file (a package defines it), but a symlink from a package **out to
`/project/src/x`** does **not** freeze `/project/src/x`, because its defining principal
is root, not a package — the walk records the *link object*, not root-owned source, and
first-party writability (which LLP 0013 grounds in workspace members being root-
principal) is preserved. A **hard link** shared between package and first-party source
is the ambiguous case: since one inode cannot have two defining principals, arming
**refuses** such a graph rather than silently choosing (open question 1). The walk
tracks visited object identities and bounds depth, so a symlink cycle back toward
`/project` terminates rather than looping.

**The lexical guard reruns after every symlink expansion**, against the canonical
retained parent plus the absent tail — so a create through an *outside* spelling like
`scratch/link/new.js`, where `link` is a symlink into a package, is caught when §4's
staged discovery (which reauthorizes each discovered target, §4 step 4) expands `link`
and re-applies the path guard to the discovered in-package location. Ordinary
package-root authority matching is principal-relative (`decision.rs:1124-1140`) and
does **not** stand in for this guard, which is global (all principals).

Both are LLP 0021 obligations (`OBL-PACKAGE-IMMUTABLE`, §9). The integrity obligation
reinforces but does not replace them — an arming-time hash proves the bytes were right
*once*; only refusing the write keeps them right. A pre-armed alias into package source
from *outside* the project is out of the armed threat model, because planting it
already required project write access, which defeats the model independently. And
because LLP 0013 Resolved Questions §1 makes **workspace-member first-party source
default to the *root* principal**, a developer's own workspace packages are *not* under
a package binding and stay writable; only third-party `node_modules` source is frozen.
A package's own writable cache directory (`node_modules/<pkg>/.cache`) is **inside** a
package binding and is therefore immutable in v1 — tools needing it use the future
state mount (OQ 2), which is the concrete v1 cost of this rule.

A program that needs the closed set gets a clear typed denial naming the
capability, not a subtly unsafe success.

### 5. The virtual resolution base (working directory)

The session has **one virtual working directory**. It is per-runtime session
state, **owned and mutated by the root principal**, and it is *canonically
native*: a sealed session identity holding a retained directory object, not a
JavaScript variable and not process-global state.

It serves two roles that must be named separately, because a stricter profile
splits them:

- the **view**: what `process.cwd()` returns; and
- the **resolution base**: what a relative path resolves against — in `fs`, in
  `node:path`'s cwd-consulting functions, in relative file URLs, and in error
  paths.

**In v1 the view and the resolution base are the same value for every principal.**

#### 5.1 Root's `chdir` does move every principal's resolution base

This must be said plainly, because the previous draft said the opposite. `fs` and
`path.resolve` resolve relative paths against the session cwd
(`src/builtins/fs.js:542-568`, `src/builtins/path.js:59-71`). There is one session
cwd. Therefore a root `chdir` **does** change what `./x` means for package code
running in that runtime. The claim that it "changes no other principal's
resolution context" was false.

This is nonetheless the right v1 design, for reasons that should be argued rather
than assumed:

- It is **Node's semantics**. A package doing `fs.readFileSync("./config.json")`
  resolves against the process cwd in Node, and against the session cwd here.
- It is a **downward** influence: root is strictly more authoritative than any
  package. Root moving the shared base cannot grant a package authority it lacks —
  every resulting path is still authorized against *that package's own binding*,
  and containment still applies. The dangerous direction is package → root, and
  that is closed (§5.2).
- The alternative — a fixed per-package resolution base — silently changes the
  meaning of ordinary package code relative to every other runtime, to defend
  against an influence that grants no authority.

What virtualization *does* close is the **shared-process** channel, and that is
exactly what the registry's reconciliation asks for. The condition recorded there
is that shared process-directory mutation stays closed "unless cwd is virtualized
or scoped without changing other principals' resolution"
(`capsec/registry/legacy-capability-reconciliation.json:112`). Read precisely
against `process:cwd`'s own `globality: shared-process-mutation`
(`capsec/registry/capability-definitions.json`, `definitions[19]`), the
"resolution" at stake is the *process-global* one: after this change, `chdir`
never calls host `chdir(2)`, and never mutates state shared with other runtimes in
the process, with other embedders, or with the Rust process itself. That condition
is met. The within-runtime, root-to-package influence on the shared resolution
base is a separate, deliberate, Node-compatible property, and §8 records it as
such rather than hiding behind the quote.

#### 5.2 `chdir` is root-only

`process.chdir(path)` changes only the calling runtime instance's virtual cwd,
and only when the operation is attributed to **root** under the complete
constrained-principal set of LLP 0021 — live frames, schedule-time owner, and
deputy identity all intersected, with missing, ambiguous, or `NoUser`
attribution denying. A package-attributed `chdir` — called directly, through a
deputy call into root code, from a promise continuation, or from a timer the
package scheduled — receives a typed denial and changes nothing. Root code cannot
be used as a deputy to move the cwd on a package's behalf.

`chdir` never calls host `chdir(2)` and never mutates process-global state shared
by other runtimes or embedders. A successful target must, in order:

1. normalize and resolve in-namespace (§3);
2. pass **both** decisions, conjunctively — the **virtual-cwd mutation** action of
   §8 (whose resource is the target logical path, and whose positive predicate
   admits root only) **and** the typed directory-metadata decision (the
   stat/enumeration edge of LLP 0021 WP5). Neither substitutes for the other:
   metadata authority says the caller may *look* at the directory, and mutation
   authority says the caller may *move the session there*. An implementation that
   gated `chdir` on the metadata edge alone would let any principal holding
   `fs:list` on a directory relocate the session into it;
3. be observed, *through that decided operation*, to exist and be a directory;
4. be retained as a platform object whose identity is verified to remain within
   the binding;

after which the new cwd is committed atomically. On failure the cwd is unchanged
and the error carries Node-compatible `code`, `syscall`, and `path` fields with
virtual spellings only.

Step 4 is why **the synthetic root is not a valid cwd**: `/` and every path that
normalizes to it (`..`, `/project/..`) are namespace metadata with no backing
platform object to retain, so `process.chdir("/")` is refused with the
synthetic-node error (§7.2) rather than silently succeeding into a directory that
cannot be verified. The same rule governs the *open* operations that require a
retained object on `/`: `opendir("/")`, a directory descriptor on `/`, and an **open
write or non-recursive `mkdir`** on `/` are refused with the synthetic-node error —
`/` has no backing object to create under. A **closed** operation on `/` — `fs.watch`,
`symlink`, `rename`, `unlink`, and the rest of §4.1's closed set — is refused *earlier*,
by its **closed-operation** denial (`EPERM`, §7.2 tier-3 row 1), which precedes the
synthetic-node check, so it never reaches the synthetic-node rule. (The distinction
matters: an open write on `/` is synthetic-node; a *closed* op on `/` is `EPERM` — not
"any mutation on `/` is `EPERM`", which an earlier draft overstated.) Only the two metadata operations of §3 — enumerating
the mount table and stat-ing the synthetic directory — are available on `/`. A session
that wants to leave `/project` has nowhere else to go in v1; this becomes meaningful
only when a second mount exists.

Because the cwd is a retained identity, a directory renamed, removed, or replaced
by a symlink after a successful `chdir` does not silently redirect later effects:
the next relative resolution re-verifies the retained identity and fails with a
**stale-cwd error** rather than resolving against the replacement. **A later
successful `chdir` clears the stale state** — the session is recoverable without
restarting. This diverges from POSIX and Node, where a process whose cwd is
renamed keeps working through the retained directory object and `getcwd` reports
the new location. The divergence is deliberate: an object-anchored cwd could be
moved *outside* the project binding by an external `mv`, after which every
`openat` against it would silently escape the mount. A spelling-anchored,
identity-verified cwd cannot.

#### 5.3 Cwd visibility is an explicit information grant

**Cwd visibility is a profile-level information grant, not a consequence-free
read.** A package that can call `process.cwd()` learns where root navigated —
`/project/secrets/customer-a` names a directory the package may hold no `fs:list`
authority over — so universal readability is a real, if narrow, metadata channel,
and LLP 0021 does not imply it. v1 nonetheless grants it to every principal, for
Node compatibility, and records it here as a decision with adversarial fixtures
rather than as an oversight: the disclosure is limited to *names within the
project namespace*, never a host path.

**Any profile that closes the view must also move the resolution base.** This is
the rule that makes the grant closeable at all. `path.resolve("x")` and
`path.relative(…)` consult the cwd (`src/builtins/path.js:59-71`; the registry
today misclassifies both as `non-capability` / `pure-in-memory-compute` — see §8),
and so do relative file URLs, `error.path`, and watch-event paths. A profile that
masked `process.cwd()` while leaving those resolving against root's real location
would leak the same information through a surface classified as pure computation,
and would additionally split a principal's *view* from its *base* — so a package
would resolve `./x` against a directory it cannot name. Therefore, normatively:

> **The authenticated native view equals the resolution base, per principal.**
> Under any profile, whatever a principal is *authorized to observe* as its cwd is
> what its relative paths resolve against.

"View" here means the **authenticated native view** — the value the sealed session
identity yields for that principal — and *not* whatever the writable `process.cwd`
JavaScript property happens to return. The distinction is what makes this rule
consistent with §5.4: a package may overwrite `process.cwd` and thereby lie to its
own callers, and that lie changes nothing about resolution, because resolution
never reads the facade. A principal can deceive itself; it cannot redirect itself.

A profile that closes the read to non-root principals therefore gives them
`/project` as *both* authenticated view and base. Open question 6 asks whether v1
should simply ship that.

#### 5.4 Facades cannot subvert it

`process.cwd` and `process.chdir` are writable JavaScript properties today
(`src/builtins/process.js:475-476`), and `fs`/`node:path` consult them dynamically
— so a package that overwrites `process.cwd` could redirect JavaScript-side
resolution without ever calling native `chdir`. Under this contract, native
resolution never consults a JavaScript-mutable facade: it reads the sealed
identity through the runtime handle (§7.1). Monkeypatching `process.cwd` changes
what a caller of `process.cwd()` sees and nothing else. `fs`, module resolution,
and `node:path` resolution against the session cwd are unaffected.

### 6. Path-bearing observables

The no-host-path property is a property of the **whole** JavaScript surface, not
of `process.cwd()` alone. An implementation that virtualizes cwd while
`process.execPath` still returns the host install path has not implemented this
contract.

The implementation therefore maintains a table **generated from the
output-disposition dataset** (§8) — so that a newly added or aliased API cannot
silently escape it — fixing the exact armed value or error for every path-bearing
observable. Each row carries a disposition drawn from a closed set:

| Disposition | Meaning |
| --- | --- |
| `virtual-absolute` | a virtual absolute path |
| `virtual-relative` | a virtual path relative to a stated base |
| `virtual-basename` | a final component only, not a path |
| `synthetic-source-id` | a reserved identity (`ibex:runtime`, `ibex:stdin`, `repl:<n>`, …) |
| `absent` | the property does not exist on this surface in this mode |
| `closed` | the surface is closed; the row states *how* (absent, throws, or a neutral value) |
| `refused` | the call fails with a stated reason (§7.2) |
| `typed-logical` | a typed logical value carried across an ABI, not a string — the resolver record's `path`/`pkgRoot`, which are typed values, never raw host strings |
| `reserved-constant` | a well-known universal constant string that names no host (`/dev/null`) |
| **`non-path`** | the field is judged **not path-bearing** (including a container object whose *own* value is not a path — its path-bearing fields are dispositioned as their own rows) |

**`non-path` is the load-bearing member.** Without it the dataset cannot decide
whether an *unmarked* field (`process.pid`, `os.cpus()[0].model`) is path-bearing
or merely un-triaged, so "an unmarked new field escapes silently" would remain true
*of the dataset itself* — the exact failure this mechanism exists to prevent. The
dataset is therefore **total** over the canonical tuple `(stable surface id, field or return-shape, alias, mode, source kind, return variant)` — the same spelling used in §8 and the §9 ledger row —
for every surface in the registry, and the build fails on any **un-dispositioned**
field, not merely on a path-bearing one lacking a disposition. Judging a field
`non-path` is a recorded decision someone signs, not a silence.

**Totality needs an independent universe, which the registry does not yet supply,
and the table below is an *illustrative interim projection* — not the normative
totality.** The coverage schema records a surface's *kind and name*, not its fields or
return shapes (`capsec/schema/coverage-edge.schema.json`), so a dataset joined only
against that cannot prove its own completeness — an omitted field is indistinguishable
from a nonexistent one. The left side of the join must therefore be an **independently
generated output-shape catalog** — a live descriptor sweep of runtime exports, object
properties, and return-record shapes, plus the native bridge registrar ids — against
which the disposition dataset is checked *bidirectionally*: every catalog field has a
disposition, and every dispositioned field exists.

Repeated review rounds each found the hand-written table missing or double-valuing a
surface in a *new* spelling — `Dir.path`, `module.__exactPackageRoot`, the watch-event
shapes, then `Exact.which`/`Bun.which` (host-`PATH` search returning a host spelling,
`src/engine/hermes_runtime_process.cc:2647`), `Exact.argv`/`main`, `fs.glob`/`globSync`,
`require.main`, `process.mainModule`, and the builtin-vs-file split of `require.resolve`
(which returns `record.id` for a builtin, so `require.resolve("fs") === "fs"`, not a
virtual path). **That churn is the signal that prose cannot carry this totality —
and it extends to the *values*, not just the surface list.** Round 8 executed the
artifacts and found several *named* values wrong (`path.posix` grouped as a foreign
dialect when it is the default impl; `Exact.resolve` marked `non-path` when it returns
a virtual path; `fs.glob` marked always-absolute when it is pattern-shaped; `Exact.main`
marked a synthetic id when it is `argv[1]`) — the same defect a hand-written table
keeps re-committing in a new cell each round. So the **generated `OBL-DISPOSITION-DATASET`**
(§9) is normative for **both membership and value**, producing each disposition from
**live execution** keyed by the one canonical tuple `(stable surface id, field or
return-shape, alias, mode, source kind, return variant)`, with the build failing on
any un-dispositioned catalog field, any duplicate key, and any dataset value that
disagrees with the executed surface. The table below is an **illustrative interim
projection**: its values are corrected where round 8 executed them, but where a value
depends on mode/kind/variant the **dataset's executed value governs**. Every surface
the churn keeps surfacing is closed or non-path-bearing under v1 (no subprocess
`which`, no reopened resolver), so this is a *classification-completeness* obligation,
not an open leak.

Its v1 content:

| Surface | Disposition | Armed value |
| --- | --- | --- |
| `process.execPath`, `process.argv0`, `process.argv[0]` | `synthetic-source-id` | the reserved identity `ibex:runtime`; never the host install path |
| `process.argv[1]` | per mode | see the mode table below |
| `process.execArgv` | `non-path` (premise) | its values are runtime flags, not paths (registry edge: authorizable `sys:read`, not `closed`). The `non-path` disposition **rests on the premise** that armed `execArgv` contains no path-valued flag — but `build_exec_argv` (`src/bin/ibex/runtime.rs:942`) splices operator-supplied `EXACT_COMPAT_EXEC_ARGV` through unvalidated, and a future `--project <hostdir>` there would falsify it. The dataset records the premise so `non-path` is **re-forced** if a path-valued flag is added; operator-supplied values are the operator's own data (like user argv), not a runtime-originated host path |
| `__filename` / `__dirname` | `virtual-absolute` / `absent` | virtual spellings in **file-backed** modules; **absent** in a module with no file (`ibex:stdin`) and where there is no module |
| `import.meta.url` | `virtual-absolute` / `synthetic-source-id` | the module's virtual `file:///project/…` URL for a **file-backed** module; the **synthetic identity** for a synthetic one — `import.meta.url === "ibex:stdin"` in program mode, as LLP 0022 and LLP 0024 require. It is not always a file URL. |
| `import.meta.path`, `.filename` | `virtual-absolute` / `absent` | the virtual path; **absent** where the module has no file |
| `import.meta.dirname`, `.dir` | `virtual-absolute` / `absent` | the virtual directory; **absent** where the module has no file |
| `import.meta.file` | `virtual-basename` | **the basename only** — it is `__filename.split('/').pop()` today (`src/engine/bootstrap/module-loader.js:3563`), not a path, and the table must say so |
| `require.resolve` — **file-backed** result | `virtual-absolute` | a resolved file path |
| `require.resolve` — **builtin** result | `synthetic-source-id` | returns the builtin **id**, e.g. `require.resolve("fs") === "fs"` (`module-loader.js:5786`), not a path |
| `module.paths` | `virtual-absolute` | virtual spellings |
| `module.id`, `module.filename`, `module.path` | `virtual-absolute` | the per-module `module` object is a path-bearing surface in its own right, and **closing `require.cache` does not close it**. Rust module ids are lossy host paths today (`src/module_loader/mod.rs:805-806`) and reach JavaScript through these fields; none may return a host path. |
| `require.cache` | `closed` | **closed** as a `runtime:inspect` surface per LLP 0022 §1. If it is ever admitted, it is as a principal-filtered immutable facade whose keys are virtual spellings. Virtualizing a value must never implicitly reopen a closed surface. |
| module records returned by the resolver (`path`, `pkgRoot`) | `typed-logical` | typed logical values across the ABI; never raw host strings (`src/host/abi.rs:2168-2187` serializes host strings today) |
| `realpath` return | `virtual-absolute` | §4 |
| `readlink` return | `virtual-relative` / `refused` | the translated virtual spelling, or refused when unmappable (§4) |
| `process.cwd()` | `virtual-absolute` | the authenticated native view (§5.3) |
| cwd-consulting `node:path` results (`resolve`, `relative`) | `virtual-absolute` / `virtual-relative` | computed against the same authenticated view (§5.3); never a host path |
| `FileHandle.path`, `ReadStream.path` / `WriteStream.path` | `virtual-absolute` | descriptor and stream routes are path-bearing too |
| `Exact.file` / `ExactFile.name` | `virtual-absolute` | |
| `fileURLToPath` / `pathToFileURL` returns — **`node:url`, the `Exact` global, and its `Bun` alias** (`Exact` and `Bun` are the **same object**, `src/engine/bootstrap/exact-global.js:2824`, so every `Bun.*` URL/path alias is covered too) | `virtual-absolute` | the `Exact` global carries a second, laxer implementation today (`exact-global.js:922-926`) |
| `Exact.resolve` / `Exact.resolveSync` (and their `Bun` aliases) | **`virtual-absolute` / `virtual-relative`** (cwd-read) | **as shipped, pure `path.resolve` delegates** (`src/engine/bootstrap/exact-global.js:849-857` — `path.resolve.apply(path, arguments)`), so they return the **same virtual-path spelling as `node:path`'s `resolve`** — dispositioned **identically** to that row (round-8 correction: a prior draft wrote `non-path`, contradicting the `node:path` row for the same computation). They are *not* module bridges (removed from `OBL-RESOLVE-GATE`). The registry classifies them `fs:list` module resolution, which the shipped code contradicts (OQ 13). |
| `path.posix.*` string results (the runtime **default** impl, `src/builtins/path.js:473`) | **`virtual-absolute` / `virtual-relative`** | POSIX results **are** virtual-path spellings embedding the projected cwd — the same disposition as the cwd-reading `node:path` row; grouping them with `path.win32` under `non-path`, as a prior draft did, was wrong |
| `path.win32.*` string results (incl. `path.win32.resolve`) | `non-path` (foreign-dialect) | Windows-shaped backslash strings like `\project\x` — not virtual paths; path-bearing only in embedding the **projected** virtual cwd (§8), so no host path. Whether a foreign-dialect string deserves its own disposition is OQ 4 |
| `os.homedir()`, `os.tmpdir()` | `closed` | **pinned outcome:** each **throws** the closed-surface denial rather than returning a host path. They read `HOME`/`TMPDIR` and return native paths today (`src/builtins/os.js:63`), which is exactly the disclosure being closed. |
| `os.devNull` | `reserved-constant` | returns the well-known constant string `/dev/null`, which names no host and discloses nothing about this machine. It is **not** a mount, so an `fs` operation *on* it fails outside-mount in v1 like any other non-mount path — an earlier draft made it a synthetic write-sink, but §3 refuses any child of `/` that is not a mount and synthetic `/` has no node semantics for it, so the sink was underspecified. A reserved `/dev/null` sink node (lookup, open/read/stat/truncate, listing, and error-order all pinned) is a named future item, not v1 (the sink question is OQ 7). It is `/dev/null` today (`src/builtins/os.js:229`). |
| `os.userInfo()` — `homedir`, `shell` | `closed` | **pinned outcome:** these fields are **absent** from the returned object; passwd-backed host paths are not disclosed |
| stack frames from runtime-owned bundles and builtins | `synthetic-source-id` | synthetic source identities |
| error `path` / `dest` | `virtual-absolute` | virtual spellings |
| watch-event paths | `virtual-relative` / `virtual-basename` | Node returns a **basename** for a non-recursive watch and a **relative** path for a recursive one (`src/builtins/fs.js:5226`); an earlier draft wrongly dispositioned these `virtual-absolute`. (Moot in v1: `fs.watch` is closed, §4.1 — the row is retained for the disposition dataset's totality and for a future reopening.) |
| `Dir.path`, `Dirent.parentPath` / `Dirent.path` | `virtual-absolute` | live path-bearing properties (`fs.js:2259`); an earlier draft omitted `Dir.path` |
| `module.id`, `module.filename`, `module.path` | `virtual-absolute` | per-module path fields |
| `module.parent`, `module.children`, `require.main`, `process.mainModule` | `closed` | these link the live loader graph (`src/engine/bootstrap/module-loader.js:5296-5315`), so leaving them open allows upward traversal to the same mutable state LLP 0022 §1 closes through `require.cache`/`require.main` — closed identically (a principal-filtered immutable facade if ever admitted) |
| `Exact.which` / `Bun.which` | `closed` | native `__exactWhich` searches host `PATH` and returns a host spelling (`src/engine/hermes_runtime_process.cc:2647`); v1 admits no subprocess authority, so the surface is closed (throws the closed-surface denial) |
| `Exact.argv` / `Bun.argv` | per `process.argv` | Bun alias of the `process.argv` mode table |
| `Exact.main` / `Bun.main` | per `process.argv[1]` | it is exactly `process.argv[1] \|\| ""` (`src/engine/bootstrap/exact-global.js:1435`) — **argv semantics**, dispositioned by the `argv[1]` mode row; a prior draft wrongly called it `synthetic-source-id`. Whether it should *become* a stable source identity distinct from `argv[1]` is OQ 3 |
| `fs.glob` / `fs.globSync` results | **`virtual-relative` / `virtual-absolute`** | Node returns **pattern-shaped** results — relative candidates for a relative pattern, absolute for an absolute pattern (`src/builtins/fs.js:2848,2919`); a single `virtual-absolute` was wrong. The traversal takes the `fs:list` decision per §2.1 |
| `module.__exactPackageRoot` | `typed-logical` / `absent` | fed raw host `pkgRoot` today (`src/engine/bootstrap/module-loader.js:5296`); must be a typed logical value or absent |
| source-map `sources`, `sourceURL` | `virtual-absolute` / `synthetic-source-id` | a **tagged source identity**: either a canonical virtual file URL or an LLP 0024 synthetic identity (`repl:<n>`, `repl:<n>:<virtual path>`, `ibex:stdin`, `ibex:eval`). Never a host path, and never an untagged string. |

**`process.argv` by mode.** The arming entry, the source identity, and the argv
identity are three different things, and an earlier draft conflated them by putting
`ibex:stdin`/`ibex:eval` into `argv[1]` — which would silently shift every user
argument by one relative to Node. The synthetic identity belongs to the *source*
(`import.meta.url`), not to argv:

| Mode | `argv[0]` | `argv[1]` | tail |
| --- | --- | --- | --- |
| file execution | `ibex:runtime` | the entry's `virtual-absolute` spelling | user arguments from index 2, as Node |
| program stdin | `ibex:runtime` | first user argument, or absent | user arguments from index 1 — a **stated divergence**: Node's `node - args…` puts `"-"` at `argv[1]` and user args at index 2 (verified by execution), and Ibex omits the `"-"` |
| one-shot `-e`/`-p`/`eval` | `ibex:runtime` | first user argument, or absent | user arguments from index 1, as Node's `-e` |
| REPL (interactive, transcript) | `ibex:runtime` | absent | — |

The divergence common to every mode is `argv[0]`, the synthetic runtime
identity rather than the host install path — the whole point of the table.

The table is *generated*, not hand-maintained: its rows are a projection of the
output-disposition dataset (§8), so an alias like `import.meta.dir` or a new `os`
field cannot be added without receiving a disposition. A hand-written list would
have missed exactly those aliases — and would have missed the *second*
`fileURLToPath`, which sits on the `Exact` global today with no `%2F` refusal at
all (`src/engine/bootstrap/exact-global.js:922-926`).

Every path-taking runtime surface uses the same resolver: callback, synchronous,
and promise `fs`; descriptor and `FileHandle` routes; file URLs; `Exact.file`;
module entry and resolution; source maps; watch paths; and any builtin that
performs a filesystem effect.

**`node:path` is not uniformly pure.** `path.resolve` and `path.relative` consult
the session resolution base whenever their arguments do not already determine the
result, and are therefore *session-state reads*, not pure computation; they must
project the same per-principal view as `process.cwd()` (§5.3). The genuinely
lexical functions (`join`, `normalize`, `basename`, `dirname`, `extname`, `parse`,
`format`) operate on virtual paths and take no capability decision. §8 records the
registry correction.

**No `node:path` function performs containment, and none of them throws an
outside-mount error.** They are string operations over the virtual namespace, so
`path.resolve("/etc/passwd")` returns the *string* `/etc/passwd` (LLP 0022 §4
depends on this), and it is the subsequent `fs` call that is refused with
`ERR_IBEX_OUTSIDE_MOUNT`. Containment is enforced where an effect is taken, not
where a string is computed; making `node:path` throw would break ordinary path
arithmetic and would move a security boundary into a pure-string surface.

Raw native bridges are part of this surface. `__exactRealpath` returning a host
spelling (`src/engine/hermes_runtime_fs.cc:2573-2577`), or `__exactModuleResolve`
serializing host `path`/`pkgRoot` into its metadata (`src/host/abi.rs:2168-2187`),
defeats this table from one identifier away — so each such bridge is sealed after
private bootstrap capture or converted to take and return typed logical values.
LLP 0022 §7 owns the **single generated inventory** of every root-reachable native
bridge; this document's bridge rows are a **projection of that one inventory**, not
a second list.

### 7. The typed logical-path ABI, runtime locality, and errors

#### 7.1 Identity, not text — and a runtime handle

The host adapters must receive identity, not text. The ABI carries the logical
root, the binding owner, the normalized components, the **runtime/session
handle**, and the original virtual spelling for diagnostics — and it must be able
to distinguish a virtual absolute path from an explicit host path structurally.
String-shape inference (`path.is_absolute()`, prefix-matching host components) is
not an acceptable substitute and is retired: it is exactly the mechanism that made
`/README.md` indistinguishable from a legitimate absolute virtual path.

**The runtime handle is a semver-major ABI change, and it is assigned.** Today the
Host is a process-global singleton (`src/host/abi.rs:130` —
`static HOST: OnceLock<RwLock<Host>>`; `install_host` at `abi.rs:214` *replaces*
it), and the typed filesystem entry point carries no runtime identity
(`src/host/abi.rs:975`). Per-runtime cwd, per-runtime module identity, and the
"a second runtime does not change" criterion are therefore **not implementable
through the current ABI**.

**Which half is semver-major, precisely.** LLP 0002's narrow consumer contract is
**five `ex_hermes_*` functions plus the host-call installer**; it says explicitly
that "the full `ex_host_*` callback surface … is an implementation detail." An
earlier draft called *both* families the narrow contract, which is wrong in a way
that matters: threading a session through `ex_host_authorize_typed_fs_*` is an
**implementation-detail change**, while anything that alters `ex_hermes_create` or
`ex_hermes_eval` is **semver-major** and amends LLP 0002 in the same change. Both
halves are rowed separately in §9 (`OBL-ABI-HANDLE`, `OBL-HOST-SESSION`).

**And part of the handle already exists.** `ExactHermesRuntime*` is already an
opaque public runtime handle (`include/exact_runtime.h:27-28`). The gap is not "a
handle must be invented"; it is that the **`Host` is a process-global singleton**
(`src/host/abi.rs:130`) and the typed filesystem ABI carries no runtime identity
(`abi.rs:975`). The work is to make host state session-indexed and to thread the
existing runtime identity through it.

The contract this document requires:

| Aspect | Requirement |
| --- | --- |
| creation | a session handle is minted with the armed snapshot, before any evaluation; it is opaque to JavaScript |
| attachment | exactly one engine runtime per session handle; the engine derives the handle natively, never from a JavaScript-supplied value |
| **async work** | filesystem effects execute on worker threads today (`src/engine/hermes_runtime_fs.cc:1918-1936`), so the handle is **not** runtime-thread-only. A worker carries an **operation lease** minted on the runtime thread: it captures the session generation, the authenticated constrained-principal set, and the decided facts, and it is what the worker presents. Workers never re-derive a principal. |
| generation | handles and leases carry a generation counter, so a destroyed-and-reallocated slot cannot be mistaken for its predecessor (ABA defense) |
| teardown | destruction stops new leases and cancels queued work. Work **already committed** cannot be un-done by teardown — an irreversible write that has happened has happened — so teardown *records* it rather than pretending to fail it. Only *undelivered* results fail, with the wrong-session reason. An earlier draft said every in-flight call fails; that is not achievable and would have been a lie in the contract. |
| worker transfer | a handle is not portable across a worker replacement; the successor mints its own. (LLP 0025 leaves worker replacement itself open — this document states only the identity consequence, not the replacement policy.) |
| state | VFS, mount table, bindings, cwd, and module cache are **session-local**, or keyed by session identity — never process-global |

**Native derivation of the caller.** JavaScript supplies only untrusted path
*syntax*. It never asserts a runtime, a principal, or a binding owner; the native
side derives all three from engine provenance. A path string arriving from
JavaScript is data, not a claim.

**Operator submission has no engine frame.** `.load` and the other session-layer
reads originate in Rust, where there is no JavaScript frame to derive a principal
from — so "native derivation from engine provenance" cannot cover them. Such a
caller presents the **session handle plus the ingress's authenticated operator-
submission provenance** (LLP 0022 §7), and is attributed to the authenticated
session root. It is not a new principal and not a bypass; it is the one route where
the principal comes from the ingress rather than from a frame, and it must be named
or an implementation will invent an ad-hoc answer.

**Worker locality.** LLP 0025 §7 specifies the supervisor/worker architecture and
its conformance gate; this document does not restate its posture, only its
consequence for identity. Retained platform objects, the sealed cwd identity, and
every VFS identity **live and are derived in the process that owns the engine**.
Only opaque, authenticated session tokens cross a process boundary; a retained
object identity is never serialized to a supervisor and never rehydrated from one.
(This constrains *VFS and authority-bearing identities* only — evaluation outcomes,
display trees, broker events, and **LLP 0025's history-scope equality-proof digest**
cross that boundary by design, per LLP 0024 and LLP 0025. The history-scope proof is a
*derived, non-rehydratable* comparison value, not a retained object identity, so it
fits this rule; naming it here closes the seam LLP 0025 §9 `OBL-HISTORY-LOCALITY`
formally requested.)

#### 7.2 The structured result and its error classes

Adapters return a **structured result with a stable, versioned reason enum**, so
that the error classes are distinguishable by consumers rather than collapsed into
a generic permission failure. Today the C ABI returns `1/0/-1`
(`src/host/abi.rs:967`), the engine collapses denial to `"Permission denied"`
(`src/engine/hermes_runtime_fs.cc:543-545`), and `fs.js` reconstructs errors by
*parsing the message string* (`src/builtins/fs.js:766-770`). None of that survives.

Each reason has a pinned JavaScript-visible projection. Novel conditions get novel
codes rather than being smuggled into Node's:

**This document owns the resolver's error order.** LLP 0024 mints several classes
(`unknown-builtin`, generic resolution failure, `unsupported-dependency-TLA`) and
LLP 0022 mints `out-of-snapshot`, but the *ordering* is a
path-and-authorization property, so it is stated **once, here**, and the siblings
cite it rather than restating it. Both previously restated it, and both drifted.

**The invariant, stated once, from which the order follows:**

> **No class that discloses existence may precede an authorization decision that
> would have denied the caller.**

Everything below is a consequence of that sentence, not an independent choice. It
is worth stating so plainly because *both* documents violated it while sounding
principled. An earlier draft of this section ordered classes by "what a specifier
*is*, before where it *resolves*, before whether the session may *see* it" — which
reads like a clean conceptual hierarchy right up until you notice that **"where it
resolves" is an observation, and observations must be authorized.** That framing was
itself the disclosure channel.

The classes fall into five tiers (0 through 4):

| Tier | Decidable from | Classes |
| --- | --- | --- |
| **0. Session** | the session handle alone — precedes everything | `ERR_IBEX_STALE_SESSION` (a dead or foreign session never reaches a specifier) |
| **1. Shape** | the specifier alone — no I/O, no snapshot | reserved scheme (`repl:`, `ibex:`); `unknown-builtin` |
| **2. Snapshot** | the armed snapshot — no I/O; discloses nothing about the filesystem | `out-of-snapshot` |
| **3. Path & authorization** | the namespace and the typed decision | this document's classes, **policy denial included** |
| **4. Graph** | reachable only *after* a path is authorized and read | module **resolution failure**; `unsupported-dependency-TLA` |

Three corrections this makes, all of which an earlier draft got wrong:

- **`out-of-snapshot` is decided from the *caller's authorized graph view*, not the
  project-global graph.** This is the subtle one, and getting it wrong is an
  existence oracle over the package graph. The armed snapshot carries *both* the
  global graph (`capsec/schema/armed-snapshot.schema.json:211`) and each principal's
  *permitted* imports (`:303`), so an implementation that answered `out-of-snapshot`
  from the global graph would let principal A distinguish "package B does not exist"
  from "B exists but A may not import it" — disclosing B's existence to a principal
  with no authority over it. The current host already decides from the caller's own
  import set (`src/host/mod.rs:1377`), and this document requires that: absent and
  unauthorized-present are **indistinguishable**, both yielding `out-of-snapshot`.
  It is a tier-2 class only because, so decided, it discloses nothing.

  **Two things this requires that are not yet true.** First, the membership decision
  must be *exactly computable* from the snapshot, which today carries only
  `{importer, imported}` edges and per-principal locators with no importer-relative
  request mapping (`armed-snapshot.schema.json:211`/`:328`) — the live predicate
  reduces both to bare package names (`src/host/mod.rs:1526`). Exact membership needs
  a **digest-bound `(importer, request specifier/alias, exact imported principal,
  platform disposition)` map** (`OBL-GRAPH-LOCATION`, extended, §9). Second — and this
  is the round-6 catch — the tier-2 gate must precede **every resolve-only *module*
  bridge**, not just `import`. `require.resolve` (local and global) does **not** call
  `checkImportGate` (`src/engine/bootstrap/module-loader.js:5768-5770`) and enters
  `resolve_module_meta`, which *stats and reads `package.json`* during resolution
  (`src/host/mod.rs:1430`, entering `resolve_meta` at `src/module_loader/mod.rs:764`)
  — so a resolve-only call would probe a path, and disclose its existence, before the
  tier-2 decision. The gate and the no-probe-before-authorization rule bind
  `require.resolve` (and any genuine module-resolution bridge) identically to
  `import`. **`Exact.resolve`/`resolveSync` are *not* module bridges** — they are
  `path.resolve` delegates (§6) and take no import decision; the resolve-gate does not
  cover them. **And a resolve-only route must not read the module body**: it takes the
  metadata/`fs:list` decision only. `resolve_meta` today does `std::fs::read_to_string`
  for `.mjs`/plain ESM (`src/module_loader/mod.rs:775`) under a metadata-only
  classification — a nonconformance of the same class as the `fs.open` oracle, and a
  resolve-only route that reads the body without a distinct `fs:read` decision does
  not conform.
- **Module resolution failure is tier 4, not tier 1.** Resolving a specifier means
  **probing paths** — extensions, index files, `exports` maps. A probe is an
  observation, so a probe of a path the caller may not see must yield the **denial**,
  never "not found." An earlier draft placed it before the path classes, which is an
  existence oracle.
- **`unsupported-dependency-TLA` is tier 4.** You cannot know a dependency uses
  top-level `await` until you have resolved it, authorized it, and **read** it.
- The premise that justified the old placement — "the two sets are disjoint on
  specifier shape" — is **false**, and its falseness is what made the unsafe order
  look safe: a bare `./foo.js` can produce a path error *and* a resolution failure.
  Deleted.

An earlier draft attributed a class called `interim` to LLP 0022. **LLP 0022 defines
no such class** — the word appears there only as ordinary prose — so it is removed
from the tiering. (This is the kind of drift the ledger's revision stamps, §9, exist
to catch: a class imported from a sibling that does not mint it.)

Within tier 3, the path/adapter members are **closed and versioned**. The **row
index is the total precedence** — where a note says a class is "decidable from the
operation alone," that describes *when the fact is available*, not that it outranks a
lower-numbered row; the order below is what a fixture asserts:

| # | Reason | JS `code` | Notes |
| --- | --- | --- | --- |
| 1 | **closed operation** (`symlink`, `link`, `rename`, `unlink`, `rmdir`, `cp`/`copyFile`, `watch`, recursive `mkdir`) | `EPERM` | §4.1 — the operation is refused before any path work, so it precedes even namespace classification |
| 2 | malformed / unsupported adapter input | `ERR_INVALID_ARG_VALUE` | non-UTF-8, empty path, lone surrogate (§3) |
| 3 | encoded separator in a file URL | `ERR_INVALID_FILE_URL_PATH` | `%2F` (§3) |
| 4 | virtual path outside every mount | `ERR_IBEX_OUTSIDE_MOUNT` | distinct from `ENOENT`; message enumerates the mount table. **No host lookup has happened yet.** |
| 5 | synthetic node (operation needs a retained object on `/`) | `ERR_IBEX_SYNTHETIC_NODE` | §5.2 — a genuinely novel condition gets a novel code, per this document's own rule; it presents `EINVAL` as its `errno` for Node compatibility |
| 6 | policy denial | `EACCES` | carries a safe decision identifier |
| 7 | resource absent | `ENOENT` | ordinary Node absence — **only after the authorization that would have denied it** |
| 8 | symlink depth exceeded | `ELOOP` | §4, bound 32 |
| 9 | unmappable `readlink` target | `ERR_IBEX_UNMAPPABLE_LINK` | §4 |
| 10 | stale retained identity (commit) | `ERR_IBEX_STALE_IDENTITY` | §5.2, §2.3 |
| 11 | ordinary host error from an authorized operation | Node's own (`EISDIR`, `ENOTDIR`, `EEXIST`, `ENOSPC`, …) | only reachable *after* the operation was authorized |

(`ERR_IBEX_ALIAS_COLLISION` is **not** a v1 error class. An earlier draft ordered it
here, but its occurrence-time predicate — what runtime fact constitutes a collision —
was never defined, and an undefined error in a "closed and versioned" union is worse
than its absence. The canonicalizer's own failure mode, if any, is defined when the
canonicalizer is built (`OBL-ALIAS-CANON`, §9); until then v1 has no alias-collision
error, only the alias *equivalence* AC 5 tests.)

A note on two cross-references the table used to get wrong: a foreign `readlink`
target is `ERR_IBEX_UNMAPPABLE_LINK` (row 9) — the *readback* classification —
**not** outside-mount; the generic traversal algorithm of §4 never runs on a
`readlink`, which returns the stored target rather than following it. And
`ERR_IBEX_STALE_IDENTITY` (row 10) is the **commit-stage final-object** fact, so it
follows the requested-stage `ENOENT` in wall-clock order; AC 14/AC 18 exercise a
retained object deleted *after* a successful open, which is row 10, not row 7.

**Retained-base and retained-referrer staleness are a *separate*, earlier fact — a
requested-stage precondition — not row 10.** This is the round-8 distinction. Before a
relative path can be *resolved at all*, the retained cwd (§5.2) or captured referrer
(§7.3) it resolves against must re-verify; if that base was renamed, removed, or moved,
the operation fails `ERR_IBEX_STALE_IDENTITY` **before the requested path is formed**,
so it necessarily precedes the requested child's own `ENOENT`. A replaced cwd followed
by `readFile("missing")` therefore reports the stale **base**, not the child's absence —
inspecting the replacement or the missing child first would violate the retained-base
guarantee. So `ERR_IBEX_STALE_IDENTITY` occupies two phase positions: a
**requested-stage precondition** (base/referrer) ahead of that stage's `ENOENT`, and a
**commit-stage** final-object check (row 10). The per-stage rule — containment →
authorization → existence — runs the base's re-verification as part of forming the
requested path, before that path's existence is ever probed.

**Rows 6 and 7 (denial and absence) are a *phase*, not two fixed slots, and this is
the subtlety that defeated two drafts.** Denial-before-absence must hold at **every
stage that resolves a path**, and §4's staging has more than one: the requested path,
and then each discovered symlink target. A flat list cannot express that — a link
whose target is both **denied and absent** would, under a flat order with `ENOENT`
before discovered-target denial, report absence and leak it. So the correct statement
is a per-stage rule:

> For each path the resolver touches — requested, and each discovered target —
> **containment → authorization → existence**, in that order. Only after a stage's
> authorization succeeds may that stage's absence be reported.

`ELOOP` (row 8) sits below denial for the same reason: establishing that a chain
exceeds the hop bound requires walking *past* a link the policy may already have
refused. The first refused link stops the walk.

**No host lookup occurs before the authorization of the stage that would need it,
and this is a confidentiality rule, not a tidiness rule.** The native **whole-file-
read** route today (`__exactReadFile`, `src/engine/hermes_runtime_fs.cc:1984`)
`open()`s the parent, `openat()`s the target, and `fstat`s it — throwing `ENOENT` on
absence and `EACCES` on a non-regular file — *before* its first typed decision. (The
actual `fs.open` route, `__exactFsOpen` at `:2676`, does **not** have this defect: it
authorizes at `~:2705` before its first `::open` at `~:2725`. A prior draft cited
`fs.open`; the oracle is in the read routes, and every adapter sharing that
open-before-authorize shape must be corrected.) A principal with no authority over a
path can otherwise distinguish "exists" from "does not exist," and learn the object's
type, purely from which error it receives: an **existence oracle** over resources it
may not read. An implementation that decides after looking does not conform, however
correct its final allow/deny answer.

Existence probes do not throw where Node returns a boolean, and the no-oracle rule
covers **every** boolean surface, not just `existsSync`: `fs.existsSync` on an
outside-mount path *or a policy-denied existing path* returns `false`, while
`fs.access` on a denied path throws the row-6 denial. The distinction between absent
and denied is never observable through a boolean.

The result carries virtual `path`/`dest` spellings, the operation, the reason, and
the safe decision identifier — never a host path, never an authority token. The
wire encoding is a **versioned discriminated union with explicit discriminant
values and stated ownership/freeing rules**, generated alongside the ABI
(`OBL-ERROR-UNION`, §9) — not the current `1/0/-1` (`src/host/abi.rs:967`) with
JavaScript re-deriving codes by parsing message strings
(`src/builtins/fs.js:766-770`).

#### 7.3 Referrer capture

A relative module specifier resolves against a **referrer captured at submission**,
not consulted later. Prompt input's referrer is the session resolution base *at the
moment the input was submitted*; a module's referrer is that module's virtual
directory; `.load`'s referrer is the loaded file's virtual directory (LLP 0022 §8,
LLP 0024 §1). A dynamic `import()` inside a closure that runs after a `chdir`
therefore resolves against the referrer its source was submitted with, not against
the new cwd. Without this rule, the same closure resolves differently depending on
when it happens to run.

**A captured referrer carries the same stale-identity re-verification as the cwd
(§5.2), and this pins the old OQ 12.** The referrer is a retained directory identity,
so if that directory is renamed, removed, or moved between capture and a later dynamic
`import()`, the resolution **fails with `ERR_IBEX_STALE_IDENTITY`** rather than
resolving against the old spelling or following the object to wherever it was moved.
The rationale is exactly §5.2's: an object-anchored referrer could be `mv`-ed *outside*
the project binding, after which resolving against it would silently escape the mount;
a spelling-anchored, identity-verified referrer cannot. A later successful re-capture
(a fresh import from a live module) clears the staleness, as a later `chdir` does for
the cwd.

### 8. Registry obligations

Per LLP 0021's no-unclassified-surface invariant, this design obliges the
following — and these are **new authorable definitions and a new dataset**, not a
regeneration of existing rows. The distinction matters: the previous draft said
"the rows are regenerated," which is not achievable.

**Why it is not achievable.** `process:cwd` is `lifecycle: "deny-only"` with
`globality: "shared-process-mutation"`
(`capsec/registry/capability-definitions.json`, `definitions[19]`), and
`crates/capsec-semantics/src/decision.rs:439-448` hard-denies any action whose
lifecycle is not `Authorable` at the `LifecycleAndTargetClosure` stratum —
**before** any positive authority, ambient root included. A deny-only action
cannot be opened by adding a grant.

The *read* edge is a different problem. It is `sys:read` with
`positiveSources: ["ambient-root", "static-floor"]`
(`capsec/registry/coverage-edges.json`), and `sys:read` is itself
`lifecycle: "authorable"`, `staticOnly: false` — so a static floor **is** a
package-admitting source, and an earlier draft's claim that "no authority source
admits a package principal to it at all" was wrong. What is true, and what matters,
is that **no shipped artifact authors such a floor**: the generator emits none, so
today no package principal can read the cwd, and v1's universal read must be
*created* by an authored floor rather than assumed to exist. Synthesizing it is an
LLP 0014 generator obligation (`OBL-CWD-FLOOR`, §9).

Therefore:

- **Two new authorable actions**, with typed resources, replacing the closed
  surfaces rather than reinterpreting them:

  | Action | Resource | Lifecycle | Channels | Positive sources | Predicate |
  | --- | --- | --- | --- | --- | --- |
  | `path:cwd-observe` | the session resolution base (a `session-state` resource kind) | authorable | static only; no dynamic, no handle | static-floor, ambient-root | none — open to all principals in v1 (§5.3), closeable per principal by profile |
  | `path:cwd-mutate` | the **target logical path** | authorable | static only; no dynamic, no handle | ambient-root only | **root-only positive predicate** |

  The root-only predicate is not optional decoration. Merely making mutation
  `Authorable` would permit a *package* static floor to authorize it — which is
  precisely the channel §5.2 exists to close. The predicate must be part of the
  action definition, not left to policy authoring.

  Each action carries its stable ID, its wire resource shape, its globality (both
  are **session-scoped**, not `shared-process-mutation` — that is the whole point),
  and its target cells. The legacy `process:cwd` deny-only row is retired together
  with the `__exactSetCwd` and `process.chdir` closed edges it backs. Its
  reconciliation entry records that the *shared-process-mutation* condition is met
  (§5.1) **and** that the within-runtime root-to-package influence on the shared
  resolution base is a deliberate, recorded property — not a claim that no other
  principal's resolution changes.

  **None of this is expressible in the current schema, and "adding rows" will not
  make it so.** `capsec/schema/capability-definitions.schema.json` admits no
  `session-state` resource kind, no `session-scoped` globality, and **no predicate
  field of any kind** — so the root-only positive predicate has nowhere to live, and
  a package-authored static floor could otherwise satisfy the mutation action.
  Likewise the evaluator takes a single adapter-supplied boolean
  (`crates/capsec-semantics/src/decision.rs:259-265`) rather than deriving root-ness
  from the complete authenticated constrained-principal set. This is a **schema and
  evaluator version change** (`OBL-CWD-SCHEMA`, §9), and the predicate must be
  **core-enforced** — derived by the semantic core from the constrained set — not
  delegated to an adapter that could be asked the wrong question.
- **Every cwd-reading path/URL alias reclassified, with a no-effect branch.**
  `export:node_path:resolve` and `export:node_path:relative` are classified
  `non-capability` / `pure-in-memory-compute` today
  (`capsec/registry/coverage-edges.json`), which is **wrong**: they *may* read the
  session resolution base. And it is not only those two — an earlier draft called
  `path.win32`/`path.posix` "pure lexical utilities," but the shipped implementation
  is shared: `path.win32.resolve` reads the cwd (`src/builtins/path.js:206`),
  `relative` calls that resolver (`:298`), `toNamespacedPath` does likewise (`:456`),
  and `url.pathToFileURL` consults the cwd for a relative input (`src/builtins/url.js`).
  Under the strict profile (§5.3), any of these left unclassified would resolve
  against root's *real* cwd while `process.cwd()` reports `/project`, breaking
  view-equals-base. So **every cwd-reading alias** — across `node:path`,
  `node:path/posix`, `node:path/win32`, `path.posix`, `path.win32`, `node:url`, and
  the Exact-global facades — is reclassified with the **same explicit no-effect
  branch**: a call whose arguments fully determine the result reads no session state
  and takes no decision (so `path.resolve("/project/a")` is free); a call that falls
  through to the base is a session-state read projecting the per-principal view. Only
  the functions that *never* read the base (`join`, `normalize`, `basename`,
  `dirname`, `extname`, `parse`, `format`) keep `non-capability`.
- **Synthetic-root no-effect branch** — namespace metadata operations on `/` do
  not require `fs:list` or any other filesystem action.
- **System-information rows** behind the §6 observables table.
- **Path-bearing native bridges** — reclassified as sealed or as typed logical
  surfaces, as a projection of LLP 0022 §7's single bridge inventory.
- **A new output-disposition dataset.** §6's table cannot be generated from the
  registry as it stands: `coverage-edges.json` describes surfaces and effects but
  carries **no** output-field, return-shape, alias, or path-disposition schema, so
  the "join" §6 depends on has no left-hand side, and an unmarked new field would
  escape silently — the exact failure §6 exists to prevent. The registry therefore
  gains a dataset keyed by the **one canonical tuple** `(stable surface id, field or
  return-shape, alias, mode, source kind, return variant)` — the identical spelling in
  §6 and the §9 ledger row — carrying a **mandatory** disposition from §6's closed set,
  generated from **live execution**. Validation fails the build on any un-dispositioned
  field, any duplicate key, or any value disagreeing with the executed surface. §6's
  table, the bridge-sealing assertions, and the fixtures are all projections of this
  dataset.
- **The arming containment invariant** (§1.2) is a new armed-snapshot invariant.
  LLP 0021's invariant list should absorb it so the two documents cannot drift on
  what arming refuses.
- **Every new file, schema, and dataset** named here joins the registry's
  `contract-files` set, its digest projections, its generated bindings, and its
  target cells. A dataset that is not digest-bound is not authority.

### 9. Delegated obligations

This document cannot land alone. It places obligations on four other documents and
on the policy generator, and — as round-2 review established — an obligation that
lives only in prose is an obligation that escapes. They are enumerated here.

**No validator enforces this table.** `./ref-check` validates `@ref` targets and
LLP metadata only; it has no obligation logic, and LLP 0022 records the same gap in
its own ledger. Stating that plainly is the point: a ledger that claimed a
verification it does not have would be worse than none. Building the checker is
itself the last row.

**Every row records the revision it was last verified against, with its verification
method named explicitly.** This convention has now been wrong twice, and the second
time is instructive. Round 4 stamped rows with the document's own shasum, which `git
cat-file` rejects. Round 5 "fixed" that by stamping sibling rows with `shasum -a 256`
prefixes and claiming "every stamp resolves [via `git cat-file`]" — but **a
document's SHA-256 content hash is not a git object id**: `git cat-file -t
88decefdc683` fails exactly as the doc-shasum did, because git objects are keyed on a
different hash (0024's git *blob* oid is `42560218ce56`; its content sha256 is
`6416ccb8c3c2` — unrelated values). The staleness detector was *again* unverifiable
by its own stated method. The honest fix is to name **two** methods, because two are
needed:

- **`commit:<oid>`** — this repository's tracked code/schema/registry state, at the
  HEAD commit (`commit:3060574776a3`). Verified with `git cat-file -t` → `commit`.
- **`sha256:<prefix>`** — a sibling LLP document, which is concurrently revised and
  may be uncommitted. Verified with `shasum -a 256`, **not** `git cat-file`.

`OBL-LEDGER-CHECK`'s first assertion is therefore "**every stamp is verifiable by its
named method**" — the `commit:` stamps via git, the `sha256:` stamps via shasum — not
the false "every stamp resolves via git." A stamp with no method, a bare line number,
or "current" is not an attestation.

**The deeper lesson, recorded so a third scheme is not invented:** the tool built to
detect unverified claims of completion was *itself* an unverified claim of completion,
twice, in exactly the family it exists to catch — a stamp is only as good as someone
having actually run its stated method against the artifact. And a **resolvable** stamp
is necessary but not sufficient: a stamp can resolve while the *owner-side claim* it
attests is stale or was only ever true of one selectively-quoted line. `OBL-LEDGER-CHECK`
must therefore verify the **owner-side semantic claim against the whole stamped
document**, not merely the stamp's syntax — the failure `OBL-TARGET-PROMOTE` and
`OBL-ERROR-ORDER` exhibited below, where the stamp resolved but the attestation did
not survive reading past the quoted line.

| ID | Obligation | Owner | Landed? | Verified against |
| --- | --- | --- | --- | --- |
| `OBL-OCCURRENCE-PROJECTION` | Project the resource into **each constrained principal's own binding**; carry an exact `{principal → projected resource}` map whose key set equals the constrained set; key the cache on **principal-resource pairs**; and make the **requested-stage** projection lexical (no I/O), which requires each binding to carry an authenticated virtual prefix (§2.2). Without it, a package's own grant structurally authorizes an occurrence on **another** package's file. **AC 20a is gated on this row.** | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-OBJECT-STATE` | Admit an `Unknown` object state at the requested stage, so a NamespacePath is expressible and existence is not speculated (§2.1) — model, schema, ABI, digest and cache vectors together | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-SOURCE-ID` | The `SourceId` algebra of §2.3 — its per-kind constructor (**including the root/project arm**), canonical wire encoding, equality, collision domain, the **query/fragment strip** decision, and its separation from the pinned `SourceLabel` | **LLP 0021** + this document | no | `commit:3060574776a3` |
| `OBL-SOURCE-PROVENANCE` | A **digest-bound provenance manifest** carrying a `SourceId` per **original** module through bundling, caching, and bytecode, produced from authenticated graph/binding data, plus the runtime original-module registry that makes a later raw load return the already-instantiated bundled module (§2.3). *Owner corrected:* this is artifact provenance, not the Hermes compat transform, so it is **not** LLP 0019's subject. | **LLP 0021** + bundler | no | `commit:3060574776a3` |
| `OBL-OBJECT-GENERATION` | Name the platform primitive supplying the retained object's **verification generation** (`st_gen` in `sys/stat.h`, or `ATTR_CMN_GEN_COUNT` via `getattrlist` — the real macOS identifiers, not the `ATTR_CMNGEN` a prior draft misnamed), and the fallback where none is reliable (§2.3) | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-OBJECT-BOUND-MUTATION` | The object-bound protocols and concurrency threat model required to **reopen** symlink/hard-link creation, rename, removal (incl. recursive), `cp`/`copyFile`, `watch`, and recursive `mkdir` — all closed in v1 (§4.1). POSIX offers no object-bound `renameat`/`linkat` operand; a reopening must name the primitive (e.g. `linkat(..., AT_EMPTY_PATH)`) and the platforms that provide it. LLP 0021 lists `copy` in its *closed* set (`0021:688-690`) — kept closed here, so no divergence — but a reopening must move it there in the same change. | **LLP 0021** | no | `sha256:daa9a6823b00` (0021) |
| `OBL-MKDIR-ROLLBACK` | §4.1 makes non-recursive `mkdir` a bare atomic `mkdirat` with **no** name-bound rollback (the rollback is a verify-then-`unlinkat` TOCTOU). LLP 0021 still specifies mkdir to "commit the opened directory identity, **rolling the new directory back if commit fails**" (`0021:678-687`), and the shipped code implements that (`hermes_runtime_fs.cc:732,740`). LLP 0021 must **retire the mkdir rollback** in the same change — the untracked contradiction the round-7 review surfaced, filed here parallel to the `copy` note above. | **LLP 0021** | no | `sha256:daa9a6823b00` (0021) |
| `OBL-PACKAGE-IMMUTABLE` | Make authenticated package source immutable via **two** guards (§4.2), because the shipped single-object `ProtectedObjectGuard` (`decision.rs:114-117,946`) cannot express it: (a) a **lexical path-tree guard** denying writes/creates within a package's virtual subtree at the requested stage, before lookup, **rerun after each symlink expansion** against the canonical parent + absent tail; (b) a **set-valued exact-object/generation guard** denying commits whose retained final object is package source however spelled. The object set is **eagerly populated by the arming-time integrity walk** (`OBL-INTEGRITY-BIND`), with membership by **defining principal** (a package symlink out to root source does not freeze it), visited-object cycle bounds, and arming refusal of a package/first-party shared inode. Immutability holds if either guard fires. | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-ABI-HANDLE` | Session identity on `ex_hermes_create`/`ex_hermes_eval` — the **semver-major** half, amending LLP 0002's five-function narrow contract (§7.1) | **LLP 0002** | no | `sha256:020f3455209e` (0002) |
| `OBL-HOST-SESSION` | Session-index the process-global `Host` and thread runtime identity through the typed `ex_host_*` ABI, plus the worker **operation lease** (§7.1). LLP 0002 calls this surface an implementation detail, so this half is **not** semver-major | **LLP 0002** (impl. surface) | no | `sha256:020f3455209e` (0002) |
| `OBL-ERROR-UNION` | The versioned discriminated result union with explicit discriminants and ownership rules (§7.2), replacing `1/0/-1`; and the generated pairwise-precedence fixtures, so a new reason cannot ship without its ordering tests | **LLP 0002** + this document | no | `commit:3060574776a3` |
| `OBL-TYPED-READ` | `.load`'s credential-verifying pre-read: the typed path decision, the authenticated byte capsule and referrer, retained identity, TOCTOU behavior. This document supplies the **path side**; the credential algebra is **LLP 0024's two-capability capsule** (`0024:240`, separate read + evaluation permits) — *not* LLP 0022's **one-permit** form (`0022:697`), which is circular (binding the byte digest requires the read, an effect). **The 0022 one-permit edit to the two-capability form is owed** and assigned here. | **this document**, **LLP 0024**, **LLP 0022** | 0024 form landed; 0022 edit owed | `sha256:6416ccb8c3c2` (0024), `sha256:88decefdc683` (0022) |
| `OBL-GRAPH-LOCATION` | Armed-snapshot fields carrying, per graph principal, its resolving specifier, canonical root object, authenticated virtual alias set/prefix, optional/platform disposition (§1.2), **and a digest-bound `(importer, request specifier/alias, exact imported principal)` map** so tier-2 `out-of-snapshot` membership is exactly computable from the caller's view (§7.2), rather than reduced to bare package names as today (`src/host/mod.rs:1526`) | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-RESOLVE-GATE` | Apply the tier-2 membership gate and the no-probe/no-body-read rule to **every resolve-only *module* bridge** — `require.resolve` local/global, `resolve_module_meta` — not just `import` (**not** `Exact.resolve`, a `path.resolve` delegate). Today `require.resolve` bypasses `checkImportGate` (`module-loader.js:5768-5770`) and `resolve_meta` **reads the ESM body** with `std::fs::read_to_string` (`src/module_loader/mod.rs:775`) under an `fs:list`-only classification — an existence oracle **and** an unauthorized body read; the shipped test (`mod.rs:1358`) only exercises `.ts`, which is classified without a read, so it misses this. The resolve route must be body-read-free. **LLP 0002 (`0002:175`) and LLP 0004 (`0004:296`) still document metadata resolution as body-read-free** — the doc owners of that claim; both must be reconciled to whichever way the code lands. | **this document**, **LLP 0014**, **LLP 0002**, **LLP 0004** | no | `commit:3060574776a3` |
| `OBL-DISCOVERY-RECORD` | Armed-snapshot fields carrying the discovery origin, selected marker kind and path, marker-set version, and selected root — digest-bound, so a marker-rule change cannot silently re-root a project (§1.1) | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-INTEGRITY-BIND` | The algorithm and point at which installed content is verified against the package principal's integrity digest (§1.2) — without it a binding authenticates a location, not a content | **LLP 0021** / **LLP 0014** | no | `commit:3060574776a3` |
| `OBL-ALIAS-CANON` | The versioned per-volume canonicalization function, applied to **authored selectors and occurrences alike**, bound into the snapshot digest, with the decision cache keying on **post-canonicalization** bytes (§3). If the built canonicalizer has a failure/collision mode, it defines that mode and its error class then — v1 carries no `ERR_IBEX_ALIAS_COLLISION` (removed from the §7.2 order for lack of a defined predicate). | **LLP 0021** | no | `commit:3060574776a3` |
| `OBL-ARMING-CONTAINMENT` | Absorb §1.2's package-containment invariant into LLP 0021's armed-snapshot invariant list | **LLP 0021** | no | `sha256:daa9a6823b00` (0021) |
| `OBL-CWD-ACTIONS` | The two authorable cwd actions and their resources, globality, and channels (§8); retire the deny-only `process:cwd` row | **LLP 0021** registry | no | `commit:3060574776a3` |
| `OBL-CWD-SCHEMA` | Version the capability schema, selector/occurrence unions, Rust model, canonical bytes, containment, and cache identity to admit a `session-state` resource kind, a `session-scoped` globality, and a **core-enforced root-only predicate** — none of which exist today (§8). Also: the stricter non-root profile is a **no-effect constant projection** to `/project`, not a denial — a binary denial cannot produce the sanitized success AC 13 requires. | **LLP 0021** schema | no | `commit:3060574776a3` |
| `OBL-CWD-FLOOR` | Synthesize the universal static-floor row admitting every principal to `path:cwd-observe` — `sys:read` permits it, but no shipped artifact authors one (§8) | **LLP 0014** generator | no | `commit:3060574776a3` |
| `OBL-DISPOSITION-DATASET` | The output-disposition dataset keyed by the **one canonical tuple** `(stable surface id, field or return-shape, alias, mode, source kind, return variant)` — the identical spelling in §6, §8, and here. It carries the independent output-shape **catalog** (the join's left side), the **bidirectional** validation, and generates each disposition **from live execution**, with the build failing on any un-dispositioned catalog field, any **duplicate key**, and any dataset **value** disagreeing with the executed surface. Includes the `non-path`/`typed-logical`/`reserved-constant` members. | **LLP 0021** registry | no | `commit:3060574776a3` |
| `OBL-BRIDGE-PROJECTION` | This document's path-bearing bridge rows are a projection of LLP 0022 §7's single generated inventory, not a second list (§6) | **LLP 0022** | no | `sha256:88decefdc683` (0022) |
| `OBL-MODULE-IDENTITY` | Keep LLP 0024's module-identity text aligned with §2.3. §7.9 defers correctly, but at the stamped revision **three 0024-side edits are outstanding**: its "one instance however it was spelled / across spellings" contradicts §2.3's **case-alias split**; its AC pluralizes synthetic modules where only `ibex:stdin` is one; and its OQ 10 (`0024:2139`) still says LLP 0023 leaves canonical display labeling open, though §2.3 now **pins** `SourceLabel`. | **LLP 0024** | 0024 edits outstanding | `sha256:6416ccb8c3c2` (0024) |
| `OBL-ERROR-ORDER` | §7.2 owns the total order; 0024 §2 defers to it ("LLP 0023 §7.2 owns the total order … this document does not restate it") — **0024 half landed**. The **0022 half is outstanding**: LLP 0022:471 says habitual host spellings produce the outside-mount error "from watches and every effectful filesystem operation," which is order-relevant and **inconsistent** with §4.1/§7.2 closing `watch` with `EPERM` *before* path work. A 0022 edit (drop "watches", since watch is closed pre-classification) is owed. *(A prior draft of this row claimed the 0022 half was "discharged by absence" — that was **itself a false whole-document attestation**, the third instance of the completion-detector-can't-detect-its-own-incompleteness bug, and the reason `OBL-LEDGER-CHECK` below must be a reviewer-performed semantic step, not a mechanical one.)* | **LLP 0024**, **LLP 0022** | 0024 **yes**, 0022 no | `sha256:6416ccb8c3c2` (0024), `sha256:88decefdc683` (0022) |
| `OBL-TARGET-PROMOTE` | These obligations execute before macOS/aarch64 is promoted from `candidateTargets` to `advertisedTargets` (§3). Two owed pieces: **(a) the sibling prose is inconsistent** — `policy-rules.json` has `advertisedTargets: []` (authoritative), but 0021 says both "the macOS candidate remains unadvertised" (`0021:8`) and "the only advertised profile" (`0021:930-943`), as does 0013 (`0013:18-24`); the docs must reconcile to the machine data. **(b) the *source* manufactures the advertised state rather than deriving it** — `src/bin/ibex/runtime.rs:1981` hardcodes `target_complete_and_advertised: true` and `crates/capsec-semantics/src/arming.rs:361` hardcodes `TargetArmState::CompleteAdvertised`, both ignoring `advertisedTargets: []`. Promotion requires **removing the hardcodes, deriving the gate from authenticated machine data + the completed target report, and a clean-build test proving the candidate refuses** (the shipped binary already refuses, so it is ahead of the source path — bind a built binary to its source/registry revision so a stale binary cannot mislead review). | **LLP 0021**, **LLP 0013**, code | no | `sha256:daa9a6823b00` (0021) + `commit:3060574776a3` |
| `OBL-LEDGER-CHECK` | **Two obligations, because a mechanical tool cannot establish arbitrary prose truth** (LLP 0022:933 says so, and this ledger proved it — a *resolvable* stamp still carried a false whole-document attestation, three times). **(a) a deterministic checker**: every stamp resolves by its named method, every obligation ID and owner-side marker exists, landed state is a fixture pass. **(b) a provenance-tracked whole-document semantic attestation** that the owner-side *claim* survives reading the whole stamped document — performed by a reviewer or a formalized executable assertion, *not* by (a). The dual-model review rounds recorded in `llp/reviews/` **are** that semantic attestation for this document's current state; a standing checker for (b) is owed. | **LLP 0000** (process tooling) | **(a) no; (b) is the review record** | `commit:3060574776a3` |

## Acceptance criteria

Fixtures are generated from the surface registry, the output-disposition dataset,
and the builtin manifest, so a new or aliased API cannot escape them; source and
vendored-generated builtins run the same fixtures. All armed execution modes
(file, REPL, program stdin, `-e`/`-p`/`eval`) share them.

1. From a temporary project containing `README.md`, callback, sync, and promise
   `fs` reads of `README.md` and `/project/README.md` return the same bytes; no
   operation attempts host `/README.md`.
2. `process.cwd()` returns `/project`; `path.resolve("README.md")` returns
   `/project/README.md`; neither output contains the host temp path.
3. **Project-root discovery (§1.1):** `ibex src/app.js`, in a repo whose marker
   and `node_modules` sit at the repo root, mounts the **repo root** as `/project`,
   not `src/`; the package graph arms; the entry's `import.meta.url` is
   `file:///project/src/app.js`. A markerless directory falls back to the discovery
   origin with the named diagnostic. REPL, program stdin, and `-e` launched in the
   same repo select the same project root. The selected marker kind and path are
   recorded in the armed snapshot.
3a. **Monorepo (§1.1 step 3):** `ibex packages/foo/src/app.js` inside a workspace
   selects the **workspace root** — not `packages/foo` — so the hoisted
   `node_modules` is inside `/project` and the graph **arms**. The nearest-first
   reading, which would select `packages/foo` and refuse arming, is asserted
   *not* to occur.
   Two variants must pass that **cannot** succeed via the lockfile fallback, so the
   membership predicate is actually exercised: (i) a workspace whose member carries
   its own lockfile, and (ii) a workspace with **no** root lockfile. Both still select
   the workspace root, proving ancestor-inclusive membership fired.
3b. **Ascent stops (§1.1 step 4):** a stray `package.json` in the invoking user's
   home directory does **not** enlarge `/project` to the home directory; ascent
   stops at the home boundary and at a device boundary.
4. Traversal and containment: `..`, `/project/..`, and `/` all denote the synthetic
   root; listing `/` enumerates exactly the mount table in the pinned order and
   takes no `fs:list` decision; `stat("/")` returns the pinned synthetic record;
   `/etc/passwd`, `/home/<user>/x`, `/README.md`, and `/project/../etc/passwd` are
   refused with `ERR_IBEX_OUTSIDE_MOUNT` before any host access, distinct from
   in-project `ENOENT`; `fs.existsSync("/etc/passwd")` returns `false` rather than
   throwing.
5. **Alias canonicalization (§3):** on a case-insensitive or normalizing volume, a
   path-keyed denial or ceiling authored for `/project/secrets` is **not**
   sidestepped by `/project/Secrets` or by an NFD spelling — both map to one
   authorization identity — while the display spelling the caller passed is
   unchanged.
6. File URLs: `%2F` is refused with `ERR_INVALID_FILE_URL_PATH`. **`%5C` is
   decoded** as a literal backslash — a legal POSIX component character — and
   `pathToFileURL(fileURLToPath(u)).href === u.href` round-trips for a path
   containing a backslash, so the serializer's own output is never rejected. (The
   comparison is on `.href`, not on object identity: `pathToFileURL` returns a fresh
   `URL`.) This matches **Node** exactly: Node on POSIX also decodes `%5C`, refuses `%2F`, and
   round-trips a backslash filename — verified by executing Node, not by assertion. Percent-encoded dot segments are **collapsed** at
   URL parse, not refused, and the resulting path is then subject to containment — so
   `file:///project/%2e%2e/etc/passwd` ends in `ERR_IBEX_OUTSIDE_MOUNT`, not a decode
   error. **Both** `fileURLToPath` implementations — `node:url` and the one on the
   `Exact` global — enforce this.
7. **Name-bound and multi-operand mutation is closed (§4.1):** `fs.symlink`,
   `fs.link`, `fs.rename`, `fs.unlink`, `fs.rmdir`, `fs.rm` (incl. `recursive`),
   `fs.cp`, `fs.copyFile`, `fs.watch`/`watchFile`, recursive `fs.mkdir`, the
   metadata-mutation family (`chmod`/`chown`/`utimes` and their `l`/`f`-variants),
   `mkdtemp`, and the disposable-temp cleanup path — sync, callback, promise,
   `FileHandle`, and descriptor forms alike — each return the typed closed-operation
   denial (`EPERM`) and take **no** filesystem action, asserted by a red-team fixture
   that no artifact was created, moved, removed, or re-permissioned. Closure is at the
   **public entry point**: `fs.rm("/project/dir", {recursive:true})` performs **no**
   `lstat` or `readdir` before denying, so a composite cannot leak existence or do
   partial effects before reaching a closed leaf. **A mutation surface not on the open
   list is closed by default** — a fixture adds a synthetic unlisted mutation op and
   asserts it denies. Non-recursive `mkdir` **is** open and is a single atomic
   `mkdirat` under the retained parent with **no** name-based rollback; a fixture with
   a directory swapped after creation asserts no `unlinkat` fires.
7a. **Authenticated package source is immutable, by both guards (§4.2):** (i) a
   package B holding a valid `fs:write` grant **cannot** mutate a file hard-linked to
   package A's source — a red-team fixture hard-links two packages' files to one inode
   (the admitted store layout), has B write its own name, and asserts A's bytes
   neither change nor later execute (the **exact-object/generation** guard, at
   commit); (ii) B **cannot create a new file** inside a package binding's subtree —
   asserted to deny **before any lookup**, so it cannot even probe the target's
   existence (the **lexical path-tree** guard, at the requested stage). First-party
   project source outside any package binding remains writable.
8. **Symlink traversal and readback (§4):** a pre-existing link whose target leaves
   every mount is refused at the discovered-target re-authorization step, before
   any content read; a chain exceeding 32 steps is refused with `ELOOP` at the
   fixed bound, not the platform's; the link's own identity is retained (or the
   pinned pre/post verification protocol runs), and a link swapped between
   authorization and follow is refused rather than followed; `readlink` returns the
   **translated virtual spelling** — identically in sync and async form and under
   `{encoding: "buffer"}` — and never raw physical bytes; a **dangling** link reads
   back through its deepest existing ancestor; `realpath` yields the canonical
   virtual absolute path; a foreign link to a host path, and a link whose target has
   no unique virtual spelling, are refused with `ERR_IBEX_UNMAPPABLE_LINK`. A
   **moved project** still resolves its own links. `node_modules` layouts that rely
   on in-project symlinks continue to load.
9. `process.chdir("subdir")` changes only the calling runtime's virtual cwd; a
   second runtime and the Rust process cwd do not change; a failed `chdir` is
   atomic. **This requires the runtime handle of §7.1** and fails against a
   process-global Host.
10. `process.chdir("/")`, `chdir("..")`, and `opendir("/")` are refused with the
    synthetic-node error (a watch or mutation on `/` is refused *earlier*, by its
    closed-operation `EPERM`, §4.1/§7.2 — not by the synthetic-node rule); only
    mount-table
    enumeration and synthetic stat succeed on `/`.
11. A package-attributed `chdir` — direct, via a deputy call into root code, via a
    promise continuation, and via a timer — is denied, and root's later relative
    resolution is unaffected. `NoUser`/ambiguous attribution denies.
12. **Shared resolution base (§5.1):** after a root `chdir("subdir")`, a *package*'s
    `fs.readFileSync("./x")`, `path.resolve("x")`, and `path.relative` observe the
    new base — the documented behavior, asserted rather than merely allowed — while
    every resulting path is still authorized against the package's own binding, and
    the package gains no authority it lacked.
13. **View equals base (§5.3):** under a profile that closes the cwd read to
    non-root principals, that principal's `process.cwd()`, `path.resolve("x")`,
    relative file URLs, and `error.path` all agree on `/project`; the view and the
    base move together, and none of them discloses root's location.
14. Replacing the cwd directory after a successful `chdir` produces
    `ERR_IBEX_STALE_IDENTITY` rather than resolution against the replacement, and a
    subsequent successful `chdir` clears it.
15. Monkeypatching `process.cwd`/`process.chdir` does not change `fs`, module
    resolution, or `node:path` resolution against the session cwd.
16. **Module identity (§2.3):** root's `import "foo/util.js"` and package `foo`'s
    own `require("./util")` yield **one** module instance (module-level state is
    shared; `instanceof` holds across the boundary), while the two callers'
    *authorization* decisions are taken against their own bindings. A `chdir`
    between two imports of the same file does not create a second entry.
17. **Module identity does not collapse compartments (§2.3):** two *different*
    packages whose files are **hard-linked to one inode** — the in-project
    content-addressed store case §1.2 admits — yield **two** module instances in
    **two** compartments, because their defining principals differ. First-load order
    does not decide the other's compartment. Two principals sharing a canonical
    root, or an equal-specificity binding tie, are **refused at arming** rather than
    broken by load order.
18. **One `SourceId` across every form (§2.3):** raw, bundled, cached, and bytecode
    execution of the same source yield **one** module instance, because they share a
    SourceId — a bundled chunk containing several original modules gives each its
    own SourceId from the provenance manifest, and the chunk's inode identifies
    none of them. Builtins and `ibex:stdin` cache correctly with no file object.
    **Script inputs take no module-cache entry at all**: `repl:<n>`, `ibex:eval`,
    and `.load` are not modules and are asserted to create none. A module whose
    retained object is deleted and recreated is a stale-identity error at **commit**,
    not a silent re-bind — and a cache *hit* performs no filesystem lookup.
18a. **`SourceId` query/fragment strip, and deterministic `SourceLabel` (§2.3):**
    `import("./x.js?v=1")` and `import("./x.js?v=2")` yield **one** instance (query
    and fragment stripped from identity — a stated divergence from Node ESM, which
    splits them). `SourceLabel` is load-order-independent, and **symlinks unify while
    hard links split**: importing a file and a **symlink** to it in either order
    yields the **same** `import.meta.url`, `realpath`, and stack-frame spelling (the
    physical target's canonical spelling); but importing two **hard-link** entries of
    one inode yields **two** instances, each labeled with **its own entry's** spelling,
    so each instance's `import.meta.url`, §7.3 referrer directory, and source-map key
    agree **per entry** in both load orders — the round-8 correction of a prior draft
    that shared one lexically-least label across the entries and thereby re-collided
    them.
19r. **Resolve-only module bridges are gated (§7.2):** `require.resolve` for a
    package **not in the caller's authorized view** yields `out-of-snapshot` with **no
    resolver probe** — asserted by syscall observation, so a resolve-only route cannot
    distinguish absent from unauthorized-present any more than `import` can, and it
    does **not** read the module body (an `.mjs` fixture asserts no body read).
    `Exact.resolve`/`resolveSync`, being `path.resolve` delegates, are **not** gated
    and take no import decision. `require.resolve.paths` returns `null` as shipped and
    is not a probing surface in v1.
19. **Staged identity (§2.1):** `writeFile` to a **nonexistent** path takes its
    requested-stage decision with **no object state asserted** — not a speculated
    `Existing` — retains the parent, and commits against the created object. The
    decision path never requires an object that does not exist.
20. Cross-principal authorization: a `/project/…` string passed from root to a
    package is re-resolved under the package's binding and authority and carries no
    authority with it.
20a. **Per-constrained-principal projection (§2.2) — gated on
    `OBL-OCCURRENCE-PROJECTION`.** In an A-owner / B-deputy call, B's own
    package-root grant **cannot** authorize an occurrence on A's files: the resource
    is projected into B's own binding, where A's file is `project/node_modules/A/x`,
    so B's `Package`-rooted grant fails on root mismatch. The **converse** is
    asserted too, because a rule that only denies is not the rule: B's own
    package-root grant **does** authorize a deputy operation genuinely targeting B's
    own file. This criterion **cannot pass against the code today** — `LogicalRoot`
    is payload-free and the resource names no owner, so B's grant currently matches
    A's file — and it is the acceptance test for that obligation, not for the
    present implementation.
21. Out-of-project package roots: arming a graph whose package binding lies outside
    the project binding (an out-of-project store, a hoisted workspace root, a
    monorepo sibling) fails with the named diagnostic, not with a confusing later
    path error. An **in-project** content-addressed store layout arms successfully.
22. Every row of the §6 observables table is asserted, including the aliases —
    `import.meta.path`/`.filename`/`.file` (**basename**)/`.dirname`/`.dir`,
    `process.execArgv`, `os.userInfo().homedir`/`.shell`, the full `process.argv`
    mode table (**including where user arguments begin**), `module.id`/`.filename`/
    `.path`/`.paths`/`.parent`/`.children`, `Dirent.parentPath`, `FileHandle.path`,
    stream `.path`, `ExactFile.name`, both `fileURLToPath` implementations, and raw
    resolver `path`/`pkgRoot` payloads. The table is verified to be *generated* from
    the output-disposition dataset, and the build **fails on any un-dispositioned
    field** — not merely on a path-bearing one lacking a disposition — which
    requires the `non-path` member to exist. `require.cache` is asserted **closed**,
    and closing it is asserted **not** to close the per-module `module` object,
    which carries its own dispositions.
22a. **`import.meta.url` is not always a file URL:** in program-stdin mode it is
    `ibex:stdin` and `__filename`/`__dirname` are absent, exactly as LLP 0022 and
    LLP 0024 require.
23. Raw path-bearing bridges (`__exactRealpath`, `__exactModuleResolve`,
    `__exactModuleResolveMeta`) are unreachable from JavaScript or return typed
    logical values only; a red-team fixture asserts each by name and fails closed;
    the rows are a projection of LLP 0022 §7's inventory.
24. **The error tiers and their order (§7.2):** every member produces its own reason
    and JS `code` and is not collapsed, and the **precedence is asserted pairwise**
    over the ambiguous cross-products — generated from the error-union dataset, so a
    new reason cannot ship without its ordering fixtures. In particular: an
    outside-mount path that also does not exist reports `ERR_IBEX_OUTSIDE_MOUNT`,
    never `ENOENT`; a policy-denied path that does not exist reports `EACCES`, never
    `ENOENT`; a reserved scheme beats a namespace error; a stale session handle beats
    everything (tier 0); a **module resolution failure never precedes a policy
    denial**; and **`out-of-snapshot` is decided from the caller's authorized graph
    view** — principal A importing a package present in the global graph but not in
    A's permitted set gets `out-of-snapshot`, the *same* class it gets for a package
    absent globally, so A cannot distinguish the two.
24a. **No existence oracle, at every stage (§7.2):** an outside-mount path and a
    policy-denied path each perform **no host lookup** — asserted by **syscall
    observation**, not by the absence of an error. The rule holds *per stage*: a
    symlink whose discovered target is **both denied and absent** reports the
    **denial**, never `ENOENT` — the cross-product a flat error list silently got
    wrong. A principal with no authority over a path cannot distinguish "exists"
    from "does not exist," nor learn the object's type, from the error it receives.
    The current **whole-file-read** routes (`__exactReadFile`,
    `src/engine/hermes_runtime_fs.cc:1984`) open and `fstat` the target before their
    first typed decision and fail this criterion; the actual **open** route
    (`__exactFsOpen`, `:2676`) already authorizes at `~:2705` *before* its first
    `::open` at `~:2725`, so the defect is in the read routes, not the open route — a
    round-8 citation correction, since a prior draft named `fs.open`.
25. Non-UTF-8: a Buffer path that does not decode is refused as malformed; a
    `readdir` encountering a non-UTF-8 host entry reports **that entry** as a
    distinguishable malformed marker and **still returns the rest of the listing**,
    so one undecodable filename cannot deny service against its parent directory.
26. The vendored generated runtime artifacts and source builtins pass identical
    path-semantic fixtures, so a hermetic build cannot retain the old `/` fallback
    behavior.
27. **Alias canonicalization is applied to both sides (§3):** on a
    case-insensitive or normalizing volume, a path-keyed denial authored for
    `/project/secrets` fires for an occurrence spelled `/project/Secrets`, **and** a
    *grant* authored for `/project/secrets` still matches an occurrence spelled
    `/project/secrets` — i.e. canonicalizing the occurrence alone, which would break
    the grant, is asserted not to happen. The canonicalizer's version is bound into
    the snapshot digest, and changing it changes the armed identity.

## Consequences

- JavaScript sees stable paths across machines, worktrees, containers, and mobile
  embedders, and never a host path — enforced over a generated table of every
  path-bearing surface rather than over `process.cwd()` alone.
- Authorization and caching key on authenticated, **staged** identity, so
  cross-principal aliasing and cwd-dependent cache splits become structurally
  impossible rather than merely unlikely.
- Module identity keys on `(runtime, SourceId)`, so one file is
  one module no matter who reached it or which form it executes in — raw, bundled,
  cached, or bytecode — **and** a hard-link coincidence between two packages cannot
  collapse two compartments into one. The retained object becomes *evidence* for an
  identity rather than the identity itself.
- Script inputs (`repl:<n>`, `ibex:eval`, `.load`) are not modules and hold no
  module identity; they have *source* identities only.
- Each constrained principal is evaluated against **its own** binding, as the armed
  model already requires. This document adds no new rule there; an earlier draft's
  attempt to add one was withdrawn.
- The project root is **discovered**, not taken from the entry's parent directory —
  without which the containment invariant would have refused ordinary projects.
- Root's `chdir` moves the resolution base for every principal in the runtime. This
  is stated, argued, and fixture-pinned rather than denied; what virtualization
  closes is the *shared-process* channel.
- The Host ABI gains a runtime/session handle. Per-runtime cwd and per-runtime
  identity are not implementable without it, and the process-global singleton is
  retired for everything this document governs.
- The registry gains two authorable cwd actions, an output-disposition dataset, and
  a corrected `node:path` classification; `process:cwd`'s deny-only row is retired
  rather than reinterpreted.
- Some Node programs that expect `process.cwd()` to reveal an OS path observe a
  deliberate virtualized difference in armed Ibex.
- `fs`, file-URL, module, and loader implementations converge on one resolver; the
  armed host's join against the Rust process cwd and its `is_absolute()` inference
  are retired.
- Name-bound and multi-operand mutation (symlink/hard-link creation, rename, removal
  incl. recursive, `cp`/`copyFile`, `watch`, recursive `mkdir`) is **closed in v1**,
  as LLP 0021 already has it: POSIX offers no object-bound primitive for it, two
  drafts of this document specified it unsafely, and a clear typed denial beats a
  subtly unsafe success. Existing links are still traversed, read back, and resolved.
  **A concrete cost consumers meet here rather than in production:** the ubiquitous
  write-to-temp-then-`rename` atomic-write idiom, and `unlink` cleanup, return `EPERM`
  in armed v1. The open surface is single-path writes; atomic replace waits for the
  object-bound rename protocol (`OBL-OBJECT-BOUND-MUTATION`).
- **Authenticated package source is immutable** (§4.2): a hard link already present in
  an admitted store, plus open writes, would otherwise let one package mutate
  another's source and have it execute under the other's authority. The shipped
  protected-object guard did not cover it. This is a supply-chain-write defense, and
  a package needing scratch space uses a future writable mount, not its own root.
- `readlink` loses fidelity for host-shaped absolute targets, non-UTF-8 paths are
  refused, and a renamed cwd is a recoverable error rather than a silent redirect —
  three deliberate v1 narrowings in favor of the disclosure and containment rules.
- Physical (`open()`-style) `..` semantics are not reproduced; lexical collapse is
  the documented behavior.

## Open questions

1. Should an explicit, typed debugging authority expose the backing host path to
   trusted root code? If it ever exists it must be **root-only, terminal-lifecycle,
   and handle-taking** — never a string surface, and never through
   `process.cwd()`. Committing to that shape now prevents it being designed as a
   string API later.
2. Should `/tmp` or `/state` become a standard mount, with specified isolation,
   lifecycle, and write policy, strictly apart from internal executable caches?
   (`LogicalRoot::Tmp` already exists in the model,
   `crates/capsec-semantics/src/model.rs:579`.) §4.2 makes this concrete: a package
   forbidden to write its own immutable root needs *somewhere* writable, so a
   per-principal writable **state mount** is the natural home for package scratch
   space — and its absence is the strongest v1 argument for a second mount.
3. Should the non-UTF-8 refusal and the `readlink` narrowing be revisited once the
   typed vocabulary's non-UTF-8 component support is exercised elsewhere?
4. Should host absolute paths ever be accepted from JavaScript? This document
   answers **no** for v1; a future typed-handle design could revisit it without
   reopening string-shape inference.
5. How should out-of-project package roots (out-of-project stores, hoisted
   workspace roots, monorepo siblings) be admitted beyond v1's arming refusal —
   synthetic per-package mounts, a containment rule that admits a principal's own
   bindings, or an authenticated virtual prefix carried on each binding? Each
   requires the armed binding to gain a display prefix it does not have today
   (`LogicalPath` is `{root, components, host_bound}`,
   `crates/capsec-semantics/src/model.rs:583-590`).
6. Should v1 simply ship the stricter profile — `process.cwd()` and the resolution
   base both pinned to `/project` for non-root principals — rather than granting the
   universal read and recording it as an information grant (§5.3)? The
   view-equals-base rule makes this a coherent option today; the cost is Node
   compatibility for packages that read the cwd.
7. *(Resolved this round — `SourceLabel` is now pinned in §2.3 to the load-order-
   independent volume-canonical spelling of the canonical physical location.
   Retained as a pointer so a reader following an old cross-reference lands here.)*
   Should a reserved `/dev/null` **sink node** be added — a namespace node with a
   no-effect write branch, its lookup/open/read/stat/truncate/listing and error-order
   fully pinned — rather than v1's "returns the constant string, fails outside-mount
   on use"? Working CLIs write to `/dev/null` constantly, so this is the cheapest
   concrete argument for a second reserved node.
8. *(Resolved this round — file-URL query and fragment are **stripped** from a
   file-backed `SourceId`, §2.3, a stated divergence from Node ESM. Retained as a
   pointer.)*
9. What platform primitive supplies the **verification generation** (§2.3) —
   `st_gen`/`ATTR_CMN_GEN_COUNT` where available — and what is the fallback where none is
   reliable? A retained descriptor per cached module is correct but has a cost that
   has not been measured — and it should be measured before AC 18's
   cache-hit-does-no-lookup fixture is written.
10. Case- or normalization-aliased spellings of one file are one *authorization*
    identity (§3) but two `SourceId`s, so two module instances — the Node-ESM
    behavior on such a volume, which v1 accepts. Should module identity instead unify
    them via a provenance-selected primary spelling, at the cost of a
    volume-dependent key — and should the split at least be *diagnosed* when it
    occurs, since silent state-duplication is a deeply confusing bug class?
11. Should the operation matrix for the **closed two-path/multi-operand operations**
    (`rename`, `copyFile`, `link`, `cp`, recursive removal) live here or in a
    generated dataset when they are reopened? Each needs source *and* destination
    actions, a binding-transition rule (a `rename` that moves a file between two
    package bindings changes its defining principal, and therefore its module
    identity), and an atomicity rule. §2.3 makes this sharper than it looks.
12. *(Resolved this round — §7.3 now pins that a captured referrer carries the same
    stale-identity re-verification as the cwd, failing a renamed/moved referrer with
    `ERR_IBEX_STALE_IDENTITY`. Retained as a pointer.)*
13. Is `Exact.resolve`/`Bun.resolve` intentionally the shipped **lexical `path.resolve`
    delegate** (`exact-global.js:849`), or should Ibex adopt Bun's actual
    **module-resolution** semantics? The registry classifies it as `fs:list` module
    resolution while the code does lexical arithmetic — a code/registry mismatch to
    resolve either way. §6 dispositions the shipped (lexical) behavior; adopting
    module resolution would be a new API with its own referrer/error/return contract.
