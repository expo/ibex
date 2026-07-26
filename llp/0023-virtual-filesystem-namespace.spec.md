# LLP 0023: Virtual Filesystem Namespace and Path Identity

**Type:** Spec
**Status:** Draft
**Systems:** Runtime, Filesystem, Security, Module Loader, Host ABI
**Author:** Charlie Cheever / Claude / Codex
**Date:** 2026-07-12
**Revised:** 2026-07-25 (armed Windows synchronous descriptor-vector reads now validate the runtime/owner-bound retained descriptor before vector materialization, authorize one exact-object `fs:read` Repeat for the aggregate request, restore the cursor for positioned reads, and scatter only after retained-identity revalidation; worker-backed vector reads remain unpromoted)
**Revised:** 2026-07-25 (armed Windows read-only open now retains the exact VFS file and its parent/final/handle identity behind a runtime/owner-bound opaque registry entry; fstat authorizes Repeat and reads metadata from that same file without pathname fallback, while write-capable opens fail closed before resolution and remaining descriptor operations stay unpromoted)
**Revised:** 2026-07-25 (armed Windows synchronous readdir now retains and enumerates the exact directory handle, authorizes requested/discovery `fs:list` plus repeat before each disclosed member, emits only the long-name coordinate, and has no armed pathname fallback; physical replacement-race and public denial tests pass while descriptors/mutations/async routes remain unpromoted)
**Revised:** 2026-07-25 (armed Windows synchronous lstat now stops contained traversal at the final reparse object, reopens and object-matches it through the retained parent, authorizes requested/discovery/repeat `fs:list` with `no-follow-final`, and has no armed pathname fallback; physical reparse and replacement-race tests pass while enumeration/descriptors/mutations/async routes remain unpromoted)
**Revised:** 2026-07-25 (armed Windows synchronous stat now opens file targets for metadata only and retains them through requested/discovery/repeat `fs:list`; it also represents the authenticated mount root with no fabricated parent, serializes after repeat, and has no armed pathname fallback; enumeration, descriptors, mutations, and async routes remain unpromoted)
**Revised:** 2026-07-25 (armed Windows synchronous whole-file reads now enter the cross-platform retained-object VFS directly with frame-derived constrained principals, authorizing requested/discovery list and commit/repeat read without any armed legacy fallback; async and other installed Windows filesystem effects remain unpromoted)
**Revised:** 2026-07-25 (Windows retained relative opens now stage the parent directory's long name, short name, and 128-bit file ID, refuse any request that selected the 8.3 name, open without delete sharing, and repeat/object-match the entry; arbitrary administrator-assigned short aliases therefore fail closed without making long names unusable, leaving the typed native filesystem backend and incomplete target evidence—not path aliasing—as the remaining Windows promotion blockers)
**Revised:** 2026-07-25 (Windows authorization selectors, occurrences, captured manifests, absences, denied subtrees, and retained traversal now share the digest-bound `windows-ascii-casefold-v1` coordinate; non-ASCII and tilde spellings refuse, case-sensitive directories cannot become traversal roots, and lexical display/SourceId plus distinct hard-link entries remain unchanged; arbitrary custom 8.3 short names, the typed native filesystem backend, and incomplete target evidence keep Windows unadvertised)
**Revised:** 2026-07-25 (Windows now decodes contained Microsoft symlink and mount-point reparses through retained no-follow handles, re-reads mutable target data from the same object, authorizes the complete target-plus-tail before lookup, and restarts from the retained root; unsupported providers, outside targets, the separate Windows alias-canonicalization gap, and the typed native filesystem backend keep the target unadvertised)
**Revised:** 2026-07-25 (corrects armed sync/async `readlink` so stored link bytes require an `fs:read` commit before the first `readlinkat` and a repeat before every buffer-growth retry; ambient `fs:list` remains limited to link/target traversal and cannot disclose the stored value)
**Revised:** 2026-07-17 (LLP 0029 compiled mount profile adds typed `app`/`work` roots, metadata-only `/app`, optional authenticated `/work`, the `ibex:cwd:unset` sentinel, and stable compiled path errors in §1.3); 2026-07-17 (LLP 0029 carrier v2 changes only physical engine binding and preserves original-module SourceId provenance); 2026-07-15 (ENG-25064 landed runtime publication and admission of digest-bound per-original-module prepared graphs); 2026-07-15 (ENG-25065 scoped development module incarnations by execution generation without changing SourceId); 2026-07-15 (ENG-25064 landed the digest-bound per-original-module carrier manifest); 2026-07-15 (ENG-25058 obligation-ledger reconciliation); 2026-07-12
(round-8 dual-model review, **terminal** — both NOT READY,
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
denial); the then-current **existence-oracle citation** was corrected to the
whole-file-**read** routes (`__exactReadFile`) rather than `fs.open` (those read
routes now authorize before lookup, as the current §7.2 records); and — sharpest — my round-7 **`OBL-ERROR-ORDER`
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
`path.resolve` delegates, so they leave `OBL-RESOLVE-GATE` and are classified as
cwd-reading virtual-path outputs; the §6 disposition table is demoted to an
**illustrative interim projection** with the generated `OBL-DISPOSITION-DATASET` as the
normative totality (visible flat contradictions — `module.parent`/`children`,
builtin-vs-file `require.resolve` — fixed, and `Exact.which`/`fs.glob`/`require.main`
closed or dispositioned); a hard link's **`SourceLabel` is its own entry's spelling**,
not a shared lexically-least one, so per-instance `SourceId`/label/referrer/source-map
key all agree and no reverse index is needed. Material: the two immutability guards get
an **arming-time integrity-walk object set** and a **rerun-after-symlink** rule; the
resolve route is now **body-read-free** and every `require.resolve` alias runs
the import gate before native metadata resolution; the open-write family is
**enumerated** and the `watch`-on-`/` vs
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
the mutation surface is **default-closed**; round 6 closed the metadata-mutation
family and `mkdtemp`, while current §4.1 records the later retained async
`chmod`/`utime` exception and keeps `mkdtemp` closed; the observables table gains
`typed-logical` and `reserved-constant` dispositions, Bun aliases, and fixed
`path.win32`/`module.parent` rows; and — humblingly — **the ledger's stamp
convention is fixed a second time**: a
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
ownership — worker locality of retained identities); LLP 0026 (authenticated
module runner and execution generations); LLP 0027 (module artifacts and interop)

## Summary

Source-mode armed Ibex gives JavaScript a **virtual absolute path namespace** rooted at
`/`, with `/project` as the `project-v1` profile's only initial mount, backed by the authenticated
project-root binding. Compiled executables use the distinct `compiled-app-work-v1`
profile in §1.3. JavaScript never sees a host path. Relative paths resolve
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

The source-execution `project-v1` namespace has one initial mount:

| Virtual path | Armed binding | Purpose |
| --- | --- | --- |
| `/project` | logical root `project` | source tree and default resolution base |

The mount table is a **typed table with per-mount attributes** — write policy,
symlink-follow policy, lifecycle, and whether it is metadata-only — even though
v1 has one row. A second mount is then an additive row rather than a new design.

The runtime's other logical bindings are **not** mounted. In particular the
`home` binding — when a snapshot declares the machine-global runtime cache
holding generated JavaScript and bytecode — stays runtime-internal: the loader
and cache machinery use it natively, and it is not addressable from JavaScript.
Mounting an internal executable cache would create cross-project disclosure and
cache-poisoning channels (a write to another project's cached bundle is a write
to code that project will later execute), and under the spelling `/home` it would
additionally shadow the most common Linux host-path prefix, turning a habitual
host spelling into an in-mount `ENOENT` instead of a clear namespace error.

Any future source-profile mount — `/tmp`, `/state`, or another — requires an update to this
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
integrity boundary (`src/module_loader/mod.rs:120-127`), while LLP 0021's package
principal is "the exact package locator plus integrity digest." A binding is only
as trustworthy as the check that the bytes on disk are the bytes the digest names.
The verification algorithm and the point at which it runs belong to LLP 0021 and
LLP 0014, not to a path document; this document *depends* on it and rows it
(`OBL-INTEGRITY-BIND`, §9). The Unix-family armed host now performs that eager,
descriptor-relative integrity walk, compares its digest with the package principal,
and derives the immutable object/generation set from the same traversal. Non-Unix
construction fails closed until an equivalent adapter exists; this is implementation
evidence, not production-target promotion.

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

#### 1.3 Compiled mount profile: `/app`, optional `/work`, and unset cwd

`compiled-app-work-v1` is a distinct mount profile, not a reinterpretation of
`project-v1`. Its typed logical-root vocabulary adds `app` and `work`; a canonical
compiled policy may use only `app`, `work`, or an explicit host-bound `absolute`
root. A `project`, `package`, `home`, or `tmp` logical root in any positive,
denial, or ceiling authority is a packaging refusal. In particular, a reviewed
project-root grant is never silently translated to the launch directory.

The compiled namespace table is:

| Virtual path | Binding | Attributes | Purpose |
| --- | --- | --- | --- |
| `/app` | authenticated embedded graph/source labels | immutable, metadata-only, no host object, no symlinks | module identity, diagnostics, `import.meta.url`, `__filename`/`__dirname`, and source maps |
| `/work` | authenticated launch-directory object, when admitted | optional, ordinary LLP 0023 containment and symlink rules | application filesystem effects and the only compiled relative-resolution base |

`/app` is present as namespace metadata but is **not a filesystem mount** in v1.
The envelope has no asset inventory, so every filesystem operation whose normalized
path falls at or below `/app` fails before host access with
`ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM`. This is distinct from `ENOENT`: the runtime
knows that the path names the embedded diagnostic namespace, not an absent host
file. Adding embedded assets requires a format and policy revision; an implementation
must not make source-relative asset reads work accidentally by consulting the build
tree.

`/work` exists only when boot receives an authenticated work-directory binding under
the embedded policy. Whether the first release authors that authority implicitly or
requires an explicit row is LLP 0029 decision-register item 1; this contract takes
the resulting boolean/binding as input and does not decide the default. When mounted,
the initial authenticated cwd view and relative-resolution base are both `/work`.
When absent, both are unset: `process.cwd()` returns the reserved non-path sentinel
`ibex:cwd:unset`, and a relative filesystem path or `chdir` fails before path
formation with `ERR_IBEX_COMPILED_CWD_UNSET`. An absolute `/work/...` path receives
the same error when the mount is absent. No fallback to the OS cwd, `/`, `/app`, or
the packager's source tree is permitted.

Normalization remains §3's root-wide lexical normalization. It does not clamp `..`
at the mount boundary: from mounted `/work`, `../etc` normalizes to `/etc` and then
fails `ERR_IBEX_OUTSIDE_MOUNT`. `/` remains the synthetic namespace root. Its fixed
compiled listing is `app`, followed by `work` only when that optional mount exists.
The source profile's project discovery and package bindings do not run in compiled
mode; embedded modules carry `/app` labels from the authenticated graph instead.

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

**A single unprojected occurrence cannot express this.** The reason is worth
stating precisely because it is not obvious:

`LogicalRoot` is a **payload-free enum** (`crates/capsec-semantics/src/model.rs:575-581`),
and a logical path is built by stripping the binding's prefix and keeping the tail
(`arming.rs:214-218`). So `/project/node_modules/A/x` mapped under **A's** binding
and `/project/node_modules/B/x` mapped under **B's** binding are the *same value* —
`{root: Package, components: ["x"]}`. **The resource does not say which package.**
Meanwhile the evaluator's owner gate compares the **authority's** declared
`package_root_owner` against the **principal under test**
(`decision.rs:1136-1139`) — never against the binding the *resource* was mapped
under, because the resource carries no such fact. Consequently, an occurrence
computed only under A's binding would let constrained principal **B's own
package-root grant pass both the owner gate (B == B) and bytewise containment**
for **A's file**. The current evaluator therefore refuses an unprojected
multi-principal package-root path instead of reusing the actor's coordinate system
(`materialize_path_projections`, `crates/capsec-semantics/src/decision.rs`).

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

The implementation now performs the batch mapping.
`ArmedSnapshot::logical_paths_for_host_components` takes the canonical principal
set once and projects the host components through each principal's exact
root-binding view. `Host::typed_requested_logical_paths` performs requested-stage
projection from lexical components and the authenticated binding's `hostPath`,
logical root, and exact package owner **before target lookup**; discovery and
commit use the validated retained location. The host supplies the result as
`PrincipalPathProjections`, indexed by effect and then principal.

**No public effect-wire change was needed.** Absolute host paths belong only to
the authenticated host adapter, so `PrincipalPathProjections` is deliberately an
internal sidecar rather than attacker-authored decision-set data. The evaluator
requires its key set to equal the constrained principal set, materializes a
separate canonical occurrence for each principal, and refuses missing, extra,
noncanonical, or actor-inconsistent rows. `DecisionCacheKey` then pairs the
projected resource bytes with `projected_principal_canonical_bytes`, so equal
package-relative bytes in two bindings cannot alias in the cache. The unit tests
`package_path_authority_uses_each_constrained_principals_projection` and
`binding_relative_projection_principal_is_part_of_the_exact_key`, plus the host
integration test `typed_fs_projects_deputy_paths_and_protects_package_source`, pin
both the denial and the legitimate converse.

This lands `OBL-OCCURRENCE-PROJECTION` for filesystem `PathOccurrence`s.
Executable and Unix-socket resources that contain a principal-relative package
path do not yet have equivalent nested-field adapters; a multi-principal use
**refuses arming** instead of falling back to the actor's projection. That
fail-closed narrowing is tested by
`unprojected_package_executable_and_unix_socket_deputies_refuse` and is not
evidence for promoting any target.

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

That key names the logical module and remains the production instance key.
Development HMR adds a separate, monotonically increasing **execution graph
generation** to name a live *module incarnation*:

```text
(runtime/session identity, SourceId, execution graph generation)
```

The extension does not enter `SourceId`, portable artifact identity, source
maps, or authorization. Two incarnations still identify the same source; they
must not share live cells, namespaces, promises, cached errors, or CommonJS
exports. Production has exactly one execution generation. A development
generation transition is atomic and may reuse immutable parse/transform
artifacts by semantic digest, never live module state. This is the LLP 0026 §8
extension, landed with ENG-25065 before any session adopts runner HMR.

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

**The production generated route is deliberately narrower than this algebra while
the full per-original compiler boundary is unfinished.** The algebra above remains
the target: a forty-original chunk carries forty SourceIds and must eventually
materialize forty ordinary module-cache entries. But executing today's flattened
Rolldown chunk as one CommonJS module would do the opposite: one wrapper would choose
one cache entry, one defining principal, and one compartment for code originating in
several modules. The emitted chunk also does not expose a native-verifiable,
independently invocable initializer for each original. Giving project JavaScript a
registry or evaluator that could select those originals would turn the identity
mechanism into a capability leak. Therefore the production route MUST keep every
multi-original or extra-runtime-chunk form closed until the compiler emits a closed,
authenticated per-original initializer representation consumed only by the loader's
native-private dispatcher.

The interim generated form is exact and fail-closed:

- The runtime first authenticates the ordinary raw file request. Its source bytes,
  SourceId, defining principal, SourceLabel, virtual path, referrer, and argv remain
  the credential; a generated artifact cannot mint or replace any of them.
- Only a fresh, authority-bound v4 CJS provenance artifact with **one dependency,
  one provenance row at `depIndex: 0`, one entry chunk, and no output other than that
  entry plus its optional source map** is eligible. The row's raw-source SHA-256,
  exact SourceId cache spelling, defining principal, SourceLabel, virtual path, and
  dependency path must all reproduce the authenticated raw request. **No preexisting
  persistent-cache artifact is eligible for this route.** Its manifest, provenance,
  and graph hashes are public and self-consistent: a cache writer can replace generated
  code and recompute all of them, so they establish freshness and field consistency,
  not compiler authorship. For each eligible request native creates an unpredictable,
  create-new process-private staging root (mode `0700` on Unix), invokes the captured
  compiler/toolchain there, and refuses a graph-named publication collision rather
  than treating it as a hit. The selected canonical runner and its repository scripts,
  lockfile, Rolldown installation, and native dependencies are hashed before and after
  the invocation. Ambient Node/Bun preload, module-path, user-config, transpiler-cache,
  and dynamic-loader injection variables are removed; Bun receives an explicit empty
  private config and no env-file loading, and runner home/config/cache state points at
  the fresh root.

  At the final execution-admission boundary, native performs an independent one-shot
  capture: it opens the one manifest and every admitted output once as bounded regular
  files, with final-component no-follow semantics on Unix and Windows. Earlier
  compiler-publication checks are not execution evidence. Admission parses that exact
  captured manifest once, hashes the exact bytes read from those descriptors, checks
  those bytes and the raw dependency row against the current authenticated request and
  retained authority, and passes only the owned entry bytes to the engine. The staging
  tree is then irrelevant and is removed best-effort; no execution lease or later
  pathname reopen participates in admission.

  This boundary assumes the operator-selected launch runner and other processes under
  the same OS account are trusted. Toolchain hashing detects change during the
  invocation but does not turn an arbitrary runner selected by a hostile launch
  `PATH` into an authorized compiler. Nor can a filesystem protocol protect a process
  from an actively hostile same-UID process that can mutate its files or inspect its
  memory while it runs; defending that actor requires an OS sandbox/account boundary.
  Project JavaScript and persistent-cache writers are inside the boundary closed here:
  neither can select the runner, staging root, manifest, or bytes admitted by a later
  generated evaluation.
- The loader-private dispatcher publishes the result under that same SourceId,
  registers the row's exact package name/locator/integrity where it is package-owned,
  binds the compiled body to that package's exact compartment, and exposes neither
  the dispatcher nor a generated-module registry to project code. Raw-first and
  generated-first loads therefore converge on the identical exports object. Native
  owns the cache transaction through typed-outcome materialization: a throw,
  cancellation, or engine fault aborts the exact SourceId reservation; only a
  committing outcome makes it durable.
- Any missing field, mismatch, stale artifact, alias remap, multi-original manifest,
  additional runtime chunk, or unsupported engine selects the **already-authenticated
  raw source route**. This is a safe representation fallback, not a fallback to a
  weaker evaluator. Once generated evaluation has begun, it never retries the body
  through raw source.

**Provenance-bearing HBC is closed in this interim form.** An HBC file for a flattened
bundle does not prove that evaluating it yields exactly one initializer Function for
the authenticated original; treating its completion value or side effects as that
initializer would bypass the loader-private principal, compartment, and cache
transaction above. The engine therefore refuses a generated bytecode payload rather
than executing it or silently interpreting it as source. HBC may enter this route
only after a versioned wrapper format authenticates that its evaluated value is
**exactly one** private initializer Function for the single SourceId, and native can
invoke that Function without making it or the dispatcher JavaScript-reachable. Until
then, the raw authenticated source route remains the semantic fallback. This
narrowing is an honest partial implementation of AC 18, not a claim that the
multi-original and bytecode portions of AC 18 are complete.

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

An authenticated route memo caches only the resolver-independent mapping to a
SourceId; it does **not** cache the requester's authority. Every cache hit returns
the opaque SourceId to the private native import gate. That gate re-derives the
current frame principal and canonical-round-trips the SourceId. A same-principal
file route remains authorized by that exact ownership. A cross-principal route must
also authenticate the immutable graph edge's requester, normalized request
spelling, target defining principal/locator, resolution kind, canonical derived
conditions, and import attributes before returning the existing exports object.
Consequently a leaked `require` closure cannot reuse a root-owned route, a different
subpath or import kind, or a same-name/different-locator route from another
principal. This check performs no filesystem lookup and therefore preserves the
retained-identity rule below. Dynamic import performs the same check synchronously
while its caller frame is live, then carries a closure-private authorization bound
to the exact resolver mode, resolution kind, normalized specifier, referrer, route
key, native referrer, and SourceId cache key; the detached Promise microtask may
consume it only for that identical memo.

**Retention separates identity coordinates from a reuse discriminator.**
`ObjectIdentity` remains platform/volume/file (device + inode on Unix), while a
path occurrence carries `finalObjectGeneration` separately. On macOS/iOS the
Unix-family adapter uses `fstat(...).st_gen` when it is nonzero. Apple documents
ordinary callers receiving zero, and other Unix targets expose no reliable inode
generation here, so the fallback is `retained-descriptor-v1`: the same
arming-time integrity walk retains one descriptor per unique authenticated
package object for the Host lifetime. Holding the original object open prevents
its device/inode coordinate from being reused while the constant fallback marker
is live. Commit evidence comes from the opened target and must match the
authenticated `(ObjectIdentity, generation)` guard; a missing or changed
generation refuses.

That mechanism is implemented for the Unix-family armed host and pinned by
`authenticated_package_inventory_pins_each_exact_file_object_once` and
`exact_package_object_guard_denies_a_post_arming_alias_outside_the_package`.
Non-Unix armed package-source authentication remains fail-closed until a target
adapter supplies an equivalent object/reuse proof. Cache hits still perform no
filesystem lookup: generation revalidation belongs to effect commit, not ordinary
module-cache reuse. This is a platform implementation boundary, not
target-promotion evidence.

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

**Current candidate-target seam (ENG-24578).** The macOS adapter admits modern
APFS, pins canonical decomposition to Unicode 9, and selects its case-sensitive
or case-insensitive identity from the bound volume. The case-insensitive adapter
implements ASCII folding plus Unicode-9 decomposition (therefore covering common
precomposed Latin aliases); if a remaining non-ASCII scalar has a case-fold
mapping, it refuses instead of borrowing a newer Unicode table or falling back to
byte equality. A bound root is also a single-volume subtree in this seam: a nested
mount on another volume refuses at arming/path projection, and a staged parent or
final object whose volume differs from the root binding refuses. Supplied snapshot
rows are re-probed from the independently authenticated bindings. These are
deliberate fail-closed limitations until the snapshot carries authenticated mount
boundaries and a complete pinned Apple case-fold table.

The Windows adapter binds `windows-ascii-casefold-v1` into the snapshot. It
requires UTF-8 ASCII components and folds ASCII case for both authored selectors
and runtime occurrences. The resolver applies the same comparison key to its
captured manifests, authenticated absences, and denied principal subtrees, without
rewriting the lexical path later used for diagnostics or module `SourceId`.
Every retained root and intermediate directory is queried with
`FileCaseSensitiveInfo`; a set case-sensitive flag, an unsupported query, or a
query failure refuses the traversal because folding would otherwise collapse two
distinct entries. Reparse-target components pass the same input gate before a
target restart. Components containing `~` refuse before native lookup, covering
ordinary generated 8.3 spellings, and non-ASCII components refuse rather than
borrowing an unpinned NTFS/Unicode case table. Distinct lexical names such as two
hard-link entries remain distinct coordinates.

The retained relative-open primitive closes the remaining 8.3 seam without
pretending short names are a stable pure canonicalization table. Before opening a
child, it queries the exact parent-directory entry and stages its long name, short
name, and 128-bit file ID. The directory query runs through a fresh handle whose
identity is first matched to the already-retained parent. If the requested
component selected the staged short name, the operation refuses. Otherwise the
child is opened no-follow without delete sharing, which prevents rename and
`SetFileShortName` mutation while the handle is live; the parent entry is then
queried again and both snapshots plus the opened child ID must agree. Unsupported
information classes, path-to-parent replacement, malformed evidence, and any
snapshot mismatch fail closed.

This staging is necessary because Windows permits an administrator-assigned legal
8.3 name that contains no `~`, while short-name state can change independently of
the long name. A one-shot path query would leave an alias-removal race, and
refusing every file that merely has a generated short name would make ordinary
long-name trees unusable. The retained entry protocol instead refuses selection
through any current short alias while preserving access through the authenticated
long entry. The physical Windows fixture assigns `CSTMSEC.JS`, proves that the
long name still opens and the custom alias refuses, and replaces an entry between
the first snapshot and open to prove the repeat/identity mismatch closes the race.

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
today: the machine-readable profile carries `advertisedTargets: []`, with candidate
targets governed by exact physical evidence (`capsec/registry/policy-rules.json`).
The CLI's hardcoded target refusal is a guard, not an advertisement. The Windows
behaviors above are physically tested candidate behavior only; the typed installed
filesystem backend and incomplete exact-target report prevent promotion. Every
obligation must execute before any candidate becomes advertised
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

Reading the stored link value is an `fs:read` effect even though the value is
withheld until translation succeeds. The retained link and its target are
discovered under ambient `fs:list`, but `fs:list` alone cannot authorize
`readlinkat`: the adapter commits `fs:read` immediately before the first call
and repeats that authorization before every buffer-growth retry. This ordering
both prevents link-byte disclosure under traversal authority and keeps denial
before the first byte read.

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
| metadata mutation except the narrow open row below — `chown`, synchronous path `chmod`/`utimes`, and all `l`- and `f`-variants (`lchmod`, `lchown`, `lutimes`, `fchmod`, …) | some are name-bound (`lchown` on a path), ownership and descriptor mutation require separate authority contracts, and permission/ownership mutation is its own escalation surface; worker-backed single-path `chmod`/`utime` are open only through the retained-object protocol below |
| `mkdtemp` | creates a directory in a temp location that a single `/project` mount does not provide; part of the temp-heavy surface closed above |

**Closure is by default, not by enumeration.** The list above is illustrative; the
normative rule is that **every filesystem mutation operation not explicitly listed
*open* below is closed**, across sync, callback, promise, `FileHandle`, descriptor,
and stream aliases. A newly added mutation surface is closed until this document opens
it, so it cannot escape classification by being unlisted — the same default-closed
discipline §6 applies to observables.

A callable that dispatches both open and closed operations represents this rule with
exact logical branches: the open branch carries its ordinary effects, while each
closed operation branch carries the deny-only `fs:unbound-mutation` disposition.
Selecting the operation is still part of the public-entry boundary; a closed branch
must refuse before resolving any path or descriptor. Immutable target facts may
select a platform-specific branch (for example, worker-backed path `chmod` on Apple
versus closure on Windows), but they come from the bound target profile and are not
caller-controlled.

**Open in v1, and specified completely** — each is a single object reached under a
retained parent:

| Open | Contract |
| --- | --- |
| read, `stat`/`lstat`, `readdir`, `realpath` | staged per §2.1; each stage projected per §2.2 |
| `readlink` and **traversal** of existing symlinks | staged discovery and translation per §4; `node_modules` depends on this |
| single-path writes — the **open-write family**: `writeFile`/`appendFile`, `truncate`/`ftruncate`, `createWriteStream`, `open`/`openSync`/`FileHandle` in any writable/create/truncate flag mode (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`O_APPEND`), descriptor writes, **and the durability operations on an already-authorized descriptor**: `fsync`/`fdatasync`, `FileHandle.sync()`/`.datasync()`, and the `flush: true` write option | one resource, staged, retained-parent-relative; **subject to the package-immutability rule below**. Durability ops are **open** because they act on a descriptor the caller already holds and was already authorized to write — closing the durability *leaf* would let a write succeed and then its `flush:true` deny, the partial-mutation-then-denial composite §4.1 prohibits (the routes perform them post-write at `src/builtins/fs.js:1850,5041,6162`). Every unlisted write alias is still closed by default; a v1 **registry migration marking all effect-classified mutation aliases closed** is owed (`OBL-OBJECT-BOUND-MUTATION`). |
| worker-backed single-path `chmod` and `utime` | the armed adapter resolves beneath the authenticated root, retains parent and final object, authorizes `fs:write` at commit, and reauthorizes the same retained object at Repeat on the worker immediately before `fchmod`/`futimes`; this exception does not open synchronous, link, ownership, or descriptor variants |
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

The same object set is also an **execution and metadata ownership guard**. A
post-arm hard link or rename cannot make a package-authenticated object executable
as Root merely by giving it a first-party spelling: the first-party load checks the
opened final object against the complete package set before submitting bytes. For
resolve-only package metadata, the selected final object must remain in that set,
and Repeat reruns the package integrity proof while VFS retains the exact final
descriptor. Replacement is therefore caught by object membership, in-place mutation
by the two-pass digest, and mutation during that proof by VFS's final metadata
comparison.

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
| `private-native-path` | a host/backing path confined to an authenticated native Host-ABI call; it is never a JavaScript value or a license to project the path into a realm |
| **`non-path`** | the field is judged **not path-bearing** (including a container object whose *own* value is not a path — its path-bearing fields are dispositioned as their own rows) |

**`non-path` is the load-bearing member.** Without it the dataset cannot decide
whether an *unmarked* field (`process.pid`, `os.cpus()[0].model`) is path-bearing
or merely un-triaged, so "an unmarked new field escapes silently" would remain true
*of the dataset itself* — the exact failure this mechanism exists to prevent. The
dataset is therefore **total** over the canonical tuple `(stable surface id,
field or return-shape, alias, mode, source kind, return variant, execution
context id)` — the same spelling used in §8 and the §9 ledger row — for every
**actual output slot** discovered for a registry surface, and the build fails on
any **un-dispositioned** field, not merely on a path-bearing one lacking a
disposition. Judging a field `non-path` is a recorded decision someone signs,
not a silence.

`private-native-path` is deliberately narrower than the other value classes.
It is valid only when the catalog key has `sourceKind: host-abi` and execution
context `host.private-native-call-initialized`, and its expected observation is
the normalized class rather than the machine-specific bytes. A corresponding
JavaScript projection must have its own catalog row and must be virtual,
logical, absent, closed, or refused; the private disposition cannot satisfy
that row.

Output-slot totality is paired with **surface-account totality**. Every coverage
surface id appears exactly once in the catalog as `output-bearing`,
`structural-only`, or `unresolved`. An output-bearing account has at least one
catalog row; a structural-only account has none and carries source evidence for
why that registry edge is not itself a value boundary; an unresolved account has
none and makes the catalog unpromotable. A zero-output surface therefore does
**not** acquire a synthetic `[[return]]` merely to make the row counts line up.

**Totality needs an independent universe, which the registry does not yet supply,
and the table below is an *illustrative interim projection* — not the normative
totality.** The coverage schema records a surface's *kind and name*, not its fields or
return shapes (`capsec/schema/coverage-edge.schema.json`), so a dataset joined only
against that cannot prove its own completeness — an omitted field is indistinguishable
from a nonexistent one. The left side of the join must therefore be an **independently
generated output-shape catalog** — a live descriptor sweep of runtime exports,
object properties, and return-record shapes, plus the native bridge registrar ids
as discovery and provenance inputs — against which the disposition dataset is
checked *bidirectionally*: every catalog field has a disposition, and every
dispositioned field exists. A registrar id proves that a bridge exists; it does
not prove that the bridge has a value-bearing return or satisfy live value
evidence. Native output rows come from source-derived return/out/callback roles
and are then verified by execution.

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
return-shape, alias, mode, source kind, return variant, execution context id)`, with
the build failing on any un-dispositioned catalog field, any duplicate key, and any dataset value that
disagrees with the executed surface. The table below is an **illustrative interim
projection**: its values are corrected where round 8 executed them, but where a value
depends on mode/kind/variant the **dataset's executed value governs**. Every surface
the churn keeps surfacing is closed or non-path-bearing under v1 (no subprocess
`which`, no reopened resolver), so this is a *classification-completeness* obligation,
not an open leak.

Verified output evidence is exact-target evidence, not a reusable corpus-wide
boolean. The v3 evidence contract retains the clean source revision and tree
digest, the exact `{triple, features}` target, the exact v3 executor id, and the
complete loaded-Hermes identity (artifact path, binary digest, file object,
architecture, and structural features). Those bindings remain in the sweep
plan, executor batch, sealed artifact, and final evidence.

The checked-in `registry/output-disposition-evidence.json` remains a corpus-wide
**unpromotable sentinel** and part of the source-derived registry identity. A
verified run from clean base commit A is instead published once under
`conformance/output-disposition-evidence/<raw-content-digest>.json`. Its raw
digest enters the conformance report, the authored target attestation, and the
generated advertisement, but neither the artifact nor its digest enters the
vocabulary, registry, implementation-manifest, or other source-dataset digest.
This separation avoids an impossible revision/tree fixed point: publication may
be a descendant of A containing only the exact digest-addressed evidence,
report, attestation, and mechanically generated target outputs.

Promotion reopens the digest-addressed bytes, which contain the complete sealed
sweep plan and full executor artifact rather than only a projection of expected
values. It revalidates the plan against the current independently authored probe
mechanisms, revalidates every artifact proof and artifact/plan digest,
reconstructs the disposition projection byte-for-byte from those proofs, then
checks the bidirectional disposition-row join and complete surface-account
universe. A catalog-derived file that merely asserts `status: verified` and
copies expected observations is therefore not promotable. Promotion also
requires the evidence's source revision/tree, target, and full loaded-engine
identity to equal the report and attestation exactly. Every target must name
distinct evidence bytes; reusing or swapping an artifact between targets is a
publication error. An incomplete report may omit this binding only while it
remains explicitly unadvertisable.

Every `Bun.*` spelling below is conditional. Armed startup leaves the `Bun`
global absent unless the authenticated snapshot's fixed
`bootstrapCompatibilityModes` set includes `bun`; when it does, `Bun` is the
same object as `Exact`, not a second facade with a separately mutable path or
environment view. The temporary mode carrier is sealed before project code, so
post-arming environment mutation cannot add or remove these aliases.

Its v1 content:

| Surface | Disposition | Armed value |
| --- | --- | --- |
| `process.execPath`, `process.argv0`, `process.argv[0]` | `synthetic-source-id` | the reserved identity `ibex:runtime`; never the host install path |
| `process.argv[1]` | per mode | see the mode table below |
| `process.execArgv` | `non-path` (premise) | its values are runtime flags, not paths (registry edge: authorizable `sys:read`, not `closed`). The `non-path` disposition **rests on the premise** that armed `execArgv` contains no path-valued flag — but `build_exec_argv` (`src/bin/ibex/runtime.rs:942`) splices operator-supplied `EXACT_COMPAT_EXEC_ARGV` through unvalidated, and a future `--project <hostdir>` there would falsify it. The dataset records the premise so `non-path` is **re-forced** if a path-valued flag is added; operator-supplied values are the operator's own data (like user argv), not a runtime-originated host path |
| `__filename` / `__dirname` | `virtual-absolute` / `absent` | virtual spellings in **file-backed** modules; **absent** in a module with no file (`ibex:stdin`) and where there is no module |
| `import.meta.url` | `virtual-absolute` / `synthetic-source-id` / `refused` | the module's virtual `file:///project/…` URL for a **file-backed** module; `"ibex:stdin"` for program-stdin's module-goal synthetic source; and the named `IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED` source-admission refusal in script-goal eval and REPL, as LLP 0022 §5 and LLP 0024 §3 require. It is not always a file URL. |
| `import.meta.path`, `.filename` | `virtual-absolute` / `absent` | the virtual path; **absent** for the program-stdin module source, which has no file. Script-goal eval and REPL reject `import.meta` before property access. |
| `import.meta.dirname`, `.dir` | `virtual-absolute` / `absent` | the virtual directory; **absent** for the program-stdin module source, which has no file. Script-goal eval and REPL reject `import.meta` before property access. |
| `import.meta.file` | `virtual-basename` / `empty` | **the basename only** for a file-backed module — it is `__filename.split('/').pop()` today (`src/engine/bootstrap/module-loader.js:3563`), not a path — and the empty basename value for program-stdin's module source. Script-goal eval and REPL reject `import.meta` before property access. |
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
| `fileURLToPath` / `pathToFileURL` returns — **`node:url`, the `Exact` global, and its enabled `Bun` alias** (`Exact` and snapshot-enabled `Bun` are the **same object**, so every enabled `Bun.*` URL/path alias is covered too) | `virtual-absolute` | the `Exact` global carries a second, laxer implementation today (`exact-global.js:922-926`) |
| `Exact.resolve` / `Exact.resolveSync` (and their enabled `Bun` aliases) | **`virtual-absolute` / `virtual-relative`** (cwd-read) | Pure `path.resolve` delegates, so they return the **same virtual-path spelling as `node:path`'s `resolve`** and are dispositioned identically. They are not module bridges (removed from `OBL-RESOLVE-GATE`); the registry now classifies their observation as `path:cwd-observe` rather than `fs:list`. |
| `path.posix.*` string results (the runtime **default** impl, `src/builtins/path.js:473`) | **`virtual-absolute` / `virtual-relative`** | POSIX results **are** virtual-path spellings embedding the projected cwd — the same disposition as the cwd-reading `node:path` row; grouping them with `path.win32` under `non-path`, as a prior draft did, was wrong |
| `path.win32.*` string results (incl. `path.win32.resolve`) | `non-path` (foreign-dialect) | Windows-shaped backslash strings like `\project\x` — not virtual paths; path-bearing only in embedding the **projected** virtual cwd (§8), so no host path. Whether a foreign-dialect string deserves its own disposition is OQ 4 |
| `os.homedir()`, `os.tmpdir()` | `closed` | **pinned outcome:** each **throws** the closed-surface denial rather than returning a host path. They read `HOME`/`TMPDIR` and return native paths today (`src/builtins/os.js:63`), which is exactly the disclosure being closed. |
| `os.devNull` | `reserved-constant` | returns the well-known constant string `/dev/null`, which names no host and discloses nothing about this machine. It is **not** a mount, so an `fs` operation *on* it fails outside-mount in v1 like any other non-mount path — an earlier draft made it a synthetic write-sink, but §3 refuses any child of `/` that is not a mount and synthetic `/` has no node semantics for it, so the sink was underspecified. A reserved `/dev/null` sink node (lookup, open/read/stat/truncate, listing, and error-order all pinned) is a named future item, not v1 (the sink question is OQ 7). It is `/dev/null` today (`src/builtins/os.js:229`). |
| `os.userInfo()` — `homedir`, `shell` | `closed` | **pinned outcome:** these fields are **absent** from the returned object; passwd-backed host paths are not disclosed |
| Android `__exactAndroidStoragePaths` and platform-state `storage` fields | `non-path` | an armed runtime never calls the JNI storage-path getter for these projections; all five compatibility descriptors are immutable empty strings. The root object is frozen and its binding is non-writable/non-configurable, so a later bundled bootstrap cannot replace the closed sentinel with a host spelling. Unarmed Android retains the LLP 0008 compatibility projection. |
| Android `process.__exactOSRelease` / `process.__exactOSVersion` | `absent` on non-Android targets | the inventory's private identifier spellings are source-bound to these exact `process` property reads, not fabricated raw call returns. Target-absence evidence therefore probes `process.__exactOSRelease` and `process.__exactOSVersion` on the loaded candidate runtime; Android retains the LLP 0008 platform metadata projection. |
| Android-seeded `HOME`, `TMPDIR`, `TEMP`, `TMP`, and `EXACT_ANDROID_*` storage environment keys | `absent` | armed direct reads return `undefined` before native environment lookup, while full environment enumeration is already empty. A grant to read environment data is not a grant to project a private Android backing root. |
| Android persistent Web Storage / default IndexedDB backing path | `closed` / `refused` | the armed empty storage descriptor is a closed sentinel, never a reason to fall through to seeded environment paths or `/tmp`. Web Storage keeps only its non-persistent facade; default IndexedDB reports `NotAllowedError` before SQLite or filesystem path construction. |
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

The POSIX armed realpath adapter uses one such private conversion boundary:
`ibex_private_vfs_project_realpath(runtime_nonce, requested_virtual,
canonical_backing, out_virtual, out_virtual_len, out_errno)` consumes the canonical
identity of an already-retained native target, revalidates the exact runtime VFS
session and authenticated mount, and transfers only an explicit-length canonical
virtual spelling. Its status is the versioned VFS result discriminant and its output
buffer is freed with `ex_host_free_buffer`; every failure initializes the output to
null/zero. It is deliberately an internal `ibex_private_*` linker symbol, not an
embedder ABI. The historical `ex_host_fs_realpath`,
`ex_host_fs_mkdir_recursive_result`, recursive form of `ex_host_fs_mkdir`, and
`ex_host_fs_mkdtemp` are diagnostic/unarmed compatibility bridges: an armed Host
returns `EPERM` before lookup, randomness, or creation. Thus an armed route can
neither obtain a backing spelling from those legacy symbols nor bypass the v1
closed-operation ordering for recursive mkdir or `mkdtemp`.

The Windows realpath route is narrower and remains unpromotable: it canonicalizes
the backing path and projects only the virtual spelling, so it closes the raw-path
disclosure, but it does not yet retain a target handle or revalidate object identity
before and after canonicalization. Windows target promotion therefore requires a
handle-based retained-target implementation and a rename/symlink-race fixture; the
string projection alone is not an object-identity proof.

### 7. The typed logical-path ABI, runtime locality, and errors

#### 7.1 Identity, not text — and a runtime handle

The host adapters must receive identity, not text. The ABI carries the logical
root, the binding owner, the normalized components, the **runtime/session
handle**, and the original virtual spelling for diagnostics — and it must be able
to distinguish a virtual absolute path from an explicit host path structurally.
String-shape inference (`path.is_absolute()`, prefix-matching host components) is
not an acceptable substitute and is retired: it is exactly the mechanism that made
`/README.md` indistinguishable from a legitimate absolute virtual path.

**The runtime handle was a semver-major ABI change, and the production route now
carries it.** `ex_hermes_create_armed` atomically claims one authenticated Host
context and mints a nonzero runtime nonce before bootstrap. The constructor binds
that exact `(host context, runtime nonce)` pair to a `RuntimeVfsSession`; every
engine entry installs it through `ScopedRuntimeSecurityContext`, and the private
VFS entry points take the nonce explicitly. The legacy `ex_hermes_create` remains
present but deliberately non-executable, while armed source is accepted only by
the credential-bearing structured-session evaluator. LLP 0002 records that
semver-major extension and the sealed legacy behavior.

**Which half is semver-major, precisely.** LLP 0002's narrow consumer contract is
**five `ex_hermes_*` functions plus the host-call installer**; it says explicitly
that "the full `ex_host_*` callback surface … is an implementation detail." An
earlier draft called *both* families the narrow contract, which is wrong in a way
that matters: threading a session through `ex_host_authorize_typed_fs_*` is an
**implementation-detail change**, while anything that alters `ex_hermes_create` or
`ex_hermes_eval` is **semver-major** and amends LLP 0002 in the same change. Both
halves are rowed separately in §9 (`OBL-ABI-HANDLE`, `OBL-HOST-SESSION`).

**The implementation has two deliberately different registries.** The old
process-default `HOST` remains only as an unarmed/diagnostic compatibility
fallback. Armed construction publishes an unguessable context token in
`HOST_CONTEXTS`, claims it exactly once, records its runtime nonce, and indexes VFS
state in `RUNTIME_VFS_SESSIONS`. An active armed context that is absent, stale, or
paired with another runtime cannot fall through to the process default. This
retires the process-global behavior for the contract governed here without
pretending that diagnostic compatibility state disappeared.

The async half now has an explicit operation lease. Each filesystem record carries
the nonce-bearing `RuntimeCallbackTarget`, a native-worker pin, the captured
canonical principal stack, retained descriptors, logical/backing spellings in
separate fields, presented handles, and one decided-work closure. A reversible
record remains `Queued`: teardown may remove it under the pool mutex, run its
rollback outside that mutex (including undoing an async-close descriptor
reservation), and release its pin without executing the operation. A worker that
wins the same mutex transition commits the record before its syscall and must
drain.

Owner-thread preparation that can itself create, truncate, make a directory, or
consume a readback uses a two-phase committed admission. Capacity, worker resources,
the queue node, the runtime pin, preallocated result/descriptor state, and the
already-built worker continuation all exist before the lease becomes `Committed`.
The node remains on a hidden preparation list while authenticated preparation runs
outside the pool mutex; preparation fills only preallocated state through
statically checked no-throw moves. Success publishes that exact node to workers with
an allocation-free list splice. Admission failure therefore precedes every effect;
a typed preparation failure abandons the hidden record while preserving its
original JavaScript error; and no worker can observe an unprepared record. Once
committed, teardown retains the exact VFS session until native-worker pins drain,
then unbinds it and frees the runtime. The saturation, queued-close rollback,
pre-admission failure, typed preparation error, and teardown-drain fixtures exercise
these distinct edges. The Windows bridge mirrors the same generation/state lease
contract; target promotion still depends on its independently required target
evidence rather than this source-level parity check.

Windows armed startup and ordinary namespace traversal now use retained handles
throughout. Startup opens the final `/project` directory object with backup
semantics and `OPEN_REPARSE_POINT`, rejects a non-directory, reparse point, or
object-identity mismatch, and retains that handle as the runtime cwd. Each
nested component is first witnessed with handle-relative `NtCreateFile` plus
`FILE_OPEN_REPARSE_POINT`; a directory transition is reopened relative to the
same retained parent and must identify the witnessed object before it becomes
the next traversal root. Whole-file reads retain the exact reopened leaf through
commit, repeat, and byte acquisition. Cwd retention applies the same transition
rules and reopens/revalidates the authenticated root pathname before later use.

A nested Microsoft symlink or mount-point reparse is a staged transition rather
than an OS-followed pathname. The VFS reads `FSCTL_GET_REPARSE_POINT` from the
witnessed no-follow handle, accepts only the Microsoft symlink and mount-point
layouts, reopens and object-matches the same component, and requires an
identical second payload because Windows permits reparse data to change in
place. It converts NT/verbatim drive and UNC substitute names to ordinary
Windows spelling, normalizes relative or absolute targets beneath the
authenticated root, appends the complete pending tail, authorizes that complete
virtual target before target lookup, and restarts from the retained root. The
transition depth is bounded at 32. A reparse `/project` root, unsupported
provider tag, malformed or changing payload, outside target, leaf replacement,
or post-startup root replacement fails closed without disclosing the host path.

The armed Oxc filesystem uses the same retained-boundary and staged-reparse
model for Windows files and directories. It captures package-manifest bytes and
explicit absences through the typed VFS, translates verbatim drive/UNC spellings
only at the Oxc compatibility boundary, and immediately restores canonical host
identity after resolution. `read_link` returns only a decoded Microsoft target
whose complete destination has already passed boundary and denied-subtree
checks; subsequent traversal independently repeats target-plus-tail
normalization and authorization before lookup. This makes authenticated entry,
relative, package-export, package-import, and contained symlink/junction
resolution executable on Windows and removes the former direct-artifact
Windows exception from the closed module-runner proof.

This is not Windows target promotion. Unsupported reparse providers remain
closed. The digest-bound Windows adapter unifies ordinary ASCII case aliases,
refuses non-ASCII and tilde spellings, refuses case-sensitive traversal
directories, and stages/refuses arbitrary 8.3 selections through the retained
parent entry.

Armed Windows synchronous whole-file read, stat, lstat, readdir, read-only
open, descriptor read, and fstat are the first installed filesystem effects to consume that
retained-object backend directly. The engine passes its native runtime generation and
frame-derived canonical constrained-principal stack to private bridges;
JavaScript supplies only virtual path syntax and an optional typed bearer.
`RuntimeVfsSession` resolves that syntax.
`VirtualFileSystem::read_authenticated` retains the selected parent and leaf
through requested/discovery `fs:list`, commit/repeat `fs:read`, and byte
acquisition. `VirtualFileSystem::stat_authenticated` opens the leaf for
metadata only and retains it through requested/discovery/repeat `fs:list`, with
Repeat immediately before serialization. The list lifecycle has no Commit
observation. Stat also handles the authenticated mount root directly: its final
retained object has no in-namespace parent, and the authorization resource
represents that fact instead of fabricating a root-walk object.
`VirtualFileSystem::lstat_authenticated` follows contained ancestor
transitions but stops at a final reparse object, then reopens that entry
no-follow through the retained parent and object-matches it before
requested/discovery/repeat `fs:list` metadata disclosure. Its occurrence uses
`no-follow-final`. `VirtualFileSystem::readdir_authenticated` reopens a nested
final directory relative to its retained parent with list access and without
delete sharing, object-matches it, and enumerates `FileIdExtdBothDirectoryInformation`
on the retained handle. It emits only each entry's long-name coordinate,
validates but never emits its short name, preserves malformed UTF-16 as an
explicit byte marker, sorts deterministically, and performs a Repeat
authorization immediately before each name joins the returned listing.
The retained mount root is structural session state, so these Windows routes
do not borrow the POSIX adapter's extra root-walk observations. Synthetic `/`
lists only the VFS mount names and has no filesystem observations. Every typed
error returns directly through the Node-shaped VFS error mapper; armed
execution cannot reopen the path through the legacy oracle.

`VirtualFileSystem::open_read_descriptor_authenticated` performs Requested and
Discovery `fs:list`, opens and object-matches the regular-file leaf for a
Commit `fs:read`, and returns the exact retained `File` with its namespace,
parent/final object identities, and retained handle ID. The private ABI also
stores the optional presented bearer. The Windows engine publishes only an
owner/runtime-bound numeric table key whose opaque entry owns that retained
file; a guessed integer carries no authority. Fstat first validates that table
owner. `read_descriptor_authenticated` authorizes one `fs:read` Repeat against
the stored object, handle ID, and bearer before reading that exact file, checks
its identity before authorization and after I/O, and restores the file cursor
after a positional read. Synchronous `__exactFsReadv` reuses that operation for
one bounded aggregate acquisition, then scatters the owned bytes across the
validated destinations only after success; denial or stale identity therefore
leaves every destination unchanged. `fstat_descriptor_authenticated`
authorizes one `fs:list` Repeat against the stored object, handle ID, and
bearer and reads metadata through the same file. It never resolves or reopens
the original pathname. Armed
write/create/truncate/append opens and unsupported numeric flag bits return
`EPERM` before resolution or any legacy capability call; this slice does not
claim a mutation protocol.

The synchronous operation inherits the VFS bounded whole-file read limit and
cannot interleave JavaScript-driven revocation while native byte acquisition is
in progress. That reasoning does not promote worker-backed
`__exactFsReadFileAsync`, `__exactFsReadAsync`, or `__exactFsReadvAsync`:
they still need operation leases with generation rechecks between observable
chunks. Durability, mutation, write-capable opens, and all other installed
Windows filesystem routes remain legacy or closed as their individual
contracts require, and exact-target public evidence remains incomplete. The
target therefore remains unadvertised.

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
a generic permission failure. The v1 dataset
(`llp/fixtures/0023-vfs-error-union.v1.json`) is authoritative for the 13 failure
reasons, explicit discriminants, precedence ranks, phases, and JavaScript codes.
`ExHostVfsResultDiscriminant` in `include/exact_runtime.h` and the Rust constants in
`src/host/abi.rs` pin the same values; `ex_host_authorize_typed_fs_stack` returns the
discriminant directly and takes the runtime nonce first. The POSIX adapter projects
that reason into structured `.code`, `.errno`, `.syscall`, `.path`, and optional
`.dest` fields, and `fs.js` preserves an already-structured native code rather than
reconstructing it from message text. The typed authorization result is a scalar and
owns no allocation; private adapters that return variable-length virtual bytes use
the explicit `ex_host_free_buffer` transfer rule and initialize output pointers and
lengths on every failure.

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

  The v1 resolver grammar now makes that membership decision exact and fail-closed.
  Each admitted package name/subpath request is preflighted against the importer's
  digest-bound exact locator/integrity set; exactly one canonical-name candidate is
  required, package-`#` aliases remain inside the requester's authenticated binding,
  and the resolved or cached `SourceId` is checked again against the exact defining
  principal. Ambiguous same-name locators refuse rather than being reduced to a bare
  package-name guess (`OBL-GRAPH-LOCATION`, §9). This is the exact map for the v1
  grammar, not a claim that an unimplemented future resolver spelling was admitted.

  After that snapshot-only admission, armed resolver I/O is likewise closed over
  authenticated inputs. The Host retains the exact project or package binding
  object as the resolver boundary and supplies OXC only the nearest-first
  `package.json` bytes (or ordered absence witnesses) read through the typed VFS.
  Capture and bounded resolution iterate to a fixed point: every manifest path
  OXC actually probes is either supplied as authenticated bytes or recorded as
  an authenticated absence, and an unknown probe is ledgered rather than
  falling through to the host filesystem. This covers nested `exports` and
  package-`#imports` scopes that are discoverable only after an earlier resolver
  step.
  Search stops at the defining binding, not at the root caller's deliberately
  project-shaped view of a foreign package. Present manifests must be strict JSON;
  a package-owned manifest is revalidated against the package's armed integrity,
  and a manifest symlink whose final defining principal differs from its scope is
  refused. The bounded resolver cannot read an uncaptured manifest, traverse an
  outside symlink target, enter a denied foreign-principal subtree through an
  ancestor link plus pending tail, or consult `NODE_PATH`; each expansion checks
  the complete substituted path before its next lookup. Direct `.js` entry grammar binds
  the ordered manifest-search evidence and selected kind into the same linear read
  credential as its source bytes. Thus a malformed home/outer-project manifest,
  a post-arm package-manifest mutation, and an ambient module search path are not
  resolver inputs.

  The tier-2 gate also now precedes **every resolve-only module bridge**: module-local,
  global, `__exactRequire`, and `createRequire` aliases call `checkImportGate` before
  native metadata resolution. `resolve_meta` returns metadata without decoding,
  parsing, transpiling, or exposing TypeScript, MJS, or plain ESM source bodies.
  A trusted package-integrity scan may hash raw installed bytes: this is an
  integrity witness, not a resolver body result. The post-resolution Host gate
  runs requested/discovery/commit/repeat against retained VFS descriptors, gates
  the exact namespace from each callback (including a raced symlink target), and
  authenticates the exact target principal. For a package target, Repeat also
  requires membership in the armed object set and revalidates package integrity
  while the final descriptor remains retained. **`Exact.resolve`/`resolveSync` remain
  outside this rule** because they are lexical `path.resolve` delegates (§6), not
  module resolvers. The alias and no-body-read fixtures named by
  `OBL-RESOLVE-GATE` execute both halves of this distinction.
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

The v1 Host/VFS failure union is **closed and versioned** across the tier-0 session
reason and the path/adapter reasons. Its rank is the total precedence within this
union; the sibling specifier/snapshot/graph classes remain ordered by the tier table
above and are not silently assigned C discriminants here. The discriminant is ABI
identity, not precedence identity: success is discriminant `0`, while the two first
failures deliberately have discriminants `2` and `1` for stale-session and
closed-operation. The dataset pins both columns independently:

| # | Reason | JS `code` | Notes |
| --- | --- | --- | --- |
| 1 | **closed operation** (`symlink`, `link`, `rename`, `unlink`, `rmdir`, `cp`/`copyFile`, `watch`, recursive `mkdir`) | `EPERM` | §4.1 — the operation is refused before any path work, so it precedes even namespace classification |
| 2 | malformed / unsupported adapter input | `ERR_INVALID_ARG_VALUE` | non-UTF-8, empty path, lone surrogate (§3) |
| 3 | encoded separator in a file URL | `ERR_INVALID_FILE_URL_PATH` | `%2F` (§3) |
| 3a | compiled cwd / `/work` mount is unset | `ERR_IBEX_COMPILED_CWD_UNSET` | §1.3 — a relative path has no base; no host cwd is consulted |
| 4 | virtual path outside every mount | `ERR_IBEX_OUTSIDE_MOUNT` | distinct from `ENOENT`; message enumerates the mount table. **No host lookup has happened yet.** |
| 4a | compiled `/app` used as a filesystem path | `ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM` | §1.3 — the embedded namespace has no v1 asset inventory or host backing |
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
and this is a confidentiality rule, not a tidiness rule.** The native whole-file-read
and open routes now enter `walkArmedPath` through authenticated preparation. The
requested-stage decision occurs before canonical-root or target lookup, and each
candidate produced by symlink discovery takes its own containment and stage-0
authorization decision before `openat`/metadata lookup. Only an allowed candidate can
produce `ENOENT` or reveal its type. The conformance observer wraps the actual
`realpath`, `open`/`openat`, `fstat`/`fstatat`, `readlink`/`readlinkat`, and Apple
`F_GETPATH` boundaries rather than incrementing a control-flow marker. Live fixtures
show zero lookups for requested denial and outside-mount, a positive lookup count plus
`ENOENT` for the allowed missing control, and zero lookups **after the refusal** of a
discovered symlink target that is also absent. Thus the test observes the per-stage
rule rather than inferring it from the final error alone.

Existence probes do not throw where Node returns a boolean, and the no-oracle rule
covers **every** boolean surface, not just `existsSync`: `fs.existsSync` on an
outside-mount path *or a policy-denied existing path* returns `false`, while
`fs.access` on a denied path throws the row-6 denial. The distinction between absent
and denied is never observable through a boolean.

The result carries virtual `path`/`dest` spellings, the operation, the reason, and
the safe decision identifier — never a host path, never an authority token. The
wire encoding is a **versioned discriminated union with explicit discriminant
values and stated ownership/freeing rules**, generated alongside the ABI
(`OBL-ERROR-UNION`, §9). The former `1/0/-1` authorization bridge and JavaScript
message-parser fallback are historical shapes, not the current typed route.

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
  return-shape, alias, mode, source kind, return variant, execution context id)` — the
  identical spelling in §6 and the §9 ledger row — carrying a **mandatory** disposition
  from §6's closed set, generated from **live execution**. The context id binds the
  principal class, access phase, runtime state, and target scope, so a cold package
  import, a trusted preload/cache read, and a callable invocation cannot collapse into
  one `mode: all` result. Alongside the rows, the catalog carries the exact one-per-id
  surface accounts defined in §6; any unresolved account prevents promotion.
  Validation fails the build on any missing or duplicate account, any output row on a
  non-output account, any output-bearing account without a row, any un-dispositioned
  field, any duplicate key, or any value disagreeing with the executed surface. A
  compiled registrar can satisfy structural provenance only, never a value observation.
  §6's table, the bridge-sealing assertions, and the fixtures are all projections of
  this dataset.
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
| `OBL-OCCURRENCE-PROJECTION` | Project the resource into **each constrained principal's own binding**; carry an exact `{principal → projected resource}` map whose key set equals the constrained set; key the cache on **principal-resource pairs**; and make requested-stage filesystem projection lexical before target lookup (§2.2). The host-internal `PrincipalPathProjections` sidecar now closes the sibling-package confusion for `PathOccurrence`; package-root executable and Unix-socket deputies refuse until their nested-field adapters exist. **AC 20a is implemented without widening target support.** | **LLP 0021** | **yes for filesystem paths; other package-root deputy kinds fail closed** | `crates/capsec-semantics/src/{arming.rs,decision.rs,cache.rs}`; `src/host/mod.rs::typed_fs_projects_deputy_paths_and_protects_package_source` |
| `OBL-OBJECT-STATE` | Admit an `Unknown` object state at the requested stage, so a NamespacePath is expressible and existence is not speculated (§2.1) — model, schema, ABI, digest and cache vectors together | **LLP 0021** | **yes** | `ObjectState::Unknown`; `effect-occurrence.schema.json`; requested-stage containment/digest vectors; typed VFS stage fixtures |
| `OBL-SOURCE-ID` | The `SourceId` algebra of §2.3 — its per-kind constructor (**including the root/project arm**), canonical wire encoding, equality, collision domain, the query/fragment strip decision, and its type-level separation from `SourceLabel` | **LLP 0021** + this document | **yes** — the canonical `SourceId` crosses the native/JavaScript record boundary and keys armed runtime records | `src/vfs/mod.rs::SourceId`; `module_source_id_is_not_its_display_label`; `file_url_decorations_and_resolution_bases_do_not_change_source_id`; compartment/source-identity fixtures |
| `OBL-SOURCE-PROVENANCE` | A **digest-bound provenance manifest** carries a `SourceId` per **original** module through bundling, cache validation, bytecode, `ibex/module-carrier/2`, and `ibex/prepared-module-graph/2`. It is derived from authenticated graph/binding authority and feeds both the private original-module registry and native linker, so raw-first, bundle-first, carrier, and prepared-graph loads reuse the same logical instance. | **LLP 0021** + bundler + **LLP 0026/0027/0028/0029** | **yes for authenticated bundle/cache/bytecode/carrier/prepared-graph production; target promotion remains separate** | `authenticated_bundle_provenance_is_per_original_and_authority_bound`; bytecode provenance tamper fixtures; `module-loader-provenance-llp0023.test.ts`; `schemas/module-carrier-v2.schema.json`; `schemas/prepared-module-graph-v2.schema.json`; ENG-25064 |
| `OBL-OBJECT-GENERATION` | Supply the retained object's **verification generation** separately from `ObjectIdentity`: the Unix-family adapter uses nonzero Apple `st_gen`; zero/unsupported generation falls back to one descriptor retained per unique authenticated package object for the Host lifetime. Commit must present the same object/generation pair. Windows now authenticates package source with two complete inventories, retained-root-relative opens, and reparse refusal, but that source-integrity path does not invent an object-generation adapter or satisfy the write-guard inventory. | **LLP 0021** | **Unix/Apple object generation yes; Windows source authentication yes but object-generation inventory remains fail-closed** | `src/module_loader/mod.rs::{authenticated_package_inventory,package_tree_integrity_and_source_windows}`; `src/host/abi.rs::object_verification_generation_from_stat`; inventory/alias-guard tests |
| `OBL-OBJECT-BOUND-MUTATION` | The object-bound protocols and concurrency threat model required to **reopen** symlink/hard-link creation, rename, removal (incl. recursive), `cp`/`copyFile`, `watch`, and recursive `mkdir` — all closed in v1 (§4.1). POSIX offers no object-bound `renameat`/`linkat` operand; a reopening must name the primitive (e.g. `linkat(..., AT_EMPTY_PATH)`) and the platforms that provide it. LLP 0021 keeps these routes in its closed set; reopening one remains future work, not a missing v1 implementation. | **LLP 0021** | **not applicable while the routes remain closed; closed-route denial fixtures pass** | `src/engine/hermes_runtime_fs.cc`; armed sync/async mutation denial fixtures |
| `OBL-MKDIR-ROLLBACK` | §4.1 makes non-recursive `mkdir` a bare atomic `mkdirat` with **no** name-bound rollback (the rollback is a verify-then-`unlinkat` TOCTOU). LLP 0021 now states the same contract, and both synchronous and worker-backed armed implementations perform one `mkdirat` after retained-parent authorization without a later `unlinkat`. | **LLP 0021** | **yes** | `src/engine/hermes_runtime_fs.cc` one-`mkdirat` implementations and `mkdir` denial/race fixtures |
| `OBL-PACKAGE-IMMUTABLE` | Make authenticated package source immutable via **two** write guards (§4.2): (a) a **lexical path-tree guard** denying writes/creates within a package's virtual subtree at the requested stage and after complete symlink-target-plus-tail expansion; (b) a **set-valued exact-object/generation guard** denying commits whose retained final object is package source however spelled. The eager Unix-family integrity walk populates the object set by defining principal, bounds cycles, and arming refuses package/first-party shared objects. The same set prevents a post-arm package object alias from executing as Root; resolve-only package targets must remain set members and pass a post-resolution integrity check while their descriptor is retained. Windows independently authenticates source through two inventories and retained-root-relative, reparse-refusing opens, but still refuses construction that requires the absent object-generation write-guard inventory. | **LLP 0021** | **Unix-family write guards yes; Windows source authentication yes but write-guard construction fails closed** | `crates/capsec-semantics/src/{arming.rs,decision.rs}`; `src/{host/mod.rs,host/abi.rs,module_loader/mod.rs}`; `typed_fs_projects_deputy_paths_and_protects_package_source`; `first_party_load_refuses_post_arm_package_object_aliases`; `metadata_only_package_resolution_reauthenticates_selected_target_after_resolution`; package inventory/alias-guard tests |
| `OBL-ABI-HANDLE` | Session identity on the armed constructor and structured evaluator — the **semver-major** half, amending LLP 0002's narrow consumer contract (§7.1). The historical symbols remain ABI-present but cannot evaluate armed project source. | **LLP 0002** | **yes** | `include/exact_runtime.h`; `ex_hermes_create_armed`; `ex_hermes_structured_session_bind`; `ex_hermes_eval_structured_session`; independent C consumer and wrong-session/replay fixtures |
| `OBL-HOST-SESSION` | Session-index the Host compatibility layer and thread runtime identity through the typed `ex_host_*` ABI, plus the worker **operation lease** (§7.1). Armed contexts cannot fall through to the process default. Each FS record captures the runtime generation, constrained principal stack, and decided descriptors/facts. Reversible queue records cancel with rollback; worker-started or owner-prepared effects commit and drain. Committed preparation reserves pin/capacity/node/continuation/state before its boundary, prepares outside the pool mutex, and publishes allocation-free; teardown keeps the exact VFS binding until committed pins finish. LLP 0002 calls this Host surface an implementation detail, so this half is **not** semver-major. | **LLP 0002** (impl. surface) | **yes for implemented filesystem worker routes; target promotion evidence remains separately gated** | `HOST_CONTEXTS`; `RUNTIME_VFS_SESSIONS`; `FsOperationLease`; `FsAsyncLifetime`; queued-close rollback, admission-failure/no-mutation, typed-preparation-error, committed-drain, two-runtime isolation, delayed-producer, and Windows lease-contract fixtures |
| `OBL-ERROR-UNION` | The versioned discriminated path result union with explicit discriminants and ownership rules (§7.2), replacing `1/0/-1`; and a generated all-pairs declaration corpus, so a new reason cannot ship without a rank/code/discriminant and every pair. The generator checks C, Rust, and POSIX C++ projections. The 78 pairs execute the model in both contender orders; reachable ambiguous adapter overlaps have separate live evidence and are not conflated with that model proof. | **LLP 0002** + this document | **yes** | `llp/fixtures/0023-vfs-error-{union.v1,precedence.generated}.json`; `generate-vfs-error-union.mjs`; `ExHostVfsResultDiscriminant`; `VfsReason::{precedence_rank,stable_code,dominant}`; typed Host stale/malformed test; closed/outside/absence and denial/absence syscall-observer fixtures; AC 24/24a |
| `OBL-TYPED-READ` | `.load` uses a credential-verifying typed path read whose decisions precede disclosure and whose result binds immutable bytes, logical referrer, retained identity, source digest, and optional `SourceId` into the same linear submission. LLP 0022 and LLP 0024 now describe the same mint → read-authorized → byte-bound → evaluated lifecycle rather than a circular one-permit shortcut. | **this document**, **LLP 0024**, **LLP 0022** | **yes** | `VfsSession::read`; `ReadAuthorizedSubmission::bind_module_bytes`; `repl_ingress_load_uses_vfs_canonical_path_and_authenticated_bytes`; replay/ordinal/TOCTOU fixtures |
| `OBL-GRAPH-LOCATION` | Bind every graph principal to one exact locator/integrity identity and authenticated root object/virtual prefix, and bind each importer's package allowlist to exact locators. A bare request is preflighted by canonical package name against that exact-locator set: exactly one candidate is required, two same-name locators refuse before resolution, and the resolved/cached `SourceId` is rechecked against the exact defining principal. Every cross-principal cache hit also reauthenticates the exact typed graph edge rather than treating that locator projection as authority. Package `#` aliases remain inside the requester's authenticated binding and receive the same post-resolution principal check. Armed target probing is descriptor-relative beneath that exact retained binding object; package-scope search reaches a fixed point over OXC's exact probe ledger and consumes only strict, typed-VFS-captured manifest bytes/explicit absence bounded to the defining root. It revalidates package-owned bytes against armed integrity, refuses cross-principal/outside symlinks and complete substituted paths entering denied subtrees, and disables `NODE_PATH`. Each typed edge also binds its exact request, resolution kind, sorted condition set, and import attributes before the module runner may admit it. Direct `.js` kind selection additionally binds the ordered manifest trace into its linear source-read credential. This is the fail-closed equivalent of materializing every possible subpath spelling as a separate triple. | **LLP 0021** | **yes for the v1 package-name/subpath and package-`#` resolver grammar** | `ArmedSnapshot::validate_snapshot_invariants`; `ArmedSnapshot::authenticates_module_edge`; `preflight_armed_module_resolution`; `authenticated_bound_package_uses_nested_manifest_for_exported_js_kind`; `authenticated_file_kind_evidence_binds_ordered_manifest_trace_a_b_a`; `authenticated_unknown_manifest_operations_record_without_host_lookup`; `authenticated_denied_subtree_blocks_ancestor_symlink_with_pending_tail`; `authenticated_resolver_disables_node_path_and_cannot_select_an_ambient_package`; `armed_bare_import_preflight_refuses_same_name_locator_ambiguity`; `armed_module_cache_hits_reauthorize_exact_defining_principal`; `armed_module_cache_hits_reauthorize_exact_resolution_kind` |
| `OBL-RESOLVE-GATE` | Apply the tier-2 membership gate and the no-probe/no-executable-body rule to **every resolve-only module bridge** — module-local, global, `__exactRequire`, and `createRequire` aliases plus native metadata resolution — not to the lexical `Exact.resolve` facade. All aliases call `checkImportGate` before native resolution. `resolve_meta` neither decodes/transpiles nor returns source; trusted package-integrity hashing is only an internal witness. The post-resolution Host gate uses the exact requested/discovery/commit/repeat VFS namespaces and retained objects, refuses a principal-changing symlink target before lookup, and revalidates a selected package target after resolution. | **this document**, **LLP 0014**, **LLP 0002**, **LLP 0004** | **yes** | `module-loader-runtime-options-llp0022.test.ts::every require.resolve alias denies before metadata resolution`; `armed_require_resolve_uses_typed_stages_without_reading_invalid_body`; `metadata_authorization_refuses_a_post_resolve_cross_principal_symlink_before_absence`; `metadata_only_package_resolution_reauthenticates_selected_target_after_resolution`; `resolve_meta_omits_source_that_full_resolve_loads` |
| `OBL-DISCOVERY-RECORD` | Armed-snapshot fields carry the discovery origin, selected marker kind/path, marker-set version, and selected root, all included in strict snapshot ingestion and digest identity so marker-rule drift cannot silently re-root a project (§1.1). | **LLP 0021** | **yes** | `ArmedProjectRootDiscovery`; `refuses_project_root_discovery_substitution_and_binding_mismatch`; project-root discovery marker/workspace/device-boundary fixtures |
| `OBL-INTEGRITY-BIND` | Verify installed content against the package principal's integrity digest at arming and derive the protected object/generation inventory from that same eager traversal (§1.2). Unix-family traversal produces both integrity and the generation-bearing guard inventory. Windows performs two complete inventories, opens every object relative to the pinned package-root handle, rejects reparses, and captures source from the authenticated opened object; it does not claim the still-absent object-generation guard inventory. | **LLP 0021** / **LLP 0014** | **content/source integrity yes on Unix-family and Windows; generation-bearing write-guard inventory Unix-family only** | `src/host/mod.rs::validate_snapshot_root_bindings`; `src/module_loader/mod.rs::{authenticated_package_inventory,package_tree_integrity_and_source_windows}`; mutation, symlink/reparse, cycle, root-swap, and add/remove inventory tests |
| `OBL-ALIAS-CANON` | The versioned per-volume canonicalization function is applied to authored selectors, occurrences, root bindings, and decision-cache keys, and is bound into the snapshot digest. The Apple candidate derives its APFS case/normalization adapter from the bound volume. Windows binds `windows-ascii-casefold-v1`, applies that coordinate to resolver control data, refuses non-ASCII/tilde components and case-sensitive traversal directories, and stages long/short entry names plus file identity so any arbitrary 8.3 selection refuses under a repeated retained-object check. Unsupported adapters fail arming rather than guessing (§3). | **LLP 0021** | **yes for Apple and the fail-closed Windows candidate; other target adapters fail closed** | `path_alias.rs`; `windows_resolver_path_key`; `windows_require_casefold_directory`; `windows_directory_entry_snapshot`; custom-short-name and entry-replacement fixtures; `canonicalizer_identity_is_trusted_and_changes_snapshot_identity`; `external_snapshot_cannot_self_assert_a_bound_volume_canonicalizer`; alias fixtures |
| `OBL-ARMING-CONTAINMENT` | Strict snapshot ingestion requires graph nodes, exact import edges, root bindings, defining owners, and the project discovery record to form one consistent containment relation before a Host can arm. | **LLP 0021** | **yes** | `validate_snapshot_invariants`; `validate_root_bindings`; `refuses_graph_authority_and_root_binding_inconsistencies` |
| `OBL-CWD-ACTIONS` | The registry defines `path:cwd-observe` and core-root-only `path:cwd-mutate`, both on the runtime-local session-state resource; native bridges reauthorize each requested/commit operation and never mutate the host process cwd. | **LLP 0021** registry | **yes** | capability definitions/coverage edges; `ex_host_vfs_get_cwd`; `ex_host_vfs_chdir`; cwd facade batch |
| `OBL-CWD-SCHEMA` | Capability schema, selector/occurrence unions, Rust model, canonical bytes, containment, and cache identity admit the `session-state` resource and `session-scoped` globality. Mutation is core-enforced root-only; a denied observation produces the specified no-effect `/project` projection rather than disclosing another base. | **LLP 0021** schema | **yes** | `SessionStateName::Cwd`; schema/registry tests; `process-env-proxy.test.ts`; cwd facade batch |
| `OBL-CWD-FLOOR` | The policy generator synthesizes the universal static-floor row admitting every admitted principal to `path:cwd-observe`; packages cannot author the root-only mutation action. | **LLP 0014** generator | **yes** | `capsec-policy-authoring.test.mjs` floor and root-only negative fixtures |
| `OBL-DISPOSITION-DATASET` | The generator now emits the canonical tuple-keyed output-shape catalog and executed disposition dataset, enforces the bidirectional join, rejects duplicate/missing/value-drifting rows, and includes `non-path`, `typed-logical`, and `reserved-constant`. The mechanism is live, but its incomplete account families now comprise one native `__esModule` marker account, three inherited-intrinsic alias accounts requiring the reviewed Android/source/Windows loaded-engine evidence set, 69 construction-private WebGPU accounts (two callback ingresses, nine private bridge methods, and 58 operation routes) whose public installation and platform-support claims remain absent, one prepared-native-startup carrier, and five test-only immediate-evaluation markers; one rowless parameterized `process.env` binding separately requires a finite authenticated exact-name account set plus complete live scalar/enumeration observations. None can be promoted from source inference or from the runtime-environment occurrence inventory. | **LLP 0021** registry | **mechanism yes; corpus completeness and target promotion blocked by 79 explicit unresolved surface accounts plus one parameterized exact-name binding** | `generate-capsec-registry`; output disposition/catalog tests; `capsec-inherited-intrinsic-alias-accounts.mjs`; `capsec-environment-output-templates.mjs`; current generated catalog counts |
| `OBL-BRIDGE-PROJECTION` | Path-bearing/raw-bridge membership is generated once from source/ABI inventory and joined into both LLP 0022 coverage and this document's output catalog; no second hand-maintained bridge list is authoritative. | **LLP 0022** | **yes** | generated coverage edges, surface inventory, output-shape catalog, and bidirectional drift tests |
| `OBL-MODULE-IDENTITY` | Keep LLP 0024's module-identity text aligned with §2.3: case/normalization-distinct `SourceId`s remain distinct instances, `ibex:stdin` is the sole synthetic module, and `SourceLabel` owns display identity | **LLP 0024** | **yes** — LLP 0024 §7.9, AC 15, and its resolved module-identity question now carry all three rules | current LLP 0024 plus its generated session fixtures |
| `OBL-ERROR-ORDER` | §7.2 owns the total order; sibling documents defer to it and must not classify a closed watch after path work | **LLP 0024**, **LLP 0022** | **yes** — LLP 0024 defers to §7.2; LLP 0022 §4 now says effectful path-classifying operations produce outside-mount while watch closes earlier with `EPERM` | current LLP 0022 §4 and LLP 0024 §2 |
| `OBL-TARGET-PROMOTE` | These obligations execute before macOS/aarch64 is promoted from `candidateTargets` to `advertisedTargets` (§3). Target state must derive from authenticated advertisements and completed reports, never a source hardcode | **LLP 0021**, **LLP 0013**, code | **derivation landed; promotion remains blocked** — production construction authenticates and derives target state in `src/host/mod.rs`; remaining `CompleteAdvertised` constructors are test fixtures. `target-advertisements.json` remains empty and every target cell remains unsupported pending the separately tracked output/alias evidence work | authenticated advertisement tests plus current generated target matrix |
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
3c. **Armed resolver scope:** after graph preflight, extension/index probing is
   descriptor-relative beneath the exact authenticated project/package binding
   object. Nearest-first `package.json` search stops at that defining binding and
   reaches a fixed point over the bounded resolver's exact unknown-probe ledger;
   every probe consumes only strict bytes or explicit absence captured through
   typed VFS decisions, never an ambient disk fallback. A
   malformed manifest outside the boundary is invisible; a malformed nearest
   manifest refuses rather than falling through; outside or cross-principal
   manifest symlinks and ancestor-link-plus-tail entries into a foreign package
   refuse before target disclosure; package-manifest mutation
   after arming refuses even for metadata-only resolution; and `NODE_PATH` cannot
   add a candidate. `#imports`, package `exports`, and direct `.js` kind selection
   all execute this same bounded adapter, with the direct-entry manifest trace
   included in its linear read evidence. Resolve-only disclosure runs all four VFS
   stages on retained objects, reauthorizes the exact callback namespace, and for
   a package target checks both armed-object membership and a post-resolution
   integrity proof; in-place and replacement races both refuse.
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
   closed metadata-mutation family (`chown` and all `l`/`f`-variants across
   their aliases, plus synchronous path `chmod`/`utimes`), `mkdtemp`, and the
   disposable-temp cleanup path — each return the typed closed-operation denial
   (`EPERM`) and take **no** filesystem action, asserted by a red-team fixture
   that no artifact was created, moved, removed, or re-permissioned. The narrow
   worker-backed single-path `chmod`/`utime` exception instead proves
   retained-object commit and Repeat decisions immediately before mutation.
   Closure is at the
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
18b. **Safe staged generated admission, without claiming full AC 18 (§2.3):** a
    source-backed v4 CJS artifact is admitted only from the exact fresh, non-reusable
    compiler transaction and one-dependency, one-provenance-row, one-entry-chunk form
    above; a self-consistent preexisting cache artifact is never executable evidence.
    The exact captured manifest and owned output bytes are descriptor-read once and
    digest-checked against the current authenticated raw request. Raw-first and generated-first
    execution return the identical exports object under the same SourceId; a package
    row is registered under its exact name/locator/integrity and compiled in its exact
    compartment; the second raw load uses the authenticated route memo and performs
    no resolver lookup; and throw, cancellation, explicit abort, or outcome
    materialization failure removes a new reservation. Multi-original/chunk-runtime
    forms fall back to the authenticated raw route. A provenance-bearing HBC payload
    is refused until the exact-single-initializer wrapper format exists. Tests MUST
    also show that ordinary resolver output cannot mint the private generated schema
    and that generated project code receives no dispatcher or original-module
    registry capability.
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
20a. **Per-constrained-principal projection (§2.2), implemented by
    `OBL-OCCURRENCE-PROJECTION`.** In an A-owner / B-deputy call, B's own
    package-root grant **cannot** authorize an occurrence on A's files: the resource
    is projected into B's own binding, where A's file is `project/node_modules/A/x`,
    so B's `Package`-rooted grant fails on root mismatch. The **converse** is
    asserted too, because a rule that only denies is not the rule: B's own
    package-root grant **does** authorize a deputy operation genuinely targeting B's
    own file. `package_path_authority_uses_each_constrained_principals_projection`
    asserts the decision algebra and exact-map refusal, while
    `typed_fs_projects_deputy_paths_and_protects_package_source` asserts the host
    adapter in both directions. These local fixtures establish the mechanism; they
    do not replace the independently advertised-target acceptance report.
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
    requires the `non-path` member to exist. The catalog's surface-account ids are
    set-equal to the coverage registry with no duplicates; every output-bearing
    account has a row, structural-only accounts have none, and any unresolved account
    prevents promotion. No synthetic return is created for a structural edge, and a
    registrar-only observation cannot satisfy a value row. `require.cache` is asserted **closed**,
    and closing it is asserted **not** to close the per-module `module` object,
    which carries its own dispositions.
22a. **`import.meta.url` is not always a file URL:** in program-stdin mode it is
    `ibex:stdin` and `__filename`/`__dirname` are absent. Eval and REPL are
    script-goal entry points and refuse `import.meta` at source admission with
    `IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED`; they do not synthesize `ibex:eval` or
    `repl:<ordinal>` as an `import.meta.url` value. This is exactly what LLP 0022
    and LLP 0024 require.
23. Raw path-bearing bridges (`__exactRealpath`, `__exactModuleResolve`,
    `__exactModuleResolveMeta`) are unreachable from JavaScript or return typed
    logical values only; a red-team fixture asserts each by name and fails closed;
    the rows are a projection of LLP 0022 §7's inventory.
24. **The error tiers and their order (§7.2):** every member produces its own reason
    and JS `code` and is not collapsed. The versioned dataset generates all 78
    unordered pairs and the Rust test executes the declared model winner in both
    contender orders; this proves the closed rank/ABI projection, not 78 fabricated
    live syscall collisions. Reachable ambiguous adapter cross-products are tested
    live: stale-session over malformed shape, closed-operation over outside/absence,
    outside-mount over absence, and policy denial over absence. A new reason cannot
    ship without its rank/code/discriminant and all-pairs model fixtures. In particular: an
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
    Both whole-file-read and open routes now authorize the requested path and every
    discovered candidate before their first lookup at that stage. The private
    conformance observer wraps actual namespace/identity syscalls. It records zero
    lookups for outside-mount and requested denial, a positive count for the allowed
    missing control, and zero lookups after denial of an absent discovered symlink
    target; the returned codes are respectively outside/`EACCES`/`ENOENT`/`EACCES`.
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
28. **Compiled mount profile (§1.3):** compiled policy authoring and strict Rust
    ingestion reject every project/package/home/tmp-rooted authority and every
    target/mount-profile mismatch. `/app/x` fails with
    `ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM` without a host lookup. With no `/work`
    binding, `process.cwd()` yields exactly `ibex:cwd:unset`, relative paths and
    `chdir` fail with `ERR_IBEX_COMPILED_CWD_UNSET`, and absolute `/work/x` fails
    identically. With an authenticated `/work` binding, cwd is `/work`, relative
    normalization resolves there, and `../etc` escapes to the namespace root then
    fails outside-mount. Relocating or deleting the source checkout does not change
    any result.

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
- Compiled mode has no `/project` binding and never treats `/app` as an asset
  filesystem. Optional `/work` is the sole host-backed compiled mount; absent it,
  cwd is explicitly unset rather than fabricated from process state.

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
9. *(Resolved for the Unix-family v1 adapter; non-Unix target work remains.)*
   The verification generation (§2.3) is nonzero Apple `st_gen` where available;
   otherwise the arming inventory retains one descriptor per unique authenticated
   package object for the Host lifetime and uses `retained-descriptor-v1`. The
   descriptor cost remains worth measuring on large graphs, but it is no longer an
   unspecified security fallback. A non-Unix target must name and test an equivalent
   object-reuse discriminator before promotion.
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
13. *(Resolved for v1.)* `Exact.resolve`/`Bun.resolve` intentionally remains the
    shipped lexical `path.resolve` delegate (`src/engine/bootstrap/exact-global.js`).
    The registry classifies the observation as `path:cwd-observe`, matching the
    implementation. Adopting Bun's module-resolution behavior would be a new API
    with its own referrer, error, and return contract rather than a silent change.
