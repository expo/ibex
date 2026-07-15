# LLP 0026: ESM Module Runner and Runtime Module Graph

**Type:** RFC
**Status:** Accepted
**Systems:** Module Loader, Runtime, Engine, Build, Security
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-15
**Revised:** 2026-07-15 (ENG-25064 implemented canonical per-principal source/HBC carriers, atomic admission, and real-Hermes execution equivalence); 2026-07-15 (ENG-25063 implemented dependency-first async SCCs,
handled internal record promises, fresh ESM/CommonJS dynamic-import promises,
sticky rejection, event-loop keepalive, and mixed re-entry refusal); 2026-07-15
(ENG-25062 implemented immutable-snapshot graph authorization receipts, the autonomous initialization context, and the no-probe trusted-loader access boundary); 2026-07-15 (accepted by the author after the bounded producer spike passed 12/12 canonical artifacts and 20/20 frozen test262 cases; wire and interop details split to LLP 0027); 2026-07-15 (moved to Review and created the ENG-25054 Linear execution program); 2026-07-15 (rounds 1–8: dual-model review revisions; see `llp/reviews/0026-esm-module-runner.{fable,codex}.md`)
**Related:** LLP 0002 (host embedding ABI); LLP 0003 (Hermes engine bridge); LLP 0004 (module loading); LLP 0005 (hermetic build); LLP 0006 (native-first diagnostics); LLP 0007 (transform convergence); LLP 0009 (runtime transform scope); LLP 0012 (runtime identity / Node compatibility target); LLP 0013 (package compartments); LLP 0014 (import policy); LLP 0018 (fail-loud agent tooling); LLP 0019 (Hermes-compat transform authority); LLP 0021 (CapSec effect model); LLP 0022 (REPL behavior); LLP 0023 (source identity); LLP 0024 (structured evaluation); LLP 0025 (terminal session ownership); LLP 0027 (artifact wire and ESM/CommonJS interop contract)

## Summary

Ibex should replace its file-at-a-time ESM-to-CommonJS compatibility path with
an **ESM module runner**: an authenticated module graph that parses and lowers
source before Hermes sees it, creates real module records, links static edges,
preserves live bindings and cycles, and evaluates asynchronous graphs including
dependency-level top-level `await`.

The target architecture is:

```text
resolve + authenticate
        ↓
parse and lower with the Oxc/Rolldown transform family
        ↓
produce a provenance-bound ModuleArtifact
        ↓
link ModuleRecords by SourceId
        ↓
evaluate factories in authenticated package compartments on Hermes
```

CommonJS remains a supported, synchronous module kind with its own record and
cache semantics. ESM may import CommonJS through an explicit adapter. A
synchronous `require()` may return an ESM namespace only when the statically
reachable ESM graph is proven synchronous; it fails with one stable error when
that graph contains top-level `await` (§7 defines the guarantee's exact scope
for edges discovered during execution).

Production builds should use Rolldown to prepare the same logical module
artifacts ahead of time, optionally as Hermes bytecode. Development, direct
`ibex` execution, and genuinely dynamic loading should create and cache those
artifacts in process. Both paths must preserve per-module `SourceId`, defining
principal, import-policy edge, source map, and integrity provenance even when
several factories share one physical chunk.

This RFC proposes to resolve the architecture fork left open by LLP 0007. LLP 0007 remains
the authority for transform-toolchain convergence; this document owns module
graph, linking, evaluation, ESM/CommonJS interop, and migration away from the
bootstrap ESM string transformer. It does not make the proposal accepted merely
by existing: the author still decides when the design has enough review and
evidence to advance.

## Motivation

### The current fallback is doing a parser and linker's job

The Rust loader currently transforms TypeScript/JSX-like extensions and a
scanner-selected subset of JavaScript, while ordinary ESM-heavy JavaScript is
served verbatim for a fast path `[observed]`
(`src/module_loader/mod.rs`, `needs_transpile`, `needs_js_downlevel`, and
`resolve_with_oxc`). Hermes cannot execute that ESM through the synchronous
function-body loader, so `transformEsmToCjs` in
`src/engine/bootstrap/module-loader.js` recognizes and rewrites module syntax
with string, delimiter, and regular-expression scanners `[observed]`.

That transformer has to rediscover JavaScript facts such as:

- where a semicolonless multiline `import` or `export` ends;
- whether a line is code, comment, regular expression, or template content;
- whether a newline terminates an initializer or continues it;
- which declarations are hoisted;
- how default, named, namespace, and re-export bindings behave; and
- when a syntax failure belongs to the current body rather than a dependency.

Those are language and module-semantics responsibilities. Correcting an
individual scanner defect is appropriate as a compatibility repair, but adding
unbounded JavaScript knowledge to this transformer is not a sustainable module
architecture.

### File-at-a-time CommonJS lowering cannot provide full ESM semantics

An AST makes syntax recognition reliable, but transforming each file into an
independent CommonJS body still does not by itself preserve:

- live imported and exported bindings;
- temporal-dead-zone behavior;
- namespace object identity and property behavior;
- cyclic instantiation before evaluation;
- star-export ambiguity and re-export resolution;
- asynchronous evaluation through top-level `await`; or
- dynamic import settlement through an asynchronous dependency graph.

These properties belong to a linked graph of module records. Reproducing them
incrementally in CommonJS wrappers would build a second, incomplete module
linker under a different name.

The current path also does not *refuse* dependency-level top-level `await` —
it mishandles it. A body that trips the await-syntax detection is wrapped in a
fire-and-forget async IIFE (`wrapAsyncModule`), the module is immediately
marked loaded, and importers receive whatever exports exist at the first
suspension; the pre-`await` prefix can deliberately execute twice `[observed]`
(`src/engine/bootstrap/module-loader.js`, `wrapAsyncModule` and its invocation
sites; ENG-22811). LLP 0024's entry-only rule and stable refusal error are
specified but not yet implemented. This defect is specifically the bootstrap
file-at-a-time dependency path: entry top-level `await` already has separate
awaited CLI machinery — for detected entries, on the non-Windows path, with
the engine-side bounded thenable pump (`src/engine/hermes_runtime.cc`,
`ex_hermes_eval`'s settle budget) doing the waiting; the text detector misses
block-nested and template-embedded `await` — and prepared Rolldown entries
can retry as ESM.
Migration therefore *tightens* observable behavior for any package
accidentally relying on fire-and-forget semantics; Phase 0 pins the current
behavior as a named divergence — with separate baselines for scanner-lowered
ESM, SWC-lowered TS/JSX, prepared entries, and the entry-TLA shim (including
its missed-detection, wait-timeout, and Windows no-unwrap cases) — so the
switch's delta is deliberate rather than discovered.

### The existing LLP corpus already points here

LLP 0007 makes Vite/Rolldown/Oxc the desired transform family and explicitly
routes a required ModuleRunner redesign into a separate document. LLP 0009
keeps SWC because it is the current reliable in-process implementation of the
synchronous CommonJS transform contract, not because CommonJS lowering is the
desired final ESM architecture. LLP 0024 states that dependency-level top-level
`await` needs an asynchronous graph and treats that graph as a separate design.

LLP 0023 also makes a graph redesign security-relevant: module identity is
derived from the authenticated `SourceId` — which itself carries the defining
principal — not from a specifier string or cache pathname. Any graph or bundle that loses that
identity would regress both correctness and CapSec attribution.

## Goals

- Execute standards-shaped ESM semantics on Hermes without requiring native
  Hermes ESM support.
- Use one AST-based transform family for TypeScript, JSX, module metadata, and
  Hermes compatibility rather than extending runtime string scanners.
- Support dependency-level top-level `await` and promise-returning dynamic
  import through an honest asynchronous graph.
- Preserve CommonJS, including synchronous `require()`, early cache publication,
  and CommonJS cycles.
- Preserve Ibex's hermetic runtime: direct TypeScript execution must not require
  Bun, Node, or a checkout with `node_modules`.
- Preserve LLP 0013/0014/0021 capability enforcement at every static, dynamic,
  and CommonJS edge.
- Preserve LLP 0023 source identity across raw source, transformed cache
  artifacts, bundles, and bytecode.
- Make development/source execution and production/prepared execution consume
  the same logical module-artifact contract.
- Retire SWC and the bootstrap ESM string transformer after measured migration
  gates pass.

## Non-goals

- Replacing Hermes.
- Embedding a full Vite development server in Ibex.
- Supporting arbitrary Vite plugins inside the runtime.
- Type checking application source.
- Removing CommonJS or Node-compatible `require()`.
- Changing filesystem namespace, source identity, or capability policy defined
  by LLPs 0013, 0014, 0021, and 0023 — with four flagged exceptions, each an
  explicit amendment in the adoption set and never adopted silently: the
  development-generation extension of module-instance identity (§8), the
  initialization task boundary in LLP 0021's intersection rule (§4), the
  trusted-loader source-acquisition classification in LLP 0021's generated
  registry (§4), and the initialization-triggering exception to LLP 0014's
  import-grant rule (§4).
- Defining REPL/session lexical persistence; LLPs 0022 and 0024 own that. Their
  module-loading portions may consume this graph once it exists.
- Requiring production applications to parse their complete dependency graph
  at startup.

## Terminology

- **SourceId** — LLP 0023's authenticated source identity. It is not a display
  path and cannot be supplied by package code.
- **SourceLabel** — a diagnostic label associated with a source; never a cache
  or authorization key.
- **ModuleKey** — `(runtime identity, SourceId)`, following LLP 0023: this is
  *module* identity, while `SourceId` alone is *source* identity. Runtime
  identity here is LLP 0023's opaque runtime/session handle (the
  pointer-plus-nonce class the engine already uses to defeat ABA reuse), not
  LLP 0012's product identity. Exactly: the graph is runtime-owned, so the
  outer key component is implicit in ownership; where it must be serialized
  it is the `(runtime pointer, runtime nonce)` pair the engine already
  validates, and Phase 1 defines its equality, construction/destruction, and
  relationship to the host-context id, LLP 0023's session handle, and the
  armed snapshot's run nonce, with two-runtime and destroy/recreate collision
  fixtures. The defining principal is carried inside the
  authenticated `SourceId` per LLP 0023 and appears nowhere else as an input.
- **Execution graph generation** — a monotonic counter over coherent
  development graph states (§8). A record instance under one generation is a
  **module incarnation**, keyed `(ModuleKey, execution generation)`;
  production has exactly one generation.
- **Authority snapshot** — the armed CapSec snapshot the runtime was created
  under (LLP 0021). Execution generations never mutate it: package principals,
  integrity-bound bytes, import axes, bindings, and policy edges change only
  by arming a new runtime (LLP 0022's regenerate-and-restart rule). HMR is an
  execution-record concept, not an authority concept.
- **ModuleArtifact** — a transform result containing executable module factory
  code or bytecode plus the metadata required to link, secure, cache, and
  diagnose it.
- **ModuleRecord** — the runtime state for one logical ESM or CommonJS module,
  including namespace/exports identity, lifecycle, dependencies, evaluation
  result, and owning principal.
- **Static edge** — an `import` or re-export discovered from the parsed module
  before evaluation.
- **Dynamic edge** — an `import()` or computed `require()` resolved and
  authorized when execution reaches it.
- **Synchronous ESM graph** — an ESM graph whose statically reachable ESM
  closure contains no top-level `await`. CommonJS bodies reached from it are
  synchronous by construction; edges they compute at call time are governed by
  §7's call-time rule, not by this static proof.

## Design principles

### Parse once; never infer grammar with runtime regular expressions

Every source module entering the new path is parsed by the selected AST
authority before Hermes evaluation. The source goal (Script versus Module) is
an input to the authoritative parse, selected by the typed resolution contract
of §1. For extension- and manifest-ambiguous `.js`, matching the pinned Node
oracle requires Node's unambiguous-module-syntax detection, which is itself a
*detection parse* of the source as a module — so "parse once" means one
**authoritative** parse: a goal-detection parse may precede it for ambiguous
input, is never authoritative for semantics, and its verdict is cached in the
artifact so no source is re-classified on a warm path — the verdict sits
among the digest-covered fields keyed by source integrity, so an edited file
naturally re-classifies. What never happens is grammar inference by runtime
regular expressions. Runtime string scans may remain temporarily as migration
guards, but they are not authoritative and receive no new language semantics.

### Separate transformation from linking

Oxc/Rolldown lowers syntax and emits module metadata. The module runner owns
identity, resolution, linking, evaluation, caching, and interop. A transform is
not allowed to erase graph facts by eagerly replacing imports with untracked
`require()` calls.

### Authenticate before discovery and execute under derived identity

The graph never trusts a principal, package name, `SourceId`, resolved path, or
integrity claim emitted by JavaScript. The host derives and verifies those
facts through LLP 0014/0023 resolution. A module factory executes only inside
the compartment bound to its authenticated defining principal.

### One logical artifact contract, multiple physical carriers

Raw-source transforms, disk cache entries, Rolldown chunks, and Hermes bytecode
may encode artifacts differently, but they represent the same logical
`ModuleArtifact`. A physical chunk is a carrier, not module identity.

### Fail closed when synchronous and asynchronous worlds meet

The runner never blocks a runtime thread waiting for asynchronous ESM. A
`require()` of an asynchronous ESM graph fails deterministically. An `import`
of CommonJS may execute CommonJS synchronously as part of an asynchronous ESM
evaluation, but CommonJS does not acquire implicit suspension semantics.

## Proposed architecture

### 1. Source admission and resolution

The existing resolver remains the authority for specifier resolution,
conditions, extension aliases, builtins, authenticated package roots, and
import policy. The new graph calls it through typed operations rather than
letting transformed JavaScript reconstruct resolution.

For every static edge, linking performs this order:

1. authorize the requested edge without probing unauthorized state;
2. resolve to an authenticated target and defining principal;
3. verify the target `SourceId`, package root, locator, and integrity;
4. obtain or create the target module record; and
5. only then read or retrieve executable source/artifact bytes.

The exact staged authorization and no-probe rules remain those of LLPs 0014,
0021, and 0023. This RFC must not create a convenient graph-prefetch bypass.

The shipped resolver is body-read-free today: module-type detection is
disabled, so the resolve-time ESM classification read is a *latent* branch,
one configuration flip from live `[observed]` (`src/module_loader/mod.rs`,
`ResolveOptions` default and the ENG-22950 dormancy note). LLP 0023's
`OBL-RESOLVE-GATE` ledger row describes that branch as live and must be
re-audited to say "latent"; LLP 0002/0004's body-read-free documentation is
currently accurate. Phase 1 makes the property hold *by construction*:
classification is split from body loading, the typed resolver is
body-read-free until the exact target edge, binding owner, locator,
integrity, and `SourceId` are authenticated, and denial/non-disclosure
fixtures use ordinary `.js`/`.mjs` targets (a `.ts` fixture is classified by
extension without a read and proves nothing).

The current resolver is also intentionally CommonJS-shaped: one merged
condition set contains both `require` and `import`, private package imports
prioritize `require`, and unclassified modules default to CommonJS
`[observed]`. The runner replaces that with a typed resolution contract.
Every request carries a **ResolutionKind** — ESM static import/re-export,
dynamic `import()`, CommonJS `require()`, or entry — which selects the ordered
condition membership set, participates in the resolution cache key so modes
can never alias, and drives source-goal classification: package `type` when
present, extension when unambiguous, and for ambiguous `.js` the pinned Node
oracle's unambiguous-module-syntax detection (a cached detection parse; see
Design principles). Conditions are **membership tests, not a precedence
order**: the pinned Node algorithm selects conditional-exports branches in
package-object key order, and `default` is unconditional — an invented
precedence over `{ "default": ..., "import": ... }` would change which code
executes and under which defining principal. Import-class requests carry the
membership `{node, import}`, require-class requests `{node, require}`;
user-configured conditions and the `module-sync` and `node-addons`
dispositions follow the pinned release, and cache identity is canonical over
the membership set. Resolution kind selects condition membership; the
evaluation-request *role* of LLP 0024 identifies entry versus dependency on
the request — the two are
related but never the same field. TLA admission follows one normative matrix
(§6): runner-executed ESM admits top-level `await` in both entry and
dependency roles; LLP 0024's script-with-extensions session surfaces keep
that document's entry-only rule until they migrate; and unmigrated
synchronous consumers keep the dependency refusal. LLP 0024 is revised at
the migration point, not silently. Two shipped resolver extensions are named
now rather than discovered later: TypeScript `extension_alias` probing is
retained inside the typed contract (and in its cache key), while the
bare-specifier-as-relative retry heuristic's ambient existence probe does not
survive as written — any retained retry probes only within already-authorized
scope, behind the edge gate, or the extension is retired; Phase 0 records the
disposition.

Dynamic-import options and import attributes are part of the dynamic edge,
validated and authorized at call time, and included in link identity exactly
like static-edge attributes. Source identity and format admission are
separate: a JSON file has an ordinary file-backed `SourceId`, and JSON is its
`source_kind`. ESM import of JSON requires the attribute exactly where the
pinned oracle does; CommonJS `require()` of `.json` stays extension-based;
both routes share the one record for that `ModuleKey` (the ESM view is a
namespace adapter). A kind-mismatched request for the same `SourceId` fails
at resolution — so the record key needs no attribute component, and
conflicting attribute requests can never silently share an instance. The corpus includes
fixtures for `import`-versus-`require` conditional-exports divergence,
ambiguous-`.js` classification (TLA, `import.meta`, and CommonJS
wrapper-variable redeclarations as detection triggers), `module-sync`
exports, and attribute-mismatch refusal.

Exact edge authorization before probing needs authenticated graph-location
data the armed snapshot does not yet carry: LLP 0023's `OBL-GRAPH-LOCATION`
digest-bound `(importer, authored spelling/alias, exact imported principal)`
map, extended with `ResolutionKind` and relevant conditions/attributes.
Phase 1 co-implements that obligation; every artifact edge verifies against
the map before any ambient resolver operation, with ambiguous-name,
conditional-export, and `#`-alias non-disclosure fixtures.

Dynamic `import()` and computed `require()` repeat the applicable resolution
and policy checks at call time. A dead dynamic branch does not resolve, probe,
or fail.

### 2. ModuleArtifact

The transform boundary produces a logical artifact with at least:

```text
ModuleArtifact {
  source_id
  source_kind          // ESM, CommonJS, JSON, builtin, or synthetic
  dialect              // JS, JSX, TS, TSX
  source_integrity
  transform_fingerprint
  static_edges[]       // authored specifier + import/re-export shape
  export_descriptors[]
  has_top_level_await
  factory_source | carrier_entry_ref   // payload binding; the semantic
                                       // digest covers the factory bytes
  source_map
}
```

`static_edges[]` and `export_descriptors[]` are typed variants, not free-form
strings: imports are named, default, namespace, or side-effect; re-exports are
named or star; exports are local, indirect, or star — each carrying the
authored specifier where one exists. Entry-versus-dependency role is not an
artifact field at all: it lives on the evaluation request, as LLP 0024's
evaluation model already places it, so it cannot fragment content-addressed
artifacts; LLP 0024's transform-emitted dependency manifest, which still
records role per source, is amended to match when its consumer migrates.

The artifact's serialized form is a versioned canonical wire schema with two
digest domains. The **semantic digest** is carrier-independent and covers
every semantic field: `source_id`, `source_kind`, `dialect`,
`has_top_level_await`, `source_integrity`, the typed edges and export
descriptors (for CommonJS, the detector-derived export names and detector
version), the exact factory *bytes*, `transform_fingerprint`, and the source
map — so an inline factory and the same factory inside a carrier are **one
logical artifact with one semantic digest**, and cache equivalence, manifest
identity, and "same artifact" claims all key on it. The **payload binding**
is separately authenticated per physical form: inline bytes verify against
the semantic digest directly; a carrier entry verifies the carrier digest
plus its entry's mapping back to the semantic digest. A field is either
digest-covered or explicitly derived and recomputed from covered data; there
is no third semantic category, because an unbound `has_top_level_await` would
invalidate the synchronous-`require` proof and an unbound `source_id` would
misattribute code. The corpus includes malformed-field, field-substitution,
cross-machine-label, and TLA-bit tampering fixtures. Only two producers are
trusted: the in-process transform running under host authority, and a
build-time Rolldown/Oxc producer whose output digests are bound into the
authenticated deployment graph. Native code accepts prepared metadata only
through that digest binding; nothing is trusted for having a plausible shape.

Portable artifact identity is honest about its collision domain. Today's
armed root identity is a literal constant, so project-arm `SourceId`s are
scoped to one project/session until LLP 0023's stable, authenticated,
host-independent project-identity derivation lands; cross-project portable
cache reuse is prohibited until then, and the corpus includes two distinct
authenticated project roots containing identical relative paths and bytes.
Phase 1's `OBL-SOURCE-ID` landing must supply the canonical encoding *and* a
total authenticated `SourceId → defining principal` derivation across the
package, project, builtin, synthetic, and generated arms — builtins today
receive the runtime principal through a separate channel, which folds into
that derivation — plus the project-root identity constructor and its
collision domain, fixture-tested.

A logical artifact and its physical carrier are distinct types. A
multi-module carrier — a chunk or an HBC file — has its own authenticated
digest and a manifest of per-module entry references; a contained module's
artifact references the carrier digest plus its entry, and the carrier is
never "the bytecode of" any single module.

The serialized artifact may include resolution results for an authenticated,
immutable deployment graph, but those results are host-produced and
digest-bound. A transform process cannot assert its own principal or widen an
import edge.

`transform_fingerprint` includes the parser/transform engine and version,
Hermes target, JSX/TypeScript options, module-runner ABI version,
Hermes-compat-pass version, and every option that changes output or metadata.
The module-runner ABI version is the internal factory-contract version; it is
distinct from LLP 0002's public embedding ABI version.

The defining principal is not a separate artifact field at all: it lives
exactly once, inside `SourceId`, per LLP 0023, and consumers that need it
decode it from there. An earlier revision carried a denormalized copy as a
verification field; it was removed because a field that must always
byte-agree with another is a standing invitation to disagree — the exact
redundancy LLP 0023 §2.3 already removed once.

`SourceLabel` does not appear in the portable artifact at all — an earlier
revision listed it as a field, which created exactly the "neither
digest-covered nor derived" third category the rule above forbids. Labels are
machine-local under LLP 0023: the portable core is fully digest-covered, and a
separate **local diagnostic envelope**, derived from the consuming runtime's
own authenticated source records, carries display labels. Source maps refer
to sources by stable `SourceId` index plus a local remapping table, never by
embedded machine-local spellings. The corpus includes same-digest/
different-label rejection and cross-machine round-trip fixtures.

Runtime import attributes and build-time authority annotations are distinct
types. LLP 0014's canonical typed `authorities` attribute is consumed into
generated policy and stripped before artifact emission; legacy
colon-delimited spellings fail generation, per LLP 0014 — they are never
consumed. The canonical attribute's effect exists only in the digest-bound
armed policy. Artifact validation rejects any
reserved policy key appearing in `static_edges`, so a prepared artifact can
never smuggle an authority annotation into the runtime graph.

The record algebra is total over the loader's existing module kinds. JSON
modules (never compiled as code; ordinary file-backed `SourceId`s), builtins
(whose admission rules and terminal denials stay with the host), and
synthetic modules (which have their own LLP 0023 `SourceId` arms) receive
records with their own namespace and cache rules;
import attributes (`with { type: "json" }`) are part of the static-edge shape.
A kind that stays outside the runner (builtins today) does so behind a typed
boundary, not by falling into an undefined default.

### 3. Transform authority

The desired in-process authority is Oxc, with Rolldown used when graph-level
bundling or chunking is beneficial. The expected default implementation is an
Ibex-authored code-generation layer over Oxc's AST: neither Oxc nor Rolldown
emits the factory shape of §4 today, so the realistic v1 producer is our own
lowering — a hand-built transform whose correctness burden is exactly why the
adoption gate's spike, the checked-in canonical artifacts, and the oracle
corpus exist. The lowering builds on the Oxc parser/semantic/codegen stack
already in-process; the uncertain work is factory lowering, linking
metadata, Hermes compatibility, source maps, and performance — not basic Oxc
integration. An Oxc ModuleRunner-style transform or a Rolldown runtime API
may replace it if one materializes; the emitted `ModuleArtifact` contract is
the stable boundary, not a particular unstable crate API.

The transform must:

- strip TypeScript-only syntax while preserving runtime TypeScript constructs
  that Ibex intentionally supports;
- compile JSX/TSX under an explicit runtime configuration;
- identify all static imports, re-exports, export stars, and exported bindings;
- identify top-level `await` from the AST rather than text;
- preserve ESM declaration instantiation and hoisting semantics;
- emit updates for live exported bindings rather than snapshots;
- rewrite `import.meta` and dynamic import through typed runner capabilities;
- apply Hermes compatibility through a hermetic in-process implementation of
  the LLP 0019 pass corpus (below); and
- emit a source map for every source-changing stage.

**The Hermes-compat seam is a revision of LLP 0019, planned as work.** The
LLP 0019 AST authority is today a build-time Node/Bun script, and 0019
deliberately pins the rewrite to exactly two implementation tiers. The
runner's in-process path cannot run that script, so this RFC requires a third
implementation: the same passes expressed over Oxc's AST inside the hermetic
Rust pipeline. That is an amendment to LLP 0019's two-tier decision, not a
silent exception — Phase 1 includes revising LLP 0019 to name the Oxc tier,
adding the new tier as a system-under-test of 0019's existing real-Hermes
behavior corpus, and composing its source maps like every other stage. The
amendment defines the authority relationship, not merely a tier list: during
migration the existing build-time implementation remains canonical and the
Rust/Oxc tier is its zero-divergence mirror, gated by the corpus with
source-map parity; at Phase 5 the roles flip — the Rust tier becomes
canonical, the scanner tier retires, and any accepted divergences are named
in LLP 0019 itself.
Applying bootstrap-scanner Hermes workarounds to runner-emitted factory source
is prohibited; it would shift locations without a composed map.

Feasibility on the pinned toolchain is a Phase 1 exit criterion, not an
assumption: LLP 0009 records that current Rolldown/Oxc releases require a
newer Rust than the repo pins, so Phase 1 either proves the selected
integration on the pinned toolchain or records an explicit toolchain-upgrade
decision.

SWC remains a compatibility engine during migration and is not extended into
the module linker. Its removal has three independent gates: the
module-transform role falls away when the Oxc/Rolldown path passes the gates
in this RFC and LLP 0007; LLP 0024 separately pins the session TypeScript
dialect to `swc_ecma_parser` and admits Oxc only when parse-equivalent over
0024's corpus; and LLP 0024 also builds its session *lowering* stage
(script-goal preservation, session/TLA lowering, hygiene, composed maps) on
SWC — a migration owned by LLP 0024 and not implied by module-runner
adoption. SWC crates leave the tree only when all three gates pass (or
0024's contracts are revised); until then a bounded SWC dependency serving
LLP 0024's session contract is an explicit, recorded state, not an
oversight.

### 4. Native graph owner and Hermes runner

Rust owns authenticated graph state: `ModuleKey`, resolution results,
principal/compartment binding, artifact integrity, lifecycle, cache admission,
and asynchronous dependency scheduling. Package JavaScript cannot mutate or
forge that state.

The embedded Hermes runner owns JavaScript objects that must have JavaScript
identity: namespace objects, CommonJS `module.exports`, export cells/getters,
and callable module factories. It receives opaque native record handles rather
than caller-selected identities.

Factory attribution is bound at **compile/load time**, not merely at
invocation: a native-only compile-or-load-factory operation verifies the
complete artifact and its carrier, stamps the authenticated principal and
compartment before the engine compiles or loads the code — extending the
ordering today's loader already partially follows: the pending principal is
set before `new Function`, while the compartment is bound just after; the
new operation makes both pre-compilation — and returns an opaque callable
handle. That operation is
unreachable from package JavaScript. Attribution fixtures cover cold source,
warm cached source, prepared source, per-module HBC, and multi-module
per-principal HBC carriers. Every graph operation
carries the full evaluation context LLP 0021 demands — requesting record,
effect owner, schedule-time identity, and the complete deduplicated
constrained-principal set, not a single "current package" — plus the graph
generation it belongs to. That context is a typed native structure
(`GraphEvaluationContext`), and one native authorization operation consumes it
for every edge kind: static import, re-export, dynamic import, literal and
computed `require()`, JSON modules, and prepared-chunk loading. Phase 1
specifies the normative construction of a complete semantic-core
`DecisionSet` for every graph operation: the `DecisionContext` (stage, actor,
canonical constrained-principal set, presented handle IDs), the emitted
`Effect`s with an effect owner *per effect*, normalized resources, operation
id, atomicity group, and the target-cell/coverage-edge mapping — with
missing-owner, wrong-owner, and multi-effect fail-closed fixtures. The
edge gate
itself is keyed by the authenticated requesting record's import policy, and
the edge decision is computed against the requester's complete constrained
context per LLP 0021, so a deputy cannot launder an edge through a
more-privileged scheduling context; the post-authorization source read is a
trusted-loader effect (below). The corpus includes fixtures
where the requesting module, the live frame, and the schedule-time owner are
three different principals. Promise continuations, dynamic imports, timers
scheduled during evaluation, and asynchronous failures retain that context
under LLP 0021/0024 rules. Internal record promises are kept permanently
handled, and each `import()` call receives a fresh public promise, so an
internal rejection cannot become both a foreground outcome and an
`unhandledrejection`.

**Initialization authority is a three-part rule.** *Edge authorization* is
per-importer, keyed by the authenticated requesting record's import policy.
*Source acquisition* is a trusted-loader operation performed only after exact
edge authorization — exactly the shipped model, where module source reads run
under the loader's own principal past the import gate — and is never charged
to the importer's filesystem authority; importers do not need, and must not
hold, raw read authority over their dependencies' files. That choice resolves
a real corpus conflict: LLP 0013's trusted `module-loader` principal and the
shipped capability code say trusted-loader, while LLP 0021's *generated
coverage edges* classify on-disk loading as `fs:list`/`fs:read` with
principal and effect owner sourced from the loader referrer. The adoption set
amends LLP 0021 and regenerates those registry rows to the trusted-loader
model, defined narrowly: a non-delegable operation, bound to an
already-authorized exact edge and its authenticated `SourceId`, binding,
locator, and integrity — never general loader filesystem authority. Denial,
no-probe, cache-hit, prepared-carrier, and wrong-principal fixtures pin it.

*Factory evaluation* is **autonomous record-owned execution**, uniformly for
synchronous and asynchronous initialization: the body runs in the defining
principal's compartment under an initialization task boundary, and the
deputy-constraint intersection for initialization-time effects is computed
from that boundary down — importer frames above it do not join the
constrained set, even when a synchronous `require()` leaves them physically
on the stack. This is a deliberate, named amendment to LLP 0021's
intersection rule (part of the adoption set), justified by determinism: the
one-instance invariant means a module initializes once for all importers, so
an intersection reaching through the importer chain would make module state
depend on which importer arrived first, and a module could shed or acquire
constraints merely by inserting `await 0`. Autonomy does not widen
authority — the module's own grants and compartment still bound it, code
attribution still derives from engine frame truth, and a low-authority
importer cannot *reach* a module its import policy forbids. LLP 0021's
intersection applies unchanged to everything after initialization: calls
into an already-initialized module's exports intersect the full live chain.
The corpus includes cold/warm, sync/async, `await 0`-insertion, and
concurrent-distinct-importer fixtures showing initialization authority is
invariant across all of them.

Triggering initialization is itself an explicit authority: the import-edge
grant includes it. Importing a module *is* causing it to initialize — the
ecosystem's universal semantics — so permission to hold the edge, reviewed at
policy-generation time under LLP 0014, is permission to trigger the target's
once-per-generation initialization at the target's own authority. LLP 0014's
rule that an import grant is not a host-capability grant is amended to name
this one bounded exception explicitly. The adversarial residue is accepted
with open eyes: an importer allowed the edge can choose *when* cold
initialization runs, but the same effects run on whichever import arrives
first and the module's own grants bound them — and the alternative is worse,
because under full-chain intersection plus sticky ESM failures, a
low-authority importer could deliberately first-import a powerful module,
have its initialization denied, and poison the record into `errored` for
every legitimate importer. The corpus adds a red-team fixture in which a
minimal-authority importer triggers initialization of an effectful
privileged module, alongside the sticky-error poisoning scenario the
amendment forecloses.

ENG-25062 realizes the synchronous half of this contract in
`module_loader::security`: every reachable static import, re-export, and JSON
edge must produce a typed graph decision and immutable-snapshot receipt before
the native graph compiles a factory. The same closed operation algebra reserves
dynamic import, literal/computed `require`, cache, prepared-carrier, and factory
operations for their owning phases. Receipt checks bind the exact target,
coverage edge, snapshot digest, authority generations, and graph generation;
chunk co-residence and cache presence therefore confer no authorization. The
unauthenticated linker remains test-only, and target cells stay unsupported
until their executed fixture evidence exists.

**Binding cells live in the Hermes runner, behind opaque native handles.**
JavaScript-side cells keep every binding read and setter dispatch inside the
engine (no native call per read); the native record holds nonce-validated
opaque handles to them. Ownership is one-directional — native records own
JavaScript handles; JavaScript never strongly owns a record — and any
operation on a handle whose runtime nonce or generation no longer matches
fails closed. Generation teardown releases the native handles, letting the
engine reclaim cells, namespaces, and factories; teardown fixtures assert
reclamation and stale-handle refusal.

Carrying `GraphEvaluationContext` across asynchronous hops needs a real
carrier: the current Hermes scheduling patch stores a single scheduler
principal per promise job and loses the originating chain after one hop —
host timer and callback queues already carry fuller principal vectors, so the
gap is specifically Hermes promise jobs. Phase 3 therefore requires an opaque
native context token — validated by runtime nonce and generation, with
defined nesting, capture/restore, teardown, and transport through Hermes jobs
and host queues — before dependency-level TLA ships.

When sessions adopt the graph under LLP 0025's supervisor/worker topology,
graph records, native authority state, and Hermes-owned handles are
worker-local; only authenticated, non-authority-bearing outcomes and control
records cross the process boundary, per LLPs 0023/0024/0025.

The factory contract (module-runner ABI v1) is versioned and
`System.register`-shaped, with exports published through a host-selected
callback rather than a global registry. A factory has two phases: **declare**,
which runs before any body code, instantiates hoisted function declarations,
registers export bindings, and receives one setter per dependency; and
**execute**, which runs the module body and returns `undefined` for a
synchronous module or a promise for a module containing top-level `await`.
Execute runs under Module-goal strict semantics — top-level `this` is
`undefined`, undeclared assignment throws, `arguments` and wrapper-parameter
names are not in scope, and directives are handled per the goal — a
normative break from today's non-strict `new Function` wrapper, pinned by
the canonical factories and their source-map fixtures.
Live bindings are evaluator-owned checked cells: a cell created at linking
holds an uninitialized sentinel, reading the sentinel throws the
temporal-dead-zone error, only the declaring module's own phases may
initialize or update its cells, and importer setters fire on every update —
Hermes provides no TDZ machinery for this, so the cells are part of the ABI,
not an engine feature. Import reads of lexical bindings lower to checked
reads everywhere in v1: in a content-addressed, graph-independent artifact,
whether an imported binding is initialized can depend on the eventual cycle
and evaluation order, so no per-artifact static proof can soundly elide the
check, and any later elision mechanism requires a reviewable per-site proof.
The checked-in canonical factories are the normative statement of the
lowering, and the steady-state performance gate measures the checked-read
cost. Namespace objects are built at linking from the export
descriptors: star re-exports resolve per the ECMAScript ambiguity rules
(local exports win; names exported ambiguously by multiple stars are
excluded), and indirect exports are views onto the source module's cells.
Async strongly connected components share settlement state per the spec's
async-parent rules. That `System.register` shape has a decade of ecosystem
proof that these semantics are expressible on engines without native ESM, and
Agoric's SES `StaticModuleRecord`/`Compartment` system is the closest
security-reviewed prior art for host-mediated linking under a capability
model; its ambient-authority cases seed the security corpus.
Phase 1 checks in canonical serialized `ModuleArtifact`s and their generated
factories for live mutation, TDZ, direct and indirect cycles, star ambiguity,
`import.meta`, and top-level `await`, so the ABI is reviewed as artifacts
rather than prose.

This split keeps policy and identity native while avoiding a native reimplementation
of JavaScript object semantics.

### 5. ESM record lifecycle

An ESM record moves monotonically through:

```text
new → loading → parsed → linking → linked → evaluating → evaluated
                                              ↘ errored
```

Re-entrant requests return the existing record. `linking` is visible to the
linker so cycles reuse namespace and binding cells rather than recursively
creating duplicate records. `evaluating` carries one evaluation promise shared
by every importer.

Linking performs declaration instantiation for the complete reachable static
graph before evaluating module bodies. Namespace objects and export cells are
created during linking. Access to an uninitialized lexical export observes the
proper temporal-dead-zone failure; imports are views onto cells, not copied
property values.

Evaluation follows ECMAScript module ordering, including strongly connected
components and async-parent propagation. The implementation need not expose
spec-internal names, but its observable results must match the adopted
Node/V8 oracle corpus.

A record that errors retains the same error outcome for subsequent imports
within its generation, matching the pinned oracle's sticky ESM failures; it
is not partially re-run against previously mutated namespace state. CommonJS
and JSON records keep their current delete-on-throw eviction, matching the
shipped loader. **Only immutable artifacts are ever shared across
generations** — live records, cells, namespaces, promises, and error objects
belong to exactly one generation and die with its teardown — so what a new
generation reuses is transform and parse work (same semantic digest), never
live module state. Until generations exist, the runner supports exactly one
generation, and session modes keep LLP 0024 §7.9's delete-on-failure behavior
unchanged: the failed record is evicted and completed dependency records
stand, exactly as today. When sessions adopt the runner's generations, retry
becomes generation advance, and LLP 0024's wording is reconciled then (see
Acceptance criteria).

### 6. Top-level await and dynamic import

Top-level `await` is permitted in ESM entries and dependencies. An evaluating
record with top-level `await` publishes a promise; importers wait through the
graph rather than blocking a native thread. Rejection propagates through the
same evaluation promise and is attributed to the owning/scheduling principal.

`import(specifier)` always returns a promise. When invoked it:

1. captures the authenticated requesting record;
2. applies import policy and resolution;
3. loads and links the target graph as needed;
4. evaluates it; and
5. resolves to the stable namespace object.

The initial native ABI realizes that contract with one retained, immediately
handled internal evaluation promise per record and a fresh derived public
promise for every invocation. Literal dynamic edges are semantic artifact
fields. Computed sites carry stable producer-order ids and may select only from
the exact authenticated candidate map supplied with the graph; a spelling not
in that map becomes a rejected promise without a resolution or filesystem
probe. Dependency closures are collapsed into deterministic SCC metadata,
async taint propagates to importers, and Rust advances the native graph only by
non-blocking polls between host event-loop drives. Both fulfillment handlers
and the internal rejection handler are attached before execution returns to
the host; public rejection remains observable without manufacturing a second
unhandled rejection from the runner's bookkeeping chain.

Event-loop keepalive, cancellation, work-unit identity, and exactly-once
rejection reporting for suspended graphs are LLP 0024/0025 contracts, and
Phase 3 treats them as prerequisites: the runner does not invent a second
structured-evaluation semantics. The embedding ABI's synchronous entry points
(LLP 0002) are unchanged; asynchronous graphs complete through the host-pumped
event loop (LLP 0003). Until LLP 0024's typed ABI lands, the asynchronous
runner is a private internal API — consumed by the CLI entry shim and, later,
sessions — and no public LLP 0002 surface changes; embedders get asynchronous
graphs only through LLP 0024's structured-evaluation contract, never through
thenable assimilation or a hidden pump-with-timeout.

v1 defines **no import-waiter cancellation primitive**. Cancellation is
exactly what LLPs 0024/0025 already define — target-id-exact cancellation of
the currently executing work unit, plus session teardown; a suspended unit
receives no cancellation delivery because no mechanism for one exists. An
`import()` promise settles with its record's evaluation or is abandoned when
its runtime/session generation is torn down. Module evaluation is never
partially cancelled into a corrupt record: a record either reaches
`evaluated`/`errored`, or its whole generation is discarded under LLP 0025's
teardown rules. If a per-waiter primitive is ever wanted, it is a new
LLP 0024/0025 contract — ownership, waiter identity, races, teardown — not a
runner extension.

A synchronous `require()` that reaches a record currently `loading`,
`linking`, or `evaluating` under an in-flight asynchronous operation fails
deterministically with the stable cycle/async error family; it never blocks a
thread and never re-enters evaluation. The same rule covers *overlap*, not
only direct re-entry: the synchronous drive runs on the JavaScript thread —
the thread that pumps the event loop — so in-flight asynchronous records are
quiescent between jobs, and overlap detection is a state check, not a lock
race. Before creating or linking any new record, the drive computes the
statically reachable closure and its async-taint proof; if any record in that
closure is owned by an in-flight asynchronous operation (directly,
transitively, or through a cycle), the `require()` fails with the same stable
error family before any new record is created or linked, and records staged
solely for the refused drive are discarded — no partial state survives
refusal. That quiescence argument is load-bearing on LLP 0003's
one-JS-thread-per-runtime invariant; an embedder pumping one runtime from
multiple threads would invalidate it, and the runner asserts the invariant
rather than tolerating its violation. That assertion becomes contract: the
adoption set amends LLPs 0002/0003 to make every runtime-driving entry point
(`eval`, `poll`, and the runner ingresses) owner-thread-only and serialized,
enforced with a stable refusal — today only destruction checks the owning
thread — with concurrent and off-owner-call fixtures. The corpus includes direct, transitive,
cyclic, and disjoint-overlap interleaving fixtures.

Synchronous *cycles* are defined by the same state machine. Within one
synchronous drive, a `require()` that reaches a record already `linking` or
`evaluating` in that same drive fails with the pinned oracle's stable cycle
error (`ERR_REQUIRE_CYCLE_MODULE`-class); an ESM `import` edge reaching a
CommonJS record mid-cycle sees the partial exports that early publication
defines, exactly as CommonJS behaves today; and Ibex's `require`-inside-ESM
extension follows the same `require()` rules. The corpus pins ESM→CJS→ESM,
CJS→ESM→CJS, self re-entry, and cycles containing top-level `await` as
oracle-or-named-divergence fixtures.

The new path replaces the current dependency-level TLA handling — today's
fire-and-forget lowering (see Motivation) and LLP 0024's specified-but-unbuilt
entry-only refusal — with honest graph suspension. LLP 0024's entry-only rule
remains correct for the old synchronous path and for any session mode that has
not migrated; that document must be revised when its consumers adopt this
runner.

### 7. CommonJS interop

CommonJS retains its familiar lifecycle:

- create and cache the `module` record before body evaluation;
- expose the mutable `module.exports` object during cycles;
- execute the body synchronously; and
- preserve the final `module.exports` identity or replacement.

Interop rules are explicit and corpus-tested:

- ESM `import` of CommonJS evaluates the CommonJS record synchronously and
  receives a namespace adapter whose `default` is `module.exports`, whose
  detected names are static snapshots, and which — per the pinned Node 24
  target — also always contains a named `'module.exports'` entry referring to
  that same value.
- Named CommonJS exports follow Node's static detection rule (the
  `cjs-module-lexer` contract) as shipped in the pinned compatibility target:
  detected names become namespace properties, `default` is `module.exports`,
  and later mutations of `module.exports` are not re-snapshotted. The oracle
  is LLP 0012's pinned Node target (`runtime-identity.json`, currently Node
  24.13.1); changing it is a revision of LLP 0012, not a loader option. The
  production bundler and runtime loader implement the same rule, and the
  detector's version is part of `transform_fingerprint`.
- CommonJS `require()` of CommonJS remains synchronous.
- CommonJS `require()` of ESM may synchronously drive the full
  load → link → evaluate pipeline for the target graph, including file I/O and
  transform, when the statically reachable ESM closure is proven free of
  top-level `await`. Its return value follows the pinned Node 24 selection
  rule: when the ESM graph explicitly exports a `'module.exports'` name,
  `require()` returns that value directly; otherwise it returns the namespace
  object, with `__esModule` conditionally present when the namespace has a
  default export. Any deliberate divergence from the pinned target's
  bidirectional interop table (namespace keys and descriptors,
  `'module.exports'`, `__esModule`, falsy defaults, `module.exports`
  replacement) is named under the expected-divergence mechanism. This
  behavior list is descriptive of the current pin; the corpus's pinned-oracle
  interop fixtures are authoritative, so a re-pin has one owner and stale
  prose is a corpus failure, not a silent divergence. The synchronous proof
  is memoized per `(record, generation)` as an async-tainted bit, so hot
  computed `require()` paths do not re-prove it; prepared manifests may carry
  the bit as a build-time fact the runtime verifies rather than computes.
- CommonJS `import()` of any ESM graph returns a promise and requires no
  synchronous proof; it is the supported route from CommonJS to asynchronous
  ESM.
- CommonJS `require()` of an ESM graph containing top-level `await` fails with
  one stable `ERR_REQUIRE_ASYNC_MODULE`-class error before evaluating any
  module of the newly selected target graph.
- The no-partial-execution guarantee is scoped to that target graph, because
  dynamic edges are discovered during execution. When already-running code —
  for example a CommonJS body reached from synchronous ESM — computes a
  `require()` whose target graph proves asynchronous, the requiring call
  fails, and the effects the caller performed before the call stand: they are
  the caller's effects, not the refused graph's. The conformance corpus
  includes this mixed re-entry fixture.

Ibex's existing `require` extension inside ESM is not removed by this RFC. It
uses the same rules and may be reconsidered by a later compatibility decision.

Mutable loader-state observables are not carried into the runner. Closure is
the *target* state, not today's: the shipped bootstrap exposes `require.cache`
and `require.main` through local requires, the global `require`,
`__exactRequire`, and `module.createRequire()`, and trusted bootstrap code
reads the cache directly — LLP 0022's `OBL-LOADER-CLOSED` is an open
obligation whose current-state prose must be corrected alongside this RFC.
Phase 2 lands the closure as deliberate migration work: reachability tests
across every require surface and runtime mode, and a private typed
invalidation operation replacing trusted cache mutation. Any facade ever
exposed afterward is principal-filtered, immutable, and keyed by virtual
spellings per LLP 0023. `import.meta` values and dynamic-import referrers are
derived from the authenticated record — `SourceLabel` for display, retained
identity for resolution — never from host path strings. `import.meta.resolve`
is supported and routed through the same typed edge gate as dynamic import,
resolution-only: no body read, no probing, non-disclosing denials, per
LLP 0023's resolve-gate rules. CommonJS `require.resolve` uses that same
resolution-only typed gate and the same denials. Today it bypasses the
JavaScript `checkImportGate` helper — though the armed native metadata bridge
it calls still preflights the authenticated requester and import policy — and
it does not yet flow through one unified typed edge path; that remaining
`OBL-RESOLVE-GATE` work (and the ledger row's wording, which overstates the
bypass) closes with Phase 2's loader-state work.

One inherited divergence is imported explicitly: LLP 0023 maps query/fragment
specifier variants to one file-backed `SourceId`, unlike Node ESM, so the
corpus carries that as a named expected divergence from the oracle.

Direct-file execution refuses generated reserved grant keys in v1 — the same
fail-closed rule LLP 0022 adopted for session inputs. The `OBL-FILE-GRANTS`
obligation (ledgered in LLP 0022, owned by LLP 0014) may later add a
pre-runtime authenticated
graph-analysis phase whose stripped-source artifact and resulting policy are
digest-bound into the armed snapshot before runtime creation; if that phase is
added, it precedes and is never performed by the on-demand evaluator, because
the armed snapshot is immutable once evaluation starts (LLP 0021).

### 8. Development, HMR, and invalidation

Source mode transforms modules on demand and stores `ModuleArtifact`s in a
content-addressed cache, starting from the existing hardened transpile-cache
machinery (tamper rejection, quota eviction, publication races) rather than
new machinery. The cache is an optimization only: every hit verifies the
artifact fingerprint, source integrity, `SourceId`, and authenticated graph
context before publication.

Development invalidation creates a new graph generation. It does not mutate an
evaluating record in place. Importers either remain on the old coherent
generation or relink to the new one through an explicit HMR transaction. Stale
dynamic-import completions cannot publish records into a newer generation.
The execution generation is part of the development record key —
`(runtime/session identity, SourceId, execution generation)` — and the
one-logical-instance invariant (security invariant 8) is scoped to a single
generation. This is a deliberate normative extension of LLP 0023 §2.3 and
LLP 0024's one-file-one-instance rule, which admit no generation dimension:
both documents are amended before Phase 4's HMR work lands (see Adoption gate
and Acceptance criteria), and until they are, the runner supports exactly one
generation. CommonJS records, namespace objects, error caching, and late
dynamic-import completions all obey the same algebra — a stale completion
belongs to its own generation and cannot publish into a newer one.

Generations never touch authority. The armed CapSec snapshot — package
principals, integrity-bound bytes, import axes, bindings, policy edges — is
immutable for the runtime's life (LLP 0021); widening a session's graph still
requires regenerate-and-restart (LLP 0022). An HMR transaction may only
replace module records whose sources re-verify against the *existing*
snapshot's integrity and policy; anything else requires arming a new runtime.
That rule has a deliberate asymmetry: root-owned first-party sources
re-verify and may hot-reload, while integrity-pinned package bytes cannot
change without re-arming — a package edit is a restart, and the corpus pins
the refusal.

This RFC does not prescribe Vite's complete HMR API, but Exact/Vite consumers
must be able to translate their module graph and invalidation events into this
record model without a second execution semantics.

### 9. Production artifacts and bytecode

Production builds should resolve and transform as much of the graph as
possible ahead of time with Rolldown/Oxc, then package module factories and
metadata into authenticated chunks. Hermes bytecode may replace factory source
when its engine identity and bytecode version are part of the artifact key.

A chunk containing multiple modules carries a provenance manifest mapping each
factory to its original `SourceId` (which carries the defining principal),
static edges, source map, and integrity. Chunking must not collapse package compartments or make the
chunk pathname the identity of every contained module.

Executable carriers are additionally constrained by Hermes attribution
granularity: one HBC file is one `RuntimeModule`, and LLP 0013's frame
attribution requires per-package module units or a function-range → principal
table the engine actually consults. v1 therefore emits executable chunks and
bytecode per authenticated principal (per-package), as production enforcement
already does. A multi-principal executable carrier is permitted only after a
native per-factory attribution mechanism (Domain- or function-range-based) is
prototyped and passes frame-attribution tests — static, dynamic, cyclic,
cached, async, and HMR — on every advertised engine build. A provenance
manifest alone never grants attribution. Production preparation must not
scope-hoist or otherwise optimize across logical module boundaries unless the
optimization carries a proof and corpus evidence that identity, attribution,
and evaluation order are preserved. Carrier admission is atomic: a
carrier that fails integrity or manifest verification is rejected before any
contained factory evaluates, and per LLP 0005 source fallback is allowed only
for a pre-execution bytecode load failure, never after program effects.

Dynamic boundaries may remain as separately authenticated chunks. Loading one
uses the same record/link/evaluate path as a source-created artifact.

The v1 wire realization is `ibex/module-carrier/1`
(`schemas/module-carrier-v1.schema.json`, `commit:c6d2aefe`). Its manifest binds
one defining principal, prepared producer binary, deployment graph, carrier
digest, encoding, and a strictly ordered table of entries. Each entry embeds
the complete original `ModuleSemanticsV1` and recomputed semantic digest. Rust
admits the manifest and carrier atomically, then the native runner accepts only
the pair of an admitted carrier entry and its matching admitted carrier-form
`ModuleArtifact`; source-table and matching-HBC fixtures execute to the same
namespace on real Hermes. Graph-location publication by the existing Rolldown
cache remains Phase 4 integration work rather than a competing format.

### 10. Diagnostics and source maps

Every transformation stage emits or composes a source map. Error attribution
uses `SourceLabel` for display and `SourceId` for identity. Wrapper preambles,
module-runner factories, Hermes compatibility passes, and bytecode compilation
must not silently shift locations.

The source-map registry is **sum-keyed**. Module entries key on the
artifact's semantic digest, `SourceId`, and the local
`SourceId`→`SourceLabel` envelope; record generation enters only where
lifecycle diagnostics need it, since identical immutable artifacts may be
reused across generations (§5's artifacts-only sharing rule). Session
*scripts* — prompt inputs, `.load` bodies, `ibex:eval` — have no `SourceId`
or artifact and keep LLP 0024's keying: session identity, submission ordinal
or source label, and source digest. Only imported modules migrate to
artifact identity. A late rejection surfacing from an old generation maps
with the map of the artifact that produced it, never a newer namesake.
LLP 0024's `SourceLabel`-keyed in-memory registry is reconciled to this sum
key when sessions adopt the runner, and error type/stack/cause preservation
follows LLP 0024's structured-outcome contract.

Errors distinguish at least resolution, authorization, parse, transform, link,
unsupported interop, evaluation, and asynchronous rejection. Every stable
runner error class joins LLP 0023's security-owned total order at a named
stage: authorization denial precedes and masks target existence, cache
state, async/SCC membership, TLA-ness, artifact validation,
parse/transform/link failure, and carrier failure — an unauthorized caller
learns none of those facts. The LLP 0023 reconciliation extends its graph
tier with these classes, and pairwise precedence fixtures prove the order. Nested module
context may annotate an error, but it must preserve the original error type,
stack, cause, and source position under LLP 0006's diagnostic principle.

## Security invariants

The module runner is part of the CapSec enforcement boundary. It must satisfy:

1. **No caller-selected principal.** Principal and compartment come from the
   authenticated target record.
2. **No unauthorized probe.** Graph discovery follows LLP 0023 staged
   authorization; prefetch does not read a forbidden module body.
3. **Exact edge authorization.** Static, dynamic, re-export, and CommonJS edges
   all pass the import-policy gate appropriate to their timing.
4. **No authority by chunk co-residence.** Sharing a bundle or bytecode file
   grants no import or host capability.
5. **Frame and continuation attribution.** Factory execution and scheduled
   continuations retain the correct package principal.
6. **Integrity before execution.** Source and prepared artifacts are verified
   before cache publication or factory invocation.
7. **No JavaScript-forged graph metadata.** Native code verifies serialized
   artifacts and does not trust export, edge, path, or identity claims merely
   because they came from a signed-looking JavaScript object.
8. **One logical module instance.** Aliases that LLP 0023 maps to one
   `SourceId` share a record; physically coincident sources with distinct
   authenticated `SourceId`s do not.

## Compatibility contract and conformance corpus

The new runner is gated by observable behavior, not transformed text. A shared
corpus runs untransformed fixtures on the adopted Node/V8 oracle and through
Ibex/Hermes. Its backbone includes test262's `language/module-code` and
top-level-await suites under the same expected-divergence mechanism, plus
Ibex-specific fixtures. The Node oracle itself is acquired hermetically at
LLP 0012's pinned release; an unavailable oracle fails the run loudly rather
than skipping it, per LLP 0018. The single-owner rule extends to sibling
corpora — LLP 0019's Hermes-compat corpus and LLP 0024's session/source-map
corpus share fixture definitions with this one (one definition, multiple
runners), never copied cases. It covers at least:

- semicolonless and multiline imports, exports, and re-exports;
- declaration hoisting, temporal dead zones, and function/class differences;
- live `let`/`var` exports and mutation observed by importers;
- direct and indirect cycles, including star re-exports;
- namespace identity, ordering, and immutability behavior;
- default/named/namespace CommonJS interop and falsy default values;
- CommonJS cycles and `module.exports` replacement;
- JSON modules and import attributes across ESM and CommonJS consumers;
- the ESM namespace view of a CommonJS record that threw and was evicted —
  the ESM adapter tracks the CJS cache algebra (re-evaluation after
  eviction), pinned against the oracle rather than inheriting ESM stickiness;
- synchronous and asynchronous ESM graphs;
- computed `require()` of an asynchronous graph reached during synchronous
  evaluation (the mixed re-entry rule of §7);
- synchronous `require()` reaching in-flight async records, and `require`
  cycles, with their stable error classes (§6);
- two-runtime, runtime destroy/recreate, old-generation late-rejection, and
  HMR-during-TLA generation behavior;
- package-edit HMR refusal under integrity-pinned bytes (§8);
- `import.meta.resolve` gating and non-disclosure;
- the pinned Node interop table: the `'module.exports'` namespace marker,
  conditional `__esModule`, and `require(ESM)` return selection;
- top-level-await fulfillment, rejection, and async cycles;
- literal and computed dynamic imports, including dead branches;
- promise-returning `import()` from CommonJS bodies;
- `import`-versus-`require` conditional-exports divergence (including
  reversed package-object key order and nested conditions) and
  ambiguous-`.js` source-goal classification;
- `import.meta.url`, filename, dirname, and main-entry behavior;
- TypeScript, TSX/JSX, decorators policy, and type-only edges;
- source maps through every wrapper and transform stage;
- package-principal attribution across static, dynamic, cyclic, cached, and
  chunked evaluation;
- unauthorized edge non-disclosure; and
- cache equivalence across source, transformed, bundled, and bytecode carriers.

Expected divergences from the oracle are named, exact, and fail when stale.
No fixture may silently skip Hermes execution or report success with zero
cases, following LLP 0018.

## Migration plan

### Adoption gate

Implementation beyond spike scope starts only after the governing decisions
are reconciled, not at retirement time. The 2026-07-15 adoption set completed
that gate: this RFC reached `Accepted`; LLP 0009 admitted the ModuleRunner
architecture; LLP 0007 resolved its open fork to this branch; LLP 0019 gained
its third (Rust/Oxc in-process) tier with the spike pass; LLP 0021 gained the
initialization task-boundary and trusted-loader registry amendments of §4;
LLP 0014 gained the initialization-triggering amendment to its import-grant
rule (§4); LLPs 0002 and 0003 gained the owner-thread-only serialized runtime-
drive contract required by §6; and LLP 0027 became the Spec-type home for the
versioned wire and interop contract.
Phase 5's document updates are then descriptive shipped-state edits, not
retroactive authorization. The intended
LLP 0019 end state is two tiers again — the build-time Node/Bun authority and
the Rust/Oxc in-process tier — with the bootstrap scanner tier retired once no
supported path depends on it.

Acceptance additionally requires a bounded producer spike: one selected
in-process integration, on the pinned toolchain (or under an explicitly
recorded toolchain-upgrade decision), emitting and executing representative
canonical artifacts on real Hermes — live mutation, cycles, TDZ, re-exports,
top-level `await`, dynamic import, TypeScript/JSX, Hermes compatibility, and
composed source maps. The spike's exit bar is falsifiable, not
"representative": an enumerated checked-in canonical-artifact list (named in
Phase 1) that must execute, plus a recorded minimum pass rate on test262
`language/module-code` and top-level-await under the expected-divergence
mechanism, set when the spike begins. Plausibility arguments do not
substitute for the spike. LLP 0027 owns the artifact wire schema and interop
contract; this document remains the architecture and migration authority.

The bounded spike freezes those two bars before its test262 run. The canonical
list is the 12 fixtures in
`tests/fixtures/module-runner-spike/manifest.json`: live mutation, a
hoisting-dependent direct cycle, a TDZ cycle, ambiguous star re-exports, named
re-export, `import.meta`, dependency TLA, dynamic import, TypeScript/JSX, the
LLP 0019 for-of capture repair, composed source maps, and Module-goal
strictness/wrapper hygiene. The independent sample is 20 tests pinned to
test262 commit `f2d1435644797268dca1f7988cad5a4e89ccd8d2`, split evenly between
`language/module-code` and its `top-level-await` subtree, with a minimum pass
rate of **90% (18/20)** on real Hermes. The checked-in subset manifest records
the upstream path and SHA-256 of every source; the expected-divergence list is
empty at spike start, so any later exception must be named and reviewed rather
than selected after observing failures.

The completed spike passed all 12 canonical fixtures and all 20 frozen test262
cases on real Hermes, exceeding the precommitted 18/20 minimum without adding
an expected divergence. Those results are adoption evidence, not a claim that
the later implementation phases are complete.

Reconciliation is phase-specific, not wholesale. The LLP 0024 TLA and
failure-caching amendments land with the first consumer that adopts the
runner (Phases 2–3); the LLP 0023/0024 generation amendments land before
Phase 4's HMR work *and before any session consumer adopts the runner's ESM
failure caching* (§5's rule); LLP 0002's owner-thread contract is already
amended and is touched again when resolver or runner ABI symbols change; and
LLP 0014 is touched again when import attributes and direct-file grant handling
land. LLP 0003's owner-thread contract is likewise already amended and is
touched again when the engine bridge gains compile/load-factory and context-
token operations, and LLP 0005 when chunk and HBC carriers change the prepared
pipeline.

### Phase 0: Baseline the current contract

- Promote existing loader regressions and representative ecosystem packages
  into an implementation-neutral module-semantics corpus.
- Add live-binding, cycle, namespace, TLA, and ESM/CommonJS fixtures that expose
  behavior the current CommonJS lowering cannot preserve.
- Measure cold transform, warm cache load, source startup, prepared startup,
  binary size, and compile time on supported desktop targets — including cold
  first-load of a representative ESM-heavy graph. Today ordinary ESM incurs
  zero Rust AST parse/transform before the bootstrap (it is still scanned by
  the bootstrap transformer and parsed by Hermes as a generated function), so
  baseline direct-source, SWC-lowered, scanner-lowered, and prepared paths
  separately.
- Record current intentional extensions and divergences before changing them,
  including a named fixture family pinning the current fire-and-forget
  dependency-TLA lowering so the default switch's tightening is deliberate.
- Inventory the existing prepared-execution pipeline — Rolldown bundle cache,
  integrity manifests, per-package chunks, entry HBC — as Phase 4 upgrade
  inputs rather than a greenfield.
- State the containment relationship with LLP 0007's transform-parity
  fixtures so the two suites share cases rather than drift.
- Convert each ENG-referenced scanner repair (ENG-22514, ENG-22520,
  ENG-22528, ENG-22811, …) into a named corpus fixture family, so the corpus
  provably covers every bug the old path accumulated before the scanner is
  deleted.
- Correct LLP 0004's "down-leveled" description of scanner-selected
  JavaScript while recording baselines: the default SWC pipeline applies no
  target-compat pass.
- Pin the shipped `#`-imports fixed-precedence divergence (an invented
  condition order over what Node treats as key-ordered membership) as a
  fixture family before the typed contract replaces it.

### Phase 1: Define and emit ModuleArtifact

The schedule-critical dependency is `OBL-SOURCE-ID` (owners: LLP 0021/0023
with this RFC). The minimal slice that unblocks Phase 2 is the `SourceId`
constructor, the typed resolver, the artifact wire schema, and canonical
factories executing on real Hermes; `OBL-GRAPH-LOCATION` and the LLP 0019
revision may land in parallel behind the experimental flag but gate Phase 2's
exit. The versioned wire schema and canonical artifacts are checked in
together under one repository path named in this phase, so later phases diff
artifacts, not prose. If `OBL-SOURCE-ID` stalls, the flag-gated experimental
runner uses no interim identity at all — artifact emission and verification
proceed against fixtures without publishing to any shared cache — rather
than creating path-keyed debt.

- Land LLP 0023's `SourceId` constructor and canonical encoding
  (`OBL-SOURCE-ID`, co-implemented with the LLP 0021/0023 owners) before any
  artifact publication or graph shadowing. Module records are never keyed on
  host-path strings; there is no interim path-keyed identity to migrate off
  later. Record in LLP 0023's obligations ledger that this RFC co-implements
  `OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE` (§9's manifest), and
  `OBL-GRAPH-LOCATION` (§1's digest-bound edge map), and consumes
  `OBL-MODULE-IDENTITY`.
- Select one Oxc/Rolldown integration and prove it compiles on the pinned Rust
  toolchain, or record an explicit toolchain-upgrade decision per LLP 0009.
- Land the typed resolution contract of §1 (`ResolutionKind` condition sets,
  source-goal selection, cache-key isolation), body-read-free by
  construction, with `.js`/`.mjs` denial and non-disclosure fixtures; correct
  LLP 0023's `OBL-RESOLVE-GATE` row to describe the classification read as a
  latent branch (LLP 0002/0004's body-read-free documentation is accurate
  today and stays accurate).
- Introduce typed `ModuleArtifact` and `ModuleRecord` structures behind an
  experimental feature/runtime flag.
- Emit artifacts with Oxc from source without changing the default evaluator;
  check in the versioned wire examples and generated factories under
  `tests/fixtures/module-runner-spike/`; canonical examples cover live mutation,
  TDZ, direct and indirect cycles, star ambiguity, `import.meta`, and
  top-level `await` — and execute those generated factories on real Hermes at
  fixture level, engine-honest from the first artifact, per LLP 0019's
  shape-tests-prove-nothing lesson.
- Revise LLP 0019 to name the hermetic in-process Oxc tier and add it as a
  system-under-test of 0019's behavior corpus.
- Verify metadata against the existing resolver and CapSec graph.
- Add source-map composition and cache-fingerprint coverage.

### Phase 2: Synchronous ESM graph

- Link and evaluate ESM graphs with no top-level `await` through real binding
  cells and module records.
- Implement CommonJS adapters and synchronous `require(ESM)` rules.
- Shadow the current loader in tests and one downstream direct-source
  workflow, comparing CapSec effect traces of corpus runs rather than
  dual-executing application side effects. Graph-shape disagreements — the
  runner's parsed static-edge set versus the scanner's discovered rewrites
  per module — fail loudly or are recorded as named divergences; the
  scanner's accreted edge-case knowledge serves as a free migration oracle
  before it is deleted.
- Keep SWC and the bootstrap transformer as the default fallback.
- Regenerate the CapSec surface registry for the runner: enumerate new,
  changed, and retired loader/edge-gate/artifact/cache/carrier/
  compile-factory surfaces; regenerate coverage and implementation manifests
  and registry digests; new target cells start unsupported and refuse arming
  until implemented; add allow/deny/wrong-principal/missing-attribution/
  cache-hit/prepared-carrier fixtures. Source acquisition is registered as
  §4's trusted-loader effect.

### Phase 3: Asynchronous ESM graph

- Add dependency-level top-level `await`, async strongly connected components,
  and promise-returning dynamic import.
- Integrate event-loop keepalive, cancellation, and asynchronous failure
  attribution with LLP 0024/0025 contracts.
- Refuse sync `require()` of async graphs without blocking a runtime thread.

### Phase 4: Prepared production graph

- Upgrade the existing Rolldown bundle cache, integrity manifests, and
  per-package chunk pipeline in place to emit the same logical artifacts and
  provenance manifests, rather than building a parallel system.
- Add chunk and Hermes-bytecode carriers with per-module identity preserved
  and the per-principal carrier constraint of §9 enforced.
- Connect Exact/Vite source graph and HMR invalidation to module-record
  generations.
- Compare source-mode and prepared-mode behavior with the same corpus.
- Carry LLP 0007's live Babel `--lower-classes` exception as a fingerprinted
  temporary stage, or gate its retirement explicitly.

### Phase 5: Default switch and retirement

- Make the module runner default after semantic, security, platform, and
  performance gates pass.
- Keep SWC as an explicit fallback for one bounded release window.
- Stop sending ordinary ESM through `transformEsmToCjs`.
- Remove bootstrap module-syntax scanners after no supported path depends on
  them; any interim Hermes workarounds remaining in the bootstrap are owned by
  LLP 0019 and retire with its scanner tier (see Adoption gate).
- Migrate entry-TLA detection to the artifact's AST-derived
  `has_top_level_await` bit; the CLI text scanner (`contains_top_level_await`)
  retires with the scanner tier.
- Remove SWC crates after the fallback window *and* after LLP 0024's
  parser-equivalence gate passes (or that contract is revised); a parser-only
  SWC dependency may outlive the module-transform role.
- Update LLPs 0004, 0007, 0009, 0013, 0019, 0021, 0022, 0023, 0024, and 0025
  to their resulting states.

### Linear execution contract

The Exact-project Linear program is [ENG-25054](https://linear.app/expo/issue/ENG-25054/program-esm-module-runner-and-runtime-module-graph-llp-0026). Every issue
carries the `Ibex` label and is a child of the program issue. Linear blocker
relations encode the adoption and implementation gates; the parent remains
blocked on the final default-switch issue so completion is defined by the child
graph rather than by manual umbrella bookkeeping.

| Workstream | Linear issue | Blocked by |
| --- | --- | --- |
| Adoption and governing-document reconciliation | ENG-25055 | — |
| Module-semantics corpus and baselines | ENG-25056 | — |
| Bounded Oxc producer spike | ENG-25057 | — |
| Authenticated `SourceId` and typed resolution | ENG-25058 | ENG-25055 |
| Versioned `ModuleArtifact` contract | ENG-25059 | ENG-25055, ENG-25057, ENG-25058 |
| Hermes factory/context ABI | ENG-25060 | ENG-25055, ENG-25059 |
| Synchronous ESM graph and CommonJS interop | ENG-25061 | ENG-25056, ENG-25058, ENG-25059, ENG-25060 |
| CapSec rev2 graph-runner integration | ENG-25062 | ENG-25055, ENG-25058, ENG-25059, ENG-25060 |
| Asynchronous graph, TLA, and dynamic import | ENG-25063 | ENG-25061, ENG-25062 |
| Prepared Rolldown/chunk/HBC graph | ENG-25064 | ENG-25063 |
| HMR execution generations | ENG-25065 | ENG-25063 |
| Default switch and compatibility retirement | ENG-25066 | ENG-25056, ENG-25062, ENG-25063, ENG-25064, ENG-25065 |

## Performance and platform gates

Before the default switch:

- warm artifact-cache module loading must remain within an explicitly accepted
  envelope of the current warm loader on macOS, Linux, and Windows;
- prepared production startup must not parse the full application graph at
  runtime;
- mobile embedders must be able to consume prepared artifacts without shipping
  a Node/Bun dependency or writable project tree;
- transform cache size, eviction, and cold-load cost must be measured on a
  representative ESM-heavy dependency graph;
- steady-state evaluation overhead of the cell/setter ABI — import reads in
  hot code (checked reads in v1), export-mutation fan-out, and namespace
  property access — must be measured against the current lowered code's plain
  property accesses and stay within an explicitly accepted envelope;
- cold synchronous `require(ESM)` drive latency — proving and then evaluating
  a representative closure on the JS thread — must be measured in Phase 0 and
  budgeted alongside the cold-first-load numbers; if the budget fails, the
  recorded fallback is to restrict synchronous `require(ESM)` to graphs whose
  async-taint bit is already a warm-cache or prepared-manifest fact, refusing
  cold drives with the same stable error family — and if that fallback is
  exercised, cold-refusal becomes a corpus-visible named divergence with its
  own fixture family, not a perf-gate footnote;
- native compile time and binary-size changes from Oxc/Rolldown versus SWC must
  be reported; and
- capability enforcement and frame attribution must pass on every advertised
  architecture, not only the CLI host — with a non-empty advertised-target
  list, since an empty target matrix satisfies per-target criteria vacuously.

Numerical regression budgets should be set from the Phase 0 baseline rather
than invented in this draft. Any accepted regression is written into this RFC
with its product rationale before the default changes.

## Alternatives considered

### Continue extending `transformEsmToCjs`

Rejected as the end state. It is valuable as a bounded compatibility fallback,
but correct ESM requires grammar and graph semantics that a bootstrap string
transformer should not own.

### Run every ESM file through SWC

Useful as an interim correctness measure. It removes scanner-level syntax
bugs, and SWC's CommonJS lowering preserves more than the bootstrap scanner
does — its getter-backed exports cover many ordinary live-binding cases and
simple cycles. It still cannot guarantee the complete linked-ESM contract:
namespace exotic behavior, exact cyclic instantiation order, star ambiguity,
temporal dead zones, and dependency-level TLA remain missing. It also retains
a transform family LLP 0007 intends to retire.

### Oxc file-at-a-time ESM-to-CommonJS lowering

Also useful as a bridge and closer to the desired toolchain. It is not the
final architecture for the same graph-semantic reasons. If its glue grows into
linking, it has become the module runner and should implement this RFC directly.

### Bundle every application into one script

Rejected as the universal solution. It can be an excellent production carrier,
but direct runtime TypeScript, dynamic imports, CLI programs, HMR, package
compartments, and per-module diagnostics still require logical module records.

### Add native ESM support to Hermes

Potentially attractive in the long term, but much larger in engine scope and
upstream-maintenance cost. Ibex would still own authenticated resolution,
CapSec principal attribution, TypeScript/JSX transforms, prepared artifacts,
and host integration. This RFC does not block an engine-native experiment, but
does not require one for v1.

## Risks

- **Async architecture spread.** A real ESM graph changes loader APIs that
  assume `require()`-shaped synchronous completion. The migration must keep
  CommonJS sync and make ESM suspension explicit rather than adding hidden
  waits.
- **Interop drift.** Node, bundlers, and existing Ibex shims differ around
  synthetic named CommonJS exports. One adopted rule must govern source and
  prepared paths.
- **Security regression through optimization.** Prefetch, graph caching, and
  chunking can accidentally bypass staged authorization or flatten principals.
- **Oxc/Rolldown Rust API maturity and the toolchain pin.** The stable
  artifact contract must isolate Ibex from churn in specific crate APIs, and
  LLP 0009 already records that recent Rolldown/Oxc releases require a newer
  Rust than the repo's pin; feasibility on the pinned toolchain is a Phase 1
  exit criterion.
- **Hermes compatibility.** Oxc browser targets do not automatically encode
  every Hermes engine quirk; LLP 0019's behavior corpus remains necessary.
- **Memory retention.** Namespace objects, binding cells, evaluation promises,
  source maps, and multiple HMR generations can retain large graphs. The
  cross-heap shape matters as much as the size: ownership is one-directional —
  native records own JavaScript handles; JavaScript never strongly owns a
  record — so native/Hermes reference cycles are unrepresentable, and
  generation teardown fixtures assert reclamation.
- **Diagnostic drift.** Factory wrappers and bytecode can make correct
  execution harder to debug unless source-map composition lands with the first
  experimental path.
- **Migration duality.** Running old and new loaders simultaneously creates
  cache, identity, and behavior splits. Shadowing must never execute side
  effects twice in production.

## Acceptance criteria

This RFC is implemented when:

1. The module-semantics corpus runs against Node/V8 and real Hermes with
   non-zero, fail-loud case counts.
2. ESM live bindings, cycles, namespaces, re-exports, dynamic import, and
   dependency-level top-level `await` pass the adopted oracle contract.
3. CommonJS cycles and the documented ESM/CommonJS adapters pass in both source
   and prepared modes.
4. Static and dynamic edges enforce the authenticated import graph without
   unauthorized path/body disclosure.
5. Module identity remains `(runtime, SourceId)` across raw, cached, chunked,
   and bytecode carriers, with defining-principal compartment execution and
   LLP 0013 frame attribution verified per carrier on every advertised engine
   build.
6. Every transform and wrapper stage emits or composes source maps.
7. A hermetic build can load TypeScript/TSX without Node, Bun, or `node_modules`.
8. Source-mode and prepared-mode outputs are behaviorally equivalent for the
   corpus.
9. Platform and performance gates are recorded and pass on the advertised
   targets.
10. Ordinary supported ESM no longer depends on `transformEsmToCjs`.
11. SWC's module-transform role has been removed; any remaining SWC
    dependency serves LLP 0024's session parsing/lowering contract, is
    governed by that document's own migration, and is recorded explicitly in
    this RFC.
12. LLPs 0002, 0003, 0004, 0005, 0007, 0009, 0013, 0014, 0019, 0021, 0022,
    0023, 0024, and 0025 have been reconciled with the shipped architecture,
    including
    LLP 0023's obligations ledger (`OBL-SOURCE-ID`, `OBL-SOURCE-PROVENANCE`,
    `OBL-MODULE-IDENTITY`, and the `OBL-RESOLVE-GATE` latent-branch
    correction), LLP 0023 §2.3's generation scoping of module identity,
    LLP 0024's failure-caching and one-file-one-instance wording, and
    LLP 0019's implementation-tier list.

## Open questions

1. Which Oxc/Rolldown Rust integration can emit the proposed artifact with the
   least custom code while preserving a hermetic binary?
2. Does the Hermes-side cell representation (§4's decided ownership) meet the
   steady-state performance gate, or does cell state eventually need to
   migrate native?
3. Does the pinned Node 24.13.1 compatibility target (LLP 0012) stay the
   interop oracle through Phase 5, or does a newer pin land first — and with
   what re-verification of the interop corpus?
4. Does v1 preserve Ibex's `require` extension inside ESM indefinitely, or
   deprecate it after the module runner is established?
5. What is the exact generation/transaction contract between this runner and
   Vite HMR?
6. Within the per-principal carrier constraint of §9, should production
   artifacts be per-module HBC, per-principal multi-module chunks, or a hybrid
   selected by dynamic boundaries?
7. Can Rolldown's graph be imported directly without allowing bundler output to
   become the authority for resolution or CapSec identity?
8. Which parts of LLP 0024's entry/session TLA model should reuse the general
   graph, and which remain intentionally session-specific?
9. What cold and warm performance budgets should Phase 0 establish?
10. Is engine-native Hermes ESM worth a parallel prototype after the runner ABI
    and corpus make the required semantics concrete?
11. Can Hermes expose trustworthy per-factory Domain or function-range
    attribution, and at what engine-maintenance cost, to eventually relax §9's
    per-principal executable-carrier constraint?
12. Given §4's worker-locality rule, which specific control records cross the
    supervisor/worker boundary when sessions adopt the graph?
