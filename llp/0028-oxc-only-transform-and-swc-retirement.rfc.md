# LLP 0028: Oxc-Only Transform Authority and SWC Retirement

**Type:** RFC
**Status:** Draft
**Systems:** Module Loader, Runtime, Build, Engine
**Author:** Charlie Cheever / Claude Fable
**Date:** 2026-07-17
**Revised:** 2026-08-03 (Snapback LLP 0062's phase boundary is corrected: phase
1 has no embedded-Ibex or computed-import dependency; the future app-bound
Ibex host instead uses LLP 0048's import-free, erasable-only external-script
profile under this RFC's pinned Oxc transform authority. Candidate tables
remain an Ibex module-runner capability, not a Snapback requirement.)
**Revised:** 2026-08-03 (the authenticated source/prepared real-binary gate was restored after the ingress refactor; direct `.cts` entries now use the Oxc TypeScript/CommonJS path, reached prepared records are published only after authenticated acquisition, and native graph failures retain Oxc diagnostics plus composed original-source locations)
**Revised:** 2026-07-18 (LLP 0030 round-1 review reconciliation: foreground
audit v1 is source-inline only, refuses every prepared/HBC carrier, and has no
production or diagnostic prepared-cache admission path)
**Revised:** 2026-07-18 (author decisions: LLP 0031 selects macOS arm64 and
Linux x64 as the evidence-gated 0.2 native tuples; computed `require` remains
fail-closed; decorators are an intentional typed incompatibility; candidate
tables stay in LLP 0014/0026/0027 rather than a new Spec; and 0.2 waits for the
window-close gates instead of extending the compatibility fence)
**Revised:** 2026-07-18 (candidate tables were selected for Ibex 0.2 and
implemented: the v1 manifest join, producer correspondence table, digest-bound
sidecar, prepared-graph v2 references, site-bearing native ABI,
source/prepared/SFE admission, invocation taxonomy, and compiled-stub
execution. The former attribution of this decision to Snapback LLP 0062 was
incorrect and is superseded by the 2026-08-03 correction above.)
**Revised:** 2026-07-17 (implementation progress: the exhaustive Hermes
target matrix, exact 31-row Tier-3 disposition map, debug-only real-binary
source/prepared receipt runner, BigInt lowering, and typed unsupported-syntax
quarantines are landed and required on the native CI tuples; only the
decorator row remains blocked on author-decision register item 4)
**Revised:** 2026-07-17 (implementation progress: the hand-written CLI await
scanner was retired in favor of one Oxc syntax projection shared by virtual
evaluation input and path-aware entry/bundle readers; lowering remains gated
on LLP 0024's hybrid Script-plus-import-plus-TLA seam)
**Revised:** 2026-07-17 (round-4 dual review: computed-site naming solved via
a reserved `ibex:site` import-options label + producer site table; 0.2
fence/release-coupling policy stated; minimal Oxc script frontend named as
its own gated workstream (resolving the §3/§4b contradiction);
`hermes_target`'s manifest meaning defined; `EXACT_COMPAT_TEST` split into
fixture-fidelity vs loader-selection semantics; reserved-key timing made an
explicit dead-branch exception; prefix gate respecified over `cargo
metadata`; inventory corrections (`.cjs`, ten registry needles, cache/env
additions). Round-3 revision: candidate mechanism narrowed to
one v1 authoring model (manifest-declared) with a versioned sidecar carrier,
producer-emitted site tables, and script-surface exclusions; three-class
failure taxonomy separating admission from invocation; transform identity
recast as a canonical configuration manifest, not one version constant;
Tier 3 typed quarantine made an immediate 0.1 blocker; computed-require
rationale corrected (LLP 0014's CJS `authorities` channel exists) and
telemetry relabeled advisory with a static-scan denominator; inventory gains
`-e`/bundle-selection TLA readers, `EXACT_COMPAT_TEST`, and five further
cache namespaces; audit-admission owner/sketch/deadline; LLP 0007 added to
reconciliation; author-decision register added. Earlier history below.)
**Revision history:** 2026-07-17 round-1 (three-gate LLP 0024 contract;
candidate-map alignment; reachability matrix; identity atomicity; gates);
2026-07-17 round-2 (explicit-declaration default; deployment-layer binding;
LLP 0024 revise-then-build; file-at-a-time deletion; Phase 0; typed
telemetry).
**Related:** LLP 0007 (transform-toolchain authority; revised and closed by §5); LLP 0009 (runtime transform candidate scope; the Decision this RFC completes); LLP 0019 (hermes-compat transform tiers and zero-divergence discipline); LLP 0024 (parser and session-lowering contracts, revised by §3); LLP 0026 (ESM module runner; Phase 5 retirement gates); LLP 0027 (ModuleArtifact wire contract; `transform_fingerprint`); LLP 0001 (platform matrix, §4d); LLP 0014 (policy generation and import attributes, revised by §2); LLP 0048 (restricted external-script profile and broker ABI)

## Summary

Make Oxc the only parse/transform engine for **Ibex's production
in-process runtime module transforms** and delete the SWC dependency
stack. LLP 0009 and LLP 0026 already accepted the direction — the module
runner's Rust/Oxc producer is canonical for ordinary ESM, and SWC is
demoted to a file-at-a-time compatibility engine bounded to the Ibex 0.1
window. This RFC proposes the concrete program that closes the window
and the decisions the existing documents left open, and it carries an
explicit **author-decision register** (§7) for the product choices that
are the author's to make rather than this document's to bury.

The normative claim is scoped deliberately: "one engine" means the
runtime's in-process module transform authority. Adjacent transform
surfaces are classified explicitly rather than silently contradicting
the title: the build-time Babel `--lower-classes` stage (retained, out
of scope — Non-goals), the `EXACT_TRANSPILE_SCRIPT` developer
subprocess override (retired, §4b), and the host's handwritten
string-level ESM/`import.meta` rewrites for Rolldown bundle outputs
(retired with the legacy pipeline, §4b).

Runtime-loaded TypeScript remains a first-class capability **on the
advertised module-runner target tuples**, per LLP 0009's "TypeScript
runtime direction": `.ts`, `.tsx`, `.mts`, `.cts`, `.jsx` keep loading
from the hermetic embedded path, with no Node/Bun/Vite subprocess and no
build-time-only carve-out. What happens on unadvertised tuples when the
window closes is a named product decision (§4d, §7). Type *checking*
stays out of the runtime (LLP 0026 non-goal); `tsc`/tsgo belong to the
editor and CI.

## Motivation

Two engines means two conformance surfaces. The engines, their
diagnostics shapes, and their cache-key domains each exist in an SWC
flavor and an Oxc flavor; the LLP 0019 hermes-compat passes are tiered
(JS-AST authority, bootstrap scanner, Rust/Oxc mirror) rather than
duplicated per engine, but the zero-divergence rule still has to hold
the tiers together. That discipline works, but it is pure carrying cost
once the module runner is the default (it has been since ENG-25066):
the SWC in-process path serves the legacy-window shapes and the host
paths inventoried in §4b, inside a compatibility window that already
has a kill switch (`IBEX_LEGACY_MODULE_LOADER=0`) and a version fence
(0.1.x).

Two external forcing functions make now the right time:

- **Downstream embedders want the guarantee, not the migration.**
  Snapback's post-phase-1 app-bound executable direction (Snapback LLP 0062,
  in the snapback repo) needs one pinned transform authority for a
  caller-selected local TypeScript/JavaScript file. It does **not** create a
  phase-1 embedded-Ibex dependency and does **not** require computed import.
  LLP 0048 therefore defines a narrower host-portable external-script profile:
  erasable-only TypeScript, top-level await, and no static, dynamic, or
  CommonJS imports. That profile consumes this RFC's Oxc configuration and
  fingerprint authority without changing the general module runner's fuller
  TypeScript surface or candidate-table design.
- **The Oxc pin is aging in place.** We are pinned to Oxc 0.121.0
  because the repo's Rust 1.93.1 toolchain rejects newer
  `oxc_transformer` code (LLP 0009 records the matrix). Every month the
  pin ages, the eventual jump gets bigger.

## Goals

- One parse/transform engine (Oxc) for every production in-process
  path that still transforms source at runtime; one cache-tag domain;
  one `transform_fingerprint` domain — governed by one canonical
  transform-configuration manifest (§1), of which the locked Oxc
  version set is a *component*, not the whole identity.
- Zero SWC crates in `Cargo.toml` and zero resolved `swc_*` packages
  in `Cargo.lock` (currently twenty) across retained feature/target
  profiles, enforced by a name-prefix check over `cargo metadata`
  (§4). The LLP 0026
  allowance that "a parser-only SWC dep may outlive the
  module-transform role" is explicitly superseded by this RFC.
- TypeScript/JSX runtime loading preserved **behaviorally, on real
  Hermes**, against the conformance corpora in §5. Exact bytes are
  asserted only where contractual (stable error codes, fingerprint
  fields).
- The remaining legacy-window interop shapes get a definitive
  disposition under a three-class failure taxonomy (§2).
- Every reachable consumer of the SWC path, the compatibility
  evaluator, and the host's string-level transforms has an explicit
  post-retirement disposition (§4), including every cache namespace,
  test selector, and env var — the removal is proven by inventory and
  CI gates, not review-time search.
- No silent behavior change: everything ships behind the existing LLP
  0026 Phase 5 gates, the LLP 0024 gates as revised by §3, and the
  native-conformance gates in §5 — with the native-path gates and the
  Tier 3 quarantine in place *before* the engine version rotates.

## Non-goals

- Type checking in the runtime (unchanged LLP 0026 non-goal).
- Reopening the transform-engine choice (LLP 0009 settled Oxc).
- Changing the **ModuleArtifact v1** wire format. `DynamicEdgeV1` is a
  closed, `deny_unknown_fields` contract and stays byte-identical; §2's
  candidate binding lives in a separately versioned, digest-bound
  sidecar referenced from the deployment layer — the strict canonical
  `ibex/prepared-module-graph/1` was not loosened in place; v2 adds the
  sidecar digest-reference inventory and v1 caches rebuild.
- Erasable-syntax-only TypeScript for the **general module runner**. Ibex
  already lowers full TS (enums, namespaces), and this RFC does not narrow
  that surface. LLP 0048 deliberately defines an erasable-only, import-free
  profile for one separately attributed external worker; that bounded profile
  is not a change to ordinary `.ts` module loading.
- Retiring the build-time Babel `--lower-classes` stage (LLP 0007
  "Current state"; build-tool concern on the Rolldown track). §4b
  classifies it so the "one engine" claim is honest about its scope.

## Design

### 1. Toolchain and pin rotation — atomic with identity rotation

Bump the repo toolchain from Rust 1.93.1 and re-pin Oxc to a current
release. LLP 0009's matrix numbers are re-measured at execution time;
the adopted pins — an exact Rust version and a coherent version set for
the ten direct `oxc_*` dependencies (eight lockstep crates plus
`oxc_sourcemap` and `oxc_resolver` on their own tracks; `oxc_resolver`
becomes exact-pinned too) — are recorded in a `Revised:` entry to LLP
0009, with lock-resolved version/source/checksum authoritative. The
bump enumerates and updates **every** pin site (`rust-toolchain.toml`;
`ci.yml`, `module-loader-baselines.yml`, `compartment-conformance.yml`,
`hermes-patch-canary.yml`; the performance fixtures), and converts
workflows to consume `rust-toolchain.toml` with a drift check. A
non-gating **latest-Oxc canary** CI job lands in this step (not a
future Guide) as the standing answer to pin aging.

**Transform identity is a configuration manifest, not a version
string.** Production identity is already structured (parser, transform,
ABI, hermes-compat, detector, options fields), and two of its real
inputs are unrepresented today: the ECMAScript output target is
hard-coded (`es2022`) *outside* the option digest, and `hermes_target`
is populated from the loaded engine's bytecode-cache identity (which
mixes evaluator and `hermesc` toolchain facts) rather than the
producer config. This step introduces one **canonical
transform-configuration manifest** — an *authored* canonical input
from which Rust constants, cache tags, receipts, and CI pin assertions
are generated with a drift check — that both constructs the Oxc
transformer and populates a domain-separated `transform_fingerprint`:
Oxc locked-set digest (over the complete output-affecting resolved
dependency closure, with source/version/checksum), ECMAScript target,
Ibex handwritten-pass version, module-runner ABI (including the §2
site-bearing `dynamicImport` change, which rotates the ABI component
when it lands in step 2), CommonJS detector and version, Hermes-compat
version, and the full option set. **`hermes_target` is redefined** as
a stable, producer-declared Hermes syntax/ABI target named in the
manifest; the loaded-evaluator and HBC-toolchain identities move
wholly to carrier admission where they belong, with same-target-reuse
and incompatible-evaluator-refusal fixtures separating the two
identities. The cache tag derives from the manifest digest. Golden tests prove rotation at *every*
output-changing phase: pre-rotation cache entries miss, pre-rotation
prepared carriers revalidate-or-rebuild, and each later phase that
changes output (step 2's ABI change) rotates its component and is
stale-tested the same way.

The bump is validated by the §5 Phase 0 gates plus the LLP 0026
performance gates (report id `ibex/module-runner-performance-gate/1`).
CI dual-produces old-pin/new-pin artifacts for the corpus and compares
semantic metadata, source maps, and real-Hermes behavior — archived as
a content-addressed report — without executing both in production.
Mechanically, the old-pin side is produced by the archived producer
binary built at the pre-bump commit (one workspace cannot build both
lockfiles); the comparison's semantic projection and
allowed-difference set are precommitted in the step-1 issue, like §3's
parser projection.

### 2. Disposition of the legacy-window interop shapes

The shapes that route to the legacy loader today each get a final
answer. The semantics conform to LLP 0026 §6's
authenticated-candidate-map contract: a computed site never performs
open call-time resolution or a filesystem probe.

**Failure taxonomy (normative).** Three classes, because "everything at
invocation" and "reject hostile wire data at admission" are both right
and must not be conflated:

1. **Source-generation failures** — producer diagnostics at build time
   for source the producer cannot represent. These never block a
   *dead-branch* site: a representable module containing an
   unsupported dynamic site still produces an admissible artifact with
   the site marked (guarded factory/runtime representation).
2. **Artifact-admission failures** — malformed or reserved wire data
   (unknown attribute keys, LLP 0014's reserved policy keys, malformed
   bags *in the artifact*) fail admission before execution, exactly as
   LLP 0027 prescribes. Hostile wire bytes never reach evaluation.
3. **Invocation failures** — well-formed, admitted artifacts whose
   guarded sites are *reached* at run time: computed sites without a
   candidate row, computed `require`, unsupported-at-runtime option
   values. These are rejected promises (or thrown `require` errors) at
   invocation, preserving specifier/options evaluation order and side
   effects, with the error naming the module and the *original-source*
   site (the current transformed-byte-offset rejection is a defect
   this fixes). Reserved-key and attribute vocabularies are derived
   from the canonical LLP 0014 schema — which today includes
   `authorities` — never from a hand-copied list, and every ingress is
   tested.

One **explicit exception** to the dead-branch rule, stated rather than
implied: source-authored *reserved policy keys* (LLP 0014's grant
vocabulary) are statically decidable misuse of a build-time-only
channel and are **unconditional class-1 generation errors**, even in
dead branches — they are policy authoring mistakes, not runtime
values, and letting them ride to invocation would let a policy-shaped
declaration silently do nothing. Every other source-authored option
defect (unknown non-reserved keys, non-literal bags) is a guarded
class-3 invocation failure. The fixture matrix pins this key/timing
split explicitly: reserved key in a dead branch → generation error;
unknown key in a dead branch → loads, never fails; the same malformed
bag in wire bytes → admission failure.

Fixtures additionally pin dead-branch loads and getter/side-effect
order.

**Candidate tables — one v1 mechanism, one carrier.**

- **Authoring (v1): manifest-declared candidates, joined by site
  label.** A reviewed manifest entry (schema owned by the LLP 0014
  revision) declares, for a **labeled** computed site, the exact
  candidate spelling set. The stable authoring key is a reserved,
  producer-recognized literal key in the site's import options —
  `import(expr, { with: { "ibex:site": "route-tables" } })` — chosen
  by the author, unique per requester module (duplicate labels are a
  generation error), and stable across source edits, re-pins, and
  fingerprint-domain rotations because it lives in the source itself.
  This is new *vocabulary* inside the already-closed options set, not
  new grammar, so it avoids the `import.meta.glob` trust/grammar
  questions; unlabeled computed sites simply have no candidate row
  and fail at invocation. In-source glob-style candidate declaration
  remains deferred. Enumeration is deterministic with specified
  package-boundary and symlink rules; manifest patterns expand at
  generation time to a frozen spelling list with a recorded
  zero-match diagnostic.
- **Site correspondence: the producer emits, the generator consumes.**
  The producer (the single parsing authority) emits a site table
  (requester `SourceId`, requester source integrity, site label if
  present, site ordinal, original-source span) as part of graph
  production; the LLP 0014 generator joins manifest declarations to
  producer sites through the label column. There is no second parse
  and no parallel numbering authority. This work also fixes the
  existing site-representation inconsistency (`DynamicEdgeV1.site`
  promises stable producer order, but ESM sites currently record a
  transformed byte offset while CJS sites record an ordinal): the
  site table becomes the single definition, and the artifact ordinal
  is derived from it.
- **Carrier: a versioned digest-bound sidecar**
  (`ibex/computed-candidates/1`), referenced by digest from the
  deployment layer, keyed by `(requester SourceId, requester source
  integrity, transform fingerprint, site, generation)`, each row
  carrying the site label, the authored spelling set, attributes, and
  resolved target `SourceId` + integrity — so an edited requester
  cannot validate against a stale row. The strict canonical
  `ibex/prepared-module-graph/1` is not loosened in place:
  `prepared-module-graph/2` adds exactly one candidate-table reference
  inventory (v1 graphs rebuild on upgrade,
  per the existing fingerprint contract). Site ordinals are valid
  **only within one transform-fingerprint domain**; a re-pin or ABI
  change rotates the domain and every table rebuilds (rotation
  fixture: no cross-domain row can validate). For large closures, the
  sidecar may bind a Merkle root with per-site row proofs rather than
  copying full tables into every carrier.
- **Non-module scripts are excluded, explicitly.** LLP 0024 scripts
  (`ibex -e`, REPL, `.load`) deliberately have no `SourceId`; computed
  dynamic import in script surfaces fails at invocation with the
  stable candidate-less error (literal dynamic import is unaffected).
  This is a documented boundary of the candidate mechanism, recorded
  in the LLP 0024 revision, not an oversight.
- **Two defaults.** Explicit manifest declaration is the only v1
  authoring path. *Package-closure* candidate sets (a site opting into
  the importer package's whole admitted import set) remain specified
  as the opt-in second mechanism: the materialized per-site closure is
  written into the generated policy artifact and participates in
  `--check` diffs as an authority-relevant expansion. The threat-model
  delta is stated honestly: attacker-influenced *data* selects which
  admitted module loads and initializes (initialization is authority),
  which is why closure is opt-in and reviewable.

**The shapes:**

- **Computed dynamic `import(expr)`** — supported natively via the
  candidate tables above; a spelling outside the site's row is an
  invocation-class rejected promise without resolution or probing.
  **Sequencing is evidence-gated** (see telemetry below): the §5
  decision rule applies to computed import symmetrically — if the
  observed populations show zero computed-import usage, the option of
  closing the window fail-closed first and landing candidate tables as
  a follow-up (decoupled from SWC deletion) goes to the author with
  the archived report; nonzero usage confirms step 2's scope. If
  a downstream module-graph consumer independently requires computed
  import, that requirement may inform the evidence decision. **Resolved
  2026-07-18 and corrected 2026-08-03:** candidate tables landed as an Ibex
  module-runner capability, so the fail-closed-first sequencing option was
  not used. Snapback LLP 0062 was not the reason: its phase 1 has no Ibex
  dependency, and LLP 0048's future external-script profile refuses every
  import form.
- **Computed CommonJS `require(expr)`** — *not* carried natively at
  window close; an invocation-class stable error (dead-branch
  preserved; argument expression still evaluates first). This is an
  explicit amendment of LLP 0026 §1/§4. The honest rationale is
  narrower than earlier revisions claimed: LLP 0014 **does** define a
  CJS authoring channel (`require("pkg", {"authorities": [...]})` —
  the JSON-only second argument), so "no authoring channel" was false.
  What distinguishes computed `require` is the *synchronous drive*
  cost — candidate admission for `import()` rides the async graph's
  call-time authorization, while `require` needs LLP 0026 §6/§7's
  sync-drive machinery — plus the observed-usage picture. Reusing the
  JSON channel for computed-require candidate rows is therefore the
  named reopening path if evidence warrants: the mechanism is
  specified as *deferred, with a design that already fits* (same
  sidecar, rows authored via the existing JSON channel), not as
  impossible. **Resolved 2026-07-18:** 0.2 keeps this fail-closed
  disposition; it does not add computed-`require` candidate rows.
- **Dynamic-import options** — the runtime attribute subset (today
  `type: "json"`) is accepted and participates in edge identity and
  authorization; reserved LLP 0014 policy keys (including
  `authorities`) are wire-rejected at admission (class 2) and
  source-diagnosed at generation (class 1); unknown keys or
  non-literal bags at a *reached* site are invocation failures
  (class 3). No pass-through of unknown options.

Candidate tables compose with prepared graphs and HMR: candidates are
ordinary admitted modules prepared into the deployment graph; tables
key on generation and rotate with execution generations. LLP 0014,
0026, and 0027 get `Revised:` entries (manifest schema + generator
join; computed-`require` amendment; sidecar schema + attribute
taxonomy respectively).

### 3. The LLP 0024 gates: revise the seam, then build on Oxc

LLP 0026 §3 names three independent gates for SWC removal and the
alternative this RFC takes for two of them: SWC crates leave "when all
three gates pass **or 0024's contracts are revised**." No SWC session
stack exists to migrate (SWC's implementation footprint is
`transpile.rs` alone; LLP 0024's session frontend is unprototyped in
either engine). But the LLP 0024 revision is **not just an engine
rename** — LLP 0024's future transform authority is literally the
synchronous-`require` pipeline this RFC deletes, and its source-map
model composes through the Tier 2 compatibility transform this RFC
retires. The revision therefore must describe the complete
post-retirement seam:

- parser entry point (`oxc_parser` at the locked version, build-time
  version assertion) and the hybrid Script-plus-`import`-plus-TLA
  goal's feasibility path in Oxc terms (owned by LLP 0024's own
  prototype question, answered before its session implementation
  starts);
- the module-runner handoff (what the session evaluator calls once
  `transpile.rs` is gone) for static/dynamic/`require` behavior,
  including the non-module requester identity above;
- source-map composition after Tier 2 deletion;
- reconciliation of every LLP 0024 reference and acceptance criterion
  that currently names deleted machinery.

The full structured-session implementation is **not** a prerequisite
of SWC deletion; the revised contracts are — **plus one bounded piece
of implementation this program does own**: a **minimal Oxc script
frontend** for the surfaces that execute through SWC-adjacent paths
today (`-e`/`-p`, REPL, `.load`, stdin), covering goal detection
(including TLA), lowering to what the runner/session evaluator
consumes, and the script-surface computed-import exclusion above. An
earlier revision routed these surfaces to "the LLP 0024 session
frontend" while simultaneously declaring that frontend deferred — a
contradiction. The minimal frontend is a named workstream with
real-Hermes fixtures, gates step 4, and is explicitly *not* the full
LLP 0024 session stack (no structured-evaluation protocol, no
composed session maps — those stay deferred with LLP 0024). Cutover evidence for the
parser re-pin is a one-shot archived differential run —
`swc_ecma_parser` vs `oxc_parser` over LLP 0024's corpus for every
goal and dialect **both parsers implement**, via a **precommitted
normalized parse-equivalence projection** (fields covered, span
handling, error-recovery classification — defined in the step-3 issue
*before* the run, so equivalence is not fitted to results), plus a
real-world sweep of a representative `node_modules` transpile cache.
The hybrid goal is out of the differential's scope. An Oxc-vs-Hermes
acceptance check for JavaScript goals is added as a separately
motivated producer gate (it proves engine acceptance, nothing about
TS).

**Implementation status (2026-07-17).** The bounded frontend is landed.
`script_frontend::prepare_hybrid_script` performs the pin-bound hybrid
validation, Oxc TypeScript/JSX transform, AST-span import lowering, completion
classification, and script computed-import exclusion. `-e`/`-p`, prompt input
and `.time`, and `.load` consume that result; the old REPL keyword/import
scanners and string replacement are absent. `prepare_module_entry` gives piped
stdin its distinct strict Module goal and `ibex:stdin` metadata. Real-Hermes
tests execute TLA and non-TLA cases for `-e`, `-p`, REPL, `.load`, and stdin.
This evidence closes only the named bounded workstream: LLP 0024's structured
session protocol and composed session maps remain deferred exactly as above.

### 4. Reachability inventory and retirement matrix

CI enforces the end state with a checked-in **retirement manifest**:
generated from the current capsec inventory and symbol table, then
frozen; exact identifiers only — all **ten** current
`surface.loader.*.swc.*` IDs (five base plus five `.main`-suffixed
variants; digest tails make substring gates unsound) plus crate
names, symbols, cache tags, and env vars. The dependency end state is
enforced by a **new CI check over `cargo metadata`/`Cargo.lock`**
rejecting any resolved package whose name starts with `swc_`, per
retained profile — introduced by this program with its config checked
in (`cargo deny` bans identify exact crate names, not name-prefix
globs, so it can carry the enumerated known crates but cannot express
the prefix invariant by itself).

**4a. The file-at-a-time path is deleted, not taught parity.** With
every §4b consumer migrating to the module-runner producer or
retiring, no consumer needs a file-at-a-time engine; `require()` of
source files flows through the producer's CommonJS artifact path
(`commonjs_artifact_transform_fingerprint_v1`), preserving per-package
attribution. Deletion covers the path's full cache-namespace and
env-contract estate, each a manifest needle: `in-process-swc-v2`, the
retiring Oxc file-at-a-time tag (`in-process-oxc-0.121.0-v1`
successor), `loader-transpile-v14-content-addressed`,
`transpile-tool-directory-v1`, `subprocess-transpile-toolchain-v2`,
`subprocess-transpile-script`, the `in-process-transpile-engine`
selector namespace, and the path's env contracts
(`IBEX_TRANSPILE_CACHE_MAX_BYTES`,
`IBEX_TEST_TRANSPILE_INPUT_BARRIER`), each with a disposition (retire
or migrate to the producer cache's equivalent).

**4b. Consumers and dispositions:**

| Consumer | Today | Disposition |
|---|---|---|
| Entry TLA shim (the former `run_entry_with_tla_shim`) | migrated: advertised authenticated entries return through `SourceModuleGraphV1`; residual `run_legacy_entry_shim` receives prepared compatibility bytes and owns only argv/async wrapping, with no parser or file-at-a-time transform | Complete for the bounded window: no entry path calls `transpile_to_cjs`; the seven-test CLI runtime delta suite pins non-TLA/TLA routing, source-marker and stale-bytecode behavior, and raw `.cjs` passthrough including `this === module.exports`. Delete the residual wrapper with the compatibility loader at window close. |
| `contains_top_level_await` CLI text scanner | retired; its former shim, `ibex -e`, REPL/`.time`, unbundled-entry, and bundle-format readers share `script_frontend::analyze_script_syntax`, an Oxc-only syntax projection | The projection is not an execution-goal decision: `-e`/REPL lowering still moves to the LLP 0024 frontend after the hybrid goal is proven, and final bundle-format selection moves to producer metadata. Each rewiring keeps its own fixture row. |
| Snapshotless audit/diagnostic runtimes (no armed snapshot ⇒ compat evaluator, no window check) | live | Audit source execution migrates under the normative LLP 0030 audit-admission contract: an ephemeral foreground graph snapshot yields would-deny receipts and structurally cannot mint executable authority. V1 is source-inline only, accepts no prepared or HBC carrier, and accesses neither production nor diagnostic prepared-cache namespaces; its named fallback is explicit source-audit refusal. Principal/`SourceId`, denied/missing/cross-principal, protected-baseline, and target-advertisement fixtures gate acceptance before step 4. The repointed conformance runner runs under audit and depends on it. |
| `EXACT_COMPAT_TEST` fixture-fidelity (compat-harness polyfills, Bun test globals, process-identity shims) and the separate `IBEX_COMPAT_LOADER_TEST` preparation-bypass selector | split implemented; both live during the window | Retain `EXACT_COMPAT_TEST` as the compat harness's fixture-fidelity contract. Retire `IBEX_COMPAT_LOADER_TEST` with the compat loader. The generated retirement manifest binds every runtime producer/reader to its selector, semantic, exact occurrence count, and `retain`/`retire` disposition; CapSec closes the new selector as a harness startup surface. Repointed native runs still require execution receipts before window close. |
| `.hbc` entries and stale-bytecode source fallback | advertised authenticated source returns through the native producer before HBC selection; a stale legacy fallback reuses prepared bundle output or invokes the bounded Rolldown producer, never SWC | Migration complete; `.hbc` direct execution is unaffected, and the remaining legacy fallback retires with the compatibility window. |
| `EXACT_TRANSPILE_SCRIPT` subprocess override | live, own cache domains | Retired at window close with its cache namespaces (§4a list). Deprecation diagnostic during the window. |
| Handwritten host string transforms: `transpile_esm_to_script`, raw `import.meta`/`import(` rewrites, remaining Rust scanners in `mod.rs` | live for legacy bundle outputs | Retire with the legacy Rolldown-bundle pipeline at window close; named needles. Post-window bundle outputs are prepared-graph carriers. |
| Bootstrap module-loader string rewrites beyond the LLP 0019 scanner | live in compat loader | Retire with the compat loader; enumerated individually. |
| `IBEX_LEGACY_MODULE_LOADER` | fence toggle | Removed at 0.2 with the fence; manifest needle. |
| `--no-default-features` (non-`module-runner`) profile | CI-checked and CI-executed | `module-runner` becomes unconditional at 0.2; the non-runner profile is retired from CI. |
| Babel `--lower-classes` build stage | build-time only | Classified, retained (Non-goals); named out-of-scope in the manifest. |

Post-retirement execution paths are stated positively, with behavior
tests for TLA and non-TLA cases on each: file entries and stdin → the
module-runner producer; `-e`/`-p` and REPL/`.load` → the LLP 0024
session frontend (script surfaces; computed-import exclusion per §2);
audit → the audit-admission contract; `.hbc` → direct execution;
bundling → prepared-graph carriers; conformance and performance
runners → the native runner (§5).

**4c. Engine surgery** — once §4a/§4b land and §5 gates are green:
delete `enum TransformEngine`, the SWC arm, and the file-at-a-time
module; remove `IBEX_RUNTIME_TRANSFORM`/`EXACT_RUNTIME_TRANSFORM`
outright at 0.2 (no deprecation half-release; release notes + stable
error index entry; selector tests cover unset/`oxc`/`swc`/alias up to
the removal commit, plus a fixture that selector removal changes
nothing on the shim path, which never read it). Capsec sequencing:
generator/model update (Oxc-only discovery, authored route/classifier
inventory) lands before enum deletion; the complete catalog
regenerates; `check:capsec-registry` green is a retirement gate; the
`surface.loader.*.swc.*` IDs disappearing is the auditable record.
Remove all nine `swc_*` crates; `cargo deny` proves transitive
cleanliness. `already_lowered` comments rewritten.

**4d. Platform disposition — a named product decision.** Native
admission is advertised for `macos-aarch64` and `linux-x86_64`; window
close makes every other tuple refuse script entries, and the
compatibility evaluator today also serves audit and diagnostics on
those tuples, so the effect is broader than armed production. **Step 4
is blocked on an accepted platform Decision LLP** covering production,
audit, diagnostics, and runtime-TypeScript behavior on every retained
tuple — either advertising native artifacts per tuple or explicit
de-support — reconciling LLP 0001 and LLP 0026. CI requirements derive
from that matrix ("every advertised tuple", never a hard-coded pair).
The choice itself is the author's (§7).

### 5. Conformance gates, telemetry, and rollout

**Immediate 0.1 blocker, independent of everything else: Tier 3 typed
quarantine.** The native for-of rewrite is *actively rewriting*
hazardous shapes today — it wraps matching identifier-bound
`const`/`let` block loops into an ordinary-function IIFE with no
checks for `this`, `arguments`, `break`/`continue`/`return`, `yield`/
`await`, hoisting, or redeclaration (an earlier revision of this RFC
wrongly said such shapes were "left raw") — while the runner is the
production default. Every Tier 3 shape not provably handled with full
canonical-pass semantics is classified as a typed `LegacyRequired`
(quarantined) **now, in 0.1**, not as a precondition of the re-pin;
the divergence is recorded in LLP 0019 as a live, dated exception
until the passes land. Because this Draft cannot itself land code,
the quarantine is filed as its own immediately-actionable Linear
issue, independent of this document's review lifecycle, and step 0
merely records it as already tracked. No quarantine may be resolved *by deletion of
the fallback*: each quarantined row needs a landed pass or an explicit
unsupported disposition with a stable diagnostic code before step 4.

**Phase 0 (before the pin rotates):**

- The quarantine above, plus the **native Tier 3 runner**: a
  real-`ibex`-binary runner driving every applicable fixture through
  the native path with a test-only execution receipt (`SourceId`,
  semantic digest, fingerprint digest, carrier kind, producer digest,
  loaded Hermes digest), on real Hermes, per advertised tuple, source
  and prepared, in named required CI jobs.
- **The Hermes target matrix**: an exhaustive syntax → (pass | typed
  unsupported) matrix defining what the native producer promises —
  for-of and async generators, `for await`, `using`/`await using`,
  BigInt lowering (Hermes rejects literal syntax; the canonical pass
  exists), decorators, and source-map expectations — each row with
  real-binary source/prepared fixtures and a final window-close
  disposition. Decorators: the SWC path parses them; the Oxc
  fingerprint pins `decorators=off`; the matrix forces the normative
  choice (supported lowering vs. intentional 0.2 incompatibility with
  a stable diagnostic) — an author decision, registered in §7.
- **Behavioral transform corpus, first tranche** (extends the existing
  single-owner module-semantics corpus): enums, namespaces,
  `import =`, JSX runtime configuration, type-only edges, CJS/ESM
  interop, TLA, dynamic import/`import.meta`, diagnostics, composed
  source maps — on real Hermes, source and prepared.
- The retirement manifest (generated, frozen), old-identity goldens,
  the telemetry schema, and the CI matrix derived from §4d.

Implementation status on 2026-07-17: the Tier-3 quarantine, native runner,
and all target-matrix rows except the decorator decision are executable and
CI-wired. `config/llp0019-native-tier3-corpus.json` is exact over the owning
31-row corpus; `config/llp0019-hermes-target-matrix.json` is exact over the
named syntax families. The pre-advertisement runner uses a debug-only CapSec
conformance constructor that retains production engine/artifact/root
authentication and bounded project/stdout authority while skipping only
report-derived target promotion. Release builds and ordinary host
construction cannot select it. The first behavioral-transform tranche also
extends LLP 0007's existing single-owner `module-semantics-corpus.mjs` rather
than creating a parallel fixture authority: twelve rows pass 24/24 through
the real binary and Hermes across source and prepared profiles, with execution
receipts on success and explicit no-receipt refusals for diagnostics and the
sloppy-CommonJS CapSec delta. Its composed-map row covers the authenticated
factory-relative map plus prepared-carrier generated-line offset.

The old-pin/new-pin dual-produce gate is now reproducible in CI and archived as
the content-addressed `ibex/oxc-old-new-dual-produce-report/1` artifact under
`llp/evidence/`. Its precommitted projection found one malformed, out-of-range
source-map segment already present in the immutable Oxc 0.121 producer. The
original contract remains recorded as failed for that old-side invariant; the
current producer clamps synthetic expansion lines to their statement's final
real source line, has zero map defects, and pins the repair with a regression
test. The disposition gate accepts only that exact retired old row. Across the
rotation, canonical semantic metadata is byte-identical, generated factory
bytes are identical, all 12 fixtures pass independently on the same real
Hermes binary, and every source-map precision/layout difference is enumerated.

`LegacyRequired` telemetry is now structured as
`ibex/legacy-required-telemetry-event/1` and aggregated into the deterministic
`ibex/legacy-required-telemetry-report/1` envelope. Events bind the stable
category/shape/code to canonical module identity, original-source location,
and runtime version. The report states its controlled/advisory population
boundary, binds the authenticated fixture tree and event stream by digest, and
includes a pinned-Oxc syntactic upper-bound denominator. The checked Ibex
native population passed 22/22 with eight events; its content-addressed report
is under `llp/evidence/`. No Snapback phase-1 population is a window-close
prerequisite; representative downstream authenticated module graphs may be
added as advisory evidence when such an Ibex consumer exists.

**Telemetry (advisory, honestly bounded).** The compat loader's
`LegacyRequired` diagnostic gains a typed event (stable category enum
covering all shapes, module, original-source site, runtime version).
Populations: CI test/fixture runs and representative authenticated downstream
module graphs — **controlled test populations, not field usage of
released binaries**, and the RFC says so; the stable invocation-time
error with its error-index entry is the safety net for unobserved
field usage. As a denominator, the program adds **static scans of
authenticated dependency graphs** (computed-`require`/computed-import
occurrence counts across the corpus of real dependency trees CI
already builds). Decision rule: the archived report (events + static
scan) goes to the author before window close; zero observations across
both channels supports fail-closed dispositions, nonzero returns the
relevant §2 decision with evidence. The telemetry is labeled advisory
— the computed-`require` disposition is registered in §7 as an
explicit 0.2 compatibility decision either way.

**Rollout order** (per-step Linear issues under a new program issue in
the Exact project; LLP updates land in the same commits):

0. Tier 3 quarantine (immediate) + Phase 0 freeze (above).
1. Toolchain bump + Oxc re-pin, atomic with the canonical
   transform-configuration manifest and rotation goldens (§1); gates:
   Phase 0 corpora + performance envelopes + archived dual-produce
   report. Audit-admission Spec drafted by end of this step (§4b).
2. Candidate tables (manifest-authored, sidecar carrier, site tables,
   ABI site-plumbing with its fingerprint rotation) — scope confirmed
   or resequenced by the §7 evidence decision; invocation-class
   errors for computed `require` and options; failure-taxonomy
   fixtures; LLP 0014/0027 revisions landed.
3. LLP 0024 revision (full seam per §3) + archived scoped differential
   + Hermes-acceptance check.
4. Window close at 0.2 — blocked on the accepted platform Decision
   (§4d), the accepted audit-admission Spec, the landed minimal Oxc
   script frontend (§3) with its fixtures, the archived telemetry
   report, and every quarantine row resolved — plus §4b migrations,
   `module-runner` unconditional, Tier 2 removal, runner repoints,
   `EXACT_TRANSPILE_SCRIPT` and string-transform retirement.
5. Engine surgery per §4c.

**Release coupling, stated:** the window fence is keyed on the
version string (`0.1`), so any 0.2 release mechanically closes the
window whether or not steps 0–3 have landed. The policy is therefore
explicit: **0.2 is release-blocked on the step-4 gates**; if 0.2 must
ship earlier for an unrelated reason, the fence constant is revised
to the next minor in the same commit as `Revised:` entries to LLP
0009/0026 recording the extension — an author decision (§7), never a
silent side effect of shipping.

Reconciliation: LLP 0009 gains its `Revised:` pin entry and moves to
**Superseded by this RFC** for the transform-scope question (its
historical rationale preserved); LLP 0019 revised to the two-tier end
state (quarantine exceptions recorded, then cleared); **LLP 0007
revised and moved to its terminal lifecycle state** (Superseded or
Tombstoned with rationale — its SWC-default, fallback-window, and
decorator questions are resolved by this program; the precise outcome
is picked in the revision itself, not left as "closed"); LLP 0024 per
§3; LLP 0026 gate-status and computed-`require` revisions; LLP 0001,
0014, 0027 per §2/§4d.

## Acceptance criteria

- Zero `swc_*` in `Cargo.toml`; zero resolved `swc_*` in `Cargo.lock`
  per retained profile (the §4 `cargo metadata` prefix gate);
  retirement manifest and `check:capsec-registry` green.
- §5 corpora and the Hermes target matrix pass on real Hermes for
  **every advertised tuple** (per the accepted platform Decision),
  source and prepared, native path, execution receipts asserted, in
  named required CI jobs.
- LLP 0024 revision landed (full seam); scoped differential archived.
- Candidate tables: producer site tables + manifest join + sidecar
  landed (or the author-approved resequenced plan recorded); computed
  `require` and unknown options fail at invocation with stable errors;
  taxonomy fixtures pin all three classes; two-site non-escalation and
  cross-domain rotation fixtures pass.
- The archived telemetry + static-scan report exists and its §7
  decisions are recorded.
- One transform-configuration manifest governs engine construction,
  fingerprint, cache tag, and receipts; rotation goldens pass for
  every output-changing phase.
- The platform Decision and audit-admission Spec are accepted and
  landed; every Tier 3 quarantine row is resolved by pass or by
  documented unsupported disposition.
- The LLP 0048 external-script profile and the general module runner both
  derive identity from this RFC's canonical Oxc configuration manifest; the
  narrower profile adds a domain-separated profile component rather than a
  second transform authority.

## Alternatives considered

- **Keep a parser-only SWC dependency** — rejected; the archived
  differential buys the assurance once, without a retained dependency.
- **Gate SWC deletion on building the LLP 0024 session stack** —
  rejected; no SWC session implementation exists, LLP 0026 §3 allows
  contract revision, and the *revised seam* (not the implementation)
  is the gate.
- **Teach the file-at-a-time Oxc candidate TLA/ESM parity** —
  rejected; no consumer remains after §4b; deletion over parity.
- **Package-closure candidate maps as default** — rejected;
  explicit-manifest is default, closure is opt-in with `--check`
  review.
- **In-source glob declarations in v1** — deferred; a new language
  surface with independent grammar/trust questions; manifest
  declarations serve the known patterns.
- **Support computed `require()` now via the sync-drive machinery and
  the LLP 0014 JSON channel** — deferred with a named reopening
  design; evidence-gated 0.2 decision (§7).
- **Wait for Rolldown wholesale** — rejected; the runtime path needs
  only the Oxc set; coupling deletion to Rolldown's cadence buys
  nothing.
- **Close the window without native computed dynamic import** — was held open
  as a real evidence-gated option (§2, §5); not selected once the independent
  Ibex 0.2 candidate-table implementation landed. Snapback is not used as the
  rationale.

## Author-decision register (§7)

Decisions this RFC surfaces but does not make; each blocks the step
noted:

1. **Resolved 2026-07-18 — platform matrix at 0.2:** LLP 0031 selects
   `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` as the intended
   evidence-gated native tuples and explicitly de-supports source/module
   execution elsewhere until independently promoted.
2. **Resolved 2026-07-18; rationale corrected 2026-08-03 — computed dynamic
   import sequencing:** implement candidate tables as an Ibex 0.2
   module-runner capability. The complete step-2 scope is implemented. The
   former statement that Snapback LLP 0062 required it was incorrect: that
   RFC creates no phase-1 Ibex dependency, and LLP 0048's post-phase-1
   external-script profile is import-free.
3. **Resolved 2026-07-18 — computed `require` at 0.2:** keep the
   invocation-time fail-closed disposition; the JSON-channel candidate design
   remains deferred.
4. **Resolved 2026-07-18 — decorators after retirement:** intentional 0.2
   incompatibility with the stable typed diagnostic; no lowering pass is
   added.
5. **Resolved 2026-07-18 — scope split:** audit admission remains the
   standalone LLP 0030 Spec and enters formal review; the candidate-table
   contract stays in the coordinated LLP 0014/0026/0027 revisions rather than
   creating another Spec.
6. **Resolved 2026-07-18 — fence extension:** do not extend the 0.1 fence.
   Hold 0.2 until the step-4 gates pass.

## Open questions

- Exact re-measured Rust/Oxc pins; pin-rotation cadence Guide.
- SWC diagnostics-text dependence (mapped diagnostic-code table vs.
  free rewording).
- Where the behavioral transform corpus lives (LLP 0007's successor
  fixture matrix vs. a new numbered LLP).
- The Oxc mechanism for LLP 0024's hybrid source goal (owned by the
  LLP 0024 revision).
- Sidecar sizing for opt-in closure tables (Merkle-proof variant vs.
  full rows) in route-table-shaped packages.
