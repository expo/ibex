# LLP 0021: Capability Security Effect-Model Migration

**Type:** Plan
**Status:** Draft
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-10
**Related:** LLP 0002 (host ABI); LLP 0004 (module loading); LLP 0005 (generated build artifacts); LLP 0013 (per-package enforcement mechanics); LLP 0014 (import-site grants and generated policy); LLP 0016 (architecture assessment); LLP 0020 (Oden portability research); Oden LLP 0019 (Capability Security, Revision 2); Oden LLP 0020 (Capability Security by Default); ENG-24143

## Summary

Ibex will replace its current string-based capability policy plane with the
effect-oriented model developed in Oden. The existing enforcement substrate
remains: runtime-instance isolation, per-package principals, native compartment
globals, lockdown, frame-derived attribution, import gating, and
authority-bearing attenuated handles. The replacement is above that substrate:
typed effects, generated coverage and conformance data, typed policy artifacts,
explicit resource semantics, and a fail-closed armed runtime snapshot.

This is a direct cutover, not a compatibility migration. Ibex has no external
users whose committed policies or CLI workflows need preservation. The project
will therefore not build a frozen legacy oracle, dual-profile runtime, policy
translator, or deprecation period. Current policy files, permissive defaults,
and weakening flags are development-state implementation details that may be
deleted as soon as their replacements work.

The destination has these properties:

1. The unit of mediation is a normalized **effect**, not a capability string
   attached one-to-one to an API. One operation may require several effects,
   and all must authorize before the corresponding effect occurs.
2. Capability definitions, surface-to-effect coverage edges, target
   conformance cells, and policy/classifier rules are generated datasets with
   deterministic drift checks.
3. Policy moves one way through **authored source → canonical review policy →
   armed snapshot**. Only the armed snapshot is consumed by the engine.
4. Canonical positive authority uses explicit actions and typed resources.
   Paths, endpoints, routes, ports, peer classes, executable identities, and
   other resource kinds are not overloaded colon-delimited strings.
5. Policy and runtime semantics are bound by profile, vocabulary, registry,
   policy, and armed-snapshot digests.
6. Every authority-bearing runtime surface is classified and tested. A surface
   is enforced, deliberately closed, absent, unsupported, or explicitly a
   non-capability; there is no unclassified production surface.
7. Normal `ibex` execution enforces the complete supported profile by default.
   Missing policy means empty dependency authority, not permissive execution.
   A target that cannot support the profile refuses before project code.

This plan is complete only when the old matcher and policy format are gone, the
default command cannot silently weaken the posture, and every advertised target
has a generated conformance report proving the profile it claims.

## Motivation

LLP 0013's mechanism work substantially exists and remains the right substrate,
but the policy plane has accumulated ambiguity that the Oden work made
concrete:

- `PolicyFile` accepts unversioned arrays of capability strings. Matching,
  resource grammar, action implication, and future vocabulary growth are
  implicit in handwritten code.
- The current shape encourages one operation to check one capability even when
  the operation discloses, reads, writes, connects, redirects, spawns, or
  delegates through several independently meaningful effects.
- Generated import-site policy is reviewable, but the artifact does not
  cryptographically bind the exact vocabulary, normalization semantics,
  surface classification, target support, or runtime bindings it relies on.
- Filesystem and network authorization can be separated from the OS object or
  final peer used after the check. String-level authorization alone cannot
  express retained-object, redirect, DNS rebinding, proxy-route, or staged
  authorization semantics cleanly.
- Enforcement completeness depends heavily on remembering to classify each new
  native, loader, builtin, callback, inspector, process-global, or resource-use
  surface. Oden demonstrated that this should be a generated inventory and CI
  invariant.
- The current CLI makes permissive execution the implicit no-policy default and
  exposes public weakening paths. That is the wrong long-term identity for a
  runtime whose defining distinction is package-level capability security.

Because Ibex has no external consumers yet, the usual reason to preserve these
semantics—migration cost—does not apply. The lowest-risk long-term choice is to
change direction now, before examples, embedders, and policies harden around the
intermediate model.

## Decision boundary

### Retained from LLP 0013 and LLP 0014

- Runtime instances remain the outer trust-domain boundary.
- Integrity-bound package principals remain the package-layer subjects.
- Hermes frame attribution and schedule-time principal capture remain the
  unforgeable source of acting-principal identity.
- Native per-package compartment globals and lockdown remain the reachability
  and shared-intrinsic integrity layer.
- Import gating and compartment endowments remain defense in depth; making an
  API unreachable never substitutes for checking its effect when reachable.
- Passed, attenuated handles remain the primary voluntary delegation channel.
- Import-site grants in root-principal code remain the concise grant-authoring
  surface, with package-authored declarations treated as requests rather than
  grants.
- Root and runtime-internal principals remain explicit identities rather than
  attribution fallbacks. Missing attribution continues to deny.

### Replaced

- `PolicyFile` as an unversioned bag of string lists.
- A single handwritten capability manifest serving simultaneously as public
  vocabulary, matcher input, implementation inventory, and conformance claim.
- Colon-delimited capability strings as the canonical review or engine format.
- Implicit action derivations and positive wildcards whose meaning can grow as
  the vocabulary grows.
- One-operation/one-check reasoning.
- Check-then-reopen filesystem and check-requested-host-only network semantics.
- A committed durable `audit` or `permissive` policy mode.
- Default permissive execution, `--allow-all`, public permissive execution,
  advisory-attribution execution, environment-selected weakening, and
  enforce-without-required-lockdown behavior on the normal production command.

### Deferred above the core

The following Oden work is not required to complete this migration: AI-assisted
grant proposal conversations, protected authorization receipt workflows,
isolated candidate publication, daemon migration, and report-artifact privacy.
The core must expose authenticated typed evidence those systems could consume,
but Ibex does not need to copy Oden's complete product workflow.

## Target model

### Effects and decision sets

A **surface** is a JavaScript API, loader path, builtin, native op, startup
route, callback, or other entry point. A generated **coverage edge** maps a
surface to one or more normalized effects and identifies the enforcement gate,
principal source, normalization rule, authorization stage, and fixture set.

An **effect occurrence** contains the runtime facts needed to decide one
authority-bearing action. A policy row contains an **authority selector** over
such occurrences. Runtime observations such as a selected DNS candidate or file
identity never become reusable authored authority.

All effects in one decision set are conjunctive. An operation may proceed to a
stage only after every effect knowable at that stage is allowed for every
non-transparent constrained principal. Later discoveries—symlink targets, DNS
candidates, redirects, proxy routes, accepted peers—pause the operation and
authorize the next stage before committing it. Missing required facts,
unclassified surfaces, missing attribution, unknown definitions, and unsupported
target cells deny or refuse arming.

### Generated semantic datasets

The implementation has four generated inputs:

1. **Capability definitions** — action identity, selector and occurrence
   schemas, normalization, authoring disposition, delegation/dynamic behavior,
   and risk metadata.
2. **Coverage edges** — surface inventory, effects, principal/effect-owner
   source, gate, stages, lifetime/recheck obligations, and stable identifiers.
3. **Backend/target conformance cells** — implemented disposition and required
   fixtures for each coverage edge on each supported target/profile.
4. **Policy and classifier rules** — derivations, non-capability rationales,
   decision precedence, protected resources, risk promotion, route/address
   classes, and other decision-affecting data.

Generated Rust, C++, JavaScript/TypeScript, JSON schemas, documentation tables,
and fixtures consume these sources. Handwritten duplicate matcher tables are
not authoritative. Drift is a build/CI failure.

### Policy forms and digests

Policy has three forms:

1. **Authored source** may use import-site syntax, aliases, macros, logical
   paths, and package selectors.
2. **Canonical review policy** contains explicit actions, typed resources,
   integrity-bound principals, explicit derivations, and reproducible logical
   bindings. It is the artifact a human reviews and may commit.
3. **Armed snapshot** binds the canonical policy to one execution: engine
   target, generated registry, effective mode, canonical host objects and paths,
   final route constraints, process-wide ceiling, protected guards, package
   graph, root identity, and immutable runtime generations. It is the only form
   the decision engine consumes.

The exact profile name and digest encoding are settled in the semantic-spec
work item. The design must distinguish at least vocabulary semantics, complete
registry/conformance provenance, canonical policy, and armed snapshot. A stale
or mismatched digest refuses arming. Duplicate keys, unknown positive actions,
unresolved selectors, aliases, macros, and machine-specific unbound paths may
not reach the armed snapshot.

### Default execution contract

Normal project-code execution uses enforce mode. Absence of authored grants
produces empty package floors and closed dynamic ceilings; it does not select a
weaker mode. Lockdown, per-package attribution, compartment globals, and full
deputy intersection are required structural posture rather than independently
disableable policy preferences.

Audit remains a purpose-specific foreground diagnostic workflow. Permissive
behavior may exist in isolated tests or a separately named developer harness,
but it is not a mode of ordinary `ibex run`. Embedders must select an explicit
supported profile and successfully arm it; the legacy host constructor must not
silently create a production runtime that claims package security while running
permissively.

## Implementation plan

The work is organized around stable work packages so Linear tickets can remain
connected to this document even if ticket titles or implementation details
change. Each package lands tests and generated outputs with its code; a later
phase does not postpone testing an earlier one.

### WP0 — Freeze the target semantics and registry contract

Define the Ibex destination vocabulary and the schemas for capability
definitions, effects, authority selectors, effect occurrences, coverage edges,
target cells, policy rules, canonical policy, and armed snapshots. Adapt Oden's
semantics deliberately rather than copying Oden/Deno-only surface rows.

Decide the initial disposition of every existing Ibex capability: authorable,
deny-only/closed, absent, unsupported, or non-capability. Settle exact versus
tree path semantics; fetch/connect/listen/resolve endpoint resources; process,
stdio, inspector, storage, device, crypto, and runtime-internal categories; and
which rows are terminal, static-only, handle-delegable, or dynamically
acquirable.

Acceptance:

- Schemas and canonical examples cover every initial authorable resource kind.
- Every current capability bit has an explicit destination disposition.
- Positive action wildcards and untyped canonical strings are impossible.
- Decision precedence, principal intersection, staged effects, handles,
  revocation, caching generations, and digest domains are specified.

### WP1 — Generate the registry and completeness inventory

Implement the four generated datasets, code generation, drift checking, and the
surface inventory. Seed the inventory from native host calls, loader branches,
builtin exports, startup/inspector paths, callback queues, and resource families.

Acceptance:

- Every inventoried surface has exactly one coverage edge or explicit
  non-capability/closed classification.
- Adding an unclassified surface or unknown capability fails generation/CI.
- Generated bindings and documentation are byte-reproducible.
- Target cells begin honestly as unsupported/closed until fixtures prove more.

### WP2 — Implement the typed policy and decision core

Replace string parsing and matching with the typed Rust semantic core. Implement
canonicalization, deterministic serialization, digest computation, decision
precedence, conjunctive decision sets, staged decisions, principal
intersection, negative generations, and cache keys.

Acceptance:

- Property and differential tests cover canonicalization and matcher behavior.
- Unknown/malformed definitions fail in every mode.
- Adding a future vocabulary action cannot widen an existing positive policy.
- The decision core consumes normalized typed effects, never authored strings.

### WP3 — Rebuild policy generation and import-site authoring

Adapt LLP 0014's import-site generator to emit authored-source inputs and the
typed canonical review policy. Preserve provenance, root-only grant authority,
request/delegation intersection, union across authorized root import sites, and
explicit import/endowment surfaces.

Acceptance:

- Generated policy contains every package in the integrity-bound graph.
- Every grant has source/delegation provenance.
- Package code cannot self-grant through import attributes or manifests.
- Drift reporting distinguishes authority expansion, narrowing, and semantic
  vocabulary changes.

### WP4 — Arm immutable snapshots through the CLI, host, and engine

Build the trusted arming pipeline that binds canonical policy to an execution
and hands the authenticated immutable snapshot to the host/engine. Report the
actually loaded profile and digests from the decision context.

Acceptance:

- The runtime refuses before project code on stale/mismatched policy, registry,
  engine target, package graph, or required target cell.
- Mutable authored files and environment variables are not consulted after
  arming.
- Audit, denial, handle, and dynamic-permission records carry the loaded
  semantic identity and snapshot generation.

### WP5 — Convert filesystem effects and checked-object execution

Map all filesystem surfaces to explicit list/read/write/watch effects and typed
exact/tree resources. Replace check-then-reopen paths with retained handles or
verified post-open identities, including symlink, hard-link, rename, metadata,
special-file, and platform alias behavior.

Acceptance:

- Multi-effect operations authorize every disclosure/read/write stage.
- Symlink/hard-link/TOCTOU fixtures operate on the object actually used.
- File descriptors and handles retain owner, authority source, revocation
  generation, and resource identity for repeated operations.

### WP6 — Convert network effects and protected peers

Map fetch, raw/bidirectional connect, listen, and standalone resolve to separate
typed resources. Authorize requested endpoint, selected candidates, redirects,
reconnects, routes/proxies, listeners, and final verified peers at their stages.
Add an engine-level protected metadata-peer guard with only an exact loud
exception if Ibex needs one.

Acceptance:

- DNS rebinding, mixed answers, numeric aliases, redirects, WebSocket/raw
  transport, proxy, reconnect, and private/metadata peer fixtures pass.
- A fetch grant never yields raw transport authority.
- A hostname grant cannot silently reach a denied address class or port.

### WP7 — Close loader, process, inspector, stdio, and escape surfaces

Classify and gate typed local imports, dynamic imports, builtin loading,
subprocesses, executable identity, child environment/stdio, inspector routes,
process-global mutation, workers, VM/eval, WASI, FFI/native addons, storage, and
runtime inspection. Unsupported authority is closed rather than represented by
a token the runtime cannot enforce.

Acceptance:

- Static, literal-dynamic, computed, text/JSON/bytes, and CJS loader paths have
  explicit coverage.
- Inspector and runtime-memory surfaces cannot bypass package isolation.
- Terminal capabilities cannot be dynamically granted or delegated through an
  ordinary handle.
- Closed rows have denial/absence fixtures on every advertised target.

### WP8 — Port handles, dynamic authority, and audit evidence

Rebase attenuated handles, revocation cascades, dynamic permission ceilings,
change signals, deputy intersection, and audit output onto typed effects and the
armed snapshot. Distinguish effect actor, effect owner, authority source, and
constrained principal set.

Acceptance:

- Possession-based delegation remains usable without becoming ambient authority.
- Revocation invalidates caches, derived handles, and live/repeated operations.
- Dynamic grants cannot exceed the canonical static ceiling or apply to
  static-only/closed definitions.
- Evidence groups denials without losing loaded-policy or effect provenance.

### WP9 — Make complete enforcement the default and remove weakening paths

Flip ordinary CLI execution and embedding defaults only after WP4–WP8 cover the
required initial profile. Remove or quarantine legacy policy parsing, public
permissive execution, `--allow-all`, advisory attribution, environment-selected
weakening, durable audit mode, optional lockdown under enforce, and permissive
legacy host construction.

Acceptance:

- Plain `ibex run` and an explicit enforce affirmation arm identical policy and
  make identical authority decisions.
- Missing policy yields empty dependency authority under enforce.
- Missing/incomplete prerequisites refuse before project code.
- Audit is a visibly separate diagnostic workflow and cannot become durable
  production posture.

### WP10 — Prove targets and publish the conformance report

Build the generated cross-target conformance report and run the red-team suite
for each advertised target. Exercise the real Exact/Snapback graphs and the npm
compatibility corpus as product-quality evidence, not as a reason to preserve
the old policy format.

Acceptance:

- Every authorable edge has positive, negative, wrong-principal, malformed,
  missing-attribution, and target-specific fixtures.
- Multi-effect, lifetime, revocation, loader, filesystem, network, process, and
  escape-surface suites pass on every advertised target.
- The report binds source revision, engine identity, target, profile, semantic
  and registry digests, fixture catalog, and observed results.
- Unsupported targets do not advertise or silently degrade the complete profile.

### WP11 — Reconcile the corpus and remove the legacy plane

Update LLP 0013 and LLP 0014 to describe the final mechanism and artifact,
revise LLP 0016's assessment, update LLP 0002/0004/0005 where their contracts
change, refresh demos and documentation, and delete dead code/generators/tests
for the legacy plane.

Acceptance:

- `./ref-check` passes and all capsec `@ref`s point to current semantics.
- No documentation teaches permissive-by-default or the legacy string format.
- No production path parses or executes the legacy `PolicyFile` model.
- The root LLP and implementation-status sections identify the supported
  profile and current target conformance honestly.

## Dependency order

The executable dependency graph is:

```text
WP0 ─┬─> WP1 ────────────────┐
     └─> WP2 ─> WP3 ─> WP4 ─┼─> WP5 ─┐
                            ├─> WP6 ─┤
                            ├─> WP7 ─┼─> WP9 ─┐
                            └─> WP8 ─┘        ├─> WP11
WP1 ────────────────────────────────> WP10 ───┘
WP5, WP6, WP7, WP8 ─────────────────> WP10
```

WP5–WP8 are intentionally parallel once the typed core and armed-snapshot seam
exist. WP10 begins with registry/fixture infrastructure during WP1 and closes
only after every enforcement workstream lands. WP9 is the product cutover, not
the point at which enforcement work starts. WP11 removes the old plane only
after both cutover and conformance are green.

## Linear execution contract

Each WP maps to one child issue beneath an umbrella issue. Issues use Linear's
blocking relations to encode the graph above and belong to the Exact project.
Every issue description must include:

- this LLP and its WP anchor;
- the exact in-scope surfaces and explicit exclusions;
- acceptance criteria copied or strengthened from the WP;
- required tests and generated artifacts;
- the LLPs and existing `@ref`s that govern its files;
- a rule that semantic/code changes update the governing LLP in the same commit.

The umbrella issue tracks the overall completion gate but is not a substitute
for dependency relations. The created issue set is:

| Work package | Linear issue | Blocked by |
|---|---|---|
| Program | ENG-24143 | completion is defined by the child graph |
| WP0 | ENG-24144 | — |
| WP1 | ENG-24145 | ENG-24144 |
| WP2 | ENG-24146 | ENG-24144 |
| WP3 | ENG-24147 | ENG-24146 |
| WP4 | ENG-24148 | ENG-24145, ENG-24147 |
| WP5 | ENG-24149 | ENG-24148 |
| WP6 | ENG-24150 | ENG-24148 |
| WP7 | ENG-24151 | ENG-24148 |
| WP8 | ENG-24152 | ENG-24148 |
| WP9 | ENG-24153 | ENG-24149, ENG-24150, ENG-24151, ENG-24152 |
| WP10 | ENG-24154 | ENG-24145, ENG-24149, ENG-24150, ENG-24151, ENG-24152 |
| WP11 | ENG-24155 | ENG-24153, ENG-24154 |

## Risks and controls

### Scope expansion

The Oden corpus contains product workflows far beyond Ibex's core needs.
Deferring grant-assistant, publication, daemon, and privacy systems keeps this
plan focused. New product surfaces must justify themselves independently.

### A typed model that remains incomplete

Schemas alone do not create security. Generated surface inventory and target
cells land before broad conversion work, and target claims stay closed until
fixtures prove each edge.

### Big-bang cutover instability

The external cutover is direct, but implementation is staged behind internal
seams. The typed decision core, generator, and armed snapshot land before
surface conversions; filesystem/network/escape/handle work then proceeds in
parallel. The legacy plane is deleted only at the end.

### Cross-project drift with Oden

Ibex should reuse runtime-neutral schemas, canonicalizers, property fixtures,
and Rust decision logic where practical, but not force Deno-specific vocabulary
or product workflow into Hermes. Shared components need one source of truth and
cross-repo fixture parity; target-specific coverage edges remain local.

### Default enforcement before evidence

Having no external users removes migration constraints, not the need for
correctness. WP9 remains gated on complete initial enforcement and WP10 remains
the release/claim gate. Development can exercise the new default earlier, but
unsupported targets may not silently claim completion.

## Completion criteria

This plan is complete when:

1. The typed effect model is the only production policy and decision plane.
2. Every production surface has a generated classification and target cell.
3. Canonical policy and armed snapshots are deterministic, typed, digest-bound,
   and fail closed on mismatch.
4. Filesystem and network checks bind the object/peer actually used, with
   staged multi-effect authorization.
5. Handles, dynamic authority, deputy intersection, import gating, and audit
   evidence operate on the same immutable effect semantics.
6. Plain `ibex` execution enforces the supported profile and offers no silent
   weakening path.
7. Every advertised target has a passing generated conformance report.
8. Legacy policy code, docs, demos, and stale LLP claims are removed or revised.

## Open questions

1. Should the runtime-neutral semantic core live in Ibex, Oden, or a small
   shared repository/crate? WP0 must choose one owner before both projects add
   generated consumers.
2. Should the profile be named `ibex/capsec/1`, reflecting Ibex's first public
   contract, or `ibex/capsec/2`, reflecting semantic kinship with Oden Rev2?
   The number has no compatibility burden, but cross-project diagnostics benefit
   from an obvious family relationship.
3. Which device capabilities are in the initial complete server/desktop profile,
   and which remain target-specific or closed until embedder broker semantics are
   specified?
4. Does the standalone Ibex CLI need a separately named raw developer harness,
   or are unit/integration fixtures sufficient for permissive compatibility
   investigation?
5. Which target subset must be complete before WP9 flips the repository default:
   macOS development only, or every currently buildable production target? The
   final public claim remains per-target regardless.
