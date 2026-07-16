# LLP 0021: Capability Security Effect-Model Migration

**Type:** Plan
**Status:** Draft
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-10
**Revised:** 2026-07-16 (ENG-24933 removes thirteen closed memory-debug implementation surfaces by capturing diagnostic state behind its deliberate API)
**Revised:** 2026-07-16 (ENG-24933 removes ten closed internal locale/accessibility state surfaces by retaining mutable state in module singletons)
**Revised:** 2026-07-16 (ENG-24933 completes malformed, missing-attribution, and wrong-principal scenarios for bounded loopback TCP connect)
**Revised:** 2026-07-16 (ENG-24933 completes thirty-six malformed, missing-attribution, and wrong-principal scenarios for system information, environment, and stdout)
**Revised:** 2026-07-16 (ENG-24933 closes twelve malformed, missing-attribution, and wrong-principal scenarios for retained metadata and whole-file reads)
**Revised:** 2026-07-16 (ENG-24933 binds direct `statfs` metadata to retained typed `fs:list` authorization and closes five exact public scenarios)
**Revised:** 2026-07-16 (ENG-24933 binds asynchronous `chmod` and `utime` to retained files, repeats authorization on the worker, and closes twelve exact public scenarios with owned cleanup)
**Revised:** 2026-07-15 (ENG-25062 registered the module-runner factory, record, CJS-to-ESM edge, generation-lease, and compatibility-marker surfaces as closed non-capability control-plane operations)
**Revised:** 2026-07-15 (ENG-25066 made the authenticated graph decision set and process-stable principal projection the ordinary-ESM execution path)
**Revised:** 2026-07-15 (LLP 0026 adoption defines the module-initialization task boundary and trusted-loader source-acquisition classification)
**Revised:** 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the Exact-bound artifact preparer while preserving empty advertisements); 2026-07-14 (ENG-24933 introduces the dedicated binary Exact app/agent ingress while preserving the unadvertised Apple target and records the remaining artifact/conformance gate); 2026-07-12 (ENG-24263: the complete exact-engine prerequisite matrix and artifact evidence now run in CI, which requires the incomplete candidate to remain unadvertised rather than treating expected refusal as conformance); 2026-07-12 (ENG-24278 bounds POSIX TCP/UDP repeat work with socket-identity, exact-peer/destination, principal-set, and mutable-generation leases); 2026-07-12 (post-cutover security review hardened WP3–WP5: exact package content/graph roots and import edges, checked digest/set invariants, actual-engine and runtime-scoped arming, complete closed-startup controls, race-safe retained filesystem objects, analysis-byte/package-tree joining, and content-addressed report-derived target advertisements; the current registry still advertises no executable target — ENG-24232 through ENG-24281); 2026-07-12 (ENG-24233/24239/24247/24249–24253 remediate conformance evidence, policy identity, selector constraints, generation publication, atomic evidence, drift classification, package-root ceilings, and descriptor authorization leases); 2026-07-12 (ENG-24267/24268/24273/24276/24278/24280 align canonical ordering and mapped-IP semantics, harden generators, correct RFC 8785 numbers and staged decisions, and bound repeat-stage work); 2026-07-12 (ENG-24462/ENG-24465 bind filesystem occurrences separately to every constrained principal and protect every authenticated package subtree lexically against writes; ENG-24464 makes production run nonces construction-fresh; ENG-24466 explicitly closes diagnostic file execution in the advertised registry pending authenticated ingress); 2026-07-11 (WP0 semantic contract frozen by ENG-24144: profile, 38-action vocabulary, 57-bit reconciliation, typed occurrence/containment semantics, digest projections, and enforce-default target rule); 2026-07-11 (WP1 generated source-surface inventory, production registry, unsupported target matrix, and cross-language bindings implemented by ENG-24145); 2026-07-11 (WP2 typed Rust policy and decision core implemented by ENG-24146 with strict contract ingestion, canonicalization/digests, typed containment, decision precedence, staged conjunction/intersection, generations, and exact cache identities); 2026-07-11 (WP3 typed ESM/CJS import authoring and integrity-bound canonical generation implemented by ENG-24147); 2026-07-11 (WP4 strict immutable snapshot ingestion, production CLI arming, and explicit host/Hermes digest handshake implemented by ENG-24148); 2026-07-11 (WP5 initial retained checked-object record plus exact logical-branch schema and filesystem branch migration in progress under ENG-24149); 2026-07-11 (WP6 retained verified-peer record, metadata-peer denial, and exact logical network branch migration landed under ENG-24150, with runtime typed gates and red-team coverage still pending); 2026-07-11 (WP7 deny-only escape/process catalog invariant plus exact loader, process, stdio, environment, and host-default branch migration landed under ENG-24151, with runtime gates and red-team coverage still pending); 2026-07-11 (WP8 structured decision evidence, exact Android media-operation branches, and immutable snapshot-to-verified-decision-context arming landed under ENG-24152, with live handles/grants/deputy gate migration still pending); 2026-07-11 (WP10 exact-target report schema and fail-closed execution-evidence binding introduced by ENG-24154; the macOS candidate remains unadvertised pending complete executed fixtures)
**Related:** LLP 0002 (host ABI); LLP 0004 (module loading); LLP 0005 (generated build artifacts); LLP 0013 (per-package enforcement mechanics); LLP 0014 (import-site grants and generated policy); LLP 0016 (architecture assessment); LLP 0020 (Oden portability research); LLP 0026 (module-runner authority amendments); Oden LLP 0019 (Capability Security, Revision 2); Oden LLP 0020 (Capability Security by Default); ENG-24143

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

Coverage edges contain semantic data only. A separately generated
`implementation-manifest.json` joins each edge to source-derived definitions,
stubs, or security-relevant references, the later work package that owns its
gate, fixture obligations, and content digests for generated outputs. Those
references are inventory evidence, not conformance evidence; only executed
fixtures can promote a target cell.

An effect edge is normally `conjunctive`. WP1 may record a known
parameter/provenance-dependent surface as `conditional-unrefined` only while
every corresponding target cell remains `unsupported`; the edge names its
refinement owner and why its possible effect set is not yet executable. Such an
edge cannot be promoted or armed. The owning filesystem, network, process, or
device work package must replace it with exact conjunctive logical branches
before conformance.

An exact conditional edge carries a canonical `logicalBranches` set. Each
branch names the normalized operation facts that select it, its complete
conjunctive effect set, principal/effect-owner sources, lifetime, and barriers.
Selection facts are produced only after argument/resource normalization and
must select exactly one branch; missing, unknown, or overlapping facts deny.
Fixture obligations are derived independently for every logical branch,
including branch selection and explicit no-effect branches, so a union of
possible effects cannot masquerade as executed conditional semantics.

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

The profile is `ibex/capsec/1`; this is Ibex's first public contract. Oden's
`/2` suffix belongs to Oden's own profile lineage, while the shared ancestry is
expressed by the effect/registry semantics and `capsec/semantics/1` core
contract. Digest encoding and domains are frozen below. A stale or mismatched
digest refuses arming. Duplicate keys, unknown positive actions, unresolved
selectors, aliases, macros, and machine-specific unbound paths may not reach
the armed snapshot.

### Default execution contract

Normal project-code execution uses enforce mode. Absence of authored grants
produces empty package floors and closed dynamic ceilings; it does not select a
weaker mode. Lockdown, per-package attribution, compartment globals, and full
deputy intersection are required structural posture rather than independently
disableable policy preferences.

Audit is the separately named, ephemeral `ibex capsec audit` foreground
workflow. Permissive behavior exists only inside isolated tests. The
`contract-fixture` armed workflow is schema-only, must use the synthetic
`capsec-contract-fixture` target, and is never executable. None of these is a
mode of ordinary `ibex run`. Embedders must select an explicit supported profile
and successfully arm it; the legacy host constructor must not silently create a
production runtime that claims package security while running permissively.

### Module initialization and trusted source acquisition

LLP 0026 adds one explicit boundary to full deputy intersection. A module
factory's once-per-execution-generation initialization is an autonomous,
record-owned task: it executes in the defining principal's authenticated
compartment, and the constrained-principal set begins at that initialization
task boundary. Importer frames physically above a synchronous `require()` do
not join initialization-time decisions. This preserves deterministic module
state across cold/warm, synchronous/asynchronous, and competing-importer
orders. It does not widen the module's own grants. Calls through exports after
initialization continue to intersect the complete live caller and scheduler
chain exactly as before.

Module source acquisition is classified as a narrow trusted-loader operation,
not as `fs:list`/`fs:read` authority borrowed from the importer. It may occur
only after the exact authenticated import edge authorizes and is bound to that
edge's `SourceId`, source binding, locator, integrity, requesting record, and
graph generation. It is non-delegable and conveys no general filesystem
authority. The generated coverage registry rows for module-source acquisition
must use this classification before the ModuleRunner security integration can
claim conformance; denial, no-probe, cache-hit, prepared-carrier, and
wrong-principal fixtures are mandatory.

ENG-25062 implements that boundary as a typed `GraphDecisionSet` over the
exact requesting and target `SourceId`, resolution kind, conditions,
attributes, actor, effect owner, schedule-time identity, canonical constrained
set, stage, atomicity group, graph generation, and coverage edge. Successful
authorization returns an opaque receipt bound to the armed snapshot digest and
all four authority generations. Source, cache, and prepared-carrier access is
possible only through a closure entered after the receipt is revalidated for
the exact target and generation. Module factories remain reachability-only at
the graph boundary; host effects they perform still enter ordinary typed
semantic-core `DecisionSet`s at their native effect gates. Generated target
cells remain unsupported until executed conformance evidence promotes them.

## WP0 semantic contract

ENG-24144 freezes the following contract for WP1–WP11. The machine-readable
authority is under `capsec/`; this section records the design decisions that
those artifacts implement.

### Ownership and profile identity

Ibex owns the initial canonical contract under `capsec/`. WP2 places the
runtime-neutral Rust implementation behind the neutral crate boundary
`crates/capsec-semantics` in this repository. A second runtime consumes that
exact source or makes an explicit ownership move; it must not copy the schemas,
canonicalizer, precedence implementation, or matcher into a second authority.
Product capability definitions, coverage edges, principal attribution adapters,
and target cells remain Ibex-local.

The product profile is `ibex/capsec/1`; the neutral semantic-core contract is
`capsec/semantics/1`. Profile suffixes are product-local compatibility versions,
not cross-runtime marketing generations.

### Typed resources and initial vocabulary

Canonical positive rows contain one explicit two-part action and one typed
resource object. No `*`, bare family, family prefix, alias, comma list, or
colon-delimited resource can survive source ingestion. Authoring macros may
expand only against the pinned vocabulary and their expansions appear as
explicit canonical rows.

Initial authorable resource kinds are:

- logical-root `path-exact` and `path-tree`. Exact matches the entire decoded
  component sequence; tree is a component-boundary prefix including its base.
  Package roots additionally require the same package-root binding owner.
  Valid UTF-8 uses UTF-8 form and other byte components use canonical unpadded
  base64url. Target-neutral identity rejects only empty, dot, dot-dot, NUL, and
  slash components; a backslash or Windows-reserved name remains representable
  for Unix. At arming, Unix/Android accepts all remaining byte names, Windows
  additionally requires valid UTF-8 and rejects controls, forbidden characters,
  trailing dot/space, DOS device names, and adapter-reported aliases, while an
  Apple bound-volume adapter supplies its actual case/normalization alias key.
  Alias collisions are compared only within the same bound-root/volume
  namespace; two packages' separate package-root bindings do not alias.
  Absolute paths are explicitly host-bound, and execution still requires a
  retained or verified platform object identity;
- separate fetch, raw/bidirectional connect, Unix connect, internet/Unix
  listen, and standalone DNS-query resources. Fetch never implies connect.
  Network selectors bind the exact scheme or transport, canonical DNS/IP/CIDR,
  remote or listen port, direct route, and peer classes. Runtime occurrences
  additionally materialize the concrete port, selected candidate, verified
  peer, and connection/listener identity applicable at each stage; those facts
  never become reusable authored selectors. Non-direct routes are discovered
  and refused before DNS, connect, or request bytes in this profile; typed
  proxies require a future profile;
- exact environment names: `env:read` accepts broker-base and
  principal-overlay, while `env:write` accepts principal-overlay and one
  child-launch. Read and write never imply one another;
- executable identity binding logical name, path, content, platform object,
  and, when present, interpreter path/content/platform object. Spawn composes
  `process:spawn`, child working-directory, child environment, and inherited
  stdio effects into one conjunctive decision set; closed stdio and unexported
  anonymous-pipe creation carry no external authority, while every exported
  endpoint has an exact owner-bound identity;
- independent stdio resources with stream and exact source identity:
  `stdio:query` accepts stdin/stdout/stderr, `stdio:read` only stdin,
  `stdio:write` only stdout/stderr, and `stdio:raw` only terminal-backed stdin;
  plus explicit system-information kinds, typed location/camera/microphone
  acquisition, and native system clipboard formats.

`fs:list`, `fs:read`, `fs:write`, and `fs:watch` are independent. A matcher
never derives one action from another. SQLite file operations decompose into
the corresponding filesystem effects for the main database, parent, and
journal/WAL/SHM objects; `sqlite:*` is not canonical authority. Unix sockets
decompose `network:local` into connect or listen plus the applicable filesystem
effects. Ordinary randomness, pure in-memory cryptography, ordinary/high-
resolution clocks, and status-only attenuations are reasoned non-capabilities.
Exact SQLite `:memory:` databases are likewise computation because the host
authorizer denies attach/detach and extension loading. URI-looking or empty
filenames are not covered by that exemption and remain file-backed effects.

Location, camera, microphone, and clipboard are authorable target-specific
definitions. Their cells remain unsupported until native gates and broker/
lifetime fixtures prove them (`device:microphone` is known ungated today).
Storage remains deny-only until principal/shared namespace and native isolation
are proven. Shared process mutation, ambient IPC, inspector/runtime inspection,
VM, workers, WASI, and FFI remain deny-only or absent. The generated
reconciliation table joins every one of the 57 current bit names to its exact
destination disposition across 38 typed action definitions; the Rust bit source
remains the sole bit-number authority.

A package principal is the exact package locator plus integrity digest (with
its review name), not a package name alone. Root-only sources author positive
grants. Canonical provenance may merge several non-authorizing source records,
while definition lifecycle and channel restrictions still determine whether a
row may become static, dynamic, handle-mediated, or terminal authority.

### Decision, staging, and principal semantics

For one normalized effect and one constrained principal, precedence is:

1. arm validity and authenticated profile/digest agreement;
2. attribution (`NoUser`, missing, or ambiguous denies);
3. definition lifecycle and exact target-cell closure;
4. built-in protected-resource guards;
5. process-wide ceiling;
6. principal-specific denial;
7. revocation and negative generation;
8. quarantine denial;
9. definition/edge positive predicates;
10. static floor;
11. an explicit unforgeable bearer handle;
12. a typed dynamic session grant within the static ceiling;
13. generated implicit package-self access;
14. ambient root for the root dimension only; and
15. the effective mode's missing-authority result.

Every deny stratum precedes every positive authority source. The direct cutover
has no runtime legacy-oracle or compatibility-mask stratum; the 57-bit table is
build-time reconciliation evidence only. An unbounded process ceiling
continues; a bounded ceiling requires containment, and an empty bounded ceiling
denies everything.
Every filesystem occurrence is projected separately through each constrained
principal's authenticated root binding before any principal-indexed authority
stratum runs. That rule applies to protected resources, process ceilings,
principal denials, revocations, static floors, handles, dynamic grants, and
implicit package-self authority; an actor-projected package path is never reused
as another package's resource. An unprojected multi-principal path occurrence
fails closed. A deeper foreign package binding shadows an owned package
ancestor, so an outer package sees a nested dependency through the best
ownerless root rather than as part of its own package tree; equal package host
bindings and package principals without bindings refuse arming. Other
path-bearing resource kinds (executables and Unix sockets) refuse a
multi-principal package-root decision until their adapters supply complete
projections. The host, ABI, and semantic core all use the same JCS principal
ordering. No later source, including ambient root, can override an earlier
ceiling or denial.

The exact reserved `runtime/ibex-runtime-internal` frame stamp is transparent;
other runtime identities are not, and the reserved identity is never an
attribution fallback. `NoUser`, missing, or ambiguous attribution denies. Live
user frames plus authenticated schedule-time and owner/deputy identities form
a deduplicated constrained set. Each non-transparent dimension must allow;
dimensions intersect and never union. All effects known at a stage are
conjunctive and authorize before that stage's first visible or irreversible
action. Later object, DNS candidate, redirect, route, accepted-peer, or resource
discovery re-enters the same precedence before the next effect. Missing facts
deny, speculative effects are forbidden, and a late denial releases provisional
resources without pretending earlier discovery was reversible.

An armed snapshot has exactly one authority row matching `rootIdentity`. Every
package-graph node has a unique locator-and-integrity principal, an exact
authority row, and its own package-root binding; package authority rows may not
exist outside the graph. Import allowlists exactly equal authenticated graph
edges, and every logical path resolves through a root binding. Exact protected
objects cover armed policy, engine binary, package graph, and registry. In
addition, arming derives `fs:write` path-tree guards for every authenticated
package binding in every principal's projected view. Authenticated package
source cannot be written through any registered package spelling, even when two
such spellings share an inode; writable package scratch space requires a
separate future binding. A pre-existing filesystem alias outside every
authenticated package binding is not covered by this lexical guarantee and
requires a future commit-time identity/integrity guard. Network posture binds
direct-only routing and always denies metadata and unspecified peers.

### Handles, dynamic authority, and generations

Ibex deliberately retains LLP 0013's possession-based delegation within one
authenticated runtime. A handle is an unforgeable bearer object whose exact
action/resource grant, source owner, ancestry, and snapshot identity are fixed
at mint. Passing the object is voluntary delegation; frame/schedule attribution
still records the holder and actor chain. Handle use re-enters every negative
stratum at every effect stage, can attenuate only to the same action and a
strict resource subset, and is invalidated by ancestor revocation. A temporary
operation lease is native, operation-bound, non-transferable, and cannot turn
mode fallback into reusable authority. This is an explicit Ibex adaptation of
the Oden model, not an accidental omission of delegatee identity.

Authority containment is meaningful only within the same armed snapshot. Any
authority containing a package logical root also requires the same package-root
binding owner. Different actions are always incomparable even when their
resource shapes coincide.

Dynamic grants use typed resources and cannot cross the canonical static
escalation ceiling. Deny-only, planned, terminal, and static-only definitions
cannot enter the dynamic overlay. Mode fallback can never mint a grant or
handle. Revocation advances a negative generation before any later positive
decision.

Arm-time ceilings, protected-object/resource guards, and principal policies
retain an identity-preserving copy-on-write backing after validation. A live
publication must present those exact four immutable identities and then fully
validates only the changed generations, revocations, handles, and dynamic
grants. Cloning and publishing live authority is therefore constant-time in
the size of the static policy; attempting to mutate any immutable component
creates a new backing identity and refuses publication `[observed]`
(ENG-24280).

Decision caches key at least action, canonical resource bytes, constrained
principal set, effect owner, stage, vocabulary/registry/policy/armed-snapshot
digests, and negative/dynamic/handle generations. Repeated and live operations
must still obey their coverage edge's lifetime recheck contract.
Authority-reducing release, reset, shutdown, and cancellation have no positive
effect stage: they validate the retained object's runtime and principal owner
but remain possible after its positive grant is revoked. Requiring a live
positive lease to relinquish an owned resource can leak authority and violates
the registry's `authority-release` non-capability classification.

### Canonicalization and digest domains

All digest inputs are valid UTF-8 containing only Unicode scalar values and are
strict I-JSON serialized with RFC 8785 JCS. Duplicate keys are rejected before
canonicalization, and integers outside the I-JSON safe range use a tagged
canonical string. Arrays named by `digestContract.setKeys` are semantic sets
sorted and deduplicated by canonical JCS bytes. Composite-row sets use the exact
`(schema, path, orderBy)` declarations in `digestContract.keyedSets`; other
arrays retain sequence meaning. The hash frame is:

```text
SHA-256(UTF8(domain) || 0x00 || canonical-payload)
```

Digest text is lowercase `sha256-` followed by unpadded base64url. Domains are:

- `ibex:capsec:vocab:1` — definitions, selector/occurrence schemas,
  decision-affecting coverage/classifier rules, and non-capability rationales;
- `ibex:capsec:registry:1` — the source-derived generated registry,
  implementation references, and fixtures. Report-promoted target-cell bytes
  are bound separately so publishing a report cannot change the registry or
  implementation digest that the same report attests;
- `ibex:capsec:policy:1` — canonical review policy with its own digest omitted;
- `ibex:capsec:armed:1` — policy/registry identities plus resolved host objects,
  engine target, routes, graph, ceilings, generations, run nonce, and channel
  epoch; and
- `ibex:capsec:conformance:1` — one observed result for every target cell and
  the exact engine/fixture/report provenance.

Vocabulary and registry aggregates use `ibex/capsec-digest-bundle/1`, with
members ordered lexically by logical name and exact member lists frozen in
`digestContract.projections`. Policy, armed-snapshot, and conformance
projections omit only their own digest fields. The checked vocabulary bundle is
assembled from the exact WP0 definition/rule/schema files plus normative
coverage and containment vectors. The registry fixture content-addresses every
semantic and invalid fixture body as well as its closed file inventory; digest
payloads and the fixed digest-vector oracle are explicitly excluded where
including their raw bytes would create a cycle, and are checked independently.
The generated production registry is available after WP1. Its target cells are
all unsupported and its source references are explicitly non-conformance
inventory evidence. A tiny authored attestation catalog may name only a
content-addressed report; generation revalidates that report against the exact
source-derived implementation manifest and derives both target cells and the
advertisement list. Target cells, their matrix, and advertisements are excluded
from `implementationManifestDigest`, breaking the otherwise circular
report-promotes-cells-that-change-the-report-input dependency. The armed
snapshot remains a `contract-fixture`, and conformance remains unavailable
until WP10. Canonical policy and armed examples carry
recomputed self-digests and exact cross-digests. One checked golden vector
freezes each of the five domains, and the domain-to-payload mapping is fixed.

Audit, handle, dynamic-permission, and denial evidence carry all four loaded
vocabulary, registry, policy, and armed-snapshot digests from the immutable
engine decision context rather than expected wrapper values.

### Default and target claim

Durable canonical policy accepts only enforce. Audit is a separately named,
ephemeral foreground workflow; production permissive/off are not profile
members. Missing policy canonicalizes to enforce with empty dependency floors
and empty escalation ceilings. Full deputy intersection, lockdown, frame
attribution, native compartments, and immutable arming are structural.

WP1 advertises no targets and records one candidate exact target,
`aarch64-apple-darwin` with structural `hermes-frame-attribution`,
`native-compartments`, and `native-lockdown` features. These are security
properties, not Cargo feature names. An executable production or diagnostic-audit
snapshot may arm only when its exact target triple and canonical feature set
are advertised and every coverage edge has a matching `enforced`, `closed`, or
`absent` cell; a missing or `unsupported` cell refuses before project code.
Public-address classification remains closed until pinned IANA IPv4 and IPv6
special-purpose snapshots enter the registry. IPv4-mapped IPv6 is classified
through its embedded IPv4 address, unmatched addresses fall back to `reserved`,
and classifier activation gates the first target advertisement.

WP9 flips the ordinary command once at least one exact advertised target has a
complete generated conformance report. The repository does not wait for every
conceivable build triple, but a build on any incomplete target refuses before
project code rather than degrading or selecting the legacy plane. Public claims
remain exact-target claims. Internal unit/integration fixtures are sufficient
for permissive compatibility investigation; the production CLI gains no raw
developer harness.

Exact embedding does not create a second or weaker target-claim plane. The
dedicated `exact.invokeHostAsync` ABI removes the generic string bridge from
app and agent traffic, with separate canonical numeric endowment sets and no
UI-worklet installation, but the same target-advertisement rule still governs
production construction. Before Exact may consume an armed artifact through
the public embedding ABI, the normal Ibex package flow must supply the generic
snapshot/expected-identity inputs plus Exact's single-source operation manifest;
the target-local producer then publishes a final pair bound to the loaded
engine, this registry, the exact package graph, and the protected manifest.
Its target row
must be promoted only from the checked conformance report. Missing artifacts,
wrong targets, identity or registry mismatches, fixed/stale nonces, replayed
input, and unadvertised rows all remain startup refusals.

Implementation status (2026-07-16): the dedicated binary app/agent ingress and
single-use completion path exist and are usable by an armed runtime without
making `__hostCall` reachable. Its setter publishes an immutable method on the
stable pre-captured `exact` object and atomically completes the one-shot package
baseline finalization, so package compartments cannot intercept or replace the
capability. Armed snapshots now conditionally authenticate the Exact manifest
as a fifth protected artifact and carry exact app, agent-isolate, and empty
UI-worklet ID sets. The setter validates that three-way binding before any JSI
or callback-state mutation. The public artifact-preparation ABI authenticates
an already-built pair against the checked registry, loaded engine, package
graph/root objects, and protected artifacts, then replaces its construction
nonce and digest; it cannot advertise a target. A second target-local preparer
now strictly validates Exact's raw operation manifest, derives the complete
three-context projection without a caller allowlist, materializes those bytes
as the fifth protected artifact, and re-authenticates the fresh pair. Exact's
Apple and Windows consumers use this seam. The normal target-local producer now
builds the complete pair directly from the installed app root, loaded engine,
checked registry, canonical empty package policy/graph, and strict Exact
manifest; it therefore does not package stale filesystem identities. Exact's
bundled-root producer is complete, while package-bearing policy input remains a
separate future contract. Apple/Windows conformance reports and target
advertisements remain incomplete. The refreshed catalog has 23,143 required
fixtures, 4,774 fully executable recipes, and 18,369 unresolved
fixtures. The latest source-bound tranche adds five cached system-information
authorization scenarios and twelve asynchronous path-operation scenarios for
the `readdir` and `realpath` branches, twelve retained-file `chmod`/`utime`
scenarios, five retained-target direct `statfs` scenarios, twelve complete
malformed/attribution/principal scenarios for retained metadata and whole-file
reads, thirty-six complete malformed/attribution/principal scenarios for system
information, environment, and stdout, three complete adversarial loopback TCP
connect scenarios, plus five zlib stream lifecycle recipes, eleven TLS lifecycle
recipes, and a principal-owned network stamp recipe. Ten internal locale and
accessibility state-object surfaces no longer exist: normalized mutable state is
held in module singletons while host snapshot inputs and update hooks remain
explicit globals. Thirteen memory-debug implementation surfaces likewise no
longer exist: the timer, samples, counters, and options are captured behind the
deliberate `__exactMemoryDebug` diagnostic API. The
resource recipes create, exercise, and release their runtime/principal-owned
native state in one bounded invocation. Fourteen Linux/Android-only
`node:constants` exports now carry source-bound Apple absence evidence from the
real public module path rather than remaining generic availability residuals.
Async evidence remains open through a bounded event-loop quiescence drain and
binds both the dispatch edge and the worker edge actually observed at runtime.
The existing Apple matrix therefore remains unsupported;
this partial implementation is not grounds to promote a target or retain
production benchmark evidence.

The source-bound native-read harness admits inherited members only for 57
static data constants whose descriptors prove the exact property path. Runtime
evidence records the owner depth for every path segment and requires a positive
final depth; own-property substitution, inherited callables/accessors, instance
members, and dynamic tables remain rejected.

### WP0 artifacts and gate

The schemas, registry inputs, examples, invalid goldens, and generated legacy
table live under `capsec/`. `contract-files.json` is a closed inventory of every
schema, registry, example, invalid fixture, and generated artifact; an unlisted
or missing file fails validation, and every registered invalid fixture must be
executed and rejected.

`capsec-contract.mjs` rejects duplicate keys, validates Draft 2020-12 schemas,
checks cross-file action/resource references, requires selector and occurrence
examples for every authorable resource kind, requires containment vectors for
every handle/dynamic resource kind, and joins definitions to normalizers and
coverage edges exactly. It also checks all five digest vectors, keyed canonical
sets, target cells, armed graph/root/binding/protected-object invariants, and an
exact one-to-one reconciliation with live rows inside
`CAPABILITY_BIT_DEFINITIONS`; commented or outside-constant Rust lookalikes are
not authority. `--check` is non-writing and participates in the repository's
single generated-drift gate.

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

Implementation: frozen by ENG-24144 in `capsec/`; validation is
`bun run check:capsec-contract` plus
`bun test packages/ibex-devtools/src/scripts/capsec-contract.test.mjs`.

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

Implementation: ENG-24145 generates the production coverage registry, exact
candidate-target product, source-surface/fixture-obligation manifest, stable-ID
schema, review tables, and Rust/C++/JavaScript/TypeScript bindings. Discovery is
source-derived across native globals, public host/embedder/worklet ABI,
builtin exports, installed globals, loader branches, callback producers,
startup installers/scripts, inspector operations, and CLI commands. Unknown
surfaces/actions/normalizers fail generation; source filenames never choose a
semantic classification. `bun run check:capsec-registry`,
`bun run check:capsec-contract`, their focused tests, and the repository drift
gate are non-writing checks.

Implementation alternatives retain their source-derived target variant,
normalized applicability, backend/stub disposition, and a globally unique
branch ID. Every target cell lists the exact applicable branch IDs even while
unsupported; fixture obligations are scoped to those branch IDs. Promotion
must execute the complete obligation union for exactly that source-derived
branch set. Unknown, wrong-target, omitted, or invented branch evidence fails
validation, while a branchless target can advance only to target-proved
`absent`. A known `unsupported-stub` branch cannot promote. Weak-fallback and
source-uncertain provenance are resolved only by the WP10 report's executed
obligations bound to the exact target binary; they are not conformance evidence
by themselves.

The ENG-24145 baseline contains 6,804 logical surfaces and coverage edges,
6,984 implementation-branch rows, and 11,048 source references. It includes
2,823 builtin surfaces: 2,696 export/prototype/inherited-shape APIs plus 127
specifier aliases. Inherited CommonJS and authored shared-runtime class shapes
are traversed exactly when their base is source-resolvable; otherwise a
review-bound dynamic-table sentinel closes the entire inherited property domain.
Builtin enforcement-route discovery likewise follows only immutable source
provenance: direct calls, constructor bodies, locally authored callable
alternatives, and literal CommonJS dependencies joined to the exact manifest
source key and export. Reassigned or computed dependency receivers, opaque
callable alternatives, intrinsic mutation, and unresolved cross-source exports
remain explicit ambiguities. Multiple source-proven terminals are retained
rather than guessed away; WP10 still requires bounded public arguments to show
which route the bound engine actually executes.
It also includes 178 host-ABI surfaces: the complete 84/36/10
`ex_host_*`/`ex_hermes_*`/`ex_worklet_*` families, one `ex_android_*` entry,
and 39 Java plus 8 JNI Android bridge routes. All 6,804 candidate-target cells
are unsupported; 760 known
parameter/provenance-dependent effect edges are explicitly
`conditional-unrefined` and therefore unpromotable.

Generator hardening now makes the reviewed/discovered join bidirectional,
rejects overlapping logical-branch predicates (including subset and
cross-fact overlaps), fails on unrouted fixed rows and Android provider
overloads, understands adjacent C++ literals and digit separators, and derives
implementation branch identity from the target variant rather than mutable
source-reference paths. Provenance remains digest-bound without becoming the
semantic identifier.

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

Implementation: ENG-24146 adds the product-neutral `crates/capsec-semantics`
workspace member. It strictly ingests the frozen WP0 definitions/rules, uses
RFC 8785 canonical bytes and domain-bound digests, validates typed selector and
occurrence semantics, evaluates every deny stratum before positive authority,
intersects constrained principals, conjoins effects, rejects speculative stage
facts, binds revocation/dynamic/handle generations, and keys decisions by the
complete frozen semantic identity. Rust golden and property tests consume the
same WP0 fixtures as the JavaScript/schema validator; CI runs the focused Rust
test and clippy gates without requiring a Hermes build.

The action-definition `selectorConstraints` fields are executable semantics in
the Rust core, not schema commentary: the same validator now governs armed
floors, denials, process/escalation ceilings, handles, dynamic grants, and
normalized occurrence requests. A corpus test routes every declared invalid
fixture through the corresponding strict JSON, selector, or occurrence ingress.
Principal and every other semantic set now use one JCS-byte order at engine,
host, and core boundaries. IPv4-mapped IPv6 values canonicalize to their
embedded IPv4 identity, RFC 8785 number bytes use ECMAScript tie-breaking, late
listen/device facts are required only when their stage produces them, and the
decision cache is bounded and generation-evictable.

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

Implementation update (2026-07-12): policy authoring reuses the contract's
action-specific selector validator. Drift review performs containment-aware
diffs for floors, denials, ceilings, package/builtin imports, endowments, and
principal identities, classifying expansion, narrowing, mixed, identity, and
vocabulary changes. Every semantic set uses canonical UTF-8/JCS byte order.

### WP4 — Arm immutable snapshots through the CLI, host, and engine

Build the trusted arming pipeline that binds canonical policy to an execution
and hands the authenticated immutable snapshot to the host/engine. Report the
actually loaded profile and digests from the decision context.

Production runtime construction owns `runNonce`. After authenticating any
supplied snapshot template, it discards the artifact/caller nonce, generates a
fresh 128-bit value with the operating-system CSPRNG, and finalizes the armed
digest before handing the snapshot to the host and engine. Fixed nonces remain
valid only in contract fixtures; RNG failure refuses construction.

Acceptance:

- The runtime refuses before project code on stale/mismatched policy, registry,
  engine target, package graph, or required target cell.
- Mutable authored files and environment variables are not consulted after
  arming.
- Audit, denial, handle, and dynamic-permission records carry the loaded
  semantic identity and snapshot generation.

Implementation status (2026-07-12): Rust ingestion checks the WP0 root,
authority/graph-edge, root-binding, and four protected-object invariants and
uses the checked digest contract's semantic-set canonicalization. Production
derives exact target cells from authenticated registry data; because every
current cell is unsupported and no target is advertised, ordinary execution
refuses before project code. Arming measures the artifact containing the loaded
Hermes factory, requires structural lockdown/compartments/frame attribution,
uses per-run nonces, rejects every generated closed startup control, and binds
an immutable Host context to each runtime. The old unarmed constructor is
non-executable. Package principals are stamped only after exact locator,
resolved root, and whole-tree integrity verification; package-to-root imports
require an exact authenticated graph edge. Default project-root discovery
selects only a canonical ancestor containing `package.json`; a manifestless
entry must receive an explicit trusted `--project-root` and otherwise refuses
before policy construction or project evaluation.

Implementation update (2026-07-12): canonical policy now carries the exact
registry digest as well as vocabulary identity. Production strictly
deserializes the complete typed artifact, recomputes its self-digest, validates
every authority against current definitions, and refuses independently
recomputed stale vocabulary or registry policies before projection. Bounded
process ceilings containing package logical roots expand into one bound row per
authenticated package principal rather than losing their owner identity.

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

Implementation status (2026-07-11): synchronous and worker-backed async native
`fs.open` now have an
armed-only staged adapter for read, write, create, and truncate. It authorizes
the requested logical path, retains and verifies the resolved parent directory
inside the authenticated logical root, distinguishes existing from
absent-create discovery, and authorizes the operation effects before `openat`.
Final symlinks are closed with `O_NOFOLLOW`; parent symlinks that resolve outside
the authenticated binding are refused. Truncation is deferred until commit has
authorized the actual `fstat` identity and retained descriptor ID, so a denial
cannot mutate an existing or absent target. An explicitly presented typed
bearer ID participates in every stage. Legacy hosts retain their existing gate;
armed refusal never falls back to it. The fd registry retains the parent
descriptor and presented bearer ID, and every armed read or write re-authorizes
at `repeat` against fresh identities and current authority generations. Async
commit runs on the worker before the descriptor is delivered to JavaScript;
registry publication remains on the attributed runtime thread. The remaining
descriptor metadata/disclosure operations (`fstat`, truncate, sync, ownership,
mode, and times, including their worker-backed forms) reuse the retained
descriptor and typed repeat checks. Synchronous and worker-backed whole-file
reads use their own conjunctive registry edges: `fs:list` authorizes requested
path lookup and retained-object discovery, then `fs:read` authorizes commit
immediately before the first byte can be observed and every repeat lease. The
private descriptor open between discovery and commit discloses no file bytes
and does not add a redundant read-discovery decision. Public `Cargo.toml`
allow/deny recipes prove the four-stage action sequence and fail closed at the
first list decision when lookup authority is absent. Whole-file reads accept
only retained regular files. They perform one full repeat decision per
descriptor lease and cheaply compare
negative, dynamic, and handle generations before each chunk; any change
re-enters the full evaluator before more bytes are observed. Leases are local
to the exact operation and retained descriptors, so operation/gate/principal/
object facts cannot collide and descriptor reuse starts a new lease. `stat` and directory
enumeration likewise use retained no-follow targets and their own `fs:list`
edges; enumeration rechecks before every disclosed entry. Worker-backed path
and descriptor stat use the async stat edge and recheck on the worker before
serialization. Sync and async lstat retain the link object itself with
`no-follow-final` semantics. Realpath returns the canonical path of the retained
no-follow descriptor under its own list edge. Whole-file replace,
append, and worker-backed write use their own edges, authorize absent-create or
existing state before `openat`, commit the actual regular file before delayed
truncation, and recheck before each write/flush. The remaining path-based
filesystem operations are still pending. Non-recursive synchronous and
worker-backed directory creation now use the `mkdir` edge: they authorize the
requested path, retain and verify the parent, preauthorize absent creation,
create with `mkdirat`, and commit the opened directory identity, rolling the
new directory back if commit fails. Recursive creation remains closed until
every created component can run that full sequence independently. Path removal
also remains closed in armed execution: retaining a target descriptor and then
calling name-based `unlinkat` would still permit a swap between identity check
and deletion, so sync and async denial fixtures require the original file or
directory to survive until a genuinely race-safe removal strategy is adopted.
The same armed denial fixture covers unported sync and async rename, copy,
symlink, and hard-link paths, proving they cannot mutate either source or
destination through the legacy oracle while their typed staged adapters remain
pending.

Post-review hardening (2026-07-12) preserves ENOENT/ENOTDIR and Node-shaped
denials, avoids read-opening metadata targets and blocking FIFO lstat, shares a
bounded runtime-scoped parent-directory descriptor cache, and rechecks regular
whole-file reads per chunk. Open/create rollback ownership is established only
by successful `O_CREAT|O_EXCL`; state races rediscover and reauthorize before
retry, so a competitor's file is never treated as ours to unlink or truncate.
FD, IPC, and transferable registries bind runtime nonce plus device/inode and
evict stale rows on descriptor-number reuse. Async worker exceptions and result
delivery failures reject instead of aborting or hanging, completed closures
release descriptor captures eagerly, and callback attribution intersects live,
captured, owner, and scheduler principals. Async directory traversal, realpath,
mkdtemp, watch polling, recursive-readdir spelling, and non-recursive `rm`
parity now use worker-backed paths. Windows preserves distinct errno values and
implements recursive-mkdir results, exclusive copy, truncate, utimes, and
statfs through the portable host ABI.

Filesystem path occurrences now retain a non-wire projection for every
constrained principal, keyed exactly to the constrained set and effect index.
Every authority stratum uses that principal's projection, so two packages with
the same package-relative tail cannot borrow one another's self grants. Arming
also derives hard-deny `fs:write` path-tree guards for every package binding in
every authenticated principal's view, including nested package layouts. These
lexical guards make installed package source immutable without attempting to
enumerate inodes or assuming that hard-linked files have distinct identities;
first-party project paths outside package bindings remain writable. A foreign
nested package is a shadow boundary rather than part of its ancestor's package
tree, and colliding physical package bindings refuse. Aliases outside all
registered package spellings remain a distinct integrity problem rather than a
claim made by the lexical guard.

### WP6 — Convert network effects and protected peers

Map fetch, raw/bidirectional connect, listen, and standalone resolve to separate
typed resources. Authorize requested endpoint, selected candidates, redirects,
reconnects, routes/proxies, listeners, and final verified peers at their stages.
Add an engine-level protected metadata-peer guard with only an exact loud
exception if Ibex needs one.

Implementation status (2026-07-11): the armed host now constructs typed
`network:fetch` decision sets for requested and candidate stages using the
authenticated principal stack, concrete scheme/host/port, resolved candidate
set, selected candidate, and optional verified peer/connection facts. Candidate
authorization applies selector peer classes, while an independent host guard
unconditionally rejects metadata-service and unspecified selected or verified
peers. Live fetch remains closed until the transport adapter can report and
recheck the actual connected peer; requested-host authorization alone is not
treated as sufficient enforcement. The host also evaluates staged typed TCP
connect occurrences under the distinct `network:connect` action and retained
verified-peer/connection facts. A package fixture proves a fetch-only floor
cannot yield raw TCP authority, while a matching connect floor commits the
verified public peer.
The C ABI accepts the complete staged network fact set for fetch and connect,
maps authenticated numeric frame stacks to typed principals, and rejects
noncanonical host/IP text, duplicate-key or ill-typed candidate JSON, invalid
ports/stages/transports, and unsafe redirect counters before host evaluation.
The synchronous POSIX TCP adapter now uses that ABI end to end: it authorizes
the request before resolution, submits the canonically sorted complete
`getaddrinfo` candidate set, authorizes each attempted address, verifies
`getpeername` at commit, retains the candidate/peer/connection facts with the
socket handle. The first later I/O, and each generation-lease renewal, verifies
the immutable connected peer with `getpeername`; stable later I/O pins the exact
socket registry identity through the syscall without copying the retained
candidate/peer strings. Retained socket use reuses a full repeat decision only
for the exact peer and principal set while all mutable authority generations
remain unchanged; a generation or deputy-set change forces a stable
before/after redecision and another peer verification. The nonblocking POSIX path applies the same request and
candidate gates, registers only a pending handle, and withholds read/write
authority until poll observes successful `SO_ERROR`, verifies `getpeername`,
and commits the peer. Pending handles may only be polled or closed. Armed
local-bind options remain closed pending their own typed effects. Windows, TLS,
WebSocket, and the remaining UDP adapters are not yet migrated. POSIX unconnected UDP sends
are gated under their own registry edge: only canonical literal IPv4/IPv6
destinations are accepted, and the first datagram authorizes requested,
candidate, and committed destination facts immediately before `sendto` through
one parsed and attributed ABI call. Repeated datagrams reuse that complete
decision only for the same socket identity, literal host/port, canonical
principal set, and unchanged negative/dynamic/handle generations. Endpoint,
principal, revocation, or handle-generation changes force a stable
before/after three-stage redecision; the registry lock pins the fd through
`sendto`, so close/reuse cannot consume the lease. A bounded live fixture proves
sixteen identical datagrams require only one three-stage decision, revocation
forces exactly one renewal, and a metadata destination is rejected before
transmission. UDP bind/receive/listen authority remains
unmigrated and closed in armed execution.
One live armed closure fixture exercises the remaining transport families at
their native boundaries: fetch, standalone DNS, WebSocket, TCP listen, HTTP
serve, Unix connect/listen, and UDP bind all refuse before an external effect;
the Unix socket path remains absent. Together with the positive TCP-connect
and per-datagram UDP fixtures, the initial advertised network profile is thus
either typed end to end or explicitly closed rather than falling back to the
legacy capability oracle.

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

Implementation status (2026-07-11): the armed host decodes explicit builtin
and package import axes from the authenticated snapshot. Numeric engine module
IDs bind only to a matching package name plus locator from that snapshot;
unknown or mismatched registrations fail closed. Root and package import checks
therefore no longer consult `PolicyFile` once armed.
Armed runtime construction also rejects every inspector activation and
configuration flag (`inspect`, wait/open/pause, host, and port), including the
duplicate `run`-subcommand spellings, before reading arming artifacts or
allocating the engine. The opt-in Bun compatibility facade is closed at the
same boundary before its process-global environment marker can be installed.
Hidden compatibility-fidelity controls that expose internals or alter
process-wide stack/HTTP-parser configuration are rejected there as well,
before armed artifact I/O.
Ad-hoc eval/print, explicit or implicit REPL entry, and debug-registry commands
are likewise rejected at the production dispatcher/runtime boundary before
arming artifact I/O, engine allocation, or evaluation of supplied code.
At runtime scalar broker-base environment reads use exact-name typed
`env:read` decisions at requested and commit before disclosure. Environment
enumeration remains explicitly closed and returns an empty object until it can
authorize every concrete name without a wildcard. Process cwd disclosure now
uses the same exact typed `sys:read`
plane as other system information: requested and commit authorize the `cwd`
selector before `getcwd`, while denial occurs before disclosure. Cwd mutation
remains denied without changing the host process directory. Live armed
fixtures cover these boundaries.
The same live fixture invokes shell exec, synchronous spawn, and asynchronous
spawn with a real marker-file command. All three are denied at the armed native
boundary and the marker remains absent, so executable selection, child
environment, stdio, and IPC option parsing cannot reach process creation via
the legacy `process:spawn` oracle.
Diagnostic audit keeps the child-process compatibility suite executable without
widening that production boundary. Its low-descriptor regression uses a plain
POSIX child to exercise IPC and extra-stdio `dup2` mapping directly; it does not
grant a nested Ibex runtime ambient ownership of inherited numeric descriptors.
Parent-side extra stdio is a bounded, backpressure-aware full-duplex stream:
`end` half-closes writes, readable EOF gates the child `close` event, and
`destroy` releases both directions. Production child environment and inherited
stdio effects remain closed pending their typed conjunctive spawn implementation.
The armed import gate also carries an artifact-independent terminal-builtin
deny set for `async_hooks`, `inspector`, `vm`, `wasi`, and `worker_threads`
(including `node:` aliases and subpaths). A deliberately overbroad but
otherwise authenticated snapshot cannot re-enable those runtime-inspection,
VM, WASI, or worker escape surfaces; ordinary typed builtins such as `node:fs`
remain governed by the snapshot import policy.
On-disk `.node` native-addon and `.wasm` module candidates now refuse in the
native resolver before their bytes are read into the JavaScript compilation
path. Exact loaded-engine fixtures use valid JavaScript payloads under both
extensions and require the resolver-specific refusal while proving the payload
marker never executes; both the public loader-kind facet and its compatibility
module facet bind to that same runtime-derived denial.
The eight native OS-information functions used by public `node:os` now enter
the same exact typed plane on every implementation target. Hostname, CPU,
memory, uptime, user, load-average, and network-interface reads authorize both
their generated requested and commit stages before invoking POSIX, Apple, or
Windows APIs. Loaded-Hermes fixtures exercise all 18 public exports in every
effect scenario. Allow, malformed, missing-attribution, and wrong-principal
fixtures independently observe the public requested/commit route under its
exact floor while their typed adapter cases exercise the scenario-specific
semantic branch; principal-deny fixtures observe the public requested-stage
denial. Neither path consults the legacy string oracle (ENG-24450).
The same exact-engine batch now exercises `node:fs` `statSync`, `lstatSync`, and
`readdirSync` against harness-owned file and directory fixtures beneath an
authenticated, canonical logical-root binding. Metadata calls must return after
emitting requested, discovery, and repeat decisions. Directory enumeration must
also emit the repeat decision that establishes its generation lease before any
entry is returned. Denial fixtures stop at requested. For these exact
source/setup/argument recipes, a noisy static dynamic-call list is diagnostic
rather than residual: promotion still requires the runtime-observed gate to
belong to the source-derived terminal allow-list.
Direct global `print()` writes now authorize the exact stdout console-broker
identity (`broker` / `ibex:console:stdout`) at requested, commit, and repeat
before enqueuing a line. Denial therefore cannot leak output through the
best-effort mirror, and this public path no longer bypasses typed
`stdio:write` authority.
The initial profile therefore has no debugger protocol or compatibility-facade
route into package memory or runtime internals.

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

Implementation status (2026-07-11): armed hosts now decode the immutable
snapshot into a validated `VerifiedDecisionContext`, accept strict typed
decision-set/effect-gate input, classify final peers, and retain bounded
structured evidence. Every legacy string check, import check, handle mint, and
dynamic grant fails closed once that typed context is installed; production
call sites must migrate to the typed ingress before a target can advertise.
Typed dynamic grant publication now validates the canonical ceiling before
advancing its generation; revocation advances negative and dynamic generations
before publishing the replacement context, invalidating prior decisions. Typed
bearer handles use OS-random identifiers, can be minted only from an owner's
static floor or re-attenuated from a handle currently held by the actor, and
revoke descendants as one negative/handle-generation publication.

The live Hermes surface also exposes typed dynamic grant and revocation as
`Ibex.permissions.requestTyped(request)` and `revokeTyped(grantId)`. Requests
cross the native boundary as strict typed JSON and therefore use the same
ceiling, lifecycle, digest, and generation validation as embedder calls;
legacy colon strings are rejected by the typed method rather than reinterpreted.
Both the private bridge and public methods are exact registry surfaces.
Typed bearer mint and cascade revocation are likewise reachable as
`Ibex.authority.mintHandle(request)` and `revokeHandle(handleId)`. Handle IDs
remain opaque strings; the live bridge exposes no numeric conversion or legacy
capability-string minting path.
The live native ABI authenticates both authority surfaces from the executing
Hermes principal rather than trusting the principal or actor supplied in JSON.
Dynamic grants must name that authenticated principal and may be revoked only
by it; handle mint actors must match it, and handle revocation is limited to the
authenticated owner or current holder. Forged package identities and unknown
grant or handle IDs therefore refuse at the bridge instead of becoming ambient
authority or cross-principal revocation.
For a new handle, the bridge also carries the canonical full Hermes principal
stack into the host. The requested selector must be covered by every
constrained principal's static floor, so an authorized inner actor cannot use
an ungranted caller as a deputy to mint authority. Re-attenuation remains bound
to an explicitly presented parent held by the authenticated actor.
Successful typed grant, revocation, mint, and cascade-revocation publications
wake the runtime. Each event-loop poll compares the authenticated negative,
dynamic, and handle generations; changes emit a frozen generation tuple through
`Ibex.authority.onChange`, including mutations initiated by an embedder rather
than JavaScript itself.
Every typed decision context carries a canonical sorted `presentedHandleIds`
set. The bearer stratum considers only those IDs, and rejects duplicate,
unsorted, unknown, or wrong-holder presentation as invalid attribution. Merely
minting a handle for a principal therefore never turns possession into ambient
principal authority.
Armed root bindings are decoded into typed values and host paths normalize
through the longest authenticated binding. Package roots match only their exact
package owner, project roots do not borrow package identity, absolute bindings
remain exact, and paths outside every armed binding refuse before a decision.
For filesystem effects the host computes that normalization once per
constrained principal, preserves the complete principal set for attribution and
evidence, and refuses a missing, extra, or noncanonical projection before any
authority match.
Live typed filesystem decisions now carry the canonical full Hermes principal
stack, including the captured schedule-time owner. Worker dispatch snapshots
that stack on the runtime thread and installs a scoped immutable copy on the
worker, so commit/repeat checks cannot lose an outer caller or detached
scheduler. The evaluator intersects every constrained principal; an ungranted
outer principal therefore denies even when the innermost actor has authority.
Timers and next-tick queues likewise retain the complete schedule-time stack
and restore it only for their callback invocation, so a later
authority-bearing operation cannot shed an outer constrained deputy;
generation checks still occur at the operation and observe intervening
revocation rather than caching the schedule-time allow.
A retained-operation fixture publishes ceiling-bounded dynamic filesystem
authority, commits a descriptor use, revokes the grant, observes both negative
and dynamic generation advances, and proves the immediately following repeat
check denies.
Distinct live dynamic grants are now restamped atomically to one published
generation on every add/revoke/regrant transition, with failed publication
leaving both rows and clocks unchanged. The typed decision ABI returns the
decision and its exact structured evidence from one evaluation; bounded
history receives a clone of that same record and is no longer queried to build
the response.

Implementation update (2026-07-12): exact source-bound public conformance now
executes six callback/control-plane invariants against the loaded armed Hermes
engine through production `process.env` and public authority-control operations:
missing attribution denies, scheduled decisions recheck authority after
generation changes, callback principals restore after delivery, bearer handles
cannot cross snapshot identities, public grant requests cannot widen the static
ceiling, and lockdown remains structurally immutable. A feature-gated one-shot
observer records only the actual principal and runtime nonce; it cannot evaluate
or authorize an operation, and the harness deletes its global before the public
invariant operation runs. The 2,836 applicable non-capability fixtures carry
runtime-derived results, exact structured typed outcomes/reasons where an
auxiliary decision is required, and zero legacy observations. This closes those
recipe obligations without advertising a target; target promotion remains gated
on the complete exact-target execution report.

### WP9 — Make complete enforcement the default and remove weakening paths

Flip ordinary CLI execution and embedding defaults only after WP4–WP8 cover the
required initial profile. Remove or quarantine legacy policy parsing, public
permissive execution, `--allow-all`, advisory attribution, environment-selected
weakening, durable audit mode, optional lockdown under enforce, and permissive
legacy host construction.

Implementation status (2026-07-11): `Auto` and explicit `enforce` now resolve
to the same enforce posture even when no policy is present. Durable audit or
permissive policy modes, `--allow-all`, explicit permissive mode, legacy
allow/deny overrides, environment-endowment widening, and advisory-attribution
flags/environment inputs refuse instead of weakening production. Lockdown is
installed structurally for both the ordinary CLI and direct `Runtime`
construction, and missing lockdown, frame attribution, or package isolation is
a hard enforce failure with no advisory override. Compatibility, inspector,
and runtime-fidelity controls also refuse at ordinary host construction. The
ordinary no-policy path now constructs an execution-bound immutable typed
snapshot instead of the legacy host: it binds the actual project directory
object, patched-Hermes binary digest, exact advertised target/features, empty
package graph, empty dependency floors and dynamic ceilings, and the current
semantic/registry identity. Auto and explicit enforce produce identical policy
and authority state. Each runtime construction injects a fresh run nonce before
finalizing the armed digest, so complete snapshot bytes and handshake digests
intentionally differ. The trusted module loader may read
only source that canonicalizes under the authenticated project binding after
the typed import gate succeeds. A project-local `ibex-policy.json` (or explicit
`--policy`) is now accepted only as strict, digest-valid canonical typed policy;
its package principals, typed floor/denial/ceiling rows, import axes,
endowments, graph nodes, root and package import edges, and authenticated package-root
bindings are projected one way into that same snapshot. Environment-selected
policy paths and stale/tampered policy digests refuse. Production builds always
enable enforce isolation and cannot persist audit or permissive posture.
Diagnostic audit is a separately named foreground command,
`ibex capsec audit <file>`; it accepts no durable policy or ambient endowment
input and never becomes an armed production profile. In the candidate registry,
that canonical file-execution dispatch route is conservatively closed under
`vm:evaluate` until authenticated code ingress and its fixtures exist; parser
and positional metadata remain structural rows and claim no ingress authority.

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

Implementation status (2026-07-12): no target is advertised complete. The
former runner incorrectly converted a handful of broad suite successes into
21,597 synthetic per-obligation passes. The runner now executes the full
default Rust/integration/red-team matrix, all-feature executable
library/binary/test/example coverage plus compile-only all-target coverage,
complete devtools and runtime-JS tests, Hermes transform/loader corpora,
all generated drift gates, contract/registry checks, and `ref-check` from a
clean revision. It launches an executable Hermes probe, but records that probe
identity separately from the actual runtime engine artifact whose digest enters
the binding; the probe can never promote a different embedded library. Those
broad results remain prerequisite suite evidence only, and command logs are
streamed to files with full digests plus bounded tails rather than retained
unbounded in the report.
The same runner is now the arm64 macOS CI gate. CI invokes
`verify:capsec-conformance --expect-incomplete`, which still runs the entire
matrix and emits exact command, adapter, public-surface, execution, and report
artifacts. That mode succeeds only after the report is generated, remains
`incomplete`, independently fails the recipe/public/report promotion checks,
and has no matching committed target attestation. It fails automatically once
the target becomes conformant, forcing CI to remove the expectation and adopt
the ordinary promotion gate rather than silently retaining a stale
"incomplete" posture.
An obligation can pass only with fixture-specific command evidence carrying
its exact fixture ID, result marker, exit status, recomputed evidence digest,
and exact execution binding. Missing, generic, duplicated, stale, or synthetic
records keep the report incomplete. Promotion remains closed until real
executable evidence exists for every required fixture and the full matrix is
green.

Implementation status (2026-07-14): the first report-crediting fixture pilot
reruns exactly seven Exact embedder mechanisms independently of the public
catalog/adapter batches: three views of the single-use host-call completion
route, endowment installation, exact-set authorization, armed-artifact
freshening, and the unendowed-operation closure. Every
`ibex/capsec-fixture-evidence/2` record carries the committed revision/tree,
exact target and mapped engine identity, full fixture plan, recipe/public
digests, producer command and exit status, and the fresh runtime observation.
The runner validates the artifact through its `--fixture-evidence` path and
credits exactly seven passes; the other 22,983 obligations remain missing, so
the report remains `incomplete` and the target remains unadvertised. Missing,
duplicate, stale, mismatched-plan/engine, or mechanism-invalid pilot evidence
fails closed rather than reverting to zero credited rows.

Builtin public-surface evidence follows the same rule at value granularity.
The source scanner records whether an export is data, a readable accessor, a
callable, or unresolved, plus source-derived platform availability where the
builtin authors conditional tables. It also distinguishes manifest-importable
aliases from bootstrap-internal names that preempt a same-named manifest
source. Registry-only names remain executable when an authenticated import
policy grants their exact spelling, even when they are neither advertised nor
bundler-external. Bootstrap-shadowed and unaliased manifest exports remain in
the completeness inventory, but receive an explicit reachability residual
rather than a public invocation recipe. A generic read recipe is valid only for
a publicly reachable root data property or readable root accessor on the
selected target; the loaded runtime must match the authored property
descriptor, and accessor evidence actually invokes the getter. Retrieving a
function, constructor, or prototype method is presence evidence rather than
execution evidence, so those surfaces remain residual until a bounded
call/setup recipe is authored.
Import-only alias recipes remain residual. Loaded execution showed that the
first selected alias performs a typed `env:read` of `NODE_DEBUG` during shared
debug-log initialization, while later aliases only appeared decision-free
because they reused the module cache. Cache order is not independent execution
evidence, so no alias is promoted by that result. Export reads and calls remain
separate obligations: their exact public module is loaded and driven to
event-loop quiescence before the per-export observer opens, then the invocation
still performs the authenticated public `require` and resolves the
source-derived export from that cache. This isolates both synchronous and
deferred module initialization from the export body without claiming that
initialization was zero-effect. Manifest-builtin initialization may resolve
exact manifest-owned private builtin dependencies without creating package
import edges, but that exemption is scoped to synchronous body evaluation and
does not suppress capability terminal checks or survive through an exported
`require` closure.

Bounded non-capability callable recipes are grouped by exact source template,
not inferred from `typeof value === "function"`. The first authored families
cover `assert`, `buffer`, `events`, `path`, `perf_hooks`, `punycode`,
`querystring`, `zlib`, `stream`, `string_decoder`, `url`, and `util`: each
recipe fixes its setup, receiver, arguments, dispatch mode, and expected return
type. Direct member-to-member aliases inherit a callable shape only from the
already observed source member, and reuse that member family's bounded
arguments rather than weakening the template allowlist. Prototype
recipes construct the declared owner (with dedicated bounded Buffer,
CallTracker, zlib-transform, string-decoder, and configured
readable/writable/duplex stream fixtures), then dispatch the exact
source-inventoried prototype function. Zlib decoder probes derive a valid
compressed input with the matching one-shot encoder, and every zlib receiver
closes native stream state in a `finally` path. Stream recipes use inert
read/write/transform callbacks; standalone `destroy` receives an explicit
non-error value so it cannot leave an asynchronous `AbortError`, and `compose`
remains residual because its normal return still owns a live pipeline.
Performance observer `observe` likewise remains residual because it retains a
callback; constructor, query, mutation, and explicitly disconnected observer
recipes have bounded lifetimes. Evidence requires a normal return from the
selected dispatch; an argument/receiver binding error or any other throw fails
the recipe and cannot stand in for body entry. Normal return is not completion
evidence on its own: the observer remains open while the harness drives the
loaded engine to event-loop quiescence under the recipe's fixed one-second
bound. A timeout or event-loop error stops the batch before another fixture can
inherit its work, and the runtime completion marker is independently checked
against the authored mode and bound. A later tranche adds exact bounded
templates for in-memory crypto hash/HMAC/sign/verify, KDF, random-buffer,
prime, key, DH, and ECDH operations; pure module/path, IP/block-list, URL, and
version helpers; and unbound server metadata operations. Promise-returning
stream consumers, pipelines, `wrap`, and Hash/HMAC readable-side finalization
remain residual;
their one-shot recipes do not own enough state to prove completion even with a
quiescence drain. All accepted calls and data/accessor reads execute against
the same mapped Hermes
identity; there are no promoted cache-dependent module imports.
Loaded execution also exposed lazy builtin assignments that were swallowed by
locked inherited primordial properties; those Buffer, AssertionError, and
StringDecoder prototype members
are now installed as explicit writable/configurable own properties without
weakening primordial lockdown. Source inventory also preserves own prototype
overrides when an inherited member of the same name was propagated into a
concrete constructor.

Closed and conditional evidence remains branch-executed rather than
classification-derived. A closed CLI facet is executable only when the harness
first reconciles its source-discovered spelling, action, arity, defaults, and
parser against the live Clap command and then observes the production entry
reject that selected control before artifact or project execution. The four
Hermes evaluator identities additionally bind the reviewed engine identity and
lockdown-taming digest, resolve their exact intrinsic access path, and must
actually throw the native lockdown error when invoked on the loaded engine.

Production startup evidence now covers ten curated structural stages against a
fresh armed runtime from the exact mapped Hermes artifact: runtime creation,
global/module-loader/shared-runtime installation, capability-hatch sealing,
eager lazy-installer sealing, lockdown, freeze-hatch sealing, compartment
registry installation, and explicitly enabled Web Streams installation. Each
stage has one fixed source descriptor and an independently validated
postcondition; the probe then executes a project marker and requires zero
legacy or typed decisions. Scanner-only script URLs, evaluation/call-site
facets, installer definitions, skipped legacy bootstraps, and platform-only
routes remain residual rather than inheriting these stage results.
The runtime-create descriptor binds `ex_hermes_create_armed`, not the historical
`ex_hermes_create` symbol that production deliberately leaves non-executable.

A zero-effect conditional branch may pass without a typed decision only when a
source-bound public invocation itself selects the registry's exact branch facts,
returns normally, emits zero legacy and typed observations, and releases every
harness-owned resource. The first such family covers the seven native JSI and
seven Rust host-ABI SQLite operations on exact in-memory handles; each proves
both branch selection and the no-effect result while the file-backed branches
remain independent obligations. A valid public API cannot inject malformed
internal branch facts, so malformed-branch-fact fixtures remain residual rather
than reusing a generic malformed adapter result or a hand-labelled terminal.

The macOS/aarch64
candidate has exact loaded-Hermes adapter-probe evidence, but probe coverage is
deliberately non-promotable and is not represented as fixture pass claims.
`bun run verify:capsec-conformance` must publish a conformant revision-, tree-,
full loaded-engine identity-, vocabulary-, registry-, source-implementation-,
target-, and fixture-catalog-bound report. Promotion then requires a checked
content-addressed attestation; the generator reopens and validates the report,
the complete executable-recipe catalog, and a separate public-surface execution
artifact. All three are immutable regular files addressed by their raw content,
and the report and attestation bind the catalog and public-execution semantic
digests. Adapter-probe evidence is a distinct diagnostic schema and is rejected
at publication. `IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT` only selects the
harness-owned diagnostic artifact destination; it never supplies authority,
policy, a principal, a target claim, or production runtime input. The generator
re-derives the exact required fixture set and
requires one passing authored public-surface invocation (or target-absence
probe) with the selected terminal observation for every recipe, with zero
residual, missing, duplicate, or failed rows. It then derives every cell and
advertisement and permits no source changes after the reported revision except
those three evidence files, the attestation, and generated publication
artifacts. Until every required fixture genuinely passes, production startup
refuses before project code on every target.

Source-derived global reads are executable evidence only when the authored
runtime graph proves a concrete access path, every path segment has an actual
registration rather than a synthesized namespace prefix, and the final value
is unambiguously data or an accessor. The loaded-engine probe resolves the
source-proven property path, checks the final descriptor shape, performs the
read, and requires zero legacy or typed authorization observations. Merely
retrieving a function is never call evidence. Conditional namespace aliases,
multi-installer globals, receiver-dependent prototype members, and lazy getters
that may already have materialized a callable remain residual until they have a
bounded call/setup recipe. This keeps inventory facts from becoming synthetic
execution claims while permitting exact non-capability data reads to close.

Bounded native-call recipes likewise use only harness-owned literals,
callbacks, listeners, handles, or results of source-bound native producers.
When two arguments need the same generated key pair, the loaded-engine harness
caches the exact producer invocation and projects only an own `privateKey` or
`publicKey` property; independently generated keys are not interchangeable
evidence. Timer callbacks are inert and their returned timers are cancelled
before the fixture completes. Resource-consuming calls receive a handle minted
inside that invocation. Compile-guarded globals absent from the attested engine
remain residual even when source discovery finds their registration text.
Every non-capability recipe requires zero legacy and zero typed authorization
observations; in particular, ordinary random bytes cannot retain the retired
always-allowed `crypto:random` legacy check.

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

Implementation status (2026-07-11): production CLI/runtime construction no
longer loads or executes `PolicyFile`; only the explicitly diagnostic legacy
Audit constructor may receive an already parsed value for historical test
coverage. LLP 0013, LLP 0014, and LLP 0016 now identify their old mode, flag,
and string-policy passages as superseded. The canonical typed artifact, armed
snapshot, and target-bound conformance report are the current contracts.
ENG-24263 subsequently retired LLP 0013's executable string-policy corpus and
its 127 legacy fixtures. A checked 69-case retirement join names the current
typed, armed-engine, production-closure, or migrated diagnostic coverage for
every former test; the live callback harness now also proves package-global
withholding and native-freeze hatch removal, while process signaling is covered
inside the authenticated armed process-closure test.

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

| Work package | Linear issue | Blocked by                                            |
| ------------ | ------------ | ----------------------------------------------------- |
| Program      | ENG-24143    | completion is defined by the child graph              |
| WP0          | ENG-24144    | —                                                     |
| WP1          | ENG-24145    | ENG-24144                                             |
| WP2          | ENG-24146    | ENG-24144                                             |
| WP3          | ENG-24147    | ENG-24146                                             |
| WP4          | ENG-24148    | ENG-24145, ENG-24147                                  |
| WP5          | ENG-24149    | ENG-24148                                             |
| WP6          | ENG-24150    | ENG-24148                                             |
| WP7          | ENG-24151    | ENG-24148                                             |
| WP8          | ENG-24152    | ENG-24148                                             |
| WP9          | ENG-24153    | ENG-24149, ENG-24150, ENG-24151, ENG-24152            |
| WP10         | ENG-24154    | ENG-24145, ENG-24149, ENG-24150, ENG-24151, ENG-24152 |
| WP11         | ENG-24155    | ENG-24153, ENG-24154                                  |

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

## Resolved WP0 questions

1. Ibex owns the canonical contract and neutral crate boundary initially;
   another consumer reuses it or explicitly moves ownership, never copies it.
2. The profile is `ibex/capsec/1`; the neutral core is
   `capsec/semantics/1`.
3. Location, camera, microphone, and clipboard are target-specific authorable
   definitions; storage and unproved device families stay closed, absent, or
   unsupported exactly as the generated reconciliation records.
4. Production gets no raw/permissive developer harness; isolated fixtures and
   the explicit ephemeral audit workflow cover compatibility work.
5. WP9 may flip after one exact target is complete, but every incomplete build
   target refuses before project code. No target silently inherits another
   target's conformance or falls back to the legacy plane.
