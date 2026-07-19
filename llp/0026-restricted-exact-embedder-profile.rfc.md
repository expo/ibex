# LLP 0026: Restricted Exact Embedder Profile

**Type:** RFC
**Status:** Draft
**Systems:** Security, Runtime, Engine, Host ABI, Module Loader, Build, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-19
**Revised:** 2026-07-19 (r2 — implements the Phase 0 additive schemas,
full-edge-set-pinned 7,110-row projection, empty advertisement authority,
implementation-manifest binding, and mutation-sensitive drift gate; all 7,110
rows remain evidence-pending and no target is advertised)
**Related:** LLP 0002 (host embedding ABI); LLP 0013 (per-package capability compartments); LLP 0021 (capability-security effect model); Exact LLP 0373 (pooled server-resident Contract sessions, cross-repository consumer)

## 1. Summary

Ibex's full `ibex/capsec/1` target cannot advertise until every reachable
runtime, CLI, builtin, compatibility, native, loader, and host surface has
complete target-specific conformance evidence. That is the correct rule for
general Ibex execution. It currently leaves the Apple candidate with 22,996
required fixtures, of which 18,344 remain unresolved.

Exact does not need that general runtime inside its native and server-session
embedders. It needs a content-addressed Contract program, a closed bootstrap,
the dedicated binary `exact.invokeHostAsync` endowment, bounded event-loop
driving, and runtime destruction. This RFC proposes a separately identified
**restricted Exact embedder profile** whose smaller conformance inventory is
earned by making every excluded surface structurally absent or unreachable,
not by marking unsupported full-profile cells as passed.

The restricted profile is not an alternate interpretation of the existing
target advertisement. It has its own versioned profile identity, generated
surface closure, report, and advertisement. It cannot authorize `ibex run`,
REPL, raw eval, arbitrary filesystem modules, Node/Bun compatibility, ambient
networking, package-installed native code, inspector/debug operations, or a
generic host-call bridge. The existing `ibex/capsec/1` advertisements remain
empty until LLP 0021's full gate passes.

Exact LLP 0373 is the first consumer. Passing this RFC's profile gate would
permit only its hermetic armed-worker work; it would not authorize external
exposure or make either LLP accepted.

## 2. Motivation

LLP 0021 correctly rejects a target claim assembled from a few broad tests or
from caller-selected allowlists. Its current completeness domain, however, is
the complete general-purpose Ibex product. Requiring proof for thousands of
surfaces that an Exact embedder must never install couples a narrow embedded
runtime to unrelated CLI and compatibility work.

There are two unsafe shortcuts, both rejected:

1. advertise the full target with incomplete cells because the Exact fixture
   happens to work; or
2. let Exact bypass `authenticated_target_cells` and trust its operation
   manifest alone.

The proposed path is a third one: generate and enforce a smaller product whose
binary/runtime construction makes the omitted surface set unavailable. The
proof obligation moves from "test every full Ibex operation" to "test every
reachable restricted operation and prove the full-minus-restricted set is
absent at all attacker-reachable installation routes." No source edge simply
disappears from accounting.

## 3. Relationship to LLP 0021

This RFC amends LLP 0021's statement that Exact embedding cannot create a
second or weaker target-claim plane as follows:

- Exact still cannot weaken or bypass `ibex/capsec/1`.
- A restricted product profile is permitted only when it has a distinct
  profile ID and target-advertisement family, a source-derived closed-world
  inventory, a complete conformance report, and runtime enforcement that
  rejects profile confusion before engine allocation.
- Every full-registry edge must project exactly once to `reachable`,
  `structurally-absent`, or `trusted-control-plane`. `unsupported`, missing,
  caller-asserted, or prose-only projections cannot advertise.
- `structurally-absent` means no attacker-reachable global, import, callback,
  lazy installer, resolver, descriptor, or retained closure reaches the
  surface after bootstrap. A policy denial alone is not structural absence.
- `trusted-control-plane` is limited to fixed native lifecycle and artifact
  operations invoked by the embedder. It grants no JavaScript authority and
  carries its own negative caller/context fixtures.
- The full-profile registry, target cells, report, and advertisements remain
  unchanged and authoritative for general Ibex execution.

This is a profile split, not a conformance waiver.

## 4. Profile identity and anti-confusion rules

The v1 profile ID is `ibex/exact-embedder-contract/1`. Every artifact and live
runtime binds:

- profile ID and profile-definition digest;
- exact target triple and canonical engine-feature set;
- loaded Hermes binary identity;
- complete Ibex vocabulary and source-registry digests;
- restricted surface-closure digest;
- Exact operation-manifest digest and complete context endowments;
- content-addressed Contract bundle and root-set digests;
- canonical package graph (empty in v1);
- construction-fresh run nonce; and
- armed snapshot/expected-identity digest.

The profile is a target discriminator in addition to the target triple and
engine features. A full-profile advertisement cannot satisfy a restricted
claim or vice versa. The following reject before engine allocation or JSI
mutation:

- missing, unknown, duplicated, or mismatched profile IDs;
- a restricted artifact passed to a general constructor or CLI route;
- a general artifact passed to the restricted constructor;
- any stale/mismatched closure, registry, engine, operation-manifest, bundle,
  root-set, package-graph, nonce, or expected-identity digest; and
- a target/profile tuple without exactly one report-derived advertisement.

## 5. Closed-world surface projection

The generator consumes the same source-derived implementation manifest as LLP
0021. It emits one projection row for every full-registry edge:

```text
full edge -> reachable | structurally-absent | trusted-control-plane
```

Each row binds its source identity, installation phase, platform branch,
aliases, lazy routes, native callbacks, reachability roots, and required
fixture IDs. Generation fails on an unclassified edge or a many/zero-row join.

### 5.1 Reachable v1 surface

The initial reachable set is deliberately small:

- ECMAScript/Hermes primitives required by the compiled Contract bundle;
- the sealed Contract runtime bootstrap embedded in the authenticated bundle;
- the exact binary `exact.invokeHostAsync` method with a complete immutable
  app or agent endowment set;
- bounded timers/microtasks and event-loop polling required by the Contract
  profile;
- runtime-scoped renderer dispatch and semantic event ingress installed by the
  trusted embedder; and
- deterministic clock/RNG/checkpoint injection explicitly bound by the
  consumer artifact.

Every reachable surface receives ordinary effect/closure/non-capability cells
and executable fixtures. The Exact operation manifest does not classify Ibex
surfaces; it only narrows the already-conformant binary endowment channel.

### 5.2 Structurally absent v1 surface

At minimum the restricted runtime excludes:

- `ibex` CLI parsing/dispatch, REPL, inspector, debugger, raw eval, structured
  evaluation, and diagnostic audit entry;
- generic `__hostCall` / `__hostCallAsync` and their completion routes;
- Node/Bun compatibility globals and builtin imports except any primitive
  explicitly promoted into the reachable Contract set;
- ambient filesystem, environment, process, child-process, socket, DNS, HTTP,
  TLS, SQLite, native-addon, WASM, FFI, and package-resolution surfaces;
- worklet, Android bridge, camera, location, clipboard, accessibility, and
  other platform capability installers not named by the profile; and
- dynamic code/source loading after the one authenticated bundle ingress.

Absence is enforced by a profile-specific bootstrap/install plan rather than
post-hoc deletion. The generated closure contains two-way checks: every
installed attacker-reachable native belongs to the reachable inventory, and
every reachable inventory row is observed at its declared identity. Descriptor
walking alone is insufficient for values retained in closures; source install
identity and live invocation probes are both required.

### 5.3 Trusted control plane

The initial fixed native control plane may:

- prepare and install one authenticated restricted artifact;
- create/destroy exactly one runtime bound to that artifact;
- load exactly the authenticated Contract bundle through the ingress in §6;
- install exact renderer/event/binary-host callbacks on the owning runtime;
- poll bounded work and inject authenticated events/checkpoints; and
- request termination and observe teardown receipts.

These functions are not JavaScript endowments. Their fixtures prove wrong
thread, wrong runtime, wrong generation, wrong profile, replay, replacement,
and post-destroy calls fail before mutation.

## 6. Authenticated Contract code ingress

The restricted profile never executes caller-supplied bytes through generic
`ex_hermes_eval`. Its production ingress accepts an immutable bundle artifact
whose bytes, format (`source-utf8` or an explicitly versioned HBC format), root
set, Contract IR, build identity, and module graph are authenticated by the
armed snapshot.

V1 admits one closed, self-contained bundle and no runtime filesystem module
resolution. If the bundle contains multiple modules, their complete graph and
content digests are part of the artifact and resolution never falls back to a
host path, cwd, package manager, URL, or ambient loader. Evaluation occurs only
after the runtime has verified the exact profile/engine/snapshot handshake and
installed its capability membrane, output sink, clock/RNG, and checkpoint
validator. Publication remains disabled until the consumer commits the turn.

The ingress is single-use per runtime generation. Replay, a second bundle,
wrong bytes, wrong format, path/source-URL substitution, post-start mutation,
and code execution before callback/membrane installation all fail closed.

Diagnostic constructors and raw eval remain available only to explicitly
diagnostic tests; they cannot consume a restricted production artifact or
emit restricted conformance evidence.

## 7. Construction and lifecycle

The public ABI gains a profile-distinct construction path (exact spelling
chosen during implementation) rather than overloading the generic constructor
with caller policy. The target-local artifact producer derives the restricted
surface closure and the Exact bundle/operation bindings itself; callers cannot
submit an allowlist or claim that a surface is absent.

The lifecycle is:

1. validate target-local protected objects and construct a fresh artifact;
2. authenticate the unique target/profile advertisement;
3. atomically install the armed Host context;
4. construct Hermes with the profile-specific install plan;
5. verify the runtime/engine/snapshot/profile handshake;
6. install the binary Exact endowment, dispatch, event, clock/RNG, checkpoint,
   and bounded output callbacks on the owner thread;
7. execute the single authenticated bundle;
8. run bounded turns; and
9. destroy the runtime and return a teardown receipt.

Any failure after Host-context installation consumes or revokes that context.
No later diagnostic or general runtime may claim it.

## 8. Generated authority and conformance

The restricted profile has additive, versioned authorities beside LLP 0021's
full-profile files:

- profile definition and schema;
- complete full-edge projection and closure digest;
- target cells keyed by target, features, and profile;
- conformance-report schema and content-addressed attestations; and
- report-derived target advertisements.

An advertisement is generated only when:

1. projection is total and unique over the full implementation manifest;
2. every reachable and control-plane obligation has fixture-specific executed
   evidence on the exact engine artifact;
3. every structural-absence obligation passes source-install and live
   reachability/invocation evidence;
4. the hostile profile-confusion, artifact-tamper, loader, bridge, lifecycle,
   and teardown corpus passes;
5. all registry/codegen/drift checks pass from a clean revision; and
6. an independent security review has no unresolved critical/high finding.

Broad suite success cannot synthesize per-obligation passes. Missing, generic,
duplicated, stale, or cross-profile evidence keeps the report incomplete.

The first candidate is `aarch64-apple-darwin` for native correctness. Linux is
a separate target report required before Exact LLP 0373 may claim its Linux
cell-isolation gate. No Apple result is transferable to Linux containment.

## 9. Security invariants

1. The restricted profile grants no authority that is absent from its
   authenticated reachable/control-plane inventories.
2. Omission from the reachable set is never treated as evidence of absence.
3. JavaScript cannot select its profile, operation set, bundle, principal,
   session, lease, cell, checkpoint generation, clock, RNG, or output sink.
4. Only the dedicated binary Exact channel crosses from JavaScript to native;
   generic host bridges remain absent.
5. Code ingress is content-addressed, graph-closed, single-use, and occurs only
   after the membrane and sinks are installed.
6. A runtime handle, call ID, event binding, and callback is generation-scoped
   and becomes unusable after destruction.
7. A restricted advertisement authorizes only the restricted constructor and
   never an Ibex CLI/general runtime.
8. Full and restricted target claims remain separately digest-bound; neither
   can satisfy or promote the other.

## 10. Implementation program

### Phase 0 — authority and projection

- add the profile/schema and additive advertisement family;
- generate the total full-edge projection;
- build the profile-specific install plan and two-way reachable-native
  inventory;
- define authenticated bundle and lifecycle records;
- add profile-confusion and mutation tests; and
- preregister the candidate report and fixture plan before promotion work.

Exit: all generators are deterministic, the projection is total, mutation
fixtures prove omissions/confusions are detected, and advertisements remain
empty.

Implementation status (2026-07-19): the additive definition, projection, and
advertisement schemas and their non-writing drift gate are implemented. The
authored definition pins the exact 7,110-edge full-registry set and binds each
of 20 candidate reachable and nine existing trusted-control-plane rows to its
source-derived kind and name; the remaining 7,081 rows are candidate
structural absences whose source-install and live-reachability evidence is
explicitly pending. The projection also binds the raw definition, coverage,
implementation-manifest, and three profile-schema byte digests. Six mutation
tests reject edge-set addition/removal/duplication, implementation-manifest
divergence, disposition overlap, bound-identity drift, ordering drift,
raw-byte/object mismatch, advertisement attempts, projection omission, and
digest tampering. The four
existing generic artifact/install/create edges are deliberately *not* trusted
restricted control-plane rows: profile-distinct replacements must first enter
the full registry and then be explicitly admitted. Advertisements remain
empty and `promotionReady` remains false.

### Phase 1 — Apple vertical slice

- implement target-local artifact construction and restricted Hermes creation;
- implement single-use authenticated Contract bundle ingress;
- install the Exact binary endowment and renderer/event callbacks;
- run fresh-runtime restore and hostile lifecycle fixtures; and
- produce the complete Apple report and independent review.

Exit: the exact Apple target/profile advertises from one complete report and
the armed Contract activation runs without diagnostic constructors or raw eval.

### Phase 2 — Linux containment target

- reproduce the complete profile report on the registered Linux engine;
- integrate with the consumer's external process/cell supervisor;
- execute kill-at-every-edge and hostile ambient-channel corpora; and
- prove teardown/reuse without cross-session authority.

Exit: the exact Linux target/profile advertises from its own report and the
consumer's containment gate passes. This does not authorize network exposure.

## 11. Kill rules

Do not advertise or cross the failed phase if any of these remains:

- a full-registry edge has no unique projection;
- an excluded surface is reachable or invocable after restricted bootstrap;
- a reachable/control-plane surface lacks fixture-specific executed evidence;
- generic eval, host-call, loader, CLI, or compatibility paths accept the
  restricted artifact;
- code executes before profile/engine/artifact verification and membrane/sink
  installation;
- target/profile/artifact confusion is accepted;
- runtime destruction leaves callable state, pending completion authority, or
  reusable Host context;
- any report is synthesized from broad tests or from another target/profile;
  or
- independent review retains a critical/high finding.

The response is fix-and-rerun, narrow the profile further, or stop. It is never
to add an exception, mark a cell passed by policy, or consume the general
target's incomplete evidence.

## 12. Alternatives

### 12.1 Complete the full Ibex target first

This remains valid and necessary for general `ibex run`, but it couples the
Exact worker to 18,344 currently unresolved fixtures for surfaces the worker
must never expose. The restricted profile can produce useful security evidence
sooner without weakening that work.

### 12.2 Let Exact bypass target advertisement

Rejected. The operation manifest is an endowment binding, not a proof of
complete runtime reachability or closure.

### 12.3 Treat policy denial as structural absence

Rejected. A denied but installed surface still expands the enforcement and
confused-deputy TCB. The profile exists to remove that surface and prove the
removal.

### 12.4 Build a separate Contract-only engine wrapper outside Ibex

This could be smaller, but it would duplicate Hermes bootstrap, runtime
identity, callback, and lifecycle machinery. A generated restricted Ibex
profile preserves one engine integration while keeping its claim distinct.

## 13. Open questions

1. Should v1 use a distinct constructor symbol or one constructor whose signed
   artifact selects a closed enum profile? The former is easier to audit; the
   latter reduces ABI surface.
2. Is source UTF-8 sufficient for the first report, or should authenticated HBC
   be required to avoid runtime parsing in the worker?
3. Which minimal timers/microtask primitives does the hibernation-safe Contract
   corpus actually require, and can connected-idle wakes remain entirely
   device/coordinator owned?
4. Should renderer dispatch and semantic event ingress be part of the Ibex
   restricted profile inventory or a consumer-owned callback layer with only
   fixed ABI obligations in Ibex?
5. Can the same source projection drive Apple and Linux install plans without
   hiding platform-conditional native branches?
6. What maximum restricted obligation count and implementation budget triggers
   a stop-and-reassess disposition before this becomes a second general runtime?
