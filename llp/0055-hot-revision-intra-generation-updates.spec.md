# LLP 0055: Hot Revisions — Intra-Generation Module Updates (Exact 0417 H1 Surface)

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Engine, Runtime, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-24
**Revised:** 2026-08-24 (r2 — round-1 dual-family fold, all findings verified against primary
sources (codex gpt-5.6-sol xhigh, repo access; grok-4.6 xhigh, full-diff-inlined; both NOT READY
with strongly convergent MATERIALs — artifacts in `llp/reviews/`). Adopted: slot resolution
extended from namespace getters to EVERY cross-module use surface after code verification that
`link_import`/`link_export` capture record ids (`import_bindings.target_record_id`,
`alias_record_id`) — per-use lookup or atomic commit-time relink, importers never re-run; the
namespace exotic object is slot-owned, one per `(generation, SourceId)`, with the never-shared
list restated as environments/cells/promises/errors/CJS export objects; cross-closure CJS
named-import boundaries refuse (0417's sharp edge, previously omitted); the v2 ceiling
additionally pins deferred-dynamic/deferred-CJS membership, bootstrap-internal CJS sets, and
computed-site attributes, and EVERY ceiling breach keeps the landed restart-class disposition
verbatim (the earlier full-reload softening is withdrawn; the server pre-classifies
shape-changing edits before staging, and v1's reload-recreate derives a fresh ceiling); the
transaction gains a typed state machine with commit legal only from `ReadyToPublish`
(effectful-unknown refused structurally at stage; observed-class mismatch, throwing dispose,
and post-preflight evaluation failure get explicit rows); §5.3 becomes a no-fail commit bundle
(all fallible work first; live-graph row swap + v2 digest recompute inside it; a consumer
activation hook inside the fence; invariant failure quarantines into runtime recreate, never an
ordinary refusal); shadow evaluation gets its transaction-local publication predicate;
loader-cache surgery is pinned loader-private/non-reentrant with a no-capture-table-reentry
rule; prepared-carrier handling rewritten from per-SourceId "eviction" to provenance switch +
reference-counted table retirement (the memo is keyed per (principal, compartment, carrier
digest) — multi-source, so eviction was undefined); the signed base-graph digest is pinned to
the live v2 digest at successor-law base (g, r), and the replay law realigned to Exact
0553.001's duplicate-first idempotence (exact duplicate returns the prior receipt; same-id/
different-bytes is `update-identity-conflict`); receipts become advisory/diagnostic — the
consumer executes class-correct recovery from its own verdict (v1 recreate is host-driven
anyway), discharging H0 MATERIAL 1 by de-fanging rather than an authentication the loopback
posture cannot provide, and ingestion gains pre-parse byte/depth/shape/budget bounds (H0
MATERIAL 2); §2.1's incarnation prohibition gains the named v1 ambient-effect exception (the
effect-class admission is the detectable guard; the lease is the future fix); slot granularity
and the `hot.data` value algebra are re-marked OPEN as Exact 0417 OQ4 — owned there, not here;
the race-lost class stays 0417's full-reload assignment with a recorded compatibility note
recommending a 0417-owner refinement to keep-last-good. Declined, with reasons recorded in the
review artifacts: moving dispose after commit (contradicts 0417 §4.8 rule 3's normative
dispose-before-evaluate and its degraded semantics); refusing revisions on "outstanding ambient
effects" (no effect census exists — the declared class is the detectable proxy).)
**Revised:** 2026-08-24 (r1 — initial draft; commissioned by Exact LLP 0417 Phase H1 after the
H0 spike's stop rule did not fire (Exact `docs/reports/0417-h0-spike.md`: median 67.7 ms vs the
250 ms line). Settles Exact 0417 OQ1/OQ2 (ceded to this corpus) and discharges or schedules
every Exact 0417 §6 H1 entry obligation. Amends LLP 0023 §2.3, 0024 §7.9, 0026 §8/Terminology,
0027, and 0042 as one coherent set; those edits land with this document. Renumbered 0054→0055
pre-review: 0054 is claimed by the capsec posture lane.)
**Related:** LLP 0023 §2.3 (module/incarnation identity — amended), LLP 0024 §7.9 (module cache —
amended), LLP 0026 §8 + Terminology (development/HMR — amended), LLP 0027 (artifact wire and
interop — amended: mixed record provenance, revision-aware pin/retirement semantics, CJS
boundary rule), LLP 0042 (prepared-graph commitment — amended: update-payload signature and
verifier delivery), LLP 0038 (unadvertised dev arming), LLP 0002/0003 (owner-thread drive
contract), Exact LLP 0417 (the program; its §4.8 refusal taxonomy and effect classes are
consumed, not restated; its OQ4 remains open and owned there), Exact LLP 0553 §9 D2 / 0553.001
§2.2 + §10 O-3 (the HotRevision successor law this spec owns; the replay law §6 aligns to),
Exact `docs/reports/0417-h0-spike.md` + `0417-h0-spike-security-review.md` (three carried
MATERIALs — §9 here)

## Summary

Exact 0417 adopted a two-level execution model: an **ExecutionGeneration** is one complete
authenticated graph/runtime lifetime — this corpus's landed contract, across which no live record
ever crosses — and a **HotRevision** is a new transaction *within* one execution generation that
swaps replacement verified records for an accepted invalidation closure behind stable logical
slots. The generation level is landed (`generation.rs`, LLP 0026 §8, LLP 0023 §2.3 / 0024 §7.9 as
amended by ENG-25065). The revision level did not exist. This spec defines it:

1. the **HotRevision counter** and its successor law (the Exact 0553.001 O-3 answer),
2. the **per-slot incarnation predicate** that fences stale completions per module, not per
   transaction — with its transaction-local shadow twin,
3. the **typed authenticated graph** extension of `generation.rs` (digest, immutable ceiling, and
   adversarial tests over `GraphEdgeKey` + candidate/deferred/bootstrap facts),
4. the **revision-scoped staging seam** (a typed-state Rust host surface; the boot-time
   dev-served capture table stays exactly-once),
5. **slot-based relink covering every cross-module use surface** (the concrete runner changes),
6. the **update-payload signature** under an ephemeral dev-session keypair (the LLP 0042
   amendment) with 0553.001-aligned replay law, and
7. the **v1 full-reload posture**: runtime recreation, with the surviving-runtime
   advance-and-retire named as a post-v1 optimization gated on retirement fixtures.

Nothing here touches armed admission, production behavior, or authority: hot revisions consume
generation authority under the immutable ceiling; they never mint capability.
`GenerationMode::Production` continues to refuse `begin_update` before any of this is reachable.

## 1. The HotRevision counter and successor law

**Definition.** `HotRevision` is a `u64` scoped to one `(runtime/session identity,
ExecutionGeneration)`. The boot graph of a generation is revision **0**. Every committed hot
revision advances the counter by exactly one.

**Successor law (normative — Exact 0553.001 §2.2 / §10 O-3).** A staged revision binds its base
coordinate `(ExecutionGeneration g, HotRevision r)`. Commit refuses unless the live coordinate
equals exactly `(g, r)` at the single publication point, evaluated under the owner's exclusive
access (`&mut` — the same compare-and-swap discipline `generation.rs` applies to generations);
the committed revision is then `r + 1`. There is no other legal successor: no skips, no
out-of-order commit, no merge of concurrently staged revisions — the loser of a race refuses,
its shadow records drop whole, and the **producer** restages against the consumer's committed
coordinates (reported in the refusal receipt). This confirms Exact 0553.001's interim
"exactly-live-plus-one against the consumer's local revision counter" as the permanent law; the
consumer's live counter is the authority, and wire fields are claims checked against it.

**Overflow.** `HotRevision` exhaustion refuses into the full-reload class. It never wraps. A
generation transition starts the **new** runtime's generation at revision 0; nothing resets a
counter on a dying runtime.

**Counter relationships (Exact 0417 OQ1, settled).** Four counters exist and stay distinct:

| Counter | Owner | Moves when |
| --- | --- | --- |
| authority generations (`SnapshotGenerations`) | armed CapSec snapshot | never during a runtime's life; drift refuses into the restart class |
| `ExecutionGeneration` | the producing session (dev server / host shell), consumed by the module runner | full reload — v1: runtime recreation (§3) |
| `HotRevision` | the runner's revision surface (§5), per generation | each committed hot revision |
| dev-server graph epoch / host engine counter | Exact's server and shell | their own machinery; they *carry* the two coordinates above, they do not define them |

Today `runner_pipeline.rs` derives its `graph_generation` from the armed snapshot's dynamic grant
generation (`snapshot.generations().dynamic.get().max(1)` — an *authority* counter that LLP 0026
§8 forbids HMR from touching), and the executable path additionally hard-codes generation 1. H1
decouples them: the pipeline takes an explicit `ExecutionGeneration` input minted by the
producing session — the same value the LLP 0042 dev commitment already carries as
`session.generation` — and the engine pin ABI (`ex_hermes_module_pin_generation`) pins that
value. The authority generations remain inside the armed snapshot and are compared only by the
immutable ceiling. Production continues to pin exactly one generation for the runtime's life;
nothing observable changes there.

## 2. Incarnations, slots, and the per-slot predicate

### 2.1 Incarnation key (amends LLP 0023 §2.3, 0024 §7.9, 0026 §8 + Terminology)

A live module incarnation is named

```text
(runtime/session identity, SourceId, ExecutionGeneration, install revision)
```

where **install revision** is the `HotRevision` at which the record was installed — 0 for boot
records. It is NOT "the current revision": committing revision `r+1` does not restamp records it
did not replace. Per `(generation, SourceId)` exactly one incarnation is live at a time;
successive committed revisions that replace a module create successor incarnations *within* the
generation. Live module environments, binding cells, promises, cached errors, and CommonJS
export objects never cross incarnations — LLP 0023's cross-generation prohibition applies at the
incarnation boundary, with two named exceptions, both deliberate:

- the `hot.data` handoff Exact 0417 §4.4 defines, passed through the dispose/accept protocol —
  its value algebra (plain values vs handles with disposers) is Exact 0417 **OQ4, open and owned
  there**; this spec constrains only that no live record, cell, or namespace may ride it;
- **v1 ambient effects are not retired at the incarnation boundary.** Timers, subscriptions,
  host registrations, and global mutations made by a replaced incarnation that its `dispose` does
  not clean up keep running — there is no effect census to fence them with. The detectable guard
  is the effect-class admission (§7): `contract-staged-pure` boundaries declare no such effects
  (observed mismatch refuses), `dispose-registered` boundaries retire their own, and everything
  else refuses into a coherent full reload. The candidate-effect lease (§7) is the future
  mechanism that makes this exception removable.

### 2.2 Per-slot incarnation predicate (Exact 0417 H1 entry obligation 1)

`GenerationPublicationToken` gains the install revision:

```text
token = (ExecutionGeneration, SourceId, install revision, semantic digest)
```

**Live predicate.** `publish(token, kind)` succeeds iff `token.generation == live.generation`
**and** `token.install_revision == current_install_revision[source_id]` **and** the semantic
digest matches the live record. The revision counter is the *transaction* coordinate; the
predicate is per slot. The lookup `publish` performs and the lookup the §2.3 slot surfaces
perform read the **same** slot authority, updated indivisibly inside the §5.3 bundle — no
ordering window exists in which a getter sees the new record while an old token can still
publish. Consequences, both fixture-pinned (§11 F1):

- an **unchanged** module's in-flight completion (TLA continuation, dynamic import, CJS cache
  publication, artifact-cache publication, error) still publishes after later revisions commit —
  its slot's install revision did not move;
- a **replaced** module's stale completion refuses — its token's install revision is older than
  the slot's.

All six `GenerationPublicationKind`s obey the same predicate: `Evaluation`, `TopLevelAwait`,
`DynamicImport`, `Error`, `CommonJsCache`, `ArtifactCache`.

**Shadow predicate (transaction-local).** Staged records evaluate under the candidate install
revision `base + 1` before commit (§5.2). Their completions publish into the **transaction's
shadow map only**: a shadow token is valid iff `token.install_revision == txn.base + 1` **and**
`source_id ∈ txn.invalidated`. The live predicate never sees shadow rows; a refused transaction
drops its shadow completions whole; commit adopts them with the records in the §5.3 bundle.

### 2.3 Stable logical slots: every cross-module use resolves through the slot

A **stable logical slot** is a generation-owned forwarding *binding target* keyed by
`(ExecutionGeneration, SourceId)`: it targets exactly one incarnation's records at a time, and
commit retargets the slots for the accepted closure inside the §5.3 bundle.

**The slot-owned namespace.** The ESM namespace exotic object an outside importer holds is
**slot-owned** — one per `(ExecutionGeneration, SourceId)`, identity-stable for the generation.
It is not any incarnation's private namespace: its per-export getters resolve through the slot at
call time, so after a commit they read the successor incarnation's cells and must never expose a
prior incarnation's. This is how the amended LLP 0023 prohibition and namespace stability
coexist: what incarnations must never share is module environments, binding cells, promises,
cached errors, and CommonJS export objects — the slot-owned facade is generation property, not
incarnation property.

**Every use surface, not just getters (normative — the concrete runner changes).** The landed
runner binds cross-module uses by captured record id in several places: namespace per-export
getters capture `(graphGeneration, recordId)` at instantiate; static named/default imports are
linked into `import_bindings` entries carrying `target_record_id`; re-export and star forwarding
store `alias_record_id`/`alias_export` on export cells; dynamic-import completions hand out
namespaces; CJS→ESM adapters snapshot exports. Retargeting only the getters would leave named
imports and re-export chains reading the old incarnation. Therefore: **every cross-closure use
of a replaced boundary's exports — namespace getters, static import bindings, re-export/star
aliases, dynamic-import namespaces — must observe the successor incarnation after commit and the
prior incarnation before it, with no mixed state observable.** The implementation may satisfy
this per surface by call-time slot lookup (an engine-owned slot table
`(ExecutionGeneration, SourceId) → live record id`) **or** by atomic relink of the captured
bindings inside the §5.3 bundle — relink is a binding rewrite, never a re-evaluation; importers
are not re-run either way. §11 F5 pins all surfaces.

**CommonJS boundaries refuse (v1).** CJS→ESM adapter namespaces are non-extensible data-property
snapshots (detected named exports do not update after `module.exports` mutation), and CJS export
objects must not cross incarnations. Exact 0417 §4.8 already names the edge: **a hot revision
whose accepted boundary is consumed from outside the closure through CJS named imports — or
whose CJS adapter/export object is held outside the closure — is ineligible and refuses
(full-reload class, `cjs-cross-boundary`).** Whole-closure CJS replacement (adapter and its
consumers all inside the invalidation set) remains eligible. §11 F10 pins success, throw/sticky
error, `default`, `'module.exports'`, and detected-named-export cases.

**Export-shape eligibility (consumed from Exact 0417 §4.1).** A replacement is slot-eligible only
if its export names, property descriptors, and interop shape are identical to the prior
incarnation's; any add/remove/rename/interop change is the `export-shape-changed` refusal
(full-reload class). ESM namespaces are non-extensible, so this is a structural constraint, not a
policy choice. §11 F6 pins it.

**Granularity (Exact 0417 OQ4 — open, owned by Exact).** v1 operates per-module (`SourceId`)
slots with the per-surface resolution above. Finer (per-export-cell) or coarser (closure-edge)
granularity, like the `hot.data` value algebra, is 0417 OQ4's question; this spec records the
per-module position as its **proposal to the 0417 owner**, not a settlement.

## 3. Generation transitions: v1 recreates the runtime

A full reload must be a genuine `ExecutionGeneration` transition. The landed engine cannot yet
prove fresh-boot equivalence for a surviving-runtime transition: `ex_hermes_module_unpin_generation`
releases ESM/CJS records, dynamic activation requests, and context references, but not timers,
next-ticks, arbitrary globals, or host registrations. Therefore, normatively:

- **v1: the full-reload class tears down and recreates the runtime.** The producing session mints
  the next `ExecutionGeneration`; the new runtime arms, boots, pins it, and derives a **fresh
  immutable ceiling from its new boot graph** — which is how everyday shape-changing edits (a
  new import, a deferred-bit flip) are served without ever weakening the ceiling (§4). Policy is
  unchanged; only the execution coordinate advances. The consuming host (Exact's runtime shell)
  owns the teardown/recreate mechanics.
- **Post-v1: surviving-runtime advance-and-retire** (unpin + retire every state owner + fence
  stale completions in place) is an optimization gated on generation-owned cancellation/fencing
  for *every* ambient-effect surface, proven by retirement fixtures: stale-TLA, dynamic-import,
  CJS cache, prepared-carrier table, publication token, **and timer / next-tick / global /
  host-registration** retirement, each demonstrating fresh-boot equivalence. Until those fixtures
  exist and pass, no consumer may claim the surviving-runtime path.

The restart class (`regenerate-policy-and-restart-runtime` — authority drift, package-integrity
drift, widening) is *stricter* than the full-reload class: it additionally regenerates policy and
re-arms. A plain reload must never impersonate it (Exact 0417 §4.8).

## 4. The typed authenticated graph (obligation 4)

`generation.rs`'s transaction/refusal algebra is adopted; its graph data model is extended — not
reused unchanged — because its records key bindings by `BTreeMap<String, SourceId>` while the
live runner keys edges by `GraphEdgeKey { specifier, resolution_kind }` plus candidate/deferred
tables. Identical spellings resolve differently under static ESM, dynamic import, and CJS; a
ceiling that cannot see `resolution_kind` cannot guard the live graph.

**V2 record and digest (normative).** `GenerationRecordV2` carries:

- `artifact` (as today),
- `bindings: BTreeMap<GraphEdgeKey, SourceId>` — typed link-time and literal call-time edges,
- `candidate_table_digests` — the `ibex/computed-candidates/1` sidecar digest per computed site
  the record owns (site-keyed; candidates never flatten into `bindings`), together with each
  site's authenticated attributes,
- deferred-membership facts: which literal dynamic-import / literal CommonJS-require edges are
  deferred (outside eager evaluation/SCC/TLA traversal), and the bootstrap-internal CJS set.

The graph digest moves to domain `ibex/module-generation-graph/2` and covers every row above
(specifier, resolutionKind, target per edge; candidate digests + attributes; deferred facts;
bootstrap-internal membership). V1-domain digests are not comparable and refuse.

**V2 ceiling — named `ImmutableGenerationAdmissionV2`.** Its edge set is
`BTreeSet<(SourceId, GraphEdgeKey, SourceId)>`, and it additionally pins, per record: the
candidate-site set `(requester, site ordinal) → candidate-table digest + attributes`, the exact
deferred-dynamic and deferred-CJS membership, and the bootstrap-internal CJS set. **Every
ceiling breach keeps the landed disposition verbatim: `regenerate policy and restart the
runtime` — the restart class.** No breach is softened to a plain reload: a hot revision may not
add or retarget an edge, add or alter a computed site, flip a deferred bit, or grow the
bootstrap-internal set, whatever the root authority would notionally allow. This is defense in
depth, not the everyday path: the producing server classifies shape-changing edits into the
reload class **before** staging a revision (the boundary computation sees the graph change), and
v1's reload-recreate derives a fresh ceiling from the new boot graph (§3), so a developer adding
an import never experiences the restart class unless an update that should never have been
staged reaches commit.

**Adversarial tests.** Every ceiling/adversarial test is rebuilt over **non-empty typed binding
maps** (the landed tests use empty maps, so the ceiling was never exercised against real edges).
Named acceptance fixtures (§11 F4): (a) one record carrying **two same-spelling edges of
distinct `resolution_kind`** over a non-empty binding map, proving both edges enter the digest
and ceiling distinctly, and that a candidate widening one kind refuses even when the identically
spelled other kind is authorized; (b) a candidate-site digest or attribute change refuses; (c) a
deferred→eager flip on an authorized edge refuses; (d) a bootstrap-internal set change refuses.

## 5. The staging seam (Exact 0417 OQ2, settled)

### 5.1 Not the capture table

The dev-served capture table (`captureDevServedModuleTable`) is a frozen exactly-once boot
handshake with quarantine semantics; reopening it per revision would dissolve exactly the
property it exists to enforce. It stays boot-only, byte-for-byte unchanged. Hot revisions enter
through a **new revision-scoped Rust host surface** — and after a commit, resolution of a
replaced `SourceId` goes only through the installed revision records: **no code path may
re-enter the capture table, trigger its quarantine, or re-serve boot bytes over a committed
incarnation** (§11 F7).

### 5.2 `HotRevisionSurfaceV1` — a typed transaction state machine

Owned by the module-runner pipeline, exclusive (`&mut`), owner-thread only (LLP 0002/0003 drive
contract). States: `Begun → Staged → Preflighted → Evaluated → ReadyToPublish → Committed |
Refused`. Commit is legal **only** from `ReadyToPublish`, a state the surface itself issues —
never the consumer.

1. `begin_revision(policy, origin, base: (ExecutionGeneration, HotRevision), invalidated) →
   Begun` — refuses in production mode; re-validates authority; refuses an empty or
   graph-widening invalidation set (the `generation.rs` preconditions, revision-scoped).
   `begin_revision` does **not** require `base` to equal the live coordinate — staging is
   optimistic and concurrent transactions may exist; only commit CASes (§1). §11 F2 stages two
   overlapping transactions.
2. `stage_replacements(txn, replacements) → Staged` — replacement records enter **only** as
   `VerifiedModuleArtifactV1` tokens plus typed edge/candidate/deferred metadata and the
   declared per-boundary effect class; raw deserialization never reaches staging. **A declared
   `effectful-unknown` class refuses here, structurally** — the state machine has no path that
   hot-applies it (Exact 0417 §4.8 rule 4). Staged records are shadow records: invisible to the
   live graph, keyed at candidate install revision `base + 1`.
3. `preflight(txn) → Preflighted` — compile/link the staged closure (factory compile, link-plan
   validation, export-shape comparison against the live incarnations, CJS-boundary eligibility
   §2.3) **without running any app code**. Failures here refuse with zero app-visible effects.
4. **Evaluation → `Evaluated`.** Class-appropriate, per Exact 0417 §4.8 — this surface exposes
   both orderings; the declared class selects one:
   - `contract-staged-pure`: shadow-evaluate the staged incarnations under the §2.2 shadow
     predicate; a throw refuses (`keep-last-good`) with the live graph untouched.
   - `dispose-registered`: stock dispose-before-evaluate. **The effects/publication split is
     explicit:** dispose is a bounded JavaScript effect under the consumer's 0417 rule-3
     ordering, never part of publication; it runs against the last *committed* incarnation,
     at most once per apply. If evaluation then throws, the module stays torn down until the
     next successful update — 0417's documented degraded state, `keep-last-good` class; records
     still never partially publish. A **throwing dispose** refuses the revision (full-reload
     class, 0417 rule 5).
   An observed effect-class mismatch (e.g. a `contract-staged-pure` boundary registering a
   dispose, or registering ambient effects during shadow evaluation where detectable) refuses
   (full-reload class). Reaching `Evaluated` requires: staged evaluation settled (including
   shadow TLA — a still-pending or rejected shadow TLA is not `Evaluated`; rejection refuses
   `keep-last-good` and the sticky shadow error drops with the transaction), CJS records inside
   the closure finalized, and dispose (where registered) completed without throw.
5. `ready(txn) → ReadyToPublish` — the surface verifies the state invariants above and freezes
   the candidate; then `commit(policy, txn)`: authority re-validation, transaction
   authority-stamp staleness check, successor-law CAS (§1), full post-revision graph validation
   against the v2 ceiling, converse check (no change outside the invalidation set), then the
   §5.3 bundle. Any refusal at any state drops shadow records and shadow completions whole; the
   live graph, revision counter, and install revisions are untouched, and the refusal maps to an
   Exact 0417 §4.8 class (§10).

### 5.3 The commit bundle (atomic, owner-thread, no-fail)

**All fallible work happens before the bundle**: verification, ceiling and converse validation,
CAS, compilation, linking, class-appropriate evaluation, export-shape and CJS eligibility checks
— everything that can refuse has refused by the time the bundle starts. The bundle itself is a
sequence of infallible, prevalidated publication operations executed as one owner-thread
critical section with **no app/user JavaScript interleaved**; if an invariant violation is
nevertheless detected mid-bundle, the runtime **quarantines and recreates** (fail-stop into the
v1 generation transition) — it never returns an ordinary refusal from a half-published state.
Replacement records are fully instantiated and past export TDZ before any of this is visible.

In order:

1. **Live-graph adoption:** swap the accepted closure's rows into the live `GenerationRecordV2`
   map (record and binding ownership passes from the transaction to the generation) and
   recompute the live v2 graph digest — the digest the next envelope's §6 base binding is
   verified against.
2. **Install-revision advance** for replaced `SourceId`s (§2.2) — the same authority `publish`
   reads.
3. **Slot retargets and binding relinks** (§2.3): slot-table writes plus whichever captured
   bindings (import bindings, export aliases) the implementation relinks rather than
   indirects.
4. **Consumer activation hook:** one registered callback slot through which the consumer's
   prepared activation (Exact's two-phase Contract adapter / root swap — 0417 §4.8's
   remount-joins-publication rule, obligation 2's seam) executes inside the same fence. The
   hook's work must itself be prevalidated/no-fail by the §8 contract; it may not run app JS.
5. **Loader-cache surgery** for replaced modules through a bootstrap-installed private bridge
   (`__privInvalidateHotRevisionRecords` class — sealed with the other `__priv*` bridges, never
   realm-visible, callable only from the engine's commit path). The surgery is loader-private
   cache-map manipulation: it runs **no user code** (the cache is a null-prototype map; no
   getters, proxies, or app callbacks are reachable) and is non-reentrant. Post-commit
   resolution obeys §5.1's no-capture-table rule.
6. **Prepared-carrier provenance switch:** replaced `SourceId`s' records now carry inline
   source-artifact provenance and stop consulting the prepared-carrier table. The carrier
   table itself (keyed per `(principal, compartment, carrier digest)` and shared by many
   sources) is **reference-retired, not evicted**: the bundle retires the replaced records'
   references; the shared table is released only when no live prepared record references it.
   Untouched records keep their carrier provenance and their table untouched.
7. **Revision counter advance and receipt emission.**

A refused revision performs none of these. No importer can observe a state between them.

### 5.4 Mixed record provenance (amends LLP 0027)

Replacement records carry inline source-artifact payloads and join a live generation whose other
records may carry prepared-carrier (HBC) provenance. This is the **sanctioned post-boot path** by
which source records join a prepared generation: boot admission is not relaxed (prepared-HBC
boots stay uniform; carrier admission is unchanged; LLP 0027's "rejects mixed inline/prepared
graphs" remains the boot/rejoin-admission rule); untouched records keep their carrier provenance
and table references; replaced `SourceId`s switch provenance per §5.3.6. HBC carriers are never
mutated, patched, or partially replaced (Exact 0417 Goal 2; LLP 0127's decision on the Exact
side).

## 6. Update-payload authentication (obligation 3; amends LLP 0042)

The dev session gains an **ephemeral signing keypair** beside the existing HMAC secret, same
custody rule (private key only in the producing session's process memory; never on disk; rotates
with `runId`). The HMAC continues to bind the *boot* commitment; the keypair signs *update
payloads*, because a device must verify what a producer-only symmetric secret cannot let it
verify. The public verifier is **delivered beside the commitment, not HMAC-covered**, and the
production commitment schema structurally rejects the keypair fields.

- **Algorithm and encoding:** Ed25519 (RFC 8032) over the JCS-canonical signed body, domain
  `ibex/hot-update-signature/1`. The public verifier rides the startup session envelope in the
  v1 loopback posture; the LAN/device follow-up binds it at boot enrollment instead (Exact 0417
  §5/OQ5 — not this spec's scope).
- **Signed body (all fields normative):** schema id; `runId`; authority stamp (armed snapshot
  digest + `SnapshotGenerations` echo); `ExecutionGeneration`; base and target `HotRevision`
  (target = base + 1 by §1); `updateId`; **normalized target descriptor; entry/profile;
  boot/consumer identity; committed base-graph digest**; the payload digest over the canonical
  update body; `issuedAtMs`.
- **The committed base-graph digest is the live v2 graph digest at the successor-law base
  `(g, r)`** — recomputed at every commit inside §5.3.1 — never LLP 0042's boot/deployment
  digest: after revision 1 the boot digest no longer names the graph the update applies to.
- **The canonical update body enumerates:** the invalidation closure; per replacement record its
  semantic digest, source integrity, declared effect class, and full typed rows — `GraphEdgeKey`
  bindings, candidate-table digests + attributes, deferred facts (the rows the ceiling checks).
  The four bold identity fields exist because Exact's server is multi-target: without them a
  valid payload for one platform/profile could verify in another consumer whose session and
  revision coordinates coincide. HTTP payload selection and WS routing must check the same
  fields (Exact 0417 H1 entry obligation 3; those transport negatives are Exact H2 fixtures).
- **Verification order:** the consumer verifies signature and every bound field against its own
  live session state **before** any record reaches `stage_replacements`. Per-record digests
  alone are self-consistency, not authentication (LLP 0042's adversarial contract).
- **Replay law (aligned to Exact 0553.001 §2.2):** `(session, producer, updateId)` is unique
  and content-bound — one `updateId` maps to exactly one payload digest. The consumer keeps a
  bounded table `(updateId) → (payloadDigest, receipt)` (1024 entries, FIFO) and checks it
  **first**: an exact duplicate (same `updateId`, same payload digest) is **idempotent** — the
  prior receipt is returned and nothing applies; the same `updateId` with a different digest
  refuses `update-identity-conflict`. The successor-law CAS is the backstop: a duplicate whose
  table entry was evicted refuses on base mismatch — safe but not idempotent, and that degraded
  mode is named, bounded, and diagnostic-visible rather than silent.
- **Limits:** canonical update body ≤ 16 MiB; ≤ 512 replaced modules per revision (within LLP
  0042's manifest limit class). Oversize refuses before decode completes.
- **Clock domains:** stage timings are stamped per domain (server stamps server stages, device
  stamps device stages); no field mixes domains and no cross-domain subtraction is defined.
- **What it defeats / does not:** cross-session, cross-target, stale-generation/-revision, and
  cache-substitution payloads. It is not a network-attacker or compromised-dev-server defense —
  in development the dev server is the source of truth for what code runs (LLP 0042's honesty,
  unchanged).

Superseding: publishing generation N+1 (or rotating `runId`) revokes the generation-N commitment
and every update verifier with it. Committed hot revisions do **not** revoke the boot commitment
— they are transactions inside its generation; a consumer that re-admits the boot graph after
revisions were applied is on the full-reload path by construction (v1 recreates the runtime).

## 7. Effect classes and the candidate-effect lease (obligation 5)

The effect-class taxonomy, ordering rules, and v1 refusal of `effectful-unknown` are Exact 0417
§4.8's and are consumed, not restated. This corpus's obligations:

- the declared per-boundary effect class enters the §6 signed body (it is admission-relevant
  metadata, not advice), and **the §5.2 state machine refuses `effectful-unknown` structurally
  at stage** — there is no code path that hot-applies it;
- the **candidate-effect lease** is the *only* sanctioned mechanism by which any future
  effectful hot path may exist: effect registrations (timers, subscriptions, host callbacks,
  resources) become revision-owned — created inactive during shadow evaluation, activated only
  on commit, auto-cancelled on refusal, with the prior incarnation's lease retired atomically at
  commit. It requires engine support (revision-stamped registration tables) that does not exist;
  nothing in v1 implements or emulates it, and until it exists §2.1's named v1 ambient-effect
  exception stands.

## 8. The Contract adapter decision (obligation 2 — recorded here, owned by Exact)

Exact's landed Contract hot-update pipeline applies in place (live slot patching, immediate
remount, registry writes before accept) and cannot participate in §5.3's atomic publication
unchanged. Decision, recorded for Exact H2 to implement: **(a) the two-phase Contract adapter**
— prepare diff/remount/registry overlays without live mutation, activate them through the §5.3.4
consumer activation hook inside the commit bundle — is the v1 target, with an objective fallback
trigger: if prepare-phase purity (no live host-target mutation, no framework-registry write
before commit) cannot be demonstrated by fixtures at H2 entry, v1 ships **(b) shadow-root-only
activation with live slot patching disabled**. Either way, no applying-in-place pipeline runs
under a hot revision, and whatever activates inside the hook obeys its no-fail, no-app-JS
contract (§5.3). The adapter is Exact-side work; this corpus's surface provides the state
machine (§5.2) and the activation hook (§5.3.4) it needs.

## 9. Receipts: advisory plane, bounded ingestion (H0 MATERIALs, carried in)

The Exact H0 security review recorded three MATERIAL findings against the spike's evidence
plumbing. Dispositions, honest about what the v1 loopback posture can and cannot provide:

1. **Receipt authenticity — discharged by de-fanging, not by authentication.** In the v1
   loopback posture every local process can obtain the envelope-served credentials, so no
   receipt signature scheme available here authenticates the sender. Therefore **receipts are
   advisory**: apply/refuse receipts echo `(updateId, ExecutionGeneration, HotRevision)` and
   the server binds them to its own staged update records for correlation, speculation warming,
   telemetry, and the measurement instrument — but **no correctness-bearing decision rides
   them**. Class-correct recovery is executed by the **consumer itself** from its own refusal
   verdict: the host initiates the reload/recreate (v1's generation transition is host-driven
   by construction, §3) and the restart-class path reaches the host teardown + re-arm join
   directly. A server action derived from a receipt must be idempotent and advisory (e.g.
   speculation warming). Order-based commit correlation (the spike's) is not carryable; the
   correlation key is the revision coordinate. Whether receipts sign under an enrolled device
   key is the LAN/device follow-up's question (§13).
2. **Bounded ingestion and retention.** Receipt ingestion enforces, before parse or allocation:
   a per-frame byte limit (64 KiB), then during parse a closed field set, maximum JSON depth 8,
   ≤ 64 stage rows, ≤ 128 total fields, bounded scalar lengths; per-session retained-receipt
   budget 1 MiB and 256 receipts (FIFO), global budget 8 MiB across sessions. Oversize or
   over-shape input is refused whole — never truncated-and-merged, never re-serialized back out.
   Unknown fields are dropped, never merged and re-served. The spike's attacker-extensible
   receipt map is non-conforming.
3. **Harness isolation** — an Exact-side **operating rule, owned there, not discharged by this
   corpus**: measurement harnesses that rewrite fixtures run only in isolated worktrees with no
   concurrent editors.

## 10. Refusal mapping

Every refusal this surface produces belongs to exactly one Exact 0417 §4.8 class:

| This corpus's refusal | Class |
| --- | --- |
| staged-record compile/link/export-shape-check failure in preflight (no app code has run) | `keep-last-good` |
| staged evaluation throw / shadow-TLA rejection (post-preflight, class-appropriate ordering) | `keep-last-good` |
| exact-duplicate update (replay table hit, same digest) | not a refusal — idempotent prior receipt (§6) |
| `update-identity-conflict` (same `updateId`, different digest) | `keep-last-good` (nothing applied; the producer must re-mint) |
| successor-law CAS failure (revision race lost) | `full-reload-current-authority` — 0417's assignment; see the note below |
| converse check (change outside invalidation set) | `full-reload-current-authority` |
| `export-shape-changed` (§2.3) | `full-reload-current-authority` |
| `cjs-cross-boundary` (§2.3) | `full-reload-current-authority` |
| declared `effectful-unknown` (refused structurally at stage) | `full-reload-current-authority` |
| observed effect-class mismatch | `full-reload-current-authority` |
| throwing dispose (0417 rule 5) | `full-reload-current-authority` |
| `HotRevision` overflow | `full-reload-current-authority` |
| ANY v2 ceiling breach — edge added/retargeted, candidate site added/changed, deferred bit flipped, bootstrap-internal set change | `regenerate-policy-and-restart-runtime` (the landed disposition, verbatim; the server pre-classifies shape edits into the reload class before staging — §4) |
| authority drift (`SnapshotGenerations` / snapshot digest) | `regenerate-policy-and-restart-runtime` |
| integrity-pinned package source change | `regenerate-policy-and-restart-runtime` |
| defining-principal change | `regenerate-policy-and-restart-runtime` |
| stale publication token (per-slot predicate) | not a revision refusal — the stale completion itself refuses; the revision is unaffected |
| production `begin_update` / `begin_revision` | refused structurally; no dev class applies |

The restart class must reach the host's teardown + re-arm path; answering it with a plain reload
is non-conforming (it either loops or tempts a ceiling bypass). **Race-class note:** the local
algebra guarantees a lost race leaves a coherent live graph at `r+1`, so 0417's full-reload
assignment for this row is wasteful-but-sound in v1 (the recreate re-delivers the newest
content); a 0417-owner refinement of exactly this row to `keep-last-good` (server restages from
the consumer's committed coordinates) is compatible with this spec and **recommended to the
Exact owner** — recorded here, not taken here.

## 11. Fixtures (the required H1 exit set — these land with the implementation slices)

Each is named so Exact 0417 H2's gate can cite green runs:

- **F1 — per-slot fencing:** unchanged-module completion survives a committed revision for all
  six publication kinds (`Evaluation`, `TopLevelAwait`, `DynamicImport`, `Error`,
  `CommonJsCache`, `ArtifactCache`), including an unchanged *importer* of a replaced module
  whose TLA continuation resumes after commit; replaced-module stale completions refuse for all
  six (§2.2).
- **F2 — race refusal:** two overlapping transactions staged from one base; the winner commits
  `r+1`, the loser refuses; no partial records, no install-revision movement from the loser.
- **F3 — package-edit refusal into the restart class:** an integrity-pinned package replacement
  refuses with the restart diagnostic, never the reload one.
- **F4 — ceiling breadth:** (a) two same-spelling edges of distinct `resolution_kind` over
  non-empty binding maps — distinct digest rows; widening one kind refuses despite the other
  being authorized; (b) candidate-site digest/attribute change refuses; (c) deferred→eager flip
  refuses; (d) bootstrap-internal set change refuses (§4).
- **F5 — cross-surface slot switch:** across a committed revision, each use surface observes
  old-then-new with no mixed state and stable namespace identity: namespace getter, static
  named import, re-export chain, star export, dynamic-import namespace, and a
  TLA-continuation in an unchanged importer; a refused revision leaves every surface on the old
  records with no observable intermediate state (§2.3).
- **F6 — export-shape-changed refusal:** add/remove/rename/interop-shape change each refuse;
  identical-shape replacement (different factory bytes, same descriptors) commits.
- **F7 — no-partial-records + no-capture-table:** a refusal at any §5.2 state leaves zero staged
  records reachable from the live graph, the loader cache, or the carrier tables; post-commit
  resolution of a replaced id yields the new incarnation without touching the frozen capture
  table (§5.1).
- **F8 — runtime-recreate coherence:** after ≥1 committed revisions, a full-reload generation
  transition (v1 recreate) produces module/cache/record state equivalent to a fresh boot of the
  same content (record-level equivalence; Exact owns the pixel-level half of the §4.8
  equivalence obligation).
- **F9 — signature adversarial set:** cross-target, cross-entry, wrong-profile, cross-consumer
  (boot identity), stale-generation, stale-revision, `target ≠ base+1`, tampered-body,
  wrong-domain, `runId`-mismatch, authority-stamp-mismatch, and **base-graph-digest mismatch
  after one committed revision** all refuse before staging; the exact-duplicate replay returns
  the prior receipt; `update-identity-conflict` refuses; the matching-tuple envelope verifies
  (§6). HTTP-selection/WS-routing negatives are Exact H2 fixtures.
- **F10 — CJS boundary set:** cross-closure CJS named-import consumption refuses
  `cjs-cross-boundary`; whole-closure CJS replacement commits with correct `default`,
  `'module.exports'`, detected-named-export snapshot, and sticky-error/eviction behavior; a CJS
  export object never crosses incarnations.
- **F11 — state-machine set:** commit from any state but `ReadyToPublish` is impossible by
  construction (type-level or runtime-refused); throwing dispose refuses full-reload class;
  observed-class mismatch refuses; shadow-TLA rejection refuses keep-last-good and its sticky
  error drops with the transaction; a replaced module's cached error does not survive into the
  successor incarnation.

## 12. Obligation ledger (Exact 0417 §6 H1 entry obligations)

| # | Obligation | Disposition |
| --- | --- | --- |
| 1 | per-slot incarnation predicate + fixture | §2.2 (live + shadow predicates, unified lookup authority), F1 |
| 2 | two-phase Contract adapter or shadow-root-only | §8 — decided: (a) with objective fallback to (b); activation joins §5.3.4's in-fence hook; Exact H2 implements |
| 3 | target/base-graph-bound signature; HTTP/WS check same fields | §6 (base digest pinned to live v2 digest at (g, r); body rows enumerated), F9; transport negatives Exact H2 |
| 4 | `generation.rs` typed-graph extension + edge-ceiling fixture | §4 (deferred/candidate/bootstrap facts pinned; restart-class discipline kept), F4 |
| 5 | candidate-effect lease as the only future effectful path | §7 + §5.2's structural `effectful-unknown` refusal |
| 6 | slot resolution at use time — every cross-module surface | §2.3 (getters, import bindings, aliases, dynamic namespaces; CJS refusal), F5/F10 |
| 7 | counter unification (OQ1) + staging-seam shape (OQ2) | §1, §5 (incl. §5.1's no-capture-table miss rule) |

H0-carried MATERIALs: receipt authenticity → §9.1 (advisory plane; consumer-executed recovery);
bounded ingestion/retention → §9.2; harness isolation → §9.3 (**operating rule, Exact-owned —
scheduled, not discharged here**). Exact 0553.001 O-3 → §1 (successor law) + §6 (replay law
aligned to its duplicate-first idempotence). Exact 0417 OQ4 (slot granularity, `hot.data`
algebra) → **explicitly left open, owned by Exact** (§2.3).

## 13. Open questions

1. **Payload record form** (Exact 0417 OQ3): v1 ships dev-served-shaped full records only; a
   fetchModule-style form for large boundaries is admissible later without changing §6's
   signature shape (the payload digest covers whichever body form is declared).
2. **Computed-candidate refresh:** v1 refuses candidate-set change at the ceiling (restart
   class as backstop; server pre-classifies to reload). Should a later version admit same-site
   candidate re-derivation under the ceiling when the armed policy already authorizes every
   candidate target? Requires its own adversarial fixtures; not v1.
3. **Surviving-runtime advance-and-retire:** the §3 retirement-fixture set is enumerated; the
   engine work (generation-owned cancellation for timers/next-ticks/globals/host registrations)
   is unscheduled. Post-v1.
4. **Receipt signing under device enrollment:** §9 deliberately stops at the advisory plane for
   v1. The LAN/device enrollment follow-up should revisit whether receipts sign under the
   enrolled device key, at which point correctness-bearing server decisions could return.
5. **Race-class refinement:** the §10 note recommends the 0417 owner refine the revision-race
   row to `keep-last-good`; until taken, v1 answers it with the coherent reload-recreate.
