# LLP 0055: Hot Revisions — Intra-Generation Module Updates (Exact 0417 H1 Surface)

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Engine, Runtime, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-24
**Revised:** 2026-08-24 (r1 — initial draft; commissioned by Exact LLP 0417 Phase H1 after the H0
spike's stop rule did not fire (Exact `docs/reports/0417-h0-spike.md`: median 67.7 ms vs the 250 ms
line). This spec is the H1 contract: it settles Exact 0417 OQ1 (counter unification) and OQ2
(staging-seam shape) — both ceded to this corpus — and discharges or schedules every Exact 0417 §6
H1 entry obligation. It amends LLP 0023 §2.3, 0024 §7.9, 0026 §8, 0027, and 0042 as one coherent
set; those edits land with this document.)
**Related:** LLP 0023 §2.3 (module/incarnation identity — amended), LLP 0024 §7.9 (module cache —
amended), LLP 0026 §8 (development/HMR — amended), LLP 0027 (artifact wire and interop — amended:
mixed record provenance, revision-aware unpin), LLP 0042 (prepared-graph commitment — amended:
update-payload signature and verifier delivery), LLP 0038 (unadvertised dev arming), LLP 0002/0003
(owner-thread drive contract), Exact LLP 0417 (the program; its §4.8 refusal taxonomy and effect
classes are consumed, not restated), Exact LLP 0553 §9 D2 / 0553.001 §2.2 + §10 O-3 (the
HotRevision successor law this spec owns), Exact `docs/reports/0417-h0-spike.md` +
`0417-h0-spike-security-review.md` (three carried MATERIALs — §9 here)

## Summary

Exact 0417 adopted a two-level execution model: an **ExecutionGeneration** is one complete
authenticated graph/runtime lifetime — this corpus's landed contract, across which no live record
ever crosses — and a **HotRevision** is a new transaction *within* one execution generation that
swaps replacement verified records for an accepted invalidation closure behind stable logical
slots. The generation level is landed (`generation.rs`, LLP 0026 §8, LLP 0023 §2.3 / 0024 §7.9 as
amended by ENG-25065). The revision level did not exist. This spec defines it:

1. the **HotRevision counter** and its successor law (the Exact 0553.001 O-3 answer),
2. the **per-slot incarnation predicate** that fences stale completions per module, not per
   transaction,
3. the **typed authenticated graph** extension of `generation.rs` (digest, immutable ceiling, and
   adversarial tests over `GraphEdgeKey` + candidate/deferred tables),
4. the **revision-scoped staging seam** (a Rust host surface; the boot-time dev-served capture
   table stays exactly-once),
5. **slot-based relink with getter indirection** (the concrete runner change),
6. the **update-payload signature** under an ephemeral dev-session keypair (the LLP 0042
   amendment), and
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
out-of-order commit, no merge of concurrently staged revisions — the loser of a race refuses
(full-reload class) and restages. This confirms Exact 0553.001's interim "exactly-live-plus-one
against the consumer's local revision counter" as the permanent law; the consumer's live counter
is the authority, and wire fields are claims checked against it.

**Overflow.** `HotRevision` exhaustion refuses into the full-reload class (a generation
transition resets the counter to 0). It never wraps.

**Counter relationships (Exact 0417 OQ1, settled).** Four counters exist and stay distinct:

| Counter | Owner | Moves when |
| --- | --- | --- |
| authority generations (`SnapshotGenerations`) | armed CapSec snapshot | never during a runtime's life; drift refuses into the restart class |
| `ExecutionGeneration` | the producing session (dev server / host shell), consumed by the module runner | full reload — v1: runtime recreation (§3) |
| `HotRevision` | the runner's revision surface (§5), per generation | each committed hot revision |
| dev-server graph epoch / host engine counter | Exact's server and shell | their own machinery; they *carry* the two coordinates above, they do not define them |

Today `runner_pipeline.rs` derives its `graph_generation` from the armed snapshot's dynamic grant
generation (`snapshot.generations().dynamic.get().max(1)` — an *authority* counter that LLP 0026
§8 forbids HMR from touching). H1 decouples them: the pipeline takes an explicit
`ExecutionGeneration` input minted by the producing session — the same value the LLP 0042 dev
commitment already carries as `session.generation` — and the engine pin ABI
(`ex_hermes_module_pin_generation`) pins that value. The authority generations remain inside the
armed snapshot and are compared only by the immutable ceiling. Production continues to pin
exactly one generation for the runtime's life; nothing observable changes there.

## 2. Incarnations, slots, and the per-slot predicate

### 2.1 Incarnation key (amends LLP 0023 §2.3, 0024 §7.9, 0026 §8)

A live module incarnation is named

```text
(runtime/session identity, SourceId, ExecutionGeneration, install revision)
```

where **install revision** is the `HotRevision` at which the record was installed — 0 for boot
records. It is NOT "the current revision": committing revision `r+1` does not restamp records it
did not replace. Per `(generation, SourceId)` exactly one incarnation is live at a time;
successive committed revisions that replace a module create successive incarnations *within* the
generation. Live cells, namespaces, promises, cached errors, and CommonJS exports never cross
incarnations — LLP 0023's cross-generation prohibition applies with the same force at the
incarnation boundary, with one deliberate exception: the `hot.data` handoff Exact 0417 §4.4
defines, which passes plain values through the dispose/accept protocol, never live records.

### 2.2 Per-slot incarnation predicate (Exact 0417 H1 entry obligation 1)

`GenerationPublicationToken` gains the install revision:

```text
token = (ExecutionGeneration, SourceId, install revision, semantic digest)
```

`publish(token, kind)` succeeds iff `token.generation == live.generation` **and**
`token.install_revision == current_install_revision[source_id]` **and** the semantic digest
matches the live record. The revision counter is the *transaction* coordinate; the predicate is
per slot. Consequences, both fixture-pinned (§11 F1):

- an **unchanged** module's in-flight completion (TLA continuation, dynamic import, CJS cache
  publication, artifact-cache publication, error) still publishes after later revisions commit —
  its slot's install revision did not move;
- a **replaced** module's stale completion refuses — its token's install revision is older than
  the slot's.

All six `GenerationPublicationKind`s obey the same predicate.

### 2.3 Stable logical slots and getter indirection (obligation 6)

A **stable logical slot** is a generation-owned forwarding *binding target* keyed by
`(ExecutionGeneration, SourceId)`: outside importers bind the slot; the slot targets exactly one
incarnation's records at a time; commit retargets the slots for the accepted closure in one
publication step. A slot is not a live namespace shared between incarnations — what outside
importers hold is the namespace object *identity*, whose per-export getters resolve **through the
slot at call time**.

**Concrete runner change (normative).** Today `hermes_module_runner.cc`'s per-export namespace
getters capture the generation and a fixed `recordId` at instantiate time; a slot retarget would
be unobservable through them. H1 adds an engine-owned slot table
`(graph_generation, slot id) → live record id`; getters capture `(generation, slot id)` and
consult the table on each get. Slot-table writes happen only inside the owner-thread commit
publication (§5.3), so no getter can observe a mixed graph. The TDZ/live-binding semantics of
cells inside one incarnation are unchanged — indirection is at the slot boundary, not inside a
record.

**Export-shape eligibility (consumed from Exact 0417 §4.1).** A replacement is slot-eligible only
if its export names, property descriptors, and interop shape are identical to the prior
incarnation's; any add/remove/rename/interop change is the `export-shape-changed` refusal
(full-reload class). ESM namespaces are non-extensible, so this is a structural constraint, not a
policy choice. §11 F6 pins it.

**Granularity (Exact 0417 OQ4, v1 position).** v1 slots are per module (`SourceId`), with
per-export getter indirection inside the namespace. Finer (per-export-cell) or coarser (closure
edge) granularity is admissible only if the Vite-parity corpus produces a counterexample; none is
known.

## 3. Generation transitions: v1 recreates the runtime

A full reload must be a genuine `ExecutionGeneration` transition. The landed engine cannot yet
prove fresh-boot equivalence for a surviving-runtime transition: `ex_hermes_module_unpin_generation`
releases ESM/CJS records, dynamic activation requests, and context references, but not timers,
next-ticks, arbitrary globals, or host registrations. Therefore, normatively:

- **v1: the full-reload class tears down and recreates the runtime.** The producing session mints
  the next `ExecutionGeneration`; the new runtime arms, boots, and pins it. Policy is unchanged;
  only the execution coordinate advances. The consuming host (Exact's runtime shell) owns the
  teardown/recreate mechanics.
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
  the record owns (site-keyed; candidates never flatten into `bindings`),
- deferred-membership facts: whether each literal dynamic-import / literal CommonJS-require edge
  is deferred (outside eager evaluation/SCC/TLA traversal), and the bootstrap-internal CJS set.

The graph digest moves to domain `ibex/module-generation-graph/2` and covers every row above
(specifier, resolutionKind, target per edge; candidate digests; deferred facts). V1-domain
digests are not comparable and refuse.

**V2 ceiling.** `ImmutableGenerationAdmissionV1`'s edge set becomes
`BTreeSet<(SourceId, GraphEdgeKey, SourceId)>`, and it additionally pins the candidate-site set:
`(requester, site ordinal) → candidate-table digest`. A hot revision may not add a computed site,
widen a candidate set, or change a site's table digest — computed-candidate change is a
full-reload-class refusal in v1 (the server recomputes the graph; a widened site is
indistinguishable from an edge widening at this layer, and the restart class governs when the
armed policy would have to move).

**Adversarial tests.** Every ceiling/adversarial test is rebuilt over **non-empty typed binding
maps** (the landed tests use empty maps, so the ceiling was never exercised against real edges).
The named acceptance fixture (§11 F4): one record carrying **two same-spelling edges of distinct
`resolution_kind`** over a non-empty binding map, proving (a) both edges enter the digest and
ceiling distinctly, and (b) a candidate that widens one kind refuses even when the identically
spelled other kind is authorized.

## 5. The staging seam (Exact 0417 OQ2, settled)

### 5.1 Not the capture table

The dev-served capture table (`captureDevServedModuleTable`) is a frozen exactly-once boot
handshake with quarantine semantics; reopening it per revision would dissolve exactly the
property it exists to enforce. It stays boot-only, byte-for-byte unchanged. Hot revisions enter
through a **new revision-scoped Rust host surface**.

### 5.2 `HotRevisionSurfaceV1` (the host API Exact 0417 H1's exit names)

Owned by the module-runner pipeline, exclusive (`&mut`), owner-thread only (LLP 0002/0003 drive
contract). Lifecycle:

1. `begin_revision(policy, origin, base: (ExecutionGeneration, HotRevision), invalidated) →
   HotRevisionTransactionV1` — refuses in production mode; re-validates authority; refuses an
   empty or graph-widening invalidation set (the `generation.rs` preconditions, revision-scoped).
2. `stage_replacements(txn, replacements)` — replacement records enter **only** as
   `VerifiedModuleArtifactV1` tokens plus typed edge/candidate/deferred metadata; raw
   deserialization never reaches staging. Staged records are shadow records: invisible to the
   live graph, keyed at candidate install revision `base + 1`.
3. `preflight(txn)` — compile/link the staged closure (factory compile, link-plan validation,
   export-shape comparison against the live incarnations) **without running any app code**.
   Failures here refuse with zero app-visible effects.
4. Evaluation ordering per declared effect class is the consumer's (Exact §4.8) responsibility;
   this surface exposes shadow-evaluate (for `contract-staged-pure`) and
   dispose-then-evaluate hooks but does not choose between them.
5. `commit(policy, txn) → HotRevisionCommitV1` — under exclusive owner-thread access: authority
   re-validation, full post-revision graph validation against the v2 ceiling, the converse check
   (no change outside the invalidation set), the successor-law CAS (§1), then the **single
   publication step** (§5.3). Any failure refuses: shadow records drop whole, the live graph and
   revision counter are untouched, and the refusal maps to an Exact 0417 §4.8 class (§10).

### 5.3 The publication step (atomic, owner-thread)

One operation publishes, in this order, with no interleaved JS execution:

1. slot-table retargets for the accepted closure (§2.3),
2. per-slot install-revision advance for replaced `SourceId`s (§2.2),
3. JS loader-cache invalidation for replaced modules through a **bootstrap-installed private
   bridge** (`__privInvalidateHotRevisionRecords` class — sealed with the other `__priv*`
   bridges, never realm-visible, callable only from the engine's commit path; the compat loader's
   cache gains this single sanctioned entry point — every existing `delete cache[...]` remains a
   failure path),
4. prepared-carrier-table memo eviction for replaced `SourceId`s (the C++ memo has no eviction
   today; it gains exactly this revision-commit path),
5. revision counter advance and receipt emission.

A refused revision performs none of these. No importer can observe a state between them.

### 5.4 Mixed record provenance (amends LLP 0027)

Replacement records carry inline source-artifact payloads and join a live generation whose other
records may carry prepared-carrier (HBC) provenance. This is the **sanctioned post-boot path** by
which source records join a prepared generation: boot admission is not relaxed (prepared-HBC
boots stay uniform; carrier admission is unchanged); untouched records keep their carrier
provenance and memo entries; replaced `SourceId`s resolve to their new inline incarnations and
their carrier memo entries are evicted (§5.3.4). HBC carriers are never mutated, patched, or
partially replaced (Exact 0417 Goal 2; LLP 0127's decision on the Exact side).

## 6. Update-payload authentication (obligation 3; amends LLP 0042)

The dev session gains an **ephemeral signing keypair** beside the existing HMAC secret, same
custody rule (private key only in the producing session's process memory; never on disk; rotates
with `runId`). The HMAC continues to bind the *boot* commitment; the keypair signs *update
payloads*, because a device must verify what a producer-only symmetric secret cannot let it
verify.

- **Algorithm and encoding:** Ed25519 (RFC 8032) over the JCS-canonical signed body, domain
  `ibex/hot-update-signature/1`. The public verifier rides the startup session envelope in the
  v1 loopback posture; the LAN/device follow-up binds it at boot enrollment instead (Exact 0417
  §5/OQ5 — not this spec's scope).
- **Signed body (all fields normative):** schema id; `runId`; authority stamp (armed snapshot
  digest + `SnapshotGenerations` echo); `ExecutionGeneration`; base and target `HotRevision`
  (target = base + 1 by §1); `updateId`; **normalized target descriptor; entry/profile;
  boot/consumer identity; committed base-graph digest (the §4 v2 digest)**; the payload digest
  over the canonical update body (invalidation closure, per-record semantic digests + source
  integrity, declared effect classes, typed metadata); `issuedAtMs`. The four bold fields exist
  because Exact's server is multi-target: without them a valid payload for one platform/profile
  could verify in another consumer whose session and revision coordinates coincide. HTTP payload
  selection and WS routing must check the same fields (Exact 0417 H1 entry obligation 3; the
  0042 commitment precedent already binds target, entry, and deployment-graph digest).
- **Verification order:** the consumer verifies signature and every bound field against its own
  live session state **before** any record reaches `stage_replacements`. Per-record digests
  alone are self-consistency, not authentication (LLP 0042's adversarial contract).
- **Idempotence and replay:** the successor-law CAS is the replay defense — a signed envelope
  binds `(g, r → r+1)` and can commit at most once; a replayed or duplicate delivery refuses on
  base mismatch. A bounded diagnostic `updateId` table (1024 entries, FIFO) improves refusal
  messages; it is not a security boundary and its eviction changes no verdict.
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
  metadata, not advice);
- the **candidate-effect lease** is the *only* sanctioned mechanism by which any future
  effectful hot path may exist: effect registrations (timers, subscriptions, host callbacks,
  resources) become revision-owned — created inactive during shadow evaluation, activated only
  on commit, auto-cancelled on refusal, with the prior incarnation's lease retired atomically at
  commit. It requires engine support (revision-stamped registration tables) that does not exist;
  nothing in v1 implements or emulates it, and no consumer may hot-apply `effectful-unknown`
  without it.

## 8. The Contract adapter decision (obligation 2 — recorded here, owned by Exact)

Exact's landed Contract hot-update pipeline applies in place (live slot patching, immediate
remount, registry writes before accept) and cannot participate in §5.3's atomic publication
unchanged. Decision, recorded for Exact H2 to implement: **(a) the two-phase Contract adapter**
— prepare diff/remount/registry overlays without live mutation, activate them inside the
HotRevision commit — is the v1 target, with an objective fallback trigger: if prepare-phase
purity (no live host-target mutation, no framework-registry write before commit) cannot be
demonstrated by fixtures at H2 entry, v1 ships **(b) shadow-root-only activation with live slot
patching disabled**. Either way, no applying-in-place pipeline runs under a hot revision. The
adapter is Exact-side work; this corpus's surface exposes the prepare/activate seam (§5.2
items 3–5) it needs.

## 9. Receipts: authenticity and bounded retention (H0 MATERIALs, carried in)

The Exact H0 security review recorded three MATERIAL findings against the spike's evidence
plumbing. Two become normative here; the third is an operating rule on the Exact side:

1. **Receipt authenticity.** Apply/refuse receipts must echo `(updateId, ExecutionGeneration,
   HotRevision)`; the server binds a receipt to its own staged update record and refuses unknown
   or mismatched coordinates. Receipts ride the dev socket behind Exact 0417 §5's enforced
   loopback peer gate (an Exact H2 acceptance criterion); within the v1 loopback posture,
   coordinate binding plus the peer gate is the receipt-integrity boundary — receipts are not
   individually signed in v1, and no correctness decision may rest on a receipt that fails
   coordinate binding. Order-based commit correlation (the spike's) is not carryable; the
   receipt correlation key is the revision coordinate.
2. **Bounded retention.** Any server-side receipt store is bounded (default 256 receipts per
   session, FIFO) and parses a closed field set; unknown fields are dropped, never merged and
   re-served. Unbounded or attacker-extensible receipt maps (the spike's) are non-conforming.
3. **Harness isolation** (Exact-side operating rule, restated for visibility): measurement
   harnesses that rewrite fixtures run only in isolated worktrees with no concurrent editors.

## 10. Refusal mapping

Every refusal this surface produces belongs to exactly one Exact 0417 §4.8 class:

| This corpus's refusal | Class |
| --- | --- |
| staged-record eval/compile/link failure in preflight | `keep-last-good` |
| successor-law CAS failure (revision race lost) | `full-reload-current-authority` |
| converse check (change outside invalidation set) | `full-reload-current-authority` |
| `export-shape-changed` (§2.3) | `full-reload-current-authority` |
| edge/candidate outside the v2 ceiling but inside root authority (e.g. new import of an already-authorized module) | `full-reload-current-authority` (the server publishes a new generation) |
| stale publication token (per-slot predicate) | not a revision refusal — the stale completion itself refuses; the revision is unaffected |
| `HotRevision` overflow | `full-reload-current-authority` |
| authority drift (`SnapshotGenerations` / snapshot digest) | `regenerate-policy-and-restart-runtime` |
| integrity-pinned package source change | `regenerate-policy-and-restart-runtime` |
| defining-principal change / graph widening beyond the ceiling | `regenerate-policy-and-restart-runtime` |
| production `begin_update` / `begin_revision` | refused structurally; no dev class applies |

The restart class must reach the host's teardown + re-arm path; answering it with a plain reload
is non-conforming (it either loops or tempts a ceiling bypass).

## 11. Fixtures (the H1 exit set)

All live in this corpus's test tree; each is named so Exact 0417 H2's gate can cite green runs:

- **F1 — per-slot fencing:** unchanged-module TLA completion survives a committed revision;
  replaced-module stale completion refuses (§2.2; all six publication kinds).
- **F2 — race refusal:** two staged revisions from one base; the winner commits `r+1`, the loser
  refuses; no partial records from the loser.
- **F3 — package-edit refusal into the restart class:** an integrity-pinned package replacement
  refuses with the restart diagnostic, never the reload one.
- **F4 — edge-ceiling:** two same-spelling edges of distinct `resolution_kind` over a non-empty
  binding map; distinct digest rows; widening one kind refuses despite the other being
  authorized (§4).
- **F5 — slot-switch atomicity:** an outside importer's namespace identity is stable across a
  committed revision while its getters observe only old-then-new, never mixed, values; a refused
  revision leaves getters on the old records with no observable intermediate state.
- **F6 — export-shape-changed refusal:** add/remove/rename/interop-shape change each refuse;
  identical-shape replacement commits.
- **F7 — no-partial-records on refusal:** a commit-time refusal (ceiling, converse, race) leaves
  zero staged records reachable from the live graph, the loader cache, or the carrier memo.
- **F8 — runtime-recreate coherence:** after ≥1 committed revisions, a full-reload generation
  transition (v1 recreate) produces module/cache/record state equivalent to a fresh boot of the
  same content (record-level equivalence; Exact owns the pixel-level half of the §4.8
  equivalence obligation).
- **F9 — signature adversarial set:** cross-target, cross-entry, cross-consumer,
  stale-generation, stale-revision, tampered-body, wrong-domain, and replayed envelopes all
  refuse before staging; the matching-tuple envelope verifies (§6).

## 12. Obligation ledger (Exact 0417 §6 H1 entry obligations)

| # | Obligation | Disposition |
| --- | --- | --- |
| 1 | per-slot incarnation predicate + fixture | §2.2, F1 |
| 2 | two-phase Contract adapter or shadow-root-only | §8 — decided: (a) with objective fallback to (b); Exact H2 implements |
| 3 | target/base-graph-bound signature; HTTP/WS check same fields | §6, F9 |
| 4 | `generation.rs` typed-graph extension + edge-ceiling fixture | §4, F4 |
| 5 | candidate-effect lease as the only future effectful path | §7 |
| 6 | getter indirection — slot resolution at call time | §2.3, F5 |
| 7 | counter unification (OQ1) + staging-seam shape (OQ2) | §1, §5 |

H0-carried MATERIALs: receipt authenticity → §9.1; bounded retention → §9.2; harness isolation →
§9.3. Exact 0553.001 O-3 → §1 (the successor law; `targetHotRevision = base + 1`, CAS against
the consumer's live counter at publication).

## 13. Open questions

1. **Payload record form** (Exact 0417 OQ3): v1 ships dev-served-shaped full records only; a
   fetchModule-style form for large boundaries is admissible later without changing §6's
   signature shape (the payload digest covers whichever body form is declared).
2. **Computed-candidate refresh:** v1 refuses candidate-set change into the full-reload class
   (§4). Should a later version admit same-site candidate re-derivation under the ceiling when
   the armed policy already authorizes every candidate target? Requires its own adversarial
   fixtures; not v1.
3. **Surviving-runtime advance-and-retire:** the §3 retirement-fixture set is enumerated; the
   engine work (generation-owned cancellation for timers/next-ticks/globals/host registrations)
   is unscheduled. Post-v1.
4. **Receipt signing:** §9 deliberately stops at coordinate binding + the loopback gate for v1.
   The LAN/device enrollment follow-up should revisit whether receipts sign under the enrolled
   device key.
