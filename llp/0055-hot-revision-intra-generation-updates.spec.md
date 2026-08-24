# LLP 0055: Hot Revisions — Intra-Generation Module Updates (Exact 0417 H1 Surface)

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Engine, Runtime, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-24
**Revised:** 2026-08-24 (r5 — round-4 dual-family fold (codex NOT READY 1–2; grok NOT READY 1;
convergent residue of the r4 replay/converse rewrites). Adopted: the replay table is pinned
**host-held** (survives v1 runtime-recreate; dies with the session), and **quarantine
settles**: an invariant-quarantine terminalizes the pending entry through the pre-reserved
outcome record before update processing resumes, and a begun transaction's ordinary refusal
overwrites pending→terminal **before the refusal is yielded** — no pending entry can outlive
its transaction (codex 1 + grok minors); the converse no-op quantifier is corrected — a
transaction is a no-op only when the **entire** staged set is row-identical (the
transaction-wide changed set is empty); an individual unchanged member inside a changed
closure is legitimate and required, since 0417 re-evaluates the invalidated importer chain
(unchanged importers become new incarnations with advanced install revisions) — F2(d) gains
the changed-leaf + unchanged-importer commit fixture (codex 2; supersedes the r4 per-member
rule); the §10 capacity row is split from overflow — replay-table capacity is a
`keep-last-good` **occupancy refusal** carrying the session-rotation diagnostic, retired only
by producer `runId` rotation, never by a reload (a reload mints a new generation under the
SAME `runId` and would loop) — overflow alone stays full-reload (grok 1); plus the convergent
minors: §5.2's recording parenthetical scoped to authenticated accepted-for-processing
attempts, §9.1's heading aligned to MITIGATED, §12's O-3 line updated to session-lifetime
semantics, F2(a)'s same-id-after-settle clarified as F9's terminal hit, F4's title scoped
until-ask-3, §13.2's recovery description made conditional.)
**Revised:** 2026-08-24 (r4 — round-3 dual-family fold (codex NOT READY 1–4; grok NOT READY 1–3;
convergent, with one cross-family conflict adjudicated). Adopted: commit-time authority and
stamp comparisons are demoted to quarantining backstops beside the base CAS — ordinary
authority admission happens at `begin` (check 3), and the armed snapshot is immutable for the
runtime's life, so a post-`Begun` mismatch is an invariant violation, never an ordinary
refusal (codex 1, grok minor 2); the §6 replay law is rewritten — the table records only
**authenticated terminal** outcomes (signature failures are never inserted; a same-`updateId`
later signed body cannot be poisoned by an unauthenticated attempt), an in-flight `updateId`
is reserved **pending** (a duplicate during flight answers busy without sealing busy as
terminal; settlement overwrites pending with the terminal receipt, so §10's post-settle retry
is a table miss), entries bind the full signed-envelope digest, retention is for the
**session (`runId`) lifetime** — not the generation — and capacity forces
refusal-until-session-rotation, never eviction; the terminal outcome record is pre-reserved
before the §5.3 fence and finalized infallibly at step 7 (duplicates can always return the
prior receipt), with transport alone post-fence best-effort (codex 2 + grok 1); ask 1's
until-taken statement is made honest — H0 MATERIAL 1 is **mitigated, not discharged**, until
the 0417 §4.3 amendment is taken (or receipts are enrollment-keyed): a forged receipt can
still trigger a redundant-but-coherent server reload, named as the bounded residual of the
loopback trust model, and the discharge completes at H2 (codex 3); the ceiling-breach row is
made self-consistent and conformant under BOTH ask-3 outcomes — the class stays 0417's
restart until ask 3 is taken, the recovery instruction routes to the **host restart join**
(whose v1 recovery — teardown + re-arm + fresh same-authority ceiling — is materially the
reload-recreate with a no-op policy regeneration), the contradictory "recovery is the reload
class's re-derivation" sentence is deleted, and F4 keeps restart-string assertions with a
recorded flip-to-class-assertion if ask 3 is taken; grok's alternative (assign
same-authority widening to the reload class in-corpus now) is DECLINED on the same
taxonomy-ownership ground as the race row (codex 4 + grok 2, adjudicated); the restage
coordinate pull gains a real vehicle — a **credential-gated consumer-status read** returning
live `(ExecutionGeneration, HotRevision)` and the live v2 digest (v1 loopback: an in-process
or status read under the §5 session credential; Exact H2 names the wire route) — replacing
the miscited payload GET, which fetches payload bytes and returns no coordinates (grok 3);
§5.2 check 1 is split precisely (signature + identity-field verification; base currency is
check 3's); `ready()` takes **linear ownership** of the activation token — the flip runs only
at §5.3.4 (grok minors); the converse check is split so a no-op replacement (staged rows
identical to live) refuses `keep-last-good` ("nothing to apply"), never full reload — a
slice-2 implementation finding; pointer and header-count corrections ("three" owner asks;
§5.2 item 8).)
**Revised:** 2026-08-24 (r3 — round-2 dual-family fold (both NOT READY; grok blockers 1–3, codex
residues 3/7/8 + new 11–13 — convergent on three defects; artifacts in `llp/reviews/`). The
admission pipeline is reordered so no fallible admission check follows an app-visible effect:
the surface is **single-flight** (a second `begin` refuses busy; overlapping transactions are
gone, and with them F2's dispose-the-winner hazard), `begin_revision` now REFUSES a stale base
with the consumer's committed coordinates (the optimistic-staging rule is withdrawn), the
duplicate/identity lookup is a named first consumer check that records every attempt outcome,
and ceiling/converse/export-shape/CJS eligibility all complete in preflight — dispose can no
longer run on a transaction already doomed by currency, which also makes the §10 race-note's
compatibility claim true. The state machine gains **ActivationPrepared**: consumer prepare
(Contract two-phase prepare — app JS allowed, shadow targets only) runs pre-commit and its
failure refuses `keep-last-good` (0417's remount rule), producing a transaction-bound no-fail
activation token; the §5.3 hook only flips that prevalidated token, and §8's fallback trigger
is sharpened (no token-able flip at H2 entry ⇒ v1 IS shadow-root-only). The commit bundle now
precomputes the candidate v2 digest before the fence, ends at counter advance, and emits the
advisory receipt AFTER the fence best-effort; commit-time CAS becomes a TOCTOU backstop that
quarantines if it ever fires (under single-flight it cannot). Receipt de-fanging completed: the
producer restages from a credential-gated pull of live coordinates, never from receipt bodies;
three **Exact-owner asks are recorded, not taken** (amend 0417 §4.3 so the server's class-driven
reload response becomes advisory — consumer-executed recovery; refine the race row to
keep-last-good; narrow §4.8's restart-row "edge widening" to authority-relevant widening) —
filed as an Exact-repo ticket by this lane. §4 replaces the pre-classification story with the
two recovery grades: same-authority generation re-derivation (a new generation's admission
derives fresh from its boot graph under the UNCHANGED armed policy — v1 recreate does this by
construction) vs authority regeneration + re-arm (the restart class proper); ceiling-breach
messages stay the landed restart strings at this layer. The §6 replay table becomes
per-generation with rotate-before-evict (idempotence stays unqualified within a generation —
0553.001's law; the key is named as the v1 single-session projection of (session, producer,
updateId)). v1 updates carry exactly one accepted boundary (closure-wide effect-class ambiguity
removed). Minors: carrier-table occupancy counting (the map's own strong ref must not block
release; first-retirement must not drop shared factories); the loader-cache bridge pins
no-checkpoint engine re-entry or native surgery; §10 gains empty-invalidation,
widened-invalidation, busy, and stale-base rows; F-fixtures assert the restart strings and the
no-dispose-before-refusal witness; 0023/0024/0026/0027 residual wording aligned
(incarnation-private namespaces; headers).)
**Revised:** 2026-08-24 (r2 — round-1 dual-family fold; see `llp/reviews/` and the r2 entry in
the git history for the full disposition ledger. Slot resolution extended to every cross-module
use surface after code verification of `link_import`/`link_export` record-id capture;
slot-owned namespace facade; CJS cross-boundary refusal; ceiling pins deferred/bootstrap/
candidate facts with restart-class discipline; typed state machine; no-fail commit bundle;
shadow publication predicate; carrier provenance-switch; live-v2-digest base binding;
0553.001-aligned replay; advisory receipts with bounded ingestion; OQ4 re-marked Exact-owned;
v1 ambient-effect exception named. Declined with recorded reasons: dispose-after-commit;
outstanding-ambient-effect refusal.)
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
consumed, not restated; its OQ4 remains open and owned there; three owner asks recorded — §12),
Exact LLP 0553 §9 D2 / 0553.001 §2.2 + §10 O-3 (the HotRevision successor law this spec owns;
the replay law §6 aligns to), Exact `docs/reports/0417-h0-spike.md` +
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
   transaction — with its transaction-local shadow twin,
3. the **typed authenticated graph** extension of `generation.rs` (digest, immutable ceiling, and
   adversarial tests over `GraphEdgeKey` + candidate/deferred/bootstrap facts),
4. the **revision-scoped staging seam**: a single-flight, typed-state Rust host surface on which
   no fallible admission check follows an app-visible effect (the boot-time dev-served capture
   table stays exactly-once),
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
coordinate `(ExecutionGeneration g, HotRevision r)`. The surface is **single-flight** (§5.2):
`begin_revision` refuses a base that is not exactly the live coordinate, reporting the
consumer's committed `(g, r)`; a transaction that begins therefore holds the live base, and the
committed revision is `r + 1`, installed at a single owner-thread publication point under
exclusive access (`&mut`). The commit-time compare is retained as a TOCTOU backstop that can
only fire on an invariant violation (§5.2 item 8). There is no other legal successor: no skips, no
out-of-order commit, no merge — a producer whose update refuses on a stale base re-obtains the
consumer's live coordinates through the credential-gated pull (§9.1) and restages; the refusal
receipt is only the advisory hint to do so, never the coordinate source. This confirms Exact
0553.001's interim "exactly-live-plus-one against the consumer's local revision counter" as the
permanent law; the consumer's live counter is the authority, and wire fields are claims checked
against it.

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
generation. What incarnations must never share, precisely: module environments, binding cells,
promises, cached errors, and CommonJS export objects (namespace identity is slot-owned
generation property — §2.3). LLP 0023's cross-generation prohibition applies at the incarnation
boundary with two named exceptions, both deliberate:

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
  immutable ceiling from its new boot graph under the unchanged armed policy** (§4's
  same-authority re-derivation) — which is how everyday shape-changing edits (a new import, a
  deferred-bit flip) are served without ever weakening a live ceiling. Policy is unchanged; only
  the execution coordinate advances. The consuming host (Exact's runtime shell) owns the
  teardown/recreate mechanics.
- **Post-v1: surviving-runtime advance-and-retire** (unpin + retire every state owner + fence
  stale completions in place) is an optimization gated on generation-owned cancellation/fencing
  for *every* ambient-effect surface, proven by retirement fixtures: stale-TLA, dynamic-import,
  CJS cache, prepared-carrier table, publication token, **and timer / next-tick / global /
  host-registration** retirement, each demonstrating fresh-boot equivalence — and it must
  perform the same §4 same-authority admission re-derivation for the new generation's graph.
  Until those fixtures exist and pass, no consumer may claim the surviving-runtime path.

The restart class (`regenerate-policy-and-restart-runtime` — authority drift, package-integrity
drift, principal change) is *stricter* than the full-reload class: it additionally regenerates
policy and re-arms. A plain reload must never impersonate it (Exact 0417 §4.8).

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
runtime` — the restart-family strings at this layer.** A hot revision may not add or retarget an
edge, add or alter a computed site, flip a deferred bit, or grow the bootstrap-internal set,
whatever the root authority would notionally allow.

**The two recovery grades (why everyday edits never weaken this).** A ceiling is derived
`from_initial` for one generation and is immutable for that generation's life. Recovery from a
shape-changing edit is a **new generation whose admission derives fresh from its own boot graph
under the UNCHANGED armed policy** — `from_initial` re-validates every record and edge against
the same authority, so nothing is bypassed and no policy regeneration is needed. v1's
reload-recreate performs exactly this by construction (§3). That is distinct from the **restart
class proper**, whose trigger is authority-relevant drift (policy digest/generations, package
integrity, defining principals) and whose recovery additionally regenerates policy and re-arms.
An update that reaches this ceiling with a widened edge is a defense-in-depth refusal, not the
everyday path: the producing server routes shape-changing edits **before staging** to whatever
class Exact 0417 assigns them. **Recorded Exact-owner ask (§12):** Exact 0417 §4.8's
restart-class row currently reads "principal or edge widening" — this spec recommends
narrowing it to authority-relevant widening. **Until the ask is taken, every ceiling breach —
same-authority edge growth included — routes to the restart class's recovery: the host restart
join (teardown + re-arm).** In v1 that recovery is materially the reload-recreate plus a
policy regeneration that is a no-op under unchanged authority, so conformance costs nothing
extra; after the ask is taken, same-authority widening moves to the reload class and only
authority/integrity/principal drift restarts. Both outcomes are sound; a consumer never
answers a restart-class refusal with a plain ws reload under either.

**Adversarial tests.** Every ceiling/adversarial test is rebuilt over **non-empty typed binding
maps** (the landed tests use empty maps, so the ceiling was never exercised against real edges),
and each ceiling-breach fixture asserts the restart-family string, so the landed disposition
cannot silently become a plain reload (if Exact-owner ask 3 is taken, the same-authority
widening fixtures flip to asserting the reload **class** — a recorded fixture amendment, not a
silent drift). Named acceptance fixtures (§11 F4): (a) one record
carrying **two same-spelling edges of distinct `resolution_kind`** over a non-empty binding
map, proving both edges enter the digest and ceiling distinctly, and that a candidate widening
one kind refuses even when the identically spelled other kind is authorized; (b) a
candidate-site digest or attribute change refuses; (c) a deferred→eager flip on an authorized
edge refuses; (d) a bootstrap-internal set change refuses.

## 5. The staging seam (Exact 0417 OQ2, settled)

### 5.1 Not the capture table

The dev-served capture table (`captureDevServedModuleTable`) is a frozen exactly-once boot
handshake with quarantine semantics; reopening it per revision would dissolve exactly the
property it exists to enforce. It stays boot-only, byte-for-byte unchanged. Hot revisions enter
through a **new revision-scoped Rust host surface** — and after a commit, resolution of a
replaced `SourceId` goes only through the installed revision records: **no code path may
re-enter the capture table, trigger its quarantine, or re-serve boot bytes over a committed
incarnation** (§11 F7).

### 5.2 `HotRevisionSurfaceV1` — single-flight, typed states, no fallible check after an effect

Owned by the module-runner pipeline, exclusive (`&mut`), owner-thread only (LLP 0002/0003 drive
contract). States: `Begun → Staged → Preflighted → Evaluated → ActivationPrepared →
ReadyToPublish → Committed | Refused`. Commit is legal **only** from `ReadyToPublish`, a state
the surface itself issues — never the consumer. **The surface is single-flight: at most one
in-flight transaction exists; a second `begin_revision` refuses ("hot revision surface is
busy", keep-last-good class) without touching the first.** The governing invariant of the whole
pipeline: **every fallible admission check completes before the first app-visible effect**
(Exact 0417 §4.8 rule 1) — under single-flight plus base-currency-at-begin, a transaction that
reaches evaluation cannot be doomed by identity, currency, ceiling, or shape.

**Named pre-begin consumer checks, in order** (only authenticated, accepted-for-processing
attempts enter the §6 replay table — check-1 failures and other-id busy nacks never do):

1. **Signature and identity-field verification** (§6) — the signature, then every bound
   identity field (`runId`, authority stamp, normalized target descriptor, entry/profile,
   boot/consumer identity, committed base-graph digest) against the consumer's live session
   state, before anything else touches the payload. Base-**coordinate** currency is check 3's,
   at `begin`. A failure here is unauthenticated and is **never** recorded in the replay
   table.
2. **Duplicate/identity lookup** (§6 replay law) — a pending same-`updateId` entry answers
   busy (the in-flight reservation, not a terminal outcome); an exact duplicate of a terminal
   entry returns the prior receipt idempotently and proceeds no further; a
   same-`updateId`/different-digest payload refuses `update-identity-conflict`.
3. **Base currency:** `begin_revision(policy, origin, base, invalidated)` refuses `base ≠ live`
   ("hot update base is stale") **reporting the consumer's committed `(g, r)`**; refuses in
   production mode; re-validates authority; refuses an empty invalidation set (keep-last-good —
   malformed update) or a graph-widening one (full-reload — producer/consumer graph desync).

Then:

4. `stage_replacements(txn, replacements) → Staged` — replacement records enter **only** as
   `VerifiedModuleArtifactV1` tokens plus typed edge/candidate/deferred metadata and the
   declared effect class of the update's **single accepted boundary — v1 updates carry exactly
   one accepted boundary; a multi-boundary batch refuses (full-reload class)**, which removes
   closure-wide class ambiguity. **A declared `effectful-unknown` class refuses here,
   structurally** — the state machine has no path that hot-applies it (Exact 0417 §4.8 rule 4).
   Staged records are shadow records: invisible to the live graph, keyed at candidate install
   revision `base + 1`.
5. `preflight(txn) → Preflighted` — with **zero app code**: factory compile, link-plan
   validation, export-shape comparison (§2.3), CJS-boundary eligibility (§2.3), **full ceiling
   validation of the candidate graph (§4), and the converse check**, which is two-sided with
   two distinct dispositions: a change *outside* the invalidation set refuses (full-reload
   class — producer/consumer desync), while a transaction whose **entire** staged set is
   row-identical to the live incarnations (the transaction-wide changed set is empty) is a
   **no-op** and refuses `keep-last-good` ("nothing to apply") — a touched-but-unchanged save
   must never trigger a reload. An **individual** unchanged member inside a closure whose
   changed set is non-empty is legitimate and required: 0417's closure semantics re-evaluate
   the accepted boundary AND its invalidated importer chain, so unchanged importers inside
   the set become new incarnations (their install revisions advance) even though their rows
   did not change. Failures refuse with zero app-visible effects. After `Preflighted`, the
   only remaining fallible steps are the transaction's own evaluation and preparation.
6. **Evaluation → `Evaluated`.** Class-appropriate, per Exact 0417 §4.8:
   - `contract-staged-pure`: shadow-evaluate the staged incarnations under the §2.2 shadow
     predicate; a throw refuses (`keep-last-good`) with the live graph untouched.
   - `dispose-registered`: stock dispose-before-evaluate. **The effects/publication split is
     explicit:** dispose is a bounded JavaScript effect under the consumer's 0417 rule-3
     ordering, never part of publication; it runs against the last *committed* incarnation, at
     most once per apply — and single-flight makes "per apply" global, so no two transactions
     can dispose one committed incarnation. If evaluation then throws, the module stays torn
     down until the next successful update — 0417's documented degraded state,
     `keep-last-good` class; records still never partially publish. A **throwing dispose**
     refuses the revision (full-reload class, 0417 rule 5).
   An observed effect-class mismatch refuses (full-reload class). Reaching `Evaluated` requires:
   staged evaluation settled (including shadow TLA — a still-pending or rejected shadow TLA is
   not `Evaluated`; rejection refuses `keep-last-good` and the sticky shadow error drops with
   the transaction), CJS records inside the closure finalized, and dispose (where registered)
   completed without throw.
7. **Consumer preparation → `ActivationPrepared`.** The consumer's prepare phase (Exact's
   two-phase Contract adapter: accept callbacks, shadow remount, registry overlays — **app JS
   is allowed here**, against shadow/prepared targets only, never live host state) runs
   pre-commit and, on success, deposits a **transaction-bound activation token** whose later
   application is no-fail (a prevalidated root-pointer / host-token flip). **Preparation or
   accept-callback failure refuses `keep-last-good`** — exactly Exact 0417 §4.8's
   remount-failure-inside-the-joint-transaction rule: last-good records, slots, and pixels
   stand. A consumer with nothing to activate deposits the trivial token.
8. `ready(txn) → ReadyToPublish` — the surface verifies the state invariants above and takes
   **linear ownership of the activation token** (the token is *held*, not applied — the flip
   runs only at §5.3.4); then `commit(policy, txn)`. **All three commit-time comparisons —
   authority snapshot, transaction authority stamp, and the base coordinate — are TOCTOU
   backstops:** ordinary authority admission already happened at check 3, and the armed
   snapshot is immutable for the runtime's life, so under single-flight none of them can fail
   after `Begun`; if any does, that is an invariant violation and the runtime quarantines into
   recreate (§5.3), never an ordinary refusal. Then the §5.3 bundle.
   Any ordinary refusal at any state drops shadow records, shadow completions, and the
   activation token whole; the live graph, revision counter, and install revisions are
   untouched, and the refusal maps to an Exact 0417 §4.8 class (§10).

### 5.3 The commit bundle (atomic, owner-thread, no-fail)

**All fallible work happens before the bundle** — including the candidate v2 graph digest,
which is **precomputed on the frozen candidate before the fence** and merely installed inside
it, and the transaction's **terminal outcome record** (the §6 receipt content and its replay-
table slot), which is **pre-reserved and constructed before the fence** so that finalizing it
at step 7 is an infallible field write — a later exact duplicate can therefore always return
the prior receipt (§6), whatever happens to transport. The bundle is a sequence of
infallible, prevalidated publication operations executed as one
owner-thread critical section with **no app/user JavaScript interleaved**; if an invariant
violation is nevertheless detected mid-bundle, the runtime **quarantines and recreates**
(fail-stop into the v1 generation transition) — it never returns an ordinary refusal from a
half-published state. Replacement records are fully instantiated and past export TDZ before any
of this is visible.

In order:

1. **Live-graph adoption:** swap the accepted closure's rows into the live `GenerationRecordV2`
   map (record and binding ownership passes from the transaction to the generation) and install
   the precomputed live v2 graph digest — the digest the next envelope's §6 base binding is
   verified against.
2. **Install-revision advance** for replaced `SourceId`s (§2.2) — the same authority `publish`
   reads.
3. **Slot retargets and binding relinks** (§2.3): slot-table writes plus whichever captured
   bindings (import bindings, export aliases) the implementation relinks rather than indirects.
4. **Activation-token flip:** apply the §5.2.7 transaction-bound token — a prevalidated,
   no-fail, no-JS pointer/handle flip (the root swap the Exact adapter prepared). Nothing is
   computed here; failure is impossible by construction or it is the quarantine case.
5. **Loader-cache surgery** for replaced modules through a bootstrap-installed private bridge
   (`__privInvalidateHotRevisionRecords` class — sealed with the other `__priv*` bridges, never
   realm-visible, callable only from the engine's commit path). The surgery is loader-private
   cache-map manipulation: it runs **no user code** (the cache is a null-prototype map; no
   getters, proxies, or app callbacks are reachable), is non-reentrant, and its invocation must
   not open an engine checkpoint (no microtask drain, no host poll, no timer slice) — or the
   implementation performs the map surgery natively. Post-commit resolution obeys §5.1's
   no-capture-table rule.
6. **Prepared-carrier provenance switch:** replaced `SourceId`s' records now carry inline
   source-artifact provenance and stop consulting the prepared-carrier table. The carrier
   table itself (keyed per `(principal, compartment, carrier digest)` and shared by many
   sources) is **reference-retired, not evicted**: the bundle retires the replaced records'
   references under an explicit **occupancy count per table key** — the map's own strong
   `shared_ptr` must not count as occupancy, and retiring the first replaced `SourceId` must
   not drop factories still selected by untouched records; the shared table is released only
   when its occupancy reaches zero. Untouched records keep their carrier provenance and their
   table untouched.
7. **Revision counter advance and terminal-outcome finalization** (the pre-reserved record's
   infallible field write — the replay table's pending entry becomes terminal here). The
   bundle ends here.

**After the fence,** the advisory receipt (§9.1) is **sent** best-effort from the already-
finalized outcome record: a transport failure there is telemetry loss (with bounded retry),
never quarantine, never recovery, never a publication outcome — and never a gap in the replay
table, whose entry was finalized inside the fence. A refused revision performs none of the bundle
steps. No importer can observe a state between them.

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
  `(g, r)`** — installed at every commit inside §5.3.1 — never LLP 0042's boot/deployment
  digest: after revision 1 the boot digest no longer names the graph the update applies to.
- **The canonical update body enumerates:** the invalidation closure; the single accepted
  boundary and its declared effect class (§5.2.4); per replacement record its semantic digest,
  source integrity, and full typed rows — `GraphEdgeKey` bindings, candidate-table digests +
  attributes, deferred facts (the rows the ceiling checks). The four bold identity fields exist
  because Exact's server is multi-target: without them a valid payload for one platform/profile
  could verify in another consumer whose session and revision coordinates coincide. HTTP payload
  selection and WS routing must check the same fields (Exact 0417 H1 entry obligation 3; those
  transport negatives are Exact H2 fixtures).
- **Verification order:** the consumer verifies signature and every bound field against its own
  live session state **before** any record reaches `stage_replacements` — §5.2's check 1.
  Per-record digests alone are self-consistency, not authentication (LLP 0042's adversarial
  contract).
- **Replay law (aligned to Exact 0553.001 §2.2; the key is the v1 single-session projection of
  its `(session, producer, updateId)`):** `updateId` is unique and content-bound — one
  `updateId` maps to exactly one **signed-envelope digest**. The consumer keeps a
  **session-lifetime** table `(updateId) → (envelopeDigest, entry)` scoped to the `runId` —
  not the generation — **held by the host shell, not the runtime**, so it survives v1
  runtime-recreate generation transitions and dies only with the session. Checked at §5.2
  check 2. Entry semantics, precisely:
  - **Only authenticated outcomes enter the table.** A §5.2 check-1 failure (signature or
    identity-field) is never recorded — an unauthenticated attempt cannot poison a later
    legitimate signed body carrying the same `updateId`.
  - **An accepted-for-processing update reserves a `pending` entry** at `begin`; a duplicate
    arriving while it is pending answers **busy** without sealing anything (the §10 busy row's
    retry stays possible). Settlement — commit or any authenticated refusal of a *begun*
    transaction — **overwrites pending with the terminal receipt**. A surface-busy nack for a
    *different* in-flight `updateId` is a transport-level occupancy answer and is not
    recorded at all. **Quarantine settles too:** an invariant-quarantine (§5.2 item 8, §5.3)
    terminalizes the pending entry through the pre-reserved outcome record — an infallible
    field write recording `quarantined` at the live coordinates — **before** update
    processing resumes, so no pending entry can outlive its transaction and answer busy
    forever across a recreate (the table is host-held; recreation does not clear it). For a
    begun transaction that refuses before the §5.3 bundle, the pending→terminal overwrite
    happens **before the refusal is yielded**, with the same durability as the in-fence
    success write.
  - **Terminal entries are idempotent, unqualified, for the session's life:** an exact
    duplicate (same `updateId`, same envelope digest) returns the prior terminal receipt and
    applies nothing — commits and refusals alike (the §5.3 fence finalizes the outcome record
    before any transport, so the prior receipt always exists). The same `updateId` with a
    different digest refuses `update-identity-conflict`.
  - **Capacity (4096 terminal entries) forces refusal-until-session-rotation, never
    eviction:** at capacity the consumer refuses further *new* `updateId`s with a distinct
    diagnostic naming session rotation — an **occupancy refusal in the `keep-last-good`
    class**: last-good stands, terminal duplicates still answer idempotently, and **no
    generation transition is implied or performed** (a reload mints a new generation under
    the SAME `runId` and cannot retire a `runId`-scoped table — folding capacity into a
    reload would loop). Only the producing session's `runId` rotation (new keypair,
    commitment, generation — revoking everything prior) retires the table, and the distinct
    diagnostic on the apply NACK is the producer-visible signal — it never depends on an
    advisory receipt. Duplicates from a rotated-away session fail check 1 (`runId`), which
    is refusal, not replay.
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

- the single accepted boundary's declared effect class enters the §6 signed body (it is
  admission-relevant metadata, not advice), and **the §5.2 state machine refuses
  `effectful-unknown` structurally at stage** — there is no code path that hot-applies it;
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
— prepare diff/remount/registry overlays against shadow targets in §5.2.7 (where app JS is
allowed and failure refuses `keep-last-good`), depositing the transaction-bound activation
token whose §5.3.4 application is a no-fail, no-JS flip — is the v1 target. **Objective
fallback trigger, sharpened: if the prepare/token split cannot be demonstrated by fixtures at
H2 entry — prepare-phase purity (no live host-target mutation, no framework-registry write
before commit) AND a no-fail token flip — then v1 IS (b) shadow-root-only activation with live
slot patching disabled, and (a) is withdrawn for v1, not "targeted".** Either way, no
applying-in-place pipeline runs under a hot revision. The adapter is Exact-side work; this
corpus's surface provides the state machine (§5.2, incl. `ActivationPrepared`) and the token
flip (§5.3.4) it needs.

## 9. Receipts: advisory plane, bounded ingestion (H0 MATERIALs, carried in)

The Exact H0 security review recorded three MATERIAL findings against the spike's evidence
plumbing. Dispositions, honest about what the v1 loopback posture can and cannot provide:

1. **Receipt authenticity — mitigated by de-fanging; discharge completes at H2.** In the v1
   loopback posture every local process can obtain the envelope-served credentials, so no
   receipt signature scheme available here authenticates the sender. Therefore **receipts are
   advisory, fully**: apply/refuse receipts echo `(updateId, ExecutionGeneration, HotRevision)`
   and the server binds them to its own staged update records for correlation, speculation
   warming, telemetry, and the measurement instrument — but **no correctness-bearing decision
   rides them anywhere**: class-correct recovery is executed by the **consumer itself** from
   its own verdict (the host initiates the reload/recreate — v1's generation transition is
   host-driven by construction, §3 — and the restart class reaches the host teardown + re-arm
   join directly), and the **producer restages from a credential-gated consumer-status read**
   that returns the consumer's live `(ExecutionGeneration, HotRevision)` and live v2 graph
   digest — a named requirement this spec adds, because the existing payload GET fetches
   payload bytes and returns no coordinates; in the v1 loopback posture this may be an
   in-process or status read under the §5 dev-session credential, and Exact H2 names the wire
   route. A refusal receipt is only the advisory hint to pull; the producer's own last-success
   record is a warm-path shortcut, never the stale-base answer (last-success is exactly the
   coordinate that just failed). Receipts are emitted after the §5.3 fence, best-effort, from
   the in-fence-finalized outcome record. **Recorded Exact-owner ask (§12), with the honest
   until-taken statement:** Exact 0417 §4.3's server-response sentence ("only the full-reload
   class is answered with one reload") predates this advisory plane; this spec asks Exact to
   amend it so the server's response is advisory/idempotent and recovery is consumer-executed.
   **Until the ask is taken, H0 MATERIAL 1 is MITIGATED, not discharged:** the consumer's
   recovery is self-sufficient and no ibex-side decision rides a receipt, but the unchanged
   Exact server can still be induced by a forged (loopback-forgeable) receipt to issue a
   reload the consumer did not need — a redundant-but-coherent action, bounded by the loopback
   single-user trust model, named here as the explicit residual. The discharge completes at
   Exact H2 when ask 1 is taken (or receipts become enrollment-keyed). Order-based commit
   correlation (the spike's) is not carryable; the correlation key is the revision coordinate.
   Whether receipts sign under an enrolled device key is the LAN/device follow-up's question
   (§13).
2. **Bounded ingestion and retention.** Receipt ingestion enforces, before parse or allocation:
   a per-frame byte limit (64 KiB), then during parse a closed field set, maximum JSON depth 8,
   ≤ 64 stage rows, ≤ 128 total fields, per-string-field bound 4 KiB; per-session
   retained-receipt budget 1 MiB and 256 receipts (FIFO), global budget 8 MiB across sessions.
   Oversize or over-shape input is refused whole — never truncated-and-merged, never
   re-serialized back out. Unknown fields are dropped, never merged and re-served. The spike's
   attacker-extensible receipt map is non-conforming.
3. **Harness isolation** — an Exact-side **operating rule, owned there, not discharged by this
   corpus**: measurement harnesses that rewrite fixtures run only in isolated worktrees with no
   concurrent editors.

## 10. Refusal mapping

Every refusal this surface produces belongs to exactly one Exact 0417 §4.8 class:

| This corpus's refusal | Class |
| --- | --- |
| surface busy (single-flight second `begin`) | `keep-last-good` (retry after the in-flight apply settles) |
| exact-duplicate update (replay table hit, same digest) | not a refusal — idempotent prior outcome (§6) |
| `update-identity-conflict` (same `updateId`, different digest) | `keep-last-good` (nothing applied; the producer must re-mint) |
| empty invalidation set | `keep-last-good` (malformed update) |
| graph-widening invalidation set | `full-reload-current-authority` (producer/consumer graph desync) |
| stale base at `begin` (revision race lost — no effect has run) | `full-reload-current-authority` — 0417's assignment; see the note below |
| multi-boundary batch (v1 single-boundary rule) | `full-reload-current-authority` |
| staged-record compile/link/export-shape/CJS/ceiling/converse failure in preflight (no app code has run) | preflight ceiling breaches: restart family (below); the rest: `keep-last-good` |
| staged evaluation throw / shadow-TLA rejection | `keep-last-good` |
| consumer preparation / accept-callback failure (§5.2.7) | `keep-last-good` (0417's remount rule: last-good records, slots, pixels stand) |
| `export-shape-changed` (§2.3) | `full-reload-current-authority` |
| `cjs-cross-boundary` (§2.3) | `full-reload-current-authority` |
| declared `effectful-unknown` (refused structurally at stage) | `full-reload-current-authority` |
| observed effect-class mismatch | `full-reload-current-authority` |
| throwing dispose (0417 rule 5) | `full-reload-current-authority` |
| `HotRevision` overflow | `full-reload-current-authority` |
| replay-table capacity (§6) | `keep-last-good` — an occupancy refusal for new `updateId`s carrying the session-rotation diagnostic; retired only by producer `runId` rotation, never by a reload |
| ANY v2 ceiling breach — edge added/retargeted, candidate site added/changed, deferred bit flipped, bootstrap-internal set change | restart-family strings and the restart class's recovery — the host restart join — until Exact-owner ask 3 is taken (§4); in v1 that recovery is materially reload-recreate + no-op policy regeneration under unchanged authority; after the ask, same-authority widening moves to `full-reload-current-authority` |
| authority drift (`SnapshotGenerations` / snapshot digest) | `regenerate-policy-and-restart-runtime` |
| integrity-pinned package source change | `regenerate-policy-and-restart-runtime` |
| defining-principal change | `regenerate-policy-and-restart-runtime` |
| any commit-time backstop failure — base coordinate, authority snapshot, or authority stamp (§5.2 item 8) | not a class — invariant violation: quarantine into recreate |
| no-op transaction (the ENTIRE staged set row-identical to live — §5.2.5) | `keep-last-good` ("nothing to apply") |
| stale publication token (per-slot predicate) | not a revision refusal — the stale completion itself refuses; the revision is unaffected |
| production `begin_update` / `begin_revision` | refused structurally; no dev class applies |

The restart class must reach the host's teardown + re-arm path; answering it with a plain reload
is non-conforming (it either loops or tempts a ceiling bypass). **Race-class note:** stale-base
now refuses at `begin`, before any dispose or evaluation — the refusal is pure, so 0417's
full-reload answer is wasteful-but-sound (the recreate re-delivers the newest content, the
refused producer's edit included), and a 0417-owner refinement of exactly this row to
`keep-last-good` (producer pulls live coordinates and restages; no reload) is **now genuinely
compatible with this spec** and recommended to the Exact owner (§12) — recorded here, not taken
here.

## 11. Fixtures (the required H1 exit set — these land with the implementation slices)

Each is named so Exact 0417 H2's gate can cite green runs:

- **F1 — per-slot fencing:** unchanged-module completion survives a committed revision for all
  six publication kinds (`Evaluation`, `TopLevelAwait`, `DynamicImport`, `Error`,
  `CommonJsCache`, `ArtifactCache`), including an unchanged *importer* of a replaced module
  whose TLA continuation resumes after commit; replaced-module stale completions refuse for all
  six (§2.2). Plus the shadow twin: a shadow token publishes only at `base+1` for an
  invalidated source; live publish is blind to shadow rows; a dropped transaction drops them.
- **F2 — single-flight and stale-base:** (a) a second `begin` while one transaction is in
  flight refuses busy — no dispose, no evaluation, no reload, and **nothing is sealed in the
  replay table** (a different-id update begins normally after the in-flight apply settles; a
  same-id retry after settlement is F9's terminal hit — idempotent receipt or conflict —
  never a fresh begin); (b) a
  `begin` against a stale base refuses with the consumer's committed coordinates — a
  dispose-count witness proves no effect ran; (c) the commit-time TOCTOU backstops are
  unreachable by construction (type-level where expressible, else a runtime test proving
  refusal precedes them); (d) a no-op transaction (the entire staged set row-identical to
  live) refuses keep-last-good, never a reload class — while a changed leaf plus an unchanged
  accepting importer, both invalidated, COMMITS with both install revisions advanced; (e) a
  forced backstop failure and a mid-bundle fail-stop each terminalize the pending replay
  entry (a post-recreate duplicate returns the quarantined terminal receipt, never busy).
- **F3 — package-edit refusal into the restart class:** an integrity-pinned package replacement
  refuses with the restart diagnostic, never the reload one.
- **F4 — ceiling breadth (each asserting the restart-family string — the until-ask-3
  posture; §4 records the class-assertion flip):** (a) two same-spelling
  edges of distinct `resolution_kind` over non-empty binding maps — distinct digest rows;
  widening one kind refuses despite the other being authorized; (b) candidate-site
  digest/attribute change refuses; (c) deferred→eager flip refuses; (d) bootstrap-internal set
  change refuses (§4).
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
  equivalence obligation), including a fresh same-authority ceiling derivation (§4).
- **F9 — signature adversarial set:** cross-target, cross-entry, wrong-profile, cross-consumer
  (boot identity), stale-generation, stale-revision, `target ≠ base+1`, tampered-body,
  wrong-domain, `runId`-mismatch, authority-stamp-mismatch, and **base-graph-digest mismatch
  after one committed revision** all refuse before staging **and none of them creates a replay
  entry** (a later legitimate signed body with the same `updateId` begins normally); the
  exact-duplicate replay returns the prior terminal outcome — commit and refused-attempt cases
  both; a duplicate of a PENDING update answers busy and, after settlement, returns the
  terminal receipt; `update-identity-conflict` refuses; capacity refuses new `updateId`s until
  session rotation, never evicting; the matching-tuple envelope verifies (§6).
  HTTP-selection/WS-routing negatives are Exact H2 fixtures.
- **F10 — CJS boundary set:** cross-closure CJS named-import consumption refuses
  `cjs-cross-boundary`; whole-closure CJS replacement commits with correct `default`,
  `'module.exports'`, detected-named-export snapshot, and sticky-error/eviction behavior; a CJS
  export object never crosses incarnations.
- **F11 — state-machine set:** commit from any state but `ReadyToPublish` is impossible by
  construction; `ready()` without a deposited activation token is impossible; the token held
  by `ready()` is applied only at §5.3.4 (a flip before live-graph adoption is impossible —
  linear ownership); consumer
  preparation failure refuses `keep-last-good` with live state intact; throwing dispose refuses
  full-reload class; observed-class mismatch refuses; multi-boundary batch refuses; shadow-TLA
  rejection refuses keep-last-good and its sticky error drops with the transaction; a replaced
  module's cached error does not survive into the successor incarnation; receipt-send failure
  after the fence changes no published state and triggers no recovery.

## 12. Obligation ledger (Exact 0417 §6 H1 entry obligations)

| # | Obligation | Disposition |
| --- | --- | --- |
| 1 | per-slot incarnation predicate + fixture | §2.2 (live + shadow predicates, unified lookup authority), F1 |
| 2 | two-phase Contract adapter or shadow-root-only | §8 — decided: (a) via §5.2.7 prepare + §5.3.4 token flip, with the sharpened objective fallback to (b); Exact H2 implements |
| 3 | target/base-graph-bound signature; HTTP/WS check same fields | §6 (base digest pinned to live v2 digest at (g, r); body rows enumerated), F9; transport negatives Exact H2 |
| 4 | `generation.rs` typed-graph extension + edge-ceiling fixture | §4 (deferred/candidate/bootstrap facts pinned; restart-string discipline fixture-asserted), F4 |
| 5 | candidate-effect lease as the only future effectful path | §7 + §5.2's structural `effectful-unknown` refusal |
| 6 | slot resolution at use time — every cross-module surface | §2.3 (getters, import bindings, aliases, dynamic namespaces; CJS refusal), F5/F10 |
| 7 | counter unification (OQ1) + staging-seam shape (OQ2) | §1, §5 (single-flight; incl. §5.1's no-capture-table miss rule) |

H0-carried MATERIALs: receipt authenticity → §9.1 (**mitigated**: fully advisory ibex plane,
consumer-executed recovery, consumer-status coordinate pull, post-fence emission from the
in-fence-finalized record; **discharge completes at Exact H2** when owner ask 1 is taken or
receipts become enrollment-keyed — the forged-receipt-induced redundant server reload is the
named residual until then); bounded ingestion/retention → §9.2;
harness isolation → §9.3 (**operating rule, Exact-owned — scheduled, not discharged here**).
Exact 0553.001 O-3 → §1 (successor law) + §6 (replay law: session-lifetime terminal
idempotence, pending reservation, refusal-until-session-rotation at capacity). Exact 0417 OQ4
(slot granularity, `hot.data` algebra) →
**explicitly left open, owned by Exact** (§2.3).

**Recorded Exact-owner asks (this lane files the Exact-repo ticket; none is taken here):**

1. Amend Exact 0417 §4.3 so the server's class-driven response becomes advisory/idempotent —
   class-correct recovery is consumer-executed (§9.1); until taken, a server reload beside the
   consumer's own recovery is redundant, never the sole path.
2. Refine Exact 0417 §4.8's revision-race row to `keep-last-good` — now genuinely compatible
   (§10's race-class note): stale-base refuses at `begin` before any effect.
3. Narrow Exact 0417 §4.8's restart-row "edge widening" to authority-relevant widening (§4's
   two recovery grades): same-authority shape growth is served by the reload class's
   generation re-derivation.

## 13. Open questions

1. **Payload record form** (Exact 0417 OQ3): v1 ships dev-served-shaped full records only; a
   fetchModule-style form for large boundaries is admissible later without changing §6's
   signature shape (the payload digest covers whichever body form is declared).
2. **Computed-candidate refresh:** v1 refuses candidate-set change at the ceiling (restart
   strings; until ask 3 the recovery is the host restart join — §4/§10 — and after it, the
   reload class's same-authority re-derivation). Should a later version admit same-site
   candidate re-derivation under a live
   ceiling when the armed policy already authorizes every candidate target? Requires its own
   adversarial fixtures; not v1.
3. **Surviving-runtime advance-and-retire:** the §3 retirement-fixture set is enumerated; the
   engine work (generation-owned cancellation for timers/next-ticks/globals/host registrations)
   is unscheduled. Post-v1.
4. **Receipt signing under device enrollment:** §9 deliberately stops at the advisory plane for
   v1. The LAN/device enrollment follow-up should revisit whether receipts sign under the
   enrolled device key, at which point correctness-bearing server decisions could return.
5. **The three recorded 0417-owner asks (§12):** their taking or refusal is Exact's; this spec
   is written to be sound under either outcome of each.
