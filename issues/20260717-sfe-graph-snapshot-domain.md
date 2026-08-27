# ibex/authenticated-graph-snapshot/1 digest domain

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 3
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “ibex/authenticated-graph-snapshot/1 digest domain” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the fix requires a few coordinated implementation and test surfaces, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
**Severity:** P2
**Systems:** Module Loader, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §1 step 1, LLP 0027, LLP 0021

The domain does not exist today: the module-generation digest covers
three of six inventories, the Rolldown `graphDigest` bound into
publication hashes records with absolute paths, and the armed snapshot
carries a third `packageGraph` digest. Define the new domain — a
canonical schema and precommitted projection over node identities,
package identities, source integrity, typed edges, candidate sets, and
entry designation — that subsumes the generation digest's packaging
role and replaces the path-bearing Rolldown digest in every embedded
binding. The embedded snapshot is the **single graph source**: compiled
arming *derives* the authority-bearing armed package graph from it via
a total normative projection (mutation vectors for every projected
field; projection mismatch = packaging refusal, boot derivation failure
= boot refusal). Carrier manifests re-bind to this digest at packaging
(payload bytes verbatim). Includes the deterministic `hermesc` recipe
(logical filenames, controlled cwd/env) so semantic identity is
path-independent end to end.

**Done when:** cross-language golden vectors pin the projection;
policy/carrier/envelope all bind one snapshot; inter-step-mutation and
divergent-graph fixtures refuse packaging; clean-root HBC byte
comparison passes.

Status note (moved verbatim off the **Status:** line by `node scripts/issue.mjs`; cdcstack issue statuses are exactly `Open` or `Closed`): remaining authority projection is deferred to v1.1 CapSec

## Progress — 2026-07-17

The product-neutral CapSec core now owns the strict
`ibex/authenticated-graph-snapshot/1` projection over entry designation, node
`SourceId`/source integrity, exact package identities, typed edges, and
candidate sets. Rust and JavaScript validate and hash one checked-in golden to
the same digest. The embedded graph and phase-0 policy/carrier/provenance all
bind and recompute that digest. The fixed catalog compiler recipe is now an
independent strict digest contract with exact arguments, empty environment, and
private working directory. Production policy generation, inter-step
mutation fixtures, armed package-graph derivation, and clean-root HBC
reproducibility remain.

## Progress — 2026-07-18

The authenticated native graph now crosses into SFE publication through one
immutable publisher boundary. Publication re-verifies every artifact digest and
the exact typed artifact/resolver edge set, derives the embedded snapshot once,
and only then constructs carrier manifests bound to that identity. Mutation
fixtures prove that changing an admitted artifact field or dropping a typed edge
between graph assembly and publication refuses before carrier bytes are emitted.
The publisher's multi-module+builtin outputs are also invariant to checkout-path
changes. Production policy generation and the armed package-graph projection
still need to consume this result; clean-root HBC comparison still awaits the
two populated release catalog cells.

## Progress — 2026-07-18 (compiled policy binding)

Compiled-policy generation now consumes the native loader's exact canonical
snapshot. It verifies the complete root/package file inventory and integrity,
package principals, and entry identity against the policy-analysis graph; typed
edges and builtin records remain native snapshot facts. `ibex compile`
independently recaptures that graph and re-admits the policy against it before
carrier compilation. The remaining graph-domain work is the authority-bearing
armed package-graph projection and the clean-root comparison using populated
release catalog cells.

## Remaining (verified 2026-07-31)

- DONE: cross-language golden vectors; one snapshot binds policy,
  carriers, and envelope on the compiled/embedded path; inter-step
  mutation refusal; hermesc recipe digest contract; checkout-path
  invariance (unit-level).
- The divergent-graph fixture (Rolldown vs module-runner semantic
  divergence, the LLP 0029 review-resolution criterion) has zero
  implementation — the Progress text reads as two items remaining but
  it is three.
- Clean-root HBC byte comparison does not exist outside prose; the only
  reproducibility harness is the factory-table dev-pack script.
- The armed `packageGraph` is still digested under its own
  `ibex:capsec:package-graph:1` domain (src/bin/ibex/runtime.rs:5433),
  not a normative projection of the snapshot; and the legacy deployment
  path still uses `ibex/rolldown-deployment-graph/1`.

## LLP 0047 reconciliation — 2026-08-01

The snapshot remains the shared identity for both modes. Clean-builder HBC
comparison is milestone 1/3 work. The normative armed-package-graph projection
is needed by the CapSec-selected path and its fixture-only successful arming;
ambient boot must still admit the same graph and policy but does not construct
or claim an authority snapshot.

## Implementation checkpoint — 2026-08-02

The producer now has explicit divergence fixtures at both boundaries. Rust
recaptures a mutated source tree and refuses the previously authored policy's
graph identity, while the JavaScript policy-authoring comparator independently
mutates file identities, package inventory, entry identity, and computed
candidate materialization and refuses each disagreement with the native
snapshot. Two physical clean Linux builders also produced identical real HBC,
CompilePlan, and unsigned executable identities. The remaining
authority-bearing `packageGraph` projection belongs to the deferred successful
CapSec path described above; it is not required by ambient v1.
