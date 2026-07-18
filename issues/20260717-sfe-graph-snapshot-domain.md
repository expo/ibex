# ibex/authenticated-graph-snapshot/1 digest domain

**Status:** In Progress
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
