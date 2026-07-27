# LLP 0014 canonical-policy schema v2 (single coordinated revision)

**Status:** Closed
**Resolution:** Closed from the completion evidence recorded in f5688afb: canonical policy v2, strict admission, regenerated examples, and rotation coverage landed together.
**Severity:** P2
**Systems:** Security, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §2, LLP 0029 §1/§4, LLP 0014, LLP 0021

Both programs need fields in the canonical policy artifact, whose Rust
ingest is `deny_unknown_fields` — two uncoordinated revisions cannot
both be "the versioned change." One owner, one version bump, carrying:

- LLP 0028: computed-candidate manifest vocabulary (site-label
  declarations, package-closure opt-in rows, per-site closure
  materialization participating in `--check` expansion diffs).
- LLP 0029: graph-identity field (`ibex/authenticated-graph-snapshot/1`
  digest), bound entry identity, target/mount profile, and the
  normalized root-ceiling declaration — all covered by `policyDigest`,
  with deterministic authoring, drift-check behavior, and artifact
  naming keyed by entry + target/profile.

**Done when:** schema v2 + Rust ingest + generator + `--check` land
together; both RFCs' field sets covered; golden vectors; LLP 0014
`Revised:` entry in the same commit.

## Completion evidence (2026-07-17)

- The strict schema, checked digest contract, canonical example, and Rust
  `deny_unknown_fields` ingest all moved atomically to
  `ibex/capsec-policy/2` / `ibex:capsec:policy:2`. Rust validates normalized
  entry and target identities, root-ceiling rows, exact package opt-ins, and
  one-to-one candidate declaration/materialization.
- The policy generator binds the entry source integrity and the
  `ibex/authenticated-graph-snapshot/1` projection, emits source or compiled
  target/mount profiles, reads provenance-carrying root ceilings, and closes
  computed sites over explicit specifiers plus exact opted-in package
  closures. Default output names include entry and deployment profile.
- Drift classification treats root-ceiling and materialized-candidate
  additions as expansions while reporting graph, entry, target, and mount
  changes as identity drift. JavaScript and Rust goldens cover compiled
  profiles, candidate widening, missing opt-ins, and strict ingest.
- All four checked-in example policies were regenerated deterministically;
  three were verified against isolated `HEAD` fixture graphs so unrelated
  pre-existing fixture deletions in the worktree were not restored.
- LLP 0014 carries the coordinated `Revised: 2026-07-17` contract and LLP
  0021 records the policy digest-domain rotation.
