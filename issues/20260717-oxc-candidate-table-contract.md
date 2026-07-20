# Computed-candidate table contract (site labels, sidecar, generation)

**Status:** Complete
**Severity:** P2
**Systems:** Module Loader, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §2, LLP 0027, LLP 0014
**Depends-on:** llp0014-canonical-policy-v2

Decision resolved 2026-07-18: Snapback requires computed dynamic imports for
0.2, so this work landed now rather than after a fail-closed-only release.

The contract layer for native computed dynamic import:
- **Site naming:** reserved literal options key
  (`import(expr, { with: { "ibex:site": "label" } })`) — author-chosen,
  unique per requester module (duplicates are generation errors),
  stable across edits/re-pins. Unlabeled computed sites have no row and
  fail at invocation.
- **Producer site table:** requester `SourceId`, requester source
  integrity, label, ordinal, original-source span — the single parsing
  authority; the LLP 0014 generator joins manifest declarations via the
  label column (no second parse). Unifies today's inconsistent site
  representation (ESM transformed byte offset vs CJS ordinal).
- **Sidecar:** `ibex/computed-candidates/1`, digest-bound, referenced
  from `prepared-module-graph/2` (one new reference field; v1 graphs
  rebuild), keyed by (requester SourceId, requester source integrity,
  transform fingerprint, site, generation); rows carry label, spelling
  set, attributes, resolved target SourceId + integrity. Site ordinals
  valid only within one fingerprint domain (rotation fixture: no
  cross-domain row validates). Merkle-root variant available for large
  closures.
- Deterministic enumeration rules (package boundary, symlinks,
  zero-match diagnostics); ModuleArtifact v1 unchanged.

**Done when:** schemas land with golden vectors; two-site disjoint
non-escalation and cross-domain rotation fixtures pass; generator join
works end-to-end from a manifest declaration.

## Completion evidence — 2026-07-18

`src/module_loader/computed_candidates.rs` and
`schemas/computed-candidates-v1.schema.json` implement the strict canonical
sidecar; `tests/fixtures/computed-candidates-v1.golden.json` pins its bytes.
The Oxc producer emits original-source correspondence once, including through
TypeScript lowering, and the source/compiled graph publishers join reviewed
`package.json` declarations without a second parse. Prepared graph v2 and SFE
candidate sections digest-bind the same bytes. Rotation, source/prepared join,
and per-site non-escalation tests are required by the workspace suite;
`tests/fixtures/computed-candidate-app/` pins the manifest-to-policy TLA path.
