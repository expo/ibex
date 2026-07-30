# Independent prepared-graph commitment (armed + session-bound dev)

**Status:** Closed
**Resolution:** The production Phase 2 blocker landed on 2026-07-29:
`preparedGraphs` is snapshot-authenticated, committed admission is source-free
and root-first, and runtime refusal goes to cold rebuild without rejoin
acceptance. The direct source-deleted/substitution test and the 36/36 external
substitution fixture are green. Development-session credential transport is
split to `issues/20260729-prepared-graph-development-session-commitment.md`.
**Systems:** Module loader, CapSec, Arming, Host embedding
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-28

**Filed:** 2026-07-28 (Exact LLP 0413 §5.7, accepted; round-1 codex
material finding)
**Related:** LLP 0026 (writable prepared cache is not an independent trust
root — it reconstructs the authenticated inline source graph, parses, and
byte-compares; production-prepared needs an independently authenticated
deployment commitment "unavailable to the writable cache"); LLP 0027
(deployment-graph binding); LLP 0036 (target advertisement)

**Impact:** 5
**Urgency:** 3
**Ease:** 2
**Confidence:** 3
**Score reviewed:** 2026-07-28
**Score rationale:** Without this contract, Exact's parse-free prepared
lane forks between violating parse-free (source rejoin) and violating
admission (trusting a self-consistent cache). It is the named prerequisite
for Exact LLP 0413 Phases 2–3 and a Phase 1 design exit.

Design and implement the commitment LLP 0026 already names:

- **Production:** bind the prepared publication root through the armed
  resources/snapshot commitment (e.g. an armed-snapshot field), so warm
  prepared startup admits without reconstructing/parsing the source graph.
- **Development:** a run/session-scoped, explicitly non-production
  commitment binding target, graph digest, producer identity, semantic
  inventory, principal set, policy identity, and lifetime (credential
  shape, binding surface, revocation are open — Exact LLP 0413 §16 Q14).
- **Adversarial gate:** an attacker who substitutes a self-consistent
  index/carrier set and recomputes every cache-local digest MUST still be
  refused because the independent commitment does not match.

## Acceptance

- A prepared generation admits against the commitment with zero
  application-source parsing on the warm path.
- The authority-substitution fixture refuses before effects.
- The development commitment cannot be confused with production authority
  (distinct schema/marking; visible in diagnostics).

**LLP:** design drafted as `llp/0042-prepared-graph-independent-commitment.rfc.md` (Draft, 2026-07-28); this ticket now tracks implementation once the design is reviewed.

## Progress 2026-07-29 (Exact LLP 0413 Phase 1 arms E/F, M4)

The Exact tournament built the PRODUCTION-SHAPED fixture layer against the
approved direction:

- The Exact producer emits `ibex/prepared-graph-commitment/1` records for
  its adapter-1 publications (`scripts/emit-prepared-graph-commitment.mjs`
  in the Exact repo): one publication-root digest over the canonical
  `index.json` bytes (`ibex:prepared-publication-root:1`) plus the facet
  fields, written OUTSIDE the publication directory. No dev credential was
  invented (open question 1 stays open); fixture placeholders (`target`,
  `policyDigest`) are labeled as such. Derived-facet conventions used
  pending the LLP 0042 wire freeze: `semanticInventoryDigest` digests the
  JCS array of sorted-unique record semantic digests
  (`ibex:prepared-semantic-inventory:1`); `principalSetDigest` digests the
  JCS array of the publication's defining principals sorted by
  `canonical_order_key` (`ibex:prepared-principal-set:1`), principals
  derived from record SourceIds with builtin -> root.
- `tests/llp0413_prepared_commitment_fixture.rs` (env-gated, skips in CI)
  proves the adversarial gate at fixture level with the REAL strict-JSON /
  JCS / digest code: 12 genuine publications accept (facets recomputed
  independently in Rust byte-match the TS emitter), and **36/36
  substitutions of fully self-consistent sibling publications** (same
  lane, same producer, same deployment-graph digest, every cache-local
  digest correct) **refuse at the root check, classified as
  commitment-mismatch** — distinct from corruption (truncation classifies
  as corrupt).

## Resolution evidence 2026-07-29

- `load_prepared_graph_committed_v1` authenticates canonical `index.json`
  against an armed publication root before consuming any cache-local claim,
  then validates facets, inventory, candidate tables, per-principal carriers,
  artifacts, and transform fingerprints.
- `ArmedSnapshot::load` validates the optional, digest-bound
  `preparedGraphs` section and refuses development-schema class confusion.
- The runtime selects committed mode before graph construction and, after
  any committed refusal, cold-builds without invoking rejoin admission.
- The focused witness removes application source before committed load,
  observes zero source receipts, admits the genuine publication, and refuses
  a genuine self-consistent sibling at the independent-root check.
