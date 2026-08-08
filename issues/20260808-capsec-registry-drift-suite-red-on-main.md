# Five capsec suites red on main — obligation counts, canonical examples, contract validation

**Opened:** 2026-08-08 · **Priority:** P2 · **Owner:** the workstream that
landed the recent `capsec/registry` changes (filed by the LLP 0049 Phase 1
session during integration, which adjudicated them as not its own)

## Symptom

`bun test packages/ibex-devtools/src/scripts/` reports five failures on
`main`:

- `canonical environment output templates > rejects empty-base, overlay,
  authorization, facade, and coverage source drift`
- `Exact fixture-evidence pilot > credits nine actual fixtures plus
  reviewed internal proofs and keeps promotion closed`
- `exact-target CapSec executable recipes > accounts for every obligation
  exactly once and reports honest residuals`
- `exact-target CapSec executable recipes > accounts for the Windows
  candidate without borrowing Apple probes`
- `LLP 0021 capsec contract > all schemas, registries, examples, and
  generated output validate`

## Adjudication (per the pre-existing-beats-papered rule)

All five reproduce at `origin/main` **without** the LLP 0049 Phase 1
findings merge (`5fa827b36`). Method: a detached worktree at
`6801ab6bb` (the commit immediately before that merge) with the same
`node_modules`, running the same suites.

The baseline in fact shows a **sixth** failure the merged tree does not —
`LLP 0021 capsec contract > target cells reject unknown and wrong-target
implementation branches` — so the Phase 1 findings work is net-neutral to
net-positive against this set, not a contributor.

These are the drift signature of recent concurrent `capsec/registry`
changes: obligation accounting, canonical example digests, and contract
validation. The LLP 0049 session did not touch `capsec/registry/` except
where the findings work required it, and its own suites are green.

## Why this session did not fix it

Restamping obligation counts and canonical digests is only safe when you
know which change moved them and whether the new numbers are correct.
Guessing re-pins a count to whatever the tree currently produces, which
converts a real drift signal into a green test — the exact inversion the
drift guards exist to prevent. The owning workstream knows what it
changed; this session does not.

## Consequences while open

The obligation-accounting and contract-validation guards are red, so
nobody can currently prove on `main` that the capsec registry, canonical
examples, and generated output agree with each other.

## Done when

Each of the five (six) failures is traced to the change that moved it,
the numbers or digests are restamped by their generators with the reason
recorded, and the suites are green on `main`.
