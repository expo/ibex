# LLP 0050 landing left `native-op:global:AsyncFunction` unclassified — root-global chain red on main

**Status:** Closed

**Opened:** 2026-08-06 · **Priority:** P1 · **Owner:** the ENG-25093 / LLP 0050
workstream (this ticket filed by the LLP 0049 Phase 0 session during
integration)

## Symptom

`bun run check:drift` is red on `main` since `8256639b` ("feat(engine): real
FinalizationRegistry semantics — LLP 0050"):

```
generate-root-global-dispositions.mjs --check
Error: unclassified observed surface native-op:global:AsyncFunction
  at classifyObservedSurface (capsec-coverage-model.mjs:15653)
```

## Adjudication (per the pre-existing-beats-papered rule)

- At `27dd0b6a` + the LLP 0049 Phase 0 changes (pre-rebase): `check:drift`
  **green** (run twice — by the authoring lane and independently at
  integration).
- At `8256639b` **alone** (throwaway worktree): the same
  `AsyncFunction` failure fires. **The red is pre-existing to the Phase 0
  rebase and belongs to the LLP 0050 landing**, which exposed a new
  observed root global without running the root-global disposition chain
  (`generate:root-global-dispositions` — note this is a DIFFERENT
  generator from `generate:capsec-registry`).

## Why the integrating session did not fix it

Classifying `AsyncFunction` is not mechanical: it is an eval-family
constructor, and its root-global disposition (gated capability vs
PRIVATE_CONSUMERS vs exclusion) is a security-posture decision that
belongs to the LLP 0050 author — see the standing rule that a
capture-then-delete global must be in PRIVATE_CONSUMERS or **armed startup
refuses to seal bootstrap**. A wrong guess here either breaks armed
startup or silently widens the eval surface.

## Consequences while open

- `check:drift` red on main (the root-global leg; all other generated
  artifacts current as of `2b7b9022`).
- The capsec catalog at merged HEAD (`sha256-C4T2GOmlKtNepQb5tBc5gulZ…`)
  differs from the Phase 0 gated catalog (`sha256-sMzObEF9jpCF5fpgJ4FI…`)
  by the 0050-induced surface delta; that delta is un-gated until this is
  classified and the chain regenerated. fs+env+process scope measured
  identical at both digests (610 / 537 / 73 / 3,927 / 491 / 80).
- Armed-startup bootstrap sealing may refuse on builds that observe the
  new global (untested here).

## Done when

`AsyncFunction` carries an author-reviewed classification, the root-global
disposition chain is regenerated (not hand-edited), `check:drift` is green
on main, and the 0050 surface delta passes the route-evidence gate
(`scripts/llp0045-route-evidence-diff.mjs --scope all`) with an authored
allow-list.

## Resolution (2026-08-07)

Resolved on `main` by `d604d116b` (`fix(capsec): restamp four-evaluator
identity after LLP 0050 lockdown delta`). The failure was not a missing or
new disposition for `AsyncFunction`. LLP 0050 added `WeakRef` and
`FinalizationRegistry` to the lockdown hardening roots, which rotated the
content-addressed lockdown taming digest and therefore the review identity
shared by all four reachable evaluator surfaces. The stale identity pin made
the classifier fail closed, and `AsyncFunction` happened to be the first
observed surface reported.

The sibling precedent determines the ruling without widening the armed
surface: `AsyncFunction`, `Function`, `GeneratorFunction`, and `eval` all
remain closed as `vm:evaluate`. `AsyncFunction` and `GeneratorFunction` are
`intrinsic-reference-only` roots reached through lockdown's prototype
reflection; neither is a capture-then-delete global, so the
`PRIVATE_CONSUMERS` rule does not apply. The reviewed restamp moved the shared
review ID and taming digest together, then regenerated the complete chain; it
did not change capability definitions, coverage semantics, target cells,
dispositions, or runtime code.

Verification on integrated `origin/main` (`e11071717`):

- `bun run check:drift` — PASS, including 2,811 root-global install branches
  and all generated artifacts current.
- `bun test packages/ibex-devtools/src/scripts/generate-capsec-registry.test.mjs`
  — 12 pass / 0 fail, including byte-identical rendering and committed-output
  currency.
- `scripts/llp0045-route-evidence-diff.mjs --scope all` — PASS in strict
  declared-allow-list mode against the exact `1c3806832..d604d116b` restamp:
  22,505 recipes on both sides, zero route changes, zero residual delta, and
  zero stale entries. The intentionally empty advance declaration is
  `llp/evidence/0050-asyncfunction-root-global-route-allow-list.json`.
- `bun test packages/ibex-devtools/src/scripts/capsec-coverage-model.test.mjs`
  — the evaluator-identity/classification regression passes. The suite is
  142/143 overall because the separate `fs:unbound-read` definition added by
  the `__exactWhich` remediation left a frozen total at 41 instead of 42; that
  unrelated red is tracked by
  `issues/20260807-capsec-definition-coverage-count-stale.md` and was not
  papered over across the Phase 1 script seam.
