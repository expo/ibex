# LLP 0050 landing left `native-op:global:AsyncFunction` unclassified — root-global chain red on main

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
