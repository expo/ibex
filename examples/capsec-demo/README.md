# Ibex Capability Security rev2 — hands-on demos

These examples demonstrate the typed, digest-bound CapSec profile described by
[LLP 0021](../../llp/0021-capsec-effect-model-migration.plan.md). They are
deliberately written for the current runtime:

- ordinary `ibex run` is enforce + lockdown; there is no permissive production
  arm and no security opt-in;
- policy files are generated canonical artifacts, not hand-authored lists of
  capability strings;
- package authority and ambient globals are separate gates—granting an effect
  does not silently restore `process`, `fetch`, or another endowment;
- audit is the explicit, ephemeral `ibex capsec audit <entry>` workflow.

Run everything, or one numbered chapter:

```sh
./run.sh
./run.sh 1
```

`run.sh` preserves the real Ibex exit status. If an example unexpectedly fails,
the script fails too.

## The four examples

| # | Folder | What it demonstrates |
|---|---|---|
| 1 | [`01-supply-chain`](01-supply-chain/) | Enforce-by-default package containment and explicit root brokering |
| 2 | [`02-least-privilege`](02-least-privilege/) | One typed env grant does not create an ambient `process` endowment |
| 3 | [`03-audit-mode`](03-audit-mode/) | The separate foreground audit diagnostic, with no durable audit policy |
| 4 | [`04-defense-in-depth`](04-defense-in-depth/) | Generated-policy drift checks and digest-tamper refusal |

## Build and regenerate

From the repository root:

```sh
cargo build --bin ibex

# Regenerate the three durable demo policies after changing an import or package.
target/debug/ibex policy generate --entry examples/capsec-demo/01-supply-chain/app.js
target/debug/ibex policy generate --entry examples/capsec-demo/02-least-privilege/app.mjs
target/debug/ibex policy generate --entry examples/capsec-demo/04-defense-in-depth/app.mjs

# CI-style drift verification.
target/debug/ibex policy check --entry examples/capsec-demo/01-supply-chain/app.js
target/debug/ibex policy check --entry examples/capsec-demo/02-least-privilege/app.mjs
target/debug/ibex policy check --entry examples/capsec-demo/04-defense-in-depth/app.mjs
```

The artifacts are lockfile-like review inputs: each package principal includes
its exact locator and integrity, each authority row has provenance, and a stale
or malformed artifact refuses execution instead of selecting a weaker mode.

## A note about target claims

CapSec conformance is exact-target evidence. A build on an unadvertised target
must refuse rather than silently degrade. If a demo stops before project code
with an unsupported-target message, that is the security contract working—not
an invitation to add a permissive flag.
