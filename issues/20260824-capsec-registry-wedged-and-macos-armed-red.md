# CapSec registry pipeline wedged (plan-seam) + macOS armed engine tests red (RAF disposition drift)

**Date:** 2026-08-24
**Found by:** the LLP 0053 §I1 carrier-ingress lane, while trying to verify its
own change. All findings below reproduce byte-for-byte at the pre-change
baseline (54e609598, on origin/main ancestry) — none are caused by the I1
work.

## 1. `check:capsec-registry` and `check:root-global-dispositions` are wedged on main

`bun run check:capsec-registry` (and `check:root-global-dispositions`, which
shares discovery) fails before evaluating anything else with:

```
embedding ABI declaration/definition drift: definitions without declarations
[ex_hermes_plan_seam_benchmark_direct_batch_v1,
 ex_hermes_plan_seam_benchmark_reset_adapter_counters_v1,
 ex_hermes_plan_seam_benchmark_take_adapter_counters_v1,
 ex_hermes_plan_seam_create_benchmark_v1]
```

The four benchmark symbols (commit e079cfae1, Exact M1 WP10 / LLP 0517 §10)
are declared in `include/exact_runtime_plan_seam_benchmark.h`, but the
surface scanner reads only `include/exact_runtime.h`. Probing past that error
(locally filtering plan-seam symbols) surfaces further pre-existing
unclassified surfaces, in order:

- `host-abi:ex_hermes_plan_seam_apply_facet_host_inputs_v1` (and siblings —
  the plan-seam family has no coverage edges / reviewed-name entries at all)
- `native-op:__exactPlanHermesSeamNativeV1`
- `native-op:global:AsyncFunction`

Consequence: **no registry-authority change can currently be regenerated or
landed** — `generate:capsec-registry --write` dies before writing, and
hand-editing `capsec/registry/coverage-edges.json` breaks the checked
registry digest that ~21 `host::` lib tests pin (verified: hand-adding edges
turned `cargo test -p ibex-runtime --lib host::` from 0 to 21 failures;
reverting restored green). `generate:vendored-fingerprint --check` is also
stale at the same baseline.

Owner suggestion: the 0514 M-track lane that landed the plan-seam surfaces.

## 2. ALL armed engine tests fail on macOS: RAF root-global disposition drift

Every armed engine test (`--features capsec-conformance-observer`) fails on
macOS with:

```
Armed startup refused: root-global disposition (…): extra post-bootstrap
roots: __exactRequestAnimationFrame
```

Commit bdd3ec1cf gates the RAF host on `#if defined(__APPLE__)`
(`src/engine/hermes_runtime_ios.cc:42` — deliberately Apple-wide, macOS
included), but `src/engine/root_global_disposition.generated.h` carries
`__exactRequestAnimationFrame` rows only for target variants `ios` and
`android` (rows at lines 359-360, 1283-1284, 3308-3309).
`rootGlobalActivationApplies` accepts `ios` only under `TARGET_OS_IOS`, so a
macOS armed runtime sees an un-manifested live root and refuses the seal.

Local probe evidence (NOT committed): temporarily rewriting the `ios` RAF
rows to `apple` in the generated header takes the armed exact suite from
11 failures to 1 on this Mac — the remaining failure
(`authenticated_commonjs_require_activates_exact_target_in_drive`,
"lifecycle exitCode write authority required") also reproduces at the
baseline with the same probe and is a separate pre-existing issue.

Fix direction: the root-global disposition generator needs an `apple`
target-variant mapping for the `hermes_runtime_ios.cc` RAF install (or the
authority input that assigns its variant), then regenerate — blocked today
by finding 1 above.

## 3. Handoff: registry rows for the LLP 0053 §I1 surfaces (blocked on 1)

The I1 commit adds five public ABI symbols that need registry joins once the
pipeline is unwedged. The exact rows were prepared and validated as far as
the probe allowed (with them in place, the registry check no longer flags the
new symbols; the next error is the pre-existing `AsyncFunction` one), then
reverted because the digest cannot be regenerated:

- `capsec/registry/coverage-edges.json` — five `non-capability` /
  `authority-control-plane` edges (rationale text identical to the v1
  siblings), ids computed with the stable-id scheme:
  - `surface.host.abi.ex.hermes.set.exact.host.call.async.v2.0071fl3`
  - `surface.host.abi.ex.host.authorize.exact.endowment.v2.1mv6d2f`
  - `surface.host.abi.ex.host.prepare.exact.armed.embedder.artifacts.v2.0vqi1s8`
  - `surface.host.abi.ex.host.build.exact.armed.embedder.artifacts.v2.0sopc7v`
  - `surface.host.abi.ex.host.build.exact.runtime.extension.armed.embedder.artifacts.v2.026ormu`
- `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs` — the five
  names appended beside their v1 siblings in `REVIEWED_HOST_ABI_NAMES`, the
  normalized `exhermessetexacthostcallasyncv2` in the embedder
  authority-control-plane set, and the four normalized `exhost…v2` names in
  the host authority-control-plane set.

After applying, run `bun run generate:capsec-registry --write` (once
finding 1 is fixed) so the digest bundle, implementation manifest, and
bindings regenerate together.

## Priority

- Impact: 4 — main's registry governance gates and all macOS armed engine
  verification are inoperative.
- Urgency: 3
- Ease: 2
- Confidence: 5
- Score reviewed: 2026-08-24
- Score rationale: blocks landing any new public ABI surface cleanly and
  hides real armed regressions on macOS.
