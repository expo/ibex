# CapSec coverage-model definition total is stale after `fs:unbound-read`

**Status:** Closed
**Severity:** P2 (suite hygiene; blocks a required focused check)
**Systems:** CapSec, Testing
**Found by:** 2026-08-07 two-P1 remediation verification
**Related:** `issues/closed/20260806-exactwhich-declares-typed-effects-it-never-emits.md`;
`issues/closed/20260806-llp0050-asyncfunction-root-global-unclassified.md`
**Date:** 2026-08-07

## Symptom

On integrated `origin/main` at `e11071717`:

```text
bun test packages/ibex-devtools/src/scripts/capsec-coverage-model.test.mjs

Expected length: 41
Received length: 42
(fail) ... definition coverage accounts for all 41 frozen definitions

142 pass
1 fail
```

`bun run check:drift`, the root-global disposition generator, and the registry
generator are green. The evaluator-identity regression itself also passes.

## Adjudication

Commit `54f69d0df` added the deny-only `fs:unbound-read` capability definition
for the `__exactHandleReadFileSync` remediation and regenerated the registry,
which now validates 42 definitions. The focused coverage-model test retained
the previous hard-coded total and title (`41`). This is not an
`AsyncFunction` classification failure and does not invalidate the physical
`__exactWhich`/legacy-bearer results, but it leaves one of the P1 handoff's
required focused checks red.

The handoff reserved `packages/ibex-devtools/src/scripts/capsec-*` to the LLP
0049 Phase 1 ownership seam and explicitly required this session to stop rather
than edit there, so the count assertion was not changed here.

## Done when

Re-derive the frozen-definition total from the reviewed registry change,
update the exact assertion/title in
`packages/ibex-devtools/src/scripts/capsec-coverage-model.test.mjs`, and confirm
the full file passes without weakening the fail-closed coverage checks.

## Resolution — 2026-08-07 (LLP 0049 Phase 1 orchestration session)

Fixed in `1eb7a78dc`: `capsec-coverage-model.test.mjs` restamped 41 -> 42.
Verified the registry actually holds 42 definitions; the suite is now
143 pass / 0 fail.

**Attribution correction.** This ticket recorded the fix as blocked on a
protected LLP 0049 Phase 1 seam. It was not. Phase 1 never touched
`capsec/registry/capability-definitions.json` or
`capsec-coverage-model.test.mjs` — zero commits against either across
`5e41aca0..1c3806832`. The definition count moved because
`54f69d0df` ("typed enforcement for `__exactWhich`") added the
`fs:unbound-read` definition (+15 lines in capability-definitions.json).
The stale assertion was a direct consequence of that change, so no seam
was in the way.
