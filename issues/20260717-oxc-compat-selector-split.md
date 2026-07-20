# Split EXACT_COMPAT_TEST: fixture fidelity vs loader selection

**Status:** In Progress
**Severity:** P2
**Systems:** Runtime, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b

`EXACT_COMPAT_TEST` carries two distinct semantics: (a) fixture
fidelity — compat-harness polyfills, Bun test globals, process-identity
shims (`compat/runner.rs:486`, `compat-polyfills.js`, `process.ts:804`,
`Headers.ts:36`) — and (b) loader-selection / preparation bypass
(`runtime.rs:1646,3292`). Retain (a) as the compat harness's
fixture-fidelity contract (rename if useful); give (b) its own selector
that retires with the compat loader. Every producer and reader gets an
explicit retain/migrate/remove disposition in the retirement manifest;
repointed native runs carry execution receipts.

**Done when:** the two semantics are separate named selectors; loader
meaning retired with the window; no reader undispositioned.

## Progress (2026-07-17)

The semantic split is implemented:

- `EXACT_COMPAT_TEST` now controls fixture fidelity only: runtime polyfill
  reapplication plus the retained compat globals, process identity, fetch, and
  stream shims.
- `IBEX_COMPAT_LOADER_TEST` is the preparation-bypass selector. The compat
  runner, module-semantics/for-of harnesses, bootstrap/compartment tests, and
  loader benchmark set it explicitly when they require the bounded legacy
  loader.
- The generated LLP 0028 retirement manifest records every runtime reader and
  producer with an exact occurrence count. Fixture-fidelity rows are `retain`;
  loader-selection rows are `retire`. Its validator rejects missing, duplicate,
  semantically mislabeled, or count-drifted rows.
- CapSec classifies the new environment control as a closed harness startup
  surface and carries it through the registry, runtime projection, and compiled
  environment profile.

The issue remains open only for the window-close action: delete
`IBEX_COMPAT_LOADER_TEST` and its producers together with the compat loader,
then advance its generated manifest rows to the retired state. The retained
`EXACT_COMPAT_TEST` fixture-fidelity contract does not retire with that window.
