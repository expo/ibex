# Hermes artifact cache workflow red on every run: credential guard trips despite persist-credentials: false

**Status:** Closed
**Resolution:** 2026-08-05
**Severity:** P2
**Systems:** CI, Build, Hermes
**Author:** Claude Fable 5 (Claude Code), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** `.github/workflows/hermes-artifacts.yml` (identity boundary guards)

Every "Hermes artifact cache" run on main has failed since at least
2026-07-28 02:52Z at the "Resolve artifact identity" job's read-only
identity boundary:

```
::error::checkout left a persisted Git credential
```

The guard is `git config --local --get-regexp
'^(http\..*\.extraheader|credential\.)'` finding a match even though the
checkout step is SHA-pinned actions/checkout v4.3.1 with
`persist-credentials: false` — that pairing worked before, so the likely
suspect is a runner-image (`ubuntu-latest`) rollover changing what the
default git config contains, or checkout's cleanup no longer removing the
`http.<url>.extraheader` it writes.

This is a fail-closed guard doing its job; do NOT weaken it to green the
badge. Diagnose first: temporarily add
`git config --local --get-regexp '^(http\..*\.extraheader|credential\.)' || true`
with output above the guard (prints which key and value class tripped),
then either fix the checkout configuration or, if the runner image now
pre-seeds an innocuous key, tighten the regexp to the actual threat shape
with a comment recording the image change.

Done when the workflow is green on main again with the guard's intent
(no ambient credential reaches the build/publish steps) intact and
re-affirmed in the workflow comments.

## Resolution

The identity boundary was repaired without weakening the credential guard.
Recent `Hermes artifact cache` runs on `main`, including the completed run for
`62e5214a`, pass while retaining the read-only build/publish boundary. The
original every-run failure is no longer present.
