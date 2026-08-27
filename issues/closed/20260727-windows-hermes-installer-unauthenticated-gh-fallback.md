# Make the Windows Hermes installer survive unauthenticated GitHub CLI

**Status:** Closed
**Resolution:** Resolved
**Severity:** P2
**Systems:** Build, Windows, Hermes
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0021

`scripts/install-windows-hermes.ps1` is intended to try the reviewed GitHub
artifact and then fall back to HTTPS or an exact source build. With
`$ErrorActionPreference = "Stop"`, however, an installed but unauthenticated
`gh` makes `gh auth status 2>$null` surface as a terminating
`NativeCommandError`. The installer exits before reaching either fallback.

This was reproduced on the Windows NucBox while rebuilding the
`e639a7bad8bfca844d982afa54fac786c65a8856` reviewed Hermes source pin. Passing
`-Source` produced and attested the exact debugger-disabled bundle, so the
CapSec replay was not weakened or blocked.

Done when:

- an unauthenticated or otherwise unusable `gh` is treated as an unavailable
  artifact transport rather than a fatal installer error;
- authenticated GitHub artifact selection remains digest- and
  provenance-checked;
- HTTPS and `-Source` fallback tests cover the unauthenticated-CLI case; and
- changing the installer authority is accompanied by the expected Hermes
  artifact/provenance regeneration.

## Resolution (2026-07-31)

Fixed on `fix/ticket-sweep-20260730`.

The installer now routes every GitHub CLI availability decision through a
`Test-GitHubCliUsable` probe that (a) treats a missing binary as an
unavailable transport, and (b) relaxes `$ErrorActionPreference` to
`Continue` around `gh auth status` so Windows PowerShell 5's
redirected-native-stderr → terminating `NativeCommandError` conversion can
never fire before the exit code is inspected. Any thrown probe failure is
also treated as "unusable". Both call sites (provenance verification and
release download) use the probe; an unusable `gh` falls through to the
HTTPS download and then the `-Source` build exactly as intended.

Security posture unchanged: `Test-ReviewedBuildProvenance` still refuses
any prebuilt bundle without an authenticated `gh` attestation verification
(`--deny-self-hosted-runners`, pinned repo/workflow/ref), and checksum +
reviewed-profile validation of the archive is untouched.

Tests: `scripts/install-windows-hermes.test.mjs` (node --test, standalone
like the sibling generator test) probes the extracted helper under
`$ErrorActionPreference = "Stop"` with fake `gh` shims — unauthenticated
(stderr + exit 1) → unusable without terminating; authenticated → usable;
missing → unusable — and guards that no bare stderr-redirected
`gh auth status` probe returns to the installer source. Limitation noted
honestly: the probes run under the host PowerShell (pwsh 7 on macOS/CI);
the 5.1 terminating-error conversion itself was reproduced on the NucBox in
the original report and is sidestepped by construction.

Authority regeneration: the installer is a reviewed authority file, so its
content digest is pinned. Restamped `sourceInstallerAuthorityDigest` in
`REVIEWED_HERMES_EVALUATOR_PROFILES` (capsec-surface-inventory.mjs),
restamped `REVIEWED_HERMES_EVALUATOR_REVIEW_ID` (capsec-coverage-model.mjs)
to the recomputed live id, and reran the full regen chain (`check:drift`
green). The prebuilt asset key embeds the installer git blob, so the
`hermes-artifacts.yml` workflow publishes the new asset name on landing;
existing installed artifacts self-invalidate against the new receipt
expectations and reinstall/rebuild on next run (by design, fail-closed).

### Addendum (2026-07-31, pre-merge review)

The adversarial review found two remaining bare `gh` invocations
(`gh release download`, `gh attestation verify`) that could still terminate
the installer under stream-capturing PowerShell 5.1 hosts (ISE/remoting)
before the fallbacks ran. Both now route through `Invoke-GitHubCliQuietly`
(same relaxed-preference shape as the probe, success by exit code alone);
the test file's guard additionally refuses any bare top-level
`gh release`/`gh attestation` statement. The installer digest moved again,
so `sourceInstallerAuthorityDigest`, the evaluator review id, and the
inherited-intrinsic-alias profile/source-review digests were restamped a
second time with the full chain green.
