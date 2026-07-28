# Make the Windows Hermes installer survive unauthenticated GitHub CLI

**Status:** Open
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
