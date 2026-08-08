# Execute reset-revision artifact-source ceremonies end to end

**Status:** Open
**Severity:** P1
**Systems:** CI, Release, Portable Engine, CapSec
**Author:** Codex
**Date:** 2026-08-07
**Related:** LLP 0021 §A8 F6h-b, §A9 M33; independent Phase 1 implementation review MATERIAL M-5

F6h-b currently pins the two artifact-source ceremony exclusions by source
inspection. That proves the product-release gate is absent, but not the
load-bearing anti-circularity property: at the reset revision, where the
checked admission is diagnostic (`authorized: false`), every ceremony output
needed by promotion n+1 must still succeed.

A local unit test cannot execute that property honestly. The Hermes artifact
cache workflow spans GitHub-hosted macOS, Linux, and Windows jobs and publishes
revision-scoped prerelease assets and attestations. The physical-promotion
workflow requires those immutable GitHub Release asset IDs, their Sigstore
bundles, signed workflow-run metadata, a GitHub-hosted macOS runner, and the
actual reset commit as source A. Mocking those dependencies would test a model
of the workflows, not whether their real outputs remain producible.

## Required retained run

At the next real M27 reset revision:

1. Run `.github/workflows/hermes-artifacts.yml` for the reset SHA and retain
   the successful job/run URLs plus the complete revision-scoped asset set and
   attestations.
2. Dispatch `.github/workflows/portable-engine-physical-promotion.yml` at the
   same reset SHA and retain its successful diagnostic/candidate outputs.
3. Verify the build-carried checked admission used by the product gate is the
   reset revision's digest-valid `authorized: false` record.
4. In the same retained evidence, run the shared product-release gate against
   that record and retain its refusal. This proves the two ceremonies remain
   runnable while product publication does not.
5. Record exact SHAs, run attempts, immutable asset IDs/digests, command
   outputs, and links in the Phase 3 ceremony evidence.

**Done when:** one retained real reset-revision run demonstrates both complete
artifact-source ceremony outputs succeed and the product-release gate refuses
the same revision. Until then F6h-b is credited only as a static smoke check,
not as proof of anti-circularity.
