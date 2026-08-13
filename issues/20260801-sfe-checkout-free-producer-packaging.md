# Package the SFE producer for checkout-free use

**Status:** Open — publication receipt remains
**Impact:** 4
**Urgency:** 3
**Ease:** 2
**Confidence:** 5
**Severity:** P2
**Systems:** Build, Distribution, Policy Tooling
**Author:** Codex
**Date:** 2026-08-01
**Related:** LLP 0047 §8; issues/20260717-sfe-program.md

The target-specific release kit now contains the catalog-pinned `ibex`, pinned
catalog installer, addressed catalog archive, and a target-bound,
content-addressed policy-authoring tree. That closed inventory contains the
exact Bun runner, policy JavaScript, CapSec inputs, lockfile, and installed
package closure. Release `ibex policy generate` admits only the adjacent digest
compiled into the binary, re-admits it after execution, and never falls back to
an Ibex checkout or ambient JavaScript runner.

The macOS arm64 and Linux x86-64 kit gates pass policy generation with an empty
environment, Bun/Node absent from `PATH`, and a poisoned `IBEX_REPO_ROOT`; a
copy of `ibex` without its toolchain refuses with `SFP002`. The generated
applications then run after source and catalog withdrawal. This closes the
checkout-dependency defect, but not the full clean-recipient distribution
receipt below.

## Checkpoint

- Complete: authenticated checkout-free policy authoring is included in both
  host-target release kits.
- Complete: the guide and kit inventory distinguish producer dependencies
  from the zero-sidecar executable.
- Complete on the official Linux baseline: an isolated installation authored
  policy and compiled a two-module TypeScript Fetch program on Ubuntu 22.04,
  then was removed before the application was transferred alone to a fresh
  compatible recipient root. With no source, catalog, Ibex, Hermes, or cache,
  that executable ran under `env -i`, fetched `sfe-network-ok`, and exited 0.
- Complete: two independent physical Ubuntu 22.04 builders produced identical
  catalog, contract, policy-toolchain, and unsigned application identities
  under the strict comparator.
- Remaining: publish the exact installation artifacts and repeat the clean
  install-to-recipient receipt beginning from that publication.

## Regression — 2026-08-13

A current-source macOS kit at `de3eb770b` failed `check-sfe-release-kit.sh`
on the first `ibex policy generate`: packaged `loadAndValidateContract`
called `readArtifactSourceFoundationDocuments`, which requires Git. That
path is checkout-only. Packaged authoring now reads the same foundation
documents from the digest-admitted toolchain tree.

The official reproducibility receipt uses catalog
`sha256-NP7lppy-B3NLsTpcSkxDR7DOftNnRXJuMhX8rtAJP8g`, contract
`sha256-mWVeON5BnOGOf3pg8dwJvZDT4SPowvrdRVY8MGmwikk`, policy toolchain
`sha256-k1Cl38UC8hitDPkVmoK41cwajN16_PAqrDFGvF50U7A`, and unsigned application
identity `sha256-yqiXHdcRQswCj7-G1o-SVszZnes57FLotKmASt_4504`. The strict
comparison report is retained at
`/tmp/ibex-sfe-linux-repro-report-carrier-final-20260802/x86_64-unknown-linux-gnu.json`
on the evidence host.

## Done when

- The supported release installation includes an authenticated policy-authoring
  toolchain without requiring an Ibex source checkout or `IBEX_REPO_ROOT`.
- A clean-machine gate starts from only the published installation artifacts,
  authors the mandatory compiled policy, installs the pinned catalog, compiles
  a short multi-module TypeScript program, and removes the installation.
- The copied application then runs on a second compatible clean machine with
  no Ibex/Hermes installation, catalog, or source tree.
- The release guide and kit inventory name every producer-time dependency and
  distinguish it from the zero-sidecar runtime contract.
