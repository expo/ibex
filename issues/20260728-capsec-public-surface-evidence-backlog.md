# Complete the residual CapSec public-surface evidence catalog

**Status:** Open
**Severity:** P2
**Systems:** Security, Conformance, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-28
**Related:** LLP 0021; issues/20260717-sfe-capsec-advertisement.md

## Problem

The security-critical CapSec rev2 implementation is complete, but neither
candidate target has a complete public-surface conformance catalog. The final
bounded catalogs at revision 2 acceptance are:

- Apple
  `sha256-GHlqGTU7b020Cp107EbGh4TShEtB_kOoRz5R1pDtYEo`: 23,598 required,
  3,928 fully executable, 3,042 internally verified, 16,628 unresolved.
- Windows
  `sha256-FAud-eHXcShfXTx3wsnucQFaQ96H2khcNzhxUqxbwzU`: 23,257 required,
  3,564 fully executable, 3,028 internally verified, 16,665 unresolved.

Advertisements correctly remain empty. These residual rows are conformance
and evidence uncertainty, not proof of a runtime bypass and not permission to
claim either target. This ticket is deliberately separate from the completed
security-implementation tranche so catalog work converges through prioritized,
reviewable batches rather than open-ended discovery.

## Priority and scope

P2. Prefer rows that are target-applicable, source-inventoried, and close a
release-relevant claim. Evidence-quality improvements and speculative
hardening stay behind those rows unless a concrete exploitable flaw is found.
Do not promote labels, generic failed imports, or one target's evidence as
another target's proof.

**Sequencing (2026-07-29, LLP 0029 §7 register item 4):** v1 ships
fail-closed with empty advertisements; this backlog now converges toward a
**single-tuple v1.1 advertisement** (leading candidate on current
verified-row volume: `aarch64-apple-darwin`). Prioritize that tuple's
target-applicable rows until its report passes complete; the other
candidate target's catalog completion follows in a later milestone rather
than being worked in parallel.

## Done when

- each shipped target's required public-surface rows have source-bound physical
  receipts or an explicit non-applicable/unsupported disposition;
- the full generated and physical validation gates pass on the exact engine
  artifacts named by the reports;
- target advertisements are generated only from complete passing reports; and
- remaining unsupported product surfaces are stated as release constraints,
  not hidden by aggregate coverage counts.
