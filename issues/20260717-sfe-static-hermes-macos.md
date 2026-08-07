# Static Hermes for the macOS stub (lean vs full by measurement)

**Status:** Open — blocked on the accepted performance budget and measurement
**Impact:** 4
**Urgency:** 3
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Static Hermes for the macOS stub (lean vs full by measurement)” shows the issue materially affects a supported product or engineering path; it belongs in the current program but is not an immediate blocker, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
**Severity:** P2
**Systems:** Engine, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2a/§7 phase 1, LLP 0001, LLP 0005

(Historical framing — now stale: macOS honors `HERMES_LINK_STATIC`
since the Progress work below; `build.rs` links `macos-static/*.a`
fail-closed.) Produce a static
macOS Hermes archive for the stub, measuring lean vs full variants
between eligible builds (equivalently pinned, patched,
capsec-conformant) — the variant decision is register item 6 (author
ratifies the measurement).

**Done when:** stub links statically on `aarch64-apple-darwin`
(`otool -L` shows system libraries only, CI-checked); measured sizes
recorded; variant decision ratified.

## Progress — 2026-07-17

The macOS build now installs and fail-closed links a catalogable static bundle
(`hermesvm*_a`, JSI, Boost.Context). A release `ibex-compiled-stub` links with
system libraries only. Full measured 39,824,848 bytes; lean measured
37,953,760 bytes (4.7% smaller). Lean is not yet an eligible release variant:
the current host bootstrap and diagnostic factory carrier still evaluate
source and the lean VM correctly refuses them. HBC-only bootstrap/carrier
execution and author ratification remain before selecting the variant.

## Remaining (verified 2026-07-31)

- No CI check exists for the static link claim: no macOS job builds a
  static stub, there is no `otool -L` invocation anywhere in the repo,
  and the only dependency-surface audit is the Linux one
  (`scripts/audit-sfe-linux-deps.sh`). `scripts/test-sfe-phase0.sh` is
  not wired into any workflow.
- Measured sizes exist only in this ticket's prose; no measurement
  artifact or gate records them.
- Register item 6 (lean vs full) remains unratified in LLP 0029 §7.

## LLP 0047 reconciliation — 2026-08-01

The static full stub and exact compiler become provisional milestone-1 catalog
artifacts, then rotate with `StubContractV2` at milestone 2. Static dependency
and signed-image evidence remains a milestone-5 release requirement; CapSec
advertisement is no longer a prerequisite for selecting or cataloging the
ambient-capable artifact.

## Implementation checkpoint — 2026-08-01

The full static variant is now the exercised V2 catalog artifact. A 49 MB
arm64 Mach-O linked no Hermes dylib, survived the required inject-then-sign
sequence with a valid ad-hoc signature, and ran genuine HBC after relocation.
The ticket remains open for a checked-in dependency-audit receipt/gate,
precommitted size budget, and explicit lean/full register ratification.

## Implementation checkpoint — 2026-08-02

The checked-in full release-kit gate now audits the assembled final Mach-O,
not merely the pre-envelope stub: `otool -L` must name only Apple system
libraries and `otool -l` must expose no runtime search path. A fresh
current-source catalog artifact passed that gate with genuine relocated HBC.
The ticket remains open only for the precommitted size budget, a current
measurement against it, and explicit lean/full register ratification.

## Maintenance reconciliation — 2026-08-05

The full static artifact is the implemented and physically reproduced release
shape. This ticket now shares its only remaining gate with
`20260717-sfe-measured-budgets.md`: accept the numeric budget, measure the
current full artifact, and record the result. Any future lean artifact is an
optimization candidate rather than an unrecorded prerequisite for the
implemented full-static release shape.
