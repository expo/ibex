# Static Hermes for the macOS stub (lean vs full by measurement)

**Status:** Open
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

macOS links `hermesvm.framework` dynamically via a checkout rpath;
`HERMES_LINK_STATIC` exists only on the Linux branch. Produce a static
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
