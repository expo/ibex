# Expose the inherited host environment through process.env in insecure mode

**Status:** Open
**Severity:** P2
**Systems:** Runtime, Node Compatibility, Security, Embedded API
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0025 §2; LLP 0038 “Fully open mode (insecure)”; LLP 0039; ENG-22976; ENG-23115

## Problem

The `insecure` Cargo feature is intended to provide a no-sandbox development
mode with the ambient authority of the invoking user, close to Ibex's
pre-CapSec behavior. Filesystem access, process spawning, and networking are
open in this mode, but `process.env` remains empty because the runtime never
projects the inherited host environment into JavaScript.

That exception is surprising, breaks ordinary Node-compatible programs and
developer tooling, and makes insecure mode less useful as the compatibility
path while secure mode and target advertisement are still under construction.
LLP 0038 currently documents the empty environment as intentional in every
mode; that decision should change for `insecure` only.

## Required behavior

- A default/insecure CLI build exposes the process environment inherited at
  Ibex startup through `process.env`.
- Enumeration, direct reads, assignment, deletion, string coercion, and
  platform name semantics match Node closely enough for existing compatibility
  tests; Windows names remain case-insensitive.
- Child-process default inheritance and explicit `env` overlays observe the
  JavaScript-visible insecure environment consistently.
- REPL, `eval`, `run`, and package-script routes receive the same projection.
- Define and test the embedded-runtime contract. If an embedder must supply the
  initial environment explicitly, make that API clear; do not silently give
  secure embedded runtimes ambient host access.
- The red insecure-build banner remains. Making `process.env` useful does not
  weaken the warning that this mode has the invoking user's ambient authority.

## Security boundary

This must be gated by the compile-time `insecure` feature. Secure builds,
including `unadvertised-dev-arming`, must retain their authenticated empty base
plus explicitly authorized principal overlays and must not acquire an ambient
fallback. Add a negative regression proving a host-only sentinel is absent in
secure mode.

Update the runtime environment inventory, compiled environment profile,
generated artifacts, and LLP 0038/0039 language in the same change. Preserve
the environment-name and process-global mutation invariants owned by LLP 0025.

## Done when

- In insecure mode, an inherited sentinel is readable and enumerable through
  `process.env` on macOS/Linux and Windows.
- Assignment/deletion and subprocess inheritance have Node-compatible
  regression coverage.
- Secure CLI and embedded tests prove the same sentinel cannot leak without an
  explicit authorized projection.
- All environment-inventory, generated-drift, Node-compatibility, and secure
  mode checks pass.

