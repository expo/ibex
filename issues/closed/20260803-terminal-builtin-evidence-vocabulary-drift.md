# Terminal-builtin evidence validator omitted two reviewed families

**Status:** Closed
**Severity:** P1
**Systems:** CapSec, CI, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0021 §WP7; PR #25

The exact-head PR #25 macOS full-matrix job physically passed the closed
`node:diagnostics_channel` import fixture, then the independent JavaScript
evidence validator rejected its authenticated source descriptor. Production,
recipe authoring, and the Rust loaded-engine executor each carried the complete
seven-family terminal-builtin vocabulary, but the evidence validator repeated
only five and omitted `node_diagnostics_channel` and `node_domain`.

## Resolution

The validator now repeats both omitted source families with their exact public
aliases and terminal roots. A focused regression constructs root-module
closure evidence for all seven reviewed terminal builtin families, preventing
another partial vocabulary from passing the local test suite.
