# Public evidence conflated process-local runtime nonce namespaces

**Status:** Closed
**Severity:** P1
**Systems:** CapSec, CI, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0021 §WP7; PR #25

The exact-head PR #25 Windows full-matrix job completed all 3,560 public
fixtures, then aggregate validation rejected thirteen runtime nonce values as
replays. Every collision paired one authenticated builtin first-load receipt
from the builtin harness with one loader source-point receipt from the loader
harness. Both harness processes allocate runtime nonces from their own
monotonic counters beginning at one, and neither family reused a nonce
internally.

## Resolution

The aggregate validator now applies LLP 0021's pairwise-distinct runtime nonce
requirement to the authenticated builtin first-load evidence schema that the
requirement governs. Loader source-point receipts remain independently
descriptor-bound and validated, but their process-local nonce namespace is no
longer compared with the builtin harness namespace. The existing replay test
continues to reject duplicate nonces within the builtin family, and a focused
regression records that a loader source-point nonce is outside that comparison.
