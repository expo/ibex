# Windows noncap builtin public batch exhausted its common deadline

**Status:** Closed
**Severity:** P2
**Systems:** CapSec, CI, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0032 §Deadline policy; PR #25

The exact-head PR #25 Windows full-matrix job completed 1,280 of 1,290
non-capability builtin probes without an assertion failure, then crossed the
common 300-second public-fixture deadline. The supervisor terminated the
attempt at 330.133 seconds after the authored 30-second cleanup grace and
correctly classified it as a timeout.

## Resolution

Timeout policy version 5 admits exact dynamic-command deadline overrides and
charges them in critical-path accounting. The exact Windows noncap builtin
batch receives 420 seconds; unrelated public batches retain 300 seconds. The
observed Windows setup took under 18 minutes, so its conservative setup reserve
narrows from 60 to 58 minutes. The authenticated worst-case Windows path
therefore remains 374 minutes under the unchanged 375-minute outer containment
bound.
