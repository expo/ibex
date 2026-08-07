# noncap readline call validator rejects data reads

**Status:** Closed
**Severity:** P3
**Systems:** CapSec, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0021 §WP10; PR #25

After the deprecated root `node:fs` accessors were made residual, a fresh
physical Windows-catalog replay reached the next public builtin fixture and
rejected the inert `node:readline.promises` data read as `contract-mismatch`.

The loaded-engine validator for three reviewed pure compatibility calls
(`exact_crypto.createPrivateKey`, `exact_crypto.createPublicKey`, and
`node_readline.CSI`) also retained the two separately reviewed readline
Interface lifecycle calls. Its default branch rejected every other
`node_readline` export, including non-callable data reads that do not belong to
that call family.

## Resolution

The validator now lets non-callable `builtin-export-read` recipes bypass the
call-only vocabulary. Exact reviewed calls still receive their full contract,
unreviewed readline calls remain rejected, and a callable disguised as a read
still returns `contract-mismatch`. A regression executes the exact
`node:readline.promises` fixture through the loaded-engine JavaScript harness
and retains the negative callable-as-read case.
