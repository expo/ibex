# Windows `__exactFsOpen` write-denial public evidence mismatch

**Status:** Resolved

The physical `x86_64-pc-windows-msvc` native public primary shard fails on:

`enforcement.src.engine.hermes.runtime.fs.windows.cc.exactfsopen.0ne1lzx.logical.write.deny`

The recipe expects the denial observation to contain `fs:list`, but the
installed Windows implementation reports `fs:write`. This row predates the
typed Windows TCP work and appears before its rows in the complete primary
shard. A focused source- and digest-bound TCP catalog passes all eight connect
and lifecycle rows, so this mismatch is not a blocker for that implementation
checkpoint; it does block claiming a complete Windows native public shard.

## Done when

- Reconcile the Windows append-open denial contract with the generated recipe:
  either make the implementation emit the authored stage/action or correct the
  recipe to match the governing LLP without weakening denial-before-mutation.
- Add a focused regression for the denied write-open branch.
- Pass both exact-target recipe generation and the complete physical Windows
  native primary shard under `IBEX_FAIL_ON_STALE_VENDORED=1`.

## Resolution

The implementation was correct. LLP 0021 requires an append-capable open to
submit `fs:write` at Requested before lookup; the generic recipe expectation
had incorrectly reused the read-open `fs:list` action on Windows. Recipe
generation now selects `fs:write` only for the Windows write-denial branch and
retains `fs:list` for read denial.

The regression suite asserts both target-specific expectations and passes 94
tests with 110,844 assertions. A focused physical Windows denial fixture passed,
then both full production native shards passed under
`IBEX_FAIL_ON_STALE_VENDORED=1` (255 primary rows and 244 secondary rows).

The complete run also exposed two evidence-harness overclaims that were fixed
in the same checkpoint: Windows no longer executes private native module-runner
lifecycle ABIs while LLP 0026 keeps that target compatibility-only, and
target-absence/retained-descriptor rows no longer inherit POSIX open edges or
attempt cleanup without an owned setup descriptor.
