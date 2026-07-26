# Windows `__exactFsOpen` write-denial public evidence mismatch

Status: Open

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
