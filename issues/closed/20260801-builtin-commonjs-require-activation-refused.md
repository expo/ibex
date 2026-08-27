# `require('net')` (and almost every builtin) refused at activation

**Status:** Closed
**Resolution:** fixed
**Severity:** P1 (the whole CommonJS builtin surface was unreachable)
**Systems:** Module loader, Builtins
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0004 (builtin module surface), LLP 0026 (native module graphs),
LLP 0021 (module initialization / trusted source acquisition)

## Symptom

```
$ ./target/debug/ibex run t_net.js          # var net = require('net');
error: uncaught file-program exception: CommonJS require activation refused:
activated builtin Builtin { domain: "ibex-runtime", source_key: "node_buffer" }
requested non-manifest dependency "bun"
```

Peeling that back exposed two more layers. In total `require` of `net`,
`dgram`, `http`, `events`, `util`, `assert`, `stream`, `dns`, `fs`, and
`buffer` all failed; only leaf builtins with an empty require closure
(`path`, and `os`/`string_decoder` up to a separate bug, below) loaded.

## Root cause

A builtin's CommonJS require edges are checked **statically**, at activation,
against the builtin manifest — not dynamically when the call executes.
`src/module_loader/runner_pipeline.rs` collects `artifact_edge_requests()`
(the artifact's `static_edges`) and resolves every `CommonJsRequire` edge
through `Host::resolve_manifest_builtin_internal`. A `require("x")` literal
inside a `try`/`catch` is still a declared static edge, so the try/catch never
runs: the refusal happens before any of the module's code is evaluated, and it
propagates to every module that transitively requires it.

Three independent defects, each of that shape:

1. **`src/builtins/buffer.js`** — `BufferProto.inspect` had a guarded
   `require("bun")` fallback. `bun` is not a manifest specifier (`bun:sqlite`
   and `bun:fs` are; bare `bun` is not), so activating `node_buffer` was
   refused. `net → dns → buffer` made this the first wall for `require('net')`.

2. **`src/module_loader/graph.rs`, `authorize_reachable_operations`** — the
   CapSec authorization loop demanded a graph target for *every*
   `CommonJsRequire` static edge of a builtin, without the
   bootstrap-internal exemption its two sibling validators
   (`validate_call_time_activation_support` and `commonjs_require_bindings`)
   already apply. Bootstrap-internal specifiers are served by the shared
   runtime's bootstrap module cache and deliberately get no binding at
   activation, so linkage failed with
   `ERR_MODULE_LINK: CommonJsRequire edge "internal/fs/utils" has no
   authenticated target`. `fs.js` names `internal/fs/utils`, and
   `assert → fs` puts `fs` in the closure of nearly every builtin, so this
   single edge broke essentially the entire CommonJS builtin surface.

3. **`src/builtins/http.js`** — `require('internal/streams/state')` (an
   optional probe for `getDefaultHighWaterMark`). That specifier is neither a
   manifest builtin nor in `BOOTSTRAP_INTERNAL_MODULE_SPECIFIERS`, so
   `node_http` was refused for the same reason as (1).

## Resolution

Fixed at the callsites and at the authorization loop; **the manifest was not
widened**. The manifest is an authority boundary, and none of the three
defects needed a new specifier to be admitted:

- `src/builtins/buffer.js` — deleted the `require("bun")` branch. It was dead
  code in Ibex: `bun` can never resolve here, and the line above already
  probes the `Bun.inspect` global, which covers every environment where a Bun
  inspector is actually reachable. Comment + `@ref LLP 0004` added so the
  branch is not reintroduced.
- `src/module_loader/graph.rs` — `authorize_reachable_operations` now skips
  bootstrap-internal CommonJS require edges, matching the two sibling
  validators. No authority is skipped: those specifiers have no graph record
  to acquire, so there is no operation to authorize.
- `src/builtins/http.js` — replaced the `internal/streams/state` probe with
  the already-required public `node:stream` module, which re-exports
  `getDefaultHighWaterMark`. Same fallback behaviour, no new manifest edge.

Regen chain run: `bun run build:builtins` (into a scratch out-dir, then only
the two changed files copied in, so a concurrently-edited `http.js` was not
clobbered) then `bun run generate:vendored-fingerprint`.
`bun run generate:modules --check` and
`bun run generate:vendored-fingerprint --check` are clean.

## Verification

Built with `cargo build --bin ibex --features standard,unadvertised-dev-arming`
(2m52s cold, ~30s incremental).

```
=== t_net ===   net ok object
=== t_dgram === dgram ok object
=== t_http ===  http ok object
```

`cargo test --lib module_loader` → 231 passed, 0 failed.
`cargo test --lib graph` → 31 passed, 0 failed.
`./ref-check` → ok, 0 errors.

## Follow-up filed separately

`require('buffer')` now gets past activation but fails at evaluation with
`Cannot assign to read-only property 'toString'` — an unrelated lockdown
override-mistake bug that also hits `os` and `string_decoder`. Tracked in
`issues/closed/20260801-lockdown-tostring-override-blocks-builtins.md`.
