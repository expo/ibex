# Native invocation-time module activation

**Status:** Open
**Severity:** P1
**Systems:** Module Loader, Engine, Runtime, CapSec
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0021, LLP 0024 §3, LLP 0026 §4 and §6, `issues/20260717-oxc-candidate-runtime.md`

Implement the private native capability that makes authored `import()` and
CommonJS `require()` true call-time graph operations in authenticated
production execution.

The existing site-specific Hermes tables prove exact selection once a target
record exists. They do not satisfy the security contract because current graph
construction represents every record with a complete artifact and therefore
must resolve, read, transform, compile, and link dynamic targets eagerly.
Normal module-runner FFI also rejects reentrant runtime drives, so a Hermes host
callback cannot safely call the existing outer-drive APIs.

Until this issue closes, authenticated source-graph construction refuses an
authored call-time edge before resolving or acquiring its target, and every
production native linker repeats the refusal. Generated manifest-builtin
fan-out is the only synchronous `require()` exception.

## Required design

1. Add a deferred authenticated edge/candidate representation containing only
   facts available without target source discovery. It must not require a
   `ModuleArtifact` for the target.
2. Give Hermes an opaque, nonce- and generation-bound activation handle owned
   by the live Rust graph drive. JavaScript receives only `import()`/`require()`
   behavior, never the resolver or loader capability.
3. Add a dedicated in-drive callback path. It must authenticate requester,
   exact site/spelling/attributes, current graph and snapshot generations, and
   owner-thread state before Rust resolution.
4. Authorize the exact edge first, then perform receipt-bound trusted source
   acquisition, recursively build only the target's static closure, compile or
   load its carrier, link, instantiate, declare, and finally evaluate it.
5. Publish the new records atomically into the generation cache. Denial,
   resolution failure, acquisition failure, transform failure, and link
   failure must leave no partial cache entry or reusable authority.
6. Preserve one stable namespace and one internal evaluation promise per
   record while returning a fresh public promise per `import()` invocation.
7. Define the prepared-carrier form without reading a cache index or carrier
   before invocation. Candidate spelling misses must reject without resolver,
   filesystem, or prepared-cache probes.
8. Cover literal/computed ESM import, authored CJS require, source/prepared
   execution, denial/no-probe, dead branches, generation teardown, cycles,
   TLA, repeated/concurrent calls, wrong requester/site, and reentrancy.

## Done when

LLP 0026 §6 holds end to end in authenticated production execution, the two
fail-closed guards can be replaced by activation-capability validation, and
the security corpus proves dead branches cause no target discovery while
reached allowed branches acquire and evaluate exactly once.
