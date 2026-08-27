# Native invocation-time module activation

**Status:** Closed
**Resolution:** Resolved
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

Authenticated source graphs now implement asynchronous `import()`, literal
synchronous CommonJS `require()`, and invocation-time prepared-carrier
selection without eager target or activation-cache discovery.

## Required design

1. Add a deferred authenticated edge/candidate representation containing only
   facts available without target source discovery. It must not require a
   `ModuleArtifact` for the target.
2. Give Hermes an opaque, nonce- and generation-bound activation handle owned
   by the live Rust graph drive. JavaScript receives only `import()`/`require()`
   behavior, never the resolver or loader capability.
3. For `import()`, use a typed reached-site mailbox drained only after the
   current JSI drive unwinds. For synchronous CommonJS `require()`, add the
   narrower dedicated in-drive callback that its return-value semantics
   require. Both paths must authenticate requester, exact
   site/spelling/attributes, current graph and snapshot generations, and
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

## Progress

The safe `import()` activation path is wired end to end in authenticated
production execution:

- Hermes can register exact deferred literal and computed-site spellings on
  both ESM and CommonJS records. Only an invocation of an exact registered
  spelling mints a fresh Promise and a nonce-, requester-, and
  generation-bound native request; dead branches and absent computed
  candidates never enter the mailbox.
- Rust takes typed, length-bearing requests only after the active JSI drive
  unwinds, then completes or refuses each request exactly once. Successful
  concurrent requests for one spelling adopt the target's stable internal
  evaluation Promise and cache the same target binding.
- The synchronous graph algebra has an explicit deferred mode that validates
  the artifact's complete static closure without requiring any dynamic target
  record. Its authenticated native linker authorizes only reachable static
  operations and installs the exact deferred declarations before evaluation.
- Real-Hermes regressions cover ESM literal/computed exactness, dead branches,
  wrong-generation reads, fresh concurrent public Promises, one-shot
  completion/refusal, an authenticated graph with no target record, and the
  CommonJS `import()` mailbox.
- Production source graphs retain exact literal attributes and computed
  declarations without resolving targets. A reached request first authorizes
  its exact edge, then receipt-gates acquisition of only the target's static
  closure and validates the expanded graph before publication.
- The native graph reuses existing record identities, links and declares every
  new record, then atomically publishes the batch. Unpublished partial batches
  are explicitly discarded even while the generation is pinned.
- Synchronous and TLA graphs both resume through incremental target
  publication. Prepared initial records can coexist with an inline activated
  target without a pre-invocation carrier/index read.
- Foreground settlement retains the authenticated source graph plus an opaque
  native handle index. Normal quiescence, ready-only, and `--keep-alive` pumps
  drain late requests; exact requester handles prevent cross-routing between
  equal `SourceId`s in separate native graph incarnations.
- End-to-end regressions cover delayed ESM and CommonJS `import()` after
  ordinary program quiescence, plus dead-target no-discovery and exact
  receipt-gated target closure growth.
- Production ingress also covers a delayed TLA target that reaches a second
  import, a reached resolution failure that rejects only its public Promise,
  and atomic publication/evaluation of a newly discovered static cycle.
- A production computed-site manifest retains every declared spelling without
  adding a target to the initial graph, then acquires and evaluates only the
  exact candidate selected at runtime. The unchosen candidate is never read or
  evaluated.
- A separately bound package with its authenticated `dynamic-import` edge
  removed is refused at the reached site. The refusal becomes only a rejected
  public `import()` Promise, leaves keep-alive healthy, and never evaluates the
  otherwise resolvable package body.
- Generation teardown removes pending requests and every record in the
  generation. Completion-before-unpin is one-shot; unpin-before-completion
  makes both a late success and a late refusal stale.
- Source graph algebra and authenticated construction now defer authored
  non-builtin literal `require()` spellings without target discovery.
  Reaching an exact spelling authorizes and receipt-gates only its target
  closure; nested dead requires remain deferred.
- The native synchronous boundary now has a generation-scoped provider token.
  Its callback carries the exact requester handle, source identity, and
  spelling. Only module mutation/publication may nest while it runs; a
  real-Hermes regression proves target publication and single evaluation while
  general eval remains reentrancy-refused.
- Retained production graph state installs that provider before initial
  evaluation and mutates the same published native index. End-to-end tests
  cover CommonJS targets, synchronous ESM static closures, builtin/VFS use, and
  prepublication `ERR_REQUIRE_ASYNC_MODULE` refusal.
- Failed synchronous and asynchronous activations roll the source graph back
  to its pre-request record, principal, candidate, and receipt checkpoint;
  native staging remains atomic and no failed require binding is cached.
- Generated builtin bodies use a distinct manifest-derived private edge for
  bootstrap-owned objects such as `internal/test/binding`. Native startup
  captures and seals the bootstrap resolver; authored modules still enter
  ordinary resolution and cannot borrow it.
- The production source-path matrix now covers repeated resolution failure
  followed by a successful activation, package-policy denial without target
  evaluation, CommonJS partial-export cycles, and a CJS→ESM→CJS cycle that
  reports `ERR_REQUIRE_CYCLE_MODULE` and then recovers when authored code
  catches it.
- Synchronous ESM execution now publishes `evaluating` before calling authored
  code, and its dependency walk recognizes CommonJS adapter records. A new CJS
  dependency is evaluated through its owning CommonJS record; re-entry through
  an adapter whose owner is already evaluating fails with the stable cycle
  error instead of recursively executing a merely-declared record.
- A prepared initial CommonJS carrier can activate and publish a fresh inline
  target at the reached `require()` site. Selecting the prepared entry still
  leaves the target undiscovered before invocation.
- Owner-thread runtime shutdown clears every retained provider registration
  while the native runtime is live and serialized. The provider unit test also
  proves that dropping a token removes its native generation entry by
  reinstalling the same generation before unpinning it.
- Invocation-time prepared records have no cache index. Each newly
  receipt-acquired `(SourceId, semantic digest)` derives a deterministic
  one-record carrier path beneath a selected deployment cache. An opaque
  runtime locator is invoked only after the exact reached edge has authorized
  and acquired its source closure.
- Every prepared member derives `PreparedCarrierRead` from its own retained
  source-acquisition receipt. A closure is changed from inline to prepared only
  after every member validates; a miss, wrong receipt, or malformed member
  leaves the complete closure inline.
- Literal ESM import and authored CommonJS require fixtures prove candidate
  misses make no locator probe, exact hits retain carrier receipts, and
  repeated bindings do not re-probe. A two-record closure with one tampered
  carrier proves atomic inline fallback.
- Authenticated production execution now starts from a prepared CommonJS entry,
  discovers the exact target cache only at its reached `require()`, publishes
  the prepared target into the live native generation, and evaluates it once.

The source and prepared paths now cover the required denial/no-probe,
failure/rollback, cycle, teardown, TLA, repeated/concurrent, requester/site,
and reentrancy boundaries.

## Resolution

Resolved on 2026-07-25. The complete secure-mode gate passed with 642 library
tests, 3 intentional ignores, and all behavioral enforcement probes reporting
the expected protected outcome. Generated-artifact, CapSec registry, and LLP
reference checks are recorded in the parent completion ticket.

## Done when

LLP 0026 §6 holds end to end in authenticated production execution, the two
fail-closed guards can be replaced by activation-capability validation, and
the security corpus proves dead branches cause no target discovery while
reached allowed branches acquire and evaluate exactly once.
