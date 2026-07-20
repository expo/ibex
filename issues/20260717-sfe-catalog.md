# Content-addressed stub/compiler catalog with release-pinned trust

**Status:** In Progress
**Severity:** P2
**Systems:** Build, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2a/§5
**Depends-on:** sfe-stub-crate-and-contract

Packaging always consumes the stub, contract, and `hermesc` as catalog
artifacts — never a warm checkout build (this is also what makes
unsigned-core determinism independent of Rust build reproducibility).
v1 trust model: one immutable catalog manifest (target →
expected-digest map) whose **exact digest is compiled into each
distributing `ibex` release**; no independent update channel (TUF-style
state machine deferred until needed). Offline; explicit fetch/update
command; missing entries fail loudly naming the fetch step; provenance
records the catalog entry + verification evidence. Publisher-statement
key custody is register item 8 (blocked-on-decision for the
"authenticated" inspection state).

**Done when:** host-tuple catalog populated for both v1 tuples;
`ibex compile` refuses non-catalog stubs; pinned-digest verification
tested incl. rollback/substitution fixtures.

## Progress — 2026-07-17

The product-neutral `ibex-sfe-catalog` crate now implements strict canonical
`ibex/sfe-catalog/1` manifests and the `ibex:sfe-catalog:1` release trust-root
digest. Entries bind target/baseline, contract/engine/compiler identities, HBC
version, and content-addressed descriptors for the canonical contract,
unsigned stub core, and `hermesc`. Admission requires the exact release-pinned
catalog digest, verifies every artifact size/digest, recomputes the typed
release contract and its cross-bindings, rejects diagnostic contracts, and
names the fetch step for missing targets. Tests cover artifact and contract
substitution, attacker-selected/prior manifests, noncanonical bytes, and
missing targets. The compiled-stub build can now embed and validate a canonical
release contract supplied by catalog construction. Catalog admission also
requires the exact fixed production `hermesc` recipe digest, and the public
compile route has no caller-selected catalog option: it can load only the
content-addressed catalog named by its build-time trust-root constant. Host catalog population,
the release-compiled digest constant/CLI fetch path, and the Linux entry remain.
