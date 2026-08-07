# Content-addressed stub/compiler catalog with release-pinned trust

**Status:** Closed
**Impact:** 4
**Urgency:** 3
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Content-addressed stub/compiler catalog with release-pinned trust” shows the issue materially affects a supported product or engineering path; it belongs in the current program but is not an immediate blocker, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** Complete
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

## Remaining (verified 2026-07-31)

- No catalog manifest exists on disk for either v1 tuple;
  `CatalogManifestV1` is constructed only in tests. The trust root is
  unset (`IBEX_RELEASE_SFE_CATALOG_DIGEST` set by nothing in the repo)
  and no fetch/update CLI subcommand exists — the header's "explicit
  fetch/update command" describes intended, not current, behavior.
- Met: `ibex compile` refuses non-catalog stubs (trust root acquired
  before source access) and pinned-digest verification has unit-level
  rollback/substitution fixtures; unmet: the same over real artifacts.

## LLP 0047 reconciliation — 2026-08-01

This is milestone 1's primary ticket. The first real catalog is explicitly
provisional: milestone 2 replaces `StubContractV1` with the authenticated
dual-mode `StubContractV2`, adds the contract envelope section, then re-cuts
the catalog and producer pin. CapSec advertisement is no longer required to
populate either v1 tuple. Remaining work is real artifact production,
installation/fetch UX, the compiled release pin, and real-artifact
substitution/reproducibility evidence.

## Implementation checkpoint — 2026-08-01

`CatalogManifestV1::from_target_artifacts` and the internal
`ibex-sfe-catalog` assembler now derive a manifest from exact V2
contract/stub/compiler bytes, self-admit it, and atomically install its
immutable digest-addressed directory. `ibex-sfe-contract` derives the static
archive-bundle digest, compiler digest, and matching compiler/VM HBC version.
macOS arm64 and Linux x86-64 catalogs were assembled and their digests compiled
into release `ibex` binaries; both public compile paths ran end to end. The
Linux evidence host truthfully recorded GLIBC 2.39, so the official GLIBC 2.35
catalog receipt remains. This ticket also stays open for published
install/fetch UX and two-builder evidence.

The local install path is now implemented. `scripts/build-sfe-release.sh`
produces a coupled release kit containing a catalog-pinned `ibex`, an
`ibex-sfe-catalog` binary compiled with the same immutable pin, and the exact
version/target/digest catalog archive. The installer has no digest override;
it admits every source artifact and cross-binding, stages fresh regular files,
re-admits the staging tree, and publishes one addressed directory atomically.
`ibex compile` now names the exact archive and extraction/install command on a
missing catalog. Remaining work is to run and publish the official macOS arm64
and Ubuntu 22.04 kits and retain two-clean-builder reproducibility receipts.

## Resolution — 2026-08-02

Both v1 target tuples have real V2 catalog entries consumed through a
release-compiled immutable trust-root digest. The local archive installer is
the explicit offline fetch/install path, and compile refuses absent,
non-catalog, stale, substituted, or cross-bound artifacts. The official
Ubuntu 22.04/GLIBC 2.35 kit passes, and two independent physical Jammy builders
produced the same catalog, contract, policy-toolchain, and unsigned application
identities under the strict comparator. Publication of those exact kits and
the remaining macOS two-builder receipt are distribution/reproducibility work
tracked separately; this catalog ticket's completion criteria are met.
