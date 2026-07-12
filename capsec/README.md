# Ibex capability-security contract

This directory is the machine-readable contract for the typed effect model in
[LLP 0021](../llp/0021-capsec-effect-model-migration.plan.md). It is deliberately
the only production policy and decision contract. Ordinary execution requests
enforce mode with empty dependency authority when no grants are authored, and
startup refuses any target that lacks a complete, artifact-bound conformance
report. No exact target is advertised complete yet; production arming remains
closed until WP10 has real per-obligation execution evidence.

The committed Rust and C++ bindings are compile-checked by the library build;
the generated JavaScript and TypeScript bindings are syntax-checked and deeply
immutable. The neutral `capsec-semantics` crate supplies canonical parsing,
containment, decisions, and digests. The aggregate
`registryDigest` must be computed alongside these artifacts, never embedded
back into a binding whose raw digest feeds the implementation manifest; doing
so would create a digest fixed-point cycle.

The first public Ibex profile is `ibex/capsec/1`. Oden's `/2` suffix belongs to
Oden's own profile lineage; shared ancestry is represented by the effect and
registry semantics rather than by borrowing another product's version number.

## Layout

- `contract-files.json` is the closed inventory of every checked schema,
  registry, example, invalid fixture, and generated artifact. Missing or
  unlisted files fail validation.
- `schema/` defines common identities and resources; capability definitions;
  authority selectors and normalized occurrences; conjunctive effect sets;
  authority containment vectors; coverage edges and target cells; policy
  rules, canonical review policy, armed snapshots, and exact-target
  conformance reports; digest bundles and vectors; the file and
  observed-source manifests; and legacy reconciliation.
- `registry/` contains the four semantic datasets: capability definitions,
  generated coverage edges, generated exact target cells, and policy/classifier
  rules. It also retains the explicit build-time disposition of every legacy
  capability bit.
- `examples/` contains canonical selector and occurrence coverage for every
  authorable resource kind, a multi-effect decision set, containment vectors,
  coverage and target rows, canonical policy and armed-snapshot fixtures, the
  exact vocabulary/registry-fixture digest bundles, and five domain vectors.
  Examples are checked consumers, not an alternate registry authority.
- `testdata/invalid/` contains malformed or semantically impossible goldens.
  Every file is registered and must be rejected by its declared validator.
- `generated/` contains the source-reference/fixture-obligation manifest,
  stable-ID schema, and review-oriented tables derived from authoritative
  sources. Source references may identify definitions, target stubs, or
  security-relevant uses; they are not conformance evidence. Do not edit these
  files by hand.

Implementation-manifest rows retain exact branch IDs and normalized target
applicability. Target cells select those IDs deterministically from the target
triple, but remain unsupported until executed fixtures exactly cover every
selected branch obligation. A target with no applicable branch may later be
proved absent; it cannot borrow a branch or fixture from another target. Known
unsupported stubs cannot promote. Weak-fallback provenance must be resolved by
fixtures bound to the exact report binary before WP10 can make a claim.

Run:

```sh
bun run check:capsec-registry
bun run check:capsec-contract
bun test packages/ibex-devtools/src/scripts/capsec-surface-inventory.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-coverage-model.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-fixture-obligations.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-target-branches.test.mjs
bun test packages/ibex-devtools/src/scripts/generated-output-io.test.mjs
bun test packages/ibex-devtools/src/scripts/generate-capsec-registry.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-contract.test.mjs
bun test packages/ibex-devtools/src/scripts/capsec-conformance.test.mjs
```

Generate a local report for the candidate target and installed patched-Hermes
binary with:

```sh
bun run generate:capsec-conformance
```

The report is written under `target/` and is intentionally incomplete unless
an independently produced `--executions` artifact supplies one unique,
passing, artifact-digested result for every exact fixture obligation. Each
execution must carry the binding digest for the report's source revision,
source tree, engine binary, target, vocabulary, registry, implementation
manifest, and fixture catalog. `--require-conformant` makes any missing or
failed result fatal. Inventory rows and a green sample suite never synthesize
execution results.

On the declared candidate target, produce the execution artifact and bound
report from a clean committed tree with:

```sh
bun run verify:capsec-conformance
```

The executor runs the complete Rust library/runtime suites, the capsec
contract, policy, target-branch, registry and conformance suites, both generated
drift checks, and `ref-check`. It emits one result for every generated exact
fixture obligation, all sharing the immutable digest of that command evidence;
the report generator independently rejects any stale source, engine, target,
registry, implementation-manifest, or fixture-catalog binding.

Regenerate the source-derived registry and bindings first, then the exact
digest bundles, policy/armed self- and cross-digests, digest-vector
expectations, and reconciliation table:

```sh
bun run generate:capsec-registry
bun run generate:capsec-contract
```

The validator also enforces canonical generic and composite-keyed sets, exact
normalizer/coverage references, selector and occurrence coverage for all
authorable resource kinds, containment coverage for every handle/dynamic kind,
target-cell joins, observed-source/semantic-edge joins, conditional-edge
non-promotion, armed graph/root/binding/protected-object invariants, and real
digest membership. The corpus contains 38 typed definitions and reconciles all
57 live rows in `src/host/capability_bits.rs` exactly once.
Commented and outside-table Rust lookalikes are ignored; bit numbers are never
copied into the reconciliation source.

## Ownership boundary

Ibex owns the canonical contract here. The runtime-neutral Rust implementation
lives behind the `capsec-semantics` crate boundary in this repository. A second
runtime must consume that exact source or trigger
an explicit ownership move; it must not create a second matcher or copied
schema authority. Product capability definitions, surface edges, attribution
adapters, and target cells remain Ibex-local.

## Canonical forms

Policy moves only from authored source to canonical review policy to an
immutable armed snapshot. Canonical positive rows use explicit action names and
typed resource objects. Aliases, macros, colon-delimited resources, and
positive action wildcards may exist only in authored-source ingestion and must
not reach these forms.

Digest inputs are strict I-JSON serialized with RFC 8785 JCS and framed as the
UTF-8 domain, one NUL byte, and the canonical payload. The checked vocabulary
bundle contains the exact files, production coverage rows, and containment
vectors named by its frozen projection. The registry bundle content-addresses
the production semantic datasets, observed-source manifest, and semantic and
invalid fixture bodies in the closed manifest. Digest-bearing
payloads and the fixed vector oracle are explicitly excluded where raw inclusion
would be cyclic and are checked independently. The production registry is
available, but every WP1 target cell remains unsupported and conformance
remains unavailable until WP10 completes its executed evidence. The WP10
report format and fail-closed generator now exist; the candidate remains
unadvertised while its report is incomplete. Canonical policy and armed examples carry
recomputed self-digests and exact cross-links.

Durable policy is enforce-only. Audit is the ephemeral, separately named
`ibex capsec audit` workflow. The `contract-fixture` armed snapshot is
schema-only, uses the synthetic `capsec-contract-fixture` target, and is never
executable. Production permissive and off modes are not members of the profile.
WP1 advertises no executable target; it records only the exact
`aarch64-apple-darwin` candidate and its required structural security features.
`conditional-unrefined` edges cannot be promoted beyond `unsupported` until
their owning work packages generate exact conjunctive branches.
Refined conditional edges use normalized fact/value predicates and carry the
full effects, attribution ownership, lifetime, and barriers for each exactly
selected logical branch. Their fixture obligations are branch-scoped; empty
branches require explicit no-effect evidence rather than disappearing from the
report.
