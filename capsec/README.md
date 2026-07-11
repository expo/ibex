# Ibex capability-security contract

This directory is the machine-readable contract for the typed effect model in
[LLP 0021](../llp/0021-capsec-effect-model-migration.plan.md). It is deliberately
not loaded by the production runtime yet: WP0 freezes and validates the model;
WP1 generates production bindings and the complete surface inventory; WP2
implements the shared decision core.

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
  rules, canonical review policy, and armed snapshots; digest bundles and
  vectors; the file manifest; and legacy reconciliation.
- `registry/` contains the WP0 capability definitions, policy/classifier
  contract, and the explicit disposition of every legacy capability bit.
- `examples/` contains canonical selector and occurrence coverage for every
  authorable resource kind, a multi-effect decision set, containment vectors,
  coverage and target rows, canonical policy and armed-snapshot fixtures, the
  exact vocabulary/registry-fixture digest bundles, and five domain vectors.
  Examples are checked consumers, not an alternate registry authority.
- `testdata/invalid/` contains malformed or semantically impossible goldens.
  Every file is registered and must be rejected by its declared validator.
- `generated/` contains review-oriented output derived from authoritative
  sources. Do not edit it by hand.

Run:

```sh
bun run check:capsec-contract
bun test packages/ibex-devtools/src/scripts/capsec-contract.test.mjs
```

Regenerate the exact digest bundles, policy/armed self- and cross-digests,
digest-vector expectations, and reconciliation table with:

```sh
bun run generate:capsec-contract
```

The validator also enforces canonical generic and composite-keyed sets, exact
normalizer/coverage references, selector and occurrence coverage for all
authorable resource kinds, containment coverage for every handle/dynamic kind,
target-cell joins, armed graph/root/binding/protected-object invariants, and
real digest membership. The current WP0 corpus contains 38 typed definitions
and reconciles all 57 live rows in `src/host/capability_bits.rs` exactly once.
Commented and outside-table Rust lookalikes are ignored; bit numbers are never
copied into the reconciliation source.

## Ownership boundary

Ibex owns the initial canonical contract here. WP2 will place the runtime-
neutral Rust implementation behind a neutral `capsec-semantics` crate boundary
in this repository. A second runtime must consume that exact source or trigger
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
bundle contains the exact files, normative coverage rows, and containment
vectors named by its frozen projection. The registry bundle content-addresses
the semantic and invalid fixture bodies in the closed manifest. Digest-bearing
payloads and the fixed vector oracle are explicitly excluded where raw inclusion
would be cyclic and are checked independently. The registry bundle is a
non-production contract fixture until WP1 supplies the generated implementation
inventory; conformance remains unavailable until WP10. Canonical policy and
armed examples carry recomputed self-digests and exact cross-links.

Durable policy is enforce-only. Audit is the ephemeral, separately named
`ibex capsec audit` workflow. The `contract-fixture` armed snapshot is
schema-only, uses the synthetic `capsec-contract-fixture` target, and is never
executable. Production permissive and off modes are not members of the profile,
and WP0 advertises no executable target.
