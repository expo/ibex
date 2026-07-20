# Production HBC carrier publication and admission

**Status:** In Progress
**Severity:** P2
**Systems:** Module Loader, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §1 step 3, LLP 0026 §9, LLP 0027
**Depends-on:** sfe-stub-crate-and-contract, sfe-graph-snapshot-domain

Production publication emits factory tables only today;
`bind_hermes_bytecode` trusts caller-supplied engine metadata, and the
real-Hermes tests label genuine bytecode with dummy digests. Wire
production HBC publication/admission: compile with the
catalog-authenticated `hermesc` paired to the target `StubContractV1`;
derive bytecode version **by inspecting the emitted HBC**, never
caller-supplied; bind the stub contract's engine compatibility
identity; bulk-preflight parses and sanity-checks every HBC payload
against manifest + contract before any carrier evaluates (today
sanity-checking happens only at lazy evaluation). Per-module carriers
in v1.

**Done when:** wrong-engine and compiler/stub-mismatch fixtures refuse;
HBC executes from an envelope end-to-end on both tuples; dummy-digest
test pattern eliminated from production paths.

## Progress — 2026-07-17

`ibex/module-carrier/2` now has a tagged engine-binding domain that cannot
confuse mapped-file digests with static compatibility identities. HBC binding
and bulk admission inspect execution magic, bytecode version, and exact file
length from the payload itself. The real-Hermes carrier tests use the loaded
engine digest and inspected version instead of dummy metadata.

Bulk admission now also calls the exact linked Hermes bytecode sanity checker
for every admitted HBC carrier before any factory table is evaluated. The
native entry point fails closed when no sanity API exists; the real-HBC test
proves valid bytes pass and a post-compile mutation refuses. Catalog-paired
production now has a product-neutral adapter: it materializes only the admitted
catalog `hermesc`, clears the environment, invokes the fixed
`-emit-binary -out {output} {input}` recipe in a private directory, inspects the
emitted HBC header/length, and binds the carrier to the target static engine
compatibility identity. A real checked-in macOS `hermesc` test emits admitted
HBC. Full graph publication, explicit compiler/stub mismatch fixtures, and
two-target envelope execution remain.

## Progress — 2026-07-18

The authenticated source-graph path now has a production-facing embedded
publisher. After validating the complete native graph plan, it deterministically
orders portable `SourceId`s, derives the single authenticated snapshot identity,
emits typed conditioned edges and `/app` labels, constructs one carrier pair per
module (including runtime builtins), binds every manifest to that identity, and
re-admits the complete graph/carrier bijection. A three-record
ESM+relative-dependency+builtin fixture proves the graph, manifests, and payloads
are identical when their admitted source records carry different checkout paths.

The catalog compiler adapter now consumes that complete publisher result and
rotates every per-module factory carrier to inspected HBC under the one admitted
compiler/engine tuple while preserving pair and semantic identities. Release
contracts additionally refuse a static-engine/catalog-compiler HBC-version
mismatch before catalog publication, and catalog tests explicitly reject
compiler-byte substitution alongside stub and contract substitution. The
full graph linker now also has a real-Hermes fixture with two independently
compiled/admitted HBC carrier pairs and an authenticated ESM edge; it links and
evaluates the entry to `{"answer":42}`. The remaining gate is an actual
catalog-populated, static-compatibility-bound release envelope run on both
tuples (plus its clean-root byte comparison); source factory tables remain
diagnostic-only.

## Progress — 2026-07-18 (public release producer)

The public release producer now compiles the whole authenticated graph to HBC
after catalog admission. Its complete-assembly test uses a real macOS `hermesc`
fixture, publishes the envelope, and re-admits the resulting release contracts.
The compiled stub now admits release provenance and verifies every HBC carrier's
static compatibility binding and bytecode version before execution. Execution
under a compiled Host on both release tuples remains gated.
