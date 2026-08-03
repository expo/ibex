# Production HBC carrier publication and admission

**Status:** Closed
**Impact:** 5
**Urgency:** 4
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Production HBC carrier publication and admission” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** Complete
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

## Remaining (verified 2026-07-31)

- Refusal fixtures (wrong-engine, compiler/stub mismatch, substitution)
  are DONE across carrier admission, stub cross-check, and catalog.
- HBC has never executed from an envelope end-to-end: real HBC execution
  is in-process via the linker only; the phase-0 envelope script
  publishes factory-table carriers; the full-HBC envelope test uses a
  synthetic non-executable stub and is macOS-arm-only (no Linux leg).
- The production route is unreachable in every build:
  `IBEX_RELEASE_SFE_CATALOG_DIGEST` is set by nothing in the repo.

## LLP 0047 reconciliation — 2026-08-01

The fixed catalog recipe now includes authenticated
`-Xes6-block-scoping`, and a real hermesc-AOT/VM fixture proves
per-iteration capture for a closure-capturing leave-raw loop. The dedicated
milestone-0 gate runs format, catalog, compiled-stub, catalog-compiler, and
producer tests. Remaining work is unchanged at product altitude: populate and
pin the real catalog, then execute genuine release HBC envelopes on macOS arm64
and Linux x64 after deleting source and catalog (LLP 0047 milestones 1 and 3).

## Implementation checkpoint — 2026-08-01

Both target legs of that remaining gate are now real: catalog-pinned public
producers emitted V2 release envelopes whose genuine HBC executed in the
static compiled Host, then relocated executables repeated the result while
their source trees and catalogs were unavailable. The fixture covers
TypeScript, argv, inherited environment, a referenced timer, stdout, and
nonzero `process.exitCode`. The installed-user kit gate additionally proves
explicit `.mts` retains Module source goal, its digest-covered top-level-await
fact selects the asynchronous compiled graph, and genuine TLA HBC settles in
relocated source/catalog-free executables on both tuples. A second graph now
covers ESM, CommonJS, builtins, literal dynamic import, and authenticated
computed dynamic import. The final-image gate corrupts every load-bearing
section independently and proves refusal before any carrier side effect,
including an unselected candidate carrier. The official Linux GLIBC 2.35
release receipt remained before this ticket could claim the complete release
tuple rather than functional Ubuntu 24 evidence.

## Resolution — 2026-08-02

The official Ubuntu 22.04/GLIBC 2.35 release kit now passes genuine HBC
execution, relocation, and clean-recipient gates, alongside the macOS arm64
release kit. HBC version and engine compatibility are derived and admitted
from the catalog-bound compiler/stub tuple; wrong-engine, compiler/stub, and
carrier-substitution fixtures refuse. Production publication is HBC-only and
no production path relies on the former dummy-digest test pattern. The ticket's
two-tuple end-to-end acceptance criteria are complete.
