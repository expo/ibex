# ibex compile + inspect-executable (producer pipeline and CLI)

**Status:** In Progress
**Severity:** P2
**Systems:** Build, Runtime, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §1, LLP 0010, LLP 0028 §2
**Depends-on:** sfe-hbc-production-wiring, sfe-macho-segment-signing, sfe-catalog

The full pipeline behind `ibex compile <entry> -o <file>
[--carrier hbc|factory-table] [--policy <path>] [--deny-unsupported]`:
one captured snapshot drives policy validation and carrier production
(policy v2 graph-identity cross-check; TOCTOU + divergence fixtures);
committed drift-checked policy only, `purpose: production,
mode: enforce` (root + local `--policy` together = explicit conflict);
unsupported shapes keep LLP 0028's invocation-time semantics (compile
diagnostic lists sites; `--deny-unsupported` upgrades to refusal);
`CompilePlanV1` as the single immutable producer input; two
independently atomic writes whose mutual digests make torn pairs
detectable; default carrier HBC (factory-table diagnostic-only pending
register item 3). `ibex inspect-executable` reports three independent
states (envelope consistency / platform signature / external
attestation), reconstructs the complete effective armed authority
bundle, exposes the env profile, and emits versioned machine-readable
JSON. LLP 0010 + `runtime-surface.json` updated together; capsec CLI
classification with a dedicated non-inspector class for
`inspect-executable`; registry/policy digest migration + drift gates.

**Done when:** policy-drift and wrong-engine refusal tests pass;
two-clean-builder reproducibility green; capsec registry checks green
with the new commands classified.

## Progress — 2026-07-17

The public clap grammar now exposes `compile` and `inspect-executable`, and the
recursive `runtime-surface.json` plus generated CapSec registry are synchronized.
`inspect-executable` has an explicit non-inspector classification, authenticates
the envelope without evaluating it, parses canonical inner sections, and emits
versioned JCS with independent envelope, platform-signature, and external-
attestation states. Development artifacts are honestly marked incomplete for
effective-authority reconstruction. Strict `ibex/compile-plan/1` and embedded
package-provenance contracts cross-bind graph, policy, catalog, compiler,
target, environment profile, and stub core. `compile` rejects factory-table
release output and conflicting policy spellings, and accepts only a catalog
trust root compiled into the distributing binary. The current build deliberately
has no release catalog, so source graph assembly, complete authority projection,
atomic output/build-statement publication, and reproducibility gates remain.

## Progress — 2026-07-18

`inspect-executable` now performs the path-independent portion of runtime
admission rather than stopping at canonical section JSON. Without evaluating
application code it verifies every carrier manifest against its payload,
requires the graph-record/carrier-pair bijection, recomputes the authenticated
graph identity, validates the canonical policy against the current vocabulary
and registry, checks policy/entry designation against the graph, and (for
release provenance) cross-checks CompilePlan graph, policy, stub-contract,
target, and carrier-encoding fields. Catalog trust, platform signing, and
publisher authentication remain explicitly separate report axes. The signed
phase-0 three-record relocation fixture now asserts the inspector reports three
internally admitted records and carriers. Release source-graph assembly is now
available as a reusable authenticated publisher plus whole-graph catalog-HBC
adapter, but the public compile route correctly remains closed until populated
release catalog cells and compiled arming are available.

## Progress — 2026-07-18 (producer pipeline)

The public `ibex compile` route now continues past catalog admission. It captures
the complete literal source graph with portable root/package/builtin identities,
admits the exact committed compiled policy, compiles every carrier with the
catalog `hermesc`, constructs the CompilePlan and release provenance, assembles
and self-preflights the envelope, and atomically publishes the executable and
detached build statement. Mach-O output is ad-hoc signed before publication. A
synthetic admitted catalog test uses the checked-in real macOS `hermesc`, builds
the complete envelope, and re-admits both release provenance and inner contracts.

`ibex policy generate/check` now accepts target and mount profiles and consumes
the exact canonical graph captured by the native loader; the JavaScript policy
analysis must match its root/package file inventory, integrity values, package
principals, and entry identity. The distributing binary still has no populated
release catalog, and compiled authority arming remains gated by the author
decisions recorded in LLP 0029.
