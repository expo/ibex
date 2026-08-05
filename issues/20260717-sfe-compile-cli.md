# ibex compile + inspect-executable (producer pipeline and CLI)

**Status:** Open — release publication/receipt actions remain
**Impact:** 5
**Urgency:** 4
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “ibex compile + inspect-executable (producer pipeline and CLI)” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
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

## Remaining (verified 2026-07-31)

- `--deny-unsupported` is inert: parsed and threaded, but its only
  effect is picking an error string — no unsupported-site diagnostic,
  no refusal upgrade.
- The TOCTOU/divergence fixtures named in the body do not exist for the
  compile route (closest is a publication-level mutation refusal).
- `inspect-executable` derives `expected_engine_binding` from the
  manifest under inspection (src/bin/ibex/sfe.rs:596-616), so a
  wrong-engine carrier is self-consistent at the inspect route; only
  the stub cross-checks against the contract. No wrong-engine refusal
  test exists for the compile/inspect CLI pair.
- Two-clean-builder reproducibility for `ibex compile` is untested (the
  only byte comparison is the dev-pack factory-table script, not in CI).
- The public compile route is unreachable until a release catalog trust
  root is compiled in (`IBEX_RELEASE_SFE_CATALOG_DIGEST` never set).
- `CompilePlanV1` is constructed after capture/compile and consumed as
  provenance cross-check, not as the single immutable producer input
  the body describes.

## LLP 0047 reconciliation — 2026-08-01

Catalog reachability and the recorded new-user policy-authoring sequence are
milestone 1. Release evaluation no longer waits for successful CapSec arming:
milestone 2 opens the ambient-default path after the same inner admission and
keeps explicit CapSec requests fail-closed. Inspection's authenticated mode
report depends on the authenticated stub contract plus its envelope section; the remaining
`--deny-unsupported`, TOCTOU, wrong-engine inspection, and two-builder gaps
remain owned here.

## Implementation checkpoint — 2026-08-01

The previously unreachable public route now works in a catalog-pinned release
build. It generates/checks the exact native graph-backed production policy,
compiles real HBC, emits a V2 executable, ad-hoc signs it, and inspection
authenticates and reports its boot contract. Both macOS arm64 and Linux x86-64
artifacts run after relocation with source and catalog unavailable. The
remaining open criteria are the official Linux GLIBC 2.35 receipt,
two-clean-builder reproducibility, and the older `--deny-unsupported`/TOCTOU
gaps above.

## Implementation checkpoint — 2026-08-02

The remaining producer correctness gaps are closed. Source capture now retains
a deterministic, path-independent inventory of computed dynamic imports
without candidate tables, computed CommonJS `require` calls, and unsupported
dynamic-import option sites. Ordinary compilation prints every site and keeps
the authenticated invocation-time guards; `--deny-unsupported` refuses the
same inventory before policy admission, HBC compilation, or output
publication. The release-kit matrix proves both behaviors and successful
dead-branch execution in a real macOS release envelope.

CompilePlanV1 is fixed before `hermesc` executes, and the producer now runs the
same inner graph/policy/carrier/provenance admission used by inspection before
publishing either output. Source-mutation and policy-divergence fixtures prove
the post-capture path consumes the immutable snapshot. The policy author's
Rolldown analysis/native-snapshot comparator has direct negative fixtures for
file, package, entry, and candidate-set divergence. Inspection derives the HBC
engine expectation from the authenticated stub contract, cross-checks the plan
against that contract, and refuses a self-consistent carrier manifest naming a
different static engine.

The official Ubuntu 22.04/GLIBC 2.35 recipient receipt and two-physical-builder
Linux exact-identity comparison are green, and CI contains duplicate clean jobs
plus a strict comparator for both tuples. This ticket remains open only for a
matching macOS two-clean-builder receipt and execution of the configured clean
jobs on a published commit.

A fresh current-source macOS release kit also passes the entire installed-user
matrix after the producer-newer/stub-older authority checks and policy/native
graph comparator were packaged. The final source-stable rebuild after the
inspection-completeness work has catalog
`sha256-LGJFbrY46eA_9MbMPx1QZijWdpQcsQTeGoL0mQIrCcw` and policy toolchain
`sha256-TFpMdNyyREUzRTT_L0heu9oac4en2dvws7hGMO8ne5I`. The remaining evidence
is external to the local implementation: a matching second clean macOS builder
and the configured clean jobs on the eventually published commit.

The matching fleet MacBook Air (Xcode 26.6 / build 17F113) was unreachable on
2026-08-02. The reachable Mac mini is on Xcode 26.4.1 / build 17E202, so it is
not substituted for the strict identical-toolchain comparison. This preserves
the meaning of the open receipt instead of accepting a merely second machine.

## Author-decision checkpoint — 2026-08-02

The author approved LLP 0047 recommendations 1, 3, and 4. Compilation keeps
explicit policy authoring and never synthesizes a minimal policy; ambient
compatibility is ratified as the v1 default; and copied artifacts reserve exact
first-position `--ibex-info`. The strict boot contract is now
`StubContractV3`, external inspection is `ibex/executable-inspection/3`, and
the artifact emits `ibex/standalone-executable-info/1` only after complete
self-admission and before application-runtime construction. Focused unit and
release-kit fixtures own first-position, later-position, leading-`--` escape,
and no-entry-evaluation behavior. This resolves the local product-decision
portion of the ticket; publication and matching clean-macOS evidence remain.

Inspection now closes the remaining LLP 0029 instance-consistency gap. Release
provenance authenticates a reconstruction descriptor for the catalog stub;
the inspector inversely projects the actual ELF or Mach-O outer bytes, rehashes
them, and reports `stubCoreConsistency` separately from platform signature and
external attestation. A fresh macOS kit refused an independent outer-stub
mutation, preserved the same rehashed stub identity through signature removal
and replacement, and passed the complete installed-user matrix with catalog
`sha256-LGJFbrY46eA_9MbMPx1QZijWdpQcsQTeGoL0mQIrCcw` and policy toolchain
`sha256-TFpMdNyyREUzRTT_L0heu9oac4en2dvws7hGMO8ne5I`.

## Maintenance reconciliation — 2026-08-05

The matching macOS two-clean-builder comparison subsequently passed and is no
longer an open criterion here. The producer implementation is complete for the
ambient-v1 scope; this ticket remains open only until the exact catalog-pinned
release is published, reinstalled from that publication, and exercised by the
configured clean release jobs on the published revision.
