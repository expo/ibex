# ibex-compiled-stub crate + StubContractV1 + instance descriptor

**Status:** In Progress
**Severity:** P2
**Systems:** Runtime, Build, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2a/§3
**Depends-on:** sfe-format-spike

Dedicated minimal binary sharing host/engine/embedded-loader/capsec
boot libraries — not a subtractive feature of the full CLI (pre-clap
interception; CLI audit). No REPL/eval/file ingress/clap tree. Acyclic
identity: `StubContractV1` (pre-build facts only — target + baseline,
engine compatibility identity, compatible `hermesc` identity, accepted
schema versions, runner/arming ABI versions, transform profile, a
runtime-relevant capsec-registry projection digest (not the repo-global
digest, which rotates on CLI-only edits), the newly defined
runtime-identity digest (strict-JCS projection, constants generated
into Rust and TS), env-profile digest) with its digest compiled into
the stub and pinned by the envelope; the post-build stub-core digest
lives in the catalog + provenance (packager- and inspector-verified;
boot does not self-hash).

**Done when:** stub boots a spike envelope; contract pin verified at
boot; swap fixtures (same-Hermes/different-stub, producer-newer/
stub-older) refuse; registry projection has its own generated digest.

## Progress — 2026-07-17

The dedicated `crates/compiled-stub` package now owns the phase-0 binary; it
has no clap tree or source-file/eval/REPL ingress. `ibex/stub-contract/1` has a
strict product-neutral type/schema and its domain-separated digest is compiled
into both packager and stub behavior, pinned by the envelope, and rechecked at
boot. The stub boots and evaluates the authenticated spike envelope. The
release contract still needs catalog-populated static engine/`hermesc` facts
and the version-swap matrix before this issue is complete.

The contract shape is now fully typed: target/baseline, tagged engine and
`hermesc` identities with independently recomputed digest domains, accepted
schemas, runner/arming ABIs, transform-profile digest, runtime CapSec
projection digest, runtime-identity digest, and environment-profile digest.
The source-carrier phase-0 contract is explicitly non-release-eligible; a
release-eligible contract rejects diagnostic engine or compiler identities.
Generated-authority assembly is shared by packager and stub rather than
accepting command-line strings. Runtime identity (`sha256-dmZB5Er2…`) and the
runtime CapSec projection (`sha256-3CpJtaP2…`) are generated and drift checked.
The catalog manifest digest is intentionally not a field of a contract stored
in that manifest, which would recreate the identity cycle §2a forbids; it
remains a separate release-compiled trust root.

The macOS stub now also links the pinned Hermes/JSI/Boost closure statically;
`otool -L` reports only Apple/system libraries, and the static full-engine stub
passes the phase-0 embedded execution smoke. Lean/full measurements are
recorded in the dedicated static-Hermes issue; no variant is claimed selected.
Boot now reads the executable only through a descriptor proven to name its
mapped object, and validates the signed Mach-O layout before admitting the
envelope; pathname replacement cannot redirect admission to another file.

## Progress — 2026-07-18 (release provenance admission)

The stub now distinguishes development from release provenance. Release boot
cross-checks the CompilePlan, graph, policy, target, environment profile,
compiler identity, and HBC-only encoding, then admits each HBC carrier against
the exact static engine compatibility identity and bytecode version. A focused
fixture proves both the accepted tuple and static-binding substitution refusal.
After that complete preflight, release execution refuses at the compiled-arming
and CapSec-advertisement gate rather than falling back to the diagnostic Host.
