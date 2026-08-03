# ibex-compiled-stub crate + StubContractV2 + instance descriptor

**Status:** Closed
**Impact:** 5
**Urgency:** 4
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “ibex-compiled-stub crate + StubContractV1 + instance descriptor” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** Complete
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

## Historical remaining list — 2026-07-31

This snapshot is retained for provenance and is superseded by the later
implementation checkpoints.

- Swap fixtures (same-Hermes/different-stub, producer-newer/stub-older)
  do not exist; `StubContractV1.accepted_schemas`/`accepted_abis` are
  validated against constants but never consulted during boot admission.
- No negative test passes a wrong contract digest to
  `admit_executable_v1` (existing negatives mutate footer/section bytes).
- A release contract cannot currently be produced:
  `COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE = false`
  (src/compiled_environment_profile_generated.rs) gates
  `release_stub_contract`, which has no non-test caller.
- Stale digest in the Progress text: the CapSec runtime projection is
  now `sha256-d1CUhCLd_-DrR27vEBEm8BWzwrqLkGq_yn1-sq6UAGU`
  (src/capsec_runtime_projection_generated.rs), not `sha256-3CpJtaP2…`.

## LLP 0047 reconciliation — 2026-08-01

The carrier-API drift is repaired and the compiled-stub tests now run in the
named milestone-0 CI gate. `StubContractV1` is provisional only: milestone 2
replaces it before release with `StubContractV2`, authenticating the default
mode, first-position selector rule, and CapSec-advertisement identity, and
embeds the canonical contract bytes in a new envelope section so inspection
can report those facts. The swap/negative fixtures above remain relevant to
that versioned replacement.

## Implementation checkpoint — 2026-08-01

The repository went directly to the final V2 cut. Boot now exact-compares the
compiled canonical contract with the admitted contract section, verifies the
envelope pin, and authenticates the ambient default, selector/escape rules, and
empty CapSec advertisement identity. Contract and artifact substitution tests
pass, and derived release-eligible contracts have produced and booted real
macOS arm64 and Linux x86-64 catalog artifacts. Linux additionally exposed and
closed the glibc `envp` republish edge between preinit and constructors. This
ticket remains open for the explicit producer-newer/stub-older ABI/schema
matrix and the official GLIBC 2.35 release receipt.

## Implementation checkpoint — 2026-08-02

`StubContractV2` now authenticates a target-exact backend inventory, and
release validation requires byte-for-byte equality with the derived inventory
for the named tuple. Non-evaluating inspection reports every entry's surface,
status, implementation, and limitations. The release gate proves Fetch through
the advertised target implementation and a loopback `node:http` server over
POSIX sockets, authenticates the WebSocket implementation, and proves stable
HTTP/2, inspector, WASI, and worker limitations on both macOS arm64 and Linux
x86-64; it also proves the limited POSIX signal contract.
Format, catalog, and stub suites cover the contract equality and substitution
paths.

## Resolution — 2026-08-02

The stub now rejects a canonically valid contract whose schema, ABI,
transform, runtime-identity, CapSec projection, or environment-profile
authorities do not exactly match the authorities compiled into that stub. The
explicit producer-newer/stub-older matrix mutates those independently and
proves refusal. The official Ubuntu 22.04/GLIBC 2.35 release kit and a
source-, catalog-, producer-, Hermes-, and cache-free recipient execution also
pass. The dedicated stub boots genuine release HBC, authenticates its V2
contract pin and instance descriptor, and has the required substitution
fixtures, so this ticket's completion criteria are met.
