# LLP 0047: Standalone Executable Finish Line

**Type:** Plan
**Status:** Accepted
**Systems:** Build, Distribution, Runtime, Module Loader, CapSec, Product
**Author:** Charlie Cheever / Codex
**Date:** 2026-08-01
**Revised:** 2026-08-13 (the accepted two-tuple performance budget is
`config/sfe-performance-budgets.json`; remaining §9 work is publication,
notarization, host measurements against that blob, and durable CI receipts)
**Revised:** 2026-08-05 (maintenance reconciliation: the macOS two-builder
comparison and all §12 decisions are complete; ambient-v1 release work is now
publication, notarization, accepted performance budgets/measurements, and
durable CI receipts. LLP 0048's app-bound formats and restricted-worker path
have substantial implementation, while their complete acceptance and
target-evidence gate remain open.)
**Revised:** 2026-08-03 (the separate LLP 0048 gate now names catalog V2 and
the catalog/stub/plan/report-bound per-target enforcement evidence; no current
M0–M5 row supplies it)
**Revised:** 2026-08-03 (LLP 0048 separates Snapback's missing external-script
worker from this plan's general embedded-entry finish line. A green standalone
compiler does not close the app-bound `run analysis.ts` contract; the matrix
now records its independent admission, broker, policy, host-parity, and
target-evidence gate.)
**Revised:** 2026-08-03 (Developer ID and physical-builder checkpoint: a fresh
arm64 application is hardened-runtime signed with the configured Developer ID,
receives Apple's secure timestamp, passes strict signature inspection and Ibex
admission, and runs Fetch after relocation. Gatekeeper's remaining refusal is
specifically the absent notarization ticket. The matching Xcode 26.6 MacBook
Air is reachable; independent default-profile Hermes builds have identical
object members for both architectures, but their universal static archives
retained builder-specific member timestamps and numeric owners. The Apple
builder now reconstructs every cached static slice with `libtool -D` and
canonical architecture order. Synthetic/idempotence coverage and normalization
of the two physical archive sets converge byte-for-byte. The first fresh full
receipt pair on the rotated cache key then exposed a second checkout leak:
`hermesc` recorded absolute bootstrap and generated-runtime source paths in HBC,
changing the stub core despite identical inputs and toolchains. Release builds
now invoke `hermesc` from each source directory with only a stable basename;
fresh full receipts after that correction remain to be recorded. The same
physical rerun found that the installed-user verifier still assumed the
non-default `rg` utility; it now uses platform `grep` throughout. The resulting
valid receipt pair exposed a third checkout leak: vendored OpenSSL records its
Cargo install prefix in `libcrypto`. Release stubs now build in a stable
target- and contract-addressed `/tmp` namespace; another physical pair remains
to be recorded. That pair removed every checkout path and reduced the raw stub
difference to 48 bytes: the independently synthesized 16-byte Mach-O `LC_UUID`
plus its dependent ad-hoc signature bytes. Omitting the command made the two
catalogs identical, but both relocated runtime matrices caught dyld's mandatory
`LC_UUID` check. The release builder instead replaces the UUID after signature
removal with a digest-derived RFC 4122 value before catalog hashing; another
physical pair remains to be recorded. The final pair at commit `2a611b4f`
passes both complete installed-user matrices and the strict comparator across
all six identities, including stub core
`sha256-l50-bX04ZMTR6mTTvyFHYmAuHgnzH45xHQdHD5uzs_I` and unsigned file
`sha256-o2i8DnpfuZoxrol10OVCwQR-lFsEaMBe1tvaI_kn884`.)
**Revised:** 2026-08-02 (author decisions 1, 3, and 4 resolved: v1 keeps
explicit policy authoring, ratifies ambient compatibility as the standalone
default against the completed two-tuple artifacts, and reserves authenticated
first-position `--ibex-info`. The new required boot fields rotate the unshipped
stub contract to `StubContractV3` / `ibex/stub-contract/3`; envelope V2 remains
unchanged. The info path completes ordinary admission, prints canonical
posture/backend/CapSec facts, and exits before Host or Hermes construction.)
**Revised:** 2026-08-02 (clean-builder receipt hardening: each release-kit
evidence bundle now records a distinct logical builder id, clean Git
commit/tree, host tuple, and exact native toolchain; reproducibility report v2
requires two different matching-toolchain receipts before comparing unsigned
application identities.)
**Revised:** 2026-08-02 (inspection-completeness checkpoint: release
provenance authenticates an inverse-projection descriptor, so inspection now
reconstructs and rehashes the actual ELF/Mach-O catalog stub instead of merely
displaying its claimed digest. Independent outer-stub tamper refuses, while
real Mach-O signature removal and replacement preserve the exact stub, graph,
and CompilePlan identities. The final source-stable macOS kit passes with
catalog `sha256-LGJFbrY46eA_9MbMPx1QZijWdpQcsQTeGoL0mQIrCcw` and policy
toolchain `sha256-TFpMdNyyREUzRTT_L0heu9oac4en2dvws7hGMO8ne5I`.)
**Revised:** 2026-08-02 (credential-free Mach-O acceptance checkpoint:
malformed signature/layout refusal vectors and a real system-codesign
remove/replace/strict-verify/relocated-Fetch matrix now pass while preserving
the exact authenticated graph and CompilePlan identities; the replacement
also carries Apple's hardened-runtime flag. Developer ID secure timestamping,
notarization, and a matching Xcode 26.6 second-
builder receipt remain external release evidence; the fleet's matching Mac was
unreachable and its reachable Mac is on Xcode 26.4.1.)
**Revised:** 2026-08-02 (final local implementation audit: the stub now
independently rejects producer-newer schema/ABI/generated-authority contracts;
macOS construction and final-image validation cross-check `LC_BUILD_VERSION`
against the authenticated catalog baseline; and a fresh current-source macOS
kit passes the complete installed-user matrix. Its final source-stable
successor is identified in the newer inspection-completeness checkpoint above.
Remaining v1
criteria require publication/signing/reproducibility evidence or the §12 author
decisions rather than further local producer implementation.)
**Revised:** 2026-08-02 (producer correctness checkpoint: default compilation
now lists every guarded unsupported site while preserving invocation-time
semantics, and `--deny-unsupported` refuses the same deterministic inventory;
CompilePlan is fixed before HBC production, final assembly self-admits its inner
contracts, policy/native graph divergence fixtures are explicit, and inspection
derives its engine expectation from authenticated StubContractV3 rather than
the carrier under inspection. The installed-user macOS matrix is green with
these gates.)
**Revised:** 2026-08-02 (Linux release-baseline and reproducibility checkpoint:
an Ubuntu 22.04/GLIBC 2.35 builder produced the final static-network ELF, and a
fresh recipient root with only that executable passed real Fetch without
Ibex, Hermes, source, catalog, or cache. Two physical Jammy builders produced
identical catalog, contract, policy-toolchain, native-stub, compile-plan, and
unsigned-application identities; the full release-kit matrix passed on both.
Random contract paths, filesystem-order Cargo directives, upstream `ring`
watch order, native timestamps, and Hermes-embedded absolute carrier paths are
now normalized, and CI has duplicate clean jobs plus a strict comparator.
Publication, a matching macOS two-builder receipt, precommitted budgets, and
the open author decisions remain.)
**Revised:** 2026-08-02 (M4 application-process checkpoint: the authenticated
V2 contract and inspection report now carry an exact target backend inventory;
the macOS and Linux release-kit gates prove Fetch and a loopback `node:http`
server through compiled target backends, authenticate the WebSocket
implementation, and prove stable HTTP/2, inspector, WASI, and worker
limitations, foreground and detached
failure status, unhandled rejection status, `process.exit`/`exitCode`, and
SIGINT/SIGTERM/SIGHUP status with bounded output flush. A raw invalid UTF-8 argv
field now refuses before entry and names its zero-based index on both tuples.
Async graph records remain alive through referenced callback quiescence. M4 is
complete for the ambient v1 product on both target tuples; a future
successfully advertised CapSec lifecycle path remains outside that release
claim.)
**Revised:** 2026-08-01 (M5 producer-packaging checkpoint: each release kit
now carries a target-bound, content-addressed closed inventory containing the
exact Bun runner, policy-authoring JavaScript, CapSec inputs, and package
closure. Release `ibex` admits only its compiled-in adjacent digest and never
falls back to a checkout or ambient runner. Checkout-poisoned macOS and Linux
gates pass; missing-toolchain refusal is proved. A candidate Linux kit also
produced a two-module TypeScript Fetch executable from an isolated installation
that was removed before the executable ran on a second Ubuntu host with no
Ibex/Hermes installation. Official publication/GLIBC 2.35 receipts,
two-builder evidence, and budgets stay open.)
**Revised:** 2026-08-01 (M3 module execution and final-image refusal matrix:
relocated macOS and Linux executables now cover ESM, CommonJS, builtins,
literal and computed dynamic import, and TLA; corrupting every load-bearing
section independently refuses before the sentinel observes any carrier
evaluation.)
**Revised:** 2026-08-01 (the installed-user release-kit gate now passes on
both v1 host tuples after catalog installation and source/catalog withdrawal;
the Linux final envelope completes real HTTP Fetch through its statically
linked backend, explicit `.mts` retains Module source goal, and authenticated
top-level-await HBC executes through the asynchronous compiled graph; the
official GLIBC 2.35, remaining M3/M4 matrix, and M5 evidence stay open)
**Revised:** 2026-08-01 (implementation checkpoint: the M0 gate, canonical
catalog assembler, derived release contract, V2 contract/envelope rotation,
catalog-pinned public producer, dual-mode pre-init dispatch, authenticated
inspection, and real relocated/offline macOS arm64 and Linux x86-64 HBC
executables now land; the official Linux GLIBC 2.35 builder and the remaining
M3–M5 matrix evidence stay open)
**Revised:** 2026-08-01 (Linux ambient-network register item 2 resolved by
the flagship Snapback CLI use case: v1 requires Fetch networking, reuses the
existing Linux libcurl Fetch/WebSocket bridge, and closes libcurl plus TLS
statically inside the release stub; the final-image audit rejects dynamic
libcurl and proves the static backend is present)
**Revised:** 2026-08-01 (round-3 delta review, **applied after the round budget
closed and therefore NOT re-reviewed**: the contract and envelope rotations are
both named and made consistent — `StubContractV2` and
`ibex/single-file-executable/2`, replacement not migration; the lockstep
ordering is qualified to the first non-provisional catalog so it no longer
reads against §4 item 6; the amendment inventory records that LLP 0029's wire
identities change; milestone 0 item 5 states the five files land in one commit)
**Revised:** 2026-08-01 (round-2 delta review: the boot-mode contract is
corrected — a digest authenticates bytes but does not reveal them, so the
canonical contract is embedded as a new digest-checked envelope section and
named `StubContractV2` rather than extending a strict V1 in place; §12 item 3
is restated as a pre-release ratification of a decision §1 makes, not an open
question, resolving a cluster-wide ambiguity; §9 gains criteria for register
items 1 and 3; catalog sequencing takes the provisional-then-re-cut option;
pre-init becomes the single authoritative mode source)
**Revised:** 2026-08-01 (round-1 dual review: the amendment scope now names
every document the posture change actually reaches — LLP 0031's release
coupling and LLP 0022's compiled-program environment exception join LLP 0029
and LLP 0039, with milestone 0 owning the edits; boot mode and selector
semantics become authenticated contract fields rather than undocumented stub
behavior; the mandatory production-policy authoring step, the Linux ambient
network asymmetry, and the ambient recipient's disclosure surface are stated
and, where they are product calls, registered in a new §12 decision register)
**Related:** LLP 0022 (armed `process.env` classification; compiled-program
exception scoped by §Summary/M0); LLP 0029 (single-file executable
architecture); LLP 0031 (v1 platform matrix; SFE release coupling amended by
§Summary/M0); LLP 0034
(Hermes ES6 block-scoping mode); LLP 0035
(portable engine provenance); LLP 0038 (enforcement-off mechanics); LLP 0039
(secure/insecure product modes); LLP 0048 (restricted external-script
admission and broker ABI); issues/20260717-sfe-compile-cli.md;
issues/closed/20260717-sfe-hbc-production-wiring.md;
issues/20260717-sfe-static-hermes-macos.md;
issues/closed/20260731-hermesc-recipe-missing-es6-block-scoping.md

## Summary

Finish and ship `ibex compile <entry> -o <executable>` by separating the
standalone product milestone from completion of the CapSec advertisement
program.

A v1 standalone executable contains both boot postures:

1. **Ambient compatibility mode is the default.** It runs the embedded program
   with the ordinary authority of the user launching the process. Capability
   enforcement is off. This is the expected posture for short, authored
   scripts and is not represented as a sandbox or security boundary.
2. **CapSec is an explicit runtime opt-in.** The same file can be launched with
   its reserved CapSec selector. That path performs disk-free arming from the
   embedded policy and graph and requires a verified target advertisement.
   Missing, stale, or incompatible CapSec material refuses before application
   code; it never falls back to ambient execution.

Envelope integrity, graph/carrier admission, embedded-policy admission, HBC
compatibility, provenance, and platform layout checks apply in both modes.
“Ambient” removes capability policy *enforcement*; it does not turn off
package-format authentication, does not skip structural and identity
validation of the embedded policy section, and does not permit runtime module
discovery outside the embedded graph. The distinction is exact: ambient boot
performs every admission check that establishes *what the artifact is*, and
performs none of the decisions that establish *what the program may do*.

### What this plan amends

The posture change reaches four documents, and this plan owns all four rather
than the two it originally named:

- **LLP 0029** — release sequencing (§7 register item 4), the compiled-mode
  authority section, and — as of §5 — the **stub-contract and envelope wire
  identities**, now `StubContractV3` and
  `ibex/single-file-executable/2`. LLP 0029 remains the normative owner of both
  formats, so its §2a/§2b/§3 text is scoped rather than left describing the
  superseded V1 layout.
- **LLP 0039** — product defaults and the acceptability trip-wires, already
  revised.
- **LLP 0031** — its release coupling ("If either selected tuple lacks a
  verified CapSec advertisement at release time, 0.2 waits"; SFE catalog
  population following the same two tuples with verified advertisement as
  required evidence) forbids exactly what §9 schedules. The amendment is
  narrow and does **not** touch 0.2 source execution: the coupling still
  governs `ibex run`/eval/REPL on both tuples, and lifts only for the
  standalone ambient path. LLP 0031's unadvertised-tuple refusal language is
  scoped likewise, so it is not read as forbidding ambient compiled boot.
- **LLP 0022** — its "Compiled-program exception" describes LLP 0029
  executables categorically (earliest-hook capture, sanitized real
  environment, broker-gated reads, "never exposes the sanitized real
  environment"). Under this plan that describes the CapSec path only; the
  default path deliberately exposes the inherited environment with no broker.
  A scoping sentence, not a rewrite.

Both edits are landed with this revision rather than deferred, because until
they land the corpus contains a Decision and a Spec that contradict this plan.

This plan does not change the default posture of the general
`ibex run`/`eval`/REPL binary.

### Relationship to app-bound external scripts

This plan finishes the general **one embedded entry** executable. It does not,
by itself, implement Snapback LLP 0062's `run analysis.ts`. LLP 0048 owns that
separate post-admission extension: the trusted embedded parent reads one
bounded local `.ts`/`.js` file or stdin stream as data, hashes and attributes
it, applies LLP 0028's import-free erasable-only profile, and starts a fresh
mandatory-enforced broker-only worker.

The distinction is load-bearing. The embedded parent may retain ambient
authority under this plan; the external worker may not. A successful M0–M5
standalone matrix therefore proves only the outer parent. It cannot be cited as
evidence for restricted source ingress, broker non-transmission, worker policy,
Node/Ibex host parity, or worker lifecycle/resource limits. Those claims begin
only when LLP 0048's acceptance suite passes on the exact artifact and tuple.

## 1. Product decision

### One artifact, two modes

The distributed application is one executable. It is not necessary to produce
separate “secure” and “insecure” files or to choose a permanent posture at
compile time.

The v1 invocation contract is:

```text
./app [application arguments...]                 # ambient compatibility
./app --ibex-capsec [application arguments...]  # CapSec, fail closed
./app --ibex-info                               # authenticated information, no entry evaluation
./app -- --ibex-capsec [...]                    # literal application argument
./app -- --ibex-info [...]                      # literal application argument
```

The stub recognizes `--ibex-capsec` and `--ibex-info` only as the first
argument. A leading `--` ends stub option parsing and is removed before
constructing application `process.argv`. Every other argument, including
later occurrences of either spelling, belongs to the application. These two
words are the complete exception for the general StubContractV3/envelope-V2
profile to LLP 0029's earlier “all argv belongs to the application” rule. LLP
0048 adds no stub-reserved selector: `run <source>` remains ordinary
application argv interpreted by the one trusted embedded parent, and its v1
worker is an in-process dedicated runtime rather than a re-exec mode.

The selector is intentionally one-way. There is no `--no-capsec` switch and
no environment variable that silently changes the posture. The stub captures
the selected mode before runtime construction, records it in immutable process
metadata, and exposes it through inspection/diagnostics.

### Ambient means ambient

Default execution makes no confinement claim. The program may use the
launching user's filesystem, inherited environment, network, subprocess, and
other authority to the extent those backends are compiled into the target
stub. The mode is appropriate for code the distributor is willing to run with
that authority. Bundling third-party or generated code does not become safe
because it is embedded in one file.

**Eligibility boundary.** The threat model has not changed; the *distribution
context* has. A capability sandbox principally defends against code the
distributor did not write, and nothing here weakens that claim — ambient mode
simply does not make it. What changes is who bears the risk: the distributor
chooses ambient and can audit the embedded graph; the recipient inherits that
choice and typically cannot. That asymmetry is the genuinely new exposure, and
it is why §8 requires the artifact to describe its own posture.

This is narrower than LLP 0029's framing of the feature as suiting "any Ibex
program" and agent-facing tools generally. Where an ambient artifact would go
to recipients who cannot audit the graph *and* would reasonably assume
confinement, the honest answer is to wait for the CapSec path, not to ship
ambient with a disclaimer. Ambient-by-default is a judgment that this case is
rarer than the short-authored-script case — not that the sandbox was
unnecessary. That judgment is **made here**, not deferred; register item 3
(§12) ratifies it once against a working end-to-end artifact before v1 ships.

The release stub must not reuse the development-only `insecure` Cargo feature
as an accidental build configuration. Instead it carries a deliberate
compiled-application boot mode using the same enforcement-off runtime
mechanisms where appropriate. This keeps the ordinary Ibex CLI's build posture
and CI matrix unchanged while making the standalone artifact's runtime choice
explicit and testable.

### CapSec remains real when selected

CapSec opt-in is not “best effort.” It retains LLP 0029's disk-free arming,
embedded policy and graph binding, protected-artifact admission, bootstrap
seal, mount vocabulary, environment profile, and target-advertisement gate.
Until a target is advertised, `--ibex-capsec` is expected to refuse with a
stable diagnostic naming the unavailable target. That refusal does not block
shipping or using the default ambient mode.

**The trust model does change, and this plan states it rather than implying
it.** Everywhere else in Ibex, enforcement-off is a *compile-time choice*:
`insecure` is a non-default feature and promotion builds spell
`--no-default-features`, so an ordinary binary offers **no runtime-selectable
route to enforcement-off** (the accurate property — the armed constructor is
compiled unconditionally; `insecure` selects a different one, so this is not
literal code absence). One artifact with two modes gives that up by
construction — every standalone binary ships the complete enforcement-off
machinery, and `--ibex-capsec`'s guarantee rests on pre-runtime dispatch
integrity rather than on the other path being absent.

That reduction in defense depth is accepted deliberately: enforcement is
in-process either way, so subverting dispatch is no easier than subverting
enforcement; the selector is one-way and captured before runtime construction;
and two separate files would move the failure into distribution, where picking
the wrong file is easier and less detectable. The compensating requirements
are fixture-proven monotonic dispatch (§5) and an authenticated — not merely
reported — mode (§5, §8).

The first successful CapSec launch remains the v1.1 milestone described by
LLP 0029. Adding it later is compatible with already-authored source programs,
but may require rebuilding the executable to embed a newer stub contract,
catalog, policy, or advertisement.

## 2. Current state

The repository now has the structural and two-host end-to-end pieces:

- public `compile` and `inspect-executable` command grammar;
- `ibex/single-file-executable/2` envelope and footer/segment layouts, with an
  authenticated canonical `StubContractV3` section;
- path-independent embedded graph, candidate-table, entry, carrier, policy,
  and provenance sections (the compile plan is a field of the provenance
  section, not a section kind of its own);
- a canonical content-addressed catalog assembler, derived contract builder,
  and compile-time-only release catalog pin;
- whole-graph catalog compilation to per-module HBC carriers;
- a compiled-stub crate with shared graph/carrier/policy admission, immutable
  pre-init ambient/CapSec dispatch, and event-loop driving;
- non-evaluating internal inspection of authority and provenance;
- macOS arm64 and Linux x86-64 target contracts.

The product path is reachable on macOS arm64 and Linux x86-64: a release `ibex`
pinned to an addressed catalog compiles real TypeScript/HBC executables; copied
files run with source and catalog unavailable; ambient argv/environment/timer/
exit semantics, explicit `.mts` top-level await, and real HTTP Fetch work; and
`--ibex-capsec` refuses before entry evaluation because the contract
deliberately carries no advertisement. The Linux final ELF has now passed the
closed dependency/ISA audit at the release baseline's truthful
`linux-glibc-2.35-x86-64-v1` floor, with the static libcurl/TLS implementation
retained. A fresh Ubuntu 22.04 recipient root containing only the executable
completed a real loopback Fetch and had no Ibex, Hermes, source, catalog, or
cache. Two physical Jammy builders also produced exact catalog, contract,
policy-toolchain, native-stub, compile-plan, and unsigned-application
identities, and both artifacts passed the complete release-kit matrix. The M3
language/module and final-envelope tamper matrix and the M4 process/backend
matrix are green on both target tuples. The two-clean-builder macOS comparison
also passes, and all §12 decisions are resolved. Remaining ambient-v1 work is
publication and reinstall from the published artifacts, the macOS notarization
ticket, precommitted performance budgets and measurements, and durable clean
CI receipts for the published revision.

The repository now contains the app-bound catalog/contract formats,
source-admission and parent bridge, restricted-worker runtime and broker
lifecycle, policy/evidence fixtures, reporting, and public compile surface
specified by LLP 0048. Complete host-portable acceptance and exact-tuple
advertisement evidence remain independent open work; no “complete” M0–M5 row
below implies that gate. The
app-bound profile deliberately rotates the strict formats to StubContractV4,
envelope V3, catalog V2 plus its target-specific restricted-worker
advertisement/evidence artifact, CompilePlanV2, PackageProvenanceV2,
executable inspection V4, and standalone-info V2. Stub V4 selects info V2 and
the catalog/stub/plan/report chain cross-binds the advertisement digest. Those
are not retroactive changes to this plan's general StubContractV3/envelope-V2/
catalog-V1/inspection-V3/info-V1 finish line.

### Implementation checkpoint — 2026-08-02

- **M0:** complete. `scripts/check-sfe-foundation.sh` is a named CI gate; the
  format, catalog, producer, compiled-stub, and catalog-compiler suites are
  green, including real Hermes closure/loop HBC execution with
  `-Xes6-block-scoping`.
- **M1:** implemented on macOS arm64 and Linux x86-64 with final V2 identities
  rather than a throwaway V1 cut. Catalog
  construction self-admits every artifact and stages it content-addressably;
  the release binary accepts no runtime catalog-trust override. A release-kit
  builder now emits the catalog-pinned `ibex`, an equally pinned
  `ibex-sfe-catalog` installer, and the exact target catalog archive. The
  installer fully admits and atomically publishes only its compiled-in pin,
  and missing-catalog diagnostics name the exact archive and install command.
  The Ubuntu 22.04/GLIBC 2.35 builder/recipient proof and a two-physical-builder
  exact-identity proof are green. Publishing both official kits, obtaining the
  macOS two-clean-builder receipt, and exercising the configured clean-job
  comparator on a pushed commit remain.
- **M2:** the shipped V2 contract authenticates the ambient default, exact
  first-position selector, escape rule, and empty advertisement identity.
  Pre-init is the sole mode authority. Both modes share bulk admission;
  ambient constructs the deliberate compiled enforcement-off host, while a
  CapSec request never falls back. A fixture-only successful advertisement
  and denied-effect proof remains.
- **M3:** genuine macOS and Linux HBC executes after relocating the file and
  making both source and catalog unavailable. Explicit `.mts` is preserved as
  Module input, its authenticated TLA fact selects the asynchronous compiled
  graph, and a relocated TLA executable settles successfully on both tuples.
  A second relocated graph covers ESM, CommonJS, builtin imports, literal
  dynamic import, and authenticated computed dynamic import. The release gate
  corrupts every singleton, candidate table, carrier manifest, and carrier
  payload in the final image independently; inspection and launch both refuse,
  and an ambient sentinel proves no module evaluated, including when only the
  unselected candidate carrier was corrupted. The M3 matrix is complete.
- **M4:** complete for ambient v1 on both release tuples. Basic argv,
  environment, timers, stdout, numeric exit status, and standalone relocation
  are demonstrated on both tuples. A raw invalid UTF-8 OS argument refuses
  before entry evaluation and names its zero-based index on both. The
  authenticated V2 contract records the exact backend implementation and
  status for every supported surface, and
  `inspect-executable` reports it without evaluating application code. Both
  final artifacts prove Fetch through the advertised macOS NSURLSession and
  Linux static-libcurl implementations plus a loopback `node:http` server over
  POSIX sockets. They authenticate the target WebSocket implementation and
  prove the stable limitations for unavailable HTTP/2, inspector, WASI, and
  worker surfaces. Foreground exceptions,
  detached timer exceptions, and unhandled rejections exit 1; `process.exit`
  and numeric `process.exitCode` preserve their selected status and flushed
  output. A dedicated POSIX signal coordinator handles SIGINT, SIGTERM, and
  SIGHUP with statuses 130, 143, and 129 after a bounded output flush even if
  the engine thread is busy. Async graph records remain retained until
  referenced work reaches quiescence so imports used after Fetch/TLA remain
  valid. The process-semantics ticket is closed; the future successful
  advertised-CapSec lifecycle path remains v1.1 work and does not change the
  ambient v1 M4 result.
- **M5:** authenticated inspection, first-compile disclosure, and Mach-O
  signing order are implemented. The Linux final image passes a truthful
  GLIBC 2.35 dependency/ISA receipt with static libcurl on an Ubuntu 22.04
  release-baseline builder. A relocated source/catalog-free final envelope also
  completed a real HTTP Fetch through that static backend.
  The release kit now packages its exact Bun runner, policy-authoring code,
  CapSec inputs, and package closure as a target-bound, content-addressed
  closed inventory. Release `ibex policy generate` admits only the adjacent
  digest compiled into that binary; it does not consult `IBEX_REPO_ROOT`,
  `PATH`, or an ambient JavaScript installation and does not fall back when
  the packaged tree is absent. Both host gates exercise that path with an
  empty environment and poisoned checkout pointer. A candidate Linux kit was
  first proved on an isolated Ubuntu 24 producer/recipient pair. The official
  baseline was then repeated from an Ubuntu 22.04 builder into a fresh Ubuntu
  22.04 recipient root: only the final executable crossed the boundary, and it
  fetched through its static backend and exited successfully with no producer,
  source, catalog, or cache present. Two physical Jammy builders produced the
  same native stub and, after the fixed carrier recipe was rebuilt, the same
  unsigned application identity; both full matrices passed. CI now expresses
  that comparison as two clean jobs per tuple and a strict identity gate.
  Publication of the exact installation artifacts, the macOS two-builder CI
  receipt, precommitted size/startup evidence, and the open §12 author
  decisions remain release work.

## 3. Milestone 0 — restore a green foundation

Before adding mode selection:

1. Repair `ibex-compiled-stub` against the current carrier API and add it to a
   normal workspace/CI check so interface drift cannot recur silently.
2. Add `-Xes6-block-scoping` to every catalog `hermesc` recipe that emits
   executable HBC, matching LLP 0034, with a closure-capturing `for-of`
   execution fixture.
3. Run and retain the SFE format/catalog/stub tests as one named gate.
4. Reconcile the open SFE filesystem tickets against current code, closing
   completed scaffolding tickets and rewriting their remaining criteria around
   this plan rather than the former CapSec-first release gate. The umbrella
   ticket `issues/20260717-sfe-program.md` still carries register item 4 in its
   original 2026-07-18 "0.2 waits for verified advertisements on both tuples"
   form, two re-resolutions stale; the sweep includes it.
5. The corpus amendments this plan owns (see §Summary) are written and land
   **with this plan's own commit**: LLP 0031's SFE release coupling and
   unadvertised-tuple refusal language are scoped, LLP 0022's compiled-program
   exception is scoped to the CapSec path, and LLP 0029 is scoped for the V2
   contract/envelope rotation. All five files must land together; a partial
   commit leaves the corpus contradicting itself.

**Exit:** format, catalog, producer, and compiled-stub crates compile and test
from a clean checkout; the fixed HBC recipe executes the semantic regression;
no LLP in the corpus still asserts the superseded advertisement-first release
gate or the categorical compiled-environment exception.

## 4. Milestone 1 — publish a real release catalog

Make the existing catalog-backed producer reachable without a developer-only
escape hatch:

1. Build exact stub, `StubContractV3`, and `hermesc` artifacts for
   `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`.
2. Produce a canonical catalog, pin its digest into the release `ibex` binary
   at build time, and publish/install its addressed artifact directory.
3. Keep the trust root compile-time only. Do not add a CLI or environment
   override for the catalog digest.
4. Exercise compiler/stub/HBC-version substitution refusals against the real
   catalog entries.
5. Make missing catalog installation actionable: the diagnostic names the
   exact release artifact or fetch/install command rather than only a cache
   directory.
6. Sequence the catalog against milestone 2. Catalog entries bind the exact
   stub-core digest and the release `ibex` embeds the catalog digest, so
   milestone 2's change to compiled boot behavior — and milestone 2's
   stub-contract rotation and new envelope section — necessarily rotate the stub, the
   contract, the catalog, and the producer's compiled-in pin. **Milestone 1's
   catalog is therefore explicitly provisional if it is cut before dispatch,
   and is re-cut at the end of milestone 2.** The implementation instead cut
   the first exercised catalog directly after V2 dispatch landed. The
   alternative, deferring the first catalog until dispatch
   exists, is circular: milestone 2's own exit needs a built executable, and
   packaging can only produce one from catalog artifacts — which would mean
   reaching for the developer-only escape hatch milestone 1 exists to remove.
   Cutting twice is the cost of keeping every milestone exercisable through
   the real producer path.

### The mandatory policy artifact is the flagship flow's real friction

Every compile — including the ambient-default flow this plan is built around —
requires an authored, committed, registry-bound `purpose: production,
mode: enforce` CapSec policy. LLP 0029 §1 step 2 mandates it, the envelope
structurally requires a singular resolved-policy section, and the producer
refuses without one, directing the user to run `ibex policy generate` and
commit the result. Compiling never generates policy silently, by design.

The consequence is blunt and was previously unstated: **v1's "compile a short
script" story requires authoring a full CapSec policy artifact that the default
mode will never enforce.** The exit criterion below and §8's "install one
release `ibex`, compile a short program, copy it, run it" were both written as
though this step did not exist. It does, and it is the largest usability
obstacle between here and a credible standalone product.

Register item 1 resolves this to explicit policy authoring. The friction is
owned rather than hidden: milestone 1's exit and the standalone guide record
the verbatim policy-generation and compile sequence. The producer continues to
refuse a missing policy and never generates one silently.

**Exit:** a clean release `ibex` can compile a multi-module TypeScript fixture
using only the pinned catalog and produces byte-identical unsigned output on
two clean builders for each tuple; the complete new-user command sequence
including policy authoring is recorded verbatim.

## 5. Milestone 2 — dual-mode compiled boot

Replace the compiled stub's unconditional release refusal with an immutable
pre-boot mode dispatch.

### Mode must be an authenticated contract field, not stub behavior

`StubContractV1` today binds engine identity, ABI and schema versions, target,
transform profile, and the generated semantic digests; `PackageProvenanceV1`
and the catalog entry bind artifact digests. None carries the default boot
mode, the selector spelling, or which CapSec evidence the stub contains. If
that stays true, §8's requirement that inspection report the default mode is
satisfiable only by trusting undocumented stub behavior — reporting a property
of the binary it cannot authenticate, on the axis that determines whether the
artifact enforces anything.

Milestone 2 therefore adds the boot-mode contract: default mode, the reserved
selector spelling and its position rule, and the CapSec-advertisement identity
the stub was built against (empty is a legitimate value and must be
represented distinctly from absent).

Two mechanical constraints follow, and an earlier draft of this section got
both wrong:

- **Milestone 2 introduced `StubContractV2`, not an extension of V1.** The V1 contract
  is strict `deny_unknown_fields` with a fixed `ibex/stub-contract/1` schema
  string and `ibex:stub-contract:1` digest domain. Adding required fields is a
  versioned schema change by LLP 0029's own rule, not an in-place edit. Since
  no catalog has shipped, V1 is **replaced outright rather than migrated** — no
  compatibility shim, no dual-version parser — and that replacement must land
  in lockstep before the first **non-provisional** catalog is cut. It does not
  forbid milestone 1's explicitly provisional V1 catalog (§4 item 6), which
  exists precisely so the producer path can be exercised before V2 lands.
  Register item 4 subsequently adds a second required selector and an
  authenticated information-report schema. That is another strict wire
  change, so the current identity is **`StubContractV3`** with schema
  `ibex/stub-contract/3` and digest domain `ibex:stub-contract:3`; unshipped V2
  is replaced rather than parsed alongside it. Envelope V2 does not rotate:
  it already carries an opaque digest-pinned stub-contract section and gains no
  section kind, layout field, or closed-enum value from this change.
- **A digest authenticates bytes; it does not reveal them.** Compiling the
  contract digest into the stub and pinning it in the envelope lets boot
  compare two constants, which is sufficient for *boot*. It is not sufficient
  for *inspection*: the contract is a catalog artifact, the envelope has no
  contract section, and a recipient inspecting a copied file has only the
  digest. Reporting "this executable is ambient-default" from a digest alone
  is impossible. Milestone 2 therefore also embeds the **canonical contract
  bytes as a new digest-checked envelope section**, admitted in the bulk
  preflight against the pinned digest like every other section (the pin already
  exists in the envelope directory). **This is envelope V2 —
  `ibex/single-file-executable/2` — on the same reasoning that forces
  the then-current `StubContractV2`, applied consistently.** The section-kind vocabulary is a
  closed enum inside a fixed `/1` schema, so a parser built for V1 rejects the
  new kind; that is a wire-identity change however cheap it is today. As with
  the contract, nothing has shipped, so V1 is replaced rather than migrated.
  Both rotations land together with the format work; neither is assumed to
  exist.

Without the embedded section, authenticated mode reporting — the compensating
control this plan leans on in §1 and §8 — is not implementable.

This also gives §10's "changing the default later is a versioned product
decision" a mechanism: a default reversal rotates the contract digest, which
rotates every catalog entry, which is precisely the visible, versioned change
the deferred-work section says it should be. Without the field, a default
reversal would be an invisible behavioral change to an identically-identified
artifact.

### Ambient path

1. Admit the self-file, platform layout, envelope, compile plan, graph,
   candidate tables, policy, entry, and every HBC carrier exactly as the
   secure path does. "Exactly" is literal and includes the policy section's
   *semantic* validation against the compiled-in capsec registry and the graph
   identity, not merely a digest check over opaque bytes — which is what the
   shared admission path already does today, before the refusal point this
   milestone replaces. Ambient boot must refuse a structurally valid envelope
   whose policy does not bind the graph it ships with, even though it will
   never evaluate that policy. Keeping admission literally shared, rather than
   parallel, is what makes the CI guard in §11 meaningful.
2. Construct the enforcement-off compiled Host and ordinary runtime backend
   set; do not synthesize target evidence or claim that policy decisions ran.
3. Project application argv, inherited environment, cwd, and host access with
   ordinary non-sandboxed semantics. This collides with the stub's existing
   pre-init environment shim, which captures and then **unconditionally
   scrubs** the real process environment before Rust `main` runs, while the
   mode is determined by argv. Both guarantees must survive: CapSec's sanitize
   step must still precede every constructor under Ibex's control (LLP 0029
   §4), and ambient must still hand the program the environment it inherited.
   The selector must therefore be read during pre-init — the platform
   init-array/constructor entry receives `argc`/`argv` on both v1 tuples — so
   the shim scrubs only on the CapSec path. Restoring a scrubbed environment
   after the fact is not an acceptable substitute: it would leave a window in
   which constructors observe the sanitized environment in ambient mode, which
   is the mirror of the bug the shim exists to prevent. The pre-init
   determination is the **single authoritative mode source**: boot dispatch
   consumes what pre-init decided rather than re-deriving it from argv, so the
   two cannot disagree on, say, byte-comparison versus Unicode-decode rules for
   argv[1]. Two independent argv reads would reproduce exactly the
   constructor-observes-the-wrong-environment bug this paragraph exists to
   prevent. Constructor-ordering probes cover both modes.
4. Resolve modules only from the admitted embedded graph. Ambient authority is
   not permission to read replacement source or discover new runtime modules.
5. Record `ambient-compatibility` in process diagnostics and
   `inspect-executable` output.

### CapSec path

1. Consume the embedded graph/policy and construct the disk-free armed Host.
2. Require a target advertisement compatible with the exact catalog/stub/
   engine tuple.
3. Refuse before entry evaluation when any prerequisite is absent or stale.
4. Prove by fixture that every CapSec-path failure terminates rather than
   retrying the ambient path.
5. Record `capsec-requested` plus `admitted` or the stable refusal reason in
   diagnostics; inspection reports availability without executing the app.

**Exit:** the same executable runs a fixture in ambient mode and refuses that
fixture before entry evaluation under `--ibex-capsec` while no advertisement
exists. Once a test advertisement is supplied in a fixture-only build, the
same CapSec path arms and enforces a denied effect. The provisional milestone-1
catalog is re-cut against the current `StubContractV3` and envelope V2, and the
producer's compiled-in pin is rotated to match.

## 6. Milestone 3 — real HBC envelope execution

Close the largest evidence gap in the current implementation:

1. Compile and run a real catalog-populated release envelope on macOS arm64.
2. Compile and run the equivalent real envelope on Linux x86-64.
3. Cover ESM, CommonJS, a builtin edge, TypeScript lowering, computed dynamic
   import candidate tables, top-level await, timers, stdout/stderr, and a
   nonzero `process.exitCode`.
4. Delete the source tree and catalog after compilation before launching the
   produced file; runtime success must depend only on the executable and
   ordinary system libraries allowed by its target contract.
5. Mutate each load-bearing section and prove bulk preflight refuses before
   any carrier evaluates.
6. Run the same fixture in both ambient and CapSec-selected modes. Differences
   must be attributable only to authority/posture, not module or language
   semantics.

**Exit:** genuine HBC executes from genuine release envelopes on both v1
tuples, including relocation and source-deletion tests.

## 7. Milestone 4 — application process contract

The first useful release needs a bounded but honest process surface:

- application argv and the two reserved first-position selector rules above;
- inherited environment/cwd in ambient mode and LLP 0029's brokered contract
  in CapSec mode;
- timers and referenced async work driven to quiescence;
- uncaught exception/rejection failure status;
- `process.exit` and numeric `process.exitCode`;
- bounded stdout/stderr flush before orderly termination;
- SIGINT, SIGTERM, and SIGHUP with conventional signal-derived status —
  matching LLP 0029 §6's normative LLP 0025 rows, which include SIGHUP; an
  earlier draft of this list omitted it and the omission was not a decision;
- stable errors for unavailable compiled backends.

The target stub contract records its backend inventory. v1 should aim to match
the ordinary `standard` runtime feature closure. Any omitted backend is an
explicit target-contract limitation, visible in inspection and release notes,
not a CapSec denial and not a silent no-op.

### The Linux ambient network gap must be decided, not inherited

Register item 2 is resolved to the static-backend option. Snapback CLIs are the
flagship first standalone workload and require Fetch on Linux; a networkless
Linux artifact would not satisfy that use case. The release-stub profile
therefore reuses Ibex's existing libcurl Fetch/WebSocket bridge and selects a
pinned Cargo-built static libcurl and TLS closure. The ELF audit rejects
dynamic libcurl and other non-system dependencies and proves that the static
backend symbol is present. Static libcurl uses the target OS's maintained CA
bundle rather than embedding an independently aging root set.

This resolves an asymmetry that existed when the plan was accepted. The Linux
release-stub profile compiled fetch and WebSocket out entirely and kept
libcurl absent from the image, while macOS had a working NSURLSession-backed
fetch. LLP 0029 §2a had justified the Linux omission by CapSec state — "the
current compiled CapSec projection advertises no network authority" — with the
trigger for adding a backend being "a future compiled target that advertises
network authority."

Without the resolution above, that rationale would be dangling: advertisement
no longer gates the shipped artifact, and the default is ambient. The ambient
v1 story would be **networking works on macOS and does not exist on Linux** —
not a capability nuance, since a fetch call is among the first things a short
script does, and on Linux it would fail with a backend-unavailable error
unrelated to capability policy.

The product evidence now decides this: v1 does not ship a Linux ambient
artifact whose only network story is a stable error. Register item 2 (§12)
selects the first of the two original options:

1. Bring a vendored or statically linked backend into the Linux stub and pass
   the same final-image ELF audit LLP 0029 §2a requires of it; or
2. ~~Ship Linux ambient v1 without network, stated in that exact language in the
   command help, the standalone guide, `inspect-executable`'s backend
   inventory, and the release notes — not discovered at runtime.~~ Rejected:
   it does not support the flagship Snapback CLI workload.

The old state — where the omission was justified by a CapSec condition this
plan removed — is not an acceptable release posture; the static profile
replaces it.

**Exit:** end-to-end fixtures cover every row above on both tuples; inspection
reports the exact backend inventory; the Linux network disposition is recorded
and matches what the shipped image actually contains.

## 8. Milestone 5 — distribution and usability

1. Make `ibex compile` discoverable and document the default ambient authority
   in the command help and standalone guide.
2. On the first compile in a terminal, print one concise notice that the
   output defaults to ambient authority and name `--ibex-capsec`; do not print
   a development “unsafe build” banner every time the distributed app runs.
3. `inspect-executable` must report:
   - default mode and selector contract, as authenticated contract fields
     (§5), not as inferred stub behavior;
   - whether the embedded tuple can currently satisfy CapSec admission;
   - envelope/graph/HBC integrity state;
   - backend inventory;
   - platform signature and external attestation independently.
4. Close the recipient's disclosure gap.
   Every disclosure surface above belongs to the *distributor*: `ibex compile`
   help, the first-compile notice, `inspect-executable`, and release metadata
   all require either the Ibex CLI or the distributor's own materials. The
   person who receives a copied executable has none of them, and by design the
   app prints no runtime banner. So the artifact that makes no confinement
   claim is also the one least able to say so at the moment it runs.

   LLP 0039's trip-wire 3 conditioned the whole exception on help, inspection,
   and release metadata disclosing the missing sandbox — but under this plan's
   argv contract the *application* owns its help surface entirely. That
   condition cannot be discharged by Ibex, and LLP 0039 is revised to state it
   over surfaces Ibex controls.

   Register item 4 selects the second reserved first-position word:
   `--ibex-info` prints canonical authenticated posture, backend inventory,
   CapSec availability, target, provenance kind, and admission identities,
   then exits successfully without constructing a Host or Hermes runtime and
   without evaluating the program. The same leading-`--` escape passes the
   spelling literally to the application. `StubContractV3` authenticates the
   exact selector rule and `ibex/standalone-executable-info/1` report schema.
5. Produce a signed macOS artifact in the required segment/signing order and
   an audited Linux artifact with no Ibex/Hermes sidecars.
6. Record size and cold-start budgets before final measurement, then publish
   the measured result rather than blocking correctness work on an unstated
   performance expectation.

**Exit:** a user can install one release `ibex`, compile a short program, copy
the resulting executable to a clean compatible machine, and run it without an
Ibex/Hermes installation or source files.

### Implementation checkpoint — 2026-08-02

Items 1–4 are implemented: the compile command and guide disclose ambient
authority, an interactive first compile emits the one-time notice,
non-evaluating inspection authenticates the boot posture, target, integrity,
backend inventory, signature, and provenance views, and the copied artifact
itself exposes the authenticated `--ibex-info` report. A current-source V3
macOS kit passed the complete installed-user matrix with catalog
`sha256-cA5f-buba8t2ubttYvTnlkNI3Eishv9V4wBsA9DoMRQ` and policy toolchain
`sha256-f7rwugejvISlnuSze3nvzIuxnEv3T2SDaN-uYTQ15ZQ`; after relocation and
source/catalog withdrawal, only the copied executable produced a report that
matched external inspection and proved application evaluation stayed false.

Candidate macOS and Linux kits satisfy item 5 functionally. The Linux
milestone exit is proved at the official Ubuntu 22.04/GLIBC 2.35 baseline: a
fresh recipient root ran only the copied final executable, including
static-network Fetch, with every producer input absent. Two physical builders
produced exact Linux identities, and the clean-job form of that comparison is
now encoded in CI. The V3 contract rotation still requires a fresh Linux kit
and matrix receipt before release.

This is not the M5 release receipt. The exact installation artifacts are not
published; the macOS two-clean-builder CI receipt has not passed; the new clean
CI jobs have not run on a pushed commit; and item 6's size/cold-start budgets
and final measurements remain open.

The credential-free part of the macOS signing receipt is now stronger than an
inject-then-sign smoke: malformed signature and layout mutations refuse, and a
completed application survives system-signature removal and replacement with
its authenticated graph and CompilePlan identities unchanged, then runs Fetch
under an ad-hoc hardened-runtime signature after relocation and producer-input
withdrawal. Actual Developer ID signing, secure timestamping/notarization, and the matching-toolchain
second-builder receipt remain distribution evidence rather than local code
gaps.

Inspection also now discharges LLP 0029's outstanding stub-instance check. It
reports `stubCoreConsistency` from a reconstruction and hash of the actual
outer file, and the release matrix mutates that projection independently from
all inner sections. Platform signing remains a separate axis, as shown by the
same identity surviving removal and replacement of the ad-hoc signature.

### Implementation checkpoint — 2026-08-03

The credentialed Developer ID leg now passes through secure timestamping. A
fresh completed standalone carries the hardened-runtime flag, the expected
Developer ID authority and team, and an Apple timestamp; `codesign --verify
--strict`, `ibex inspect-executable`, relocation, and real Fetch all pass.
`spctl` rejects it only as an unnotarized Developer ID application. No local
`notarytool` keychain profile or API-key material is configured, so notarization
remains a publisher-credential action rather than a code change.

The matching Xcode 26.6 physical MacBook Air is reachable. Its independently
built debugger-enabled Hermes archives have the same architecture sets, member
names, member sizes, and every extracted object digest as the primary builder,
but raw archive digests differ. The only observed differences are archive
member timestamps and numeric owner/group fields. Rebuilding each thin slice
with Apple's deterministic `libtool -D`, then recreating the fat archive in
canonical architecture order, makes the real `hermesvm`, JSI, and
Boost.Context inputs byte-identical across the machines. `build-hermes.sh` now
applies that transform before cache publication, its own digest rotates the
source-cache authority, and the SFE foundation gate exercises two synthetic
builders plus idempotence and symbol preservation.

The first full pair of clean release-kit receipts from the newly keyed source
builds passed the complete installed-user matrix independently and agreed on
the contract and packaged policy-toolchain digests. The strict comparator still
refused because the catalog, CompilePlan, stub core, and unsigned file differed.
A byte-level Mach-O comparison found checkout-absolute bootstrap and
generated-runtime JavaScript paths embedded in Hermes bytecode. Those paths
entered because `build.rs` passed absolute source paths to `hermesc`; the two
otherwise matching stubs had the same size but differed in about 2.6 million
bytes and carried different linker UUIDs. The build now changes to the source
directory and passes only its basename, and the foundation gate unit-tests that
compiler argument contract. A direct two-directory Hermes vector produces
identical HBC under the corrected invocation. The next physical invocation also
found an undeclared `rg` dependency in the installed-user verifier on the clean
second Mac; the verifier now uses platform `grep` throughout. Both corrected
kits then passed the installed-user matrix, but their strict comparison exposed
vendored OpenSSL's checkout-absolute Cargo install prefix in `libcrypto` engine
and module directory strings. The release stub now builds in a stable target-
and contract-addressed `/tmp` namespace so equivalent builders give OpenSSL the
same prefix. Fresh full physical receipts are still required before recording
the macOS comparator as passed. The first stable-prefix pair removed every
checkout path and reduced the raw stub difference to 48 bytes: the
independently synthesized 16-byte Mach-O `LC_UUID` plus its dependent ad-hoc
signature bytes. Because the catalog authenticates the stub core directly and
does not use UUID as an authority, the first correction omitted the command and
made the two catalogs identical. Both relocated runtime matrices then refused:
dyld requires `LC_UUID` even though it does not use the value as Ibex release
authority. The release builder now preserves the command but, after removing
the linker's signature, replaces its UUID with an RFC 4122 value derived from
the otherwise complete stub bytes. The normalizer refuses signed, malformed,
fat, missing-UUID, and duplicate-UUID inputs and is covered for convergence and
idempotence.

That final pair used two distinct clean physical arm64 Macs at commit
`2a611b4f4455b1a39013d88e229c0e23f13100cf`, both with Xcode 26.6 build
17F113, SDK 26.5 build 25F70, and Rust/Cargo 1.97.0. Each complete
installed-user matrix passed. The strict receipt comparator passed with no
mismatches across the catalog, contract, packaged policy toolchain,
CompilePlan, stub core, and unsigned file. The shared catalog is
`sha256-TCdWrod4l9HVkiDEDCCY6pIZWhj-3WjWfXOig5C_x8o`; the shared stub core is
`sha256-l50-bX04ZMTR6mTTvyFHYmAuHgnzH45xHQdHD5uzs_I`; and the shared unsigned
file is `sha256-o2i8DnpfuZoxrol10OVCwQR-lFsEaMBe1tvaI_kn884`. The macOS
physical-builder reproducibility criterion is complete.

The first required native-matrix run also exposed two clean-checkout-only
packaging faults. The Ubuntu foundation probe assumed `rg` was installed even
though its runner contract does not provide it, and the repository-wide
`*.o` ignore rule excluded the published `ring` crate's pregenerated Windows
COFF inputs. The probe now uses baseline `grep`, and the exact 17 object files
from the checksummed `ring` 0.17.14 crate are explicitly tracked under
`vendor/ring/pregenerated/`. The standalone drift gate now checks the generated
root-global disposition manifest directly as well, closing the stale-artifact
gap revealed when the authenticated Hermes builder identity rotated.

## 9. Release criteria

The standalone v1 is done when all of the following are true:

- `ibex compile` is reachable from a published catalog-pinned release;
- the compiled-stub and SFE suites are mandatory green CI;
- real HBC release envelopes run on both v1 tuples;
- the default ambient path has no capability-security claim and behaves as
  documented;
- `--ibex-capsec` is present and monotonically fail-closed, even if no shipped
  tuple can yet arm successfully;
- envelope, graph, carrier, and policy admission run identically across modes —
  the same code path, including the policy section's semantic validation, not
  two implementations asserted to agree;
- the default boot mode and both selector contracts are authenticated contract
  fields, so inspection reports them rather than inferring them;
- source deletion and relocation do not affect execution;
- argv, environment, lifecycle, signals, output flushing, and backend
  inventory meet the bounded v1 contract;
- the Linux ambient network disposition is resolved and the shipped image
  matches it (§12 item 2);
- the mandatory-policy disposition is resolved and the documented new-user
  command sequence matches what the producer actually requires (§12 item 1);
- ambient-by-default has been ratified against a working artifact rather than
  only against this design (§12 item 3);
- inspection can explain the artifact without evaluating application code;
- LLP 0031 and LLP 0022 no longer contradict this plan;
- platform distribution checks and precommitted size/startup measurements are
  recorded.

CapSec advertisement completion is explicitly **not** a v1 release criterion.
It is the criterion for claiming that the optional CapSec mode works on a
specific shipped tuple.

LLP 0048 external-worker completion is likewise not a criterion for the
general one-entry standalone v1 release. It **is** a criterion for claiming the
Snapback phase-2 app-bound executable: standalone compilation green alone does
not satisfy that downstream contract.

### Requirement-by-requirement audit — reconciled 2026-08-05

| §9 criterion | State | Evidence or remaining action |
| --- | --- | --- |
| Published catalog-pinned `ibex compile` | **Open — release action** | Checkout-free candidate kits pass; exact installation artifacts have not been published or reinstalled from that publication. |
| Mandatory compiled-stub/SFE CI | **Wired, run pending** | The required foundation gate and duplicate clean release jobs are in `module-loader-baselines.yml`; they have not run for this unpublished worktree. |
| Real HBC on both v1 tuples | **Complete** | Full macOS arm64 and Ubuntu 22.04 x86-64 installed-user matrices pass. |
| Honest ambient behavior/no CapSec claim | **Complete locally** | Help, one-time compile notice, guide, authenticated boot fields, and ambient behavior fixtures agree. Final release notes remain part of publication. |
| Monotonic `--ibex-capsec` refusal | **Complete** | The same artifacts refuse before entry with no ambient fallback; successful advertisement is v1.1. |
| Identical cross-mode admission | **Complete** | Selection occurs after the single envelope/contract/graph/policy/carrier/provenance admission path. |
| Authenticated default/selector fields | **Complete** | `StubContractV3` carries the default, both exact first-position selectors, their shared escape, and the info report schema. |
| Source deletion and relocation | **Complete** | Both tuple matrices run copied executables after source/catalog withdrawal. |
| Bounded process/backend contract | **Complete for ambient v1** | Argv/UTF-8, environment, lifecycle, failures, signals, flush, Fetch, HTTP server, and limitations pass on both tuples. |
| Linux ambient networking | **Complete** | Static libcurl/TLS final-image audit and clean-recipient Fetch pass at GLIBC 2.35. |
| Mandatory-policy disposition | **Resolved — explicit authoring** | The author approved the implemented contract: every compile requires a committed generated policy; no silent minimal-policy path is added. |
| Ambient-default ratification | **Resolved — ratified** | The author ratified ambient compatibility as the v1 default against the working macOS and Linux end-to-end artifacts. |
| Non-evaluating explanation | **Complete** | Inspection v3 admits inner contracts; the artifact's authenticated `--ibex-info` path reports recipient-facing posture/backend/CapSec facts after the same admission and before application evaluation. |
| LLP 0022/0031 reconciliation | **Complete** | Both documents scope the former categorical/advertisement-first gates to the CapSec path. |
| LLP 0048 external-script worker | **Substantially implemented; acceptance/evidence open** | App-bound formats, source admission, parent bridge, restricted-worker construction, broker lifecycle, policy/evidence fixtures, reporting, and compile surface exist. The complete host-portable, planted-secret, lifecycle/ceiling, and exact-tuple evidence gate remains open and is not implied by any M0–M5 completion row. |
| Distribution + precommitted performance | **Open — release evidence** | Credential-free Mach-O minimum/hardened/replacement vectors, Developer ID hardened-runtime signing with secure timestamp, Linux audit, and the strict two-physical-Mac comparator pass. Gatekeeper still requires notarization credentials/ticket. Numeric ceilings are accepted in `config/sfe-performance-budgets.json`; uncontended host measurements against that blob remain. |

Milestone 5's recipient-side disclosure choice is resolved by the authenticated
`--ibex-info` path. Release artifacts must keep its first-position, escape,
no-evaluation, and copied-file-without-catalog fixtures green.

## 10. Deferred work

- successful production CapSec admission and advertised target coverage;
- Windows and x86-64 macOS catalog entries;
- cross-target compilation;
- embedded filesystem assets;
- native addons/FFI payloads;
- multi-entry executables;
- LLP 0048 restricted external-script worker implementation and promotion on
  exact target tuples (specified separately; not a general second entry);
- self-update/installers;
- making CapSec the default for standalone applications.

Changing the default later is a versioned product decision. The mode selector,
inspection fields, and fail-closed CapSec path are designed so that a future
release can change the default without changing the embedded program or
weakening a user who explicitly requested CapSec.

## 11. Risks and follow-ups

- **Expectation risk:** users may assume “single binary” implies sandboxing.
  Help, compile output, inspection, and release notes must say ambient authority
  plainly.
- **Dependency risk:** short scripts can still bundle untrusted packages. The
  default is a compatibility choice, not evidence that dependencies are safe.
- **Mode drift:** both paths share envelope and module admission; CI must run
  both from the same artifact so the CapSec path does not rot unseen.
- **Selector collision:** reserving two first-position arguments is a real
  compatibility cost. The leading `--` escape is mandatory and tested.
- **Backend skew:** a minimal static stub can accidentally look like a CapSec
  refusal when a backend was simply omitted. Inspection and stable error
  classes must keep those cases distinct.
- **Future default reversal:** changing to CapSec-by-default requires a new
  LLP update, migration/release notes, and a deliberate ambient opt-out design;
  it must not be inferred merely because one target becomes advertised. §5's
  boot-mode contract field is what makes such a reversal a visible, versioned
  identity change rather than a silent behavioral one.
- **Recipient-side disclosure:** the copied binary now owns one disclosure
  surface itself: authenticated first-position `--ibex-info`. Distributor help,
  inspection, guide, and release metadata remain required as complementary
  surfaces; the recipient gap described by the earlier draft is closed.
- **Defense-depth reduction:** shipping enforcement-off machinery inside every
  standalone artifact removes the compile-time-absence property the rest of
  Ibex relies on (§1). Accepted deliberately, with fixture-proven monotonic
  dispatch as the compensating control — but it means a dispatch defect is a
  security defect, and the CI guard in the mode-drift risk above must treat it
  that way rather than as a functional regression.

## 12. Author-decision register

None of these blocked starting milestone 0. All four product decisions are now
resolved. Their implementation and audit evidence remain subject to the §9
release gates.

Item 3's status is stated precisely, because an earlier draft left it
ambiguous. Ambient-by-default is **decided** — §1 makes it, LLP 0029 §7 item 4
records it re-resolved, and LLP 0031 and LLP 0039 are amended on its strength.
Item 3 was therefore a **pre-release ratification**, not an open question about
whether to proceed. The 2026-08-02 author approval records that required second
look against real artifacts and closes it.

1. **Mandatory production policy for ambient compiles** (§4) — **decided
   2026-08-02: option (a)**. Own the friction: v1 requires explicit policy
   authoring for every compile, documented plainly. The producer never creates
   a minimal policy silently, because that same policy would become enforced
   authority when the artifact is launched with `--ibex-capsec`. The standalone
   guide records the complete new-user sequence.
2. **Linux ambient network** (§7) — **decided 2026-08-01: option (a)**. The
   flagship outer-parent use case is producing Snapback CLIs, which require
   Fetch on Linux. This establishes parent transport only, not LLP 0048's
   external worker. Reuse the existing libcurl Fetch/WebSocket bridge, build its pinned
   libcurl/TLS closure statically into the Linux stub, and pass the final-image
   ELF audit. Shipping Linux ambient v1 without network is rejected. Evidence
   completed 2026-08-02: the final ELF has no dynamic libcurl dependency,
   inspection authenticates the static-libcurl Fetch/WebSocket
   implementations, and a relocated source-free Fetch fixture passes.
3. **Ratify ambient-by-default before release** (§1) — **ratified
   2026-08-02**. Confirmed against the working macOS arm64 and Linux x86-64
   end-to-end artifacts. Ambient compatibility remains the v1 default before a
   shipped tuple can successfully arm CapSec. The authenticated boot field
   keeps a future reversal versioned and inspectable. A reversal remains a new
   product decision; §5's boot-mode contract field makes it a visible identity
   change rather than latent behavior.
4. **Second reserved selector `--ibex-info`** (§8) — **decided 2026-08-02:
   reserve it**. Making the copied artifact self-describing justifies the
   second exact first-position reservation. It prints the authenticated
   `ibex/standalone-executable-info/1` report after complete admission and exits
   before application evaluation; leading `--` escapes it literally.
