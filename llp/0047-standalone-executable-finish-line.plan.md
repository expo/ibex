# LLP 0047: Standalone Executable Finish Line

**Type:** Plan
**Status:** Draft
**Systems:** Build, Distribution, Runtime, Module Loader, CapSec, Product
**Author:** Charlie Cheever / Codex
**Date:** 2026-08-01
**Related:** LLP 0029 (single-file executable architecture); LLP 0031 (v1
platform matrix); LLP 0034 (Hermes ES6 block-scoping mode); LLP 0035
(portable engine provenance); LLP 0038 (enforcement-off mechanics); LLP 0039
(secure/insecure product modes); issues/20260717-sfe-compile-cli.md;
issues/20260717-sfe-hbc-production-wiring.md;
issues/20260717-sfe-static-hermes-macos.md;
issues/20260731-hermesc-recipe-missing-es6-block-scoping.md

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

Envelope integrity, graph/carrier admission, HBC compatibility, provenance,
and platform layout checks apply in both modes. “Ambient” removes capability
policy enforcement; it does not turn off package-format authentication or
permit runtime module discovery outside the embedded graph.

This plan is a scoped amendment to LLP 0029's release sequencing and LLP
0039's product defaults. It does not change the default posture of the general
`ibex run`/`eval`/REPL binary.

## 1. Product decision

### One artifact, two modes

The distributed application is one executable. It is not necessary to produce
separate “secure” and “insecure” files or to choose a permanent posture at
compile time.

The v1 invocation contract is:

```text
./app [application arguments...]                 # ambient compatibility
./app --ibex-capsec [application arguments...]  # CapSec, fail closed
./app -- --ibex-capsec [...]                    # literal application argument
```

The stub recognizes `--ibex-capsec` only as the first argument. A leading
`--` ends stub option parsing and is removed before constructing application
`process.argv`. Every other argument, including later occurrences of
`--ibex-capsec`, belongs to the application. This is the sole v1 exception to
LLP 0029's earlier “all argv belongs to the application” rule.

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

The first successful CapSec launch remains the v1.1 milestone described by
LLP 0029. Adding it later is compatible with already-authored source programs,
but may require rebuilding the executable to embed a newer stub contract,
catalog, policy, or advertisement.

## 2. Current state

The repository already has most structural pieces:

- public `compile` and `inspect-executable` command grammar;
- `ibex/single-file-executable/1` envelope and footer/segment layouts;
- path-independent embedded graph, candidate-table, entry, carrier, policy,
  compile-plan, and provenance sections;
- pinned SFE catalog and stub/compiler/contract admission types;
- whole-graph catalog compilation to per-module HBC carriers;
- a compiled-stub crate with graph/carrier admission and event-loop driving;
- non-evaluating internal inspection of authority and provenance;
- macOS arm64 and Linux x86-64 target contracts.

The product is nevertheless unreachable: no repository build sets
`IBEX_RELEASE_SFE_CATALOG_DIGEST`, release compiled boot deliberately refuses,
the compiled-stub crate has drifted from the current carrier admission API,
and no real release envelope has executed HBC end to end on both v1 tuples.

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
   this plan rather than the former CapSec-first release gate.

**Exit:** format, catalog, producer, and compiled-stub crates compile and test
from a clean checkout; the fixed HBC recipe executes the semantic regression.

## 4. Milestone 1 — publish a real release catalog

Make the existing catalog-backed producer reachable without a developer-only
escape hatch:

1. Build exact stub, `StubContractV1`, and `hermesc` artifacts for
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

**Exit:** a clean release `ibex` can compile a multi-module TypeScript fixture
using only the pinned catalog and produces byte-identical unsigned output on
two clean builders for each tuple.

## 5. Milestone 2 — dual-mode compiled boot

Replace the compiled stub's unconditional release refusal with an immutable
pre-boot mode dispatch.

### Ambient path

1. Admit the self-file, platform layout, envelope, compile plan, graph,
   candidate tables, policy bytes, entry, and every HBC carrier exactly as the
   secure path does.
2. Construct the enforcement-off compiled Host and ordinary runtime backend
   set; do not synthesize target evidence or claim that policy decisions ran.
3. Project application argv, inherited environment, cwd, and host access with
   ordinary non-sandboxed semantics.
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
same CapSec path arms and enforces a denied effect.

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

- application argv and the single reserved selector rule above;
- inherited environment/cwd in ambient mode and LLP 0029's brokered contract
  in CapSec mode;
- timers and referenced async work driven to quiescence;
- uncaught exception/rejection failure status;
- `process.exit` and numeric `process.exitCode`;
- bounded stdout/stderr flush before orderly termination;
- SIGINT and SIGTERM with conventional signal-derived status;
- stable errors for unavailable compiled backends.

The target stub contract records its backend inventory. v1 should aim to match
the ordinary `standard` runtime feature closure. Any omitted backend is an
explicit target-contract limitation, visible in inspection and release notes,
not a CapSec denial and not a silent no-op.

**Exit:** end-to-end fixtures cover every row above on both tuples; inspection
reports the exact backend inventory.

## 8. Milestone 5 — distribution and usability

1. Make `ibex compile` discoverable and document the default ambient authority
   in the command help and standalone guide.
2. On the first compile in a terminal, print one concise notice that the
   output defaults to ambient authority and name `--ibex-capsec`; do not print
   a development “unsafe build” banner every time the distributed app runs.
3. `inspect-executable` must report:
   - default mode and selector contract;
   - whether the embedded tuple can currently satisfy CapSec admission;
   - envelope/graph/HBC integrity state;
   - backend inventory;
   - platform signature and external attestation independently.
4. Produce a signed macOS artifact in the required segment/signing order and
   an audited Linux artifact with no Ibex/Hermes sidecars.
5. Record size and cold-start budgets before final measurement, then publish
   the measured result rather than blocking correctness work on an unstated
   performance expectation.

**Exit:** a user can install one release `ibex`, compile a short program, copy
the resulting executable to a clean compatible machine, and run it without an
Ibex/Hermes installation or source files.

## 9. Release criteria

The standalone v1 is done when all of the following are true:

- `ibex compile` is reachable from a published catalog-pinned release;
- the compiled-stub and SFE suites are mandatory green CI;
- real HBC release envelopes run on both v1 tuples;
- the default ambient path has no capability-security claim and behaves as
  documented;
- `--ibex-capsec` is present and monotonically fail-closed, even if no shipped
  tuple can yet arm successfully;
- envelope/integrity admission is identical across modes;
- source deletion and relocation do not affect execution;
- argv, environment, lifecycle, signals, output flushing, and backend
  inventory meet the bounded v1 contract;
- inspection can explain the artifact without evaluating application code;
- platform distribution checks and precommitted size/startup measurements are
  recorded.

CapSec advertisement completion is explicitly **not** a v1 release criterion.
It is the criterion for claiming that the optional CapSec mode works on a
specific shipped tuple.

## 10. Deferred work

- successful production CapSec admission and advertised target coverage;
- Windows and x86-64 macOS catalog entries;
- cross-target compilation;
- embedded filesystem assets;
- native addons/FFI payloads;
- multi-entry executables;
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
- **Selector collision:** reserving one first-position argument is a real
  compatibility cost. The leading `--` escape is mandatory and tested.
- **Backend skew:** a minimal static stub can accidentally look like a CapSec
  refusal when a backend was simply omitted. Inspection and stable error
  classes must keep those cases distinct.
- **Future default reversal:** changing to CapSec-by-default requires a new
  LLP update, migration/release notes, and a deliberate ambient opt-out design;
  it must not be inferred merely because one target becomes advertised.
