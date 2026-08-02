# LLP 0047: Standalone Executable Finish Line

**Type:** Plan
**Status:** Accepted
**Systems:** Build, Distribution, Runtime, Module Loader, CapSec, Product
**Author:** Charlie Cheever / Codex
**Date:** 2026-08-01
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
  identities**, which rotate to `StubContractV2` and
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

The repository already has most structural pieces:

- public `compile` and `inspect-executable` command grammar;
- `ibex/single-file-executable/1` envelope and footer/segment layouts;
- path-independent embedded graph, candidate-table, entry, carrier, policy,
  and provenance sections (the compile plan is a field of the provenance
  section, not a section kind of its own);
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
6. Sequence the catalog against milestone 2. Catalog entries bind the exact
   stub-core digest and the release `ibex` embeds the catalog digest, so
   milestone 2's change to compiled boot behavior — and milestone 2's
   `StubContractV2` and new envelope section — necessarily rotate the stub, the
   contract, the catalog, and the producer's compiled-in pin. **Milestone 1's
   catalog is therefore explicitly provisional and is re-cut at the end of
   milestone 2.** The alternative, deferring the first catalog until dispatch
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

The two candidate resolutions are product decisions, not engineering ones, so
§12 register item 1 carries them. What this plan requires is that the friction
be measured rather than assumed: milestone 1's exit records the verbatim
command sequence a new user must run. A sequence nobody will put in a README
is evidence for resolving item 1 before v1 rather than after.

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

- **It is `StubContractV2`, not an extension of V1.** The implemented contract
  is strict `deny_unknown_fields` with a fixed `ibex/stub-contract/1` schema
  string and `ibex:stub-contract:1` digest domain. Adding required fields is a
  versioned schema change by LLP 0029's own rule, not an in-place edit. Since
  no catalog has shipped, V1 is **replaced outright rather than migrated** — no
  compatibility shim, no dual-version parser — and that replacement must land
  in lockstep before the first **non-provisional** catalog is cut. It does not
  forbid milestone 1's explicitly provisional V1 catalog (§4 item 6), which
  exists precisely so the producer path can be exercised before V2 lands.
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
  `StubContractV2`, applied consistently.** The section-kind vocabulary is a
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
catalog is re-cut against `StubContractV2` and the revised envelope, and the
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

- application argv and the single reserved selector rule above;
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
4. Close the recipient's disclosure gap, or record that v1 accepts it.
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

   The mechanism that would close it is a second reserved first-position word —
   an `--ibex-info` printing posture, backend inventory, and CapSec
   availability, then exiting without evaluating the program. That widens the
   argv reservation §1 calls the sole v1 exception, so it is register item 4
   (§12). If item 4 declines it, v1 ships with the recipient-side gap recorded
   in §11 as accepted, not left implicit.
5. Produce a signed macOS artifact in the required segment/signing order and
   an audited Linux artifact with no Ibex/Hermes sidecars.
6. Record size and cold-start budgets before final measurement, then publish
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
- envelope, graph, carrier, and policy admission run identically across modes —
  the same code path, including the policy section's semantic validation, not
  two implementations asserted to agree;
- the default boot mode and selector contract are authenticated contract
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
  it must not be inferred merely because one target becomes advertised. §5's
  boot-mode contract field is what makes such a reversal a visible, versioned
  identity change rather than a silent behavioral one.
- **Recipient-side disclosure:** every posture disclosure surface belongs to
  the distributor, not the person who receives a copied binary (§8 item 4). If
  register item 4 declines the second reserved selector, this is an accepted
  v1 limitation rather than a solved problem, and saying so is the condition
  under which LLP 0039's amended trip-wire 3 is satisfied.
- **Defense-depth reduction:** shipping enforcement-off machinery inside every
  standalone artifact removes the compile-time-absence property the rest of
  Ibex relies on (§1). Accepted deliberately, with fixture-proven monotonic
  dispatch as the compensating control — but it means a dispatch defect is a
  security defect, and the CI guard in the mode-drift risk above must treat it
  that way rather than as a functional regression.

## 12. Author-decision register

None of these block starting milestone 0. **Items 1 and 3 still block the §9
release criteria**; item 2 is decided and its corresponding criterion now
requires implementation/audit evidence; item 4 blocks claiming the
recipient-side disclosure posture is adequate.

Item 3's status is stated precisely, because an earlier draft left it
ambiguous. Ambient-by-default is **decided** — §1 makes it, LLP 0029 §7 item 4
records it re-resolved, and LLP 0031 and LLP 0039 are amended on its strength.
Item 3 is therefore not an open question about whether to proceed but a
**pre-release ratification**: the decision was made before the ambient path
could be exercised end to end, so it is revisited once with real artifacts
before v1 ships.

1. **Mandatory production policy for ambient compiles** (§4). Options: (a) own
   the friction — v1 requires policy authoring for every compile, documented
   plainly; (b) amend the producer contract so compiling an **ambient-default**
   artifact may consume a generated minimal policy. Option (b) collides with
   LLP 0029's "compiling never generates policy silently" and would need that
   rule scoped rather than broken; it must also say what the generated policy
   *means* when that same artifact is later launched with `--ibex-capsec`,
   since every artifact keeps a reachable CapSec selector — a generated policy
   that silently became the enforced authority would be the worst outcome
   available. Evidence to gather first: the verbatim new-user command sequence
   from milestone 1's exit.
2. **Linux ambient network** (§7) — **decided 2026-08-01: option (a)**. The
   flagship first use case is producing Snapback CLIs, which require Fetch on
   Linux. Reuse the existing libcurl Fetch/WebSocket bridge, build its pinned
   libcurl/TLS closure statically into the Linux stub, and pass the final-image
   ELF audit. Shipping Linux ambient v1 without network is rejected.
3. **Ratify ambient-by-default before release** (§1). Confirm, against a
   working end-to-end artifact rather than a design, that ambient is the right
   v1 default before the CapSec path works on any tuple — or narrow it so v1
   ships ambient only for artifacts the distributor keeps inside a trust
   boundary they control. A reversal here is a product decision with an
   unusually cheap mechanism: §5's boot-mode contract field makes the default
   a versioned, inspectable identity rather than latent behavior.
4. **Second reserved selector `--ibex-info`** (§8). Whether making the artifact
   self-describing to its recipient justifies widening the argv reservation
   beyond the single word §1 calls the sole v1 exception.
