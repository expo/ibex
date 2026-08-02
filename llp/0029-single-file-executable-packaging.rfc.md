# LLP 0029: Single-File Executable Packaging

**Type:** RFC
**Status:** Accepted
**Systems:** Build, Module Loader, Runtime, Security
**Author:** Charlie Cheever / Claude Fable
**Date:** 2026-07-17
**Revised:** 2026-08-01 (author-decision register item 2 resolved: the CapSec
pre-init restore allowlist is deliberately empty; ambient boot does not scrub
the inherited environment, while application-visible CapSec environment values
remain brokered snapshot data)
**Revised:** 2026-08-01 (round-3 delta review, **applied after the round
budget closed and therefore NOT re-reviewed**: §2 gains the wire-identity
rotation note — LLP 0047 rotates the stub contract and envelope to
`StubContractV2` / `ibex/single-file-executable/2`, so this RFC no longer reads
as normative on the superseded V1 layout)
**Revised:** 2026-08-01 (round-2 delta review: computed-`require` restated as
resolved-for-0.2 with a named reopening path, matching LLP 0028's register;
`hermesc` recipe-identity enforcement attributed to catalog/compiler admission
rather than carrier admission; ambient admission enumerations now include the
embedded policy section and its semantic validation; the graph-snapshot
open question closed; Summary scoped by LLP 0047's eligibility boundary)
**Revised:** 2026-08-01 (round-1 dual review: stale present-tense repo claims
swept — the graph-snapshot domain, derived HBC metadata, and embedded
protected-artifact identity have all landed since they were written as future
work; the LLP 0047 boot change is relabeled a proposed amendment rather than an
implementation update; the normative `hermesc` recipe now requires
`-Xes6-block-scoping` per LLP 0034, with the coordinated recipe-digest bump
named; `inspect-executable`'s third state is stated at its true strength; the
Linux network rationale is re-founded now that advertisement no longer gates
the shipped artifact)
**Revised:** 2026-08-01 (LLP 0047 supplies the finish-line plan and revises
the v1 product posture: one standalone artifact defaults to ambient
compatibility execution, with CapSec selected explicitly at runtime and
remaining fail-closed on missing target advertisement; envelope, graph, HBC,
and provenance admission remain mandatory in both modes)
**Revised:** 2026-07-29 (register item 4 re-resolved: v1 ships fail-closed
with empty CapSec advertisements — production arming keeps refusing every
unadvertised target — and the first verified advertisement moves to a v1.1
milestone scoped to a single tuple working the prioritized target-applicable
subset of the residual catalog rows; supersedes the 2026-07-18 "holds release
until both exact tuples have verified CapSec advertisements" posture)
**Revised:** 2026-07-18 (the compiled environment profile classifies the Win32
process-block flag lookup as typed internal dispatch, keeping Rust and the
Hermes DLL on one pre-construction runtime configuration value)
**Revised:** 2026-07-18 (platform decision: LLP 0031 keeps the v1 SFE matrix at
macOS arm64 and Linux x64, defers Windows/macOS x64, and holds release until
both exact tuples have verified CapSec advertisements); 2026-07-18 (Snapback 0.2 decision: computed dynamic imports are
required; phase 4 now embeds each producer-owned, digest-addressed candidate
table, cross-binds its projection into graph/policy identity, and links it in
the compiled stub); 2026-07-18 (implementation: compiled boot now drives referenced
Hermes work to quiescence on the native timer clock, treats unconsumed async
failures as fatal, propagates the final numeric `process.exitCode`, and bounded-flushes the
output broker before orderly termination); 2026-07-18 (implementation: `inspect-executable` now internally
admits graph/policy/entry/carrier cross-bindings and release CompilePlan fields
without evaluation, while keeping catalog, platform-signature, and publisher
trust as independent states); 2026-07-18 (implementation: the authenticated source-graph
publisher now emits and re-admits a path-independent per-module carrier set;
the catalog compiler rotates the entire set to inspected, engine-bound HBC;
and release contracts cross-check engine/compiler HBC versions); 2026-07-18 (implementation: the phase-0 packer now walks literal
typed ESM/CommonJS edges, assigns portable root/package/builtin identities,
emits and pre-admits one carrier pair per module, and proves byte-identical
multi-module+builtin relocation after deleting both source trees on signed
macOS); 2026-07-18 (implementation: the Linux release-stub profile now
closes full Hermes, JSI, Boost.Context, and ICU statically; disables network
while the compiled CapSec projection advertises none; records
`linux-glibc-2.35-x86-64-v1`; and gates its ELF system-library, RPATH, GLIBC,
and ISA surface in CI); 2026-07-17 (implementation: LLP 0023's compiled mount revision and
product-neutral contract now pin `LogicalRoot::App`/`Work`, project-root policy
refusal, optional `/work`, `ibex:cwd:unset`, and stable no-assets/unset-cwd
errors; compiled runtime adapters and relocation evidence remain); 2026-07-17 (implementation: the evaluator-owned bootstrap phase
token, strict immutable bootstrap floor, ambient-root exclusion, and one-shot
Host/Hermes post-lockdown seal are implemented; concrete compiled bootstrap
authorities and application callback fixtures remain); 2026-07-17 (implementation: fixed catalog-authenticated hermesc
recipe and real-HBC compiler adapter, root-only ceiling and embedded protected
ranges, canonical CompilePlanV1/provenance contracts, and public compile/
inspect-executable grammar with a three-state non-evaluating inspector landed;
release compile remains unavailable until a release catalog and compiled arming
consumer are populated); 2026-07-17 (implementation: deterministic thin Mach-O injection
uses `__IBEX,__payload`, 16 KiB allocation alignment, zero padding, and 0x1000
bytes of linker-reserved header space; signed-layout admission and mapped-object
self-file pinning landed); 2026-07-17 (round-4 dual review: macOS embedding respecified —
both reviewers independently established that a trailer-appended Mach-O
cannot be code-signed (Apple TN2206; the reason postject/libsui exist), so a
dedicated segment is now the normative macOS layout with the trailer kept for
ELF; process-ceiling semantics split (root-specific ceiling distinct from the
whole-process bound); bootstrap sealing given a candidate mechanism; env
capture narrowed to the earliest executable-controlled hook with a
consumer-disposition taxonomy; canonical policy v2 named; per-module HBC
carriers for v1; `/app` scoped to a module/diagnostic namespace (no
filesystem assets in v1); catalog pinned per release; LLP 0028 sequencing and
LLP 0014 schema ownership stated; budgets precommitted before measurement.
Round-3 revision: stub identity made acyclic
(compatibility identifier vs instance descriptor); root ceiling wired to the
evaluator's `processAuthorityCeiling` stratum with a distinct bootstrap
stage; environment scrub made default-deny with app-env-as-data semantics
(profiled controls inert even when app-written); LLP 0028 invocation-time
error semantics preserved in compiled binaries; macOS distribution recast
around unstaplable standalone binaries; pinned-fd self-file acquisition;
`ibex/authenticated-graph-snapshot/1` digest domain reconciling the three
existing graph digests; carriers re-bound (payload verbatim, manifests
re-bound); HBC engine-binding field versioned; explicit LLP 0023 revision
with `/app`//`/work` vocabulary; catalog trust root; author-decision
register. Earlier history below.)
**Revision history:** 2026-07-17 round-1 (envelope replacing "no new
format"; digest domains; dedicated command + stub crate; disk-free arming;
committed policy; host-target v1; threat model; phases); 2026-07-17 round-2
(embedded-module-graph contract; StubContractV1; single snapshot; mounts;
env sequence; signing state machine; Unicode argv; capsec CLI
classification).
**Related:** LLP 0010 (ibex binary ownership; command inventory this RFC extends); LLP 0012 (runtime identity); LLP 0013 (capability compartments); LLP 0014 (generated policy artifact; the embedded authority; revised by §4); LLP 0021 (typed policy and `ArmedSnapshot`; governing for §4); LLP 0022 (armed `process.env` classification); LLP 0023 (virtual filesystem namespace; revised by §4); LLP 0025 (terminal session ownership; §6 lifecycle); LLP 0026 (prepared production artifacts and Hermes bytecode, §9); LLP 0027 (module-carrier wire contract; engine-binding and snapshot-digest revisions, §3/§1); LLP 0028 (Oxc-only transform; error-timing contract preserved by §1); LLP 0047 (v1 finish-line plan and dual-mode product posture)

## Summary

Add a packaging mode that compiles an entry point into a **single
self-contained platform executable**: a minimal Ibex runtime stub, the
entry's complete prepared module graph (per-principal LLP 0027 carriers
plus an embedded graph index), the resolved LLP 0014 capability policy,
and a package provenance manifest, in one file with no Ibex or Hermes
sidecar files — the `deno compile` / `bun build --compile` shape, built
on the artifact contracts Ibex already has. Proposed surface:
`ibex compile <entry> -o <file>` plus `ibex inspect-executable` (§1).

The motivating consumer is distributable agent-facing tools — most
concretely Snapback's generated per-app CLI (Snapback LLP 0062; a
cross-repo dependency not verifiable from this tree) — which wants a
small, fast-starting binary with an opt-in capability-bounded posture rather
than a ~60 MB
Deno/Bun artifact or a Node installation requirement. v1's tuples
(`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`) do **not** cover
Snapback's full distribution surface (Windows, x86_64 macOS): v1
prototypes the contract for Snapback; full coverage tracks the LLP
0026 patched-Hermes question and the catalog mechanism of §5. The
feature is general: any Ibex program becomes shippable as one file.
**Scoped by LLP 0047's eligibility boundary:** the *mechanism* is general, but
the v1 ambient default is not appropriate for every distribution. Where an
artifact would reach recipients who cannot audit the embedded graph and would
reasonably assume confinement, LLP 0047 §1 says to wait for the CapSec path
rather than ship ambient with a disclaimer.

The proposal reuses the hard parts Ibex already has — LLP 0027's
versioned, digest-bound, per-principal carriers; LLP 0014's generated
policy artifact; LLP 0026 §9's prepared-graph production — but
packaging is **composition plus new contracts**, not concatenation:
an outer executable envelope (`ibex/single-file-executable/1`, §2b);
an inner path-independent embedded graph
(`ibex/embedded-module-graph/1`, §2b) replacing the path-bearing
on-disk index; and one **authenticated graph-snapshot digest domain**
(§1) that policy, carriers, and envelope all bind, reconciling the
three partial graph identities the repo has today. Carrier **payload
bytes** are embedded verbatim; carrier **manifests are re-bound** at
packaging to the snapshot digest and the stub's engine identity —
earlier revisions' "carriers verbatim" claim was internally
inconsistent with path independence, and this revision says precisely
which bytes are preserved and which bindings rotate.

## Motivation

- **Distribution without a runtime prerequisite.** Today running an
  Ibex program requires the `ibex` binary plus the program's source or
  prepared artifacts. Tools meant for other people's machines need one
  file that just runs.
- **Size and startup look favorable, as hypotheses with budgets.**
  Hermes has no parse step for bytecode and lean engine builds are
  small, so a Hermes-based executable plausibly lands well under `deno
  compile`'s ~65 MB hello-world with fast cold starts. These are
  estimates: no in-repo benchmark exists, today's HBC path copies
  bytes into aligned heap storage, and engine-variant comparisons are
  only meaningful between equivalently pinned, patched,
  capsec-conformant static builds. §7 phase 7 sets **pass/fail
  budgets** (size, cold start, dependency count), not just recorded
  measurements — a report without thresholds cannot decide whether
  the advantage over Deno/Bun was achieved.
- **A compiled artifact is a legible posture story.** In ambient compatibility
  mode, inspection states plainly that the app has the launching user's
  authority. When CapSec is selected, the same file's total capability surface
  is a frozen, embedded, auditable policy artifact — with the runtime's own
  configuration surface closed (§4) — making the LLP 0013/0014 model portable.
  §3 states
  what the integrity mechanisms do and do not defend against; per LLP
  0013's honesty discipline, no tamper-proofness is claimed that only
  platform signing can provide.

## Goals

- One command produces one executable from one entry point, for the
  host target tuple in v1 (§5), consuming only content-addressed,
  catalog-authenticated inputs (§2a, §5).
- The executable embeds the complete envelope (§2b). Nothing is
  resolved from disk or network at run time: module resolution is
  bounded to the embedded graph, with out-of-graph and
  unsupported-shape sites failing at **invocation** with LLP 0028's
  stable errors (§1 step 4) — compiled mode preserves `ibex run`'s
  observable error timing, including dead branches.
- When CapSec is explicitly selected, the compiled program's authority is
  exactly the embedded policy as armed by the disk-free arming procedure (§4),
  with the root ceiling carried in the armed snapshot's
  `processAuthorityCeiling` and a bootstrap stage that ends before application
  code runs. LLP 0047 makes ambient compatibility the v1 default; that path
  makes no capability-security claim but retains the same envelope, graph,
  HBC, policy, and provenance admission.
- Deterministic output at the **unsigned-core** layer: same input
  digests → same unsigned package bytes, two-clean-builder verified.
  Signing (§2c) is a recorded, separable step.
- TypeScript entry points work identically to `ibex run` on the same
  tuple (LLP 0028's guarantee); types erased at compile time only.

## Non-goals

- Self-update, installers, or package-manager integration.
- Publisher code-signing automation (§2c defines order of operations
  and ad-hoc signing where the OS requires it; publisher signing and
  container packaging are the distributor's step).
- Cross-target packaging in v1 (§5: same catalog machinery, deferred
  population).
- Native addons or FFI payloads inside the executable.
- Byte-preserving non-Unicode argv (§6: Unicode contract with stable
  indexed rejection; reversible surrogate-escape recorded as the
  considered alternative if field friction demands it).

## Design

### 1. Command surface and producer pipeline

A new subcommand, updating LLP 0010's clap inventory and
`runtime-surface.json` together (capsec CLI-registry consequences in
phase 4: new names rotate registry/policy digests;
`inspect-executable` gets a dedicated classification so the coverage
model's `inspect` → `inspector:activate` heuristic cannot misfile it).
LLP 0010 also gains one sentence: compiled binaries are outside the
clap-surface contract (they own argv, §6).

```
ibex compile <entry> -o <file>
  [--carrier hbc|factory-table]     # default: hbc (see below)
  [--policy <resolved-policy-path>]
  [--deny-unsupported]
ibex inspect-executable <file>
```

`ibex compile` is not an overload of `ibex build`: today's `build` is
the legacy positional-`FILE`/`--outdir` grammar dispatching to the
Rolldown-bundle → `hermesc` path (with a raw-source fallback), it does
not produce LLP 0027 carriers, and the root `--policy` option is
syntactically accepted but unbound there. If both the root and a
compile-local `--policy` are given, that is an **explicit conflict
error**, never precedence. The default release carrier is **HBC**;
`factory-table` is diagnostic-only until phase 7 measures its
parser-exposure and performance posture (§7 registers the author
decision on its release status).

The producer pipeline:

1. **Capture one authenticated graph snapshot.** The entry's prepared
   graph is produced via the LLP 0026 §9 production path, and its
   identity is a **new digest domain, `ibex/authenticated-graph-
   snapshot/1`** — a canonical schema and precommitted projection over
   node identities, package identities, source integrity, typed edges,
   candidate sets, and the entry designation. This domain **has since
   been implemented** (`crates/capsec-semantics/src/graph_snapshot.rs`)
   and is consumed by the producer; when this section was first written
   it did not exist, and the three partial identities it reconciles were
   the current module-generation digest (covering three of those six
   inventories), the Rolldown `graphDigest` bound into publication hashes
   containing **absolute source paths**, and the armed snapshot's third
   `packageGraph` digest. The new domain subsumes the
   generation digest's role for packaging and **replaces** the
   path-bearing Rolldown digest in every embedded binding. The armed
   `packageGraph` is not a parallel fact set: **the embedded snapshot
   is the single graph source, and compiled arming *derives* the
   authority-bearing armed package graph from it** through a total
   normative projection (module-to-principal assignment, exact
   package set, root/package/builtin and candidate edges, conditions,
   attributes, entry identity, aliases, embedded object identities,
   platform disposition — arming's exact-equality checks then run
   against the derived graph as they do today), with mutation vectors
   for every projected field; a projection mismatch is a packaging
   refusal, and at boot a derivation failure is a boot refusal.
   Cross-language golden vectors pin the snapshot projection.
   Policy validation and carrier production consume this one
   snapshot, and the compiled authority source is **one committed,
   auditable artifact**: a **canonical policy v2** revision (the Rust
   ingest is `deny_unknown_fields`, so this is a versioned schema
   change, named in phase 3, and it is the single coordinated LLP
   0014 schema revision shared with LLP 0028 — see §7) whose
   `policyDigest` covers the bound entry identity, graph identity,
   target/mount profile, and the normalized root-ceiling declaration
   (§4) with provenance. Artifact naming is keyed by entry and
   target/profile; authoring and drift-check are deterministic; and
   compile never rereads a mutable side manifest at assembly time —
   everything it consumes is under the digest. Packaging refuses on
   mismatch, with inter-step-mutation and divergent-graph fixtures
   proving the refusal.
2. **Consume the committed, drift-checked canonical policy artifact**
   (LLP 0014 v2, above), failing on missing, stale, or drifted
   policy. Compiling never generates policy silently. `--policy
   <path>` accepts only canonical, registry-bound
   `purpose: production, mode: enforce` artifacts.
   `inspect-executable` reconstructs and reports the **complete
   effective armed authority bundle** (policy, ceilings, bootstrap
   floor, graph projection, mounts, env profile, implicit authority),
   not just the review policy.
3. **Produce carriers bound to the stub, not to the packager.** HBC
   is compiled with a catalog-authenticated `hermesc` paired with the
   target `StubContractV1` (§2a); carrier manifests bind the stub
   contract's **engine compatibility identity** and the bytecode
   version **derived by inspecting the emitted HBC**, never accepted
   as caller-supplied metadata. (This has since been implemented —
   `HermesBytecodeMetadataV1::inspect` derives the version from the
   emitted bytes; the earlier caller-trusting `bind_hermes_bytecode`
   behavior and the real-Hermes test that labeled real bytecode with a
   dummy digest are no longer the current state.) The
   carrier engine-binding field is **versioned/tagged** in an LLP 0027
   schema revision so loaded-file identities and static compatibility
   identities cannot be confused. The `hermesc` invocation recipe is exact and
   digest-bound, over a private temporary
   directory, UTF-8 factory-table input, Hermes-bytecode-file output, and an
   empty inherited environment; clean-root HBC byte comparison is a
   phase-4 gate. **The recipe must pass `-Xes6-block-scoping`.** An earlier
   revision pinned the flagless `-emit-binary -out {output} {input}` vector,
   which contradicts LLP 0034's requirement that every Ibex-owned `hermesc`
   invocation emitting executable HBC carry the flag, and is an actual
   miscompile hazard: without it, AOT compilation gives `for-of` `let` bindings
   capture-last semantics. Because the recipe is covered by the
   `ibex:hermesc-compatibility:1` identity, correcting it rotates that digest
   and every catalog entry binding it — a coordinated bump, scheduled as LLP
   0047 milestone 0. Enforcement of the recipe identity lives at the
   **catalog/compiler admission** boundary, not in carrier admission (which
   checks engine binding and the inspected HBC version); rejection fixtures
   belong there. Wrong-engine and compiler/stub-mismatch fixtures
   prove rejection. The SFE producer now invokes authenticated `hermesc` and
   emits HBC carriers; the earlier "publisher emits factory tables only" state
   applied to the general publication path before that wiring landed.
4. **Unsupported shapes keep LLP 0028's invocation-time semantics.**
   A graph containing shapes the runner cannot execute natively
   (computed dynamic import without a candidate table, computed
   `require`, unsupported import options) still **compiles**: the
   sites carry LLP 0028's guarded representation and fail at
   invocation with its stable errors, preserving dead-branch behavior
   and evaluation order — compiled binaries do not fork the language.
   `ibex compile` emits a compile-time **diagnostic** listing every
   such site; `--deny-unsupported` upgrades the diagnostic to a
   refusal for producers who want a clean-graph guarantee. (An
   earlier revision made these compile-time failures and claimed the
   subset "widens automatically"; both contradicted LLP 0028 and are
   withdrawn. LLP 0028 *resolved* computed `require` for 0.2 on
   2026-07-18 — the fail-closed disposition stands and no candidate
   rows are added — while naming a reopening path (the same sidecar
   and JSON authoring channel) if evidence later warrants; if that
   reopening lands, compiled binaries carry its candidate rows in the
   same embedded tables with no format change here.) Cross-mode fixtures
   compare `ibex run` and compiled behavior for timing, ordering, and
   dead branches.
5. Assemble the §2 envelope, append, write the footer, and (macOS)
   run the §2c signing sequence. Output publication is **two
   independently atomic writes** (executable; detached build
   statement) whose mutual digests make any torn pair detectably
   invalid — honest wording, since two sibling renames are not one
   filesystem transaction.

A canonical **`CompilePlanV1`** — graph-snapshot digest, policy
digest, stub contract digest, release-pinned catalog digest, compiler identity,
carrier encoding, target, environment-profile digest — is the single immutable producer
input; final assembly is a pure function of the plan, and the plan is
recorded in provenance.

`ibex inspect-executable` reports **three independent states**:
envelope consistency, platform-signature validity, and detached-attestation
state for an adjacent `<file>.build.json`. The third state is deliberately
weaker than its name suggests and the RFC does not overstate it: today the
inspector reports only whether such a statement is *present*, marking it
`unverified` because no publisher trust policy is configured (§7 register item
8 owns that), and it displays the provenance-recorded stub-core digest without
rehashing the stub core against it. So the current third state is neither
"authenticated" nor yet "digest-consistent"; reaching the latter is
`inspect-executable` work, and reaching the former needs register item 8.
Inspection also dumps the embedded
policy, environment profile, and digests. Introspection never reserves
application flags.

Implementation status (2026-07-17): the public clap tree and recursive runtime
surface manifest now include `compile` and `inspect-executable`. The latter
authenticates the envelope without treating its self-described contract as a
release trust root, parses canonical inner JSON without evaluation, and reports
envelope consistency, platform-signature validity/availability, and detached
attestation authentication independently. Its current development-envelope
report marks authority reconstruction incomplete rather than inventing the
missing release arming projection. `compile` accepts only HBC for release,
rejects root/local policy ambiguity, and requires a catalog digest compiled
into the distributing binary; the current build has no such digest and refuses
before source acquisition. `ibex/compile-plan/1` and strict embedded
`ibex/package-provenance/1` contracts cross-bind the catalog target, plan, and
stub core. The remaining producer graph/arming stages must land before a
release catalog is enabled.

Implementation update (2026-07-18): the public producer now implements the
catalog-admitted graph → policy → HBC → CompilePlan → envelope → self-preflight
→ atomic-output path. Compiled-policy authoring consumes the native loader's
exact authenticated snapshot. The stub performs complete release provenance and
static-HBC admission.

Proposed amendment (2026-08-01, **not implemented**): LLP 0047 replaces the
unconditional release refusal with ambient compatibility boot by default and an
explicitly selected CapSec path that retains the compiled-Host arming and
target-advertisement gates. As of this revision the stub still refuses every
release envelope unconditionally after admission, and its argument parser
recognizes no reserved selector — both are LLP 0047 milestone 2 work. This
paragraph states a design decision, not repository state.

### 2. Executable layout: stub, envelope, footer

> **Wire-identity rotation (2026-08-01, LLP 0047 §5).** This section is written
> against `StubContractV1` and `ibex/single-file-executable/1`, and both
> rotate. LLP 0047 requires the stub contract to carry the boot-mode contract
> (default mode, reserved selector spelling and position rule, CapSec-
> advertisement identity) and requires the canonical contract bytes to be
> embedded as a **new envelope section** so non-evaluating inspection can read
> *and* authenticate them from the file alone — a digest pins bytes without
> revealing them, and the contract is otherwise a catalog-only artifact.
>
> Both are strict schemas: `StubContractV1` is `deny_unknown_fields` with a
> fixed schema string, and the envelope's section-kind vocabulary is a closed
> enum. So both changes are versioned rotations, to **`StubContractV2`** and
> **`ibex/single-file-executable/2`**, not in-place edits. Because no catalog
> has shipped, each is a replacement rather than a migration — no compatibility
> shim, no dual-version parser. Everything below describes the layout, digest
> domains, boot checks, and signing sequence unchanged in substance; read `V1`
> as `V2` and the envelope section list as gaining the contract section. LLP
> 0047 milestone 2 owns the rotation, and both versions bump together.

**2a. Runtime stub, contract, and catalog trust.** A dedicated minimal
binary (`ibex-compiled-stub` crate) sharing host, engine,
embedded-loader, and capsec boot libraries — not a subtractive feature
of the full CLI (whose pre-clap namespace interception and audit rules
reject that shape). No REPL, no `eval`, no file-execution ingress, no
clap tree; exactly one entry, the embedded designation.

Stub identity is **acyclic**, split into two objects (an earlier
revision compiled the contract digest into the stub while the contract
carried the stub's own digest — a cycle; withdrawn):

- **`StubContractV1` — the compatibility identifier**, containing only
  pre-build facts: target tuple and minimum platform baseline, engine
  compatibility identity (static Hermes build profile, archive digest,
  HBC version), compatible `hermesc` identity, accepted
  envelope/graph/carrier/policy schema versions, module-runner and
  arming ABI versions, transform profile, a **runtime-relevant capsec
  registry projection digest** (not the repo-global registry digest,
  which rotates on CLI-surface-only edits — adding `ibex compile`
  itself would churn every stub contract; the projection covers what
  the stub actually enforces, with its own digest), a
  **runtime-identity digest** (defined here, since none exists today:
  a strict-JCS projection of `runtime-identity.json`'s semantic
  fields, its domain named, its constant generated into Rust and
  TypeScript), and the environment-profile digest. Its digest is
  **compiled into the stub** and **pinned by the envelope**; boot
  compares the two constants. No stub-byte digest appears inside it.

  The runtime CapSec projection is
  `ibex/capsec-runtime-projection/1`, with digest domain
  `ibex:capsec-runtime-projection:1`. It projects the capability rows'
  runtime fields plus decision, normalization, classifier, arming,
  digest, cache, handle, and initial-target rules from the two checked
  CapSec authorities. Descriptions, risk-review metadata, ownership
  provenance, source coverage, target-cell evidence, and CLI command
  spelling are excluded. Tests prove review/CLI prose does not rotate
  it and a decision-precedence change does. The canonical projection
  and generated Rust/TypeScript constants are drift checked.

  `StubContractV1` is a strict tagged contract rather than a tuple of
  caller strings. Target triple and minimum baseline, engine and
  compiler identities, accepted schemas, ABIs, and all four generated
  semantic digests are required. Engine identity has its own
  `ibex:engine-compatibility:1` domain and covers the static archive
  bundle digest, build profile, and HBC version; the catalog `hermesc`
  identity has `ibex:hermesc-compatibility:1` and covers binary, recipe,
  and HBC version. Diagnostic source-carrier contracts are explicitly
  `releaseEligible: false`; validation refuses diagnostic engine or
  compiler variants in a release-eligible contract.
- **The instance descriptor** — the post-build stub-core digest
  (signature-stripped bytes, §2c), recorded in the **catalog** and in
  the envelope's provenance manifest. The *packager* verifies the stub
  bytes against it before assembly, and `inspect-executable` is specified to
  re-check it — a check the current inspector does not yet perform, per §1;
  boot does not self-hash (a file cannot prove its own bytes —
  boot's integrity comes from the platform loader plus the envelope
  digest checks).

Swap fixtures (same-Hermes/different-stub, producer-newer/stub-older)
prove contract-mismatch rejection. Packaging **always consumes the
stub, contract, and `hermesc` as catalog artifacts** — never a warm
checkout build — and the catalog itself has a **trust root**: an
catalog manifest whose **exact digest is compiled into each
distributing `ibex` release** — v1's trust model is deliberately the
simplest sound one: one immutable, release-pinned catalog manifest
(target → expected-digest map), no independent update channel, no
replay window, rotation happening only via `ibex` releases. A
genuinely updateable TUF-style state machine (keys, rotation, expiry,
freeze, durable trusted state) is deferred until catalog updates
independent of releases are demonstrably needed. Fetch/update
verifies against the pinned digest; provenance records the catalog
entry and verification evidence.
Content addressing alone is not a trust root — an attacker-selected
stub with a matching contract is internally consistent, which is
exactly why the catalog manifest, not the content digest, anchors
trust.

The v1 wire artifact is `ibex/sfe-catalog/1`, strict canonical JCS in
the `ibex:sfe-catalog:1` digest domain. A monotonically increasing
sequence is covered by the digest, but v1 rollback resistance comes
from equality with the release-compiled digest, not from trusting a
caller-supplied sequence. Entries are strictly target-sorted and bind
target/baseline, contract digest, engine identity, compiler identity,
HBC version, and content-addressed descriptors for the canonical
contract, unsigned stub core, and `hermesc`. Admission first verifies
the pinned manifest, then all artifact sizes/digests, then decodes and
recomputes `StubContractV1` and its engine/compiler cross-bindings.
Missing-target errors name the explicit fetch step. The catalog never
treats a matching content digest without the release pin as trusted.

The stub is statically self-contained: no non-system dynamic libraries,
verified with `otool -L`/`ldd` in CI. The release Hermes bundles carry the
full static Hermes archive plus JSI and Boost.Context; Linux additionally
closes ICU through the pinned baseline builder's static archives. The Linux
v1 contract baseline is `linux-glibc-2.35-x86-64-v1`. Its ELF audit rejects
RPATH/RUNPATH, a GLIBC symbol above 2.35, a GNU ISA requirement above the
baseline x86-64 ABI, unresolved libraries, and every `DT_NEEDED` entry outside
the recorded system set (`ld-linux`, `libc`, `libdl`, `libgcc_s`, `libm`,
`libpthread`, `libresolv`, `librt`, `libstdc++`, and `libz`).

The Linux release-stub profile compiles fetch/WebSocket as unavailable and
**libcurl is absent**, not reclassified as a system dependency. The ordinary
source runtime keeps its native libcurl backend. Any compiled target that
offers network authority must bring a vendored/static backend and pass the
same final-image audit before its catalog cell is release eligible.

The original rationale for the omission was that the compiled CapSec projection
advertised no network authority. **LLP 0047 invalidates that rationale**: the
shipped artifact's default path is ambient and does not consult advertisement
at all, so the Linux stub's missing network is now a plain product gap — and an
asymmetric one, since macOS ambient has a working NSURLSession-backed fetch.
Which way it resolves is LLP 0047 register item 2; this section fixes only the
dependency rule that applies once it resolves.

**2b. Envelope, embedded graph, footer.**

```
[ runtime stub (ELF/Mach-O) ]
[ envelope: ibex/single-file-executable/1
    package provenance manifest (§3) — pins StubContractV1 digest,
        CompilePlanV1, catalog evidence
    embedded module graph: ibex/embedded-module-graph/1
    per-principal carrier sections, one HBC carrier per module in v1:
        manifest + payload as separate typed sections with a required
        bijection (payload bytes verbatim; manifests re-bound per §1
        step 3; page-aligned, alignment recorded). Per-module carriers
        are chosen for v1 because grouped HBC tables evaluate under
        one Hermes source label with no composed carrier map — grouped
        carriers return only with a digest-bound carrier/HBC map that
        composes positions to per-module labels, after measurement
    resolved policy artifact (LLP 0014, with graph-identity field)
    entry designation ]
[ footer: section directory, envelope digest, format version, magic ]
```

The envelope is a canonical, versioned container with a Merkle-style
section directory; every section typed, length-bound, digest-bound,
cross-referenced. Boot **bulk-preflights** the whole structure before
evaluating anything: section types, offsets, lengths, ordering,
non-overlap, non-duplication, allocation limits, entry designation,
the graph-record ↔ carrier-manifest ↔ payload bijection, and every
engine binding — no incremental discover-as-you-link. Format golden
vectors and parser fuzzing are gates. Page alignment keeps phase 7's
options open, including the **zero-copy** variant: evaluating HBC
directly from the OS-mapped executable image with a non-owning buffer
(today's path memcpys into aligned heap storage). The entry
designation is a **table with one required row** in v1 — costless now,
and it avoids foreclosing multi-entry (busybox-style argv0-selected)
envelopes later.

`ibex/embedded-module-graph/1` is the new inner contract (compact
content-addressed table: sorted `SourceId → semantic digest, carrier
binding, typed edges, virtual source label` records; full
ModuleArtifact semantics stay in carrier manifests). It specifies what
the on-disk index cannot: every `SourceId` variant (file, builtin,
synthetic — the on-disk schema admits only file IDs while publication
emits builtin records; that latent LLP 0027 defect is filed
independently), path-independent virtual labels and their
`import.meta.url`/`__filename`/`__dirname`/source-map spellings
(anchored under `/app`, §4), LLP 0028 candidate-table references when
present, and the embedded admission rules (admission from envelope
bytes against manifest digests; no original-file reads). Relocation
tests — delete the source tree, build from two checkout paths,
byte-compare **including carrier bytes**, run — enforce path
independence end to end.

The phase-0 implementation exercises that contract with an ESM entry, a
relative ESM dependency, and a runtime builtin. Its deterministic packer walks
all literal typed ESM/CommonJS edges, assigns integrity-bound portable
identities (including package and builtin identities), emits one carrier pair
per module, and locally re-admits the graph/carrier bijection before writing the
envelope. The macOS smoke builds from two checkout paths, compares the complete
unsigned images, deletes both source trees, signs the relocated image, and runs
it from embedded bytes. This closes the format-spike relocation gate; it does
not select computed-edge behavior or promote factory-table carriers to the
release default.

**Embedding is per-format.** On **ELF (Linux)** the envelope is an
appended trailer — no per-target linker toolchain at packaging time,
byte concatenation plus footer. On **Mach-O (macOS)** the envelope is
embedded as a **dedicated segment/section** (postject/libsui-style
load-command injection): both round-4 reviewers independently
established that appending unsealed bytes to a Mach-O is prohibited by
Apple's code-signing layout (`LC_CODE_SIGNATURE` must terminate
`__LINKEDIT`; Apple TN2206) — a naive trailer cannot be signed, which
is exactly why Node SEA uses postject and Deno built libsui. The
envelope's *logical* format (section directory, digests, footer
record) is identical across both embeddings; only the byte placement
and boot discovery differ, and each format's boot check is specified
with its embedding (ELF: bounded EOF magic scan; Mach-O: the named
segment, with the load-command table as the discovery mechanism).

**2c. Signing and determinism.** Packaging first produces the complete
unsigned executable and records its digest (the deterministic
artifact; two-clean-builder gate — determinism holds because the stub
is a catalog artifact, not a local build). macOS sequence, normative
(per the §2b segment embedding):

1. Start from the catalog stub; **strip the linker's ad-hoc
   signature** (stub-core bytes are defined over the stripped form).
2. **Inject the envelope as the dedicated segment** — deterministic
   load-command insertion with precommitted layout rules (segment
   name, placement, alignment, zero padding) so the operation is a
   pure function of stub + envelope bytes; record the unsigned-file
   digest.
3. Ad-hoc sign (`codesign -s -`), which seals the injected segment
   inside the signature's coverage; record the signed-file digest in
   the detached build statement.
4. Boot-side layout validation: exactly one `LC_CODE_SIGNATURE`
   terminating `__LINKEDIT` with no trailing bytes; the envelope
   segment present exactly once at its declared load-command entry
   (duplicates refuse); the signature range covers the segment. An
   unsigned-modified file (segment injected after signing) fails the
   platform's own signature validation and boot's coverage check —
   internal digests alone cannot prove ordering; the platform layout
   is the mechanism.

**Distribution state, macOS:** the supported v1 shape is a **raw
signed binary relying on the online notarization ticket** — Apple
creates tickets for standalone binaries but does **not** support
stapling to them (an earlier revision assumed stapling; withdrawn).
Distributors who need offline stapling package the binary in a
staplable container (**dmg/pkg — not zip**, which is transport only
and likewise unstaplable) as their own step, documented, with the
container digest in the publisher statement. Publisher signing
requirements are stated, not implied: Developer ID identity,
hardened runtime (`--options=runtime`), secure timestamp, and an
identifier/entitlement policy, verified by real notarization and
Gatekeeper tests on the minimum supported macOS. Provenance splits
into the **immutable build statement** (emitted by `compile`:
CompilePlan, input digests, unsigned + ad-hoc-signed digests) and the
optional **publisher statement** (Developer ID signature, notarization
evidence, container digests) appended by distributor tooling — a
versioned DSSE/in-toto-style envelope is the named realization, with
key custody and trust policy a registered open item (§7). Byte-level
signing vectors (ad-hoc and Developer ID, minimum macOS, segment
layout, signature replacement, notarization verification) gate
phase 2. Apple's `codesign` output is not bit-stable across
toolchains; determinism is scoped to the unsigned core, and
**rcodesign (the `apple-codesign` crate)** is the named candidate for
deterministic, Linux-runnable signing if signed-artifact
reproducibility is later pursued.

The v1 layout rules are now exact: the stub linker reserves `0x1000`
zero-filled bytes of load-command slack; injection inserts one 152-byte
`LC_SEGMENT_64` + `section_64` pair named `__IBEX,__payload`
immediately before the existing `__LINKEDIT` command. The payload begins at
the old, already-16-KiB-aligned `__LINKEDIT` file offset, occupies the exact
logical envelope length, and is followed by zero padding to a 16 KiB
allocation boundary. The old `__LINKEDIT` bytes move by that allocation size;
its file and VM addresses and every supported linkedit-relative load-command
offset move by the corresponding delta. Injection refuses a signature-bearing
stub, nonzero/insufficient command slack, duplicate payload or `__LINKEDIT`,
unsupported/fat/endian Mach-O, or a nonterminal/unaligned stripped
`__LINKEDIT`. Signing may then append only the one terminal code-signature
superblob inside the relocated terminal `__LINKEDIT`.

### 3. Identity: separated digest domains

Domains, acyclic, with the compiled-mode engine identity an
**explicitly named new domain in an LLP 0027 revision** (not a silent
reinterpretation of the loaded-file field):

- **Engine compatibility identity** — link-time constant (static
  Hermes archive digest + build profile + HBC version) in
  `StubContractV1`; carriers bind to it at packaging (§1 step 3); the
  compiled-mode provider returns it with no boot-time file hashing.
- **Stub-core identity** — post-build instance descriptor (§2a):
  catalog- and provenance-recorded, packager- and inspector-verified.
- **Producer identity** — the packaging `ibex`'s digest, recorded in
  provenance as data; compatibility is proven by `StubContractV1`
  schema/ABI pins, not by producer-equals-executor self-hashing.
- **Envelope digest** — the footer's digest; what boot verifies.
- **Unsigned-/signed-file digests** — detached statements only.

**Self-file acquisition is pinned, not pathname-based.** Boot acquires
one fd/handle for the executable and proves it is the same object
backing the mapped stub (the mapped-image identity check the engine
loader already performs for Hermes artifacts is the model); footer
parsing, hashing, and section admission all read from that pinned
handle. Reopening `current_exe` by path can race a file replacement —
mapped code from file A admitting an envelope from file B — and is
forbidden. Arming consumes embedded sections through a new
**embedded protected-artifact identity** — `(mapped executable
object, authenticated byte range, section role, digest)` — an LLP
0021/arming revision, since protected artifacts originally required a
host path plus filesystem object identity. That revision **has since
landed**: `ExpectedEmbeddedProtectedArtifact` exists and LLP 0021 records
arming ABI v2 carrying embedded protected ranges.

For the v1 desktop tuples, Linux opens the kernel-maintained
`/proc/self/exe` object and compares its `fstat` device/inode with the mapping
containing the acquisition routine in `/proc/self/maps`. macOS opens the path
reported by dyld exactly once, then compares that descriptor's device/inode
with the main Mach-O vnode reported by `proc_pidinfo` for
`_dyld_get_image_header(0)`. A replacement racing the macOS open therefore
fails closed; after the proof, no pathname is consulted again. The descriptor
is kept through the complete executable read, whose length is revalidated.

The package provenance manifest carries these fields plus LLP 0012
runtime-identity lineage; `runtime-identity.json` itself stays
product/version identity.

**Threat model (LLP 0013 honesty rule):** internal digests detect
corruption, truncation, skew, and accidental mix-and-match; an
adversary who can rewrite the file can recompute them all.
Authenticity comes from platform signing and the detached statements
(build statement default-on). Pre-main dynamic-loader environment
(`DYLD_*`, `LD_PRELOAD`) acts before the stub's first instruction and
is outside every in-process mechanism; hardened-runtime signing and
platform policy are the honest answer there.

### 4. Compiled-mode authority

Per LLP 0047, this section governs the explicitly selected CapSec boot path.
The v1 default is ambient compatibility execution: it skips policy
*enforcement* but still admits the self-file layout, envelope, graph, HBC
carriers, compile plan, provenance, **and the embedded policy section** —
including that section's semantic validation against the compiled-in registry
and graph identity — before application code. Skipping enforcement is not
skipping admission. CapSec selection is monotonic
and fail-closed; failure at any prerequisite in this section never retries the
ambient path.

LLP 0021 is governing: the embedded policy is the reviewable authority
object; the engine consumes an `ArmedSnapshot`. Compiled boot runs a
**disk-free arming procedure**: bind the embedded graph, embedded
policy, engine compatibility identity, capsec registry (contract-
pinned), the mounts below, and embedded protected artifacts (§3), with
fresh run/channel nonces. Reload-time source re-authentication is
replaced by envelope admission. Prerequisites as program gates:

- **Root ceiling via the evaluator's real mechanism — two ceilings,
  not one.** `AmbientRoot` authorizes otherwise-unauthorized root
  effects late in the decision order; the existing
  `processAuthorityCeiling` stratum constrains it — but that stratum
  is a **whole-process bound applied to every constrained principal
  before package floors**, so deriving it from a root-only entry
  declaration would let a narrow declaration deny legitimate package
  floors, and unioning package needs into it would hand those
  authorities to `AmbientRoot`. The design therefore keeps
  `processAuthorityCeiling` as the true whole-process envelope
  (generated as the union of all granted authority, as today's
  semantics imply) and introduces a **distinct root-specific
  ceiling** — a new, earlier root-only stratum in the capsec-semantics
  revision — populated from an **entry-manifest declaration** (schema
  owned by the coordinated LLP 0014 revision; bound to the captured
  entry) flowing through the generator with provenance. Omission
  default: no declaration ⇒ root ceiling equals the bootstrap floor
  only (fail-closed). Fixtures prove root/package containment both
  ways and over-ceiling denial.
- **Bootstrap authority is a sealed stage, with a named mechanism.**
  Runtime-internal bootstrap effects (builtin initialization per LLP
  0027) must be available during boot and unavailable to application
  root code afterward — and a shared root HBC carrier cannot
  distinguish the two by Hermes frame alone. The candidate mechanism
  (owned by the arming/evaluator revision) is an **unforgeable
  evaluator phase token orthogonal to frame principal**: boot holds
  the token, the sealing transition destroys it before application
  evaluation, and decisions requiring bootstrap authority check the
  token, not the principal. Bootstrap-floor matches are ineligible for
  later `AmbientRoot` fallback, so destroying the token removes the
  authority rather than merely changing its evidence stratum. Hermes
  requires the active Host to consume the shared token exactly once
  after final lockdown/posture verification and before application
  attribution. Fixtures prove successful initialization,
  denial of the same effect to application root code after sealing,
  and denial through callbacks/functions retained across the seal.
- **Mount contract — an explicit LLP 0023 revision in the same
  change** (LLP 0023 names `/project` as the sole initial mount and
  requires any additional mount to specify isolation, lifecycle, and
  policy; `/app`/`/work` is that update, with `LogicalRoot::App` and
  `LogicalRoot::Work` added to the schema vocabulary):
  - **`/app`** — the immutable embedded namespace: module identity,
    virtual labels, `import.meta.url`, `__filename`/`__dirname`,
    source-map spellings. In v1 it is a **module/diagnostic namespace
    only — no filesystem-visible embedded assets**: the envelope has
    no asset inventory and the producer has no asset
    authoring/discovery contract, so pretending `fs.readFile(new
    URL("./asset", import.meta.url))` works would be an unspecified
    surface. Every filesystem operation against `/app` fails with a
    distinct stable error naming the reason (asset embedding is a
    future format revision with its own authoring, digest, and policy
    joins). Symlink semantics: none (no links
    inside the envelope).
  - **`/work`** (optional) — the launch working directory, mounted
    only when the embedded policy grants it, backed by an
    authenticated directory object per LLP 0023's own mechanics.
    When absent, the virtual cwd is **unset**: relative filesystem
    paths and `chdir` fail with the policy's stable denial (path
    *observables* like `process.cwd()` return the unset sentinel the
    LLP 0023 revision defines rather than a fabricated path).
  - **Project-rooted grants are a compile-time error**: canonical
    policy carrying `root: project` resources cannot be embedded; the
    generator's compiled-target mode emits `/app`/`/work`/absolute
    resources so the reviewed artifact says what the shipped binary
    means. Denial and relocation fixtures pin the semantics.
- **CapSec target advertisement — a visible optional-posture dependency.**
  Production arming refuses unadvertised targets; today the matrix
  advertises **zero** verified targets (host tuple: 0 enforced / 7528
  unsupported cells as of 2026-08-01; the count grows as the registry
  expands and is not itself progress). That gate is the completion condition of the
  LLP 0021 conformance program, which this RFC inherits but does not
  own; the dependency's magnitude is a scheduling fact stated here,
  and §7's register carries the sequencing question. Module-runner
  advertisement, CapSec advertisement, and stub-contract availability
  remain three separate predicates. Per LLP 0047, this predicate gates only
  explicitly selected CapSec boot; ambient compatibility boot neither consumes
  nor manufactures target evidence.

**Environment: default-deny, and application env is data, not
configuration.**

1. **Capture** — at the **earliest executable-controlled hook**, the
   full `environ` is copied into an immutable **application base
   snapshot**. Stated honestly: an ordinary Rust `main` runs after
   the platform loader and any static constructors, so "first
   instruction" is not achievable by decree — the stub uses a
   platform pre-init shim (init-array/constructor-priority placement,
   with constructor-ordering probes on both tuples as a phase-5
   gate, and no `#[tokio::main]`-style pre-main runtime in the stub)
   to run capture-and-sanitize before every constructor under Ibex's
   control; anything earlier (the dynamic loader, system-library
   init) is classified outside the in-process boundary alongside
   `DYLD_*`/`LD_PRELOAD` (§3).
2. **Sanitize, default-deny** — the real process environment is then
   **cleared entirely** and only the contract-pinned allowlist is
   restored (locale/terminal hints; a diagnostics-verbosity toggle
   pinned to stderr, which may report a count-only summary of
   scrubbed variables for diagnosability). Default-deny is the only
   posture that also covers readers invisible to source scanning —
   the static Hermes archive, libcurl proxy/TLS variables,
   `SSL_CERT_FILE`, resolver and libc internals — which no inventory
   of this repo's sources can enumerate. The generated name-level
   profile (own schema/version/digest, pinned by `StubContractV1`)
   still exists, but its role is classification and testing, not the
   security boundary.
3. **Broker** — application `process.env` reads are served from the
   base snapshot through the capability gate, with a mutable
   process-local overlay (writes/deletes keep Node-compatible
   semantics) and children inheriting exactly the overlay state.
   **Privileged controls are never read from the snapshot or
   overlay** — but the boundary is a generated taxonomy, not a
   blanket rule, because Node compatibility legitimately reads app
   environment for behavior: the profile generation step produces a
   **consumer-to-disposition inventory** classifying every runtime
   read of application-visible environment as either a *privileged
   security control* (`NODE_TLS_REJECT_UNAUTHORIZED` and
   `NODE_EXTRA_CA_CERTS` in fetch, `EXACT_ALLOW_INSECURE_CRYPTO` and
   the `NODE_ENV=test` crypto fallback, the `__exactHostEnv` side
   channel) or *intentional application behavior* (debug/terminal
   conveniences). Privileged controls move to a typed internal
   configuration surface that in compiled mode answers from the
   closed profile, so those names are **inert even when application
   code writes them into `process.env` or `__exactHostEnv`**;
   intentional-behavior reads keep Node semantics. (Production
   startup already rejects closed controls before boot; compiled mode
   extends that posture.) Name/value algebra is explicit:
   byte-preserving where the capsec `EnvironmentName` vocabulary
   allows, with stated rejection/recording rules for names it cannot
   represent (non-UTF-8, lowercase-exotic), duplicates (first wins,
   recorded), and Windows case folding (deferred with the tuple; rule
   stated now). Enumeration returns the snapshot/overlay view — a
   deliberate, documented compiled-mode exception to armed
   enumeration's empty-set rule, carried in the LLP 0022 revision.
   Per-principal composition follows LLP 0022's armed classification:
   the snapshot is the *root* view (root reads flow through the
   existing exact-name broker gate against the embedded policy's env
   selectors — not ambient), and package principals keep their
   per-principal overlay classification, with package-principal and
   cross-principal isolation fixtures in phase 5.

   The generated name-level artifact is
   `ibex/compiled-environment-profile/1`, domain
   `ibex:compiled-environment-profile:1`. Its consumer inventory is
   projected from the source-derived CapSec implementation manifest;
   every exact-name consumer defaults to `privileged-control` unless
   the reviewed config names it as intentional application behavior,
   and every dynamic consumer requires an explicit capture, broker, or
   typed-internal-dispatch disposition. New dynamic reads fail drift.
   The artifact records the name algebra and allowlist decision state.
   **Resolved 2026-08-01:** the restore allowlist is empty. This is a decided,
   release-eligible default-deny posture, not a placeholder: no inherited name
   is restored to the real process environment on CapSec boot. Application-
   visible environment values remain immutable captured data mediated by the
   broker, and LLP 0047's ambient path does not sanitize the inherited real
   environment at all. Widening the CapSec restore set later is a contract-
   digest rotation with explicit compatibility evidence.

   Implementation update (2026-07-18): the compiled stub now performs the
   platform early-hook capture/default-deny sequence and restores only the
   allowlist generated from the contract-pinned environment profile. It retains
   an immutable raw application snapshot with first-wins duplicate recording
   and proves sanitization precedes the stub's constructor probe. Exact reads
   and authorized enumeration use that immutable base while the existing JS
   proxy supplies the mutable overlay; the real environment stays sanitized.
   Typed privileged-control migration and isolation fixtures remain.
   The Windows Hermes flag lookup is explicitly classified as
   `typed-internal-dispatch`: it reads the named process-block value selected by
   trusted runtime construction rather than capturing or brokering the whole
   ambient environment.

No REPL, no `eval`, no `.env` loading in compiled mode.

### 5. Targets: host-target v1 on the catalog machinery

v1 packages for the host target only, on `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu`. v1 already uses the full catalog machinery
(§2a) — stub, contract, and `hermesc` are authenticated catalog
artifacts even for the host — so cross-target packaging later is
catalog population plus the genuinely deferred work: HBC production
has no target parameter today, module semantic fingerprints embed the
Hermes target, and no foreign-target stubs exist. The catalog is
offline; packaging never downloads implicitly; a missing entry fails
loudly naming the fetch step.

### 6. Compiled boot and process semantics

- Verify §2c layout, section directory, envelope digest, contract
  pin — all from the pinned self-file handle (§3) — refusing with a
  stable error carrying the embedded identity.
- Select the immutable boot posture before runtime construction. Ambient boot
  projects ordinary inherited process state without capability enforcement;
  CapSec boot runs the environment sequence and disk-free arming (§4). Then
  evaluate the entry designation. Out-of-graph resolution fails closed in both;
  guarded sites fail at invocation per §1 step 4.
- **Argv belongs to the application, except for one first-position posture
  selector.** LLP 0047 reserves `--ibex-capsec` only as argv[1], with a leading
  `--` escape for passing it literally; every other argument and later
  occurrence reaches the program (fixtures). Unicode
  argv contract: non-Unicode arguments fail at boot with a stable
  error **naming the offending argument index**; surrogate-escape is
  the recorded alternative if field friction (non-UTF-8 filenames)
  demands it. `process.argv` is `[execPath, "<entry designation>",
  ...args]`; `argv0` is the invoked name; `execArgv` is empty.
  The stub implements this projection before linking the entry: `args_os` is
  decoded with an index-specific Unicode refusal. As of 2026-08-01 it passes
  *every* argument through unchanged, including Ibex spellings — that is the
  pre-LLP-0047 contract, and recognizing `--ibex-capsec` at argv[1] is
  unimplemented milestone-2 work, not current behavior. Compiled boot also uses the native Hermes
  clock and wake hook to drain referenced work to quiescence, treats an
  unconsumed asynchronous failure as fatal, reads the final numeric
  `process.exitCode`, and bounded-flushes accepted broker output before
  termination. Signal handling and the privileged lifecycle-control migration
  below remain outstanding.
- **Lifecycle and signals are normative rows** adopted from LLP 0025's
  file-execution obligations, with completion tied to those rows
  landing: event-loop drain and pending-async semantics, uncaught
  exception/rejection exits, `process.exit`/`exitCode` with
  output-broker flush before termination, SIGINT/SIGTERM/SIGHUP and
  signal-derived exit status, stdio brokering per LLP 0022/0025. The
  stub is in-process (no supervisor). End-to-end fixtures per row.
  Stdio/cwd implicit-vs-policy is the named author decision (§7),
  settled before `Accepted`.
- Introspection via `ibex inspect-executable` and an in-app
  namespaced API only.

### 7. Phases, gates, and the author-decision register

**Sequencing against LLP 0028.** The two programs are concurrent
Drafts and touch shared contracts, so the ordering is explicit. The
2026-07-18 Snapback decision requires computed dynamic imports for 0.2;
phase 4 therefore consumes LLP 0028's guarded-site representation and
complete candidate-table contract from rollout step 2. Each canonical
table is carried as a digest-addressed candidate section, its projection
is bound into authenticated graph and policy identity, and the compiled
stub links only those admitted rows. An unlabeled site or absent row still
refuses at invocation rather than widening to runtime resolution. The
**LLP 0014 canonical-policy schema revision is a single coordinated
change** (one owner, one version bump) carrying both programs' fields —
0028's candidate-manifest vocabulary and this RFC's v2 fields (graph
identity, entry identity, target/mount profile, root-ceiling declaration)
— since the schema is `deny_unknown_fields` and two uncoordinated revisions
cannot both be "the versioned change."

0. **Format spike:** factory-table payload on a dynamically-linked dev
   stub — envelope parsing, bulk preflight, embedded admission,
   disk-free arming — before static-Hermes work completes; gate:
   relocation smoke test.
1. **Static stub + contract + catalog** — static macOS Hermes
   (lean-vs-full by measurement between eligible builds), Linux
   dependency audit (libcurl disposition required), stub crate,
   `StubContractV1` + instance descriptor + catalog manifest with
   trust root; gate: `otool`/`ldd` checks, swap-rejection fixtures,
   measured stub sizes.
2. **Formats** — envelope + embedded-graph schemas, canonical
   encodings, golden vectors, fuzzing, §2c signing vectors incl.
   post-signing layout; gate: format suite + fuzz corpus; real graphs
   incl. builtins validate.
3. **Admission + arming** — pinned-handle self-file acquisition,
   embedded protected-artifact identity (LLP 0021/arming revision),
   path-independent labels, `processAuthorityCeiling` channel +
   bootstrap stage (LLP 0014/0021/schema revisions), LLP 0023
   revision (`/app`//`/work`, `LogicalRoot` vocabulary),
   policy graph-identity field; gate: relocation (incl. carrier
   bytes), authority-denial, bootstrap/application split,
   wrong-engine fixtures.
4. **Producer + CLI** — snapshot domain + cross-checks (TOCTOU and
   divergence fixtures), production HBC publication/admission with
   derived metadata and deterministic `hermesc` recipe,
   invocation-preserving unsupported-shape handling +
   `--deny-unsupported`, `compile`/`inspect-executable` with capsec
   classification and registry/policy digest migration, LLP
   0010/`runtime-surface.json` together, CompilePlan + two-atomic-file
   publication, build statement; gate: drift/wrong-engine refusals,
   clean-root HBC byte comparison, two-clean-builder reproducibility.
5. **Environment** — ordinary inherited environment semantics in ambient mode;
   capture/default-deny-sanitize/broker, typed internal config surface
   (profiled controls inert), generated profile, overlay/child fixtures, and
   package-principal composition in CapSec mode; gate: every profiled variable
   plus ambient inheritance, CapSec inheritance, and inertness tests.
6. **Process semantics + optional CapSec posture** — argv/lifecycle/signal
   fixtures incl. the reserved selector and escape; LLP 0025 rows landed;
   ambient compatibility boot works without a CapSec advertisement; explicit
   CapSec selection refuses before application code until the exact shipped
   contract is advertised. A verified advertisement is a gate for claiming
   that optional posture works on a tuple, not for shipping ambient v1.
7. **Measured claims against precommitted budgets** — the budget
   numbers are fixed **before measurement begins** (register item 7;
   thresholds set at measurement time can be fitted to results — the
   trap LLP 0028's precommitted projections exist to avoid) — size,
   cold start (copy vs
   mmap vs zero-copy mapped image), large-graph startup,
   signature-scan cost, factory-table vs HBC; gate: recorded report
   **with pass/fail thresholds** (LLP 0026 pattern).

**Author-decision register:** (1) stdio/cwd implicit vs
policy-explicit (blocks `Accepted`); (2) **resolved 2026-08-01:** the initial
CapSec real-environment restore allowlist is empty; application values are
brokered from the captured base and ambient boot does not scrub; (3) factory-table as release encoding
vs diagnostic-only (blocks phase-7 exit); (4) **re-resolved 2026-08-01 by LLP
0047** (supersedes both earlier advertisement-first postures): v1 defaults to
ambient compatibility execution and ships without a verified CapSec target.
The same artifact accepts an explicit CapSec selector, which keeps refusing
every unadvertised target before application code and never falls back to
ambient execution. The first successful CapSec posture remains a v1.1
milestone scoped to a single tuple (leading candidate on current verified-row
volume: `aarch64-apple-darwin`; final tuple choice is an author call at v1.1
scoping) working the prioritized target-applicable subset of the residual
catalog rows tracked in
issues/20260728-capsec-public-surface-evidence-backlog.md; (5)
**resolved 2026-07-18:** Snapback does not pull Windows or macOS x64 ahead of
the v1 catalog order; LLP 0031 keeps them deferred pending exact artifacts and
evidence; (6) lean-vs-full
engine variant (decided by phase-1 measurement, ratified by author);
(7) the phase-7 budget numbers, fixed before measurement (blocks
phase-7 entry); (8) publisher-statement key custody and trust policy
(who signs, what identities are trusted, especially on Linux where no
platform signature exists — blocks calling the third
`inspect-executable` state "authenticated" rather than "present and
digest-consistent").

## Alternatives considered

- **Ship `ibex` + a sidecar carrier file** — rejected; skew, no
  single-artifact attestation.
- **Object-section embedding** — named macOS fallback.
- **Overload `ibex build --compile`** — rejected; conflicting legacy
  grammar, pipeline owned by the LLP 0028 window-closure program.
- **Subtractive `compiled-mode` feature** — rejected; CLI audit and
  pre-clap interception make a dedicated stub crate strictly better.
- **Reuse `prepared-module-graph/1` verbatim** — rejected;
  path-bearing, file-only schema.
- **Compile-time refusal of unsupported shapes (previous revision)** —
  withdrawn; contradicts LLP 0028's invocation-time contract; kept
  only as opt-in `--deny-unsupported`.
- **Stapled standalone binary (previous revision)** — withdrawn;
  Apple does not staple standalone binaries; raw-signed + online
  ticket, container packaging as distributor step.
- **Content addressing as catalog trust** — rejected; an
  authenticated catalog manifest with rollback resistance is the
  trust root.
- **Factory-table-only (no HBC)** — rejected as default; kept
  diagnostic-only pending phase-7 measurement.

## Open questions

- ~~The concrete `ibex/authenticated-graph-snapshot/1` projection
  details.~~ **Closed:** the canonical projection and its identity are
  implemented; golden vectors remain the pinning mechanism.
- Whether the LLP 0023 revision's unset-cwd sentinel breaks real
  Node-compat libraries in practice (phase-3 fixture evidence).
- Signed-artifact reproducibility (pinned in-tree signer) vs the
  unsigned-core + detached-statement posture.
- Per-section compression (digests over uncompressed bytes) vs boot
  simplicity.
- Multi-entry designation tables (kept format-possible, product
  question deferred).
- The register items in §7.
